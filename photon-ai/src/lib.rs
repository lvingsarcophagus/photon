//! # photon-ai — AI-Assisted Analysis Layer (Optional Extension)
//!
//! Runs strictly AFTER the three deterministic engines have produced final findings.
//! Consumes findings as read-only input and produces auxiliary annotations.
//!
//! ## Hard Boundary (Section 8.4 — Non-Negotiable)
//!
//! The AI layer:
//! - NEVER feeds back into CFG/DFG, static rules, Z3 solver, or VM fuzzer
//! - NEVER suppresses, deletes, or downgrades severity of deterministic findings
//! - Only produces `AiAnnotations` (remediation text, FP confidence, summaries)
//!
//! ## Provider Abstraction (Section 8.2)
//!
//! Trait-based multi-provider interface:
//! - Groq Llama (fast/low-cost: most findings)
//! - OpenAI GPT (high-reasoning: Critical/High findings)
//! - Anthropic Claude (high-reasoning: Critical/High findings)

use photon_types::{AiAnnotations, AiConfig, AiProviderConfig, AiTask, Finding, Severity};
use reqwest::Client;
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum AiError {
    #[error("AI provider not configured: {0}")]
    ProviderNotConfigured(String),

    #[error("AI provider request failed: {0}")]
    RequestFailed(String),

    #[error("AI provider timeout")]
    Timeout,

    #[error("AI feature disabled")]
    Disabled,

    #[error("JSON parse error: {0}")]
    ParseError(String),
}

// ─────────────────────────────────────────────────────────────
// Prompt builder (shared by all providers)
// ─────────────────────────────────────────────────────────────

fn build_prompt(finding: &Finding, source_context: &str) -> String {
    let ctx = if source_context.is_empty() {
        String::new()
    } else {
        format!("\n\nSource context:\n```solidity\n{}\n```", &source_context[..source_context.len().min(800)])
    };

    format!(
        "You are an expert smart contract security auditor.\n\
        Analyze this finding and respond ONLY with valid JSON.\n\n\
        Finding:\n\
        - Rule: {rule}\n\
        - Severity: {severity}\n\
        - File: {file}:{line}\n\
        - Description: {desc}\
        {ctx}\n\n\
        Respond with this exact JSON schema:\n\
        {{\"explanation\": \"<2-4 sentence explanation of the risk and how an attacker exploits it>\", \
        \"remediation\": \"<step-by-step concrete fix>\", \
        \"fp_confidence\": <float 0.0-1.0 where 0.0=definitely real, 1.0=definitely false positive>}}",
        rule = finding.rule_id,
        severity = finding.severity,
        file = finding.file.display(),
        line = finding.line,
        desc = finding.description,
        ctx = ctx,
    )
}

fn parse_ai_response(json_text: &str, provider: &str, model: &str) -> AiAnnotations {
    // Try to extract JSON from the response (model may add text around it)
    let json_str = extract_json(json_text);

    match serde_json::from_str::<Value>(&json_str) {
        Ok(v) => {
            let explanation = v["explanation"].as_str().map(str::to_string);
            let remediation = v["remediation"].as_str().map(str::to_string);
            let fp = v["fp_confidence"].as_f64();

            // Combine explanation + remediation into remediation_detail
            let detail = match (explanation, remediation) {
                (Some(e), Some(r)) => Some(format!("{}\n\n**Remediation:** {}", e, r)),
                (Some(e), None) => Some(e),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            };

            AiAnnotations {
                remediation_detail: detail,
                fp_confidence: fp,
                provider: Some(provider.to_string()),
                model: Some(model.to_string()),
            }
        }
        Err(_) => {
            // Fallback: use raw text as remediation detail
            AiAnnotations {
                remediation_detail: Some(json_text.trim().to_string()),
                fp_confidence: None,
                provider: Some(provider.to_string()),
                model: Some(model.to_string()),
            }
        }
    }
}

fn extract_json(text: &str) -> String {
    // Find the first '{' and last '}' to extract JSON from prose
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
        if end > start {
            return text[start..=end].to_string();
        }
    }
    text.to_string()
}

// ─────────────────────────────────────────────────────────────
// Groq Provider
// ─────────────────────────────────────────────────────────────

pub struct GroqProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl GroqProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self {
            api_key: config.api_key,
            model: if config.model.is_empty() {
                "llama-3.3-70b-versatile".to_string()
            } else {
                config.model
            },
            client: Client::new(),
        }
    }

    pub async fn explain_finding(&self, finding: &Finding, source_context: &str) -> Result<AiAnnotations, AiError> {
        let prompt = build_prompt(finding, source_context);

        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "user", "content": prompt }
            ],
            "temperature": 0.2,
            "max_tokens": 600
        });

        let resp = self
            .client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AiError::RequestFailed(format!("HTTP {}: {}", status, text)));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        let content = data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(parse_ai_response(&content, "groq", &self.model))
    }

    pub async fn summarize_report(&self, findings: &[Finding]) -> Result<String, AiError> {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

        let prompt = format!(
            "You are a smart contract security auditor. Write a 3-5 sentence executive summary \
            of a security scan that found {} total issues: {} Critical, {} High, {} Medium. \
            Include overall risk assessment and priority recommendations. Be concise and direct.",
            findings.len(), critical, high, medium
        );

        let body = json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": prompt }],
            "temperature": 0.3,
            "max_tokens": 300
        });

        let resp = self
            .client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AiError::RequestFailed(format!("HTTP {}", resp.status())));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        Ok(data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Summary unavailable.")
            .to_string())
    }
}

// ─────────────────────────────────────────────────────────────
// OpenAI Provider
// ─────────────────────────────────────────────────────────────

pub struct OpenAiProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl OpenAiProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self {
            api_key: config.api_key,
            model: if config.model.is_empty() {
                "gpt-4o-mini".to_string()
            } else {
                config.model
            },
            client: Client::new(),
        }
    }

    pub async fn explain_finding(&self, finding: &Finding, source_context: &str) -> Result<AiAnnotations, AiError> {
        let prompt = build_prompt(finding, source_context);

        let body = json!({
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Always respond with valid JSON only."
                },
                { "role": "user", "content": prompt }
            ],
            "temperature": 0.2,
            "max_tokens": 600,
            "response_format": { "type": "json_object" }
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AiError::RequestFailed(format!("HTTP {}: {}", status, text)));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        let content = data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(parse_ai_response(&content, "openai", &self.model))
    }

    pub async fn summarize_report(&self, findings: &[Finding]) -> Result<String, AiError> {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();

        let prompt = format!(
            "Write a 3-5 sentence executive summary for a smart contract security audit \
            with {} total findings ({} Critical, {} High). Prioritize critical issues.",
            findings.len(), critical, high
        );

        let body = json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": prompt }],
            "temperature": 0.3,
            "max_tokens": 300
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AiError::RequestFailed(format!("HTTP {}", resp.status())));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        Ok(data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("Summary unavailable.")
            .to_string())
    }
}

// ─────────────────────────────────────────────────────────────
// Anthropic Provider
// ─────────────────────────────────────────────────────────────

pub struct AnthropicProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl AnthropicProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self {
            api_key: config.api_key,
            model: if config.model.is_empty() {
                "claude-3-haiku-20240307".to_string()
            } else {
                config.model
            },
            client: Client::new(),
        }
    }

    pub async fn explain_finding(&self, finding: &Finding, source_context: &str) -> Result<AiAnnotations, AiError> {
        let prompt = build_prompt(finding, source_context);

        let body = json!({
            "model": self.model,
            "max_tokens": 600,
            "messages": [
                { "role": "user", "content": prompt }
            ]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AiError::RequestFailed(format!("HTTP {}: {}", status, text)));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        let content = data["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(parse_ai_response(&content, "anthropic", &self.model))
    }

    pub async fn summarize_report(&self, findings: &[Finding]) -> Result<String, AiError> {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();

        let body = json!({
            "model": self.model,
            "max_tokens": 300,
            "messages": [{
                "role": "user",
                "content": format!(
                    "Write a 3-5 sentence executive summary for a smart contract security audit \
                    with {} total findings ({} Critical, {} High). Be direct and actionable.",
                    findings.len(), critical, high
                )
            }]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AiError::RequestFailed(format!("HTTP {}", resp.status())));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        Ok(data["content"][0]["text"]
            .as_str()
            .unwrap_or("Summary unavailable.")
            .to_string())
    }
}

// ─────────────────────────────────────────────────────────────
// Gemini Provider
// ─────────────────────────────────────────────────────────────

pub struct GeminiProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl GeminiProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self {
            api_key: config.api_key,
            model: if config.model.is_empty() {
                "gemini-2.5-flash".to_string()
            } else {
                config.model
            },
            client: Client::new(),
        }
    }

    pub async fn explain_finding(&self, finding: &Finding, source_context: &str) -> Result<AiAnnotations, AiError> {
        let prompt = build_prompt(finding, source_context);

        let body = json!({
            "contents": [
                {
                    "parts": [
                        { "text": prompt }
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        });

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AiError::RequestFailed(format!("HTTP {}: {}", status, text)));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        let content = data["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(parse_ai_response(&content, "gemini", &self.model))
    }

    pub async fn summarize_report(&self, findings: &[Finding]) -> Result<String, AiError> {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

        let prompt = format!(
            "Write a 3-5 sentence executive summary for a smart contract security audit \
            with {} total findings ({} Critical, {} High, {} Medium). Be direct and actionable.",
            findings.len(), critical, high, medium
        );

        let body = json!({
            "contents": [
                {
                    "parts": [
                        { "text": prompt }
                    ]
                }
            ]
        });

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AiError::RequestFailed(format!("HTTP {}", resp.status())));
        }

        let data: Value = resp.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
        Ok(data["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("Summary unavailable.")
            .to_string())
    }
}

// ─────────────────────────────────────────────────────────────
// Provider enum & routing
// ─────────────────────────────────────────────────────────────

pub enum AiProvider {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
    Groq(GroqProvider),
    Gemini(GeminiProvider),
}

impl AiProvider {
    pub fn name(&self) -> &str {
        match self {
            AiProvider::Anthropic(_) => "anthropic",
            AiProvider::OpenAi(_) => "openai",
            AiProvider::Groq(_) => "groq",
            AiProvider::Gemini(_) => "gemini",
        }
    }

    pub fn supported_tasks(&self) -> &[AiTask] {
        match self {
            AiProvider::Anthropic(_) => &[AiTask::RemediationExplanation, AiTask::FalsePositiveTriage],
            AiProvider::OpenAi(_) => &[AiTask::RemediationExplanation, AiTask::FalsePositiveTriage],
            AiProvider::Groq(_) => &[AiTask::RemediationExplanation, AiTask::ReportSummarization, AiTask::ContractClassification],
            AiProvider::Gemini(_) => &[AiTask::RemediationExplanation, AiTask::ReportSummarization],
        }
    }

    pub async fn explain_finding(&self, finding: &Finding, source_context: &str) -> Result<AiAnnotations, AiError> {
        match self {
            AiProvider::Anthropic(p) => p.explain_finding(finding, source_context).await,
            AiProvider::OpenAi(p) => p.explain_finding(finding, source_context).await,
            AiProvider::Groq(p) => p.explain_finding(finding, source_context).await,
            AiProvider::Gemini(p) => p.explain_finding(finding, source_context).await,
        }
    }

    pub async fn summarize_report(&self, findings: &[Finding]) -> Result<String, AiError> {
        match self {
            AiProvider::Anthropic(p) => p.summarize_report(findings).await,
            AiProvider::OpenAi(p) => p.summarize_report(findings).await,
            AiProvider::Groq(p) => p.summarize_report(findings).await,
            AiProvider::Gemini(p) => p.summarize_report(findings).await,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// AiPostProcessor — orchestrates annotation generation
// ─────────────────────────────────────────────────────────────

pub struct AiPostProcessor {
    config: AiConfig,
    providers: Vec<AiProvider>,
}

impl AiPostProcessor {
    pub fn new(config: AiConfig) -> Self {
        let mut providers = Vec::new();

        for provider_config in &config.providers {
            match provider_config.name.as_str() {
                "anthropic" => {
                    providers.push(AiProvider::Anthropic(AnthropicProvider::new(provider_config.clone())));
                }
                "openai" => {
                    providers.push(AiProvider::OpenAi(OpenAiProvider::new(provider_config.clone())));
                }
                "groq" => {
                    providers.push(AiProvider::Groq(GroqProvider::new(provider_config.clone())));
                }
                "gemini" => {
                    providers.push(AiProvider::Gemini(GeminiProvider::new(provider_config.clone())));
                }
                _ => {
                    warn!("Unknown AI provider: {}", provider_config.name);
                }
            }
        }

        Self { config, providers }
    }


    /// Build a simple AI post-processor from a provider name and API key.
    /// Convenience constructor used by the CLI.
    pub fn from_provider(provider_name: &str, api_key: &str) -> Self {
        use std::time::Duration;
        let config = AiConfig {
            enabled: true,
            providers: vec![AiProviderConfig {
                name: provider_name.to_string(),
                api_key: api_key.to_string(),
                model: String::new(), // use default model per provider
                timeout: Duration::from_secs(30),
                tasks: vec![AiTask::RemediationExplanation, AiTask::ReportSummarization],
            }],
        };
        Self::new(config)
    }

    /// Pick the best available provider for a given finding.
    /// Routes Critical/High to high-reasoning models; others to Groq.
    fn pick_provider(&self, finding: &Finding) -> Option<&AiProvider> {
        if self.providers.is_empty() {
            return None;
        }

        let needs_high_reasoning = matches!(finding.severity, Severity::Critical | Severity::High);

        if needs_high_reasoning {
            // Prefer Anthropic or OpenAI for critical findings
            let high_reasoning = self.providers.iter().find(|p| {
                matches!(p, AiProvider::Anthropic(_) | AiProvider::OpenAi(_))
            });
            if high_reasoning.is_some() {
                return high_reasoning;
            }
        }

        // Fall back to first available provider (Groq works fine for all)
        self.providers.first()
    }

    /// Annotate findings with AI-generated content.
    ///
    /// Takes findings by reference, returns (finding_index, annotations) pairs.
    /// Hard boundary: findings are never modified by this function.
    /// Cap at 15 findings to avoid excessive API costs.
    pub async fn annotate(&self, findings: &[Finding]) -> Vec<(usize, AiAnnotations)> {
        if !self.config.enabled || self.providers.is_empty() {
            info!("AI post-processing disabled — returning empty annotations");
            return Vec::new();
        }

        let mut results = Vec::new();

        // Prioritise Critical and High first, cap total at 15
        let mut prioritised: Vec<usize> = (0..findings.len())
            .filter(|&i| matches!(findings[i].severity, Severity::Critical | Severity::High))
            .collect();
        let rest: Vec<usize> = (0..findings.len())
            .filter(|&i| !matches!(findings[i].severity, Severity::Critical | Severity::High))
            .collect();
        prioritised.extend(rest);
        prioritised.truncate(15);

        for idx in prioritised {
            let finding = &findings[idx];
            let provider = match self.pick_provider(finding) {
                Some(p) => p,
                None => continue,
            };

            info!(
                "AI annotating finding #{} ({}) via {}",
                idx + 1,
                finding.rule_id,
                provider.name()
            );

            match provider.explain_finding(finding, "").await {
                Ok(annotations) => {
                    results.push((idx, annotations));
                }
                Err(e) => {
                    warn!("AI annotation failed for finding #{}: {}", idx + 1, e);
                }
            }
        }

        results
    }

    /// Generate an executive summary of the full scan.
    pub async fn summarize(&self, findings: &[Finding]) -> Option<String> {
        if !self.config.enabled || self.providers.is_empty() {
            return None;
        }

        let provider = self.providers.first()?;

        match provider.summarize_report(findings).await {
            Ok(summary) => Some(summary),
            Err(e) => {
                warn!("AI summary failed: {}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use photon_types::Severity;
    use std::path::PathBuf;

    fn dummy_finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "TEST-RULE".to_string(),
            severity,
            file: PathBuf::from("Test.sol"),
            line: 12,
            column: None,
            vuln_class: photon_types::VulnClass::Reentrancy,
            description: "Test description".to_string(),
            remediation: "Test remediation".to_string(),
            confidence: photon_types::Confidence::High,
            engine: photon_types::Engine::Static,
            solver_status: None,
            ai_annotations: None,
        }
    }

    #[test]
    fn test_extract_json() {
        assert_eq!(extract_json("not json"), "not json");
        assert_eq!(
            extract_json("prose block {\"explanation\": \"val\"} other prose"),
            "{\"explanation\": \"val\"}"
        );
        assert_eq!(
            extract_json("{\n  \"explanation\": \"val\"\n}"),
            "{\n  \"explanation\": \"val\"\n}"
        );
    }

    #[test]
    fn test_parse_ai_response() {
        let raw = "{\"explanation\": \"exp\", \"remediation\": \"rem\", \"fp_confidence\": 0.1}";
        let ann = parse_ai_response(raw, "groq", "llama-3.3");
        assert_eq!(ann.remediation_detail, Some("exp\n\n**Remediation:** rem".to_string()));
        assert_eq!(ann.fp_confidence, Some(0.1));
        assert_eq!(ann.provider, Some("groq".to_string()));

        let invalid = "invalid json response";
        let ann_fallback = parse_ai_response(invalid, "groq", "llama-3.3");
        assert_eq!(ann_fallback.remediation_detail, Some("invalid json response".to_string()));
        assert_eq!(ann_fallback.fp_confidence, None);
    }

    #[test]
    fn test_pick_provider() {
        // Groq only
        let processor = AiPostProcessor::from_provider("groq", "key");
        let crit = dummy_finding(Severity::Critical);
        let low = dummy_finding(Severity::Low);
        assert_eq!(processor.pick_provider(&crit).unwrap().name(), "groq");
        assert_eq!(processor.pick_provider(&low).unwrap().name(), "groq");

        // OpenAI + Groq
        let config = AiConfig {
            enabled: true,
            providers: vec![
                AiProviderConfig {
                    name: "openai".to_string(),
                    api_key: "key".to_string(),
                    model: String::new(),
                    timeout: std::time::Duration::from_secs(10),
                    tasks: vec![],
                },
                AiProviderConfig {
                    name: "groq".to_string(),
                    api_key: "key".to_string(),
                    model: String::new(),
                    timeout: std::time::Duration::from_secs(10),
                    tasks: vec![],
                },
            ],
        };
        let processor_mixed = AiPostProcessor::new(config);
        assert_eq!(processor_mixed.pick_provider(&crit).unwrap().name(), "openai");
        assert_eq!(processor_mixed.pick_provider(&low).unwrap().name(), "openai"); // falls back to first (openai) if no groq-specific logic for low other than fallback
    }


    #[tokio::test]
    async fn test_disabled_by_default() {
        let processor = AiPostProcessor::new(AiConfig::default());
        let findings = vec![dummy_finding(Severity::Critical)];
        let annotations = processor.annotate(&findings).await;
        assert!(annotations.is_empty());
        assert!(processor.summarize(&findings).await.is_none());
    }
}

