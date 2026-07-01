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
//! - Anthropic Claude (high-reasoning: remediation + FP triage)
//! - OpenAI GPT (high-reasoning: remediation + FP triage)
//! - Groq Llama (fast/low-cost: summarization + classification)

use photon_types::{AiAnnotations, AiConfig, AiProviderConfig, AiTask, Finding};
use thiserror::Error;
use tracing::info;

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
}


/// Anthropic Claude provider (high-reasoning tasks).
pub struct AnthropicProvider {
    config: AiProviderConfig,
}

impl AnthropicProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self { config }
    }

    pub async fn explain_remediation(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<String, AiError> {
        // Phase 4: HTTP call to Anthropic API
        info!("Anthropic remediation: Phase 4 stub");
        Err(AiError::Disabled)
    }

    pub async fn triage_finding(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<f64, AiError> {
        info!("Anthropic triage: Phase 4 stub");
        Err(AiError::Disabled)
    }

    pub async fn summarize_report(&self, _findings: &[Finding]) -> Result<String, AiError> {
        Err(AiError::Disabled)
    }
}

/// OpenAI GPT provider (high-reasoning tasks).
pub struct OpenAiProvider {
    config: AiProviderConfig,
}

impl OpenAiProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self { config }
    }

    pub async fn explain_remediation(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<String, AiError> {
        info!("OpenAI remediation: Phase 4 stub");
        Err(AiError::Disabled)
    }

    pub async fn triage_finding(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<f64, AiError> {
        info!("OpenAI triage: Phase 4 stub");
        Err(AiError::Disabled)
    }

    pub async fn summarize_report(&self, _findings: &[Finding]) -> Result<String, AiError> {
        Err(AiError::Disabled)
    }
}

/// Groq Llama provider (fast/low-cost tasks).
pub struct GroqProvider {
    config: AiProviderConfig,
}

impl GroqProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self { config }
    }

    pub async fn explain_remediation(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<String, AiError> {
        // Groq is not recommended for high-reasoning tasks
        Err(AiError::ProviderNotConfigured(
            "Groq not suited for remediation explanation".to_string(),
        ))
    }

    pub async fn triage_finding(
        &self,
        _finding: &Finding,
        _source_context: &str,
    ) -> Result<f64, AiError> {
        Err(AiError::ProviderNotConfigured(
            "Groq not suited for FP triage".to_string(),
        ))
    }

    pub async fn summarize_report(&self, _findings: &[Finding]) -> Result<String, AiError> {
        info!("Groq summarization: Phase 4 stub");
        Err(AiError::Disabled)
    }
}

/// AI Provider representation.
///
/// Each variant handles specific task types routed based on
/// accuracy/cost/latency profiles (Section 8.2).
pub enum AiProvider {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
    Groq(GroqProvider),
}

impl AiProvider {
    /// Provider name (e.g., "anthropic", "openai", "groq").
    pub fn name(&self) -> &str {
        match self {
            AiProvider::Anthropic(_) => "anthropic",
            AiProvider::OpenAi(_) => "openai",
            AiProvider::Groq(_) => "groq",
        }
    }

    /// Supported tasks.
    pub fn supported_tasks(&self) -> &[AiTask] {
        match self {
            AiProvider::Anthropic(_) => &[AiTask::RemediationExplanation, AiTask::FalsePositiveTriage],
            AiProvider::OpenAi(_) => &[AiTask::RemediationExplanation, AiTask::FalsePositiveTriage],
            AiProvider::Groq(_) => &[AiTask::ReportSummarization, AiTask::ContractClassification],
        }
    }

    /// Generate remediation explanation for a finding.
    pub async fn explain_remediation(
        &self,
        finding: &Finding,
        source_context: &str,
    ) -> Result<String, AiError> {
        match self {
            AiProvider::Anthropic(p) => p.explain_remediation(finding, source_context).await,
            AiProvider::OpenAi(p) => p.explain_remediation(finding, source_context).await,
            AiProvider::Groq(p) => p.explain_remediation(finding, source_context).await,
        }
    }

    /// Triage a finding for false-positive confidence (0.0 = real, 1.0 = FP).
    /// ADVISORY ONLY — never used for suppression.
    pub async fn triage_finding(
        &self,
        finding: &Finding,
        source_context: &str,
    ) -> Result<f64, AiError> {
        match self {
            AiProvider::Anthropic(p) => p.triage_finding(finding, source_context).await,
            AiProvider::OpenAi(p) => p.triage_finding(finding, source_context).await,
            AiProvider::Groq(p) => p.triage_finding(finding, source_context).await,
        }
    }

    /// Summarize a full scan report.
    pub async fn summarize_report(
        &self,
        findings: &[Finding],
    ) -> Result<String, AiError> {
        match self {
            AiProvider::Anthropic(p) => p.summarize_report(findings).await,
            AiProvider::OpenAi(p) => p.summarize_report(findings).await,
            AiProvider::Groq(p) => p.summarize_report(findings).await,
        }
    }
}

/// The AI post-processor that orchestrates annotation generation.
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
                _ => {
                    tracing::warn!("Unknown AI provider: {}", provider_config.name);
                }
            }
        }

        Self { config, providers }
    }

    /// Annotate findings with AI-generated content.
    ///
    /// This function takes findings by reference and returns annotations separately,
    /// enforcing the hard boundary from Section 8.4.
    pub async fn annotate(&self, _findings: &[Finding]) -> Vec<(usize, AiAnnotations)> {
        if !self.config.enabled {
            info!("AI post-processing disabled — returning empty annotations");
            return Vec::new();
        }

        info!("AI post-processing: Phase 4 stub — no annotations generated");
        Vec::new()
    }
}
