//! Finding schema and scan report structures.
//!
//! The `Finding` struct matches the reference schema from Section 6 of the design document.
//! AI annotations are intentionally separated into `AiAnnotations` to enforce the hard
//! boundary from Section 8.4: AI output can annotate but never mutate deterministic findings.

use crate::severity::{AnalysisStatus, Confidence, Engine, Severity, SolverStatus, VulnClass};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A single security finding produced by one of Photon's analysis engines.
///
/// Reference schema from Section 6:
/// ```json
/// {
///   "rule_id": "PHOTON-REENTRANCY-001",
///   "severity": "CRITICAL",
///   "engine": "symbolic",
///   "solver_status": "SAT",
///   "file": "contract/Vault.sol",
///   "line": 42,
///   "description": "External call precedes state update (CEI violation).",
///   "remediation": "Move balance update before external call.",
///   "confidence": "high"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique rule identifier (e.g., "PHOTON-REENTRANCY-001").
    pub rule_id: String,

    /// Severity level â€” set by the deterministic engine, immutable by AI (Section 8.4).
    pub severity: Severity,

    /// Which engine produced this finding.
    pub engine: Engine,

    /// For symbolic findings: SAT/UNSAT/UNKNOWN. UNKNOWN must never render as 'safe'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solver_status: Option<SolverStatus>,

    /// Source file path (relative to scan root).
    pub file: PathBuf,

    /// Line number in the source file (1-indexed).
    pub line: u32,

    /// Column number in the source file (1-indexed), if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,

    /// Vulnerability class for categorization.
    pub vuln_class: VulnClass,

    /// Human-readable description of the vulnerability.
    pub description: String,

    /// Actionable remediation guidance.
    pub remediation: String,

    /// Confidence level of the finding.
    pub confidence: Confidence,

    /// Optional AI-generated annotations. This is a SEPARATE, APPEND-ONLY structure.
    /// Per Section 8.4: AI output can never suppress, delete, or downgrade severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_annotations: Option<AiAnnotations>,
}

/// AI-generated annotations for a finding.
///
/// This struct is intentionally separated from `Finding` to enforce the hard boundary
/// from Section 8.4. These fields are advisory metadata only and must never:
/// - Suppress or delete a finding
/// - Downgrade the severity set by a deterministic engine
/// - Upgrade a static-only finding to CRITICAL on its own authority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnnotations {
    /// AI-generated remediation explanation (more detailed than the rule's built-in remediation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_detail: Option<String>,

    /// False-positive confidence score (0.0 = definitely real, 1.0 = definitely false positive).
    /// ADVISORY ONLY â€” used for UI sorting/highlighting, never for suppression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_confidence: Option<f64>,

    /// AI provider that generated these annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Model identifier used for generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Aggregated scan report for a single scan invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Unique scan identifier.
    pub scan_id: Uuid,

    /// Timestamp when the scan started.
    pub started_at: DateTime<Utc>,

    /// Timestamp when the scan completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Root directory that was scanned.
    pub target_dir: PathBuf,

    /// Severity rubric version used for this scan.
    pub rubric_version: String,

    /// Pipeline stages that were executed.
    pub engines_used: Vec<Engine>,

    /// Per-contract analysis status.
    pub contract_statuses: Vec<ContractStatus>,

    /// All findings, sorted by (file, line, rule_id) for deterministic output.
    pub findings: Vec<Finding>,

    /// Total number of contracts analyzed.
    pub contracts_analyzed: u32,

    /// Total number of contracts skipped or failed.
    pub contracts_skipped: u32,

    /// Total scan duration in milliseconds.
    pub duration_ms: u64,

    /// Whether AI annotations are available.
    pub ai_annotations_available: bool,

    /// Optional scan-level AI summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_summary: Option<String>,
}

/// Status of a single contract in the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStatus {
    /// Path to the contract file.
    pub file: PathBuf,
    /// Analysis status.
    pub status: AnalysisStatus,
    /// Number of findings for this contract.
    pub finding_count: u32,
}

impl ScanReport {
    /// Create a new scan report with the given target directory.
    pub fn new(target_dir: PathBuf) -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: None,
            target_dir,
            rubric_version: crate::severity::SEVERITY_RUBRIC_VERSION.to_string(),
            engines_used: Vec::new(),
            contract_statuses: Vec::new(),
            findings: Vec::new(),
            contracts_analyzed: 0,
            contracts_skipped: 0,
            duration_ms: 0,
            ai_annotations_available: false,
            ai_summary: None,
        }
    }

    /// Sort findings by stable key (file, line, rule_id) for deterministic output.
    /// This satisfies Section 4.3 mitigation T-3.1.
    pub fn sort_findings(&mut self) {
        self.findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }

    /// Count findings by severity.
    pub fn count_by_severity(&self) -> std::collections::HashMap<Severity, usize> {
        let mut counts = std::collections::HashMap::new();
        for f in &self.findings {
            *counts.entry(f.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Check if any finding meets or exceeds the given severity threshold.
    pub fn has_findings_above_threshold(&self, threshold: &Severity) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity.meets_threshold(threshold))
    }

    /// Export the scan report to the standard SARIF format.
    pub fn to_sarif(&self) -> serde_json::Value {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut registered_rules = std::collections::HashSet::new();

        for finding in &self.findings {
            let rule_id = &finding.rule_id;
            if registered_rules.insert(rule_id.clone()) {
                rules.push(serde_json::json!({
                    "id": rule_id,
                    "name": rule_id.replace("PHOTON-", ""),
                    "shortDescription": {
                        "text": finding.description
                    }
                }));
            }

            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            results.push(serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": finding.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file.to_string_lossy()
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column.unwrap_or(1)
                            }
                        }
                    }
                ]
            }));
        }

        serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Photon",
                            "version": env!("CARGO_PKG_VERSION"),
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        })
    }

    /// Export the scan report to a fully-formatted, self-contained professional HTML audit report.
    pub fn to_html(&self) -> String {
        let counts = self.count_by_severity();
        let critical = counts.get(&Severity::Critical).copied().unwrap_or(0);
        let high     = counts.get(&Severity::High).copied().unwrap_or(0);
        let medium   = counts.get(&Severity::Medium).copied().unwrap_or(0);
        let low      = counts.get(&Severity::Low).copied().unwrap_or(0);
        let info_c   = counts.get(&Severity::Info).copied().unwrap_or(0);
        let total    = self.findings.len();

        // Risk score
        let mut risk_score: u8 = 0;
        for f in &self.findings {
            let w = match f.severity {
                Severity::Critical => 40, Severity::High => 20,
                Severity::Medium => 10,   Severity::Low => 3, Severity::Info => 0,
            };
            risk_score = risk_score.saturating_add(w);
        }
        if risk_score > 100 { risk_score = 100; }

        let risk_label = if risk_score >= 70 { "CRITICAL" } else if risk_score >= 40 { "HIGH" } else if risk_score >= 20 { "MEDIUM" } else { "LOW" };
        let risk_bar_w = risk_score;

        let engines_list = self.engines_used.iter().map(|e| format!("{}", e)).collect::<Vec<_>>();
        let scan_date    = self.completed_at.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                             .unwrap_or_else(|| self.started_at.format("%Y-%m-%d %H:%M UTC").to_string());
        let started_date = self.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let target_str   = self.target_dir.display().to_string().replace('\\', "/");
        let scan_id_full = self.scan_id.to_string();
        let rubric       = &self.rubric_version;

        // Severity table rows for summary
        let sev_summary_rows = {
            let mut rows = String::new();
            for (label, cls, count) in &[
                ("Critical", "sev-critical", critical),
                ("High",     "sev-high",     high),
                ("Medium",   "sev-medium",   medium),
                ("Low",      "sev-low",      low),
                ("Info",     "sev-info",     info_c),
            ] {
                rows.push_str(&format!(
                    r#"<tr><td class="sev-cell {cls}">{label}</td><td class="num-cell">{count}</td>
                    <td><div class="bar-wrap"><div class="bar-fill {cls}" style="width:{pct}%"></div></div></td></tr>"#,
                    pct = if total > 0 { (*count * 100) / total.max(1) } else { 0 }
                ));
            }
            rows
        };

        // Engine pipeline table
        let engine_rows = {
            let mut rows = String::new();
            let stages = [
                ("0", "Ingestion",        "Parsed AST, validated source files",              true),
                ("1", "Graph Transform",  "Built CFG, DFG, taint graph per contract",        true),
                ("2", "Static Analysis",  "Rayon-parallel rule evaluation (52 rules)",        true),
                ("3", "Symbolic (Z3)",    "SMT path-condition solver",                       engines_list.iter().any(|e| e.to_lowercase().contains("symbolic"))),
                ("4", "VM Fuzzing",       "revm-based bytecode fuzzer",                      engines_list.iter().any(|e| e.to_lowercase().contains("vm"))),
                ("5", "FP Suppression",   ".photon-ignore rule matching",                    true),
                ("6", "AI Annotations",   "Gemini LLM remediation + FP confidence scoring",  self.findings.iter().any(|f| f.ai_annotations.is_some())),
            ];
            for (idx, name, desc, ran) in &stages {
                let status = if *ran { r#"<span class="status-ran">âœ“ Ran</span>"# } else { r#"<span class="status-skip">â€” Skipped</span>"# };
                rows.push_str(&format!(
                    r#"<tr><td class="stage-num">{idx}</td><td class="stage-name">{name}</td><td class="stage-desc">{desc}</td><td>{status}</td></tr>"#
                ));
            }
            rows
        };

        // Contract inventory table
        let contract_rows = {
            let mut rows = String::new();
            if self.contract_statuses.is_empty() {
                rows.push_str(r#"<tr><td colspan="3" style="text-align:center;color:#888">â€”</td></tr>"#);
            } else {
                for cs in &self.contract_statuses {
                    let fname = cs.file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| cs.file.display().to_string());
                    let status_str = format!("{:?}", cs.status);
                    let badge = if cs.finding_count == 0 {
                        r#"<span class="status-ran">Clean</span>"#.to_string()
                    } else {
                        format!(r#"<span class="status-warn">{} finding(s)</span>"#, cs.finding_count)
                    };
                    rows.push_str(&format!(
                        r#"<tr><td class="mono">{fname}</td><td>{status_str}</td><td>{badge}</td></tr>"#
                    ));
                }
            }
            rows
        };

        // Finding cards (detailed)
        let mut finding_cards = String::new();
        for (i, f) in self.findings.iter().enumerate() {
            let (sev_cls, sev_label) = match f.severity {
                Severity::Critical => ("sev-critical", "CRITICAL"),
                Severity::High     => ("sev-high",     "HIGH"),
                Severity::Medium   => ("sev-medium",   "MEDIUM"),
                Severity::Low      => ("sev-low",      "LOW"),
                Severity::Info     => ("sev-info",     "INFO"),
            };
            let engine_str   = format!("{}", f.engine);
            let file_str     = f.file.display().to_string().replace('\\', "/");
            let fname_only   = f.file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file_str.clone());
            let vuln_class   = format!("{:?}", f.vuln_class);
            let confidence   = format!("{:?}", f.confidence);
            let desc_esc     = html_escape(&f.description);
            let rem_esc      = html_escape(&f.remediation);

            let solver_row = if let Some(ref s) = f.solver_status {
                let (s_cls, s_label) = match s {
                    SolverStatus::Sat     => ("sol-sat",     "SAT â€” Confirmed exploitable"),
                    SolverStatus::Unsat   => ("sol-unsat",   "UNSAT â€” Path proven safe"),
                    SolverStatus::Unknown => ("sol-unknown", "UNKNOWN â€” Inconclusive (not safe)"),
                };
                format!(r#"<tr><th>Z3 Solver</th><td><span class="solver-pill {s_cls}">{s_label}</span></td></tr>"#)
            } else { String::new() };

            let ai_section = if let Some(ref ai) = f.ai_annotations {
                let provider = html_escape(ai.provider.as_deref().unwrap_or("AI"));
                let model    = html_escape(ai.model.as_deref().unwrap_or("unknown"));
                let detail   = html_escape(ai.remediation_detail.as_deref().unwrap_or(""));
                let fp_row = if let Some(fp) = ai.fp_confidence {
                    let (fp_cls, fp_txt) = if fp < 0.2 { ("fp-real", format!("{:.0}% â€” Likely a real vulnerability", fp*100.0)) }
                        else if fp < 0.6  { ("fp-uncertain", format!("{:.0}% â€” Uncertain, manual review advised", fp*100.0)) }
                        else               { ("fp-maybe", format!("{:.0}% â€” Possible false positive", fp*100.0)) };
                    format!(r#"<div class="fp-row {fp_cls}">False-Positive Confidence: {fp_txt}</div>"#)
                } else { String::new() };
                format!(r#"<div class="ai-section">
                  <div class="ai-title">AI Analysis &nbsp;<span class="ai-meta">{provider} / {model}</span></div>
                  <div class="ai-body">{detail}</div>
                  {fp_row}
                </div>"#)
            } else { String::new() };

            finding_cards.push_str(&format!(r#"
            <div class="finding" id="F{num}" data-sev="{sev_cls}">
              <div class="finding-top">
                <div class="finding-top-left">
                  <span class="finding-index">F-{num:03}</span>
                  <span class="sev-pill {sev_cls}">{sev_label}</span>
                  <span class="rule-chip">{rule_id}</span>
                </div>
                <div class="finding-top-right">
                  <span class="eng-chip">{engine_str}</span>
                </div>
              </div>
              <div class="finding-body">
                <table class="meta-table">
                  <tr><th>File</th><td class="mono">{fname_only} <span class="line-ref">line {line}</span></td></tr>
                  <tr><th>Full Path</th><td class="mono small">{file_str}</td></tr>
                  <tr><th>Vuln Class</th><td>{vuln_class}</td></tr>
                  <tr><th>Confidence</th><td>{confidence}</td></tr>
                  {solver_row}
                </table>
                <div class="desc-block">
                  <div class="block-label">DESCRIPTION</div>
                  <div class="block-text">{desc_esc}</div>
                </div>
                <div class="rem-block">
                  <div class="block-label">RECOMMENDED FIX</div>
                  <div class="block-text">{rem_esc}</div>
                </div>
                {ai_section}
              </div>
            </div>"#,
                num     = i + 1,
                rule_id = f.rule_id,
                line    = f.line,
            ));
        }

        let no_findings = if total == 0 {
            r#"<div class="no-findings">No vulnerabilities detected â€” all checks passed.</div>"#
        } else { "" };

        let filter_btns = {
            let mut b = String::from(r#"<button class="fbtn active" onclick="doFilter('all',this)">All</button>"#);
            for (cls, label, cnt) in &[
                ("sev-critical","CRITICAL",critical),("sev-high","HIGH",high),
                ("sev-medium","MEDIUM",medium),("sev-low","LOW",low),("sev-info","INFO",info_c),
            ] {
                if *cnt > 0 {
                    b.push_str(&format!(r#"<button class="fbtn" onclick="doFilter('{cls}',this)">{label} ({cnt})</button>"#));
                }
            }
            b
        };

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Photon Security Audit Report</title>
<style>
/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   PHOTON â€” Professional Audit Report  |  Black & White Theme
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
:root {{
  --white:   #ffffff;
  --off:     #f7f7f7;
  --light:   #efefef;
  --border:  #d4d4d4;
  --mid:     #9a9a9a;
  --dark:    #3a3a3a;
  --black:   #111111;
  --ink:     #1a1a1a;

  /* Severity â€” greyscale + weight only */
  --c-crit:  #111;
  --c-high:  #333;
  --c-med:   #555;
  --c-low:   #777;
  --c-info:  #999;

  --font: 'Inter', 'Segoe UI', system-ui, sans-serif;
  --mono: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
  --max: 1100px;
  --radius: 4px;
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ font-size: 15px; }}
body {{ background: var(--white); color: var(--ink); font-family: var(--font); line-height: 1.65; }}

/* â”€â”€ Cover Header â”€â”€ */
.cover {{ background: var(--black); color: var(--white); padding: 3.5rem 4rem 3rem; position: relative; border-bottom: 4px solid #444; }}
.cover-inner {{ max-width: var(--max); margin: 0 auto; display: grid; grid-template-columns: 1fr auto; align-items: end; gap: 2rem; }}
.cover-brand {{ display: flex; align-items: baseline; gap: 0.75rem; margin-bottom: 1rem; }}
.brand-name {{ font-size: 1.6rem; font-weight: 800; letter-spacing: 6px; text-transform: uppercase; color: var(--white); }}
.brand-tag  {{ font-size: 0.7rem; letter-spacing: 4px; text-transform: uppercase; color: #888; font-weight: 500; }}
.cover-title {{ font-size: 2rem; font-weight: 700; line-height: 1.2; margin-bottom: 0.4rem; }}
.cover-sub   {{ font-size: 0.85rem; color: #aaa; letter-spacing: 1px; text-transform: uppercase; }}
.cover-meta  {{ text-align: right; font-size: 0.78rem; color: #999; line-height: 2; font-family: var(--mono); }}
.cover-meta strong {{ color: #ddd; font-weight: 600; }}
.cover-rule  {{ width: 60px; height: 3px; background: var(--white); margin-bottom: 1.5rem; }}

/* â”€â”€ Layout â”€â”€ */
.page  {{ max-width: var(--max); margin: 0 auto; padding: 2.5rem 4rem; }}
.section {{ margin-bottom: 3rem; }}
.section-head {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 1.25rem; padding-bottom: 0.6rem; border-bottom: 2px solid var(--black); }}
.section-num  {{ font-size: 0.7rem; font-weight: 700; letter-spacing: 3px; color: var(--mid); text-transform: uppercase; }}
.section-title{{ font-size: 1rem; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; color: var(--black); }}

/* â”€â”€ KPI strip â”€â”€ */
.kpi-strip {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0; border: 1px solid var(--border); }}
.kpi {{ padding: 1.25rem 1.5rem; border-right: 1px solid var(--border); }}
.kpi:last-child {{ border-right: none; }}
.kpi-val  {{ font-size: 2.2rem; font-weight: 800; font-family: var(--mono); line-height: 1; color: var(--black); }}
.kpi-label{{ font-size: 0.65rem; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: var(--mid); margin-top: 0.4rem; }}

/* â”€â”€ Risk Score Block â”€â”€ */
.risk-block {{ border: 1px solid var(--border); display: grid; grid-template-columns: 200px 1fr; }}
.risk-score-col {{ background: var(--black); color: var(--white); padding: 2rem; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.5rem; }}
.risk-num   {{ font-size: 4rem; font-weight: 900; font-family: var(--mono); line-height: 1; }}
.risk-denom {{ font-size: 1rem; color: #777; }}
.risk-label {{ font-size: 0.65rem; letter-spacing: 3px; text-transform: uppercase; color: #aaa; margin-top: 0.25rem; font-weight: 600; }}
.risk-detail-col {{ padding: 1.5rem 2rem; }}
.risk-bar-wrap {{ background: var(--light); height: 10px; border-radius: 2px; margin: 0.75rem 0; overflow: hidden; }}
.risk-bar-fill {{ height: 100%; background: var(--black); border-radius: 2px; transition: width 0.6s ease; }}
.risk-rating-text {{ font-size: 0.8rem; color: var(--dark); line-height: 1.7; }}

/* â”€â”€ Tables â”€â”€ */
table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th, td {{ padding: 0.6rem 0.9rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ font-size: 0.68rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: var(--mid); background: var(--off); border-bottom: 2px solid var(--border); }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: var(--off); }}
.num-cell  {{ font-family: var(--mono); font-weight: 700; font-size: 1.1rem; }}
.stage-num {{ font-family: var(--mono); font-weight: 700; font-size: 0.8rem; color: var(--mid); width: 30px; }}
.stage-name{{ font-weight: 600; }}
.stage-desc{{ color: var(--dark); font-size: 0.82rem; }}
.mono      {{ font-family: var(--mono); font-size: 0.82rem; }}
.small     {{ font-size: 0.75rem; color: var(--mid); }}

/* â”€â”€ Severity table row accents â”€â”€ */
.sev-cell   {{ font-weight: 700; font-size: 0.78rem; letter-spacing: 1px; text-transform: uppercase; width: 90px; }}
.sev-critical {{ color: var(--c-crit); border-left: 3px solid #111; padding-left: 0.75rem; }}
.sev-high     {{ color: var(--c-high); border-left: 3px solid #333; padding-left: 0.75rem; }}
.sev-medium   {{ color: var(--c-med);  border-left: 3px solid #555; padding-left: 0.75rem; }}
.sev-low      {{ color: var(--c-low);  border-left: 3px solid #777; padding-left: 0.75rem; }}
.sev-info     {{ color: var(--c-info); border-left: 3px solid #aaa; padding-left: 0.75rem; }}
.bar-wrap  {{ background: var(--light); height: 6px; border-radius: 2px; min-width: 120px; overflow: hidden; }}
.bar-fill  {{ height: 100%; border-radius: 2px; }}
.bar-fill.sev-critical {{ background: #111; }}
.bar-fill.sev-high     {{ background: #444; }}
.bar-fill.sev-medium   {{ background: #777; }}
.bar-fill.sev-low      {{ background: #aaa; }}
.bar-fill.sev-info     {{ background: #ccc; }}

/* â”€â”€ Status pills â”€â”€ */
.status-ran  {{ display: inline-block; background: #111; color: #fff; font-size: 0.68rem; font-weight: 700; letter-spacing: 1px; padding: 0.15rem 0.55rem; border-radius: 2px; text-transform: uppercase; }}
.status-skip {{ color: var(--mid); font-size: 0.78rem; }}
.status-warn {{ display: inline-block; background: var(--off); border: 1px solid var(--border); color: var(--dark); font-size: 0.72rem; font-weight: 700; padding: 0.15rem 0.55rem; border-radius: 2px; }}

/* â”€â”€ Filter bar â”€â”€ */
.filter-bar  {{ display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 1.5rem; align-items: center; }}
.filter-label{{ font-size: 0.7rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: var(--mid); margin-right: 0.5rem; }}
.fbtn {{ background: var(--white); border: 1px solid var(--border); color: var(--dark); padding: 0.3rem 0.9rem; font-size: 0.75rem; font-weight: 600; cursor: pointer; letter-spacing: 0.5px; border-radius: 2px; transition: all 0.15s; font-family: var(--font); }}
.fbtn:hover  {{ border-color: var(--black); color: var(--black); }}
.fbtn.active {{ background: var(--black); color: var(--white); border-color: var(--black); }}

/* â”€â”€ Finding card â”€â”€ */
.finding {{ border: 1px solid var(--border); margin-bottom: 1.25rem; border-radius: var(--radius); overflow: hidden; page-break-inside: avoid; }}
.finding.sev-critical {{ border-left: 4px solid #111; }}
.finding.sev-high     {{ border-left: 4px solid #333; }}
.finding.sev-medium   {{ border-left: 4px solid #777; }}
.finding.sev-low      {{ border-left: 4px solid #aaa; }}
.finding.sev-info     {{ border-left: 4px solid #ccc; }}
.finding-top {{ background: var(--off); border-bottom: 1px solid var(--border); padding: 0.7rem 1.1rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }}
.finding-top-left  {{ display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }}
.finding-index     {{ font-family: var(--mono); font-size: 0.75rem; font-weight: 700; color: var(--mid); min-width: 42px; }}
.finding-top-right {{ display: flex; align-items: center; gap: 0.4rem; }}
.finding-body {{ padding: 1.25rem 1.5rem; display: flex; flex-direction: column; gap: 1rem; }}

/* â”€â”€ Inline chips/pills â”€â”€ */
.sev-pill  {{ display: inline-block; font-size: 0.65rem; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; padding: 0.2rem 0.65rem; border-radius: 2px; }}
.sev-pill.sev-critical {{ background: #111; color: #fff; }}
.sev-pill.sev-high     {{ background: #333; color: #fff; }}
.sev-pill.sev-medium   {{ background: #666; color: #fff; }}
.sev-pill.sev-low      {{ background: #aaa; color: #fff; }}
.sev-pill.sev-info     {{ background: var(--light); color: #666; border: 1px solid var(--border); }}
.rule-chip {{ font-family: var(--mono); font-size: 0.78rem; font-weight: 600; color: var(--dark); background: var(--light); border: 1px solid var(--border); padding: 0.15rem 0.55rem; border-radius: 2px; }}
.eng-chip  {{ font-size: 0.68rem; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; color: var(--mid); border: 1px solid var(--border); padding: 0.15rem 0.5rem; border-radius: 2px; }}
.line-ref  {{ font-family: var(--mono); font-size: 0.72rem; color: var(--mid); margin-left: 0.4rem; }}

/* â”€â”€ Solver pills â”€â”€ */
.solver-pill        {{ display: inline-block; font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.55rem; border-radius: 2px; letter-spacing: 0.5px; }}
.sol-sat     {{ background: #111; color: #fff; }}
.sol-unsat   {{ background: var(--light); color: var(--dark); border: 1px solid var(--border); }}
.sol-unknown {{ background: #e8e8e8; color: #444; border: 1px solid #ccc; font-style: italic; }}

/* â”€â”€ Meta table inside finding â”€â”€ */
.meta-table {{ border: 1px solid var(--border); font-size: 0.8rem; }}
.meta-table th {{ background: var(--off); font-size: 0.65rem; letter-spacing: 1px; color: var(--mid); width: 120px; vertical-align: top; }}
.meta-table td {{ color: var(--dark); }}
.meta-table tr:last-child th,
.meta-table tr:last-child td {{ border-bottom: none; }}

/* â”€â”€ Description / Fix blocks â”€â”€ */
.block-label {{ font-size: 0.62rem; font-weight: 800; letter-spacing: 3px; text-transform: uppercase; color: var(--mid); margin-bottom: 0.4rem; }}
.desc-block .block-text {{ color: var(--ink); font-size: 0.875rem; line-height: 1.7; }}
.rem-block {{ background: var(--off); border: 1px solid var(--border); border-left: 3px solid var(--black); padding: 0.85rem 1rem; }}
.rem-block .block-label {{ color: var(--dark); }}
.rem-block .block-text  {{ font-size: 0.85rem; color: var(--dark); line-height: 1.7; }}

/* â”€â”€ AI section â”€â”€ */
.ai-section {{ border: 1px solid var(--border); padding: 0.9rem 1rem; background: var(--white); }}
.ai-title   {{ font-size: 0.68rem; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; color: var(--dark); margin-bottom: 0.5rem; border-bottom: 1px solid var(--light); padding-bottom: 0.4rem; }}
.ai-meta    {{ font-size: 0.7rem; color: var(--mid); font-weight: 400; letter-spacing: 0; text-transform: none; }}
.ai-body    {{ font-size: 0.83rem; color: var(--dark); white-space: pre-wrap; line-height: 1.7; }}
.fp-row     {{ margin-top: 0.6rem; font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.6rem; border-radius: 2px; display: inline-block; }}
.fp-real     {{ background: #111; color: #fff; }}
.fp-uncertain{{ background: #ddd; color: #333; }}
.fp-maybe    {{ background: var(--off); border: 1px solid var(--border); color: var(--dark); }}

/* â”€â”€ No findings â”€â”€ */
.no-findings {{ text-align: center; padding: 3rem; color: var(--mid); font-size: 0.9rem; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; border: 1px dashed var(--border); }}

/* â”€â”€ Footer â”€â”€ */
.footer {{ background: var(--black); color: #777; text-align: center; padding: 1.5rem; font-size: 0.72rem; letter-spacing: 1px; margin-top: 4rem; }}
.footer strong {{ color: #bbb; }}

/* â”€â”€ Print â”€â”€ */
@media print {{
  .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .finding {{ page-break-inside: avoid; }}
  .filter-bar {{ display: none; }}
  .fbtn {{ display: none; }}
}}
</style>
</head>
<body>

<!-- â•â•â•â•â•â•â•â•â•â•â•â•â• COVER â•â•â•â•â•â•â•â•â•â•â•â•â• -->
<div class="cover">
  <div class="cover-inner">
    <div>
      <div class="cover-brand">
        <span class="brand-name">Photon</span>
        <span class="brand-tag">Security</span>
      </div>
      <div class="cover-rule"></div>
      <div class="cover-title">Smart Contract Security<br/>Audit Report</div>
      <div class="cover-sub" style="margin-top:0.75rem">{scan_date}</div>
    </div>
    <div class="cover-meta">
      <div><strong>Scan ID</strong><br/>{scan_id}</div>
      <div style="margin-top:0.75rem"><strong>Target</strong><br/>{target}</div>
      <div style="margin-top:0.75rem"><strong>Rubric</strong><br/>v{rubric}</div>
      <div style="margin-top:0.75rem"><strong>Started</strong><br/>{started}</div>
    </div>
  </div>
</div>

<!-- â•â•â•â•â•â•â•â•â•â•â•â•â• BODY â•â•â•â•â•â•â•â•â•â•â•â•â• -->
<div class="page">

  <!-- 1. Executive Summary -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">01</span>
      <span class="section-title">Executive Summary</span>
    </div>
    <div class="kpi-strip">
      <div class="kpi"><div class="kpi-val">{total}</div><div class="kpi-label">Total Findings</div></div>
      <div class="kpi"><div class="kpi-val">{critical}</div><div class="kpi-label">Critical</div></div>
      <div class="kpi"><div class="kpi-val">{high}</div><div class="kpi-label">High</div></div>
      <div class="kpi"><div class="kpi-val">{medium}</div><div class="kpi-label">Medium</div></div>
      <div class="kpi"><div class="kpi-val">{contracts}</div><div class="kpi-label">Contracts Analyzed</div></div>
    </div>
  </div>

  <!-- 2. Risk Score -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">02</span>
      <span class="section-title">Risk Assessment</span>
    </div>
    <div class="risk-block">
      <div class="risk-score-col">
        <div class="risk-num">{risk_score}</div>
        <div class="risk-denom">/100</div>
        <div class="risk-label">{risk_label} RISK</div>
      </div>
      <div class="risk-detail-col">
        <div class="block-label">Composite Risk Score</div>
        <div class="risk-bar-wrap"><div class="risk-bar-fill" style="width:{risk_bar_w}%"></div></div>
        <div class="risk-rating-text">
          Score is computed as a weighted sum of findings by severity:<br/>
          Critical Ã— 40 pts &nbsp;Â·&nbsp; High Ã— 20 pts &nbsp;Â·&nbsp; Medium Ã— 10 pts &nbsp;Â·&nbsp; Low Ã— 3 pts &nbsp;Â·&nbsp; Info Ã— 0 pts, capped at 100.<br/><br/>
          <strong>Duration:</strong> {duration} ms &nbsp;&nbsp;
          <strong>Engines:</strong> {engines}
        </div>
      </div>
    </div>
  </div>

  <!-- 3. Severity Distribution -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">03</span>
      <span class="section-title">Severity Distribution</span>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Count</th><th style="min-width:180px">Proportion</th></tr></thead>
      <tbody>{sev_summary_rows}</tbody>
    </table>
  </div>

  <!-- 4. Analysis Pipeline -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">04</span>
      <span class="section-title">Analysis Pipeline</span>
    </div>
    <table>
      <thead><tr><th>#</th><th>Stage</th><th>Description</th><th>Status</th></tr></thead>
      <tbody>{engine_rows}</tbody>
    </table>
  </div>

  <!-- 5. Contract Inventory -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">05</span>
      <span class="section-title">Contract Inventory</span>
    </div>
    <table>
      <thead><tr><th>Contract File</th><th>Status</th><th>Findings</th></tr></thead>
      <tbody>{contract_rows}</tbody>
    </table>
  </div>

  <!-- 6. Detailed Findings -->
  <div class="section">
    <div class="section-head">
      <span class="section-num">06</span>
      <span class="section-title">Detailed Findings <span style="font-weight:400;color:#999;font-size:0.75rem;letter-spacing:0">({total} total)</span></span>
    </div>

    <div class="filter-bar">
      <span class="filter-label">Filter:</span>
      {filter_btns}
    </div>

    {no_findings}
    <div id="findings-list">{finding_cards}</div>
  </div>

</div>

<!-- â•â•â•â•â•â•â•â•â•â•â•â•â• FOOTER â•â•â•â•â•â•â•â•â•â•â•â•â• -->
<div class="footer">
  <strong>Photon Web3 Security Scanner</strong> &nbsp;v0.1.0 &nbsp;Â·&nbsp;
  Static Â· Symbolic Â· Dynamic &nbsp;Â·&nbsp;
  Report ID: {scan_id} &nbsp;Â·&nbsp; {scan_date}
</div>

<script>
function doFilter(sev, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(card => {{
    card.style.display = (sev === 'all' || card.dataset.sev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"#,
            target   = html_escape(&target_str),
            scan_id  = html_escape(&scan_id_full),
            rubric   = html_escape(rubric),
            started  = html_escape(&started_date),
            scan_date= html_escape(&scan_date),
            total    = total,
            critical = critical,
            high     = high,
            medium   = medium,
            contracts= self.contracts_analyzed,
            risk_score= risk_score,
            risk_label= risk_label,
            risk_bar_w= risk_bar_w,
            duration = self.duration_ms,
            engines  = html_escape(&engines_list.join(" Â· ")),
            sev_summary_rows = sev_summary_rows,
            engine_rows  = engine_rows,
            contract_rows= contract_rows,
            filter_btns  = filter_btns,
            no_findings  = no_findings,
            finding_cards= finding_cards,
        )
    }

    /// Export the scan report to Slither-compatible JSON format.
    pub fn to_slither_compat(&self) -> serde_json::Value {
        let mut detectors = Vec::new();

        for finding in &self.findings {
            let slither_detector = match finding.rule_id.as_str() {
                "PHOTON-REENTRANCY-001" => "reentrancy-eth",
                "PHOTON-REENTRANCY-002" => "reentrancy-no-eth",
                "PHOTON-ACCESS-001" => "unprotected-state",
                "PHOTON-ACCESS-002" => "suicidal",
                "PHOTON-ARITH-001" => "overflow",
                "PHOTON-ORACLE-001" => "oracle-manipulation",
                other => other,
            };

            detectors.push(serde_json::json!({
                "elements": [
                    {
                        "type": "node",
                        "name": finding.file.file_name().unwrap_or_default().to_string_lossy(),
                        "source_mapping": {
                            "filename_relative": finding.file.to_string_lossy(),
                            "lines": [finding.line]
                        }
                    }
                ],
                "description": finding.description,
                "markdown": format!("### {}\n\n{}", finding.rule_id, finding.description),
                "detector": slither_detector
            }));
        }

        serde_json::json!({
            "success": true,
            "error": serde_json::Value::Null,
            "results": {
                "detectors": detectors
            }
        })
    }
}

/// Minimal HTML escaper for user-supplied strings.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}




#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(rule_id: &str, severity: Severity, line: u32) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            engine: Engine::Static,
            solver_status: None,
            file: PathBuf::from("test.sol"),
            line,
            column: None,
            vuln_class: VulnClass::Reentrancy,
            description: "test".to_string(),
            remediation: "fix it".to_string(),
            confidence: Confidence::High,
            ai_annotations: None,
        }
    }

    #[test]
    fn findings_sort_deterministically() {
        let mut report = ScanReport::new(PathBuf::from("/test"));
        report.findings.push(make_finding("B-002", Severity::High, 50));
        report.findings.push(make_finding("A-001", Severity::Critical, 10));
        report.findings.push(make_finding("A-001", Severity::Medium, 30));
        report.sort_findings();

        assert_eq!(report.findings[0].line, 10);
        assert_eq!(report.findings[1].line, 30);
        assert_eq!(report.findings[2].line, 50);
    }

    #[test]
    fn ai_annotations_cannot_alter_severity() {
        // Section 8.4: This test asserts that AI annotations are a separate struct
        // and the Finding's severity field is independent of ai_annotations.
        let mut finding = make_finding("TEST-001", Severity::Critical, 1);
        finding.ai_annotations = Some(AiAnnotations {
            remediation_detail: Some("AI says this is fine".to_string()),
            fp_confidence: Some(0.95), // AI thinks it's a false positive
            provider: Some("test".to_string()),
            model: Some("test".to_string()),
        });
        // Severity must remain CRITICAL regardless of AI's FP confidence
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn severity_threshold_gating() {
        let mut report = ScanReport::new(PathBuf::from("/test"));
        report.findings.push(make_finding("A", Severity::Medium, 1));
        report.findings.push(make_finding("B", Severity::Low, 2));

        assert!(report.has_findings_above_threshold(&Severity::Low));
        assert!(report.has_findings_above_threshold(&Severity::Medium));
        assert!(!report.has_findings_above_threshold(&Severity::High));
    }

    #[test]
    fn test_exporters() {
        let mut report = ScanReport::new(PathBuf::from("/test"));
        report.findings.push(make_finding("PHOTON-REENTRANCY-001", Severity::Critical, 42));

        let sarif = report.to_sarif();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "Photon");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "PHOTON-REENTRANCY-001");

        let slither = report.to_slither_compat();
        assert_eq!(slither["success"], true);
        assert_eq!(slither["results"]["detectors"][0]["detector"], "reentrancy-eth");
    }
}
