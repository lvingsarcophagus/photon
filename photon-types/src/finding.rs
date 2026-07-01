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

    /// Severity level — set by the deterministic engine, immutable by AI (Section 8.4).
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
    /// ADVISORY ONLY — used for UI sorting/highlighting, never for suppression.
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
}
