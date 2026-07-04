//! # photon-symbolic — Symbolic Solver Engine (Phase 2)
//!
//! Z3-backed SMT evaluation, gated to flagged execution paths only.
//! Uses a subprocess model (invokes `z3 -in` with SMT-LIB2 on stdin)
//! for build portability — no native C++ linking required.
//!
//! Key design constraints from Section 4.4:
//! - Three-valued result: SAT / UNSAT / UNKNOWN
//! - UNKNOWN must never be flattened to 'safe'
//! - Fixed-width 256-bit bitvector theory for EVM word semantics
//! - Per-function solver timeout cap

pub mod smt;
pub mod solver;

use photon_ir::ContractIR;
use photon_types::{
    Confidence, Engine, Finding, SolverStatus, SymbolicConfig, VulnClass,
};
use solver::{SolverResult, Z3Solver};
use std::time::Instant;
use tracing::{debug, info, warn};

/// The symbolic analysis engine.
pub struct SymbolicEngine {
    config: SymbolicConfig,
}

impl SymbolicEngine {
    pub fn new(config: SymbolicConfig) -> Self {
        Self { config }
    }

    /// Analyze flagged paths with Z3 symbolic execution.
    ///
    /// Takes the contract IRs and the static findings. Only findings with
    /// `escalate_to_symbolic: true` are processed (gated execution per Section 4.4).
    ///
    /// Returns a new Vec of findings with `engine: Symbolic` and `solver_status` set.
    /// These are **new findings** that complement (not replace) the static findings.
    pub fn analyze(
        &self,
        contracts: &[ContractIR],
        static_findings: &[Finding],
    ) -> SymbolicResult {
        if !self.config.enabled {
            info!("Symbolic engine disabled — skipping");
            return SymbolicResult {
                findings: Vec::new(),
                queries_total: 0,
                queries_sat: 0,
                queries_unsat: 0,
                queries_unknown: 0,
                z3_available: false,
            };
        }

        let start = Instant::now();

        // Initialize Z3 solver
        let z3 = Z3Solver::new(
            self.config.z3_path.as_deref(),
            self.config.solver_timeout,
        );

        info!(
            "Symbolic engine: Z3 {} — processing {} static findings against {} contracts",
            if z3.is_available() { "available" } else { "NOT available (degraded mode)" },
            static_findings.len(),
            contracts.len()
        );

        // Generate SMT-LIB2 queries for flagged findings
        let queries = smt::generate_queries(contracts, static_findings);

        info!("Generated {} SMT queries for symbolic verification", queries.len());

        let mut findings = Vec::new();
        let mut queries_sat = 0u32;
        let mut queries_unsat = 0u32;
        let mut queries_unknown = 0u32;

        for query in &queries {
            debug!(
                "Solving query for {} at {}:{}",
                query.finding_rule_id, query.file, query.line
            );

            let result: SolverResult = match z3.solve(&query.script) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Z3 solver error for {}: {}", query.finding_rule_id, e);
                    queries_unknown += 1;
                    SolverResult {
                        status: SolverStatus::Unknown,
                        raw_output: format!("Solver error: {}", e),
                        duration: std::time::Duration::from_millis(0),
                    }
                }
            };

            match result.status {
                SolverStatus::Sat => queries_sat += 1,
                SolverStatus::Unsat => queries_unsat += 1,
                SolverStatus::Unknown => queries_unknown += 1,
            }

            // Create a symbolic finding
            let severity = match result.status {
                SolverStatus::Sat => severity_for_vuln_class(&query.vuln_class),
                SolverStatus::Unsat => {
                    debug!(
                        "UNSAT for {} — path proven safe, no finding emitted",
                        query.finding_rule_id
                    );
                    continue; // Don't emit a finding for UNSAT paths
                }
                SolverStatus::Unknown => {
                    // UNKNOWN gets the same severity as the static finding,
                    // but with solver_status: UNKNOWN so the UI can badge it
                    severity_for_vuln_class(&query.vuln_class)
                }
            };

            findings.push(Finding {
                rule_id: query.finding_rule_id.clone(),
                severity,
                engine: Engine::Symbolic,
                solver_status: Some(result.status),
                file: std::path::PathBuf::from(&query.file),
                line: query.line,
                column: None,
                vuln_class: query.vuln_class,
                description: format!(
                    "[Symbolic] {} — Z3 result: {}",
                    query.description,
                    result.status
                ),
                remediation: match result.status {
                    SolverStatus::Sat => format!(
                        "Z3 confirmed this vulnerability is reachable. {}",
                        remediation_for_vuln_class(&query.vuln_class)
                    ),
                    SolverStatus::Unknown => format!(
                        "Z3 solver returned UNKNOWN (timeout or inconclusive). \
                         This does NOT mean the path is safe. {}",
                        remediation_for_vuln_class(&query.vuln_class)
                    ),
                    SolverStatus::Unsat => unreachable!(), // filtered above
                },
                confidence: match result.status {
                    SolverStatus::Sat => Confidence::High,
                    SolverStatus::Unknown => Confidence::Low,
                    SolverStatus::Unsat => unreachable!(),
                },
                ai_annotations: None,
            });
        }

        let elapsed = start.elapsed();
        info!(
            "Symbolic analysis complete in {:?}: {} queries ({} SAT, {} UNSAT, {} UNKNOWN)",
            elapsed,
            queries.len(),
            queries_sat,
            queries_unsat,
            queries_unknown
        );

        SymbolicResult {
            findings,
            queries_total: queries.len() as u32,
            queries_sat,
            queries_unsat,
            queries_unknown,
            z3_available: z3.is_available(),
        }
    }
}

/// Result of symbolic analysis.
#[derive(Debug)]
pub struct SymbolicResult {
    /// Findings produced by symbolic verification.
    pub findings: Vec<Finding>,
    /// Total number of SMT queries generated.
    pub queries_total: u32,
    /// Queries that returned SAT (vulnerability confirmed).
    pub queries_sat: u32,
    /// Queries that returned UNSAT (path proven safe).
    pub queries_unsat: u32,
    /// Queries that returned UNKNOWN (timeout/incomplete).
    pub queries_unknown: u32,
    /// Whether Z3 was available on this system.
    pub z3_available: bool,
}

/// Map vulnerability class to severity for symbolic-confirmed findings.
fn severity_for_vuln_class(vuln_class: &VulnClass) -> photon_types::Severity {
    match vuln_class {
        VulnClass::Reentrancy => photon_types::Severity::Critical,
        VulnClass::AccessControl => photon_types::Severity::High,
        VulnClass::Arithmetic => photon_types::Severity::High,
        VulnClass::OracleManipulation => photon_types::Severity::Medium,
        _ => photon_types::Severity::Medium,
    }
}

/// Default remediation text per vulnerability class.
fn remediation_for_vuln_class(vuln_class: &VulnClass) -> &'static str {
    match vuln_class {
        VulnClass::Reentrancy => {
            "Apply the Checks-Effects-Interactions pattern: update all state \
             variables before making any external calls. Consider using \
             OpenZeppelin's ReentrancyGuard."
        }
        VulnClass::AccessControl => {
            "Add an access control modifier (e.g., `onlyOwner`) or a \
             `require(msg.sender == owner)` check to restrict function access."
        }
        VulnClass::Arithmetic => {
            "Upgrade to Solidity >= 0.8.0 for built-in overflow checking, \
             or use OpenZeppelin's SafeMath library."
        }
        _ => "Review and fix the vulnerability according to best practices.",
    }
}

/// Placeholder for Z3 solver status display.
pub fn solver_status_to_string(status: SolverStatus) -> &'static str {
    match status {
        SolverStatus::Sat => "SAT — vulnerability confirmed on this path",
        SolverStatus::Unsat => "UNSAT — proven safe on this path",
        SolverStatus::Unknown => "UNKNOWN — solver timeout/incomplete (NOT safe)",
    }
}
