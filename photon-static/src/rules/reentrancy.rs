//! Reentrancy vulnerability detection rules.
//!
//! PHOTON-REENTRANCY-001: External call precedes state update (CEI violation)
//! PHOTON-REENTRANCY-002: Cross-function reentrancy via shared state

use crate::{Rule, RuleFinding};
use photon_ir::{ContractIR, IrStmtKind, Visibility};
use photon_types::{Confidence, Severity, VulnClass};
use std::time::Duration;

/// PHOTON-REENTRANCY-001: Detects Check-Effects-Interactions (CEI) pattern violations.
///
/// A CEI violation occurs when an external call (interaction) is made before
/// the contract's state (effects) is updated. This is the classic reentrancy pattern.
pub struct ReentrancyCeiViolation;

impl Rule for ReentrancyCeiViolation {
    fn id(&self) -> &str {
        "PHOTON-REENTRANCY-001"
    }

    fn name(&self) -> &str {
        "CEI Violation (Reentrancy)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::Reentrancy
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn description(&self) -> &str {
        "Detects external calls that precede state updates, violating the Check-Effects-Interactions pattern. \
         An attacker can re-enter the function before state is updated, potentially draining funds."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for func in &ir.functions {
            // Skip internal/private functions (less likely to be entry points)
            if func.visibility == Visibility::Internal || func.visibility == Visibility::Private {
                continue;
            }

            // Look for the pattern: external call followed by state write
            let mut seen_external_call = false;
            let mut external_call_line = 0u32;
            let mut external_call_target = String::new();

            for stmt in &func.statements {
                match &stmt.kind {
                    IrStmtKind::ExternalCall { target, function } => {
                        seen_external_call = true;
                        external_call_line = stmt.source_line;
                        external_call_target = format!("{}.{}", target, function);
                    }
                    IrStmtKind::StateWrite { variable } => {
                        if seen_external_call {
                            findings.push(RuleFinding {
                                line: external_call_line,
                                column: None,
                                description: format!(
                                    "External call to `{}` precedes state update of `{}` in function `{}`. \
                                     This violates the Check-Effects-Interactions pattern and may allow reentrancy.",
                                    external_call_target, variable, func.name
                                ),
                                remediation: format!(
                                    "Move the state update of `{}` before the external call to `{}`. \
                                     Alternatively, use a reentrancy guard (e.g., OpenZeppelin's ReentrancyGuard).",
                                    variable, external_call_target
                                ),
                                escalate_to_symbolic: true,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        findings
    }
}

/// PHOTON-REENTRANCY-002: Detects cross-function reentrancy via shared state.
///
/// This occurs when a function makes an external call and another public function
/// reads the same state variable that the first function writes after the call.
pub struct CrossFunctionReentrancy;

impl Rule for CrossFunctionReentrancy {
    fn id(&self) -> &str {
        "PHOTON-REENTRANCY-002"
    }

    fn name(&self) -> &str {
        "Cross-Function Reentrancy"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::Reentrancy
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn description(&self) -> &str {
        "Detects potential cross-function reentrancy where one function makes an external call \
         and another function reads/writes shared state that could be manipulated during reentry."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // Find functions that make external calls and write state after them
        let mut vulnerable_funcs: Vec<(&str, Vec<String>, u32)> = Vec::new();

        for func in &ir.functions {
            if func.visibility == Visibility::Internal || func.visibility == Visibility::Private {
                continue;
            }

            let mut seen_call = false;
            let mut post_call_writes: Vec<String> = Vec::new();
            let mut call_line = 0u32;

            for stmt in &func.statements {
                match &stmt.kind {
                    IrStmtKind::ExternalCall { .. } => {
                        seen_call = true;
                        call_line = stmt.source_line;
                    }
                    IrStmtKind::StateWrite { variable } if seen_call => {
                        post_call_writes.push(variable.clone());
                    }
                    _ => {}
                }
            }

            if seen_call && !post_call_writes.is_empty() {
                vulnerable_funcs.push((&func.name, post_call_writes, call_line));
            }
        }

        // Check if any other public function reads the same state variables
        for (vuln_func, written_vars, call_line) in &vulnerable_funcs {
            for func in &ir.functions {
                if func.name == *vuln_func {
                    continue;
                }
                if func.visibility == Visibility::Internal || func.visibility == Visibility::Private
                {
                    continue;
                }

                // Check if this function reads any of the vulnerable state variables
                for stmt in &func.statements {
                    if let IrStmtKind::StateRead { variable } = &stmt.kind {
                        if written_vars.contains(variable) {
                            findings.push(RuleFinding {
                                line: *call_line,
                                column: None,
                                description: format!(
                                    "Potential cross-function reentrancy: `{}` makes an external call and writes `{}` \
                                     after it, while `{}` reads the same state variable. An attacker could re-enter \
                                     via `{}` during the external call.",
                                    vuln_func, variable, func.name, func.name
                                ),
                                remediation: format!(
                                    "Add a reentrancy guard to both `{}` and `{}`, or restructure to update \
                                     state before external calls.",
                                    vuln_func, func.name
                                ),
                                escalate_to_symbolic: true,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
