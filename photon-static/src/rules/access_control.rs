//! Access control vulnerability detection rules.
//!
//! PHOTON-ACCESS-001: Missing access control on sensitive functions
//! PHOTON-ACCESS-002: Unprotected selfdestruct / delegatecall

use crate::{Rule, RuleFinding};
use photon_ir::{ContractIR, IrStmtKind, Visibility};
use photon_types::{Confidence, Severity, VulnClass};
use std::time::Duration;

/// PHOTON-ACCESS-001: Detects public/external functions that perform sensitive
/// operations without access control modifiers.
pub struct MissingAccessControl;

impl Rule for MissingAccessControl {
    fn id(&self) -> &str {
        "PHOTON-ACCESS-001"
    }

    fn name(&self) -> &str {
        "Missing Access Control"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::AccessControl
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn description(&self) -> &str {
        "Detects public or external functions that write to sensitive state variables \
         without any access control modifiers (e.g., onlyOwner, onlyAdmin)."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // Common access control modifier keywords
        let access_modifiers = [
            "only",
            "admin",
            "owner",
            "auth",
            "role",
            "guard",
            "restricted",
            "governor",
            "pauser",
            "minter",
            "whennotpaused",
        ];

        for func in &ir.functions {
            // Only check public/external functions
            if func.visibility == Visibility::Internal || func.visibility == Visibility::Private {
                continue;
            }

            // Skip constructors and view-only functions
            if func.is_constructor || func.is_fallback {
                continue;
            }

            // Check if function has any access control modifier
            let has_access_control = func.modifiers.iter().any(|m| {
                let lower = m.to_lowercase();
                access_modifiers.iter().any(|am| lower.contains(am))
            });

            if has_access_control {
                continue;
            }

            // Check if function has a require(msg.sender == ...) guard
            let has_sender_check = func.statements.iter().any(|s| {
                matches!(&s.kind, IrStmtKind::Guard { .. })
            });

            // Check if function performs sensitive state writes
            let has_state_write = func.statements.iter().any(|s| {
                matches!(&s.kind, IrStmtKind::StateWrite { .. })
            });

            // If there's a state write without access control or sender check
            if has_state_write && !has_sender_check {
                let written_vars: Vec<String> = func
                    .statements
                    .iter()
                    .filter_map(|s| match &s.kind {
                        IrStmtKind::StateWrite { variable } => Some(variable.clone()),
                        _ => None,
                    })
                    .collect();

                let loc_line = match func.loc {
                    solang_parser::pt::Loc::File(_, start, _) => start as u32,
                    _ => 0,
                };

                findings.push(RuleFinding {
                    line: loc_line,
                    column: None,
                    description: format!(
                        "Function `{}` is {} and modifies state variables {:?} without \
                         access control. Any external account can call this function.",
                        func.name,
                        if func.visibility == Visibility::External {
                            "external"
                        } else {
                            "public"
                        },
                        written_vars,
                    ),
                    remediation: format!(
                        "Add an access control modifier (e.g., `onlyOwner`) to `{}`, \
                         or add a `require(msg.sender == owner)` check.",
                        func.name
                    ),
                    escalate_to_symbolic: false,
                });
            }
        }

        findings
    }
}

/// PHOTON-ACCESS-002: Detects unprotected selfdestruct or delegatecall.
pub struct UnprotectedSelfDestruct;

impl Rule for UnprotectedSelfDestruct {
    fn id(&self) -> &str {
        "PHOTON-ACCESS-002"
    }

    fn name(&self) -> &str {
        "Unprotected selfdestruct/delegatecall"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::SelfDestruct
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn description(&self) -> &str {
        "Detects selfdestruct or delegatecall operations in public/external functions \
         without access control. An attacker could destroy the contract or hijack execution."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for func in &ir.functions {
            if func.visibility == Visibility::Internal || func.visibility == Visibility::Private {
                continue;
            }

            // Check for selfdestruct
            for stmt in &func.statements {
                match &stmt.kind {
                    IrStmtKind::SelfDestruct => {
                        let has_guard = func
                            .statements
                            .iter()
                            .any(|s| matches!(&s.kind, IrStmtKind::Guard { .. }));

                        if !has_guard && func.modifiers.is_empty() {
                            findings.push(RuleFinding {
                                line: stmt.source_line,
                                column: None,
                                description: format!(
                                    "Unprotected `selfdestruct` in function `{}`. \
                                     Any external account can destroy this contract.",
                                    func.name
                                ),
                                remediation: format!(
                                    "Add an `onlyOwner` modifier to `{}` or remove the selfdestruct call.",
                                    func.name
                                ),
                                escalate_to_symbolic: false,
                            });
                        }
                    }
                    IrStmtKind::DelegateCall { target } => {
                        let has_guard = func
                            .statements
                            .iter()
                            .any(|s| matches!(&s.kind, IrStmtKind::Guard { .. }));

                        if !has_guard && func.modifiers.is_empty() {
                            findings.push(RuleFinding {
                                line: stmt.source_line,
                                column: None,
                                description: format!(
                                    "Unprotected `delegatecall` to `{}` in function `{}`. \
                                     An attacker could hijack the contract's execution context.",
                                    target, func.name
                                ),
                                remediation: format!(
                                    "Add access control to `{}` and validate the delegatecall target.",
                                    func.name
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
