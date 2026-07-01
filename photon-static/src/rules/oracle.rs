//! Oracle manipulation vulnerability detection rules.
//!
//! PHOTON-ORACLE-001: Single-source price oracle without staleness check

use crate::{Rule, RuleFinding};
use photon_ir::ContractIR;
use photon_types::{Confidence, Severity, VulnClass};
use std::time::Duration;

/// PHOTON-ORACLE-001: Detects single-source price oracle usage without staleness checks.
///
/// Contracts that rely on a single price oracle without checking for stale data
/// are vulnerable to oracle manipulation attacks.
pub struct SingleSourceOracle;

impl Rule for SingleSourceOracle {
    fn id(&self) -> &str {
        "PHOTON-ORACLE-001"
    }

    fn name(&self) -> &str {
        "Single-Source Oracle"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::OracleManipulation
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn description(&self) -> &str {
        "Detects contracts that use a single price oracle (e.g., Chainlink, Uniswap TWAP) \
         without checking for stale or manipulated data."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // Known oracle interfaces
        let oracle_patterns = [
            "latestRoundData",
            "latestAnswer",
            "getAmountsOut",
            "getReserves",
            "slot0",
            "observe",
            "consult",
        ];

        // Staleness check patterns
        let staleness_checks = [
            "updatedAt",
            "timestamp",
            "answeredInRound",
            "roundId",
            "block.timestamp",
            "staleness",
            "heartbeat",
            "MAX_DELAY",
            "maxDelay",
        ];

        for func in &ir.functions {
            let func_source = match func.loc {
                solang_parser::pt::Loc::File(_, start, end) => {
                    if start < end && end <= ir.source.len() {
                        &ir.source[start..end]
                    } else {
                        &ir.source
                    }
                }
                _ => &ir.source,
            };

            for pattern in &oracle_patterns {
                if func_source.contains(pattern) {
                    // Check if there's a staleness check in this function's source
                    let has_staleness = staleness_checks.iter().any(|check| func_source.contains(check));

                    if !has_staleness {
                        // Estimate line number
                        let line = match func.loc {
                            solang_parser::pt::Loc::File(_, start, _) => {
                                ir.source[..start].lines().count() as u32 + 1
                            }
                            _ => 1,
                        };

                        findings.push(RuleFinding {
                            line,
                            column: None,
                            description: format!(
                                "Oracle call `{}` in function `{}` of contract `{}` without staleness check. \
                                 The price data may be stale or manipulated.",
                                pattern, func.name, ir.name
                            ),
                            remediation: format!(
                                "Add a staleness check for `{}` in function `{}`: verify the `updatedAt` timestamp \
                                 is within an acceptable range, and check that `answeredInRound >= roundId` \
                                 (for Chainlink). Consider using multiple oracle sources for critical price data.",
                                pattern, func.name
                            ),
                            escalate_to_symbolic: false,
                        });
                    }
                }
            }
        }

        findings
    }
}
