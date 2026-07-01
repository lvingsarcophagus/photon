//! Arithmetic vulnerability detection rules.
//!
//! PHOTON-ARITH-001: Unchecked arithmetic in Solidity < 0.8.0

use crate::{Rule, RuleFinding};
use photon_ir::ContractIR;
use photon_types::{Confidence, Severity, VulnClass};
use std::time::Duration;

/// PHOTON-ARITH-001: Detects contracts using Solidity < 0.8.0 without SafeMath.
///
/// Before Solidity 0.8.0, arithmetic operations silently overflow/underflow.
/// Contracts must use SafeMath or equivalent checked arithmetic.
pub struct UncheckedArithmetic;

impl Rule for UncheckedArithmetic {
    fn id(&self) -> &str {
        "PHOTON-ARITH-001"
    }

    fn name(&self) -> &str {
        "Unchecked Arithmetic"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn vuln_class(&self) -> VulnClass {
        VulnClass::Arithmetic
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn description(&self) -> &str {
        "Detects contracts compiled with Solidity < 0.8.0 that may be vulnerable to \
         integer overflow/underflow due to unchecked arithmetic operations."
    }

    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // Check if the source contains a pragma for Solidity < 0.8.0
        let source_lower = ir.source.to_lowercase();

        // Look for pragma solidity directives
        let uses_old_solidity = source_lower
            .lines()
            .any(|line| {
                let line = line.trim();
                if !line.starts_with("pragma solidity") {
                    return false;
                }
                // Check for versions < 0.8.0
                // Patterns like: ^0.7.x, ^0.6.x, >=0.4.x, etc.
                let old_version_patterns = [
                    "0.4.", "0.5.", "0.6.", "0.7.",
                    "^0.4.", "^0.5.", "^0.6.", "^0.7.",
                    ">=0.4.", ">=0.5.", ">=0.6.", ">=0.7.",
                ];
                old_version_patterns.iter().any(|p| line.contains(p))
            });

        if !uses_old_solidity {
            return findings;
        }

        // Strip comments to avoid false negatives if SafeMath is only mentioned in comments
        let cleaned_source = strip_comments(&source_lower);

        // Check if SafeMath is imported or used
        let uses_safemath = cleaned_source.contains("safemath")
            || cleaned_source.contains("using safemath");

        // Check for unchecked blocks (Solidity 0.8.0+)
        let has_unchecked = cleaned_source.contains("unchecked {");

        if !uses_safemath && !has_unchecked {
            findings.push(RuleFinding {
                line: 1, // Report at the pragma line
                column: None,
                description: format!(
                    "Contract `{}` uses Solidity < 0.8.0 without SafeMath. \
                     Arithmetic operations may silently overflow or underflow.",
                    ir.name
                ),
                remediation: "Upgrade to Solidity >= 0.8.0 for built-in overflow checking, \
                     or use OpenZeppelin's SafeMath library for all arithmetic operations."
                    .to_string(),
                escalate_to_symbolic: true,
            });
        }

        findings
    }
}

fn strip_comments(source: &str) -> String {
    let mut cleaned = String::new();
    let mut chars = source.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(c) = chars.next() {
        if in_line_comment {
            if c == '\n' || c == '\r' {
                in_line_comment = false;
                cleaned.push(c);
            }
        } else if in_block_comment {
            if c == '*' {
                if let Some('/') = chars.peek() {
                    chars.next();
                    in_block_comment = false;
                }
            }
        } else if c == '/' {
            if let Some('/') = chars.peek() {
                chars.next();
                in_line_comment = true;
            } else if let Some('*') = chars.peek() {
                chars.next();
                in_block_comment = true;
            } else {
                cleaned.push(c);
            }
        } else {
            cleaned.push(c);
        }
    }
    cleaned
}
