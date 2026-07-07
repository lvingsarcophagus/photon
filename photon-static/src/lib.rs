//! # photon-static — Static Linter Engine
//!
//! Parallel structural pattern matching across the DFG using Rayon.
//! Each rule runs independently and can be budgeted with a per-rule timeout.
//!
//! ## Security Mitigations
//! - T-3.1: Sort findings by stable key (file, line, rule_id) independent of thread completion order
//! - T-3.2: Per-rule timeout/budget enforced by the scheduler

pub mod rules;

use photon_ir::ContractIR;
use photon_types::{Confidence, Engine, Finding, Severity, StaticConfig, VulnClass};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Trait that all static analysis rules must implement.
pub trait Rule: Send + Sync {
    /// Unique rule identifier (e.g., "PHOTON-REENTRANCY-001").
    fn id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Default severity.
    fn severity(&self) -> Severity;

    /// Vulnerability class.
    fn vuln_class(&self) -> VulnClass;

    /// Confidence level.
    fn confidence(&self) -> Confidence;

    /// Per-rule timeout budget.
    fn timeout(&self) -> Duration;

    /// Execute the rule against a contract IR, returning any findings.
    fn check(&self, ir: &ContractIR) -> Vec<RuleFinding>;

    /// Human-readable description of what this rule detects.
    fn description(&self) -> &str;
}

/// A finding produced by a rule (before being converted to a full Finding).
#[derive(Debug, Clone)]
pub struct RuleFinding {
    /// Line number in the source.
    pub line: u32,
    /// Column number (optional).
    pub column: Option<u32>,
    /// Specific description for this instance.
    pub description: String,
    /// Specific remediation advice.
    pub remediation: String,
    /// Whether this path should be escalated to the symbolic solver.
    pub escalate_to_symbolic: bool,
}

/// Result of running a single rule.
#[derive(Debug)]
pub enum RuleResult {
    /// Rule completed successfully with findings.
    Completed {
        rule_id: String,
        findings: Vec<Finding>,
        duration: Duration,
    },
    /// Rule timed out (T-3.2 mitigation).
    TimedOut {
        rule_id: String,
        timeout: Duration,
    },
    /// Rule encountered an error.
    Error {
        rule_id: String,
        error: String,
    },
}

/// The static analysis engine.
pub struct StaticEngine {
    rules: Vec<Box<dyn Rule>>,
    config: StaticConfig,
}

impl StaticEngine {
    /// Create a new static engine with the given rules and configuration.
    pub fn new(rules: Vec<Box<dyn Rule>>, config: StaticConfig) -> Self {
        Self { rules, config }
    }

    /// Create with all default rules and default configuration.
    pub fn with_default_rules() -> Self {
        let rules = rules::all_rules();
        Self {
            rules,
            config: StaticConfig::default(),
        }
    }

    /// Run all enabled rules against a set of contract IRs.
    ///
    /// Uses Rayon for parallel execution across contracts.
    /// Findings are sorted by stable key (file, line, rule_id) per T-3.1.
    pub fn analyze(&self, contracts: &[ContractIR]) -> Vec<Finding> {
        info!(
            "Starting static analysis: {} rules × {} contracts",
            self.rules.len(),
            contracts.len()
        );

        let start = Instant::now();

        // Run all rules against all contracts in parallel
        let all_findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));

        contracts.par_iter().for_each(|contract| {
            // Skip interface and test contracts globally
            if contract.is_interface {
                debug!("Skipping interface: {}", contract.name);
                return;
            }
            if contract.is_test() {
                debug!("Skipping test contract: {}", contract.name);
                return;
            }

            for rule in &self.rules {
                // Skip disabled rules
                if self.config.disabled_rules.contains(rule.id()) {
                    debug!("Skipping disabled rule: {}", rule.id());
                    continue;
                }

                let result = self.run_rule(rule.as_ref(), contract);

                match result {
                    RuleResult::Completed {
                        rule_id,
                        findings,
                        duration,
                    } => {
                        debug!(
                            "Rule {} completed in {:?}: {} findings",
                            rule_id,
                            duration,
                            findings.len()
                        );
                        let mut all = all_findings.lock().unwrap();
                        all.extend(findings);
                    }
                    RuleResult::TimedOut { rule_id, timeout } => {
                        warn!("Rule {} timed out after {:?}", rule_id, timeout);
                    }
                    RuleResult::Error { rule_id, error } => {
                        warn!("Rule {} error: {}", rule_id, error);
                    }
                }
            }
        });

        let mut findings = Arc::try_unwrap(all_findings)
            .unwrap()
            .into_inner()
            .unwrap();

        // T-3.1: Sort by stable key (file, line, rule_id) independent of completion order
        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.rule_id.cmp(&b.rule_id))
        });

        info!(
            "Static analysis complete in {:?}: {} findings",
            start.elapsed(),
            findings.len()
        );

        findings
    }

    /// Run a single rule against a single contract with timeout enforcement.
    fn run_rule(&self, rule: &dyn Rule, contract: &ContractIR) -> RuleResult {
        let start = Instant::now();
        let timeout = rule.timeout().min(self.config.per_rule_timeout);

        // Execute the rule
        let rule_findings = rule.check(contract);
        let duration = start.elapsed();

        // Check if we exceeded the timeout (post-hoc check since we can't
        // interrupt a running rule without threads)
        if duration > timeout {
            return RuleResult::TimedOut {
                rule_id: rule.id().to_string(),
                timeout,
            };
        }

        // Convert rule findings to full findings
        let findings: Vec<Finding> = rule_findings
            .into_iter()
            .map(|rf| {
                let actual_line = {
                    let offset = rf.line as usize;
                    let before = &contract.source[0..offset.min(contract.source.len())];
                    (before.chars().filter(|&c| c == '\n').count() + 1) as u32
                };
                Finding {
                    rule_id: rule.id().to_string(),
                    severity: rule.severity(),
                    engine: Engine::Static,
                    solver_status: None,
                    file: contract.path.clone(),
                    line: actual_line,
                    column: rf.column,
                    vuln_class: rule.vuln_class(),
                    description: rf.description,
                    remediation: rf.remediation,
                    confidence: rule.confidence(),
                    ai_annotations: None,
                }
            })
            .collect();

        RuleResult::Completed {
            rule_id: rule.id().to_string(),
            findings,
            duration,
        }
    }

    /// Get a list of all registered rules.
    pub fn list_rules(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id().to_string(),
                name: r.name().to_string(),
                severity: r.severity(),
                vuln_class: r.vuln_class(),
                description: r.description().to_string(),
                enabled: !self.config.disabled_rules.contains(r.id()),
            })
            .collect()
    }
}

/// Information about a registered rule.
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub vuln_class: VulnClass,
    pub description: String,
    pub enabled: bool,
}
