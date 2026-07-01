//! Pipeline configuration structures.
//!
//! Defines scan configuration, timeout budgets, RPC allow-lists,
//! and AI provider settings.

use crate::severity::{Chain, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

/// Top-level scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Root directory to scan (must be canonicalized and validated).
    pub target_dir: PathBuf,

    /// Minimum severity to include in output.
    pub severity_threshold: Severity,

    /// Output format for findings.
    pub output_format: OutputFormat,

    /// Ingestion engine configuration.
    pub ingestion: IngestionConfig,

    /// Static linter configuration.
    pub static_engine: StaticConfig,

    /// Symbolic solver configuration.
    pub symbolic_engine: SymbolicConfig,

    /// VM fuzzer configuration.
    pub vm_engine: VmConfig,

    /// AI post-processing configuration.
    pub ai: AiConfig,

    /// Resilience configuration (Section 7.5).
    pub resilience: ResilienceConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_dir: PathBuf::new(),
            severity_threshold: Severity::Info,
            output_format: OutputFormat::Json,
            ingestion: IngestionConfig::default(),
            static_engine: StaticConfig::default(),
            symbolic_engine: SymbolicConfig::default(),
            vm_engine: VmConfig::default(),
            ai: AiConfig::default(),
            resilience: ResilienceConfig::default(),
        }
    }
}

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON format (default).
    Json,
    /// SARIF format for GitHub Code Scanning integration.
    Sarif,
    /// Human-readable text format.
    Text,
}

/// Ingestion engine configuration (Section 4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionConfig {
    /// Maximum file size in bytes (T-1.3 mitigation).
    pub max_file_size_bytes: u64,

    /// Maximum AST depth before rejecting a file (T-1.3 mitigation).
    pub max_ast_depth: u32,

    /// Maximum AST node count before rejecting a file (T-1.3 mitigation).
    pub max_ast_node_count: u32,

    /// RPC endpoints allow-list (T-1.4 mitigation).
    /// Only these endpoints may be used for live bytecode fetching.
    pub rpc_allow_list: HashSet<String>,

    /// Target chain for live bytecode validation.
    pub chain: Option<Chain>,

    /// File extensions to scan.
    pub file_extensions: Vec<String>,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 1_048_576, // 1 MB
            max_ast_depth: 256,
            max_ast_node_count: 100_000,
            rpc_allow_list: HashSet::new(),
            chain: None,
            file_extensions: vec!["sol".to_string()],
        }
    }
}

/// Static linter configuration (Section 4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    /// Whether static analysis is enabled.
    pub enabled: bool,

    /// Per-rule timeout (T-3.2 mitigation).
    #[serde(with = "duration_serde")]
    pub per_rule_timeout: Duration,

    /// Rules to disable (by rule ID).
    pub disabled_rules: HashSet<String>,

    /// Number of Rayon threads (0 = auto-detect).
    pub thread_count: usize,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_rule_timeout: Duration::from_secs(10),
            disabled_rules: HashSet::new(),
            thread_count: 0,
        }
    }
}

/// Symbolic solver configuration (Section 4.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicConfig {
    /// Whether symbolic analysis is enabled.
    pub enabled: bool,

    /// Maximum solver wall-clock time per function (Section 4.4 mitigation).
    #[serde(with = "duration_serde")]
    pub solver_timeout: Duration,

    /// Maximum symbolic exploration depth.
    pub max_depth: u32,

    /// Only run on paths flagged by static analysis (gated execution).
    pub gated_only: bool,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled in Phase 1 (stub)
            solver_timeout: Duration::from_secs(30),
            max_depth: 64,
            gated_only: true,
        }
    }
}

/// VM fuzzer configuration (Section 4.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Whether VM fuzzing is enabled.
    pub enabled: bool,

    /// Maximum fuzz iterations per contract.
    pub max_iterations: u32,

    /// EVM hard-fork to pin (T-5.1 mitigation).
    pub evm_fork: String,

    /// Fuzzing timeout per contract.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled in Phase 1 (stub)
            max_iterations: 10_000,
            evm_fork: "cancun".to_string(),
            timeout: Duration::from_secs(60),
        }
    }
}

/// AI post-processing configuration (Section 8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Whether AI post-processing is enabled.
    pub enabled: bool,

    /// AI provider configurations.
    pub providers: Vec<AiProviderConfig>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default until explicitly configured
            providers: Vec::new(),
        }
    }
}

/// Configuration for a single AI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderConfig {
    /// Provider name (e.g., "anthropic", "openai", "groq").
    pub name: String,

    /// API key (held server-side, never exposed to webview — T-7.4 mitigation).
    pub api_key: String,

    /// Model identifier.
    pub model: String,

    /// Request timeout.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,

    /// Tasks this provider handles.
    pub tasks: Vec<AiTask>,
}

/// AI task types (Section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiTask {
    /// Remediation explanation (requires high-reasoning model).
    RemediationExplanation,
    /// False-positive triage (advisory only, requires high-reasoning model).
    FalsePositiveTriage,
    /// Report summarization (fast/low-cost model).
    ReportSummarization,
    /// Contract intent classification (fast/low-cost model).
    ContractClassification,
}

/// Resilience configuration (Section 7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    /// Maximum retries for transient failures.
    pub max_retries: u32,

    /// Base backoff duration for exponential backoff.
    #[serde(with = "duration_serde")]
    pub base_backoff: Duration,

    /// Circuit breaker failure threshold (trip after N failures).
    pub circuit_breaker_threshold: u32,

    /// Circuit breaker reset timeout.
    #[serde(with = "duration_serde")]
    pub circuit_breaker_reset: Duration,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_backoff: Duration::from_millis(500),
            circuit_breaker_threshold: 5,
            circuit_breaker_reset: Duration::from_secs(60),
        }
    }
}

/// Serde support for Duration as milliseconds.
mod duration_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
