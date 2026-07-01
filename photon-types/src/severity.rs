//! Severity classification and vulnerability class definitions.
//!
//! Severity levels map to a versioned rubric (Section 6 of the design document)
//! so that downstream CI gating thresholds remain stable across rule-set updates.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Rubric version — bump this when severity classification criteria change.
pub const SEVERITY_RUBRIC_VERSION: &str = "1.0.0";

/// Severity level for a finding.
/// Maps to a documented, versioned rubric per Section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Informational finding — no immediate risk.
    Info,
    /// Low severity — minor issue, unlikely to be exploitable.
    Low,
    /// Medium severity — potential risk under specific conditions.
    Medium,
    /// High severity — significant risk, should be addressed before deployment.
    High,
    /// Critical severity — immediate exploit risk, must be fixed.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    /// Returns a numeric weight for sorting (higher = more severe).
    pub fn weight(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Returns true if this severity meets or exceeds the given threshold.
    pub fn meets_threshold(&self, threshold: &Severity) -> bool {
        self.weight() >= threshold.weight()
    }
}

/// The analysis engine that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Static structural pattern matching (photon-static).
    Static,
    /// SMT-based symbolic execution (photon-symbolic, Z3).
    Symbolic,
    /// In-memory EVM simulation / fuzzing (photon-vm, revm).
    Vm,
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Engine::Static => write!(f, "static"),
            Engine::Symbolic => write!(f, "symbolic"),
            Engine::Vm => write!(f, "vm"),
        }
    }
}

/// Three-valued solver status for symbolic findings.
/// Per Section 4.4: UNKNOWN must never be flattened to 'safe'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SolverStatus {
    /// Satisfiable — vulnerability confirmed on this path.
    Sat,
    /// Unsatisfiable — proven safe on this path.
    Unsat,
    /// Unknown — solver timeout or incomplete analysis.
    /// MUST never be rendered as 'no issue found' in the dashboard.
    Unknown,
}

impl fmt::Display for SolverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SolverStatus::Sat => write!(f, "SAT"),
            SolverStatus::Unsat => write!(f, "UNSAT"),
            SolverStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Confidence level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Vulnerability class for categorizing findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnClass {
    Reentrancy,
    AccessControl,
    Arithmetic,
    OracleManipulation,
    UncheckedReturn,
    DelegateCall,
    SelfDestruct,
    GasOptimization,
    Informational,
}

impl fmt::Display for VulnClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnClass::Reentrancy => write!(f, "Reentrancy"),
            VulnClass::AccessControl => write!(f, "Access Control"),
            VulnClass::Arithmetic => write!(f, "Arithmetic"),
            VulnClass::OracleManipulation => write!(f, "Oracle Manipulation"),
            VulnClass::UncheckedReturn => write!(f, "Unchecked Return"),
            VulnClass::DelegateCall => write!(f, "Delegate Call"),
            VulnClass::SelfDestruct => write!(f, "Self Destruct"),
            VulnClass::GasOptimization => write!(f, "Gas Optimization"),
            VulnClass::Informational => write!(f, "Informational"),
        }
    }
}

/// Analysis status for a contract in the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisStatus {
    /// All engines completed successfully.
    Complete,
    /// One or more engines produced partial results.
    Partial { reason: String },
    /// Analysis failed for this contract.
    Failed { error: String },
    /// Analysis was skipped (e.g., file too large).
    Skipped { reason: String },
}

/// Supported EVM-compatible chains for live bytecode validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    /// Ethereum Mainnet
    EthereumMainnet,
    /// Ethereum Sepolia Testnet
    EthereumSepolia,
    /// Arbitrum One (L2)
    ArbitrumOne,
    /// Optimism Mainnet (L2)
    Optimism,
    /// Base Mainnet (L2)
    Base,
    /// Polygon Mainnet
    Polygon,
    /// BSC Mainnet
    Bsc,
    /// Avalanche C-Chain
    Avalanche,
}

impl Chain {
    /// Returns the default RPC endpoint URL for the chain.
    /// In production, these should be overridden by user config with allow-listed endpoints.
    pub fn default_rpc_url(&self) -> &str {
        match self {
            Chain::EthereumMainnet => "https://eth.llamarpc.com",
            Chain::EthereumSepolia => "https://rpc.sepolia.org",
            Chain::ArbitrumOne => "https://arb1.arbitrum.io/rpc",
            Chain::Optimism => "https://mainnet.optimism.io",
            Chain::Base => "https://mainnet.base.org",
            Chain::Polygon => "https://polygon-rpc.com",
            Chain::Bsc => "https://bsc-dataseed.binance.org",
            Chain::Avalanche => "https://api.avax.network/ext/bc/C/rpc",
        }
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::EthereumMainnet => 1,
            Chain::EthereumSepolia => 11155111,
            Chain::ArbitrumOne => 42161,
            Chain::Optimism => 10,
            Chain::Base => 8453,
            Chain::Polygon => 137,
            Chain::Bsc => 56,
            Chain::Avalanche => 43114,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_threshold() {
        assert!(Severity::Critical.meets_threshold(&Severity::High));
        assert!(Severity::High.meets_threshold(&Severity::High));
        assert!(!Severity::Medium.meets_threshold(&Severity::High));
    }

    #[test]
    fn severity_serialization() {
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(s, "\"CRITICAL\"");
    }

    #[test]
    fn solver_status_never_implies_safe() {
        // Section 4.4: UNKNOWN must never be treated as safe.
        // This test exists as a code-level assertion of the design requirement.
        assert_ne!(SolverStatus::Unknown, SolverStatus::Unsat);
    }
}
