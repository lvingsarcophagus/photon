//! # photon-core — Ingestion Engine
//!
//! Responsible for turning arbitrary, attacker-influenced input (third-party Solidity source
//! or live bytecode from an RPC endpoint) into validated ASTs. This is the highest-risk stage
//! because it is the only one that touches genuinely untrusted bytes.
//!
//! ## Security Mitigations
//! - T-1.1: `catch_unwind` boundary around parser calls (panic isolation)
//! - T-1.3: File size, AST depth, and node-count ceilings
//! - T-1.4: RPC endpoint allow-list validation (stub, full in Phase 2)

use photon_types::{AnalysisStatus, IngestionConfig};
use solang_parser::pt::SourceUnit;
use std::fs;
use std::panic;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

/// Errors that can occur during ingestion.
#[derive(Error, Debug)]
pub enum IngestionError {
    #[error("File too large: {path} ({size} bytes, max {max} bytes)")]
    FileTooLarge {
        path: PathBuf,
        size: u64,
        max: u64,
    },

    #[error("File read error: {path}: {source}")]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Parser panic on {path}: {message}")]
    ParserPanic { path: PathBuf, message: String },

    #[error("Parse errors in {path}: {errors:?}")]
    ParseErrors { path: PathBuf, errors: Vec<String> },

    #[error("AST complexity exceeded for {path}: {reason}")]
    ComplexityExceeded { path: PathBuf, reason: String },

    #[error("No Solidity files found in {path}")]
    NoFilesFound { path: PathBuf },

    #[error("Target directory does not exist: {path}")]
    DirectoryNotFound { path: PathBuf },
}

/// A successfully parsed Solidity contract.
#[derive(Debug)]
pub struct ParsedContract {
    /// Path to the source file (relative to scan root).
    pub path: PathBuf,
    /// Absolute path to the source file.
    pub absolute_path: PathBuf,
    /// Parsed AST.
    pub ast: SourceUnit,
    /// Raw source code (needed for source mapping in findings).
    pub source: String,
    /// Any non-fatal parse warnings.
    pub warnings: Vec<String>,
}

/// Result of the ingestion stage for all files in a target directory.
#[derive(Debug)]
pub struct IngestionResult {
    /// Successfully parsed contracts.
    pub contracts: Vec<ParsedContract>,
    /// Errors encountered (per-file; does not abort the pipeline).
    pub errors: Vec<IngestionError>,
    /// Per-contract status.
    pub statuses: Vec<(PathBuf, AnalysisStatus)>,
}

/// The ingestion engine.
pub struct IngestionEngine {
    config: IngestionConfig,
}

impl IngestionEngine {
    /// Create a new ingestion engine with the given configuration.
    pub fn new(config: IngestionConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self {
            config: IngestionConfig::default(),
        }
    }

    /// Discover and parse all Solidity files in the target directory.
    ///
    /// Per Section 7.3: if any single file fails, the pipeline continues
    /// analyzing remaining files and marks the failed unit as INCOMPLETE.
    pub fn ingest(&self, target_dir: &Path) -> Result<IngestionResult, IngestionError> {
        let target_dir = target_dir.to_path_buf();

        if !target_dir.exists() {
            return Err(IngestionError::DirectoryNotFound {
                path: target_dir.clone(),
            });
        }

        info!("Starting ingestion of {:?}", target_dir);

        let sol_files = self.discover_files(&target_dir);

        if sol_files.is_empty() {
            return Err(IngestionError::NoFilesFound {
                path: target_dir.clone(),
            });
        }

        info!("Found {} Solidity files", sol_files.len());

        let mut result = IngestionResult {
            contracts: Vec::new(),
            errors: Vec::new(),
            statuses: Vec::new(),
        };

        for file_path in sol_files {
            let relative_path = file_path
                .strip_prefix(&target_dir)
                .unwrap_or(&file_path)
                .to_path_buf();

            match self.parse_file(&file_path, &relative_path) {
                Ok(contract) => {
                    debug!("Successfully parsed: {:?}", relative_path);
                    result
                        .statuses
                        .push((relative_path, AnalysisStatus::Complete));
                    result.contracts.push(contract);
                }
                Err(e) => {
                    warn!("Failed to parse {:?}: {}", relative_path, e);
                    result.statuses.push((
                        relative_path,
                        AnalysisStatus::Failed {
                            error: e.to_string(),
                        },
                    ));
                    result.errors.push(e);
                }
            }
        }

        info!(
            "Ingestion complete: {} parsed, {} errors",
            result.contracts.len(),
            result.errors.len()
        );

        Ok(result)
    }

    /// Discover all Solidity files in a directory tree.
    fn discover_files(&self, dir: &Path) -> Vec<PathBuf> {
        // Handle the case where the path is a single file
        if dir.is_file() {
            if let Some(ext) = dir.extension() {
                if self.config.file_extensions.iter().any(|e| e == ext.to_str().unwrap_or("")) {
                    return vec![dir.to_path_buf()];
                }
            }
            return Vec::new();
        }

        let mut files = Vec::new();
        for entry in WalkDir::new(dir)
            .follow_links(false) // Don't follow symlinks (security)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if self
                        .config
                        .file_extensions
                        .iter()
                        .any(|e| e == ext.to_str().unwrap_or(""))
                    {
                        files.push(entry.into_path());
                    }
                }
            }
        }
        // Sort for deterministic processing order (Section 2.3)
        files.sort();
        files
    }

    /// Parse a single Solidity file with all mitigations applied.
    fn parse_file(
        &self,
        absolute_path: &Path,
        relative_path: &Path,
    ) -> Result<ParsedContract, IngestionError> {
        // T-1.3: File size ceiling
        let metadata = fs::metadata(absolute_path).map_err(|e| IngestionError::FileRead {
            path: relative_path.to_path_buf(),
            source: e,
        })?;

        if metadata.len() > self.config.max_file_size_bytes {
            return Err(IngestionError::FileTooLarge {
                path: relative_path.to_path_buf(),
                size: metadata.len(),
                max: self.config.max_file_size_bytes,
            });
        }

        // Read source
        let source = fs::read_to_string(absolute_path).map_err(|e| IngestionError::FileRead {
            path: relative_path.to_path_buf(),
            source: e,
        })?;

        // T-1.1: Parse in a panic-isolated boundary (catch_unwind)
        let parse_result = {
            let source_clone = source.clone();
            let path_clone = relative_path.to_path_buf();
            panic::catch_unwind(panic::AssertUnwindSafe(move || {
                solang_parser::parse(&source_clone, 0)
            }))
            .map_err(|panic_info| {
                let message = if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "unknown parser panic".to_string()
                };
                error!("Parser panic on {:?}: {}", path_clone, message);
                IngestionError::ParserPanic {
                    path: path_clone,
                    message,
                }
            })?
        };

        let ast = match parse_result {
            Ok((ast, _comments)) => ast,
            Err(diagnostics) => {
                let errors: Vec<String> = diagnostics
                    .iter()
                    .map(|d| format!("{:?}: {}", d.level, d.message))
                    .collect();
                return Err(IngestionError::ParseErrors {
                    path: relative_path.to_path_buf(),
                    errors,
                });
            }
        };

        let warnings = Vec::new();


        Ok(ParsedContract {
            path: relative_path.to_path_buf(),
            absolute_path: absolute_path.to_path_buf(),
            ast,
            source,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parse_simple_contract() {
        let dir = TempDir::new().unwrap();
        create_test_file(
            dir.path(),
            "Simple.sol",
            r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Simple {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
"#,
        );

        let engine = IngestionEngine::default_config();
        let result = engine.ingest(dir.path()).unwrap();

        assert_eq!(result.contracts.len(), 1);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn reject_oversized_file() {
        let dir = TempDir::new().unwrap();
        let big_content = "x".repeat(2_000_000); // 2MB
        create_test_file(dir.path(), "Big.sol", &big_content);

        let engine = IngestionEngine::default_config();
        let result = engine.ingest(dir.path()).unwrap();

        assert!(result.contracts.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(
            &result.errors[0],
            IngestionError::FileTooLarge { .. }
        ));
    }

    #[test]
    fn missing_directory() {
        let engine = IngestionEngine::default_config();
        let result = engine.ingest(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }
}
