//! Z3 subprocess solver runner.
//!
//! Executes Z3 as an external process, piping SMT-LIB2 constraints via stdin
//! and parsing the three-valued result from stdout.
//!
//! This approach avoids native C++ linking (no MSVC build tools required) and
//! provides graceful degradation if Z3 is not installed.

use photon_types::SolverStatus;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors from the Z3 solver subprocess.
#[derive(Error, Debug)]
pub enum SolverError {
    #[error("Z3 binary not found at '{path}'. Install Z3 or set z3_path in config.")]
    Z3NotFound { path: String },

    #[error("Z3 process failed to start: {reason}")]
    ProcessSpawnFailed { reason: String },

    #[error("Z3 process timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    #[error("Z3 produced unexpected output: {output}")]
    UnexpectedOutput { output: String },

    #[error("Z3 process error: {stderr}")]
    ProcessError { stderr: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result of a single SMT query.
#[derive(Debug, Clone)]
pub struct SolverResult {
    /// The three-valued solver status.
    pub status: SolverStatus,
    /// Raw Z3 stdout (for debugging/logging).
    pub raw_output: String,
    /// Wall-clock time the solver took.
    pub duration: Duration,
}

/// The Z3 subprocess solver.
pub struct Z3Solver {
    /// Path to the Z3 binary.
    z3_path: PathBuf,
    /// Timeout per query.
    timeout: Duration,
    /// Whether Z3 is available on this system.
    available: bool,
}

impl Z3Solver {
    /// Create a new Z3 solver, detecting the Z3 binary.
    ///
    /// If `z3_path` is None, searches for "z3" in the system PATH.
    /// If Z3 is not found, the solver marks itself as unavailable and
    /// all queries will return `UNKNOWN` (graceful degradation).
    pub fn new(z3_path: Option<&Path>, timeout: Duration) -> Self {
        let path = z3_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("z3"));

        // Check if Z3 is available
        let available = check_z3_available(&path);

        if available {
            info!("Z3 solver found at: {}", path.display());
        } else {
            warn!(
                "Z3 solver NOT found at '{}'. Symbolic analysis will return UNKNOWN for all queries. \
                 Install Z3 (https://github.com/Z3Prover/z3/releases) or set z3_path in config.",
                path.display()
            );
        }

        Self {
            z3_path: path,
            timeout,
            available,
        }
    }

    /// Whether Z3 is available on this system.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Execute an SMT-LIB2 script against Z3 and return the result.
    ///
    /// Returns:
    /// - `SAT` if Z3 finds a satisfying assignment (vulnerability confirmed)
    /// - `UNSAT` if Z3 proves no solution exists (path proven safe)
    /// - `UNKNOWN` if Z3 times out, is unavailable, or returns unknown
    pub fn solve(&self, smt_script: &str) -> Result<SolverResult, SolverError> {
        if !self.available {
            return Ok(SolverResult {
                status: SolverStatus::Unknown,
                raw_output: "Z3 not available — graceful degradation".to_string(),
                duration: Duration::from_millis(0),
            });
        }

        let start = std::time::Instant::now();

        debug!("Sending SMT-LIB2 query to Z3 ({} bytes)", smt_script.len());

        // Spawn Z3 process with stdin pipe
        let mut child = Command::new(&self.z3_path)
            .arg("-in") // Read from stdin
            .arg("-smt2") // SMT-LIB2 format
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SolverError::ProcessSpawnFailed {
                reason: e.to_string(),
            })?;

        // Write SMT-LIB2 script to stdin
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(smt_script.as_bytes())?;
        }
        // Drop stdin to signal EOF
        drop(child.stdin.take());

        // Wait for result (wait_with_output consumes child)
        let output = child.wait_with_output().map_err(|e| {
            SolverError::ProcessSpawnFailed {
                reason: e.to_string(),
            }
        })?;

        let duration = start.elapsed();

        // Check timeout
        if duration > self.timeout {
            return Ok(SolverResult {
                status: SolverStatus::Unknown,
                raw_output: format!("Solver timed out after {:?}", duration),
                duration,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !stderr.is_empty() && !output.status.success() {
            debug!("Z3 stderr: {}", stderr);
        }

        // Parse the result
        let status = parse_z3_output(&stdout);

        debug!(
            "Z3 result: {:?} in {:?} (output: {})",
            status,
            duration,
            stdout.trim()
        );

        Ok(SolverResult {
            status,
            raw_output: stdout,
            duration,
        })
    }
}

/// Check if Z3 is available at the given path.
fn check_z3_available(z3_path: &Path) -> bool {
    match Command::new(z3_path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => {
            let version_str = String::from_utf8_lossy(&output.stdout);
            if version_str.contains("Z3") || version_str.contains("z3") {
                info!("Z3 version: {}", version_str.trim());
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Parse Z3's stdout to determine the solver status.
///
/// Z3 outputs one of: "sat", "unsat", "unknown", or "timeout"
/// UNKNOWN must never be flattened to safe (Section 4.4).
fn parse_z3_output(output: &str) -> SolverStatus {
    let trimmed = output.trim().to_lowercase();

    // Z3 may output multiple lines; we look for the first relevant one
    for line in trimmed.lines() {
        let line = line.trim();
        match line {
            "sat" => return SolverStatus::Sat,
            "unsat" => return SolverStatus::Unsat,
            "unknown" | "timeout" => return SolverStatus::Unknown,
            _ => continue,
        }
    }

    // If we can't parse the output, return UNKNOWN (safe default per Section 4.4)
    SolverStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sat() {
        assert_eq!(parse_z3_output("sat\n"), SolverStatus::Sat);
    }

    #[test]
    fn parse_unsat() {
        assert_eq!(parse_z3_output("unsat\n"), SolverStatus::Unsat);
    }

    #[test]
    fn parse_unknown() {
        assert_eq!(parse_z3_output("unknown\n"), SolverStatus::Unknown);
    }

    #[test]
    fn parse_timeout() {
        assert_eq!(parse_z3_output("timeout\n"), SolverStatus::Unknown);
    }

    #[test]
    fn parse_garbage_defaults_to_unknown() {
        // Section 4.4: unparseable output must never be treated as safe
        assert_eq!(
            parse_z3_output("some weird output"),
            SolverStatus::Unknown
        );
    }

    #[test]
    fn parse_multiline() {
        assert_eq!(
            parse_z3_output("(some warning)\nsat\n"),
            SolverStatus::Sat
        );
    }

    #[test]
    fn unavailable_solver_returns_unknown() {
        let solver = Z3Solver::new(Some(Path::new("/nonexistent/z3")), Duration::from_secs(5));
        assert!(!solver.is_available());
        let result = solver.solve("(check-sat)").unwrap();
        assert_eq!(result.status, SolverStatus::Unknown);
    }
}
