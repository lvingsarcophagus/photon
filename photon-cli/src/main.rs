//! # photon-cli — Photon Command Line Interface
//!
//! Entry point for the Photon Web3 vulnerability assessment framework.
//! Supports scanning Solidity projects, listing rules, and outputting
//! findings in JSON, SARIF, or human-readable text format.
//!
//! ## Usage
//! ```
//! photon scan <target_dir> [--format json|sarif|text] [--severity-threshold critical|high|medium]
//! photon rules --list
//! photon version
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use photon_core::IngestionEngine;
use photon_ir::IrBuilder;
use photon_static::StaticEngine;
use photon_symbolic::SymbolicEngine;
use photon_types::{
    AnalysisStatus, ContractStatus, Engine, Finding, OutputFormat, ScanConfig, ScanReport,
    Severity, SymbolicConfig, VmConfig,
};
use photon_vm::VmEngine;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Photon — Web3 Vulnerability Assessment Framework
#[derive(Parser)]
#[command(
    name = "photon",
    version = "0.1.0",
    about = "Rust-native multi-engine smart contract security scanner",
    long_about = "Photon is a multi-engine (static + symbolic + dynamic) analysis framework \
                  for smart contract security. It detects reentrancy, access control, arithmetic, \
                  and oracle manipulation vulnerabilities with source-mapped diagnostics."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory of Solidity contracts for vulnerabilities
    Scan {
        /// Target directory containing .sol files
        target_dir: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: FormatArg,

        /// Minimum severity threshold for findings (exit code 1 if exceeded)
        #[arg(short, long, default_value = "info")]
        severity_threshold: SeverityArg,

        /// Enable symbolic analysis (Phase 2)
        #[arg(long, default_value = "false")]
        symbolic: bool,

        /// Enable VM fuzzing (Phase 3)
        #[arg(long, default_value = "false")]
        fuzz: bool,
    },

    /// List available analysis rules
    Rules,

    /// Show version information
    Version,
}

#[derive(Clone, ValueEnum)]
enum FormatArg {
    Json,
    Sarif,
    Text,
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Scan {
            target_dir,
            format,
            severity_threshold,
            symbolic,
            fuzz,
        } => {
            let exit_code = run_scan(target_dir, format, severity_threshold.into(), symbolic, fuzz);
            std::process::exit(exit_code);
        }
        Commands::Rules => {
            list_rules();
        }
        Commands::Version => {
            print_version();
        }
    }
}

fn run_scan(
    target_dir: PathBuf,
    format: FormatArg,
    threshold: Severity,
    enable_symbolic: bool,
    enable_fuzz: bool,
) -> i32 {
    let start = Instant::now();

    // Print banner
    print_banner();

    println!(
        "{}",
        format!("  Target: {}", target_dir.display()).cyan()
    );
    println!(
        "{}",
        format!("  Threshold: {}", threshold).cyan()
    );
    println!();

    // Canonicalize target path
    let target_dir = match target_dir.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            error!("Invalid target directory: {}", e);
            eprintln!("{}", format!("✗ Invalid target directory: {}", e).red());
            return 1;
        }
    };

    let mut report = ScanReport::new(target_dir.clone());
    report.engines_used.push(Engine::Static);

    // ═══════════════════════════════════════════════════════════
    // Stage 0: Ingestion
    // ═══════════════════════════════════════════════════════════
    println!("{}", "  ◆ Stage 0: Ingestion".yellow().bold());

    let engine = IngestionEngine::default_config();
    let ingestion_result = match engine.ingest(&target_dir) {
        Ok(result) => result,
        Err(e) => {
            error!("Ingestion failed: {}", e);
            eprintln!("{}", format!("  ✗ Ingestion failed: {}", e).red());
            return 1;
        }
    };

    println!(
        "    {} contracts parsed, {} errors",
        ingestion_result.contracts.len().to_string().green(),
        ingestion_result.errors.len().to_string().red()
    );

    if ingestion_result.contracts.is_empty() {
        eprintln!("{}", "  ✗ No contracts to analyze".red());
        return 1;
    }

    // ═══════════════════════════════════════════════════════════
    // Stage 1: Graph Transformation
    // ═══════════════════════════════════════════════════════════
    println!("{}", "  ◆ Stage 1: Graph Transformation".yellow().bold());

    let ir_builder = IrBuilder::new();
    let mut all_irs = Vec::new();

    for contract in &ingestion_result.contracts {
        match ir_builder.build(contract) {
            Ok(irs) => {
                for ir in irs {
                    println!(
                        "    {} — {} functions, {} state vars",
                        ir.name.green(),
                        ir.functions.len(),
                        ir.state_variables.len()
                    );
                    all_irs.push(ir);
                }
            }
            Err(e) => {
                eprintln!("    {} IR build failed: {}", contract.path.display(), e);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Stage 2: Static Analysis
    // ═══════════════════════════════════════════════════════════
    println!("{}", "  ◆ Stage 2: Static Analysis (Rayon)".yellow().bold());

    let static_engine = StaticEngine::with_default_rules();
    let mut findings = static_engine.analyze(&all_irs);

    println!(
        "    {} findings from {} rules",
        findings.len().to_string().green(),
        static_engine.list_rules().len()
    );

    // ═══════════════════════════════════════════════════════════
    // Stage 3: Symbolic Analysis (Phase 2 stub)
    // ═══════════════════════════════════════════════════════════
    if enable_symbolic {
        println!("{}", "  ◆ Stage 3: Symbolic Analysis (Z3)".yellow().bold());
        let symbolic = SymbolicEngine::new(SymbolicConfig {
            enabled: true,
            ..SymbolicConfig::default()
        });
        let sym_findings = symbolic.analyze(&all_irs, &findings);
        findings.extend(sym_findings);
        report.engines_used.push(Engine::Symbolic);
        println!("    {}", "Phase 2 stub — no symbolic analysis performed".dimmed());
    }

    // ═══════════════════════════════════════════════════════════
    // Stage 4: VM Fuzzing (Phase 3 stub)
    // ═══════════════════════════════════════════════════════════
    if enable_fuzz {
        println!("{}", "  ◆ Stage 4: VM Fuzzing (revm)".yellow().bold());
        let vm = VmEngine::new(VmConfig {
            enabled: true,
            ..VmConfig::default()
        });
        let vm_findings = vm.analyze(&all_irs);
        findings.extend(vm_findings);
        report.engines_used.push(Engine::Vm);
        println!("    {}", "Phase 3 stub — no fuzzing performed".dimmed());
    }

    // ═══════════════════════════════════════════════════════════
    // Aggregate Results
    // ═══════════════════════════════════════════════════════════
    report.findings = findings;
    report.sort_findings(); // T-3.1: deterministic sort
    report.contracts_analyzed = all_irs.len() as u32;
    report.duration_ms = start.elapsed().as_millis() as u64;
    report.completed_at = Some(chrono::Utc::now());

    // Build contract statuses
    for (path, status) in &ingestion_result.statuses {
        let finding_count = report
            .findings
            .iter()
            .filter(|f| f.file == *path)
            .count() as u32;
        report.contract_statuses.push(ContractStatus {
            file: path.clone(),
            status: status.clone(),
            finding_count,
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Output
    // ═══════════════════════════════════════════════════════════
    println!();

    match format {
        FormatArg::Json => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        FormatArg::Sarif => {
            // SARIF output (simplified)
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            println!("{}", "(Full SARIF format coming in a future release)".dimmed());
        }
        FormatArg::Text => {
            print_text_report(&report);
        }
    }

    // Exit code based on severity threshold
    if report.has_findings_above_threshold(&threshold) {
        1
    } else {
        0
    }
}

fn print_banner() {
    println!();
    println!(
        "{}",
        r#"
  ╔═══════════════════════════════════════════════════════╗
  ║                                                       ║
  ║   ██████╗ ██╗  ██╗ ██████╗ ████████╗ ██████╗ ███╗  ██╗║
  ║   ██╔══██╗██║  ██║██╔═══██╗╚══██╔══╝██╔═══██╗████╗ ██║║
  ║   ██████╔╝███████║██║   ██║   ██║   ██║   ██║██╔██╗██║║
  ║   ██╔═══╝ ██╔══██║██║   ██║   ██║   ██║   ██║██║╚████║║
  ║   ██║     ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚███║║
  ║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚══╝║
  ║                                                       ║
  ║   Web3 Vulnerability Assessment Framework  v0.1.0     ║
  ║   Static · Symbolic · Dynamic                         ║
  ╚═══════════════════════════════════════════════════════╝
"#
        .bright_cyan()
    );
}

fn print_text_report(report: &ScanReport) {
    println!("{}", "═══════════════════════════════════════════════════".bright_cyan());
    println!("{}", "  SCAN RESULTS".bright_white().bold());
    println!("{}", "═══════════════════════════════════════════════════".bright_cyan());
    println!();
    println!(
        "  Scan ID:    {}",
        report.scan_id.to_string().dimmed()
    );
    println!(
        "  Duration:   {}ms",
        report.duration_ms.to_string().green()
    );
    println!(
        "  Contracts:  {} analyzed, {} skipped",
        report.contracts_analyzed.to_string().green(),
        report.contracts_skipped.to_string().yellow()
    );
    println!(
        "  Engines:    {:?}",
        report
            .engines_used
            .iter()
            .map(|e| format!("{}", e))
            .collect::<Vec<_>>()
    );
    println!(
        "  Rubric:     v{}",
        report.rubric_version
    );
    println!();

    if report.findings.is_empty() {
        println!("{}", "  ✓ No vulnerabilities found!".green().bold());
        println!();
        return;
    }

    // Count by severity
    let counts = report.count_by_severity();
    println!("  {} Findings Summary:", "▸".bright_cyan());
    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = counts.get(sev).unwrap_or(&0);
        if *count > 0 {
            let label = match sev {
                Severity::Critical => format!("  CRITICAL: {}", count).red().bold(),
                Severity::High => format!("  HIGH:     {}", count).red(),
                Severity::Medium => format!("  MEDIUM:   {}", count).yellow(),
                Severity::Low => format!("  LOW:      {}", count).blue(),
                Severity::Info => format!("  INFO:     {}", count).dimmed(),
            };
            println!("    {}", label);
        }
    }
    println!();

    // Print each finding
    println!("{}", "───────────────────────────────────────────────────".bright_cyan());
    for (i, finding) in report.findings.iter().enumerate() {
        let sev_badge = match finding.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
            Severity::Info => "INFO".dimmed(),
        };

        println!(
            "  {} [{}] {} ({})",
            format!("#{}", i + 1).bright_white().bold(),
            sev_badge,
            finding.rule_id.bright_white(),
            format!("{}", finding.engine).dimmed()
        );
        println!(
            "  File: {}:{}",
            finding.file.display().to_string().cyan(),
            finding.line
        );
        println!("  {}", finding.description);
        println!(
            "  {} {}",
            "Fix:".green().bold(),
            finding.remediation
        );

        if let Some(status) = &finding.solver_status {
            let status_str = match status {
                photon_types::SolverStatus::Sat => "SAT (confirmed)".red().bold(),
                photon_types::SolverStatus::Unsat => "UNSAT (safe)".green(),
                photon_types::SolverStatus::Unknown => "UNKNOWN (inconclusive)".yellow().bold(),
            };
            println!("  Solver: {}", status_str);
        }

        println!(
            "{}",
            "───────────────────────────────────────────────────".bright_cyan()
        );
    }

    println!();
}

fn list_rules() {
    print_banner();
    println!("{}", "  Available Analysis Rules".bright_white().bold());
    println!("{}", "═══════════════════════════════════════════════════".bright_cyan());
    println!();

    let engine = StaticEngine::with_default_rules();
    for rule in engine.list_rules() {
        let sev_badge = match rule.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
            Severity::Info => "INFO".dimmed(),
        };

        println!(
            "  {} [{}] {}",
            rule.id.bright_white(),
            sev_badge,
            rule.name
        );
        println!("    {}", rule.description.dimmed());
        println!();
    }
}

fn print_version() {
    println!("photon {}", env!("CARGO_PKG_VERSION"));
    println!("Rust-native Web3 vulnerability assessment framework");
    println!("Engines: static (active), symbolic (Phase 2), vm (Phase 3)");
    println!("AI: Anthropic, OpenAI, Groq (Phase 4)");
}
