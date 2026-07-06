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
use photon_ai::AiPostProcessor;
use photon_core::IngestionEngine;
use photon_ir::IrBuilder;
use photon_static::StaticEngine;
use photon_symbolic::SymbolicEngine;
use photon_types::{
    ContractStatus, Engine, ScanReport,
    Severity, SymbolicConfig, VmConfig,
};
use photon_vm::VmEngine;
use std::path::PathBuf;
use std::time::Instant;
use tracing::error;
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
        /// Target directory containing .sol files
        target_dir: Option<PathBuf>,

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

        /// Export Chainlink Functions attestation payload to the specified JSON file path
        #[arg(long)]
        export_attestation: Option<PathBuf>,

        /// Export findings to a SARIF report file
        #[arg(long)]
        export_sarif: Option<PathBuf>,

        /// Enable Slither compatibility mode (detector name mapping & JSON schema)
        #[arg(long, default_value = "false")]
        slither_compat: bool,

        /// AI provider for annotations (groq, openai, anthropic)
        #[arg(long)]
        ai_provider: Option<String>,

        /// API key for the AI provider (or set PHOTON_AI_KEY / GROQ_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY)
        #[arg(long)]
        ai_key: Option<String>,

        /// Print an AI-generated executive summary at the end of the scan
        #[arg(long, default_value = "false")]
        ai_summary: bool,
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
            export_attestation,
            export_sarif,
            slither_compat,
            ai_provider,
            ai_key,
            ai_summary,
        } => {
            // Resolve AI key: flag > env var (provider-specific) > generic env var
            let resolved_ai_key = ai_key
                .or_else(|| std::env::var("PHOTON_AI_KEY").ok())
                .or_else(|| {
                    match ai_provider.as_deref() {
                        Some("groq") => std::env::var("GROQ_API_KEY").ok(),
                        Some("openai") => std::env::var("OPENAI_API_KEY").ok(),
                        Some("anthropic") => std::env::var("ANTHROPIC_API_KEY").ok(),
                        Some("gemini") => std::env::var("GEMINI_API_KEY").ok(),
                        _ => None,
                    }
                });

            let rt = tokio::runtime::Runtime::new().unwrap();
            let exit_code = rt.block_on(run_scan(
                target_dir,
                format,
                severity_threshold.into(),
                symbolic,
                fuzz,
                export_attestation,
                export_sarif,
                slither_compat,
                ai_provider,
                resolved_ai_key,
                ai_summary,
            ));
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

async fn run_scan(
    target_dir: Option<PathBuf>,
    format: FormatArg,
    threshold: Severity,
    enable_symbolic: bool,
    enable_fuzz: bool,
    export_attestation: Option<PathBuf>,
    export_sarif: Option<PathBuf>,
    slither_compat: bool,
    ai_provider: Option<String>,
    ai_key: Option<String>,
    ai_summary: bool,
) -> i32 {
    let start = Instant::now();

    // Print banner
    print_banner();

    // Project auto-detection if target_dir is omitted
    let resolved_target = match target_dir {
        Some(path) => path,
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            if cwd.join("foundry.toml").exists() || cwd.join("remappings.txt").exists() {
                println!("{}", "  Foundry project auto-detected! Defaulting to scan ./src".yellow());
                cwd.join("src")
            } else if cwd.join("hardhat.config.js").exists() || cwd.join("hardhat.config.ts").exists() {
                println!("{}", "  Hardhat project auto-detected! Defaulting to scan ./contracts".yellow());
                cwd.join("contracts")
            } else if cwd.join("contracts").exists() {
                println!("{}", "  Local contracts directory detected! Defaulting to scan ./contracts".yellow());
                cwd.join("contracts")
            } else if cwd.join("test-contracts").exists() {
                println!("{}", "  Local test-contracts directory detected! Defaulting to scan ./test-contracts".yellow());
                cwd.join("test-contracts")
            } else {
                println!("{}", "  No specific project config found. Defaulting to current directory (.)".yellow());
                cwd
            }
        }
    };

    println!(
        "{}",
        format!("  Target: {}", resolved_target.display()).cyan()
    );
    println!(
        "{}",
        format!("  Threshold: {}", threshold).cyan()
    );
    println!();

    // Canonicalize target path
    let target_dir = match resolved_target.canonicalize() {
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
    // Stage 3: Symbolic Analysis (Z3)
    // ═══════════════════════════════════════════════════════════
    if enable_symbolic {
        println!("{}", "  ◆ Stage 3: Symbolic Analysis (Z3)".yellow().bold());
        let symbolic = SymbolicEngine::new(SymbolicConfig {
            enabled: true,
            ..SymbolicConfig::default()
        });
        let sym_result = symbolic.analyze(&all_irs, &findings);

        if sym_result.z3_available {
            println!(
                "    Z3 solver: {} — {} queries ({} {}, {} {}, {} {})",
                "available".green(),
                sym_result.queries_total,
                sym_result.queries_sat.to_string().red().bold(),
                "SAT".red(),
                sym_result.queries_unsat.to_string().green(),
                "UNSAT".green(),
                sym_result.queries_unknown.to_string().yellow(),
                "UNKNOWN".yellow()
            );
        } else {
            println!(
                "    Z3 solver: {} — {} queries marked as UNKNOWN",
                "not found (degraded mode)".yellow(),
                sym_result.queries_total
            );
        }

        findings.extend(sym_result.findings);
        report.engines_used.push(Engine::Symbolic);
    }


    // ═══════════════════════════════════════════════════════════
    // Stage 4: VM Fuzzing (revm)
    // ═══════════════════════════════════════════════════════════
    if enable_fuzz {
        println!("{}", "  ◆ Stage 4: VM Fuzzing (revm)".yellow().bold());
        let vm = VmEngine::new(VmConfig {
            enabled: true,
            ..VmConfig::default()
        });
        let vm_findings = vm.analyze(&all_irs);
        println!(
            "    VM Fuzzer: completed, {} findings emitted",
            vm_findings.len().to_string().green()
        );
        findings.extend(vm_findings);
        report.engines_used.push(Engine::Vm);
    }

    // ═══════════════════════════════════════════════════════════
    // False Positive Suppression (.photon-ignore)
    // ═══════════════════════════════════════════════════════════
    let ignore_path = target_dir.join(".photon-ignore");
    if ignore_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&ignore_path) {
            let ignore_rules = photon_core::ignore::parse_ignore_file(&content);
            let before_count = findings.len();
            findings.retain(|finding| {
                !ignore_rules.iter().any(|rule| {
                    rule.matches(&finding.file, finding.line, &finding.rule_id, Some(&finding.description), None)
                })
            });
            let ignored_count = before_count - findings.len();
            if ignored_count > 0 {
                println!(
                    "    ✓ Suppressed {} false positives via .photon-ignore",
                    ignored_count.to_string().green()
                );
            }
        }
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

    if slither_compat {
        let slither_json = report.to_slither_compat();
        println!("{}", serde_json::to_string_pretty(&slither_json).unwrap());
    } else {
        match format {
            FormatArg::Json => {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
            FormatArg::Sarif => {
                let sarif_json = report.to_sarif();
                println!("{}", serde_json::to_string_pretty(&sarif_json).unwrap());
            }
            FormatArg::Text => {
                print_text_report(&report);
            }
        }
    }

    if let Some(sarif_path) = export_sarif {
        let sarif_json = report.to_sarif();
        if let Err(e) = std::fs::write(&sarif_path, serde_json::to_string_pretty(&sarif_json).unwrap()) {
            error!("Failed to write SARIF report: {}", e);
        } else {
            println!("  ✓ Exported SARIF report to {}", sarif_path.display());
        }
    }

    // Calculate risk score for Chainlink Functions attestation
    let mut risk_score: u8 = 0;
    for finding in &report.findings {
        let weight = match finding.severity {
            Severity::Critical => 40,
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 3,
            Severity::Info => 0,
        };
        risk_score = risk_score.saturating_add(weight);
    }
    if risk_score > 100 {
        risk_score = 100;
    }

    if let Some(att_path) = export_attestation {
        let att_payload = serde_json::json!({
            "is_scanned": true,
            "risk_score": risk_score,
            "timestamp": chrono::Utc::now().timestamp(),
            "findings_count": report.findings.len()
        });
        if let Err(e) = std::fs::write(&att_path, serde_json::to_string_pretty(&att_payload).unwrap()) {
            error!("Failed to write attestation payload: {}", e);
        } else {
            println!("  ✓ Exported Chainlink Functions attestation payload to {}", att_path.display());
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 6: AI Annotations (optional, non-deterministic)
    // ═══════════════════════════════════════════════════════════
    if let (Some(provider_name), Some(key)) = (ai_provider.as_deref(), ai_key.as_deref()) {
        if !report.findings.is_empty() {
            println!();
            println!(
                "{}",
                format!("  ◆ Stage 6: AI Annotations ({})", provider_name)
                    .yellow()
                    .bold()
            );

            let processor = AiPostProcessor::from_provider(provider_name, key);

            // Annotate findings (caps at 15, prioritises Critical/High)
            let annotations = processor.annotate(&report.findings).await;
            let annotated_count = annotations.len();

            // Attach annotations back to findings
            for (idx, annotation) in annotations {
                if let Some(finding) = report.findings.get_mut(idx) {
                    finding.ai_annotations = Some(annotation);
                }
            }

            println!(
                "    {} findings annotated via {}",
                annotated_count.to_string().green(),
                provider_name
            );

            // Print executive summary if requested
            if ai_summary {
                if let Some(summary) = processor.summarize(&report.findings).await {
                    println!();
                    println!("{}", "  ╔══════════════════════════════════════════════════╗".bright_cyan());
                    println!("{}", "  ║  AI Executive Summary                           ║".bright_cyan());
                    println!("{}", "  ╚══════════════════════════════════════════════════╝".bright_cyan());
                    for line in summary.lines() {
                        println!("  {}", line.dimmed());
                    }
                    println!();
                }
            }

            // Re-print text report with AI annotations if in text mode
            if matches!(format, FormatArg::Text) && !slither_compat {
                println!();
                print_text_report_with_ai(&report);
            }
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

fn print_text_report_with_ai(report: &ScanReport) {
    println!("{}", "═══════════════════════════════════════════════════".bright_cyan());
    println!("{}", "  SCAN RESULTS  (with AI annotations)".bright_white().bold());
    println!("{}", "═══════════════════════════════════════════════════".bright_cyan());
    println!();

    if report.findings.is_empty() {
        println!("{}", "  ✓ No vulnerabilities found!".green().bold());
        println!();
        return;
    }

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

        // AI annotation block
        if let Some(ai) = &finding.ai_annotations {
            println!();
            if let (Some(provider), Some(model)) = (&ai.provider, &ai.model) {
                println!(
                    "  {} {} ({})",
                    "💡 AI".bright_yellow().bold(),
                    provider.bright_yellow(),
                    model.dimmed()
                );
            } else {
                println!("  {}", "💡 AI Analysis".bright_yellow().bold());
            }
            if let Some(detail) = &ai.remediation_detail {
                for line in detail.lines() {
                    println!("  {}", line.dimmed());
                }
            }
            if let Some(fp) = ai.fp_confidence {
                let fp_label = if fp < 0.2 {
                    format!("False-positive confidence: {:.0}% (likely real)", fp * 100.0).red()
                } else if fp < 0.6 {
                    format!("False-positive confidence: {:.0}% (uncertain)", fp * 100.0).yellow()
                } else {
                    format!("False-positive confidence: {:.0}% (possible FP)", fp * 100.0).green()
                };
                println!("  {}", fp_label);
            }
            println!();
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
