<p align="center">
  <img src="assets/logo-circular.png" alt="Photon Logo" width="200" height="200" />
</p>

<h1 align="center">Photon</h1>

<p align="center">
  <b>Rust-native multi-engine smart contract security scanner</b><br/>
  Static · Symbolic · Dynamic · On-Chain Attestations
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/rules-50%2B-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/chainlink-functions-375BD2?style=flat-square&logo=chainlink" />
  <img src="https://img.shields.io/badge/SARIF-2.1.0-blueviolet?style=flat-square" />
</p>

---

**Photon** is a Rust-native, multi-engine smart contract vulnerability assessment framework. It integrates structural static analysis, SMT-based symbolic verification, dynamic EVM invariant fuzzing, and on-chain Chainlink attestations into a unified, high-performance scanning pipeline.

Designed for direct integration into developer workflows (CLI) and CI/CD pipelines, Photon prioritizes speed, determinism, and detailed source-mapped diagnostics with built-in remediation advice.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **50+ Security Rules** | Ported from Slither's catalog — reentrancy, access control, arithmetic, oracle manipulation, and more |
| **Multi-Engine Pipeline** | Static linting → Symbolic verification (Z3) → VM fuzzing (revm) |
| **Rayon-Parallel Engine** | Work-stealing parallel static linter scales sub-linearly with contract size |
| **CFG & DFG IR** | Lowers Solidity ASTs into SSA control flow and data flow graphs |
| **Taint Analysis** | BFS-based data-flow taint tracking from user-controlled sources to dangerous sinks |
| **SARIF Export** | Standard SARIF v2.1.0 output compatible with GitHub Actions and VS Code |
| **Slither Compatibility** | `--slither-compat` flag outputs Slither-schema JSON with mapped detector IDs |
| **False-Positive Suppression** | `.photon-ignore` file supports rule/file/function-level and date-expiring suppressions |
| **On-Chain Attestations** | Chainlink Functions integration — any DeFi protocol can query a contract's risk score on-chain |
| **Invariant Fuzzing** | Built-in ERC20/DeFi invariants + custom `/// @invariant` Solidity docstring annotations |
| **AI Layer** *(coming soon)* | Optional Anthropic/OpenAI/Groq post-processor for remediation guidance |

---

## Architecture

Photon is built as a strict, unidirectional pipeline:

```
[Solidity Source]
      │
      ▼
┌──────────────┐
│ photon-core  │  ◄── Ingestion & Panic-Isolated Parsing (solang-parser)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  photon-ir   │  ◄── AST → SSA-form CFG / DFG + Taint Analysis
└──────┬───────┘
       │
       ▼
┌──────────────┐
│photon-static │  ◄── Rayon-parallel linter (50+ rules)
└──────┬───────┘
       │
       ├──────────────────────────────┐
       ▼                              ▼
┌──────────────┐               ┌──────────────┐
│photon-symbolic│              │  photon-vm   │
│  (Z3 / SMT)  │               │(revm Fuzzer) │
└──────────────┘               └──────────────┘
       │                              │
       └──────────────┬───────────────┘
                      ▼
              ┌──────────────┐
              │  photon-cli  │  ◄── Aggregation, filtering, output
              └──────────────┘
                      │
          ┌───────────┼──────────────┐
          ▼           ▼              ▼
       Text/JSON    SARIF      Chainlink
       Report      Report     Attestation
```

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 1** | Static Analysis Engine — 50+ Rayon-parallel rules | ✅ Complete |
| **Phase 2** | Symbolic Execution — Z3 SMT solver path verification | ✅ Complete |
| **Phase 3** | Dynamic VM Fuzzing — revm-based invariant fuzzer | ✅ Complete |
| **Phase 4** | On-Chain Attestations — Chainlink Functions integration | ✅ Complete |
| **Phase 5** | Advanced CLI — SARIF, Slither compat, taint analysis, `.photon-ignore` | ✅ Complete |
| **Phase 6** | AI-Assisted Analysis — Multi-provider remediation post-processor | 🚧 In Development |

---

## Security Rules (50+)

### Core Rules
| Rule ID | Severity | Description |
|---------|----------|-------------|
| `PHOTON-REENTRANCY-001` | 🔴 Critical | CEI violation — external call precedes state update |
| `PHOTON-REENTRANCY-002` | 🔴 Critical | Cross-function reentrancy via shared state variables |
| `PHOTON-ACCESS-001` | 🟠 High | Missing access control on state-modifying public functions |
| `PHOTON-ACCESS-002` | 🔴 Critical | Unprotected `selfdestruct` / `delegatecall` |
| `PHOTON-ARITH-001` | 🟠 High | Unchecked arithmetic on Solidity < 0.8.0 |
| `PHOTON-ORACLE-001` | 🟡 Medium | Single-source oracle without staleness check |

### Extended Rules (Slither-Ported)
`tx-origin-auth` · `shadow-variable` · `uninitialized-state` · `divide-before-multiply` · `block-timestamp` · `calls-in-loop` · `dangerous-delegatecall` · `low-level-call` · `selfdestruct` · `floating-pragma` · `arbitrary-send-eth` · `oracle-manipulation` · `locked-ether` · `incorrect-equality` · `constant-function-changing-state` · and 35+ more.

---

## Installation & Build

### Prerequisites
- **Rust**: 1.86.0+ via `rustup` (`rustup update`)
- **Windows**: GNU toolchain — `rustup target add x86_64-pc-windows-gnu`

### Build from Source
```bash
git clone <your-repository-url>
cd photon

# Build optimized release binary
cargo +stable-x86_64-pc-windows-gnu build --release
```

The binary is placed at `./target/release/photon.exe`.

---

## CLI Usage

### Basic Scan
```bash
# Scan a directory of Solidity files
./target/release/photon scan ./contracts

# Filter by minimum severity
./target/release/photon scan ./contracts --severity-threshold high

# Enable symbolic analysis (Z3)
./target/release/photon scan ./contracts --symbolic

# Enable VM fuzzing (revm)
./target/release/photon scan ./contracts --fuzz
```

### Output Formats
```bash
# JSON output (for CI pipelines)
./target/release/photon scan ./contracts --format json

# SARIF output (for GitHub / VS Code)
./target/release/photon scan ./contracts --format sarif

# Slither-compatible JSON (for tooling that consumes Slither output)
./target/release/photon scan ./contracts --slither-compat
```

### Export Reports
```bash
# Export SARIF report to a file
./target/release/photon scan ./contracts --export-sarif report.sarif

# Export Chainlink Functions attestation payload
./target/release/photon scan ./contracts --export-attestation attestation.json
```

### Utility Commands
```bash
# List all registered analysis rules
./target/release/photon rules

# Print version information
./target/release/photon version
```

---

## Developer Integrations (Foundry & Hardhat)

### 1. Zero-Config Project Scanning
If you omit the target path, Photon will automatically scan your workspace:
```bash
# Automatically detects foundry.toml/remappings.txt -> scans `./src`
# Automatically detects hardhat.config.js/ts -> scans `./contracts`
# Automatically detects `./contracts` or `./test-contracts` folders
./target/release/photon scan
```

### 2. Hardhat Plugin
Run Photon directly inside your Hardhat task suite:
```bash
# Add the local plugin to your package.json devDependencies:
# "hardhat-photon": "file:./photon-hardhat"

# Run scan using Hardhat task:
npx hardhat photon --symbolic --fuzz
```

---

## False Positive Suppression (`.photon-ignore`)

Place a `.photon-ignore` file in your project root to suppress known false positives:

```bash
# Rule-level (suppresses this rule across all files)
PHOTON-SECURITY-007

# File-level (suppresses rule in one file)
reentrancy.sol:PHOTON-SECURITY-007

# Function-level (suppresses rule only in a specific function)
arithmetic.sol:mint:PHOTON-ACCESS-001

# Date-expiring (automatically re-enables after the date)
reentrancy.sol:PHOTON-SECURITY-007:2026-12-31
```

---

## On-Chain Attestations (Chainlink Functions)

Photon supports **verifiable security attestations on-chain** via Chainlink Functions, so any DeFi protocol can trustlessly query a contract's security status before interacting with it.

### How It Works

```
Photon CLI  ──►  Scan Results  ──►  Your Registry API
                                           │
                                   Chainlink DON fetches
                                           │
                                           ▼
                              PhotonAttestationConsumer.sol
                              attestations[0xContract] = {
                                isScanned: true,
                                riskScore: 72,
                                timestamp: ...
                              }
```

### DeFi Integration Example
```solidity
// A lending protocol gating collateral acceptance:
Attestation memory att = photonOracle.attestations[newTokenAddress];
require(att.isScanned, "Contract not scanned");
require(att.riskScore < 30, "Risk score too high");
require(block.timestamp - att.timestamp < 30 days, "Scan expired");
```

### Files
- **[`test-contracts/PhotonAttestationConsumer.sol`](test-contracts/PhotonAttestationConsumer.sol)** — Solidity consumer contract (requests + stores attestations)
- **[`photon-functions/photon-functions-source.js`](photon-functions/photon-functions-source.js)** — JavaScript source executed by Chainlink DON nodes

---

## Invariant Fuzzing

Photon's VM fuzzer checks built-in invariants and supports custom `@invariant` annotations in Solidity docstrings:

```solidity
contract MyToken {
    /// @invariant balance >= 0
    /// @invariant totalSupply == sum(balances)
    /// @invariant owner != address(0)
    mapping(address => uint256) public balances;
}
```

Built-in invariant categories:
- **ERC20**: Balance non-negativity, total supply consistency
- **DeFi**: Constant product AMM (`x * y = k`)
- **Security**: Owner address validation, storage slot integrity

---

## Project Structure

```
photon/
├── photon-cli/        # CLI binary — entry point, argument parsing, output
├── photon-core/       # Solidity ingestion, filesystem walk, .photon-ignore parser
├── photon-ir/         # AST → CFG/DFG/SSA lowering + taint analysis engine
├── photon-static/     # Rayon-parallel rule engine (50+ detectors)
├── photon-symbolic/   # Z3 SMT solver integration for path verification
├── photon-vm/         # revm-based invariant fuzzer + @invariant parser
├── photon-types/      # Shared schemas: findings, severities, SARIF, Slither compat
├── photon-ai/         # Multi-provider AI post-processor (Phase 6)
├── photon-functions/  # Chainlink Functions JS source code
├── test-contracts/    # Sample vulnerable Solidity contracts for testing
└── assets/            # Logos and branding assets
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
