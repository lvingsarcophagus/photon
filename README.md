<p align="center">
  <img src="photon-logo.jpg" alt="Photon Logo" width="250" height="250" style="border-radius: 50%; object-fit: cover;" />
</p>

# Photon

**Photon** is a Rust-native, multi-engine smart contract vulnerability assessment and security analysis framework. It integrates structural static analysis, SMT-based symbolic verification, and dynamic EVM invariant fuzzing into a unified, high-performance scanning pipeline.

Designed to be integrated directly into developer workflows (CLI) and CI/CD pipelines, Photon prioritizes speed, determinism, and detailed source-mapped diagnostics with built-in remediation advice.

---

## Key Features

- **Multi-Engine Pipeline**: Runs static linting, symbolic verification, and VM fuzzing stages sequentially.
- **Rayon-Parallel Engine**: Rayon work-stealing parallel static linter for lightning-fast analysis scaling sub-linearly with contract size.
- **CFG & DFG Graph IR**: Lowers Solidity ASTs into static single assignment (SSA) control flow and data flow graphs.
- **Deterministic Scanning**: Guarantees identical finding outputs across repeated runs for reproducible CI gating.
- **On-Chain Attestations**: Integrated Chainlink Functions support for verifiable security attestations on-chain.
- **Hard-Boundaried AI Layer** (Coming Soon): Optional AI post-processor (Anthropic Claude, OpenAI GPT, Groq Llama) for advisory remediation prose and false-positive triage without mutating or suppressing deterministic results.

---

## Architecture Overview

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
│  photon-ir   │  ◄── Lowering AST to SSA-form CFG / DFG
└──────┬───────┘
       │
       ▼
┌──────────────┐
│photon-static │  ◄── Parallel linter (CEI violations, Access Control, etc.)
└──────┬───────┘
       │
       ├───────────────────────────────┐
       ▼                               ▼
┌──────────────┐                ┌──────────────┐
│photon-symbolic│               │  photon-vm   │
│ (SMT Solver) │                │ (revm Fuzzer)│
└──────────────┘                └──────────────┘
```

---

## Project Status

**✅ Completed Phases (1-4):**
- **Phase 1**: Static Analysis Engine - Rayon-parallel structural pattern matching and rule evaluation
- **Phase 2**: Symbolic Execution - Z3 SMT solver integration for path verification
- **Phase 3**: Dynamic VM Fuzzing - revm-based property and invariant testing
- **Phase 4**: On-Chain Attestations - Chainlink Functions integration for verifiable security proofs

**🚧 In Development:**
- **Phase 5**: AI-Assisted Analysis Layer - Multi-provider post-processor for remediation guidance and false-positive triage (optional, non-deterministic layer that never affects core findings)

---

## Active Security Rules (Phase 1)

Photon currently implements 6 high-precision analysis rules:

1. **`PHOTON-REENTRANCY-001` (Critical)**: CEI Violation (Reentrancy) — Detects external calls preceding state updates in public/external functions.
2. **`PHOTON-REENTRANCY-002` (High)**: Cross-Function Reentrancy — Detects reentrancy vectors across multiple entry points sharing state variables.
3. **`PHOTON-ACCESS-001` (High)**: Missing Access Control — Detects public or external state-modifying functions without validation modifiers (e.g., `onlyOwner`).
4. **`PHOTON-ACCESS-002` (Critical)**: Unprotected `selfdestruct` / `delegatecall` — Detects critical control hijacking vectors.
5. **`PHOTON-ARITH-001` (High)**: Unchecked Arithmetic — Flags contracts using Solidity < 0.8.0 without importing or using SafeMath.
6. **`PHOTON-ORACLE-001` (Medium)**: Single-Source Oracle — Detects Chainlink / oracle invocations lacking staleness and heartbeat validation.

---

## Installation & Build

### Prerequisites
- **Rust Toolchain**: Rust 1.85.0+ installed via `rustup`.
- **Linker/Compiler**: GCC / MinGW toolchain (recommended for Windows build portability).

### Build from Source
```bash
# Clone the repository
git clone <your-repository-url>
cd photon

# Build the workspace using the GNU toolchain (Windows)
cargo +stable-x86_64-pc-windows-gnu build --release
```

---

## CLI Usage

Run scans against a directory of smart contracts:

```bash
# Scan a Solidity directory (default human-readable format)
./target/release/photon scan ./test-contracts

# Filter output by severity threshold (Critical/High/Medium/Low/Info)
./target/release/photon scan ./test-contracts --severity-threshold high

# Scan a Solidity directory (default human-readable format)
./target/release/photon scan ./test-contracts

# Filter output by severity threshold (Critical/High/Medium/Low/Info)
./target/release/photon scan ./test-contracts --severity-threshold high

# Export report in JSON format for CI pipelines
./target/release/photon scan ./test-contracts --format json

# Export Chainlink Functions attestation payload
./target/release/photon scan ./test-contracts --export-attestation attestation.json
```

---

## On-Chain Attestations (Chainlink Functions)

Photon supports on-chain security attestations via **Chainlink Functions**, allowing DeFi protocols and smart contracts to query if a contract has been scanned and verify its risk score.

- **Solidity Attestation Client (`test-contracts/PhotonAttestationConsumer.sol`)**: A consumer contract that requests and stores security attestations (`isScanned`, `riskScore`, `timestamp`).
- **Off-chain JavaScript Source (`photon-functions/photon-functions-source.js`)**: Executed by Chainlink decentralized oracle nodes (DON), this script queries the Photon scan registry API, decodes the results, and encodes them into a 64-byte payload for on-chain consumption.
- **Payload Export**: Use the `--export-attestation <path>` flag on the CLI to export JSON metadata for your deployed contracts.

### Other Commands
```bash
# List all registered rules
./target/release/photon rules

# Print version and engine status
./target/release/photon version
```

---

## Project Structure

- `photon-types`: Shared schemas, findings, severities, configs, and serialization.
- `photon-core`: Solidity ingestion, filesystem walk, AST parser, and panic-isolation layer.
- `photon-ir`: Graph builder lowering AST into CFGs, DFGs, and SSA representation.
- `photon-static`: The parallel linter engine and standard ruleset.
- `photon-symbolic`: Z3 SMT solver path verification engine.
- `photon-vm`: revm-hosted dynamic simulation and property-based invariant fuzzing engine.
- `photon-functions`: Off-chain Chainlink Functions Javascript source code.
- `photon-ai`: Multi-provider async post-processor interface (Phase 5 - In Development).
- `photon-cli`: The terminal CLI binary.

---

## License

MIT License. See LICENSE for details.
