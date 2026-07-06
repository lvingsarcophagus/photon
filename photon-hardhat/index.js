const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

let task;
try {
  task = require("hardhat/config").task;
} catch (e) {
  // Safe fallback for local development where hardhat is in the project's node_modules
  const resolveFrom = require("module").createRequire(path.join(process.cwd(), "package.json"));
  task = resolveFrom("hardhat/config").task;
}

task("photon", "Runs Photon smart contract vulnerability scanner")
  .addOptionalParam("severityThreshold", "Minimum severity threshold (critical, high, medium, low, info)")
  .addFlag("symbolic", "Enable SMT symbolic analysis verification")
  .addFlag("fuzz", "Enable EVM invariant fuzzing engine")
  .addOptionalParam("aiProvider", "AI provider for explanations (gemini, groq, openai, anthropic)")
  .addOptionalParam("aiKey", "AI provider API key")
  .addFlag("aiSummary", "Generate and print an AI executive summary")
  .addOptionalParam("exportSarif", "Save results to a SARIF report file")
  .addOptionalParam("exportAttestation", "Save results to a Chainlink Functions attestation JSON")
  .setAction(async (taskArgs, hre) => {
    // Get the configured contracts sources directory from Hardhat HRE
    const contractsDir = hre.config.paths.sources;
    console.log(`[hardhat-photon] Target contracts directory: ${contractsDir}`);

    // Resolve the photon binary
    let photonPath = "";

    // 1. Check workspace target/release directories
    const exeName = process.platform === "win32" ? "photon.exe" : "photon";
    
    // Check multiple potential locations
    const possiblePaths = [
      path.join(__dirname, "..", "target", "release", exeName),
      path.join(__dirname, "..", "..", "target", "release", exeName),
      path.join(__dirname, "bin", exeName),
    ];

    for (const p of possiblePaths) {
      if (fs.existsSync(p)) {
        photonPath = p;
        break;
      }
    }

    // 2. Fallback: assume it is installed globally
    if (!photonPath) {
      photonPath = exeName;
    }

    console.log(`[hardhat-photon] Using binary: ${photonPath}`);

    // Build command-line arguments
    const args = ["scan", contractsDir];

    if (taskArgs.severityThreshold) {
      args.push("--severity-threshold", taskArgs.severityThreshold);
    }
    if (taskArgs.symbolic) {
      args.push("--symbolic");
    }
    if (taskArgs.fuzz) {
      args.push("--fuzz");
    }
    if (taskArgs.aiProvider) {
      args.push("--ai-provider", taskArgs.aiProvider);
    }
    if (taskArgs.aiKey) {
      args.push("--ai-key", taskArgs.aiKey);
    }
    if (taskArgs.aiSummary) {
      args.push("--ai-summary");
    }
    if (taskArgs.exportSarif) {
      args.push("--export-sarif", taskArgs.exportSarif);
    }
    if (taskArgs.exportAttestation) {
      args.push("--export-attestation", taskArgs.exportAttestation);
    }

    // Run the process
    return new Promise((resolve, reject) => {
      const child = spawn(photonPath, args, {
        stdio: "inherit",
        shell: true
      });

      child.on("close", (code) => {
        if (code === 0) {
          console.log("[hardhat-photon] Scan finished successfully with no critical findings.");
          resolve();
        } else {
          console.error(`[hardhat-photon] Scan failed or findings exceeded severity threshold (Exit code: ${code})`);
          reject(new Error(`Photon exited with code ${code}`));
        }
      });

      child.on("error", (err) => {
        console.error("[hardhat-photon] Failed to start Photon binary:", err.message);
        reject(err);
      });
    });
  });
