# hardhat-photon

Hardhat plugin to run the **Photon** smart contract vulnerability and security scanner directly inside your Hardhat project.

## Installation

Add this plugin dependency to your project:

```bash
npm install --save-dev ./path/to/photon-hardhat
```

Then, import the plugin in your `hardhat.config.js` or `hardhat.config.ts`:

### JavaScript (`hardhat.config.js`)
```javascript
require("hardhat-photon");
```

### TypeScript (`hardhat.config.ts`)
```typescript
import "hardhat-photon";
```

## Usage

Run the scanner on your project contracts:

```bash
npx hardhat photon
```

### Options

You can pass all standard Photon parameters as command-line arguments:

```bash
# Enable deep analysis engines (Z3 solver and invariant fuzzing)
npx hardhat photon --symbolic --fuzz

# Filter findings by minimum severity threshold
npx hardhat photon --severity-threshold high

# Add AI annotations (using Gemini)
npx hardhat photon --ai-provider gemini --ai-key $GEMINI_API_KEY --ai-summary

# Save findings report to a SARIF report file
npx hardhat photon --export-sarif report.sarif
```
