// Chainlink Functions JavaScript Source Code
// Decodes and returns Photon Security Scan Attestations for a contract address.

// Read the target contract address from arguments
const targetContract = args[0];
if (!targetContract) {
  throw new Error("Missing target contract address argument");
}

// Format API URL
const url = `https://api.photon-security.com/v1/scans/${targetContract.toLowerCase()}`;

let riskScore = 0;
let isScanned = false;

try {
  const response = await Functions.makeHttpRequest({
    url: url,
    timeout: 5000,
    headers: {
      "Content-Type": "application/json",
    }
  });

  if (!response.error && response.status === 200 && response.data) {
    riskScore = response.data.risk_score || 0;
    isScanned = response.data.is_scanned || false;
  }
} catch (e) {
  // Graceful degradation: treat errors/timeouts as unscanned
  riskScore = 0;
  isScanned = false;
}

// Encode the result as a 64-byte buffer (Solidity abi.encode compatible)
// First 32 bytes: uint256(riskScore)
// Second 32 bytes: uint256(isScanned ? 1 : 0)
const buffer = Buffer.alloc(64);

// Write riskScore (uint256) at offset 0 (ends at byte 31)
buffer.writeUInt32BE(riskScore, 28);

// Write isScanned (uint256) at offset 32 (ends at byte 63)
buffer.writeUInt32BE(isScanned ? 1 : 0, 60);

return buffer;
