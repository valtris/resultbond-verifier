# Security Policy — ResultBond Verifier

## Supported versions

Use the latest stable GitHub Release and verify its wheel before installation.
Version 0.1.0 used a cryptography 46.x dependency constraint that matches
published security advisories. The security maintenance release 0.1.1 raises
the minimum to cryptography 50.0.2. Do not assume an unreleased version is live.

## Reporting vulnerabilities

Report privately through GitHub's **Report a vulnerability** / private
vulnerability reporting feature if available. If not, use the repository's
Security tab to request a private contact route; do not post exploit samples,
keys or user data in public issues. Do not email keys to strangers.

## Trust boundaries

- Verifier is local/offline only. It never runs code, signs receipts, publishes
  checks or transfers cryptocurrency.
- A valid Ed25519 signature by itself does not authorize PASS. A root-signed,
  time-valid, non-revoked evaluator keyset and identity match are required.
- The verifier has no trusted source of the newest keyset serial. Users must
  provide a minimum serial from a separately authenticated channel.
- A receipt proves what an authorized evaluator attested, NOT a direct
  observation of real-world completion or on-chain finality.
- Under a compromised trusted evaluator, a forged-looking but correctly
  signed statement remains a broader trust problem. The verifier additionally
  rejects internally contradictory PASS decisions as defense in depth.
- Do not reuse demo/test private keys or put secrets in receipts or MCP inputs.
- Production API/webhook attacks, penetration testing, and load testing
  require independent written scope and a safe test environment.
