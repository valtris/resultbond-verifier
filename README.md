# ResultBond Verifier — public-client staging

**Read-only cryptographic verifier** for signed ResultBond Proof Receipts.
Not the ResultBond Judge: this package has no evaluator, signing, Linux runner,
hidden tests, escrow, GitHub API or hosted service.

## Installation

With Python 3.12 or newer, activate a virtual environment and install the published v0.1.1 GitHub Release wheel. The digest pins the downloaded file. The MCP extra includes the local stdio server.

    python -m pip install "resultbond-verifier[mcp] @ https://github.com/valtris/resultbond-verifier/releases/download/v0.1.1/resultbond_verifier-0.1.1-py3-none-any.whl#sha256=446aa98af0cc97807e4530d7cd9c34e90d8c60120a3f6a9af2d19513bd2e5ffd"

From a trusted local checkout for development:

    python3.12 -m venv .venv
    .venv/bin/python -m pip install -e ".[mcp]"

Check a locally saved receipt and a root-signed keyset:

    resultbond-verify receipt.json --keyset resultbond-keys.json

If you have a previously trusted minimum keyset serial, add `--min-serial` with that value. Keep the highest trusted serial when you update. The signed example receipts on the website use demonstration signers and report `UNTRUSTED`.

Exit code 0 means a trusted signed outcome (it may be FAIL or INCONCLUSIVE),
1 = signature valid but signer untrusted, 2 = invalid or unreadable evidence.
Only the JSON field **certified_pass** indicates a trusted PASS.

For MCP clients, start the installed command as a local stdio subprocess:

    {
      "mcpServers": {
        "resultbond": {
          "command": "/absolute/path/to/resultbond-verifier-mcp"
        }
      }
    }

Tools: verify_receipt_tool(receipt_json, keyset_json?, minimum_keyset_serial=1),
and resultbond_capabilities(). Neither can alter files or make network calls.

The offline root public key is built in. A trusted outcome requires a valid
receipt signature, valid root-signed keyset, evaluator role and identity match,
time validity, no revocation and a serial >= the caller's trusted minimum.
The verifier cannot know the highest serial or independently confirm a
real-world result. Keep your highest observed serial in trusted storage.

Demo receipts with known public demo signing keys never certify PASS.

**License:** Apache-2.0 applies to this standalone verifier package only.
Private ResultBond Core and the Linux evaluator are not included or licensed
under Apache-2.0. Publication requires successful CI, audited wheel and
trusted publisher identity; no hosted MCP endpoint is enabled.
