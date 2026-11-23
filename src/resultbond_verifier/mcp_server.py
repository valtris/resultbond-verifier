# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ResultBond contributors
"""Local, read-only Model Context Protocol interface (optional dependency)."""

from __future__ import annotations

import json
import sys
from typing import Any

from .verifier import verify_receipt


def describe_capabilities() -> dict[str, Any]:
    return {
        "product": "ResultBond",
        "package": "resultbond-verifier",
        "transport": "stdio",
        "read_only": True,
        "network_access": False,
        "issues_receipts": False,
        "runs_untrusted_code": False,
        "publishes_checks": False,
        "creates_signatures": False,
        "tools": ["verify_receipt_tool", "resultbond_capabilities"],
        "trust": "time-valid root-signed keyset; caller must pin latest serial independently",
    }


def create_server() -> Any:
    from mcp.server import MCPServer

    server = MCPServer("ResultBond Verifier")

    @server.tool()  # type: ignore[untyped-decorator]
    def verify_receipt_tool(
        receipt_json: str,
        keyset_json: dict[str, Any] | str | None = None,
        minimum_keyset_serial: int = 1,
    ) -> dict[str, Any]:
        """Verify read-only evidence; accept MCP's JSON-decoded keyset object.

        Some MCP clients/servers decode JSON-looking string arguments to a
        JSON object before Pydantic validates the tool schema. Accepting that
        object is safe only because the verifier still validates the
        root-signature, exact key roles, serial and revocations. Receipt JSON
        stays a string: its strict parser must catch duplicate field names.
        """
        keyset_text: str | None
        if isinstance(keyset_json, dict):
            try:
                keyset_text = json.dumps(keyset_json, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            except (TypeError, ValueError, OverflowError):
                keyset_text = "{}"  # Fail closed; never silently skip invalid provided evidence.
        else:
            keyset_text = keyset_json
        return verify_receipt(
            receipt_json,
            keyset_text,
            minimum_keyset_serial=minimum_keyset_serial,
        )

    @server.tool()  # type: ignore[untyped-decorator]
    def resultbond_capabilities() -> dict[str, Any]:
        """Read-only verifier capabilities; no execution, signing or mutation."""
        return describe_capabilities()

    return server


def main() -> int:
    try:
        server = create_server()
    except ImportError:
        print('Install optional MCP support: pip install "resultbond-verifier[mcp]"', file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
