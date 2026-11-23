"""Real stdio MCP round-trip: JSON keyset string may be decoded into an object."""
from __future__ import annotations

import asyncio
import json
import sys
import unittest

from mcp import Client, StdioServerParameters
from test_verifier import synthetic_proofs


class MCPKeysetTransportTests(unittest.TestCase):
    def test_valid_json_keyset_does_not_fail_schema(self) -> None:
        receipt, keyset, _, _ = synthetic_proofs()
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "resultbond_verifier.mcp_server"],
        )

        async def scenario() -> None:
            async with Client(params, raise_exceptions=True, read_timeout_seconds=15) as client:
                result = await client.call_tool(
                    "verify_receipt_tool", {"receipt_json": receipt, "keyset_json": keyset}
                )
                self.assertFalse(result.is_error, result.content)
                record = result.structured_content
                self.assertEqual(record["status"], "UNTRUSTED")
                self.assertFalse(record["certified_pass"])
                self.assertTrue(record["signature_valid"])

                # An absent keyset stays untrusted, not falsely certified.
                absent = await client.call_tool("verify_receipt_tool", {"receipt_json": receipt})
                self.assertFalse(absent.is_error)
                self.assertFalse(absent.structured_content["certified_pass"])

                # Invalid root signed keysets also fail closed.
                corrupted = json.loads(keyset)
                corrupted["body"]["serial"] += 1
                bad = await client.call_tool("verify_receipt_tool", {
                    "receipt_json": receipt, "keyset_json": json.dumps(corrupted)
                })
                self.assertFalse(bad.is_error, bad.content)
                self.assertFalse(bad.structured_content["certified_pass"])

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
