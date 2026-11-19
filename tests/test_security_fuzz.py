# SPDX-License-Identifier: Apache-2.0
"""Deterministic adversarial regression: malformed receipts and signed keysets.

All cryptographic keys are synthetic, ephemeral test keys. No live endpoints.
"""

from __future__ import annotations

import asyncio
import copy
import json
import random
import string
import unittest
from unittest.mock import patch

from mcp import Client
from test_verifier import synthetic_proofs

from resultbond_verifier import verify_receipt
from resultbond_verifier.mcp_server import create_server


class SecurityFuzzTests(unittest.TestCase):
    def test_malformed_json_never_certifies_or_crashes(self) -> None:
        rng = random.Random(20261119)
        alphabet = string.ascii_letters + string.digits + '\0\n\t\u2028\u2603{}[]:,."\\'
        failures = 0
        for iteration in range(3600):
            mode = iteration % 6
            if mode == 0:
                value = "".join(rng.choices(alphabet, k=rng.randint(0, 280)))
            elif mode == 1:
                value = json.dumps(
                    {
                        "payload": [
                            rng.choice([None, False, True, "PASS", rng.randint(-10000, 10000)]) for _ in range(20)
                        ],
                        "signature": {"purpose": "proof-receipt"},
                    }
                )
            elif mode == 2:
                value = "{" + ('"x":1,' * rng.randint(0, 17)) + '"z":0}'
            elif mode == 3:
                value = "{" + '"x":' * rng.randint(1, 40) + "null" + "}" * rng.randint(0, 40)
            elif mode == 4:
                value = rng.choice(["NaN", "Infinity", "-Infinity", "1.0", "1e999", "-0", "99999999999999999999"])
            else:
                value = rng.choice(["\ud800", "\udfff", "\ufeff", "[]", "null", "true", "", "{}"])
            result = verify_receipt(value)
            self.assertIn(result["status"], ("INVALID", "UNTRUSTED"), iteration)
            self.assertFalse(result["certified_pass"], iteration)
            failures += 1
        self.assertEqual(failures, 3600)

    def test_mutated_genuine_signatures_never_certify(self) -> None:
        rng = random.Random(106)
        receipt_json, keyset_json, root_id, root_pub = synthetic_proofs()
        original = json.loads(receipt_json)
        for iteration in range(1000):
            mutated = copy.deepcopy(original)
            field = rng.choice(
                [
                    "payload",
                    "payload_digest",
                    "signature",
                    "evaluator_public_key_b64url",
                ]
            )
            if field == "payload":
                key = rng.choice(list(mutated["payload"]))
                mutated["payload"][key] = rng.choice(
                    [
                        None,
                        0,
                        1,
                        True,
                        "NO",
                        "PASS",
                        "HIDDEN_TEST_FAILURE",
                        [],
                        {"unexpected": "new field"},
                    ]
                )
            elif field == "signature":
                mutated["signature"][rng.choice(list(mutated["signature"]))] = rng.choice(
                    [
                        None,
                        "",
                        0,
                        "Ed448",
                        "proof-receipt-v2",
                        "AAAAAAAAAAAA",
                    ]
                )
            else:
                mutated[field] = rng.choice([0, None, "", "AA", "sha256:" + "0" * 64])
            if mutated == original:
                continue
            with (
                patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
                patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_pub),
            ):
                outcome = verify_receipt(json.dumps(mutated), keyset_json)
            self.assertFalse(outcome["certified_pass"], (iteration, field))
            self.assertNotEqual(outcome["status"], "TRUSTED_PASS", iteration)

    def test_modified_signed_registry_rejected(self) -> None:
        rng = random.Random(901)
        receipt_json, keyset_json, root_id, root_pub = synthetic_proofs()
        original = json.loads(keyset_json)
        for iteration in range(600):
            forged = copy.deepcopy(original)
            field = rng.choice(["serial", "issuer", "root_key_id", "issued_at", "expires_at", "keys", "signature"])
            if field == "signature":
                forged["signature"]["signature_b64url"] = "A" * 86
            elif field == "keys":
                record = forged["body"]["keys"][0]["record"]
                chosen = rng.choice(["key_id", "party_id", "public_key_b64url", "roles", "revoked"])
                record[chosen] = rng.choice([None, 99, [], "attacker", ["EVALUATOR", "BUYER"], True])
            else:
                forged["body"][field] = rng.choice([0, None, "not signed", [], {}])
            with (
                patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
                patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_pub),
            ):
                outcome = verify_receipt(receipt_json, json.dumps(forged))
            self.assertFalse(outcome["certified_pass"], (iteration, field))
            self.assertEqual(outcome["status"], "UNTRUSTED")

    def test_contradictory_signed_pass_is_not_certified(self) -> None:
        # Even an otherwise legitimate evaluator signature must not elevate a
        # policy-contradictory PASS to certified status.
        variants = [
            {"reason_code": "HIDDEN_TEST_FAILURE"},
            {"payment_action": "REFUND_PAYMENT"},
            {"payment_action": "HOLD_FOR_REVIEW"},
            {"manual_review": True},
        ]
        for change in variants:
            with self.subTest(change=change):
                receipt, keyset, root_id, root_pub = synthetic_proofs(**change)
                with (
                    patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
                    patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_pub),
                ):
                    decision = verify_receipt(receipt, keyset)
                self.assertFalse(decision["certified_pass"])
                self.assertNotEqual(decision["status"], "TRUSTED_PASS")

    def test_resource_boundaries_and_nested_documents(self) -> None:
        inputs = [
            " " * 1_048_577,
            '{"bad":"' + "x" * 1_048_576 + '"}',
            "[" * 2000 + "0" + "]" * 2000,
            '{"payload":' + "[" * 1200 + "null" + "]" * 1200 + "}",
            '{"payload":{"duplicate":1,"duplicate":2}}',
            '{"payload":1e999}',
        ]
        for payload in inputs:
            with self.subTest(length=len(payload)):
                result = verify_receipt(payload)
                self.assertEqual(result["status"], "INVALID")
                self.assertFalse(result["certified_pass"])

    def test_mcp_inmemory_concurrent_malformed_calls(self) -> None:
        async def check() -> None:
            async with Client(create_server(), raise_exceptions=True) as mcp:
                responses = await asyncio.gather(
                    *[mcp.call_tool("verify_receipt_tool", {"receipt_json": '{"x":' + str(i) + "}"}) for i in range(32)]
                )
                self.assertEqual(len(responses), 32)
                for response in responses:
                    self.assertFalse(response.is_error)
                    self.assertEqual(response.structured_content["status"], "INVALID")
                    self.assertFalse(response.structured_content["certified_pass"])

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
