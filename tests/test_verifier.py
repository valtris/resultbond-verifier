# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ResultBond contributors
"""Independent public tests: temporary keys, no ResultBond Core imports."""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resultbond_verifier import verify_receipt
from resultbond_verifier.verifier import DOMAIN, _canonical, _sha


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def public_key(key: Ed25519PrivateKey) -> str:
    return b64(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sign(key: Ed25519PrivateKey, payload: dict, purpose: str, key_id: str) -> dict:
    message = DOMAIN + purpose.encode("utf-8") + b"\x00" + _canonical(payload)
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "purpose": purpose,
        "signature_b64url": b64(key.sign(message)),
    }


def synthetic_proofs(
    *,
    serial: int = 17,
    revoked: bool = False,
    outcome: str = "PASS",
    reason_code: str = "ALL_CHECKS_PASS",
    payment_action: str = "RELEASE_PAYMENT",
    manual_review: bool = False,
) -> tuple[str, str, str, str]:
    now = datetime.now(UTC)
    root = Ed25519PrivateKey.generate()
    evaluator = Ed25519PrivateKey.generate()
    key_id = "synthetic:evaluator"
    evaluator_id = "synthetic:party"
    root_id = "synthetic:root"
    digest = "sha256:" + "0" * 64
    payload = {
        "receipt_version": "rb.proof-receipt.v0.3",
        "receipt_id": "synthetic:receipt",
        "evaluator_id": evaluator_id,
        "evaluator_key_id": key_id,
        "job_id": "synthetic:job",
        "partner_id": "synthetic:partner",
        "manifest_digest": digest,
        "evidence_digest": digest,
        "candidate_submission_digest": digest,
        "decision_digest": digest,
        "outcome": outcome,
        "reason_code": reason_code,
        "settlement": {
            "currency": "USDC",
            "payment_action": payment_action,
            "payment_atomic": 0,
            "stipend_atomic": 0,
            "requires_manual_review": manual_review,
        },
        "policy_id": "synthetic:policy",
        "issued_at": stamp(now),
        "event_sequence": 1,
        "previous_event_digest": digest,
    }
    receipt = {
        "payload": payload,
        "payload_digest": _sha(payload),
        "evaluator_public_key_b64url": public_key(evaluator),
        "signature": sign(evaluator, payload, "proof-receipt", key_id),
    }
    body = {
        "keyset_version": "rb.keyset.v1",
        "issuer": "synthetic",
        "root_key_id": root_id,
        "serial": serial,
        "issued_at": stamp(now - timedelta(minutes=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "keys": [
            {
                "record": {
                    "key_id": key_id,
                    "party_id": evaluator_id,
                    "public_key_b64url": public_key(evaluator),
                    "roles": ["EVALUATOR"],
                    "revoked": False,
                },
                "valid_from": stamp(now - timedelta(minutes=2)),
                "revoked_at": stamp(now - timedelta(seconds=1)) if revoked else None,
            }
        ],
    }
    keyset = {"body": body, "signature": sign(root, body, "rb.keyset.v1", root_id)}
    return json.dumps(receipt), json.dumps(keyset), root_id, public_key(root)


class StandaloneVerifierTests(unittest.TestCase):
    def test_synthetic_signature_only_is_not_certification(self) -> None:
        receipt, keyset, root_id, root_public = synthetic_proofs()
        untrusted = verify_receipt(receipt)
        self.assertEqual(untrusted["status"], "UNTRUSTED")
        self.assertTrue(untrusted["signature_valid"])
        self.assertFalse(untrusted["certified_pass"])
        self.assertFalse(verify_receipt(receipt, keyset)["certified_pass"])
        with (
            patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
            patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_public),
        ):
            accepted = verify_receipt(receipt, keyset, minimum_keyset_serial=17)
        self.assertEqual(accepted["status"], "TRUSTED_PASS")
        self.assertTrue(accepted["certified_pass"])

    def test_serial_rollback_and_revocation_fail_closed(self) -> None:
        receipt, keyset, root_id, root_public = synthetic_proofs()
        with (
            patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
            patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_public),
        ):
            self.assertEqual(
                verify_receipt(receipt, keyset, minimum_keyset_serial=18)["status"],
                "UNTRUSTED",
            )
        receipt, keyset, root_id, root_public = synthetic_proofs(revoked=True)
        with (
            patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
            patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_public),
        ):
            self.assertEqual(verify_receipt(receipt, keyset)["status"], "UNTRUSTED")

    def test_malicious_and_invalid_proofs_rejected(self) -> None:
        receipt, _, _, _ = synthetic_proofs()
        changed = json.loads(receipt)
        changed["payload"]["outcome"] = "FAIL"
        self.assertEqual(verify_receipt(json.dumps(changed))["status"], "INVALID")
        self.assertEqual(verify_receipt('{"payload":1,"payload":2}')["status"], "INVALID")
        self.assertEqual(verify_receipt("\ud800")["status"], "INVALID")
        self.assertEqual(verify_receipt("x" * 1_048_577)["status"], "INVALID")
        self.assertEqual(verify_receipt(receipt, minimum_keyset_serial=0)["status"], "INVALID")

    def test_non_pass_verdict_does_not_certify_pass(self) -> None:
        receipt, keyset, root_id, root_public = synthetic_proofs(outcome="FAIL")
        with (
            patch("resultbond_verifier.verifier.ROOT_KEY_ID", root_id),
            patch("resultbond_verifier.verifier.ROOT_PUBLIC_KEY", root_public),
        ):
            status = verify_receipt(receipt, keyset)
        self.assertEqual(status["status"], "TRUSTED_FAIL")
        self.assertFalse(status["certified_pass"])

    def test_canonical_hash_vectors(self) -> None:
        self.assertEqual(_canonical({"b": 1, "a": 2}), b'{"a":2,"b":1}')
        self.assertEqual(
            _sha({}),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        )

    def test_cli_exit_status_invalid_and_untrusted(self) -> None:
        receipt, _, _, _ = synthetic_proofs()
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / "receipt.json"
            filename.write_text(receipt, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "resultbond_verifier.cli", str(filename)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["certified_pass"])
            filename.write_text("{}", encoding="utf-8")
            bad = subprocess.run(
                [sys.executable, "-m", "resultbond_verifier.cli", str(filename)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(bad.returncode, 2)

    def test_real_stdio_mcp_subprocess(self) -> None:
        from mcp import Client, StdioServerParameters

        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "resultbond_verifier.mcp_server"],
        )

        async def check() -> None:
            async with Client(params, raise_exceptions=True, read_timeout_seconds=10) as client:
                names = [item.name for item in (await client.list_tools()).tools]
                self.assertIn("verify_receipt_tool", names)
                self.assertIn("resultbond_capabilities", names)
                answer = await client.call_tool("verify_receipt_tool", {"receipt_json": "{}"})
                self.assertFalse(answer.is_error)
                self.assertFalse(answer.structured_content["certified_pass"])

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
