# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ResultBond contributors
"""Independent, read-only ResultBond Proof Receipt verifier.

No issuer, signer, sandbox, payment, GitHub client, network or private keys.
The only identity anchor is the public offline ROOT pinned in this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT_KEY_ID = "rb:root:2026-10"
ROOT_PUBLIC_KEY = "k4kS-tpmIN5OQFjdt8Q8AJiaPC_iOa6jfhU5IIz3AUE"
DOMAIN = b"RESULTBOND-CANONICAL-SIGNATURE-V0.1\x00"
MAX_INPUT = 1_048_576
MAX_SAFE = (1 << 53) - 1
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
RECEIPT_KEYS = {"payload", "payload_digest", "evaluator_public_key_b64url", "signature"}
SIGNATURE_KEYS = {"algorithm", "key_id", "purpose", "signature_b64url"}
PAYLOAD_KEYS = {
    "receipt_version",
    "receipt_id",
    "evaluator_id",
    "evaluator_key_id",
    "job_id",
    "partner_id",
    "manifest_digest",
    "evidence_digest",
    "candidate_submission_digest",
    "decision_digest",
    "outcome",
    "reason_code",
    "settlement",
    "policy_id",
    "issued_at",
    "event_sequence",
    "previous_event_digest",
}
SETTLEMENT_KEYS = {
    "currency",
    "payment_action",
    "payment_atomic",
    "stipend_atomic",
    "requires_manual_review",
}
KEYSET_KEYS = {"body", "signature"}
KEYSET_BODY_KEYS = {
    "keyset_version",
    "issuer",
    "root_key_id",
    "serial",
    "issued_at",
    "expires_at",
    "keys",
}
PUBLISHED_KEY_KEYS = {"record", "valid_from", "revoked_at"}
KEY_RECORD_KEYS = {"key_id", "party_id", "public_key_b64url", "roles", "revoked"}
ROLES = {"BUYER", "PARTNER", "PROVIDER", "EVALUATOR", "RESOLVER", "RUNNER", "AUDITOR"}
REASONS = {
    "ALL_CHECKS_PASS",
    "PUBLIC_TEST_FAILURE",
    "HIDDEN_TEST_FAILURE",
    "REGRESSION_FAILURE",
    "BASELINE_NOT_REPRODUCIBLE",
    "CANDIDATE_NOT_REPRODUCIBLE",
    "INFRASTRUCTURE_ERROR",
    "HIDDEN_INDEPENDENCE_NOT_PROVEN",
    "EVIDENCE_BINDING_MISMATCH",
    "EVIDENCE_INCONSISTENT",
    "POLICY_VIOLATION",
    "CANDIDATE_RUNTIME_FAILURE",
    "CANDIDATE_TEST_ERROR",
    "BOUND_TEST_SKIPPED",
    "TEST_HARNESS_TAMPERING",
}
OUTCOMES = {"PASS", "FAIL", "INCONCLUSIVE"}


class VerificationError(ValueError):
    """A structurally or cryptographically invalid proof."""


def _strict_load(raw: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON keys")
            result[key] = value
        return result

    def refuse_number(value: str) -> Any:
        raise VerificationError("floating point and nonfinite numbers are forbidden")

    try:
        return json.loads(
            raw,
            object_pairs_hook=unique,
            parse_float=refuse_number,
            parse_constant=refuse_number,
        )
    except (ValueError, RecursionError) as exc:
        raise VerificationError("invalid strict JSON") from exc


def _canonical(value: Any) -> bytes:
    """Canonical JSON v0.2, restricted to the common JS/Python signed domain."""

    def validate(item: Any) -> None:
        if item is None or type(item) is bool:
            return
        if type(item) is int and -MAX_SAFE <= item <= MAX_SAFE:
            return
        if isinstance(item, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise VerificationError("lone surrogate")
            return
        if type(item) is list:
            for child in item:
                validate(child)
            return
        if type(item) is dict:
            for key, child in item.items():
                if not isinstance(key, str) or not key.isascii():
                    raise VerificationError("non-ASCII signed key")
                validate(child)
            return
        raise VerificationError("unsupported signed JSON type")

    try:
        validate(value)
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise VerificationError("cannot canonicalize document") from exc


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _b64(value: Any, expected: int) -> bytes:
    if not isinstance(value, str) or not BASE64URL.fullmatch(value):
        raise VerificationError("invalid base64url")
    try:
        output = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise VerificationError("invalid base64url") from exc
    if len(output) != expected or base64.urlsafe_b64encode(output).decode().rstrip("=") != value:
        raise VerificationError("noncanonical base64url or length")
    return output


def _keys(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    if type(value) is not dict or not required.issubset(value.keys()):
        raise VerificationError("missing required fields")
    if not set(value).issubset(required | (optional or set())):
        raise VerificationError("unexpected fields")


def _signature(payload: Any, signature: Any, public_key: str, purpose: str, key_id: str) -> None:
    _keys(signature, SIGNATURE_KEYS)
    if signature["algorithm"] != "Ed25519" or signature["purpose"] != purpose or signature["key_id"] != key_id:
        raise VerificationError("signature identity or purpose mismatch")
    message = DOMAIN + purpose.encode("utf-8") + b"\x00" + _canonical(payload)
    try:
        Ed25519PublicKey.from_public_bytes(_b64(public_key, 32)).verify(
            _b64(signature["signature_b64url"], 64),
            message,
        )
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("Ed25519 signature invalid") from exc


def _string(value: Any, limit: int = 200) -> None:
    if not isinstance(value, str) or not value or len(value) > limit or value != value.strip():
        raise VerificationError("invalid normalized string")


def _int(value: Any, *, lower: int = 0) -> None:
    if type(value) is not int or not lower <= value <= MAX_SAFE:
        raise VerificationError("integer outside supported range")


def _digest(value: Any) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise VerificationError("invalid SHA-256 digest")


def _stamp(value: Any, *, strict_receipt: bool = False) -> datetime:
    if not isinstance(value, str):
        raise VerificationError("missing signed timestamp")
    if strict_receipt and not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
        value,
    ):
        raise VerificationError("noncanonical receipt timestamp")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise VerificationError("invalid timestamp") from exc
    if timestamp.tzinfo is None:
        raise VerificationError("timestamp must be timezone-aware")
    if (
        strict_receipt
        and timestamp.astimezone(UTC)
        .isoformat(
            timespec="microseconds",
        )
        .replace("+00:00", "Z")
        != value
    ):
        raise VerificationError("noncanonical UTC timestamp")
    return timestamp.astimezone(UTC)


def _validate_receipt(raw: Any) -> tuple[dict[str, Any], str]:
    _keys(raw, RECEIPT_KEYS)
    payload = raw["payload"]
    _keys(payload, PAYLOAD_KEYS, {"previous_receipt_digest"})
    _keys(payload["settlement"], SETTLEMENT_KEYS)
    for key in ("receipt_id", "evaluator_id", "evaluator_key_id"):
        _string(payload[key])
    for key in ("job_id", "partner_id", "policy_id"):
        _string(payload[key], limit=1000)
    _digest(raw["payload_digest"])
    for key in (
        "manifest_digest",
        "evidence_digest",
        "candidate_submission_digest",
        "decision_digest",
        "previous_event_digest",
    ):
        _digest(payload[key])
    if "previous_receipt_digest" in payload:
        _digest(payload["previous_receipt_digest"])
    if payload["receipt_version"] != "rb.proof-receipt.v0.3":
        raise VerificationError("unsupported receipt format")
    if payload["outcome"] not in OUTCOMES or payload["reason_code"] not in REASONS:
        raise VerificationError("unsupported outcome or reason")
    _stamp(payload["issued_at"], strict_receipt=True)
    _int(payload["event_sequence"], lower=1)
    settlement = payload["settlement"]
    if (
        settlement["currency"] != "USDC"
        or settlement["payment_action"]
        not in {
            "RELEASE_PAYMENT",
            "REFUND_PAYMENT",
            "HOLD_FOR_REVIEW",
        }
        or type(settlement["requires_manual_review"]) is not bool
    ):
        raise VerificationError("invalid settlement")
    _int(settlement["payment_atomic"])
    _int(settlement["stipend_atomic"])
    # A cryptographically authentic but internally contradictory PASS must
    # never be promoted to a certified success. This mirrors Core policy.py.
    if payload["outcome"] == "PASS" and (
        payload["reason_code"] != "ALL_CHECKS_PASS"
        or settlement["payment_action"] != "RELEASE_PAYMENT"
        or settlement["requires_manual_review"]
        or settlement["stipend_atomic"] != 0
    ):
        raise VerificationError("signed PASS conflicts with policy")
    _b64(raw["evaluator_public_key_b64url"], 32)
    if _sha(payload) != raw["payload_digest"]:
        raise VerificationError("receipt digest mismatch")
    _signature(
        payload,
        raw["signature"],
        raw["evaluator_public_key_b64url"],
        "proof-receipt",
        payload["evaluator_key_id"],
    )
    return payload, raw["payload_digest"]


def _validate_keyset(raw: Any, minimum_serial: int, now: datetime) -> dict[str, dict[str, Any]]:
    _keys(raw, KEYSET_KEYS)
    body = raw["body"]
    _keys(body, KEYSET_BODY_KEYS)
    if body["keyset_version"] != "rb.keyset.v1" or body["root_key_id"] != ROOT_KEY_ID:
        raise VerificationError("untrusted root or keyset version")
    _string(body["issuer"])
    _int(body["serial"], lower=minimum_serial)
    issued_at = _stamp(body["issued_at"])
    expires_at = _stamp(body["expires_at"])
    if issued_at > now or expires_at <= now or expires_at <= issued_at:
        raise VerificationError("expired or not-yet-issued keyset")
    entries = body["keys"]
    if type(entries) is not list or len(entries) > 4096:
        raise VerificationError("invalid key registry")
    _signature(body, raw["signature"], ROOT_PUBLIC_KEY, "rb.keyset.v1", ROOT_KEY_ID)
    trusted: dict[str, dict[str, Any]] = {}
    all_keys: set[str] = set()
    deal_parties: set[str] = set()
    service_parties: set[str] = set()
    for entry in entries:
        _keys(entry, PUBLISHED_KEY_KEYS)
        record = entry["record"]
        _keys(record, KEY_RECORD_KEYS)
        _string(record["key_id"])
        _string(record["party_id"])
        _b64(record["public_key_b64url"], 32)
        if (
            type(record["roles"]) is not list
            or not record["roles"]
            or len(set(record["roles"])) != len(record["roles"])
            or set(record["roles"]) - ROLES
            or sorted(record["roles"]) != record["roles"]
        ):
            raise VerificationError("invalid key roles")
        if type(record["revoked"]) is not bool or record["revoked"]:
            raise VerificationError("invalid published revocation")
        key_id = record["key_id"]
        if key_id in all_keys:
            raise VerificationError("duplicate signer ID")
        all_keys.add(key_id)
        roles = set(record["roles"])
        if roles & {"BUYER", "PARTNER", "PROVIDER"}:
            deal_parties.add(record["party_id"])
        if roles & {"EVALUATOR", "RESOLVER", "RUNNER", "AUDITOR"}:
            service_parties.add(record["party_id"])
        valid_from = _stamp(entry["valid_from"])
        revoked_at = None if entry["revoked_at"] is None else _stamp(entry["revoked_at"])
        if "EVALUATOR" in roles and valid_from <= now and (revoked_at is None or revoked_at > now):
            trusted[key_id] = record
    if service_parties & deal_parties:
        raise VerificationError("key role identity overlap")
    return trusted


def verify_receipt(
    receipt_json: str, keyset_json: str | None = None, *, minimum_keyset_serial: int = 1
) -> dict[str, Any]:
    """Check signed proof and optional independently pinned root-signed keyset.

    Without keyset, a cryptographically valid receipt is NEVER a certified PASS.
    Offline verification cannot establish the latest root keyset serial.
    """
    invalid: dict[str, Any] = {
        "status": "INVALID",
        "signature_valid": False,
        "trusted_signer": False,
        "claimed_outcome": None,
        "receipt_digest": None,
        "certified_pass": False,
    }
    if type(minimum_keyset_serial) is not int or not 1 <= minimum_keyset_serial <= MAX_SAFE:
        return {**invalid, "error": "invalid_minimum_serial"}
    try:
        if not isinstance(receipt_json, str) or len(receipt_json.encode("utf-8")) > MAX_INPUT:
            raise VerificationError("receipt too large")
        receipt = _strict_load(receipt_json)
        payload, digest = _validate_receipt(receipt)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return {**invalid, "error": "receipt_invalid_or_tampered"}

    result: dict[str, Any] = {
        "status": "UNTRUSTED",
        "signature_valid": True,
        "trusted_signer": False,
        "claimed_outcome": payload["outcome"],
        "receipt_digest": digest,
        "certified_pass": False,
        "reason_code": payload["reason_code"],
        "evaluator_key_id": payload["evaluator_key_id"],
    }
    if keyset_json is None:
        return {**result, "trust_reason": "independently_trusted_keyset_required"}
    if str(payload["evaluator_key_id"]).startswith("demo:"):
        return {**result, "trust_reason": "demo_signers_never_trusted"}
    try:
        if not isinstance(keyset_json, str) or len(keyset_json.encode("utf-8")) > MAX_INPUT:
            raise VerificationError("keyset too large")
        keyset = _strict_load(keyset_json)
        registry = _validate_keyset(keyset, minimum_keyset_serial, datetime.now(UTC))
        record = registry.get(payload["evaluator_key_id"])
        if (
            not record
            or record["party_id"] != payload["evaluator_id"]
            or record["public_key_b64url"] != receipt["evaluator_public_key_b64url"]
        ):
            raise VerificationError("evaluator role or key not authorized")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return {**result, "trust_reason": "keyset_invalid_expired_revoked_or_mismatched"}
    return {
        **result,
        "status": "TRUSTED_" + payload["outcome"],
        "trusted_signer": True,
        "certified_pass": payload["outcome"] == "PASS",
        "trust_reason": "pinned_offline_root_verified",
        "keyset_freshness": "latest_serial_requires_external_trusted_record",
    }
