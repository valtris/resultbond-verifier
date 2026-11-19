# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ResultBond contributors
"""Offline CLI; exit 0 trusted signed outcome (including FAIL), 1 untrusted, 2 invalid."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import MAX_INPUT, verify_receipt


def _read(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ValueError("expected local input file <= 1 MiB")
    return path.read_text("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ResultBond offline Proof Receipt verifier")
    parser.add_argument("receipt", type=Path, help="local JSON receipt")
    parser.add_argument("--keyset", type=Path, help="locally pinned root-signed keyset")
    parser.add_argument(
        "--min-serial", type=int, default=1, help="highest keyset serial already observed from a trusted source"
    )
    args = parser.parse_args(argv)
    try:
        result = verify_receipt(
            _read(args.receipt),
            _read(args.keyset) if args.keyset else None,
            minimum_keyset_serial=args.min_serial,
        )
    except (OSError, UnicodeError, ValueError):
        result = {
            "status": "INVALID",
            "certified_pass": False,
            "error": "cannot_read_local_evidence",
        }
    print(json.dumps(result, sort_keys=True))
    return {"INVALID": 2, "UNTRUSTED": 1}.get(result["status"], 0)


if __name__ == "__main__":
    sys.exit(main())
