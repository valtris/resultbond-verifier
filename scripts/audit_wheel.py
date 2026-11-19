"""Fail-closed byte-level allowlist for the standalone ResultBond Verifier wheel.

This does not prove license ownership and is not authorization to publish.
"""

from __future__ import annotations

import argparse
import re
import stat
import sys
import zipfile
from pathlib import Path

PACKAGE = "resultbond_verifier/"
CODE_FILES = {
    PACKAGE + "__init__.py",
    PACKAGE + "verifier.py",
    PACKAGE + "cli.py",
    PACKAGE + "mcp_server.py",
}
DENIED_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"RESULTBOND_GITHUB_APP_PRIVATE_KEY",
    b"RESULTBOND_RELEASE_KEY=",
)
MAX_WHEEL = 64 * 1024
MAX_FILE = 45 * 1024


def audit(wheel: Path, version: str = "0.1.0") -> dict[str, int | str]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid version")
    if wheel.name != f"resultbond_verifier-{version}-py3-none-any.whl":
        raise ValueError("unexpected wheel name")
    if wheel.stat().st_size > MAX_WHEEL:
        raise ValueError("public wheel unexpectedly large")
    metadata_prefix = f"resultbond_verifier-{version}.dist-info/"
    allowed_metadata = {
        metadata_prefix + part
        for part in (
            "METADATA",
            "WHEEL",
            "RECORD",
            "entry_points.txt",
            "top_level.txt",
            "licenses/LICENSE",
            "licenses/NOTICE",
        )
    }
    required = CODE_FILES | allowed_metadata
    with zipfile.ZipFile(wheel) as z:
        members = z.infolist()
        names = [x.filename for x in members]
        if set(names) != required or len(names) != len(set(names)):
            raise ValueError("unexpected or missing public wheel files")
        for member in members:
            path = member.filename
            if (
                path.startswith("/")
                or "\\" in path
                or ".." in Path(path).parts
                or path not in required
                or member.file_size > MAX_FILE
                or stat.S_ISLNK(member.external_attr >> 16)
                or member.is_dir()
            ):
                raise ValueError("unapproved public wheel entry: " + path)
            content = z.read(member)
            if any(marker in content for marker in DENIED_MARKERS):
                raise ValueError("secret/private-key pattern in public wheel")
            if b"from resultbond." in content or b"import resultbond_runner" in content:
                raise ValueError("private ResultBond Core dependency in standalone client")
        license_text = z.read(metadata_prefix + "licenses/LICENSE")
        notice_text = z.read(metadata_prefix + "licenses/NOTICE")
        if (
            b"Apache License" not in license_text
            or b"Version 2.0, January 2004" not in license_text
            or b"ResultBond Verifier" not in notice_text
        ):
            raise ValueError("missing Apache-2.0 license or attribution")
        metadata = z.read(metadata_prefix + "METADATA")
        if (
            b"License-Expression: Apache-2.0" not in metadata
            or b"License-File: LICENSE" not in metadata
            or b"License-File: NOTICE" not in metadata
        ):
            raise ValueError("package metadata does not declare Apache-2.0")
        if b"Name: resultbond-verifier\n" not in metadata or f"Version: {version}\n".encode() not in metadata:
            raise ValueError("invalid distribution identity")
        for banned in (b"resultbond_core", b"resultbond-runner", b"RESULTBOND_RELEASE_KEY"):
            if banned in metadata:
                raise ValueError("private core reference in public package metadata")
    return {"result": "allowlist_pass", "files": len(names), "bytes": wheel.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    try:
        report = audit(args.wheel, args.version)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print("ResultBond public wheel REFUSED: " + str(exc), file=sys.stderr)
        return 2
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
