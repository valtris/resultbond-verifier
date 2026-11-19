# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ResultBond contributors
"""Public read-only ResultBond receipt verifier."""

from .verifier import ROOT_KEY_ID, ROOT_PUBLIC_KEY, verify_receipt

__all__ = ["ROOT_KEY_ID", "ROOT_PUBLIC_KEY", "verify_receipt"]
