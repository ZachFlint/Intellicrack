# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Warm the tiktoken BPE encoding cache during the sandbox image build.

The Intellicrack test sandbox runs network-isolated, but the orchestrator's
token counting relies on :mod:`tiktoken`, which downloads its BPE encoding
files on first use. This script is executed at image-build time (when the
build host has network access) so the encodings are written into
``TIKTOKEN_CACHE_DIR`` and baked into the image, letting runtime token counting
work offline. It is invoked from ``docker/Dockerfile.windows``.
"""

from __future__ import annotations

import sys

import tiktoken


def _emit(message: str) -> None:
    """Write a build-progress line to stdout.

    Args:
        message: The line to write (a newline is appended).
    """
    sys.stdout.write(f"{message}\n")


_ENCODINGS: tuple[str, ...] = (
    "o200k_base",
    "cl100k_base",
    "p50k_base",
    "r50k_base",
    "gpt2",
)


def main() -> int:
    """Download and cache each required tiktoken encoding.

    Returns:
        int: ``0`` on success; ``1`` if any encoding fails to load.
    """
    for name in _ENCODINGS:
        encoding = tiktoken.get_encoding(name)
        token_count = len(encoding.encode("intellicrack sandbox warm-up"))
        _emit(f"cached tiktoken encoding {name} ({token_count} warm-up tokens)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
