#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end test for the commit message pipeline.

Runs the full pipeline (diff capture, token counting, splitting, chunk
summarization, reduce) against the real Gemini API using the current
staged changes. Does NOT commit or push - only prints the generated
commit message.

Usage::

    pixi run python scripts/test_commit_pipeline.py

Or with a custom diff source::

    git diff HEAD~1 | pixi run python scripts/test_commit_pipeline.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

import generate_commit_message as gcm


def _get_diff() -> str:
    """Get diff from stdin if piped with data, otherwise capture from git.

    Returns:
        str: The diff text including stat header and diff body.
    """
    if not sys.stdin.isatty():
        piped = sys.stdin.read()
        if piped.strip():
            return piped

    stat_result = subprocess.run(
        ["git", "diff", "--cached", "--stat"],
        capture_output=True,
        text=True,
        check=False,
    )
    diff_result = subprocess.run(
        ["git", "diff", "--cached"],
        capture_output=True,
        text=True,
        check=False,
    )

    if not diff_result.stdout.strip():
        stat_result = subprocess.run(
            ["git", "diff", "--stat"],
            capture_output=True,
            text=True,
            check=False,
        )
        diff_result = subprocess.run(
            ["git", "diff"],
            capture_output=True,
            text=True,
            check=False,
        )

    if not diff_result.stdout.strip():
        stat_result = subprocess.run(
            ["git", "diff", "HEAD~1", "--stat"],
            capture_output=True,
            text=True,
            check=False,
        )
        diff_result = subprocess.run(
            ["git", "diff", "HEAD~1"],
            capture_output=True,
            text=True,
            check=False,
        )

    stat = stat_result.stdout.strip()
    diff = diff_result.stdout.strip()

    if not diff:
        print("[test] No diff found (staged, unstaged, or HEAD~1)", file=sys.stderr)
        sys.exit(1)

    return f"FILES CHANGED:\n{stat}\n\nDIFF:\n{diff}"


def main() -> int:
    """Run the full commit message pipeline without committing.

    Returns:
        int: Exit code (0=success, 1=failure).
    """
    print("[test] Capturing diff...", file=sys.stderr)
    diff_input = _get_diff()

    print(f"[test] Diff captured: {len(diff_input):,} chars", file=sys.stderr)

    try:
        client = gcm.create_client()
    except gcm.ApiKeyError as exc:
        print(f"[test] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[test] Model: {gcm.get_model(client)}", file=sys.stderr)

    stat_section, diff_body = gcm.extract_stat_section(diff_input)

    total_tokens = gcm.count_tokens(client, diff_body)
    print(f"[test] Diff size: {len(diff_body):,} chars, {total_tokens:,} tokens", file=sys.stderr)

    result: str | None = None

    if total_tokens <= gcm.SINGLE_CALL_TOKEN_LIMIT:
        print("[test] Mode: single-call", file=sys.stderr)
        result = gcm.single_generate(client, diff_input, total_tokens)
    else:
        print("[test] Mode: batch (map-reduce)", file=sys.stderr)
        result = gcm.batch_generate(client, diff_body, stat_section)

        if not result:
            print("[test] Batch failed, falling back to truncated single call", file=sys.stderr)
            result = gcm.single_generate(client, diff_input, total_tokens)

    if result:
        print("\n" + "=" * 60, file=sys.stderr)
        print("GENERATED COMMIT MESSAGE:", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(result, file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"[test] Success ({len(result)} chars)", file=sys.stderr)
        return 0

    print("[test] FAILED: No commit message generated", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
