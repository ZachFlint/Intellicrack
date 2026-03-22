#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate git commit messages using Google's Gemini API.

This script reads a git diff from stdin and generates a conventional commit
message using the Gemini API. It implements honest truncation thresholds
that reflect actual model capabilities.

Exit codes:
    0 - Success, commit message printed to stdout.
    1 - Error, diagnostic printed to stderr (for caller capture).
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Final

from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai.errors import ClientError


class CommitMessageError(RuntimeError):
    """Raised when commit message generation fails."""


class ApiKeyError(CommitMessageError):
    """Raised when the Gemini API key is missing or invalid."""


class ApiCallError(CommitMessageError):
    """Raised when the Gemini API call fails."""


def load_env() -> None:
    """Load environment variables from .env file."""
    env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)


load_env()


TRUNCATION_THRESHOLD: Final = 500_000
FALLBACK_THRESHOLD: Final = 1_000_000

COMMIT_MESSAGE_PROMPT: Final = """Write a git commit message for these changes.

Rules:
- Conventional commit format: type: description
- Subject line under 72 characters
- Developer voice, technical and precise
- NO AI mentions, NO preamble, NO emojis
- Output ONLY the commit message
- For multi-area changes, add bullet points after a blank line

{truncation_notice}

{diff_input}
"""


def _log(msg: str) -> None:
    """Write a diagnostic line to stderr.

    Args:
        msg: The diagnostic message to write.
    """
    print(f"[commit-msg] {msg}", file=sys.stderr, flush=True)


def _fail(msg: str) -> int:
    """Log an error to stderr and return exit code 1.

    Args:
        msg: The error message to log.

    Returns:
        int: Always returns 1 (failure exit code).
    """
    _log(f"ERROR: {msg}")
    return 1


def get_client() -> genai.Client:
    """Create and return a Gemini API client.

    Returns:
        genai.Client: Configured Gemini API client instance.

    Raises:
        ApiKeyError: If GOOGLE_API_KEY is not set.
    """
    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not api_key:
        msg = "GOOGLE_API_KEY not set. Add it to .env or export it."
        raise ApiKeyError(msg)
    _log(f"API key loaded ({len(api_key)} chars, ends ...{api_key[-4:]})")
    return genai.Client(api_key=api_key)


def generate_commit_message(diff_input: str, client: genai.Client) -> str:
    """Generate a commit message from the provided diff.

    Args:
        diff_input: The git diff content.
        client: The Gemini API client.

    Returns:
        str: Generated commit message.

    Raises:
        ApiCallError: If the API call fails or returns empty response.
    """
    truncation_notice = ""
    actual_input = diff_input

    diff_length = len(diff_input)
    if diff_length >= FALLBACK_THRESHOLD:
        _log(f"Diff very large ({diff_length:,} chars), using stat summary only")
        actual_input = (
            diff_input.split("DIFF:\n")[1].split("\n", maxsplit=1)[0]
            if "DIFF:\n" in diff_input
            else diff_input[:10_000]
        )
        truncation_notice = (
            "Note: Full diff exceeds practical limits. "
            "Message based on file change summary only.\n"
        )
    elif diff_length >= TRUNCATION_THRESHOLD:
        _log(f"Diff large ({diff_length:,} chars), truncating to {TRUNCATION_THRESHOLD:,}")
        actual_input = diff_input[:TRUNCATION_THRESHOLD]
        truncation_notice = (
            f"Note: Diff truncated at {TRUNCATION_THRESHOLD:,} characters "
            "for practical processing. Message reflects visible changes.\n"
        )
    else:
        _log(f"Diff size: {diff_length:,} chars")

    prompt = COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=actual_input,
    )

    _log("Calling Gemini 2.5 Flash...")
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=512,
            ),
        )
    except ClientError as exc:
        msg = f"Gemini API client error: {exc}"
        raise ApiCallError(msg) from exc
    except ConnectionError as exc:
        msg = f"Network error connecting to Gemini API: {exc}"
        raise ApiCallError(msg) from exc

    if not response.text:
        candidates_info = ""
        if hasattr(response, "candidates") and response.candidates:
            first = response.candidates[0]
            finish = getattr(first, "finish_reason", "unknown")
            candidates_info = f" (finish_reason={finish})"
        msg = f"Gemini returned empty response{candidates_info}"
        raise ApiCallError(msg)

    result = response.text.strip()
    _log(f"Generated message ({len(result)} chars): {result.splitlines()[0]}")
    return result


def main() -> int:
    """Read diff from stdin, generate commit message, print to stdout.

    Returns:
        int: Exit code (0=success, 1=failure).
    """
    diff_input = sys.stdin.read()

    if not diff_input.strip():
        return _fail("No diff input provided on stdin")

    try:
        client = get_client()
    except CommitMessageError as exc:
        return _fail(str(exc))
    except Exception:
        return _fail(f"Unexpected error creating client:\n{traceback.format_exc()}")

    try:
        message = generate_commit_message(diff_input, client)
    except CommitMessageError as exc:
        return _fail(str(exc))
    except Exception:
        return _fail(f"Unexpected error generating message:\n{traceback.format_exc()}")

    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
