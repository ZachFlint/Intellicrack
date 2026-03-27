#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate git commit messages using Google Gemini.

Primary method: Gemini CLI headless mode via OAuth (latest model).
Fallback: ``GOOGLE_API_KEY`` from ``.env`` (lite model).

The script reads a git diff from stdin and generates a conventional commit
message.  It implements honest truncation thresholds that reflect actual
model capabilities.

Exit codes:
    0 - Success, commit message printed to stdout.
    1 - Error, diagnostic printed to stderr (for caller capture).
"""

from __future__ import annotations

import os
import shutil
import subprocess
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


def _load_env() -> None:
    """Load environment variables from .env file."""
    env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)


_load_env()


API_KEY_MODEL: Final[str] = os.environ.get(
    "GEMINI_COMMIT_MODEL", "gemini-3.1-flash-lite-preview"
)
TRUNCATION_THRESHOLD: Final[int] = 3_500_000
FALLBACK_THRESHOLD: Final[int] = 3_800_000
CLI_TIMEOUT_SECONDS: Final[int] = 120

COMMIT_MESSAGE_PROMPT: Final[str] = """Write a git commit message for these changes.

Rules:
- Conventional commit format: type: description
- Subject line under 72 characters
- Developer voice, technical and precise
- NO AI mentions, NO preamble, NO emojis
- Output ONLY the commit message
- For non-trivial changes, include a short body paragraph (1-3 sentences) \
after a blank line explaining the motivation or key design choice
- For multi-area changes, add bullet points after the body

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


_CYAN: Final[str] = "\033[36m"
_RESET: Final[str] = "\033[0m"


def _log_message(msg: str) -> None:
    """Write the full commit message to stderr in cyan for readability.

    Args:
        msg: The complete commit message to display.
    """
    for line in msg.splitlines():
        print(
            f"[commit-msg] {_CYAN}{line}{_RESET}",
            file=sys.stderr,
            flush=True,
        )


def _prepare_diff(diff_input: str) -> tuple[str, str]:
    """Truncate the diff if needed and build a truncation notice.

    Args:
        diff_input: Raw diff content from stdin.

    Returns:
        tuple[str, str]: Tuple of (possibly-truncated diff, truncation
            notice string).  The notice is empty when no truncation occurred.
    """
    diff_length = len(diff_input)

    if diff_length >= FALLBACK_THRESHOLD:
        _log(f"Diff very large ({diff_length:,} chars), using stat summary only")
        actual = (
            diff_input.split("DIFF:\n")[1].split("\n", maxsplit=1)[0]
            if "DIFF:\n" in diff_input
            else diff_input[:10_000]
        )
        notice = (
            "Note: Full diff exceeds practical limits. "
            "Message based on file change summary only.\n"
        )
        return actual, notice

    if diff_length >= TRUNCATION_THRESHOLD:
        _log(
            f"Diff large ({diff_length:,} chars), "
            f"truncating to {TRUNCATION_THRESHOLD:,}",
        )
        notice = (
            f"Note: Diff truncated at {TRUNCATION_THRESHOLD:,} characters "
            "for practical processing. Message reflects visible changes.\n"
        )
        return diff_input[:TRUNCATION_THRESHOLD], notice

    _log(f"Diff size: {diff_length:,} chars")
    return diff_input, ""


def _build_prompt(diff_input: str, truncation_notice: str) -> str:
    """Format the full prompt from diff content and truncation notice.

    Args:
        diff_input: The (possibly truncated) diff content.
        truncation_notice: Notice about truncation, or empty string.

    Returns:
        str: Fully formatted prompt ready for the model.
    """
    return COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=diff_input,
    )


def _try_gemini_cli(prompt: str) -> str | None:
    """Generate a commit message via Gemini CLI headless mode.

    Strips ``GOOGLE_API_KEY`` and ``GEMINI_API_KEY`` from the subprocess
    environment so the CLI uses its OAuth credentials stored at
    ``~/.gemini/oauth_creds.json``.  No ``-m`` flag is passed, so the
    CLI uses its default model (always the latest).

    Args:
        prompt: The fully formatted prompt to send.

    Returns:
        str | None: Generated commit message, or ``None`` on any failure.
    """
    gemini_path = shutil.which("gemini")
    if not gemini_path:
        _log("WARN: Gemini CLI not found in PATH, skipping")
        return None

    oauth_creds = Path.home() / ".gemini" / "oauth_creds.json"
    if not oauth_creds.exists():
        _log("WARN: No OAuth credentials at ~/.gemini/oauth_creds.json, skipping CLI")
        return None

    env = os.environ.copy()
    env.pop("GOOGLE_API_KEY", None)
    env.pop("GEMINI_API_KEY", None)

    cmd: list[str] = [
        gemini_path,
        "-p", " ",
        "--allowed-mcp-server-names", "",
        "-o", "text",
    ]

    _log("Running Gemini CLI...")
    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _log(f"WARN: Gemini CLI timed out ({CLI_TIMEOUT_SECONDS}s)")
        return None
    except FileNotFoundError:
        _log("WARN: Gemini CLI binary not executable")
        return None
    except OSError as exc:
        _log(f"WARN: Gemini CLI OS error: {exc}")
        return None

    if result.returncode != 0:
        stderr_preview = (result.stderr or "").strip()[:300]
        _log(f"WARN: Gemini CLI failed (exit {result.returncode}): {stderr_preview}")
        return None

    output = result.stdout.strip()
    if not output:
        _log("WARN: Gemini CLI returned empty output")
        return None

    return output


def _try_api_key(prompt: str) -> str | None:
    """Generate a commit message using ``GOOGLE_API_KEY``.

    Uses ``gemini-3.1-flash-lite-preview`` by default, overridable via
    ``GEMINI_COMMIT_MODEL`` environment variable.

    Args:
        prompt: The fully formatted prompt to send.

    Returns:
        str | None: Generated commit message, or ``None`` on any failure.
    """
    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not api_key:
        _log("WARN: GOOGLE_API_KEY not set, skipping API key fallback")
        return None

    _log(f"API key loaded ({len(api_key)} chars, ends ...{api_key[-4:]})")
    client = genai.Client(api_key=api_key)

    _log(f"Calling {API_KEY_MODEL} via API key...")
    try:
        response = client.models.generate_content(
            model=API_KEY_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=1024,
            ),
        )
    except ClientError as exc:
        _log(f"WARN: API key client error: {exc}")
        return None
    except ConnectionError as exc:
        _log(f"WARN: API key network error: {exc}")
        return None

    if not response.text:
        candidates_info = ""
        if hasattr(response, "candidates") and response.candidates:
            first = response.candidates[0]
            finish = getattr(first, "finish_reason", "unknown")
            candidates_info = f" (finish_reason={finish})"
        _log(f"WARN: API returned empty response{candidates_info}")
        return None

    return response.text.strip()


def main() -> int:
    """Read diff from stdin, generate commit message, print to stdout.

    Returns:
        int: Exit code (0=success, 1=failure).
    """
    diff_input = sys.stdin.read()

    if not diff_input.strip():
        return _fail("No diff input provided on stdin")

    actual_diff, truncation_notice = _prepare_diff(diff_input)
    prompt = _build_prompt(actual_diff, truncation_notice)

    result = _try_gemini_cli(prompt)
    if result:
        _log(f"Generated via CLI ({len(result)} chars):")
        _log_message(result)
        print(result)
        return 0

    _log("Falling back to API key...")
    try:
        result = _try_api_key(prompt)
    except Exception:
        _log(f"WARN: Unexpected API key error:\n{traceback.format_exc()}")
        result = None

    if result:
        _log(f"Generated via API key ({len(result)} chars):")
        _log_message(result)
        print(result)
        return 0

    return _fail("All generation methods failed")


if __name__ == "__main__":
    sys.exit(main())
