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
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from io import TextIOWrapper

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
CLI_TIMEOUT_SECONDS: Final[int] = 45
CLI_INPUT_LIMIT: Final[int] = 200_000

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


@dataclass
class _CliResult:
    """Result from streaming a CLI subprocess."""

    stdout: str = ""
    stderr_lines: list[str] = field(default_factory=list)
    returncode: int = -1
    timed_out: bool = False


def _read_stderr_live(stream: TextIOWrapper, dest: list[str]) -> None:
    """Read stderr line-by-line, logging each line in real time.

    Runs in a daemon thread so the main thread can enforce a timeout.

    Args:
        stream: The stderr text stream from a subprocess.
        dest: List to append each stripped stderr line to.
    """
    for raw_line in stream:
        stripped: str = raw_line.rstrip()
        if stripped:
            dest.append(stripped)
            _log(f"  [cli] {stripped}")


def _read_stdout(stream: TextIOWrapper, dest: list[str]) -> None:
    """Read stdout in chunks, buffering for later retrieval.

    Runs in a daemon thread so the main thread can enforce a timeout.

    Args:
        stream: The stdout text stream from a subprocess.
        dest: List to append each chunk to.
    """
    while True:
        chunk: str = stream.read(4096)
        if not chunk:
            break
        dest.append(chunk)


def _stream_cli_process(
    proc: subprocess.Popen[str],
    timeout: int,
) -> _CliResult:
    """Stream stdout/stderr from a Popen process with timeout.

    Uses threads to read both pipes concurrently (Windows-compatible).
    Stderr lines are logged in real time so the caller can observe CLI
    progress.  Stdout is buffered for return.

    Args:
        proc: An open subprocess with text-mode stdout and stderr pipes.
        timeout: Maximum seconds to wait before killing the process.

    Returns:
        _CliResult: Captured output, collected stderr lines, return code,
            and whether a timeout occurred.
    """
    result = _CliResult()

    if proc.stdout is None or proc.stderr is None:
        proc.kill()
        proc.wait()
        result.returncode = -1
        return result

    stdout_chunks: list[str] = []

    stderr_thread = threading.Thread(
        target=_read_stderr_live,
        args=(proc.stderr, result.stderr_lines),
        daemon=True,
    )
    stdout_thread = threading.Thread(
        target=_read_stdout,
        args=(proc.stdout, stdout_chunks),
        daemon=True,
    )
    stderr_thread.start()
    stdout_thread.start()

    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            proc.wait()
            stderr_thread.join(timeout=2)
            stdout_thread.join(timeout=2)
            result.timed_out = True
            return result
        time.sleep(0.25)

    stderr_thread.join(timeout=5)
    stdout_thread.join(timeout=5)

    result.stdout = "".join(stdout_chunks).strip()
    result.returncode = proc.returncode if proc.returncode is not None else -1
    return result


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

    cli_prompt = prompt
    if len(cli_prompt) > CLI_INPUT_LIMIT:
        _log(
            f"Truncating CLI input from {len(cli_prompt):,} to {CLI_INPUT_LIMIT:,} chars"
        )
        cli_prompt = cli_prompt[:CLI_INPUT_LIMIT] + "\n... (truncated for CLI)"

    _log("Running Gemini CLI...")
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if proc.stdin is not None:
            proc.stdin.write(cli_prompt)
            proc.stdin.close()

        result = _stream_cli_process(proc, CLI_TIMEOUT_SECONDS)
    except FileNotFoundError:
        _log("WARN: Gemini CLI binary not executable")
        return None
    except OSError as exc:
        _log(f"WARN: Gemini CLI OS error: {exc}")
        return None

    if result.timed_out:
        _log(f"WARN: Gemini CLI timed out ({CLI_TIMEOUT_SECONDS}s)")
        if result.stderr_lines:
            _log("CLI stderr before timeout:")
            for err_line in result.stderr_lines[-20:]:
                _log(f"  | {err_line}")
        return None

    if result.returncode != 0:
        _log(f"WARN: Gemini CLI failed (exit {result.returncode})")
        if result.stderr_lines:
            for err_line in result.stderr_lines[-10:]:
                _log(f"  | {err_line}")
        return None

    if not result.stdout:
        _log("WARN: Gemini CLI returned empty output")
        return None

    return result.stdout


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
