#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate git commit messages using Google Gemini API via Vertex AI.

Uses Application Default Credentials and ``GOOGLE_CLOUD_PROJECT`` from
``.env`` to call the Gemini API through Vertex AI. Billing flows through
GCP project credits. Supports map-reduce batching for diffs that exceed
Paid Tier 1 token limits.

The script reads a git diff from stdin and generates a conventional commit
message. For large diffs (>900K tokens), it splits the diff into chunks,
summarizes each chunk separately, then combines summaries into a final
commit message.

Exit codes:
    0 - Success, commit message printed to stdout.
    1 - Error, diagnostic printed to stderr (for caller capture).
"""

from __future__ import annotations

import os
import re
import sys
import time
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
    "GEMINI_COMMIT_MODEL", "gemini-2.5-flash",
)
SINGLE_CALL_TOKEN_LIMIT: Final[int] = 900_000
CHUNK_TOKEN_TARGET: Final[int] = 800_000
BATCH_COOLDOWN: Final[int] = 2
MAX_BATCH_TIME: Final[int] = 300
_TOKEN_THRESHOLD_MILLIONS: Final[int] = 1_000_000
_TOKEN_THRESHOLD_THOUSANDS: Final[int] = 1_000

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

CHUNK_SUMMARY_PROMPT: Final[str] = """Summarize the key changes in this diff chunk.

For each file modified, state:
- The file path
- What was changed (added, removed, refactored, renamed, etc.)
- The apparent motivation (if discernible from the diff)

Be concise but complete. Use bullet points. Do NOT write a commit message yet.

{chunk}
"""

REDUCE_PROMPT: Final[str] = """Write a git commit message based on these change summaries.

Rules:
- Conventional commit format: type: description
- Subject line under 72 characters
- Developer voice, technical and precise
- NO AI mentions, NO preamble, NO emojis
- Output ONLY the commit message
- For non-trivial changes, include a short body paragraph (1-3 sentences) \
after a blank line explaining the motivation or key design choice
- For multi-area changes, add bullet points after the body

FILES CHANGED (full list):
{stat_section}

CHANGE SUMMARIES:
{summaries}
"""

_CYAN: Final[str] = "\033[36m"
_GREEN: Final[str] = "\033[32m"
_YELLOW: Final[str] = "\033[33m"
_RESET: Final[str] = "\033[0m"


def _log(msg: str) -> None:
    """Write a diagnostic line to stderr.

    Args:
        msg: The diagnostic message to write.
    """
    print(f"[commit-msg] {msg}", file=sys.stderr, flush=True)


def _progress(msg: str, *, overwrite: bool = True) -> None:
    """Write a live-updating progress line to stderr.

    Args:
        msg: The progress message to display.
        overwrite: If True, use carriage return to overwrite the current line.
    """
    end = "\r" if overwrite else "\n"
    padded = f"[commit-msg] {msg}".ljust(100)
    print(f"\r{padded}", file=sys.stderr, end=end, flush=True)


def _fail(msg: str) -> int:
    """Log an error to stderr and return exit code 1.

    Args:
        msg: The error message to log.

    Returns:
        int: Always returns 1 (failure exit code).
    """
    _log(f"ERROR: {msg}")
    return 1


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


def _count_tokens(client: genai.Client, text: str) -> int:
    """Count tokens for the given text using the Gemini tokenizer.

    Args:
        client: The genai client instance.
        text: Text to count tokens for.

    Returns:
        int: Number of tokens in the text.
    """
    response = client.models.count_tokens(
        model=API_KEY_MODEL,
        contents=text,
    )
    return response.total_tokens


def _format_tokens(count: int) -> str:
    """Format a token count for display (e.g. 1,234,567 -> 1.2M).

    Args:
        count: The token count to format.

    Returns:
        str: Human-readable token count string.
    """
    if count >= _TOKEN_THRESHOLD_MILLIONS:
        return f"{count / _TOKEN_THRESHOLD_MILLIONS:.1f}M"
    if count >= _TOKEN_THRESHOLD_THOUSANDS:
        return f"{count / _TOKEN_THRESHOLD_THOUSANDS:.0f}K"
    return str(count)


def _build_progress_bar(current: int, total: int, width: int = 20) -> str:
    """Build a text-based progress bar string.

    Args:
        current: Current progress value.
        total: Total value for 100% completion.
        width: Character width of the progress bar.

    Returns:
        str: Progress bar string like ``[####------]``.
    """
    filled = current * width // total if total > 0 else 0
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}]"


def _batch_cooldown_wait(chunk_num: int, total_chunks: int) -> None:
    """Wait between batches with a live countdown display.

    Args:
        chunk_num: The chunk number just completed.
        total_chunks: Total number of chunks to process.
    """
    for remaining in range(BATCH_COOLDOWN, 0, -1):
        bar = _build_progress_bar(BATCH_COOLDOWN - remaining, BATCH_COOLDOWN)
        _progress(
            f"[{chunk_num}/{total_chunks}] "
            f"Next batch in: {bar} {remaining}s",
        )
        time.sleep(1)
    _progress(
        f"[{chunk_num}/{total_chunks}] Batch ready",
        overwrite=False,
    )


def _split_diff_on_file_boundaries(
    diff_input: str,
    client: genai.Client,
) -> list[str]:
    """Split a unified diff into token-bounded chunks on file boundaries.

    Splits on ``diff --git`` markers so each chunk contains complete file
    diffs. Groups adjacent file diffs together until adding the next file
    would exceed ``CHUNK_TOKEN_TARGET`` (800K tokens for Paid Tier 1).

    Args:
        diff_input: The full unified diff string.
        client: The genai client instance (for token counting).

    Returns:
        list[str]: List of diff chunk strings, each under the token target.
    """
    file_diffs = re.split(r"(?=^diff --git )", diff_input, flags=re.MULTILINE)
    file_diffs = [fd for fd in file_diffs if fd.strip()]

    if not file_diffs:
        return [diff_input]

    _progress(f"Splitting diff into chunks ({len(file_diffs)} files)...")

    chunks: list[str] = []
    current_chunk: list[str] = []
    current_tokens = 0

    for i, file_diff in enumerate(file_diffs):
        file_tokens = _count_tokens(client, file_diff)
        _progress(
            f"Splitting: file {i + 1}/{len(file_diffs)} "
            f"({_format_tokens(current_tokens)} in current chunk, "
            f"{len(chunks)} chunks built)",
        )

        if file_tokens > CHUNK_TOKEN_TARGET:
            if current_chunk:
                chunks.append("".join(current_chunk))
                current_chunk = []
                current_tokens = 0
            chunks.append(file_diff)
            continue

        if current_tokens + file_tokens > CHUNK_TOKEN_TARGET and current_chunk:
            chunks.append("".join(current_chunk))
            current_chunk = []
            current_tokens = 0

        current_chunk.append(file_diff)
        current_tokens += file_tokens

    if current_chunk:
        chunks.append("".join(current_chunk))

    _progress(
        f"Split complete: {len(chunks)} chunks from {len(file_diffs)} files",
        overwrite=False,
    )
    return chunks


def _generate_content(
    client: genai.Client,
    prompt: str,
    max_output_tokens: int = 1024,
) -> str | None:
    """Call ``generate_content`` with standard error handling.

    Args:
        client: The genai client instance.
        prompt: The prompt to send.
        max_output_tokens: Maximum tokens in the response.

    Returns:
        str | None: Generated text, or ``None`` on failure.
    """
    try:
        response = client.models.generate_content(
            model=API_KEY_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=max_output_tokens,
            ),
        )
    except ClientError as exc:
        _log(f"WARN: API client error: {exc}")
        return None
    except ConnectionError as exc:
        _log(f"WARN: API network error: {exc}")
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


def _summarize_chunk(
    client: genai.Client,
    chunk: str,
    chunk_num: int,
    total_chunks: int,
) -> str | None:
    """Summarize a single diff chunk via the Gemini API.

    Args:
        client: The genai client instance.
        chunk: The diff chunk text to summarize.
        chunk_num: 1-based index of this chunk.
        total_chunks: Total number of chunks being processed.

    Returns:
        str | None: Summary text, or ``None`` on failure.
    """
    chunk_tokens = _count_tokens(client, chunk)
    _progress(
        f"{_GREEN}[{chunk_num}/{total_chunks}]{_RESET} "
        f"Summarizing chunk ({_format_tokens(chunk_tokens)} tokens)...",
        overwrite=False,
    )

    prompt = CHUNK_SUMMARY_PROMPT.format(chunk=chunk)
    result = _generate_content(client, prompt, max_output_tokens=2048)

    if result:
        _progress(
            f"{_GREEN}[{chunk_num}/{total_chunks}]{_RESET} "
            f"Summary received ({len(result)} chars)",
            overwrite=False,
        )
    else:
        _progress(
            f"{_YELLOW}[{chunk_num}/{total_chunks}]{_RESET} "
            f"Summary failed, skipping chunk",
            overwrite=False,
        )

    return result


def _extract_stat_section(diff_input: str) -> tuple[str, str]:
    """Extract the stat section and diff body from combined input.

    The justfile sends input in the format::

        FILES CHANGED:
        <stat output>
        DIFF:
        <diff body>

    Args:
        diff_input: The combined stat + diff input from stdin.

    Returns:
        tuple[str, str]: Tuple of (stat_section, diff_body). If the format
            is not detected, stat_section is empty and diff_body is the
            full input.
    """
    diff_marker = "\nDIFF:\n"
    marker_pos = diff_input.find(diff_marker)
    if marker_pos == -1:
        return "", diff_input

    stat_section = diff_input[:marker_pos]
    stat_section = stat_section.removeprefix("FILES CHANGED:\n")
    diff_body = diff_input[marker_pos + len(diff_marker) :]
    return stat_section, diff_body


def _batch_generate(
    client: genai.Client,
    diff_body: str,
    stat_section: str,
) -> str | None:
    """Generate a commit message using map-reduce batching.

    Splits the diff into chunks, summarizes each chunk separately (with
    cooldown waits between API calls), then combines all summaries into
    a final commit message.

    Args:
        client: The genai client instance.
        diff_body: The diff portion of the input (without stat header).
        stat_section: The ``git diff --stat`` output for full file listing.

    Returns:
        str | None: Generated commit message, or ``None`` on total failure.
    """
    chunks = _split_diff_on_file_boundaries(diff_body, client)
    total_chunks = len(chunks)
    estimated_time = total_chunks * BATCH_COOLDOWN
    _log(
        f"Batch mode: {total_chunks} chunks, "
        f"~{estimated_time // 60}m {estimated_time % 60}s estimated",
    )

    if estimated_time > MAX_BATCH_TIME:
        max_chunks = MAX_BATCH_TIME // BATCH_COOLDOWN
        _log(
            f"Capping at {max_chunks} chunks to stay under "
            f"{MAX_BATCH_TIME // 60}m timeout",
        )
        chunks = chunks[:max_chunks]
        total_chunks = len(chunks)

    summaries: list[str] = []
    start_time = time.monotonic()

    for i, chunk in enumerate(chunks):
        chunk_num = i + 1
        elapsed = time.monotonic() - start_time
        remaining_chunks = total_chunks - chunk_num + 1
        eta = remaining_chunks * BATCH_COOLDOWN
        _progress(
            f"Progress: {_build_progress_bar(i, total_chunks)} "
            f"{chunk_num}/{total_chunks} chunks | "
            f"~{eta // 60}m {eta % 60}s remaining | "
            f"{elapsed:.0f}s elapsed",
            overwrite=False,
        )

        summary = _summarize_chunk(client, chunk, chunk_num, total_chunks)
        if summary:
            summaries.append(f"--- Chunk {chunk_num}/{total_chunks} ---\n{summary}")

        if chunk_num < total_chunks:
            _batch_cooldown_wait(chunk_num, total_chunks)

    _progress(
        f"Progress: {_build_progress_bar(total_chunks, total_chunks)} "
        f"{total_chunks}/{total_chunks} chunks | "
        f"All batches complete",
        overwrite=False,
    )

    if not summaries:
        _log("All chunk summaries failed, cannot generate commit message")
        return None

    _log(f"Collected {len(summaries)}/{total_chunks} summaries, generating final message...")
    _progress(
        f"{_GREEN}[FINAL]{_RESET} Combining {len(summaries)} summaries "
        f"into commit message...",
        overwrite=False,
    )

    combined_summaries = "\n\n".join(summaries)
    reduce_prompt = REDUCE_PROMPT.format(
        stat_section=stat_section,
        summaries=combined_summaries,
    )

    return _generate_content(client, reduce_prompt, max_output_tokens=1024)


def _single_generate(
    client: genai.Client,
    diff_input: str,
    total_tokens: int,
) -> str | None:
    """Generate a commit message in a single API call.

    Used when the diff is small enough to fit within the single-call
    token limit.

    Args:
        client: The genai client instance.
        diff_input: The full diff input (stat + diff body).
        total_tokens: Pre-counted token count of the input.

    Returns:
        str | None: Generated commit message, or ``None`` on failure.
    """
    truncation_notice = ""

    if total_tokens > SINGLE_CALL_TOKEN_LIMIT:
        ratio = SINGLE_CALL_TOKEN_LIMIT / total_tokens
        cut_point = int(len(diff_input) * ratio * 0.95)
        diff_input = diff_input[:cut_point]
        final_tokens = _count_tokens(client, diff_input)
        truncation_notice = (
            f"NOTE: Diff was truncated from {total_tokens:,} to "
            f"{final_tokens:,} tokens. Focus on the visible changes."
        )
        _log(f"Truncated for single call: {total_tokens:,} -> {final_tokens:,} tokens")

    prompt = COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=diff_input,
    )

    _log(f"Calling {API_KEY_MODEL}...")
    return _generate_content(client, prompt)


def main() -> int:
    """Read diff from stdin, generate commit message, print to stdout.

    Routes to single-call or batch mode based on diff size. Diffs under
    900K tokens use a single API call. Larger diffs are split into chunks,
    summarized individually, and combined via a reduce step.

    Returns:
        int: Exit code (0=success, 1=failure).
    """
    diff_input = sys.stdin.read()

    if not diff_input.strip():
        return _fail("No diff input provided on stdin")

    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1").strip()
    if not project:
        return _fail("GOOGLE_CLOUD_PROJECT not set")

    _log(f"Vertex AI: project={project}, location={location}")
    client = genai.Client(vertexai=True, project=project, location=location)

    stat_section, diff_body = _extract_stat_section(diff_input)

    try:
        total_tokens = _count_tokens(client, diff_body)
    except (ClientError, ConnectionError, OSError, ValueError):
        _log(f"WARN: Token counting failed:\n{traceback.format_exc()}")
        total_tokens = len(diff_body) // 4

    _log(f"Diff size: {len(diff_body):,} chars, {total_tokens:,} tokens")

    result: str | None = None

    try:
        if total_tokens <= SINGLE_CALL_TOKEN_LIMIT:
            _log("Using single-call mode")
            result = _single_generate(client, diff_input, total_tokens)
        else:
            _log(
                f"Diff exceeds {SINGLE_CALL_TOKEN_LIMIT:,} token limit, "
                f"using batch mode",
            )
            result = _batch_generate(client, diff_body, stat_section)

            if not result:
                _log("Batch mode failed, falling back to truncated single call")
                result = _single_generate(client, diff_input, total_tokens)
    except (ClientError, ConnectionError, OSError, ValueError):
        _log(f"WARN: Unexpected error:\n{traceback.format_exc()}")
        result = None

    if result:
        _log(f"Generated ({len(result)} chars):")
        _log_message(result)
        print(result)
        return 0

    return _fail("Commit message generation failed")


if __name__ == "__main__":
    sys.exit(main())
