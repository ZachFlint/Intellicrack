#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate git commit messages using the Google Gemini API.

Uses ``GOOGLE_API_KEY`` or ``GEMINI_API_KEY`` from ``.env`` to call the
Gemini API directly. The default model is ``gemini-flash-latest`` which
always resolves to the newest Flash release. Override with the
``GEMINI_COMMIT_MODEL`` env var.

Supports map-reduce batching for diffs that exceed Paid Tier 1 token limits.

The script reads a git diff from stdin and generates a conventional commit
message. For large diffs (>900K tokens), it splits the diff into chunks,
summarizes each chunk separately, then combines summaries into a final
commit message.

Exit codes:
    0 - Success, commit message printed to stdout.
    1 - Error, diagnostic printed to stderr (for caller capture).
"""

from __future__ import annotations

import heapq
import operator
import os
import re
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Final

from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai.errors import ClientError, ServerError


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


_DEFAULT_MODEL: Final[str] = "gemini-flash-latest"
_FALLBACK_MODEL: Final[str] = "gemini-flash-lite-latest"
_GEMINI_COMMIT_MODEL_OVERRIDE: Final[str] = os.environ.get(
    "GEMINI_COMMIT_MODEL",
    "",
)
SINGLE_CALL_TOKEN_LIMIT: Final[int] = 900_000
CHUNK_TOKEN_TARGET: Final[int] = 800_000
MODEL_INPUT_LIMIT: Final[int] = 1_000_000
BATCH_COOLDOWN: Final[int] = 2
GENERATE_MAX_RETRIES: Final[int] = 3
GENERATE_RETRY_BASE_DELAY: Final[float] = 10.0
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

REDUCE_PROMPT: Final[str] = """Below are change summaries from a large diff, followed by the full file list.
The diff was split into {total_chunks} chunks because it is very large ({total_files} files).
Write a thorough, comprehensive commit message that documents every significant change.
Brevity is NOT a virtue here - this diff touches {total_files} files and deserves detailed coverage.

CHANGE SUMMARIES:
{summaries}

FILES CHANGED:
{stat_section}

Write the commit message now. Follow these rules exactly:
- Conventional commit format: type: description
- Subject line under 72 characters
- Developer voice, technical and precise
- Body paragraph(s) after a blank line explaining motivation, scope, and key design decisions.
  Size the body proportionally to the diff:
  * small diff (1-3 chunks): 2-4 sentences
  * medium diff (4-10 chunks): 5-10 sentences across 2-3 paragraphs
  * large diff (11+ chunks): 10-20 sentences across 3-5 paragraphs covering motivation,
    architectural decisions, major subsystems touched, and impact on the codebase
- After the body, add a comprehensive bullet list covering every significant area of change.
  For a diff of {total_chunks} chunks, aim for roughly {min_bullets}-{max_bullets} bullets.
  Each bullet must be specific: name the module, class, function, or concrete behavior.
  Generic bullets like "improved X" or "refactored Y" are forbidden - say what was improved or how.
  Group related bullets together (e.g., all bridge changes, then all GUI changes) for readability.
- Do NOT compress or omit significant areas just to keep the message short.
  If the diff touches 20 subsystems, the bullets should cover all 20.
- Do NOT invent changes that aren't in the summaries.
- Output ONLY the raw commit message text, nothing else.
"""

_CYAN: Final[str] = "\033[36m"
_GREEN: Final[str] = "\033[32m"
_YELLOW: Final[str] = "\033[33m"
_RESET: Final[str] = "\033[0m"


_resolved_model: list[str] = [""]
_resolved_fallback: list[str] = [""]
_resolved_output_limit: list[int] = [0]
_model_log_done: list[bool] = [False]


def _discover_model(
    client: genai.Client,
    candidates: list[str],
) -> str | None:
    """Verify and return the first accessible model from a candidate list.

    Tries each candidate with a ``count_tokens`` call. Returns the first
    model that responds successfully.

    Args:
        client: The genai client instance.
        candidates: Model names to try, in priority order.

    Returns:
        str | None: The first working model name, or ``None`` if all fail.
    """
    for candidate in candidates:
        try:
            client.models.count_tokens(model=candidate, contents="test")
        except (ClientError, ServerError, ConnectionError, OSError, ValueError):
            _log(f"  Model {candidate} listed but not accessible, skipping")
        else:
            return candidate
    return None


def _resolve_models(client: genai.Client) -> tuple[str, str]:
    """Auto-discover the latest working Flash and Flash-Lite models.

    Lists available models, separates into flash and flash-lite groups,
    sorts each by version (highest first), then verifies each candidate.
    Falls back to AI Studio aliases if no working models are found.

    Args:
        client: The genai client instance.

    Returns:
        tuple[str, str]: Tuple of (primary_model, fallback_model).
    """
    try:
        models = list(client.models.list())
    except (ClientError, ServerError, ConnectionError, OSError, ValueError) as exc:
        _log(f"WARN: Model discovery failed: {exc}")
        return _DEFAULT_MODEL, _FALLBACK_MODEL

    flash_models: list[str] = []
    flash_lite_models: list[str] = []
    for m in models:
        name = m.name or ""
        short = name.split("/")[-1]
        if "tts" in short or "audio" in short or "image" in short:
            continue
        if "flash" not in short:
            continue
        if "lite" in short:
            flash_lite_models.append(short)
        else:
            flash_models.append(short)

    def _version_key(name: str) -> tuple[float, int]:
        version_match = re.search(r"gemini-(\d+(?:\.\d+)?)-flash", name)
        version = float(version_match.group(1)) if version_match else 0.0
        is_preview = 1 if "preview" in name else 0
        return (version, -is_preview)

    flash_models.sort(key=_version_key, reverse=True)
    flash_lite_models.sort(key=_version_key, reverse=True)

    primary = _discover_model(client, flash_models)
    secondary = _discover_model(client, flash_lite_models)

    resolved_primary = primary or _DEFAULT_MODEL
    resolved_secondary = secondary or _FALLBACK_MODEL
    _log(f"Discovered model: {resolved_primary}")
    _log(f"Discovered model: {resolved_secondary}")
    return resolved_primary, resolved_secondary


def _get_model(client: genai.Client | None = None) -> str:
    """Return the primary model name for API calls.

    If ``GEMINI_COMMIT_MODEL`` env var is set, uses that. Otherwise,
    for Vertex AI clients, auto-discovers the latest flash model since
    Vertex AI doesn't support ``*-latest`` aliases. For AI Studio
    clients, uses ``gemini-flash-latest``.

    Args:
        client: Optional genai client for model discovery.

    Returns:
        str: The model identifier to use for API calls.
    """
    if _GEMINI_COMMIT_MODEL_OVERRIDE:
        return _GEMINI_COMMIT_MODEL_OVERRIDE

    if _resolved_model[0]:
        return _resolved_model[0]

    if client is not None:
        api_client = getattr(client, "_api_client", None)
        is_vertex = bool(
            getattr(client, "vertexai", False)
            or getattr(api_client, "vertexai", False),
        )

        if is_vertex:
            primary, fallback = _resolve_models(client)
            _resolved_model[0] = primary
            _resolved_fallback[0] = fallback
            return primary

    return _DEFAULT_MODEL


def _get_max_output_tokens(client: genai.Client | None = None) -> int:
    """Return the model's maximum output token limit.

    Queries the model info on first call and caches the result. Falls
    back to 65536 if the model info is unavailable.

    Args:
        client: Optional genai client for querying model info.

    Returns:
        int: Maximum output tokens the model supports.
    """
    if _resolved_output_limit[0] > 0:
        return _resolved_output_limit[0]

    if client is not None:
        model_name = _get_model(client)
        try:
            model_info = client.models.get(model=model_name)
            limit = getattr(model_info, "output_token_limit", None)
            if limit and limit > 0:
                _resolved_output_limit[0] = limit
                _log(f"Model output token limit: {_format_tokens(limit)}")
                return limit
        except (ClientError, ServerError, ConnectionError, OSError, ValueError):
            _log("WARN: Could not query model output limit, using 65536")

    _resolved_output_limit[0] = 65536
    return 65536


def _get_fallback_model() -> str:
    """Return the fallback model name for retry attempts.

    Returns the auto-discovered flash-lite model, or the AI Studio
    ``gemini-flash-lite-latest`` alias if discovery hasn't run.

    Returns:
        str: The fallback model identifier.
    """
    return _resolved_fallback[0] or _FALLBACK_MODEL


_HTTP_TIMEOUT_MS: Final[int] = 120_000


def _create_client() -> genai.Client:
    """Create a Gemini API client, preferring Vertex AI for free credits.

    Checks ``GOOGLE_CLOUD_PROJECT`` first to use Vertex AI with
    subscription credits. Falls back to API key if no project is
    configured. Sets a 120-second HTTP timeout so blocking API calls
    return control to Python periodically, allowing Ctrl+C to interrupt.

    Returns:
        genai.Client: Configured Gemini API client.

    Raises:
        ApiKeyError: If no Vertex AI project or API key is configured.
    """
    http_options = types.HttpOptions(timeout=_HTTP_TIMEOUT_MS)

    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1").strip()
    if project:
        _log(f"Using Vertex AI: project={project}, location={location}")
        return genai.Client(
            vertexai=True,
            project=project,
            location=location,
            http_options=http_options,
        )

    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if api_key:
        _log("Using Gemini API key")
        return genai.Client(api_key=api_key, http_options=http_options)

    msg = "Set GOOGLE_API_KEY, GEMINI_API_KEY, or GOOGLE_CLOUD_PROJECT in .env"
    raise ApiKeyError(msg)


_CLEAR_LINE: Final[str] = "\r\033[2K"


def _log(msg: str) -> None:
    """Write a diagnostic line to stderr, clearing any active progress line.

    Args:
        msg: The diagnostic message to write.
    """
    print(f"{_CLEAR_LINE}[commit-msg] {msg}", file=sys.stderr, flush=True)


def _progress(msg: str, *, overwrite: bool = True) -> None:
    r"""Write a live-updating progress line to stderr.

    Uses ANSI ``\033[2K`` to erase the full terminal line before writing,
    which correctly handles strings with embedded color escape codes
    (which would break naive space-padding).

    Args:
        msg: The progress message to display.
        overwrite: If True, use carriage return to overwrite the current line.
    """
    end = "\r" if overwrite else "\n"
    print(f"{_CLEAR_LINE}[commit-msg] {msg}", file=sys.stderr, end=end, flush=True)


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
    """Write the full commit message to stderr in cyan with clear borders.

    Args:
        msg: The complete commit message to display.
    """
    border = "=" * 72
    print(f"[commit-msg] {border}", file=sys.stderr, flush=True)
    for line in msg.splitlines():
        print(
            f"[commit-msg] {_CYAN}{line}{_RESET}",
            file=sys.stderr,
            flush=True,
        )
    print(f"[commit-msg] {border}", file=sys.stderr, flush=True)


def _estimate_tokens(text: str) -> int:
    """Estimate token count from character length without an API call.

    Uses a ~3 chars/token heuristic which is conservative to ensure
    oversized files always trigger sub-splitting.

    Args:
        text: Text to estimate tokens for.

    Returns:
        int: Estimated token count.
    """
    return len(text) // 3


_last_count_time: list[float] = [0.0]
_COUNT_TOKENS_INTERVAL: Final[float] = 0.5


def _count_tokens(client: genai.Client, text: str) -> int:
    """Count tokens for the given text using the Gemini tokenizer.

    Calls are throttled to avoid 503 errors from rapid-fire requests.
    Falls back to a character-based estimate if the API call fails.

    Args:
        client: The genai client instance.
        text: Text to count tokens for.

    Returns:
        int: Number of tokens in the text (exact or estimated).
    """
    now = time.monotonic()
    elapsed = now - _last_count_time[0]
    if elapsed < _COUNT_TOKENS_INTERVAL:
        time.sleep(_COUNT_TOKENS_INTERVAL - elapsed)
    _last_count_time[0] = time.monotonic()

    try:
        response = client.models.count_tokens(
            model=_get_model(client),
            contents=text,
        )
    except (ClientError, ServerError) as exc:
        exc_str = str(exc)
        if "too large" in exc_str.lower():
            est = _estimate_tokens(text)
            _log(f"WARN: Text too large for token count API, estimate={_format_tokens(est)}")
            return est
        _log(f"WARN: Token count API error, using estimate: {exc}")
        return _estimate_tokens(text)
    except ConnectionError:
        _log("WARN: Token count network error, using estimate")
        return _estimate_tokens(text)
    except (OSError, ValueError, RuntimeError):
        _log("WARN: Token count failed, using estimate")
        return _estimate_tokens(text)
    if response.total_tokens is None:
        return _estimate_tokens(text)
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
            f"[{chunk_num}/{total_chunks}] Next batch in: {bar} {remaining}s",
        )
        time.sleep(1)
    _progress(
        f"[{chunk_num}/{total_chunks}] Batch ready",
        overwrite=False,
    )


def _max_chars_per_piece() -> int:
    """Return max characters per sub-piece to guarantee under token target.

    Uses 2 chars/token worst case (dense JSON/SARIF), so ``CHUNK_TOKEN_TARGET``
    tokens corresponds to at most ``CHUNK_TOKEN_TARGET * 2`` characters.

    Returns:
        int: Maximum characters per sub-piece.
    """
    return CHUNK_TOKEN_TARGET * 2


def _split_text_by_lines(text: str, max_chars: int) -> list[str]:
    """Split text into pieces of at most ``max_chars`` on line boundaries.

    When a single line exceeds ``max_chars``, that line is hard-split at
    character boundaries to guarantee the limit.

    Args:
        text: The text to split.
        max_chars: Maximum characters per resulting piece.

    Returns:
        list[str]: Pieces, each at most ``max_chars`` characters.
    """
    if len(text) <= max_chars:
        return [text]

    pieces: list[str] = []
    current: list[str] = []
    current_size = 0

    for line in text.splitlines(keepends=True):
        if len(line) > max_chars:
            if current_size > 0:
                pieces.append("".join(current))
                current = []
                current_size = 0
            pieces.extend(
                line[start : start + max_chars]
                for start in range(0, len(line), max_chars)
            )
            continue

        if current_size + len(line) > max_chars and current_size > 0:
            pieces.append("".join(current))
            current = []
            current_size = 0

        current.append(line)
        current_size += len(line)

    if current_size > 0:
        pieces.append("".join(current))

    return pieces


def _subsplit_large_file_diff(file_diff: str) -> list[str]:
    """Split an oversized single-file diff into sub-chunks deterministically.

    Uses character-based splitting (no API calls) to guarantee each sub-chunk
    is under ``_max_chars_per_piece()`` characters, which at 2 chars/token
    worst case guarantees tokens under ``CHUNK_TOKEN_TARGET``.

    Prefers hunk boundaries, falls back to line boundaries within oversized
    hunks, and hard-splits lines that individually exceed the limit.

    Args:
        file_diff: The unified diff for a single file.

    Returns:
        list[str]: Sub-chunks, each under the character target.
    """
    max_chars = _max_chars_per_piece()
    if len(file_diff) <= max_chars:
        return [file_diff]

    hunk_pattern = re.compile(r"^@@\s", re.MULTILINE)
    hunk_positions = [m.start() for m in hunk_pattern.finditer(file_diff)]

    if not hunk_positions:
        pieces = _split_text_by_lines(file_diff, max_chars)
        _log(f"  Sub-split oversized file into {len(pieces)} line-based pieces")
        return pieces

    file_header = file_diff[: hunk_positions[0]]
    header_size = len(file_header)

    hunks: list[str] = []
    for idx, pos in enumerate(hunk_positions):
        end = hunk_positions[idx + 1] if idx + 1 < len(hunk_positions) else len(file_diff)
        hunks.append(file_diff[pos:end])

    sub_chunks: list[str] = []
    current_hunks: list[str] = []
    current_size = header_size

    for hunk in hunks:
        if header_size + len(hunk) > max_chars:
            if current_hunks:
                sub_chunks.append(file_header + "".join(current_hunks))
                current_hunks = []
                current_size = header_size
            hunk_budget = max(max_chars - header_size, 1)
            big_pieces = _split_text_by_lines(hunk, hunk_budget)
            sub_chunks.extend(file_header + piece for piece in big_pieces)
            continue

        if current_size + len(hunk) > max_chars and current_hunks:
            sub_chunks.append(file_header + "".join(current_hunks))
            current_hunks = []
            current_size = header_size

        current_hunks.append(hunk)
        current_size += len(hunk)

    if current_hunks:
        sub_chunks.append(file_header + "".join(current_hunks))

    _log(f"  Sub-split oversized file into {len(sub_chunks)} hunk-based pieces")
    return sub_chunks or [file_diff]


def _split_diff_on_file_boundaries(diff_input: str) -> list[str]:
    """Split a unified diff into balanced, size-bounded chunks.

    Uses deterministic character-based splitting (no API calls during split).
    Files over ``_max_chars_per_piece()`` are sub-split on hunk/line
    boundaries. Pieces are then LPT bin-packed by character count into
    roughly equal chunks, each guaranteed under ``CHUNK_TOKEN_TARGET``
    tokens (at 2 chars/token worst case).

    Args:
        diff_input: The full unified diff string.

    Returns:
        list[str]: Balanced diff chunks, each under the token target.
    """
    file_diffs = re.split(r"(?=^diff --git )", diff_input, flags=re.MULTILINE)
    file_diffs = [fd for fd in file_diffs if fd.strip()]

    if not file_diffs:
        return [diff_input]

    max_chars = _max_chars_per_piece()
    file_groups: list[list[tuple[str, int]]] = []
    for fd in file_diffs:
        if len(fd) > max_chars:
            file_groups.append(
                [(sub, len(sub)) for sub in _subsplit_large_file_diff(fd)],
            )
        else:
            file_groups.append([(fd, len(fd))])

    total_chars = sum(sum(p[1] for p in g) for g in file_groups)
    total_pieces = sum(len(g) for g in file_groups)
    num_chunks = max(1, -(-total_chars // max_chars))
    num_chunks = min(num_chunks, total_pieces)

    file_groups.sort(key=lambda g: sum(p[1] for p in g), reverse=True)

    _log(
        f"  Packing {total_pieces} pieces from {len(file_groups)} files "
        f"({sum(1 for g in file_groups if len(g) > 1)} sub-split) "
        f"({total_chars:,} chars) into {num_chunks} bins "
        f"(~{total_chars // num_chunks:,} chars each)",
    )

    bins: list[tuple[int, int, list[str]]] = [
        (0, i, []) for i in range(num_chunks)
    ]
    heapq.heapify(bins)

    for group in file_groups:
        group_size = sum(p[1] for p in group)
        bin_chars, bin_idx, bin_pieces = heapq.heappop(bins)

        if bin_chars + group_size <= max_chars:
            bin_pieces.extend(p[0] for p in group)
            heapq.heappush(bins, (bin_chars + group_size, bin_idx, bin_pieces))
        else:
            heapq.heappush(bins, (bin_chars, bin_idx, bin_pieces))
            for piece_text, piece_size in sorted(
                group, key=operator.itemgetter(1), reverse=True,
            ):
                b_chars, b_idx, b_pieces = heapq.heappop(bins)
                b_pieces.append(piece_text)
                heapq.heappush(bins, (b_chars + piece_size, b_idx, b_pieces))

    chunks = [
        "".join(bp) for _, _, bp in sorted(bins, key=operator.itemgetter(1)) if bp
    ]

    _progress(
        f"Split complete: {len(chunks)} chunks from {len(file_diffs)} files",
        overwrite=False,
    )
    return chunks


def _parse_retry_delay(error_text: str) -> float:
    """Extract the retry delay from a Gemini 429 error message.

    Parses the ``retryDelay`` field from the error JSON. Falls back to
    ``GENERATE_RETRY_BASE_DELAY`` if the delay cannot be parsed.

    Args:
        error_text: The stringified error message from the API.

    Returns:
        float: Number of seconds to wait before retrying.
    """
    match = re.search(r"[Rr]etry\s*(?:[Ii]n\s+|[Dd]elay['\"]?:\s*['\"]?)(\d+(?:\.\d+)?)\s*s", error_text)
    if match:
        return float(match.group(1)) + 1.0
    return GENERATE_RETRY_BASE_DELAY


def _generate_content(
    client: genai.Client,
    prompt: str,
    max_output_tokens: int = 0,
    model: str = "",
) -> str | None:
    """Call ``generate_content`` with standard error handling.

    Uses ``thinking_level=LOW`` for Gemini 3 models. The
    ``max_output_tokens`` parameter caps thinking + output combined
    (confirmed Gemini API behavior), so it defaults to the model's
    full output limit to avoid truncating visible output.

    Args:
        client: The genai client instance.
        prompt: The prompt to send.
        max_output_tokens: Maximum tokens in the response (includes thinking).
            Defaults to the model's full output limit when 0.
        model: Optional model override. When empty, uses the resolved
            primary model from ``_get_model(client)``.

    Returns:
        str | None: Generated text, or ``None`` on failure.

    Raises:
        CommitMessageError: If the monthly spending cap is exceeded.
    """
    if max_output_tokens <= 0:
        max_output_tokens = _get_max_output_tokens(client)

    effective_model = model or _get_model(client)
    response = None
    for attempt in range(1, GENERATE_MAX_RETRIES + 1):
        try:
            response = client.models.generate_content(
                model=effective_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=max_output_tokens,
                    thinking_config=types.ThinkingConfig(
                        thinking_level=types.ThinkingLevel.LOW,
                    ),
                ),
            )
            break
        except ClientError as exc:
            exc_str = str(exc)
            if "spending cap" in exc_str:
                _log(f"FATAL: Monthly spending cap exceeded: {exc}")
                msg = "Monthly spending cap exceeded"
                raise CommitMessageError(msg) from exc
            if "429" in exc_str and attempt < GENERATE_MAX_RETRIES:
                delay = _parse_retry_delay(exc_str)
                _log(f"WARN: Rate limited (attempt {attempt}/{GENERATE_MAX_RETRIES}), retrying in {delay:.0f}s")
                time.sleep(delay)
                continue
            _log(f"WARN: API client error: {exc}")
            return None
        except ServerError:
            if attempt < GENERATE_MAX_RETRIES:
                delay = GENERATE_RETRY_BASE_DELAY * attempt
                _log(f"WARN: API server error (attempt {attempt}/{GENERATE_MAX_RETRIES}), retrying in {delay:.0f}s")
                time.sleep(delay)
            else:
                _log(f"WARN: API server error (attempt {attempt}/{GENERATE_MAX_RETRIES}), giving up")
                return None
        except ConnectionError:
            if attempt < GENERATE_MAX_RETRIES:
                delay = GENERATE_RETRY_BASE_DELAY * attempt
                _log(f"WARN: Network error (attempt {attempt}/{GENERATE_MAX_RETRIES}), retrying in {delay:.0f}s")
                time.sleep(delay)
            else:
                _log(f"WARN: Network error (attempt {attempt}/{GENERATE_MAX_RETRIES}), giving up")
                return None

    if response is None:
        return None

    if not _model_log_done[0]:
        _model_log_done[0] = True
        model_version = getattr(response, "model_version", "")
        if model_version:
            _log(f"Resolved model: {model_version}")

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
        f"{_GREEN}[{chunk_num}/{total_chunks}]{_RESET} Summarizing chunk ({_format_tokens(chunk_tokens)} tokens)...",
        overwrite=False,
    )

    prompt = CHUNK_SUMMARY_PROMPT.format(chunk=chunk)
    result = _generate_content(client, prompt, model=_get_fallback_model())

    if result:
        _progress(
            f"{_GREEN}[{chunk_num}/{total_chunks}]{_RESET} Summary received ({len(result)} chars)",
            overwrite=False,
        )
    else:
        _progress(
            f"{_YELLOW}[{chunk_num}/{total_chunks}]{_RESET} Summary failed, skipping chunk",
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
    chunks = _split_diff_on_file_boundaries(diff_body)
    total_chunks = len(chunks)
    estimated_time = total_chunks * (15 + BATCH_COOLDOWN)
    _log(
        f"Batch mode: {total_chunks} chunks, "
        f"~{estimated_time // 60}m {estimated_time % 60}s estimated",
    )
    _log(
        f"Chunk summaries via {_get_fallback_model()}, "
        f"final reduce via {_get_model(client)}",
    )

    summaries: list[str] = []
    start_time = time.monotonic()
    ticker_stop = threading.Event()

    def _tick_elapsed(
        chunk_num: int,
        total: int,
        completed: int,
        stop: threading.Event,
    ) -> None:
        while not stop.is_set():
            elapsed = time.monotonic() - start_time
            avg = elapsed / max(completed, 1)
            remaining = total - chunk_num
            eta = int(remaining * avg) if completed > 0 else remaining * 15
            _progress(
                f"Progress: {_build_progress_bar(chunk_num - 1, total)} "
                f"{chunk_num}/{total} chunks | "
                f"~{eta // 60}m {eta % 60}s remaining | "
                f"{elapsed:.0f}s elapsed",
            )
            stop.wait(1.0)

    for i, chunk in enumerate(chunks):
        chunk_num = i + 1

        ticker_stop.clear()
        ticker = threading.Thread(
            target=_tick_elapsed,
            args=(chunk_num, total_chunks, i, ticker_stop),
            daemon=True,
        )
        ticker.start()

        summary = _summarize_chunk(client, chunk, chunk_num, total_chunks)

        ticker_stop.set()
        ticker.join()

        if summary:
            summaries.append(f"--- Chunk {chunk_num}/{total_chunks} ---\n{summary}")

        if chunk_num < total_chunks:
            _batch_cooldown_wait(chunk_num, total_chunks)

    _progress(
        f"Progress: {_build_progress_bar(total_chunks, total_chunks)} {total_chunks}/{total_chunks} chunks | All batches complete",
        overwrite=False,
    )

    if not summaries:
        _log("All chunk summaries failed, cannot generate commit message")
        return None

    _log(f"Collected {len(summaries)}/{total_chunks} summaries, generating final message...")

    combined_summaries = "\n\n".join(summaries)
    _log(f"  Summaries: {len(combined_summaries):,} chars across {len(summaries)} entries")
    if combined_summaries:
        preview = combined_summaries[:300].replace("\n", " ")
        _log(f"  Preview: {preview}...")

    reduce_prompt = REDUCE_PROMPT.format(
        stat_section=stat_section,
        summaries=combined_summaries,
        total_chunks=total_chunks,
        total_files=diff_body.count("diff --git "),
        min_bullets=max(8, total_chunks * 2),
        max_bullets=max(16, total_chunks * 4),
    )
    reduce_tokens = _count_tokens(client, reduce_prompt)
    _log(f"  Reduce prompt: {len(reduce_prompt):,} chars, {_format_tokens(reduce_tokens)} tokens")

    _progress(
        f"{_GREEN}[FINAL]{_RESET} Combining {len(summaries)} summaries into commit message...",
        overwrite=False,
    )

    return _generate_content(client, reduce_prompt)


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
        truncation_notice = f"NOTE: Diff was truncated from {total_tokens:,} to {final_tokens:,} tokens. Focus on the visible changes."
        _log(f"Truncated for single call: {total_tokens:,} -> {final_tokens:,} tokens")

    prompt = COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=diff_input,
    )

    _log(f"Calling {_get_model(client)}...")
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

    try:
        client = _create_client()
    except ApiKeyError as exc:
        return _fail(str(exc))

    _log(f"Model: {_get_model(client)}")

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
                f"Diff exceeds {SINGLE_CALL_TOKEN_LIMIT:,} token limit, using batch mode",
            )
            result = _batch_generate(client, diff_body, stat_section)

            if not result:
                _log("Batch mode failed, falling back to truncated single call")
                result = _single_generate(client, diff_input, total_tokens)
    except CommitMessageError as exc:
        return _fail(str(exc))
    except (ClientError, ConnectionError, OSError, ValueError):
        _log(f"WARN: Unexpected error:\n{traceback.format_exc()}")
        result = None

    if result:
        _log(f"Generated ({len(result)} chars):")
        _log_message(result)
        print(result)
        return 0

    return _fail("Commit message generation failed")


create_client = _create_client
get_model = _get_model
extract_stat_section = _extract_stat_section
count_tokens = _count_tokens
single_generate = _single_generate
batch_generate = _batch_generate


if __name__ == "__main__":
    sys.exit(main())
