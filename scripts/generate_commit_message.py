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
import itertools
import json
import math
import operator
import os
import re
import statistics
import sys
import threading
import time
import traceback
from abc import ABC, abstractmethod
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, Self, cast, override

from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai.errors import ClientError, ServerError


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence
    from types import TracebackType


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
_LATENCY_STORE_PATH: Final[Path] = Path(__file__).resolve().parent / ".cache" / "commit_msg_latency.json"
_LATENCY_STORE_VERSION: Final[int] = 1
_LATENCY_HISTORY_LIMIT: Final[int] = 48
_PRIOR_CALL_OVERHEAD_SECONDS: Final[float] = 1.5
_PRIOR_PREFILL_TOKENS_PER_SECOND: Final[float] = 60_000.0
_PRIOR_DECODE_CHARS_PER_SECOND: Final[float] = 900.0
_PRIOR_COUNT_OVERHEAD_SECONDS: Final[float] = 0.8
_PRIOR_COUNT_CHARS_PER_SECOND: Final[float] = 4_000_000.0
_DIFF_CHARS_PER_TOKEN: Final[float] = 3.0
_PROSE_CHARS_PER_TOKEN: Final[float] = 4.0
_RESIDUAL_TAIL_FRACTION: Final[float] = 0.15
_LIVE_RATE_SETTLE_SECONDS: Final[float] = 8.0
_MIN_DECODE_SECONDS: Final[float] = 0.5
_MIN_CURVE_VALUE: Final[float] = 1e-6
_DRIFT_PRIOR_WEIGHT: Final[float] = 1.0
_ETA_TICK_SECONDS: Final[float] = 1.0
_PROGRESS_RESOLUTION: Final[int] = 1000


class _CallKind(StrEnum):
    """Category of timed API call, used to select calibration samples."""

    COUNT = "count"
    SUMMARY = "summary"
    REDUCE = "reduce"
    SINGLE = "single"


class _Metric(StrEnum):
    """Quantity a latency curve predicts from a call's input size."""

    FIRST_OUTPUT = "first_output"
    OUTPUT = "output"
    DURATION = "duration"


_PRIOR_OUTPUT_CHARS: Final[dict[_CallKind, float]] = {
    _CallKind.SUMMARY: 25_000.0,
    _CallKind.REDUCE: 12_000.0,
    _CallKind.SINGLE: 1_500.0,
}

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
            getattr(client, "vertexai", False) or getattr(api_client, "vertexai", False),
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
_output_lock: Final[threading.Lock] = threading.Lock()


def _log(msg: str) -> None:
    """Write a diagnostic line to stderr, clearing any active progress line.

    Args:
        msg: The diagnostic message to write.
    """
    with _output_lock:
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
    with _output_lock:
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
    with _output_lock:
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
    """Wait between batches while the live ETA line shows the countdown.

    Args:
        chunk_num: The chunk number just completed.
        total_chunks: Total number of chunks to process.
    """
    time.sleep(BATCH_COOLDOWN)
    _progress(
        f"[{chunk_num}/{total_chunks}] Batch ready",
        overwrite=False,
    )


def _format_duration(seconds: float, *, round_up: bool = True) -> str:
    """Format a duration as whole minutes and zero-padded seconds.

    Args:
        seconds: Duration in seconds; negative values clamp to zero.
        round_up: Round partial seconds up, as suits a countdown; when
            ``False`` they are truncated, as suits an elapsed clock.

    Returns:
        str: Duration string like ``1m 05s``.
    """
    whole = max(0, math.ceil(seconds) if round_up else math.floor(seconds))
    return f"{whole // 60}m {whole % 60:02d}s"


def _as_measure(value: object) -> float | None:
    """Return ``value`` as a finite non-negative float, or ``None``.

    Args:
        value: A decoded JSON value.

    Returns:
        float | None: The measurement, or ``None`` when it is not a
            finite, non-negative real number.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0.0 else None


@dataclass(frozen=True, slots=True)
class _CallProfile:
    """Identity of a timed call: what kind of call and which model served it."""

    kind: _CallKind
    model: str


@dataclass(frozen=True, slots=True)
class _CallSample:
    """One measured API call used to calibrate the latency model.

    ``input_size`` is prompt tokens for generation calls and characters for
    token-count calls. ``first_token_seconds`` is the time from request to
    the first streamed text, covering upload, prefill, and thinking.
    """

    kind: _CallKind
    model: str
    input_size: int
    output_chars: int
    first_token_seconds: float
    total_seconds: float

    def to_json(self) -> dict[str, str | int | float]:
        """Serialize the sample for the calibration store.

        Returns:
            dict[str, str | int | float]: JSON-compatible mapping.
        """
        return {
            "kind": self.kind.value,
            "model": self.model,
            "input_size": self.input_size,
            "output_chars": self.output_chars,
            "first_token_seconds": self.first_token_seconds,
            "total_seconds": self.total_seconds,
        }

    @classmethod
    def from_json(cls, entry: object) -> Self | None:
        """Decode a stored sample, rejecting malformed or inconsistent entries.

        Args:
            entry: A decoded JSON value from the calibration store.

        Returns:
            Self | None: The sample, or ``None`` when ``entry`` is invalid.
        """
        if not isinstance(entry, dict):
            return None
        fields = cast("dict[str, object]", entry)
        kind = fields.get("kind")
        model = fields.get("model")
        if not isinstance(kind, str) or not isinstance(model, str) or kind not in _CallKind.__members__.values():
            return None
        input_size = _as_measure(fields.get("input_size"))
        output_chars = _as_measure(fields.get("output_chars"))
        first_token = _as_measure(fields.get("first_token_seconds"))
        total = _as_measure(fields.get("total_seconds"))
        if input_size is None or output_chars is None or first_token is None or total is None or first_token > total:
            return None
        return cls(_CallKind(kind), model, round(input_size), round(output_chars), first_token, total)


def _decode_samples(raw: object) -> list[_CallSample]:
    """Decode the calibration store document into samples.

    Args:
        raw: The parsed JSON document.

    Returns:
        list[_CallSample]: Valid samples; empty when the document has an
            unknown version or shape.
    """
    if not isinstance(raw, dict):
        return []
    document = cast("dict[str, object]", raw)
    entries = document.get("samples")
    if document.get("version") != _LATENCY_STORE_VERSION or not isinstance(entries, list):
        return []
    decoded = (_CallSample.from_json(entry) for entry in cast("list[object]", entries))
    return [sample for sample in decoded if sample is not None]


def _theil_sen(points: Sequence[tuple[float, float]]) -> tuple[float, float] | None:
    """Fit a non-negative line with the outlier-robust Theil-Sen estimator.

    Args:
        points: ``(x, y)`` observations.

    Returns:
        tuple[float, float] | None: ``(intercept, slope)``, or ``None`` when
            the points do not span at least two distinct ``x`` values or the
            fit degenerates to zero.
    """
    slopes = [(y2 - y1) / (x2 - x1) for (x1, y1), (x2, y2) in itertools.combinations(points, 2) if x2 != x1]
    if not slopes:
        return None
    slope = max(0.0, statistics.median(slopes))
    intercept = max(0.0, statistics.median([y - slope * x for x, y in points]))
    if slope <= 0.0 and intercept <= 0.0:
        return None
    return intercept, slope


@dataclass(frozen=True, slots=True)
class _Curve:
    """Linear size-to-latency curve plus empirical residual ratios.

    ``ratios`` holds ``actual / predicted`` for every calibration sample, so
    the curve can return the conditional mean of the outcome given how much
    of it has already been observed rather than a fixed point estimate.
    """

    intercept: float
    slope: float
    ratios: tuple[float, ...]

    def at(self, x: float) -> float:
        """Return the curve's typical value at ``x``.

        Args:
            x: Input size.

        Returns:
            float: ``intercept + slope * x``.
        """
        return self.intercept + self.slope * x

    def expected(self, x: float, observed: float = 0.0) -> float:
        """Return the expected final value given ``observed`` so far.

        Averages the historical outcomes that reached at least the observed
        fraction of the prediction, so a call already running long is
        forecast from calls that also ran long. When nothing in history ran
        that long, the observed value is stretched by the residual tail.

        Args:
            x: Input size.
            observed: Portion of the quantity already observed.

        Returns:
            float: Expected total, never below ``observed``.
        """
        base = max(self.at(x), _MIN_CURVE_VALUE)
        stretched = observed * (1.0 + _RESIDUAL_TAIL_FRACTION)
        if not self.ratios:
            return max(base, stretched)
        progress = observed / base
        tail = [ratio for ratio in self.ratios if ratio >= progress]
        return base * statistics.fmean(tail) if tail else stretched


def _fit_curve(
    points: Sequence[tuple[float, float]],
    prior_intercept: float,
    prior_slope: float,
) -> _Curve:
    """Fit a curve to observations, falling back to a scaled prior.

    With two or more distinct input sizes a Theil-Sen line is fitted. With
    fewer, the prior line is rescaled by the median observed-to-prior ratio
    so even a single sample calibrates the forecast.

    Args:
        points: ``(x, y)`` observations.
        prior_intercept: Intercept used before calibration.
        prior_slope: Slope used before calibration.

    Returns:
        _Curve: The fitted curve with residual ratios for each observation.
    """
    fit = _theil_sen(points)
    if fit is None:
        scale = statistics.median([y / (prior_intercept + prior_slope * x) for x, y in points]) if points else 1.0
        if scale <= 0.0:
            scale = 1.0
        fit = (prior_intercept * scale, prior_slope * scale)
    intercept, slope = fit
    line = _Curve(intercept, slope, ())
    ratios = tuple(y / line.at(x) for x, y in points if line.at(x) > 0.0)
    return _Curve(intercept, slope, ratios)


class _LatencyModel:
    """Persistent, self-calibrating latency model for Gemini API calls."""

    def __init__(self, store_path: Path, samples: list[_CallSample]) -> None:
        """Initialize the model from previously recorded samples.

        Args:
            store_path: Calibration file to persist to.
            samples: Previously recorded samples.
        """
        self._store_path = store_path
        self._samples = samples
        self._lock = threading.Lock()
        self._curves: dict[tuple[_CallProfile, _Metric], _Curve] = {}
        self._rates: dict[_CallProfile, float] = {}

    @classmethod
    def load(cls) -> Self:
        """Load the in-repo calibration store, tolerating a missing or corrupt file.

        The store lives in the gitignored ``scripts/.cache`` directory, so
        ``git add -A`` never stages it.

        Returns:
            Self: A model seeded with every valid stored sample.
        """
        store_path = _LATENCY_STORE_PATH
        try:
            raw: object = json.loads(store_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls(store_path, [])
        except (OSError, ValueError) as exc:
            _log(f"WARN: Ignoring unreadable latency history {store_path}: {exc}")
            return cls(store_path, [])
        return cls(store_path, _decode_samples(raw))

    def calibration_note(self) -> str:
        """Describe how the current forecast was calibrated.

        Returns:
            str: Human-readable calibration summary.
        """
        with self._lock:
            count = len(self._samples)
        if count == 0:
            return "uncalibrated defaults, refined as calls complete"
        return f"calibrated from {count} recorded calls"

    def record(self, sample: _CallSample) -> None:
        """Add a measured call, trim stale history, and persist the store.

        Args:
            sample: The measured call.
        """
        with self._lock:
            self._samples.append(sample)
            matching = [s for s in self._samples if s.kind is sample.kind and s.model == sample.model]
            for stale in matching[: max(0, len(matching) - _LATENCY_HISTORY_LIMIT)]:
                self._samples.remove(stale)
            self._curves.clear()
            self._rates.clear()
            snapshot = list(self._samples)
        self._persist(snapshot)

    def curve(self, profile: _CallProfile, metric: _Metric) -> _Curve:
        """Return the fitted curve for a call profile and metric.

        Args:
            profile: Kind and model of the call.
            metric: Quantity to predict.

        Returns:
            _Curve: The cached or freshly fitted curve.
        """
        key = (profile, metric)
        with self._lock:
            cached = self._curves.get(key)
            if cached is None:
                cached = self._fit(profile, metric)
                self._curves[key] = cached
            return cached

    def decode_rate(self, profile: _CallProfile) -> float:
        """Return the typical streaming output rate in characters per second.

        Args:
            profile: Kind and model of the call.

        Returns:
            float: Median observed decode rate, or the prior rate.
        """
        with self._lock:
            cached = self._rates.get(profile)
            if cached is None:
                rates = [
                    s.output_chars / (s.total_seconds - s.first_token_seconds)
                    for s in self._similar(profile)
                    if s.output_chars > 0 and s.total_seconds - s.first_token_seconds >= _MIN_DECODE_SECONDS
                ]
                cached = statistics.median(rates) if rates else _PRIOR_DECODE_CHARS_PER_SECOND
                self._rates[profile] = cached
            return cached

    def generation_seconds(self, profile: _CallProfile, input_tokens: float) -> float:
        """Forecast the full duration of a generation call not yet started.

        Args:
            profile: Kind and model of the call.
            input_tokens: Prompt size in tokens.

        Returns:
            float: Expected seconds from request to final streamed text.
        """
        first_token = self.curve(profile, _Metric.FIRST_OUTPUT).expected(input_tokens)
        output_chars = self.curve(profile, _Metric.OUTPUT).expected(input_tokens)
        return first_token + output_chars / self.decode_rate(profile)

    def _similar(self, profile: _CallProfile) -> list[_CallSample]:
        """Return samples for the profile, widening to any model of that kind.

        Args:
            profile: Kind and model of the call.

        Returns:
            list[_CallSample]: Matching samples; caller holds the lock.
        """
        exact = [s for s in self._samples if s.kind is profile.kind and s.model == profile.model]
        return exact or [s for s in self._samples if s.kind is profile.kind]

    def _fit(self, profile: _CallProfile, metric: _Metric) -> _Curve:
        """Fit the curve for a profile and metric from recorded samples.

        Args:
            profile: Kind and model of the call.
            metric: Quantity to predict.

        Returns:
            _Curve: The fitted curve; caller holds the lock.
        """
        samples = self._similar(profile)
        if metric is _Metric.FIRST_OUTPUT:
            return _fit_curve(
                [(float(s.input_size), s.first_token_seconds) for s in samples],
                _PRIOR_CALL_OVERHEAD_SECONDS,
                1.0 / _PRIOR_PREFILL_TOKENS_PER_SECOND,
            )
        if metric is _Metric.OUTPUT:
            return _fit_curve(
                [(float(s.input_size), float(s.output_chars)) for s in samples],
                _PRIOR_OUTPUT_CHARS.get(profile.kind, _PRIOR_OUTPUT_CHARS[_CallKind.SINGLE]),
                0.0,
            )
        return _fit_curve(
            [(float(s.input_size), s.total_seconds) for s in samples],
            _PRIOR_COUNT_OVERHEAD_SECONDS,
            1.0 / _PRIOR_COUNT_CHARS_PER_SECOND,
        )

    def _persist(self, samples: list[_CallSample]) -> None:
        """Atomically write the calibration store.

        Args:
            samples: Samples to persist.
        """
        payload = {"version": _LATENCY_STORE_VERSION, "samples": [s.to_json() for s in samples]}
        staging = self._store_path.with_name(f"{self._store_path.name}.tmp")
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            staging.write_text(json.dumps(payload), encoding="utf-8")
            staging.replace(self._store_path)
        except OSError as exc:
            _log(f"WARN: Could not save latency history to {self._store_path}: {exc}")


class _CallMonitor:
    """Live, thread-safe timing state of one streamed generation call."""

    def __init__(self, latency: _LatencyModel, profile: _CallProfile, input_tokens: float) -> None:
        """Initialize monitoring for a call that is about to start.

        Args:
            latency: Model used to forecast and to record the outcome.
            profile: Kind and model of the call.
            input_tokens: Prompt size in tokens.
        """
        self._latency = latency
        self._profile = profile
        self._input_tokens = input_tokens
        self._lock = threading.Lock()
        self._attempt_started = time.monotonic()
        self._first_output: float | None = None
        self._output_chars = 0
        self._wait_until: float | None = None

    def begin_attempt(self) -> None:
        """Reset timing for a new request attempt."""
        with self._lock:
            self._attempt_started = time.monotonic()
            self._first_output = None
            self._output_chars = 0
            self._wait_until = None

    def begin_wait(self, seconds: float) -> None:
        """Record that the call is sleeping before a retry.

        Args:
            seconds: Retry delay about to be slept.
        """
        with self._lock:
            self._wait_until = time.monotonic() + seconds

    def add_output(self, chars: int) -> None:
        """Account for streamed text, marking the first-token time.

        Args:
            chars: Characters in the streamed piece.
        """
        with self._lock:
            if self._first_output is None:
                self._first_output = time.monotonic()
            self._output_chars += chars

    def complete(self, prompt_tokens: int | None) -> None:
        """Record the successful attempt as a calibration sample.

        Args:
            prompt_tokens: Exact prompt tokens reported by the API, if any.
        """
        finished = time.monotonic()
        with self._lock:
            total = finished - self._attempt_started
            first_token = total if self._first_output is None else self._first_output - self._attempt_started
            chars = self._output_chars
        input_size = prompt_tokens if prompt_tokens is not None and prompt_tokens > 0 else round(self._input_tokens)
        self._latency.record(
            _CallSample(self._profile.kind, self._profile.model, input_size, chars, first_token, total),
        )

    def remaining(self, now: float, drift: float) -> float:
        """Forecast the seconds left in this call from its live state.

        While waiting for the first token, uses the conditional first-token
        expectation given the time already waited. While streaming, blends
        the live output rate with the historical one and projects the
        conditional expected output length given the text already received.

        Args:
            now: Current monotonic time.
            drift: Run-level ratio of actual to forecast durations.

        Returns:
            float: Expected remaining seconds.
        """
        with self._lock:
            started = self._attempt_started
            first_output = self._first_output
            chars = self._output_chars
            wait_until = self._wait_until
        tokens = self._input_tokens
        first_curve = self._latency.curve(self._profile, _Metric.FIRST_OUTPUT)
        output_curve = self._latency.curve(self._profile, _Metric.OUTPUT)
        history_rate = self._latency.decode_rate(self._profile) / drift
        if wait_until is not None:
            fresh = first_curve.expected(tokens) * drift + output_curve.expected(tokens) / history_rate
            return max(0.0, wait_until - now) + fresh
        if first_output is None:
            waited = now - started
            first_left = first_curve.expected(tokens, waited / drift) * drift - waited
            return max(0.0, first_left) + output_curve.expected(tokens) / history_rate
        streaming = max(now - first_output, _MIN_CURVE_VALUE)
        weight = min(1.0, streaming / _LIVE_RATE_SETTLE_SECONDS)
        rate = weight * (chars / streaming) + (1.0 - weight) * history_rate
        return max(0.0, output_curve.expected(tokens, chars) - chars) / max(rate, _MIN_CURVE_VALUE)

    def describe(self, now: float) -> str:
        """Describe the call's current phase for the progress line.

        Args:
            now: Current monotonic time.

        Returns:
            str: Phase description.
        """
        with self._lock:
            started = self._attempt_started
            first_output = self._first_output
            chars = self._output_chars
            wait_until = self._wait_until
        if wait_until is not None:
            return f"retrying in {_format_duration(wait_until - now)}"
        if first_output is None:
            return f"awaiting first token {_format_duration(now - started, round_up=False)}"
        streaming = max(now - first_output, _MIN_CURVE_VALUE)
        return f"streaming {_format_tokens(chars)} chars at {chars / streaming:,.0f}/s"


class _Stage(ABC):
    """One sequential step of a run whose duration is forecast."""

    def __init__(self, label: str, *, is_unit: bool = False, tracks_drift: bool = False) -> None:
        """Initialize the stage.

        Args:
            label: Name shown in the progress line.
            is_unit: Whether completing the stage advances the unit counter.
            tracks_drift: Whether the stage's forecast error calibrates the
                run-level drift factor.
        """
        self.label = label
        self.is_unit = is_unit
        self.tracks_drift = tracks_drift
        self.started_at = 0.0
        self.predicted_at_start = 0.0
        self.actual_seconds = 0.0

    def begin(self, now: float) -> None:
        """Mark the stage as started.

        Args:
            now: Current monotonic time.
        """
        self.started_at = now
        self.predicted_at_start = self.predicted(1.0)

    def finish(self, elapsed: float) -> None:
        """Record the stage's measured duration on successful completion.

        Args:
            elapsed: Seconds the stage took.
        """
        self.actual_seconds = elapsed

    def describe(self, now: float) -> str:
        """Describe the active stage for the progress line.

        Args:
            now: Current monotonic time.

        Returns:
            str: Stage description.
        """
        return f"{self.label} {_format_duration(now - self.started_at, round_up=False)}"

    @abstractmethod
    def predicted(self, drift: float) -> float:
        """Forecast the stage's full duration before it starts.

        Args:
            drift: Run-level ratio of actual to forecast durations.

        Returns:
            float: Expected seconds.
        """

    @abstractmethod
    def remaining(self, now: float, drift: float) -> float:
        """Forecast the seconds left in the active stage.

        Args:
            now: Current monotonic time.
            drift: Run-level ratio of actual to forecast durations.

        Returns:
            float: Expected remaining seconds.
        """


class _SleepStage(_Stage):
    """A fixed-length pause, such as the cooldown between batches."""

    def __init__(self, label: str, seconds: float) -> None:
        """Initialize the pause.

        Args:
            label: Name shown in the progress line.
            seconds: Pause length.
        """
        super().__init__(label)
        self._seconds = seconds

    @override
    def predicted(self, drift: float) -> float:
        """Return the fixed pause length.

        Args:
            drift: Unused; pauses do not drift.

        Returns:
            float: Pause length in seconds.
        """
        return self._seconds

    @override
    def remaining(self, now: float, drift: float) -> float:
        """Return the seconds left in the pause.

        Args:
            now: Current monotonic time.
            drift: Unused; pauses do not drift.

        Returns:
            float: Remaining pause seconds.
        """
        return max(0.0, self._seconds - (now - self.started_at))

    @override
    def describe(self, now: float) -> str:
        """Describe the pause countdown.

        Args:
            now: Current monotonic time.

        Returns:
            str: Countdown description.
        """
        return f"{self.label} in {_format_duration(self.remaining(now, 1.0))}"


class _CountStage(_Stage):
    """A ``count_tokens`` call whose duration scales with uploaded characters."""

    def __init__(
        self,
        label: str,
        latency: _LatencyModel,
        profile: _CallProfile,
        chars: Callable[[], float],
    ) -> None:
        """Initialize the stage.

        Args:
            label: Name shown in the progress line.
            latency: Model used to forecast and to record the outcome.
            profile: Kind and model of the call.
            chars: Returns the current best estimate of the text length.
        """
        super().__init__(label)
        self._latency = latency
        self._profile = profile
        self._chars = chars

    @override
    def predicted(self, drift: float) -> float:
        """Forecast the call's duration from the text length.

        Args:
            drift: Unused; token counting is not a generation call.

        Returns:
            float: Expected seconds.
        """
        return self._latency.curve(self._profile, _Metric.DURATION).expected(self._chars())

    @override
    def remaining(self, now: float, drift: float) -> float:
        """Forecast the seconds left given the time already waited.

        Args:
            now: Current monotonic time.
            drift: Unused; token counting is not a generation call.

        Returns:
            float: Expected remaining seconds.
        """
        waited = now - self.started_at
        return max(0.0, self._latency.curve(self._profile, _Metric.DURATION).expected(self._chars(), waited) - waited)

    @override
    def finish(self, elapsed: float) -> None:
        """Record the measured call.

        Args:
            elapsed: Seconds the call took.
        """
        super().finish(elapsed)
        self._latency.record(
            _CallSample(self._profile.kind, self._profile.model, round(self._chars()), 0, elapsed, elapsed),
        )


class _GenerateStage(_Stage):
    """A streamed generation call monitored live while it runs."""

    def __init__(
        self,
        label: str,
        latency: _LatencyModel,
        profile: _CallProfile,
        input_tokens: Callable[[], float],
        *,
        is_unit: bool = False,
    ) -> None:
        """Initialize the stage.

        Args:
            label: Name shown in the progress line.
            latency: Model used to forecast the call.
            profile: Kind and model of the call.
            input_tokens: Returns the current best estimate of prompt tokens.
            is_unit: Whether completing the stage advances the unit counter.
        """
        super().__init__(label, is_unit=is_unit, tracks_drift=True)
        self._latency = latency
        self._profile = profile
        self._input_tokens = input_tokens
        self.monitor: _CallMonitor | None = None

    @override
    def begin(self, now: float) -> None:
        """Start the stage and attach a live call monitor.

        Args:
            now: Current monotonic time.
        """
        self.monitor = _CallMonitor(self._latency, self._profile, self._input_tokens())
        super().begin(now)

    @override
    def predicted(self, drift: float) -> float:
        """Forecast the call's full duration.

        Args:
            drift: Run-level ratio of actual to forecast durations.

        Returns:
            float: Expected seconds.
        """
        return self._latency.generation_seconds(self._profile, self._input_tokens()) * drift

    @override
    def remaining(self, now: float, drift: float) -> float:
        """Forecast the seconds left from the live call state.

        Args:
            now: Current monotonic time.
            drift: Run-level ratio of actual to forecast durations.

        Returns:
            float: Expected remaining seconds.
        """
        if self.monitor is None:
            return self.predicted(drift)
        return self.monitor.remaining(now, drift)

    @override
    def describe(self, now: float) -> str:
        """Describe the call's live phase.

        Args:
            now: Current monotonic time.

        Returns:
            str: Phase description.
        """
        if self.monitor is None:
            return self.label
        return f"{self.label}: {self.monitor.describe(now)}"


class _EtaPipeline:
    """Forecasts and live-reports the remaining time of a sequence of stages.

    The remaining time is the active stage's live forecast plus the forecasts
    of every stage still pending, scaled by a drift factor learned from how
    far this run's finished generation calls deviated from their forecasts.
    """

    def __init__(self, stages: Sequence[_Stage], unit_name: str) -> None:
        """Initialize the pipeline and compute the up-front forecast.

        Args:
            stages: Stages in execution order.
            unit_name: Plural noun for unit stages in the progress line.
        """
        self._stages = list(stages)
        self._unit_name = unit_name
        self._total_units = sum(1 for stage in self._stages if stage.is_unit)
        self._lock = threading.Lock()
        self._cursor = 0
        self._active: _Stage | None = None
        self._done_units = 0
        self._drift_ratios: list[float] = []
        self._initial_forecast = sum(stage.predicted(1.0) for stage in self._stages)
        self._started_at = time.monotonic()
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None

    def forecast(self) -> float:
        """Return the forecast made before any stage ran.

        Returns:
            float: Expected total seconds.
        """
        return self._initial_forecast

    def __enter__(self) -> Self:
        """Start the live progress ticker.

        Returns:
            Self: The running pipeline.
        """
        self._started_at = time.monotonic()
        self._ticker = threading.Thread(target=self._run_ticker, name="commit-msg-eta", daemon=True)
        self._ticker.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop the ticker and report forecast accuracy on success.

        Args:
            exc_type: Exception type raised in the block, if any.
            exc: Exception raised in the block, if any.
            exc_tb: Traceback of the exception, if any.
        """
        self._stop.set()
        if self._ticker is not None:
            self._ticker.join()
        if exc_type is None:
            elapsed = time.monotonic() - self._started_at
            _log(
                f"Finished in {_format_duration(elapsed, round_up=False)} (forecast {_format_duration(self._initial_forecast)})",
            )

    @contextmanager
    def track[StageT: _Stage](self, stage: StageT) -> Generator[StageT]:
        """Run ``stage`` as the active stage for the duration of the block.

        Args:
            stage: The stage about to run; must be the next pending one.

        Yields:
            StageT: The started stage.
        """
        with self._lock:
            self._cursor = self._stages.index(stage)
            stage.begin(time.monotonic())
            self._active = stage
        completed = False
        try:
            yield stage
            completed = True
        finally:
            self._settle(stage, completed=completed)

    def _settle(self, stage: _Stage, *, completed: bool) -> None:
        """Close out the active stage, learning from it only on success.

        Args:
            stage: The stage that just ended.
            completed: Whether the stage's block finished without raising.
        """
        if completed:
            stage.finish(time.monotonic() - stage.started_at)
        with self._lock:
            if completed and stage.tracks_drift and stage.predicted_at_start > 0.0:
                self._drift_ratios.append(stage.actual_seconds / stage.predicted_at_start)
            if completed and stage.is_unit:
                self._done_units += 1
            self._active = None
            self._cursor += 1

    def _drift(self) -> float:
        """Return the shrunk mean of this run's actual-to-forecast ratios.

        Returns:
            float: Drift factor; ``1.0`` until a generation stage finishes.
        """
        return (sum(self._drift_ratios) + _DRIFT_PRIOR_WEIGHT) / (len(self._drift_ratios) + _DRIFT_PRIOR_WEIGHT)

    def _snapshot(self, now: float) -> tuple[float, str, int]:
        """Compute the current forecast for the progress line.

        Args:
            now: Current monotonic time.

        Returns:
            tuple[float, str, int]: Remaining seconds, active-stage status,
                and completed unit count.
        """
        with self._lock:
            drift = self._drift()
            active = self._active
            pending = self._stages[self._cursor + (1 if active is not None else 0) :]
            active_left = active.remaining(now, drift) if active is not None else 0.0
            status = active.describe(now) if active is not None else "preparing next step"
            remaining = active_left + sum(stage.predicted(drift) for stage in pending)
            return remaining, status, self._done_units

    def _render(self) -> None:
        """Write one live progress line."""
        now = time.monotonic()
        remaining, status, done = self._snapshot(now)
        elapsed = now - self._started_at
        span = elapsed + remaining
        filled = round(elapsed / span * _PROGRESS_RESOLUTION) if span > 0.0 else _PROGRESS_RESOLUTION
        _progress(
            f"Progress: {_build_progress_bar(filled, _PROGRESS_RESOLUTION)} "
            f"{done}/{self._total_units} {self._unit_name} | {status} | "
            f"~{_format_duration(remaining)} remaining | {_format_duration(elapsed, round_up=False)} elapsed",
        )

    def _run_ticker(self) -> None:
        """Refresh the progress line until the pipeline stops."""
        while True:
            self._render()
            if self._stop.wait(_ETA_TICK_SECONDS):
                return


class _BatchForecast:
    """Running knowledge of a batch run used to size calls not yet made."""

    def __init__(
        self,
        latency: _LatencyModel,
        summary_profile: _CallProfile,
        chunks: Sequence[str],
        fixed_reduce_chars: int,
    ) -> None:
        """Initialize the forecast for a set of diff chunks.

        Args:
            latency: Model used to predict summary lengths.
            summary_profile: Kind and model of the chunk summary calls.
            chunks: Diff chunks to be summarized.
            fixed_reduce_chars: Length of the reduce prompt without summaries.
        """
        self._latency = latency
        self._summary_profile = summary_profile
        self._chunk_chars = [len(chunk) for chunk in chunks]
        self._fixed_reduce_chars = fixed_reduce_chars
        self._entry_overhead = len(f"--- Chunk {len(chunks)}/{len(chunks)} ---\n\n\n")
        self._counted: dict[int, int] = {}
        self._summary_chars: dict[int, int] = {}
        self._reduce_prompt_chars: int | None = None
        self._reduce_tokens: int | None = None

    def record_count(self, index: int, tokens: int) -> None:
        """Store a chunk's exact token count.

        Args:
            index: Zero-based chunk index.
            tokens: Counted tokens.
        """
        self._counted[index] = tokens

    def record_summary(self, index: int, chars: int) -> None:
        """Store a chunk summary's length, zero when it failed.

        Args:
            index: Zero-based chunk index.
            chars: Summary length in characters.
        """
        self._summary_chars[index] = chars

    def record_reduce_prompt(self, chars: int) -> None:
        """Store the final reduce prompt's exact length.

        Args:
            chars: Prompt length in characters.
        """
        self._reduce_prompt_chars = chars

    def record_reduce_tokens(self, tokens: int) -> None:
        """Store the final reduce prompt's exact token count.

        Args:
            tokens: Counted tokens.
        """
        self._reduce_tokens = tokens

    def chunk_chars(self, index: int) -> float:
        """Return a chunk's length.

        Args:
            index: Zero-based chunk index.

        Returns:
            float: Chunk length in characters.
        """
        return float(self._chunk_chars[index])

    def chunk_tokens(self, index: int) -> float:
        """Return a chunk's exact or estimated token count.

        Uncounted chunks are estimated from the characters-per-token ratio
        measured on the chunks counted so far.

        Args:
            index: Zero-based chunk index.

        Returns:
            float: Token count.
        """
        counted = self._counted.get(index)
        if counted is not None:
            return float(counted)
        counted_tokens = sum(self._counted.values())
        chars_per_token = sum(self._chunk_chars[i] for i in self._counted) / counted_tokens if counted_tokens > 0 else _DIFF_CHARS_PER_TOKEN
        return self._chunk_chars[index] / chars_per_token

    def summary_chars(self, index: int) -> float:
        """Return a chunk summary's actual or expected length.

        Args:
            index: Zero-based chunk index.

        Returns:
            float: Summary length in characters.
        """
        known = self._summary_chars.get(index)
        if known is not None:
            return float(known)
        return self._latency.curve(self._summary_profile, _Metric.OUTPUT).expected(self.chunk_tokens(index))

    def reduce_chars(self) -> float:
        """Return the reduce prompt's actual or expected length.

        Returns:
            float: Prompt length in characters.
        """
        if self._reduce_prompt_chars is not None:
            return float(self._reduce_prompt_chars)
        total = float(self._fixed_reduce_chars)
        for index in range(len(self._chunk_chars)):
            body = self.summary_chars(index)
            if body > 0.0:
                total += body + self._entry_overhead
        return total

    def reduce_tokens(self) -> float:
        """Return the reduce prompt's exact or estimated token count.

        Returns:
            float: Token count.
        """
        if self._reduce_tokens is not None:
            return float(self._reduce_tokens)
        return self.reduce_chars() / _PROSE_CHARS_PER_TOKEN


@dataclass(frozen=True, slots=True)
class _ChunkPlan:
    """ETA tracking wiring for one chunk's count and summary calls."""

    eta: _EtaPipeline
    forecast: _BatchForecast
    count_stage: _CountStage
    summary_stage: _GenerateStage


@dataclass(frozen=True, slots=True)
class _BatchStages:
    """Every forecast stage of a batch run, grouped by role."""

    counts: tuple[_CountStage, ...]
    summaries: tuple[_GenerateStage, ...]
    cooldowns: tuple[_SleepStage, ...]
    reduce_count: _CountStage
    reduce: _GenerateStage

    def ordered(self) -> list[_Stage]:
        """Return the stages in execution order.

        Returns:
            list[_Stage]: Count, summary, and cooldown per chunk, then the
                reduce count and reduce call.
        """
        ordered: list[_Stage] = []
        for index, (count, summary) in enumerate(zip(self.counts, self.summaries, strict=True)):
            ordered.extend((count, summary))
            if index < len(self.cooldowns):
                ordered.append(self.cooldowns[index])
        ordered.extend((self.reduce_count, self.reduce))
        return ordered


def _plan_batch_stages(
    latency: _LatencyModel,
    forecast: _BatchForecast,
    primary_model: str,
    summary_profile: _CallProfile,
    total_chunks: int,
) -> _BatchStages:
    """Build the forecast stages for a batch run.

    Args:
        latency: Model shared by every stage.
        forecast: Running batch knowledge that sizes each stage.
        primary_model: Model used for token counting and the reduce call.
        summary_profile: Kind and model of the chunk summary calls.
        total_chunks: Number of chunks.

    Returns:
        _BatchStages: Stages grouped by role.
    """
    count_profile = _CallProfile(_CallKind.COUNT, primary_model)
    return _BatchStages(
        counts=tuple(
            _CountStage(f"chunk {i + 1} token count", latency, count_profile, partial(forecast.chunk_chars, i)) for i in range(total_chunks)
        ),
        summaries=tuple(
            _GenerateStage(
                f"chunk {i + 1} summary",
                latency,
                summary_profile,
                partial(forecast.chunk_tokens, i),
                is_unit=True,
            )
            for i in range(total_chunks)
        ),
        cooldowns=tuple(_SleepStage("next batch", BATCH_COOLDOWN) for _ in range(total_chunks - 1)),
        reduce_count=_CountStage("final prompt token count", latency, count_profile, forecast.reduce_chars),
        reduce=_GenerateStage(
            "final commit message",
            latency,
            _CallProfile(_CallKind.REDUCE, primary_model),
            forecast.reduce_tokens,
        ),
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
            pieces.extend(line[start : start + max_chars] for start in range(0, len(line), max_chars))
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

    Splits on ``@@`` hunk boundaries, grouping one or more whole hunks per
    sub-chunk and re-prepending the original ``diff --git`` file header to
    every emitted sub-chunk so each remains a self-describing, applicable
    diff. A single hunk that on its own exceeds the limit is kept intact in
    its own sub-chunk rather than being broken mid-hunk. When the file
    contains no hunk boundaries (only one logical block), the body is split
    on line boundaries and the header is re-prepended to each line piece so
    every piece still identifies its file.

    Args:
        file_diff: The unified diff for a single file.

    Returns:
        list[str]: Sub-chunks, each carrying the file header.
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

    if len(hunks) == 1:
        body_budget = max(1, max_chars - header_size)
        body_pieces = _split_text_by_lines(hunks[0], body_budget)
        sub_chunks = [file_header + piece for piece in body_pieces]
        _log(f"  Sub-split oversized single-hunk file into {len(sub_chunks)} line-based pieces")
        return sub_chunks

    sub_chunks: list[str] = []
    current_hunks: list[str] = []
    current_size = header_size

    for hunk in hunks:
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

    bins: list[tuple[int, int, list[str]]] = [(0, i, []) for i in range(num_chunks)]
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
                group,
                key=operator.itemgetter(1),
                reverse=True,
            ):
                b_chars, b_idx, b_pieces = heapq.heappop(bins)
                b_pieces.append(piece_text)
                heapq.heappush(bins, (b_chars + piece_size, b_idx, b_pieces))

    chunks = ["".join(bp) for _, _, bp in sorted(bins, key=operator.itemgetter(1)) if bp]

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


def _stream_response(
    client: genai.Client,
    request: tuple[str, str, types.GenerateContentConfig],
    text_parts: list[str],
    monitor: _CallMonitor | None,
) -> types.GenerateContentResponse | None:
    """Consume one streamed ``generate_content`` attempt.

    Args:
        client: The genai client instance.
        request: ``(model, prompt, config)`` for the call.
        text_parts: Receives each streamed text piece in order.
        monitor: Optional live monitor fed with streaming progress.

    Returns:
        types.GenerateContentResponse | None: The final streamed chunk, or
            ``None`` when the stream yielded nothing.
    """
    model, prompt, config = request
    final_chunk: types.GenerateContentResponse | None = None
    for piece in client.models.generate_content_stream(model=model, contents=prompt, config=config):
        final_chunk = piece
        piece_text = piece.text
        if piece_text:
            text_parts.append(piece_text)
            if monitor is not None:
                monitor.add_output(len(piece_text))
    return final_chunk


def _wait_for_retry(delay: float, monitor: _CallMonitor | None) -> None:
    """Sleep before a retry, letting the live ETA account for the pause.

    Args:
        delay: Seconds to sleep.
        monitor: Live monitor of the call being retried, if any.
    """
    if monitor is not None:
        monitor.begin_wait(delay)
    time.sleep(delay)


def _generate_content(
    client: genai.Client,
    prompt: str,
    max_output_tokens: int = 0,
    model: str = "",
    monitor: _CallMonitor | None = None,
) -> str | None:
    """Stream ``generate_content`` with standard error handling.

    Uses ``thinking_level=LOW`` for Gemini 3 models. The
    ``max_output_tokens`` parameter caps thinking + output combined
    (confirmed Gemini API behavior), so it defaults to the model's
    full output limit to avoid truncating visible output.

    The response is streamed so ``monitor`` observes when prefill and
    thinking end and how fast text arrives; a successful call is recorded
    as a latency calibration sample.

    Args:
        client: The genai client instance.
        prompt: The prompt to send.
        max_output_tokens: Maximum tokens in the response (includes thinking).
            Defaults to the model's full output limit when 0.
        model: Optional model override. When empty, uses the resolved
            primary model from ``_get_model(client)``.
        monitor: Optional live monitor fed with streaming progress.

    Returns:
        str | None: Generated text, or ``None`` on failure.

    Raises:
        CommitMessageError: If the monthly spending cap is exceeded.
    """
    if max_output_tokens <= 0:
        max_output_tokens = _get_max_output_tokens(client)

    effective_model = model or _get_model(client)
    config = types.GenerateContentConfig(
        temperature=0.3,
        max_output_tokens=max_output_tokens,
        thinking_config=types.ThinkingConfig(
            thinking_level=types.ThinkingLevel.LOW,
        ),
    )
    final_chunk: types.GenerateContentResponse | None = None
    text_parts: list[str] = []
    for attempt in range(1, GENERATE_MAX_RETRIES + 1):
        final_chunk = None
        text_parts.clear()
        if monitor is not None:
            monitor.begin_attempt()
        try:
            final_chunk = _stream_response(client, (effective_model, prompt, config), text_parts, monitor)
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
                _wait_for_retry(delay, monitor)
                continue
            _log(f"WARN: API client error: {exc}")
            return None
        except ServerError:
            if attempt < GENERATE_MAX_RETRIES:
                delay = GENERATE_RETRY_BASE_DELAY * attempt
                _log(f"WARN: API server error (attempt {attempt}/{GENERATE_MAX_RETRIES}), retrying in {delay:.0f}s")
                _wait_for_retry(delay, monitor)
            else:
                _log(f"WARN: API server error (attempt {attempt}/{GENERATE_MAX_RETRIES}), giving up")
                return None
        except ConnectionError:
            if attempt < GENERATE_MAX_RETRIES:
                delay = GENERATE_RETRY_BASE_DELAY * attempt
                _log(f"WARN: Network error (attempt {attempt}/{GENERATE_MAX_RETRIES}), retrying in {delay:.0f}s")
                _wait_for_retry(delay, monitor)
            else:
                _log(f"WARN: Network error (attempt {attempt}/{GENERATE_MAX_RETRIES}), giving up")
                return None

    if final_chunk is None:
        _log("WARN: API returned an empty stream")
        return None

    if not _model_log_done[0]:
        _model_log_done[0] = True
        model_version = final_chunk.model_version
        if model_version:
            _log(f"Resolved model: {model_version}")

    text = "".join(text_parts).strip()
    if not text:
        candidates_info = ""
        if final_chunk.candidates:
            candidates_info = f" (finish_reason={final_chunk.candidates[0].finish_reason})"
        _log(f"WARN: API returned empty response{candidates_info}")
        return None

    if monitor is not None:
        usage = final_chunk.usage_metadata
        monitor.complete(usage.prompt_token_count if usage is not None else None)
    return text


def _summarize_chunk(
    client: genai.Client,
    chunk: str,
    chunk_num: int,
    total_chunks: int,
    plan: _ChunkPlan | None = None,
) -> str | None:
    """Summarize a single diff chunk via the Gemini API.

    Args:
        client: The genai client instance.
        chunk: The diff chunk text to summarize.
        chunk_num: 1-based index of this chunk.
        total_chunks: Total number of chunks being processed.
        plan: Optional ETA tracking for the chunk's count and summary calls.

    Returns:
        str | None: Summary text, or ``None`` on failure.
    """
    count_scope = plan.eta.track(plan.count_stage) if plan is not None else nullcontext()
    with count_scope:
        chunk_tokens = _count_tokens(client, chunk)
    if plan is not None:
        plan.forecast.record_count(chunk_num - 1, chunk_tokens)
    _progress(
        f"{_GREEN}[{chunk_num}/{total_chunks}]{_RESET} Summarizing chunk ({_format_tokens(chunk_tokens)} tokens)...",
        overwrite=False,
    )

    prompt = CHUNK_SUMMARY_PROMPT.format(chunk=chunk)
    summary_scope = plan.eta.track(plan.summary_stage) if plan is not None else nullcontext(None)
    with summary_scope as stage:
        monitor = stage.monitor if stage is not None else None
        result = _generate_content(client, prompt, model=_get_fallback_model(), monitor=monitor)
    if plan is not None:
        plan.forecast.record_summary(chunk_num - 1, len(result) if result else 0)

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
    total_files = diff_body.count("diff --git ")
    primary_model = _get_model(client)
    summary_profile = _CallProfile(_CallKind.SUMMARY, _get_fallback_model())
    latency = _LatencyModel.load()
    forecast = _BatchForecast(
        latency,
        summary_profile,
        chunks,
        len(_format_reduce_prompt(stat_section, "", total_chunks, total_files)),
    )
    stages = _plan_batch_stages(latency, forecast, primary_model, summary_profile, total_chunks)
    eta = _EtaPipeline(stages.ordered(), "chunks")
    _log(
        f"Batch mode: {total_chunks} chunks, ~{_format_duration(eta.forecast())} estimated ({latency.calibration_note()})",
    )
    _log(
        f"Chunk summaries via {summary_profile.model}, final reduce via {primary_model}",
    )

    with eta:
        summaries = _summarize_all_chunks(client, chunks, eta, stages, forecast)

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

        reduce_prompt = _format_reduce_prompt(stat_section, combined_summaries, total_chunks, total_files)
        forecast.record_reduce_prompt(len(reduce_prompt))
        with eta.track(stages.reduce_count):
            reduce_tokens = _count_tokens(client, reduce_prompt)
        forecast.record_reduce_tokens(reduce_tokens)
        _log(f"  Reduce prompt: {len(reduce_prompt):,} chars, {_format_tokens(reduce_tokens)} tokens")

        _progress(
            f"{_GREEN}[FINAL]{_RESET} Combining {len(summaries)} summaries into commit message...",
            overwrite=False,
        )

        with eta.track(stages.reduce) as stage:
            return _generate_content(client, reduce_prompt, monitor=stage.monitor)


def _summarize_all_chunks(
    client: genai.Client,
    chunks: Sequence[str],
    eta: _EtaPipeline,
    stages: _BatchStages,
    forecast: _BatchForecast,
) -> list[str]:
    """Summarize every chunk in order, pausing between batches.

    Args:
        client: The genai client instance.
        chunks: Diff chunks to summarize.
        eta: Running pipeline that tracks each stage.
        stages: Forecast stages for the batch.
        forecast: Running batch knowledge updated as results arrive.

    Returns:
        list[str]: Labeled summaries of the chunks that succeeded.
    """
    total_chunks = len(chunks)
    summaries: list[str] = []
    for index, chunk in enumerate(chunks):
        chunk_num = index + 1
        plan = _ChunkPlan(eta, forecast, stages.counts[index], stages.summaries[index])
        summary = _summarize_chunk(client, chunk, chunk_num, total_chunks, plan)

        if summary:
            summaries.append(f"--- Chunk {chunk_num}/{total_chunks} ---\n{summary}")

        if index < len(stages.cooldowns):
            with eta.track(stages.cooldowns[index]):
                _batch_cooldown_wait(chunk_num, total_chunks)
    return summaries


def _format_reduce_prompt(
    stat_section: str,
    summaries: str,
    total_chunks: int,
    total_files: int,
) -> str:
    """Render the reduce prompt that merges chunk summaries.

    Args:
        stat_section: The ``git diff --stat`` output for full file listing.
        summaries: Joined chunk summaries.
        total_chunks: Number of chunks the diff was split into.
        total_files: Number of files in the diff.

    Returns:
        str: The rendered prompt.
    """
    return REDUCE_PROMPT.format(
        stat_section=stat_section,
        summaries=summaries,
        total_chunks=total_chunks,
        total_files=total_files,
        min_bullets=max(8, total_chunks * 2),
        max_bullets=max(16, total_chunks * 4),
    )


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
    prompt_tokens = total_tokens

    if total_tokens > SINGLE_CALL_TOKEN_LIMIT:
        ratio = SINGLE_CALL_TOKEN_LIMIT / total_tokens
        cut_point = int(len(diff_input) * ratio * 0.95)
        diff_input = diff_input[:cut_point]
        final_tokens = _count_tokens(client, diff_input)
        prompt_tokens = final_tokens
        truncation_notice = f"NOTE: Diff was truncated from {total_tokens:,} to {final_tokens:,} tokens. Focus on the visible changes."
        _log(f"Truncated for single call: {total_tokens:,} -> {final_tokens:,} tokens")

    prompt = COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=diff_input,
    )

    model = _get_model(client)
    latency = _LatencyModel.load()
    stage = _GenerateStage(
        "commit message",
        latency,
        _CallProfile(_CallKind.SINGLE, model),
        partial(float, prompt_tokens),
        is_unit=True,
    )
    eta = _EtaPipeline([stage], "calls")
    _log(f"Calling {model}... (~{_format_duration(eta.forecast())} estimated, {latency.calibration_note()})")
    with eta, eta.track(stage) as active:
        return _generate_content(client, prompt, monitor=active.monitor)


def _route_generation(
    client: genai.Client,
    diff_input: str,
    diff_body: str,
    stat_section: str,
    total_tokens: int,
) -> str | None:
    """Route to single-call or batch generation based on diff size.

    Diffs under the single-call token limit use one API call. Larger diffs
    are split into chunks, summarized individually, and combined via a
    reduce step, falling back to a truncated single call if batching fails.

    Args:
        client: The genai client instance.
        diff_input: The full diff input (stat + diff body).
        diff_body: The diff portion of the input (without stat header).
        stat_section: The ``git diff --stat`` output for full file listing.
        total_tokens: Pre-counted token count of the diff body.

    Returns:
        str | None: Generated commit message, or ``None`` on failure.
    """
    if total_tokens <= SINGLE_CALL_TOKEN_LIMIT:
        _log("Using single-call mode")
        return _single_generate(client, diff_input, total_tokens)

    _log(f"Diff exceeds {SINGLE_CALL_TOKEN_LIMIT:,} token limit, using batch mode")
    result = _batch_generate(client, diff_body, stat_section)
    if not result:
        _log("Batch mode failed, falling back to truncated single call")
        result = _single_generate(client, diff_input, total_tokens)
    return result


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
        result = _route_generation(client, diff_input, diff_body, stat_section, total_tokens)
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
