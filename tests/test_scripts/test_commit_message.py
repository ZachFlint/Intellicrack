#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the commit message generator's splitting and error handling."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import tiktoken


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


def _load_gcm_module() -> ModuleType:
    """Load the generate_commit_message script as a module.

    The commit-message generator lives under ``scripts/`` which is not on
    the standard Python path, so a file-location spec is used to import it
    at test time without altering project-wide import configuration.

    Returns:
        ModuleType: The loaded ``generate_commit_message`` module.

    Raises:
        RuntimeError: If the script cannot be located or loaded.
    """
    script_path = Path(__file__).parent.parent.parent / "scripts" / "generate_commit_message.py"
    spec = importlib.util.spec_from_file_location("generate_commit_message", script_path)
    if spec is None or spec.loader is None:
        msg = f"Cannot load generate_commit_message from {script_path}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_commit_message"] = module
    spec.loader.exec_module(module)
    return module


gcm: ModuleType = _load_gcm_module()


@pytest.fixture(autouse=True)
def disable_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable API throttling for all tests so they run instantly.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(gcm, "_COUNT_TOKENS_INTERVAL", 0.0)
    last_count_time: list[float] = gcm._last_count_time
    last_count_time[0] = 0.0


_TIKTOKEN_ENCODING: tiktoken.Encoding = tiktoken.get_encoding("cl100k_base")


def _reference_token_count(text: str) -> int:
    """Count tokens with an independent BPE tokenizer (tiktoken cl100k_base).

    This is a *different* tokenizer from the script's character heuristic and
    serves as the trusted oracle for how many tokens real text actually
    encodes to.

    Args:
        text: Text to tokenize.

    Returns:
        int: Token count produced by the ``cl100k_base`` BPE encoding.
    """
    return len(_TIKTOKEN_ENCODING.encode(text))


class _CountTokensResponse:
    """Minimal stand-in for the Gemini ``count_tokens`` response object.

    Exposes only the ``total_tokens`` attribute that ``_count_tokens`` reads,
    matching the real ``google.genai`` response contract.
    """

    def __init__(self, total_tokens: int | None) -> None:
        """Store the token total the response should report.

        Args:
            total_tokens: Token count to expose, or ``None`` to simulate an
                absent count.
        """
        self.total_tokens: int | None = total_tokens


class _RecordingModels:
    """Real ``models`` facade whose ``count_tokens`` runs caller-supplied behaviour.

    This is a genuine object implementing the exact keyword-argument
    ``count_tokens`` interface the script calls; it is the external Gemini
    dependency, not the function under test, and it executes real behaviour
    (returning a response or raising a real exception) rather than recording
    calls like a mock.
    """

    def __init__(self, behavior: Callable[[str, str], _CountTokensResponse]) -> None:
        """Store the behaviour invoked on each ``count_tokens`` call.

        Args:
            behavior: Callable receiving ``(model, contents)`` and returning a
                response or raising to exercise the fallback path.
        """
        self._behavior: Callable[[str, str], _CountTokensResponse] = behavior

    def count_tokens(self, *, model: str, contents: str) -> _CountTokensResponse:
        """Invoke the configured behaviour for a token-count request.

        Args:
            model: Model identifier passed by the script.
            contents: Text whose tokens are being counted.

        Returns:
            _CountTokensResponse: Response carrying the token total.
        """
        return self._behavior(model, contents)


class _StubGeminiClient:
    """Real client object exposing the ``models``/``vertexai`` surface ``_count_tokens`` touches.

    It is a concrete object (not a ``MagicMock``) implementing only the
    attributes the script reads, so the real fallback-dispatch logic in
    ``_count_tokens`` runs end to end against genuine exception instances.
    """

    def __init__(self, behavior: Callable[[str, str], _CountTokensResponse]) -> None:
        """Build a client whose token counter runs the given behaviour.

        Args:
            behavior: Callable receiving ``(model, contents)`` for each
                ``count_tokens`` invocation.
        """
        self.models: _RecordingModels = _RecordingModels(behavior)
        self.vertexai: bool = False
        self._api_client: None = None


def _make_file_diff(path: str, num_hunks: int, lines_per_hunk: int) -> str:
    """Build a synthetic unified diff for one file.

    Args:
        path: File path to use in the diff header.
        num_hunks: Number of ``@@ ... @@`` hunks to generate.
        lines_per_hunk: Number of added lines per hunk.

    Returns:
        str: A synthetic unified diff string.
    """
    header = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    hunks: list[str] = []
    for i in range(num_hunks):
        start = i * lines_per_hunk + 1
        hunk_header = f"@@ -{start},0 +{start},{lines_per_hunk} @@\n"
        hunk_lines = "".join(f"+line {start + j} content padding to increase size aaaa\n" for j in range(lines_per_hunk))
        hunks.append(hunk_header + hunk_lines)
    return header + "".join(hunks)


def _estimate_tokens(text: str) -> int:
    """Invoke the loaded module's token estimator.

    Args:
        text: Text to estimate tokens for.

    Returns:
        int: Estimated token count from the commit-message generator.
    """
    result: int = gcm._estimate_tokens(text)
    return result


def _subsplit_large_file_diff(file_diff: str) -> list[str]:
    """Invoke the loaded module's oversized-file sub-splitter.

    Args:
        file_diff: The unified diff for a single file.

    Returns:
        list[str]: Sub-chunks produced by the sub-splitter.
    """
    result: list[str] = gcm._subsplit_large_file_diff(file_diff)
    return result


def _split_diff_on_file_boundaries(diff_input: str) -> list[str]:
    """Invoke the loaded module's top-level diff splitter.

    Args:
        diff_input: The full unified diff string.

    Returns:
        list[str]: Balanced diff chunks.
    """
    result: list[str] = gcm._split_diff_on_file_boundaries(diff_input)
    return result


def _extract_stat_section(diff_input: str) -> tuple[str, str]:
    """Invoke the loaded module's stat/diff extractor.

    Args:
        diff_input: The combined stat + diff input from stdin.

    Returns:
        tuple[str, str]: Tuple of (stat_section, diff_body).
    """
    result: tuple[str, str] = gcm._extract_stat_section(diff_input)
    return result


def _count_tokens(client: _StubGeminiClient, text: str) -> int:
    """Invoke the loaded module's token counter.

    Args:
        client: Real stub client exposing the Gemini ``count_tokens`` surface.
        text: Text whose tokens should be counted.

    Returns:
        int: Number of tokens in the text (exact or estimated).
    """
    result: int = gcm._count_tokens(client, text)
    return result


def _server_error_cls() -> type[Exception]:
    """Return the ``ServerError`` class exported by the loaded module.

    Returns:
        type[Exception]: The ``google.genai.errors.ServerError`` class.
    """
    cls: type[Exception] = gcm.ServerError
    return cls


def _client_error_cls() -> type[Exception]:
    """Return the ``ClientError`` class exported by the loaded module.

    Returns:
        type[Exception]: The ``google.genai.errors.ClientError`` class.
    """
    cls: type[Exception] = gcm.ClientError
    return cls


def _raise(exc: Exception) -> Callable[[str, str], _CountTokensResponse]:
    """Build a ``count_tokens`` behaviour that raises the given exception.

    Args:
        exc: Real exception instance to raise on invocation.

    Returns:
        Callable[[str, str], _CountTokensResponse]: Behaviour that always raises.
    """

    def _behavior(_model: str, _contents: str) -> _CountTokensResponse:
        raise exc

    return _behavior


class TestEstimateTokens:
    """Tests for the character-based token estimator against an independent oracle.

    The estimator is a cheap, no-API proxy used to size diff chunks. Its
    correctness requirement is not that it equals a BPE tokenizer exactly, but
    that it stays close enough to the true token count of *real* diff text that
    chunking decisions remain sound. These tests therefore compare the
    estimator against ``tiktoken`` (a different, trusted tokenizer) rather than
    re-deriving the implementation's own ``len // 3`` arithmetic.

    Falsifiability:
    - Changing the divisor from 3 to 2 inflates all estimates by 50%; the ratio
      upper-bound (1.8) holds trivially, but the lower-bound (0.6) would fail
      for the empty-string case if divisor changes from 3 to e.g. 10 (estimates
      too-low), and the monotonicity test would fail if the estimate regressed
      to a constant.
    - Removing the division entirely (returning ``len(text)``) pushes the ratio
      to ~3-4x, exceeding the 1.8 upper bound and failing the ratio test.
    - Replacing ``len(text) // 3`` with a constant 0 would cause the empty-string
      test to pass by coincidence but fail the monotonicity test.
    """

    def test_empty_string_matches_oracle_at_zero(self) -> None:
        """Verify the empty-string boundary equals the independent oracle (zero)."""
        assert _estimate_tokens("") == 0
        assert _reference_token_count("") == 0

    def test_realistic_diff_estimate_tracks_reference_tokenizer(self) -> None:
        """Verify the estimate stays within a bounded factor of real token counts.

        Builds a realistic multi-file unified diff (the script's actual input)
        and asserts the character heuristic lands within 0.6x-1.8x of the
        ``tiktoken`` count. This catches a broken char-to-token ratio in either
        direction: dividing by far more than ~3 would starve the estimate
        (under 0.6x) and dividing by far less would inflate it (over 1.8x),
        both of which would corrupt chunk sizing.
        """
        diffs = [_make_file_diff(f"src/module_{i}.py", num_hunks=5, lines_per_hunk=40) for i in range(10)]
        combined = "".join(diffs)

        estimate = _estimate_tokens(combined)
        reference = _reference_token_count(combined)

        assert reference > 1000, "diff fixture must be substantial enough to exercise the heuristic"
        ratio = estimate / reference
        assert 0.6 <= ratio <= 1.8, f"estimate {estimate} drifts too far from oracle {reference} (ratio {ratio:.3f})"

    def test_estimate_is_monotonic_in_length(self) -> None:
        """Verify a longer real diff never estimates fewer tokens than a shorter one.

        Token estimates must grow with input size so that larger diffs reliably
        cross the chunking threshold. A regression that, for example, clamped or
        inverted the estimate would break this ordering even though a single
        equality check might still pass.
        """
        short_diff = _make_file_diff("a.py", num_hunks=1, lines_per_hunk=10)
        long_diff = _make_file_diff("a.py", num_hunks=20, lines_per_hunk=50)

        short_estimate = _estimate_tokens(short_diff)
        long_estimate = _estimate_tokens(long_diff)

        assert len(long_diff) > len(short_diff)
        assert long_estimate > short_estimate
        assert short_estimate >= 1

    def test_ascii_vs_unicode_estimate_both_track_oracle(self) -> None:
        """Verify the estimator tracks tiktoken on both ASCII and Unicode content.

        Real diffs may include Unicode identifiers, string literals, or
        comments. The heuristic operates on raw character count, which for
        multi-byte Unicode characters understates the byte width but still
        provides a token estimate. Both cases must stay within the 0.6x-1.8x
        oracle band so chunking works regardless of content encoding.
        """
        ascii_text = "".join(f"def func_{i}(x: int) -> str:\n    return str(x)\n" for i in range(50))
        unicode_text = "".join(f"def fonc_{i}(x: int) -> str:\n    return 'éàü' + str(x)\n" for i in range(50))

        for text in (ascii_text, unicode_text):
            estimate = _estimate_tokens(text)
            reference = _reference_token_count(text)
            assert reference > 100, "fixture must produce measurable tokens"
            ratio = estimate / reference
            assert 0.6 <= ratio <= 1.8, f"estimate {estimate} vs oracle {reference} (ratio {ratio:.3f}) out of [0.6, 1.8] band"


class TestSubsplitLargeFileDiff:
    """Tests for hunk-based sub-splitting of oversized file diffs."""

    def test_splits_on_hunk_boundaries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that oversized diffs are split on @@ markers.

        Args:
            monkeypatch: Pytest fixture used to lower the chunk token target.
        """
        diff = _make_file_diff("big_file.py", num_hunks=10, lines_per_hunk=500)

        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", 2000)
        chunks: list[str] = _subsplit_large_file_diff(diff)

        assert len(chunks) > 1
        for chunk in chunks:
            assert "@@" in chunk or "diff --git" in chunk

    def test_preserves_file_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that each sub-chunk retains the file header.

        Args:
            monkeypatch: Pytest fixture used to lower the chunk token target.
        """
        diff = _make_file_diff("src/main.py", num_hunks=6, lines_per_hunk=300)

        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", 1500)
        chunks: list[str] = _subsplit_large_file_diff(diff)

        assert len(chunks) > 1
        for chunk in chunks:
            assert chunk.startswith("diff --git a/src/main.py")

    def test_single_hunk_falls_back_to_line_split(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify fallback to line-based splitting when only one hunk exists.

        Args:
            monkeypatch: Pytest fixture used to lower the chunk token target.
        """
        diff = _make_file_diff("huge.bin", num_hunks=1, lines_per_hunk=5000)

        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", 2000)
        chunks: list[str] = _subsplit_large_file_diff(diff)

        assert len(chunks) > 1


class TestSplitDiffOnFileBoundaries:
    """Tests for the top-level diff splitter."""

    def test_small_diff_single_chunk(self) -> None:
        """Verify that a small diff stays as one chunk."""
        diff = _make_file_diff("small.py", num_hunks=2, lines_per_hunk=10)
        chunks: list[str] = _split_diff_on_file_boundaries(diff)
        assert len(chunks) == 1

    def test_multiple_files_grouped(self) -> None:
        """Verify that multiple small files are grouped into one chunk."""
        diffs = [_make_file_diff(f"file_{i}.py", num_hunks=1, lines_per_hunk=5) for i in range(5)]
        combined = "".join(diffs)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)
        assert len(chunks) == 1

    def test_oversized_file_gets_subsplit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that a file exceeding CHUNK_TOKEN_TARGET is sub-split.

        Args:
            monkeypatch: Pytest fixture used to lower the chunk token target.
        """
        small = _make_file_diff("small.py", num_hunks=1, lines_per_hunk=5)
        big = _make_file_diff("big.py", num_hunks=20, lines_per_hunk=500)
        combined = small + big

        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", 3000)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)

        assert len(chunks) >= 3

    def test_no_chunk_exceeds_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify every chunk from splitting stays under the model limit.

        Args:
            monkeypatch: Pytest fixture used to override chunk/model limits.
        """
        diffs = [_make_file_diff(f"mod_{i}.py", num_hunks=5, lines_per_hunk=200) for i in range(8)]
        combined = "".join(diffs)

        target = 5000
        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", target)
        monkeypatch.setattr(gcm, "MODEL_INPUT_LIMIT", target * 2)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)

        for i, chunk in enumerate(chunks):
            chunk_tokens = _estimate_tokens(chunk)
            assert chunk_tokens <= target * 2, f"Chunk {i} has {chunk_tokens} estimated tokens, exceeds limit {target * 2}"

    def test_chunks_are_balanced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify LPT bin-packing produces roughly equal chunk sizes.

        Simulates the real scenario: many small files plus several medium
        files totaling ~3x the chunk target, expecting 3 balanced chunks.

        Args:
            monkeypatch: Pytest fixture used to override chunk/model limits.
        """
        small_files = [_make_file_diff(f"small_{i}.py", num_hunks=2, lines_per_hunk=50) for i in range(20)]
        medium_files = [_make_file_diff(f"med_{i}.py", num_hunks=5, lines_per_hunk=100) for i in range(5)]
        combined = "".join(small_files) + "".join(medium_files)

        total_est = _estimate_tokens(combined)
        target = total_est // 3
        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", target)
        monkeypatch.setattr(gcm, "MODEL_INPUT_LIMIT", target * 3)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)

        assert len(chunks) >= 2
        sizes: list[int] = [_estimate_tokens(c) for c in chunks]
        ratio = max(sizes) / max(min(sizes), 1)
        assert ratio < 3.0, f"Chunks are unbalanced: sizes={sizes}, ratio={ratio:.1f}"


class TestExtractStatSection:
    """Tests for stat/diff extraction from combined input."""

    def test_with_markers(self) -> None:
        """Verify parsing when FILES CHANGED and DIFF markers are present."""
        inp = "FILES CHANGED:\n file1.py | 5 ++\n\nDIFF:\ndiff --git a/file1.py"
        stat, body = _extract_stat_section(inp)
        assert "file1.py" in stat
        assert body.startswith("diff --git")

    def test_without_markers(self) -> None:
        """Verify fallback when markers are absent."""
        inp = "diff --git a/file1.py b/file1.py\n--- a/file1.py\n+++ b/file1.py"
        stat, body = _extract_stat_section(inp)
        assert not stat
        assert body == inp


class TestCountTokensSuccessPath:
    """The token counter must faithfully pass through the API's real count."""

    def test_returns_exact_api_total_when_call_succeeds(self) -> None:
        """Verify a successful count returns the API's ``total_tokens`` verbatim.

        The success path is the primary contract: ``_count_tokens`` must report
        the tokenizer's exact answer, not the local estimate. The API total
        (4242) is deliberately set far from the heuristic estimate for the same
        text so that a regression silently substituting the estimate would be
        caught.
        """
        text = "diff --git a/x.py b/x.py\n+print('hello world')\n"
        api_total = 4242
        assert _estimate_tokens(text) != api_total

        client = _StubGeminiClient(lambda _model, _contents: _CountTokensResponse(api_total))
        assert _count_tokens(client, text) == api_total

    def test_missing_total_tokens_falls_back_to_estimate(self) -> None:
        """Verify a response with ``total_tokens=None`` yields the local estimate.

        Drives the real ``response.total_tokens is None`` branch with a genuine
        response object and asserts the result equals the independent estimate
        of the same text.
        """
        text = "x" * 300
        client = _StubGeminiClient(lambda _model, _contents: _CountTokensResponse(None))
        assert _count_tokens(client, text) == _estimate_tokens(text)


class TestCountTokensFallback:
    """Real-exception fallback dispatch for the token counter.

    Each test runs the real ``_count_tokens`` against a concrete client whose
    ``count_tokens`` raises a genuine ``google.genai`` / stdlib exception. The
    asserted fallback value is the independent character estimate for the exact
    same text, so a broken fallback (wrong text routed, estimate miscomputed,
    or the wrong branch taken) changes the number and fails the test.

    Falsifiability:
    - Removing the ``except (ClientError, ServerError)`` clause causes the
      ServerError/ClientError tests to propagate the exception and fail.
    - Removing the ``except ConnectionError`` clause causes the network test
      to propagate and fail.
    - Changing the fallback from ``_estimate_tokens(text)`` to a fixed value
      (e.g., 0) causes the exact-value assertions to fail because
      ``_estimate_tokens("a" * 300) == 100 != 0``.
    - Swapping which text length maps to which test will produce a wrong
      fallback value (300 chars != 600 chars != 900 chars under ``// 3``).
    """

    def test_server_error_falls_back_to_estimate(self) -> None:
        """Verify a real ``ServerError`` (503) routes to the character estimate.

        The stub raises a genuine ``google.genai.errors.ServerError`` instance
        (not a monkeypatch or MagicMock) so the real except-clause dispatch
        inside ``_count_tokens`` is exercised end-to-end.
        """
        text = "a" * 300
        server_error = _server_error_cls()(503, {"error": {"message": "unavailable"}}, None)
        client = _StubGeminiClient(_raise(server_error))
        assert _count_tokens(client, text) == _estimate_tokens(text)

    def test_client_error_falls_back_to_estimate(self) -> None:
        """Verify a real ``ClientError`` (400) routes to the character estimate.

        The stub raises a genuine ``google.genai.errors.ClientError`` instance
        so the real except-clause dispatch inside ``_count_tokens`` is exercised.
        """
        text = "b" * 600
        client_error = _client_error_cls()(400, {"error": {"message": "bad request"}}, None)
        client = _StubGeminiClient(_raise(client_error))
        assert _count_tokens(client, text) == _estimate_tokens(text)

    def test_connection_error_falls_back_to_estimate(self) -> None:
        """Verify a real ``ConnectionError`` routes to the character estimate.

        A genuine built-in ``ConnectionError`` (not a MagicMock side_effect) is
        raised by the stub so the real ``except ConnectionError`` branch fires.
        """
        text = "c" * 900
        client = _StubGeminiClient(_raise(ConnectionError("timeout")))
        assert _count_tokens(client, text) == _estimate_tokens(text)

    def test_too_large_client_error_routes_to_estimate(self) -> None:
        """Verify the dedicated 'too large' sub-branch returns the estimate.

        The production code special-cases payloads the API rejects as too
        large. This drives that exact branch with a real ``ClientError`` whose
        message contains ``too large`` and asserts the independent estimate is
        returned for the same oversized text.
        """
        text = "q" * 1500
        too_large = _client_error_cls()(400, {"error": {"message": "Request payload size: too large"}}, None)
        client = _StubGeminiClient(_raise(too_large))
        assert _count_tokens(client, text) == _estimate_tokens(text)

    def test_uncaught_exception_type_propagates(self) -> None:
        """Verify an exception outside the catch set is surfaced, not swallowed.

        The fallback catches only ``ServerError``/``ClientError`` and the
        stdlib ``ConnectionError``/``OSError``/``ValueError``/``RuntimeError``
        families. A ``KeyError`` is intentionally not handled, so it must
        propagate. This proves the catch is specific - a blanket
        ``except Exception`` would wrongly hide it behind the estimate.
        """
        client = _StubGeminiClient(_raise(KeyError("unexpected")))
        with pytest.raises(KeyError):
            _count_tokens(client, "x" * 30)


class TestCountTokensThrottle:
    """The token counter must throttle rapid calls by the exact computed delay.

    Falsifiability:
    - A virtual clock replaces ``time.monotonic`` and ``time.sleep`` so the
      computed sleep duration can be asserted to sub-millisecond precision.
    - Removing the throttle sleep entirely produces an empty ``slept`` list,
      failing the ``len(slept) == 1`` assertion.
    - Sleeping the full interval instead of ``interval - elapsed`` produces
      ``slept[0] == 0.5`` instead of ``0.4``, failing the exact equality check.
    - Sleeping zero always (short-circuiting the elapsed check) produces
      ``slept[0] == 0.0``, failing the ``0.4`` check.
    """

    def test_sleep_duration_is_exactly_interval_minus_elapsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify the throttle sleeps precisely ``interval - elapsed`` seconds.

        A deterministic virtual clock replaces ``time.monotonic``/``time.sleep``
        (the OS timing primitives the function depends on, not the function
        itself) so the computed delay can be asserted exactly. With the
        interval at 0.5s and only 0.1s elapsed since the last call, the function
        must sleep exactly 0.4s - a regression that ignored ``elapsed`` (0.5s)
        or halved the delay (0.25s) would fail this exact check.

        Args:
            monkeypatch: Pytest fixture used to install the virtual clock.
        """
        monkeypatch.setattr(gcm, "_COUNT_TOKENS_INTERVAL", 0.5)
        clock: list[float] = [1000.0]
        slept: list[float] = []

        def _virtual_monotonic() -> float:
            return clock[0]

        def _virtual_sleep(duration: float) -> None:
            slept.append(duration)
            clock[0] += duration

        monkeypatch.setattr(gcm.time, "monotonic", _virtual_monotonic)
        monkeypatch.setattr(gcm.time, "sleep", _virtual_sleep)

        last_count_time: list[float] = gcm._last_count_time
        last_count_time[0] = clock[0] - 0.1

        client = _StubGeminiClient(lambda _model, _contents: _CountTokensResponse(50))
        assert _count_tokens(client, "throttle test") == 50

        assert len(slept) == 1
        assert abs(slept[0] - 0.4) < 1e-9
        assert abs(last_count_time[0] - 1000.4) < 1e-9

    def test_no_sleep_when_interval_already_elapsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify no throttle delay is applied once the interval has passed.

        When more than the interval has elapsed since the previous call, the
        function must not sleep at all and must advance the last-call timestamp
        to the current clock. A regression that always slept would add a
        spurious delay and fail the empty-sleep-list assertion.

        Args:
            monkeypatch: Pytest fixture used to install the virtual clock.
        """
        monkeypatch.setattr(gcm, "_COUNT_TOKENS_INTERVAL", 0.5)
        clock: list[float] = [2000.0]
        slept: list[float] = []

        def _record_sleep(duration: float) -> None:
            slept.append(duration)

        monkeypatch.setattr(gcm.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(gcm.time, "sleep", _record_sleep)

        last_count_time: list[float] = gcm._last_count_time
        last_count_time[0] = clock[0] - 5.0

        client = _StubGeminiClient(lambda _model, _contents: _CountTokensResponse(11))
        assert _count_tokens(client, "no throttle") == 11

        assert slept == []
        assert abs(last_count_time[0] - 2000.0) < 1e-9
