#!/usr/bin/env python3
"""Tests for the commit message generator's splitting and error handling."""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest


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
    script_path = (
        Path(__file__).parent.parent.parent / "scripts" / "generate_commit_message.py"
    )
    spec = importlib.util.spec_from_file_location(
        "generate_commit_message", script_path
    )
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


def _make_file_diff(path: str, num_hunks: int, lines_per_hunk: int) -> str:
    """Build a synthetic unified diff for one file.

    Args:
        path: File path to use in the diff header.
        num_hunks: Number of ``@@ ... @@`` hunks to generate.
        lines_per_hunk: Number of added lines per hunk.

    Returns:
        str: A synthetic unified diff string.
    """
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
    )
    hunks: list[str] = []
    for i in range(num_hunks):
        start = i * lines_per_hunk + 1
        hunk_header = f"@@ -{start},0 +{start},{lines_per_hunk} @@\n"
        hunk_lines = "".join(
            f"+line {start + j} content padding to increase size aaaa\n"
            for j in range(lines_per_hunk)
        )
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


def _count_tokens(client: MagicMock, text: str) -> int:
    """Invoke the loaded module's token counter.

    Args:
        client: MagicMock standing in for the Gemini ``Client`` instance.
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


class TestEstimateTokens:
    """Tests for the character-based token estimator."""

    def test_empty_string(self) -> None:
        """Test that empty string returns 0 tokens."""
        assert _estimate_tokens("") == 0

    def test_short_string(self) -> None:
        """Test estimation for a short string."""
        assert _estimate_tokens("abcd") == 1

    def test_known_length(self) -> None:
        """Test estimation for a string of known length."""
        text = "x" * 3000
        assert _estimate_tokens(text) == 1000


class TestSubsplitLargeFileDiff:
    """Tests for hunk-based sub-splitting of oversized file diffs."""

    def test_splits_on_hunk_boundaries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that oversized diffs are split on @@ markers.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
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
            monkeypatch: Pytest monkeypatch fixture.
        """
        diff = _make_file_diff("src/main.py", num_hunks=6, lines_per_hunk=300)

        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", 1500)
        chunks: list[str] = _subsplit_large_file_diff(diff)

        assert len(chunks) > 1
        for chunk in chunks:
            assert chunk.startswith("diff --git a/src/main.py")

    def test_single_hunk_falls_back_to_line_split(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify fallback to line-based splitting when only one hunk exists.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
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
        diffs = [
            _make_file_diff(f"file_{i}.py", num_hunks=1, lines_per_hunk=5)
            for i in range(5)
        ]
        combined = "".join(diffs)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)
        assert len(chunks) == 1

    def test_oversized_file_gets_subsplit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify that a file exceeding CHUNK_TOKEN_TARGET is sub-split.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
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
            monkeypatch: Pytest monkeypatch fixture.
        """
        diffs = [
            _make_file_diff(f"mod_{i}.py", num_hunks=5, lines_per_hunk=200)
            for i in range(8)
        ]
        combined = "".join(diffs)

        target = 5000
        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", target)
        monkeypatch.setattr(gcm, "MODEL_INPUT_LIMIT", target * 2)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)

        for i, chunk in enumerate(chunks):
            chunk_tokens = _estimate_tokens(chunk)
            assert chunk_tokens <= target * 2, (
                f"Chunk {i} has {chunk_tokens} estimated tokens, "
                f"exceeds limit {target * 2}"
            )

    def test_chunks_are_balanced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify LPT bin-packing produces roughly equal chunk sizes.

        Simulates the real scenario: many small files plus several medium
        files totaling ~3x the chunk target, expecting 3 balanced chunks.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        small_files = [
            _make_file_diff(f"small_{i}.py", num_hunks=2, lines_per_hunk=50)
            for i in range(20)
        ]
        medium_files = [
            _make_file_diff(f"med_{i}.py", num_hunks=5, lines_per_hunk=100)
            for i in range(5)
        ]
        combined = "".join(small_files) + "".join(medium_files)

        total_est = _estimate_tokens(combined)
        target = total_est // 3
        monkeypatch.setattr(gcm, "CHUNK_TOKEN_TARGET", target)
        monkeypatch.setattr(gcm, "MODEL_INPUT_LIMIT", target * 3)
        chunks: list[str] = _split_diff_on_file_boundaries(combined)

        assert len(chunks) >= 2
        sizes: list[int] = [_estimate_tokens(c) for c in chunks]
        ratio = max(sizes) / max(min(sizes), 1)
        assert ratio < 3.0, (
            f"Chunks are unbalanced: sizes={sizes}, ratio={ratio:.1f}"
        )


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
        assert stat == ""
        assert body == inp


class TestCountTokensFallback:
    """Tests for _count_tokens error handling."""

    def test_api_error_falls_back_to_estimate(self) -> None:
        """Verify that API errors produce an estimate instead of crashing."""
        client = MagicMock()
        client.models.count_tokens.side_effect = _server_error_cls()(
            503, {"error": {"message": "unavailable"}}, None
        )
        result = _count_tokens(client, "a" * 300)
        assert result == 100

    def test_client_error_falls_back(self) -> None:
        """Verify that client errors produce an estimate."""
        client = MagicMock()
        client.models.count_tokens.side_effect = _client_error_cls()(
            400, {"error": {"message": "bad request"}}, None
        )
        result = _count_tokens(client, "b" * 600)
        assert result == 200

    def test_connection_error_falls_back(self) -> None:
        """Verify that network errors produce an estimate."""
        client = MagicMock()
        client.models.count_tokens.side_effect = ConnectionError("timeout")
        result = _count_tokens(client, "c" * 900)
        assert result == 300

    def test_throttle_prevents_rapid_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify that rapid calls are throttled with a delay.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        interval = 0.15
        monkeypatch.setattr(gcm, "_COUNT_TOKENS_INTERVAL", interval)

        client = MagicMock()
        resp = MagicMock()
        resp.total_tokens = 50
        client.models.count_tokens.return_value = resp

        last_count_time: list[float] = gcm._last_count_time
        last_count_time[0] = time.monotonic()
        start = time.monotonic()
        _count_tokens(client, "throttle test")
        elapsed = time.monotonic() - start

        assert elapsed >= interval * 0.8
