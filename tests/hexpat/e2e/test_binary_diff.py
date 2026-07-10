# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for binary diff operations via diff_bytes and diff_files.

The native ``diff_bytes`` / ``diff_files`` functions return a dict with exactly
three keys: ``files_identical`` (bool), ``total_differences`` (int) and
``regions`` (a list of region dicts, each with ``offset_a``, ``offset_b``,
``length`` and ``diff_type``). ``diff_type`` is one of ``"match"``,
``"modified"``, ``"inserted_a"`` or ``"inserted_b"``.

The native engine emits a Myers edit script (via the ``similar`` crate) where
contiguous matched runs become ``match`` regions, equal-length replaced runs
become ``modified`` regions (length = ``max(old_len, new_len)``), bytes present
only in A become ``inserted_a`` regions and bytes present only in B become
``inserted_b`` regions. ``total_differences`` is the summed length of every
non-match region.

Expected region layouts are cross-checked against Python's
``difflib.SequenceMatcher`` (the same Myers edit-script family the Rust engine
uses) for the contiguous single-replace cases where the two implementations
agree, and against the byte content directly for the remaining cases, so every
oracle is independent of the native engine's own output.
"""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    import types
    from pathlib import Path

_DIFF_TYPES: frozenset[str] = frozenset({"match", "modified", "inserted_a", "inserted_b"})
_RESULT_KEYS: frozenset[str] = frozenset({"files_identical", "total_differences", "regions"})
_NON_MATCH_TYPES: frozenset[str] = frozenset({"modified", "inserted_a", "inserted_b"})


def _write_bin(directory: Path, name: str, data: bytes) -> Path:
    """Write data to a named file in the given directory and return its path.

    Args:
        directory: Target directory for the file.
        name: Filename to create.
        data: Raw bytes to write.

    Returns:
        Path: Absolute path to the created file.
    """
    p = directory / name
    p.write_bytes(data)
    return p


def _assert_well_formed_regions(result: dict[str, Any], len_a: int, len_b: int) -> list[dict[str, Any]]:
    """Validate that a diff result has the exact schema and well-formed regions.

    The result must carry exactly the three documented top-level keys with the
    correct value types. Each region must carry exactly the four documented
    keys, a known ``diff_type`` tag, integer offsets and length, and
    offsets/spans that stay inside the respective input bounds.

    Args:
        result: The dict returned by ``diff_bytes`` / ``diff_files``.
        len_a: Length of the first input buffer.
        len_b: Length of the second input buffer.

    Returns:
        list[dict[str, Any]]: The validated ``regions`` list from the result.
    """
    assert set(result.keys()) == _RESULT_KEYS
    assert isinstance(result["files_identical"], bool)
    assert isinstance(result["total_differences"], int)
    assert result["total_differences"] >= 0
    regions: list[dict[str, Any]] = result["regions"]
    assert isinstance(regions, list)
    for region in regions:
        assert set(region.keys()) == {"offset_a", "offset_b", "length", "diff_type"}
        assert region["diff_type"] in _DIFF_TYPES
        offset_a: int = region["offset_a"]
        offset_b: int = region["offset_b"]
        length: int = region["length"]
        assert isinstance(offset_a, int)
        assert isinstance(offset_b, int)
        assert isinstance(length, int)
        assert 0 <= offset_a <= len_a
        assert 0 <= offset_b <= len_b
        assert length >= 0
        if region["diff_type"] in {"match", "inserted_a"}:
            assert offset_a + length <= len_a
        if region["diff_type"] in {"match", "inserted_b"}:
            assert offset_b + length <= len_b
    return regions


def _assert_total_differences_consistent(result: dict[str, Any]) -> None:
    """Assert ``total_differences`` equals the summed length of non-match regions.

    This independently re-derives the differing-byte count from the region list
    using the engine's documented contract (every non-match region's length
    counts toward ``total_differences``) and confirms the reported scalar
    matches that sum.

    Args:
        result: The dict returned by ``diff_bytes`` / ``diff_files``.
    """
    regions: list[dict[str, Any]] = result["regions"]
    summed = sum(r["length"] for r in regions if r["diff_type"] in _NON_MATCH_TYPES)
    assert summed == result["total_differences"]


def _expected_replace_span(data_a: bytes, data_b: bytes) -> tuple[int, int]:
    """Compute the single replaced span via difflib as an independent oracle.

    The two inputs must differ by exactly one contiguous ``replace`` opcode
    surrounded only by ``equal`` opcodes. Returns the start offset (in A) and
    length of that replaced region.

    Args:
        data_a: First buffer.
        data_b: Second buffer.

    Returns:
        tuple[int, int]: ``(start_offset_a, length)`` of the replaced region.
    """
    matcher = difflib.SequenceMatcher(a=data_a, b=data_b, autojunk=False)
    replaces = [(i1, i2) for tag, i1, i2, _j1, _j2 in matcher.get_opcodes() if tag == "replace"]
    assert len(replaces) == 1, f"oracle expected exactly one replace span, got {replaces}"
    start, end = replaces[0]
    return start, end - start


class TestDiffBytes:
    """Tests covering the diff_bytes() module-level function."""

    def test_identical_bytes_reports_identical(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes on two identical payloads reports exact equality.

        Args:
            hexcore: The native module fixture.
        """
        data = bytes(range(64))
        result: dict[str, Any] = hexcore.diff_bytes(data, data)
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        regions = _assert_well_formed_regions(result, len(data), len(data))
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "diff_type": "match"}]
        _assert_total_differences_consistent(result)

    def test_completely_different_bytes_is_single_modified_region(self, hexcore: types.ModuleType) -> None:
        """Verify a fully disjoint pair yields one modified region spanning the buffer.

        Two 64-byte payloads that share no bytes must be reported as not
        identical, with ``total_differences == 64`` and a single ``modified``
        region covering offset 0 through 64 in both buffers. The difflib oracle
        confirms the whole buffer is a single replace span.

        Args:
            hexcore: The native module fixture.
        """
        data_a = b"\x00" * 64
        data_b = b"\xff" * 64
        oracle_start, oracle_len = _expected_replace_span(data_a, data_b)
        assert (oracle_start, oracle_len) == (0, 64)

        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert result["files_identical"] is False
        assert result["total_differences"] == 64
        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "diff_type": "modified"}]
        _assert_total_differences_consistent(result)

    def test_diff_bytes_match_then_modified_region_layout(self, hexcore: types.ModuleType) -> None:
        """Verify diff_bytes produces a match prefix followed by the modified tail.

        Asserts the exact two-region edit script: a 16-byte ``match`` prefix and
        an 8-byte ``modified`` region, with ``total_differences`` equal to the
        modified span length. The difflib oracle confirms the single replace
        span begins at offset 16 with length 8.

        Args:
            hexcore: The native module fixture.
        """
        prefix = bytes(range(16))
        data_a = prefix + b"\x11" * 8
        data_b = prefix + b"\x22" * 8
        oracle_start, oracle_len = _expected_replace_span(data_a, data_b)
        assert (oracle_start, oracle_len) == (16, 8)

        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert result["files_identical"] is False
        assert result["total_differences"] == 8
        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 16, "diff_type": "match"},
            {"offset_a": 16, "offset_b": 16, "length": 8, "diff_type": "modified"},
        ]
        _assert_total_differences_consistent(result)

    def test_diff_bytes_partial_difference_reports_modified_tail(self, hexcore: types.ModuleType) -> None:
        """Verify diff_bytes reports the modified tail for partially differing data.

        ``0x00*50 + 0xff*50`` against ``0x00*100`` must yield a 50-byte ``match``
        prefix and a 50-byte ``modified`` region at offset 50, with
        ``total_differences == 50``. The difflib oracle confirms the replace
        span starts at offset 50 with length 50.

        Args:
            hexcore: The native module fixture.
        """
        data_a = b"\x00" * 50 + b"\xff" * 50
        data_b = b"\x00" * 100
        oracle_start, oracle_len = _expected_replace_span(data_a, data_b)
        assert (oracle_start, oracle_len) == (50, 50)

        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert result["files_identical"] is False
        assert result["total_differences"] == 50
        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 50, "diff_type": "match"},
            {"offset_a": 50, "offset_b": 50, "length": 50, "diff_type": "modified"},
        ]
        _assert_total_differences_consistent(result)

    def test_diff_empty_vs_empty_is_identical(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes on two empty byte strings reports exact equality.

        Args:
            hexcore: The native module fixture.
        """
        result: dict[str, Any] = hexcore.diff_bytes(b"", b"")
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        assert _assert_well_formed_regions(result, 0, 0) == []

    def test_diff_bytes_one_empty_is_full_insertion(self, hexcore: types.ModuleType) -> None:
        """Verify diff_bytes flags an empty-vs-nonempty pair as a full insertion.

        Diffing ``b"ABC"`` against ``b""`` must report the three A-only bytes as
        a single ``inserted_a`` region at offset 0 with length 3 and
        ``total_differences == 3``. The difflib oracle confirms a single delete
        opcode over the whole of A.

        Args:
            hexcore: The native module fixture.
        """
        data_a = b"ABC"
        opcodes = difflib.SequenceMatcher(a=data_a, b=b"", autojunk=False).get_opcodes()
        assert opcodes == [("delete", 0, 3, 0, 0)]

        result: dict[str, Any] = hexcore.diff_bytes(data_a, b"")
        assert result["files_identical"] is False
        assert result["total_differences"] == 3
        regions = _assert_well_formed_regions(result, len(data_a), 0)
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 3, "diff_type": "inserted_a"}]
        _assert_total_differences_consistent(result)


class TestDiffFiles:
    """Tests covering the diff_files() module-level function."""

    def test_diff_identical_files_reports_identical(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files on two identical files reports exact equality.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(64))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        regions = _assert_well_formed_regions(result, len(data), len(data))
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "diff_type": "match"}]
        _assert_total_differences_consistent(result)

    def test_diff_files_result_has_full_schema_with_valid_values(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files returns the complete schema with sensible values.

        Asserts the result contains exactly the three documented keys, that
        ``files_identical`` is the bool ``False`` for differing inputs,
        ``total_differences`` is a non-negative int, and that the byte count
        summed across modified and inserted regions equals ``total_differences``
        and equals the 50 bytes that actually differ.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 100
        data_b = b"\x00" * 50 + b"\xff" * 50
        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))

        assert set(result.keys()) == _RESULT_KEYS
        assert isinstance(result["files_identical"], bool)
        assert result["files_identical"] is False
        total_differences: int = result["total_differences"]
        assert isinstance(total_differences, int)
        assert total_differences >= 0

        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        diff_bytes_in_regions = sum(r["length"] for r in regions if r["diff_type"] in _NON_MATCH_TYPES)
        assert diff_bytes_in_regions == total_differences == 50
        match_total = sum(r["length"] for r in regions if r["diff_type"] == "match")
        assert match_total == 50
        _assert_total_differences_consistent(result)

    def test_diff_files_detects_known_modification_region(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files pinpoints the exact modified region at offset 50-100.

        The difflib oracle establishes the replace span is offset 50 length 50.
        The native result must be exactly a 50-byte ``match`` prefix followed by
        a ``modified`` region that fully covers offsets 50 through 100 in both
        buffers, with ``total_differences == 50``.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 100
        data_b = b"\x00" * 50 + b"\xff" * 50
        oracle_start, oracle_len = _expected_replace_span(data_a, data_b)
        assert (oracle_start, oracle_len) == (50, 50)

        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert result["files_identical"] is False
        assert result["total_differences"] == 50

        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 50, "diff_type": "match"},
            {"offset_a": 50, "offset_b": 50, "length": 50, "diff_type": "modified"},
        ]
        covering = [r for r in regions if r["diff_type"] == "modified" and r["offset_a"] == 50 and r["offset_a"] + r["length"] == 100]
        assert len(covering) == 1
        _assert_total_differences_consistent(result)

    def test_diff_files_truncated_tail_is_inserted_a(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files reports a truncated file's lost tail as inserted_a.

        ``0xaa*200`` against ``0xaa*100`` shares a 100-byte prefix; the extra
        100 bytes present only in A must be a single ``inserted_a`` region at
        offset 100 with length 100, and ``total_differences == 100``. The
        difflib oracle confirms an equal prefix followed by a delete of A's tail.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\xaa" * 200
        data_b = b"\xaa" * 100
        opcodes = difflib.SequenceMatcher(a=data_a, b=data_b, autojunk=False).get_opcodes()
        assert opcodes == [("equal", 0, 100, 0, 100), ("delete", 100, 200, 100, 100)]

        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert result["files_identical"] is False
        assert result["total_differences"] == 100

        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 100, "diff_type": "match"},
            {"offset_a": 100, "offset_b": 100, "length": 100, "diff_type": "inserted_a"},
        ]
        _assert_total_differences_consistent(result)

    def test_diff_empty_files(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files on two empty files reports exact equality.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "a.bin", b"")
        f_b = _write_bin(tmp_path, "b.bin", b"")
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert result["files_identical"] is True
        assert result["total_differences"] == 0
        assert _assert_well_formed_regions(result, 0, 0) == []

    def test_diff_files_single_byte_change(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files isolates a single differing byte at offset 32.

        A 64-byte zero buffer differing only at offset 32 must yield
        ``total_differences == 1`` with a one-byte ``modified`` region at
        offset 32, flanked by a 32-byte match prefix and a 31-byte match suffix.
        Because both buffers have equal length and differ in exactly one byte,
        the minimal edit script is unambiguously this match/modified/match
        layout regardless of Myers tie-breaking.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytes(64)
        data_b = bytearray(64)
        data_b[32] = 0xFF
        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert result["files_identical"] is False
        assert result["total_differences"] == 1

        regions = _assert_well_formed_regions(result, 64, 64)
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 32, "diff_type": "match"},
            {"offset_a": 32, "offset_b": 32, "length": 1, "diff_type": "modified"},
            {"offset_a": 33, "offset_b": 33, "length": 31, "diff_type": "match"},
        ]
        _assert_total_differences_consistent(result)

    def test_diff_files_missing_path_raises_io_error(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files surfaces an OSError when an input file is missing.

        The native reader maps a failed ``std::fs::read`` to a Python
        ``IOError`` (a subclass of ``OSError``); the failure must propagate
        rather than be swallowed into a result dict.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        existing = _write_bin(tmp_path, "present.bin", bytes(range(16)))
        missing = tmp_path / "does_not_exist.bin"
        assert not missing.exists()
        with pytest.raises(OSError, match="Failed to read"):
            hexcore.diff_files(str(existing), str(missing))
