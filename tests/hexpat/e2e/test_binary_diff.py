# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for binary diff operations via diff_bytes and diff_files.

The native ``diff_bytes`` / ``diff_files`` functions return a dict with exactly
eight keys: ``files_identical`` (bool), ``total_differences`` (int),
``size_a`` / ``size_b`` (the byte counts actually compared), ``regions``
(a list of region dicts, each with ``offset_a``, ``offset_b``, ``length``,
``length_a``, ``length_b`` and ``diff_type``), and the three keys that account
for a list cut short by ``max_regions``: ``region_count`` (every region, listed
or not), ``change_count`` (the non-match ones) and ``truncated`` (whether any
region was left out). ``diff_type`` is one of ``"match"``, ``"modified"``,
``"inserted_a"`` or ``"inserted_b"``.

Two keyword arguments bound and group the output without changing which bytes
are reported as different: ``min_match`` folds an equal run shorter than it
that sits between two changes into one ``modified`` region, and ``max_regions``
stops listing regions past it while still counting them.

The native engine emits a Myers edit script (via the ``similar`` crate) where
contiguous matched runs become ``match`` regions, replaced runs become
``modified`` regions, bytes present only in A become ``inserted_a`` regions and
bytes present only in B become ``inserted_b`` regions. ``length_a`` and
``length_b`` are the true per-side spans actually consumed in A and B
respectively; for a ``modified`` region whose ``old_len`` and ``new_len``
differ, these are NOT equal. ``length`` is ``max(length_a, length_b)``, kept
for backward compatibility, and ``total_differences`` is the summed ``length``
of every non-match region.

Expected region layouts are cross-checked against Python's
``difflib.SequenceMatcher`` (the same Myers edit-script family the Rust engine
uses) for the contiguous single-replace cases where the two implementations
agree, and against the byte content directly for the remaining cases, so every
oracle is independent of the native engine's own output.
"""

from __future__ import annotations

import difflib
import hashlib
import inspect
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    import types
    from pathlib import Path

_DIFF_TYPES: frozenset[str] = frozenset({"match", "modified", "inserted_a", "inserted_b"})
_RESULT_KEYS: frozenset[str] = frozenset({
    "files_identical",
    "total_differences",
    "regions",
    "region_count",
    "change_count",
    "truncated",
    "size_a",
    "size_b",
})
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

    The result must carry exactly the eight documented top-level keys with the
    correct value types, and the listed regions must agree with the counts the
    engine reports for the whole comparison: ``region_count`` is never below the
    number listed, ``truncated`` is true exactly when it is above it, and
    ``change_count`` covers at least the changes that are listed (and exactly
    them when nothing was left out). Each region must carry exactly the six documented
    keys, a known ``diff_type`` tag, integer offsets and lengths, and
    offsets/spans that stay inside the respective input bounds. ``length_a``
    and ``length_b`` are the true per-side spans -- for a size-changing
    ``modified`` region they differ from one another and from ``length``,
    which must equal ``max(length_a, length_b)``. ``size_a`` and ``size_b``
    report the byte counts actually compared, so they must equal the input
    lengths exactly.

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
    assert result["size_a"] == len_a
    assert result["size_b"] == len_b
    regions: list[dict[str, Any]] = result["regions"]
    assert isinstance(regions, list)
    assert isinstance(result["region_count"], int)
    assert isinstance(result["change_count"], int)
    assert isinstance(result["truncated"], bool)
    listed_changes = sum(1 for region in regions if region["diff_type"] in _NON_MATCH_TYPES)
    assert result["region_count"] >= len(regions)
    assert result["truncated"] is (result["region_count"] > len(regions))
    assert listed_changes <= result["change_count"] <= result["region_count"]
    if not result["truncated"]:
        assert result["region_count"] == len(regions)
        assert result["change_count"] == listed_changes
    for region in regions:
        assert set(region.keys()) == {"offset_a", "offset_b", "length", "length_a", "length_b", "diff_type"}
        assert region["diff_type"] in _DIFF_TYPES
        offset_a: int = region["offset_a"]
        offset_b: int = region["offset_b"]
        length: int = region["length"]
        length_a: int = region["length_a"]
        length_b: int = region["length_b"]
        assert isinstance(offset_a, int)
        assert isinstance(offset_b, int)
        assert isinstance(length, int)
        assert isinstance(length_a, int)
        assert isinstance(length_b, int)
        assert 0 <= offset_a <= len_a
        assert 0 <= offset_b <= len_b
        assert length >= 0
        assert length_a >= 0
        assert length_b >= 0
        assert length == max(length_a, length_b)
        assert offset_a + length_a <= len_a
        assert offset_b + length_b <= len_b
        if region["diff_type"] == "match":
            assert length_a == length_b == length
        elif region["diff_type"] == "inserted_a":
            assert length_a == length
            assert length_b == 0
        elif region["diff_type"] == "inserted_b":
            assert length_b == length
            assert length_a == 0
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
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "length_a": 64, "length_b": 64, "diff_type": "match"}]
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
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "length_a": 64, "length_b": 64, "diff_type": "modified"}]
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
            {"offset_a": 0, "offset_b": 0, "length": 16, "length_a": 16, "length_b": 16, "diff_type": "match"},
            {"offset_a": 16, "offset_b": 16, "length": 8, "length_a": 8, "length_b": 8, "diff_type": "modified"},
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
            {"offset_a": 0, "offset_b": 0, "length": 50, "length_a": 50, "length_b": 50, "diff_type": "match"},
            {"offset_a": 50, "offset_b": 50, "length": 50, "length_a": 50, "length_b": 50, "diff_type": "modified"},
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
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 3, "length_a": 3, "length_b": 0, "diff_type": "inserted_a"}]
        _assert_total_differences_consistent(result)

    def test_diff_bytes_replace_with_differing_lengths_reports_true_per_side_spans(self, hexcore: types.ModuleType) -> None:
        """Verify a size-changing replace reports independent length_a/length_b spans.

        When a modified span consumes a different number of bytes in each
        buffer (``old_len != new_len``), the region must report ``length_a``
        as the exact A-side span and ``length_b`` as the exact B-side span
        rather than collapsing both to ``max(old_len, new_len)`` -- doing so
        would claim a byte range in A that runs past the bytes actually
        replaced there. The difflib oracle confirms the single replace opcode
        has ``old_len == 5`` and ``new_len == 8``.

        Args:
            hexcore: The native module fixture.
        """
        prefix = bytes(range(16))
        suffix = bytes(range(200, 216))
        data_a = prefix + b"\x11" * 5 + suffix
        data_b = prefix + b"\x22" * 8 + suffix
        matcher = difflib.SequenceMatcher(a=data_a, b=data_b, autojunk=False)
        replaces = [(i1, i2, j1, j2) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag == "replace"]
        assert len(replaces) == 1, f"oracle expected exactly one replace span, got {replaces}"
        i1, i2, j1, j2 = replaces[0]
        assert (i1, i2 - i1, j1, j2 - j1) == (16, 5, 16, 8)

        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert result["files_identical"] is False
        regions = _assert_well_formed_regions(result, len(data_a), len(data_b))
        assert regions == [
            {"offset_a": 0, "offset_b": 0, "length": 16, "length_a": 16, "length_b": 16, "diff_type": "match"},
            {"offset_a": 16, "offset_b": 16, "length": 8, "length_a": 5, "length_b": 8, "diff_type": "modified"},
            {"offset_a": 21, "offset_b": 24, "length": 16, "length_a": 16, "length_b": 16, "diff_type": "match"},
        ]
        modified = regions[1]
        assert modified["length_a"] != modified["length_b"]
        assert modified["offset_a"] + modified["length_a"] == len(data_a) - len(suffix)
        assert modified["offset_b"] + modified["length_b"] == len(data_b) - len(suffix)
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
        assert regions == [{"offset_a": 0, "offset_b": 0, "length": 64, "length_a": 64, "length_b": 64, "diff_type": "match"}]
        _assert_total_differences_consistent(result)

    def test_diff_files_result_has_full_schema_with_valid_values(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify diff_files returns the complete schema with sensible values.

        Asserts the result contains exactly the eight documented keys, that
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
            {"offset_a": 0, "offset_b": 0, "length": 50, "length_a": 50, "length_b": 50, "diff_type": "match"},
            {"offset_a": 50, "offset_b": 50, "length": 50, "length_a": 50, "length_b": 50, "diff_type": "modified"},
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
            {"offset_a": 0, "offset_b": 0, "length": 100, "length_a": 100, "length_b": 100, "diff_type": "match"},
            {"offset_a": 100, "offset_b": 100, "length": 100, "length_a": 100, "length_b": 0, "diff_type": "inserted_a"},
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
            {"offset_a": 0, "offset_b": 0, "length": 32, "length_a": 32, "length_b": 32, "diff_type": "match"},
            {"offset_a": 32, "offset_b": 32, "length": 1, "length_a": 1, "length_b": 1, "diff_type": "modified"},
            {"offset_a": 33, "offset_b": 33, "length": 31, "length_a": 31, "length_b": 31, "diff_type": "match"},
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


_HEAD = 64 * 1024
_PERIOD = 64
_TOP_BIT = 0x80
_DEFAULT_MAX_REGIONS = 100_000
_SMALL_A = b"AAAA-B-CCCC-D-EEEE"
_SMALL_B = b"AAAA-X-CCCC-Y-EEEE"
_CHAIN_A = b"S1ab2cd3EEEEEEEEEE4T"
_CHAIN_B = b"SWabXcdYEEEEEEEEEEZT"


def _region(diff_type: str, offset_a: int, offset_b: int, length_a: int, length_b: int) -> dict[str, Any]:
    """Build the region dict the engine reports for the given span.

    Args:
        diff_type: One of the four ``diff_type`` tags.
        offset_a: Start of the region in the first buffer.
        offset_b: Start of the region in the second buffer.
        length_a: Bytes the region covers in the first buffer.
        length_b: Bytes the region covers in the second buffer.

    Returns:
        dict[str, Any]: The region exactly as ``diff_bytes`` would list it.
    """
    return {
        "offset_a": offset_a,
        "offset_b": offset_b,
        "length": max(length_a, length_b),
        "length_a": length_a,
        "length_b": length_b,
        "diff_type": diff_type,
    }


def _assert_regions_partition(regions: list[dict[str, Any]], data_a: bytes, data_b: bytes) -> None:
    """Walk the regions with one cursor per buffer and rebuild both ends.

    Every region must start where the previous one ended on both sides, every
    ``match`` region must cover equal bytes, and the walk must finish exactly at
    both buffer lengths. This holds an independent copy of the contract the
    engine's ordered, gap-free edit script is documented to keep.

    Args:
        regions: The complete (untruncated) region list.
        data_a: First buffer.
        data_b: Second buffer.
    """
    cursor_a = cursor_b = 0
    for region in regions:
        assert (region["offset_a"], region["offset_b"]) == (cursor_a, cursor_b), region
        if region["diff_type"] == "match":
            assert data_a[cursor_a : cursor_a + region["length_a"]] == data_b[cursor_b : cursor_b + region["length_b"]]
        cursor_a += region["length_a"]
        cursor_b += region["length_b"]
    assert (cursor_a, cursor_b) == (len(data_a), len(data_b))


def _periodic(length: int) -> bytes:
    """Build a buffer repeating the values ``0..63``.

    Args:
        length: Number of bytes.

    Returns:
        bytes: The buffer.
    """
    return bytes(index % _PERIOD for index in range(length))


def _flipped(source: bytes, positions: range) -> bytes:
    """Copy a buffer with the top bit set at the given positions.

    The source holds only values below 128, so a flipped byte equals nothing in
    it and every edit is a lone substitution with a unique minimal alignment.

    Args:
        source: Buffer of values below 128.
        positions: Offsets to flip.

    Returns:
        bytes: The edited copy.
    """
    edited = bytearray(source)
    for position in positions:
        edited[position] |= _TOP_BIT
    return bytes(edited)


def _noise(seed: int, length: int) -> bytes:
    """Produce reproducible noise that no run or period in it can be mistaken for.

    Args:
        seed: Selects the stream.
        length: Number of bytes.

    Returns:
        bytes: ``length`` bytes of a SHAKE-256 stream keyed by ``seed``.
    """
    return hashlib.shake_256(seed.to_bytes(4, "little")).digest(length)


def _padded(pad: int, fill: int, seed: int) -> bytes:
    """Build noise, a long run of one byte, and more noise.

    Args:
        pad: Length of the run.
        fill: Value of the run.
        seed: Seed of the noise on either side.

    Returns:
        bytes: ``HEAD`` noise bytes, ``pad`` copies of ``fill``, ``HEAD`` more noise bytes.
    """
    return _noise(seed, _HEAD) + bytes([fill]) * pad + _noise(seed + 1, _HEAD)


class TestDiffMinMatch:
    """``min_match`` folds a short equal run between two changes into one region."""

    def test_a_gap_shorter_than_min_match_folds_the_changes_together(self, hexcore: types.ModuleType) -> None:
        """Verify a six-byte gap between two changes folds at ``min_match=7``.

        The inputs have a one-byte change, six equal bytes, then another
        one-byte change. At the default the script is match/modified/match/
        modified/match. With ``min_match=7`` the gap is shorter than the
        minimum, so everything from the first change to the second becomes one
        eight-byte ``modified`` region, while ``total_differences`` stays the
        two bytes that differ.

        Args:
            hexcore: The native module fixture.
        """
        unfolded = hexcore.diff_bytes(_SMALL_A, _SMALL_B)
        assert unfolded["regions"] == [
            _region("match", 0, 0, 5, 5),
            _region("modified", 5, 5, 1, 1),
            _region("match", 6, 6, 6, 6),
            _region("modified", 12, 12, 1, 1),
            _region("match", 13, 13, 5, 5),
        ]

        folded: dict[str, Any] = hexcore.diff_bytes(_SMALL_A, _SMALL_B, min_match=7)
        regions = _assert_well_formed_regions(folded, len(_SMALL_A), len(_SMALL_B))
        assert regions == [_region("match", 0, 0, 5, 5), _region("modified", 5, 5, 8, 8), _region("match", 13, 13, 5, 5)]
        assert folded["total_differences"] == 2
        assert folded["change_count"] == 1
        assert folded["region_count"] == 3
        _assert_regions_partition(regions, _SMALL_A, _SMALL_B)

    def test_a_gap_exactly_min_match_long_is_kept(self, hexcore: types.ModuleType) -> None:
        """Verify only a run strictly shorter than ``min_match`` folds.

        The gap between the changes is six bytes, so ``min_match=6`` keeps it
        and ``min_match=7`` folds it.

        Args:
            hexcore: The native module fixture.
        """
        kept: dict[str, Any] = hexcore.diff_bytes(_SMALL_A, _SMALL_B, min_match=6)
        folded: dict[str, Any] = hexcore.diff_bytes(_SMALL_A, _SMALL_B, min_match=7)
        assert kept["change_count"] == 2
        assert folded["change_count"] == 1

    def test_runs_before_the_first_change_and_after_the_last_never_fold(self, hexcore: types.ModuleType) -> None:
        """Verify a huge ``min_match`` leaves the context around a lone change alone.

        Only a run *between* two changes folds. The two-byte run before the
        change and the two-byte run after it are context, so a minimum of 100
        must not swallow them.

        Args:
            hexcore: The native module fixture.
        """
        result: dict[str, Any] = hexcore.diff_bytes(b"x_Y_z", b"x_Q_z", min_match=100)
        assert result["regions"] == [_region("match", 0, 0, 2, 2), _region("modified", 2, 2, 1, 1), _region("match", 3, 3, 2, 2)]

    def test_folding_chains_across_short_gaps_and_stops_at_a_long_one(self, hexcore: types.ModuleType) -> None:
        """Verify consecutive short gaps fold into one region and a long gap ends it.

        ``S1ab2cd3EEEEEEEEEE4T`` against ``SWabXcdYEEEEEEEEEEZT`` has four
        one-byte changes separated by gaps of 2, 2 and 10 bytes. At
        ``min_match=5`` the first three changes fold into one seven-byte region
        and the last stays apart behind the ten-byte gap. At ``min_match=11``
        even that gap folds.

        Args:
            hexcore: The native module fixture.
        """
        chained: dict[str, Any] = hexcore.diff_bytes(_CHAIN_A, _CHAIN_B, min_match=5)
        assert chained["regions"] == [
            _region("match", 0, 0, 1, 1),
            _region("modified", 1, 1, 7, 7),
            _region("match", 8, 8, 10, 10),
            _region("modified", 18, 18, 1, 1),
            _region("match", 19, 19, 1, 1),
        ]
        everything: dict[str, Any] = hexcore.diff_bytes(_CHAIN_A, _CHAIN_B, min_match=11)
        assert everything["regions"] == [
            _region("match", 0, 0, 1, 1),
            _region("modified", 1, 1, 18, 18),
            _region("match", 19, 19, 1, 1),
        ]

    @pytest.mark.parametrize("min_match", [0, 1, 2, 5, 11, 100])
    def test_min_match_never_changes_how_many_bytes_differ(self, hexcore: types.ModuleType, min_match: int) -> None:
        """Verify ``total_differences`` is the same whatever ``min_match`` is.

        Args:
            hexcore: The native module fixture.
            min_match: Minimum equal-run length under test.
        """
        result: dict[str, Any] = hexcore.diff_bytes(_CHAIN_A, _CHAIN_B, min_match=min_match)
        assert result["total_differences"] == 4
        assert result["files_identical"] is False

    def test_zero_and_one_fold_nothing(self, hexcore: types.ModuleType) -> None:
        """Verify the default minimum of one, and zero, give the unfolded script.

        The one-byte gaps in ``aXbYc`` against ``aPbQc`` would fold at
        ``min_match=2`` but must not at 0 or 1.

        Args:
            hexcore: The native module fixture.
        """
        unfolded = [
            _region("match", 0, 0, 1, 1),
            _region("modified", 1, 1, 1, 1),
            _region("match", 2, 2, 1, 1),
            _region("modified", 3, 3, 1, 1),
            _region("match", 4, 4, 1, 1),
        ]
        assert hexcore.diff_bytes(b"aXbYc", b"aPbQc")["regions"] == unfolded
        assert hexcore.diff_bytes(b"aXbYc", b"aPbQc", min_match=1)["regions"] == unfolded
        assert hexcore.diff_bytes(b"aXbYc", b"aPbQc", min_match=0)["regions"] == unfolded
        assert hexcore.diff_bytes(b"aXbYc", b"aPbQc", min_match=2)["regions"] == [
            _region("match", 0, 0, 1, 1),
            _region("modified", 1, 1, 3, 3),
            _region("match", 4, 4, 1, 1),
        ]

    def test_diff_files_honors_min_match(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify ``diff_files`` takes the same ``min_match`` as ``diff_bytes``.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "a.bin", _SMALL_A)
        f_b = _write_bin(tmp_path, "b.bin", _SMALL_B)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b), min_match=7)
        assert result["regions"] == [_region("match", 0, 0, 5, 5), _region("modified", 5, 5, 8, 8), _region("match", 13, 13, 5, 5)]
        assert hexcore.diff_files(str(f_a), str(f_b), 7)["change_count"] == 1


class TestDiffMaxRegions:
    """``max_regions`` bounds what is listed while every count stays exact."""

    def test_regions_past_the_cap_are_counted_but_not_listed(self, hexcore: types.ModuleType) -> None:
        """Verify a cap of 50 over 401 regions lists 50 and still reports 401.

        200 isolated one-byte substitutions give 200 change regions and 201
        match regions. The list is cut at 50, ``truncated`` is set, and the
        counts and ``total_differences`` describe the whole comparison.

        Args:
            hexcore: The native module fixture.
        """
        source = _periodic(3 + 7 * 200 + 4)
        edited = _flipped(source, range(3, 3 + 7 * 200, 7))
        result: dict[str, Any] = hexcore.diff_bytes(source, edited, max_regions=50)
        assert len(result["regions"]) == 50
        assert result["region_count"] == 401
        assert result["change_count"] == 200
        assert result["total_differences"] == 200
        assert result["truncated"] is True
        assert result["files_identical"] is False
        _assert_well_formed_regions(result, len(source), len(edited))

    def test_the_listed_regions_are_the_front_of_the_full_list(self, hexcore: types.ModuleType) -> None:
        """Verify truncation drops the tail, so what is listed still partitions a prefix.

        Args:
            hexcore: The native module fixture.
        """
        source = _periodic(3 + 7 * 200 + 4)
        edited = _flipped(source, range(3, 3 + 7 * 200, 7))
        full: dict[str, Any] = hexcore.diff_bytes(source, edited, max_regions=10_000)
        capped: dict[str, Any] = hexcore.diff_bytes(source, edited, max_regions=50)
        assert full["truncated"] is False
        assert capped["regions"] == full["regions"][:50]
        assert (full["region_count"], full["change_count"]) == (capped["region_count"], capped["change_count"])

    def test_a_cap_of_zero_lists_nothing_and_counts_everything(self, hexcore: types.ModuleType) -> None:
        """Verify ``max_regions=0`` is a valid way to ask only for the counts.

        Args:
            hexcore: The native module fixture.
        """
        different: dict[str, Any] = hexcore.diff_bytes(b"abc", b"abd", max_regions=0)
        assert different["regions"] == []
        assert (different["region_count"], different["change_count"], different["total_differences"]) == (2, 1, 1)
        assert different["truncated"] is True
        same: dict[str, Any] = hexcore.diff_bytes(b"same", b"same", max_regions=0)
        assert same["regions"] == []
        assert (same["region_count"], same["change_count"]) == (1, 0)
        assert same["truncated"] is True
        assert same["files_identical"] is True

    def test_a_result_that_exactly_fits_is_not_truncated(self, hexcore: types.ModuleType) -> None:
        """Verify ``truncated`` is false when the cap equals the region count.

        Args:
            hexcore: The native module fixture.
        """
        exact: dict[str, Any] = hexcore.diff_bytes(_SMALL_A, _SMALL_B, max_regions=5)
        assert exact["truncated"] is False
        assert len(exact["regions"]) == exact["region_count"] == 5
        assert hexcore.diff_bytes(_SMALL_A, _SMALL_B, max_regions=4)["truncated"] is True

    def test_the_defaults_are_one_and_one_hundred_thousand(self, hexcore: types.ModuleType) -> None:
        """Verify the compiled signature advertises the documented defaults.

        Args:
            hexcore: The native module fixture.
        """
        for function in (hexcore.diff_bytes, hexcore.diff_files):
            parameters = inspect.signature(function).parameters
            assert parameters["min_match"].default == 1
            assert parameters["max_regions"].default == _DEFAULT_MAX_REGIONS

    def test_every_other_byte_differing_is_bounded_at_the_default_cap(self, hexcore: types.ModuleType) -> None:
        """Verify two 1 MiB inputs differing at every other byte list 100000 regions.

        There are 524285 isolated substitutions, so the comparison has 1048571
        regions: a million dicts and tree rows before the cap existed. With the
        default cap exactly the first 100000 are listed, the list ends on the
        region the pattern puts there, and every count and ``total_differences``
        still describes the whole comparison.

        Args:
            hexcore: The native module fixture.
        """
        length = 1 << 20
        positions = range(3, length - 4, 2)
        source = _periodic(length)
        edited = _flipped(source, positions)
        result: dict[str, Any] = hexcore.diff_bytes(source, edited)
        assert len(result["regions"]) == _DEFAULT_MAX_REGIONS
        assert result["region_count"] == 2 * len(positions) + 1 == 1_048_571
        assert result["change_count"] == len(positions) == 524_285
        assert result["total_differences"] == len(positions)
        assert result["truncated"] is True
        assert result["regions"][0] == _region("match", 0, 0, 3, 3)
        assert result["regions"][1] == _region("modified", 3, 3, 1, 1)
        last_change_offset = 3 + 2 * 49_999
        assert result["regions"][-1] == _region("modified", last_change_offset, last_change_offset, 1, 1)

    def test_a_negative_limit_is_refused(self, hexcore: types.ModuleType) -> None:
        """Verify a negative limit raises instead of wrapping around to a huge one.

        Args:
            hexcore: The native module fixture.
        """
        with pytest.raises(OverflowError):
            hexcore.diff_bytes(b"a", b"b", max_regions=-1)
        with pytest.raises(OverflowError):
            hexcore.diff_bytes(b"a", b"b", min_match=-1)

    def test_diff_files_honors_max_regions(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify ``diff_files`` takes the same ``max_regions`` as ``diff_bytes``.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "a.bin", _SMALL_A)
        f_b = _write_bin(tmp_path, "b.bin", _SMALL_B)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b), max_regions=2)
        assert len(result["regions"]) == 2
        assert (result["region_count"], result["change_count"], result["total_differences"]) == (5, 2, 2)
        assert result["truncated"] is True


class TestDiffPaddedInputs:
    """Large inputs with long runs of one byte compare exactly, edits inside the runs included."""

    @pytest.mark.parametrize("fill", [0x00, 0xFF])
    def test_distant_edits_inside_huge_padding_stay_separate(self, hexcore: types.ModuleType, fill: int) -> None:
        """Verify two single-byte edits ten million bytes apart are two one-byte regions.

        The padding is a 12 MiB run of one byte between two noise blocks. The
        old anchor test could not anchor such a run at all, so the segment
        holding both edits was too large for the byte-level diff and everything
        between the edits was reported as one ten-megabyte ``modified`` region.

        Args:
            hexcore: The native module fixture.
            fill: Byte value of the padding.
        """
        source = _padded(12 * 1024 * 1024, fill, seed=3)
        first = _HEAD + 1_000_003
        second = _HEAD + 11_000_007
        edited = bytearray(source)
        edited[first] = fill ^ 0x5A
        edited[second] = fill ^ 0xA5
        result: dict[str, Any] = hexcore.diff_bytes(source, bytes(edited))
        assert result["regions"] == [
            _region("match", 0, 0, first, first),
            _region("modified", first, first, 1, 1),
            _region("match", first + 1, first + 1, second - first - 1, second - first - 1),
            _region("modified", second, second, 1, 1),
            _region("match", second + 1, second + 1, len(source) - second - 1, len(source) - second - 1),
        ]
        assert result["total_differences"] == 2

    @pytest.mark.parametrize("edit", [1, 300_001, 2 * 1024 * 1024 - 2])
    def test_one_edit_inside_padding_is_one_byte(self, hexcore: types.ModuleType, edit: int) -> None:
        """Verify a single changed byte inside a padded run is one one-byte region.

        With anchors in the padding, the anchors after the edit must still line
        up with the other buffer's. When they do not, the segment between two
        mismatched anchors reports a shift that is in neither input (a
        1055-byte insertion paired with a 1055-byte deletion, 2110 differences
        for one changed byte).

        Args:
            hexcore: The native module fixture.
            edit: Offset of the changed byte inside the padding.
        """
        source = _padded(2 * 1024 * 1024, 0x00, seed=4)
        edited = bytearray(source)
        edited[_HEAD + edit] = 0x5A
        result: dict[str, Any] = hexcore.diff_bytes(source, bytes(edited))
        at = _HEAD + edit
        assert result["regions"] == [
            _region("match", 0, 0, at, at),
            _region("modified", at, at, 1, 1),
            _region("match", at + 1, at + 1, len(source) - at - 1, len(source) - at - 1),
        ]
        assert result["total_differences"] == 1

    def test_resized_padding_is_found_wherever_it_is(self, hexcore: types.ModuleType) -> None:
        """Verify two grown pads five megabytes apart are two insertions of exactly their growth.

        Args:
            hexcore: The native module fixture.
        """
        before, between, after = _noise(5, _HEAD), _noise(6, 5 * 1024 * 1024), _noise(7, _HEAD)

        def build(pad: int) -> bytes:
            return before + bytes(pad) + between + bytes(pad) + after

        source, grown = build(30 * 1024), build(60 * 1024)
        result: dict[str, Any] = hexcore.diff_bytes(source, grown)
        regions = _assert_well_formed_regions(result, len(source), len(grown))
        changes = [(r["diff_type"], r["length_a"], r["length_b"]) for r in regions if r["diff_type"] != "match"]
        assert changes == [("inserted_b", 0, 30 * 1024), ("inserted_b", 0, 30 * 1024)]
        assert result["total_differences"] == 60 * 1024
        _assert_regions_partition(regions, source, grown)

    def test_a_near_identical_large_pair_is_three_regions_not_one_per_segment(self, hexcore: types.ModuleType) -> None:
        """Verify the equal stretches either side of one edit are single regions.

        The anchored path cuts the inputs into segments of about two kilobytes;
        listing each equal segment as its own ``match`` region would give a
        1.5 MiB pair roughly 750 regions and spend the region cap on nothing.

        Args:
            hexcore: The native module fixture.
        """
        source = _noise(8, 1_572_864)
        at = 700_001
        edited = bytearray(source)
        edited[at] ^= 0xFF
        result: dict[str, Any] = hexcore.diff_bytes(source, bytes(edited))
        assert result["regions"] == [
            _region("match", 0, 0, at, at),
            _region("modified", at, at, 1, 1),
            _region("match", at + 1, at + 1, len(source) - at - 1, len(source) - at - 1),
        ]
        assert result["region_count"] == 3
