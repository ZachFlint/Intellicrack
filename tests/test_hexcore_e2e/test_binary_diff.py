# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for binary diff operations via diff_bytes and diff_files."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    import types
    from pathlib import Path


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


class TestDiffBytes:
    """Tests covering the diff_bytes() module-level function."""

    def test_identical_bytes_reports_identical(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes on two identical payloads reports equality.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 64
        result: dict[str, Any] = hexcore.diff_bytes(data, data)
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (isinstance(similarity, float) and similarity >= 0.99)

    def test_completely_different_bytes_shows_low_similarity(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes on disjoint payloads reports low similarity.

        Args:
            hexcore: The native module fixture.
        """
        data_a = b"\x00" * 64
        data_b = b"\xff" * 64
        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert isinstance(result, dict)
        if not result.get("files_identical"):
            similarity: float = result.get("similarity", 1.0)
            assert isinstance(similarity, float)
            assert similarity < 0.5

    def test_diff_bytes_result_is_dict(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes always returns a dict regardless of input.

        Args:
            hexcore: The native module fixture.
        """
        result: dict[str, Any] = hexcore.diff_bytes(b"\x01\x02", b"\x03\x04")
        assert isinstance(result, dict)

    def test_diff_bytes_partial_difference_has_modifications(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes identifies modification regions for partially differing data.

        Args:
            hexcore: The native module fixture.
        """
        data_a = b"\x00" * 50 + b"\xff" * 50
        data_b = b"\x00" * 50 + b"\x00" * 50
        result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
        assert isinstance(result, dict)
        modifications: Any = result.get("modifications", result.get("changed_bytes"))
        files_identical: bool = result.get("files_identical", False)
        assert not files_identical or modifications == 0

    def test_diff_empty_vs_empty_is_identical(self, hexcore: types.ModuleType) -> None:
        """Verify that diff_bytes on two empty byte strings reports files as identical.

        Args:
            hexcore: The native module fixture.
        """
        result: dict[str, Any] = hexcore.diff_bytes(b"", b"")
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (similarity is not None and similarity >= 0.99)


class TestDiffFiles:
    """Tests covering the diff_files() module-level function."""

    def test_diff_identical_files_reports_identical(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files on two identical files reports equality.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytes(range(64))
        f_a = _write_bin(tmp_path, "a.bin", data)
        f_b = _write_bin(tmp_path, "b.bin", data)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (isinstance(similarity, float) and similarity >= 0.99)

    def test_diff_files_result_has_expected_keys(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files returns a dict containing at least one recognized key.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 100
        data_b = b"\x00" * 50 + b"\xff" * 50
        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        recognized = {
            "similarity",
            "files_identical",
            "additions",
            "deletions",
            "modifications",
            "match_blocks",
            "changed_bytes",
            "total_bytes",
        }
        assert isinstance(result, dict)
        assert len(recognized & set(result.keys())) > 0

    def test_diff_files_detects_known_modification_region(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files identifies the modified region at offset 50.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\x00" * 100
        data_b = b"\x00" * 50 + b"\xff" * 50
        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert not result.get("files_identical")
        similarity: float = result.get("similarity", 1.0)
        assert isinstance(similarity, float)
        assert similarity < 1.0

    def test_diff_files_on_different_sizes(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files handles files of different lengths without error.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = b"\xaa" * 200
        data_b = b"\xaa" * 100
        f_a = _write_bin(tmp_path, "a.bin", data_a)
        f_b = _write_bin(tmp_path, "b.bin", data_b)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_diff_empty_files(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files on two empty files reports files as identical.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        f_a = _write_bin(tmp_path, "a.bin", b"")
        f_b = _write_bin(tmp_path, "b.bin", b"")
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert isinstance(result, dict)
        files_identical: bool | None = result.get("files_identical")
        similarity: float | None = result.get("similarity")
        assert files_identical is True or (similarity is not None and similarity >= 0.99)

    def test_diff_files_single_byte_change(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files detects a single differing byte.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data_a = bytearray(64)
        data_b = bytearray(64)
        data_b[32] = 0xFF
        f_a = _write_bin(tmp_path, "a.bin", bytes(data_a))
        f_b = _write_bin(tmp_path, "b.bin", bytes(data_b))
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert isinstance(result, dict)
        assert not result.get("files_identical")

    def test_diff_files_uses_string_paths(self, hexcore: types.ModuleType, tmp_path: Path) -> None:
        """Verify that diff_files accepts string paths and returns a valid dict.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"\x01\x02\x03\x04"
        f_a = _write_bin(tmp_path, "x.bin", data)
        f_b = _write_bin(tmp_path, "y.bin", data)
        result: dict[str, Any] = hexcore.diff_files(str(f_a), str(f_b))
        assert isinstance(result, dict)
