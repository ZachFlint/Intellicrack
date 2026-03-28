# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument creation, opening, saving, and lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


class TestDocumentCreation:
    """Tests covering HexDocument construction and identity properties."""

    def test_empty_doc_has_zero_length(self, empty_doc: Any) -> None:
        """Verify that a freshly constructed HexDocument has length 0.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert empty_doc.length() == 0

    def test_open_bytes_creates_doc_with_correct_length(self, hexcore: Any, sample_bytes: bytes) -> None:
        """Verify that open_bytes produces a document whose length matches the input.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        assert doc.length() == len(sample_bytes)

    def test_open_bytes_content_matches_input(self, hexcore: Any, sample_bytes: bytes) -> None:
        """Verify that the bytes stored in the document match the input exactly.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        assert doc.read(0, len(sample_bytes)) == sample_bytes

    def test_open_from_file_has_correct_length(self, sample_doc: Any, sample_bytes: bytes) -> None:
        """Verify that opening a file produces a document with correct length.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        assert sample_doc.length() == len(sample_bytes)

    def test_open_from_file_content_matches_file(self, sample_doc: Any, sample_bytes: bytes) -> None:
        """Verify that a file-opened document exposes the file's exact bytes.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        assert sample_doc.read(0, len(sample_bytes)) == sample_bytes

    def test_in_memory_doc_file_path_is_none(self, sample_doc_from_bytes: Any) -> None:
        """Verify that an in-memory document returns None for file_path().

        Args:
            sample_doc_from_bytes: HexDocument created via open_bytes.
        """
        assert sample_doc_from_bytes.file_path() is None

    def test_file_opened_doc_returns_path(self, hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that a document opened from a file reports the correct path.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        f = tmp_path / "target.bin"
        f.write_bytes(sample_bytes)
        doc = hexcore.HexDocument.open(str(f))
        returned_path = doc.file_path()
        assert returned_path is not None
        assert Path(returned_path).resolve() == f.resolve()

    def test_empty_doc_file_path_is_none(self, empty_doc: Any) -> None:
        """Verify that a freshly constructed empty document has no file path.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert empty_doc.file_path() is None

    def test_open_nonexistent_file_raises(self, hexcore: Any, tmp_path: Path) -> None:
        """Verify that opening a non-existent file raises an exception.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        missing = tmp_path / "does_not_exist.bin"
        with pytest.raises((OSError, RuntimeError, ValueError)):
            hexcore.HexDocument.open(str(missing))

    def test_open_empty_file_succeeds_with_zero_length(self, hexcore: Any, tmp_path: Path) -> None:
        """Verify that opening a zero-byte file yields a document of length 0.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
        """
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")
        doc = hexcore.HexDocument.open(str(empty_file))
        assert doc.length() == 0


class TestDocumentSave:
    """Tests covering save, save_as, and modification-state after persistence."""

    def test_save_writes_correct_content_to_disk(self, hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that save() writes the document content verbatim to disk.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        src = tmp_path / "src.bin"
        src.write_bytes(sample_bytes)
        doc = hexcore.HexDocument.open(str(src))
        out = tmp_path / "out.bin"
        doc.save(str(out))
        assert out.read_bytes() == sample_bytes

    def test_save_as_creates_new_file(self, sample_doc: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that save_as() creates a new file at the given path.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        dest = tmp_path / "copy.bin"
        assert not dest.exists()
        sample_doc.save_as(str(dest))
        assert dest.exists()
        assert dest.read_bytes() == sample_bytes

    def test_is_modified_false_after_save(self, hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that is_modified() returns False immediately after a save.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        src = tmp_path / "base.bin"
        src.write_bytes(sample_bytes)
        doc = hexcore.HexDocument.open(str(src))
        doc.write_bytes(0, b"\xaa")
        assert doc.is_modified()
        out = tmp_path / "saved.bin"
        doc.save(str(out))
        assert not doc.is_modified()

    def test_save_then_reopen_preserves_data(self, hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that data saved to disk survives a fresh open of the same file.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        src = tmp_path / "base.bin"
        src.write_bytes(sample_bytes)
        doc = hexcore.HexDocument.open(str(src))
        patch = b"\xde\xad\xbe\xef"
        doc.write_bytes(0, patch)
        saved = tmp_path / "modified.bin"
        doc.save(str(saved))

        doc2 = hexcore.HexDocument.open(str(saved))
        assert doc2.read(0, 4) == patch
        assert doc2.read(4, len(sample_bytes) - 4) == sample_bytes[4:]

    def test_save_as_original_unchanged(self, hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> None:
        """Verify that save_as does not overwrite the original source file.

        Args:
            hexcore: The native module fixture.
            tmp_path: Pytest temporary directory.
            sample_bytes: The 256-byte payload fixture.
        """
        src = tmp_path / "original.bin"
        src.write_bytes(sample_bytes)
        doc = hexcore.HexDocument.open(str(src))
        doc.write_bytes(0, b"\xff\xff")
        dest = tmp_path / "new_copy.bin"
        doc.save_as(str(dest))
        assert src.read_bytes() == sample_bytes
