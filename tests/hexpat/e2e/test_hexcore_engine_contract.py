# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Python-visible contract of the hexcore engine.

Each test drives the real ``intellicrack_hexcore`` extension and pins a
behaviour pinned here: malformed input raises ``ValueError``
instead of returning an empty, indistinguishable-from-no-match result; edits
that rebuild the whole document keep its file path and stay undoable; patch
exports refuse histories they cannot reproduce; and the long-running analyses
release the GIL so another Python thread keeps running.
"""

from __future__ import annotations

import struct
import threading
import time
from typing import TYPE_CHECKING, Final

import intellicrack_hexcore
import pytest
from intellicrack_hexcore import HexDocument


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_CALIBRATION_SECONDS: Final[float] = 0.05
"""How long the spinning thread runs unopposed to measure its tick rate."""

_MIN_CALL_SECONDS: Final[float] = 0.05
"""Shortest call worth measuring; the GIL switch interval is 0.005 s."""

_RELEASED_FRACTION: Final[float] = 0.2
"""Share of the unopposed tick rate a detached call must still allow."""


def _ticks_while(call: Callable[[], object]) -> tuple[int, float, float]:
    """Count how far a busy Python thread advances while ``call`` runs.

    Args:
        call: The engine call to measure.

    Returns:
        tuple[int, float, float]: Ticks observed during the call, the call's
        duration in seconds, and the spinning thread's unopposed ticks per
        second.
    """
    counter = [0]
    stop = threading.Event()
    running = threading.Event()

    def spin() -> None:
        running.set()
        while not stop.is_set():
            counter[0] += 1

    worker = threading.Thread(target=spin, name="gil-probe")
    worker.start()
    try:
        assert running.wait(5.0), "probe thread never started"
        start_ticks = counter[0]
        time.sleep(_CALIBRATION_SECONDS)
        rate = (counter[0] - start_ticks) / _CALIBRATION_SECONDS
        before = counter[0]
        started = time.perf_counter()
        call()
        elapsed = time.perf_counter() - started
        during = counter[0] - before
    finally:
        stop.set()
        worker.join(5.0)
    assert not worker.is_alive(), "probe thread did not stop"
    return during, elapsed, rate


def _assert_releases_gil(call: Callable[[], object]) -> None:
    """Assert ``call`` lets another Python thread run while it works.

    A call that holds the GIL freezes the probe thread for its whole duration,
    so the probe advances by at most one switch interval's worth of ticks; a
    call that detaches lets it run at a large share of its unopposed rate.

    Args:
        call: The engine call to measure.
    """
    during, elapsed, rate = _ticks_while(call)
    assert elapsed >= _MIN_CALL_SECONDS, f"call took only {elapsed:.3f}s; enlarge the input"
    assert during > rate * elapsed * _RELEASED_FRACTION, (
        f"probe advanced {during} ticks in {elapsed:.3f}s at {rate:.0f} ticks/s: the call held the GIL"
    )


def _large_pe(size: int) -> bytes:
    """Build a structurally valid PE image of ``size`` bytes.

    Args:
        size: Total image size; must exceed the headers.

    Returns:
        bytes: An MZ/PE image whose checksum can be verified.
    """
    image = bytearray(size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, 0x8664)
    struct.pack_into("<H", image, 0x94, 0xF0)
    struct.pack_into("<H", image, 0x98, 0x20B)
    for offset in range(0x400, size, 4096):
        image[offset] = offset & 0xFF
    return bytes(image)


class TestGilReleasedDuringHeavyWork:
    """Long analyses release the GIL while they work on the whole document."""

    @staticmethod
    def test_extract_strings_releases_gil() -> None:
        """String extraction over 128 MiB lets another Python thread run.

        Falsifiable: if ``extract_strings`` scanned with the GIL held, the probe thread
                would make no progress during the call.
        """
        doc = HexDocument.open_bytes(b"ABCD\x00" * (128 * 1024 * 1024 // 5))
        _assert_releases_gil(lambda: doc.extract_strings(min_length=4, include_ascii=True, include_utf16=True, max_results=1))

    @staticmethod
    def test_verify_pe_checksum_releases_gil() -> None:
        """PE checksum verification over 192 MiB lets another thread run.

        Falsifiable: if the whole-image copy and word sum ran with
        the GIL held.
        """
        doc = HexDocument.open_bytes(_large_pe(192 * 1024 * 1024))
        _assert_releases_gil(doc.verify_pe_checksum)

    @staticmethod
    def test_save_releases_gil(tmp_path: Path) -> None:
        """Saving 128 MiB lets another thread run during the write and sync.

        Args:
            tmp_path: Pytest temporary directory.
        """
        doc = HexDocument.open_bytes(b"\x5a" * (128 * 1024 * 1024))
        target = tmp_path / "saved.bin"
        _assert_releases_gil(lambda: doc.save(str(target)))
        assert target.stat().st_size == 128 * 1024 * 1024

    @staticmethod
    def test_fill_block_releases_gil() -> None:
        """Filling 128 MiB lets another Python thread run during the copy.

        Falsifiable: if ``fill_block`` built its pattern and overwrote the range
        with the GIL held, the probe thread would make no progress for the whole
        call.
        """
        size = 128 * 1024 * 1024
        doc = HexDocument.open_bytes(b"\x00" * size)
        _assert_releases_gil(lambda: doc.fill_block(0, size, b"\xa5"))
        assert doc.read(size - 1, 1) == b"\xa5"


class TestMalformedInputRaises:
    """Input that cannot be evaluated is reported, never silently empty."""

    @staticmethod
    def test_invalid_regex_raises() -> None:
        """An uncompilable regex raises instead of reporting zero matches."""
        doc = HexDocument.open_bytes(b"data")
        with pytest.raises(ValueError, match="invalid regex"):
            doc.search_regex("[unclosed", 10)

    @staticmethod
    def test_unknown_text_encoding_raises() -> None:
        """An unknown encoding name raises from both text-search entry points."""
        doc = HexDocument.open_bytes(b"hello")
        with pytest.raises(ValueError, match="unsupported encoding: no-such-encoding"):
            doc.search_text("he", "no-such-encoding", case_sensitive=True, max_results=10)
        with pytest.raises(ValueError, match="unsupported encoding: no-such-encoding"):
            doc.search_text_encoded("he", "no-such-encoding", case_sensitive=True, max_results=10)

    @staticmethod
    def test_hex_pattern_with_prefix_raises_instead_of_searching_other_bytes() -> None:
        """``0x4D 0x5A`` is rejected rather than searched as ``04 D0 5A``."""
        doc = HexDocument.open_bytes(bytes([0x04, 0xD0, 0x5A]))
        with pytest.raises(ValueError, match="unexpected character 'x' at position 1"):
            doc.search_hex("0x4D 0x5A", 10)
        assert doc.search_hex("4D 5A", 10) == []

    @staticmethod
    def test_zero_block_size_raises() -> None:
        """A zero block size raises instead of returning an empty map."""
        doc = HexDocument.open_bytes(b"abc")
        for method in (doc.entropy_map, doc.entropy_map_bytes, doc.content_classification):
            with pytest.raises(ValueError, match="block_size must be at least 1"):
                method(0)

    @staticmethod
    def test_replace_with_empty_pattern_raises() -> None:
        """An empty pattern raises, matching ``fill_block``."""
        doc = HexDocument.open_bytes(b"abcd")
        with pytest.raises(ValueError, match="pattern cannot be empty"):
            doc.replace_bytes(b"", b"X")
        assert doc.read(0, 4) == b"abcd"

    @staticmethod
    def test_offsets_past_the_end_raise_like_read() -> None:
        """``decode_text`` and ``transform_data`` reject an offset past the end."""
        doc = HexDocument.open_bytes(b"ABCDEFGH")
        with pytest.raises(ValueError, match="offset 9 beyond document size 8"):
            doc.decode_text(9, 1, "utf-8")
        with pytest.raises(ValueError, match="offset 9 beyond document size 8"):
            doc.transform_data("base64_encode", 9, 4, {})
        assert not doc.decode_text(8, 4, "utf-8")

    @staticmethod
    def test_numeric_search_rejects_unsupported_widths_and_infinite_tolerance() -> None:
        """Invalid numeric search parameters raise instead of matching nothing or everything."""
        doc = HexDocument.open_bytes(bytes(16))
        with pytest.raises(ValueError, match=r"integer width must be 1\.\.=8 bytes, got 0"):
            doc.search_numeric(0, 0, signed=False, big_endian=False, alignment=1, max_results=10)
        with pytest.raises(ValueError, match="tolerance must be finite"):
            doc.search_numeric_float(0.0, 4, big_endian=False, tolerance=float("inf"), alignment=1, max_results=10)
        assert doc.search_numeric(0, 5, signed=False, big_endian=False, alignment=1, max_results=2) == [(0, 5), (1, 5)]


class TestWholeDocumentEdits:
    """Edits that rebuild the document keep its identity and stay undoable."""

    @staticmethod
    def test_replace_bytes_keeps_file_path(tmp_path: Path) -> None:
        """A replacement that changes the length keeps the document's path.

        Args:
            tmp_path: Pytest temporary directory.
        """
        source = tmp_path / "replace.bin"
        source.write_bytes(b"aaaa-aaaa")
        doc = HexDocument.open(str(source))
        assert doc.replace_bytes(b"aaaa", b"b") == 2
        assert doc.read(0, 9) == b"b-b"
        assert doc.file_path() == str(source)
        assert doc.undo() is True
        assert doc.read(0, 9) == b"aaaa-aaaa"

    @staticmethod
    def test_bps_import_keeps_path_and_is_one_undo_entry(tmp_path: Path) -> None:
        """A BPS import is undoable and does not detach the document from its file.

        Args:
            tmp_path: Pytest temporary directory.
        """
        source_bytes = b"ABCD" * 8
        target_bytes = b"ABCD" * 6 + b"WXYZ" * 3
        patch = HexDocument.open_bytes(target_bytes).export_patches_bps(source_bytes)
        path = tmp_path / "bps_target.bin"
        path.write_bytes(source_bytes)
        doc = HexDocument.open(str(path))
        assert doc.import_patches_bps(patch, source_bytes) == len(target_bytes)
        assert doc.read(0, 64) == target_bytes
        assert doc.file_path() == str(path)
        assert doc.undo() is True
        assert doc.read(0, 64) == source_bytes
        assert doc.can_undo() is False

    @staticmethod
    def test_save_copy_does_not_adopt_the_path(tmp_path: Path) -> None:
        """``save_copy`` writes the bytes without re-pointing the document.

        Args:
            tmp_path: Pytest temporary directory.
        """
        doc = HexDocument.open_bytes(b"unsaved content")
        copy_path = tmp_path / "copy.bin"
        doc.save_copy(str(copy_path))
        assert copy_path.read_bytes() == b"unsaved content"
        assert doc.file_path() is None
        copy_path.unlink()
        assert not copy_path.exists()


class TestPatchExportContract:
    """Overwrite-only patch formats refuse histories they cannot reproduce."""

    @staticmethod
    def test_export_after_insert_raises() -> None:
        """An insert shifts every later offset, so IPS export must refuse."""
        doc = HexDocument.open_bytes(b"ABCDEFGH")
        doc.write_bytes(2, b"Z")
        assert doc.export_patches_ips() == b"PATCH\x00\x00\x02\x00\x01ZEOF"
        doc.insert_bytes(0, b"Q")
        for export in (doc.export_patches_ips, doc.export_patches_ips32, doc.export_patches_cod, doc.export_patches_json):
            with pytest.raises(ValueError, match="use BPS or UPS instead"):
                export()

    @staticmethod
    def test_later_lower_offset_write_wins_in_export() -> None:
        """Overlapping writes export the newest bytes, exactly as the document holds them."""
        doc = HexDocument.open_bytes(b"ABCDEFGHIJKLMNOP")
        doc.write_bytes(10, b"\x11" * 4)
        doc.write_bytes(8, b"\x22" * 4)
        assert doc.export_patches_ips() == b"PATCH\x00\x00\x08\x00\x06" + b"\x22" * 4 + b"\x11" * 2 + b"EOF"


class TestStringsAndInspector:
    """Wide-string extraction and inspection follow the dedicated-editor rules."""

    @staticmethod
    def test_wide_strings_are_printable_ascii_at_any_alignment() -> None:
        """UTF-16LE strings are ASCII code units found at even and odd offsets."""
        data = b"\xff" + "Hello".encode("utf-16-le") + b"\x00" * 4 + "Привет".encode("utf-16-le") + b"\x00\x00"
        doc = HexDocument.open_bytes(data)
        found = [
            (m["offset"], m["length"], m["encoding"], m["content"])
            for m in doc.extract_strings(min_length=4, include_ascii=False, include_utf16=True, max_results=10)
        ]
        assert found == [(1, 10, "utf16le", "Hello")]

    @staticmethod
    def test_inspector_wide_string_reads_32_units() -> None:
        """The inspector's wide-string view is not cut to 8 characters."""
        text = "ABCDEFGHIJKLMNOP"
        doc = HexDocument.open_bytes(text.encode("utf-16-le"))
        assert doc.inspect_at(0)["wide_string"] == text


def test_bookmark_repr_matches_stub() -> None:
    """``Bookmark.__repr__`` is declared in the stub and renders every field."""
    mark = intellicrack_hexcore.Bookmark(16, 4, "entry", "#ff0000")
    assert repr(mark) == "Bookmark(offset=16, length=4, label='entry', color='#ff0000')"
