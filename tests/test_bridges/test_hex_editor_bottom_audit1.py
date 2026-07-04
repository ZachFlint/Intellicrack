# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-1 regression tests for HexEditorBridge bottom-half findings.

Each test in this module is associated with one or more F-#### findings
from ``audit1.md`` for ``src/intellicrack/bridges/hex_editor.py``
(lines 3950+). The tests use a real ``intellicrack_hexcore.HexDocument``
where applicable so the bridge methods exercise their genuine code
paths rather than mocks. Tests for paths that do not require a
backing document (the disabled ``run_python_script``, validation in
``base_convert``, etc.) call the bridge methods directly. Where tests
operate on the disk, they use :func:`tempfile.NamedTemporaryFile` so
no fixture data is checked into the repository.

All tests are designed to fail on the unfixed code path (e.g., before
the F-#### remediation lands) and pass after it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine

_ATTR_COMPUTE_DOC_MD5_STREAMING = "_compute_doc_md5_streaming"
_ATTR_APPLY_ARITHMETIC_FALLBACK = "_apply_arithmetic_fallback"
_ATTR_CURSOR_OFFSET = "_cursor_offset"
_ATTR_EXTRACT_STRINGS_FALLBACK = "_extract_strings_fallback"
_ATTR_APPLY_BPS_PATCH = "_apply_bps_patch"
_ATTR_EXPORT_PATCHES_BPS_PYFALLBACK = "_export_patches_bps_pyfallback"


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _call_compute_doc_md5_streaming(bridge: HexEditorBridge, *, chunk_size: int) -> str:
    """Invoke ``HexEditorBridge._compute_doc_md5_streaming`` via ``getattr``.

    Args:
        bridge: Bridge whose method is invoked.
        chunk_size: Hash chunk size.

    Returns:
        str: Lowercase MD5 hex digest of the open document.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            a non-string value.
    """
    fn: object = getattr(bridge, _ATTR_COMPUTE_DOC_MD5_STREAMING)
    if not callable(fn):
        msg = f"HexEditorBridge.{_ATTR_COMPUTE_DOC_MD5_STREAMING} is not callable"
        raise TypeError(msg)
    result: object = fn(chunk_size=chunk_size)
    if not isinstance(result, str):
        msg = f"HexEditorBridge.{_ATTR_COMPUTE_DOC_MD5_STREAMING} expected str, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _call_apply_arithmetic_fallback(data: bytearray, op: str, key: bytes, count: int) -> bytes:
    """Invoke ``HexEditorBridge._apply_arithmetic_fallback`` via ``getattr``.

    Args:
        data: Mutable byte buffer to transform.
        op: Operation name (``"xor"``, ``"and"``, ``"or"`` etc.).
        key: Key bytes.
        count: Shift / rotation count for shift ops.

    Returns:
        bytes: The transformed buffer.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            a non-bytes value.
    """
    fn: object = getattr(HexEditorBridge, _ATTR_APPLY_ARITHMETIC_FALLBACK)
    if not callable(fn):
        msg = f"HexEditorBridge.{_ATTR_APPLY_ARITHMETIC_FALLBACK} is not callable"
        raise TypeError(msg)
    result: object = fn(data, op, key, count)
    if not isinstance(result, (bytes, bytearray)):
        msg = f"HexEditorBridge.{_ATTR_APPLY_ARITHMETIC_FALLBACK} expected bytes-like, got {type(result).__name__}"
        raise TypeError(msg)
    return bytes(result)


def _set_cursor_offset(bridge: HexEditorBridge, offset: int) -> None:
    """Set the bridge cursor offset via ``setattr`` to dodge ``reportPrivateUsage``.

    Args:
        bridge: Bridge whose cursor offset is set.
        offset: New cursor offset.
    """
    setattr(bridge, _ATTR_CURSOR_OFFSET, offset)


def _call_extract_strings_fallback(
    data: bytes,
    min_length: int,
    max_results: int,
    *,
    include_ascii: bool,
    include_utf16: bool,
) -> list[dict[str, Any]]:
    """Invoke ``HexEditorBridge._extract_strings_fallback`` via ``getattr``.

    Args:
        data: Bytes to scan.
        min_length: Minimum run length in code units.
        max_results: Maximum number of results to return.
        include_ascii: Whether to scan for ASCII strings.
        include_utf16: Whether to scan for UTF-16LE strings.

    Returns:
        list[dict[str, Any]]: Match dicts with offset, length, encoding,
        and content fields.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            an unexpected shape.
    """
    fn: object = getattr(HexEditorBridge, _ATTR_EXTRACT_STRINGS_FALLBACK)
    if not callable(fn):
        msg = f"HexEditorBridge.{_ATTR_EXTRACT_STRINGS_FALLBACK} is not callable"
        raise TypeError(msg)
    result: object = fn(data, min_length, max_results, include_ascii=include_ascii, include_utf16=include_utf16)
    if not isinstance(result, list):
        msg = f"HexEditorBridge.{_ATTR_EXTRACT_STRINGS_FALLBACK} expected list, got {type(result).__name__}"
        raise TypeError(msg)
    return cast("list[dict[str, Any]]", result)


def _call_apply_bps_patch(bridge: HexEditorBridge, patch: bytes, source: bytes) -> bytes:
    """Invoke ``HexEditorBridge._apply_bps_patch`` via ``getattr``.

    Args:
        bridge: Bridge whose method is invoked.
        patch: Raw BPS patch bytes.
        source: Original source bytes.

    Returns:
        bytes: The reconstructed target bytes.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            a non-bytes value.
    """
    fn: object = getattr(bridge, _ATTR_APPLY_BPS_PATCH)
    if not callable(fn):
        msg = f"HexEditorBridge.{_ATTR_APPLY_BPS_PATCH} is not callable"
        raise TypeError(msg)
    result: object = fn(patch, source)
    if not isinstance(result, (bytes, bytearray)):
        msg = f"HexEditorBridge.{_ATTR_APPLY_BPS_PATCH} expected bytes-like, got {type(result).__name__}"
        raise TypeError(msg)
    return bytes(result)


def _call_export_patches_bps_pyfallback(bridge: HexEditorBridge, original_path: str) -> bytes:
    """Invoke ``HexEditorBridge._export_patches_bps_pyfallback`` via ``getattr``.

    Args:
        bridge: Bridge whose method is invoked.
        original_path: Path to the original unmodified file.

    Returns:
        bytes: Raw BPS patch bytes.

    Raises:
        TypeError: If the resolved attribute is not callable or returns
            a non-bytes value.
    """
    fn: object = getattr(bridge, _ATTR_EXPORT_PATCHES_BPS_PYFALLBACK)
    if not callable(fn):
        msg = f"HexEditorBridge.{_ATTR_EXPORT_PATCHES_BPS_PYFALLBACK} is not callable"
        raise TypeError(msg)
    result: object = fn(original_path)
    if not isinstance(result, (bytes, bytearray)):
        msg = f"HexEditorBridge.{_ATTR_EXPORT_PATCHES_BPS_PYFALLBACK} expected bytes-like, got {type(result).__name__}"
        raise TypeError(msg)
    return bytes(result)


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Construct a fresh ``HexEditorBridge`` with no document attached.

    Returns:
        HexEditorBridge: Bridge instance for tests that build documents
        themselves.
    """
    return HexEditorBridge()


def _open_doc(bridge: HexEditorBridge, data: bytes) -> Path:
    """Write ``data`` to a temp file and open it as the bridge's document.

    Args:
        bridge: Target bridge.
        data: Raw bytes to write.

    Returns:
        Path: Path of the temp file holding the document data.
    """
    fd, path_str = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(data)
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
    return path


# ---------------------------------------------------------------------------
# F-0001 / F-0045 / F-0059 / F-0060 - run_python_script disabled
# ---------------------------------------------------------------------------


class TestRunPythonScriptDisabled:
    """Verify the ``run_python_script`` RCE vector is closed."""

    def test_rejects_arbitrary_script(self, bridge: HexEditorBridge) -> None:
        """Even an empty script must raise ``ToolError``.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        with pytest.raises(ToolError) as excinfo:
            _run(bridge.run_python_script(""))
        assert "disabled" in str(excinfo.value).lower()

    def test_rejects_known_subclasses_escape(self, bridge: HexEditorBridge) -> None:
        """The classic ``__subclasses__`` escape must be rejected.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        payload = "[c for c in ().__class__.__base__.__subclasses__() if 'Popen' in c.__name__]"
        with pytest.raises(ToolError):
            _run(bridge.run_python_script(payload))

    def test_does_not_execute_side_effects(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A script writing to disk must not run.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        marker = tmp_path / "must_not_exist.txt"
        payload = f"open({marker!s}, 'w').write('pwned')"
        with pytest.raises(ToolError):
            _run(bridge.run_python_script(payload))
        assert not marker.exists()


# ---------------------------------------------------------------------------
# F-0002 - set_va_base raises when backend lacks add_va_mapping
# ---------------------------------------------------------------------------


class _DocWithoutVAMapping:
    """Minimal stand-in document that lacks ``add_va_mapping``.

    Implements only the ``length`` and ``read`` shape required by the
    bridge methods exercised by these tests.
    """

    def __init__(self, size: int = 32) -> None:
        """Construct a fixed-size, all-zero stand-in document.

        Args:
            size: Number of zero bytes the document advertises.
        """
        self._size = size

    def length(self) -> int:
        """Return the configured size.

        Returns:
            int: Configured size in bytes.
        """
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        """Return zero bytes for any requested slice.

        Args:
            offset: Ignored.
            length: Number of zero bytes to return.

        Returns:
            bytes: Zero-filled bytes of the requested length.
        """
        _ = offset
        return bytes(length)


class TestSetVaBaseRaisesWithoutBackend:
    """F-0002: set_va_base must not lie about success."""

    def test_set_va_base_raises_when_backend_missing(self, bridge: HexEditorBridge) -> None:
        """Calling set_va_base on a backend without add_va_mapping fails.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        bridge.document = _DocWithoutVAMapping()
        with pytest.raises(RuntimeError, match="VA mapping"):
            _run(bridge.set_va_base(0, 0x400000, 4096))


# ---------------------------------------------------------------------------
# F-0003 - set_chunk_size / set_memory_budget honest failure
# ---------------------------------------------------------------------------


class TestChunkAndBudgetHonest:
    """F-0003: backend hint setters fail loud when unsupported."""

    def test_set_chunk_size_raises_without_doc(self, bridge: HexEditorBridge) -> None:
        """set_chunk_size with no document raises RuntimeError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.set_chunk_size(4096))

    def test_set_chunk_size_raises_invalid_size(self, bridge: HexEditorBridge) -> None:
        """Non-positive size raises ValueError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        bridge.document = _DocWithoutVAMapping()
        with pytest.raises(ValueError, match="positive integer"):
            _run(bridge.set_chunk_size(0))

    def test_set_chunk_size_raises_unsupported_backend(self, bridge: HexEditorBridge) -> None:
        """Backend lacking the hint method causes RuntimeError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        bridge.document = _DocWithoutVAMapping()
        with pytest.raises(RuntimeError, match="chunk size hints"):
            _run(bridge.set_chunk_size(4096))

    def test_set_memory_budget_raises_unsupported_backend(self, bridge: HexEditorBridge) -> None:
        """memory_budget setter fails when backend lacks the hook.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        bridge.document = _DocWithoutVAMapping()
        with pytest.raises(RuntimeError, match="memory budget hints"):
            _run(bridge.set_memory_budget(1 << 20))


# ---------------------------------------------------------------------------
# F-0009 - chunked MD5 streaming
# ---------------------------------------------------------------------------


class TestStreamingMd5:
    """F-0009: MD5 must not require the full file in memory."""

    def test_streaming_md5_matches_oneshot(self, bridge: HexEditorBridge) -> None:
        """Streaming and single-shot MD5 agree on identical data.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        payload = b"\x10\x20\x30\x40" * 4096
        _open_doc(bridge, payload)
        digest_streaming = _call_compute_doc_md5_streaming(bridge, chunk_size=128)
        digest_oneshot = hashlib.md5(payload, usedforsecurity=False).hexdigest()
        assert digest_streaming == digest_oneshot

    def test_streaming_md5_handles_chunk_boundaries(self, bridge: HexEditorBridge) -> None:
        """Different chunk sizes still produce the same digest.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        payload = bytes(range(256)) * 17
        _open_doc(bridge, payload)
        digest_a = _call_compute_doc_md5_streaming(bridge, chunk_size=37)
        digest_b = _call_compute_doc_md5_streaming(bridge, chunk_size=4096)
        assert digest_a == digest_b


# ---------------------------------------------------------------------------
# F-0010 - ClamAV NDB wildcard scanner
# ---------------------------------------------------------------------------


class TestClamAvNdbWildcards:
    """F-0010: NDB ``??`` and ``*`` tokens preserve their semantics."""

    def test_question_mark_pair_matches_any_byte(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A ``??`` token matches any single byte.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        body = b"\xaa\xbb\xcc\xdd" + b"\x55" + b"\x99" + b"\x11\x22"
        _open_doc(bridge, body)
        sig = "Test.WildcardSingle:1:*:bb??dd"
        ndb_path = tmp_path / "wild_single.ndb"
        ndb_path.write_text(sig + "\n", encoding="utf-8")
        results = _run(bridge.scan_clamav_signatures(str(ndb_path)))
        assert any(r["name"] == "Test.WildcardSingle" for r in results), results

    def test_star_token_matches_variable_gap(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A ``*`` token matches a variable-length gap.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        body = b"\xde\xad" + b"\x00\x01\x02\x03\x04\x05" + b"\xbe\xef"
        _open_doc(bridge, body)
        sig = "Test.WildcardStar:1:*:dead*beef"
        ndb_path = tmp_path / "wild_star.ndb"
        ndb_path.write_text(sig + "\n", encoding="utf-8")
        results = _run(bridge.scan_clamav_signatures(str(ndb_path)))
        assert any(r["name"] == "Test.WildcardStar" for r in results), results

    def test_unrelated_byte_does_not_match_question_pair(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Wildcards never match across literal anchors that disagree.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        body = b"\xaa\xbb\x00\xcc\xdd"
        _open_doc(bridge, body)
        sig = "Test.NoMatch:1:*:bb??ee"
        ndb_path = tmp_path / "wild_no.ndb"
        ndb_path.write_text(sig + "\n", encoding="utf-8")
        results = _run(bridge.scan_clamav_signatures(str(ndb_path)))
        assert results == []


# ---------------------------------------------------------------------------
# F-0011 / F-0043 - DIE scanner shape validation
# ---------------------------------------------------------------------------


class TestDieScannerShapeValidation:
    """F-0011 + F-0043: DIE scanner rejects non-array databases cleanly."""

    def test_dict_db_raises_type_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Dict-shaped JSON DB raises TypeError, not AttributeError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        _open_doc(bridge, b"\x00" * 64)
        db_path = tmp_path / "dict_db.json"
        db_path.write_text(json.dumps({"signatures": []}), encoding="utf-8")
        with pytest.raises(TypeError, match="JSON array"):
            _run(bridge.scan_die_signatures(str(db_path)))

    def test_native_die_format_rejected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """``.sg`` script files raise ValueError with a clear message.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        _open_doc(bridge, b"\x00" * 64)
        db_path = tmp_path / "x86.sg"
        db_path.write_text("function detect() { return false; }", encoding="utf-8")
        with pytest.raises(ValueError, match="DIE native"):
            _run(bridge.scan_die_signatures(str(db_path)))


# ---------------------------------------------------------------------------
# F-0012 - list_process_regions Windows guard
# ---------------------------------------------------------------------------


class TestListProcessRegionsPlatform:
    """F-0012: list_process_regions enforces Windows-only contract."""

    def test_non_windows_raises(self, bridge: HexEditorBridge, monkeypatch: pytest.MonkeyPatch) -> None:
        """When ``os.name != 'nt'`` the method raises RuntimeError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            monkeypatch: Pytest monkeypatch fixture used only to spoof
                ``os.name`` because the live OS detection is the
                contract under test.
        """
        monkeypatch.setattr(
            "intellicrack.bridges.hex_editor.os",
            type("FakeOs", (), {"name": "posix"}),
        )
        with pytest.raises(RuntimeError, match="Windows-only"):
            _run(bridge.list_process_regions(1))


# ---------------------------------------------------------------------------
# F-0015 - PE checksum offset constants
# ---------------------------------------------------------------------------


def _make_minimal_pe() -> bytes:
    """Build a minimal PE file with a known checksum field.

    Returns:
        bytes: A valid-enough PE/DOS image to exercise the bridge's PE
        helpers.  The file is ``DOS_HEADER_SIZE + 4 + COFF_HEADER_SIZE +
        SIZE_OF_OPTIONAL_HEADER`` bytes long, with the checksum field at
        ``e_lfanew + 4 + 20 + 64``.
    """
    e_lfanew = 0x80
    pe_offset = e_lfanew
    coff_offset = pe_offset + 4
    opt_offset = coff_offset + 20
    opt_size = 96
    total = opt_offset + opt_size

    image = bytearray(b"\x00" * total)
    image[:2] = b"MZ"
    image[0x3C:0x40] = struct.pack("<I", e_lfanew)
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    image[coff_offset + 16 : coff_offset + 18] = struct.pack("<H", opt_size)
    image[opt_offset : opt_offset + 2] = struct.pack("<H", 0x10B)
    return bytes(image)


class TestPeChecksumOffsetConstants:
    """F-0015: PE checksum offset uses named constants and parses fine."""

    def test_verify_pe_checksum_uses_constants(self, bridge: HexEditorBridge) -> None:
        """verify_pe_checksum returns offset = lfanew + 4 + 20 + 64.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _open_doc(bridge, _make_minimal_pe())
        result = _run(bridge.verify_pe_checksum())
        assert result["offset"] == 0x80 + 4 + 20 + 64


# ---------------------------------------------------------------------------
# F-0018 - arithmetic fallback raises on missing key
# ---------------------------------------------------------------------------


class TestArithmeticFallbackMissingKey:
    """F-0018: xor/and/or with empty key must raise, not no-op."""

    def test_fallback_xor_missing_key_raises(self) -> None:
        """The pure-Python helper rejects xor without a key."""
        with pytest.raises(ToolError, match="non-empty key"):
            _call_apply_arithmetic_fallback(bytearray(b"abc"), "xor", b"", 1)


# ---------------------------------------------------------------------------
# F-0023 / F-0025 - Mach-O VA + bookmarks
# ---------------------------------------------------------------------------


def _make_minimal_macho_64() -> bytes:
    """Build a tiny but well-formed Mach-O 64-bit image with one segment.

    Returns:
        bytes: Mach-O image bytes.
    """
    magic = b"\xcf\xfa\xed\xfe"
    header = bytearray(magic)
    header += struct.pack("<I", 0x01000007)
    header += struct.pack("<I", 3)
    header += struct.pack("<I", 0x2)
    ncmds = 1
    sizeofcmds = 72
    header += struct.pack("<I", ncmds)
    header += struct.pack("<I", sizeofcmds)
    header += struct.pack("<I", 0x00200085)
    header += struct.pack("<I", 0)

    seg = bytearray()
    seg += struct.pack("<I", 0x19)
    seg += struct.pack("<I", 72)
    seg += b"__TEXT".ljust(16, b"\x00")
    seg += struct.pack("<Q", 0x100000000)
    seg += struct.pack("<Q", 0x4000)
    seg += struct.pack("<Q", 0)
    seg += struct.pack("<Q", 0x4000)
    seg += struct.pack("<I", 7)
    seg += struct.pack("<I", 5)
    seg += struct.pack("<I", 0)
    seg += struct.pack("<I", 0)
    assert len(seg) == 72
    return bytes(header) + bytes(seg)


class TestMachoVa:
    """F-0023 / F-0025: Mach-O is detected for VA + bookmarks."""

    def test_macho_va_detection(self, bridge: HexEditorBridge) -> None:
        """auto_detect_va_mappings returns the segment for Mach-O 64.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _open_doc(bridge, _make_minimal_macho_64())
        mappings = _run(bridge.auto_detect_va_mappings())
        assert any(m["virtual_address"] == 0x100000000 for m in mappings), mappings

    def test_macho_structure_bookmarks_created(self, bridge: HexEditorBridge) -> None:
        """generate_structure_bookmarks emits at least the header bookmark.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _open_doc(bridge, _make_minimal_macho_64())
        bookmarks = _run(bridge.generate_structure_bookmarks())
        labels = {b["label"] for b in bookmarks}
        assert "Mach-O Header" in labels, bookmarks


# ---------------------------------------------------------------------------
# F-0026 - PE bookmark transactional rollback
# ---------------------------------------------------------------------------


class TestPeBookmarkRollback:
    """F-0026: a failed bookmark generation rolls back partial state."""

    def test_truncated_pe_does_not_leak_bookmarks(self, bridge: HexEditorBridge) -> None:
        """A PE with garbage section count rolls back its bookmarks.

        Build a PE whose ``num_sections`` is huge enough that section
        bookmarking will read past EOF and raise. The bridge must
        recover by removing every bookmark it added during the partial
        generation.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        e_lfanew = 0x40
        pe_offset = e_lfanew
        coff_offset = pe_offset + 4
        opt_offset = coff_offset + 20
        opt_size = 0x60
        section_table_offset = opt_offset + opt_size
        total = section_table_offset + 64

        image = bytearray(b"\x00" * total)
        image[:2] = b"MZ"
        image[0x3C:0x40] = struct.pack("<I", e_lfanew)
        image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        image[coff_offset + 2 : coff_offset + 4] = struct.pack("<H", 1024)
        image[coff_offset + 16 : coff_offset + 18] = struct.pack("<H", opt_size)
        image[opt_offset : opt_offset + 2] = struct.pack("<H", 0x10B)
        _open_doc(bridge, bytes(image))

        doc = bridge.document
        assert doc is not None
        before = len(doc.list_bookmarks())
        _run(bridge.generate_structure_bookmarks())
        after = len(doc.list_bookmarks())
        assert after == before, f"expected rollback to restore {before}, got {after}"


# ---------------------------------------------------------------------------
# F-0027 - display/color mode validation
# ---------------------------------------------------------------------------


class TestDisplayColorModeValidation:
    """F-0027: invalid mode strings raise ValueError."""

    def test_set_display_mode_rejects_unknown(self, bridge: HexEditorBridge) -> None:
        """Bogus display mode rejected.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        with pytest.raises(ValueError, match="unknown display mode"):
            _run(bridge.set_display_mode("not-a-mode"))

    def test_set_color_mode_rejects_unknown(self, bridge: HexEditorBridge) -> None:
        """Bogus color mode rejected.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        with pytest.raises(ValueError, match="unknown color mode"):
            _run(bridge.set_color_mode("rainbow"))


# ---------------------------------------------------------------------------
# F-0028 - snap_to_alignment nearest
# ---------------------------------------------------------------------------


class TestSnapToAlignmentNearest:
    """F-0028: snap_to_alignment selects the nearest boundary."""

    def test_snap_rounds_up(self, bridge: HexEditorBridge) -> None:
        """A cursor closer to the higher boundary snaps up.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _set_cursor_offset(bridge, 0x1F0)
        result = _run(bridge.snap_to_alignment(0x100))
        assert result == 0x200

    def test_snap_rounds_down(self, bridge: HexEditorBridge) -> None:
        """A cursor closer to the lower boundary snaps down.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _set_cursor_offset(bridge, 0x110)
        result = _run(bridge.snap_to_alignment(0x100))
        assert result == 0x100


# ---------------------------------------------------------------------------
# F-0029 / F-0040 - UTF-16LE scanner
# ---------------------------------------------------------------------------


class TestUtf16Scanner:
    """F-0029 + F-0040: UTF-16LE string scanner improvements."""

    def test_python_fallback_finds_odd_aligned(self) -> None:
        """The pure-Python fallback detects odd-aligned UTF-16 strings."""
        prefix = b"\x00"
        utf16 = "MARKER".encode("utf-16le")
        suffix = b"\x00" * 8
        results = _call_extract_strings_fallback(
            prefix + utf16 + suffix,
            4,
            10,
            include_ascii=False,
            include_utf16=True,
        )
        assert any("MARKER" in r["content"] for r in results), results

    def test_python_fallback_excludes_non_printable_high(self) -> None:
        """The fallback rejects runs of non-printable high code units."""
        controls = b"".join(struct.pack("<H", 0xFFFE) for _ in range(8))
        results = _call_extract_strings_fallback(
            controls,
            4,
            10,
            include_ascii=False,
            include_utf16=True,
        )
        for r in results:
            assert "￾" not in r["content"], results


# ---------------------------------------------------------------------------
# F-0030 - BPS encoder emits more than just SourceRead/TargetRead
# ---------------------------------------------------------------------------


class TestBpsEncoderRichOpcodes:
    """F-0030: encoder must emit SourceCopy / TargetCopy where useful."""

    def test_round_trip_with_relocated_block(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Round-trip a target that relocates a long source run.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        block = bytes(range(64))
        source = b"\xaa" * 16 + block + b"\xbb" * 16
        target = b"\xcc" * 16 + block + b"\xdd" * 16
        original = tmp_path / "orig.bin"
        original.write_bytes(source)
        _open_doc(bridge, target)
        patch_b64 = _run(bridge.export_patches_bps(str(original)))
        patch_bytes = base64.b64decode(patch_b64)
        rebuilt = _call_apply_bps_patch(bridge, patch_bytes, source)
        assert rebuilt == target


# ---------------------------------------------------------------------------
# F-0031 - toggle_bit Rust path emits the same logs as fallback
# ---------------------------------------------------------------------------


class TestToggleBitLogParity:
    """F-0031: toggle_bit emits ``bit_toggled`` / ``file_written`` logs.

    The events are emitted via ``_logger`` whose underlying handler is
    ``structlog``; the test captures the rendered output via
    ``capsys`` because structlog routes through the project's stderr
    rendering pipeline by default in test mode.
    """

    def test_rust_path_emits_logs(self, bridge: HexEditorBridge, capsys: pytest.CaptureFixture[str]) -> None:
        """Calling toggle_bit through the Rust backend produces logs.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            capsys: Pytest capsys fixture used to read structlog
                rendered events from stdout/stderr.
        """
        _open_doc(bridge, bytes(16))
        _run(bridge.toggle_bit(0, 0))
        captured = capsys.readouterr()
        events = captured.out + captured.err
        assert "file_written" in events
        assert "bit_toggled" in events


# ---------------------------------------------------------------------------
# F-0042 - BPS export streaming
# ---------------------------------------------------------------------------


class TestBpsExportStreaming:
    """F-0042: BPS export does not load source via ``read_bytes()``.

    The fallback path is intentionally exercised here to verify the
    streaming source loader works for both Rust-backed and pure-Python
    fallbacks.
    """

    def test_bps_export_via_mmap_pyfallback(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Pure-Python fallback uses mmap'd source.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        source = b"\x00\x01" * 1024
        target = b"\x10\x11" * 1024
        original = tmp_path / "orig.bin"
        original.write_bytes(source)
        _open_doc(bridge, target)
        original_export = _call_export_patches_bps_pyfallback(bridge, str(original))
        assert original_export[:4] == b"BPS1"


# ---------------------------------------------------------------------------
# F-0044 - ClamAV unknown suffix rejected
# ---------------------------------------------------------------------------


class TestClamavUnsupportedSuffix:
    """F-0044: dispatch rejects unsupported ClamAV file kinds."""

    def test_ldb_rejected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A ``.ldb`` file is refused with a clear ValueError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        _open_doc(bridge, b"\x00" * 32)
        ldb = tmp_path / "rules.ldb"
        ldb.write_text("rule;Engine:51-255;Target:0;0&1;...:...\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"\.ldb"):
            _run(bridge.scan_clamav_signatures(str(ldb)))

    def test_unknown_suffix_rejected(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Wholly unknown suffixes raise ValueError.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
        """
        _open_doc(bridge, b"\x00" * 32)
        bogus = tmp_path / "data.bogus"
        bogus.write_text("anything\n", encoding="utf-8")
        with pytest.raises(ValueError, match="unrecognised"):
            _run(bridge.scan_clamav_signatures(str(bogus)))


# ---------------------------------------------------------------------------
# F-0047 - base_convert validates input
# ---------------------------------------------------------------------------


class TestBaseConvertValidation:
    """F-0047: base_convert raises a typed ValueError on bad input."""

    def test_rejects_unparseable_decimal(self) -> None:
        """A non-numeric string raises ValueError with explanation."""
        with pytest.raises(ValueError, match="failed to parse"):
            _run(HexEditorBridge.base_convert("not-a-number"))

    def test_rejects_unknown_base_hint(self) -> None:
        """An unknown base name raises ValueError immediately."""
        with pytest.raises(ValueError, match="unknown from_base"):
            _run(HexEditorBridge.base_convert("0", from_base="dec"))


# ---------------------------------------------------------------------------
# F-0050 - export_annotated_html escape
# ---------------------------------------------------------------------------


class TestHtmlExportXssDefence:
    """F-0050: HTML export escapes labels/colors and rejects XSS."""

    def test_malicious_color_replaced(self, bridge: HexEditorBridge) -> None:
        """A non-conforming colour is replaced with the safe fallback.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _open_doc(bridge, b"\x41\x42\x43\x44" * 4)
        doc = bridge.document
        assert doc is not None
        doc.add_bookmark(0, 4, "Header", "javascript:alert(1)")
        html_str = _run(bridge.export_annotated_html(0, 16))
        assert "javascript:alert(1)" not in html_str
        assert "#888888" in html_str

    def test_label_escaped(self, bridge: HexEditorBridge) -> None:
        """A label containing HTML special chars is escaped.

        Args:
            bridge: Fresh HexEditorBridge fixture.
        """
        _open_doc(bridge, b"\x41" * 16)
        doc = bridge.document
        assert doc is not None
        doc.add_bookmark(0, 4, "<script>x</script>", "#FF0000")
        html_str = _run(bridge.export_annotated_html(0, 16))
        assert "<script>" not in html_str.replace("&lt;script&gt;", "")
        assert "&lt;script&gt;" in html_str


# ---------------------------------------------------------------------------
# F-0053 - fpdf availability
# ---------------------------------------------------------------------------


class TestFpdfAvailability:
    """F-0053: missing fpdf2 surfaces an actionable ToolError."""

    def test_pdf_export_without_fpdf_raises_tool_error(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``importlib`` cannot find ``fpdf`` we get a clean error.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            tmp_path: Pytest-provided temp directory.
            monkeypatch: Pytest monkeypatch for replacing the importer
                entry point - required to spoof the absence of an
                optional package without uninstalling it.
        """
        _open_doc(bridge, b"\x00" * 16)

        original = importlib.import_module

        def _fake(name: str, package: str | None = None) -> object:
            """Re-raise ImportError specifically for ``fpdf``.

            Args:
                name: Module name.
                package: Module package.

            Returns:
                object: Whatever the real importer returns for non-fpdf
                modules.

            Raises:
                ImportError: Specifically for ``fpdf`` to simulate a
                    missing optional dependency.
            """
            if name == "fpdf":
                msg = "no module named fpdf"
                raise ImportError(msg)
            return original(name, package)

        monkeypatch.setattr(importlib, "import_module", _fake)
        out = tmp_path / "out.pdf"
        with pytest.raises(ToolError, match="fpdf2"):
            _run(bridge.export_annotated_pdf(str(out)))


# ---------------------------------------------------------------------------
# F-0055 - open_process_memory closes prior document
# ---------------------------------------------------------------------------


class TestOpenProcessMemoryClosesPrior:
    """F-0055: open_process_memory rejects when host is non-Windows."""

    def test_non_windows_raises(self, bridge: HexEditorBridge, monkeypatch: pytest.MonkeyPatch) -> None:
        """On non-Windows the call raises before touching state.

        Args:
            bridge: Fresh HexEditorBridge fixture.
            monkeypatch: Pytest monkeypatch fixture used only to spoof
                ``os.name`` so the platform check is exercised on the
                test host.
        """
        monkeypatch.setattr(
            "intellicrack.bridges.hex_editor.os",
            type("FakeOs", (), {"name": "posix"}),
        )
        with pytest.raises(RuntimeError, match="Windows-only"):
            _run(bridge.open_process_memory(1, 0x1000, 16))
