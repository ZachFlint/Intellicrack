# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge IPS patch export, import, and roundtrip.

The bridge's ``export_patches`` produces IPS / IPS32 patch blobs (base64
encoded). These are validated against an independent decoder that follows the
published IPS specification (3-byte big-endian offset, 2-byte big-endian size,
literal data, terminated by ``EOF``; IPS32 widens the offset to 4 bytes and
terminates with ``EEOF``). The decoder is a different implementation from the
native Rust exporter under test, so it serves as a trusted external oracle
rather than re-deriving the exporter's own output.
"""

from __future__ import annotations

import asyncio
import base64
import struct
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _decode_ips(raw: bytes) -> dict[int, bytes]:
    """Decode an IPS / IPS32 patch blob into an offset-to-bytes mapping.

    Independent reference parser implementing the published IPS format: a
    ``PATCH`` (or ``IPS32``) magic header, followed by records of a big-endian
    offset (3 bytes for IPS, 4 for IPS32), a 2-byte big-endian size, and that
    many literal data bytes; a zero size selects an RLE record (2-byte run
    length plus a single fill byte). The stream ends with ``EOF`` (``EEOF`` for
    IPS32). Structural violations raise ``ValueError`` so corruption surfaces.

    Args:
        raw: The decoded (un-base64) IPS or IPS32 blob.

    Returns:
        dict[int, bytes]: Mapping of patch offset to the exact bytes the record
        writes at that offset.

    Raises:
        ValueError: If the magic, a record, or the terminator is malformed.
    """
    if raw[:5] == b"IPS32":
        terminator = b"EEOF"
        offset_field = 4
        pos = 5
    elif raw[:5] == b"PATCH":
        terminator = b"EOF"
        offset_field = 3
        pos = 5
    else:
        msg = f"unknown IPS magic: {raw[:5]!r}"
        raise ValueError(msg)

    patches: dict[int, bytes] = {}
    term_len = len(terminator)
    while pos < len(raw):
        if raw[pos : pos + term_len] == terminator:
            pos += term_len
            if pos != len(raw):
                msg = f"trailing bytes after terminator at {pos}"
                raise ValueError(msg)
            return patches
        offset_raw = raw[pos : pos + offset_field]
        offset = struct.unpack(">I", offset_raw.rjust(4, b"\x00"))[0]
        pos += offset_field
        size = struct.unpack(">H", raw[pos : pos + 2])[0]
        pos += 2
        if size == 0:
            run_length = struct.unpack(">H", raw[pos : pos + 2])[0]
            fill = raw[pos + 2]
            pos += 3
            patches[offset] = bytes([fill]) * run_length
        else:
            patches[offset] = raw[pos : pos + size]
            pos += size
    msg = "IPS stream not terminated"
    raise ValueError(msg)


class TestBridgeExportPatches:
    """Tests covering IPS/IPS32 patch export from a modified document."""

    def test_export_patches_ips_decodes_to_exact_written_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the IPS blob is valid base64 decoding to the exact patch records written.

        Two non-contiguous writes are applied; the base64 result must decode to
        a well-formed IPS stream whose records map exactly to the bytes written
        at each offset, per the independent IPS-spec decoder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 256
        f = tmp_path / "patch_export.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0x10, "AA BB CC DD"))
        _run(bridge.write_bytes(0x80, "11 22"))

        result: str = _run(bridge.export_patches("ips"))
        assert base64.b64encode(base64.b64decode(result, validate=True)).decode("ascii") == result

        raw = base64.b64decode(result)
        assert raw[:5] == b"PATCH"
        assert raw[-3:] == b"EOF"
        decoded = _decode_ips(raw)
        assert decoded == {0x10: b"\xaa\xbb\xcc\xdd", 0x80: b"\x11\x22"}

    def test_export_patches_ips_record_byte_layout_matches_spec(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the exact IPS byte layout for a single known patch record.

        A 4-byte write at offset 4 must serialize to ``PATCH`` + 3-byte BE
        offset ``00 00 04`` + 2-byte BE size ``00 04`` + the data + ``EOF`` with
        no other bytes, asserted byte-for-byte against the hand-computed blob.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "ips_magic.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(4, "DE AD BE EF"))

        raw = base64.b64decode(_run(bridge.export_patches("ips")))
        expected = b"PATCH" + b"\x00\x00\x04" + b"\x00\x04" + b"\xde\xad\xbe\xef" + b"EOF"
        assert raw == expected
        assert _decode_ips(raw) == {4: b"\xde\xad\xbe\xef"}

    def test_export_patches_ips32_byte_layout_and_decode(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify IPS32 export carries the IPS32 magic, 4-byte offset, and EEOF footer.

        A single-byte write at offset 0 must serialize to ``IPS32`` + 4-byte BE
        offset ``00 00 00 00`` + 2-byte BE size ``00 01`` + the data + ``EEOF``,
        asserted byte-for-byte and via the independent decoder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "ips32_export.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "FF"))

        raw = base64.b64decode(_run(bridge.export_patches("ips32")))
        expected = b"IPS32" + b"\x00\x00\x00\x00" + b"\x00\x01" + b"\xff" + b"EEOF"
        assert raw[:5] == b"IPS32"
        assert raw[-4:] == b"EEOF"
        assert raw == expected
        assert _decode_ips(raw) == {0: b"\xff"}

    def test_export_patches_ips32_high_offset_uses_four_byte_field(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify IPS32 encodes offsets beyond the 24-bit IPS range in a 4-byte field.

        A write at offset ``0x01020304`` (exceeding the 24-bit IPS limit) must
        be representable only in IPS32; the decoder must recover the full offset
        and exact bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        high_offset = 0x01020304
        payload = b"\x00" * (high_offset + 16)
        f = tmp_path / "ips32_high.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(high_offset, "CA FE"))

        raw = base64.b64decode(_run(bridge.export_patches("ips32")))
        assert raw[:5] == b"IPS32"
        assert raw[5:9] == struct.pack(">I", high_offset)
        assert _decode_ips(raw) == {high_offset: b"\xca\xfe"}

    def test_export_patches_unknown_format_raises_tool_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify an unrecognized patch format raises ToolError rather than returning a blob.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bad_fmt.bin"
        f.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AB"))
        with pytest.raises(ToolError, match=r"unknown|format"):
            _run(bridge.export_patches("nonsense"))

    def test_export_patches_no_document_raises_runtime_error(self) -> None:
        """Verify exporting with no open document raises RuntimeError, not a silent blob."""
        fresh = HexEditorBridge()
        _run(fresh.initialize())
        with pytest.raises(RuntimeError, match="no document"):
            _run(fresh.export_patches("ips"))


class TestBridgeImportPatches:
    """Tests covering IPS patch import into a fresh document."""

    def test_import_patches_applies_exact_record_count_and_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify import applies the exact number of records and writes the exact bytes.

        Two distinct writes are exported from one document, imported into a
        fresh document of the same size, and the import count plus the resulting
        bytes at each offset are asserted exactly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        src = tmp_path / "src.bin"
        src.write_bytes(payload)
        _run(bridge.open_file(str(src)))
        _run(bridge.write_bytes(0, "AA BB"))
        _run(bridge.write_bytes(0x20, "CC"))
        b64_patches: str = _run(bridge.export_patches("ips"))
        assert _decode_ips(base64.b64decode(b64_patches)) == {0: b"\xaa\xbb", 0x20: b"\xcc"}

        dst = tmp_path / "dst.bin"
        dst.write_bytes(payload)

        fresh: HexEditorBridge = HexEditorBridge()
        _run(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        count: int = _run(fresh.import_patches(b64_patches))
        assert count == 2
        assert _run(fresh.read_bytes(0, 2)) == "AA BB"
        assert _run(fresh.read_bytes(0x20, 1)) == "CC"
        assert _run(fresh.read_bytes(2, 1)) == "00"

    def test_import_patches_unknown_magic_raises_tool_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify importing a blob with an unrecognized magic raises ToolError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "imp_bad.bin"
        f.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(f)))
        garbage = base64.b64encode(b"NOTAPATCHBLOB").decode("ascii")
        with pytest.raises(ToolError, match=r"magic|IPS|patch"):
            _run(bridge.import_patches(garbage))


class TestBridgePatchRoundtrip:
    """Tests covering full modify-export-import-verify roundtrip."""

    def test_patch_roundtrip_data_matches(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify bytes written before export are reproduced exactly after import.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        src = tmp_path / "rt_src.bin"
        src.write_bytes(payload)

        _run(bridge.open_file(str(src)))
        _run(bridge.write_bytes(8, "CA FE BA BE"))
        b64_patches: str = _run(bridge.export_patches("ips"))
        assert _decode_ips(base64.b64decode(b64_patches)) == {8: b"\xca\xfe\xba\xbe"}

        dst = tmp_path / "rt_dst.bin"
        dst.write_bytes(payload)

        fresh = HexEditorBridge()
        _run(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        applied: int = _run(fresh.import_patches(b64_patches))
        assert applied == 1

        after: str = _run(fresh.read_bytes(8, 4))
        assert after == "CA FE BA BE"
        assert _run(fresh.read_bytes(0, 8)) == "00 00 00 00 00 00 00 00"

    def test_ips32_roundtrip_preserves_high_offset_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify an IPS32 export of a high offset roundtrips through import exactly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        high_offset = 0x00FF0010
        size = high_offset + 8
        payload = b"\x00" * size
        src = tmp_path / "rt32_src.bin"
        src.write_bytes(payload)
        _run(bridge.open_file(str(src)))
        _run(bridge.write_bytes(high_offset, "DE AD BE EF"))
        b64_patches: str = _run(bridge.export_patches("ips32"))
        assert _decode_ips(base64.b64decode(b64_patches)) == {high_offset: b"\xde\xad\xbe\xef"}

        dst = tmp_path / "rt32_dst.bin"
        dst.write_bytes(payload)
        fresh = HexEditorBridge()
        _run(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        applied: int = _run(fresh.import_patches(b64_patches))
        assert applied == 1
        assert _run(fresh.read_bytes(high_offset, 4)) == "DE AD BE EF"
