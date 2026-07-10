# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge IPS patch export, import, and roundtrip."""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING

from intellicrack.bridges.hex_editor import HexEditorBridge


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


class TestBridgeExportPatches:
    """Tests covering IPS/IPS32 patch export from a modified document."""

    def test_export_patches_ips_decodes_to_bytes_starting_with_patch(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that decoded IPS data begins with the PATCH magic header.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "ips_magic.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(4, "DE AD BE EF"))
        b64_result: str = _run(bridge.export_patches("ips"))
        decoded = base64.b64decode(b64_result)
        assert decoded[:5] == b"PATCH"

    def test_export_patches_ips32_record_roundtrips_written_byte(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify IPS32 export emits a structurally valid record for the written byte.

        Decodes the base64 IPS32 blob and validates it against the IPS32 wire
        format independently of the producer: the ``IPS32`` magic header, the
        ``EEOF`` terminator, and a single record whose 32-bit big-endian offset,
        16-bit big-endian size, and payload bytes equal the offset, length, and
        value written into the document. A regression that emitted the wrong
        magic, dropped the terminator, mislocated the record, or corrupted the
        payload fails this gate.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "ips32_export.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "FF"))
        decoded = base64.b64decode(_run(bridge.export_patches("ips32")))

        assert decoded[:5] == b"IPS32"
        assert decoded[-4:] == b"EEOF"
        body = decoded[5:-4]
        offset = int.from_bytes(body[:4], "big")
        size = int.from_bytes(body[4:6], "big")
        data = body[6 : 6 + size]
        assert offset == 0
        assert size == 1
        assert data == b"\xff"
        assert len(body) == 6 + size


class TestBridgeImportPatches:
    """Tests covering IPS patch import into a fresh document."""

    def test_import_patches_returns_integer_count(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that import_patches applies exactly one IPS record and restores the written bytes.

        One contiguous write_bytes call produces exactly one IPS record, so count must equal 1.
        Reading back offset 0..1 on the destination document must match the two bytes written
        in the source document, proving the import actually applied the patch payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        src = tmp_path / "src.bin"
        src.write_bytes(payload)
        _run(bridge.open_file(str(src)))
        _run(bridge.write_bytes(0, "AA BB"))
        b64_patches: str = _run(bridge.export_patches("ips"))

        dst = tmp_path / "dst.bin"
        dst.write_bytes(payload)

        fresh: HexEditorBridge = HexEditorBridge()
        _run(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        count: int = _run(fresh.import_patches(b64_patches))
        assert count == 1
        after: str = _run(fresh.read_bytes(0, 2))
        assert after == "AA BB"


class TestBridgePatchRoundtrip:
    """Tests covering full modify-export-import-verify roundtrip."""

    def test_patch_roundtrip_data_matches(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that bytes written before export match bytes after import.

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

        dst = tmp_path / "rt_dst.bin"
        dst.write_bytes(payload)

        fresh = HexEditorBridge()
        _run(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        _run(fresh.import_patches(b64_patches))

        after: str = _run(fresh.read_bytes(8, 4))
        assert after == "CA FE BA BE"
