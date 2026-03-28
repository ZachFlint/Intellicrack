# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge IPS patch export, import, and roundtrip."""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING, Any

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from pathlib import Path


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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

    def test_export_patches_returns_string(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that export_patches returns a string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "patch_export.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        result: str = _run(bridge.export_patches("ips"))
        assert isinstance(result, str)
        assert len(result) > 0

    def test_export_patches_ips_decodes_to_bytes_starting_with_patch(self, bridge: Any, tmp_path: Path) -> None:
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

    def test_export_patches_ips32_returns_valid_base64(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that ips32 export result is valid base64.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 64
        f = tmp_path / "ips32_export.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "FF"))
        b64_result: str = _run(bridge.export_patches("ips32"))
        decoded = base64.b64decode(b64_result)
        assert len(decoded) > 0


class TestBridgeImportPatches:
    """Tests covering IPS patch import into a fresh document."""

    def test_import_patches_returns_integer_count(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that import_patches returns a non-negative integer.

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
        asyncio.get_event_loop().run_until_complete(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        count: int = _run(fresh.import_patches(b64_patches))
        assert isinstance(count, int)
        assert count >= 0


class TestBridgePatchRoundtrip:
    """Tests covering full modify-export-import-verify roundtrip."""

    def test_patch_roundtrip_data_matches(self, bridge: Any, tmp_path: Path) -> None:
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
        asyncio.get_event_loop().run_until_complete(fresh.initialize())
        _run(fresh.open_file(str(dst)))
        _run(fresh.import_patches(b64_patches))

        after: str = _run(fresh.read_bytes(8, 4))
        assert after == "CA FE BA BE"
