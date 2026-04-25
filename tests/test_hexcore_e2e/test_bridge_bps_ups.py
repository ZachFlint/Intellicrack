# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge BPS and UPS patch format roundtrip operations."""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING, TypeVar

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


_T = TypeVar("_T")


def _run(coro: Coroutine[object, object, _T]) -> _T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        _T: The result of the coroutine.
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


class TestBPSExport:
    """Tests for BPS patch export functionality."""

    def test_bps_export_returns_base64(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify BPS export returns valid base64 that decodes to BPS1 header.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\x00" * 64
        orig_file = tmp_path / "bps_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "bps_mod.bin"
        mod_file.write_bytes(original)
        _run(bridge.open_file(str(mod_file)))
        _run(bridge.write_bytes(0, "DE AD BE EF"))
        b64_result = _run(bridge.export_patches_bps(str(orig_file)))
        decoded = base64.b64decode(b64_result)
        assert decoded[:4] == b"BPS1"

    def test_bps_import_invalid_patch_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that importing garbage base64 as BPS raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bps_target.bin"
        f.write_bytes(b"\x00" * 64)
        orig = tmp_path / "bps_orig2.bin"
        orig.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        garbage_b64 = base64.b64encode(b"not a real patch").decode("ascii")
        with pytest.raises(ValueError):
            _run(bridge.import_patches_bps(garbage_b64, str(orig)))

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify export_patches_bps raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.export_patches_bps("/nonexistent"))


class TestBPSRoundtrip:
    """Tests for BPS patch export and import roundtrip data integrity."""

    def test_bps_roundtrip_data_integrity(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify BPS export then import reproduces the modified data exactly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\x00" * 64
        orig_file = tmp_path / "bps_rt_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "bps_rt_mod.bin"
        mod_file.write_bytes(original)

        _run(bridge.open_file(str(mod_file)))
        _run(bridge.write_bytes(8, "CA FE BA BE"))
        modified_hex = _run(bridge.read_bytes(0, 64))
        modified_bytes = bytes.fromhex(modified_hex.replace(" ", ""))
        b64_patch = _run(bridge.export_patches_bps(str(orig_file)))

        _run(bridge.close_file())
        target_file = tmp_path / "bps_rt_target.bin"
        target_file.write_bytes(original)
        _run(bridge.open_file(str(target_file)))
        _run(bridge.import_patches_bps(b64_patch, str(orig_file)))
        after_hex = _run(bridge.read_bytes(0, 64))
        after_bytes = bytes.fromhex(after_hex.replace(" ", ""))
        assert after_bytes == modified_bytes

    def test_bps_import_wrong_source_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify BPS import with mismatched source file raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        orig_a = tmp_path / "bps_a.bin"
        orig_a.write_bytes(b"\x00" * 64)
        mod_file = tmp_path / "bps_mod_a.bin"
        mod_file.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(mod_file)))
        _run(bridge.write_bytes(0, "FF"))
        b64_patch = _run(bridge.export_patches_bps(str(orig_a)))

        _run(bridge.close_file())
        orig_b = tmp_path / "bps_b.bin"
        orig_b.write_bytes(b"\xff" * 64)
        target = tmp_path / "bps_target_b.bin"
        target.write_bytes(b"\xff" * 64)
        _run(bridge.open_file(str(target)))
        with pytest.raises(ValueError):
            _run(bridge.import_patches_bps(b64_patch, str(orig_b)))

    def test_bps_large_modification(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify BPS roundtrip preserves 256+ bytes of modifications.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\x00" * 512
        orig_file = tmp_path / "bps_large_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "bps_large_mod.bin"
        mod_file.write_bytes(original)

        _run(bridge.open_file(str(mod_file)))
        mod_hex = " ".join(f"{i & 0xFF:02X}" for i in range(256))
        _run(bridge.write_bytes(0, mod_hex))
        modified_hex = _run(bridge.read_bytes(0, 512))
        modified_bytes = bytes.fromhex(modified_hex.replace(" ", ""))
        b64_patch = _run(bridge.export_patches_bps(str(orig_file)))

        _run(bridge.close_file())
        target_file = tmp_path / "bps_large_target.bin"
        target_file.write_bytes(original)
        _run(bridge.open_file(str(target_file)))
        _run(bridge.import_patches_bps(b64_patch, str(orig_file)))
        after_hex = _run(bridge.read_bytes(0, 512))
        after_bytes = bytes.fromhex(after_hex.replace(" ", ""))
        assert after_bytes == modified_bytes


class TestUPSExport:
    """Tests for UPS patch export functionality."""

    def test_ups_export_returns_base64(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify UPS export returns valid base64 that decodes to UPS1 header.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\x00" * 64
        orig_file = tmp_path / "ups_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "ups_mod.bin"
        mod_file.write_bytes(original)
        _run(bridge.open_file(str(mod_file)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        b64_result = _run(bridge.export_patches_ups(str(orig_file)))
        decoded = base64.b64decode(b64_result)
        assert decoded[:4] == b"UPS1"

    def test_ups_import_invalid_patch_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that importing garbage base64 as UPS raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "ups_target.bin"
        f.write_bytes(b"\x00" * 64)
        orig = tmp_path / "ups_orig2.bin"
        orig.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        garbage_b64 = base64.b64encode(b"garbage data here").decode("ascii")
        with pytest.raises(ValueError):
            _run(bridge.import_patches_ups(garbage_b64, str(orig)))


class TestUPSRoundtrip:
    """Tests for UPS patch export and import roundtrip data integrity."""

    def test_ups_roundtrip_data_integrity(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify UPS export then import reproduces the modified data exactly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\x00" * 64
        orig_file = tmp_path / "ups_rt_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "ups_rt_mod.bin"
        mod_file.write_bytes(original)

        _run(bridge.open_file(str(mod_file)))
        _run(bridge.write_bytes(8, "11 22 33 44"))
        modified_hex = _run(bridge.read_bytes(0, 64))
        modified_bytes = bytes.fromhex(modified_hex.replace(" ", ""))
        b64_patch = _run(bridge.export_patches_ups(str(orig_file)))

        _run(bridge.close_file())
        target_file = tmp_path / "ups_rt_target.bin"
        target_file.write_bytes(original)
        _run(bridge.open_file(str(target_file)))
        _run(bridge.import_patches_ups(b64_patch, str(orig_file)))
        after_hex = _run(bridge.read_bytes(0, 64))
        after_bytes = bytes.fromhex(after_hex.replace(" ", ""))
        assert after_bytes == modified_bytes

    def test_ups_identical_files_empty_patch(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify UPS patch for identical files is small (headers + CRCs only).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = b"\xaa" * 64
        orig_file = tmp_path / "ups_ident_orig.bin"
        orig_file.write_bytes(original)
        mod_file = tmp_path / "ups_ident_mod.bin"
        mod_file.write_bytes(original)
        _run(bridge.open_file(str(mod_file)))
        b64_result = _run(bridge.export_patches_ups(str(orig_file)))
        decoded = base64.b64decode(b64_result)
        max_header_size = 32
        assert len(decoded) < max_header_size
