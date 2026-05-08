# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
"""Regression tests for F-0008: dead _ips.py module removal.

Verifies that the dead-code module is gone, and that both live IPS code
paths (bridge._build_ips_from_patches and HexDocument.export_patches_ips)
remain functional and produce valid IPS payloads.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import inspect
import sys
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    import types
    from collections.abc import Coroutine
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

_IPS_MAGIC = b"PATCH"
_IPS_FOOTER = b"EOF"
_IPS32_MAGIC = b"IPS32"
_IPS32_FOOTER = b"EEOF"


@pytest.fixture
def hexcore() -> types.ModuleType:
    """Return the imported intellicrack_hexcore native module.

    Returns:
        types.ModuleType: The intellicrack_hexcore native module.
    """
    return hexcore_mod


@pytest.fixture
def sample_bytes() -> bytes:
    """Provide a 256-byte test payload.

    Returns:
        bytes: 256 bytes from 0x00 through 0xFF.
    """
    return bytes(range(256))


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Create and initialize a HexEditorBridge instance.

    Returns:
        HexEditorBridge: An initialized HexEditorBridge.
    """
    b = HexEditorBridge()
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    loop.run_until_complete(b.initialize())
    return b


def _run_async(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
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


class TestDeadModuleRemoved:
    """Regression guard: importing the deleted _ips module must raise ModuleNotFoundError."""

    def test_ips_module_import_raises_module_not_found(self) -> None:
        """Verify that importing the deleted module raises ModuleNotFoundError."""
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("intellicrack.ui.panels.hex_editor._ips")

    def test_ips_module_not_in_sys_modules(self) -> None:
        """Verify that the deleted module is absent from sys.modules after a failed import."""
        with contextlib.suppress(ModuleNotFoundError):
            importlib.import_module("intellicrack.ui.panels.hex_editor._ips")
        assert "intellicrack.ui.panels.hex_editor._ips" not in sys.modules

    def test_hex_editor_package_imports_cleanly(self) -> None:
        """Verify that the hex_editor package itself imports without errors after deletion."""
        mod = importlib.import_module("intellicrack.ui.panels.hex_editor")
        assert mod is not None


class TestBridgeBuildIpsFromPatches:
    """Tests for the live IPS path on HexEditorBridge._build_ips_from_patches."""

    def test_method_exists_on_bridge(self) -> None:
        """Verify that HexEditorBridge exposes _build_ips_from_patches as a callable."""
        assert callable(getattr(HexEditorBridge, "_build_ips_from_patches", None))

    def test_method_is_static(self) -> None:
        """Verify that _build_ips_from_patches is a static method on HexEditorBridge."""
        raw = inspect.getattr_static(HexEditorBridge, "_build_ips_from_patches")
        assert isinstance(raw, staticmethod)

    def test_returns_bytes_type(self) -> None:
        """Verify that _build_ips_from_patches returns a bytes object."""
        patches: list[tuple[int, bytes]] = [(0x10, b"\xaa\xbb\xcc")]
        result = HexEditorBridge._build_ips_from_patches(patches)
        assert isinstance(result, bytes)

    def test_ips_header_is_patch_magic(self) -> None:
        """Verify that the IPS payload begins with the PATCH magic header."""
        patches: list[tuple[int, bytes]] = [(0x00, b"\xde\xad\xbe\xef")]
        result = HexEditorBridge._build_ips_from_patches(patches)
        assert result[:5] == _IPS_MAGIC

    def test_ips_footer_is_eof_marker(self) -> None:
        """Verify that the IPS payload ends with the EOF marker."""
        patches: list[tuple[int, bytes]] = [(0x20, b"\x11\x22\x33")]
        result = HexEditorBridge._build_ips_from_patches(patches)
        assert result[-3:] == _IPS_FOOTER

    def test_ips32_header_is_ips32_magic(self) -> None:
        """Verify that the IPS32 payload begins with the IPS32 magic header."""
        patches: list[tuple[int, bytes]] = [(0x100, b"\xca\xfe")]
        result = HexEditorBridge._build_ips_from_patches(patches, ips32=True)
        assert result[:5] == _IPS32_MAGIC

    def test_ips32_footer_is_eeof_marker(self) -> None:
        """Verify that the IPS32 payload ends with the EEOF marker."""
        patches: list[tuple[int, bytes]] = [(0x200, b"\xba\xbe")]
        result = HexEditorBridge._build_ips_from_patches(patches, ips32=True)
        assert result[-4:] == _IPS32_FOOTER

    def test_minimum_ips_payload_size(self) -> None:
        """Verify that a single-byte patch produces at least 14 bytes of IPS payload.

        The minimum is: 5 (PATCH) + 3 (offset) + 2 (size) + 1 (data) + 3 (EOF) = 14.
        """
        patches: list[tuple[int, bytes]] = [(0x01, b"\xff")]
        result = HexEditorBridge._build_ips_from_patches(patches)
        assert len(result) >= 14

    def test_multi_patch_ips_payload(self) -> None:
        """Verify that multiple patches produce a valid IPS payload with correct header and footer."""
        patches: list[tuple[int, bytes]] = [
            (0x00, b"\xaa\xbb"),
            (0x50, b"\xcc\xdd\xee"),
            (0xA0, b"\x11"),
        ]
        result = HexEditorBridge._build_ips_from_patches(patches)
        assert result[:5] == _IPS_MAGIC
        assert result[-3:] == _IPS_FOOTER

    def test_empty_patches_list_produces_header_and_footer_only(self) -> None:
        """Verify that an empty patch list produces a payload of header plus footer only.

        The expected result is exactly PATCH + EOF = 8 bytes.
        """
        result = HexEditorBridge._build_ips_from_patches([])
        assert result == _IPS_MAGIC + _IPS_FOOTER

    def test_overflow_on_negative_offset(self) -> None:
        """Verify that a negative patch offset raises OverflowError."""
        with pytest.raises(OverflowError):
            HexEditorBridge._build_ips_from_patches([(-1, b"\x00")])

    def test_overflow_on_offset_exceeding_ips_max(self) -> None:
        """Verify that an offset exceeding the 24-bit IPS maximum raises OverflowError."""
        with pytest.raises(OverflowError):
            HexEditorBridge._build_ips_from_patches([(0x1000000, b"\x00")])


class TestDocumentExportPatchesIps:
    """Tests for the live IPS path on HexDocument.export_patches_ips."""

    def test_export_patches_ips_callable_on_document(self, hexcore: types.ModuleType) -> None:
        """Verify that HexDocument exposes export_patches_ips as a callable method.

        Args:
            hexcore: The native module fixture.
        """
        assert callable(getattr(hexcore.HexDocument, "export_patches_ips", None))

    def test_export_patches_ips_returns_bytes(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that export_patches_ips returns a bytes object.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(10, b"\xaa\xbb\xcc")
        result = doc.export_patches_ips()
        assert isinstance(result, bytes)

    def test_export_patches_ips_starts_with_patch_magic(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that the IPS payload from export_patches_ips begins with PATCH magic.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(0, b"\xde\xad\xbe\xef")
        result = doc.export_patches_ips()
        assert result[:5] == _IPS_MAGIC

    def test_export_patches_ips_ends_with_eof_marker(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that the IPS payload from export_patches_ips ends with the EOF marker.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(5, b"\x11\x22")
        result = doc.export_patches_ips()
        assert result[-3:] == _IPS_FOOTER

    def test_export_patches_ips_minimum_size(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that a single-byte patch produces at least 14 bytes from export_patches_ips.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(0, b"\xff")
        result = doc.export_patches_ips()
        assert len(result) >= 14

    def test_bridge_export_patches_ips_via_open_bytes(
        self,
        bridge: HexEditorBridge,
        sample_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        """Verify that the bridge export_patches path produces valid IPS for a modified document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            sample_bytes: The 256-byte payload fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bridge_ips_test.bin"
        f.write_bytes(sample_bytes)
        _run_async(bridge.open_file(str(f)))
        _run_async(bridge.write_bytes(0, "DE AD BE EF"))
        b64_result: str = str(_run_async(bridge.export_patches("ips")))
        decoded = base64.b64decode(b64_result)
        assert decoded[:5] == _IPS_MAGIC
        assert decoded[-3:] == _IPS_FOOTER
