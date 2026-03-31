# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge error handling when no document is open."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")


def _run(coro: Coroutine[object, object, object]) -> object:
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


class TestReadBytesErrors:
    """Tests covering read_bytes error behaviour without an open document."""

    def test_read_bytes_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify read_bytes raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.read_bytes(0, 4))


class TestWriteBytesErrors:
    """Tests covering write_bytes error behaviour without an open document."""

    def test_write_bytes_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify write_bytes raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.write_bytes(0, "AABB"))

    def test_write_bytes_beyond_length_on_loaded_doc(self, loaded_bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify write_bytes on a loaded document can attempt an out-of-range write.

        The bridge delegates to the Rust layer; this test confirms the call
        either raises an exception or silently clips without crashing Python.

        Args:
            loaded_bridge: HexEditorBridge with a PE file already opened.
            pe_binary: Path to the PE binary fixture.
        """
        size = pe_binary.stat().st_size
        try:
            result: bool = _run(loaded_bridge.write_bytes(size + 100, "FF"))
            assert isinstance(result, bool)
        except (RuntimeError, ValueError, OverflowError):
            pass


class TestSearchErrors:
    """Tests covering search method behaviour without an open document."""

    def test_search_hex_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify search_hex raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.search_hex("4D 5A"))

    def test_search_text_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify search_text raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.search_text("MZ"))


class TestDisassembleErrors:
    """Tests covering disassemble error behaviour without an open document."""

    def test_disassemble_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify disassemble raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.disassemble(0))


class TestYaraScanErrors:
    """Tests covering yara_scan error behaviour without an open document."""

    def test_yara_scan_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify yara_scan raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule = "rule test { condition: true }"
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.yara_scan(rule))


class TestCalculateHashErrors:
    """Tests covering hash calculation error behaviour without an open document."""

    def test_calculate_hash_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify calculate_hash raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.calculate_hash("sha256"))

    def test_calculate_hash_range_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify calculate_hash_range raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.calculate_hash_range(0, 64, "sha256"))

    def test_calculate_hash_custom_crc_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify calculate_hash_custom_crc raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.calculate_hash_custom_crc(0, 64, 0x04C11DB7, 0xFFFFFFFF, 32))


class TestEntropyErrors:
    """Tests covering entropy error behaviour without an open document."""

    def test_get_entropy_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify get_entropy raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_entropy())


class TestTransformErrors:
    """Tests covering transform and pipeline error behaviour without an open document."""

    def test_apply_transform_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify apply_transform raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.apply_transform("xor_single", 0, 4, '{"key": "ff"}'))

    def test_apply_pipeline_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify apply_pipeline raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.apply_pipeline('[{"name":"xor_single","params":{"key":"ff"}}]', 0, 4))


class TestDecodeTextErrors:
    """Tests covering decode_text error behaviour without an open document."""

    def test_decode_text_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Verify decode_text raises RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.decode_text(0, 8, "utf-8"))
