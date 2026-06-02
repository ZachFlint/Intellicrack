# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge PE checksum verification and repair."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


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


class TestVerifyPEChecksum:
    """Tests for the verify_pe_checksum method."""

    def test_verify_returns_all_fields(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that verify_pe_checksum returns stored, calculated, offset, valid keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert "stored" in result
        assert "calculated" in result
        assert "offset" in result
        assert "valid" in result

    def test_verify_detects_zero_checksum(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that a PE with CheckSum=0 is detected as invalid.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with zero CheckSum field.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert result["stored"] == 0
        assert result["calculated"] > 0
        assert result["valid"] is False

    def test_verify_non_pe_raises(self, bridge: HexEditorBridge, elf_binary: Path) -> None:
        """Verify that verifying checksum on an ELF file is rejected.

        The native ``HexDocument.verify_pe_checksum`` maps its ``HashError`` to a
        ``ValueError`` whose message reports the missing ``MZ`` signature, so a
        non-PE input raises ``ValueError`` rather than ``RuntimeError``.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            elf_binary: Path to an ELF binary.
        """
        _run(bridge.open_file(str(elf_binary)))
        with pytest.raises(ValueError, match="not a PE file"):
            _run(bridge.verify_pe_checksum())

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify verify_pe_checksum raises RuntimeError without a document.

        Asserts the bridge is genuinely in the no-document state both before
        and after the failed call: ``bridge.document is None`` and
        ``bridge.state.binary_loaded is False`` guard against a bridge that
        accidentally constructs a default document at init (which would make
        the RuntimeError fire for an unrelated reason), and the same assertions
        after the raise prove the failed verify did not leave a partially-opened
        document or stale ``target_path`` behind.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert bridge.document is None
        assert bridge.state.binary_loaded is False
        assert bridge.state.target_path is None

        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.verify_pe_checksum())

        assert bridge.document is None
        assert bridge.state.binary_loaded is False
        assert bridge.state.target_path is None


class TestRepairPEChecksum:
    """Tests for the repair_pe_checksum method."""

    def test_repair_writes_correct_checksum(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that repair writes a valid checksum to the PE.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with zero CheckSum.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        _run(bridge.repair_pe_checksum())
        verify: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert verify["valid"] is True

    def test_repair_roundtrip(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that repair then verify produces matching stored and calculated values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        _run(bridge.repair_pe_checksum())
        verify: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert verify["stored"] == verify["calculated"]


class TestPEChecksumAlgorithm:
    """Tests for the PE checksum computation algorithm correctness."""

    def test_checksum_algorithm_correctness(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify checksum computation produces consistent non-zero results.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result1: dict[str, Any] = _run(bridge.verify_pe_checksum())
        result2: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert result1["calculated"] > 0
        assert result1["calculated"] == result2["calculated"]
        assert isinstance(result1["calculated"], int)
