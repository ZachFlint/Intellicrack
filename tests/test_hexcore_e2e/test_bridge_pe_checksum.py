# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge PE checksum verification and repair."""

from __future__ import annotations

import asyncio
import struct
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

# Independent oracle constants derived from the conftest._build_pe_binary_full()
# layout without re-implementing the production checksum algorithm.
#
# Layout (all offsets in decimal):
#   e_lfanew = 0x80 = 128  (PE_SIGNATURE_OFFSET written at 0x3C)
#   checksum_offset = e_lfanew + 4(PE sig) + 20(COFF hdr) + 64(relative) = 216
#   file_size = 0x400(data section raw offset) + 0x100(data section size) = 1280
#
# The expected calculated checksum (60996) was computed by applying the
# standard Windows PE checksum algorithm (sum of 16-bit words with carry
# folding, skipping the checksum field, plus file size) independently of
# the production implementation, and confirmed to match the bridge output.
_ORACLE_CHECKSUM_OFFSET: int = 216
_ORACLE_CALCULATED: int = 60996
_ORACLE_FILE_SIZE: int = 1280


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


def _pe_checksum_oracle(data: bytes, checksum_offset: int) -> int:
    """Compute the Windows PE checksum by an independent reference implementation.

    This is an independent oracle used only in tests to produce the expected
    value against which the bridge output is compared. It is NOT the production
    code path; it is a standalone reference to make tests falsifiable.

    Args:
        data: Full file bytes.
        checksum_offset: Byte offset of the 4-byte CheckSum field.

    Returns:
        int: The independently computed PE checksum.
    """
    checksum: int = 0
    top: int = 1 << 32
    for i in range(0, len(data) & ~1, 2):
        if i in {checksum_offset, checksum_offset + 2}:
            continue
        word: int = data[i] | (data[i + 1] << 8)
        checksum += word
        if checksum >= top:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    if len(data) & 1:
        checksum += data[-1]
        if checksum >= top:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += checksum >> 16
    return (checksum & 0xFFFF) + len(data)


class TestVerifyPEChecksum:
    """Tests for the verify_pe_checksum method."""

    def test_verify_returns_all_fields(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that verify_pe_checksum returns stored, calculated, offset, valid with correct exact values.

        The expected values are independently derived from the known layout of
        the conftest PE fixture: stored=0 (the fixture sets CheckSum to 0),
        calculated=60996 (independently computed oracle), offset=216 (e_lfanew
        + 4 + 20 + 64), valid=False (stored 0 != calculated 60996).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result: dict[str, Any] = _run(bridge.verify_pe_checksum())

        assert set(result.keys()) == {"stored", "calculated", "offset", "valid"}
        assert result["stored"] == 0
        assert result["calculated"] == _ORACLE_CALCULATED
        assert result["offset"] == _ORACLE_CHECKSUM_OFFSET
        assert result["valid"] is False

    def test_verify_detects_zero_checksum(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that a PE with CheckSum=0 is detected as invalid with exact oracle values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with zero CheckSum field.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert result["stored"] == 0
        assert result["calculated"] == _ORACLE_CALCULATED
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

    def test_no_document_raises(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify verify_pe_checksum raises RuntimeError without a document.

        The pre-condition is earned by a real open-then-close cycle so that
        the ``bridge.document is None`` assertion is falsifiable: if
        ``close_file()`` ever failed to reset ``self.document`` to ``None``,
        this assertion would turn red and immediately surface the regression.
        Relying on construction-time ``None`` alone would make it a
        cannot-fail assertion; the open-then-close cycle makes it a genuine
        gate over the close path as well.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        assert bridge.document is not None, "open_file must set bridge.document; bridge is broken if None here."
        closed: bool = _run(bridge.close_file())
        assert closed is True, "close_file must return True when a file was open."
        assert bridge.document is None, "close_file must reset bridge.document to None; if non-None here, close_file has a regression."
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.verify_pe_checksum())

    def test_no_document_repair_raises(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify repair_pe_checksum raises RuntimeError without a document.

        The pre-condition is earned by a real open-then-close cycle so that
        the ``bridge.document is None`` assertion is falsifiable: if
        ``close_file()`` ever failed to reset ``self.document`` to ``None``,
        this assertion would turn red, exposing the regression before the
        ``pytest.raises`` body is reached.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        assert bridge.document is not None, "open_file must set bridge.document; bridge is broken if None here."
        closed: bool = _run(bridge.close_file())
        assert closed is True, "close_file must return True when a file was open."
        assert bridge.document is None, "close_file must reset bridge.document to None; if non-None here, close_file has a regression."
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.repair_pe_checksum())


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
        assert verify["stored"] == _ORACLE_CALCULATED
        assert verify["stored"] == verify["calculated"]

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
        assert verify["stored"] == _ORACLE_CALCULATED

    def test_repair_returns_correct_fields(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify that repair_pe_checksum returns old_checksum, new_checksum, offset fields.

        The fixture PE has CheckSum=0, so old_checksum must be 0 and
        new_checksum must equal the independently computed oracle value.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with zero CheckSum.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        repair_result: dict[str, Any] = _run(bridge.repair_pe_checksum())

        assert "old_checksum" in repair_result
        assert "new_checksum" in repair_result
        assert "offset" in repair_result
        assert repair_result["new_checksum"] == _ORACLE_CALCULATED
        assert repair_result["offset"] == _ORACLE_CHECKSUM_OFFSET


class TestPEChecksumAlgorithm:
    """Tests for the PE checksum computation algorithm correctness."""

    def test_checksum_algorithm_correctness(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify checksum computation produces the exact oracle-expected value.

        The expected value 60996 is independently computed by applying the
        Windows PE checksum algorithm to the known fixture binary without
        reusing the production code path, then confirmed to be stable across
        two consecutive calls (proving determinism).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result1: dict[str, Any] = _run(bridge.verify_pe_checksum())
        result2: dict[str, Any] = _run(bridge.verify_pe_checksum())

        assert result1["calculated"] == _ORACLE_CALCULATED
        assert result2["calculated"] == _ORACLE_CALCULATED
        assert result1["calculated"] == result2["calculated"]
        assert isinstance(result1["calculated"], int)

    def test_checksum_offset_matches_pe_layout(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify the checksum field offset matches the independently known PE layout.

        For the conftest fixture: e_lfanew=0x80, COFF header=20 bytes, relative
        offset to CheckSum=64 bytes, so checksum_offset = 0x80 + 4 + 20 + 64 = 216.
        This is derived from the PE spec layout, not from the production code.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        result: dict[str, Any] = _run(bridge.verify_pe_checksum())
        assert result["offset"] == _ORACLE_CHECKSUM_OFFSET

        raw: bytes = pe_binary_full.read_bytes()
        e_lfanew: int = struct.unpack_from("<I", raw, 0x3C)[0]
        oracle_checksum: int = _pe_checksum_oracle(raw, _ORACLE_CHECKSUM_OFFSET)
        assert oracle_checksum == _ORACLE_CALCULATED
        assert e_lfanew == 0x80
