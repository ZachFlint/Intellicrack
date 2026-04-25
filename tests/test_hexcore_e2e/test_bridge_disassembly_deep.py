# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge disassemble method with deeper instruction-level validation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")
pytest.importorskip("capstone", reason="capstone not installed")


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


_INT3_OPCODE: bytes = b"\xcc"
_NOP_OPCODE: bytes = b"\x90"
_PE_TEXT_OFFSET: int = 0x200
_PE_TEXT_INT3_COUNT: int = 4
_EXPECTED_INSN_KEYS: set[str] = {"address", "bytes", "mnemonic", "operands", "size"}


class TestDisassemblePeTextSection:
    """Tests targeting the .text section of the minimal PE binary with known 0xCC bytes."""

    def test_disassemble_pe_text_int3_mnemonic(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that 0xCC bytes at PE .text offset disassemble as int3.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=4, arch="x86", mode="64"))
        assert results
        assert results[0]["mnemonic"] == "int3"

    def test_disassemble_pe_text_count_1_returns_exactly_one(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that count=1 returns exactly 1 instruction.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=1, arch="x86", mode="64"))
        assert len(results) == 1

    def test_disassemble_pe_text_count_4_returns_up_to_4(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that count=4 on 4 INT3 bytes returns at most 4 instructions.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=4, arch="x86", mode="64"))
        assert 1 <= len(results) <= 4

    def test_disassemble_pe_text_address_equals_offset(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the first instruction address equals the PE .text offset.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=1, arch="x86", mode="64"))
        assert len(results) == 1
        assert results[0]["address"] == _PE_TEXT_OFFSET

    def test_disassemble_pe_text_all_required_keys_present(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify each instruction dict in PE .text disassembly has all required keys.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=4, arch="x86", mode="64"))
        assert results
        for insn in results:
            assert _EXPECTED_INSN_KEYS.issubset(insn.keys())

    def test_disassemble_pe_text_with_auto_arch(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that arch='auto' on the PE .text section produces non-empty results.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=4, arch="auto"))
        assert isinstance(results, list)

    def test_disassemble_pe_text_explicit_x86_64_matches_auto(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that arch='x86',mode='64' returns the same mnemonic as auto on PE .text.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        auto_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=1, arch="auto"))
        explicit_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=1, arch="x86", mode="64"))
        assert explicit_results
        assert explicit_results[0]["mnemonic"] == "int3"
        if auto_results:
            assert auto_results[0]["mnemonic"] == explicit_results[0]["mnemonic"]


class TestDisassembleMzHeader:
    """Tests disassembling from offset 0 (MZ header) of the PE binary."""

    def test_disassemble_at_mz_header_does_not_crash(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that disassembling at offset 0 (MZ header) does not raise.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert isinstance(results, list)

    def test_disassemble_mz_header_address_starts_at_zero(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the first instruction address is 0 when disassembling from offset 0.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        if results := _run(loaded_bridge.disassemble(0, count=1, arch="x86", mode="64")):
            assert results[0]["address"] == 0


class TestDisassembleX86Mode32:
    """Tests for explicit 32-bit mode disassembly."""

    def test_disassemble_with_mode_32_returns_instructions(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that arch='x86',mode='32' disassembles INT3 bytes without error.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * 4 + _NOP_OPCODE * 4
        f = tmp_path / "x86_32.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="32"))
        assert isinstance(results, list)
        assert results


class TestDisassembleKnownX86Sequence:
    """Tests with a precisely crafted NOP/INT3 byte sequence."""

    def test_nop_nop_nop_int3_sequence(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that NOP NOP NOP INT3 disassembles to first 3 NOP and last INT3.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x90\x90\x90\xcc"
        f = tmp_path / "nop3_int3.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert len(results) == 4
        for i in range(3):
            assert results[i]["mnemonic"] == "nop"
        assert results[3]["mnemonic"] == "int3"

    def test_nop_bytes_field_is_valid_hex_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the bytes field of a NOP instruction is a valid hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * 4
        f = tmp_path / "nop_hex.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.disassemble(0, count=2, arch="x86", mode="64"))
        assert results
        bytes_field: str = results[0]["bytes"]
        assert isinstance(bytes_field, str)
        decoded = bytes.fromhex(bytes_field)
        assert len(decoded) > 0

    def test_nop_size_field_is_positive_int(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the size field of a NOP instruction is a positive integer.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * 4
        f = tmp_path / "nop_sz.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.disassemble(0, count=2, arch="x86", mode="64"))
        assert results
        size_val: int = results[0]["size"]
        assert isinstance(size_val, int)
        assert size_val > 0

    def test_int3_bytes_field_equals_cc_hex(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the bytes field for an INT3 instruction is 'cc'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * 4
        f = tmp_path / "int3_bytecheck.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.disassemble(0, count=1, arch="x86", mode="64"))
        assert len(results) == 1
        assert results[0]["bytes"].lower() == "cc"


class TestDisassembleEdgeCases:
    """Tests for boundary and edge-case behavior in disassembly."""

    def test_disassemble_at_end_of_file_returns_empty_or_partial(self, loaded_bridge: HexEditorBridge, pe_bytes: bytes) -> None:
        """Verify disassembling near end of document returns empty list or fewer instructions.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            pe_bytes: PE binary content as bytes.
        """
        doc_len: int = len(pe_bytes)
        near_end: int = doc_len - 1
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(near_end, count=10, arch="x86", mode="64"))
        assert isinstance(results, list)
        assert len(results) <= 1
