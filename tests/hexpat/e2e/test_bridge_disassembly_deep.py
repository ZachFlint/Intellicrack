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
        """Verify arch='auto' on the AMD64 PE header decodes like explicit x86-64.

        Architecture auto-detection reads the magic and machine fields at the
        start of the disassembled window; the fixture PE carries the AMD64
        machine field (0x8664), so ``arch='auto'`` from offset 0 must resolve
        to x86-64. The auto run is checked against an explicit ``x86``/``64``
        run as the independent oracle: identical mnemonic, operands, byte
        encoding, and size for the same first instruction. A broken detector
        that picked the wrong arch/mode, or a disassembler that returned an
        empty list, would diverge from the explicit run and fail.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        auto_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=4, arch="auto"))
        explicit_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert explicit_results
        assert auto_results
        assert len(auto_results) == len(explicit_results)
        assert auto_results[0]["mnemonic"] == explicit_results[0]["mnemonic"]
        assert auto_results[0]["operands"] == explicit_results[0]["operands"]
        assert auto_results[0]["bytes"] == explicit_results[0]["bytes"]
        assert auto_results[0]["size"] == explicit_results[0]["size"]

    def test_disassemble_pe_text_explicit_x86_64_matches_auto(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify auto-detected arch matches explicit x86-64 for the PE header.

        Architecture auto-detection reads the magic and machine fields at the
        start of the disassembled window, so both runs start at offset 0 where
        the AMD64 PE header lives. The auto run must resolve to x86-64 and yield
        the same first-instruction mnemonic as the explicit ``x86``/``64`` run.
        The .text section's known ``int3`` bytes are validated separately.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        auto_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=1, arch="auto"))
        explicit_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=1, arch="x86", mode="64"))
        text_results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(_PE_TEXT_OFFSET, count=1, arch="x86", mode="64"))
        assert explicit_results
        assert auto_results
        assert auto_results[0]["mnemonic"] == explicit_results[0]["mnemonic"]
        assert text_results
        assert text_results[0]["mnemonic"] == "int3"


class TestDisassembleMzHeader:
    """Tests disassembling from offset 0 (MZ header) of the PE binary."""

    def test_disassemble_at_mz_header_produces_coherent_first_instruction(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify disassembling at offset 0 yields a coherent first instruction.

        The bridge uses the read offset as the instruction base address, so the
        first instruction decoded from offset 0 must report ``address == 0``.
        Each instruction's ``bytes`` field is a hex encoding of the raw opcode
        bytes and ``size`` is the byte length; the independent oracle is that
        the decoded ``bytes`` length must equal ``size`` (capstone's own
        invariant). A disassembler that returned an empty list, mis-set the
        base address, or produced an inconsistent size/bytes pair would fail.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert results
        first: dict[str, Any] = results[0]
        assert first["address"] == 0
        first_size: int = first["size"]
        assert first_size > 0
        first_bytes: bytes = bytes.fromhex(first["bytes"])
        assert len(first_bytes) == first_size
        running_address: int = 0
        for insn in results:
            assert insn["address"] == running_address
            insn_size: int = insn["size"]
            assert len(bytes.fromhex(insn["bytes"])) == insn_size
            running_address += insn_size


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

    def test_disassemble_last_byte_decodes_single_trailing_instruction(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the trailing byte at end-of-file decodes to exactly one instruction.

        A controlled buffer of three INT3 bytes followed by a single NOP is
        written to disk; the final byte (``0x90``) is a complete one-byte x86
        instruction. Disassembling at ``doc_len - 1`` with a generous count
        must read only the one remaining byte and decode it without reading
        past the end. The independent oracle is the x86 encoding: ``0x90`` is
        ``nop`` with ``size == 1``, and the bridge uses the read offset as the
        base address, so the single result must report ``mnemonic == "nop"``,
        ``size == 1``, ``bytes == "90"``, and ``address == near_end``. A
        disassembler that returned an empty list (broken boundary read) or
        over-read the file would fail.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * 3 + _NOP_OPCODE
        f = tmp_path / "trailing_nop.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        doc_len: int = len(payload)
        near_end: int = doc_len - 1
        results: list[dict[str, Any]] = _run(bridge.disassemble(near_end, count=10, arch="x86", mode="64"))
        assert len(results) == 1
        only: dict[str, Any] = results[0]
        assert only["address"] == near_end
        assert only["mnemonic"] == "nop"
        assert only["size"] == 1
        assert only["bytes"].lower() == "90"
