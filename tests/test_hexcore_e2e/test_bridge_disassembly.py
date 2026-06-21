# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge disassemble method."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


capstone = pytest.importorskip("capstone", reason="capstone not installed")


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


_INT3_OPCODE = b"\xcc"
_INT3_COUNT = 8
_NOP_OPCODE = b"\x90"
_NOP_COUNT = 8

_EXPECTED_INSN_KEYS = {"address", "bytes", "mnemonic", "operands", "size"}


class TestBridgeDisassembly:
    """Tests covering disassemble with x86_64 machine code bytes."""

    def test_disassemble_matches_independent_capstone_decode(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify disassemble output matches an independent capstone decode.

        The bridge result for a known INT3 payload is checked field-by-field
        against capstone decoding the same bytes directly. capstone is an
        independent oracle: it is not the code path the bridge selects through
        ``_get_disassembler``. Each returned instruction must match capstone's
        address, mnemonic, operands, byte size, and raw byte encoding. A broken
        disassembler returning an empty list, wrong mnemonics, or garbage byte
        encodings would diverge from the oracle and fail.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * _INT3_COUNT
        f = tmp_path / "int3.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        expected: list[tuple[int, str, str, int, str]] = [
            (insn.address, insn.mnemonic, insn.op_str, insn.size, insn.bytes.hex())
            for insn in md.disasm(payload, 0, count=4)
        ]
        assert expected
        assert len(result) == len(expected)
        for actual_insn, (addr, mnemonic, op_str, size, byte_hex) in zip(result, expected, strict=True):
            assert actual_insn["address"] == addr
            assert actual_insn["mnemonic"] == mnemonic
            assert actual_insn["operands"] == op_str
            assert actual_insn["size"] == size
            assert actual_insn["bytes"] == byte_hex

    def test_disassemble_int3_mnemonic(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that INT3 bytes disassemble to the int3 mnemonic.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * _INT3_COUNT
        f = tmp_path / "int3_mnem.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert result
        assert result[0]["mnemonic"] == "int3"

    def test_disassemble_result_items_have_required_keys(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that each instruction dict contains the required keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * _NOP_COUNT
        f = tmp_path / "nop_keys.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert result
        for insn in result:
            assert _EXPECTED_INSN_KEYS.issubset(insn.keys())

    def test_disassemble_instruction_address_starts_at_offset(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the first instruction address equals the given offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * _NOP_COUNT
        f = tmp_path / "nop_addr.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert result[0]["address"] == 0

    def test_disassemble_nop_has_size_one(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that NOP instructions have size 1.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * _NOP_COUNT
        f = tmp_path / "nop_size.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert result[0]["size"] == 1

    def test_disassemble_bytes_field_is_hex_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the bytes field of an instruction is a hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _NOP_OPCODE * _NOP_COUNT
        f = tmp_path / "nop_bytehex.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=2, arch="x86", mode="64"))
        assert isinstance(result[0]["bytes"], str)
        bytes.fromhex(result[0]["bytes"])

    def test_disassemble_pe_section_code_with_auto_arch(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify auto arch detection on the AMD64 PE header decodes like x86-64.

        ``disassemble`` runs architecture auto-detection from offset 0, where
        the fixture PE carries the AMD64 machine field (0x8664). The auto run
        is checked against an explicit ``x86``/``64`` run as the independent
        oracle and against a fresh capstone decode of the same header bytes:
        instruction count, and each first instruction's mnemonic, operands,
        byte encoding, and size must agree. A detector that resolved the wrong
        arch/mode, or a disassembler returning an empty list, would diverge and
        fail.

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

        header: bytes = bytes(loaded_bridge.document.read(0, 16)) if loaded_bridge.document is not None else b""
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        first_oracle = next(md.disasm(header, 0, count=1))
        assert auto_results[0]["mnemonic"] == first_oracle.mnemonic
        assert auto_results[0]["operands"] == first_oracle.op_str
        assert auto_results[0]["size"] == first_oracle.size
        assert auto_results[0]["bytes"] == first_oracle.bytes.hex()
