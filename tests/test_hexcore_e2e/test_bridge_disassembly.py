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


_INT3_OPCODE = b"\xcc"
_INT3_COUNT = 8
_NOP_OPCODE = b"\x90"
_NOP_COUNT = 8

_EXPECTED_INSN_KEYS = {"address", "bytes", "mnemonic", "operands", "size"}


class TestBridgeDisassembly:
    """Tests covering disassemble with x86_64 machine code bytes."""

    def test_disassemble_returns_list(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that disassemble returns a list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = _INT3_OPCODE * _INT3_COUNT
        f = tmp_path / "int3.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: list[dict[str, Any]] = _run(bridge.disassemble(0, count=4, arch="x86", mode="64"))
        assert isinstance(result, list)

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
        """Verify that auto arch detection works on the PE text section code bytes.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        result: list[dict[str, Any]] = _run(loaded_bridge.disassemble(0x200, count=4, arch="auto"))
        assert isinstance(result, list)
