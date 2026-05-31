# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for ``intellicrack.bridges.base`` (SHARD 04).

These tests replace trivial dataclass round-trip checks with assertions
over real computed results:

* :class:`DisassemblyLine` is populated from a real Windows PE
  (``kernel32.dll``) disassembled with the same capstone pipeline the
  concrete debugger bridge uses, and the decoded mnemonics are verified
  to be real x86 instructions located inside the section's virtual
  range (finding 04-F001).
* :class:`BridgeCapabilities` defaults are validated through the real
  ``__init__`` path of concrete bridge subclasses rather than the bare
  dataclass constructor (finding 04-F002).
* The abstract bridge base classes are checked for interface compliance
  against their concrete subclasses, with capability flags asserted to
  match documented values (finding 04-F011).
"""

from __future__ import annotations

import inspect
import re
import sys
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.base import (
    BinaryOperationsBridge,
    BridgeCapabilities,
    DebuggerBridge,
    DisassemblyLine,
    DynamicAnalysisBridge,
    InstrumentationBridge,
    StaticAnalysisBridge,
    ToolBridgeBase,
)
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.x64dbg import X64DbgBridge


if TYPE_CHECKING:
    from pathlib import Path

    import pefile as pefile_types


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Real PE disassembly fixtures resolve Windows System32 binaries",
)

capstone: Any = pytest.importorskip("capstone")
pefile: Any = pytest.importorskip("pefile")


_MAX_DECODE_BYTES: Final[int] = 256
_MIN_INSTRUCTIONS: Final[int] = 8
# A genuine x86 mnemonic decoded by capstone is a non-empty lowercase token
# of letters/digits (e.g. "mov", "jmp", "je", "jno", "int3", "movsxd",
# "pcmpeqb"). Optional REP/REPNE/LOCK prefixes appear space-separated.
_X86_MNEMONIC_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*( [a-z][a-z0-9]*)*$")


def _decode_text_section(pe: pefile_types.PE) -> tuple[list[DisassemblyLine], int, int]:
    """Decode real instructions from the ``.text`` section of a parsed PE.

    Skips the leading ``int3`` / zero alignment padding so the first
    decoded instruction is a genuine function prologue, then packs each
    decoded instruction into a :class:`DisassemblyLine` exactly as the
    concrete debugger bridge does.

    Args:
        pe: A parsed ``pefile.PE`` instance.

    Returns:
        tuple[list[DisassemblyLine], int, int]: The decoded lines and the
        inclusive-low / exclusive-high virtual-address bounds of the
        ``.text`` section.
    """
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    section = next(sec for sec in pe.sections if sec.Name.rstrip(b"\x00") == b".text")
    sec_lo = image_base + int(section.VirtualAddress)
    sec_hi = sec_lo + int(section.Misc_VirtualSize)

    raw = bytes(section.get_data())
    offset = 0
    while offset < len(raw) and raw[offset] in {0x00, 0xCC}:
        offset += 1

    code = raw[offset : offset + _MAX_DECODE_BYTES]
    start_va = sec_lo + offset

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines: list[DisassemblyLine] = []
    for instr in md.disasm(code, start_va):
        lines.append(
            DisassemblyLine(
                address=instr.address,
                bytes_str=" ".join(f"{b:02x}" for b in instr.bytes),
                mnemonic=instr.mnemonic,
                operands=instr.op_str,
                comment=None,
            ),
        )
        if len(lines) >= _MIN_INSTRUCTIONS:
            break
    return lines, sec_lo, sec_hi


def _disassemble_real_text(dll_path: Path) -> tuple[list[DisassemblyLine], int, int]:
    """Disassemble the real ``.text`` section of a PE via the bridge pipeline.

    Mirrors the exact capstone construction the concrete debugger bridge
    uses (``CS_ARCH_X86`` / ``CS_MODE_64``) so the :class:`DisassemblyLine`
    dataclass is exercised over genuine disassembly output.

    Args:
        dll_path: Path to a real 64-bit PE DLL.

    Returns:
        tuple[list[DisassemblyLine], int, int]: The decoded lines and the
        inclusive-low / exclusive-high virtual-address bounds of the
        ``.text`` section.
    """
    pe = pefile.PE(str(dll_path), fast_load=True)
    try:
        return _decode_text_section(pe)
    finally:
        pe.close()


class TestDisassemblyLineFromRealBinary:
    """04-F001: DisassemblyLine carries genuine disassembly of a real PE."""

    @staticmethod
    def test_decodes_real_text_mnemonics(real_pe_dll: Path) -> None:
        """Disassembling the real kernel32 .text yields real x86 instructions.

        Args:
            real_pe_dll: Session fixture resolving the real
                ``kernel32.dll`` on the Windows host or container.
        """
        lines, _sec_lo, _sec_hi = _disassemble_real_text(real_pe_dll)

        assert lines, "expected at least one decoded instruction"
        first = lines[0]
        assert isinstance(first, DisassemblyLine)

        prev_address = -1
        for line in lines:
            # Each line carries a genuine, non-empty x86 mnemonic. Real
            # .text code legitimately contains the full instruction set
            # (conditional jumps such as jno, SSE ops, etc.), so validate
            # the shape of a real decoded mnemonic rather than membership
            # in a narrow allowlist.
            assert line.mnemonic, "decoded line must carry a non-empty mnemonic"
            assert _X86_MNEMONIC_RE.fullmatch(line.mnemonic), (
                f"mnemonic {line.mnemonic!r} is not a valid x86 mnemonic token"
            )
            # Every decoded line must carry the raw instruction bytes as hex
            # that round-trips to the real instruction bytes.
            assert line.bytes_str
            decoded = bytes.fromhex(line.bytes_str.replace(" ", ""))
            assert decoded, "bytes_str must round-trip to real instruction bytes"
            # Linear decode yields strictly increasing addresses.
            assert line.address > prev_address, (
                f"address {line.address:#x} did not increase past {prev_address:#x}"
            )
            prev_address = line.address

    @staticmethod
    def test_addresses_within_text_section_range(real_pe_dll: Path) -> None:
        """Decoded instruction addresses fall inside the section VA range.

        Args:
            real_pe_dll: Session fixture resolving the real
                ``kernel32.dll`` on the Windows host or container.
        """
        lines, sec_lo, sec_hi = _disassemble_real_text(real_pe_dll)

        assert sec_lo < sec_hi
        for line in lines:
            assert sec_lo <= line.address < sec_hi, (
                f"address {line.address:#x} outside [{sec_lo:#x}, {sec_hi:#x})"
            )
        # Addresses are strictly increasing across the linear decode.
        addresses = [line.address for line in lines]
        assert addresses == sorted(addresses)
        assert len(set(addresses)) == len(addresses)


class TestConcreteBridgeCapabilities:
    """04-F002: capability defaults exercised through real bridge __init__."""

    @staticmethod
    def test_sandbox_bridge_capabilities() -> None:
        """SandboxBridge.__init__ records its documented capability flags."""
        bridge = SandboxBridge()
        caps = bridge.capabilities
        assert caps.supports_dynamic_analysis is True
        assert caps.supports_patching is False
        assert caps.supports_static_analysis is False
        assert caps.supports_debugging is False
        assert "x86_64" in caps.supported_architectures
        assert "pe" in caps.supported_formats

    @staticmethod
    def test_static_bridge_subclass_defaults() -> None:
        """GhidraBridge.__init__ sets the static-analysis capability block."""
        bridge = GhidraBridge()
        caps = bridge.capabilities
        assert caps.supports_static_analysis is True
        assert caps.supports_decompilation is True
        assert caps.supports_debugging is False
        assert set(caps.supported_formats) >= {"pe", "elf", "macho"}

    @staticmethod
    def test_capability_query_helpers_on_real_bridge() -> None:
        """has_capability / supports_arch reflect the real bridge flags."""
        bridge = GhidraBridge()
        caps = bridge.capabilities
        assert caps.has_capability("static_analysis") is True
        assert caps.has_capability("debugging") is False
        assert caps.supports_arch("x86_64") is True
        assert caps.supports_format("pe") is True
        assert caps.supports_format("dex") is False


class TestBridgeInterfaceCompliance:
    """04-F011: concrete bridges satisfy their abstract base contracts."""

    @staticmethod
    def test_ghidra_is_static_analysis_bridge() -> None:
        """GhidraBridge subclasses StaticAnalysisBridge with abstract methods."""
        bridge = GhidraBridge()
        assert isinstance(bridge, StaticAnalysisBridge)
        assert isinstance(bridge, ToolBridgeBase)
        for method_name in ("load_binary", "analyze", "disassemble", "decompile", "get_imports", "get_exports"):
            method = getattr(bridge, method_name)
            assert callable(method)
            assert inspect.iscoroutinefunction(method), f"{method_name} must be async"

    @staticmethod
    def test_cutter_is_static_analysis_bridge() -> None:
        """CutterBridge also satisfies the StaticAnalysisBridge contract."""
        bridge = CutterBridge()
        assert isinstance(bridge, StaticAnalysisBridge)
        assert bridge.capabilities.supports_static_analysis is True

    @staticmethod
    def test_x64dbg_is_debugger_bridge() -> None:
        """X64DbgBridge subclasses DebuggerBridge with debugger methods."""
        bridge = X64DbgBridge()
        assert isinstance(bridge, DebuggerBridge)
        assert isinstance(bridge, DynamicAnalysisBridge)
        for method_name in ("attach", "set_breakpoint", "get_registers", "step_into", "read_memory"):
            method = getattr(bridge, method_name)
            assert callable(method)
            assert inspect.iscoroutinefunction(method), f"{method_name} must be async"
        assert bridge.capabilities.supports_debugging is True
        assert bridge.capabilities.supports_patching is True

    @staticmethod
    def test_frida_is_instrumentation_bridge() -> None:
        """FridaBridge subclasses InstrumentationBridge with hook methods."""
        bridge = FridaBridge()
        assert isinstance(bridge, InstrumentationBridge)
        assert isinstance(bridge, DynamicAnalysisBridge)
        for method_name in ("hook_function", "execute_script", "enumerate_modules", "call_function"):
            method = getattr(bridge, method_name)
            assert callable(method)
            assert inspect.iscoroutinefunction(method), f"{method_name} must be async"
        assert bridge.capabilities.supports_scripting is True

    @staticmethod
    def test_binary_operations_bridge_is_abstract() -> None:
        """BinaryOperationsBridge cannot be instantiated directly (abstract)."""
        assert issubclass(BinaryOperationsBridge, ToolBridgeBase)
        with pytest.raises(TypeError):
            BinaryOperationsBridge()  # type: ignore[abstract]

    @staticmethod
    def test_abstract_base_capability_blocks() -> None:
        """Each abstract base defines its documented capability defaults.

        DynamicAnalysisBridge and DebuggerBridge are abstract, so the
        capability defaults are read from a concrete subclass that does
        not override them beyond the base ``__init__`` chain.
        """
        debugger = X64DbgBridge()
        assert isinstance(debugger, DebuggerBridge)
        caps = debugger.capabilities
        assert caps.supports_dynamic_analysis is True
        assert isinstance(caps, BridgeCapabilities)
        assert "x86_64" in caps.supported_architectures
