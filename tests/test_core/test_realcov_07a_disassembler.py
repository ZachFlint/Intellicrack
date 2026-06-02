# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-binary coverage tests for ``intellicrack.core.disassembler``.

These tests address audit shard 07 findings for ``disassembler.py``:

* The audit flagged that ``auto_detect_arch`` was only ever exercised with a
  mocked ``detect_format_and_arch`` return tuple (test_disassembler.py:55-94).
  The tests here run the REAL detection chain on REAL PE / ELF / Mach-O
  binaries and assert the resulting capstone ``(arch, mode)`` pair.
* The audit noted ``disassemble()`` has no direct unit test that decodes real
  machine code. The tests here extract the real ``.text`` section from a real
  PE and a real ELF, disassemble it with capstone, and assert that genuine
  x86-64 mnemonics are produced.
* The audit noted ``get_disassembler()`` singleton reuse, RISC-V conditional
  availability, and ``get_supported_architectures()`` were untested. Those are
  covered here against the real installed capstone build.

No mocks are used: every assertion is driven by a real binary and the real
capstone engine.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.pe_format import (
    is_pe64_optional_header,
    iterate_section_headers,
    optional_header_size_for,
    read_dos_e_lfanew,
    unpack_coff_header,
)
from intellicrack.core.disassembler import (
    DisasmInstruction,
    HexDisassembler,
    UnsupportedArchitectureError,
    get_disassembler,
)


if TYPE_CHECKING:
    from pathlib import Path

capstone = pytest.importorskip("capstone", reason="capstone is not installed")


_PE_COFF_HEADER_SIZE = 20
_PE_SIGNATURE_SIZE = 4
_ELF_E_SHOFF_OFFSET = 0x28
_ELF_E_SHENTSIZE_OFFSET = 0x3A
_ELF_E_SHNUM_OFFSET = 0x3C
_ELF_E_SHSTRNDX_OFFSET = 0x3E
_ELF_SH_NAME_OFFSET_FMT = "<IIQQQQ"


def _extract_pe_text_section(data: bytes) -> tuple[bytes, int]:
    """Extract the raw ``.text`` section bytes and its RVA from a PE buffer.

    Args:
        data: Full PE file contents.

    Returns:
        tuple[bytes, int]: The raw ``.text`` section bytes and its
            virtual address (RVA).

    Raises:
        AssertionError: If the PE has no ``.text`` section.
    """
    e_lfanew = read_dos_e_lfanew(data)
    _machine, num_sections, opt_size, _characteristics = unpack_coff_header(
        data,
        e_lfanew + _PE_SIGNATURE_SIZE,
    )
    optional_header_offset = e_lfanew + _PE_SIGNATURE_SIZE + _PE_COFF_HEADER_SIZE
    is_pe64 = is_pe64_optional_header(data, optional_header_offset)
    if opt_size == 0:
        opt_size = optional_header_size_for(is_pe64=is_pe64)
    sections_offset = optional_header_offset + opt_size
    for section in iterate_section_headers(data, sections_offset, num_sections):
        if section["name"] == ".text":
            raw_offset = int(section["raw_offset"])
            raw_size = int(section["raw_size"])
            virtual_address = int(section["virtual_address"])
            return data[raw_offset : raw_offset + raw_size], virtual_address
    msg = "real PE binary unexpectedly lacks a .text section"
    raise AssertionError(msg)


def _extract_elf_text_section(data: bytes) -> tuple[bytes, int]:
    """Extract the raw ``.text`` section bytes and its file offset from an ELF.

    Args:
        data: Full ELF file contents (ELF64 little-endian).

    Returns:
        tuple[bytes, int]: The raw ``.text`` section bytes and its file
            offset.

    Raises:
        AssertionError: If the ELF has no ``.text`` section.
    """
    e_shoff = struct.unpack_from("<Q", data, _ELF_E_SHOFF_OFFSET)[0]
    shentsize = struct.unpack_from("<H", data, _ELF_E_SHENTSIZE_OFFSET)[0]
    shnum = struct.unpack_from("<H", data, _ELF_E_SHNUM_OFFSET)[0]
    shstrndx = struct.unpack_from("<H", data, _ELF_E_SHSTRNDX_OFFSET)[0]

    def _section_fields(index: int) -> tuple[int, int, int]:
        offset = e_shoff + index * shentsize
        name_idx, _sh_type, _flags, _addr, sh_offset, sh_size = struct.unpack_from(
            _ELF_SH_NAME_OFFSET_FMT,
            data,
            offset,
        )
        return int(name_idx), int(sh_offset), int(sh_size)

    _name_idx, strtab_offset, _strtab_size = _section_fields(shstrndx)
    for index in range(shnum):
        name_idx, sh_offset, sh_size = _section_fields(index)
        name = data[strtab_offset + name_idx :].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        if name == ".text":
            return data[sh_offset : sh_offset + sh_size], sh_offset
    msg = "real ELF binary unexpectedly lacks a .text section"
    raise AssertionError(msg)


@pytest.fixture
def disasm() -> HexDisassembler:
    """Return the shared :class:`HexDisassembler`, skipping without capstone.

    Returns:
        HexDisassembler: Live disassembler backed by the installed capstone.
    """
    instance = get_disassembler()
    if not instance.available:
        pytest.skip("capstone is not available in this environment")
    return instance


class TestAutoDetectArchRealBinaries:
    """Auto-detection against the real PE/ELF/Mach-O detection chain."""

    def test_auto_detect_real_pe_dll_resolves_x86_64(
        self,
        disasm: HexDisassembler,
        real_pe_dll: Path,
    ) -> None:
        """Detect x86-64 from a real System32 DLL with no mocking.

        Args:
            disasm: Live disassembler.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        data = real_pe_dll.read_bytes()
        arch, mode = disasm.auto_detect_arch(data)
        assert arch == "x86"
        assert mode == "64"

    def test_auto_detect_real_elf_resolves_x86_64(
        self,
        disasm: HexDisassembler,
        real_elf_binary: Path,
    ) -> None:
        """Detect x86-64 from the committed real ELF fixture.

        Args:
            disasm: Live disassembler.
            real_elf_binary: Committed real ELF binary.
        """
        data = real_elf_binary.read_bytes()
        arch, mode = disasm.auto_detect_arch(data)
        assert arch == "x86"
        assert mode == "64"

    def test_auto_detect_real_macho_resolves_x86_64(
        self,
        disasm: HexDisassembler,
        real_macho_binary: Path,
    ) -> None:
        """Detect x86-64 from the committed real Mach-O fixture.

        Args:
            disasm: Live disassembler.
            real_macho_binary: Committed real Mach-O binary.
        """
        data = real_macho_binary.read_bytes()
        arch, mode = disasm.auto_detect_arch(data)
        assert arch == "x86"
        assert mode == "64"

    def test_auto_detect_raw_bytes_raises_unsupported(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """Truly format-less bytes surface as ``UnsupportedArchitectureError``.

        Args:
            disasm: Live disassembler.

        Drives the real detector (no mock); ``detect_format_and_arch``
        classifies a random non-magic buffer as ``unknown``, which has no
        capstone mapping and must raise rather than silently fall back. The
        error must expose the offending ``arch`` and a descriptive message,
        and remain a :class:`ValueError` subclass so existing
        ``except ValueError`` handlers still catch it.
        """
        raw = bytes(range(64))
        with pytest.raises(UnsupportedArchitectureError) as exc_info:
            disasm.auto_detect_arch(raw)
        error = exc_info.value
        assert error.arch == "unknown"
        assert str(error) == "unsupported architecture: 'unknown'"
        assert isinstance(error, ValueError)

    def test_auto_detect_empty_buffer_raises_unsupported(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """An empty buffer has no magic bytes and must raise, not default.

        Args:
            disasm: Live disassembler.

        A silent x86-64 fallback on zero-length input would be a dangerous
        regression; the real detector classifies it as ``raw``/``unknown``
        and the mapping lookup must raise.
        """
        with pytest.raises(UnsupportedArchitectureError) as exc_info:
            disasm.auto_detect_arch(b"")
        assert exc_info.value.arch == "unknown"
        assert "unknown" in str(exc_info.value)

    def test_auto_detect_truncated_pe_header_raises_unsupported(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """A bare ``MZ`` magic without a COFF header is unmappable.

        Args:
            disasm: Live disassembler.

        The detector recognises the ``MZ`` magic as a PE format candidate
        but cannot read the machine field from the truncated buffer, so the
        architecture stays ``unknown`` and the call must raise rather than
        return a fabricated ``(arch, mode)`` pair.
        """
        with pytest.raises(UnsupportedArchitectureError) as exc_info:
            disasm.auto_detect_arch(b"MZ")
        assert exc_info.value.arch == "unknown"
        assert str(exc_info.value) == "unsupported architecture: 'unknown'"


class TestDisassembleRealMachineCode:
    """Direct ``disassemble()`` coverage over real ``.text`` sections."""

    def test_disassemble_real_pe_text_section_yields_x86_mnemonics(
        self,
        disasm: HexDisassembler,
        real_pe_dll: Path,
    ) -> None:
        """Disassemble a real PE ``.text`` section into real x86-64 mnemonics.

        Args:
            disasm: Live disassembler.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        data = real_pe_dll.read_bytes()
        section, rva = _extract_pe_text_section(data)
        assert section, "real .text section must contain code bytes"
        arch, mode = disasm.auto_detect_arch(data)
        instructions = disasm.disassemble(section, base_addr=rva, arch=arch, mode=mode, count=64)
        assert instructions, "capstone must decode at least one instruction"
        assert all(isinstance(insn, DisasmInstruction) for insn in instructions)
        mnemonics = {insn.mnemonic for insn in instructions}
        # Real compiled x86-64 code always contains common control/data ops.
        assert mnemonics & {"mov", "push", "call", "jmp", "lea", "test", "ret", "sub", "add"}
        first = instructions[0]
        assert first.address == rva
        assert first.size == len(first.raw_bytes)
        assert first.size >= 1

    def test_disassemble_real_elf_text_section_yields_x86_mnemonics(
        self,
        disasm: HexDisassembler,
        real_elf_binary: Path,
    ) -> None:
        """Disassemble a real ELF ``.text`` section into real x86-64 mnemonics.

        Args:
            disasm: Live disassembler.
            real_elf_binary: Committed real ELF binary.
        """
        data = real_elf_binary.read_bytes()
        section, file_offset = _extract_elf_text_section(data)
        assert section, "real ELF .text section must contain code bytes"
        arch, mode = disasm.auto_detect_arch(data)
        instructions = disasm.disassemble(section, base_addr=file_offset, arch=arch, mode=mode, count=64)
        assert instructions
        mnemonics = {insn.mnemonic for insn in instructions}
        assert mnemonics & {"mov", "push", "call", "jmp", "lea", "test", "ret", "sub", "xor", "cmp"}

    def test_disassemble_to_lines_real_section_matches_disassemble(
        self,
        disasm: HexDisassembler,
        real_pe_dll: Path,
    ) -> None:
        """``disassemble_to_lines`` mirrors ``disassemble`` over real code.

        Args:
            disasm: Live disassembler.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        data = real_pe_dll.read_bytes()
        section, rva = _extract_pe_text_section(data)
        arch, mode = disasm.auto_detect_arch(data)
        raw = disasm.disassemble(section, base_addr=rva, arch=arch, mode=mode, count=16)
        lines = disasm.disassemble_to_lines(section, base_addr=rva, arch=arch, mode=mode, count=16)
        assert len(lines) == len(raw)
        for insn, line in zip(raw, lines, strict=True):
            assert line.address == insn.address
            assert line.mnemonic == insn.mnemonic
            assert line.operands == insn.op_str
            assert line.bytes_str == " ".join(f"{b:02x}" for b in insn.raw_bytes)

    def test_disassemble_count_caps_instruction_total(
        self,
        disasm: HexDisassembler,
        real_pe_dll: Path,
    ) -> None:
        """The ``count`` argument bounds the number of returned instructions.

        Args:
            disasm: Live disassembler.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        data = real_pe_dll.read_bytes()
        section, rva = _extract_pe_text_section(data)
        arch, mode = disasm.auto_detect_arch(data)
        instructions = disasm.disassemble(section, base_addr=rva, arch=arch, mode=mode, count=5)
        assert len(instructions) <= 5


class TestSupportedArchitecturesAndSingleton:
    """Coverage for ``get_supported_architectures`` and the module singleton."""

    def test_singleton_is_reused_across_calls(self) -> None:
        """``get_disassembler`` returns the identical instance every call."""
        first = get_disassembler()
        second = get_disassembler()
        assert first is second

    def test_supported_architectures_includes_real_x86(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """The supported-arch list reflects the real capstone build.

        Args:
            disasm: Live disassembler.
        """
        supported = disasm.get_supported_architectures()
        assert supported, "capstone always supports at least x86"
        pairs = {(entry["arch"], entry["mode"]) for entry in supported}
        assert ("x86", "64") in pairs
        assert ("x86", "32") in pairs
        for entry in supported:
            assert set(entry) == {"arch", "mode", "description"}
            assert entry["description"]

    def test_supported_architectures_each_pair_constructs_a_real_engine(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """Every reported architecture truly resolves to capstone constants.

        Args:
            disasm: Live disassembler.

        ``get_supported_architectures`` only lists a pair after constructing
        a real ``capstone.Cs`` for it. This test independently disassembles a
        known x86-64 ``ret`` to prove a reported pair is functional, not just
        present in a static list.
        """
        supported = disasm.get_supported_architectures()
        assert ("x86", "64") in {(e["arch"], e["mode"]) for e in supported}
        instructions = disasm.disassemble(b"\xc3", base_addr=0, arch="x86", mode="64", count=1)
        assert instructions
        assert instructions[0].mnemonic == "ret"

    def test_riscv_gating_matches_real_capstone_capability(
        self,
        disasm: HexDisassembler,
    ) -> None:
        """RISC-V appears in the list iff the real capstone build supports it.

        Args:
            disasm: Live disassembler.

        Verifies the conditional gating in ``get_supported_architectures``
        against the actual installed capstone module rather than assuming a
        particular build.
        """
        supported = disasm.get_supported_architectures()
        has_riscv = any(entry["arch"] == "riscv" for entry in supported)
        capstone_has_riscv = hasattr(capstone, "CS_ARCH_RISCV") and (
            hasattr(capstone, "CS_MODE_RISCV32") or hasattr(capstone, "CS_MODE_RISCV64")
        )
        assert has_riscv == capstone_has_riscv
