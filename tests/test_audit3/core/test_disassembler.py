# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U10 tests for ``intellicrack.core.disassembler`` remediation.

Validates the fixes applied to ``src/intellicrack/core/disassembler.py``:

* F-0002 - :meth:`HexDisassembler.auto_detect_arch` now raises
  :class:`UnsupportedArchitectureError` instead of silently returning the
  ``("x86", "64")`` fallback for arch strings that are not in
  :data:`_CAPSTONE_ARCH_MODE_MAP`.
* F-0009 - :meth:`HexDisassembler.disassemble_to_lines` no longer logs the
  literal ``binary_path="<bytes-buffer>"``; the field is omitted from the
  log call when ``binary_path`` is ``None`` and populated with the real
  :class:`pathlib.Path` when supplied.

The tests build real ARM64, ELF, and Mach-O headers as bytes in-process so
the verification does not depend on any external binary on disk.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
import structlog.testing

from intellicrack.core import disassembler as disasm_module
from intellicrack.core.disassembler import (
    _CAPSTONE_ARCH_MODE_MAP,
    HexDisassembler,
    UnsupportedArchitectureError,
)


if TYPE_CHECKING:
    from pathlib import Path


def _build_elf_header(e_machine: int, *, is_64bit: bool) -> bytes:
    """Build a minimal valid ELF header sufficient for arch detection.

    Args:
        e_machine: ELF ``e_machine`` value (e.g. 0xB7 for AArch64).
        is_64bit: True for ELFCLASS64, False for ELFCLASS32.

    Returns:
        bytes: Header bytes long enough for
        :func:`detect_format_and_arch` to read ``e_machine``.
    """
    ei_class = 2 if is_64bit else 1
    header = bytearray(0x40)
    header[0:4] = b"\x7fELF"
    header[4] = ei_class
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 0x12, e_machine)
    return bytes(header)


_ELF_EM_AARCH64: int = 0xB7
_ELF_EM_X86_64: int = 0x3E


@pytest.fixture
def disassembler() -> HexDisassembler:
    """Return a fresh :class:`HexDisassembler` instance for each test.

    Returns:
        HexDisassembler: Newly constructed disassembler.
    """
    return HexDisassembler()


class TestUnsupportedArchitectureError:
    """Verify :class:`UnsupportedArchitectureError` carries the offending arch."""

    def test_inherits_value_error(self) -> None:
        """Subclassing ``ValueError`` keeps existing ``except ValueError`` paths working."""
        exc = UnsupportedArchitectureError("xtensa")
        assert isinstance(exc, ValueError)

    def test_records_arch(self) -> None:
        """The constructor stores the arch on the instance and in the message."""
        exc = UnsupportedArchitectureError("vax")
        assert exc.arch == "vax"
        assert "vax" in str(exc)


class TestAutoDetectArchRaises:
    """F-0002: arch mismatch must raise rather than silently fall back."""

    def test_unknown_format_raises(self, disassembler: HexDisassembler) -> None:
        """Random non-binary bytes resolve to ``arch="unknown"`` and must raise."""
        random_bytes = b"hello world this is plain text not a binary"
        with pytest.raises(UnsupportedArchitectureError) as info:
            disassembler.auto_detect_arch(random_bytes)
        assert info.value.arch == "unknown"

    def test_zip_input_raises(self, disassembler: HexDisassembler) -> None:
        """A ZIP archive header detected as ``zip`` has arch ``"unknown"``."""
        zip_bytes = b"PK\x03\x04" + b"\x00" * 60
        with pytest.raises(UnsupportedArchitectureError):
            disassembler.auto_detect_arch(zip_bytes)

    def test_no_silent_x86_64_fallback(self, disassembler: HexDisassembler) -> None:
        """The deleted ``("x86", "64")`` fallback must no longer trigger."""
        garbage = b"\x00" * 128
        with pytest.raises(UnsupportedArchitectureError):
            disassembler.auto_detect_arch(garbage)

    def test_truncated_pe_dos_only_raises(self, disassembler: HexDisassembler) -> None:
        """A bare ``MZ`` header without PE signature reports ``unknown``."""
        mz_only = b"MZ" + b"\x00" * 0x3E + b"\x00\x00\x00\x00"
        with pytest.raises(UnsupportedArchitectureError):
            disassembler.auto_detect_arch(mz_only)


class TestAutoDetectArchReal:
    """F-0002 positive path: real headers must map to capstone tuples."""

    def test_arm64_elf_detected(self, disassembler: HexDisassembler) -> None:
        """An ELF AArch64 header maps to the capstone ARM64 tuple."""
        header = _build_elf_header(_ELF_EM_AARCH64, is_64bit=True)
        assert disassembler.auto_detect_arch(header) == ("arm64", "arm")

    def test_x86_64_elf_detected(self, disassembler: HexDisassembler) -> None:
        """An ELF x86_64 header maps to the capstone x86 64-bit tuple."""
        header = _build_elf_header(_ELF_EM_X86_64, is_64bit=True)
        assert disassembler.auto_detect_arch(header) == ("x86", "64")

    def test_arch_map_has_no_fallback_constant(self) -> None:
        """The deleted ``_CAPSTONE_DEFAULT_ARCH_MODE`` symbol must be gone."""
        assert not hasattr(disasm_module, "_CAPSTONE_DEFAULT_ARCH_MODE")

    def test_arch_map_includes_ppc(self) -> None:
        """The map must cover ``ppc`` / ``ppc64`` so they don't raise."""
        assert _CAPSTONE_ARCH_MODE_MAP["ppc"] == ("ppc", "32")
        assert _CAPSTONE_ARCH_MODE_MAP["ppc64"] == ("ppc", "64")


class TestArm64RealDisassembly:
    """F-0002 follow-through: detected ARM64 must actually disassemble correctly."""

    def test_arm64_instructions_decode(self, disassembler: HexDisassembler) -> None:
        """A canonical AArch64 instruction sequence decodes to expected mnemonics."""
        if not disassembler.available:
            pytest.skip("capstone is not available in this environment")
        header = _build_elf_header(_ELF_EM_AARCH64, is_64bit=True)
        arch, mode = disassembler.auto_detect_arch(header)
        assert (arch, mode) == ("arm64", "arm")
        code = bytes.fromhex("400080d2c0035fd6")
        instructions = disassembler.disassemble(code, base_addr=0x1000, arch=arch, mode=mode, count=10)
        assert len(instructions) == 2
        assert instructions[0].mnemonic == "mov"
        assert instructions[0].address == 0x1000
        assert instructions[1].mnemonic == "ret"


class TestDisassembleToLinesLogging:
    """F-0009: the bytes-buffer placeholder must be replaced with real Path or omission."""

    def test_buffer_input_omits_binary_path(
        self,
        disassembler: HexDisassembler,
    ) -> None:
        """When ``binary_path`` is ``None`` the log entry has no ``binary_path`` key."""
        if not disassembler.available:
            pytest.skip("capstone is not available in this environment")
        code = b"\x90" * 16
        with structlog.testing.capture_logs() as captured:
            disassembler.disassemble_to_lines(code, base_addr=0, arch="x86", mode="64", count=4)
        invocation = [c for c in captured if c.get("event") == "disassemble_to_lines_invoked"]
        assert invocation, f"expected disassemble_to_lines_invoked event, got: {captured}"
        record = invocation[-1]
        assert "binary_path" not in record, (
            f"binary_path field must be omitted entirely for buffer-only input, got: {record}"
        )
        for value in record.values():
            assert value != "<bytes-buffer>"

    def test_path_input_includes_binary_path(
        self,
        disassembler: HexDisassembler,
        tmp_path: Path,
    ) -> None:
        """A real :class:`Path` is logged verbatim when supplied."""
        if not disassembler.available:
            pytest.skip("capstone is not available in this environment")
        code = b"\x90" * 16
        binary_path = tmp_path / "sample.bin"
        binary_path.write_bytes(code)
        with structlog.testing.capture_logs() as captured:
            disassembler.disassemble_to_lines(
                code,
                base_addr=0,
                arch="x86",
                mode="64",
                count=4,
                binary_path=binary_path,
            )
        invocation = [c for c in captured if c.get("event") == "disassemble_to_lines_invoked"]
        assert invocation, f"expected disassemble_to_lines_invoked event, got: {captured}"
        record = invocation[-1]
        assert record.get("binary_path") == str(binary_path)
