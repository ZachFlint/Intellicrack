# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Multi-architecture disassembler module for the hex editor.

Wraps the capstone disassembly engine to provide instruction-level analysis across all architectures supported by capstone, with automatic
binary-header detection for PE, ELF, and Mach-O targets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from intellicrack.bridges._pe_format import detect_format_and_arch
from intellicrack.bridges.base import DisassemblyLine
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

_logger = get_logger(__name__)

_capstone_mod: ModuleType | None = None
try:
    import capstone as _capstone_import

    _capstone_mod = _capstone_import
except ImportError:
    _logger.warning("capstone_unavailable", reason="import failed")

_ERR_NO_CAPSTONE = "capstone is not available"
_ERR_RISCV_UNAVAIL = "riscv support not available in this capstone build"
_ERR_UNSUPPORTED_ARCH = "unsupported architecture"


_CAPSTONE_ARCH_MODE_MAP: dict[str, tuple[str, str]] = {
    "x86_64": ("x86", "64"),
    "x86": ("x86", "32"),
    "arm64": ("arm64", "arm"),
    "arm": ("arm", "arm"),
    "mips": ("mips", "32"),
    "mips64": ("mips", "64"),
    "ppc": ("ppc", "32"),
    "ppc64": ("ppc", "64"),
    "riscv": ("riscv", "32"),
    "riscv64": ("riscv", "64"),
    "riscv128": ("riscv", "64"),
}
"""Map a canonical :func:`detect_format_and_arch` arch string to capstone ``(arch, mode)``.

Capstone's mode field is overloaded: ``"32"`` / ``"64"`` for x86 and MIPS, the literal string ``"arm"`` for ARM/AArch64. RISC-V 128-bit is
squashed to ``"64"`` because capstone has no separate 128-bit mode.
"""


class UnsupportedArchitectureError(ValueError):
    """Raised when an architecture string cannot be mapped to capstone constants.

    Subclass of :class:`ValueError` so callers that catch ``ValueError`` for capstone resolution failures still see this case, while
    specific handlers can match the narrower type. The offending architecture string is exposed via the :attr:`arch` instance attribute set
    in :meth:`__init__`.
    """

    arch: str

    def __init__(self, arch: str) -> None:
        """Initialize the error with the offending architecture string.

        Args:
            arch: Unrecognised architecture identifier.
        """
        self.arch = arch
        super().__init__(f"unsupported architecture: {arch!r}")


__all__ = [
    "DisasmInstruction",
    "HexDisassembler",
    "UnsupportedArchitectureError",
]


@dataclass(frozen=True, slots=True)
class DisasmInstruction:
    """A single decoded machine instruction.

    Attributes:
        address: Virtual address of the instruction.
        raw_bytes: Raw machine-code bytes for this instruction.
        mnemonic: Assembly mnemonic string (e.g. ``mov``, ``jmp``).
        op_str: Operand string as produced by capstone.
        size: Byte length of the encoded instruction.
    """

    address: int
    raw_bytes: bytes
    mnemonic: str
    op_str: str
    size: int


def _to_disassembly_line(insn: DisasmInstruction) -> DisassemblyLine:
    """Convert a :class:`DisasmInstruction` to a :class:`DisassemblyLine`.

    Args:
        insn: Source instruction produced by :class:`HexDisassembler`.

    Returns:
        DisassemblyLine: Equivalent line suitable for bridge consumers.
    """
    hex_bytes = " ".join(f"{b:02x}" for b in insn.raw_bytes)
    return DisassemblyLine(
        address=insn.address,
        bytes_str=hex_bytes,
        mnemonic=insn.mnemonic,
        operands=insn.op_str,
        comment=None,
    )


class HexDisassembler:
    """Multi-architecture disassembler using capstone.

    Wraps the capstone engine with a unified interface for all supported architectures.  The class handles optional availability of capstone
    gracefully so callers can query :attr:`available` before use.
    """

    def __init__(self) -> None:
        """Initialize the Disassembler instance."""
        self._cs_mod: ModuleType | None = _capstone_mod
        if self._cs_mod is not None:
            version: str = str(getattr(self._cs_mod, "__version__", "unknown"))
            _logger.debug("capstone_loaded", version=version)

    @property
    def available(self) -> bool:
        """Whether capstone was successfully imported.

        Returns:
            bool: ``True`` when capstone is available for disassembly.
        """
        return self._cs_mod is not None

    # ------------------------------------------------------------------
    # Architecture / mode resolution
    # ------------------------------------------------------------------

    def _resolve_arch_mode(self, arch: str, mode: str) -> tuple[int, int]:
        """Map architecture and mode strings to capstone integer constants.

        Args:
            arch: Architecture name (case-insensitive).
            mode: Mode string (e.g. ``"64"``, ``"thumb"``).

        Returns:
            tuple[int, int]: ``(cs_arch, cs_mode)`` constants.

        Raises:
            ValueError: If capstone is not available, or the
                architecture/mode combination is not supported.
        """
        if self._cs_mod is None:
            _logger.error("disassembler_capstone_unavailable", arch=arch, mode=mode)
            raise ValueError(_ERR_NO_CAPSTONE)

        cs: Any = self._cs_mod
        arch_lower = arch.lower()
        mode_lower = mode.lower()
        _logger.debug("arch_mode_resolve", arch=arch_lower, mode=mode_lower)

        if arch_lower == "arm":
            return (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB) if mode_lower == "thumb" else (cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        if arch_lower == "x86":
            if mode_lower == "16":
                return cs.CS_ARCH_X86, cs.CS_MODE_16
            return (cs.CS_ARCH_X86, cs.CS_MODE_32) if mode_lower == "32" else (cs.CS_ARCH_X86, cs.CS_MODE_64)
        if arch_lower in {"arm64", "aarch64"}:
            return cs.CS_ARCH_ARM64, cs.CS_MODE_ARM

        if arch_lower == "mips":
            if mode_lower == "64":
                return cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64
            return cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32

        if arch_lower == "ppc":
            if mode_lower == "64":
                return cs.CS_ARCH_PPC, cs.CS_MODE_64
            return cs.CS_ARCH_PPC, cs.CS_MODE_32

        if arch_lower == "sparc":
            return cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN

        if arch_lower in {"systemz", "s390x"}:
            return cs.CS_ARCH_SYSZ, cs.CS_MODE_BIG_ENDIAN

        if arch_lower == "riscv":
            if hasattr(cs, "CS_ARCH_RISCV"):
                if mode_lower == "64" and hasattr(cs, "CS_MODE_RISCV64"):
                    return cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64
                if hasattr(cs, "CS_MODE_RISCV32"):
                    return cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV32
            raise ValueError(_ERR_RISCV_UNAVAIL)

        raise ValueError(_ERR_UNSUPPORTED_ARCH)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def disassemble(
        self,
        data: bytes,
        base_addr: int = 0,
        arch: str = "x86",
        mode: str = "64",
        count: int = 100,
    ) -> list[DisasmInstruction]:
        """Disassemble bytes into a list of instructions.

        Args:
            data: Raw bytes to disassemble.
            base_addr: Virtual base address for the first byte.
            arch: Target architecture (``"x86"``, ``"arm"``, ``"arm64"``,
                ``"mips"``, ``"ppc"``, ``"sparc"``, ``"systemz"``,
                ``"riscv"``).
            mode: Architecture mode (``"16"``, ``"32"``, ``"64"``,
                ``"arm"``, ``"thumb"``).
            count: Maximum number of instructions to return.

        Returns:
            list[DisasmInstruction]: Decoded instructions in address order.

        Raises:
            ValueError: If capstone is not available or the
                architecture/mode combination is unsupported.
        """
        if self._cs_mod is None:
            _logger.error("disassembler_capstone_unavailable_for_disassemble", arch=arch, mode=mode)
            raise ValueError(_ERR_NO_CAPSTONE)

        cs_arch, cs_mode = self._resolve_arch_mode(arch, mode)
        cs: Any = self._cs_mod

        _logger.debug(
            "disassembly_start",
            base_addr=hex(base_addr),
            arch=arch,
            mode=mode,
            count=count,
            data_len=len(data),
        )

        md = cs.Cs(cs_arch, cs_mode)
        md.detail = False

        instructions: list[DisasmInstruction] = []
        for insn in md.disasm(data, base_addr):
            instructions.append(
                DisasmInstruction(
                    address=insn.address,
                    raw_bytes=bytes(insn.bytes),
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    size=insn.size,
                ),
            )
            if len(instructions) >= count:
                break

        _logger.debug("disassembly_complete", instruction_count=len(instructions))
        return instructions

    def disassemble_to_lines(
        self,
        data: bytes,
        base_addr: int = 0,
        arch: str = "x86",
        mode: str = "64",
        count: int = 100,
        binary_path: Path | None = None,
    ) -> list[DisassemblyLine]:
        """Disassemble bytes and return bridge-compatible DisassemblyLine objects.

        Args:
            data: Raw bytes to disassemble.
            base_addr: Virtual base address for the first byte.
            arch: Target architecture string (see :meth:`disassemble`).
            mode: Architecture mode string (see :meth:`disassemble`).
            count: Maximum number of instructions to return.
            binary_path: Optional on-disk path that backs ``data``. When
                supplied the path is included in the structured log entry;
                when ``None`` (raw buffer input) the field is omitted from
                the log call entirely.

        Returns:
            list[DisassemblyLine]: Decoded instructions as bridge lines.
        """
        log_fields: dict[str, Any] = {
            "data_size": len(data),
            "offset": base_addr,
            "arch": arch,
            "mode": mode,
            "count": count,
        }
        if binary_path is not None:
            log_fields["binary_path"] = str(binary_path)
        _logger.debug("disassemble_to_lines_invoked", **log_fields)
        raw = self.disassemble(data, base_addr, arch, mode, count)
        return [_to_disassembly_line(insn) for insn in raw]

    @staticmethod
    def auto_detect_arch(data: bytes) -> tuple[str, str]:
        """Detect architecture from PE, ELF, or Mach-O binary headers.

        Delegates magic-byte and machine-field decoding to
        :func:`intellicrack.bridges._pe_format.detect_format_and_arch`,
        then maps the canonical ``(arch, is_64bit)`` result into the
        capstone ``(arch, mode)`` shape that :meth:`disassemble`
        expects.

        Args:
            data: Raw binary data, including at least the file header.

        Returns:
            tuple[str, str]: ``(arch, mode)`` suitable for
            :meth:`disassemble`.

        Raises:
            UnsupportedArchitectureError: If the format is unrecognised
                or the architecture string returned by
                :func:`detect_format_and_arch` does not have a capstone
                mapping. Callers must handle this rather than receive a
                silent x86-64 fallback.
        """
        fmt, arch, is_64bit = detect_format_and_arch(data)
        _logger.debug(
            "auto_detect_arch_result",
            fmt=fmt,
            arch=arch,
            is_64bit=is_64bit,
        )
        result = _CAPSTONE_ARCH_MODE_MAP.get(arch)
        if result is None:
            _logger.warning(
                "arch_detection_unsupported",
                fmt=fmt,
                arch=arch,
                is_64bit=is_64bit,
            )
            raise UnsupportedArchitectureError(arch)
        return result

    def get_supported_architectures(self) -> list[dict[str, str]]:
        """Return metadata for every architecture supported at runtime.

        The list reflects which capstone architecture constants are actually
        present in the installed capstone build, so RISCV or other optional
        architectures are only included when available.

        Returns:
            list[dict[str, str]]: Each entry has ``"arch"``, ``"mode"``,
            and ``"description"`` keys.

        Raises:
            ValueError: If capstone is not available.
        """
        if self._cs_mod is None:
            _logger.error("disassembler_capstone_unavailable_for_arch_list")
            raise ValueError(_ERR_NO_CAPSTONE)

        cs: Any = self._cs_mod

        candidates: list[dict[str, str]] = [
            {"arch": "x86", "mode": "16", "description": "x86 16-bit real mode"},
            {"arch": "x86", "mode": "32", "description": "x86 32-bit protected mode"},
            {"arch": "x86", "mode": "64", "description": "x86-64 long mode"},
            {"arch": "arm", "mode": "arm", "description": "ARM 32-bit (ARM state)"},
            {"arch": "arm", "mode": "thumb", "description": "ARM 32-bit (Thumb state)"},
            {"arch": "arm64", "mode": "arm", "description": "AArch64 / ARM64"},
            {"arch": "mips", "mode": "32", "description": "MIPS 32-bit"},
            {"arch": "mips", "mode": "64", "description": "MIPS 64-bit"},
            {"arch": "ppc", "mode": "32", "description": "PowerPC 32-bit"},
            {"arch": "ppc", "mode": "64", "description": "PowerPC 64-bit"},
            {"arch": "sparc", "mode": "big", "description": "SPARC big-endian"},
            {"arch": "systemz", "mode": "big", "description": "IBM System/z (s390x)"},
        ]

        if hasattr(cs, "CS_ARCH_RISCV"):
            if hasattr(cs, "CS_MODE_RISCV32"):
                candidates.append({"arch": "riscv", "mode": "32", "description": "RISC-V 32-bit"})
            if hasattr(cs, "CS_MODE_RISCV64"):
                candidates.append({"arch": "riscv", "mode": "64", "description": "RISC-V 64-bit"})

        supported: list[dict[str, str]] = []
        for entry in candidates:
            try:
                cs_arch, cs_mode = self._resolve_arch_mode(entry["arch"], entry["mode"])
                _ = cs.Cs(cs_arch, cs_mode)
                supported.append(entry)
            except (ValueError, OSError, AttributeError):
                _logger.debug(
                    "arch_not_supported",
                    arch=entry["arch"],
                    mode=entry["mode"],
                    exc_info=True,
                )

        return supported


_singleton: dict[str, HexDisassembler] = {}


def get_disassembler() -> HexDisassembler:
    """Return the module-level singleton :class:`HexDisassembler` instance.

    Returns:
        HexDisassembler: Shared disassembler instance, created on first call.
    """
    if "instance" not in _singleton:
        _singleton["instance"] = HexDisassembler()
    return _singleton["instance"]
