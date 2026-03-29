# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Binary operations bridge for direct file manipulation.

This module provides binary file analysis and patching capabilities using pefile, lief, and capstone without requiring external tools.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, override

import capstone
import lief
import lief.COFF
import lief.ELF
import lief.MachO
import lief.OAT
import lief.PE
import pefile

from ..core.logging import get_logger, log_binary_operation
from ..core.types import (
    BinaryInfo,
    ExportInfo,
    ImportInfo,
    PatchInfo,
    SectionInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from .base import BinaryOperationsBridge, BridgeCapabilities, BridgeState


if TYPE_CHECKING:
    _LiefParsedType = lief.PE.Binary | lief.OAT.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None

    def _lief_parse_raw(data: bytes) -> _LiefParsedType:
        """
        Typed wrapper for lief.parse (type-checking only).

        Args:
            data: Raw binary data to parse.

        Returns:
            _LiefParsedType: Parsed binary object, or None on failure.
        """
        _ = data
        return None

else:
    _lief_parse_raw = lief.parse

_logger = get_logger("bridges.binary")

_ERR_NO_BINARY = "no binary loaded"
_ERR_FILE_NOT_FOUND = "file not found"
_ERR_LOAD_FAILED = "failed to load binary"
_ERR_INVALID_OFFSET = "invalid offset"
_ERR_WRITE_EXTENDS = "write extends beyond file size"
_ERR_NO_SAVE_PATH = "no save path specified"
_ERR_UNSUPPORTED_ARCH = "unsupported architecture"
_ERR_UNKNOWN_ALGO = "unknown algorithm"
_ERR_RVA_NOT_AVAIL = "RVA conversion not available for raw binaries"
_ERR_OFFSET_NOT_AVAIL = "offset conversion not available for raw binaries"

_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C
_MACHINE_ARM64 = 0xAA64
_MACHINE_ARM = 0x1C0
_MIN_STRING_LEN = 4
_MIN_HEADER_LEN = 4


class BinaryBridge(BinaryOperationsBridge):
    """
    Bridge for direct binary file operations.

    Provides analysis and patching of PE, ELF, and Mach-O binaries using pefile, lief, and capstone libraries.
    """

    def __init__(self) -> None:
        super().__init__()
        self._binary_path: Path | None = None
        self._pe: pefile.PE | None = None
        self._lief_binary: lief.Binary | None = None
        self._data: bytearray | None = None
        self._modified: bool = False
        self._patches: list[PatchInfo] = []
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    @property
    def name(self) -> ToolName:
        """
        Get the tool's name.

        Returns:
            ToolName: ToolName.BINARY
        """
        return ToolName.BINARY

    @property
    def tool_definition(self) -> ToolDefinition:
        """
        Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.BINARY,
            description="Direct binary file operations - reading, patching, and analysis",
            functions=[
                ToolFunction(
                    name="binary.load_file",
                    description="Load a binary file for analysis and patching",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file",
                            required=True,
                        ),
                    ],
                    returns="BinaryInfo object with file details",
                ),
                ToolFunction(
                    name="binary.read_bytes",
                    description="Read bytes from the binary at a specific offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to read from",
                            required=True,
                        ),
                        ToolParameter(
                            name="size",
                            type="integer",
                            description="Number of bytes to read",
                            required=True,
                        ),
                    ],
                    returns="Hex string of read bytes",
                ),
                ToolFunction(
                    name="binary.write_bytes",
                    description="Write bytes to the binary at a specific offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to write at",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex string of bytes to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="binary.search_pattern",
                    description="Search for a byte pattern in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern with ?? wildcards (e.g., '48 8B ?? ??')",
                            required=True,
                        ),
                        ToolParameter(
                            name="max_results",
                            type="integer",
                            description="Maximum number of results to return",
                            required=False,
                            default=100,
                        ),
                    ],
                    returns="List of offsets where pattern found",
                ),
                ToolFunction(
                    name="binary.disassemble_at",
                    description="Disassemble instructions at a file offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to disassemble",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=10,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="binary.get_sections",
                    description="Get all sections in the binary",
                    parameters=[],
                    returns="List of SectionInfo objects",
                ),
                ToolFunction(
                    name="binary.get_imports",
                    description="Get all imported functions",
                    parameters=[],
                    returns="List of ImportInfo objects",
                ),
                ToolFunction(
                    name="binary.get_exports",
                    description="Get all exported functions",
                    parameters=[],
                    returns="List of ExportInfo objects",
                ),
                ToolFunction(
                    name="binary.get_strings",
                    description="Get strings from the binary",
                    parameters=[
                        ToolParameter(
                            name="min_length",
                            type="integer",
                            description="Minimum string length",
                            required=False,
                            default=4,
                        ),
                    ],
                    returns="List of strings with their offsets",
                ),
                ToolFunction(
                    name="binary.calculate_checksum",
                    description="Calculate hash of the binary",
                    parameters=[
                        ToolParameter(
                            name="algorithm",
                            type="string",
                            description="Hash algorithm (md5, sha256)",
                            required=False,
                            default="sha256",
                            enum=["md5", "sha256"],
                        ),
                    ],
                    returns="Hex digest of hash",
                ),
                ToolFunction(
                    name="binary.rva_to_offset",
                    description="Convert relative virtual address to file offset",
                    parameters=[
                        ToolParameter(
                            name="rva",
                            type="integer",
                            description="Relative virtual address",
                            required=True,
                        ),
                    ],
                    returns="File offset",
                ),
                ToolFunction(
                    name="binary.offset_to_rva",
                    description="Convert file offset to relative virtual address",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset",
                            required=True,
                        ),
                    ],
                    returns="Relative virtual address",
                ),
                ToolFunction(
                    name="binary.apply_patch",
                    description="Apply a patch to the binary",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to patch",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex string of new bytes",
                            required=True,
                        ),
                        ToolParameter(
                            name="description",
                            type="string",
                            description="Description of the patch",
                            required=False,
                            default="",
                        ),
                    ],
                    returns="PatchInfo object",
                ),
                ToolFunction(
                    name="binary.revert_patch",
                    description="Revert a previously applied patch",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="Offset of patch to revert",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="binary.save",
                    description="Save the binary to file",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to save to (optional, uses original if not specified)",
                            required=False,
                        ),
                    ],
                    returns="Path where file was saved",
                ),
                ToolFunction(
                    name="binary.search_pattern_wildcard",
                    description="Search for hex pattern with wildcards in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern like '48 8B ?? ?? 00'",
                            required=True,
                        ),
                        ToolParameter(
                            name="start_offset",
                            type="integer",
                            description="Starting offset for search",
                            required=False,
                            default=0,
                        ),
                        ToolParameter(
                            name="max_results",
                            type="integer",
                            description="Maximum results to return",
                            required=False,
                            default=100,
                        ),
                    ],
                    returns="List of offsets where pattern found",
                ),
                ToolFunction(
                    name="binary.disassemble_at_offset",
                    description="Disassemble instructions at a file offset",
                    parameters=[
                        ToolParameter(
                            name="offset",
                            type="integer",
                            description="File offset to disassemble",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=10,
                        ),
                    ],
                    returns="Disassembly text",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """
        Initialize the binary operations bridge.

        Args:
            tool_path: Not used for this bridge.
        """
        del tool_path
        self._state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )
        _logger.info("bridge_initialized", bridge="binary")

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources."""
        self._pe = None
        self._lief_binary = None
        self._data = None
        self._binary_path = None
        self._modified = False
        self._patches = []
        await super().shutdown()
        _logger.info("bridge_shutdown", bridge="binary")

    @override
    async def is_available(self) -> bool:
        """
        Check if binary operations are available.

        Returns:
            bool: Always True since this uses built-in libraries.
        """
        return True

    async def load_file(self, path: Path) -> BinaryInfo:
        """
        Load a binary file for analysis.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo: BinaryInfo with file details.

        Raises:
            ToolError: If file cannot be loaded.
        """
        if not path.exists():
            raise ToolError(_ERR_FILE_NOT_FOUND)

        log_binary_operation("load", path, size=path.stat().st_size)
        try:
            self._binary_path = path.resolve()
            self._data = bytearray(path.read_bytes())
            self._modified = False
            self._patches = []

            file_type = self._detect_format()

            if file_type == "pe":
                self._pe = await asyncio.to_thread(
                    pefile.PE,
                    data=bytes(self._data),
                )
                self._lief_binary = await asyncio.to_thread(
                    self._parse_lief,
                    bytes(self._data),
                )
            elif file_type in {"elf", "macho"}:
                self._lief_binary = await asyncio.to_thread(
                    self._parse_lief,
                    bytes(self._data),
                )
            else:
                self._lief_binary = None
                self._pe = None

            md5_hash = hashlib.md5(self._data, usedforsecurity=False).hexdigest()
            sha256_hash = hashlib.sha256(self._data).hexdigest()

            arch, is_64 = self._detect_architecture()
            entry_point = self._get_entry_point()
            sections = await self._get_sections_internal()
            imports = await self._get_imports_internal()
            exports = await self._get_exports_internal()

            self._state.connected = True
            self._state.tool_running = True
            self._state.binary_loaded = True
            self._state.target_path = self._binary_path

            _logger.info("binary_loaded", path=str(path.name), file_type=file_type, arch=arch)

            return BinaryInfo(
                path=self._binary_path,
                name=path.name,
                size=len(self._data),
                md5=md5_hash,
                sha256=sha256_hash,
                file_type=file_type,
                architecture=arch,
                is_64bit=is_64,
                entry_point=entry_point,
                sections=sections,
                imports=imports,
                exports=exports,
            )

        except Exception as e:
            _logger.warning("binary_load_failed", path=str(self._binary_path), error=str(e))
            raise ToolError(_ERR_LOAD_FAILED) from e

    def _detect_format(self) -> str:
        """
        Detect the binary format.

        Returns:
            str: The binary format ('pe', 'elf', 'macho', or 'raw').
        """
        if self._data is None or len(self._data) < _MIN_HEADER_LEN:
            return "raw"

        header_2 = bytes(self._data[:2])
        header_4 = bytes(self._data[:4])

        if header_2 == b"MZ":
            return "pe"

        if header_4 == b"\x7fELF":
            return "elf"

        if header_4 in {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        }:
            return "macho"

        return "raw"

    @staticmethod
    def _parse_lief(data: bytes) -> lief.Binary | None:
        """
        Parse binary data with lief.

        Args:
            data: Raw binary data.

        Returns:
            lief.Binary | None: Parsed lief Binary object or None if parsing fails.
        """
        parsed: _LiefParsedType = _lief_parse_raw(data)
        if parsed is None:
            return None
        return None if isinstance(parsed, lief.COFF.Binary) else parsed

    def _detect_architecture(self) -> tuple[str, bool]:
        """
        Detect the CPU architecture.

        Returns:
            tuple[str, bool]: Tuple of (architecture name, is_64bit).
        """
        if self._pe is not None:
            machine: int = self._pe.FILE_HEADER.Machine
            if machine == _MACHINE_AMD64:
                return "x86_64", True
            if machine == _MACHINE_I386:
                return "x86", False
            if machine == _MACHINE_ARM64:
                return "arm64", True
            if machine == _MACHINE_ARM:
                return "arm", False

        if self._lief_binary is not None:
            lief_header: lief.Header = self._lief_binary.header
            arch_val: lief.Header.ARCHITECTURES = lief_header.architecture
            if arch_val == lief.Header.ARCHITECTURES.X86_64:
                return "x86_64", True
            if arch_val == lief.Header.ARCHITECTURES.X86:
                return "x86", False
            if arch_val == lief.Header.ARCHITECTURES.ARM64:
                return "arm64", True
            if arch_val == lief.Header.ARCHITECTURES.ARM:
                return "arm", False

        return "unknown", False

    def _get_entry_point(self) -> int:
        """
        Get the entry point address.

        Returns:
            int: Entry point address or 0 if not found.
        """
        if self._pe is not None:
            return int(self._pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        return self._lief_binary.entrypoint if self._lief_binary is not None else 0

    async def _get_sections_internal(self) -> list[SectionInfo]:
        """
        Get section information.

        Returns:
            list[SectionInfo]: List of section info.
        """
        sections: list[SectionInfo] = []

        if self._pe is not None:
            for section in self._pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                entropy: float = await asyncio.to_thread(section.get_entropy)
                sections.append(
                    SectionInfo(
                        name=name,
                        virtual_address=int(section.VirtualAddress),
                        virtual_size=int(section.Misc_VirtualSize),
                        raw_size=int(section.SizeOfRawData),
                        characteristics=int(section.Characteristics),
                        entropy=entropy,
                    )
                )

        elif self._lief_binary is not None:
            for section in self._lief_binary.sections:
                content_view: memoryview = section.content
                section_data: bytes = bytes(content_view) if len(content_view) > 0 else b""
                entropy = self._calculate_entropy(section_data)
                section_name_raw: str | bytes = section.name
                section_name: str = (
                    section_name_raw.decode("utf-8", errors="replace") if isinstance(section_name_raw, bytes) else section_name_raw
                )
                sections.append(
                    SectionInfo(
                        name=section_name,
                        virtual_address=section.virtual_address,
                        virtual_size=section.size,
                        raw_size=len(section_data),
                        characteristics=0,
                        entropy=entropy,
                    )
                )

        return sections

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze.

        Returns:
            float: Entropy value between 0 and 8.
        """
        if not data:
            return 0.0

        counts = Counter(data)
        total = len(data)
        entropy = 0.0

        for count in counts.values():
            if count > 0:
                freq = count / total
                entropy -= freq * math.log2(freq)

        return entropy

    async def _get_imports_internal(self) -> list[ImportInfo]:
        """
        Get import information.

        Returns:
            list[ImportInfo]: List of import info.
        """
        imports: list[ImportInfo] = []

        if self._pe is not None and hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else ""
                    imports.append(
                        ImportInfo(
                            dll=dll_name,
                            function=name,
                            ordinal=None if imp.name else int(imp.ordinal),
                            address=int(imp.address),
                        )
                    )

        elif self._lief_binary is not None and hasattr(self._lief_binary, "imported_functions"):
            for func in self._lief_binary.imported_functions:
                func_name_raw: str | bytes = func.name
                func_name: str = func_name_raw.decode("utf-8", errors="replace") if isinstance(func_name_raw, bytes) else func_name_raw
                imports.append(
                    ImportInfo(
                        dll="",
                        function=func_name,
                        ordinal=None,
                        address=func.address,
                    )
                )

        return imports

    async def _get_exports_internal(self) -> list[ExportInfo]:
        """
        Get export information.

        Returns:
            list[ExportInfo]: List of export info.
        """
        exports: list[ExportInfo] = []

        if self._pe is not None and hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else ""
                exports.append(
                    ExportInfo(
                        name=name,
                        ordinal=int(exp.ordinal),
                        address=int(exp.address),
                    )
                )

        elif self._lief_binary is not None and hasattr(self._lief_binary, "exported_functions"):
            for idx, func in enumerate(self._lief_binary.exported_functions):
                export_name_raw: str | bytes = func.name
                export_name: str = (
                    export_name_raw.decode("utf-8", errors="replace") if isinstance(export_name_raw, bytes) else export_name_raw
                )
                exports.append(
                    ExportInfo(
                        name=export_name,
                        ordinal=idx,
                        address=func.address,
                    )
                )

        return exports

    async def read_bytes(self, offset: int, size: int) -> bytes:
        """
        Read bytes from the binary.

        Args:
            offset: File offset.
            size: Number of bytes to read.

        Returns:
            bytes: Read bytes.

        Raises:
            ToolError: If read fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        if offset < 0 or offset >= len(self._data):
            raise ToolError(_ERR_INVALID_OFFSET)

        _logger.debug("bytes_read", offset=hex(offset), size=size)
        end = min(offset + size, len(self._data))
        return bytes(self._data[offset:end])

    async def write_bytes(self, offset: int, data: bytes) -> None:
        """
        Write bytes to the binary.

        Args:
            offset: File offset.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        if offset < 0 or offset >= len(self._data):
            raise ToolError(_ERR_INVALID_OFFSET)

        end = offset + len(data)
        if end > len(self._data):
            raise ToolError(_ERR_WRITE_EXTENDS)

        self._data[offset:end] = data
        self._modified = True
        _logger.debug("bytes_written", length=len(data), offset=hex(offset))

    async def apply_patch(self, patch: PatchInfo) -> bool:
        """
        Apply a patch to the binary.

        Args:
            patch: Patch information.

        Returns:
            bool: True if patch applied successfully.

        Raises:
            ToolError: If patching fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        offset = patch.address
        log_binary_operation(
            "patch",
            self._binary_path or Path("unknown"),
            offset=hex(offset),
            size=len(patch.new_bytes),
        )

        original = await self.read_bytes(offset, len(patch.new_bytes))
        if original != patch.original_bytes:
            _logger.warning(
                "patch_bytes_mismatch",
                offset=hex(offset),
                expected=patch.original_bytes.hex(),
                found=original.hex(),
            )

        await self.write_bytes(offset, patch.new_bytes)

        patch_record = PatchInfo(
            address=offset,
            original_bytes=original,
            new_bytes=patch.new_bytes,
            description=patch.description,
            applied=True,
        )
        self._patches.append(patch_record)

        _logger.info(
            "patch_applied",
            offset=hex(offset),
            original=original.hex(),
            new=patch.new_bytes.hex(),
            description=patch.description,
        )

        return True

    async def revert_patch(self, patch: PatchInfo) -> bool:
        """
        Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Returns:
            bool: True if reverted successfully.

        Raises:
            ToolError: If revert fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        for idx, applied in enumerate(self._patches):
            if applied.address == patch.address and applied.applied:
                await self.write_bytes(patch.address, applied.original_bytes)
                self._patches[idx] = PatchInfo(
                    address=applied.address,
                    original_bytes=applied.original_bytes,
                    new_bytes=applied.new_bytes,
                    description=applied.description,
                    applied=False,
                )
                _logger.info("patch_reverted", address=hex(patch.address))
                return True

        _logger.warning("patch_not_found", address=hex(patch.address))
        return False

    async def save(self, path: Path | None = None) -> Path:
        """
        Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Returns:
            Path: Path where file was saved.

        Raises:
            ToolError: If save fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        save_path = path or self._binary_path
        if save_path is None:
            raise ToolError(_ERR_NO_SAVE_PATH)

        save_path.write_bytes(bytes(self._data))
        _logger.info("binary_saved", path=str(save_path))

        if save_path == self._binary_path:
            self._modified = False

        return save_path

    async def search_pattern(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """
        Search for byte pattern in the binary.

        Args:
            pattern: Byte pattern to find.
            start_offset: Starting offset.
            max_results: Maximum results to return.

        Returns:
            list[int]: List of offsets where pattern found.

        Raises:
            ToolError: If search fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        log_binary_operation(
            "search",
            self._binary_path or Path("unknown"),
            pattern_length=len(pattern),
            start_offset=start_offset,
        )

        results: list[int] = []
        data = bytes(self._data)

        offset = start_offset
        while len(results) < max_results:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            results.append(pos)
            offset = pos + 1

        return results

    async def search_pattern_with_wildcards(
        self,
        hex_pattern: str,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """
        Search for hex pattern with wildcards.

        Args:
            hex_pattern: Hex pattern like '48 8B ?? ?? 00'.
            start_offset: Starting offset.
            max_results: Maximum results to return.

        Returns:
            list[int]: List of offsets where pattern found.

        Raises:
            ToolError: If search fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        _logger.debug("wildcard_pattern_search_starting", pattern=hex_pattern, start_offset=start_offset)
        hex_pattern = hex_pattern.replace(" ", "")
        regex_pattern = "".join(
            ("." if hex_pattern[i : i + 2] == "??" else re.escape(chr(int(hex_pattern[i : i + 2], 16))))
            for i in range(0, len(hex_pattern), 2)
        )
        compiled = re.compile(regex_pattern.encode("latin-1"), re.DOTALL)

        results: list[int] = []
        data = bytes(self._data)

        for match in compiled.finditer(data, start_offset):
            results.append(match.start())
            if len(results) >= max_results:
                break

        _logger.debug("wildcard_search_completed", matches=len(results))
        return results

    async def disassemble_at_offset(
        self,
        offset: int,
        count: int = 10,
    ) -> str:
        """
        Disassemble instructions at a file offset.

        Args:
            offset: File offset.
            count: Number of instructions.

        Returns:
            str: Disassembly text.

        Raises:
            ToolError: If disassembly fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        _logger.debug("disassembly_starting", offset=hex(offset), count=count)
        arch, is_64 = self._detect_architecture()

        if arch in {"x86", "x86_64"}:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
        elif arch in {"arm", "arm64"}:
            cs_arch = capstone.CS_ARCH_ARM64 if is_64 else capstone.CS_ARCH_ARM
            cs_mode = capstone.CS_MODE_ARM
        else:
            raise ToolError(_ERR_UNSUPPORTED_ARCH)

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True

        code = bytes(self._data[offset : offset + count * 15])
        base_addr = offset

        lines: list[str] = []

        for instruction_count, insn in enumerate(md.disasm(code, base_addr)):
            if instruction_count >= count:
                break
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
            lines.append(f"0x{insn.address:08X}:  {hex_bytes:<24} {insn.mnemonic} {insn.op_str}")

        return "\n".join(lines)

    async def calculate_checksum(self, algorithm: str = "sha256") -> str:
        """
        Calculate hash of the binary.

        Args:
            algorithm: Hash algorithm (md5, sha256).

        Returns:
            str: Hex digest of hash.

        Raises:
            ToolError: If calculation fails.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        _logger.debug("checksum_calculating", algorithm=algorithm)
        if algorithm == "md5":
            return hashlib.md5(self._data, usedforsecurity=False).hexdigest()
        if algorithm == "sha256":
            return hashlib.sha256(self._data).hexdigest()
        raise ToolError(_ERR_UNKNOWN_ALGO)

    async def rva_to_offset(self, rva: int) -> int:
        """
        Convert RVA to file offset.

        Args:
            rva: Relative virtual address.

        Returns:
            int: File offset.

        Raises:
            ToolError: If conversion fails.
        """
        _logger.debug("rva_to_offset_converting", rva=hex(rva))
        if self._pe is not None:
            return int(self._pe.get_offset_from_rva(rva))

        if self._lief_binary is not None:
            if isinstance(self._lief_binary, lief.PE.Binary):
                return self._lief_binary.rva_to_offset(rva)
            raise ToolError(_ERR_RVA_NOT_AVAIL)

        raise ToolError(_ERR_RVA_NOT_AVAIL)

    async def offset_to_rva(self, offset: int) -> int:
        """
        Convert file offset to RVA.

        Args:
            offset: File offset.

        Returns:
            int: Relative virtual address.

        Raises:
            ToolError: If conversion fails.
        """
        _logger.debug("offset_to_rva_converting", offset=hex(offset))
        if self._pe is not None:
            return int(self._pe.get_rva_from_offset(offset))

        if self._lief_binary is not None:
            lief_ova_result: int | lief.lief_errors = self._lief_binary.offset_to_virtual_address(offset)
            if isinstance(lief_ova_result, int):
                return lief_ova_result
            raise ToolError(_ERR_OFFSET_NOT_AVAIL)

        raise ToolError(_ERR_OFFSET_NOT_AVAIL)

    async def get_strings(self, min_length: int = _MIN_STRING_LEN) -> list[tuple[int, str]]:
        """
        Extract strings from the binary.

        Args:
            min_length: Minimum string length.

        Returns:
            list[tuple[int, str]]: List of (offset, string) tuples.

        Raises:
            ToolError: If no binary is loaded.
        """
        if self._data is None:
            raise ToolError(_ERR_NO_BINARY)

        data = bytes(self._data)

        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
        results = [(match.start(), match.group().decode("ascii")) for match in ascii_pattern.finditer(data)]
        _logger.debug("strings_extracted", count=len(results), min_length=min_length)
        return results
