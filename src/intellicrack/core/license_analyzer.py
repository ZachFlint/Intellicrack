# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""License analysis utilities for Intellicrack."""

from __future__ import annotations

import base64
import binascii
import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .logging import get_logger
from .types import (
    AlgorithmType,
    CryptoAPICall,
    KeyFormat,
    LicensingAnalysis,
    MagicConstant,
    StringInfo,
    ValidationFunctionInfo,
)


if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path
    from types import ModuleType

try:
    import pefile as _pefile_imported

    _pefile_module: ModuleType | None = _pefile_imported
except ImportError:
    _pefile_module = None

try:
    import lief as _lief_imported

    _lief_module: ModuleType | None = _lief_imported
except ImportError:
    _lief_module = None

try:
    import capstone as _capstone_imported

    _capstone_module: ModuleType | None = _capstone_imported
except ImportError:
    _capstone_module = None

# Module-level constants for magic values
_MIN_RSA_MODULUS_BITS = 256
_CONFIDENCE_THRESHOLD_LOW = 0.3
_CONFIDENCE_SIGNAL_WEIGHT = 2
_CONFIDENCE_CONSTANT_WEIGHT = 1
_CONFIDENCE_MAX_SIGNALS = 9
_DEFAULT_FUNCTION_SIZE = 0x400
_MAX_CHECKSUM_GROUP_SIZE = 4
_SECTION_EXEC_CHARACTERISTIC = 0x20000000
_PE_OFFSET_LOCATION = 0x3C
_PE_OFFSET_SIZE = 4
_PE_MACHINE_OFFSET = 4
_PE_MACHINE_SIZE = 2
_PE_MACHINE_AMD64 = 0x8664
_PE_MACHINE_I386 = 0x14C
_PE_HEADER_MIN_SIZE = 0x40
_MIN_HEADER_SIZE_PE = 2
_MIN_HEADER_SIZE_ELF = 4
_MIN_DATA_SIZE_ARCH = 64
_ELF_CLASS_OFFSET = 4
_ELF_CLASS_64 = 2
_DER_SEQUENCE_TAG = 0x30
_DER_INTEGER_TAG = 0x02
_DER_LONG_FORM_MASK = 0x80
_DER_LENGTH_BYTES_MASK = 0x7F
_DER_KEY_MIN_SCAN_BYTES = 8
_STRING_COMPLEXITY_MULTIPLIER = 2
_DIGEST_LEN_MD5 = 32
_DIGEST_LEN_SHA1 = 40
_DIGEST_LEN_SHA256 = 64
_DEFAULT_KEY_LENGTH = 16
_ASCII_PRINTABLE_MIN = 0x20
_ASCII_PRINTABLE_MAX = 0x7E


_logger = get_logger("core.license_analyzer")


def _extract_pefile_sections(pe: object, image_base: int) -> list[SectionData]:
    """Extract sections from a pefile PE object.

    Args:
        pe: pefile.PE object.
        image_base: Image base address.

    Returns:
        List of SectionData entries.
    """
    sections: list[SectionData] = []
    for section in getattr(pe, "sections", []):
        name_bytes = getattr(section, "Name", b"")
        name = name_bytes.decode("utf-8", errors="ignore").rstrip("\x00")
        virtual_address = image_base + int(getattr(section, "VirtualAddress", 0))
        virtual_size = int(getattr(section, "Misc_VirtualSize", 0))
        raw_offset = int(getattr(section, "PointerToRawData", 0))
        raw_size = int(getattr(section, "SizeOfRawData", 0))
        section_data = section.get_data()
        executable = bool(getattr(section, "Characteristics", 0) & _SECTION_EXEC_CHARACTERISTIC)
        sections.append(
            SectionData(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                data=section_data,
                executable=executable,
            )
        )
    return sections


def _extract_pefile_imports(pe: object) -> list[ImportEntry]:
    """Extract imports from a pefile PE object.

    Args:
        pe: pefile.PE object.

    Returns:
        List of ImportEntry entries.
    """
    imports: list[ImportEntry] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll_name = ""
        dll_bytes = getattr(entry, "dll", b"")
        if isinstance(dll_bytes, (bytes, bytearray)):
            dll_name = dll_bytes.decode("utf-8", errors="ignore")
        for imp in getattr(entry, "imports", []) or []:
            imp_name = ""
            imp_raw = getattr(imp, "name", None)
            if isinstance(imp_raw, (bytes, bytearray)):
                imp_name = imp_raw.decode("utf-8", errors="ignore")
            elif imp_raw is None:
                ordinal = getattr(imp, "ordinal", None)
                imp_name = f"ord_{ordinal}" if ordinal is not None else ""
            address = int(getattr(imp, "address", 0))
            imports.append(
                ImportEntry(
                    dll=dll_name,
                    name=imp_name,
                    address=address,
                )
            )
    return imports


def _extract_lief_sections(binary: object, image_base: int) -> list[SectionData]:
    """Extract sections from a LIEF binary object.

    Args:
        binary: LIEF binary object.
        image_base: Image base address.

    Returns:
        List of SectionData entries.
    """
    sections: list[SectionData] = []
    for section in getattr(binary, "sections", []) or []:
        name = getattr(section, "name", "")
        virtual_address = int(getattr(section, "virtual_address", 0)) + image_base
        virtual_size = int(getattr(section, "virtual_size", 0))
        raw_offset = int(getattr(section, "offset", 0))
        raw_size = int(getattr(section, "size", 0))
        content = bytes(getattr(section, "content", []) or [])
        executable = False
        if hasattr(section, "has_characteristic") and _lief_module is not None and hasattr(_lief_module, "PE"):
            executable = section.has_characteristic(_lief_module.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
        sections.append(
            SectionData(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                data=content,
                executable=bool(executable),
            )
        )
    return sections


def _extract_lief_imports(binary: object) -> list[ImportEntry]:
    """Extract imports from a LIEF binary object.

    Args:
        binary: LIEF binary object.

    Returns:
        List of ImportEntry entries.
    """
    imports: list[ImportEntry] = []
    for imp in getattr(binary, "imports", []) or []:
        dll_name = getattr(imp, "name", "")
        for entry in getattr(imp, "entries", []) or []:
            name = getattr(entry, "name", "") or ""
            if not name:
                ordinal = getattr(entry, "ordinal", 0)
                name = f"ord_{ordinal}" if ordinal else ""
            address = int(getattr(entry, "iat_address", 0) or getattr(entry, "address", 0))
            imports.append(
                ImportEntry(
                    dll=dll_name,
                    name=name,
                    address=address,
                )
            )
    return imports


@dataclass(frozen=True)
class ImportEntry:
    """Imported function metadata."""

    dll: str
    name: str
    address: int


@dataclass(frozen=True)
class SectionData:
    """Binary section metadata."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    data: bytes
    executable: bool


@dataclass(frozen=True)
class BinaryView:
    """Parsed binary view with sections and imports."""

    path: Path
    data: bytes
    file_type: str
    architecture: str
    is_64bit: bool
    image_base: int
    entry_point: int
    sections: list[SectionData]
    imports: list[ImportEntry]

    def offset_to_va(self, offset: int) -> tuple[int, str]:
        """Convert file offset to virtual address when possible.

        Args:
            offset: File offset to map.

        Returns:
            Tuple of (virtual_address, section_name). If no section matches,
            virtual_address is the file offset and section_name is empty.
        """
        for section in self.sections:
            start = section.raw_offset
            end = section.raw_offset + section.raw_size
            if start <= offset < end:
                return section.virtual_address + (offset - start), section.name
        return offset, ""


@dataclass(frozen=True)
class InstructionRecord:
    """Disassembled instruction record."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes


@dataclass(frozen=True)
class FilteredStrings:
    """Container for filtered string categories."""

    license: list[StringInfo]
    feature: list[StringInfo]
    blacklist: list[StringInfo]
    time: list[StringInfo]
    hardware: list[StringInfo]
    network: list[StringInfo]


@dataclass(frozen=True)
class CryptoAnalysisData:
    """Container for cryptographic analysis data."""

    crypto_api_calls: list[CryptoAPICall]
    magic_constants: list[MagicConstant]
    validation_functions: list[ValidationFunctionInfo]
    algorithm_type: AlgorithmType
    secondary_algorithms: list[AlgorithmType]


@dataclass(frozen=True)
class KeyFormatData:
    """Container for key format analysis data."""

    key_format: KeyFormat
    key_length: int
    group_size: int | None
    group_separator: str | None
    checksum_algorithm: str | None
    checksum_position: Literal["prefix", "suffix", "embedded"] | None


@dataclass(frozen=True)
class RuntimeIndicators:
    """Container for runtime analysis indicators."""

    hardware_id_apis: list[str]
    time_check_present: bool
    feature_flags: dict[str, int]
    blacklist_present: bool
    online_validation: bool


@dataclass
class _FunctionAnalysisContext:
    """Context for analyzing a single function during validation detection."""

    comparisons: list[int]
    branches: int
    string_refs: set[str]
    calls_crypto: bool
    arithmetic_count: int

    @classmethod
    def create_empty(cls) -> _FunctionAnalysisContext:
        """Create an empty analysis context.

        Returns:
            Empty analysis context instance.
        """
        return cls(
            comparisons=[],
            branches=0,
            string_refs=set(),
            calls_crypto=False,
            arithmetic_count=0,
        )


_ARITHMETIC_MNEMONICS: frozenset[str] = frozenset({
    "xor",
    "add",
    "sub",
    "mul",
    "imul",
    "div",
    "idiv",
    "and",
    "or",
    "shl",
    "shr",
    "sal",
    "sar",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "not",
    "neg",
    "inc",
    "dec",
})
_MIN_ARITHMETIC_FOR_CHECKSUM = 5
_MIN_BRANCHES_FOR_VALIDATION = 2


class LicenseAnalyzer:
    """Analyze binaries for licensing and key validation mechanisms."""

    def __init__(
        self,
        min_string_length: int = 4,
        max_string_length: int = 256,
    ) -> None:
        """Initialize the license analyzer.

        Args:
            min_string_length: Minimum length for extracted strings.
            max_string_length: Maximum length for extracted strings.
        """
        self._min_string_length = min_string_length
        self._max_string_length = max_string_length
        self._license_keywords = (
            "license",
            "serial",
            "registration",
            "register",
            "activate",
            "activation",
            "trial",
            "expire",
            "expired",
            "invalid",
            "valid",
            "unlock",
            "key",
            "keygen",
            "product",
        )
        self._feature_keywords = (
            "feature",
            "edition",
            "enterprise",
            "professional",
            "premium",
            "basic",
            "standard",
            "ultimate",
        )
        self._blacklist_keywords = ("blacklist", "revoked", "banned", "blocked")
        self._time_keywords = ("expire", "expiration", "trial", "time", "date")
        self._hardware_keywords = (
            "machineguid",
            "hardware",
            "hwid",
            "volume",
            "serial",
            "mac",
            "uuid",
        )
        self._network_keywords = ("http://", "https://", "license server", "activation server")
        self._crypto_api_keywords = {
            "CryptAcquireContext": AlgorithmType.CUSTOM_HASH,
            "CryptCreateHash": AlgorithmType.CUSTOM_HASH,
            "CryptHashData": AlgorithmType.CUSTOM_HASH,
            "CryptDeriveKey": AlgorithmType.CUSTOM_HASH,
            "CryptDecrypt": AlgorithmType.CUSTOM_HASH,
            "CryptEncrypt": AlgorithmType.CUSTOM_HASH,
            "BCryptOpenAlgorithmProvider": AlgorithmType.CUSTOM_HASH,
            "BCryptCreateHash": AlgorithmType.CUSTOM_HASH,
            "BCryptHashData": AlgorithmType.CUSTOM_HASH,
            "BCryptFinishHash": AlgorithmType.CUSTOM_HASH,
            "BCryptDecrypt": AlgorithmType.CUSTOM_HASH,
            "BCryptEncrypt": AlgorithmType.CUSTOM_HASH,
            "MD5": AlgorithmType.MD5,
            "SHA1": AlgorithmType.SHA1,
            "SHA256": AlgorithmType.SHA256,
            "SHA512": AlgorithmType.SHA256,
            "CRC32": AlgorithmType.CRC32,
            "crc32": AlgorithmType.CRC32,
            "RtlComputeCrc32": AlgorithmType.CRC32,
            "RtlCrc32": AlgorithmType.CRC32,
            "AES": AlgorithmType.AES,
            "DES": AlgorithmType.DES,
            "RSA": AlgorithmType.RSA,
        }
        self._hardware_api_keywords = (
            "GetVolumeInformation",
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "WMI",
            "Win32_Processor",
            "Win32_ComputerSystem",
            "GetSystemFirmwareTable",
        )
        self._time_api_keywords = (
            "GetSystemTime",
            "GetLocalTime",
            "GetSystemTimeAsFileTime",
            "time",
            "clock",
            "QueryPerformanceCounter",
        )
        self._network_api_keywords = (
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "WSAStartup",
            "connect",
            "send",
            "recv",
            "curl",
        )
        self._key_patterns = [
            re.compile(r"\b[A-Z0-9]{4}(-[A-Z0-9]{4}){2,}\b"),
            re.compile(r"\b[A-Z0-9]{5}(-[A-Z0-9]{5}){2,}\b"),
            re.compile(r"\b[A-Z0-9]{16,}\b"),
            re.compile(r"\b[0-9]{10,}\b"),
            re.compile(r"\b[0-9A-Fa-f]{16,}\b"),
            re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b"),
        ]
        self._known_constants = {
            0xEDB88320: "crc32_polynomial",
            0x04C11DB7: "crc32_polynomial",
            0x1EDC6F41: "crc32c_polynomial",
            0x67452301: "md5_init",
            0xEFCDAB89: "md5_init",
            0x98BADCFE: "md5_init",
            0x10325476: "md5_init",
            0xC3D2E1F0: "sha1_init",
            0x6A09E667: "sha256_init",
            0xBB67AE85: "sha256_init",
            0x3C6EF372: "sha256_init",
            0xA54FF53A: "sha256_init",
            0x510E527F: "sha256_init",
            0x9B05688C: "sha256_init",
            0x1F83D9AB: "sha256_init",
            0x5BE0CD19: "sha256_init",
            0x10001: "rsa_public_exponent",
        }

    def analyze(self, path: Path) -> LicensingAnalysis:
        """Analyze a binary for licensing patterns.

        Args:
            path: Path to the binary.

        Returns:
            LicensingAnalysis populated with detected signals.

        Raises:
            FileNotFoundError: If the binary does not exist.
        """
        _logger.info("analyze_started", extra={"binary_path": str(path)})

        if not path.exists():
            raise FileNotFoundError(str(path))

        data = path.read_bytes()
        view = self._build_binary_view(path, data)
        strings = self._extract_strings(view)
        filtered = self._extract_filtered_strings(strings)
        crypto_data = self._analyze_crypto_data(view, strings, filtered.license)
        key_data = self._analyze_key_format(strings, crypto_data.magic_constants, crypto_data.algorithm_type)
        runtime_flags = self._analyze_runtime_indicators(view, filtered)
        confidence_score, analysis_notes = self._build_confidence(
            crypto_data.algorithm_type,
            key_data.key_format,
            crypto_data.validation_functions,
            crypto_data.crypto_api_calls,
            crypto_data.magic_constants,
        )
        analysis_notes.extend(self._build_context_notes(view, filtered.license))

        result = LicensingAnalysis(
            binary_name=view.path.name,
            algorithm_type=crypto_data.algorithm_type,
            secondary_algorithms=crypto_data.secondary_algorithms,
            key_format=key_data.key_format,
            key_length=key_data.key_length,
            group_size=key_data.group_size,
            group_separator=key_data.group_separator,
            validation_functions=crypto_data.validation_functions,
            crypto_api_calls=crypto_data.crypto_api_calls,
            magic_constants=crypto_data.magic_constants,
            checksum_algorithm=key_data.checksum_algorithm,
            checksum_position=key_data.checksum_position,
            hardware_id_apis=runtime_flags.hardware_id_apis,
            time_check_present=runtime_flags.time_check_present,
            feature_flags=runtime_flags.feature_flags,
            blacklist_present=runtime_flags.blacklist_present,
            online_validation=runtime_flags.online_validation,
            confidence_score=confidence_score,
            analysis_notes=analysis_notes,
        )

        _logger.info(
            "analyze_completed",
            extra={
                "binary_path": str(path),
                "algorithm": crypto_data.algorithm_type.value,
                "key_format": key_data.key_format.value,
                "confidence": confidence_score,
                "validation_functions_count": len(crypto_data.validation_functions),
            },
        )

        return result

    def _extract_filtered_strings(self, strings: list[StringInfo]) -> FilteredStrings:
        """Extract and categorize strings by keyword groups.

        Args:
            strings: All extracted strings.

        Returns:
            FilteredStrings with categorized string lists.
        """
        filtered = FilteredStrings(
            license=self._filter_strings(strings, self._license_keywords),
            feature=self._filter_strings(strings, self._feature_keywords),
            blacklist=self._filter_strings(strings, self._blacklist_keywords),
            time=self._filter_strings(strings, self._time_keywords),
            hardware=self._filter_strings(strings, self._hardware_keywords),
            network=self._filter_strings(strings, self._network_keywords),
        )
        _logger.debug(
            "strings_filtered",
            extra={
                "license_count": len(filtered.license),
                "feature_count": len(filtered.feature),
                "blacklist_count": len(filtered.blacklist),
                "time_count": len(filtered.time),
                "hardware_count": len(filtered.hardware),
                "network_count": len(filtered.network),
            },
        )
        return filtered

    def _analyze_crypto_data(
        self,
        view: BinaryView,
        strings: list[StringInfo],
        license_strings: list[StringInfo],
    ) -> CryptoAnalysisData:
        """Analyze cryptographic aspects of the binary.

        Args:
            view: Parsed binary view.
            strings: All extracted strings.
            license_strings: License-related strings.

        Returns:
            CryptoAnalysisData with crypto analysis results.
        """
        _logger.debug("crypto_analysis_started", extra={"sections_count": len(view.sections)})
        crypto_api_calls = self._detect_crypto_apis(view, strings)
        magic_constants = self._extract_magic_constants(view)
        validation_functions = self._identify_validation_functions(view, license_strings, crypto_api_calls)
        algorithm_type, secondary_algorithms = self._detect_algorithms(crypto_api_calls, magic_constants, strings)
        _logger.debug(
            "crypto_analysis_completed",
            extra={
                "crypto_api_count": len(crypto_api_calls),
                "magic_constants_count": len(magic_constants),
                "validation_functions_count": len(validation_functions),
                "algorithm": algorithm_type.value,
                "secondary_count": len(secondary_algorithms),
            },
        )
        return CryptoAnalysisData(
            crypto_api_calls=crypto_api_calls,
            magic_constants=magic_constants,
            validation_functions=validation_functions,
            algorithm_type=algorithm_type,
            secondary_algorithms=secondary_algorithms,
        )

    def _analyze_key_format(
        self,
        strings: list[StringInfo],
        magic_constants: list[MagicConstant],
        algorithm_type: AlgorithmType,
    ) -> KeyFormatData:
        """Analyze key format from strings and algorithm.

        Args:
            strings: All extracted strings.
            magic_constants: Magic constants found.
            algorithm_type: Detected algorithm type.

        Returns:
            KeyFormatData with key format analysis results.
        """
        key_format, key_length, group_size, group_separator = self._detect_key_format(strings, algorithm_type)
        checksum_algorithm, checksum_position = self._detect_checksum_info(strings, magic_constants, algorithm_type, key_format, group_size)
        _logger.debug(
            "key_format_analysis_completed",
            extra={
                "key_format": key_format.value,
                "key_length": key_length,
                "group_size": group_size,
                "checksum_algorithm": checksum_algorithm,
                "checksum_position": checksum_position,
            },
        )
        return KeyFormatData(
            key_format=key_format,
            key_length=key_length,
            group_size=group_size,
            group_separator=group_separator,
            checksum_algorithm=checksum_algorithm,
            checksum_position=checksum_position,
        )

    def _analyze_runtime_indicators(self, view: BinaryView, filtered: FilteredStrings) -> RuntimeIndicators:
        """Analyze runtime protection indicators.

        Args:
            view: Parsed binary view.
            filtered: Filtered string categories.

        Returns:
            RuntimeIndicators with runtime analysis results.
        """
        _logger.debug("runtime_indicator_analysis_started", extra={"imports_count": len(view.imports)})
        hardware_id_apis = self._collect_matching_imports(view, self._hardware_api_keywords)
        if filtered.hardware:
            hardware_id_apis.extend(s.value for s in filtered.hardware if s.value not in hardware_id_apis)
        time_check_present = bool(self._collect_matching_imports(view, self._time_api_keywords) or filtered.time)
        online_validation = bool(self._collect_matching_imports(view, self._network_api_keywords) or filtered.network)
        _logger.debug(
            "runtime_indicator_analysis_completed",
            extra={
                "hardware_apis_count": len(hardware_id_apis),
                "time_check": time_check_present,
                "online_validation": online_validation,
            },
        )
        return RuntimeIndicators(
            hardware_id_apis=hardware_id_apis,
            time_check_present=time_check_present,
            feature_flags=self._build_feature_flags(filtered.feature),
            blacklist_present=bool(filtered.blacklist),
            online_validation=online_validation,
        )

    def _build_binary_view(self, path: Path, data: bytes) -> BinaryView:
        """Construct a parsed binary view.

        Args:
            path: Binary path.
            data: Binary data.

        Returns:
            BinaryView with sections and imports when available.
        """
        file_type = self._detect_format(data)
        architecture, is_64bit = self._detect_architecture(data)
        _logger.debug(
            "binary_format_detected",
            extra={
                "path": str(path),
                "file_type": file_type,
                "architecture": architecture,
                "is_64bit": is_64bit,
                "data_size": len(data),
            },
        )

        if file_type == "pe":
            pe_view = self._parse_pe(path, data, architecture, is_64bit)
            if pe_view is not None:
                return pe_view

        return BinaryView(
            path=path,
            data=data,
            file_type=file_type,
            architecture=architecture,
            is_64bit=is_64bit,
            image_base=0,
            entry_point=0,
            sections=[],
            imports=[],
        )

    def _parse_pe(
        self,
        path: Path,
        data: bytes,
        architecture: str,
        is_64bit: bool,
    ) -> BinaryView | None:
        """Parse a PE binary using available libraries.

        Args:
            path: Binary path.
            data: Binary data.
            architecture: Detected architecture.
            is_64bit: Whether the binary is 64-bit.

        Returns:
            BinaryView if parsing succeeds, otherwise None.
        """
        _logger.debug("pe_parse_attempt", extra={"path": str(path), "parser": "pefile"})
        pe_view = self._parse_pe_with_pefile(path, data, architecture, is_64bit)
        if pe_view is not None:
            return pe_view

        _logger.debug("pe_parse_attempt", extra={"path": str(path), "parser": "lief"})
        return self._parse_pe_with_lief(path, data, architecture, is_64bit)

    @staticmethod
    def _parse_pe_with_pefile(
        path: Path,
        data: bytes,
        architecture: str,
        is_64bit: bool,
    ) -> BinaryView | None:
        """Parse a PE binary with pefile if available.

        Args:
            path: Binary path.
            data: Binary data.
            architecture: Detected architecture.
            is_64bit: Whether the binary is 64-bit.

        Returns:
            BinaryView or None if pefile is unavailable or parsing fails.
        """
        if _pefile_module is None:
            _logger.debug("pefile_unavailable", extra={"path": str(path)})
            return None

        try:
            pe = _pefile_module.PE(data=data, fast_load=True)
            pe.parse_data_directories()

            image_base = int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0))
            entry_rva = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
            entry_point = image_base + entry_rva if entry_rva else 0

            sections = _extract_pefile_sections(pe, image_base)
            imports = _extract_pefile_imports(pe)

            _logger.debug(
                "pefile_parse_succeeded",
                extra={
                    "path": str(path),
                    "image_base": hex(image_base),
                    "entry_point": hex(entry_point),
                    "sections_count": len(sections),
                    "imports_count": len(imports),
                },
            )

            return BinaryView(
                path=path,
                data=data,
                file_type="pe",
                architecture=architecture,
                is_64bit=is_64bit,
                image_base=image_base,
                entry_point=entry_point,
                sections=sections,
                imports=imports,
            )
        except Exception as exc:
            _logger.warning("pefile_parse_failed", extra={"path": str(path), "error": str(exc)})
            return None

    @staticmethod
    def _parse_pe_with_lief(
        path: Path,
        data: bytes,
        architecture: str,
        is_64bit: bool,
    ) -> BinaryView | None:
        """Parse a PE binary with LIEF if available.

        Args:
            path: Binary path.
            data: Binary data.
            architecture: Detected architecture.
            is_64bit: Whether the binary is 64-bit.

        Returns:
            BinaryView or None if LIEF is unavailable or parsing fails.
        """
        if _lief_module is None:
            _logger.debug("lief_unavailable", extra={"path": str(path)})
            return None

        try:
            binary = _lief_module.parse(str(path))
            if binary is None or binary.format != _lief_module.EXE_FORMATS.PE:
                _logger.debug("lief_not_pe_format", extra={"path": str(path)})
                return None

            image_base = int(getattr(binary.optional_header, "imagebase", 0))
            entry_point = int(getattr(binary.optional_header, "addressof_entrypoint", 0))
            if entry_point:
                entry_point += image_base

            sections = _extract_lief_sections(binary, image_base)
            imports = _extract_lief_imports(binary)

            _logger.debug(
                "lief_parse_succeeded",
                extra={
                    "path": str(path),
                    "image_base": hex(image_base),
                    "entry_point": hex(entry_point),
                    "sections_count": len(sections),
                    "imports_count": len(imports),
                },
            )

            return BinaryView(
                path=path,
                data=data,
                file_type="pe",
                architecture=architecture,
                is_64bit=is_64bit,
                image_base=image_base,
                entry_point=entry_point,
                sections=sections,
                imports=imports,
            )
        except Exception as exc:
            _logger.warning("lief_parse_failed", extra={"path": str(path), "error": str(exc)})
            return None

    @staticmethod
    def _detect_format(data: bytes) -> str:
        """Detect binary format.

        Args:
            data: Binary data.

        Returns:
            Format string.
        """
        if len(data) >= _MIN_HEADER_SIZE_PE and data[:_MIN_HEADER_SIZE_PE] == b"MZ":
            return "pe"
        if len(data) >= _MIN_HEADER_SIZE_ELF:
            if data[:_MIN_HEADER_SIZE_ELF] == b"\x7fELF":
                return "elf"
            if data[:_MIN_HEADER_SIZE_ELF] in {
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",
            }:
                return "macho"
        return "raw"

    @staticmethod
    def _detect_architecture(data: bytes) -> tuple[str, bool]:
        """Detect architecture from binary headers.

        Args:
            data: Binary data.

        Returns:
            Tuple of (architecture, is_64bit).
        """
        if len(data) < _MIN_DATA_SIZE_ARCH:
            return "unknown", False

        if data[:_MIN_HEADER_SIZE_PE] == b"MZ" and len(data) > _PE_HEADER_MIN_SIZE:
            pe_offset = int.from_bytes(
                data[_PE_OFFSET_LOCATION : _PE_OFFSET_LOCATION + _PE_OFFSET_SIZE],
                "little",
                signed=False,
            )
            machine_offset = pe_offset + _PE_MACHINE_OFFSET
            if len(data) > machine_offset + _PE_MACHINE_SIZE:
                machine = int.from_bytes(
                    data[machine_offset : machine_offset + _PE_MACHINE_SIZE],
                    "little",
                    signed=False,
                )
                if machine == _PE_MACHINE_AMD64:
                    return "x86_64", True
                if machine == _PE_MACHINE_I386:
                    return "x86", False
        if data[:_MIN_HEADER_SIZE_ELF] == b"\x7fELF":
            return ("x86_64", True) if data[_ELF_CLASS_OFFSET] == _ELF_CLASS_64 else ("x86", False)
        return "unknown", False

    def _extract_strings(self, view: BinaryView) -> list[StringInfo]:
        """Extract printable strings from the binary.

        Args:
            view: Parsed binary view.

        Returns:
            List of extracted strings.
        """
        strings: list[StringInfo] = []
        strings.extend(self._extract_ascii_strings(view))
        strings.extend(self._extract_utf16le_strings(view))
        _logger.debug(
            "strings_extracted",
            extra={"total_count": len(strings), "data_size": len(view.data)},
        )
        return strings

    def _extract_ascii_strings(self, view: BinaryView) -> list[StringInfo]:
        """Extract ASCII strings.

        Args:
            view: Parsed binary view.

        Returns:
            List of ASCII StringInfo entries.
        """
        results: list[StringInfo] = []
        current: bytearray = bytearray()
        start_offset = 0
        printable = set(range(0x20, 0x7F))

        for idx, byte in enumerate(view.data):
            if byte in printable:
                if not current:
                    start_offset = idx
                if len(current) < self._max_string_length:
                    current.append(byte)
                continue
            if len(current) >= self._min_string_length:
                value = current.decode("utf-8", errors="ignore")
                address, section = view.offset_to_va(start_offset)
                results.append(
                    StringInfo(
                        address=address,
                        value=value,
                        encoding="ascii",
                        section=section,
                    )
                )
            current = bytearray()

        if len(current) >= self._min_string_length:
            value = current.decode("utf-8", errors="ignore")
            address, section = view.offset_to_va(start_offset)
            results.append(
                StringInfo(
                    address=address,
                    value=value,
                    encoding="ascii",
                    section=section,
                )
            )
        return results

    def _extract_utf16le_strings(self, view: BinaryView) -> list[StringInfo]:
        """Extract UTF-16LE strings.

        Args:
            view: Parsed binary view.

        Returns:
            List of UTF-16LE StringInfo entries.
        """
        results: list[StringInfo] = []
        current_chars: list[int] = []
        start_offset = 0

        data = view.data
        idx = 0
        while idx + 1 < len(data):
            char = data[idx]
            null = data[idx + 1]
            if _ASCII_PRINTABLE_MIN <= char <= _ASCII_PRINTABLE_MAX and null == 0:
                if not current_chars:
                    start_offset = idx
                if len(current_chars) < self._max_string_length:
                    current_chars.append(char)
                idx += 2
                continue
            if len(current_chars) >= self._min_string_length:
                value = bytes(current_chars).decode("utf-8", errors="ignore")
                address, section = view.offset_to_va(start_offset)
                results.append(
                    StringInfo(
                        address=address,
                        value=value,
                        encoding="utf-16le",
                        section=section,
                    )
                )
            current_chars = []
            idx += 2

        if len(current_chars) >= self._min_string_length:
            value = bytes(current_chars).decode("utf-8", errors="ignore")
            address, section = view.offset_to_va(start_offset)
            results.append(
                StringInfo(
                    address=address,
                    value=value,
                    encoding="utf-16le",
                    section=section,
                )
            )
        return results

    @staticmethod
    def _filter_strings(
        strings: Sequence[StringInfo],
        keywords: Iterable[str],
    ) -> list[StringInfo]:
        """Filter strings containing any keyword.

        Args:
            strings: Strings to scan.
            keywords: Keywords to match.

        Returns:
            List of matching strings.
        """
        lowered = tuple(k.lower() for k in keywords)
        return [s for s in strings if any(k in s.value.lower() for k in lowered)]

    def _detect_crypto_apis(
        self,
        view: BinaryView,
        strings: Sequence[StringInfo],
    ) -> list[CryptoAPICall]:
        """Detect crypto APIs from imports and strings.

        Args:
            view: Parsed binary view.
            strings: Extracted strings.

        Returns:
            List of CryptoAPICall entries.
        """
        _logger.debug(
            "crypto_api_detection_started",
            extra={"imports_count": len(view.imports), "strings_count": len(strings)},
        )
        calls: list[CryptoAPICall] = []
        seen: set[tuple[str, int]] = set()

        for entry in view.imports:
            algo = self._match_crypto_keyword(entry.name)
            if algo is not None:
                key = (entry.name, entry.address)
                if key not in seen:
                    calls.append(
                        CryptoAPICall(
                            api_name=entry.name,
                            address=entry.address,
                            dll=entry.dll,
                            caller_function=None,
                            parameters_hint=None,
                        )
                    )
                    seen.add(key)

        for string in strings:
            for keyword in self._crypto_api_keywords:
                if keyword.lower() in string.value.lower():
                    key = (keyword, string.address)
                    if key not in seen:
                        calls.append(
                            CryptoAPICall(
                                api_name=keyword,
                                address=string.address,
                                dll="",
                                caller_function=None,
                                parameters_hint=None,
                            )
                        )
                        seen.add(key)
        _logger.debug("crypto_api_detection_completed", extra={"detected_count": len(calls)})
        return calls

    def _match_crypto_keyword(self, name: str) -> AlgorithmType | None:
        """Map a function name to an algorithm type.

        Args:
            name: Function name.

        Returns:
            AlgorithmType if matched, otherwise None.
        """
        lowered = name.lower()
        return next(
            (algo for keyword, algo in self._crypto_api_keywords.items() if keyword.lower() in lowered),
            None,
        )

    def _extract_magic_constants(self, view: BinaryView) -> list[MagicConstant]:
        """Extract known magic constants from binary sections.

        Args:
            view: Parsed binary view.

        Returns:
            List of MagicConstant entries.
        """
        _logger.debug(
            "magic_constant_scan_started",
            extra={"sections_count": len(view.sections), "known_constants_count": len(self._known_constants)},
        )
        constants: list[MagicConstant] = []
        seen: set[tuple[int, int]] = set()

        for value, context in self._known_constants.items():
            for section in view.sections:
                constants.extend(
                    self._scan_section_for_constant(
                        section=section,
                        value=value,
                        context=context,
                        seen=seen,
                    )
                )

        rsa_constants = self._extract_rsa_constants(view)
        for constant in rsa_constants:
            key = (constant.value, constant.address)
            if key not in seen:
                constants.append(constant)
                seen.add(key)

        _logger.debug("magic_constant_scan_completed", extra={"constants_found": len(constants)})
        return constants

    @staticmethod
    def _scan_section_for_constant(
        section: SectionData,
        value: int,
        context: str,
        seen: set[tuple[int, int]],
    ) -> list[MagicConstant]:
        """Scan a section for a specific constant.

        Args:
            section: Section to scan.
            value: Constant value.
            context: Context label.
            seen: Set of already-recorded constants.

        Returns:
            List of MagicConstant entries found in the section.
        """
        results: list[MagicConstant] = []
        for fmt, width in (("<I", 32), ("<Q", 64)):
            try:
                packed = struct.pack(fmt, value)
            except struct.error as exc:
                _logger.debug(
                    "constant_pack_skipped",
                    extra={"value": hex(value), "format": fmt, "error": str(exc)},
                )
                continue
            offset = 0
            while True:
                index = section.data.find(packed, offset)
                if index == -1:
                    break
                address = section.virtual_address + index
                key = (value, address)
                if key not in seen:
                    results.append(
                        MagicConstant(
                            value=value,
                            address=address,
                            usage_context=context,
                            bit_width=width,
                        )
                    )
                    seen.add(key)
                offset = index + 1
        return results

    @staticmethod
    def _extract_rsa_constants(view: BinaryView) -> list[MagicConstant]:
        """Extract RSA public key components when present.

        Args:
            view: Parsed binary view.

        Returns:
            List of MagicConstant entries for RSA key data.
        """
        _logger.debug("rsa_constant_extraction_started", extra={"data_size": len(view.data)})
        constants: list[MagicConstant] = []
        rsa_keys = LicenseAnalyzer._find_rsa_public_keys(view.data)
        _logger.debug("rsa_keys_found", extra={"key_count": len(rsa_keys)})
        for modulus, exponent, offset in rsa_keys:
            mod_address, _ = view.offset_to_va(offset)
            constants.extend((
                MagicConstant(
                    value=modulus,
                    address=mod_address,
                    usage_context="rsa_modulus",
                    bit_width=modulus.bit_length(),
                ),
                MagicConstant(
                    value=exponent,
                    address=mod_address,
                    usage_context="rsa_public_exponent",
                    bit_width=exponent.bit_length(),
                ),
            ))
        return constants

    @staticmethod
    def _find_rsa_public_keys(data: bytes) -> list[tuple[int, int, int]]:
        """Find RSA public keys encoded in DER or PEM.

        Args:
            data: Binary data.

        Returns:
            List of tuples (modulus, exponent, offset).
        """
        _logger.debug("rsa_key_search_started", extra={"data_size": len(data)})
        results: list[tuple[int, int, int]] = []
        results.extend(LicenseAnalyzer._find_pem_keys(data))
        results.extend(LicenseAnalyzer._find_der_keys(data))
        _logger.debug(
            "rsa_key_search_completed",
            extra={"pem_and_der_total": len(results)},
        )
        return results

    @staticmethod
    def _find_pem_keys(data: bytes) -> list[tuple[int, int, int]]:
        """Locate PEM-encoded public keys.

        Args:
            data: Binary data.

        Returns:
            List of tuples (modulus, exponent, offset).
        """
        results: list[tuple[int, int, int]] = []
        for match in re.finditer(
            rb"-----BEGIN (RSA )?PUBLIC KEY-----(.*?)-----END (RSA )?PUBLIC KEY-----",
            data,
            re.DOTALL,
        ):
            payload = match.group(2)
            try:
                der = base64.b64decode(payload, validate=True)
            except binascii.Error as exc:
                _logger.debug(
                    "pem_base64_decode_failed",
                    extra={"offset": match.start(), "error": str(exc)},
                )
                continue
            parsed = LicenseAnalyzer._parse_rsa_public_key_der(der)
            if parsed is not None:
                modulus, exponent = parsed
                _logger.debug(
                    "pem_rsa_key_extracted",
                    extra={
                        "offset": match.start(),
                        "modulus_bits": modulus.bit_length(),
                        "exponent": exponent,
                    },
                )
                results.append((modulus, exponent, match.start()))
        _logger.debug("pem_key_search_completed", extra={"keys_found": len(results)})
        return results

    @staticmethod
    def _find_der_keys(data: bytes) -> list[tuple[int, int, int]]:
        """Locate DER-encoded RSA public keys.

        Args:
            data: Binary data.

        Returns:
            List of tuples (modulus, exponent, offset).
        """
        results: list[tuple[int, int, int]] = []
        for idx in range(len(data) - _DER_KEY_MIN_SCAN_BYTES):
            if data[idx] != _DER_SEQUENCE_TAG:
                continue
            parsed = LicenseAnalyzer._parse_rsa_public_key_der_from_offset(data, idx)
            if parsed is None:
                continue
            modulus, exponent, _total_len = parsed
            _logger.debug(
                "der_rsa_key_extracted",
                extra={
                    "offset": idx,
                    "modulus_bits": modulus.bit_length(),
                    "exponent": exponent,
                },
            )
            results.append((modulus, exponent, idx))
        _logger.debug("der_key_search_completed", extra={"keys_found": len(results)})
        return results

    @staticmethod
    def _parse_rsa_public_key_der_from_offset(data: bytes, offset: int) -> tuple[int, int, int] | None:
        """Parse DER-encoded RSA public key at offset.

        Args:
            data: Binary data.
            offset: Offset to parse from.

        Returns:
            Tuple of (modulus, exponent, total_length) or None.
        """
        if offset >= len(data) or data[offset] != _DER_SEQUENCE_TAG:
            return None
        length_info = LicenseAnalyzer._read_der_length(data, offset + 1)
        if length_info is None:
            return None
        seq_len, seq_len_bytes = length_info
        start = offset + 1 + seq_len_bytes
        end = start + seq_len
        if end > len(data):
            return None
        parsed = LicenseAnalyzer._parse_rsa_public_key_der(data[start:end])
        if parsed is None:
            return None
        modulus, exponent = parsed
        return modulus, exponent, end - offset

    @staticmethod
    def _parse_der_integer(data: bytes, cursor: int) -> tuple[int, int] | None:
        """Parse a DER INTEGER from data at cursor position.

        Args:
            data: DER data.
            cursor: Current position in data.

        Returns:
            Tuple of (integer_value, new_cursor) or None.
        """
        if cursor >= len(data) or data[cursor] != _DER_INTEGER_TAG:
            return None
        len_info = LicenseAnalyzer._read_der_length(data, cursor + 1)
        if len_info is None:
            return None
        int_len, len_bytes = len_info
        start = cursor + 1 + len_bytes
        end = start + int_len
        if end > len(data):
            return None
        value = int.from_bytes(data[start:end], "big", signed=False)
        return value, end

    @staticmethod
    def _parse_rsa_public_key_der(data: bytes) -> tuple[int, int] | None:
        """Parse DER-encoded RSA public key data.

        Args:
            data: DER data.

        Returns:
            Tuple of (modulus, exponent) or None.
        """
        if not data or data[0] != _DER_SEQUENCE_TAG:
            return None
        length_info = LicenseAnalyzer._read_der_length(data, 1)
        if length_info is None:
            return None
        _seq_len, seq_len_bytes = length_info
        cursor = 1 + seq_len_bytes

        mod_result = LicenseAnalyzer._parse_der_integer(data, cursor)
        if mod_result is None:
            return None
        modulus, cursor = mod_result

        exp_result = LicenseAnalyzer._parse_der_integer(data, cursor)
        if exp_result is None:
            return None
        exponent, _ = exp_result

        if modulus.bit_length() < _MIN_RSA_MODULUS_BITS:
            return None
        return modulus, exponent

    @staticmethod
    def _read_der_length(data: bytes, offset: int) -> tuple[int, int] | None:
        """Read DER length from data.

        Args:
            data: DER data.
            offset: Offset to read length from.

        Returns:
            Tuple of (length, bytes_consumed) or None.
        """
        if offset >= len(data):
            return None
        first = data[offset]
        if first < _DER_LONG_FORM_MASK:
            return first, 1
        num_bytes = first & _DER_LENGTH_BYTES_MASK
        if num_bytes == 0 or offset + 1 + num_bytes > len(data):
            return None
        length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big", signed=False)
        return length, 1 + num_bytes

    @staticmethod
    def _identify_validation_functions(
        view: BinaryView,
        license_strings: Sequence[StringInfo],
        crypto_calls: Sequence[CryptoAPICall],
    ) -> list[ValidationFunctionInfo]:
        """Identify candidate validation functions.

        Args:
            view: Parsed binary view.
            license_strings: License-related strings.
            crypto_calls: Crypto API calls.

        Returns:
            List of ValidationFunctionInfo entries.
        """
        _logger.debug(
            "validation_function_detection_started",
            extra={
                "sections_count": len(view.sections),
                "license_strings_count": len(license_strings),
                "crypto_calls_count": len(crypto_calls),
            },
        )
        if not view.sections:
            _logger.debug("validation_function_detection_skipped", extra={"reason": "no_sections"})
            return []

        instructions = LicenseAnalyzer._disassemble_sections(view)
        if not instructions:
            _logger.debug("validation_function_detection_skipped", extra={"reason": "no_instructions"})
            return []

        lookup_maps = LicenseAnalyzer._build_validation_lookup_maps(view, license_strings, crypto_calls)
        function_ranges = LicenseAnalyzer._get_function_ranges(view, instructions)
        _logger.debug(
            "validation_function_ranges_built",
            extra={
                "instruction_count": len(instructions),
                "function_range_count": len(function_ranges),
            },
        )

        results = LicenseAnalyzer._analyze_function_ranges(instructions, function_ranges, lookup_maps)
        _logger.debug("validation_function_detection_completed", extra={"candidates_found": len(results)})
        return results

    @staticmethod
    def _build_validation_lookup_maps(
        view: BinaryView,
        license_strings: Sequence[StringInfo],
        crypto_calls: Sequence[CryptoAPICall],
    ) -> tuple[dict[int, str], dict[int, str], set[str]]:
        """Build lookup maps for validation function detection.

        Args:
            view: Parsed binary view.
            license_strings: License-related strings.
            crypto_calls: Crypto API calls.

        Returns:
            Tuple of (string_map, import_map, crypto_imports).
        """
        string_map = {s.address: s.value for s in license_strings}
        import_map = {imp.address: imp.name for imp in view.imports if imp.address}
        crypto_imports = {call.api_name for call in crypto_calls}
        return string_map, import_map, crypto_imports

    @staticmethod
    def _get_function_ranges(
        view: BinaryView,
        instructions: Sequence[InstructionRecord],
    ) -> list[tuple[int, int]]:
        """Get function ranges from view and instructions.

        Args:
            view: Parsed binary view.
            instructions: Disassembled instructions.

        Returns:
            List of (start, end) ranges for functions.
        """
        function_starts = LicenseAnalyzer._collect_function_candidates(
            view=view,
            instructions=instructions,
        )
        return LicenseAnalyzer._build_function_ranges(view, function_starts)

    @staticmethod
    def _analyze_function_ranges(
        instructions: Sequence[InstructionRecord],
        function_ranges: Sequence[tuple[int, int]],
        lookup_maps: tuple[dict[int, str], dict[int, str], set[str]],
    ) -> list[ValidationFunctionInfo]:
        """Analyze function ranges for validation patterns.

        Args:
            instructions: Disassembled instructions.
            function_ranges: List of (start, end) ranges.
            lookup_maps: Tuple of (string_map, import_map, crypto_imports).

        Returns:
            List of ValidationFunctionInfo entries.
        """
        string_map, import_map, crypto_imports = lookup_maps
        functions: list[ValidationFunctionInfo] = []

        for start, end in function_ranges:
            ctx = LicenseAnalyzer._analyze_single_function(instructions, start, end, string_map, import_map, crypto_imports)
            func_info = LicenseAnalyzer._create_validation_info_if_valid(start, ctx)
            if func_info is not None:
                functions.append(func_info)

        return functions

    @staticmethod
    def _analyze_single_function(
        instructions: Sequence[InstructionRecord],
        start: int,
        end: int,
        string_map: dict[int, str],
        import_map: dict[int, str],
        crypto_imports: set[str],
    ) -> _FunctionAnalysisContext:
        """Analyze a single function for validation patterns.

        Args:
            instructions: Disassembled instructions.
            start: Function start address.
            end: Function end address.
            string_map: Map of addresses to license strings.
            import_map: Map of addresses to import names.
            crypto_imports: Set of crypto API names.

        Returns:
            _FunctionAnalysisContext with analysis results.
        """
        ctx = _FunctionAnalysisContext.create_empty()

        for instr in instructions:
            if instr.address < start or instr.address >= end:
                continue
            LicenseAnalyzer._update_context_for_instruction(ctx, instr, string_map, import_map, crypto_imports)

        return ctx

    @staticmethod
    def _update_context_for_instruction(
        ctx: _FunctionAnalysisContext,
        instr: InstructionRecord,
        string_map: dict[int, str],
        import_map: dict[int, str],
        crypto_imports: set[str],
    ) -> None:
        """Update analysis context based on instruction.

        Args:
            ctx: Analysis context to update.
            instr: Instruction to analyze.
            string_map: Map of addresses to license strings.
            import_map: Map of addresses to import names.
            crypto_imports: Set of crypto API names.
        """
        if instr.mnemonic in {"cmp", "test"}:
            ctx.comparisons.append(instr.address)
        if instr.mnemonic.startswith("j") and instr.mnemonic != "jmp":
            ctx.branches += 1
        if instr.mnemonic in _ARITHMETIC_MNEMONICS:
            ctx.arithmetic_count += 1

        ref_addr = LicenseAnalyzer._extract_reference_address(instr)
        if ref_addr is not None and ref_addr in string_map:
            ctx.string_refs.add(string_map[ref_addr])
        if (
            ref_addr is not None
            and ref_addr in import_map
            and any(keyword.lower() in import_map[ref_addr].lower() for keyword in crypto_imports)
        ):
            ctx.calls_crypto = True

    @staticmethod
    def _create_validation_info_if_valid(
        start: int,
        ctx: _FunctionAnalysisContext,
    ) -> ValidationFunctionInfo | None:
        """Create ValidationFunctionInfo if context indicates a validation function.

        Args:
            start: Function start address.
            ctx: Analysis context.

        Returns:
            ValidationFunctionInfo or None if not a validation function.
        """
        has_license_indicators = bool(ctx.string_refs) or ctx.calls_crypto
        has_math_based_validation = (
            ctx.arithmetic_count >= _MIN_ARITHMETIC_FOR_CHECKSUM and ctx.comparisons and ctx.branches >= _MIN_BRANCHES_FOR_VALIDATION
        )

        if not has_license_indicators and not has_math_based_validation:
            return None

        complexity_score = (
            len(ctx.comparisons) + ctx.branches + (len(ctx.string_refs) * _STRING_COMPLEXITY_MULTIPLIER) + (ctx.arithmetic_count // 2)
        )
        return ValidationFunctionInfo(
            address=start,
            name=f"sub_{start:08X}",
            return_type="bool" if ctx.comparisons else "int",
            comparison_addresses=ctx.comparisons,
            string_references=sorted(ctx.string_refs),
            calls_crypto_api=ctx.calls_crypto,
            complexity_score=complexity_score,
            arithmetic_operations=ctx.arithmetic_count,
        )

    @staticmethod
    def _disassemble_sections(view: BinaryView) -> list[InstructionRecord]:
        """Disassemble executable sections using Capstone if available.

        Args:
            view: Parsed binary view.

        Returns:
            List of InstructionRecord entries.
        """
        if _capstone_module is None:
            _logger.warning("disassembly_skipped", extra={"reason": "capstone_unavailable"})
            return []

        mode = _capstone_module.CS_MODE_64 if view.is_64bit else _capstone_module.CS_MODE_32
        md = _capstone_module.Cs(_capstone_module.CS_ARCH_X86, mode)
        md.detail = True

        _logger.debug(
            "disassembly_started",
            extra={"is_64bit": view.is_64bit, "sections_count": len(view.sections)},
        )
        instructions: list[InstructionRecord] = []
        for section in view.sections:
            if not section.executable or not section.data:
                continue
            for instr in md.disasm(section.data, section.virtual_address):
                mnemonic = getattr(instr, "mnemonic", "")
                op_str = getattr(instr, "op_str", "")
                size = int(getattr(instr, "size", 0))
                raw_bytes = bytes(getattr(instr, "bytes", b""))
                instructions.append(
                    InstructionRecord(
                        address=int(getattr(instr, "address", 0)),
                        size=size,
                        mnemonic=mnemonic,
                        op_str=op_str,
                        raw_bytes=raw_bytes,
                    )
                )
        _logger.debug("disassembly_completed", extra={"instruction_count": len(instructions)})
        return instructions

    @staticmethod
    def _collect_function_candidates(
        view: BinaryView,
        instructions: Sequence[InstructionRecord],
    ) -> list[int]:
        """Collect candidate function start addresses.

        Args:
            view: Parsed binary view.
            instructions: Disassembled instructions.

        Returns:
            Sorted list of candidate start addresses.
        """
        starts: set[int] = set()
        if view.entry_point:
            starts.add(view.entry_point)

        for instr in instructions:
            if instr.mnemonic == "call":
                target = LicenseAnalyzer._parse_call_target(instr)
                if target is not None and LicenseAnalyzer._address_in_exec_section(view, target):
                    starts.add(target)

        for i in range(len(instructions) - 1):
            current = instructions[i]
            next_instr = instructions[i + 1]
            if (
                current.mnemonic == "push"
                and current.op_str in {"rbp", "ebp"}
                and next_instr.mnemonic == "mov"
                and "bp" in next_instr.op_str
            ):
                starts.add(current.address)

        return sorted(starts)

    @staticmethod
    def _build_function_ranges(
        view: BinaryView,
        starts: Sequence[int],
    ) -> list[tuple[int, int]]:
        """Build function ranges from start candidates.

        Args:
            view: Parsed binary view.
            starts: Function start addresses.

        Returns:
            List of (start, end) ranges.
        """
        ranges: list[tuple[int, int]] = []
        if not starts:
            return ranges
        starts_sorted = sorted(starts)
        for idx, start in enumerate(starts_sorted):
            end = starts_sorted[idx + 1] if idx + 1 < len(starts_sorted) else 0
            if end == 0:
                section_end = LicenseAnalyzer._section_end_for_address(view, start)
                end = section_end or start + _DEFAULT_FUNCTION_SIZE
            ranges.append((start, end))
        return ranges

    @staticmethod
    def _section_end_for_address(view: BinaryView, address: int) -> int:
        """Find the end of the section containing the address.

        Args:
            view: Parsed binary view.
            address: Address to locate.

        Returns:
            Section end address or 0 if not found.
        """
        for section in view.sections:
            start = section.virtual_address
            end = section.virtual_address + max(section.virtual_size, len(section.data))
            if start <= address < end:
                return end
        return 0

    @staticmethod
    def _address_in_exec_section(view: BinaryView, address: int) -> bool:
        """Check if an address belongs to an executable section.

        Args:
            view: Parsed binary view.
            address: Address to test.

        Returns:
            True if address is inside an executable section.
        """
        for section in view.sections:
            if not section.executable:
                continue
            start = section.virtual_address
            end = start + max(section.virtual_size, len(section.data))
            if start <= address < end:
                return True
        return False

    @staticmethod
    def _parse_call_target(instr: InstructionRecord) -> int | None:
        """Parse call target address from instruction operand.

        Args:
            instr: Instruction record.

        Returns:
            Target address or None if not resolved.
        """
        if instr.mnemonic != "call":
            return None
        return LicenseAnalyzer._parse_hex_address(instr.op_str)

    @staticmethod
    def _extract_reference_address(instr: InstructionRecord) -> int | None:
        """Extract a referenced address from an instruction.

        Args:
            instr: Instruction record.

        Returns:
            Referenced address or None.
        """
        if rip_match := re.search(r"\[rip ([+-]) (0x[0-9a-fA-F]+)\]", instr.op_str):
            sign = 1 if rip_match[1] == "+" else -1
            offset = int(rip_match[2], 16)
            return instr.address + instr.size + sign * offset
        return LicenseAnalyzer._parse_hex_address(instr.op_str)

    @staticmethod
    def _parse_hex_address(text: str) -> int | None:
        """Parse a hexadecimal address from text.

        Args:
            text: Operand text.

        Returns:
            Parsed address or None.
        """
        match = re.search(r"0x[0-9a-fA-F]+", text)
        if not match:
            return None
        try:
            return int(match[0], 16)
        except ValueError as exc:
            _logger.debug("hex_address_parse_failed", extra={"text": text, "error": str(exc)})
            return None

    def _detect_algorithms(
        self,
        crypto_calls: Sequence[CryptoAPICall],
        constants: Sequence[MagicConstant],
        strings: Sequence[StringInfo],
    ) -> tuple[AlgorithmType, list[AlgorithmType]]:
        """Detect algorithm types from analysis signals.

        Args:
            crypto_calls: Crypto API call records.
            constants: Magic constants.
            strings: Extracted strings.

        Returns:
            Tuple of (primary_algorithm, secondary_algorithms).
        """
        _logger.debug(
            "algorithm_detection_started",
            extra={
                "crypto_calls_count": len(crypto_calls),
                "constants_count": len(constants),
                "strings_count": len(strings),
            },
        )
        detected: list[AlgorithmType] = []
        for call in crypto_calls:
            algo = self._match_crypto_keyword(call.api_name)
            if algo is not None and algo not in detected:
                detected.append(algo)

        for constant in constants:
            if constant.usage_context.startswith("md5") and AlgorithmType.MD5 not in detected:
                detected.append(AlgorithmType.MD5)
            if constant.usage_context.startswith("sha1") and AlgorithmType.SHA1 not in detected:
                detected.append(AlgorithmType.SHA1)
            if constant.usage_context.startswith("sha256") and AlgorithmType.SHA256 not in detected:
                detected.append(AlgorithmType.SHA256)
            if constant.usage_context.startswith("crc32") and AlgorithmType.CRC32 not in detected:
                detected.append(AlgorithmType.CRC32)
            if constant.usage_context.startswith("rsa") and AlgorithmType.RSA not in detected:
                detected.append(AlgorithmType.RSA)

        for string in strings:
            lowered = string.value.lower()
            for keyword, algo in self._crypto_api_keywords.items():
                if keyword.lower() in lowered and algo not in detected:
                    detected.append(algo)

        primary = detected[0] if detected else AlgorithmType.UNKNOWN
        secondary = detected[1:] if len(detected) > 1 else []
        _logger.debug(
            "algorithm_detection_completed",
            extra={
                "primary": primary.value,
                "secondary": [a.value for a in secondary],
                "total_detected": len(detected),
            },
        )
        return primary, secondary

    def _detect_key_format(
        self,
        strings: Sequence[StringInfo],
        algorithm: AlgorithmType,
    ) -> tuple[KeyFormat, int, int | None, str | None]:
        """Detect key format from strings and algorithm cues.

        Args:
            strings: Extracted strings.
            algorithm: Detected algorithm.

        Returns:
            Tuple of (key_format, key_length, group_size, group_separator).
        """
        _logger.debug(
            "key_format_detection_started",
            extra={"strings_count": len(strings), "algorithm": algorithm.value},
        )
        best_match = ""
        for string in strings:
            for pattern in self._key_patterns:
                match = pattern.search(string.value)
                if match and len(match.group(0)) > len(best_match):
                    best_match = match.group(0)

        if best_match:
            if "-" in best_match:
                groups = best_match.split("-")
                group_size = len(groups[0])
                _logger.debug(
                    "key_format_detected",
                    extra={"format": "serial_dashed", "key_length": len(best_match.replace("-", "")), "group_size": group_size},
                )
                return (
                    KeyFormat.SERIAL_DASHED,
                    len(best_match.replace("-", "")),
                    group_size,
                    "-",
                )
            if best_match.isdigit():
                _logger.debug("key_format_detected", extra={"format": "numeric_only", "key_length": len(best_match)})
                return KeyFormat.NUMERIC_ONLY, len(best_match), None, None
            if re.fullmatch(r"[0-9A-Fa-f]+", best_match):
                _logger.debug("key_format_detected", extra={"format": "hex_string", "key_length": len(best_match)})
                return KeyFormat.HEX_STRING, len(best_match), None, None
            if re.fullmatch(r"[A-Za-z0-9+/=]+", best_match):
                _logger.debug("key_format_detected", extra={"format": "base64", "key_length": len(best_match)})
                return KeyFormat.BASE64, len(best_match), None, None
            _logger.debug("key_format_detected", extra={"format": "alphanumeric", "key_length": len(best_match)})
            return KeyFormat.ALPHANUMERIC, len(best_match), None, None

        if algorithm in {AlgorithmType.MD5, AlgorithmType.SHA1, AlgorithmType.SHA256}:
            if algorithm == AlgorithmType.MD5:
                digest_len = _DIGEST_LEN_MD5
            elif algorithm == AlgorithmType.SHA1:
                digest_len = _DIGEST_LEN_SHA1
            else:
                digest_len = _DIGEST_LEN_SHA256
            _logger.debug("key_format_detected", extra={"format": "hex_string", "key_length": digest_len, "source": "algorithm_hint"})
            return KeyFormat.HEX_STRING, digest_len, None, None

        _logger.debug("key_format_detected", extra={"format": "unknown", "key_length": _DEFAULT_KEY_LENGTH})
        return KeyFormat.UNKNOWN, _DEFAULT_KEY_LENGTH, None, None

    @staticmethod
    def _detect_checksum_info(
        strings: Sequence[StringInfo],
        constants: Sequence[MagicConstant],
        algorithm: AlgorithmType,
        key_format: KeyFormat,
        group_size: int | None,
    ) -> tuple[str | None, Literal["prefix", "suffix", "embedded"] | None]:
        """Detect checksum algorithm and placement.

        Args:
            strings: Extracted strings.
            constants: Magic constants.
            algorithm: Detected algorithm.
            key_format: Detected key format.
            group_size: Group size if grouped.

        Returns:
            Tuple of (checksum_algorithm, checksum_position).
        """
        checksum_position: Literal["prefix", "suffix", "embedded"] | None = None

        checksum_algorithm: str | None = next(
            ("crc32" for constant in constants if constant.usage_context.startswith("crc32")),
            None,
        )
        if checksum_algorithm is None and algorithm == AlgorithmType.CRC32:
            checksum_algorithm = "crc32"

        for string in strings:
            lowered = string.value.lower()
            if "checksum" in lowered or "crc" in lowered:
                checksum_position = "suffix"
                break

        if checksum_position is None and key_format == KeyFormat.SERIAL_DASHED and group_size and group_size <= _MAX_CHECKSUM_GROUP_SIZE:
            checksum_position = "suffix"

        return checksum_algorithm, checksum_position

    @staticmethod
    def _collect_matching_imports(
        view: BinaryView,
        keywords: Iterable[str],
    ) -> list[str]:
        """Collect import names matching keywords.

        Args:
            view: Parsed binary view.
            keywords: Keywords to match.

        Returns:
            List of matching import names.
        """
        lowered = tuple(k.lower() for k in keywords)
        matches: list[str] = []
        for entry in view.imports:
            name_lower = entry.name.lower()
            if any(k in name_lower for k in lowered):
                matches.append(entry.name)
        return matches

    @staticmethod
    def _build_feature_flags(strings: Sequence[StringInfo]) -> dict[str, int]:
        """Build feature flag map from strings.

        Args:
            strings: Feature-related strings.

        Returns:
            Mapping of feature names to bit positions.
        """
        flags: dict[str, int] = {}
        for string in strings:
            name = string.value.strip()
            if name and name not in flags:
                flags[name] = len(flags)
        return flags

    @staticmethod
    def _build_confidence(
        algorithm: AlgorithmType,
        key_format: KeyFormat,
        validation_functions: Sequence[ValidationFunctionInfo],
        crypto_calls: Sequence[CryptoAPICall],
        constants: Sequence[MagicConstant],
    ) -> tuple[float, list[str]]:
        """Compute confidence score for analysis.

        Args:
            algorithm: Primary algorithm.
            key_format: Detected key format.
            validation_functions: Validation function candidates.
            crypto_calls: Crypto API calls.
            constants: Magic constants.

        Returns:
            Tuple of (confidence_score, notes).
        """
        _logger.debug(
            "confidence_calculation_started",
            extra={
                "algorithm": algorithm.value,
                "key_format": key_format.value,
                "validation_count": len(validation_functions),
                "crypto_call_count": len(crypto_calls),
                "constant_count": len(constants),
            },
        )
        signals = 0
        notes: list[str] = []
        if algorithm != AlgorithmType.UNKNOWN:
            signals += _CONFIDENCE_SIGNAL_WEIGHT
        if key_format != KeyFormat.UNKNOWN:
            signals += _CONFIDENCE_SIGNAL_WEIGHT
        if validation_functions:
            signals += _CONFIDENCE_SIGNAL_WEIGHT
        if crypto_calls:
            signals += _CONFIDENCE_SIGNAL_WEIGHT
        if constants:
            signals += _CONFIDENCE_CONSTANT_WEIGHT
        score = min(1.0, signals / _CONFIDENCE_MAX_SIGNALS)
        if score < _CONFIDENCE_THRESHOLD_LOW:
            notes.append("Low confidence: limited signals found.")
        _logger.debug(
            "confidence_calculation_completed",
            extra={"score": score, "signals": signals, "notes_count": len(notes)},
        )
        return score, notes

    @staticmethod
    def _build_context_notes(
        view: BinaryView,
        license_strings: Sequence[StringInfo],
    ) -> list[str]:
        """Build context notes for analysis output.

        Args:
            view: Parsed binary view.
            license_strings: License-related strings.

        Returns:
            List of analysis notes.
        """
        notes: list[str] = []
        if not view.imports:
            notes.append("Import table unavailable; analysis used string heuristics.")
        if not license_strings:
            notes.append("No explicit license strings detected.")
        return notes
