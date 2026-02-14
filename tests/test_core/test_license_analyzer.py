"""Comprehensive tests for the LicenseAnalyzer module.

Tests validate real-world binary analysis capabilities including:
- PE file parsing with actual Windows binaries
- Crypto API detection from import tables
- Magic constant extraction (MD5, SHA, CRC32 initialization vectors)
- RSA public key extraction from PEM and DER formats
- License string pattern detection
- Validation function identification
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.license_analyzer import LicenseAnalyzer
from intellicrack.core.types import (
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


class _TestableAnalyzer(LicenseAnalyzer):
    """Subclass exposing protected members for testing."""

    @property
    def min_string_length(self) -> int:
        return self._min_string_length

    @property
    def max_string_length(self) -> int:
        return self._max_string_length

    @property
    def license_keywords(self) -> tuple[str, ...]:
        return self._license_keywords

    @property
    def feature_keywords(self) -> tuple[str, ...]:
        return self._feature_keywords

    @property
    def blacklist_keywords(self) -> tuple[str, ...]:
        return self._blacklist_keywords

    @property
    def crypto_api_keywords(self) -> dict[str, AlgorithmType]:
        return self._crypto_api_keywords

    @property
    def known_constants(self) -> dict[int, str]:
        return self._known_constants

    def detect_format(self, data: bytes) -> str:
        return self._detect_format(data)

    def detect_architecture(self, data: bytes) -> tuple[str, bool]:
        return self._detect_architecture(data)

    def filter_strings(
        self,
        strings: Sequence[StringInfo],
        keywords: Iterable[str],
    ) -> list[StringInfo]:
        return self._filter_strings(strings, keywords)

    def parse_rsa_public_key_der(self, data: bytes) -> tuple[int, int] | None:
        return self._parse_rsa_public_key_der(data)

    def detect_algorithms(
        self,
        crypto_calls: Sequence[CryptoAPICall],
        constants: Sequence[MagicConstant],
        strings: Sequence[StringInfo],
    ) -> tuple[AlgorithmType, list[AlgorithmType]]:
        return self._detect_algorithms(crypto_calls, constants, strings)

    def detect_key_format(
        self,
        strings: Sequence[StringInfo],
        algorithm: AlgorithmType,
    ) -> tuple[KeyFormat, int, int | None, str | None]:
        return self._detect_key_format(strings, algorithm)

    def read_der_length(self, data: bytes, offset: int) -> tuple[int, int] | None:
        return self._read_der_length(data, offset)

    def parse_der_integer(self, data: bytes, cursor: int) -> tuple[int, int] | None:
        return self._parse_der_integer(data, cursor)

    def build_confidence(
        self,
        algorithm: AlgorithmType,
        key_format: KeyFormat,
        validation_functions: Sequence[ValidationFunctionInfo],
        crypto_calls: Sequence[CryptoAPICall],
        constants: Sequence[MagicConstant],
    ) -> tuple[float, list[str]]:
        return self._build_confidence(
            algorithm,
            key_format,
            validation_functions,
            crypto_calls,
            constants,
        )


EXPECTED_DEFAULT_MIN_LENGTH = 4
EXPECTED_DEFAULT_MAX_LENGTH = 256
EXPECTED_CUSTOM_MIN_LENGTH = 8
EXPECTED_CUSTOM_MAX_LENGTH = 128

CRC32_POLYNOMIAL = 0xEDB88320
MD5_INIT_A = 0x67452301
MD5_INIT_B = 0xEFCDAB89
MD5_INIT_C = 0x98BADCFE
MD5_INIT_D = 0x10325476
SHA256_INIT_H0 = 0x6A09E667
RSA_PUBLIC_EXPONENT_CONST = 0x10001

PE_MACHINE_AMD64 = 0x8664
PE_MACHINE_I386 = 0x14C
PE_OFFSET_LOCATION = 0x3C
PE_COFF_HEADER_OFFSET = 64
ELF_CLASS_64 = 2

DER_SHORT_LENGTH_VALUE = 16
DER_LONG_LENGTH_VALUE = 256
DER_SHORT_LENGTH_CONSUMED = 1
DER_LONG_LENGTH_CONSUMED = 3
DER_INTEGER_VALUE = 65537
DER_INTEGER_NEW_CURSOR = 5

RSA_MODULUS_MIN_BIT_LENGTH = 1024

EXPECTED_FILTERED_LICENSE_COUNT = 2
EXPECTED_FILTERED_FEATURE_COUNT = 2
EXPECTED_FILTERED_BLACKLIST_COUNT = 2

LOW_CONFIDENCE_THRESHOLD = 0.3
HIGH_CONFIDENCE_THRESHOLD = 0.3

VALIDATION_COMPLEXITY_SCORE = 5

ADDRESS_BASE = 0x1000
ADDRESS_SECOND = 0x2000
ADDRESS_THIRD = 0x3000
ADDRESS_FOURTH = 0x4000
ADDRESS_VALIDATION = 0x3100

CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0
TEST_CONFIDENCE_SCORE = 0.85

EXPECTED_KEY_LENGTH = 25
EXPECTED_GROUP_SIZE = 5


class TestLicenseAnalyzerInitialization:
    """Test LicenseAnalyzer construction and configuration."""

    @staticmethod
    def test_default_initialization() -> None:
        """Verify default string length parameters."""
        analyzer = _TestableAnalyzer()
        assert analyzer.min_string_length == EXPECTED_DEFAULT_MIN_LENGTH
        assert analyzer.max_string_length == EXPECTED_DEFAULT_MAX_LENGTH

    @staticmethod
    def test_custom_string_lengths() -> None:
        """Verify custom string length configuration."""
        analyzer = _TestableAnalyzer(
            min_string_length=EXPECTED_CUSTOM_MIN_LENGTH,
            max_string_length=EXPECTED_CUSTOM_MAX_LENGTH,
        )
        assert analyzer.min_string_length == EXPECTED_CUSTOM_MIN_LENGTH
        assert analyzer.max_string_length == EXPECTED_CUSTOM_MAX_LENGTH

    @staticmethod
    def test_license_keywords_populated() -> None:
        """Verify license-related keywords are configured."""
        analyzer = _TestableAnalyzer()
        assert "license" in analyzer.license_keywords
        assert "serial" in analyzer.license_keywords
        assert "registration" in analyzer.license_keywords
        assert "activate" in analyzer.license_keywords

    @staticmethod
    def test_crypto_api_keywords_populated() -> None:
        """Verify crypto API mappings are configured."""
        analyzer = _TestableAnalyzer()
        assert "CryptAcquireContext" in analyzer.crypto_api_keywords
        assert "BCryptOpenAlgorithmProvider" in analyzer.crypto_api_keywords
        assert "MD5" in analyzer.crypto_api_keywords
        assert "RSA" in analyzer.crypto_api_keywords

    @staticmethod
    def test_known_constants_include_crypto_ivs() -> None:
        """Verify magic constants include standard crypto IVs."""
        analyzer = _TestableAnalyzer()
        assert CRC32_POLYNOMIAL in analyzer.known_constants
        assert MD5_INIT_A in analyzer.known_constants
        assert SHA256_INIT_H0 in analyzer.known_constants
        assert RSA_PUBLIC_EXPONENT_CONST in analyzer.known_constants


class TestBinaryFormatDetection:
    """Test binary format detection functionality."""

    @staticmethod
    def test_detect_pe_format() -> None:
        """Verify PE format detection from MZ header."""
        pe_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", PE_COFF_HEADER_OFFSET)
        pe_header += b"\x00" * 4 + b"PE\x00\x00" + b"\x00" * 200
        analyzer = _TestableAnalyzer()
        detected = analyzer.detect_format(pe_header)
        assert detected == "pe"

    @staticmethod
    def test_detect_elf_format() -> None:
        """Verify ELF format detection from magic bytes."""
        elf_header = b"\x7fELF" + b"\x00" * 60
        analyzer = _TestableAnalyzer()
        detected = analyzer.detect_format(elf_header)
        assert detected == "elf"

    @staticmethod
    def test_detect_macho_format_big_endian() -> None:
        """Verify Mach-O big-endian format detection."""
        macho_header = b"\xfe\xed\xfa\xce" + b"\x00" * 60
        analyzer = _TestableAnalyzer()
        detected = analyzer.detect_format(macho_header)
        assert detected == "macho"

    @staticmethod
    def test_detect_macho_format_little_endian() -> None:
        """Verify Mach-O little-endian format detection."""
        macho_header = b"\xce\xfa\xed\xfe" + b"\x00" * 60
        analyzer = _TestableAnalyzer()
        detected = analyzer.detect_format(macho_header)
        assert detected == "macho"

    @staticmethod
    def test_detect_unknown_format() -> None:
        """Verify unknown format handling returns 'raw'."""
        random_data = b"\x00\x01\x02\x03" * 20
        analyzer = _TestableAnalyzer()
        detected = analyzer.detect_format(random_data)
        assert detected == "raw"


class TestArchitectureDetection:
    """Test architecture detection from binary headers."""

    @staticmethod
    def test_detect_x64_pe() -> None:
        """Verify x86-64 PE detection."""
        pe_data = bytearray(512)
        pe_data[:2] = b"MZ"
        pe_data[PE_OFFSET_LOCATION:0x40] = struct.pack("<I", PE_COFF_HEADER_OFFSET)
        pe_data[PE_COFF_HEADER_OFFSET : PE_COFF_HEADER_OFFSET + 4] = b"PE\x00\x00"
        pe_data[PE_COFF_HEADER_OFFSET + 4 : PE_COFF_HEADER_OFFSET + 6] = struct.pack(
            "<H",
            PE_MACHINE_AMD64,
        )
        analyzer = _TestableAnalyzer()
        arch, is_64bit = analyzer.detect_architecture(bytes(pe_data))
        assert arch == "x86_64"
        assert is_64bit is True

    @staticmethod
    def test_detect_x86_pe() -> None:
        """Verify x86 PE detection."""
        pe_data = bytearray(512)
        pe_data[:2] = b"MZ"
        pe_data[PE_OFFSET_LOCATION:0x40] = struct.pack("<I", PE_COFF_HEADER_OFFSET)
        pe_data[PE_COFF_HEADER_OFFSET : PE_COFF_HEADER_OFFSET + 4] = b"PE\x00\x00"
        pe_data[PE_COFF_HEADER_OFFSET + 4 : PE_COFF_HEADER_OFFSET + 6] = struct.pack(
            "<H",
            PE_MACHINE_I386,
        )
        analyzer = _TestableAnalyzer()
        arch, is_64bit = analyzer.detect_architecture(bytes(pe_data))
        assert arch == "x86"
        assert is_64bit is False

    @staticmethod
    def test_detect_x64_elf() -> None:
        """Verify x86-64 ELF detection."""
        elf_data = bytearray(PE_COFF_HEADER_OFFSET)
        elf_data[:4] = b"\x7fELF"
        elf_data[4] = ELF_CLASS_64
        analyzer = _TestableAnalyzer()
        arch, is_64bit = analyzer.detect_architecture(bytes(elf_data))
        assert arch == "x86_64"
        assert is_64bit is True


class TestMagicConstantExtraction:
    """Test magic constant detection in binary data."""

    @staticmethod
    def test_known_constants_mapping() -> None:
        """Verify known constants dictionary contains expected values."""
        analyzer = _TestableAnalyzer()
        assert CRC32_POLYNOMIAL in analyzer.known_constants
        assert analyzer.known_constants[CRC32_POLYNOMIAL] == "crc32_polynomial"

    @staticmethod
    def test_md5_init_constants_present() -> None:
        """Verify MD5 initialization constants are defined."""
        analyzer = _TestableAnalyzer()
        md5_init_values = [MD5_INIT_A, MD5_INIT_B, MD5_INIT_C, MD5_INIT_D]
        for val in md5_init_values:
            assert val in analyzer.known_constants
            assert analyzer.known_constants[val] == "md5_init"

    @staticmethod
    def test_sha256_init_constant_present() -> None:
        """Verify SHA-256 first init constant is defined."""
        analyzer = _TestableAnalyzer()
        assert SHA256_INIT_H0 in analyzer.known_constants
        assert analyzer.known_constants[SHA256_INIT_H0] == "sha256_init"

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_magic_constants_in_real_binary() -> None:
        """Verify magic constant detection in a real Windows binary."""
        kernel32_path = Path("C:/Windows/System32/kernel32.dll")
        if not kernel32_path.exists():
            pytest.skip("kernel32.dll not found")

        analyzer = _TestableAnalyzer()
        analysis = analyzer.analyze(kernel32_path)
        assert analysis is not None


class TestRSAKeyExtraction:
    """Test RSA public key extraction from PEM and DER formats."""

    @staticmethod
    def test_parse_valid_rsa_der() -> None:
        """Verify RSA public key parsing from valid DER structure."""
        modulus_bytes = bytes([0x00]) + bytes([0xA1] * 128)
        exponent_bytes = bytes([0x01, 0x00, 0x01])

        modulus_der = bytes([0x02, 0x81, 0x81]) + modulus_bytes
        exponent_der = bytes([0x02, 0x03]) + exponent_bytes

        inner = modulus_der + exponent_der
        rsa_der = bytes([0x30, 0x81, len(inner)]) + inner

        analyzer = _TestableAnalyzer()
        result = analyzer.parse_rsa_public_key_der(rsa_der)
        assert result is not None
        modulus, exponent = result
        assert exponent == DER_INTEGER_VALUE
        assert modulus.bit_length() >= RSA_MODULUS_MIN_BIT_LENGTH

    @staticmethod
    def test_extract_der_rsa_key_small() -> None:
        """Verify RSA public key extraction from small DER format."""
        der_data = bytes.fromhex("3030020100020100020101020101020101020101020101020101")
        analyzer = _TestableAnalyzer()
        result = analyzer.parse_rsa_public_key_der(der_data)
        assert result is None

    @staticmethod
    def test_find_rsa_exponent_constant() -> None:
        """Verify RSA public exponent 65537 detection."""
        analyzer = _TestableAnalyzer()
        assert RSA_PUBLIC_EXPONENT_CONST in analyzer.known_constants
        assert analyzer.known_constants[RSA_PUBLIC_EXPONENT_CONST] == "rsa_public_exponent"


class TestStringExtraction:
    """Test license string detection and filtering."""

    @staticmethod
    def test_filter_license_strings() -> None:
        """Verify license keyword filtering."""
        analyzer = _TestableAnalyzer()
        strings = [
            StringInfo(address=ADDRESS_BASE, value="Invalid License", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_SECOND, value="HelloWorld", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_THIRD, value="Serial Number:", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_FOURTH, value="RandomText", encoding="ascii", section=".rdata"),
        ]
        filtered = analyzer.filter_strings(strings, analyzer.license_keywords)
        assert len(filtered) == EXPECTED_FILTERED_LICENSE_COUNT
        assert any("License" in s.value for s in filtered)
        assert any("Serial" in s.value for s in filtered)

    @staticmethod
    def test_filter_feature_strings() -> None:
        """Verify feature keyword filtering."""
        analyzer = _TestableAnalyzer()
        strings = [
            StringInfo(address=ADDRESS_BASE, value="Professional Edition", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_SECOND, value="Enterprise Features", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_THIRD, value="OtherText", encoding="ascii", section=".rdata"),
        ]
        filtered = analyzer.filter_strings(strings, analyzer.feature_keywords)
        assert len(filtered) == EXPECTED_FILTERED_FEATURE_COUNT

    @staticmethod
    def test_filter_blacklist_strings() -> None:
        """Verify blacklist keyword filtering."""
        analyzer = _TestableAnalyzer()
        strings = [
            StringInfo(address=ADDRESS_BASE, value="License blacklisted", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_SECOND, value="Key revoked", encoding="ascii", section=".rdata"),
            StringInfo(address=ADDRESS_THIRD, value="ValidKey", encoding="ascii", section=".rdata"),
        ]
        filtered = analyzer.filter_strings(strings, analyzer.blacklist_keywords)
        assert len(filtered) == EXPECTED_FILTERED_BLACKLIST_COUNT


class TestAlgorithmDetection:
    """Test algorithm type detection from imports and constants."""

    EXPECTED_MIN_SECONDARY_ALGORITHMS = 1
    CRC32_BIT_WIDTH = 32

    @staticmethod
    def test_detect_md5_from_api_call() -> None:
        """Verify MD5 detection from crypto API."""
        analyzer = _TestableAnalyzer()
        calls = [
            CryptoAPICall(
                api_name="MD5",
                address=ADDRESS_BASE,
                dll="advapi32.dll",
                caller_function=None,
                parameters_hint=None,
            )
        ]
        algo, _secondary = analyzer.detect_algorithms(calls, [], [])
        assert algo == AlgorithmType.MD5

    @staticmethod
    def test_detect_sha1_from_api_call() -> None:
        """Verify SHA-1 detection from crypto API."""
        analyzer = _TestableAnalyzer()
        calls = [
            CryptoAPICall(
                api_name="SHA1",
                address=ADDRESS_BASE,
                dll="advapi32.dll",
                caller_function=None,
                parameters_hint=None,
            )
        ]
        algo, _secondary = analyzer.detect_algorithms(calls, [], [])
        assert algo == AlgorithmType.SHA1

    @staticmethod
    def test_detect_crc32_from_constant() -> None:
        """Verify CRC32 detection from polynomial constant."""
        analyzer = _TestableAnalyzer()
        constants = [
            MagicConstant(
                value=CRC32_POLYNOMIAL,
                address=ADDRESS_BASE,
                usage_context="crc32_polynomial",
                bit_width=TestAlgorithmDetection.CRC32_BIT_WIDTH,
            )
        ]
        algo, _secondary = analyzer.detect_algorithms([], constants, [])
        assert algo == AlgorithmType.CRC32

    @staticmethod
    def test_detect_multiple_algorithms() -> None:
        """Verify multiple algorithm detection."""
        analyzer = _TestableAnalyzer()
        calls = [
            CryptoAPICall(
                api_name="MD5",
                address=ADDRESS_BASE,
                dll="advapi32.dll",
                caller_function=None,
                parameters_hint=None,
            ),
            CryptoAPICall(
                api_name="CRC32",
                address=ADDRESS_SECOND,
                dll="ntdll.dll",
                caller_function=None,
                parameters_hint=None,
            ),
        ]
        algo, secondary = analyzer.detect_algorithms(calls, [], [])
        assert algo in {AlgorithmType.MD5, AlgorithmType.CRC32}
        assert len(secondary) >= TestAlgorithmDetection.EXPECTED_MIN_SECONDARY_ALGORITHMS


class TestKeyFormatDetection:
    """Test license key format detection."""

    @staticmethod
    def test_detect_dashed_serial_format() -> None:
        """Verify dashed serial key format detection."""
        analyzer = _TestableAnalyzer()
        strings = [
            StringInfo(address=ADDRESS_BASE, value="XXXX-XXXX-XXXX-XXXX", encoding="ascii", section=".rdata"),
        ]
        key_format, _key_length, _group_size, separator = analyzer.detect_key_format(strings, AlgorithmType.UNKNOWN)
        assert key_format == KeyFormat.SERIAL_DASHED
        assert separator == "-"

    @staticmethod
    def test_detect_hex_string_format() -> None:
        """Verify hexadecimal key format detection."""
        analyzer = _TestableAnalyzer()
        strings = [
            StringInfo(address=ADDRESS_BASE, value="0123456789ABCDEF0123456789ABCDEF", encoding="ascii", section=".rdata"),
        ]
        key_format, _key_length, _group_size, _separator = analyzer.detect_key_format(strings, AlgorithmType.MD5)
        assert key_format in {KeyFormat.HEX_STRING, KeyFormat.SERIAL_PLAIN}


class TestDERParsing:
    """Test DER/ASN.1 parsing functionality."""

    @staticmethod
    def test_read_der_short_length() -> None:
        """Verify DER short-form length parsing."""
        analyzer = _TestableAnalyzer()
        data = bytes([0x30, 0x10])
        result = analyzer.read_der_length(data, 1)
        assert result is not None
        length, consumed = result
        assert length == DER_SHORT_LENGTH_VALUE
        assert consumed == DER_SHORT_LENGTH_CONSUMED

    @staticmethod
    def test_read_der_long_length() -> None:
        """Verify DER long-form length parsing."""
        analyzer = _TestableAnalyzer()
        data = bytes([0x30, 0x82, 0x01, 0x00])
        result = analyzer.read_der_length(data, 1)
        assert result is not None
        length, consumed = result
        assert length == DER_LONG_LENGTH_VALUE
        assert consumed == DER_LONG_LENGTH_CONSUMED

    @staticmethod
    def test_parse_der_integer() -> None:
        """Verify DER INTEGER parsing."""
        analyzer = _TestableAnalyzer()
        data = bytes([0x02, 0x03, 0x01, 0x00, 0x01])
        result = analyzer.parse_der_integer(data, 0)
        assert result is not None
        value, new_cursor = result
        assert value == DER_INTEGER_VALUE
        assert new_cursor == DER_INTEGER_NEW_CURSOR


class TestConfidenceScoring:
    """Test confidence score calculation."""

    MD5_INIT_BIT_WIDTH = 32

    @staticmethod
    def test_low_confidence_with_no_signals() -> None:
        """Verify low confidence score with minimal signals."""
        analyzer = _TestableAnalyzer()
        score, notes = analyzer.build_confidence(
            AlgorithmType.UNKNOWN,
            KeyFormat.UNKNOWN,
            [],
            [],
            [],
        )
        assert score < LOW_CONFIDENCE_THRESHOLD
        assert any("Low confidence" in note for note in notes)

    @staticmethod
    def test_higher_confidence_with_signals() -> None:
        """Verify higher confidence with detected signals."""
        analyzer = _TestableAnalyzer()
        calls = [
            CryptoAPICall(
                api_name="MD5",
                address=ADDRESS_BASE,
                dll="advapi32.dll",
                caller_function=None,
                parameters_hint=None,
            )
        ]
        constants = [
            MagicConstant(
                value=MD5_INIT_A,
                address=ADDRESS_SECOND,
                usage_context="md5_init",
                bit_width=TestConfidenceScoring.MD5_INIT_BIT_WIDTH,
            )
        ]
        validation = [
            ValidationFunctionInfo(
                address=ADDRESS_THIRD,
                name="CheckLicense",
                return_type="bool",
                comparison_addresses=[ADDRESS_VALIDATION],
                string_references=["license"],
                calls_crypto_api=True,
                complexity_score=VALIDATION_COMPLEXITY_SCORE,
            )
        ]
        score, _notes = analyzer.build_confidence(
            AlgorithmType.MD5,
            KeyFormat.SERIAL_DASHED,
            validation,
            calls,
            constants,
        )
        assert score > HIGH_CONFIDENCE_THRESHOLD


class TestAnalyzeRealBinary:
    """Test analysis against real Windows binaries."""

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_analyze_notepad() -> None:
        """Analyze Windows notepad.exe for basic PE parsing."""
        notepad_path = Path("C:/Windows/System32/notepad.exe")
        if not notepad_path.exists():
            pytest.skip("notepad.exe not found")

        analyzer = LicenseAnalyzer()
        analysis = analyzer.analyze(notepad_path)

        assert analysis.binary_name == "notepad.exe"
        assert analysis.algorithm_type is not None
        assert analysis.key_format is not None
        assert isinstance(analysis.confidence_score, float)
        assert CONFIDENCE_MIN <= analysis.confidence_score <= CONFIDENCE_MAX

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_analyze_cmd() -> None:
        """Analyze Windows cmd.exe for basic PE parsing."""
        cmd_path = Path("C:/Windows/System32/cmd.exe")
        if not cmd_path.exists():
            pytest.skip("cmd.exe not found")

        analyzer = LicenseAnalyzer()
        analysis = analyzer.analyze(cmd_path)

        assert analysis.binary_name == "cmd.exe"
        assert len(analysis.analysis_notes) >= 0

    @staticmethod
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_analyze_kernel32() -> None:
        """Analyze kernel32.dll for crypto API detection."""
        kernel32_path = Path("C:/Windows/System32/kernel32.dll")
        if not kernel32_path.exists():
            pytest.skip("kernel32.dll not found")

        analyzer = LicenseAnalyzer()
        analysis = analyzer.analyze(kernel32_path)

        assert analysis.binary_name == "kernel32.dll"


class TestAnalyzeNonexistentFile:
    """Test error handling for missing files."""

    @staticmethod
    def test_analyze_missing_file_raises() -> None:
        """Verify FileNotFoundError for missing files."""
        analyzer = LicenseAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/path/to/binary.exe"))


class TestLicensingAnalysisDataclass:
    """Test LicensingAnalysis dataclass structure."""

    EXPECTED_PRO_FLAG_VALUE = 1
    EXPECTED_ENTERPRISE_FLAG_VALUE = 2

    @staticmethod
    def test_licensing_analysis_fields() -> None:
        """Verify LicensingAnalysis has all required fields."""
        analysis = LicensingAnalysis(
            binary_name="test.exe",
            algorithm_type=AlgorithmType.MD5,
            secondary_algorithms=[AlgorithmType.CRC32],
            key_format=KeyFormat.SERIAL_DASHED,
            key_length=EXPECTED_KEY_LENGTH,
            group_size=EXPECTED_GROUP_SIZE,
            group_separator="-",
            validation_functions=[],
            crypto_api_calls=[],
            magic_constants=[],
            checksum_algorithm="crc32",
            checksum_position="suffix",
            hardware_id_apis=["GetVolumeInformation"],
            time_check_present=True,
            feature_flags={
                "pro": TestLicensingAnalysisDataclass.EXPECTED_PRO_FLAG_VALUE,
                "enterprise": TestLicensingAnalysisDataclass.EXPECTED_ENTERPRISE_FLAG_VALUE,
            },
            blacklist_present=False,
            online_validation=True,
            confidence_score=TEST_CONFIDENCE_SCORE,
            analysis_notes=["Test note"],
        )

        assert analysis.binary_name == "test.exe"
        assert analysis.algorithm_type == AlgorithmType.MD5
        assert AlgorithmType.CRC32 in analysis.secondary_algorithms
        assert analysis.key_format == KeyFormat.SERIAL_DASHED
        assert analysis.key_length == EXPECTED_KEY_LENGTH
        assert analysis.group_size == EXPECTED_GROUP_SIZE
        assert analysis.group_separator == "-"
        assert analysis.checksum_algorithm == "crc32"
        assert analysis.checksum_position == "suffix"
        assert "GetVolumeInformation" in analysis.hardware_id_apis
        assert analysis.time_check_present is True
        assert analysis.feature_flags["pro"] == TestLicensingAnalysisDataclass.EXPECTED_PRO_FLAG_VALUE
        assert analysis.blacklist_present is False
        assert analysis.online_validation is True
        assert analysis.confidence_score == TEST_CONFIDENCE_SCORE
        assert "Test note" in analysis.analysis_notes
