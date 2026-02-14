"""Comprehensive tests for the script_gen.py keygen generation module.

Tests validate:
- Algorithm-specific keygen generation (MD5, SHA1, CRC32, XOR, RSA, HWID, etc.)
- Generated script syntax validity
- Key format compliance (dashed, plain, hex)
- Checksum computation correctness
- RSA cryptographic operations
- Feature flag encoding
"""

from __future__ import annotations

import ast
from typing import Any, Literal

import pytest

from intellicrack.core.script_gen import GeneratedScript, ScriptGenerator
from intellicrack.core.types import (
    AlgorithmType,
    KeyFormat,
    LicensingAnalysis,
    MagicConstant,
)


ChecksumPosition = Literal["prefix", "suffix", "embedded"]

DEFAULT_KEY_LENGTH = 32
DEFAULT_GROUP_SIZE = 4
RSA_TEST_MODULUS = 17 * 19
RSA_PUBLIC_EXPONENT = 65537
MAGIC_CONST_DEADBEEF = 0xDEADBEEF
MAGIC_CONST_CAFEBABE = 0xCAFEBABE
MAGIC_CONST_ADDRESS_BASE = 0x1000
MAGIC_CONST_BIT_WIDTH = 32
RSA_CONST_ADDRESS = 0x5000
RSA_EXP_ADDRESS = 0x5008
TEST_CONFIDENCE = 0.8
MD5_HEX_KEY_LENGTH = 32
SHA1_HEX_KEY_LENGTH = 40
CRC32_KEY_LENGTH = 8
XOR_KEY_LENGTH = 16
DASHED_KEY_LENGTH_16 = 16
KEY_LENGTH_25 = 25
GROUP_SIZE_5 = 5
CHECKSUM_EXTRA_LENGTH = 8
KEY_WITH_CHECKSUM_LENGTH = 40
MIN_SCRIPT_LENGTH = 100
EXPECTED_DASHED_GROUP_COUNT = 4


def create_test_analysis(
    algorithm: AlgorithmType = AlgorithmType.MD5,
    key_format: KeyFormat = KeyFormat.SERIAL_DASHED,
    key_length: int = DEFAULT_KEY_LENGTH,
    group_size: int = DEFAULT_GROUP_SIZE,
    checksum_algorithm: str | None = None,
    checksum_position: ChecksumPosition | None = None,
    feature_flags: dict[str, int] | None = None,
    magic_constants: list[int] | None = None,
    rsa_modulus: int = 0,
    rsa_exponent: int = RSA_PUBLIC_EXPONENT,
) -> LicensingAnalysis:
    """Create a test LicensingAnalysis instance.

    Args:
        algorithm: Primary algorithm type.
        key_format: Key format type.
        key_length: Length of generated keys.
        group_size: Characters per group for dashed format.
        checksum_algorithm: Checksum algorithm name.
        checksum_position: Checksum position (prefix/suffix/embedded).
        feature_flags: Feature flag mapping.
        magic_constants: List of magic constant values.
        rsa_modulus: RSA modulus for RSA keygens.
        rsa_exponent: RSA public exponent.

    Returns:
        Configured LicensingAnalysis instance.
    """
    constants: list[MagicConstant] = []
    if magic_constants:
        constants.extend(
            MagicConstant(
                value=val,
                address=MAGIC_CONST_ADDRESS_BASE + i * DEFAULT_GROUP_SIZE,
                usage_context="test",
                bit_width=MAGIC_CONST_BIT_WIDTH,
            )
            for i, val in enumerate(magic_constants)
        )
    if rsa_modulus:
        constants.extend((
            MagicConstant(
                value=rsa_modulus,
                address=RSA_CONST_ADDRESS,
                usage_context="rsa_modulus",
                bit_width=rsa_modulus.bit_length(),
            ),
            MagicConstant(
                value=rsa_exponent,
                address=RSA_EXP_ADDRESS,
                usage_context="rsa_public_exponent",
                bit_width=rsa_exponent.bit_length(),
            ),
        ))
    return LicensingAnalysis(
        binary_name="test_app.exe",
        algorithm_type=algorithm,
        secondary_algorithms=[],
        key_format=key_format,
        key_length=key_length,
        group_size=group_size,
        group_separator="-",
        validation_functions=[],
        crypto_api_calls=[],
        magic_constants=constants,
        checksum_algorithm=checksum_algorithm,
        checksum_position=checksum_position,
        hardware_id_apis=[],
        time_check_present=False,
        feature_flags=feature_flags or {},
        blacklist_present=False,
        online_validation=False,
        confidence_score=TEST_CONFIDENCE,
        analysis_notes=[],
    )


class TestScriptGeneratorInitialization:
    """Test ScriptGenerator construction."""

    @staticmethod
    def test_default_initialization() -> None:
        """Verify default ScriptGenerator creation."""
        generator = ScriptGenerator()
        assert generator is not None


class TestKeygenFromAnalysis:
    """Test generate_keygen_from_analysis routing."""

    @staticmethod
    def test_routes_to_md5_generator() -> None:
        """Verify MD5 algorithm routes to MD5 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.MD5)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "MD5" in result.content or "md5" in result.content.lower()

    @staticmethod
    def test_routes_to_sha1_generator() -> None:
        """Verify SHA1 algorithm routes to SHA1 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.SHA1)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "SHA1" in result.content or "sha1" in result.content.lower()

    @staticmethod
    def test_routes_to_crc32_generator() -> None:
        """Verify CRC32 algorithm routes to CRC32 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.CRC32)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "CRC32" in result.content or "crc32" in result.content.lower()

    @staticmethod
    def test_routes_to_xor_generator() -> None:
        """Verify XOR algorithm routes to XOR generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.XOR)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "XOR" in result.content or "xor" in result.content.lower()

    @staticmethod
    def test_routes_to_hwid_generator() -> None:
        """Verify HWID_BASED algorithm routes to HWID generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.HWID_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "HWID" in result.content or "hardware" in result.content.lower()

    @staticmethod
    def test_routes_to_time_based_generator() -> None:
        """Verify TIME_BASED algorithm routes to time generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.TIME_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "TIME" in result.content or "expir" in result.content.lower()

    @staticmethod
    def test_routes_to_feature_flag_generator() -> None:
        """Verify FEATURE_FLAG algorithm routes to feature generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.FEATURE_FLAG,
            feature_flags={"pro": 1, "enterprise": 2},
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "FEATURE" in result.content or "mask" in result.content.lower()


class TestGeneratedScriptSyntax:
    """Test that generated scripts are syntactically valid Python."""

    @staticmethod
    def test_md5_keygen_is_valid_python() -> None:
        """Verify MD5 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.MD5)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated MD5 keygen has syntax error: {e}")

    @staticmethod
    def test_sha1_keygen_is_valid_python() -> None:
        """Verify SHA1 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.SHA1)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated SHA1 keygen has syntax error: {e}")

    @staticmethod
    def test_crc32_keygen_is_valid_python() -> None:
        """Verify CRC32 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.CRC32)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated CRC32 keygen has syntax error: {e}")

    @staticmethod
    def test_xor_keygen_is_valid_python() -> None:
        """Verify XOR keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.XOR)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated XOR keygen has syntax error: {e}")

    @staticmethod
    def test_hwid_keygen_is_valid_python() -> None:
        """Verify HWID keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.HWID_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated HWID keygen has syntax error: {e}")

    @staticmethod
    def test_time_keygen_is_valid_python() -> None:
        """Verify time-based keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.TIME_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated time keygen has syntax error: {e}")

    @staticmethod
    def test_feature_keygen_is_valid_python() -> None:
        """Verify feature flag keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.FEATURE_FLAG,
            feature_flags={"pro": 1},
        )
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated feature keygen has syntax error: {e}")

    @staticmethod
    def test_rsa_keygen_is_valid_python() -> None:
        """Verify RSA keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=RSA_TEST_MODULUS,
            rsa_exponent=RSA_PUBLIC_EXPONENT,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated RSA keygen has syntax error: {e}")

    @staticmethod
    def test_custom_hash_keygen_is_valid_python() -> None:
        """Verify custom hash keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.CUSTOM_HASH)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated custom hash keygen has syntax error: {e}")


class TestGeneratedScriptContent:
    """Test that generated scripts contain required elements."""

    @staticmethod
    def test_includes_shebang() -> None:
        """Verify generated script includes shebang line."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.content.startswith("#!/usr/bin/env python3")

    @staticmethod
    def test_includes_future_annotations() -> None:
        """Verify generated script includes future annotations import."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "from __future__ import annotations" in result.content

    @staticmethod
    def test_includes_keygen_class() -> None:
        """Verify generated script includes Keygen class."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "class Keygen:" in result.content

    @staticmethod
    def test_includes_generate_method() -> None:
        """Verify generated script includes generate method."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "def generate(" in result.content

    @staticmethod
    def test_includes_validate_method() -> None:
        """Verify generated script includes validate method."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "def validate(" in result.content

    @staticmethod
    def test_includes_key_format_constant() -> None:
        """Verify generated script includes KEY_FORMAT constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(key_format=KeyFormat.SERIAL_DASHED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "KEY_FORMAT = " in result.content

    @staticmethod
    def test_includes_key_length_constant() -> None:
        """Verify generated script includes KEY_LENGTH constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(key_length=KEY_LENGTH_25)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "KEY_LENGTH = " in result.content

    @staticmethod
    def test_includes_group_size_constant() -> None:
        """Verify generated script includes GROUP_SIZE constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(group_size=GROUP_SIZE_5)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "GROUP_SIZE = " in result.content


class TestKeyFormatting:
    """Test key formatting functions in generated scripts."""

    @staticmethod
    def test_dashed_format_output() -> None:
        """Verify dashed format produces correct grouping."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            key_format=KeyFormat.SERIAL_DASHED,
            group_size=DEFAULT_GROUP_SIZE,
            key_length=DASHED_KEY_LENGTH_16,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "serial_dashed" in result.content
        assert "GROUP_SEPARATOR = '-'" in result.content

    @staticmethod
    def test_checksum_suffix_inclusion() -> None:
        """Verify checksum suffix configuration."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            checksum_algorithm="crc32",
            checksum_position="suffix",
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "CHECKSUM_ALGORITHM = 'crc32'" in result.content
        assert "CHECKSUM_POSITION = 'suffix'" in result.content

    @staticmethod
    def test_checksum_prefix_inclusion() -> None:
        """Verify checksum prefix configuration."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            checksum_algorithm="crc32",
            checksum_position="prefix",
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "CHECKSUM_POSITION = 'prefix'" in result.content


class TestMagicConstantsInclusion:
    """Test that magic constants are included in generated scripts."""

    @staticmethod
    def test_includes_magic_constants_list() -> None:
        """Verify magic constants are included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            magic_constants=[MAGIC_CONST_DEADBEEF, MAGIC_CONST_CAFEBABE],
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "MAGIC_CONSTANTS" in result.content
        assert "3735928559" in result.content or "0xDEADBEEF" in result.content.upper()


class TestFeatureFlagsInclusion:
    """Test that feature flags are included in generated scripts."""

    @staticmethod
    def test_includes_feature_flags_dict() -> None:
        """Verify feature flags dictionary is included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            feature_flags={"pro": 1, "enterprise": 2, "ultimate": 4},
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "FEATURE_FLAGS" in result.content
        assert '"pro"' in result.content or "'pro'" in result.content


class TestRSAKeygenSpecifics:
    """Test RSA-specific keygen generation."""

    @staticmethod
    def test_includes_rsa_modulus() -> None:
        """Verify RSA modulus is included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=RSA_TEST_MODULUS,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "RSA_MODULUS" in result.content
        assert str(RSA_TEST_MODULUS) in result.content

    @staticmethod
    def test_includes_rsa_exponent() -> None:
        """Verify RSA public exponent is included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=RSA_TEST_MODULUS,
            rsa_exponent=RSA_PUBLIC_EXPONENT,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "RSA_PUBLIC_EXPONENT" in result.content
        assert str(RSA_PUBLIC_EXPONENT) in result.content

    @staticmethod
    def test_includes_rsa_helpers() -> None:
        """Verify RSA helper functions are included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=RSA_TEST_MODULUS,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "_modinv" in result.content
        assert "_rsa_sign" in result.content
        assert "_rsa_verify" in result.content
        assert "_pkcs1_v1_5_encode" in result.content


class TestGeneratedScriptExecution:
    """Test that generated scripts can be executed."""

    @staticmethod
    def test_md5_keygen_executes() -> None:
        """Verify MD5 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=MD5_HEX_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)
        assert len(key) > 0

    @staticmethod
    def test_crc32_keygen_executes() -> None:
        """Verify CRC32 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.CRC32,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=CRC32_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)

    @staticmethod
    def test_sha1_keygen_executes() -> None:
        """Verify SHA1 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.SHA1,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=SHA1_HEX_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)
        assert len(key) == SHA1_HEX_KEY_LENGTH

    @staticmethod
    def test_xor_keygen_executes() -> None:
        """Verify XOR keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.XOR,
            key_format=KeyFormat.HEX_STRING,
            key_length=XOR_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)

    @staticmethod
    def test_generated_key_validates() -> None:
        """Verify generated keys validate correctly."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=MD5_HEX_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        is_valid = keygen.validate("TestUser", key)
        assert is_valid is True

    @staticmethod
    def test_invalid_key_fails_validation() -> None:
        """Verify invalid keys fail validation."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=MD5_HEX_KEY_LENGTH,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        is_valid = keygen.validate("TestUser", "INVALIDKEY12345678901234567890AB")
        assert is_valid is False


class TestDashedKeyFormatExecution:
    """Test dashed key format in executed scripts."""

    @staticmethod
    def test_dashed_key_has_separators() -> None:
        """Verify dashed keys contain separators."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_DASHED,
            key_length=MD5_HEX_KEY_LENGTH,
            group_size=DEFAULT_GROUP_SIZE,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert "-" in key

    @staticmethod
    def test_dashed_key_group_count() -> None:
        """Verify dashed keys have correct group count."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_DASHED,
            key_length=DASHED_KEY_LENGTH_16,
            group_size=DEFAULT_GROUP_SIZE,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        groups = key.split("-")
        assert len(groups) == EXPECTED_DASHED_GROUP_COUNT


class TestChecksumComputation:
    """Test checksum computation in generated scripts."""

    @staticmethod
    def test_crc32_checksum_appended() -> None:
        """Verify CRC32 checksum is appended to key."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=MD5_HEX_KEY_LENGTH,
            checksum_algorithm="crc32",
            checksum_position="suffix",
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert len(key) == KEY_WITH_CHECKSUM_LENGTH


class TestGeneratedScriptMetadata:
    """Test GeneratedScript metadata fields."""

    @staticmethod
    def test_script_has_name() -> None:
        """Verify generated script has a name."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.name is not None
        assert len(result.name) > 0

    @staticmethod
    def test_script_has_description() -> None:
        """Verify generated script has a description."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.description is not None
        assert len(result.description) > 0

    @staticmethod
    def test_script_has_content() -> None:
        """Verify generated script has content."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.content is not None
        assert len(result.content) > MIN_SCRIPT_LENGTH


class TestUnknownAlgorithmHandling:
    """Test handling of unknown algorithm types."""

    @staticmethod
    def test_unknown_algorithm_uses_fallback() -> None:
        """Verify unknown algorithm uses fallback generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.UNKNOWN)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Fallback keygen has syntax error: {e}")
