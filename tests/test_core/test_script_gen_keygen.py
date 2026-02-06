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


def create_test_analysis(
    algorithm: AlgorithmType = AlgorithmType.MD5,
    key_format: KeyFormat = KeyFormat.SERIAL_DASHED,
    key_length: int = 32,
    group_size: int = 4,
    checksum_algorithm: str | None = None,
    checksum_position: ChecksumPosition | None = None,
    feature_flags: dict[str, int] | None = None,
    magic_constants: list[int] | None = None,
    rsa_modulus: int = 0,
    rsa_exponent: int = 65537,
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
                address=0x1000 + i * 4,
                usage_context="test",
                bit_width=32,
            )
            for i, val in enumerate(magic_constants)
        )
    if rsa_modulus:
        constants.extend((
            MagicConstant(
                value=rsa_modulus,
                address=0x5000,
                usage_context="rsa_modulus",
                bit_width=rsa_modulus.bit_length(),
            ),
            MagicConstant(
                value=rsa_exponent,
                address=0x5008,
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
        confidence_score=0.8,
        analysis_notes=[],
    )


class TestScriptGeneratorInitialization:
    """Test ScriptGenerator construction."""

    def test_default_initialization(self) -> None:
        """Verify default ScriptGenerator creation."""
        generator = ScriptGenerator()
        assert generator is not None


class TestKeygenFromAnalysis:
    """Test generate_keygen_from_analysis routing."""

    def test_routes_to_md5_generator(self) -> None:
        """Verify MD5 algorithm routes to MD5 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.MD5)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "MD5" in result.content or "md5" in result.content.lower()

    def test_routes_to_sha1_generator(self) -> None:
        """Verify SHA1 algorithm routes to SHA1 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.SHA1)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "SHA1" in result.content or "sha1" in result.content.lower()

    def test_routes_to_crc32_generator(self) -> None:
        """Verify CRC32 algorithm routes to CRC32 generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.CRC32)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "CRC32" in result.content or "crc32" in result.content.lower()

    def test_routes_to_xor_generator(self) -> None:
        """Verify XOR algorithm routes to XOR generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.XOR)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "XOR" in result.content or "xor" in result.content.lower()

    def test_routes_to_hwid_generator(self) -> None:
        """Verify HWID_BASED algorithm routes to HWID generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.HWID_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "HWID" in result.content or "hardware" in result.content.lower()

    def test_routes_to_time_based_generator(self) -> None:
        """Verify TIME_BASED algorithm routes to time generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.TIME_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        assert "TIME" in result.content or "expir" in result.content.lower()

    def test_routes_to_feature_flag_generator(self) -> None:
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

    def test_md5_keygen_is_valid_python(self) -> None:
        """Verify MD5 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.MD5)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated MD5 keygen has syntax error: {e}")

    def test_sha1_keygen_is_valid_python(self) -> None:
        """Verify SHA1 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.SHA1)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated SHA1 keygen has syntax error: {e}")

    def test_crc32_keygen_is_valid_python(self) -> None:
        """Verify CRC32 keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.CRC32)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated CRC32 keygen has syntax error: {e}")

    def test_xor_keygen_is_valid_python(self) -> None:
        """Verify XOR keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.XOR)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated XOR keygen has syntax error: {e}")

    def test_hwid_keygen_is_valid_python(self) -> None:
        """Verify HWID keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.HWID_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated HWID keygen has syntax error: {e}")

    def test_time_keygen_is_valid_python(self) -> None:
        """Verify time-based keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.TIME_BASED)
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated time keygen has syntax error: {e}")

    def test_feature_keygen_is_valid_python(self) -> None:
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

    def test_rsa_keygen_is_valid_python(self) -> None:
        """Verify RSA keygen produces valid Python syntax."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=17 * 19,
            rsa_exponent=65537,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Generated RSA keygen has syntax error: {e}")

    def test_custom_hash_keygen_is_valid_python(self) -> None:
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

    def test_includes_shebang(self) -> None:
        """Verify generated script includes shebang line."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.content.startswith("#!/usr/bin/env python3")

    def test_includes_future_annotations(self) -> None:
        """Verify generated script includes future annotations import."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "from __future__ import annotations" in result.content

    def test_includes_keygen_class(self) -> None:
        """Verify generated script includes Keygen class."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "class Keygen:" in result.content

    def test_includes_generate_method(self) -> None:
        """Verify generated script includes generate method."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "def generate(" in result.content

    def test_includes_validate_method(self) -> None:
        """Verify generated script includes validate method."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert "def validate(" in result.content

    def test_includes_key_format_constant(self) -> None:
        """Verify generated script includes KEY_FORMAT constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(key_format=KeyFormat.SERIAL_DASHED)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "KEY_FORMAT = " in result.content

    def test_includes_key_length_constant(self) -> None:
        """Verify generated script includes KEY_LENGTH constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(key_length=25)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "KEY_LENGTH = " in result.content

    def test_includes_group_size_constant(self) -> None:
        """Verify generated script includes GROUP_SIZE constant."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(group_size=5)
        result = generator.generate_keygen_from_analysis(analysis)
        assert "GROUP_SIZE = " in result.content


class TestKeyFormatting:
    """Test key formatting functions in generated scripts."""

    def test_dashed_format_output(self) -> None:
        """Verify dashed format produces correct grouping."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            key_format=KeyFormat.SERIAL_DASHED,
            group_size=4,
            key_length=16,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "serial_dashed" in result.content
        assert "GROUP_SEPARATOR = '-'" in result.content

    def test_checksum_suffix_inclusion(self) -> None:
        """Verify checksum suffix configuration."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            checksum_algorithm="crc32",
            checksum_position="suffix",
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "CHECKSUM_ALGORITHM = 'crc32'" in result.content
        assert "CHECKSUM_POSITION = 'suffix'" in result.content

    def test_checksum_prefix_inclusion(self) -> None:
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

    def test_includes_magic_constants_list(self) -> None:
        """Verify magic constants are included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            magic_constants=[0xDEADBEEF, 0xCAFEBABE],
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "MAGIC_CONSTANTS" in result.content
        assert "3735928559" in result.content or "0xDEADBEEF" in result.content.upper()


class TestFeatureFlagsInclusion:
    """Test that feature flags are included in generated scripts."""

    def test_includes_feature_flags_dict(self) -> None:
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

    def test_includes_rsa_modulus(self) -> None:
        """Verify RSA modulus is included."""
        generator = ScriptGenerator()
        test_modulus = 17 * 19
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=test_modulus,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "RSA_MODULUS" in result.content
        assert str(test_modulus) in result.content

    def test_includes_rsa_exponent(self) -> None:
        """Verify RSA public exponent is included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=17 * 19,
            rsa_exponent=65537,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "RSA_PUBLIC_EXPONENT" in result.content
        assert "65537" in result.content

    def test_includes_rsa_helpers(self) -> None:
        """Verify RSA helper functions are included."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.RSA,
            rsa_modulus=17 * 19,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        assert "_modinv" in result.content
        assert "_rsa_sign" in result.content
        assert "_rsa_verify" in result.content
        assert "_pkcs1_v1_5_encode" in result.content


class TestGeneratedScriptExecution:
    """Test that generated scripts can be executed."""

    def test_md5_keygen_executes(self) -> None:
        """Verify MD5 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=32,
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

    def test_crc32_keygen_executes(self) -> None:
        """Verify CRC32 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.CRC32,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=8,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)

    def test_sha1_keygen_executes(self) -> None:
        """Verify SHA1 keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.SHA1,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=40,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)
        assert len(key) == 40

    def test_xor_keygen_executes(self) -> None:
        """Verify XOR keygen script executes without error."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.XOR,
            key_format=KeyFormat.HEX_STRING,
            key_length=16,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert isinstance(key, str)

    def test_generated_key_validates(self) -> None:
        """Verify generated keys validate correctly."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=32,
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

    def test_invalid_key_fails_validation(self) -> None:
        """Verify invalid keys fail validation."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=32,
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

    def test_dashed_key_has_separators(self) -> None:
        """Verify dashed keys contain separators."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_DASHED,
            key_length=32,
            group_size=4,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        assert "-" in key

    def test_dashed_key_group_count(self) -> None:
        """Verify dashed keys have correct group count."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_DASHED,
            key_length=16,
            group_size=4,
        )
        result = generator.generate_keygen_from_analysis(analysis)
        exec_globals: dict[str, Any] = {}
        exec(result.content, exec_globals)
        keygen_class = exec_globals.get("Keygen")
        assert keygen_class is not None
        keygen = keygen_class()
        key = keygen.generate("TestUser")
        groups = key.split("-")
        assert len(groups) == 4


class TestChecksumComputation:
    """Test checksum computation in generated scripts."""

    def test_crc32_checksum_appended(self) -> None:
        """Verify CRC32 checksum is appended to key."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(
            algorithm=AlgorithmType.MD5,
            key_format=KeyFormat.SERIAL_PLAIN,
            key_length=32,
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
        assert len(key) == 32 + 8


class TestGeneratedScriptMetadata:
    """Test GeneratedScript metadata fields."""

    def test_script_has_name(self) -> None:
        """Verify generated script has a name."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.name is not None
        assert len(result.name) > 0

    def test_script_has_description(self) -> None:
        """Verify generated script has a description."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.description is not None
        assert len(result.description) > 0

    def test_script_has_content(self) -> None:
        """Verify generated script has content."""
        generator = ScriptGenerator()
        analysis = create_test_analysis()
        result = generator.generate_keygen_from_analysis(analysis)
        assert result.content is not None
        assert len(result.content) > 100


class TestUnknownAlgorithmHandling:
    """Test handling of unknown algorithm types."""

    def test_unknown_algorithm_uses_fallback(self) -> None:
        """Verify unknown algorithm uses fallback generator."""
        generator = ScriptGenerator()
        analysis = create_test_analysis(algorithm=AlgorithmType.UNKNOWN)
        result = generator.generate_keygen_from_analysis(analysis)
        assert isinstance(result, GeneratedScript)
        try:
            ast.parse(result.content)
        except SyntaxError as e:
            pytest.fail(f"Fallback keygen has syntax error: {e}")
