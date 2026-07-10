# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit 5 u4 / F-0026 - HexPatCompiler propagates #pragma metadata to JSON.

Before remediation ``HexPatCompiler.compile_to_dict`` skipped the
preprocessor entirely. The static JSON template was emitted with
``default_endianness="little"`` regardless of ``#pragma endian big``, no
``author`` even when ``#pragma author`` was set, and the description was a
hardcoded ``"<Name> (compiled from HexPat DSL)"`` string regardless of
``#pragma description``. ``#pragma magic`` and ``#pragma base_address`` were
likewise silently dropped.

The remediation runs the preprocessor before lexing/parsing and threads the
extracted ``PragmaInfo`` into the codegen so the static template reflects
the user's pragma directives. Runtime constructs continue to be rejected by
the codegen so this fix does not weaken the static-template guarantees.
"""

from __future__ import annotations

import json

import pytest

from intellicrack.core.hexpat.errors import HexPatError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat_compiler import HexPatCodegen, HexPatCompiler


class TestCompilerHonoursPragmaEndian:
    """F-0026: ``#pragma endian`` controls the emitted ``default_endianness``."""

    def test_default_endianness_is_little_when_no_pragma(self) -> None:
        """Patterns with no endian pragma fall back to little endian."""
        source = "struct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["default_endianness"] == "little"

    def test_pragma_endian_big_threads_into_default_endianness(self) -> None:
        """``#pragma endian big`` produces ``default_endianness="big"``."""
        source = "#pragma endian big\nstruct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["default_endianness"] == "big"

    def test_pragma_endian_little_threads_into_default_endianness(self) -> None:
        """``#pragma endian little`` produces ``default_endianness="little"`` explicitly."""
        source = "#pragma endian little\nstruct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["default_endianness"] == "little"


class TestCompilerHonoursPragmaDescription:
    """F-0026: ``#pragma description`` populates the template description."""

    def test_pragma_description_used_as_template_description(self) -> None:
        """``#pragma description "<text>"`` sets the JSON template description."""
        source = '#pragma description "Custom PE description"\nstruct Hdr { u32 magic; };'
        result = HexPatCompiler.compile_to_dict(source)
        assert result["description"] == "Custom PE description"

    def test_no_pragma_falls_back_to_generic_description(self) -> None:
        """Without a pragma the template description names the struct."""
        source = "struct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert "Hdr" in result["description"]


class TestCompilerHonoursPragmaAuthor:
    """F-0026: ``#pragma author`` populates the template ``author`` field."""

    def test_pragma_author_emitted_as_author_field(self) -> None:
        """``#pragma author "<name>"`` sets the JSON template ``author`` field."""
        source = '#pragma author "Test Author"\nstruct Hdr { u32 magic; };'
        result = HexPatCompiler.compile_to_dict(source)
        assert result["author"] == "Test Author"

    def test_no_pragma_omits_author_field(self) -> None:
        """Without a pragma the ``author`` key is absent from the template."""
        source = "struct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert "author" not in result


class TestCompilerHonoursPragmaMagic:
    """F-0026: ``#pragma magic`` populates ``magic_detection``."""

    def test_pragma_magic_emitted_as_magic_detection(self) -> None:
        """``#pragma magic [0x0, "4D5A"]`` sets ``magic_detection``."""
        source = '#pragma magic [0x0, "4D5A"]\nstruct Hdr { u32 magic; };'
        result = HexPatCompiler.compile_to_dict(source)
        magic = result["magic_detection"]
        assert magic["offset"] == 0
        assert magic["bytes"] == [0x4D, 0x5A]

    def test_no_pragma_omits_magic_detection_field(self) -> None:
        """Without a pragma the ``magic_detection`` key is absent."""
        source = "struct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert "magic_detection" not in result


class TestCompilerHonoursPragmaMetadata:
    """F-0026: ``#pragma base_address`` and ``#pragma bitfield_order`` are recorded."""

    def test_pragma_base_address_emitted_in_metadata(self) -> None:
        """``#pragma base_address`` is recorded under ``pragma_metadata.base_address``."""
        source = "#pragma base_address 0x1000\nstruct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["pragma_metadata"]["base_address"] == 0x1000

    def test_pragma_bitfield_order_emitted_in_metadata(self) -> None:
        """``#pragma bitfield_order`` is recorded under ``pragma_metadata.bitfield_order``."""
        source = "#pragma bitfield_order left_to_right\nstruct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["pragma_metadata"]["bitfield_order"] == "left_to_right"

    def test_no_metadata_pragmas_omits_metadata_field(self) -> None:
        """Without any metadata-only pragmas the ``pragma_metadata`` key is absent."""
        source = "struct Hdr { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert "pragma_metadata" not in result


class TestCompilerOutputIsValidJson:
    """F-0026: the emitted dict round-trips through JSON serialisation."""

    def test_compile_emits_json_serialisable_output(self) -> None:
        """The dict from ``compile_to_dict`` must serialise via ``json.dumps``."""
        source = (
            "#pragma endian big\n"
            "#pragma base_address 0x40\n"
            '#pragma author "ACME"\n'
            '#pragma description "ACME format"\n'
            "struct Hdr { u32 magic; };"
        )
        result = HexPatCompiler.compile_to_dict(source)
        text = json.dumps(result)
        # The serialised form must contain every pragma value, proving the
        # compiler now propagates them into the static template.
        assert "big" in text
        assert "ACME" in text
        assert "ACME format" in text
        assert "0x40" not in text  # serialised as decimal 64
        assert '"base_address": 64' in text


class TestCompilerStillRejectsRuntimeConstructs:
    """F-0026 fix must not weaken the existing static-template guarantees."""

    def test_function_decl_still_rejected(self) -> None:
        """Top-level functions remain runtime-only and must raise ``HexPatError``."""
        source = "fn double(u32 x) { return x * 2; };\nstruct Hdr { u32 magic; };"
        with pytest.raises(HexPatError):
            HexPatCompiler.compile_to_dict(source)


class TestCodegenAcceptsPragmaArg:
    """The codegen constructor accepts a ``pragma`` keyword for direct callers."""

    def test_codegen_constructor_optional_pragma_default_omits_metadata(self) -> None:
        """When no pragma is supplied, the codegen falls back to legacy defaults."""
        tokens = HexPatLexer("struct Hdr { u32 magic; };").tokenize()
        decls = HexPatParser(tokens).parse()
        codegen = HexPatCodegen(list(decls))
        result = codegen.generate()
        assert result["default_endianness"] == "little"
        assert "author" not in result
        assert "magic_detection" not in result
        assert "pragma_metadata" not in result
