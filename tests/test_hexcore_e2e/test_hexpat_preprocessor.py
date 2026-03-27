# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat preprocessor directive handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.hexpat.errors import HexPatPreprocessorError
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor, extract_pragmas_fast


if TYPE_CHECKING:
    from pathlib import Path


class TestDefineExpansion:
    """Tests that #define macros expand correctly in source code."""

    def test_single_define_expands_in_expression(self) -> None:
        """Single #define replaces all occurrences in the source body."""
        pp = HexPatPreprocessor()
        source = "#define MAGIC 0xDEAD\nu32 val @ MAGIC;"
        result, _ = pp.process(source)
        assert "0xDEAD" in result
        assert "MAGIC" not in result.replace("#define MAGIC 0xDEAD", "")

    def test_multiple_defines_all_expand(self) -> None:
        """Multiple #define directives each expand their respective tokens."""
        pp = HexPatPreprocessor()
        source = (
            "#define OFFSET_A 0x10\n"
            "#define OFFSET_B 0x20\n"
            "u8 a @ OFFSET_A;\n"
            "u8 b @ OFFSET_B;"
        )
        result, _ = pp.process(source)
        assert "0x10" in result
        assert "0x20" in result

    def test_define_with_no_value_records_name(self) -> None:
        """#define with no value registers the macro name for ifdef checks."""
        pp = HexPatPreprocessor()
        source = "#define MY_FLAG\n#ifdef MY_FLAG\nu8 x @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 x @ 0;" in result

    def test_define_value_used_in_array_size(self) -> None:
        """#define value substitutes correctly inside an array size expression."""
        pp = HexPatPreprocessor()
        source = "#define COUNT 4\nu8 arr[COUNT] @ 0;"
        result, _ = pp.process(source)
        assert "arr[4]" in result

    def test_define_replaces_all_occurrences(self) -> None:
        """#define replacement applies to every occurrence in the file."""
        pp = HexPatPreprocessor()
        source = "#define SZ 8\nu8 a[SZ] @ 0;\nu8 b[SZ] @ SZ;"
        result, _ = pp.process(source)
        assert result.count("8") >= 3

    def test_define_stripped_from_output(self) -> None:
        """#define directives themselves do not appear in the processed output as non-empty lines."""
        pp = HexPatPreprocessor()
        source = "#define FOO 42\nu32 x @ 0;"
        result, _ = pp.process(source)
        non_empty = [ln for ln in result.splitlines() if ln.strip()]
        assert all("#define" not in ln for ln in non_empty)


class TestPragmaDirectives:
    """Tests for #pragma directive extraction."""

    def test_pragma_endian_little(self) -> None:
        """#pragma endian little sets PragmaInfo.endian to 'little'."""
        pp = HexPatPreprocessor()
        source = "#pragma endian little\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.endian == "little"

    def test_pragma_endian_big(self) -> None:
        """#pragma endian big sets PragmaInfo.endian to 'big'."""
        pp = HexPatPreprocessor()
        source = "#pragma endian big\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.endian == "big"

    def test_pragma_endian_native_maps_to_little(self) -> None:
        """#pragma endian native is normalised to 'little'."""
        pp = HexPatPreprocessor()
        source = "#pragma endian native\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.endian == "little"

    def test_pragma_description_extracted(self) -> None:
        """#pragma description string is captured in PragmaInfo."""
        pp = HexPatPreprocessor()
        source = '#pragma description "PE binary format"\nu32 x @ 0;'
        _, pragma = pp.process(source)
        assert pragma.description == "PE binary format"

    def test_pragma_author_extracted(self) -> None:
        """#pragma author string is captured in PragmaInfo."""
        pp = HexPatPreprocessor()
        source = '#pragma author "Test Author"\nu32 x @ 0;'
        _, pragma = pp.process(source)
        assert pragma.author == "Test Author"

    def test_pragma_mime_extracted(self) -> None:
        """#pragma MIME type is captured in PragmaInfo."""
        pp = HexPatPreprocessor()
        source = "#pragma MIME application/x-pe\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.mime == "application/x-pe"

    def test_pragma_magic_extracted(self) -> None:
        """#pragma magic bytes are extracted as (offset, bytes) tuples."""
        pp = HexPatPreprocessor()
        source = '#pragma magic [0x0, "4D5A"]\nu32 x @ 0;'
        _, pragma = pp.process(source)
        assert len(pragma.magic) == 1
        assert pragma.magic[0][0] == 0
        assert pragma.magic[0][1] == b"\x4D\x5A"

    def test_pragma_eval_depth_extracted(self) -> None:
        """#pragma eval_depth value is captured in PragmaInfo."""
        pp = HexPatPreprocessor()
        source = "#pragma eval_depth 64\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.eval_depth == 64

    def test_pragma_array_limit_hex(self) -> None:
        """#pragma array_limit supports hex values."""
        pp = HexPatPreprocessor()
        source = "#pragma array_limit 0x100\nu32 x @ 0;"
        _, pragma = pp.process(source)
        assert pragma.array_limit == 0x100

    def test_pragma_stripped_from_output_lines(self) -> None:
        """#pragma lines are replaced with empty lines in processed output."""
        pp = HexPatPreprocessor()
        source = '#pragma description "Test"\nu32 x @ 0;'
        result, _ = pp.process(source)
        non_empty = [ln for ln in result.splitlines() if ln.strip()]
        assert all("#pragma" not in ln for ln in non_empty)

    def test_extract_pragmas_fast_description(self) -> None:
        """extract_pragmas_fast returns description without full preprocessing."""
        source = '#pragma description "Fast Extract"\nu32 x @ 0;'
        pragma = extract_pragmas_fast(source)
        assert pragma.description == "Fast Extract"

    def test_extract_pragmas_fast_author(self) -> None:
        """extract_pragmas_fast returns author without full preprocessing."""
        source = '#pragma author "Quick Author"\nu32 x @ 0;'
        pragma = extract_pragmas_fast(source)
        assert pragma.author == "Quick Author"


class TestIncludeResolution:
    """Tests for #include directive file resolution."""

    def test_include_quote_resolves_from_same_dir(self, tmp_path: Path) -> None:
        """#include "file.hexpat" resolves relative to the including file.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        child = tmp_path / "child.hexpat"
        child.write_text("u8 included_field @ 0;", encoding="utf-8")
        parent = tmp_path / "parent.hexpat"
        parent.write_text('#include "child.hexpat"', encoding="utf-8")

        pp = HexPatPreprocessor()
        result, _ = pp.process(parent.read_text(), parent)
        assert "included_field" in result

    def test_include_angle_resolves_from_include_paths(self, tmp_path: Path) -> None:
        """#include <file.hexpat> resolves from configured include_paths.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "mylib.hexpat").write_text("u16 lib_field @ 0;", encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[lib_dir])
        source = "#include <mylib.hexpat>"
        result, _ = pp.process(source)
        assert "lib_field" in result

    def test_include_missing_does_not_raise(self) -> None:
        """Missing #include produces an empty substitution (logged warning)."""
        pp = HexPatPreprocessor()
        source = "#include <nonexistent_file.hexpat>\nu32 x @ 0;"
        result, _ = pp.process(source)
        assert "u32 x @ 0;" in result

    def test_pragma_once_prevents_double_include(self, tmp_path: Path) -> None:
        """#pragma once in an included file prevents it from being inlined twice.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        child = tmp_path / "once.hexpat"
        child.write_text("#pragma once\nu8 once_field @ 0;", encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        source = '#include "once.hexpat"\n#include "once.hexpat"'
        result, _ = pp.process(source, tmp_path / "main.hexpat")
        assert result.count("once_field") == 1


class TestNestedDefines:
    """Tests for defines that reference other defines."""

    def test_define_referencing_define(self) -> None:
        """A #define whose value contains another macro name is expanded transitively."""
        pp = HexPatPreprocessor()
        source = "#define BASE 16\n#define OFFSET BASE\nu32 x @ OFFSET;"
        result, _ = pp.process(source)
        assert "16" in result

    def test_two_defines_independent(self) -> None:
        """Two unrelated defines each expand independently."""
        pp = HexPatPreprocessor()
        source = "#define A 100\n#define B 200\nu32 x @ A;\nu32 y @ B;"
        result, _ = pp.process(source)
        assert "100" in result
        assert "200" in result


class TestConditionalPreprocessor:
    """Tests for #ifdef / #ifndef / #else / #endif conditional blocks."""

    def test_ifdef_defined_includes_body(self) -> None:
        """#ifdef on a defined macro includes the conditional body."""
        pp = HexPatPreprocessor()
        source = "#define ENABLED\n#ifdef ENABLED\nu8 x @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 x @ 0;" in result

    def test_ifdef_undefined_excludes_body(self) -> None:
        """#ifdef on an undefined macro excludes the conditional body."""
        pp = HexPatPreprocessor()
        source = "#ifdef UNDEFINED_MACRO\nu8 x @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 x @ 0;" not in result

    def test_ifndef_undefined_includes_body(self) -> None:
        """#ifndef on an undefined macro includes the conditional body."""
        pp = HexPatPreprocessor()
        source = "#ifndef NOT_DEFINED\nu8 x @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 x @ 0;" in result

    def test_ifndef_defined_excludes_body(self) -> None:
        """#ifndef on a defined macro excludes the conditional body."""
        pp = HexPatPreprocessor()
        source = "#define IS_DEF\n#ifndef IS_DEF\nu8 x @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 x @ 0;" not in result

    def test_ifdef_else_takes_else_branch(self) -> None:
        """#ifdef/#else selects the else branch when macro is not defined."""
        pp = HexPatPreprocessor()
        source = "#ifdef NOT_DEF\nu8 a @ 0;\n#else\nu8 b @ 0;\n#endif"
        result, _ = pp.process(source)
        assert "u8 b @ 0;" in result
        assert "u8 a @ 0;" not in result

    def test_error_directive_raises(self) -> None:
        """#error directive raises HexPatPreprocessorError."""
        pp = HexPatPreprocessor()
        source = '#error "intentional test error"'
        with pytest.raises(HexPatPreprocessorError):
            pp.process(source)
