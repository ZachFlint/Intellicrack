# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The preprocessor preserves pragma metadata in emitted source.

``HexPatPreprocessor.process`` extracts ``#pragma`` directives into ``PragmaInfo`` and
emits each pragma as a comment, so the textual output still records every pragma; a
consumer that re-parses the emitted source keeps the metadata.

``PragmaInfo`` extraction is unchanged, and each pragma is emitted as a
``// hexpat-pragma: <directive>`` comment so the emitted source is self-describing.
The lexer skips ``//`` line comments, so downstream stages are unaffected.
"""

from __future__ import annotations

from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor, extract_pragmas_fast


class TestPreprocessorPreservesPragmas:
    """Emitted source records every #pragma directive as a comment."""

    def test_base_address_directive_recorded_in_output(self) -> None:
        """``#pragma base_address`` survives preprocessing as a comment carrying the literal value."""
        pp = HexPatPreprocessor()
        source = "#pragma base_address 0x1000\nu32 x @ 0;"
        result, pragma = pp.process(source)
        assert pragma.base_address == 0x1000
        assert "0x1000" in result
        assert "hexpat-pragma" in result

    def test_endian_directive_recorded_in_output(self) -> None:
        """``#pragma endian big`` survives preprocessing as a comment."""
        pp = HexPatPreprocessor()
        source = "#pragma endian big\nu32 x @ 0;"
        result, pragma = pp.process(source)
        assert pragma.endian == "big"
        assert "endian" in result
        assert "big" in result

    def test_emitted_pragma_comment_does_not_break_lexer(self) -> None:
        """The lexer must accept the emitted source: pragma comments are valid ``//`` comments.

        This is the regression bar that justifies the comment marker choice:
        keeping the value visible in the source must not introduce a fresh
        lex error.
        """
        pp = HexPatPreprocessor()
        source = "#pragma base_address 0x1000\n#pragma endian big\nstruct Hdr { u32 magic; };"
        result, _ = pp.process(source)
        # If preserving pragmas produced anything the lexer rejects, this raises.
        tokens = HexPatLexer(result).tokenize()
        # And the parser must still accept the resulting token stream.
        nodes = HexPatParser(tokens).parse()
        assert nodes, "preserved-pragma source must still produce AST nodes"

    def test_emitted_source_has_no_raw_pragma_directive(self) -> None:
        """The emitted source must not retain raw ``#pragma`` lines (lexer would reject)."""
        pp = HexPatPreprocessor()
        source = "#pragma base_address 0x1000\nu32 x @ 0;"
        result, _ = pp.process(source)
        for line in result.splitlines():
            assert not line.lstrip().startswith("#pragma")

    def test_extract_pragmas_fast_scans_full_source(self) -> None:
        """``extract_pragmas_fast`` must surface a pragma deeper than line 80.

        The helper must not truncate to ``splitlines()[:80]``, which would silently
        drop any pragma further down.
        """
        body = "\n".join(f"u8 padding_{i} @ {i};" for i in range(120))
        source = body + "\n#pragma base_address 0xDEADBEEF\nu32 final @ 0x200;"
        pragma = extract_pragmas_fast(source)
        assert pragma.base_address == 0xDEADBEEF

    def test_multiple_pragmas_all_preserved(self) -> None:
        """Every pragma directive in the source is emitted as a comment."""
        pp = HexPatPreprocessor()
        source = '#pragma endian big\n#pragma base_address 0x40\n#pragma description "Test"\nu32 x @ 0;'
        result, pragma = pp.process(source)
        assert pragma.endian == "big"
        assert pragma.base_address == 0x40
        assert pragma.description == "Test"
        # All three pragma lines must be visible in the output.
        marker_count: int = sum("hexpat-pragma" in line for line in result.splitlines())
        assert marker_count == 3
