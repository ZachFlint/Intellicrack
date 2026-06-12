# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Preprocessor coverage against the real vendor include corpus.

These tests drive :class:`HexPatPreprocessor` against the genuine
``vendor/ImHex-Patterns/includes`` standard library and a self-contained real
vendor pattern, instead of the two-file temporary-directory setups the
existing suite uses. They prove multi-level include flattening, transitive
``#define`` expansion, function-like macro substitution, and that a real
pattern file is fully normalised (no surviving ``#include`` or ``#pragma``
directives) after preprocessing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.tokens import TokenType


_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_PATTERNS_DIR: Path = _REPO_ROOT / "vendor" / "ImHex-Patterns" / "patterns"
_INCLUDES_DIR: Path = _REPO_ROOT / "vendor" / "ImHex-Patterns" / "includes"


def _require_vendor_includes() -> None:
    """Skip the calling test when the vendor include corpus is unavailable.

    Skipping with a precise reason avoids a fabricated pass when the vendor
    submodule is not checked out.
    """
    if not _INCLUDES_DIR.is_dir():
        pytest.skip(f"vendor include corpus not present at {_INCLUDES_DIR}")


class TestVendorIncludeFlattening:
    """Resolve real multi-level include chains from the std library."""

    def test_std_io_include_is_flattened(self) -> None:
        """Including ``std/io.pat`` inlines its full content and removes the directive.

        The oracle is the actual file on disk: specific function signatures that exist
        only inside ``std/io.pat`` must appear verbatim in the preprocessed output,
        confirming the bridge faithfully inlines the include rather than silently
        dropping or truncating it.  The ``#pragma once`` guard must be consumed so
        it does not appear as a raw directive.  The statement that follows the
        include in the caller must also survive unchanged.  Finally the flattened
        output is tokenized via the real HexPat lexer, confirming it is valid
        HexPat and that exactly four ``fn`` definitions and one ``namespace``
        declaration were inlined.
        """
        _require_vendor_includes()
        io_pat: Path = _INCLUDES_DIR / "std" / "io.pat"
        if not io_pat.is_file():
            pytest.skip(f"std/io.pat not present at {io_pat}")

        # Independent oracle: read the vendor file directly so expected values
        # are NOT derived from the preprocessor's own output.
        io_source: str = io_pat.read_text(encoding="utf-8", errors="replace")

        # Tokens that must appear in the inlined output -- independently verified
        # by reading std/io.pat above.  These are structural identifiers unique to
        # that file that could not be produced by any other means.
        expected_tokens: list[str] = [
            "namespace auto std",
            "fn print(auto fmt, auto ... args)",
            "builtin::std::print(fmt, args);",
            "fn format(auto fmt, auto ... args)",
            "return builtin::std::format(fmt, args);",
            "fn error(str message)",
            "builtin::std::error(message);",
            "fn warning(str message)",
            "builtin::std::warning(message);",
        ]
        # Confirm every expected token actually exists in the vendor file (so the
        # test is not asserting against a constant that was removed upstream).
        for token in expected_tokens:
            assert token in io_source, f"oracle token not found in vendor std/io.pat: {token!r}"

        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        source = "#include <std/io.pat>\nu8 x @ 0;"
        processed, _ = preprocessor.process(source)

        # The include directive itself must be fully consumed.
        assert "#include" not in processed, "raw #include survived preprocessing"

        # The #pragma once guard inside std/io.pat must not survive as a raw
        # directive; the preprocessor transforms it into a comment annotation.
        assert "#pragma once" not in processed, "#pragma once leaked into output"

        # Every structural token from std/io.pat must appear in the output,
        # proving the file was genuinely inlined (not silently dropped).
        for token in expected_tokens:
            assert token in processed, f"std/io.pat token missing from flattened output: {token!r}"

        # The placement statement that follows the include in the caller must be
        # preserved verbatim -- include expansion must not eat surrounding source.
        assert "u8 x @ 0;" in processed, "caller statement after #include was lost"

        # The output must be longer than the caller source alone, confirming
        # file content was injected rather than the directive simply deleted.
        # We use the actual vendor file length as the lower-bound oracle.
        assert len(processed) > len(io_source), (
            f"output ({len(processed)} chars) is not longer than vendor file ({len(io_source)} chars); "
            "include content was not properly inlined"
        )

        # Tokenize the flattened output through the real HexPat lexer to confirm
        # the result is valid HexPat, not garbage.  Expected counts are derived
        # from the vendor file structure (4 fn definitions, 1 namespace block)
        # and verified by independently reading std/io.pat above.
        tokens = HexPatLexer(processed).tokenize()
        assert tokens[-1].type is TokenType.EOF, "tokenizer did not reach EOF on flattened output"
        fn_count: int = sum(1 for t in tokens if t.type is TokenType.FN)
        ns_count: int = sum(1 for t in tokens if t.type is TokenType.NAMESPACE)
        assert fn_count == 4, f"expected 4 fn definitions from std/io.pat inlining, got {fn_count}"
        assert ns_count == 1, f"expected 1 namespace block from std/io.pat inlining, got {ns_count}"

    def test_std_io_include_absent_without_include_path(self) -> None:
        """Without a vendor include path the library content is absent from output.

        This contrast test proves that the tokens verified in
        ``test_std_io_include_is_flattened`` come specifically from inlining
        the file via the include search path, and could not be produced by any
        other mechanism.  When the preprocessor is constructed with an empty
        include path list the ``#include`` directive produces an empty
        expansion: all library declarations must be absent, the directive must
        still be consumed, and the placement statement must survive intact.
        """
        preprocessor = HexPatPreprocessor(include_paths=[])
        processed, _ = preprocessor.process("#include <std/io.pat>\nu8 x @ 0;")

        assert "#include" not in processed, "raw #include directive was not consumed"
        assert "fn print(" not in processed, "fn print appeared without include path"
        assert "namespace auto std" not in processed, "namespace appeared without include path"
        non_empty: list[str] = [line for line in processed.splitlines() if line.strip()]
        assert non_empty == ["u8 x @ 0;"], f"expected only the placement statement without include path, got: {non_empty!r}"

    def test_std_io_pragma_once_prevents_double_inclusion(self) -> None:
        """The ``#pragma once`` guard in ``std/io.pat`` prevents duplicate inlining.

        When the same file is included twice in one translation unit, the second
        directive must produce no additional output -- the preprocessor must track
        pragma-once files and silently suppress re-inclusion.  The flattened output
        must contain each structural function body exactly once.
        """
        _require_vendor_includes()
        io_pat: Path = _INCLUDES_DIR / "std" / "io.pat"
        if not io_pat.is_file():
            pytest.skip(f"std/io.pat not present at {io_pat}")

        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        source = "#include <std/io.pat>\n#include <std/io.pat>\nu8 sentinel @ 0;"
        processed, _ = preprocessor.process(source)

        assert "#include" not in processed

        # The unique marker that identifies whether std/io.pat was duplicated.
        # Count occurrences of a token that appears exactly once in the file;
        # if the file is inlined twice, the count would double.
        marker = "builtin::std::print(fmt, args);"
        count: int = processed.count(marker)
        assert count == 1, f"std/io.pat content appears {count} times in output; pragma-once guard failed"

    def test_missing_include_does_not_raise(self) -> None:
        """A missing include file is silently skipped, not an exception.

        The preprocessor's contract for unavailable optional library files is to
        log a warning and continue rather than abort -- verified by confirming
        no exception propagates and the remainder of the source is intact.
        This test does not require the vendor corpus to be present; it only
        needs the preprocessor to handle an unresolvable include gracefully.
        """
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        source = "#include <std/nonexistent_file_xyzzy.pat>\nu8 x @ 42;"
        processed, _ = preprocessor.process(source)

        # The residual source after the missing include must be preserved.
        assert "u8 x @ 42;" in processed
        # No raw include directive may survive; the line is simply dropped.
        assert "#include" not in processed

    def test_std_core_pulls_transitive_content(self) -> None:
        """Including ``std/core.pat`` resolves its own nested includes."""
        _require_vendor_includes()
        core = _INCLUDES_DIR / "std" / "core.pat"
        if not core.is_file():
            pytest.skip(f"std/core.pat not present at {core}")
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        processed, _ = preprocessor.process("#include <std/core.pat>\nu8 x @ 0;")
        assert "#include" not in processed
        assert len(processed) > 100


class TestTransitiveMacroExpansion:
    """Expand chained and function-like macros to a fixed point."""

    def test_chained_object_macros_expand_transitively(self) -> None:
        """``C -> B -> A -> 5`` expands fully in one ``process`` call."""
        preprocessor = HexPatPreprocessor()
        source = "#define A 5\n#define B A\n#define C B\nu8 x @ C;"
        processed, _ = preprocessor.process(source)
        body = [line for line in processed.splitlines() if line.strip()]
        assert body == ["u8 x @ 5;"]

    def test_function_like_macro_substitutes_arguments(self) -> None:
        """A function-like macro expands positional arguments into its body."""
        preprocessor = HexPatPreprocessor()
        source = "#define SQ(v) ((v) * (v))\nu8 x @ SQ(3);"
        processed, _ = preprocessor.process(source)
        body = [line for line in processed.splitlines() if line.strip()]
        assert body == ["u8 x @ ((3) * (3));"]


class TestVendorPatternFullyNormalised:
    """Preprocess a self-contained real vendor pattern end-to-end."""

    def test_bmp_pattern_has_no_residual_directives(self) -> None:
        """The real BMP pattern preprocesses with no surviving directives."""
        _require_vendor_includes()
        bmp = _PATTERNS_DIR / "bmp.hexpat"
        if not bmp.is_file():
            pytest.skip(f"vendor pattern bmp.hexpat not present at {bmp}")
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        processed, pragma = preprocessor.process(bmp.read_text(encoding="utf-8", errors="replace"), bmp)

        assert "#include" not in processed
        for line in processed.splitlines():
            assert not line.strip().startswith("#pragma"), "raw #pragma survived"
        # The BMP header declares little-endian via pragma; metadata is captured.
        assert pragma.endian == "little"
        # std/mem.pat is pulled in, so the flattened output dwarfs the header.
        assert len(processed) > len(bmp.read_text(encoding="utf-8", errors="replace"))
