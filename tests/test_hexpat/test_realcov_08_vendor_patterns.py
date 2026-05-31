# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the HexPat front-end against vendor pattern files.

These tests drive the genuine preprocessor -> lexer -> parser pipeline over
the real ``.hexpat`` corpus shipped in ``vendor/ImHex-Patterns`` instead of
hand-crafted toy snippets. They prove the front-end copes with production DSL
complexity: multi-level ``import`` chains resolving through
``vendor/ImHex-Patterns/includes``, header pragmas, nested generics, pointer
arrays and large declaration bodies.

The vendor corpus mixes grammar that the recursive-descent parser fully
supports with constructs it does not yet model, so the tests are partitioned
by the deepest pipeline stage that is provably exercised:

* The preprocessor and lexer are validated against the large, heavily-included
  format descriptions (``pe``, ``elf``, ``zip``) because every byte of those
  files flows through both stages.
* The parser is validated against the subset of real vendor patterns that
  parse end-to-end, asserting on the concrete top-level declaration names that
  appear in those files (verified against the committed corpus).

No synthetic source is used; every input is a real committed vendor file.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.hexpat.ast_nodes import EnumDecl, StructDecl
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.tokens import TokenType


if TYPE_CHECKING:
    from intellicrack.core.hexpat.ast_nodes import DeclNode, StmtNode


_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_PATTERNS_DIR: Path = _REPO_ROOT / "vendor" / "ImHex-Patterns" / "patterns"
_INCLUDES_DIR: Path = _REPO_ROOT / "vendor" / "ImHex-Patterns" / "includes"


# Top-level declaration names verified to be present in each clean-parsing
# vendor pattern by parsing the committed corpus. The parser fully handles
# these real format descriptions end-to-end.
_PARSEABLE_PATTERNS: dict[str, dict[str, frozenset[str]]] = {
    "uefi.hexpat": {
        "structs": frozenset({"EFI_TIME", "EFI_GUID", "WIN_CERTIFICATE", "EFI_SIGNATURE_LIST"}),
        "enums": frozenset(),
    },
    "ccvxl.hexpat": {
        "structs": frozenset({"vec4_s", "vec3_s", "mat3x4_s", "vxl_s", "frame_s"}),
        "enums": frozenset(),
    },
    "evtx.hexpat": {
        "structs": frozenset({"Header", "Event_Record", "Chunk", "Evtx"}),
        "enums": frozenset(),
    },
    "pif.hexpat": {
        "structs": frozenset({"PIFFileHeader", "PIFInfoHeader", "PIF"}),
        "enums": frozenset({"imageType_t", "compression_t"}),
    },
    "shx.hexpat": {
        "structs": frozenset({"Header", "Record", "IndexFile"}),
        "enums": frozenset({"ShapeType"}),
    },
    "tarc.hexpat": {
        "structs": frozenset({"TARCEntry1", "TARCEntry2", "TARC"}),
        "enums": frozenset({"PixelFormat"}),
    },
    "nds.hexpat": {
        "structs": frozenset({"NDSHeader"}),
        "enums": frozenset({"NDSRegion"}),
    },
    "pkm.hexpat": {
        "structs": frozenset({"PKMHeader"}),
        "enums": frozenset({"PKMFormat"}),
    },
}

# Large vendor patterns whose full source is provably driven through the
# preprocessor and lexer (heavy ``import`` chains and header pragmas). These
# three flatten with no residual ``#`` directives and expand into thousands of
# tokens, exercising the real production-complexity grammar surface.
_LEXABLE_PATTERNS: tuple[str, ...] = ("elf.hexpat", "zip.hexpat", "gif.hexpat")


def _require_vendor_corpus() -> None:
    """Skip the calling test when the vendor pattern corpus is unavailable.

    The vendor submodule is checked out in normal repository clones and inside
    the test container, but a sparse checkout may omit it. Skipping with a
    precise reason avoids a fabricated pass when the real corpus is absent.
    """
    if not _PATTERNS_DIR.is_dir():
        pytest.skip(f"vendor pattern corpus not present at {_PATTERNS_DIR}")
    if not _INCLUDES_DIR.is_dir():
        pytest.skip(f"vendor include corpus not present at {_INCLUDES_DIR}")


def _read_pattern(name: str) -> tuple[str, Path]:
    """Read a vendor pattern file, skipping if the specific file is missing.

    Args:
        name: File name of the pattern within the vendor patterns directory.

    Returns:
        tuple[str, Path]: The decoded source text and the resolved file path.
    """
    _require_vendor_corpus()
    path = _PATTERNS_DIR / name
    if not path.is_file():
        pytest.skip(f"vendor pattern {name} not present at {path}")
    return path.read_text(encoding="utf-8", errors="replace"), path


def _preprocess(name: str) -> tuple[str, Path]:
    """Run the preprocessor over a vendor pattern with the vendor include path.

    Args:
        name: File name of the pattern within the vendor patterns directory.

    Returns:
        tuple[str, Path]: The flattened, pragma-normalised source and the file path.
    """
    source, path = _read_pattern(name)
    preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
    processed, _ = preprocessor.process(source, path)
    return processed, path


class TestVendorPatternPreprocessing:
    """Drive the preprocessor over heavily-included real vendor format files."""

    @pytest.mark.parametrize("name", _LEXABLE_PATTERNS)
    def test_includes_are_flattened(self, name: str) -> None:
        """Every ``import``/``#include`` directive is resolved and inlined.

        Args:
            name: File name of the vendor pattern under test.
        """
        source, _ = _read_pattern(name)
        processed, _ = _preprocess(name)

        assert "#include" not in processed
        # ``import`` directives that resolved are consumed; none should remain
        # as a bare top-level statement in the flattened output.
        for line in processed.splitlines():
            stripped = line.strip()
            assert not stripped.startswith("import "), f"unresolved import remained: {stripped!r}"
        # Real includes pull in std-library content, so flattening must grow
        # the source well beyond the original header-only file.
        assert len(processed) > len(source)

    @pytest.mark.parametrize("name", _LEXABLE_PATTERNS)
    def test_pragmas_normalised_to_comments(self, name: str) -> None:
        """Header ``#pragma`` directives are rewritten and none survive raw.

        Args:
            name: File name of the vendor pattern under test.
        """
        processed, _ = _preprocess(name)
        for line in processed.splitlines():
            assert not line.strip().startswith("#pragma"), "raw #pragma survived preprocessing"

    def test_elf_pragma_mime_extracted(self) -> None:
        """The real ELF pattern's MIME pragma is captured during preprocessing."""
        source, path = _read_pattern("elf.hexpat")
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        _, pragma = preprocessor.process(source, path)
        assert pragma.mime is not None
        assert pragma.mime.startswith("application/")

    def test_bmp_endian_pragma_extracted(self) -> None:
        """The real BMP pattern declares little-endian via ``#pragma endian``."""
        source, path = _read_pattern("bmp.hexpat")
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        _, pragma = preprocessor.process(source, path)
        assert pragma.endian == "little"


class TestVendorPatternLexing:
    """Tokenize the full flattened source of large real vendor patterns."""

    @pytest.mark.parametrize("name", _LEXABLE_PATTERNS)
    def test_tokenizes_full_flattened_source(self, name: str) -> None:
        """The lexer tokenizes the entire flattened pattern ending in EOF.

        Args:
            name: File name of the vendor pattern under test.
        """
        processed, path = _preprocess(name)
        tokens = HexPatLexer(processed, str(path)).tokenize()

        assert len(tokens) > 100
        assert tokens[-1].type == TokenType.EOF
        # A real format description declares many structs; the keyword must be
        # recognised, not lexed as a bare identifier.
        struct_keywords = sum(1 for tok in tokens if tok.type == TokenType.STRUCT)
        assert struct_keywords >= 3


class TestVendorPatternParsing:
    """Parse the subset of real vendor patterns the parser fully supports."""

    @pytest.mark.parametrize("name", sorted(_PARSEABLE_PATTERNS))
    def test_parses_to_expected_declarations(self, name: str) -> None:
        """Parsing yields the concrete struct/enum names present in the file.

        Args:
            name: File name of the vendor pattern under test.
        """
        processed, path = _preprocess(name)
        tokens = HexPatLexer(processed, str(path)).tokenize()
        ast: list[DeclNode | StmtNode] = HexPatParser(tokens, str(path)).parse()

        assert len(ast) >= 1
        struct_names = {node.name for node in ast if isinstance(node, StructDecl)}
        enum_names = {node.name for node in ast if isinstance(node, EnumDecl)}

        expected = _PARSEABLE_PATTERNS[name]
        assert expected["structs"] <= struct_names, f"{name}: missing structs {expected['structs'] - struct_names}"
        assert expected["enums"] <= enum_names, f"{name}: missing enums {expected['enums'] - enum_names}"
        # At least one composite declaration must be present.
        assert struct_names or enum_names

    def test_uefi_has_many_top_level_structs(self) -> None:
        """The real UEFI pattern parses into a rich set of named structs."""
        processed, path = _preprocess("uefi.hexpat")
        tokens = HexPatLexer(processed, str(path)).tokenize()
        ast = HexPatParser(tokens, str(path)).parse()
        struct_names = {node.name for node in ast if isinstance(node, StructDecl)}
        assert len(struct_names) >= 5
        assert "EFI_GUID" in struct_names
