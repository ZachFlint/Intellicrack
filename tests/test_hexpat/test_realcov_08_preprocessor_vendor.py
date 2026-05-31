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

from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor


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
        """Including ``std/io.pat`` inlines its content and removes the directive."""
        _require_vendor_includes()
        preprocessor = HexPatPreprocessor(include_paths=[_INCLUDES_DIR])
        source = "#include <std/io.pat>\nu8 x @ 0;"
        processed, _ = preprocessor.process(source)

        assert "#include" not in processed
        assert len(processed) > len(source)
        # The placement statement after the include is preserved verbatim.
        assert "u8 x @ 0;" in processed

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
