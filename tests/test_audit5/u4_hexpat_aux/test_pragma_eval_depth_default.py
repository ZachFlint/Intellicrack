# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit 5 u4 / F-0028 - PragmaInfo.eval_depth default handles common patterns.

Before remediation the default ``eval_depth`` was ``32``. Common
``parent``-relative and recursive struct patterns from the upstream vendor
pattern collection (for example ``tiff.hexpat`` which explicitly bumps the
limit to ``100``) routinely exceed that depth and abort partway through
evaluation. The remediation lifts the default to a value that handles
real-world patterns while still bounding accidental unbounded recursion.

The new default is exposed as ``DEFAULT_EVAL_DEPTH`` in
``intellicrack.core.hexpat.pragma`` so the preprocessor and any other
consumers share a single source of truth.
"""

from __future__ import annotations

from intellicrack.core.hexpat.pragma import (
    DEFAULT_ARRAY_LIMIT,
    DEFAULT_EVAL_DEPTH,
    DEFAULT_PATTERN_LIMIT,
    DEFAULT_POINTER_SIZE,
    PragmaInfo,
)
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor, extract_pragmas_fast


class TestPragmaDefaultEvalDepth:
    """F-0028: default eval_depth is high enough for common parent/recursive patterns."""

    def test_default_eval_depth_handles_tiff_pattern(self) -> None:
        """The default must clear the bar that ``tiff.hexpat`` sets explicitly.

        The upstream vendor pattern collection's ``patterns/tiff.hexpat`` bumps
        ``eval_depth`` to ``100``. The default must be at least that high so
        users can run the TIFF pattern (and similar parent-relative patterns)
        without manually editing the source.
        """
        assert DEFAULT_EVAL_DEPTH >= 100

    def test_default_eval_depth_handles_common_parent_recursion(self) -> None:
        """The default has enough headroom for typical parent-relative chains.

        Real-world parent-walk patterns commonly nest 50+ levels deep when
        traversing pointer-rich file formats. A default of 256+ is the
        smallest safe headroom; the new constant must clear it.
        """
        assert DEFAULT_EVAL_DEPTH >= 256

    def test_default_eval_depth_finite(self) -> None:
        """The default must remain finite to bound accidental unbounded recursion.

        Setting it to ``0`` (the upstream sentinel for "unlimited") would
        allow infinite recursion to crash the interpreter. The default must
        stay well below an obviously unreasonable value.
        """
        assert 0 < DEFAULT_EVAL_DEPTH < 1_000_000

    def test_pragma_info_dataclass_default_uses_constant(self) -> None:
        """``PragmaInfo()`` instantiated with no args picks up the new default."""
        info = PragmaInfo()
        assert info.eval_depth == DEFAULT_EVAL_DEPTH

    def test_pragma_info_other_defaults_share_module_constants(self) -> None:
        """Other default-bearing fields also reference the shared constants.

        Centralising the defaults in ``pragma`` is the single-source-of-truth
        contract that lets the preprocessor and dataclass agree.
        """
        info = PragmaInfo()
        assert info.array_limit == DEFAULT_ARRAY_LIMIT
        assert info.pattern_limit == DEFAULT_PATTERN_LIMIT
        assert info.pointer_size == DEFAULT_POINTER_SIZE

    def test_preprocessor_uses_shared_default_when_no_pragma(self) -> None:
        """``HexPatPreprocessor.process`` picks up the new default for sourceless input."""
        pp = HexPatPreprocessor()
        _, info = pp.process("u32 x @ 0;")
        assert info.eval_depth == DEFAULT_EVAL_DEPTH

    def test_extract_pragmas_fast_uses_shared_default(self) -> None:
        """``extract_pragmas_fast`` uses the same shared default."""
        info = extract_pragmas_fast("u32 x @ 0;")
        assert info.eval_depth == DEFAULT_EVAL_DEPTH

    def test_pragma_override_still_wins(self) -> None:
        """An explicit ``#pragma eval_depth`` still overrides the default."""
        pp = HexPatPreprocessor()
        _, info = pp.process("#pragma eval_depth 17\nu32 x @ 0;")
        assert info.eval_depth == 17
