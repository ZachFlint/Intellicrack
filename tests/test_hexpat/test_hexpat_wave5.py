# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave 5 gates for Group 01: HexPat engine findings (F14-F17).

Closes the following NOT_RESOLVED findings from group-01-report.md:

F14 - HexPatError.__str__ exact format (errors.py:44-45)
F15 - preprocessor import directive (preprocessor.py:220)
F16 - circular include prevention (preprocessor.py:290)
F17 - _process_defines 64-pass limit (preprocessor.py:320)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.hexpat.errors import HexPatError, HexPatPreprocessorError
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor


if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# F14 -- HexPatError.__str__ exact format (errors.py:44-45)
# ---------------------------------------------------------------------------


class TestHexPatErrorStrFormat:
    """Assert the exact string representation of HexPatError.

    Oracle: the format `"file:line:col: message"` produced by errors.py:44-45
    via `":".join(location_parts)` and `f"{location}: {message}"`.
    Mutation caught: reordering location_parts (e.g. column before line) or
    changing the separator character produces a different string that fails
    the exact-equality check.
    """

    def test_full_location_format(self) -> None:
        """str(HexPatError) with file, line and column must be 'file:line:col: msg'.

        Oracle: errors.py:38-45 builds location from [file, str(line), str(column)]
        joined by ':'.  Mutation caught: swapping line and column makes the
        string 'test.hexpat:7:3: bad type' != 'test.hexpat:3:7: bad type'.
        """
        err = HexPatError("bad type", line=3, column=7, file="test.hexpat")
        assert str(err) == "test.hexpat:3:7: bad type"

    def test_file_and_line_only_no_column(self) -> None:
        """str(HexPatError) with file+line but no column must be 'file:line: msg'.

        Oracle: errors.py:41-43 only appends column when column > 0.
        Mutation caught: unconditionally including column produces
        'test.hexpat:5:0: oops' instead of 'test.hexpat:5: oops'.
        """
        err = HexPatError("oops", line=5, column=0, file="test.hexpat")
        assert str(err) == "test.hexpat:5: oops"

    def test_message_only_no_location(self) -> None:
        """str(HexPatError) with no file/line/column must be just the message.

        Oracle: errors.py:44-45: location is empty when no parts are added,
        so the format is just message.  Mutation caught: unconditionally
        prepending ':' or location produces extra characters.
        """
        err = HexPatError("standalone error")
        assert str(err) == "standalone error"

    def test_file_only_no_line(self) -> None:
        """str(HexPatError) with file but no line must be 'file: message'.

        Oracle: errors.py:38-43 -- line only appended when line > 0, so
        column is also omitted.  Mutation caught: including line=0 in
        location_parts produces 'test.hexpat:0: msg'.
        """
        err = HexPatError("missing include", file="test.hexpat")
        assert str(err) == "test.hexpat: missing include"

    def test_line_only_no_file(self) -> None:
        """str(HexPatError) with line but no file must be 'line: message'.

        Oracle: errors.py:38-43 -- file is omitted when empty string.
        Mutation caught: always prepending file string produces ':3: msg'.
        """
        err = HexPatError("syntax error", line=3)
        assert str(err) == "3: syntax error"

    def test_exact_string_from_report_spec(self) -> None:
        """Assert the exact example from the group-01-report STILL OPEN spec.

        The report spec is:
        `str(HexPatError('bad type', line=3, column=7, file='test.hexpat'))
        == 'test.hexpat:3:7: bad type'`

        Mutation caught: any change to the format string or location_parts
        construction breaks this exact-match assertion.
        """
        result = str(HexPatError("bad type", line=3, column=7, file="test.hexpat"))
        assert result == "test.hexpat:3:7: bad type"


# ---------------------------------------------------------------------------
# F15 -- preprocessor import directive (preprocessor.py:220)
# ---------------------------------------------------------------------------


class TestPreprocessorImportDirective:
    """Assert that the preprocessor resolves 'import std.mem;' style directives.

    The _IMPORT_RE regex at preprocessor.py:49 matches `import X.Y.Z;` and
    the handler at preprocessor.py:306-316 converts module path separators
    (dots) to slashes and appends '.pat' before resolving via _resolve_include.

    Oracle: a known include file created in tmp_path whose content appears
    verbatim in the preprocessor output.
    Mutation caught: if the import handler failed to convert '.' to '/', the
    include path 'std.mem.pat' would not match the file 'std/mem.pat', the
    include would be silently skipped, and the content assertion fails.
    """

    def test_import_directive_inlines_library_content(self, tmp_path: Path) -> None:
        """'import std.mem;' must inline the content of std/mem.pat from include paths.

        Args:
            tmp_path: Pytest temporary directory for creating library files.
        """
        std_dir = tmp_path / "std"
        std_dir.mkdir()
        mem_pat = std_dir / "mem.pat"
        mem_pat.write_text("u32 offset @ 0;\n", encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        source = "import std.mem;\nu32 x @ 4;\n"
        processed_text, _ = pp.process(source)

        assert "u32 offset @ 0;" in processed_text, (
            f"Expected std/mem.pat content to be inlined; got:\n{processed_text}"
        )
        assert "u32 x @ 4;" in processed_text

    def test_import_directive_missing_library_is_graceful(self, tmp_path: Path) -> None:
        """A missing import target must be silently skipped, not raise an exception.

        Oracle: _resolve_include logs a warning and returns None when the
        target file is absent.  Mutation caught: raising instead of skipping
        makes this test error rather than pass.
        """
        pp = HexPatPreprocessor(include_paths=[tmp_path])
        source = "import no_such_module;\nu32 x @ 0;\n"
        processed_text, _ = pp.process(source)
        assert "u32 x @ 0;" in processed_text

    def test_import_nested_module_path_resolution(self, tmp_path: Path) -> None:
        """'import a.b.c;' must resolve to a/b/c.pat via dot-to-slash conversion.

        Oracle: the handler at preprocessor.py:307 replaces '.' with '/'.
        Mutation caught: if '.' were not replaced, the path 'a.b.c.pat' would
        not match the file at 'a/b/c.pat' and the content assertion fails.

        Args:
            tmp_path: Pytest temporary directory.
        """
        a_dir = tmp_path / "a" / "b"
        a_dir.mkdir(parents=True)
        target = a_dir / "c.pat"
        target.write_text("u8 tag @ 0;\n", encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        source = "import a.b.c;\nu32 x @ 1;\n"
        processed_text, _ = pp.process(source)

        assert "u8 tag @ 0;" in processed_text, (
            f"Expected a/b/c.pat content inlined; got:\n{processed_text}"
        )

    def test_import_line_removed_from_output(self, tmp_path: Path) -> None:
        """The 'import X;' line itself must not appear verbatim in the output.

        Oracle: preprocessor.py replaces include directives with their
        content or empty string; the directive text is never echoed.
        Mutation caught: passing the import line through as-is would cause
        the assertion to fail.

        Args:
            tmp_path: Pytest temporary directory.
        """
        std_dir = tmp_path / "std"
        std_dir.mkdir()
        (std_dir / "io.pat").write_text("u8 byte @ 0;\n", encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        source = "import std.io;\n"
        processed_text, _ = pp.process(source)

        assert "import std.io;" not in processed_text, (
            "The import directive must be replaced, not echoed to output"
        )


# ---------------------------------------------------------------------------
# F16 -- circular include prevention (preprocessor.py:290)
# ---------------------------------------------------------------------------


class TestCircularIncludePrevention:
    """Assert that A-includes-B-includes-A circular includes terminate and produce bounded output.

    The _included_files set at preprocessor.py:287/390 prevents infinite
    recursion by skipping files already in the set.  Each file's content
    appears a bounded number of times.

    Oracle: with a.hexpat containing 'u32 x @ 0;' and b.hexpat containing
    'u32 y @ 0;', the processed result of a.hexpat has exactly 2 occurrences
    of 'u32 x @ 0;' and exactly 1 occurrence of 'u32 y @ 0;' (traced by the
    _included_files algorithm).

    Mutation caught: removing the ``_included_files`` guard causes A and B
    to be re-included at each nesting level until _MAX_INCLUDE_DEPTH is
    exceeded, raising HexPatPreprocessorError -- the preprocessing does NOT
    return the expected text with 2 x-occurrences, and the count assertion fails.
    """

    def test_circular_include_terminates(self, tmp_path: Path) -> None:
        """Processing a.hexpat that circularly includes b.hexpat must terminate.

        Args:
            tmp_path: Pytest temporary directory.
        """
        a_hexpat = tmp_path / "a.hexpat"
        b_hexpat = tmp_path / "b.hexpat"
        a_hexpat.write_text('#include "b.hexpat"\nu32 x @ 0;\n', encoding="utf-8")
        b_hexpat.write_text('#include "a.hexpat"\nu32 y @ 0;\n', encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        processed_text, _ = pp.process(a_hexpat.read_text(encoding="utf-8"), file_path=a_hexpat)
        assert isinstance(processed_text, str)

    def test_circular_include_x_count_is_exactly_two(self, tmp_path: Path) -> None:
        """Processing a.hexpat must produce exactly 2 occurrences of 'u32 x @ 0;'.

        Trace: a→b→a (circular, skips b again) yields the inner 'u32 x @ 0;'
        from the nested a-inclusion plus the outer 'u32 x @ 0;' from a's own body.

        Mutation caught: without _included_files, b would be re-included
        inside the nested a-inclusion (depth 3) and so on until
        HexPatPreprocessorError is raised, never reaching the count assertion.

        Args:
            tmp_path: Pytest temporary directory.
        """
        a_hexpat = tmp_path / "a.hexpat"
        b_hexpat = tmp_path / "b.hexpat"
        a_hexpat.write_text('#include "b.hexpat"\nu32 x @ 0;\n', encoding="utf-8")
        b_hexpat.write_text('#include "a.hexpat"\nu32 y @ 0;\n', encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        processed_text, _ = pp.process(a_hexpat.read_text(encoding="utf-8"), file_path=a_hexpat)

        x_count = processed_text.count("u32 x @ 0;")
        assert x_count == 2, (
            f"Expected exactly 2 occurrences of 'u32 x @ 0;' but got {x_count}; "
            f"output:\n{processed_text}"
        )

    def test_circular_include_y_count_is_exactly_one(self, tmp_path: Path) -> None:
        """Processing a.hexpat must produce exactly 1 occurrence of 'u32 y @ 0;'.

        b.hexpat is resolved exactly once (on first encounter from a.hexpat).
        Its own body 'u32 y @ 0;' thus appears exactly once.

        Mutation caught: if _included_files was never populated, nested
        processing would continue until depth exceeded, raising an error
        rather than returning a string with a single 'u32 y @ 0;'.

        Args:
            tmp_path: Pytest temporary directory.
        """
        a_hexpat = tmp_path / "a.hexpat"
        b_hexpat = tmp_path / "b.hexpat"
        a_hexpat.write_text('#include "b.hexpat"\nu32 x @ 0;\n', encoding="utf-8")
        b_hexpat.write_text('#include "a.hexpat"\nu32 y @ 0;\n', encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        processed_text, _ = pp.process(a_hexpat.read_text(encoding="utf-8"), file_path=a_hexpat)

        y_count = processed_text.count("u32 y @ 0;")
        assert y_count == 1, (
            f"Expected exactly 1 occurrence of 'u32 y @ 0;' but got {y_count}; "
            f"output:\n{processed_text}"
        )

    def test_circular_include_does_not_raise(self, tmp_path: Path) -> None:
        """Circular includes must not raise HexPatPreprocessorError.

        The _included_files guard must prevent the nesting depth from being
        exceeded.  Mutation caught: removing the guard lets depth grow to
        _MAX_INCLUDE_DEPTH+1 and raises an exception.

        Args:
            tmp_path: Pytest temporary directory.
        """
        a_hexpat = tmp_path / "a.hexpat"
        b_hexpat = tmp_path / "b.hexpat"
        a_hexpat.write_text('#include "b.hexpat"\nu32 x @ 0;\n', encoding="utf-8")
        b_hexpat.write_text('#include "a.hexpat"\nu32 y @ 0;\n', encoding="utf-8")

        pp = HexPatPreprocessor(include_paths=[tmp_path])
        try:
            pp.process(a_hexpat.read_text(encoding="utf-8"), file_path=a_hexpat)
        except HexPatPreprocessorError as exc:
            pytest.fail(f"Circular include raised HexPatPreprocessorError: {exc}")


# ---------------------------------------------------------------------------
# F17 -- _process_defines 64-pass limit (preprocessor.py:320)
# ---------------------------------------------------------------------------


class TestProcessDefines64PassLimit:
    """Assert that _process_defines raises HexPatPreprocessorError after 64 expansion passes.

    Oracle: _MAX_MACRO_EXPANSION_PASSES = 64 at preprocessor.py:58 and the
    error message 'macro expansion exceeded 64 passes' at preprocessor.py:445.

    A mutually-recursive macro pair (A expands to B, B expands to A) never
    reaches a fixed point, so the pass counter reaches 64 and the error
    is raised.

    Mutation caught: removing the pass limit check causes an infinite loop
    (Python would hang indefinitely rather than raising), making any
    test-runner timeout count as a failure.  More precisely, if the loop
    were changed to `while True:`, the HexPatPreprocessorError is never
    raised and pytest.raises fails with ``ExceptionInfo is None``.
    """

    def test_self_referential_macros_hit_pass_limit(self) -> None:
        """Mutually-recursive macros A<->B must raise HexPatPreprocessorError after 64 passes.

        Mutation caught: removing the range(_MAX_MACRO_EXPANSION_PASSES)
        upper bound replaces finite iteration with an infinite loop; the
        pytest.raises context never receives an exception and reports
        'DID NOT RAISE', failing the test.
        """
        source = "#define A B\n#define B A\nA\n"
        pp = HexPatPreprocessor()
        with pytest.raises(HexPatPreprocessorError, match=r"64 passes"):
            pp.process(source)

    def test_pass_limit_error_message_contains_64(self) -> None:
        """The error message must mention '64 passes' exactly.

        Oracle: preprocessor.py:445 formats
        f'macro expansion exceeded {_MAX_MACRO_EXPANSION_PASSES} passes ...'
        where _MAX_MACRO_EXPANSION_PASSES == 64.
        Mutation caught: changing _MAX_MACRO_EXPANSION_PASSES to 128 makes
        the message 'macro expansion exceeded 128 passes ...' which no longer
        matches the regex r'64 passes'.
        """
        source = "#define A B\n#define B A\nA\n"
        pp = HexPatPreprocessor()
        with pytest.raises(HexPatPreprocessorError, match=r"64 passes") as exc_info:
            pp.process(source)
        assert "64 passes" in str(exc_info.value)

    def test_convergent_macros_do_not_hit_limit(self) -> None:
        """Macros that converge within 64 passes must not raise.

        This confirms the gate is specific to non-converging expansions.
        Mutation caught: raising on ANY macro (not just non-converging ones)
        would make this assertion fail.
        """
        source = "#define STATUS active\nstatus = STATUS;\n"
        pp = HexPatPreprocessor()
        processed_text, _ = pp.process(source)
        assert "status = active;" in processed_text

    def test_triple_cycle_macros_hit_pass_limit(self) -> None:
        """A three-way cyclic macro expansion A->B->C->A must also hit the pass limit.

        Confirms the limit applies to cycles longer than 2 nodes.
        Mutation caught: removing the pass limit allows infinite iteration.

        """
        source = "#define A B\n#define B C\n#define C A\nA\n"
        pp = HexPatPreprocessor()
        with pytest.raises(HexPatPreprocessorError, match=r"64 passes"):
            pp.process(source)
