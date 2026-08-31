# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Preprocessor for HexPat .hexpat pattern files.

Handles #include, #define, #ifdef/#ifndef/#endif, and #pragma directives.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.errors import HexPatPreprocessorError
from intellicrack.core.hexpat.pragma import (
    DEFAULT_ARRAY_LIMIT,
    DEFAULT_EVAL_DEPTH,
    DEFAULT_PATTERN_LIMIT,
    DEFAULT_POINTER_SIZE,
    PragmaInfo,
)
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger(__name__)

_PRAGMA_ENDIAN_RE = re.compile(r"#pragma\s+endian\s+(big|little|native)")
_PRAGMA_MIME_RE = re.compile(r"#pragma\s+MIME\s+(\S+)")
_PRAGMA_MAGIC_RE = re.compile(r"#pragma\s+magic\s+\[\s*(0x[0-9A-Fa-f]+)\s*,\s*\"([^\"]*)\"\s*\]")
_PRAGMA_BASE_RE = re.compile(r"#pragma\s+base_address\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_EVAL_DEPTH_RE = re.compile(r"#pragma\s+eval_depth\s+(\d+)")
_PRAGMA_ARRAY_LIMIT_RE = re.compile(r"#pragma\s+array_limit\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_PATTERN_LIMIT_RE = re.compile(r"#pragma\s+pattern_limit\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_ONCE_RE = re.compile(r"#pragma\s+once\b")
_PRAGMA_AUTHOR_RE = re.compile(r'#pragma\s+author\s+"([^"]*)"')
_PRAGMA_DESCRIPTION_RE = re.compile(r'#pragma\s+description\s+"([^"]*)"')
_PRAGMA_DEBUG_RE = re.compile(r"#pragma\s+debug\b")
_MAX_INCLUDE_DEPTH = 50
_PRAGMA_BITFIELD_ORDER_RE = re.compile(r"#pragma\s+bitfield_order\s+(left_to_right|right_to_left)")
_PRAGMA_POINTER_SIZE_RE = re.compile(r"#pragma\s+pointer_size\s+(\d+)")

_INCLUDE_ANGLE_RE = re.compile(r"#include\s+<([^>]+)>")
_INCLUDE_QUOTE_RE = re.compile(r'#include\s+"([^"]+)"')
_IMPORT_RE = re.compile(r"import\s+([\w.]+)\s*;")
_DEFINE_OBJECT_RE = re.compile(r"#define\s+(\w+)(?:\s+(.*))?")
_DEFINE_FUNC_RE = re.compile(r"#define\s+(\w+)\(([^)]*)\)(?:\s+(.*))?")
_IFDEF_RE = re.compile(r"#ifdef\s+(\w+)")
_IFNDEF_RE = re.compile(r"#ifndef\s+(\w+)")
_ENDIF_RE = re.compile(r"#endif\b")
_ELSE_RE = re.compile(r"#else\b")
_ERROR_RE = re.compile(r'#error\s+"([^"]*)"')
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
_MAX_MACRO_EXPANSION_PASSES = 64


def _parse_int_value(value_str: str) -> int:
    """Parse an integer from a string, supporting hex prefix.

    Args:
        value_str: The string to parse, optionally prefixed with 0x.

    Returns:
        int: The parsed integer value.
    """
    if value_str.startswith(("0x", "0X")):
        return int(value_str, 16)
    return int(value_str)


class HexPatPreprocessor:
    """Preprocesses HexPat .hexpat source files before parsing.

    Resolves #include directives, expands #define macros, processes conditional compilation (#ifdef/#ifndef/#endif), and extracts #pragma
    metadata.
    """

    def __init__(self, include_paths: list[Path] | None = None) -> None:
        """Initialize the HexPatPreprocessor with include search paths.

        Args:
            include_paths: Directories to search for included files.
        """
        self._include_paths: list[Path] = list(include_paths) if include_paths else []
        self._defines: dict[str, str] = {}
        self._func_defines: dict[str, tuple[tuple[str, ...], str]] = {}
        self._included_files: set[str] = set()
        self._pragma_once_files: set[str] = set()
        _logger.info(
            "hexpat_preprocessor_initialized",
            include_path_count=len(self._include_paths),
        )

    def process(
        self,
        source: str,
        file_path: Path | None = None,
    ) -> tuple[str, PragmaInfo]:
        """Preprocess source code, resolving includes and extracting pragmas.

        Args:
            source: The .hexpat source code to preprocess.
            file_path: Path to the source file, used for relative include
                resolution. None for inline source.

        Returns:
            tuple[str, PragmaInfo]: A tuple of (preprocessed_source, pragma_info).
        """
        _logger.debug("hexpat_preprocess_started", source_length=len(source), file_path=str(file_path) if file_path else None)
        self._defines = {}
        self._func_defines = {}
        self._included_files = set()

        endian: str | None = None
        mime: str | None = None
        magic_list: list[tuple[int, bytes]] = []
        base_address: int = 0
        eval_depth: int = DEFAULT_EVAL_DEPTH
        array_limit: int = DEFAULT_ARRAY_LIMIT
        pattern_limit: int = DEFAULT_PATTERN_LIMIT
        author: str | None = None
        description: str | None = None
        pointer_size: int = DEFAULT_POINTER_SIZE
        bitfield_order: str | None = None

        processed = self._process_source(source, file_path, depth=0)

        output_lines: list[str] = []
        for line in processed.splitlines():
            stripped = line.strip()
            if not stripped.startswith("#pragma"):
                output_lines.append(line)
                continue

            output_lines.append(f"// hexpat-pragma: {stripped[len('#pragma') :].strip()}")

            m = _PRAGMA_ENDIAN_RE.match(stripped)
            if m:
                val = m.group(1)
                endian = "little" if val == "native" else val
                continue

            m = _PRAGMA_MIME_RE.match(stripped)
            if m:
                mime = m.group(1)
                continue

            m = _PRAGMA_MAGIC_RE.match(stripped)
            if m:
                offset_val = _parse_int_value(m.group(1))
                hex_str = m.group(2)
                magic_bytes = bytes.fromhex(hex_str.replace(" ", ""))
                magic_list.append((offset_val, magic_bytes))
                continue

            if m := _PRAGMA_BASE_RE.match(stripped):
                base_address = _parse_int_value(m.group(1))
                continue

            if m := _PRAGMA_EVAL_DEPTH_RE.match(stripped):
                eval_depth = int(m.group(1))
                continue

            if m := _PRAGMA_ARRAY_LIMIT_RE.match(stripped):
                array_limit = _parse_int_value(m.group(1))
                continue

            if m := _PRAGMA_PATTERN_LIMIT_RE.match(stripped):
                pattern_limit = _parse_int_value(m.group(1))
                continue

            if m := _PRAGMA_AUTHOR_RE.match(stripped):
                author = m.group(1)
                continue

            if m := _PRAGMA_DESCRIPTION_RE.match(stripped):
                description = m.group(1)
                continue

            if m := _PRAGMA_BITFIELD_ORDER_RE.match(stripped):
                bitfield_order = m.group(1)
                continue

            if m := _PRAGMA_POINTER_SIZE_RE.match(stripped):
                pointer_size = int(m.group(1))
                continue

        pragma = PragmaInfo(
            endian=endian,
            mime=mime,
            magic=tuple(magic_list),
            base_address=base_address,
            eval_depth=eval_depth,
            array_limit=array_limit,
            pattern_limit=pattern_limit,
            author=author,
            description=description,
            pointer_size=pointer_size,
            bitfield_order=bitfield_order,
        )

        output_source = "\n".join(output_lines)
        _logger.debug("hexpat_preprocess_completed", output_length=len(output_source), included_files=len(self._included_files))
        return output_source, pragma

    def _process_source(
        self,
        source: str,
        file_path: Path | None,
        depth: int,
    ) -> str:
        """Recursively process source, handling includes and conditionals.

        Args:
            source: Source code to process.
            file_path: Path of the current file for relative resolution.
            depth: Current include nesting depth.

        Returns:
            str: Processed source with includes inlined and conditionals resolved.

        Raises:
            HexPatPreprocessorError: On circular includes, missing files,
                nesting too deep, or macro expansion exceeding recursion cap.
        """
        if depth > _MAX_INCLUDE_DEPTH:
            msg = f"include nesting depth exceeded (>{_MAX_INCLUDE_DEPTH})"
            raise HexPatPreprocessorError(msg)

        output_lines: list[str] = []
        file_str: str = str(file_path) if file_path is not None else ""
        skip_stack: list[bool] = []
        else_seen: list[bool] = []

        for line_num, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()

            if m := _IFDEF_RE.match(stripped):
                name = m.group(1)
                is_defined: bool = name in self._defines or name in self._func_defines
                active: bool = not any(skip_stack) and is_defined
                skip_stack.append(not active)
                else_seen.append(False)
                output_lines.append("")
                continue

            if m := _IFNDEF_RE.match(stripped):
                name = m.group(1)
                is_defined = name in self._defines or name in self._func_defines
                active = not any(skip_stack) and not is_defined
                skip_stack.append(not active)
                else_seen.append(False)
                output_lines.append("")
                continue

            if _ELSE_RE.match(stripped):
                if skip_stack and not else_seen[-1]:
                    parent_skip: bool = any(skip_stack[:-1])
                    skip_stack[-1] = True if parent_skip else not skip_stack[-1]
                    else_seen[-1] = True
                output_lines.append("")
                continue

            if _ENDIF_RE.match(stripped):
                if skip_stack:
                    skip_stack.pop()
                    else_seen.pop()
                output_lines.append("")
                continue

            if any(skip_stack):
                output_lines.append("")
                continue

            if m := _INCLUDE_ANGLE_RE.match(stripped):
                include_path = m.group(1)
                resolved = self._resolve_include(
                    include_path,
                    file_path,
                    is_angle=True,
                    line=line_num,
                    depth=depth,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            if m := _INCLUDE_QUOTE_RE.match(stripped):
                include_path = m.group(1)
                resolved = self._resolve_include(
                    include_path,
                    file_path,
                    is_angle=False,
                    line=line_num,
                    depth=depth,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            if m := _IMPORT_RE.match(stripped):
                module_path = m.group(1).replace(".", "/") + ".pat"
                resolved = self._resolve_include(
                    module_path,
                    file_path,
                    is_angle=True,
                    line=line_num,
                    depth=depth,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            if m := _DEFINE_FUNC_RE.match(stripped):
                name = m.group(1)
                params_raw: str = m.group(2) or ""
                body = (m.group(3) or "").strip()
                params: tuple[str, ...] = tuple(p.strip() for p in params_raw.split(",") if p.strip())
                self._func_defines[name] = (params, body)
                self._defines.pop(name, None)
                output_lines.append("")
                continue

            if m := _DEFINE_OBJECT_RE.match(stripped):
                name = m.group(1)
                value = m.group(2) or ""
                self._defines[name] = value.strip()
                self._func_defines.pop(name, None)
                output_lines.append("")
                continue

            if m := _ERROR_RE.match(stripped):
                raise HexPatPreprocessorError(
                    m.group(1),
                    line=line_num,
                    file=file_str,
                )

            output_lines.append(line)

        joined: str = "\n".join(output_lines)
        return self._process_defines(joined, file_path)

    def _resolve_include(
        self,
        include_path: str,
        current_file: Path | None,
        *,
        is_angle: bool,
        line: int,
        depth: int,
    ) -> str | None:
        """Resolve and inline an #include directive.

        Args:
            include_path: The path string from the include directive.
            current_file: Path of the file containing the include.
            is_angle: True for angle-bracket includes, False for quoted.
            line: Source line number of the include directive.
            depth: Current include nesting depth.

        Returns:
            str | None: The preprocessed contents of the included file, None if
            the file was already included with #pragma once, or None (an empty
            substitution) when the include cannot be resolved from any search
            path. A missing include is logged as a warning rather than aborting
            preprocessing so a pattern that references an unavailable optional
            library still parses the remainder of its source.
        """
        search_paths: list[Path] = []

        if not is_angle and current_file is not None:
            search_paths.append(current_file.parent)

        search_paths.extend(self._include_paths)

        for search_dir in search_paths:
            candidate = search_dir / include_path
            if candidate.exists():
                resolved_str = str(candidate.resolve())

                if resolved_str in self._pragma_once_files or resolved_str in self._included_files:
                    return None

                self._included_files.add(resolved_str)

                _logger.debug("hexpat_include_resolved", include_path=include_path, resolved_path=resolved_str, line=line)
                content = candidate.read_text(encoding="utf-8", errors="replace")

                if _PRAGMA_ONCE_RE.search(content):
                    self._pragma_once_files.add(resolved_str)

                return self._process_source(
                    content,
                    candidate,
                    depth=depth + 1,
                )

        _logger.warning(
            "include_not_found",
            include_path=include_path,
            search_paths=[str(p) for p in search_paths],
            line=line,
            current_file=str(current_file) if current_file is not None else "",
        )
        return None

    def _process_defines(self, source: str, file_path: Path | None = None) -> str:
        """Expand object-like and function-like #define macros in source text.

        Performs a token-aware scan that preserves string literals
        (``"..."`` and ``'...'``) and comments (``//...`` and ``/* ... */``)
        verbatim. Object-like macros are substituted as whole identifiers.
        Function-like macros parse balanced-paren argument lists and expand
        positionally. Expansion iterates to a fixed point, bounded by a
        recursion cap to prevent runaway self-referential macros.

        Args:
            source: Source code with potential macro references.
            file_path: Path of the source file, used for error context.

        Returns:
            str: Source with all defined macros expanded to a fixed point.

        Raises:
            HexPatPreprocessorError: If macro expansion does not converge
                within the recursion cap.
        """
        if not self._defines and not self._func_defines:
            return source

        current: str = source
        file_str: str = str(file_path) if file_path is not None else ""
        for _ in range(_MAX_MACRO_EXPANSION_PASSES):
            expanded: str = self._expand_macros_once(current)
            if expanded == current:
                return expanded
            current = expanded

        msg: str = f"macro expansion exceeded {_MAX_MACRO_EXPANSION_PASSES} passes (possible recursive macro)"
        raise HexPatPreprocessorError(msg, file=file_str)

    def _expand_macros_once(self, source: str) -> str:
        """Perform one token-aware macro expansion pass over the source.

        Scans the source character-by-character, skipping string literals and
        comments, and substitutes identifiers that match a known object-like
        or function-like macro.

        Args:
            source: Source text to scan for macro identifiers.

        Returns:
            str: Source with one pass of macro substitutions applied.
        """
        out: list[str] = []
        i: int = 0
        n: int = len(source)
        while i < n:
            ch: str = source[i]

            if ch in {'"', "'"}:
                end: int = self._find_string_end(source, i, ch)
                out.append(source[i:end])
                i = end
                continue

            if ch == "/" and i + 1 < n:
                nxt: str = source[i + 1]
                if nxt == "/":
                    end = source.find("\n", i)
                    if end == -1:
                        end = n
                    out.append(source[i:end])
                    i = end
                    continue
                if nxt == "*":
                    end = source.find("*/", i + 2)
                    end = n if end == -1 else end + 2
                    out.append(source[i:end])
                    i = end
                    continue

            if ch == "_" or ch.isalpha():
                match = _IDENTIFIER_RE.match(source, i)
                if match is None:
                    out.append(ch)
                    i += 1
                    continue
                ident: str = match.group(0)
                end = match.end()

                if ident in self._func_defines:
                    arg_start: int = self._skip_whitespace(source, end)
                    if arg_start < n and source[arg_start] == "(":
                        args, after = self._parse_macro_arguments(source, arg_start)
                        params, body = self._func_defines[ident]
                        out.append(self._substitute_func_macro(params, body, args))
                        i = after
                        continue

                if ident in self._defines:
                    out.append(self._defines[ident])
                    i = end
                    continue

                out.append(ident)
                i = end
                continue

            out.append(ch)
            i += 1

        return "".join(out)

    @staticmethod
    def _find_string_end(source: str, start: int, quote: str) -> int:
        """Return the index just past the closing quote of a string literal.

        Handles backslash escapes. If no closing quote is found, returns
        the end of the source.

        Args:
            source: Source text containing the string literal.
            start: Index of the opening quote character.
            quote: The quote character (``"`` or ``'``).

        Returns:
            int: The index of the character immediately after the closing quote,
            or ``len(source)`` if the string is unterminated.
        """
        n: int = len(source)
        j: int = start + 1
        while j < n:
            c: str = source[j]
            if c == "\\" and j + 1 < n:
                j += 2
                continue
            if c == quote:
                return j + 1
            j += 1
        return n

    @staticmethod
    def _skip_whitespace(source: str, start: int) -> int:
        """Return the index of the first non-whitespace character at or after ``start``.

        Args:
            source: Source text to scan.
            start: Index to begin scanning from.

        Returns:
            int: Index of the first non-whitespace character, or ``len(source)``
            if no such character exists.
        """
        n: int = len(source)
        j: int = start
        while j < n and source[j] in " \t\r\n":
            j += 1
        return j

    @staticmethod
    def _parse_macro_arguments(source: str, start: int) -> tuple[list[str], int]:
        """Parse a balanced-paren function-like macro argument list.

        Respects nested parentheses, string literals, and comments inside
        argument expressions. Splits arguments on top-level commas only.

        Args:
            source: Source text starting at or before the opening paren.
            start: Index of the opening ``(`` character.

        Returns:
            tuple[list[str], int]: A tuple of (argument list, index after closing paren).
            If the argument list is unterminated, returns the arguments parsed so far
            and an index at end-of-source.
        """
        n: int = len(source)
        args: list[str] = []
        buf: list[str] = []
        depth: int = 0
        j: int = start
        if j >= n or source[j] != "(":
            return args, j
        j += 1
        depth = 1
        while j < n and depth > 0:
            c: str = source[j]

            if c in {'"', "'"}:
                end: int = HexPatPreprocessor._find_string_end(source, j, c)
                buf.append(source[j:end])
                j = end
                continue

            if c == "/" and j + 1 < n:
                nxt: str = source[j + 1]
                if nxt == "/":
                    end = source.find("\n", j)
                    if end == -1:
                        end = n
                    buf.append(source[j:end])
                    j = end
                    continue
                if nxt == "*":
                    end = source.find("*/", j + 2)
                    end = n if end == -1 else end + 2
                    buf.append(source[j:end])
                    j = end
                    continue

            if c == "(":
                depth += 1
                buf.append(c)
                j += 1
                continue
            if c == ")":
                depth -= 1
                if depth == 0:
                    args.append("".join(buf).strip())
                    j += 1
                    return args, j
                buf.append(c)
                j += 1
                continue
            if c == "," and depth == 1:
                args.append("".join(buf).strip())
                buf = []
                j += 1
                continue

            buf.append(c)
            j += 1

        if buf:
            args.append("".join(buf).strip())
        return args, j

    @staticmethod
    def _substitute_func_macro(
        params: tuple[str, ...],
        body: str,
        args: list[str],
    ) -> str:
        """Substitute positional arguments into a function-like macro body.

        Replaces whole-identifier occurrences of each parameter in the body
        with the corresponding argument expression. Substitution respects
        string literals and comments in the body. Extra or missing arguments
        are tolerated: missing parameters expand to the empty string and
        extra arguments are ignored.

        Args:
            params: The declared parameter names of the macro.
            body: The macro body text as written in the ``#define``.
            args: The actual argument expressions from the invocation.

        Returns:
            str: The macro body with parameter occurrences replaced by arguments.
        """
        if not params:
            return body

        replacements: dict[str, str] = {param: args[idx] if idx < len(args) else "" for idx, param in enumerate(params)}
        out: list[str] = []
        i: int = 0
        n: int = len(body)
        while i < n:
            ch: str = body[i]

            if ch in {'"', "'"}:
                end: int = HexPatPreprocessor._find_string_end(body, i, ch)
                out.append(body[i:end])
                i = end
                continue

            if ch == "/" and i + 1 < n:
                nxt: str = body[i + 1]
                if nxt == "/":
                    end = body.find("\n", i)
                    if end == -1:
                        end = n
                    out.append(body[i:end])
                    i = end
                    continue
                if nxt == "*":
                    end = body.find("*/", i + 2)
                    end = n if end == -1 else end + 2
                    out.append(body[i:end])
                    i = end
                    continue

            if ch == "_" or ch.isalpha():
                match = _IDENTIFIER_RE.match(body, i)
                if match is None:
                    out.append(ch)
                    i += 1
                    continue
                ident: str = match.group(0)
                end = match.end()
                if ident in replacements:
                    out.append(replacements[ident])
                else:
                    out.append(ident)
                i = end
                continue

            out.append(ch)
            i += 1

        return "".join(out)


def extract_pragmas_fast(source: str) -> PragmaInfo:
    """Extract pragma metadata from source without full preprocessing.

    Scans every line of the source for ``#pragma`` directives. Pragmas in
    common .hexpat files are emitted in the file header, but vendor patterns
    occasionally interleave additional pragmas (for example ``#pragma debug``
    blocks or pragma-controlled feature toggles) deeper in the source. This
    function therefore scans the full file rather than truncating to a fixed
    line window so that no pragma is silently dropped during indexing.

    Args:
        source: The .hexpat source code.

    Returns:
        PragmaInfo: A PragmaInfo with extracted metadata.
    """
    _logger.debug("hexpat_extract_pragmas_fast_started", source_length=len(source))
    endian: str | None = None
    mime: str | None = None
    magic_list: list[tuple[int, bytes]] = []
    base_address: int = 0
    eval_depth: int = DEFAULT_EVAL_DEPTH
    array_limit: int = DEFAULT_ARRAY_LIMIT
    pattern_limit: int = DEFAULT_PATTERN_LIMIT
    author: str | None = None
    description: str | None = None
    pointer_size: int = DEFAULT_POINTER_SIZE
    bitfield_order: str | None = None

    for line in source.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#pragma"):
            continue

        m = _PRAGMA_ENDIAN_RE.match(stripped)
        if m:
            val = m.group(1)
            endian = "little" if val == "native" else val
            continue

        m = _PRAGMA_MIME_RE.match(stripped)
        if m:
            mime = m.group(1)
            continue

        m = _PRAGMA_MAGIC_RE.match(stripped)
        if m:
            offset_val = _parse_int_value(m.group(1))
            hex_str = m.group(2)
            magic_bytes = bytes.fromhex(hex_str.replace(" ", ""))
            magic_list.append((offset_val, magic_bytes))
            continue

        if m := _PRAGMA_BASE_RE.match(stripped):
            base_address = _parse_int_value(m.group(1))
            continue

        if m := _PRAGMA_EVAL_DEPTH_RE.match(stripped):
            eval_depth = int(m.group(1))
            continue

        if m := _PRAGMA_ARRAY_LIMIT_RE.match(stripped):
            array_limit = _parse_int_value(m.group(1))
            continue

        if m := _PRAGMA_PATTERN_LIMIT_RE.match(stripped):
            pattern_limit = _parse_int_value(m.group(1))
            continue

        if m := _PRAGMA_AUTHOR_RE.match(stripped):
            author = m.group(1)
            continue

        if m := _PRAGMA_DESCRIPTION_RE.match(stripped):
            description = m.group(1)
            continue

        if m := _PRAGMA_BITFIELD_ORDER_RE.match(stripped):
            bitfield_order = m.group(1)
            continue

        if m := _PRAGMA_POINTER_SIZE_RE.match(stripped):
            pointer_size = int(m.group(1))
            continue

    result_pragma = PragmaInfo(
        endian=endian,
        mime=mime,
        magic=tuple(magic_list),
        base_address=base_address,
        eval_depth=eval_depth,
        array_limit=array_limit,
        pattern_limit=pattern_limit,
        author=author,
        description=description,
        pointer_size=pointer_size,
        bitfield_order=bitfield_order,
    )
    _logger.debug("hexpat_extract_pragmas_fast_completed", magic_count=len(magic_list), endian=endian, mime=mime)
    return result_pragma
