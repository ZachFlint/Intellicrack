# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Preprocessor for HexPat .hexpat pattern files.

Handles #include, #define, #ifdef/#ifndef/#endif, and #pragma directives.
"""

from __future__ import annotations

import re
from pathlib import Path

from intellicrack.core.hexpat._pragma import PragmaInfo
from intellicrack.core.hexpat.errors import HexPatPreprocessorError
from intellicrack.core.logging import get_logger


_logger = get_logger("core.hexpat.preprocessor")

_PRAGMA_ENDIAN_RE = re.compile(r"#pragma\s+endian\s+(big|little|native)")
_PRAGMA_MIME_RE = re.compile(r'#pragma\s+MIME\s+(\S+)')
_PRAGMA_MAGIC_RE = re.compile(
    r"#pragma\s+magic\s+\[\s*(0x[0-9A-Fa-f]+)\s*,\s*\"([^\"]*)\"\s*\]"
)
_PRAGMA_BASE_RE = re.compile(r"#pragma\s+base_address\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_EVAL_DEPTH_RE = re.compile(r"#pragma\s+eval_depth\s+(\d+)")
_PRAGMA_ARRAY_LIMIT_RE = re.compile(r"#pragma\s+array_limit\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_PATTERN_LIMIT_RE = re.compile(r"#pragma\s+pattern_limit\s+(0x[0-9A-Fa-f]+|\d+)")
_PRAGMA_ONCE_RE = re.compile(r"#pragma\s+once\b")
_PRAGMA_AUTHOR_RE = re.compile(r'#pragma\s+author\s+"([^"]*)"')
_PRAGMA_DESCRIPTION_RE = re.compile(r'#pragma\s+description\s+"([^"]*)"')
_PRAGMA_DEBUG_RE = re.compile(r"#pragma\s+debug\b")
_MAX_INCLUDE_DEPTH = 50
_PRAGMA_BITFIELD_ORDER_RE = re.compile(
    r"#pragma\s+bitfield_order\s+(left_to_right|right_to_left)"
)

_INCLUDE_ANGLE_RE = re.compile(r'#include\s+<([^>]+)>')
_INCLUDE_QUOTE_RE = re.compile(r'#include\s+"([^"]+)"')
_IMPORT_RE = re.compile(r"import\s+([\w.]+)\s*;")
_DEFINE_RE = re.compile(r"#define\s+(\w+)(?:\s+(.*))?")
_IFDEF_RE = re.compile(r"#ifdef\s+(\w+)")
_IFNDEF_RE = re.compile(r"#ifndef\s+(\w+)")
_ENDIF_RE = re.compile(r"#endif\b")
_ELSE_RE = re.compile(r"#else\b")
_ERROR_RE = re.compile(r'#error\s+"([^"]*)"')


def _parse_int_value(value_str: str) -> int:
    """Parse an integer from a string, supporting hex prefix.

    Args:
        value_str: The string to parse, optionally prefixed with 0x.

    Returns:
        The parsed integer value.
    """
    if value_str.startswith("0x") or value_str.startswith("0X"):
        return int(value_str, 16)
    return int(value_str)


class HexPatPreprocessor:
    """Preprocesses HexPat .hexpat source files before parsing.

    Resolves #include directives, expands #define macros, processes
    conditional compilation (#ifdef/#ifndef/#endif), and extracts
    #pragma metadata.

    Attributes:
        include_paths: Ordered list of directories to search for includes.
    """

    def __init__(self, include_paths: list[Path] | None = None) -> None:
        """Initialize the preprocessor.

        Args:
            include_paths: Directories to search for included files.
                Defaults to an empty list.
        """
        self._include_paths: list[Path] = list(include_paths) if include_paths else []
        self._defines: dict[str, str] = {}
        self._included_files: set[str] = set()
        self._pragma_once_files: set[str] = set()

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
            A tuple of (preprocessed_source, pragma_info).

        Raises:
            HexPatPreprocessorError: On include resolution failure or
                preprocessing errors.
        """
        self._defines = {}
        self._included_files = set()

        endian: str | None = None
        mime: str | None = None
        magic_list: list[tuple[int, bytes]] = []
        base_address: int = 0
        eval_depth: int = 32
        array_limit: int = 0x10000
        pattern_limit: int = 0x40000
        author: str | None = None
        description: str | None = None

        processed = self._process_source(source, file_path, depth=0)

        for line in processed.splitlines():
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

            m = _PRAGMA_BASE_RE.match(stripped)
            if m:
                base_address = _parse_int_value(m.group(1))
                continue

            m = _PRAGMA_EVAL_DEPTH_RE.match(stripped)
            if m:
                eval_depth = int(m.group(1))
                continue

            m = _PRAGMA_ARRAY_LIMIT_RE.match(stripped)
            if m:
                array_limit = _parse_int_value(m.group(1))
                continue

            m = _PRAGMA_PATTERN_LIMIT_RE.match(stripped)
            if m:
                pattern_limit = _parse_int_value(m.group(1))
                continue

            m = _PRAGMA_AUTHOR_RE.match(stripped)
            if m:
                author = m.group(1)
                continue

            m = _PRAGMA_DESCRIPTION_RE.match(stripped)
            if m:
                description = m.group(1)
                continue

        output_lines: list[str] = []
        for line in processed.splitlines():
            stripped = line.strip()
            if stripped.startswith("#pragma"):
                output_lines.append("")
            else:
                output_lines.append(line)

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
        )

        return "\n".join(output_lines), pragma

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
            Processed source with includes inlined and conditionals resolved.

        Raises:
            HexPatPreprocessorError: On circular includes, missing files,
                or nesting too deep.
        """
        if depth > _MAX_INCLUDE_DEPTH:
            msg = f"include nesting depth exceeded (>{_MAX_INCLUDE_DEPTH})"
            raise HexPatPreprocessorError(msg)

        source = self._process_conditionals(source)
        source = self._process_defines(source)

        output_lines: list[str] = []
        for line_num, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()

            m = _INCLUDE_ANGLE_RE.match(stripped)
            if m:
                include_path = m.group(1)
                resolved = self._resolve_include(
                    include_path, file_path, is_angle=True, line=line_num,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            m = _INCLUDE_QUOTE_RE.match(stripped)
            if m:
                include_path = m.group(1)
                resolved = self._resolve_include(
                    include_path, file_path, is_angle=False, line=line_num,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            m = _IMPORT_RE.match(stripped)
            if m:
                module_path = m.group(1).replace(".", "/") + ".pat"
                resolved = self._resolve_include(
                    module_path, file_path, is_angle=True, line=line_num,
                )
                if resolved is not None:
                    output_lines.append(resolved)
                continue

            m = _DEFINE_RE.match(stripped)
            if m:
                name = m.group(1)
                value = m.group(2) or ""
                self._defines[name] = value.strip()
                output_lines.append("")
                continue

            m = _ERROR_RE.match(stripped)
            if m:
                raise HexPatPreprocessorError(
                    m.group(1),
                    line=line_num,
                )

            output_lines.append(line)

        return "\n".join(output_lines)

    def _resolve_include(
        self,
        include_path: str,
        current_file: Path | None,
        *,
        is_angle: bool,
        line: int,
    ) -> str | None:
        """Resolve and inline an #include directive.

        Args:
            include_path: The path string from the include directive.
            current_file: Path of the file containing the include.
            is_angle: True for angle-bracket includes, False for quoted.
            line: Source line number of the include directive.

        Returns:
            The preprocessed contents of the included file, or None if
            the file was already included with #pragma once.

        Raises:
            HexPatPreprocessorError: If the included file cannot be found.
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

                content = candidate.read_text(encoding="utf-8", errors="replace")

                if _PRAGMA_ONCE_RE.search(content):
                    self._pragma_once_files.add(resolved_str)

                return self._process_source(
                    content,
                    candidate,
                    depth=1,
                )

        _logger.warning(
            "include_not_found",
            include_path=include_path,
            search_paths=[str(p) for p in search_paths],
            line=line,
        )
        return ""

    def _process_conditionals(self, source: str) -> str:
        """Process #ifdef/#ifndef/#else/#endif conditional blocks.

        Args:
            source: Source code with conditional directives.

        Returns:
            Source with conditional blocks resolved based on current defines.
        """
        output_lines: list[str] = []
        skip_stack: list[bool] = []
        else_seen: list[bool] = []

        for line in source.splitlines():
            stripped = line.strip()

            m = _IFDEF_RE.match(stripped)
            if m:
                name = m.group(1)
                active = not any(skip_stack) and name in self._defines
                skip_stack.append(not active)
                else_seen.append(False)
                output_lines.append("")
                continue

            m = _IFNDEF_RE.match(stripped)
            if m:
                name = m.group(1)
                active = not any(skip_stack) and name not in self._defines
                skip_stack.append(not active)
                else_seen.append(False)
                output_lines.append("")
                continue

            if _ELSE_RE.match(stripped):
                if skip_stack and not else_seen[-1]:
                    parent_skip = any(skip_stack[:-1])
                    skip_stack[-1] = not skip_stack[-1] if not parent_skip else True
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
            else:
                output_lines.append(line)

        return "\n".join(output_lines)

    def _process_defines(self, source: str) -> str:
        """Expand #define macros in source text.

        Args:
            source: Source code with potential macro references.

        Returns:
            Source with all defined macros expanded.
        """
        result = source
        for name, value in self._defines.items():
            if name in result:
                result = result.replace(name, value)
        return result


def extract_pragmas_fast(source: str) -> PragmaInfo:
    """Extract pragma metadata from source without full preprocessing.

    Reads only lines starting with #pragma for fast metadata extraction.
    Used by PatternRegistry for indexing .hexpat files.

    Args:
        source: The .hexpat source code.

    Returns:
        A PragmaInfo with extracted metadata.
    """
    endian: str | None = None
    mime: str | None = None
    magic_list: list[tuple[int, bytes]] = []
    base_address: int = 0
    eval_depth: int = 32
    array_limit: int = 0x10000
    pattern_limit: int = 0x40000
    author: str | None = None
    description: str | None = None

    for line in source.splitlines()[:80]:
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

        m = _PRAGMA_BASE_RE.match(stripped)
        if m:
            base_address = _parse_int_value(m.group(1))
            continue

        m = _PRAGMA_EVAL_DEPTH_RE.match(stripped)
        if m:
            eval_depth = int(m.group(1))
            continue

        m = _PRAGMA_ARRAY_LIMIT_RE.match(stripped)
        if m:
            array_limit = _parse_int_value(m.group(1))
            continue

        m = _PRAGMA_PATTERN_LIMIT_RE.match(stripped)
        if m:
            pattern_limit = _parse_int_value(m.group(1))
            continue

        m = _PRAGMA_AUTHOR_RE.match(stripped)
        if m:
            author = m.group(1)
            continue

        m = _PRAGMA_DESCRIPTION_RE.match(stripped)
        if m:
            description = m.group(1)
            continue

    return PragmaInfo(
        endian=endian,
        mime=mime,
        magic=tuple(magic_list),
        base_address=base_address,
        eval_depth=eval_depth,
        array_limit=array_limit,
        pattern_limit=pattern_limit,
        author=author,
        description=description,
    )
