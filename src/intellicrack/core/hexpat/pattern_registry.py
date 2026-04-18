# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pattern registry for discovering, indexing, and matching .hexpat files."""

from __future__ import annotations

import operator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.preprocessor import extract_pragmas_fast
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.core.hexpat.data_reader import DataReader


_logger = get_logger("core.hexpat.pattern_registry")


@dataclass(frozen=True)
class PatternMetadata:
    """Metadata extracted from a .hexpat pattern file.

    Attributes:
        name: The pattern name derived from the filename.
        file_path: Absolute path to the .hexpat file.
        description: Human-readable description from #pragma description.
        author: Pattern author from #pragma author.
        mime_types: MIME types this pattern handles from #pragma MIME.
        magic_bytes: Magic byte patterns for detection, as (offset, bytes) pairs.
        category: Category derived from the parent directory name.
    """

    name: str
    file_path: Path
    description: str | None
    author: str | None
    mime_types: tuple[str, ...]
    magic_bytes: tuple[tuple[int, bytes], ...]
    category: str


class PatternRegistry:
    """Discovers, indexes, and matches .hexpat pattern files.

    Scans specified directories for .hexpat files, extracts metadata from
    #pragma directives, and provides file-format matching via magic bytes.

    Args:
        pattern_dirs: Directories to scan for .hexpat files.
    """

    def __init__(self, pattern_dirs: list[Path] | None = None) -> None:
        """Initialize the PatternRegistry with directories to scan.

        Args:
            pattern_dirs: Directories to scan for .hexpat files.
        """
        self._pattern_dirs: list[Path] = list(pattern_dirs) if pattern_dirs else []
        self._patterns: list[PatternMetadata] = []
        self._by_name: dict[str, PatternMetadata] = {}
        self._scanned: bool = False
        self._max_magic_end: int = 0

    def scan(self) -> None:
        """Scan all configured directories for .hexpat files.

        Reads the first ~80 lines of each file to extract #pragma metadata. Results are cached until scan() is called again.
        """
        self._patterns = []
        self._by_name = {}
        self._max_magic_end = 0

        for pattern_dir in self._pattern_dirs:
            if not pattern_dir.exists():
                _logger.debug(
                    "pattern_dir_missing",
                    path=str(pattern_dir),
                )
                continue

            for hexpat_file in sorted(pattern_dir.rglob("*.hexpat")):
                metadata = self._extract_metadata(hexpat_file)
                if metadata is not None:
                    self._patterns.append(metadata)
                    self._by_name[metadata.name] = metadata
                    self._update_max_magic_end(metadata)

        self._scanned = True
        _logger.info(
            "pattern_scan_complete",
            pattern_count=len(self._patterns),
            directories=[str(d) for d in self._pattern_dirs],
        )

    def list_patterns(self) -> list[PatternMetadata]:
        """List all discovered patterns.

        Returns:
            list[PatternMetadata]: A list of PatternMetadata for all indexed .hexpat files,
            sorted by name.
        """
        if not self._scanned:
            self.scan()
        return sorted(self._patterns, key=lambda p: p.name)

    def list_by_category(self) -> dict[str, list[PatternMetadata]]:
        """List patterns grouped by category.

        Returns:
            dict[str, list[PatternMetadata]]: A dict mapping category names to lists of PatternMetadata.
        """
        if not self._scanned:
            self.scan()
        result: dict[str, list[PatternMetadata]] = {}
        for pattern in self._patterns:
            result.setdefault(pattern.category, []).append(pattern)
        for patterns in result.values():
            patterns.sort(key=lambda p: p.name)
        return dict(sorted(result.items()))

    def get_pattern(self, name: str) -> PatternMetadata | None:
        """Look up a pattern by name.

        Args:
            name: The pattern name to look up.

        Returns:
            PatternMetadata | None: The PatternMetadata if found, None otherwise.
        """
        if not self._scanned:
            self.scan()
        return self._by_name.get(name)

    def match_file(self, data_reader: DataReader) -> list[PatternMetadata]:
        """Find patterns whose magic bytes match the given binary data.

        Reads the first 1024 bytes and checks each indexed pattern's
        magic_bytes against the data.

        Args:
            data_reader: DataReader wrapping the binary data to match.

        Returns:
            list[PatternMetadata]: A list of matching PatternMetadata, sorted by specificity
            (longer magic sequences first).
        """
        if not self._scanned:
            self.scan()

        max_magic_end = max(1024, self._max_magic_end)

        read_size = min(max_magic_end, data_reader.size)
        if read_size == 0:
            return []

        header = data_reader.read(0, read_size)
        matches: list[tuple[int, PatternMetadata]] = []

        for pattern in self._patterns:
            if not pattern.magic_bytes:
                continue

            all_match = True
            total_magic_len = 0
            for offset, magic in pattern.magic_bytes:
                end = offset + len(magic)
                if end > len(header):
                    all_match = False
                    break
                if header[offset:end] != magic:
                    all_match = False
                    break
                total_magic_len += len(magic)

            if all_match:
                matches.append((total_magic_len, pattern))

        matches.sort(key=operator.itemgetter(0), reverse=True)
        return [m[1] for m in matches]

    def _update_max_magic_end(self, metadata: PatternMetadata) -> None:
        """Update the cached maximum magic-byte end offset for a pattern.

        Args:
            metadata: The pattern metadata whose magic_bytes should be folded
                into the cached maximum.
        """
        for pat_offset, magic in metadata.magic_bytes:
            end = pat_offset + len(magic)
            self._max_magic_end = max(self._max_magic_end, end)

    @staticmethod
    def load_source(metadata: PatternMetadata) -> str:
        """Load the full source code of a pattern file.

        Args:
            metadata: The pattern metadata with the file path.

        Returns:
            str: The full .hexpat source code as a string.
        """
        return metadata.file_path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _extract_metadata(path: Path) -> PatternMetadata | None:
        """Extract metadata from a .hexpat file's pragma directives.

        Args:
            path: Path to the .hexpat file.

        Returns:
            PatternMetadata | None: PatternMetadata if extraction succeeds, None on read errors.
        """
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _logger.debug("pattern_read_error", path=str(path))
            return None

        pragma = extract_pragmas_fast(source)

        name = path.stem

        category = path.parent.name if path.parent.name != "patterns" else "other"

        mime_types: tuple[str, ...] = (pragma.mime,) if pragma.mime else ()

        return PatternMetadata(
            name=name,
            file_path=path.resolve(),
            description=pragma.description,
            author=pragma.author,
            mime_types=mime_types,
            magic_bytes=pragma.magic,
            category=category,
        )
