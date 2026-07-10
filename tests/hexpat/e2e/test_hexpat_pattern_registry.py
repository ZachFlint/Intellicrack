# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat PatternRegistry discovery and matching."""

from __future__ import annotations

from pathlib import Path

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.pattern_registry import PatternMetadata, PatternRegistry


def _write_pattern(directory: Path, name: str, content: str) -> Path:
    """Write a .hexpat file to a directory and return its path.

    Args:
        directory: Target directory for the file.
        name: Stem of the file (without .hexpat extension).
        content: Source text to write.

    Returns:
        Path: Path to the created file.
    """
    p = directory / f"{name}.hexpat"
    p.write_text(content, encoding="utf-8")
    return p


class TestPatternDiscovery:
    """Tests for .hexpat file discovery via PatternRegistry.scan."""

    def test_scan_finds_single_pattern(self, tmp_path: Path) -> None:
        """scan() discovers a single .hexpat file in the configured directory.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "my_format", "u32 magic @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        registry.scan()
        patterns = registry.list_patterns()
        assert len(patterns) == 1
        assert patterns[0].name == "my_format"

    def test_scan_finds_multiple_patterns(self, tmp_path: Path) -> None:
        """scan() discovers all .hexpat files in the configured directory.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "format_a", "u8 a @ 0;")
        _write_pattern(tmp_path, "format_b", "u8 b @ 0;")
        _write_pattern(tmp_path, "format_c", "u8 c @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        registry.scan()
        names = [p.name for p in registry.list_patterns()]
        assert "format_a" in names
        assert "format_b" in names
        assert "format_c" in names

    def test_scan_ignores_non_hexpat_files(self, tmp_path: Path) -> None:
        """scan() does not index files without the .hexpat extension.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "valid", "u8 x @ 0;")
        (tmp_path / "readme.txt").write_text("not a pattern", encoding="utf-8")
        (tmp_path / "script.py").write_text("# not a pattern", encoding="utf-8")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        registry.scan()
        assert len(registry.list_patterns()) == 1

    def test_scan_recurses_into_subdirectories(self, tmp_path: Path) -> None:
        """scan() finds .hexpat files in subdirectories of the pattern directory.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sub = tmp_path / "binary"
        sub.mkdir()
        _write_pattern(sub, "elf", "u32 magic @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        registry.scan()
        names = [p.name for p in registry.list_patterns()]
        assert "elf" in names

    def test_scan_missing_directory_does_not_raise(self) -> None:
        """scan() silently skips a configured directory that does not exist."""
        registry = PatternRegistry(pattern_dirs=[Path("/nonexistent/path/xyz")])
        registry.scan()
        assert registry.list_patterns() == []

    def test_list_patterns_triggers_scan_if_not_scanned(self, tmp_path: Path) -> None:
        """list_patterns() calls scan() implicitly when not yet scanned.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "lazy", "u8 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        patterns = registry.list_patterns()
        assert len(patterns) == 1

    def test_list_patterns_sorted_by_name(self, tmp_path: Path) -> None:
        """list_patterns() returns patterns sorted alphabetically by name.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "zebra", "u8 x @ 0;")
        _write_pattern(tmp_path, "apple", "u8 y @ 0;")
        _write_pattern(tmp_path, "mango", "u8 z @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        names = [p.name for p in registry.list_patterns()]
        assert names == sorted(names)


class TestPatternMetadata:
    """Tests for metadata extraction from #pragma directives."""

    def test_description_extracted(self, tmp_path: Path) -> None:
        """PatternMetadata.description reflects the #pragma description value.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "desc_test", '#pragma description "ELF Binary"\nu32 x @ 0;')
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert pattern.description == "ELF Binary"

    def test_author_extracted(self, tmp_path: Path) -> None:
        """PatternMetadata.author reflects the #pragma author value.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "auth_test", '#pragma author "Alice"\nu32 x @ 0;')
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert pattern.author == "Alice"

    def test_mime_extracted(self, tmp_path: Path) -> None:
        """PatternMetadata.mime_types reflects the #pragma MIME value.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "mime_test", "#pragma MIME application/x-elf\nu32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert "application/x-elf" in pattern.mime_types

    def test_magic_bytes_extracted(self, tmp_path: Path) -> None:
        """PatternMetadata.magic_bytes reflects the #pragma magic value.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "magic_test",
            '#pragma magic [0x0, "7F454C46"]\nu32 x @ 0;',
        )
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert len(pattern.magic_bytes) == 1
        assert pattern.magic_bytes[0][0] == 0
        assert pattern.magic_bytes[0][1] == b"\x7f\x45\x4c\x46"

    def test_category_from_parent_directory(self, tmp_path: Path) -> None:
        """PatternMetadata.category is derived from the parent directory name.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sub = tmp_path / "executable"
        sub.mkdir()
        _write_pattern(sub, "pe", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert pattern.category == "executable"

    def test_no_description_is_none(self, tmp_path: Path) -> None:
        """PatternMetadata.description is None when no #pragma description is present.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "no_desc", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert pattern.description is None

    def test_file_path_is_absolute(self, tmp_path: Path) -> None:
        """PatternMetadata.file_path is an absolute resolved path.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "abs_test", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        assert pattern.file_path.is_absolute()


class TestPatternAutoDetect:
    """Tests for magic-byte-based pattern matching via match_file."""

    def test_match_file_finds_elf_pattern(self, tmp_path: Path) -> None:
        """match_file returns the ELF pattern when ELF magic bytes are present in data.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "elf_match",
            '#pragma magic [0x0, "7F454C46"]\nu32 magic @ 0;',
        )
        data = b"\x7fELF" + bytes(60)
        reader = DataReader.from_bytes(data)
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        matches = registry.match_file(reader)
        assert len(matches) == 1
        assert matches[0].name == "elf_match"

    def test_match_file_no_match_returns_empty(self, tmp_path: Path) -> None:
        """match_file returns an empty list when no magic bytes match.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "pe_match",
            '#pragma magic [0x0, "4D5A"]\nu32 magic @ 0;',
        )
        data = b"\x7fELF" + bytes(60)
        reader = DataReader.from_bytes(data)
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        matches = registry.match_file(reader)
        assert matches == []

    def test_match_file_prefers_longer_magic(self, tmp_path: Path) -> None:
        """match_file sorts results so longer magic sequences come first.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "short_magic",
            '#pragma magic [0x0, "4D5A"]\nu32 x @ 0;',
        )
        _write_pattern(
            tmp_path,
            "long_magic",
            '#pragma magic [0x0, "4D5A0090"]\nu32 x @ 0;',
        )
        data = bytes([0x4D, 0x5A, 0x00, 0x90]) + bytes(60)
        reader = DataReader.from_bytes(data)
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        matches = registry.match_file(reader)
        assert len(matches) == 2
        assert matches[0].name == "long_magic"

    def test_match_file_empty_data_returns_empty(self, tmp_path: Path) -> None:
        """match_file returns empty list for zero-length data.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "some_magic",
            '#pragma magic [0x0, "4D5A"]\nu32 x @ 0;',
        )
        reader = DataReader.from_bytes(b"")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        matches = registry.match_file(reader)
        assert matches == []


class TestPatternListing:
    """Tests for PatternRegistry listing and lookup methods."""

    def test_get_pattern_by_name(self, tmp_path: Path) -> None:
        """get_pattern returns the correct PatternMetadata for a known name.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "lookup_me", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        result = registry.get_pattern("lookup_me")
        assert result is not None
        assert result.name == "lookup_me"

    def test_get_pattern_unknown_returns_none(self, tmp_path: Path) -> None:
        """get_pattern returns None for an unknown pattern name.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(tmp_path, "exists", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        assert registry.get_pattern("does_not_exist") is None

    def test_list_by_category_groups_correctly(self, tmp_path: Path) -> None:
        """list_by_category groups patterns by their parent directory name.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        cat_a = tmp_path / "archives"
        cat_a.mkdir()
        cat_b = tmp_path / "executables"
        cat_b.mkdir()
        _write_pattern(cat_a, "zip", "u32 x @ 0;")
        _write_pattern(cat_b, "elf64", "u32 x @ 0;")
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        by_cat = registry.list_by_category()
        assert "archives" in by_cat
        assert "executables" in by_cat
        assert any(p.name == "zip" for p in by_cat["archives"])
        assert any(p.name == "elf64" for p in by_cat["executables"])

    def test_load_source_returns_file_content(self, tmp_path: Path) -> None:
        """load_source returns the full source text of a pattern file.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        content = '#pragma description "Test"\nu32 magic @ 0;'
        _write_pattern(tmp_path, "source_test", content)
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        pattern = registry.list_patterns()[0]
        loaded = PatternRegistry.load_source(pattern)
        assert "#pragma description" in loaded
        assert "u32 magic @ 0;" in loaded

    def test_pattern_metadata_fields_correct_type(self, tmp_path: Path) -> None:
        """PatternMetadata fields have the expected types after discovery.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        _write_pattern(
            tmp_path,
            "type_check",
            '#pragma author "Bob"\n#pragma MIME application/x-zip\nu32 x @ 0;',
        )
        registry = PatternRegistry(pattern_dirs=[tmp_path])
        p = registry.list_patterns()[0]
        assert isinstance(p, PatternMetadata)
        assert isinstance(p.name, str)
        assert isinstance(p.file_path, Path)
        assert isinstance(p.mime_types, tuple)
        assert isinstance(p.magic_bytes, tuple)
        assert isinstance(p.category, str)
