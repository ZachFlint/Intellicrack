# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge yara_scan and yara_scan_files with deeper rule validation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")
pytest.importorskip("yara", reason="yara module not installed")


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


_EXPECTED_MATCH_KEYS: set[str] = {"rule", "tags", "meta", "namespace", "strings"}
_PE_TEXT_OFFSET: int = 0x200

_MZ_RULE: str = """\
rule MzSignature {
    meta:
        description = "Matches MZ executable header"
        author = "test"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
"""

_INT3_TEXT_RULE: str = """\
rule Int3InTextSection {
    meta:
        description = "Matches INT3 bytes in PE text section"
    strings:
        $breakpoint = { CC CC CC CC }
    condition:
        $breakpoint
}
"""

_TAGGED_RULE: str = """\
rule TaggedRule : executable windows {
    meta:
        author = "tester"
        version = "1.0"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
"""

_ASCII_PATTERN_RULE: str = """\
rule AsciiText {
    strings:
        $s1 = "INTELLITEST"
    condition:
        $s1
}
"""

_REGEX_RULE: str = """\
rule RegexMatch {
    strings:
        $r1 = /MAGIC[0-9]{4}/
    condition:
        $r1
}
"""

_NO_MATCH_RULE: str = """\
rule NeverMatches {
    strings:
        $x = { 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 01 02 03 04 05 }
    condition:
        $x
}
"""

_MULTI_RULE_SOURCE: str = """\
rule RuleAlpha {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule RuleBeta {
    strings:
        $breakpoint = { CC CC CC CC }
    condition:
        $breakpoint
}
"""


class TestYaraScanInline:
    """Tests for HexEditorBridge.yara_scan using inline YARA rule source strings."""

    def test_multi_rule_source_both_rules_match(self, loaded_bridge: Any) -> None:
        """Verify that a two-rule source returns two matches when both rules fire on the PE.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MULTI_RULE_SOURCE))
        rule_names = {r["rule"] for r in results}
        assert "RuleAlpha" in rule_names
        assert "RuleBeta" in rule_names

    def test_tagged_rule_populates_tags_field(self, loaded_bridge: Any) -> None:
        """Verify that a rule with tags returns a non-empty tags list in each match.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_TAGGED_RULE))
        assert results
        tags: list[str] = results[0]["tags"]
        assert isinstance(tags, list)
        assert "executable" in tags
        assert "windows" in tags

    def test_rule_with_meta_populates_meta_field(self, loaded_bridge: Any) -> None:
        """Verify that a rule with meta entries returns a non-empty meta dict per match.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_TAGGED_RULE))
        assert results
        meta: dict[str, Any] = results[0]["meta"]
        assert isinstance(meta, dict)
        assert "author" in meta
        assert meta["author"] == "tester"

    def test_regex_string_rule_finds_match(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a YARA regex string rule finds a matching substring.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"prefix MAGIC1234 suffix"
        f = tmp_path / "regex_target.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.yara_scan(_REGEX_RULE))
        assert results
        assert results[0]["rule"] == "RegexMatch"

    def test_int3_hex_pattern_matches_pe_text_section(self, loaded_bridge: Any) -> None:
        """Verify that a hex pattern {CC CC CC CC} matches the INT3 bytes in the PE .text section.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_INT3_TEXT_RULE))
        assert results
        assert results[0]["rule"] == "Int3InTextSection"

    def test_int3_match_strings_contain_correct_offset(self, loaded_bridge: Any) -> None:
        """Verify that the strings field in INT3 match contains an entry at the .text offset.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_INT3_TEXT_RULE))
        assert results
        strings: list[dict[str, Any]] = results[0]["strings"]
        assert isinstance(strings, list)
        assert strings
        found_offset = any(s["offset"] == _PE_TEXT_OFFSET for s in strings)
        assert found_offset

    def test_int3_match_strings_data_hex_equals_cc_bytes(self, loaded_bridge: Any) -> None:
        """Verify that the data field in the INT3 match strings is 'cccccccc'.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_INT3_TEXT_RULE))
        assert results
        strings: list[dict[str, Any]] = results[0]["strings"]
        target = next((s for s in strings if s["offset"] == _PE_TEXT_OFFSET), None)
        assert target is not None
        assert target["data"].lower() == "cccccccc"

    def test_no_match_rule_returns_empty_list(self, loaded_bridge: Any) -> None:
        """Verify that a rule that cannot match returns an empty list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_NO_MATCH_RULE))
        assert not results

    def test_ascii_string_rule_matches_embedded_text(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a plain ASCII string rule finds the literal in the document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00\x00INTELLITEST\x00\x00"
        f = tmp_path / "ascii_scan.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.yara_scan(_ASCII_PATTERN_RULE))
        assert results
        assert results[0]["rule"] == "AsciiText"

    def test_match_dict_has_all_required_keys(self, loaded_bridge: Any) -> None:
        """Verify every match dict contains rule, tags, meta, namespace, and strings keys.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_RULE))
        assert results
        for match in results:
            assert _EXPECTED_MATCH_KEYS.issubset(match.keys())


class TestYaraScanFiles:
    """Tests for HexEditorBridge.yara_scan_files using on-disk .yar rule files."""

    def test_single_yar_file_matches_same_as_inline_source(self, loaded_bridge: Any, tmp_path: Path) -> None:
        """Verify yara_scan_files with one .yar file produces the same rule names as yara_scan.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_file = tmp_path / "mz.yar"
        rule_file.write_text(_MZ_RULE, encoding="utf-8")
        file_results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(str(rule_file)))
        inline_results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_RULE))
        assert file_results
        file_rule_names = {r["rule"] for r in file_results}
        inline_rule_names = {r["rule"] for r in inline_results}
        assert file_rule_names == inline_rule_names

    def test_multiple_comma_separated_yar_files_both_match(self, loaded_bridge: Any, tmp_path: Path) -> None:
        """Verify yara_scan_files with two comma-separated paths returns matches from both files.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_a = tmp_path / "mz.yar"
        rule_a.write_text(_MZ_RULE, encoding="utf-8")
        rule_b = tmp_path / "int3.yar"
        rule_b.write_text(_INT3_TEXT_RULE, encoding="utf-8")
        combined_paths = f"{rule_a},{rule_b}"
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(combined_paths))
        rule_names = {r["rule"] for r in results}
        assert "MzSignature" in rule_names
        assert "Int3InTextSection" in rule_names

    def test_yar_file_with_no_match_rule_returns_empty(self, loaded_bridge: Any, tmp_path: Path) -> None:
        """Verify yara_scan_files with a non-matching rule file returns an empty list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_file = tmp_path / "nomatch.yar"
        rule_file.write_text(_NO_MATCH_RULE, encoding="utf-8")
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(str(rule_file)))
        assert not results

    def test_nonexistent_yar_file_raises_or_returns_error(self, loaded_bridge: Any, tmp_path: Path) -> None:
        """Verify yara_scan_files with a nonexistent path raises an exception.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        missing_path = str(tmp_path / "does_not_exist_xyz.yar")
        with pytest.raises((FileNotFoundError, RuntimeError, Exception)):
            _run(loaded_bridge.yara_scan_files(missing_path))

    def test_yar_file_match_strings_have_identifier_offset_data(self, loaded_bridge: Any, tmp_path: Path) -> None:
        """Verify that match strings from a file-based scan have identifier, offset, and data.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_file = tmp_path / "int3_strings.yar"
        rule_file.write_text(_INT3_TEXT_RULE, encoding="utf-8")
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(str(rule_file)))
        assert results
        strings: list[dict[str, Any]] = results[0]["strings"]
        assert strings
        for s in strings:
            assert "identifier" in s
            assert "offset" in s
            assert "data" in s
            assert isinstance(s["data"], str)
            bytes.fromhex(s["data"])
