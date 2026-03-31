# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge YARA scan operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


yara = pytest.importorskip("yara", reason="yara module not installed")


def _run(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
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


_MZ_YARA_RULE = """\
rule MZHeader {
    meta:
        description = "Matches MZ executable header"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
"""

_DEAD_BEEF_RULE = """\
rule DeadBeef {
    strings:
        $magic = { DE AD BE EF }
    condition:
        $magic
}
"""

_NO_MATCH_RULE = """\
rule NeverMatches {
    strings:
        $x = { 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 01 02 03 04 }
    condition:
        $x
}
"""

_EXPECTED_MATCH_KEYS = {"rule", "tags", "meta", "strings"}


class TestBridgeYaraScan:
    """Tests covering YARA scanning of document data via inline rule source."""

    def test_yara_scan_returns_list(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that yara_scan returns a list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_YARA_RULE))
        assert isinstance(results, list)

    def test_yara_scan_mz_rule_matches_pe_file(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the MZ header rule returns at least one match on a PE file.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_YARA_RULE))
        assert results

    def test_yara_scan_match_has_required_keys(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that each match dict has the rule, tags, meta, and strings keys.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_YARA_RULE))
        assert results
        for match in results:
            assert _EXPECTED_MATCH_KEYS.issubset(match.keys())

    def test_yara_scan_match_rule_name_matches_rule_identifier(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the rule field in the match equals the declared rule name.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_MZ_YARA_RULE))
        assert results[0]["rule"] == "MZHeader"

    def test_yara_scan_no_match_returns_empty_list(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that a rule with no matches returns an empty list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan(_NO_MATCH_RULE))
        assert not results

    def test_yara_scan_custom_bytes_match(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that a DEADBEEF rule matches a document containing those bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 8 + b"\xde\xad\xbe\xef" + b"\x00" * 8
        f = tmp_path / "deadbeef.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.yara_scan(_DEAD_BEEF_RULE))
        assert results
        assert results[0]["rule"] == "DeadBeef"


class TestBridgeYaraScanFiles:
    """Tests covering YARA scanning with rule files loaded from disk."""

    def test_yara_scan_files_with_rule_file_matches_pe(self, loaded_bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that yara_scan_files with a .yar file on disk produces matches.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_file = tmp_path / "mz.yar"
        rule_file.write_text(_MZ_YARA_RULE, encoding="utf-8")
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(str(rule_file)))
        assert isinstance(results, list)
        assert results

    def test_yara_scan_files_no_match_rule_returns_empty(self, loaded_bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that a rule file with no matches returns an empty list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            tmp_path: Pytest temporary directory.
        """
        rule_file = tmp_path / "nomatch.yar"
        rule_file.write_text(_NO_MATCH_RULE, encoding="utf-8")
        results: list[dict[str, Any]] = _run(loaded_bridge.yara_scan_files(str(rule_file)))
        assert not results
