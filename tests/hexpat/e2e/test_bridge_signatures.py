# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge non-YARA signature database scanning."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
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


class TestDIESignatures:
    """Tests for DIE-style JSON signature database scanning."""

    def test_die_scan_detects_mz_header(
        self,
        bridge: HexEditorBridge,
        pe_binary_full: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify DIE scan detects MZ pattern in a PE file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
            sig_db_dir: Path to the directory with test signature databases.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        results = _run(bridge.scan_die_signatures(str(sig_db_dir / "die_test.json")))
        assert results
        assert any(r["name"] == "MZ Executable" for r in results)

    def test_die_scan_no_match_returns_empty(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify DIE scan returns empty list when no pattern matches.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            sig_db_dir: Path to the directory with test signature databases.
        """
        f = tmp_path / "not_pe.bin"
        f.write_bytes(b"\x00" * 128)
        _run(bridge.open_file(str(f)))
        results = _run(bridge.scan_die_signatures(str(sig_db_dir / "die_test.json")))
        assert results == []


class TestClamAVSignatures:
    """Tests for ClamAV .hdb and .ndb signature scanning."""

    def test_clamav_hdb_md5_match(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify HDB scan matches a file by MD5 hash.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            sig_db_dir: Path to the directory with test signature databases.
        """
        known_data = b"MZ" + b"\x00" * 62
        f = tmp_path / "hdb_target.bin"
        f.write_bytes(known_data)
        _run(bridge.open_file(str(f)))
        results = _run(bridge.scan_clamav_signatures(str(sig_db_dir / "test.hdb")))
        assert results
        assert results[0]["type"] == "hash"

    def test_clamav_hdb_no_match(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify HDB scan returns empty for a non-matching file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            sig_db_dir: Path to the directory with test signature databases.
        """
        f = tmp_path / "hdb_nomatch.bin"
        f.write_bytes(b"\xff" * 128)
        _run(bridge.open_file(str(f)))
        results = _run(bridge.scan_clamav_signatures(str(sig_db_dir / "test.hdb")))
        assert results == []

    def test_clamav_ndb_pattern_match(
        self,
        bridge: HexEditorBridge,
        pe_binary_full: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify NDB scan finds MZ hex pattern at wildcard offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary.
            sig_db_dir: Path to the directory with test signature databases.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        results = _run(bridge.scan_clamav_signatures(str(sig_db_dir / "test.ndb")))
        assert results
        assert results[0]["type"] == "ndb"


class TestCustomSignatures:
    """Tests for custom JSON signature database scanning."""

    def test_custom_json_ep_match(
        self,
        bridge: HexEditorBridge,
        pe_binary_full: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify custom scan with ep offset matches MZ at entry point.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary.
            sig_db_dir: Path to the directory with test signature databases.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        results = _run(bridge.scan_custom_signatures(str(sig_db_dir / "custom.json")))
        ep_matches = [r for r in results if r["name"] == "MZ EP Match"]
        assert ep_matches
        assert ep_matches[0]["offset"] == 0

    def test_custom_json_any_match(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify custom scan with any offset finds pattern anywhere in file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            sig_db_dir: Path to the directory with test signature databases.
        """
        data = b"\x00" * 32 + b"\xde\xad\xbe\xef" + b"\x00" * 32
        f = tmp_path / "custom_any.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))
        results = _run(bridge.scan_custom_signatures(str(sig_db_dir / "custom.json")))
        any_matches = [r for r in results if r["name"] == "Any Byte Match"]
        assert any_matches
        assert any_matches[0]["offset"] == 32

    def test_custom_json_fixed_offset_match(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify custom scan with fixed offset matches at exact position.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            sig_db_dir: Path to the directory with test signature databases.
        """
        data = b"\x00\x01\x02\x03" + b"\x00" * 60
        f = tmp_path / "custom_fixed.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))
        results = _run(bridge.scan_custom_signatures(str(sig_db_dir / "custom.json")))
        fixed_matches = [r for r in results if r["name"] == "Fixed Offset Match"]
        assert fixed_matches
        assert fixed_matches[0]["offset"] == 0


class TestSignatureResultStructure:
    """Tests for the structure of signature scan result dictionaries."""

    def test_scan_result_structure(
        self,
        bridge: HexEditorBridge,
        pe_binary_full: Path,
        sig_db_dir: Path,
    ) -> None:
        """Verify each scan result has name, type, version, offset, details keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary.
            sig_db_dir: Path to the directory with test signature databases.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        results = _run(bridge.scan_die_signatures(str(sig_db_dir / "die_test.json")))
        assert results
        for r in results:
            assert "name" in r
            assert "type" in r
            assert "version" in r
            assert "offset" in r
            assert "details" in r

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify scan_die_signatures raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.scan_die_signatures("/nonexistent.json"))
