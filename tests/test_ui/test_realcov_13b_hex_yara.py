# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the hex editor YARA result rendering path.

The audit (shard 13) flagged the YARA UI mixin (``yara.py``) as untested at
the panel level. These tests run a REAL YARA scan (via
:class:`intellicrack.core.yara_scanner.YaraScanner`) against a genuine Windows
PE binary, convert the real :class:`YaraMatch` objects into the exact dict
shape the bridge emits (hex-encoded match ``data``), and drive the mixin's
result-rendering method :meth:`YaraMixin._append_yara_match_strings`. The tests
assert that the rendered tree rows and the returned highlight offsets exactly
reflect the real, verifiable match positions in the file, not fabricated data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem

from intellicrack.ui.panels.hex_editor.yara import YaraMixin


if TYPE_CHECKING:
    from pathlib import Path


yara_scanner = pytest.importorskip(
    "intellicrack.core.yara_scanner",
    reason="yara_scanner backend required for real YARA result rendering",
)

if not yara_scanner.YaraScanner().available:
    pytest.skip("yara-python is not installed", allow_module_level=True)


pytestmark = pytest.mark.integration


_DOS_STUB_PREFIX: str = "This program cannot be run"
_RULE_SOURCE: str = 'rule dos_stub { strings: $a = "This program cannot be run" condition: $a }'


def _real_match_dicts(path: Path) -> list[dict[str, Any]]:
    """Run a real YARA scan and return matches in the bridge dict shape.

    Args:
        path: Path to a real PE binary to scan.

    Returns:
        list[dict[str, Any]]: Match dicts with ``rule`` and hex-encoded
            ``strings`` entries, matching the bridge's output contract.
    """
    scanner = yara_scanner.YaraScanner()
    data = path.read_bytes()
    rules = scanner.compile_source(_RULE_SOURCE)
    matches = scanner.scan_data(data, rules)
    result: list[dict[str, Any]] = []
    for match in matches:
        strings = [
            {
                "identifier": s.identifier,
                "offset": s.offset,
                "data": s.data.hex(),
            }
            for s in match.strings
        ]
        result.append({"rule": match.rule_name, "strings": strings})
    return result


class TestYaraMatchRendering:
    """Real YARA matches must render correctly and yield real offsets."""

    @pytest.fixture(scope="class")
    def qapp(self) -> QApplication:
        """Provide a shared QApplication for the YARA rendering tests.

        Returns:
            QApplication: The Qt application instance.
        """
        existing = QApplication.instance()
        if isinstance(existing, QApplication):
            return existing
        return QApplication([])

    def test_match_offset_matches_real_file(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify the rendered offset equals the real position of the matched string.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        data = real_pe_dll.read_bytes()
        matches = _real_match_dicts(real_pe_dll)
        assert matches, "real YARA scan produced no matches"
        match = matches[0]
        assert match["rule"] == "dos_stub"

        rule_item = QTreeWidgetItem([match["rule"], "", "", ""])
        offsets = YaraMixin._append_yara_match_strings(rule_item, match)

        assert len(offsets) == len(match["strings"])
        for offset, length in offsets:
            window = data[offset : offset + length]
            assert window.startswith(_DOS_STUB_PREFIX.encode("ascii"))

    def test_tree_children_encode_match_bytes(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify each rendered child row carries the real offset and hex bytes.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        matches = _real_match_dicts(real_pe_dll)
        match = matches[0]
        string_entry = match["strings"][0]
        real_offset = int(string_entry["offset"])

        rule_item = QTreeWidgetItem([match["rule"], "", "", ""])
        offsets = YaraMixin._append_yara_match_strings(rule_item, match)

        assert rule_item.childCount() == len(match["strings"])
        child = rule_item.child(0)
        assert child is not None
        assert child.text(1) == f"0x{real_offset:08X}"
        assert child.text(2) == string_entry["identifier"]
        first_byte_hex = string_entry["data"][:2].upper()
        assert child.text(3).startswith(first_byte_hex)
        assert offsets[0][0] == real_offset

    def test_malformed_strings_are_skipped(self, qapp: QApplication) -> None:
        """Verify entries without a valid offset are skipped, not crashed on.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        match: dict[str, Any] = {
            "rule": "partial",
            "strings": [
                {"identifier": "$bad", "data": "deadbeef"},
                {"identifier": "$ok", "offset": 256, "data": "cafebabe"},
            ],
        }
        rule_item = QTreeWidgetItem([match["rule"], "", "", ""])
        offsets = YaraMixin._append_yara_match_strings(rule_item, match)
        assert offsets == [(256, 4)]
        assert rule_item.childCount() == 1
