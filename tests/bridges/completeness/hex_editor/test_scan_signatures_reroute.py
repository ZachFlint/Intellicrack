# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for the hex-editor DIE/ClamAV/custom signature-scan reroute.

Covers the signatures tab's "Scan" action
(``ui/panels/hex_editor/signatures.py``
``SignaturesMixin._on_scan_signatures`` /
``_scan_signatures_via_bridge``), which now dispatches non-YARA scans to
the matching ``HexEditorBridge.scan_die_signatures`` /
``scan_clamav_signatures`` / ``scan_custom_signatures`` method (selected
by the database-type combo) when a bridge is attached, instead of
running the scan through a ``GenericCallableWorker`` calling a
module-level ``execute_signature_scan_from_source`` function. YARA has
no bridge equivalent and continues to run via the local worker
regardless of whether a bridge is attached.

Every test drives the real, unmodified ``SignaturesMixin`` wiring
through a real ``HexEditorPanel`` against a real
``intellicrack_hexcore.HexDocument`` and a real signature-database file
on disk; the only test double is a recording ``HexEditorBridge``
subclass (``RecordingHexEditorBridge`` in ``conftest.py``) that
delegates to the real scan implementations after appending to its call
ledgers, so the rendered results remain genuine end-to-end matches
rather than canned responses.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QComboBox, QTreeWidget

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import RecordingHexEditorBridge, open_doc, priv, priv_method, priv_set, pump_until, release_and_unlink, tree_columns


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_DIE_MAGIC = bytes.fromhex("deadbeef")
_DIE_DB_JSON = '[{"name": "gate-die-sig", "type": "packer", "version": "1.0", "patterns": [{"pattern": "DEADBEEF", "offset": "ep"}]}]'
_CUSTOM_DB_JSON = '[{"name": "gate-custom-sig", "type": "marker", "pattern": "deadbeef", "offset": "any"}]'
_CLAMAV_NDB_DB = "gate-clamav-sig:0:*:DEADBEEF\n"

_DB_TYPE_COMBO_INDEX = {"die": 0, "clamav": 1, "custom": 2}
"""Mirrors ``SignaturesMixin._on_scan_signatures``'s ``db_type_map`` (index -> type string), inverted."""


def _write_db(tmp_dir: Path, name: str, content: str) -> Path:
    """Write a signature-database file to a temp directory.

    Args:
        tmp_dir: Directory to write the file into.
        name: File name, including extension.
        content: Text content to write.

    Returns:
        Path: Path of the written database file.
    """
    db_path = tmp_dir / name
    db_path.write_text(content, encoding="utf-8")
    return db_path


class TestScanSignaturesRoutesThroughMatchingBridgeMethod:
    """The signature-scan action must dispatch to the bridge method matching the selected db type."""

    @staticmethod
    def test_die_scan_with_bridge_dispatches_scan_die_signatures(qapp: QApplication) -> None:
        """Selecting "DIE (JSON)" with a bridge attached must call ``bridge.scan_die_signatures`` only.

        Falsifiable: if ``_on_scan_signatures`` were reverted to always
        run the ``GenericCallableWorker``/``execute_signature_scan_from_source``
        path (the pre-remediation behaviour), ``scan_die_signatures_calls``
        would stay empty even though a bridge was attached and "DIE
        (JSON)" was selected. Broken production line: the
        ``{"die": bridge.scan_die_signatures, ...}[db_type](self._sig_db_path)``
        dispatch table in ``SignaturesMixin._scan_signatures_via_bridge``
        (``ui/panels/hex_editor/signatures.py:625``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, _DIE_MAGIC + b"\x00" * 12)
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = _write_db(tmp_dir, "gate.json", _DIE_DB_JSON)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_sig_db_type_combo", QComboBox).setCurrentIndex(_DB_TYPE_COMBO_INDEX["die"])
            priv_set(panel, "_sig_db_path", str(db_path))

            priv_method(panel, "_on_scan_signatures")()
            pump_until(qapp, lambda: len(bridge.scan_die_signatures_calls) > 0)

            assert bridge.scan_die_signatures_calls == [str(db_path)]
            assert bridge.scan_clamav_signatures_calls == []
            assert bridge.scan_custom_signatures_calls == []

            results_tree = priv(panel, "_sig_results_tree", QTreeWidget)
            pump_until(qapp, lambda: results_tree.topLevelItemCount() > 0)
            rows = tree_columns(results_tree, 0, 1, 2)
            assert rows == [("gate-die-sig", "packer", "1.0")]
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_clamav_scan_with_bridge_dispatches_scan_clamav_signatures(qapp: QApplication) -> None:
        """Selecting "ClamAV (.ndb/.hdb)" with a bridge attached must call ``bridge.scan_clamav_signatures`` only.

        Falsifiable: same failure mode as the DIE case above, but for
        the ClamAV branch of the dispatch table -- if the dispatch
        table were removed or hard-coded to a single method,
        ``scan_clamav_signatures_calls`` would stay empty (or the wrong
        ledger would be populated) for this ClamAV-selected scan.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, _DIE_MAGIC + b"\x00" * 12)
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = _write_db(tmp_dir, "gate.ndb", _CLAMAV_NDB_DB)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_sig_db_type_combo", QComboBox).setCurrentIndex(_DB_TYPE_COMBO_INDEX["clamav"])
            priv_set(panel, "_sig_db_path", str(db_path))

            priv_method(panel, "_on_scan_signatures")()
            pump_until(qapp, lambda: len(bridge.scan_clamav_signatures_calls) > 0)

            assert bridge.scan_clamav_signatures_calls == [str(db_path)]
            assert bridge.scan_die_signatures_calls == []
            assert bridge.scan_custom_signatures_calls == []

            results_tree = priv(panel, "_sig_results_tree", QTreeWidget)
            pump_until(qapp, lambda: results_tree.topLevelItemCount() > 0)
            assert tree_columns(results_tree, 0) == [("gate-clamav-sig",)]
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_custom_scan_with_bridge_dispatches_scan_custom_signatures(qapp: QApplication) -> None:
        """Selecting "Custom (JSON)" with a bridge attached must call ``bridge.scan_custom_signatures`` only.

        Falsifiable: same failure mode as the DIE/ClamAV cases above,
        but for the custom-JSON branch -- proves all three dispatch
        arms are wired, not just one.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, _DIE_MAGIC + b"\x00" * 12)
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = _write_db(tmp_dir, "gate_custom.json", _CUSTOM_DB_JSON)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_sig_db_type_combo", QComboBox).setCurrentIndex(_DB_TYPE_COMBO_INDEX["custom"])
            priv_set(panel, "_sig_db_path", str(db_path))

            priv_method(panel, "_on_scan_signatures")()
            pump_until(qapp, lambda: len(bridge.scan_custom_signatures_calls) > 0)

            assert bridge.scan_custom_signatures_calls == [str(db_path)]
            assert bridge.scan_die_signatures_calls == []
            assert bridge.scan_clamav_signatures_calls == []

            results_tree = priv(panel, "_sig_results_tree", QTreeWidget)
            pump_until(qapp, lambda: results_tree.topLevelItemCount() > 0)
            assert tree_columns(results_tree, 0) == [("gate-custom-sig",)]
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_scan_without_bridge_never_calls_any_bridge_scan_method(qapp: QApplication) -> None:
        """With no bridge attached, scanning must fall back to the worker path and never touch the bridge.

        Confirms the local ``GenericCallableWorker`` fallback remains
        reachable and distinct from the bridge path: this test
        constructs its own ``RecordingHexEditorBridge`` but never
        attaches it to the panel, so any call recorded on it would
        prove the panel reached for a bridge instance it was never
        given.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        unattached_bridge = RecordingHexEditorBridge()
        local_holder = RecordingHexEditorBridge()
        path = open_doc(local_holder, _DIE_MAGIC + b"\x00" * 12)
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = _write_db(tmp_dir, "gate.json", _DIE_DB_JSON)
        try:
            assert priv(panel, "_bridge", (RecordingHexEditorBridge, type(None))) is None
            panel.document = local_holder.document
            panel.file_path = path
            priv(panel, "_sig_db_type_combo", QComboBox).setCurrentIndex(_DB_TYPE_COMBO_INDEX["die"])
            priv_set(panel, "_sig_db_path", str(db_path))

            priv_method(panel, "_on_scan_signatures")()

            results_tree = priv(panel, "_sig_results_tree", QTreeWidget)
            pump_until(qapp, lambda: results_tree.topLevelItemCount() > 0, timeout_s=15.0)

            assert unattached_bridge.scan_die_signatures_calls == []
            assert unattached_bridge.scan_clamav_signatures_calls == []
            assert unattached_bridge.scan_custom_signatures_calls == []
            assert local_holder.scan_die_signatures_calls == []

            assert tree_columns(results_tree, 0) == [("gate-die-sig",)]
        finally:
            release_and_unlink(local_holder, path)
            panel.deleteLater()
