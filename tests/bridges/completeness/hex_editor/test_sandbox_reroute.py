# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gates for the hex-editor sandbox reroute (rows #92-93).

Covers ``audit/bridge-completeness/agent-09-hex-editor.md`` rows #92-93:
``ui/panels/hex_editor/sandbox.py``'s "Save to Sandbox"/"Test in Sandbox"
buttons previously called a generic ``SandboxBridge.copy_to``/``.execute``
directly, bypassing the hex-editor-specific ``HexEditorBridge.save_to_sandbox``/
``test_in_sandbox`` methods that auto-provision a sandbox instance, clean up
an orphaned instance on failure, and transparently handle unsaved/in-memory
documents. The remediation rewires both handlers to call
``run_bridge_coroutine_logged(bridge.save_to_sandbox(...))`` /
``bridge.test_in_sandbox(...)`` against the hex-editor's own bridge.

Because provisioning a real Windows Sandbox/QEMU VM cannot run inside the
Docker test sandbox, these tests substitute a fake ``SandboxBridge``
collaborator (``FakeSandboxBridge`` in ``conftest.py``) registered under
``ToolName.SANDBOX`` on a real ``ToolRegistry``. The ``HexEditorBridge``
itself, the real panel, and the real GUI-to-bridge dispatch machinery
(``run_bridge_coroutine_logged``) all execute for real; only the innermost
sandbox-VM boundary is faked.
"""

from __future__ import annotations

import posixpath
from typing import TYPE_CHECKING, cast

from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import FakeSandboxBridge, make_registry_with_sandbox, open_doc, priv, priv_method, pump_until, release_and_unlink


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_SANDBOX_DEST_PATH: str = posixpath.join("/", "tmp", "target.bin")
"""Destination path inside the (fake) sandbox container, not a host temp file."""


class TestSaveToSandboxRoutesThroughHexEditorBridge:
    """Row #92: "Save to Sandbox" must call ``HexEditorBridge.save_to_sandbox``, not a raw copy."""

    @staticmethod
    def test_click_dispatches_bridge_save_to_sandbox_and_never_calls_raw_copy_to(
        qapp: QApplication,
    ) -> None:
        """Clicking "Save to Sandbox" must route through create+copy_to via the hex-editor bridge.

        Falsifiable: if ``_on_save_to_sandbox`` were reverted to call
        ``SandboxBridge.copy_to`` directly against a pre-selected instance
        (the pre-remediation behaviour), the fake's ``create_calls`` list
        would stay empty (no auto-provisioning) while a ``copy_calls`` entry
        would appear referencing an instance ID the test never provided.
        Broken production line: ``run_bridge_coroutine_logged(
        bridge.save_to_sandbox(dest_path, sandbox_type=sandbox_type), ...)``
        in ``SandboxMixin._on_save_to_sandbox`` (``ui/panels/hex_editor/sandbox.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        fake_sandbox = FakeSandboxBridge()
        bridge.set_tool_registry(make_registry_with_sandbox(fake_sandbox))
        original = b"\x4d\x5a\x90\x00" * 4
        path = open_doc(bridge, original)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            panel.file_path = path

            priv(panel, "_sandbox_dest_input", QLineEdit).setText(_SANDBOX_DEST_PATH)

            priv_method(panel, "_on_save_to_sandbox")()
            pump_until(qapp, lambda: len(fake_sandbox.copy_calls) > 0 or len(fake_sandbox.create_calls) > 0)

            assert len(fake_sandbox.create_calls) == 1, "save_to_sandbox must auto-provision a sandbox instance via sandbox_bridge.create()"
            assert len(fake_sandbox.copy_calls) == 1
            assert fake_sandbox.copy_calls[0]["instance_id"] == fake_sandbox.next_instance_id
            assert fake_sandbox.copy_calls[0]["dest"] == _SANDBOX_DEST_PATH
            assert fake_sandbox.copy_calls[0]["source"] == str(path)

            instance_combo = priv(panel, "_sandbox_instance_combo", QComboBox)
            pump_until(qapp, lambda: instance_combo.currentText() == fake_sandbox.next_instance_id)
            assert instance_combo.currentText() == fake_sandbox.next_instance_id
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_failed_copy_destroys_the_auto_provisioned_instance(qapp: QApplication) -> None:
        """A failed copy must trigger ``sandbox_bridge.destroy`` on the auto-created instance.

        This orphan-cleanup behaviour only exists in
        ``HexEditorBridge.save_to_sandbox``'s ``finally`` block, never in
        the old raw ``SandboxBridge.copy_to`` GUI path. Falsifiable: if the
        GUI reverted to the raw-copy path, ``destroy_calls`` would stay
        empty since no instance was ever auto-created to clean up.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        fake_sandbox = FakeSandboxBridge()
        fake_sandbox.copy_should_fail = True
        bridge.set_tool_registry(make_registry_with_sandbox(fake_sandbox))
        original = b"\x90" * 16
        path = open_doc(bridge, original)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            panel.file_path = path

            priv_method(panel, "_on_save_to_sandbox")()
            sandbox_status = priv(panel, "_sandbox_status", QLabel)
            pump_until(
                qapp,
                lambda: len(fake_sandbox.destroy_calls) > 0 and "Error" in sandbox_status.text(),
            )

            assert fake_sandbox.destroy_calls == [fake_sandbox.next_instance_id], (
                "save_to_sandbox must destroy the orphaned auto-provisioned instance on copy failure"
            )
            assert sandbox_status.text() == "Error"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestTestInSandboxRoutesThroughHexEditorBridge:
    """Row #93: "Test in Sandbox" must call ``HexEditorBridge.test_in_sandbox``, not a raw execute."""

    @staticmethod
    def test_click_dispatches_bridge_test_in_sandbox_and_never_calls_raw_execute(
        qapp: QApplication,
    ) -> None:
        """Clicking "Test in Sandbox" must route through ``run_binary``, never the raw ``execute`` RPC.

        Falsifiable: if ``_on_test_in_sandbox`` were reverted to call
        ``SandboxBridge.execute`` directly, the fake's ``run_binary_calls``
        entries would carry ``_via_raw_execute: True`` and reference a
        pre-selected instance ID the test never set, instead of the
        end-to-end ``binary_path``/``args``/``sandbox_type``/``time_limit``
        signature that only ``run_binary`` receives. Broken production
        line: ``run_bridge_coroutine_logged(bridge.test_in_sandbox(...))``
        in ``SandboxMixin._on_test_in_sandbox`` (``ui/panels/hex_editor/sandbox.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        fake_sandbox = FakeSandboxBridge()
        fake_sandbox.run_binary_result = {"exit_code": 7, "stdout": "hello-sandbox", "stderr": ""}
        bridge.set_tool_registry(make_registry_with_sandbox(fake_sandbox))
        original = b"\x4d\x5a\x90\x00" * 4
        path = open_doc(bridge, original)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            panel.file_path = path

            priv(panel, "_sandbox_args_input", QLineEdit).setText("--flag value")
            priv(panel, "_sandbox_timeout_spin", QSpinBox).setValue(45)

            priv_method(panel, "_on_test_in_sandbox")()
            pump_until(qapp, lambda: len(fake_sandbox.run_binary_calls) > 0)

            assert len(fake_sandbox.run_binary_calls) == 1
            call = fake_sandbox.run_binary_calls[0]
            assert "_via_raw_execute" not in call, "test_in_sandbox must never fall back to the raw execute() RPC"
            assert call["binary_path"] == str(path)
            assert call["args"] == ["--flag", "value"]
            assert call["time_limit"] == 45

            sandbox_output = priv(panel, "_sandbox_output", QPlainTextEdit)
            pump_until(qapp, lambda: "hello-sandbox" in sandbox_output.toPlainText())
            assert "hello-sandbox" in sandbox_output.toPlainText()
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_without_saved_file_path_warns_and_never_dispatches(qapp: QApplication) -> None:
        """An unsaved (no ``file_path``) document must not reach the sandbox bridge at all.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        fake_sandbox = FakeSandboxBridge()
        bridge.set_tool_registry(make_registry_with_sandbox(fake_sandbox))
        panel.set_bridge(bridge)
        panel.file_path = None
        try:
            priv_method(panel, "_on_test_in_sandbox")()
            assert fake_sandbox.run_binary_calls == []
        finally:
            panel.deleteLater()


class TestSandboxButtonsWiredToRemediatedHandlers:
    """The Sandbox tab's buttons must be connected to the remediated handlers."""

    @staticmethod
    def test_save_and_test_buttons_have_connected_slots(qapp: QApplication) -> None:
        """Both sandbox buttons must exist by their real label text and have a connected slot.

        Falsifiable: if the buttons were removed from ``_create_sandbox_tab``
        (``ui/panels/hex_editor/sandbox.py``), no ``QPushButton`` with the
        expected text would be found; if the ``clicked.connect(...)`` calls
        were removed, ``receivers`` would be ``0``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            container = cast("QWidget", priv_method(panel, "_create_sandbox_tab")())
            buttons = {btn.text(): btn for btn in container.findChildren(QPushButton)}
            assert "Save to Sandbox" in buttons
            assert "Test in Sandbox" in buttons

            save_btn = buttons["Save to Sandbox"]
            test_btn = buttons["Test in Sandbox"]
            assert save_btn.receivers(save_btn.clicked) >= 1
            assert test_btn.receivers(test_btn.clicked) >= 1
        finally:
            panel.deleteLater()
