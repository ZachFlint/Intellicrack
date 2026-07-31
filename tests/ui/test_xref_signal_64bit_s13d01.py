# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for S13-D01: 64-bit VA truncated by 32-bit Qt signals.

``XRefPanel.xref_selected`` and ``_ToolOutputPanelBase.address_clicked`` were
declared as ``pyqtSignal(int)``, which PyQt6 maps to a C++ ``int`` (32-bit
signed). Emitting a real x64 virtual address through either signal silently
wrapped it to the low 32 bits, so cross-references never populated for the
correct address on any binary loaded above the 2 GiB mark. Both signals must
now carry the full 64-bit width (``qint64``).
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.tools import ToolOutputPanel, XRefPanel


if TYPE_CHECKING:
    from PyQt6.QtCore import QCoreApplication


# A genuine x64 user-mode virtual address. Its low 32 bits (0x12345678)
# differ from the full value, so any truncation to a 32-bit C++ int is
# directly observable in the received value.
_REAL_X64_VA: Final[int] = 0x7FF6_1234_5678
_TRUNCATED_LOW32: Final[int] = 0x1234_5678


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Provide a single QApplication for the test module.

    Returns:
        QCoreApplication: The running Qt application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


@pytest.mark.usefixtures("qapp")
class TestS13D01XRefPanelSignal64Bit:
    """``XRefPanel.xref_selected`` must round-trip a full 64-bit VA."""

    @staticmethod
    def test_item_click_emits_untruncated_64bit_address() -> None:
        """Clicking a real xref tree item must emit the full 64-bit VA.

        Drives the real production path (``set_xrefs`` populates the tree,
        a genuine ``QTreeWidgetItem`` click fires ``itemClicked``, which is
        wired to ``_on_item_clicked`` -> ``xref_selected.emit``) rather than
        emitting the signal directly, so the test also exercises the
        address parsing and click-handling code that feeds the signal.
        """
        panel = XRefPanel()
        received: list[int] = []
        panel.xref_selected.connect(received.append)
        try:
            panel.set_xrefs([(_REAL_X64_VA, "caller_a")], [])

            in_root = panel.xref_display.topLevelItem(0)
            assert in_root is not None
            in_child = in_root.child(0)
            assert in_child is not None
            assert f"0x{_REAL_X64_VA:08X}" in in_child.text(0)

            panel.xref_display.itemClicked.emit(in_child, 0)

            assert received == [_REAL_X64_VA]
            assert received[0] != _TRUNCATED_LOW32
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestS13D01ToolOutputPanelAddressClickedSignal64Bit:
    """``ToolOutputPanel.address_clicked`` must round-trip a full 64-bit VA."""

    @staticmethod
    def test_function_selection_emits_untruncated_64bit_address() -> None:
        """Selecting a function above the 32-bit boundary must not truncate.

        Drives the real production path (``func_list.function_selected`` ->
        ``_on_function_selected`` -> ``address_clicked.emit``) so the test
        exercises the actual wiring, not a synthetic direct emit.
        """
        panel = ToolOutputPanel()
        received: list[int] = []
        panel.address_clicked.connect(received.append)
        try:
            panel.func_list.function_selected.emit("main", _REAL_X64_VA)

            assert received == [_REAL_X64_VA]
            assert received[0] != _TRUNCATED_LOW32
        finally:
            panel.deleteLater()

    @staticmethod
    def test_xref_selection_emits_untruncated_64bit_address() -> None:
        """Following a cross-reference above the 32-bit boundary must not truncate.

        Drives ``xref_panel.xref_selected`` -> ``_on_xref_selected`` ->
        ``address_clicked.emit`` through the real signal chain connected in
        ``ToolOutputPanel._setup_ui``.
        """
        panel = ToolOutputPanel()
        received: list[int] = []
        panel.address_clicked.connect(received.append)
        try:
            panel.xref_panel.xref_selected.emit(_REAL_X64_VA)

            assert received == [_REAL_X64_VA]
            assert received[0] != _TRUNCATED_LOW32
        finally:
            panel.deleteLater()
