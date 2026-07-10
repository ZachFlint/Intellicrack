# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.modules_tab``.

Audit shard 14 flagged the existing modules-tab tests for populating the
module tree from hand-built module dicts and never exercising the real
``ProcessBridge.get_modules`` enumeration. These tests attach a real
:class:`ProcessBridge` to the running interpreter and drive
``ModulesTab._refresh_modules`` so the module tree renders genuine loaded
Win32 modules. Assertions check real, verifiable values: every Python
process on Windows loads ``ntdll.dll`` and ``kernel32.dll`` with non-zero
base addresses and sizes, and the rendered base address must match the real
base reported by the bridge.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab
from tests._helpers.realcov_process_panel import (
    close_real_bridge,
    make_real_bridge_attached_to_self,
    pump_until,
    require_windows,
    run_bridge_sync,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.bridges.process import ProcessBridge

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def qapp() -> Iterator[QApplication]:
    """Provide a live QApplication for widget construction.

    Yields:
        QApplication: The running application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def real_bridge() -> Iterator[ProcessBridge]:
    """Provide a real ProcessBridge attached to the current process.

    Yields:
        ProcessBridge: Bridge initialized and attached to this process.
    """
    require_windows()
    bridge = make_real_bridge_attached_to_self()
    try:
        yield bridge
    finally:
        close_real_bridge(bridge)


class _ModulesTabProbe(ModulesTab):
    """Test subclass exposing typed accessors to protected tab members."""

    def refresh(self) -> None:
        """Drive the real module-list refresh."""
        self._refresh_modules()

    def module_count(self) -> int:
        """Return the number of top-level module rows.

        Returns:
            int: Count of rendered modules in the tree.
        """
        return self._mod_tree.topLevelItemCount()

    def count_label(self) -> str:
        """Return the module-count label text.

        Returns:
            str: The label text such as ``"79 modules"``.
        """
        return self._mod_count.text()

    def module_bases(self) -> dict[str, int]:
        """Map each rendered module name to its parsed base address.

        Returns:
            dict[str, int]: Lowercased module name to integer base address.
        """
        names: dict[str, int] = {}
        root = self._mod_tree.invisibleRootItem()
        if root is None:
            return names
        for i in range(root.childCount()):
            child = root.child(i)
            if child is None:
                continue
            names[child.text(0).lower()] = int(child.text(1), 16)
        return names


@pytest.fixture
def tab(qapp: QApplication, real_bridge: ProcessBridge) -> _ModulesTabProbe:
    """Create a ModulesTab probe wired to the real bridge and attached PID.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge attached to this process.

    Returns:
        _ModulesTabProbe: A probe driving the real bridge against this process.
    """
    del qapp
    widget = _ModulesTabProbe()
    widget.set_bridge(real_bridge)
    widget.set_attached_pid(os.getpid())
    return widget


def test_module_tree_lists_real_system_dlls(qapp: QApplication, tab: _ModulesTabProbe) -> None:
    """Real enumeration must render the always-present system DLLs.

    Every Win32 process loads ``ntdll.dll`` and (for a normal user-mode
    process) ``kernel32.dll``; the rendered tree must contain both with
    non-zero base addresses, proving genuine module enumeration drives the UI.

    Args:
        qapp: Qt application driving the event loop.
        tab: ModulesTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.module_count() > 0)
    assert populated, "module tree never populated from real get_modules()"

    rendered = tab.module_bases()
    assert "ntdll.dll" in rendered, f"ntdll.dll missing from {sorted(rendered)[:10]}"
    assert "kernel32.dll" in rendered
    assert rendered["ntdll.dll"] > 0
    assert rendered["kernel32.dll"] > 0


def test_rendered_base_matches_real_bridge_base(qapp: QApplication, tab: _ModulesTabProbe) -> None:
    """The base address rendered for ntdll must match the real bridge value.

    Args:
        qapp: Qt application driving the event loop.
        tab: ModulesTab probe bound to the real bridge.
    """
    bridge = tab.get_bridge()
    assert bridge is not None
    real_modules = run_bridge_sync(bridge.get_modules(os.getpid()))
    real_bases = {m.name.lower(): m.base_address for m in real_modules}

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.module_count() > 0)
    assert populated

    rendered = tab.module_bases()
    assert rendered["ntdll.dll"] == real_bases["ntdll.dll"]


def test_module_count_label_matches_real_count(qapp: QApplication, tab: _ModulesTabProbe) -> None:
    """The module-count label must equal the number of enumerated modules.

    Args:
        qapp: Qt application driving the event loop.
        tab: ModulesTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.module_count() > 0)
    assert populated

    count = tab.module_count()
    assert count >= 2
    assert tab.count_label() == f"{count} modules"
