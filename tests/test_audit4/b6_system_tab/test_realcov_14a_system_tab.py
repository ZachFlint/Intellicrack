# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.system_tab``.

Audit shard 14 flagged the existing system-tab tests for populating tables
from synthetic OS/registry dicts and never exercising real Win32 queries.
These tests attach a real :class:`ProcessBridge` to the running interpreter
and drive ``SystemTab._refresh_privileges`` so the privilege table renders the
process token's genuine privileges. Assertions check real, verifiable values:
the rendered privilege names must be valid ``Se*Privilege`` identifiers, must
include the always-present ``SeChangeNotifyPrivilege`` granted to every user
token, and the enabled/LUID columns must match the real bridge enumeration.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.process_panel.system_tab import SystemTab
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


class _SystemTabProbe(SystemTab):
    """Test subclass exposing typed accessors to protected tab members."""

    def refresh_privileges(self) -> None:
        """Drive the real token-privilege refresh."""
        self._refresh_privileges()

    def privilege_row_count(self) -> int:
        """Return the number of rows in the privilege table.

        Returns:
            int: Privilege-table row count.
        """
        return self._priv_table.rowCount()

    def rendered_privileges(self) -> dict[str, str]:
        """Map each rendered privilege name to its enabled-column text.

        Returns:
            dict[str, str]: Privilege name to enabled column ("Yes"/"No").
        """
        rows: dict[str, str] = {}
        for row in range(self._priv_table.rowCount()):
            name_item = self._priv_table.item(row, 0)
            enabled_item = self._priv_table.item(row, 2)
            if name_item is not None and enabled_item is not None:
                rows[name_item.text()] = enabled_item.text()
        return rows


@pytest.fixture
def tab(qapp: QApplication, real_bridge: ProcessBridge) -> _SystemTabProbe:
    """Create a SystemTab probe wired to the real bridge and attached PID.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge attached to this process.

    Returns:
        _SystemTabProbe: A probe driving the real bridge against this process.
    """
    del qapp
    widget = _SystemTabProbe()
    widget.set_bridge(real_bridge)
    widget.set_attached_pid(os.getpid())
    return widget


def test_privilege_table_populated_from_real_token(qapp: QApplication, tab: _SystemTabProbe) -> None:
    """Refresh must fill the privilege table from real token enumeration.

    Every user-mode Windows token holds at least ``SeChangeNotifyPrivilege``;
    the rendered table must be non-empty and every name must be a real
    ``Se*Privilege`` identifier read from this process's access token.

    Args:
        qapp: Qt application driving the event loop.
        tab: SystemTab probe bound to the real bridge.
    """
    tab.refresh_privileges()
    populated = pump_until(qapp, lambda: tab.privilege_row_count() > 0)
    assert populated, "privilege table never populated from real token"

    rendered = tab.rendered_privileges()
    assert rendered, "no privileges rendered"
    for name in rendered:
        assert name.startswith("Se"), f"unexpected privilege name {name!r}"
        assert name.endswith("Privilege"), f"unexpected privilege name {name!r}"
    assert "SeChangeNotifyPrivilege" in rendered


def test_rendered_privileges_match_real_bridge(
    qapp: QApplication,
    real_bridge: ProcessBridge,
    tab: _SystemTabProbe,
) -> None:
    """Rendered privilege names and enabled flags must match the real bridge.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge attached to this process.
        tab: SystemTab probe bound to the real bridge.
    """
    real_privs = run_bridge_sync(real_bridge.get_token_privileges(os.getpid()))
    expected = {str(p["name"]): ("Yes" if p.get("enabled") else "No") for p in real_privs if "name" in p}

    tab.refresh_privileges()
    populated = pump_until(qapp, lambda: tab.privilege_row_count() > 0)
    assert populated

    assert tab.rendered_privileges() == expected


def test_privilege_row_count_matches_real_count(
    qapp: QApplication,
    real_bridge: ProcessBridge,
    tab: _SystemTabProbe,
) -> None:
    """The rendered row count must equal the real privilege count.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge attached to this process.
        tab: SystemTab probe bound to the real bridge.
    """
    real_count = len(run_bridge_sync(real_bridge.get_token_privileges(os.getpid())))

    tab.refresh_privileges()
    populated = pump_until(qapp, lambda: tab.privilege_row_count() > 0)
    assert populated
    assert tab.privilege_row_count() == real_count
