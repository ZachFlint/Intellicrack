# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit finding M8: ThreadsTab combo selection reset.

The auto-refresh timer rebuilds the Registers/Stack/Exceptions/Fibers/TLS
thread selectors every three seconds by calling
``ThreadsTab.update_thread_list``. The pre-fix implementation cleared and
repopulated each combo unconditionally, which reset the user's chosen thread
back to index 0 on every refresh. These tests pin the fixed contract:

* When the previously selected thread is still present after a refresh, its
  selection is preserved (``currentData`` is unchanged).
* When the previously selected thread has disappeared, the selector falls
  back to the first available thread rather than retaining a stale id.
* Every one of the five thread selectors preserves its selection
  independently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.types import ThreadInfo
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication, QComboBox


def _make_threads(tids: list[int]) -> list[ThreadInfo]:
    """Build a list of ThreadInfo records for the given thread IDs.

    Args:
        tids: Thread IDs to materialize.

    Returns:
        list[ThreadInfo]: One ThreadInfo per supplied TID.
    """
    return [ThreadInfo(tid=t, start_address=0x401000, current_pc=0x401050, state="running") for t in tids]


def _combo(tab: ThreadsTab, name: str) -> QComboBox:
    """Return a named thread-selector combo without tripping private-usage checks.

    Args:
        tab: The ThreadsTab owning the selector.
        name: The private attribute name of the combo.

    Returns:
        QComboBox: The requested combo box.
    """
    value: object = getattr(tab, name)
    return cast("QComboBox", value)


@pytest.fixture
def threads_tab(qapp: QApplication) -> Iterator[ThreadsTab]:
    """Create a ThreadsTab ready for combo-selection assertions.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        ThreadsTab: A ready-to-use tab instance.
    """
    del qapp
    tab = ThreadsTab()
    yield tab
    tab.cleanup()
    tab.deleteLater()


class TestM8ThreadComboSelectionPreserved:
    """M8: repopulating thread selectors must not clobber the user's selection."""

    def test_selection_preserved_when_thread_still_present(self, threads_tab: ThreadsTab) -> None:
        """Selecting TID 4000 then refreshing with 4000 still present keeps it selected.

        This is the core regression: the pre-fix ``update_thread_list`` reset
        the combo to index 0 (TID 4000) on every call. Here we deliberately
        select the *non-default* TID 4001 so a reset-to-index-0 bug is
        distinguishable from correct preservation.

        Args:
            threads_tab: ThreadsTab fixture.
        """
        threads_tab.update_thread_list(_make_threads([4000, 4001, 4002]))
        combo = _combo(threads_tab, "_reg_combo")
        target_index = combo.findData(4001)
        assert target_index >= 0, "TID 4001 must be present to select it"
        combo.setCurrentIndex(target_index)
        assert combo.currentData() == 4001, "precondition: TID 4001 must be selected before refresh"

        threads_tab.update_thread_list(_make_threads([4000, 4001, 4002]))

        assert combo.currentData() == 4001, (
            "after a refresh that still contains TID 4001, the selection must be preserved "
            f"(got {combo.currentData()!r}); the pre-fix bug reset it to index 0 (TID 4000)"
        )

    def test_selection_resets_when_thread_gone(self, threads_tab: ThreadsTab) -> None:
        """When the selected thread disappears, the selector falls back to the first entry.

        Args:
            threads_tab: ThreadsTab fixture.
        """
        threads_tab.update_thread_list(_make_threads([4000, 4001, 4002]))
        combo = _combo(threads_tab, "_reg_combo")
        combo.setCurrentIndex(combo.findData(4001))
        assert combo.currentData() == 4001, "precondition: TID 4001 selected"

        threads_tab.update_thread_list(_make_threads([4000, 4002]))

        assert combo.currentData() != 4001, "a thread that no longer exists must not remain selected"
        assert combo.currentData() == 4000, "with TID 4001 gone the selector must fall back to the first thread (4000)"

    def test_every_selector_preserves_independently(self, threads_tab: ThreadsTab) -> None:
        """All five thread selectors preserve their own distinct selection across a refresh.

        Args:
            threads_tab: ThreadsTab fixture.
        """
        threads_tab.update_thread_list(_make_threads([7000, 7001, 7002, 7003, 7004]))

        selectors: list[tuple[QComboBox, int]] = [
            (_combo(threads_tab, "_reg_combo"), 7000),
            (_combo(threads_tab, "_stack_combo"), 7001),
            (_combo(threads_tab, "_seh_combo"), 7002),
            (_combo(threads_tab, "_fiber_combo"), 7003),
            (_combo(threads_tab, "_tls_thread_combo"), 7004),
        ]
        for combo, tid in selectors:
            combo.setCurrentIndex(combo.findData(tid))
            assert combo.currentData() == tid, f"precondition: combo must be able to select TID {tid}"

        threads_tab.update_thread_list(_make_threads([7000, 7001, 7002, 7003, 7004]))

        for combo, tid in selectors:
            assert combo.currentData() == tid, (
                f"selector must independently preserve its selection of TID {tid} across refresh; got {combo.currentData()!r}"
            )
