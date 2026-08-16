# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack.

"""Gates for the Windows Sandbox graceful-close target selection (S18-D24).

The window inventory these tests are built from was captured from a live
Windows Sandbox session on 26100: one visible ``Windows Sandbox`` shell window
and twelve invisible helpers owned by the same session process.
"""

from __future__ import annotations

from typing import Final

from intellicrack.sandbox.windows import TopLevelWindow, select_close_targets

from .backend_constants import production_seconds


_SESSION_PID: Final[int] = 3836
_OTHER_PID: Final[int] = 15492
_SHELL_HANDLE: Final[int] = 329338

# Captured live from WindowsSandboxRemoteSession.exe (pid 3836). Only the
# WinUIDesktopWin32WindowClass shell window is visible; every other window the
# session owns is an IME, MSCTFIME UI, RDP sound/clipboard, timer or
# GUID-classed helper.
_LIVE_SESSION_WINDOWS: Final[tuple[TopLevelWindow, ...]] = (
    TopLevelWindow(handle=329456, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=_SHELL_HANDLE, owner_pid=_SESSION_PID, visible=True),
    TopLevelWindow(handle=394750, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=263866, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=329342, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=394934, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=1246570, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=263886, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=329352, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=460460, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=198362, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=263786, owner_pid=_SESSION_PID, visible=False),
    TopLevelWindow(handle=329332, owner_pid=_SESSION_PID, visible=False),
)

# Measured live: a single WM_CLOSE to the shell window took the session host and
# vmmemWindowsSandbox down together at 26.6s on an idle guest, and a guest still
# finishing its first boot took minutes. A budget that expires mid-unwind forces
# the kill that strands the VM.
_OBSERVED_IDLE_CLOSE_SECONDS: Final[float] = 26.6


class TestOnlyTheVisibleShellWindowIsClosed:
    """The close targets the window a user would close, not the helpers."""

    def test_the_live_session_inventory_yields_only_the_shell_window(self) -> None:
        """Thirteen real windows reduce to the one visible shell window."""
        targets = select_close_targets(_LIVE_SESSION_WINDOWS, _SESSION_PID)

        assert targets == (_SHELL_HANDLE,), f"expected only the visible shell window, selected {targets!r}"

    def test_an_invisible_helper_alone_is_not_a_close(self) -> None:
        """A session owning only helpers offers nothing to close.

        This is the case that let the caller lie: a post to a hidden helper
        counted as "the sandbox was asked to close".
        """
        helpers = tuple(window for window in _LIVE_SESSION_WINDOWS if not window.visible)
        assert helpers, "fixture must contain invisible helper windows"

        assert select_close_targets(helpers, _SESSION_PID) == ()

    def test_another_process_visible_window_is_never_closed(self) -> None:
        """Visibility alone does not make a window a target."""
        foreign = TopLevelWindow(handle=987654, owner_pid=_OTHER_PID, visible=True)

        targets = select_close_targets((*_LIVE_SESSION_WINDOWS, foreign), _SESSION_PID)

        assert foreign.handle not in targets
        assert targets == (_SHELL_HANDLE,)


class TestTheGracefulBudgetOutlastsARealClose:
    """The graceful wait must cover an actual sandbox teardown."""

    def test_the_budget_exceeds_the_measured_idle_close(self) -> None:
        """A close measured at 26.6s must fit inside the budget with room."""
        budget = production_seconds("_GRACEFUL_CLOSE_TIMEOUT")

        assert budget > _OBSERVED_IDLE_CLOSE_SECONDS * 2, (
            f"graceful budget {budget}s leaves no margin over a "
            f"{_OBSERVED_IDLE_CLOSE_SECONDS}s close; a budget that expires "
            "mid-unwind forces the kill that strands the VM"
        )
