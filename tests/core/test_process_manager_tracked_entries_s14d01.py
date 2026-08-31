# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S14-D01: externally registered PIDs must surface as tracked.

Prior to this fix, ``ProcessManager.get_all_tracked()`` read only the
subprocess-backed ``_processes`` store, silently omitting every PID
registered through ``register_external_pid`` (the store used for
daemonized / attached / inspected processes). The Process panel's Tracked
tab is populated from that store via ``TrackedRefreshWorker``, so a user who
attached to or inspected a process saw "0 tracked" no matter what they did --
there was no code path that could ever surface an externally registered PID.

``ProcessManager.get_all_tracked_entries`` is the fix: it merges both stores
into a single list of ``TrackedEntry`` objects. These tests spawn real child
processes, register one via each store, and assert both appear with correct
identity and live running state -- and that killing the external PID's
backing process flips its reported running state to False. Each assertion is
falsifiable against the pre-fix ``get_all_tracked()`` behaviour, which would
either omit the external entry entirely or raise ``AttributeError`` because
``TrackedEntry`` did not exist.
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.process_manager import (
    ProcessManager,
    ProcessType,
    TrackedEntry,
)
from intellicrack.core.subprocess_compat import PIPE, Popen


if TYPE_CHECKING:
    from collections.abc import Generator

_PROCESS_WAIT_TIMEOUT_S: float = 5.0
_KILL_POLL_TIMEOUT_S: float = 5.0
_KILL_POLL_INTERVAL_S: float = 0.05


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ``ProcessManager`` singleton instance for each test.

    Yields:
        ProcessManager: A freshly reset ``ProcessManager`` instance.
    """
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


def _spawn_sleeper() -> Popen[bytes]:
    """Spawn a real, short-lived child process that sleeps.

    Returns:
        Popen[bytes]: The spawned child process handle.
    """
    return Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=PIPE,
        stderr=PIPE,
    )


def _find_entry(entries: list[TrackedEntry], pid: int) -> TrackedEntry:
    """Locate the entry for ``pid`` in a list of tracked entries.

    Args:
        entries: Entries returned by ``get_all_tracked_entries``.
        pid: Process ID to search for.

    Returns:
        TrackedEntry: The matching entry.
    """
    matches = [e for e in entries if e.pid == pid]
    assert len(matches) == 1, f"expected exactly one tracked entry for pid={pid}, found {len(matches)}"
    return matches[0]


class TestGetAllTrackedEntriesIncludesExternalPids:
    """get_all_tracked_entries must surface both subprocess- and externally-registered PIDs."""

    @staticmethod
    def test_external_pid_registered_via_the_ui_code_path_appears(
        process_manager: ProcessManager,
    ) -> None:
        """A PID registered exactly as the Track-This-Process UI action does must appear.

        This exercises the same call -- ``register_external_pid(pid, name)`` --
        that ``ProcessTab._on_track_process`` invokes when a user right-clicks a
        row in the System Processes table and selects "Track This Process".
        Pre-fix, this PID would never appear in ``get_all_tracked()`` (nor did
        ``get_all_tracked_entries`` exist at all), which is exactly the "0
        tracked" defect.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        external_proc = _spawn_sleeper()
        try:
            process_manager.register_external_pid(external_proc.pid, name="inspected-process")

            entries = process_manager.get_all_tracked_entries()

            entry = _find_entry(entries, external_proc.pid)
            assert entry.name == "inspected-process"
            assert entry.process_type == ProcessType.EXTERNAL_TOOL
            assert entry.is_running is True
        finally:
            external_proc.kill()
            external_proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)

    @staticmethod
    def test_combines_subprocess_and_external_entries_without_dropping_either(
        process_manager: ProcessManager,
    ) -> None:
        """Both a register()'d subprocess and a register_external_pid()'d PID must be present.

        A regression to the pre-fix behaviour (only reading ``_processes``)
        would make this test fail by omitting the external entry while the
        subprocess entry is still visible.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        spawned_proc = _spawn_sleeper()
        external_proc = _spawn_sleeper()
        try:
            process_manager.register(spawned_proc, name="app-spawned")
            process_manager.register_external_pid(external_proc.pid, name="attached-external")

            entries = process_manager.get_all_tracked_entries()
            pids = {e.pid for e in entries}

            assert spawned_proc.pid in pids
            assert external_proc.pid in pids

            spawned_entry = _find_entry(entries, spawned_proc.pid)
            external_entry = _find_entry(entries, external_proc.pid)
            assert spawned_entry.name == "app-spawned"
            assert external_entry.name == "attached-external"
        finally:
            spawned_proc.kill()
            spawned_proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)
            external_proc.kill()
            external_proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)

    @staticmethod
    def test_external_entry_running_state_reflects_live_os_state(
        process_manager: ProcessManager,
    ) -> None:
        """An external PID's is_running must flip to False once the OS process exits.

        Verifies ``get_all_tracked_entries`` resolves live state per-entry
        (via ``_pid_exists``) rather than reporting a static snapshot, so the
        Tracked tab's Status column reflects reality after the tracked
        process terminates.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        external_proc = _spawn_sleeper()
        process_manager.register_external_pid(external_proc.pid, name="short-lived-external")

        entries_before = process_manager.get_all_tracked_entries()
        assert _find_entry(entries_before, external_proc.pid).is_running is True

        external_proc.kill()
        external_proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)

        deadline = time.monotonic() + _KILL_POLL_TIMEOUT_S
        entries_after: list[TrackedEntry] = []
        while time.monotonic() < deadline:
            entries_after = process_manager.get_all_tracked_entries()
            if _find_entry(entries_after, external_proc.pid).is_running is False:
                break
            time.sleep(_KILL_POLL_INTERVAL_S)

        assert _find_entry(entries_after, external_proc.pid).is_running is False

    @staticmethod
    def test_empty_registries_produce_empty_entry_list(
        process_manager: ProcessManager,
    ) -> None:
        """A ProcessManager with nothing registered must report zero tracked entries.

        Args:
            process_manager: Fresh ProcessManager fixture.
        """
        assert process_manager.get_all_tracked_entries() == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
