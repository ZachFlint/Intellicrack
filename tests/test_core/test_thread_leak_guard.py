# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the session thread-leak detector.

Exercises :func:`tests._helpers.thread_leaks.find_leaked_background_threads`, the
predicate behind the session-scoped ``no_leaked_background_threads`` guard in
``tests/conftest.py``. That guard is what converts the whole-suite exit-124
shutdown hang -- a non-daemon worker left running by a test or fixture -- into a
loud, attributable failure. Each test drives the detector against a real,
controlled ``threading.Thread`` (no mocks) and joins it before returning, so the
gates themselves never leak a thread.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from tests._helpers.thread_leaks import find_leaked_background_threads


_JOIN_TIMEOUT_S = 5.0


def _live_idents() -> frozenset[int]:
    """Return the identifiers of every currently live thread.

    Returns:
        frozenset[int]: Identifiers reported by ``threading.enumerate()``.
    """
    return frozenset(thread.ident for thread in threading.enumerate() if thread.ident is not None)


def test_find_leaked_flags_live_nondaemon_thread_then_clears_after_join() -> None:
    """A non-daemon thread started after the baseline is flagged, and dropped once it exits."""
    release = threading.Event()
    baseline = _live_idents()
    worker = threading.Thread(target=release.wait, name="leak-guard-nondaemon-probe", daemon=False)
    worker.start()
    try:
        assert worker in find_leaked_background_threads(baseline)
    finally:
        release.set()
        worker.join(timeout=_JOIN_TIMEOUT_S)

    assert not worker.is_alive(), "probe thread must exit once released so no real leak remains"
    assert worker not in find_leaked_background_threads(baseline)


def test_find_leaked_flags_daemon_thread_only_when_name_is_managed() -> None:
    """A daemon thread is ignored by default and flagged only when its name matches a managed prefix."""
    release = threading.Event()
    baseline = _live_idents()
    worker = threading.Thread(target=release.wait, name="session-autosave-probe", daemon=True)
    worker.start()
    try:
        assert worker not in find_leaked_background_threads(baseline)
        assert worker in find_leaked_background_threads(baseline, managed_daemon_prefixes=("session-autosave",))
    finally:
        release.set()
        worker.join(timeout=_JOIN_TIMEOUT_S)

    assert not worker.is_alive(), "probe thread must exit once released so no real leak remains"


def test_find_leaked_ignores_threads_present_in_baseline() -> None:
    """A non-daemon thread already alive at the baseline is never reported as leaked."""
    release = threading.Event()
    worker = threading.Thread(target=release.wait, name="leak-guard-baseline-probe", daemon=False)
    worker.start()
    try:
        baseline_including_worker = _live_idents()
        assert worker.ident in baseline_including_worker
        assert worker not in find_leaked_background_threads(baseline_including_worker)
    finally:
        release.set()
        worker.join(timeout=_JOIN_TIMEOUT_S)

    assert not worker.is_alive(), "probe thread must exit once released so no real leak remains"


def test_find_leaked_ignores_idle_thread_pool_worker() -> None:
    """A parked ThreadPoolExecutor worker (idle on its queue) is not reported as a leak.

    An idle executor worker is non-daemon and started after the baseline, yet it
    is reaped cleanly at interpreter exit and does not hang shutdown, so the
    detector must exclude it. Falsifiable: dropping the idle-worker exclusion in
    ``find_leaked_background_threads`` makes the parked worker be reported, so the
    poll below never clears and this fails.
    """
    prefix = "leak-guard-idle-probe"
    baseline = _live_idents()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix=prefix) as pool:
        pool.submit(int).result(timeout=_JOIN_TIMEOUT_S)
        assert any(t.name.startswith(prefix) for t in threading.enumerate()), "the executor must have started a worker"

        deadline = time.monotonic() + _JOIN_TIMEOUT_S
        flagged = any(t.name.startswith(prefix) for t in find_leaked_background_threads(baseline))
        while flagged and time.monotonic() < deadline:
            time.sleep(0.05)
            flagged = any(t.name.startswith(prefix) for t in find_leaked_background_threads(baseline))
        assert not flagged, "an idle thread-pool worker must not be reported as a leaked thread"


def test_find_leaked_flags_busy_thread_pool_worker() -> None:
    """A ThreadPoolExecutor worker still running a task (blocked in user code) is reported.

    Distinguishes a genuinely stuck worker -- the failure mode behind the exit-124
    hang -- from a harmless idle one. Falsifiable: if the idle-worker exclusion
    also swallowed a worker executing a task, the busy worker below would never be
    reported and this fails.
    """
    prefix = "leak-guard-busy-probe"
    release = threading.Event()
    baseline = _live_idents()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix=prefix) as pool:
        future = pool.submit(release.wait, _JOIN_TIMEOUT_S * 2)
        try:
            deadline = time.monotonic() + _JOIN_TIMEOUT_S
            flagged = any(t.name.startswith(prefix) for t in find_leaked_background_threads(baseline))
            while not flagged and time.monotonic() < deadline:
                time.sleep(0.05)
                flagged = any(t.name.startswith(prefix) for t in find_leaked_background_threads(baseline))
            assert flagged, "a thread-pool worker blocked in a running task must be reported as a leak"
        finally:
            release.set()
            _ = future.result(timeout=_JOIN_TIMEOUT_S)
