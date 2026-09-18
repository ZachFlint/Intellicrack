# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Detection of background threads that a clean test run must not leave running.

A non-daemon thread that a test or fixture leaves alive blocks
``threading._shutdown`` when the interpreter exits: the main thread joins every
non-daemon thread, so one that never finishes hangs the process. That is the
exact mechanism behind the whole non-UI sandbox suite printing its summary and
then hanging until the container's hard timeout killed it (exit 124). This
module provides the pure predicate the session-scoped guard in
``tests/conftest.py`` uses, factored out so it can be exercised directly.

An *idle* ``concurrent.futures`` worker (an ``asyncio`` default-executor thread
parked on its work queue) is non-daemon but does **not** hang shutdown: the
executor registers ``_python_exit`` through :func:`threading._register_atexit`,
which runs inside ``threading._shutdown`` and wakes those parked workers so they
exit before they are joined. Tests that drive coroutines through a throwaway
``asyncio.new_event_loop()`` (closed without ``shutdown_default_executor``) leave
exactly such idle workers behind, so they are deliberately excluded here; only a
worker still *executing* a task (blocked in user code) is a genuine hang.
"""

from __future__ import annotations

import sys
import threading
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType


_POOL_WORKER_FUNCTION = "_worker"
_POOL_WORKER_MODULE = str(PurePosixPath("concurrent", "futures", "thread.py"))

# ``sys._current_frames`` is the only way to read another thread's current stack
# frame; it is reached through ``getattr`` (rather than direct attribute access)
# so the leading-underscore standard-library entry point stays type-clean.
_current_frames = cast("Callable[[], dict[int, FrameType]]", getattr(sys, "_current_frames"))


def _is_idle_pool_worker(ident: int | None) -> bool:
    """Report whether the thread with ``ident`` is a parked thread-pool worker.

    An idle ``concurrent.futures.ThreadPoolExecutor`` worker is blocked in
    ``_worker`` on ``work_queue.get(block=True)`` (the queue's ``get`` is C code
    with no Python frame), so its top Python frame is ``_worker`` in
    ``concurrent/futures/thread.py``. A worker that is running a task has deeper
    user-code frames on top instead, so this returns ``False`` for it.

    Args:
        ident: Thread identifier to inspect, or ``None``.

    Returns:
        bool: ``True`` only when the thread's current top frame is the executor's
            idle work-queue wait.
    """
    if ident is None:
        return False
    frame = _current_frames().get(ident)
    if frame is None:
        return False
    code = frame.f_code
    return code.co_name == _POOL_WORKER_FUNCTION and code.co_filename.replace("\\", "/").endswith(_POOL_WORKER_MODULE)


def find_leaked_background_threads(
    baseline_idents: frozenset[int],
    *,
    managed_daemon_prefixes: tuple[str, ...] = (),
) -> list[threading.Thread]:
    """Return live threads a clean test run should not have left running.

    A thread is reported when it was started after the session began (its
    identifier is absent from ``baseline_idents``), is still alive, is not the
    main thread, and is either non-daemon -- which blocks interpreter shutdown --
    or a managed daemon worker whose name starts with one of
    ``managed_daemon_prefixes`` (for example the ``SessionManager`` auto-save
    worker, which a fixture is expected to stop on teardown even though it is a
    daemon). A non-daemon thread that is only an *idle* thread-pool worker (see
    :func:`_is_idle_pool_worker`) is excluded, because such workers are reaped
    cleanly at interpreter exit and never hang shutdown.

    Args:
        baseline_idents: Thread identifiers already alive when the session began;
            threads with these identifiers are never reported.
        managed_daemon_prefixes: Name prefixes of daemon workers that a clean
            teardown must stop. Daemon threads whose name does not start with one
            of these are ignored.

    Returns:
        list[threading.Thread]: The offending live threads, empty when nothing
            was left running.
    """
    main = threading.main_thread()
    leaked: list[threading.Thread] = []
    for thread in threading.enumerate():
        if thread is main or not thread.is_alive() or thread.ident in baseline_idents:
            continue
        if thread.name.startswith(managed_daemon_prefixes):
            leaked.append(thread)
            continue
        if not thread.daemon and not _is_idle_pool_worker(thread.ident):
            leaked.append(thread)
    return leaked
