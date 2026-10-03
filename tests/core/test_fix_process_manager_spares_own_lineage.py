# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: the process manager never terminates the process it runs in, or an ancestor of it.

A tracked PID is terminated together with all of its descendants. The registry
accepts any live PID, Intellicrack's own included -- the Process panel's "Track
This Process" action registers whichever row was clicked -- and closing the main
window sweeps everything tracked. With its own PID in the registry the
application therefore killed itself in the middle of closing, and in the test
suite one test that left the worker's PID registered made the next test to
close a main window kill the whole worker, which the session could only report
as "node down: Not properly terminated" under an unrelated test's name.

Every gate here runs in a child interpreter, because the behaviour under test
is whether the process survives: without the fix the child is gone before it
can report anything.
"""

from __future__ import annotations

from typing import Final

from tests._helpers.child_python import run_child_json


_CHILD_TIMEOUT_S: Final[float] = 120.0


def test_a_shutdown_sweep_spares_the_process_that_runs_it_and_still_ends_the_others() -> None:
    """With its own PID tracked beside a real child's, a sweep ends the child and the process lives to say so.

    Falsifiable: an unguarded sweep terminates its own process, so the child
    interpreter exits before printing its report.
    """
    report = run_child_json(
        """
        import json
        import os
        import subprocess
        import sys

        import psutil

        from intellicrack.core.process_manager import ProcessManager

        sleeper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        manager = ProcessManager.get_instance()
        manager.register_external_pid(os.getpid(), name="self")
        manager.register_external_pid(sleeper.pid, name="sleeper")
        manager.request_shutdown()
        print(json.dumps({"survived": True, "sleeper_alive": psutil.pid_exists(sleeper.pid) and sleeper.poll() is None}))
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )

    assert report == {"survived": True, "sleeper_alive": False}


def test_terminating_its_own_tracked_pid_leaves_the_process_running() -> None:
    """Asking for the tracked entry that names this process to be terminated does not end the process.

    Falsifiable: an unguarded tree kill ends the child interpreter before it
    prints its report.
    """
    report = run_child_json(
        """
        import json
        import os

        from intellicrack.core.process_manager import ProcessManager

        manager = ProcessManager.get_instance()
        manager.register_external_pid(os.getpid(), name="self")
        manager.terminate_external_pid(os.getpid(), force=True)
        ProcessManager.terminate_tree(os.getpid())
        print(json.dumps({"survived": True}))
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )

    assert report == {"survived": True}


def test_a_shutdown_sweep_spares_an_ancestor_of_the_process_that_runs_it() -> None:
    """A sweep in a process whose parent's PID is tracked leaves the parent, and so itself, running.

    The child interpreter starts a grandchild that tracks the child's PID and
    sweeps. A tracked PID is terminated with its descendants, so an unguarded
    sweep ends the child and the grandchild together.

    Falsifiable: without the guard the child is terminated by its own
    grandchild and never prints the grandchild's report.
    """
    report = run_child_json(
        """
        import subprocess
        import sys

        grandchild = '''
        import json
        import os

        from intellicrack.core.process_manager import ProcessManager

        manager = ProcessManager.get_instance()
        manager.register_external_pid(os.getppid(), name="parent")
        manager.request_shutdown()
        print(json.dumps({"survived": True, "parent_tracked": True}))
        '''
        import textwrap

        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(grandchild)],
            capture_output=True,
            text=True,
            check=True,
            timeout=90,
        )
        print(completed.stdout.strip().splitlines()[-1])
        """,
        timeout_s=_CHILD_TIMEOUT_S,
    )

    assert report == {"survived": True, "parent_tracked": True}
