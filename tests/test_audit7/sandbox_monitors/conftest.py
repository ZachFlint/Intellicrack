# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Mark every Audit7 sandbox-monitor test as integration.

The tests in this directory invoke real Windows scripts via subprocess
(``pwsh.exe`` / ``cmd.exe``) and exercise live kernel-object polling
and named-event signalling. They are end-to-end integration tests, so
they are tagged ``integration`` and excluded from the default unit
suite. A session-scoped autouse fixture also resets the shared named
``IntellicrackMonitorStop`` event between tests so a previously
signalled manual-reset handle cannot leak across cases.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


_THIS_DIR = Path(__file__).resolve().parent
_STOP_EVENT_NAME: Final[str] = "IntellicrackMonitorStop"
_RESET_TIMEOUT_SEC: Final[float] = 10.0


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: Iterable[pytest.Item],
) -> None:
    """Tag every collected item under this directory with ``integration``.

    Args:
        config: Active pytest configuration (unused; required by hook
            signature).
        items: Collected test items to annotate; only items whose
            source file lives beneath this conftest's directory are
            tagged.
    """
    _ = config
    integration = pytest.mark.integration
    for item in items:
        path = getattr(item, "path", None)
        if path is None:
            continue
        try:
            resolved = Path(path).resolve()
        except OSError:
            continue
        if _THIS_DIR in resolved.parents:
            item.add_marker(integration)


def _reset_named_event(event_name: str) -> None:
    """Reset the named manual-reset event to its non-signalled state.

    The helper uses ``EventWaitHandle.OpenExisting`` first; if no
    handle exists the call is a no-op. When a handle does exist the
    helper calls ``Reset()`` so the next monitor that opens it starts
    from a clean non-signalled state.

    Args:
        event_name: Name of the kernel named event to reset.
    """
    if sys.platform != "win32":
        return
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh is None:
        return
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        f"  $h = [System.Threading.EventWaitHandle]::OpenExisting('{event_name}');"
        "  try { $h.Reset() | Out-Null } finally { $h.Dispose() }"
        "} catch {"
        "  $null = $_"
        "}"
    )
    try:
        subprocess.run(
            [
                pwsh,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_RESET_TIMEOUT_SEC,
        )
    except (subprocess.SubprocessError, OSError):
        return


@pytest.fixture(autouse=True)
def reset_stop_event() -> Iterator[None]:
    """Reset the shared ``IntellicrackMonitorStop`` event around each test.

    Without this fixture, a manual-reset event signalled by one test
    would remain signalled for the next test, causing a freshly
    spawned monitor to short-circuit its main loop before the test had
    a chance to observe behaviour.

    Yields:
        None: Tests run between the setup and teardown resets.
    """
    _reset_named_event(_STOP_EVENT_NAME)
    yield
    _reset_named_event(_STOP_EVENT_NAME)
