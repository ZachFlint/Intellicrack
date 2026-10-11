# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Mark every Audit7 sandbox-monitor test as integration.

The tests in this directory invoke real Windows scripts via subprocess
(``pwsh.exe`` / ``cmd.exe``) and exercise live kernel-object polling
and named-event signalling. They are end-to-end integration tests, so
they are tagged ``integration`` and excluded from the default unit
suite. An autouse fixture also reserves the shared named
``IntellicrackMonitorStop`` event for each test, so a test in another
pytest process cannot signal or reset it meanwhile, and leaves it
unsignaled so a previously signaled manual-reset handle cannot leak
across cases.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests._helpers.monitor_stop_event import monitor_stop_event_reserved


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


_THIS_DIR = Path(__file__).resolve().parent


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


@pytest.fixture(autouse=True)
def reset_stop_event() -> Iterator[None]:
    """Reserve the shared ``IntellicrackMonitorStop`` event for each test and leave it unsignaled.

    Without the reset, a manual-reset event signaled by one test
    would remain signaled for the next test, causing a freshly
    spawned monitor to short-circuit its main loop before the test had
    a chance to observe behavior. Without the reservation, a test in
    another pytest process that starts or stops monitors at the same
    time would see this test's signal, or signal this test's monitors.

    Yields:
        None: The test runs while the reservation is held.
    """
    with monitor_stop_event_reserved():
        yield
