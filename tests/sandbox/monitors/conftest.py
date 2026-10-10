# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Mark every Audit3 sandbox monitor test as integration.

The tests in this directory invoke real Windows scripts via subprocess
(``pwsh.exe`` / ``cmd.exe``) against the live kernel-object table,
service control manager, clipboard, and injection surfaces. They are
end-to-end integration tests that exercise the real sandbox monitor
contracts against the host operating system rather than isolated unit
behaviour, so they are tagged ``integration`` and excluded from the
unit suite (``-m "not slow and not integration"``).

The monitors and ``stop_monitors.cmd`` share one machine-wide stop event,
so an autouse fixture reserves it for each test: a test in another pytest
process cannot signal it while this directory's monitors are running.
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
def reserved_stop_event() -> Iterator[None]:
    """Reserve the shared ``IntellicrackMonitorStop`` event for each test and leave it unsignaled.

    Yields:
        None: The test runs while the reservation is held.
    """
    with monitor_stop_event_reserved():
        yield
