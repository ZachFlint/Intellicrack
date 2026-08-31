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
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Iterable


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
