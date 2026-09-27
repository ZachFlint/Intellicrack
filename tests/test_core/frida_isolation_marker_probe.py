# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Module-marked isolation probe, run only by the isolation gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_frida_isolation` passes it to a real
pytest run by path. It requests no ``self_attached_bridge`` fixture: its only
claim to isolation is the module-level ``pytestmark``, which is exactly how the
Frida modules that attach through a differently named fixture opt in.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests._helpers.frida_isolation import in_isolated_child


PROCESS_REPORT_ENV = "IC_FRIDA_ISOLATION_PROCESS_REPORT"

pytestmark = pytest.mark.frida_selfattach


def test_reports_the_process_it_ran_in() -> None:
    """Write whether this test ran in an isolation child, and in which process."""
    report = os.environ.get(PROCESS_REPORT_ENV)
    if report is None:
        pytest.skip("the process report is written only for the isolation gate")
    _ = Path(report).write_text(f"{in_isolated_child()}\t{os.getppid()}", encoding="utf-8")
