# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ordinary probe that runs just before an isolated module, run only by the isolation gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_frida_isolation` passes it to a real
pytest run ahead of a module served from an isolation child. It lives in the
isolated probe's own package on purpose: tearing it down toward the isolated
item leaves that shared package on the session's setup stack.
"""

from __future__ import annotations

from tests._helpers.frida_isolation import in_isolated_child


def test_runs_in_the_session_process() -> None:
    """An ordinary test is not served from an isolation child."""
    assert not in_isolated_child()
