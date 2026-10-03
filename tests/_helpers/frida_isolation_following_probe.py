# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ordinary probe that runs just after an isolated module, run only by the isolation gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_frida_isolation` passes it to a real
pytest run behind a module served from an isolation child. It lives outside the
isolated probe's package on purpose: its setup is what fails when a collector
the session no longer needs is still on the setup stack.
"""

from __future__ import annotations

from tests._helpers.frida_isolation import in_isolated_child


def test_sets_up_after_an_isolated_module() -> None:
    """An ordinary test that follows an isolated module runs in the session process."""
    assert not in_isolated_child()
