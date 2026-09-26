# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Self-attach Frida probe module whose tests skip, run only by the isolation gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_frida_isolation` passes it to a real
pytest run by path, which collects it, marks it for isolation through its
``self_attached_bridge`` fixture and serves its skips from the isolated child.
"""

from __future__ import annotations

import pytest


SETUP_SKIP_REASON = "self-attach target unavailable\tin setup"
CALL_SKIP_REASON = "frida-core refused the attach in the call"


@pytest.fixture
def self_attached_bridge() -> None:
    """Skip during setup, the way the real fixture does without a usable Frida."""
    pytest.skip(SETUP_SKIP_REASON)


def test_skips_in_setup(self_attached_bridge: None) -> None:
    """Never runs: its fixture skips.

    Args:
        self_attached_bridge: The skipping probe fixture.
    """
    _ = self_attached_bridge


def test_skips_in_call() -> None:
    """Skip from the test body."""
    pytest.skip(CALL_SKIP_REASON)


def test_passes() -> None:
    """Pass, so the module reports a mix of outcomes."""
