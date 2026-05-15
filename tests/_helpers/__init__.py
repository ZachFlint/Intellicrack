# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared test infrastructure helpers.

Public surface:

* :mod:`tests._helpers.process_cleanup`: managed-process context manager and
  descendant snapshot/kill primitives used by the root ``conftest.py`` orphan
  killer fixture.
* :mod:`tests._helpers.guest_allowlist`: host-side emulation of the QEMU
  Windows guest agent ``Test-AllowedCommand`` helper, shared by audit
  regression tests that assert command dispatches are allowlist-safe.
"""

from __future__ import annotations
