# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared test infrastructure helpers.

Public surface:

* :mod:`tests._helpers.process_cleanup`: managed-process context manager and
  descendant snapshot/kill primitives used by the root ``conftest.py`` orphan
  killer fixture.
"""

from __future__ import annotations
