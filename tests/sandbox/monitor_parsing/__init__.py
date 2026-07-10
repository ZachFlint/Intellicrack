# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit7 sandbox-monitor tests.

Covers F-0019 (structured ``dll_event_unparsed`` record promoted to the
main log with ``image_path=null``, ``payload_schema`` and ``event_id``)
and F-0025 (named ``IntellicrackMonitorStop`` event coordination across
the four monitor scripts plus the ``stop_monitors.cmd`` driver).
"""

from __future__ import annotations
