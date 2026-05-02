# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Integration tests for Audit-1 hexcore-rust findings.

Each test in this package is named after the finding (F-0001 ...
F-0005) it regresses, and exercises the Python bridge surface so that
both the Rust fix and the Python plumbing stay correct end-to-end.
"""
