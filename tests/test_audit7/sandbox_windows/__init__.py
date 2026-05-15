# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for audit7 ``windows.py`` findings (F-0013, F-0021).

The package collects regression tests for two anti-evasion / minidump defects
in :mod:`intellicrack.sandbox.windows`:

* **F-0013**: ``apply_anti_evasion`` previously wrote spoofed identity values
  to ``HKLM:\HARDWARE\DESCRIPTION``. That hive is volatile (rebuilt by the
  kernel at boot) and evasive samples query WMI providers anyway. The fix
  replaces the writes with a WMI provider hijack via a compiled MOF file.

* **F-0021**: ``dump_memory`` previously called ``MiniDumpWriteDump`` with
  ``GetCurrentProcess()`` — dumping the PowerShell host rather than the
  analysis target. The fix threads a required ``target_pid`` argument into
  the in-guest PowerShell so it ``OpenProcess`` es the right process.
"""
