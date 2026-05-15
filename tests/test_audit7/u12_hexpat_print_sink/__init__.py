# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit7 U12 regression tests for the HexPat ``std::print`` sink wiring.

Pins the unit-12 remediation for core-hexpat F-0007 (``set_print_sink`` is dead
code: never called from any consumer). Two regression layers:

* Bridge layer: :class:`intellicrack.bridges.hex_editor.HexEditorBridge`
  must accept a ``print_sink`` callback on :meth:`execute_pattern` /
  :meth:`execute_pattern_file` and must expose new sibling methods
  ``execute_pattern_with_output`` / ``execute_pattern_file_with_output``
  that return the captured ``std::print`` text in the response payload
  under the ``hexpat_print`` key.
* UI layer: :class:`intellicrack.ui.panels.hex_editor._pattern_editor.
  PatternEditorMixin._apply_via_interpreter` must construct the cached
  interpreter with a ``print_sink`` callback that routes ``std::print``
  output into the pattern panel's dedicated print-output widget.
"""
