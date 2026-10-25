# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for the HexPat ``std::print`` sink wiring.

Pins the wiring of ``set_print_sink``, which every consumer must call. Two
regression layers:

* Bridge layer: :class:`intellicrack.bridges.hex_editor.HexEditorBridge`
  must accept a ``print_sink`` callback on :meth:`execute_pattern` /
  :meth:`execute_pattern_file` and must expose new sibling methods
  ``execute_pattern_with_output`` / ``execute_pattern_file_with_output``
  that return the captured ``std::print`` text in the response payload
  under the ``hexpat_print`` key.
* UI layer: :class:`intellicrack.ui.panels.hex_editor.pattern_editor.
  PatternEditorMixin._apply_via_interpreter` must construct the cached
  interpreter with a ``print_sink`` callback that routes ``std::print``
  output into the pattern panel's dedicated print-output widget.
"""
