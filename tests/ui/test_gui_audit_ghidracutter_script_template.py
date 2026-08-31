# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the 2026-07-01 GUI audit script-template fix.

The Cutter/Rizin (``r2``) template literal was indented to the Python source,
so every emitted command carried ~24 leading spaces, producing a malformed r2
script. This gate fails against that indented literal and passes once the
template is dedented to column zero like the other templates.
"""

from __future__ import annotations

from intellicrack.ui.panels.script_manager import ScriptTypeInfo


def test_r2_template_has_no_leading_whitespace() -> None:
    """No non-empty line of the rendered r2 template starts with whitespace."""
    rendered = ScriptTypeInfo.get_template("cutter", target="sample.exe")
    offending = [line for line in rendered.splitlines() if line and line[0].isspace()]
    assert offending == []


def test_r2_template_emits_expected_commands() -> None:
    """The dedented r2 template still contains its real analysis commands."""
    rendered = ScriptTypeInfo.get_template("cutter", target="sample.exe")
    lines = rendered.splitlines()
    assert "aaa" in lines
    assert "pdf" in lines
    assert "s main" in lines
    assert "# Target: sample.exe" in lines
