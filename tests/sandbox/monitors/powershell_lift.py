# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Lift real functions out of the guest monitor scripts for use in harnesses.

Gates over the PowerShell collectors are only worth anything when the bytes they
exercise are the bytes the guest runs. Cutting a named function straight out of
the shipped ``.ps1`` and running it under a real PowerShell keeps a harness from
quietly testing a restatement of the script instead of the script.
"""

from __future__ import annotations


def lift_function(text: str, name: str) -> str:
    """Cut one PowerShell function out of a script by matching its braces.

    Args:
        text: Full text of the PowerShell script.
        name: Name of the function to lift.

    Returns:
        str: The function's source, or an empty string when it is not defined.
    """
    marker = f"function {name} {{"
    start = text.find(marker)
    if start < 0:
        return ""
    depth = 0
    for index in range(start + len(marker) - 1, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return ""
