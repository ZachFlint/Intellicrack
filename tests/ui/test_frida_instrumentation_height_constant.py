# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for D40: a width constant driving a height property.

``ScriptMessagingControls`` built its ``QPlainTextEdit`` message box with
``setMaximumHeight(_ADDR_INPUT_MAX_WIDTH // 2)`` -- a *width* constant halved
to stand in for a height value. The numeric result happened to be a
reasonable height, but the coupling was accidental: any change intended for
the address-input column width would silently reshape the message box too,
and the name at the call site actively lied about what quantity it fed.

The fix introduces a correctly named ``_POST_MESSAGE_INPUT_MAX_HEIGHT``
constant and wires ``setMaximumHeight`` to it directly, leaving every width
usage of ``_ADDR_INPUT_MAX_WIDTH`` untouched. These tests drive the real
``ScriptMessagingControls`` widget under an offscreen ``QApplication`` and
also inspect the module source directly, so they fail both if the rendered
height regresses and if the call site is ever coupled back to the width
constant.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from intellicrack.ui.panels import frida_instrumentation_tab
from intellicrack.ui.panels.frida_instrumentation_tab import (
    _ADDR_INPUT_MAX_WIDTH,
    _POST_MESSAGE_INPUT_MAX_HEIGHT,
    ScriptMessagingControls,
)


pytestmark = pytest.mark.usefixtures("qapp")


class TestD40PostMessageHeightConstant:
    """Falsifiable gates for D40: the message box height must use its own named constant."""

    @staticmethod
    def test_height_constant_has_intended_value() -> None:
        """The height constant must hold its own intended value, not derive from the width one.

        Falsifiable: this fails if ``_POST_MESSAGE_INPUT_MAX_HEIGHT`` is
        edited away from the intended ``80`` (for example back to an
        expression tied to ``_ADDR_INPUT_MAX_WIDTH``).
        """
        assert _POST_MESSAGE_INPUT_MAX_HEIGHT == 80
        assert _ADDR_INPUT_MAX_WIDTH == 160

    @staticmethod
    def test_widget_maximum_height_matches_intended_value() -> None:
        """A real ``ScriptMessagingControls`` widget must render the intended max height.

        Falsifiable: reverting the call site to
        ``setMaximumHeight(_ADDR_INPUT_MAX_WIDTH // 2)`` still passes this
        specific numeric assertion by coincidence (80 == 160 // 2), so this
        test only proves the rendered value is correct; the source-coupling
        test below is what actually falsifies a revert to the width
        constant.
        """
        controls = ScriptMessagingControls()
        try:
            assert controls._post_message_input.maximumHeight() == _POST_MESSAGE_INPUT_MAX_HEIGHT
        finally:
            controls.deleteLater()

    @staticmethod
    def test_source_call_site_is_not_coupled_to_width_constant() -> None:
        """The ``setMaximumHeight`` call must reference the height constant, never the width one.

        Parses the module's source with ``ast`` and locates the
        ``setMaximumHeight`` call inside ``ScriptMessagingControls.__init__``,
        then asserts the argument expression is a bare reference to
        ``_POST_MESSAGE_INPUT_MAX_HEIGHT`` and contains no reference to
        ``_ADDR_INPUT_MAX_WIDTH`` anywhere in its expression tree.
        Falsifiable: reverting the call site to
        ``setMaximumHeight(_ADDR_INPUT_MAX_WIDTH // 2)`` makes the "no
        ``_ADDR_INPUT_MAX_WIDTH`` reference" assertion fail even though the
        numeric result is unchanged.
        """
        source = inspect.getsource(frida_instrumentation_tab)
        module_ast = ast.parse(source)

        class_node = next(
            node for node in ast.walk(module_ast) if isinstance(node, ast.ClassDef) and node.name == "ScriptMessagingControls"
        )
        init_node = next(node for node in ast.walk(class_node) if isinstance(node, ast.FunctionDef) and node.name == "__init__")

        set_max_height_calls = [
            node
            for node in ast.walk(init_node)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "setMaximumHeight"
        ]
        assert len(set_max_height_calls) == 1, "expected exactly one setMaximumHeight call in ScriptMessagingControls.__init__"

        call_node = set_max_height_calls[0]
        assert len(call_node.args) == 1
        arg_node = call_node.args[0]

        names_referenced = {node.id for node in ast.walk(arg_node) if isinstance(node, ast.Name)}
        assert names_referenced == {"_POST_MESSAGE_INPUT_MAX_HEIGHT"}
        assert "_ADDR_INPUT_MAX_WIDTH" not in names_referenced
