# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Screen geometry detection for PyQt6 SIP-generated bindings.

Provides wrapper functions that use dynamic attribute dispatch to access
Qt screen and widget geometry methods. These wrappers exist because
basedpyright cannot resolve certain inherited method signatures from
the auto-generated PyQt6 type definitions. Each function performs a real
runtime call to the underlying Qt method.

Every wrapper validates that the target method exists at runtime and
raises ``AttributeError`` with a clear diagnostic if the method is
missing, ensuring failures are immediately identifiable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from PyQt6.QtWidgets import QApplication, QWidget

_PRIMARY_SCREEN = "primaryScreen"
_AVAILABLE_GEOMETRY = "availableGeometry"
_MOVE = "move"


def _resolve(obj: object, method_name: str) -> Callable[..., Any]:
    """Resolve a method on a Qt object, raising a clear error if absent.

    Args:
        obj: The Qt object instance.
        method_name: The camelCase method name to look up.

    Returns:
        The bound method callable.

    Raises:
        AttributeError: If the method does not exist on the object.
    """
    if not hasattr(obj, method_name):
        cls_name = type(obj).__name__
        msg = f"{cls_name} has no method '{method_name}'; PyQt6 binding may be incompatible"
        raise AttributeError(msg)
    method: Callable[..., Any] = getattr(obj, method_name)
    return method


def get_screen_geometry(app: QApplication) -> tuple[int, int, int, int] | None:
    """Return the primary screen's available area as (x, y, width, height).

    Args:
        app: The QApplication instance.

    Returns:
        Tuple of (x, y, width, height) or None if no screen detected.
    """
    screen: object = _resolve(app, _PRIMARY_SCREEN)()
    if screen is None:
        return None
    rect: object = _resolve(screen, _AVAILABLE_GEOMETRY)()
    x: int = _resolve(rect, "x")()
    y: int = _resolve(rect, "y")()
    w: int = _resolve(rect, "width")()
    h: int = _resolve(rect, "height")()
    return (x, y, w, h)


def move_widget(widget: QWidget, x: int, y: int) -> None:
    """Move a widget to the specified screen coordinates.

    Args:
        widget: The widget to move.
        x: X coordinate in screen pixels.
        y: Y coordinate in screen pixels.
    """
    _resolve(widget, _MOVE)(x, y)
