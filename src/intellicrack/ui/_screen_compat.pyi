# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
from collections.abc import Callable
from typing import Any

from PyQt6.QtWidgets import QApplication, QWidget

def _resolve(obj: object, method_name: str) -> Callable[..., Any]: ...
def get_screen_geometry(app: QApplication) -> tuple[int, int, int, int] | None: ...
def move_widget(widget: QWidget, x: int, y: int) -> None: ...
