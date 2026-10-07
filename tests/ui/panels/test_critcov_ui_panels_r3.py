# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the Ghidra panel's optional-import fallbacks and the win32 embed style-write failure.

The Ghidra panel imports its CFG graph view and its Python syntax highlighter in ``try`` blocks. ``intellicrack.ui`` itself imports both
modules unguarded (through ``cutter_panel``), so a fresh interpreter cannot start with either one blocked; the fallbacks are only reachable by
re-importing ``ghidra_panel`` after the package has loaded. One child interpreter does exactly that: it imports ``intellicrack.ui``, drops
``ghidra_panel`` from ``sys.modules`` and from the ``intellicrack.ui.panels`` package attributes, blocks both optional modules with
``sys.modules[name] = None`` and imports ``ghidra_panel`` again, then drives the panel that module builds. Nothing is reloaded in the pytest
process.

The reparent helper's failure branch for a refused style write is driven with the desktop window. Its style is readable, and the operating
system refuses ``SetWindowLongPtrW`` on it with an access-denied error in the container, which is a measured fact; a window owned by another
process that the test spawns accepts the write, so it cannot reach that branch.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.ui import win32_embed as win32_embed_mod
from tests._helpers.child_python import run_child_json


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

pytestmark = pytest.mark.spawns_process

_Dynamic = Any

_CHILD_TIMEOUT_S: Final[float] = 300.0
_WS_OVERLAPPEDWINDOW: Final[int] = 0x00CF0000

_GWL_STYLE: Final[int] = cast("int", getattr(win32_embed_mod, "_GWL_STYLE"))
_WS_CHILD: Final[int] = cast("int", getattr(win32_embed_mod, "_WS_CHILD"))
_reparent_foreign_hwnd: Callable[[Any, int, int], bool] = getattr(win32_embed_mod, "_reparent_foreign_hwnd")
_get_user32: Callable[[], Any] = getattr(win32_embed_mod, "_get_user32")

_CHILD_CODE: Final[str] = """
import importlib
import json
import os
import sys

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QTreeWidgetItem

QSettings.setDefaultFormat(QSettings.Format.IniFormat)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, os.environ["CRITCOV_R3_SETTINGS"])
app = QApplication([])

import intellicrack.ui
import intellicrack.ui.panels as panels_pkg
from intellicrack.core.types import FunctionInfo
from intellicrack.ui.panels import async_bridge
from intellicrack.ui.resources import FontManager

PANEL = "intellicrack.ui.panels.ghidra_panel"
loaded_by_ui_import = PANEL in sys.modules
sys.modules.pop(PANEL, None)
if hasattr(panels_pkg, "ghidra_panel"):
    delattr(panels_pkg, "ghidra_panel")
sys.modules["intellicrack.ui.panels.graph_view"] = None
sys.modules["intellicrack.ui.highlighter"] = None
gp = importlib.import_module(PANEL)

panel = gp.GhidraPanel()
tabs = panel._code_tabs
result = {
    "ghidra_panel_was_loaded_by_ui_import": loaded_by_ui_import,
    "cfg_graph_view_is_none": gp.CFGGraphView is None,
    "numeric_item_is_plain_tree_item": gp.NumericSortTreeItem is QTreeWidgetItem,
    "highlighter_is_none": gp.PythonSyntaxHighlighter is None,
    "code_tab_titles": [tabs.tabText(i) for i in range(tabs.count())],
    "cfg_tab_index": tabs.indexOf(panel._cfg_view),
    "cfg_is_plain_text": isinstance(panel._cfg_view, QPlainTextEdit),
    "cfg_read_only": panel._cfg_view.isReadOnly(),
    "cfg_font_family": panel._cfg_view.font().family(),
    "code_font_family": FontManager.get_instance().get_code_font(10).family(),
}

blocks = [
    {"start": 0x401000, "end": 0x401010, "sources": [0x400000], "destinations": [0x401020, 0x401030]},
    {"start": 0x401020, "end": 0x401028, "sources": [], "destinations": []},
]
panel._apply_cfg({"function": "f", "blocks": blocks})
result["cfg_text_for_blocks"] = panel._cfg_view.toPlainText()
panel._apply_cfg({"function": "f", "blocks": "not-a-list"})
result["cfg_text_for_unusable_blocks"] = panel._cfg_view.toPlainText()

functions = [
    FunctionInfo(name=name, address=address, size=size, calling_convention="cdecl", return_type="int", parameters=[], local_variables=[])
    for name, address, size in (("alpha", 0x401000, 16), ("beta", 0x400500, 32), ("gamma", 0x4010, 9))
]
panel._apply_functions(functions)
tree = panel._func_tree
items = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
result["function_rows"] = {item.text(0): [item.text(1), item.text(2)] for item in items}
result["function_item_classes"] = sorted({type(item).__name__ for item in items})

editor = panel._script_editor
editor.setPlainText("def f():\\n    return 1\\n")
result["editor_children"] = [type(child).__name__ for child in editor.document().children()]
result["editor_text"] = editor.toPlainText()

panel.deleteLater()
app.processEvents()
async_bridge.drain_bridge_workers()
async_bridge.shutdown_bridge_loop()
print(json.dumps(result))
"""


@pytest.fixture(scope="module")
def blocked_import_panel(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run the child interpreter that re-imports ``ghidra_panel`` with both optional modules blocked.

    The child gets a private settings directory, offscreen Qt and every coverage variable of this process, so lines it runs are counted.

    Args:
        tmp_path_factory: Pytest factory for the child's private settings directory.

    Returns:
        dict[str, Any]: The JSON the child printed describing the panel it built.
    """
    settings_dir = tmp_path_factory.mktemp("r3-settings")
    coverage_env = {key: value for key, value in os.environ.items() if key.startswith("COV")}
    return run_child_json(
        _CHILD_CODE,
        timeout_s=_CHILD_TIMEOUT_S,
        extra_env={"QT_QPA_PLATFORM": "offscreen", "CRITCOV_R3_SETTINGS": str(settings_dir), **coverage_env},
    )


def test_blocked_graph_view_leaves_no_graph_class_and_a_plain_tree_item(blocked_import_panel: dict[str, Any]) -> None:
    """With ``graph_view`` unimportable the module keeps ``None`` for the graph class and uses the stock tree item.

    Args:
        blocked_import_panel: Description of the panel built with both optional modules blocked.
    """
    assert blocked_import_panel["ghidra_panel_was_loaded_by_ui_import"] is True
    assert blocked_import_panel["cfg_graph_view_is_none"] is True
    assert blocked_import_panel["numeric_item_is_plain_tree_item"] is True


def test_blocked_graph_view_still_builds_every_code_tab_with_a_text_cfg(blocked_import_panel: dict[str, Any]) -> None:
    """The panel still builds, and its CFG tab holds a read-only plain-text editor in the code font.

    Args:
        blocked_import_panel: Description of the panel built with both optional modules blocked.
    """
    assert blocked_import_panel["code_tab_titles"] == ["Decompiled", "Disassembly", "PCode", "CFG"]
    assert blocked_import_panel["cfg_tab_index"] == 3
    assert blocked_import_panel["cfg_is_plain_text"] is True
    assert blocked_import_panel["cfg_read_only"] is True
    assert blocked_import_panel["cfg_font_family"] == blocked_import_panel["code_font_family"]


def test_text_cfg_lists_each_block_with_its_sources_and_destinations(blocked_import_panel: dict[str, Any]) -> None:
    """The text CFG prints one header per block, then its sources and destinations when it has any, and clears for unusable data.

    Args:
        blocked_import_panel: Description of the panel built with both optional modules blocked.
    """
    expected = "Block: 0x401000 - 0x401010\n  Sources: 0x400000\n  Destinations: 0x401020, 0x401030\nBlock: 0x401020 - 0x401028"
    assert blocked_import_panel["cfg_text_for_blocks"] == expected
    unusable = blocked_import_panel["cfg_text_for_unusable_blocks"]
    assert isinstance(unusable, str)
    assert not unusable


def test_function_list_uses_stock_tree_items_with_hex_addresses(blocked_import_panel: dict[str, Any]) -> None:
    """Without the numeric-sort item the function tree is filled with stock items holding the name, hex address and size.

    Args:
        blocked_import_panel: Description of the panel built with both optional modules blocked.
    """
    assert blocked_import_panel["function_item_classes"] == ["QTreeWidgetItem"]
    assert blocked_import_panel["function_rows"] == {
        "alpha": ["0x401000", "16"],
        "beta": ["0x400500", "32"],
        "gamma": ["0x4010", "9"],
    }


def test_blocked_highlighter_leaves_the_script_editor_plain(blocked_import_panel: dict[str, Any]) -> None:
    """With the highlighter unimportable the script editor keeps no highlighter and still holds the typed text.

    Args:
        blocked_import_panel: Description of the panel built with both optional modules blocked.
    """
    assert blocked_import_panel["highlighter_is_none"] is True
    assert "QSyntaxHighlighter" not in blocked_import_panel["editor_children"]
    assert blocked_import_panel["editor_text"] == "def f():\n    return 1\n"


class _Win32:
    """Independent ctypes bindings to create a window and to read the style and parent of a window."""

    def __init__(self) -> None:
        """Load ``user32`` and declare the prototypes from the Windows SDK."""
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.create_window = user32.CreateWindowExW
        self.create_window.restype = wintypes.HWND
        self.create_window.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPVOID,
        ]
        self.destroy_window = user32.DestroyWindow
        self.destroy_window.restype = wintypes.BOOL
        self.destroy_window.argtypes = [wintypes.HWND]
        self.get_parent = user32.GetParent
        self.get_parent.restype = wintypes.HWND
        self.get_parent.argtypes = [wintypes.HWND]
        self.get_desktop_window = user32.GetDesktopWindow
        self.get_desktop_window.restype = wintypes.HWND
        self.get_desktop_window.argtypes = []
        self.get_style = user32.GetWindowLongPtrW
        self.get_style.restype = ctypes.c_longlong
        self.get_style.argtypes = [wintypes.HWND, ctypes.c_int]

    def style_of(self, hwnd: int) -> int:
        """Read the 32 style bits of a window.

        Args:
            hwnd: Window handle.

        Returns:
            int: The window style as an unsigned 32-bit value.
        """
        return int(self.get_style(hwnd, _GWL_STYLE)) & 0xFFFFFFFF


@contextlib.contextmanager
def _parent_window(api: _Win32) -> Generator[int]:
    """Create a real, never-shown top-level window in this process and destroy it afterwards.

    Args:
        api: Window bindings.

    Yields:
        int: The window handle.
    """
    hwnd = api.create_window(0, "Static", "CritcovR3Parent", _WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, None, None, None, None)
    assert hwnd
    try:
        yield int(hwnd)
    finally:
        api.destroy_window(hwnd)


def test_reparent_reports_failure_and_changes_nothing_when_the_style_write_is_refused() -> None:
    """The desktop window's style is readable but the system refuses to change it, so the helper reports failure and the window is untouched."""
    api = _Win32()
    user32 = _get_user32()
    desktop = api.get_desktop_window()
    assert desktop
    style_before = api.style_of(int(desktop))
    assert style_before != 0
    assert style_before & _WS_CHILD == 0
    assert api.get_parent(desktop) is None

    with _parent_window(api) as parent:
        assert _reparent_foreign_hwnd(user32, int(desktop), parent) is False

    assert api.style_of(int(desktop)) == style_before
    assert api.get_parent(desktop) is None
