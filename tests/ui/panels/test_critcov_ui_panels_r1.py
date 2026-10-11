# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the remaining reachable lines of the x64dbg, Ghidra, Frida, Cutter and win32 embed panels.

Every test drives a real panel or real Win32 windows that the test creates in its own process. The lazy binding caches of
``x64dbg_panel`` and ``win32_embed`` are raced by a second thread that is held at the cache lock until the test fills the cache itself.
Window reparenting runs against two real top-level windows with their own ctypes prototypes. The Cutter context menus are opened for real
and answered from inside their own event loop by a zero-delay timer, with a watchdog timer that closes any popup still open after a hard
limit. Cutter actions run against a real ``CutterBridge`` that never loaded a binary, whose documented ``no binary loaded`` refusal shows
which slot a menu entry reached, or against a subclass that records only the cross-reference requests.
"""

from __future__ import annotations

import contextlib
import ctypes
import inspect
import sys
import threading
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, Final, Literal, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, QPoint, QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QInputDialog,
    QLabel,
    QMenu,
    QPushButton,
    QSpacerItem,
    QTabWidget,
    QTreeWidget,
    QWidget,
)

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import CrossReference, FunctionInfo
from intellicrack.ui import win32_embed as win32_embed_mod
from intellicrack.ui.panels import x64dbg_panel as x64dbg_panel_mod
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.frida_instrumentation_tab import ScriptSnapshotControls
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.graph_view import CFGGraphView
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel
from intellicrack.ui.win32_embed import capture_window_image


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from types import FrameType, FunctionType

    from pytestqt.qtbot import QtBot


_Dynamic = Any

_WAIT_MS: Final[int] = 20_000
_JOIN_S: Final[float] = 20.0
_MENU_LIMIT_MS: Final[int] = 10_000
_NOT_ATTACHED: Final[str] = "not attached to a process"
_NO_BINARY: Final[str] = "no binary loaded"
_GARBAGE_HWND: Final[int] = 0xDEADBEEF
_WS_OVERLAPPEDWINDOW: Final[int] = 0x00CF0000
_FUNC_ADDRESS: Final[int] = 0x401000
_CALLER_ADDRESS: Final[int] = 0x402000
_CALLEE_ADDRESS: Final[int] = 0x403000

_GWL_STYLE: Final[int] = cast("int", getattr(win32_embed_mod, "_GWL_STYLE"))
_WS_CHILD: Final[int] = cast("int", getattr(win32_embed_mod, "_WS_CHILD"))
_WS_CAPTION: Final[int] = cast("int", getattr(win32_embed_mod, "_WS_CAPTION"))
_WS_POPUP: Final[int] = cast("int", getattr(win32_embed_mod, "_WS_POPUP"))
_reparent_foreign_hwnd: Callable[[Any, int, int], bool] = getattr(win32_embed_mod, "_reparent_foreign_hwnd")
_get_user32: Callable[[], Any] = getattr(win32_embed_mod, "_get_user32")
_get_capture_bindings: Callable[[], object] = getattr(win32_embed_mod, "_get_capture_bindings")
_capture_bindings_cache: list[Any] = getattr(win32_embed_mod, "_capture_bindings_cache")
_capture_bindings_lock: threading.Lock = getattr(win32_embed_mod, "_capture_bindings_lock")
_CaptureBindings: type = getattr(win32_embed_mod, "_CaptureBindings")
_desktop_window_bindings: Callable[[], object] = getattr(x64dbg_panel_mod, "_desktop_window_bindings")
_desktop_window_bindings_cache: list[Any] = getattr(x64dbg_panel_mod, "_desktop_window_bindings_cache")
_desktop_window_bindings_lock: threading.Lock = getattr(x64dbg_panel_mod, "_desktop_window_bindings_lock")
_DesktopWindowBindings: type = getattr(x64dbg_panel_mod, "_DesktopWindowBindings")


class _WindowApi:
    """Independent ctypes bindings the tests use to create and inspect real top-level windows in this process."""

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
        self.get_style = user32.GetWindowLongPtrW
        self.get_style.restype = ctypes.c_longlong
        self.get_style.argtypes = [wintypes.HWND, ctypes.c_int]
        self.get_window_rect = user32.GetWindowRect
        self.get_window_rect.restype = wintypes.BOOL
        self.get_window_rect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]

    def style_of(self, hwnd: int) -> int:
        """Read the 32 style bits of a window.

        Args:
            hwnd: Window handle.

        Returns:
            int: The window style as an unsigned 32-bit value.
        """
        return int(self.get_style(hwnd, _GWL_STYLE)) & 0xFFFFFFFF

    def extent_of(self, hwnd: int) -> tuple[int, int]:
        """Read the width and height ``GetWindowRect`` reports.

        Args:
            hwnd: Window handle.

        Returns:
            tuple[int, int]: Width and height in pixels.
        """
        rect = wintypes.RECT()
        assert self.get_window_rect(hwnd, ctypes.byref(rect))
        return int(rect.right - rect.left), int(rect.bottom - rect.top)


@contextlib.contextmanager
def _window(api: _WindowApi, title: str, style: int, width: int, height: int) -> Generator[int]:
    """Create a real, never-shown top-level window in this process and destroy it afterwards.

    Args:
        api: Window bindings.
        title: Window caption.
        style: Window style bits.
        width: Requested width in pixels.
        height: Requested height in pixels.

    Yields:
        int: The window handle.
    """
    hwnd = api.create_window(0, "Static", title, style, 0, 0, width, height, None, None, None, None)
    assert hwnd
    try:
        yield int(hwnd)
    finally:
        api.destroy_window(hwnd)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _race_first_use(
    qtbot: QtBot,
    getter: Callable[[], object],
    cache: list[Any],
    lock: threading.Lock,
    build: Callable[[], object],
) -> tuple[list[object], object, list[Any]]:
    """Race a second thread against the first use of a lazily bound cache.

    The test holds ``lock`` and clears ``cache``. A worker thread then calls ``getter``; once the worker is observed parked on the ``with``
    statement of the getter, the test stores a binding it built itself, releases the lock and lets the worker finish.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker to reach the lock.
        getter: Product function that returns the cached binding.
        cache: Product cache list that is cleared for the race and restored afterwards.
        lock: Product lock that guards the cache.
        build: Builds the binding the test stores while the worker waits.

    Returns:
        tuple[list[object], object, list[Any]]: What the worker returned, the binding the test stored and a snapshot of the cache after
        the worker finished.
    """
    lines, first = inspect.getsourcelines(getter)
    with_line = first + next(index for index, text in enumerate(lines) if text.strip().startswith("with "))
    code = cast("FunctionType", getter).__code__
    current_frames = cast("Callable[[], dict[int, FrameType]]", getattr(sys, "_current_frames"))
    saved = list(cache)
    cache.clear()
    outcome: list[object] = []

    def _run() -> None:
        """Call the getter on the worker thread and keep what it returns."""
        outcome.append(getter())

    worker = threading.Thread(target=_run, name="critcov-first-use-race", daemon=True)

    def _parked() -> bool:
        """Report whether the worker is waiting on the getter's lock statement.

        Returns:
            bool: ``True`` when the worker's top frame is the getter at or past its ``with`` line.
        """
        frame = current_frames().get(worker.ident or 0)
        return frame is not None and frame.f_code is code and frame.f_lineno >= with_line

    built: object = None
    snapshot: list[Any] = []
    held = False
    try:
        lock.acquire()
        held = True
        worker.start()
        qtbot.waitUntil(_parked, timeout=_WAIT_MS)
        built = build()
        cache.append(built)
        lock.release()
        held = False
        worker.join(timeout=_JOIN_S)
        assert not worker.is_alive()
        snapshot = list(cache)
    finally:
        if held:
            lock.release()
        if worker.ident is not None:
            worker.join(timeout=_JOIN_S)
        cache.clear()
        cache.extend(saved)
    return outcome, built, snapshot


@contextlib.contextmanager
def _menu_driver(owner: QWidget, caption: str | None) -> Generator[list[str]]:
    """Answer the next context menu from inside its own event loop.

    ``QMenu.exec`` returns only once the menu closes, so a zero-delay timer records the entries the menu offers, triggers the entry whose
    caption matches and always closes the menu. A watchdog timer closes any popup still open after ``_MENU_LIMIT_MS`` so a failure can
    never leave the test blocked.

    Args:
        owner: Widget that owns the menu.
        caption: Caption of the entry to trigger, or ``None`` to only close the menu.

    Yields:
        list[str]: Captions the menu offered, with ``-`` for a separator; empty until the menu opens.
    """
    offered: list[str] = []

    def _find() -> QMenu | None:
        """Find the open context menu.

        Returns:
            QMenu | None: The active popup menu, or a visible menu owned by ``owner``.
        """
        popup = QApplication.activePopupWidget()
        if isinstance(popup, QMenu):
            return popup
        visible = [menu for menu in owner.findChildren(QMenu) if menu.isVisible()]
        return visible[-1] if visible else None

    def _answer() -> None:
        """Record the entries, trigger the wanted one and close the menu."""
        menu = _find()
        if menu is None:
            return
        try:
            offered.extend("-" if action.isSeparator() else action.text() for action in menu.actions())
            for action in menu.actions():
                if caption is not None and action.text() == caption:
                    action.trigger()
        finally:
            menu.close()

    def _rescue() -> None:
        """Close the menu when the answer never arrived."""
        menu = _find()
        if menu is not None:
            menu.close()

    watchdog = QTimer()
    watchdog.setSingleShot(True)
    watchdog.timeout.connect(_rescue)
    watchdog.start(_MENU_LIMIT_MS)
    QTimer.singleShot(0, _answer)
    try:
        yield offered
    finally:
        watchdog.stop()


def _text_answer(text: str) -> Callable[..., tuple[str, bool]]:
    """Build a ``QInputDialog.getText`` replacement that accepts with a fixed text.

    Args:
        text: Text the dialog returns.

    Returns:
        Callable[..., tuple[str, bool]]: Plain function with the static dialog's result shape.
    """

    def _answer(*_args: object, **_kwargs: object) -> tuple[str, bool]:
        """Return the fixed accepted answer.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, bool]: The text and acceptance.
        """
        return (text, True)

    return _answer


def _int_answer(value: int) -> Callable[..., tuple[int, bool]]:
    """Build a ``QInputDialog.getInt`` replacement that accepts with a fixed number.

    Args:
        value: Number the dialog returns.

    Returns:
        Callable[..., tuple[int, bool]]: Plain function with the static dialog's result shape.
    """

    def _answer(*_args: object, **_kwargs: object) -> tuple[int, bool]:
        """Return the fixed accepted answer.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[int, bool]: The number and acceptance.
        """
        return (value, True)

    return _answer


class _XrefBridge(CutterBridge):
    """Real ``CutterBridge`` that records cross-reference edits and answers the two xref queries with fixed data."""

    def __init__(self) -> None:
        """Create the bridge with an empty request record."""
        super().__init__()
        self.requests: list[tuple[str, tuple[object, ...]]] = []

    @override
    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Return one caller of the requested address.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: A single call from ``_CALLER_ADDRESS`` to ``address``.
        """
        return [CrossReference(_CALLER_ADDRESS, address, "call", "caller_fn", None)]

    @override
    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Return one callee of the requested address.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: A single jump from ``address`` to ``_CALLEE_ADDRESS``.
        """
        return [CrossReference(address, _CALLEE_ADDRESS, "jump", None, "callee_fn")]

    @override
    async def add_xref(
        self,
        from_address: int,
        to_address: int,
        xref_type: Literal["code", "call", "data"] = "code",
    ) -> bool:
        """Record a request to add a cross-reference.

        Args:
            from_address: Source address.
            to_address: Target address.
            xref_type: Cross-reference kind.

        Returns:
            bool: Always ``True``.
        """
        self.requests.append(("add_xref", (from_address, to_address, xref_type)))
        return True

    @override
    async def remove_xref(self, to_address: int, from_address: int | None = None) -> bool:
        """Record a request to remove a cross-reference.

        Args:
            to_address: Target address.
            from_address: Source address.

        Returns:
            bool: Always ``True``.
        """
        self.requests.append(("remove_xref", (to_address, from_address)))
        return True


def _function(name: str, address: int) -> FunctionInfo:
    """Build a function record of the bridge's real result type.

    Args:
        name: Function name.
        address: Function address.

    Returns:
        FunctionInfo: The record.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=32,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


def _settle_cutter(panel: CutterPanel) -> None:
    """Join the Cutter panel's bridge workers and deliver their results, following chained requests.

    Args:
        panel: Panel whose workers are joined.
    """
    for _ in range(6):
        drain_bridge_workers_for(panel, timeout_ms=_WAIT_MS)
        QCoreApplication.processEvents()


def _cutter_status(panel: CutterPanel) -> str:
    """Read the Cutter panel's status text.

    Args:
        panel: Panel under test.

    Returns:
        str: The status label text.
    """
    label = panel.status_label
    assert label is not None
    return label.text()


def _row_center(tree: QTreeWidget, direction: str) -> QPoint:
    """Return a viewport point inside the top-level row whose first column equals ``direction``.

    Args:
        tree: Tree holding the row.
        direction: First-column text of the wanted row.

    Returns:
        QPoint: A point inside the row, in viewport coordinates.
    """
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item is not None and item.text(0) == direction:
            center = tree.visualItemRect(item).center()
            found = tree.itemAt(center)
            assert found is not None
            assert found.text(1) == item.text(1)
            return center
    return pytest.fail(f"no {direction} row in the cross-reference tree")


@pytest.fixture
def x64dbg_panel(qapp: QApplication) -> Generator[X64DbgPanel]:
    """Build a real x64dbg panel and stop everything it started on teardown.

    Args:
        qapp: Shared application.

    Yields:
        X64DbgPanel: The panel under test.
    """
    widget = X64DbgPanel()
    try:
        yield widget
    finally:
        _priv(widget, "_stop_embed_timer")()
        _priv(widget, "_stop_mirror_timer")()
        drain_bridge_workers_for(widget)
        widget.close()
        qapp.processEvents()


@pytest.fixture
def ghidra_panel(qtbot: QtBot) -> Generator[GhidraPanel]:
    """Build a real Ghidra panel with no bridge.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        GhidraPanel: The panel under test.
    """
    widget = GhidraPanel()
    qtbot.addWidget(widget)
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)


@pytest.fixture
def frida_panel(qapp: QApplication) -> Generator[FridaPanel]:
    """Build a real Frida panel holding a bridge that was never initialized or attached.

    Args:
        qapp: Shared application.

    Yields:
        FridaPanel: The panel under test.
    """
    widget = FridaPanel()
    widget.set_bridge(FridaBridge())
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget, _WAIT_MS)
        qapp.processEvents()
        _priv(widget, "_console_drain_timer").stop()
        widget.close()
        qapp.processEvents()


@pytest.fixture
def snapshot_controls(qapp: QApplication) -> Generator[ScriptSnapshotControls]:
    """Build a real script-snapshot control.

    Args:
        qapp: Shared application.

    Yields:
        ScriptSnapshotControls: A control with no bridge set.
    """
    controls = ScriptSnapshotControls()
    try:
        yield controls
    finally:
        drain_bridge_workers_for(controls)
        controls.deleteLater()
        qapp.processEvents()


@pytest.fixture
def cutter_panel(qapp: QApplication, qtbot: QtBot) -> Generator[CutterPanel]:
    """Build a shown Cutter panel and tear it down with its workers joined.

    Args:
        qapp: Shared application.
        qtbot: pytest-qt fixture used to wait for the window.

    Yields:
        CutterPanel: The panel under test.
    """
    widget = CutterPanel()
    with qtbot.waitExposed(widget):
        widget.show()
    try:
        yield widget
    finally:
        _settle_cutter(widget)
        _ = widget.stop_tool()
        widget.close()
        widget.deleteLater()
        qapp.processEvents()


@pytest.fixture
def function_row(cutter_panel: CutterPanel) -> QPoint:
    """Give the Cutter panel an unloaded real bridge and one listed, selected function, and locate its row.

    Args:
        cutter_panel: Shown panel under test.

    Returns:
        QPoint: A viewport point inside the function's row of the function tree.
    """
    cutter_panel.set_bridge(CutterBridge())
    _priv(cutter_panel, "_apply_functions")([_function("sub.main", _FUNC_ADDRESS)])
    tree = cast("QTreeWidget", _priv(cutter_panel, "_func_tree"))
    item = tree.topLevelItem(0)
    assert item is not None
    tree.setCurrentItem(item)
    center = tree.visualItemRect(item).center()
    found = tree.itemAt(center)
    assert found is not None
    assert found.text(0) == "sub.main"
    return center


def test_mirror_start_drops_layout_items_that_hold_no_widget(x64dbg_panel: X64DbgPanel) -> None:
    """A spacer sitting in the embed host is discarded and the placeholder label is replaced by the mirror label.

    Args:
        x64dbg_panel: Panel under test.
    """
    host_layout = x64dbg_panel.embed_host.layout()
    assert host_layout is not None
    status_label = _priv(x64dbg_panel, "_embed_status_label")
    host_layout.addItem(QSpacerItem(0, 0))
    assert host_layout.count() == 2

    _priv(x64dbg_panel, "_start_mirror_capture")(_GARBAGE_HWND, 4321)

    label = _priv(x64dbg_panel, "_mirror_label")
    assert label is not None
    assert host_layout.count() == 1
    item = host_layout.itemAt(0)
    assert item is not None
    assert item.widget() is label
    assert status_label.parent() is None


def test_desktop_bindings_first_use_race_keeps_the_binding_stored_by_the_winner(qtbot: QtBot) -> None:
    """A thread that waits on the lock while another stores the bindings returns the stored object and builds no second one.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
    """
    outcome, built, cache_after = _race_first_use(
        qtbot,
        _desktop_window_bindings,
        _desktop_window_bindings_cache,
        _desktop_window_bindings_lock,
        _DesktopWindowBindings,
    )

    assert isinstance(built, _DesktopWindowBindings)
    assert len(outcome) == 1
    assert outcome[0] is built
    assert len(cache_after) == 1
    assert cache_after[0] is built


def test_capture_bindings_first_use_race_keeps_the_binding_stored_by_the_winner(qtbot: QtBot) -> None:
    """A thread that waits on the lock while another stores the capture bindings returns the stored object and builds no second one.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
    """
    outcome, built, cache_after = _race_first_use(
        qtbot,
        _get_capture_bindings,
        _capture_bindings_cache,
        _capture_bindings_lock,
        _CaptureBindings,
    )

    assert isinstance(built, _CaptureBindings)
    assert len(outcome) == 1
    assert outcome[0] is built
    assert len(cache_after) == 1
    assert cache_after[0] is built


def test_reparent_makes_a_top_level_window_a_captionless_child_of_the_parent() -> None:
    """A real top-level window loses its caption, gains the child style and ends up owned by the parent window."""
    api = _WindowApi()
    user32 = _get_user32()
    with (
        _window(api, "CritcovParent", _WS_OVERLAPPEDWINDOW, 320, 200) as parent,
        _window(api, "CritcovChild", _WS_OVERLAPPEDWINDOW, 160, 100) as child,
    ):
        assert api.style_of(child) & _WS_CAPTION == _WS_CAPTION
        assert api.get_parent(child) is None

        assert _reparent_foreign_hwnd(user32, child, parent) is True

        assert api.get_parent(child) == parent
        style = api.style_of(child)
        assert style & _WS_CHILD == _WS_CHILD
        assert style & _WS_CAPTION == 0


def test_reparent_reports_failure_when_the_parent_handle_names_no_window() -> None:
    """``SetParent`` rejects a handle that is not a window, and the helper reports that instead of success."""
    api = _WindowApi()
    user32 = _get_user32()
    with _window(api, "CritcovOrphan", _WS_OVERLAPPEDWINDOW, 160, 100) as child:
        assert _reparent_foreign_hwnd(user32, child, _GARBAGE_HWND) is False


def test_capture_of_a_window_without_area_yields_no_image() -> None:
    """A window whose rectangle is empty cannot be captured, so no image is returned."""
    api = _WindowApi()
    with _window(api, "CritcovEmpty", _WS_POPUP, 0, 0) as hwnd:
        assert api.extent_of(hwnd) == (0, 0)

        assert capture_window_image(hwnd) is None


def test_ghidra_cfg_with_an_unusable_block_list_draws_nothing(ghidra_panel: GhidraPanel) -> None:
    """A CFG payload whose ``blocks`` entry is not a list replaces the drawn graph with an empty one.

    Args:
        ghidra_panel: Panel without a bridge.
    """
    view = _priv(ghidra_panel, "_cfg_view")
    assert isinstance(view, CFGGraphView)
    blocks: list[dict[str, object]] = [
        {"start": 0x401000, "end": 0x40100F, "sources": [], "destinations": [0x401010], "destination_edges": []},
        {"start": 0x401010, "end": 0x40101F, "sources": [0x401000], "destinations": [], "destination_edges": []},
    ]
    _priv(ghidra_panel, "_apply_cfg")({"function": "main", "blocks": blocks})
    assert set(view.graph_scene().block_items) == {0x401000, 0x401010}

    _priv(ghidra_panel, "_apply_cfg")({"function": "main", "blocks": "not-a-list"})

    assert set(view.graph_scene().block_items) == set()


def test_stalker_summary_stop_without_a_thread_id_still_asks_the_bridge(qapp: QApplication, frida_panel: FridaPanel) -> None:
    """With the thread id field empty, Stop is dispatched for the default trace and the bridge's refusal is shown.

    Args:
        qapp: Shared application.
        frida_panel: Panel holding a bridge that is not attached.
    """
    _priv(frida_panel, "_stalker_tid_input").setText("")
    stop_btn = _priv(frida_panel, "_stalker_summary_stop_btn")
    start_btn = _priv(frida_panel, "_stalker_summary_start_btn")
    stop_btn.setEnabled(True)
    start_btn.setEnabled(False)

    _priv(frida_panel, "_on_stalker_summary_stop")()

    assert stop_btn.isEnabled() is False
    drain_bridge_workers_for(frida_panel, _WAIT_MS)
    qapp.processEvents()
    assert str(_priv(frida_panel, "_console").toPlainText()) == f"[-] Stalker call-summary stop failed: {_NOT_ATTACHED}"
    assert start_btn.isEnabled() is True
    assert stop_btn.isEnabled() is False


@pytest.mark.parametrize(
    ("result", "expected"),
    [("script-42", "Loaded script script-42"), (7, "Loaded script 7")],
    ids=["text_id", "numeric_id"],
)
def test_load_with_snapshot_done_reenables_the_button_and_names_the_script(
    snapshot_controls: ScriptSnapshotControls,
    result: object,
    expected: str,
) -> None:
    """A finished snapshot-started load re-enables its button and shows the script id the bridge returned.

    Args:
        snapshot_controls: Control under test.
        result: Script id handed to the done handler.
        expected: Status text the control must show.
    """
    button = cast("QPushButton", _priv(snapshot_controls, "_load_with_snapshot_btn"))
    button.setEnabled(False)

    _priv(snapshot_controls, "_on_load_script_with_snapshot_done")(result)

    assert button.isEnabled() is True
    assert cast("QLabel", _priv(snapshot_controls, "_status_label")).text() == expected


def test_function_menu_offers_every_function_action_in_order(cutter_panel: CutterPanel, function_row: QPoint) -> None:
    """The function tree's context menu lists the six actions in their documented order.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed function.
    """
    with _menu_driver(cutter_panel, None) as offered:
        _priv(cutter_panel, "_on_func_context_menu")(function_row)

    assert offered == ["Rename...", "Add Comment...", "Decompile", "Show Graph", "Copy Address", "Read Bytes..."]


def test_function_menu_copy_address_puts_the_hex_address_on_the_clipboard(cutter_panel: CutterPanel, function_row: QPoint) -> None:
    """Choosing Copy Address copies the function's address as upper-case hex and says so.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed function.
    """
    with _menu_driver(cutter_panel, "Copy Address"):
        _priv(cutter_panel, "_on_func_context_menu")(function_row)

    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() == "0x401000"
    assert _cutter_status(cutter_panel) == "Copied 0x401000"


def test_function_menu_rename_runs_the_rename_flow(
    cutter_panel: CutterPanel,
    function_row: QPoint,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing Rename asks for a name and sends it, and the unloaded bridge's refusal is shown as a rename failure.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed function.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_answer("renamed_main"))

    with _menu_driver(cutter_panel, "Rename..."):
        _priv(cutter_panel, "_on_func_context_menu")(function_row)
    _settle_cutter(cutter_panel)

    status = _cutter_status(cutter_panel)
    assert status.startswith("Rename failed:")
    assert _NO_BINARY in status


def test_function_menu_add_comment_runs_the_comment_flow(
    cutter_panel: CutterPanel,
    function_row: QPoint,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing Add Comment asks for a comment and sends it, and the unloaded bridge's refusal is shown as a comment failure.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed function.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getText", _text_answer("checks the license"))

    with _menu_driver(cutter_panel, "Add Comment..."):
        _priv(cutter_panel, "_on_func_context_menu")(function_row)
    _settle_cutter(cutter_panel)

    status = _cutter_status(cutter_panel)
    assert status.startswith("Comment failed:")
    assert _NO_BINARY in status


def test_function_menu_read_bytes_runs_the_read_flow(
    cutter_panel: CutterPanel,
    function_row: QPoint,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Choosing Read Bytes asks for a count and reads, and the unloaded bridge's refusal is printed in the console.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed function.
        monkeypatch: Fixture used to replace the input dialog.
    """
    monkeypatch.setattr(QInputDialog, "getInt", _int_answer(4))

    with _menu_driver(cutter_panel, "Read Bytes..."):
        _priv(cutter_panel, "_on_func_context_menu")(function_row)
    _settle_cutter(cutter_panel)

    text = str(_priv(cutter_panel, "console_output").toPlainText())
    assert text.startswith("[error] Read failed:")
    assert _NO_BINARY in text


@pytest.mark.parametrize(("caption", "tab_index"), [("Decompile", 1), ("Show Graph", 2)], ids=["decompile", "graph"])
def test_function_menu_decompile_and_graph_switch_to_their_tabs(
    cutter_panel: CutterPanel,
    function_row: QPoint,
    caption: str,
    tab_index: int,
) -> None:
    """Choosing Decompile or Show Graph for the selected function brings the matching code tab to the front.

    Args:
        cutter_panel: Shown panel under test.
        function_row: Point over the listed (and selected) function.
        caption: Menu entry to choose.
        tab_index: Code tab the entry must show.
    """
    code_tabs = cast("QTabWidget", _priv(cutter_panel, "_code_tabs"))
    code_tabs.setCurrentIndex(0)

    with _menu_driver(cutter_panel, caption):
        _priv(cutter_panel, "_on_func_context_menu")(function_row)
    _settle_cutter(cutter_panel)

    assert code_tabs.currentIndex() == tab_index


@pytest.fixture
def xref_panel(cutter_panel: CutterPanel) -> tuple[CutterPanel, _XrefBridge, QPoint]:
    """Show the cross-references of one function through a recording bridge and locate the caller row.

    Args:
        cutter_panel: Shown panel under test.

    Returns:
        tuple[CutterPanel, _XrefBridge, QPoint]: The panel, its bridge and a point over the "To" row of the XRefs tree.
    """
    bridge = _XrefBridge()
    cutter_panel.set_bridge(bridge)
    _priv(cutter_panel, "_show_xrefs")(_FUNC_ADDRESS)
    _settle_cutter(cutter_panel)
    tree = cast("QTreeWidget", _priv(cutter_panel, "_xrefs_tree"))
    page = tree.parentWidget()
    while page is not None and not isinstance(page, QTabWidget):
        page = page.parentWidget()
    assert isinstance(page, QTabWidget)
    page.setCurrentWidget(tree)
    QCoreApplication.processEvents()
    return cutter_panel, bridge, _row_center(tree, "To")


def test_xrefs_menu_offers_the_add_and_remove_actions(xref_panel: tuple[CutterPanel, _XrefBridge, QPoint]) -> None:
    """The XRefs tree's context menu lists the three add actions, a separator and the remove action.

    Args:
        xref_panel: Panel with xrefs shown, its bridge and a row position.
    """
    panel, _bridge, position = xref_panel

    with _menu_driver(panel, None) as offered:
        _priv(panel, "_on_xrefs_context_menu")(position)

    assert offered == ["Add Code Xref...", "Add Call Xref...", "Add Data Xref...", "-", "Remove This Xref"]


@pytest.mark.parametrize(
    ("caption", "xref_type"),
    [("Add Code Xref...", "code"), ("Add Call Xref...", "call"), ("Add Data Xref...", "data")],
    ids=["code", "call", "data"],
)
def test_xrefs_menu_add_entries_add_a_reference_of_their_own_kind(
    xref_panel: tuple[CutterPanel, _XrefBridge, QPoint],
    monkeypatch: pytest.MonkeyPatch,
    caption: str,
    xref_type: str,
) -> None:
    """Each add entry sends a reference of its own kind from the shown function to the typed target.

    Args:
        xref_panel: Panel with xrefs shown, its bridge and a row position.
        monkeypatch: Fixture used to replace the input dialog.
        caption: Menu entry to choose.
        xref_type: Reference kind the entry must request.
    """
    panel, bridge, position = xref_panel
    monkeypatch.setattr(QInputDialog, "getText", _text_answer("0x404000"))

    with _menu_driver(panel, caption):
        _priv(panel, "_on_xrefs_context_menu")(position)
    _settle_cutter(panel)

    assert ("add_xref", (_FUNC_ADDRESS, 0x404000, xref_type)) in bridge.requests


def test_xrefs_menu_remove_entry_removes_the_edge_of_the_clicked_row(xref_panel: tuple[CutterPanel, _XrefBridge, QPoint]) -> None:
    """The remove entry removes the edge from the clicked caller row into the shown function.

    Args:
        xref_panel: Panel with xrefs shown, its bridge and a row position.
    """
    panel, bridge, position = xref_panel

    with _menu_driver(panel, "Remove This Xref"):
        _priv(panel, "_on_xrefs_context_menu")(position)
    _settle_cutter(panel)

    assert ("remove_xref", (_FUNC_ADDRESS, _CALLER_ADDRESS)) in bridge.requests
