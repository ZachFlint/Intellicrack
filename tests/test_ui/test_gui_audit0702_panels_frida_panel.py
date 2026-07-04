# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gates for ``intellicrack.ui.panels.frida_panel``.

Covers the 2026-07-02 audit findings for ``frida_panel.py``:

* H23 -- ``_on_remove_hook`` must keep ``_hook_ids`` in sync with the hooks
  table row-for-row even on the no-bridge fallback path, so later lookups by
  ``_find_hook_row`` do not resolve to the wrong row.
* M44 -- ``main_splitter`` and ``top_splitter`` must be non-collapsible so no
  pane (process browser, script editor, tool tabs, console) can be dragged to
  zero size and vanish.
* M45 -- the load-module result label must word-wrap and expose the full
  message as a tooltip instead of clipping long bridge exception text.
* L9 -- the module combo box must grow to fit its contents
  (``AdjustToContents``) and expose the full selected module name as a
  tooltip instead of eliding it at a fixed 120px floor.

All tests drive a real, constructed :class:`FridaPanel` under an offscreen
``QApplication``; no widget behaviour under test is mocked or stubbed.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QComboBox, QSplitter

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import frida_panel as frida_panel_module
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.frida_bridge import FridaBridge


pytestmark = pytest.mark.usefixtures("qapp")


class _RecordingBridge:
    """Stand-in bridge exposing a connected state and a recording ``remove_hook``.

    Used only by the bridge-backed sanity test to force ``_on_remove_hook``
    down its bridge branch and observe exactly which hook id it forwards;
    the H23 gate itself exercises the no-bridge fallback path with no
    bridge object at all.
    """

    def __init__(self) -> None:
        """Initialise a connected, tool-running bridge state and empty call log."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.remove_hook_calls: list[str] = []

    async def remove_hook(self, hook_id: str) -> None:
        """Record a ``remove_hook`` invocation.

        Args:
            hook_id: The hook identifier the panel forwarded.
        """
        self.remove_hook_calls.append(hook_id)


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine so tests observe its effects in-thread.

    The production dispatcher hands coroutines to a background thread; tests
    need deterministic in-thread execution so the recording bridge observes
    the call before the assertion runs.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Success callback, invoked synchronously with the
            coroutine's result.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (event, logger, level,
            context).
    """
    del on_error, parent
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    finally:
        loop.close()
    if on_success is not None:
        cast("Any", on_success)(result)


def test_h23_remove_hook_without_bridge_pops_matching_hook_id() -> None:
    """Removing row 0 with no bridge must drop ``_hook_ids[0]``, not leave it stale.

    Regression: pre-fix, the pop-and-return branch only ran when
    ``self._bridge is not None``. With ``self._bridge is None`` -- a state
    the code itself explicitly checks for -- execution fell straight through
    to ``removeRow`` with no matching ``_hook_ids.pop``. After removing row 0
    with two hooks present, the table would show 1 row while ``_hook_ids``
    still held both original entries, so ``_hook_ids[0]`` would remain the
    *removed* hook's id (``"hook-a"``) instead of shifting up to
    ``"hook-b"``.
    """
    panel = FridaPanel()
    assert panel._bridge is None
    panel.add_hook_entry("0x1000", "mod.dll", "func_a", hook_id="hook-a")
    panel.add_hook_entry("0x2000", "mod.dll", "func_b", hook_id="hook-b")
    assert panel._hook_ids == ["hook-a", "hook-b"]

    panel._hooks_table.setCurrentCell(0, 0)
    panel._on_remove_hook()

    assert panel._hooks_table.rowCount() == 1, "the removed row must be gone from the table"
    assert panel._hook_ids == ["hook-b"], f"_hook_ids desynced from the table after a no-bridge removal: {panel._hook_ids!r}"


def test_h23_remove_hook_without_bridge_keeps_find_hook_row_correct() -> None:
    """After a no-bridge removal, ``_find_hook_row`` must resolve the surviving id to row 0.

    This is the concrete downstream failure mode described by the finding: a
    stale ``_hook_ids`` list means the next lookup by hook id (used by
    ``_on_hook_installed``/``_on_hook_removed`` to locate a row) resolves to
    the wrong table row for every row that shifted up.
    """
    panel = FridaPanel()
    panel.add_hook_entry("0x1000", "mod.dll", "func_a", hook_id="hook-a")
    panel.add_hook_entry("0x2000", "mod.dll", "func_b", hook_id="hook-b")

    panel._hooks_table.setCurrentCell(0, 0)
    panel._on_remove_hook()

    assert panel._find_hook_row("hook-b") == 0, "hook-b must now resolve to row 0 after hook-a's row was removed"
    assert panel._find_hook_row("hook-a") == -1, "hook-a must no longer resolve to any row"


def test_h23_remove_hook_with_bridge_forwards_correct_id_and_pops_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bridge-backed branch must forward the right id and pop ``_hook_ids`` exactly once.

    Sanity companion to the no-bridge gates above: confirms the H23 fix
    (popping on the no-bridge fallback branch) did not introduce a
    double-pop on the pre-existing bridge-backed branch. With a bridge
    attached, ``_on_remove_hook`` must forward the selected row's hook id to
    ``bridge.remove_hook`` and, once the success callback fires,
    ``_hook_ids`` must drop from two entries to one -- not zero, and not two.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to drive the bridge
            coroutine synchronously in-thread instead of on a background
            worker.
    """
    monkeypatch.setattr(frida_panel_module, "run_bridge_coroutine_logged", _drive)
    panel = FridaPanel()
    bridge = _RecordingBridge()
    panel._bridge = cast("FridaBridge", bridge)
    panel.add_hook_entry("0x1000", "mod.dll", "func_a", hook_id="hook-a")
    panel.add_hook_entry("0x2000", "mod.dll", "func_b", hook_id="hook-b")

    panel._hooks_table.setCurrentCell(0, 0)
    panel._on_remove_hook()

    assert bridge.remove_hook_calls == ["hook-a"], "the selected row's hook id must be forwarded to the bridge"
    assert panel._hook_ids == ["hook-b"], "exactly one entry must be popped once the removal callback runs"
    assert panel._hooks_table.rowCount() == 1


def test_m44_main_and_top_splitters_are_non_collapsible() -> None:
    """Both the vertical main splitter and horizontal top splitter must be non-collapsible.

    Regression: neither splitter called ``setChildrenCollapsible(False)``, so
    dragging a handle to the edge could collapse the process browser, script
    editor, or tool tabs (or the console, on the vertical splitter) to 0px
    with no visible handle remnant to grab and recover it.
    """
    panel = FridaPanel()
    splitters = panel.findChildren(QSplitter)
    assert splitters, "the Frida panel must contain splitters"

    vertical = [s for s in splitters if s.orientation() == Qt.Orientation.Vertical]
    horizontal = [s for s in splitters if s.orientation() == Qt.Orientation.Horizontal]
    assert vertical, "expected a vertical main splitter (top area / console)"
    assert horizontal, "expected a horizontal top splitter (process browser / editor / tabs)"

    for splitter in vertical + horizontal:
        assert splitter.childrenCollapsible() is False, (
            f"splitter {splitter.objectName() or splitter} allows a pane to collapse to zero width"
        )


def test_m44_top_splitter_hosts_three_panes_none_collapsible() -> None:
    """The horizontal top splitter must host exactly the process/editor/tabs trio, all non-collapsible."""
    panel = FridaPanel()
    horizontal = [s for s in panel.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Horizontal]
    assert len(horizontal) == 1, "expected exactly one horizontal top splitter"
    top_splitter = horizontal[0]
    assert top_splitter.count() == 3, "top splitter must host the process browser, editor, and tool tabs"
    assert top_splitter.childrenCollapsible() is False


def test_m44_dragging_top_splitter_handle_to_edge_does_not_collapse_process_browser(
    qapp: QApplication,
) -> None:
    """Dragging the top splitter's first handle to the far edge must not zero the process browser pane.

    This exercises the concrete, user-visible consequence of the M44 fix
    rather than only the ``childrenCollapsible`` flag: with the flag left at
    Qt's default ``True`` (pre-fix) and no minimum size floor set on any
    pane, moving the handle to position 0 shrinks the process-browser pane
    to zero width. Post-fix, ``setChildrenCollapsible(False)`` clamps the
    pane to its (non-zero, real-widget) minimum size hint instead.

    Args:
        qapp: The shared, offscreen ``QApplication`` fixture.
    """
    panel = FridaPanel()
    panel.resize(1200, 800)
    panel.show()
    qapp.processEvents()

    horizontal = [s for s in panel.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Horizontal]
    top_splitter = horizontal[0]

    top_splitter.moveSplitter(0, 1)
    qapp.processEvents()

    sizes = top_splitter.sizes()
    assert sizes[0] > 0, (
        "dragging the top splitter's first handle to the left edge collapsed the process "
        f"browser pane to zero width (sizes={sizes!r}); childrenCollapsible must be False "
        "so panes clamp to their minimum size instead of vanishing"
    )
    panel.hide()


def test_m45_load_module_result_has_word_wrap_enabled() -> None:
    """``_load_module_result`` must have word wrap enabled at construction.

    Regression: pre-fix, the bare ``QLabel("")`` never called
    ``setWordWrap(True)``, so a long bridge exception string would force the
    modules pane to grow past its splitter share instead of wrapping onto
    multiple lines.
    """
    panel = FridaPanel()
    assert panel._load_module_result.wordWrap() is True


def test_m45_load_module_error_sets_wrapping_text_and_full_tooltip() -> None:
    """A long load-module failure must populate both the label text and its tooltip in full.

    Drives the real ``_on_load_module_error`` handler with a long, realistic
    ``OSError``-style message and asserts the label carries the complete
    text (relying on word wrap rather than truncation) and that the tooltip
    exposes the identical full string as a fallback for any residual
    clipping.

    Regression: pre-fix ``_on_load_module_error`` called
    ``self._load_module_result.setText(...)`` directly with no tooltip
    assignment anywhere in the file, so ``toolTip()`` stayed the empty
    string regardless of how long the error text was.
    """
    panel = FridaPanel()
    long_message = (
        "[WinError 5] Access is denied: "
        "'C:\\Program Files\\SomeVendor\\VeryLongModuleNameThatWouldOverflowALabel"
        "\\native_component_x64_debug_build.dll' while attempting Module.load "
        "from a permission-restricted target process"
    )
    panel._on_load_module_error(OSError(long_message))

    text = panel._load_module_result.text()
    tooltip = panel._load_module_result.toolTip()
    assert long_message in text, "the full error message must appear in the label text, not be truncated"
    assert long_message in tooltip, "the full error message must be available via tooltip"
    assert panel._load_module_result.wordWrap() is True


def test_m45_load_module_success_also_sets_tooltip() -> None:
    """A successful load must also mirror its text into the tooltip via the shared setter.

    Confirms the fix applies uniformly through ``_set_load_module_result``
    rather than being a special case bolted only onto the error path.
    """
    panel = FridaPanel()

    class _Result:
        """Minimal stand-in exposing the attributes ``_on_load_module_done`` reads."""

        name = "injected.dll"
        base_address = 0x7FFE_0000

    panel._on_load_module_done(_Result())

    assert "injected.dll" in panel._load_module_result.text()
    assert panel._load_module_result.toolTip() == panel._load_module_result.text()


def test_l9_module_combo_has_adjust_to_contents_policy() -> None:
    """``_module_combo`` must use ``AdjustToContents`` so long names are not elided.

    Regression: pre-fix the combo only had a 120px ``setMinimumWidth`` with
    the Qt default ``AdjustToContentsOnFirstShow`` policy, which freezes the
    widget's width at first paint (while the combo is still empty) and never
    grows for items added later by ``_populate_modules_table``.
    """
    panel = FridaPanel()
    assert panel._module_combo.sizeAdjustPolicy() == QComboBox.SizeAdjustPolicy.AdjustToContents


def test_l9_combo_width_grows_after_first_show_when_long_names_are_added(
    qapp: QApplication,
) -> None:
    """The combo must widen for long module names even after already being shown once empty.

    Reproduces the exact failure sequence from the finding: the panel is
    shown (and thus painted) while ``_module_combo`` is still empty, then
    ``_populate_modules_table`` adds a long real module name afterward.
    Pre-fix, ``AdjustToContentsOnFirstShow`` would cache the (near-zero
    content) width from that first, empty paint and never revisit it; the
    post-fix ``AdjustToContents`` policy recomputes the size hint from the
    combo's current contents on every query.

    Args:
        qapp: The shared, offscreen ``QApplication`` fixture.
    """
    panel = FridaPanel()
    panel.resize(1200, 800)
    panel.show()
    qapp.processEvents()
    empty_width = panel._module_combo.sizeHint().width()

    long_name = "api-ms-win-core-synchronization-l1-2-0-extended-shim-example.dll"
    panel._module_combo.clear()
    panel._module_combo.addItem(long_name)
    qapp.processEvents()

    populated_width = panel._module_combo.sizeHint().width()
    fm = panel._module_combo.fontMetrics()
    text_width = fm.horizontalAdvance(long_name)

    assert populated_width > empty_width, (
        f"combo sizeHint width did not grow after adding a long module name "
        f"(empty={empty_width}, populated={populated_width}); the combo is still frozen "
        "at its empty-at-first-show width"
    )
    assert populated_width >= text_width, (
        f"combo sizeHint width ({populated_width}px) is narrower than the module name's "
        f"rendered text width ({text_width}px); the name would still be elided"
    )
    panel.hide()


def test_l9_selecting_long_module_name_sets_full_tooltip() -> None:
    """Populating the combo with a long module name must set it as the current tooltip.

    Drives the real population path (``_populate_modules_table``) with a
    fake bridge ``ModuleInfo``-shaped result, relying on the genuine
    ``currentTextChanged`` signal Qt emits when the first item added to an
    empty combo becomes current, and asserts the tooltip mirrors the long
    name in full rather than being left unset.

    Regression: pre-fix there was no ``currentTextChanged`` connection at
    all, so the combo's tooltip stayed empty regardless of which module was
    selected.
    """
    panel = FridaPanel()

    class _ModuleInfo:
        """Minimal stand-in exposing the attributes ``_populate_modules_table`` reads."""

        def __init__(self, name: str) -> None:
            """Store the module's display name and other read attributes.

            Args:
                name: Module filename to expose via the ``name`` attribute.
            """
            self.name = name
            self.base_address = 0x1_4000_0000
            self.size = 0x2000
            self.path = f"C:\\Windows\\System32\\{name}"

    long_name = "api-ms-win-core-synch-l1-2-0-extended-compat-shim.dll"
    panel._populate_modules_table([_ModuleInfo(long_name)])

    assert panel._module_combo.count() == 1
    assert panel._module_combo.currentText() == long_name
    assert panel._module_combo.toolTip() == long_name, "selecting a long module name must expose it in full via the combo tooltip"


def test_l9_combo_changed_handler_updates_tooltip_directly() -> None:
    """The dedicated combo-changed handler must set the tooltip to the given text.

    Exercises ``_on_module_combo_changed`` directly (independent of signal
    wiring) so this gate stays true to the concrete fix even if the
    connection is later rewired.
    """
    panel = FridaPanel()
    panel._on_module_combo_changed("libcrypto-3-x64.dll")
    assert panel._module_combo.toolTip() == "libcrypto-3-x64.dll"
