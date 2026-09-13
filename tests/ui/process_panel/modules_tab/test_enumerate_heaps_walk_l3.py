# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""L3 wiring gates for finding T2-8d (``ProcessBridge.enumerate_heaps`` GUI reachability).

``ProcessBridge.enumerate_heaps`` (the budget/cap-bounded per-block heap
walker, distinct from the shallow heap-list-only ``get_heaps``) had no
caller anywhere in the codebase. The fix adds a "Walk Heap Blocks" button to
``ModulesTab``'s existing "Heap" sub-tab, alongside the pre-existing
"Enumerate Heaps" (``get_heaps``) control, dispatching to the real
``enumerate_heaps`` bridge method and rendering a heap/block tree.

Each wiring test replaces ``run_bridge_coroutine_logged`` in the
``modules_tab`` module with a capture shim (never the bridge) and asserts
the button dispatches the coroutine returned by the real
``ProcessBridge.enumerate_heaps`` mock -- proving it is wired to that method
specifically, and not to ``get_heaps``. The rendering test then invokes the
captured, real ``on_success``/``on_error`` callbacks with a realistic
``enumerate_heaps`` payload to prove the tree-population logic itself is
correct; only the bridge call is mocked, matching the project convention in
``tests/bridges/completeness/sandbox_process/test_process_panel_new_controls_l3.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QMessageBox, QTreeWidget

from intellicrack.ui.panels.process_panel import modules_tab as _modules_tab_mod
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication

_DispatchCall = dict[str, object]


def _intercept_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[_DispatchCall]:
    """Replace ``run_bridge_coroutine_logged`` in ``modules_tab`` with a capture shim.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[_DispatchCall]: Live list receiving one dict per dispatch call
            with keys ``"coro"``, ``"on_success"``, and ``"on_error"`` --
            the coroutine and callbacks the handler under test passed to
            the real dispatcher.
    """
    captured: list[_DispatchCall] = []

    def _capture(
        coro: object,
        *,
        on_success: object = None,
        on_error: object = None,
        **kwargs: object,
    ) -> None:
        del kwargs
        captured.append({"coro": coro, "on_success": on_success, "on_error": on_error})

    monkeypatch.setattr(_modules_tab_mod, "run_bridge_coroutine_logged", _capture)
    return captured


def _capture_warnings(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    """Replace ``QMessageBox.warning`` with a non-modal capture returning Ok.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[object, ...]]: Live list receiving the positional arguments of
            each ``QMessageBox.warning`` call.
    """
    calls: list[tuple[object, ...]] = []

    def _capture(*args: object, **kwargs: object) -> QMessageBox.StandardButton:
        del kwargs
        calls.append(args)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _capture)
    return calls


@pytest.fixture
def modules_tab(qapp: QApplication) -> Iterator[ModulesTab]:
    """Create a ``ModulesTab`` ready for heap-block wiring assertions.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        ModulesTab: A ready-to-use tab instance.
    """
    del qapp
    tab = ModulesTab()
    yield tab
    tab.deleteLater()


class TestModulesTabWalkHeapBlocksWiringL3:
    """ModulesTab's "Walk Heap Blocks" button invokes ProcessBridge.enumerate_heaps."""

    def test_on_refresh_heap_blocks_dispatches_enumerate_heaps_with_attached_pid(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_refresh_heap_blocks dispatches bridge.enumerate_heaps with the attached pid, not get_heaps.

        Falsified by: rewiring "Walk Heap Blocks" to call ``get_heaps``
        instead of ``enumerate_heaps``, or dropping the attached-pid
        argument.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        modules_tab.set_bridge(mock_bridge)
        modules_tab.set_attached_pid(4321)

        dispatch_calls = _intercept_dispatch(monkeypatch)

        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()

        assert dispatch_calls, "run_bridge_coroutine_logged must be called when attached"
        assert dispatch_calls[0]["coro"] is mock_bridge.enumerate_heaps.return_value, (
            f"first positional arg must be the coroutine from bridge.enumerate_heaps; got {dispatch_calls[0]['coro']!r}"
        )
        mock_bridge.enumerate_heaps.assert_called_once_with(4321)
        mock_bridge.get_heaps.assert_not_called()

    def test_on_refresh_heap_blocks_no_dispatch_without_attached_pid(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_refresh_heap_blocks skips dispatch entirely when no process is attached.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        modules_tab.set_bridge(mock_bridge)

        dispatch_calls = _intercept_dispatch(monkeypatch)

        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()

        assert dispatch_calls == [], "enumerate_heaps must not be dispatched without an attached pid"
        mock_bridge.enumerate_heaps.assert_not_called()

    def test_on_refresh_heap_blocks_no_dispatch_without_bridge(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_refresh_heap_blocks skips dispatch entirely when no bridge is configured.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        modules_tab.set_attached_pid(4321)
        dispatch_calls = _intercept_dispatch(monkeypatch)

        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()

        assert dispatch_calls == [], "enumerate_heaps must not be dispatched without a bridge"

    def test_on_refresh_heap_blocks_error_shows_message_box(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real dispatch failure surfaces through QMessageBox.warning, not silently swallowed.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        modules_tab.set_bridge(mock_bridge)
        modules_tab.set_attached_pid(4321)

        dispatch_calls = _intercept_dispatch(monkeypatch)
        warning_calls = _capture_warnings(monkeypatch)

        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()

        assert dispatch_calls
        on_error = cast("Callable[[object], None]", dispatch_calls[0]["on_error"])
        on_error(RuntimeError("heap snapshot failed"))

        assert warning_calls, "a dispatch failure must surface a QMessageBox warning"
        assert "heap snapshot failed" in str(warning_calls[0][2])


class TestModulesTabHeapBlocksTreeRenderingL3:
    """The real on_success callback renders heap/block data with the correct, distinct tree shape."""

    def test_on_success_renders_heaps_and_blocks(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real enumerate_heaps-shaped payload populates one tree node per heap and per block.

        Falsifiable: if the tree-population logic read the wrong dict keys
        (e.g. ``heap_id``/``is_default`` -- ``get_heaps``'s schema -- instead
        of ``id``/``blocks``), the heap and block rows would come back
        empty or wrongly shaped.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        modules_tab.set_bridge(mock_bridge)
        modules_tab.set_attached_pid(4321)

        dispatch_calls = _intercept_dispatch(monkeypatch)
        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()
        assert dispatch_calls

        on_success = cast("Callable[[object], None]", dispatch_calls[0]["on_success"])
        payload: list[dict[str, object]] = [
            {
                "id": 0x10000,
                "flags": 0,
                "blocks": [
                    {"address": 0x20000, "size": 64, "flags": 1},
                    {"address": 0x20100, "size": 128, "flags": 1},
                ],
            },
            {"id": 0x30000, "flags": 2, "blocks": []},
        ]
        on_success(payload)

        tree = cast("QTreeWidget", getattr(modules_tab, "_heap_blocks_tree"))
        assert tree.topLevelItemCount() == 2

        heap0 = tree.topLevelItem(0)
        assert heap0 is not None
        assert f"0x{0x10000:X}" in heap0.text(0)
        assert "2 blocks" in heap0.text(0)
        assert heap0.text(3) == "0"
        assert heap0.childCount() == 2

        block0 = heap0.child(0)
        assert block0 is not None
        assert block0.text(1) == f"0x{0x20000:X}"
        assert block0.text(2) == "64"
        assert block0.text(3) == "1"

        block1 = heap0.child(1)
        assert block1 is not None
        assert block1.text(1) == f"0x{0x20100:X}"
        assert block1.text(2) == "128"

        heap1 = tree.topLevelItem(1)
        assert heap1 is not None
        assert "0 blocks" in heap1.text(0)
        assert heap1.childCount() == 0

    def test_on_success_ignores_non_list_result(
        self,
        modules_tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A malformed (non-list) result must not raise and must leave the tree untouched.

        Args:
            modules_tab: ModulesTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        modules_tab.set_bridge(mock_bridge)
        modules_tab.set_attached_pid(4321)

        dispatch_calls = _intercept_dispatch(monkeypatch)
        handler = cast("Callable[[], None]", getattr(modules_tab, "_refresh_heap_blocks"))
        handler()
        assert dispatch_calls

        on_success = cast("Callable[[object], None]", dispatch_calls[0]["on_success"])
        on_success(None)

        tree = cast("QTreeWidget", getattr(modules_tab, "_heap_blocks_tree"))
        assert tree.topLevelItemCount() == 0
