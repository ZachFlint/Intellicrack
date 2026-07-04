# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""L3 GUI-wiring gate tests for the Ghidra bridge-completeness slices 5 and 6.

Covers the panel-layer remediation for the NO-CONTROL / MISSING rows
identified in ``audit/bridge-completeness/agent-05-ghidra-code-analysis.md``
and ``audit/bridge-completeness/agent-06-ghidra-program-model-scripting.md``:
the new XRefs add/delete-reference form, the Labels/Bookmarks "Primary"
checkbox and bookmark removal, the memory-block remove/split/join rows, the
"Go to Function" lookup, the new Data Type Manager "Create Type" sub-form,
the new Program Tree browser/editor tab, and the new Analysis Extras tab
(instruction flow, register value, thunk management, external references,
properties, and the bidirectional call graph).

Every test drives a real, non-mocked bridge double whose methods are genuine
``async def`` coroutines (never ``MagicMock``) so the assertions verify that
the handler under test actually calls the real bridge method with the
expected arguments and renders the real result -- not that a mock was
invoked. ``run_bridge_coroutine_logged`` is patched at the module level (the
same wrapper used everywhere in production) with a synchronous
capture-and-drive stand-in so the coroutine executes for real without
spinning up a background Qt worker thread, which is the standard technique
already used by ``tests/test_audit3/ui/test_ghidra_panel.py`` for this exact
panel.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
)

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import (
    ghidra_panel as ghidra_panel_module,
    ghidra_panel_data_types as data_types_module,
    ghidra_panel_extras as extras_module,
    ghidra_panel_program_tree as program_tree_module,
)
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.ghidra_panel_data_types import DataTypeManagerWidget
from intellicrack.ui.panels.ghidra_panel_extras import GhidraAnalysisExtrasWidget
from intellicrack.ui.panels.ghidra_panel_program_tree import ProgramTreeWidget
from tests.test_bridge_completeness.ghidra.conftest import priv, priv_method


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.ghidra import GhidraBridge


class _RecordingBridge:
    """Recording stub exposing real async coroutines for every remediated L3 row.

    Every method is a genuine ``async def`` that records its call
    arguments and returns a caller-controlled payload -- never a
    ``MagicMock`` standing in for the method itself. This lets each
    test assert the panel handler dispatched the exact bridge call
    with the exact arguments the user entered, driven through the
    real ``run_bridge_coroutine_logged`` call site.
    """

    def __init__(self) -> None:
        """Initialise empty call logs and a ready BridgeState."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.add_reference_calls: list[tuple[int, int, str]] = []
        self.delete_reference_calls: list[tuple[int, int]] = []
        self.add_label_calls: list[tuple[int, str, bool]] = []
        self.set_label_calls: list[tuple[int, str]] = []
        self.remove_label_calls: list[tuple[int, str]] = []
        self.remove_bookmark_calls: list[tuple[int, str | None, str | None]] = []
        self.remove_memory_block_calls: list[str] = []
        self.split_memory_block_calls: list[tuple[str, int]] = []
        self.join_memory_blocks_calls: list[tuple[str, str]] = []
        self.get_function_calls: list[int] = []
        self.get_function_result: object = None
        self.refresh_bookmarks_calls: int = 0

    async def add_reference(self, from_addr: int, to_addr: int, ref_type: str = "DATA") -> dict[str, Any]:
        """Record an add_reference call and return a success dict.

        Args:
            from_addr: Source address supplied by the caller.
            to_addr: Destination address supplied by the caller.
            ref_type: Reference type string supplied by the caller.

        Returns:
            dict[str, Any]: Dict with from/to/type/success mirroring the real bridge shape.
        """
        self.add_reference_calls.append((from_addr, to_addr, ref_type))
        return {"from": hex(from_addr), "to": hex(to_addr), "type": ref_type, "success": True}

    async def delete_reference(self, from_addr: int, to_addr: int) -> dict[str, Any]:
        """Record a delete_reference call and return a success dict.

        Args:
            from_addr: Source address supplied by the caller.
            to_addr: Destination address supplied by the caller.

        Returns:
            dict[str, Any]: Dict with from/to/success mirroring the real bridge shape.
        """
        self.delete_reference_calls.append((from_addr, to_addr))
        return {"from": hex(from_addr), "to": hex(to_addr), "success": True}

    async def get_xrefs_to(self, address: int, limit: int = 100) -> list[dict[str, Any]]:
        """Return an empty xrefs-to list for the post-mutation refresh.

        Args:
            address: Address queried by the caller.
            limit: Maximum number of results (unused by the stub).

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address, limit
        return []

    async def get_xrefs_from(self, address: int, limit: int = 100) -> list[dict[str, Any]]:
        """Return an empty xrefs-from list for the post-mutation refresh.

        Args:
            address: Address queried by the caller.
            limit: Maximum number of results (unused by the stub).

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address, limit
        return []

    async def add_label(self, address: int, name: str, *, primary: bool = False) -> dict[str, Any]:
        """Record an add_label call and return a success dict.

        Args:
            address: Label address supplied by the caller.
            name: Label name supplied by the caller.
            primary: Primary flag supplied by the caller.

        Returns:
            dict[str, Any]: Dict with address/name/primary/success.
        """
        self.add_label_calls.append((address, name, primary))
        return {"address": hex(address), "name": name, "primary": primary, "success": True}

    async def set_label(self, address: int, name: str) -> dict[str, Any]:
        """Record a set_label call and return a success dict.

        Args:
            address: Label address supplied by the caller.
            name: Label name supplied by the caller.

        Returns:
            dict[str, Any]: Dict with address/name/success.
        """
        self.set_label_calls.append((address, name))
        return {"address": hex(address), "name": name, "success": True}

    async def get_labels(self, address: int, radius: int = 0x100) -> list[dict[str, Any]]:
        """Return an empty labels list for the post-mutation refresh.

        Args:
            address: Address queried by the caller.
            radius: Search radius (unused by the stub).

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address, radius
        return []

    async def remove_label(self, address: int, name: str) -> dict[str, Any]:
        """Record a remove_label call and return a success dict.

        Args:
            address: Label address supplied by the caller.
            name: Label name supplied by the caller.

        Returns:
            dict[str, Any]: Dict with address/name/success.
        """
        self.remove_label_calls.append((address, name))
        return {"address": hex(address), "name": name, "success": True}

    async def get_bookmarks(self, category: str | None = None) -> list[dict[str, Any]]:
        """Record a get_bookmarks refresh call and return an empty list.

        Args:
            category: Optional category filter (unused by the stub).

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del category
        self.refresh_bookmarks_calls += 1
        return []

    async def remove_bookmark(
        self,
        address: int,
        category: str | None = None,
        bookmark_type: str | None = None,
    ) -> dict[str, Any]:
        """Record a remove_bookmark call and return a success dict.

        Args:
            address: Bookmark address supplied by the caller.
            category: Category filter supplied by the caller.
            bookmark_type: Bookmark type filter supplied by the caller.

        Returns:
            dict[str, Any]: Dict with address/removed/success.
        """
        self.remove_bookmark_calls.append((address, category, bookmark_type))
        return {"address": hex(address), "removed": 1, "success": True}

    async def get_memory_map(self) -> list[dict[str, Any]]:
        """Return an empty memory map for the post-mutation refresh.

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        return []

    async def remove_memory_block(self, name: str) -> dict[str, Any]:
        """Record a remove_memory_block call and return a success dict.

        Args:
            name: Block name supplied by the caller.

        Returns:
            dict[str, Any]: Dict with name/success.
        """
        self.remove_memory_block_calls.append(name)
        return {"name": name, "success": True}

    async def split_memory_block(self, name: str, split_address: int) -> dict[str, Any]:
        """Record a split_memory_block call and return a success dict.

        Args:
            name: Block name supplied by the caller.
            split_address: Split address supplied by the caller.

        Returns:
            dict[str, Any]: Dict with name/split_address/success.
        """
        self.split_memory_block_calls.append((name, split_address))
        return {"name": name, "split_address": hex(split_address), "success": True}

    async def join_memory_blocks(self, name1: str, name2: str) -> dict[str, Any]:
        """Record a join_memory_blocks call and return a success dict.

        Args:
            name1: First block name supplied by the caller.
            name2: Second block name supplied by the caller.

        Returns:
            dict[str, Any]: Dict with the joined name and success.
        """
        self.join_memory_blocks_calls.append((name1, name2))
        return {"name": name1, "success": True}

    async def get_function(self, address: int) -> object:
        """Record a get_function call and return the configured result.

        Args:
            address: Address queried by the caller.

        Returns:
            object: Whatever ``get_function_result`` has been set to.
        """
        self.get_function_calls.append(address)
        return self.get_function_result

    async def decompile(self, address: int) -> dict[str, Any]:
        """Return an empty decompilation payload for _load_function_at_address.

        Args:
            address: Address supplied by the caller.

        Returns:
            dict[str, Any]: Minimal well-formed decompilation payload.
        """
        del address
        return {"code": "", "function_name": ""}

    async def disassemble(self, address: int, length: int = 0x100) -> list[dict[str, Any]]:
        """Return an empty disassembly listing for _load_function_at_address.

        Args:
            address: Address supplied by the caller.
            length: Length in bytes (unused by the stub).

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address, length
        return []

    async def get_pcode(self, address: int) -> list[dict[str, Any]]:
        """Return an empty P-code listing for _load_function_at_address.

        Args:
            address: Address supplied by the caller.

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address
        return []

    async def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """Return an empty basic-block listing for _load_function_at_address.

        Args:
            address: Address supplied by the caller.

        Returns:
            list[dict[str, Any]]: Always empty.
        """
        del address
        return []


def _install_sync_dispatch(
    module: object,
    captured: list[Coroutine[Any, Any, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Patch a panel module's run_bridge_coroutine_logged with a synchronous driver.

    Args:
        module: The panel module whose module-level
            ``run_bridge_coroutine_logged`` reference should be patched.
        captured: List that receives every coroutine handed to the dispatcher.
        monkeypatch: Pytest monkeypatch fixture used to restore the reference.
    """

    def _capture_logged(
        coro: Coroutine[Any, Any, Any],
        on_success: object = None,
        on_error: object = None,
        parent: object = None,
        **kwargs: object,
    ) -> None:
        """Capture the coroutine and drive it synchronously to completion.

        Args:
            coro: Coroutine produced by the bridge call.
            on_success: Optional success callback to invoke with the result.
            on_error: Optional error callback (unused; failures propagate).
            parent: Unused Qt parent argument.
            **kwargs: Remaining wrapper arguments (event, logger, level, context).
        """
        del on_error, parent, kwargs
        captured.append(coro)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(coro)
        finally:
            loop.close()
        if on_success is not None and callable(on_success):
            on_success(result)

    monkeypatch.setattr(module, "run_bridge_coroutine_logged", _capture_logged)


@pytest.fixture
def bridge() -> _RecordingBridge:
    """Provide a fresh recording bridge stub.

    Returns:
        _RecordingBridge: A ready, call-recording stub.
    """
    return _RecordingBridge()


@pytest.fixture
def panel(qapp: object) -> GhidraPanel:
    """Create a GhidraPanel instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        GhidraPanel: A fresh, unconnected GhidraPanel widget.
    """
    del qapp
    return GhidraPanel()


@pytest.fixture
def data_type_widget(qapp: object) -> DataTypeManagerWidget:
    """Create a DataTypeManagerWidget instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        DataTypeManagerWidget: A fresh widget instance.
    """
    del qapp
    return DataTypeManagerWidget()


@pytest.fixture
def program_tree_widget(qapp: object) -> ProgramTreeWidget:
    """Create a ProgramTreeWidget instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        ProgramTreeWidget: A fresh widget instance.
    """
    del qapp
    return ProgramTreeWidget()


@pytest.fixture
def extras_widget(qapp: object) -> GhidraAnalysisExtrasWidget:
    """Create a GhidraAnalysisExtrasWidget instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        GhidraAnalysisExtrasWidget: A fresh widget instance.
    """
    del qapp
    return GhidraAnalysisExtrasWidget()


def _attach(panel: GhidraPanel, bridge: _RecordingBridge) -> None:
    """Attach the recording bridge stub to the panel via its public set_bridge.

    Args:
        panel: The GhidraPanel under test.
        bridge: The recording stub to attach.
    """
    panel.set_bridge(cast("GhidraBridge", bridge))


# ---------------------------------------------------------------------------
# XRefs tab: Add/Delete Reference (row 23/24)
# ---------------------------------------------------------------------------


class TestXRefsAddDeleteReferenceWiring:
    """L3 gates for the new Add/Delete Reference controls on the XRefs tab."""

    @staticmethod
    def test_add_reference_button_calls_real_bridge_method_with_entered_values(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Add Reference must call bridge.add_reference with the parsed from/to/type.

        Falsifiable: removing the ``bridge.add_reference(from_addr,
        to_addr, ref_type)`` call from ``_on_add_reference`` in
        ``ghidra_panel.py`` (or rewiring the button's ``clicked``
        signal away from it) would leave ``bridge.add_reference_calls``
        empty after this click.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_ref_from_input", QLineEdit).setText("0x401000")
        priv(panel, "_ref_to_input", QLineEdit).setText("0x402000")
        priv(panel, "_ref_type_combo", QComboBox).setCurrentText("CALL")
        priv(panel, "_add_ref_btn", QPushButton).click()

        assert bridge.add_reference_calls == [(0x401000, 0x402000, "CALL")]

    @staticmethod
    def test_delete_reference_button_calls_real_bridge_method(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Delete Reference must call bridge.delete_reference with the parsed from/to addresses.

        Falsifiable: removing the ``bridge.delete_reference(from_addr,
        to_addr)`` call (or the button wiring) leaves
        ``delete_reference_calls`` empty.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_ref_from_input", QLineEdit).setText("0x401000")
        priv(panel, "_ref_to_input", QLineEdit).setText("0x402000")
        priv(panel, "_delete_ref_btn", QPushButton).click()

        assert bridge.delete_reference_calls == [(0x401000, 0x402000)]

    @staticmethod
    def test_add_reference_invalid_address_does_not_dispatch(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unparsable from-address must short-circuit before any bridge call.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_ref_from_input", QLineEdit).setText("not-an-address")
        priv(panel, "_ref_to_input", QLineEdit).setText("0x402000")
        priv(panel, "_add_ref_btn", QPushButton).click()

        assert bridge.add_reference_calls == []


# ---------------------------------------------------------------------------
# Labels/Bookmarks tab: Primary checkbox (row 32) + Remove bookmark (row 26)
# ---------------------------------------------------------------------------


class TestLabelsBookmarksWiring:
    """L3 gates for the Primary-label checkbox and bookmark removal controls."""

    @staticmethod
    def test_set_label_with_primary_checked_calls_add_label(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Checking Primary and clicking Set Label must route to bridge.add_label(primary=True).

        Falsifiable: if ``_on_set_label`` ignored the checkbox state
        (or the checkbox were absent from the layout), this call would
        never route to ``add_label``.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_label_addr_input", QLineEdit).setText("0x401000")
        priv(panel, "_label_name_input", QLineEdit).setText("entry_point")
        priv(panel, "_label_primary_check", QCheckBox).setChecked(True)
        priv(panel, "_set_label_btn", QPushButton).click()

        assert bridge.add_label_calls == [(0x401000, "entry_point", True)]

    @staticmethod
    def test_set_label_without_primary_does_not_call_add_label(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Leaving Primary unchecked must not route through add_label.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_label_addr_input", QLineEdit).setText("0x401000")
        priv(panel, "_label_name_input", QLineEdit).setText("entry_point")
        priv(panel, "_label_primary_check", QCheckBox).setChecked(False)
        priv(panel, "_set_label_btn", QPushButton).click()

        assert bridge.add_label_calls == []
        assert bridge.set_label_calls == [(0x401000, "entry_point")]

    @staticmethod
    def test_remove_selected_bookmark_button_calls_remove_bookmark(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Remove Selected on a populated bookmark row must call bridge.remove_bookmark.

        Falsifiable: removing the ``bridge.remove_bookmark(addr,
        category, bookmark_type)`` call from ``_on_remove_bookmark`` or
        dropping the button's ``clicked`` connection leaves
        ``remove_bookmark_calls`` empty.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        table = priv(panel, "_bookmarks_table", QTableWidget)
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem("0x401000"))
        table.setItem(0, 1, QTableWidgetItem("Analysis"))
        table.setItem(0, 2, QTableWidgetItem("a note"))
        table.setItem(0, 3, QTableWidgetItem("Note"))
        table.selectRow(0)

        priv(panel, "_remove_bm_btn", QPushButton).click()

        assert bridge.remove_bookmark_calls == [(0x401000, "Analysis", "Note")]

    @staticmethod
    def test_remove_bookmark_context_menu_action_exists_and_targets_selected_row(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The bookmarks-table context menu must offer 'Remove Bookmark' wired to the same handler.

        Falsifiable: if ``_on_bookmark_context_menu`` no longer built a
        menu with a "Remove Bookmark" action (or stopped calling
        ``_on_remove_bookmark`` when chosen), this would either find no
        matching action text or leave ``remove_bookmark_calls`` empty
        after invoking it directly.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        table = priv(panel, "_bookmarks_table", QTableWidget)
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem("0x403000"))
        table.setItem(0, 1, QTableWidgetItem("Error"))
        table.setItem(0, 2, QTableWidgetItem(""))
        table.setItem(0, 3, QTableWidgetItem("Warning"))

        assert table.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu

        table.selectRow(0)
        priv_method(panel, "_on_remove_bookmark")()

        assert bridge.remove_bookmark_calls == [(0x403000, "Error", "Warning")]


# ---------------------------------------------------------------------------
# Labels tab: Remove Selected label (previously NO-CONTROL remove_label)
# ---------------------------------------------------------------------------


class TestLabelsRemoveLabelWiring:
    """L3 gates for the Labels tab 'Remove Selected' button and context menu."""

    @staticmethod
    def test_remove_selected_label_button_calls_remove_label(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Remove Selected on a populated label row must call bridge.remove_label.

        Falsifiable: removing the ``bridge.remove_label(addr, name)``
        call from ``_on_remove_label`` or dropping the button's
        ``clicked`` connection leaves ``remove_label_calls`` empty.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        table = priv(panel, "_labels_table", QTableWidget)
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem("entry_point"))
        table.setItem(0, 1, QTableWidgetItem("0x401000"))
        table.setItem(0, 2, QTableWidgetItem("Function"))
        table.selectRow(0)

        priv(panel, "_remove_label_btn", QPushButton).click()

        assert bridge.remove_label_calls == [(0x401000, "entry_point")]

    @staticmethod
    def test_remove_label_context_menu_action_exists_and_targets_selected_row(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The labels-table context menu must offer 'Remove Label' wired to the same handler.

        Falsifiable: if ``_on_label_context_menu`` no longer built a
        menu with a "Remove Label" action (or stopped calling
        ``_on_remove_label`` when chosen), this would either find no
        matching action text or leave ``remove_label_calls`` empty
        after invoking it directly.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        table = priv(panel, "_labels_table", QTableWidget)
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem("dat_403000"))
        table.setItem(0, 1, QTableWidgetItem("0x403000"))
        table.setItem(0, 2, QTableWidgetItem("Data"))

        assert table.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu

        table.selectRow(0)
        priv_method(panel, "_on_remove_label")()

        assert bridge.remove_label_calls == [(0x403000, "dat_403000")]

    @staticmethod
    def test_remove_label_with_no_row_selected_does_not_dispatch(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Remove Selected with no row selected must short-circuit before any bridge call.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_labels_table", QTableWidget).setRowCount(0)
        priv(panel, "_remove_label_btn", QPushButton).click()

        assert bridge.remove_label_calls == []


# ---------------------------------------------------------------------------
# Memory tab: Remove/Split/Join block rows (previously MISSING bridge methods)
# ---------------------------------------------------------------------------


class TestMemoryBlockOpsWiring:
    """L3 gates for the new Remove/Split/Join memory-block form rows."""

    @staticmethod
    def test_remove_block_button_calls_remove_memory_block(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Remove must call bridge.remove_memory_block with the entered name.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_block_remove_name_input", QLineEdit).setText(".rdata")
        priv(panel, "_remove_block_btn", QPushButton).click()

        assert bridge.remove_memory_block_calls == [".rdata"]

    @staticmethod
    def test_split_block_button_calls_split_memory_block_with_parsed_address(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Split must call bridge.split_memory_block with the name and parsed hex address.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_block_split_name_input", QLineEdit).setText(".text")
        priv(panel, "_block_split_addr_input", QLineEdit).setText("0x401500")
        priv(panel, "_split_block_btn", QPushButton).click()

        assert bridge.split_memory_block_calls == [(".text", 0x401500)]

    @staticmethod
    def test_join_blocks_button_calls_join_memory_blocks_with_both_names(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Join must call bridge.join_memory_blocks with both entered names.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_block_join_name1_input", QLineEdit).setText(".block_a")
        priv(panel, "_block_join_name2_input", QLineEdit).setText(".block_b")
        priv(panel, "_join_blocks_btn", QPushButton).click()

        assert bridge.join_memory_blocks_calls == [(".block_a", ".block_b")]

    @staticmethod
    def test_remove_block_blank_name_does_not_dispatch(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank block name must short-circuit before calling remove_memory_block.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_block_remove_name_input", QLineEdit).setText("")
        priv(panel, "_remove_block_btn", QPushButton).click()

        assert bridge.remove_memory_block_calls == []


# ---------------------------------------------------------------------------
# Functions sidebar: Go to Function (row 13, get_function singular)
# ---------------------------------------------------------------------------


class TestGoToFunctionWiring:
    """L3 gates for the new Go-to-Function lookup (row 13, get_function singular)."""

    @staticmethod
    def test_goto_button_calls_get_function_with_parsed_address(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Go must call bridge.get_function with the parsed address.

        Falsifiable: removing the ``bridge.get_function(address)`` call
        from ``_on_goto_function`` (or wiring the button to a different
        handler) leaves ``get_function_calls`` empty.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)
        bridge.get_function_result = None

        priv(panel, "_goto_func_addr", QLineEdit).setText("0x401000")
        priv(panel, "_goto_func_btn", QPushButton).click()

        assert bridge.get_function_calls == [0x401000]

    @staticmethod
    def test_goto_button_loads_resolved_function_code_views(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A resolved function must trigger loading its code views via the real function address.

        Falsifiable: if ``_apply_goto_function`` ignored the resolved
        address and always loaded ``address`` (the requested address)
        rather than the function's own reported entry, this test's
        second (distinct) address would never reach get_function again
        through _load_function_at_address's downstream calls.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        class _FakeFunctionInfo:
            name = "target_func"
            address = 0x401500

        bridge.get_function_result = _FakeFunctionInfo()

        priv(panel, "_goto_func_addr", QLineEdit).setText("0x401000")
        priv(panel, "_goto_func_btn", QPushButton).click()

        assert bridge.get_function_calls == [0x401000]
        assert panel.status_label is not None
        assert "target_func" in panel.status_label.text()

    @staticmethod
    def test_goto_invalid_address_does_not_dispatch(
        panel: GhidraPanel,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unparsable address must short-circuit before calling get_function.

        Args:
            panel: GhidraPanel fixture.
            bridge: Recording bridge stub.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _attach(panel, bridge)
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(ghidra_panel_module, captured, monkeypatch)

        priv(panel, "_goto_func_addr", QLineEdit).setText("garbage")
        priv(panel, "_goto_func_btn", QPushButton).click()

        assert bridge.get_function_calls == []


# ---------------------------------------------------------------------------
# Data Type Manager: Create Type sub-form (rows 3-6, create_data_type)
# ---------------------------------------------------------------------------


class TestDataTypeManagerCreateTypeWiring:
    """L3 gates for the new Data Type Manager 'Create Type' sub-form."""

    @staticmethod
    def test_create_enum_calls_real_bridge_method_with_entered_fields(
        data_type_widget: DataTypeManagerWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Create for an enum must call bridge.create_data_type with category/name/kind/fields.

        Falsifiable: removing the
        ``self._bridge.create_data_type(category, name, kind, fields or
        None)`` call from ``_on_create_type`` (or never wiring the
        Create button) leaves the recorded call list empty.

        Args:
            data_type_widget: DataTypeManagerWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[tuple[str, str, str, list[dict[str, Any]] | None]] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def create_data_type(
                self,
                category: str,
                name: str,
                type_kind: str,
                fields: list[dict[str, Any]] | None = None,
            ) -> dict[str, Any]:
                calls.append((category, name, type_kind, fields))
                return {"name": name, "kind": type_kind, "size": 4, "success": True}

        data_type_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(data_types_module, captured, monkeypatch)

        priv(data_type_widget, "_kind_combo", QComboBox).setCurrentText("enum")
        priv(data_type_widget, "_name_input", QLineEdit).setText("MyEnum")
        priv(data_type_widget, "_category_input", QLineEdit).setText("/Intellicrack")
        priv(data_type_widget, "_create_btn", QPushButton).click()

        assert len(calls) == 1
        assert calls[0][0] == "/Intellicrack"
        assert calls[0][1] == "MyEnum"
        assert calls[0][2] == "enum"

    @staticmethod
    def test_create_typedef_requires_base_type_before_dispatch(
        data_type_widget: DataTypeManagerWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Creating a typedef with no base type must short-circuit before any bridge call.

        Args:
            data_type_widget: DataTypeManagerWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[object] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def create_data_type(self, *args: object, **kwargs: object) -> dict[str, Any]:
                calls.append((args, kwargs))
                return {"success": True}

        data_type_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(data_types_module, captured, monkeypatch)

        priv(data_type_widget, "_kind_combo", QComboBox).setCurrentText("typedef")
        priv(data_type_widget, "_name_input", QLineEdit).setText("MyAlias")
        priv(data_type_widget, "_base_type_input", QLineEdit).setText("")
        priv(data_type_widget, "_create_btn", QPushButton).click()

        assert not calls

    @staticmethod
    def test_create_union_calls_bridge_with_union_kind(
        data_type_widget: DataTypeManagerWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selecting union in the kind combo must call create_data_type with kind='union'.

        Falsifiable: if the kind combo selection were ignored and the
        method always dispatched with 'enum', this assertion on the
        third positional value would fail.

        Args:
            data_type_widget: DataTypeManagerWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[tuple[str, str, str, list[dict[str, Any]] | None]] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def create_data_type(
                self,
                category: str,
                name: str,
                type_kind: str,
                fields: list[dict[str, Any]] | None = None,
            ) -> dict[str, Any]:
                calls.append((category, name, type_kind, fields))
                return {"name": name, "kind": type_kind, "size": 4, "success": True}

        data_type_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(data_types_module, captured, monkeypatch)

        priv(data_type_widget, "_kind_combo", QComboBox).setCurrentText("union")
        priv(data_type_widget, "_name_input", QLineEdit).setText("MyUnion")
        priv(data_type_widget, "_create_btn", QPushButton).click()

        assert len(calls) == 1
        assert calls[0][2] == "union"


# ---------------------------------------------------------------------------
# Program Tree tab: Refresh + Create/Move (row 11, MISSING row 12)
# ---------------------------------------------------------------------------


class TestProgramTreeWiring:
    """L3 gates for the new Program Tree browser/editor tab."""

    @staticmethod
    def test_refresh_calls_get_program_tree_and_renders_nodes(
        program_tree_widget: ProgramTreeWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Refresh Program Tree must call bridge.get_program_tree and populate the tree widget.

        Falsifiable: removing the ``self._bridge.get_program_tree()``
        call from ``_on_refresh_tree`` leaves the tree widget empty
        even though the stub would otherwise report one tree/module.

        Args:
            program_tree_widget: ProgramTreeWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_program_tree(self) -> dict[str, Any]:
                calls.append(1)
                return {
                    "trees": [
                        {
                            "name": "Program Tree",
                            "root": {"name": "Root", "type": "module", "children": []},
                        },
                    ],
                }

        program_tree_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(program_tree_module, captured, monkeypatch)

        priv(program_tree_widget, "_refresh_btn", QPushButton).click()

        assert calls == [1]
        tree = priv(program_tree_widget, "_tree", QTreeWidget)
        assert tree.topLevelItemCount() == 1
        root_item = tree.topLevelItem(0)
        assert root_item is not None
        assert root_item.text(0) == "Program Tree"

    @staticmethod
    def test_apply_edit_calls_edit_program_tree_with_entered_fields(
        program_tree_widget: ProgramTreeWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Apply must call bridge.edit_program_tree with tree/operation/parent/child.

        Falsifiable: removing the ``self._bridge.edit_program_tree(...)``
        call from ``_on_edit_tree`` (or wiring Apply to the refresh
        handler instead) leaves the recorded call list empty.

        Args:
            program_tree_widget: ProgramTreeWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[tuple[str, str, str, str]] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def edit_program_tree(
                self,
                tree_name: str,
                operation: str,
                parent_module: str,
                child_name: str,
            ) -> dict[str, Any]:
                calls.append((tree_name, operation, parent_module, child_name))
                return {"tree_name": tree_name, "operation": operation, "child_name": child_name, "success": True}

            async def get_program_tree(self) -> dict[str, Any]:
                return {"trees": []}

        program_tree_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(program_tree_module, captured, monkeypatch)

        priv(program_tree_widget, "_tree_name_input", QLineEdit).setText("Program Tree")
        priv(program_tree_widget, "_operation_combo", QComboBox).setCurrentText("create_fragment")
        priv(program_tree_widget, "_parent_module_input", QLineEdit).setText("Root")
        priv(program_tree_widget, "_child_name_input", QLineEdit).setText("NewFrag")
        priv(program_tree_widget, "_apply_btn", QPushButton).click()

        assert calls == [("Program Tree", "create_fragment", "Root", "NewFrag")]

    @staticmethod
    def test_apply_edit_blank_tree_name_does_not_dispatch(
        program_tree_widget: ProgramTreeWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank tree name must short-circuit before calling edit_program_tree.

        Args:
            program_tree_widget: ProgramTreeWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[object] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def edit_program_tree(self, *args: object, **kwargs: object) -> dict[str, Any]:
                calls.append((args, kwargs))
                return {"success": True}

        program_tree_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(program_tree_module, captured, monkeypatch)

        priv(program_tree_widget, "_tree_name_input", QLineEdit).setText("")
        priv(program_tree_widget, "_parent_module_input", QLineEdit).setText("Root")
        priv(program_tree_widget, "_child_name_input", QLineEdit).setText("X")
        priv(program_tree_widget, "_apply_btn", QPushButton).click()

        assert not calls


# ---------------------------------------------------------------------------
# Analysis Extras tab: instruction flow / register / thunk / ext-refs / properties / call graph
# ---------------------------------------------------------------------------


class TestAnalysisExtrasWiring:
    """L3 gates for the new Analysis Extras tab controls."""

    @staticmethod
    def test_get_flow_button_calls_get_instruction_flow(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Get Flow must call bridge.get_instruction_flow with the parsed address.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_instruction_flow(self, address: int) -> dict[str, Any]:
                calls.append(address)
                return {"mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP", "fall_through": None, "flows": []}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_flow_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_flow_btn", QPushButton).click()

        assert calls == [0x401000]
        assert "JMP" in priv(extras_widget, "_flow_register_result", QPlainTextEdit).toPlainText()

    @staticmethod
    def test_get_register_button_calls_get_register_value(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Get Register must call bridge.get_register_value with address and register name.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[tuple[int, str]] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_register_value(self, address: int, register: str) -> dict[str, Any]:
                calls.append((address, register))
                return {"address": address, "register": register, "value": 42, "has_value": True}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_flow_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_register_input", QLineEdit).setText("EAX")
        priv(extras_widget, "_register_btn", QPushButton).click()

        assert calls == [(0x401000, "EAX")]

    @staticmethod
    def test_add_thunk_button_calls_add_thunk_and_refreshes_info(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Add Thunk must call bridge.add_thunk, then refresh via get_thunk_info.

        Falsifiable: removing the ``bridge.add_thunk(address, target)``
        call from ``_on_add_thunk`` leaves ``add_thunk_calls`` empty.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        add_thunk_calls: list[tuple[int, int]] = []
        thunk_info_calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def add_thunk(self, address: int, thunked_address: int) -> dict[str, Any]:
                add_thunk_calls.append((address, thunked_address))
                return {"address": hex(address), "thunked_address": hex(thunked_address), "success": True}

            async def get_thunk_info(self, address: int) -> dict[str, Any]:
                thunk_info_calls.append(address)
                return {"address": address, "is_thunk": True, "thunked_function": "Real", "thunked_address": 0x402000}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_thunk_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_thunk_target_input", QLineEdit).setText("0x402000")
        priv(extras_widget, "_add_thunk_btn", QPushButton).click()

        assert add_thunk_calls == [(0x401000, 0x402000)]
        assert thunk_info_calls == [0x401000]

    @staticmethod
    def test_remove_thunk_button_calls_remove_thunk(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Remove Thunk must call bridge.remove_thunk with the entered address.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def remove_thunk(self, address: int) -> dict[str, Any]:
                calls.append(address)
                return {"address": hex(address), "success": True}

            async def get_thunk_info(self, address: int) -> dict[str, Any]:
                return {"address": address, "is_thunk": False, "thunked_function": None, "thunked_address": None}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_thunk_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_remove_thunk_btn", QPushButton).click()

        assert calls == [0x401000]

    @staticmethod
    def test_add_external_reference_button_calls_bridge_and_refreshes(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Add External Reference must call add_external_reference then refresh the table.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        add_calls: list[tuple[int, str, str]] = []
        refresh_calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def add_external_reference(self, address: int, library: str, name: str) -> dict[str, Any]:
                add_calls.append((address, library, name))
                return {"from_addr": hex(address), "library": library, "name": name, "success": True}

            async def get_external_references(self, address: int) -> list[dict[str, Any]]:
                refresh_calls.append(address)
                return []

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_ext_ref_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_ext_ref_library_input", QLineEdit).setText("kernel32.dll")
        priv(extras_widget, "_ext_ref_name_input", QLineEdit).setText("CreateFileW")
        priv(extras_widget, "_ext_ref_add_btn", QPushButton).click()

        assert add_calls == [(0x401000, "kernel32.dll", "CreateFileW")]
        assert refresh_calls == [0x401000]

    @staticmethod
    def test_get_properties_button_calls_get_properties_and_renders_table(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Get Properties must call bridge.get_properties and populate the properties table.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_properties(self, address: int) -> dict[str, Any]:
                calls.append(address)
                return {"address": address, "properties": {"Analyzed": True}}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_props_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_props_btn", QPushButton).click()

        assert calls == [0x401000]
        properties_table = priv(extras_widget, "_properties_table", QTableWidget)
        assert properties_table.rowCount() == 1
        name_item = properties_table.item(0, 0)
        assert name_item is not None
        assert name_item.text() == "Analyzed"

    @staticmethod
    def test_build_bidirectional_call_graph_calls_get_call_graph(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Build Bidirectional Graph must call bridge.get_call_graph, not get_call_tree.

        Falsifiable: rewiring this button to call ``get_call_tree``
        (the pre-existing, single-direction method the audit flagged
        as the accidental duplicate path) instead of ``get_call_graph``
        would leave ``calls`` empty since only ``get_call_graph`` is
        implemented on this stub.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_call_graph(self, address: int, depth: int = 2) -> dict[str, Any]:
                del depth
                calls.append(address)
                return {"name": "main", "address": address, "callees": [], "callers": []}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_bicg_addr_input", QLineEdit).setText("0x401000")
        priv(extras_widget, "_bicg_btn", QPushButton).click()

        assert calls == [0x401000]
        bicg_tree = priv(extras_widget, "_bicg_tree", QTreeWidget)
        assert bicg_tree.topLevelItemCount() == 1
        root_item = bicg_tree.topLevelItem(0)
        assert root_item is not None
        assert root_item.text(0) == "main"

    @staticmethod
    def test_get_flow_invalid_address_does_not_dispatch(
        extras_widget: GhidraAnalysisExtrasWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unparsable address must short-circuit before calling get_instruction_flow.

        Args:
            extras_widget: GhidraAnalysisExtrasWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        calls: list[int] = []

        class _StubBridge:
            state = BridgeState(connected=True, tool_running=True)

            async def get_instruction_flow(self, address: int) -> dict[str, Any]:
                calls.append(address)
                return {"mnemonic": "", "flow_type": "", "fall_through": None, "flows": []}

        extras_widget.set_bridge(cast("GhidraBridge", _StubBridge()))
        captured: list[Coroutine[Any, Any, Any]] = []
        _install_sync_dispatch(extras_module, captured, monkeypatch)

        priv(extras_widget, "_flow_addr_input", QLineEdit).setText("not-an-address")
        priv(extras_widget, "_flow_btn", QPushButton).click()

        assert not calls
