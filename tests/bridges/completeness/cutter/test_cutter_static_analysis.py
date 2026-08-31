# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness gate tests for the Cutter/Rizin static-analysis slice.

Covers ``audit/bridge-completeness/agent-03-cutter-rizin-static-analysis.md``
and its verifier. Every test drives a real ``CutterBridge`` (backed by a
recording r2pipe double, the genuine external boundary a live rizin child
process would occupy) and/or a real Qt widget from
``intellicrack.ui.panels.cutter_panel``/``cutter_static_extra_tab`` so the
production bridge parsing, tool-def dispatch, and GUI handler code all run
for real.

Regression coverage for the confirmed defect:

* Rows 20/21 -- ``get_relocations``/``get_resources`` had their rizin
  commands swapped (``iRj``/``irj`` inverted relative to upstream rizin,
  where ``ir`` = relocations and ``iR`` = resources). The fix un-swaps the
  two command strings. These tests assert the bridge issues the *correct*
  command for each method and parses the *matching* dataset, not the other
  feature's data.

L3 gates for the remediated GUI gaps in this slice:

* Row 1 -- the analysis-depth selector (``quick``/``normal``/``deep``) is
  now a real combo box threaded into ``CutterPanel._on_analyze``'s call to
  ``bridge.analyze(level=...)``.
* Row 26 -- the hexdump mode combo box in ``HexdumpTab`` now threads through
  to ``hexdump_words`` (``pxw``) when "Words" mode is selected, distinct
  from the byte-mode ``hexdump`` (``px``) default.
* Rows 4, 7, 8, 18, 19, 22, 23, 24/24b/24c/24d -- the previously NO-CONTROL
  static-analysis capabilities (classes/RTTI, call graph, vtables, syscalls,
  zignatures list/generate/add/search, basic-block listing, and linear
  whole-function disassembly) are now real Qt tabs in
  ``StaticAnalysisExtrasTab`` (``cutter_static_extra_tab.py``), each wired
  to its real bridge method via ``run_bridge_coroutine_logged``.
* Row 25 -- binary debug information (``iDj``) is now the ``DebugInfoTab``
  sub-tab of ``StaticAnalysisExtrasTab``, wired to ``get_debug_info``.
* Rows 40/41 -- ESIL function emulation (``aef``) and PC assignment
  (``aepc``) are now the "Emulate Function"/"Set PC" controls of
  ``ESILConsoleTab`` (``cutter_tabs.py``), wired to
  ``esil_emulate_function``/``esil_set_pc``.
* Rows 42/43 -- adding a named flag (``f <name> <size> @ <addr>``) and
  resolving the nearest flag from an address (``fdj``) are now the "Add
  Flag"/"Resolve Flag" controls of ``FlagsTab`` (``cutter_tabs.py``), wired
  to ``add_flag``/``resolve_flag``.
* Rows 46/47 -- reading and writing a Rizin configuration variable (``e``)
  are now the "Get"/"Set" controls of ``ConfigTab`` (``cutter_tabs.py``),
  wired to ``get_config``/``set_config``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit, QPlainTextEdit, QTableWidget, QTabWidget, QTreeWidget

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import RelocationInfo, ResourceInfo, ToolName
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.cutter_static_extra_tab import (
    BasicBlocksTab,
    CallGraphTab,
    ClassesTab,
    DebugInfoTab,
    FunctionDisasmTab,
    StaticAnalysisExtrasTab,
    SyscallsTab,
    VtablesTab,
    ZignaturesTab,
)
from intellicrack.ui.panels.cutter_tabs import ConfigTab, ESILConsoleTab, FlagsTab, HexdumpTab
from tests.bridges.completeness.cutter.conftest import CommandRecorder, as_r2pipe, priv


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.02


def _pump_until(app: QApplication, predicate: object, *, timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Args:
        app: The live ``QApplication`` instance used to process pending events.
        predicate: Zero-argument callable checked after each pump iteration.
        timeout_s: Maximum time in seconds to keep pumping.

    Returns:
        bool: ``True`` if ``predicate()`` became truthy before the timeout,
        ``False`` otherwise.
    """
    assert callable(predicate)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


def _item_text(table: QTableWidget, row: int, column: int) -> str:
    """Return the text of a table cell, asserting the cell item is not ``None``.

    Args:
        table: The ``QTableWidget`` to read from.
        row: Row index of the cell.
        column: Column index of the cell.

    Returns:
        str: The cell's text content.
    """
    item = table.item(row, column)
    assert item is not None
    return item.text()


def _no_op_run_async(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None,
    on_error: Callable[[object], None] | None,
) -> None:
    """Discard a coroutine without scheduling it, matching ``RunAsyncFn``.

    Used in place of a lambda so the deprecated ``_run_async`` parameter of
    ``FlagsTab.refresh``/``ESILConsoleTab.refresh``/``ConfigTab.refresh`` is
    fully resolved by basedpyright instead of inferred as partially unknown.

    Args:
        coro: Coroutine that would normally be scheduled onto a worker thread.
        on_success: Deprecated success callback, retained for parity with the
            production ``RunAsyncFn`` signature.
        on_error: Deprecated error callback, retained for parity with the
            production ``RunAsyncFn`` signature.
    """
    coro.close()
    del on_success
    del on_error


class TestRelocationsResourcesSwapRegression:
    """L1 regression gate: ``get_relocations``/``get_resources`` must not have their commands swapped.

    Falsified by: reverting ``cutter.py``'s ``get_relocations``/``get_resources``
    command strings back to the swapped state (``get_relocations`` issuing
    ``iRj`` and ``get_resources`` issuing ``irj``) turns every assertion in
    this class red, because the recorder is seeded with *distinct* real
    relocation and resource JSON payloads keyed to their correct commands
    only.
    """

    @staticmethod
    def test_get_relocations_issues_irj_and_returns_relocation_data() -> None:
        """``get_relocations`` must issue ``irj`` and parse it as relocation entries, not resources.

        Falsifiable: if ``get_relocations`` issued ``iRj`` (the swapped/buggy
        command), the recorder would return the resource JSON payload
        instead, and the returned ``RelocationInfo.type`` would read
        ``"icon"`` (a resource type) rather than the real relocation type
        ``"R_X86_64_RELATIVE"``. Broken production line: the command string
        literal inside ``CutterBridge.get_relocations`` (``cutter.py``).
        """
        recorder = CommandRecorder({
            "irj": '[{"name":"reloc_1","paddr":4096,"vaddr":4194304,"type":"R_X86_64_RELATIVE"}]',
            "iRj": '[{"name":"ICON_1","paddr":8192,"size":512,"type":"icon","language":"en-US"}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        result = asyncio.run(bridge.get_relocations())

        assert "irj" in recorder.commands, "get_relocations must issue the real rizin 'irj' relocations command"
        assert len(result) == 1
        assert result[0].name == "reloc_1"
        assert result[0].address == 4096
        assert result[0].vaddr == 4194304
        assert result[0].type == "R_X86_64_RELATIVE"

    @staticmethod
    def test_get_resources_issues_resources_command_and_returns_resource_data() -> None:
        """``get_resources`` must issue ``iRj`` and parse it as resource entries, not relocations.

        Falsifiable: if ``get_resources`` issued ``irj`` (the swapped/buggy
        command), the recorder would return the relocation JSON payload
        instead, and the returned ``ResourceInfo.type`` would read
        ``"R_X86_64_RELATIVE"`` (a relocation type) rather than the real
        resource type ``"icon"``. Broken production line: the command
        string literal inside ``CutterBridge.get_resources`` (``cutter.py``).
        """
        recorder = CommandRecorder({
            "irj": '[{"name":"reloc_1","paddr":4096,"vaddr":4194304,"type":"R_X86_64_RELATIVE"}]',
            "iRj": '[{"name":"ICON_1","paddr":8192,"size":512,"type":"icon","language":"en-US"}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        result = asyncio.run(bridge.get_resources())

        assert "iRj" in recorder.commands, "get_resources must issue the real rizin 'iRj' resources command"
        assert len(result) == 1
        assert result[0].name == "ICON_1"
        assert result[0].address == 8192
        assert result[0].size == 512
        assert result[0].type == "icon"
        assert result[0].language == "en-US"


class TestRelocationsResourcesToolDefDispatchL2:
    """L2 gate: ``cutter.get_relocations``/``cutter.get_resources`` dispatch through the real ToolRegistry."""

    @staticmethod
    def test_execute_tool_call_get_relocations_returns_real_relocation_data(tmp_path: Path) -> None:
        """Dispatching ``cutter.get_relocations`` via the registry returns real, correctly-typed data.

        Falsifiable: if the tool-def's ``function_name`` did not exactly
        match the real bound method ``get_relocations``, ``execute_tool_call``
        would raise ``ToolError`` (unknown function) instead of returning the
        parsed relocation list. Broken production line: the ``_tf("get_relocations", ...)``
        entry in ``_build_tool_functions`` (``cutter.py``).
        """
        recorder = CommandRecorder({
            "irj": '[{"name":"reloc_x","paddr":256,"vaddr":65536,"type":"R_X86_64_GLOB_DAT"}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        registry.register_bridge(ToolName.CUTTER, bridge)

        raw_result = asyncio.run(registry.execute_tool_call("cutter", "cutter.get_relocations", {}))

        assert isinstance(raw_result, list)
        relocations = cast(list[RelocationInfo], raw_result)
        assert len(relocations) == 1
        assert relocations[0].name == "reloc_x"
        assert relocations[0].type == "R_X86_64_GLOB_DAT"

    @staticmethod
    def test_execute_tool_call_get_resources_returns_real_resource_data(tmp_path: Path) -> None:
        """Dispatching ``cutter.get_resources`` via the registry returns real, correctly-typed data.

        Falsifiable: if the tool-def's ``function_name`` did not exactly
        match the real bound method ``get_resources``, ``execute_tool_call``
        would raise ``ToolError`` (unknown function) instead of returning the
        parsed resource list. Broken production line: the ``_tf("get_resources", ...)``
        entry in ``_build_tool_functions`` (``cutter.py``).
        """
        recorder = CommandRecorder({
            "iRj": '[{"name":"BITMAP_1","paddr":1024,"size":2048,"type":"bitmap","language":"neutral"}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        registry.register_bridge(ToolName.CUTTER, bridge)

        raw_result = asyncio.run(registry.execute_tool_call("cutter", "cutter.get_resources", {}))

        assert isinstance(raw_result, list)
        resources = cast(list[ResourceInfo], raw_result)
        assert len(resources) == 1
        assert resources[0].name == "BITMAP_1"
        assert resources[0].type == "bitmap"
        assert resources[0].size == 2048


@pytest.mark.usefixtures("qapp")
class TestAnalysisDepthSelectorL3:
    """L3 gate: the analysis-depth combo box must thread its value into ``bridge.analyze``."""

    @staticmethod
    def test_quick_level_selection_issues_aa_not_aaa(qapp: QApplication) -> None:
        """Selecting 'quick' in the combo box and clicking Analyze must issue rizin's 'aa', not the default 'aaa'.

        Falsifiable: if ``CutterPanel._on_analyze`` ignored
        ``self._analysis_level_combo.currentText()`` and always called
        ``self._bridge.analyze()`` with no argument (the pre-fix behaviour),
        the bridge would always run the default 'normal' level ('aaa'), and
        this test's assertion that 'aa' is issued (and 'aaa' is not) would
        fail. Broken production line: the
        ``level = self._analysis_level_combo.currentText() or _DEFAULT_ANALYSIS_LEVEL``
        /``self._bridge.analyze(level)`` call in ``CutterPanel._on_analyze``
        (``cutter_panel.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop while
                the real background bridge-call worker thread runs.
        """
        recorder = CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        bridge.state.binary_loaded = True

        panel = CutterPanel()
        panel.set_bridge(bridge)
        analysis_level_combo = cast(QComboBox, getattr(panel, "_analysis_level_combo"))
        analysis_level_combo.setCurrentText("quick")
        on_analyze = cast(Callable[[], None], getattr(panel, "_on_analyze"))

        on_analyze()

        assert _pump_until(qapp, lambda: "aa" in recorder.commands or "aaa" in recorder.commands)
        assert "aa" in recorder.commands
        assert "aaa" not in recorder.commands
        assert "aaaa" not in recorder.commands

    @staticmethod
    def test_deep_level_selection_issues_aaaa(qapp: QApplication) -> None:
        """Selecting 'deep' in the combo box and clicking Analyze must issue rizin's 'aaaa'.

        Falsifiable: same production line as the quick-level test above --
        without threading the combo box value through, the deep pass would
        never be reachable from the GUI and 'aaaa' would never be issued.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        bridge.state.binary_loaded = True

        panel = CutterPanel()
        panel.set_bridge(bridge)
        analysis_level_combo = cast(QComboBox, getattr(panel, "_analysis_level_combo"))
        analysis_level_combo.setCurrentText("deep")
        on_analyze = cast(Callable[[], None], getattr(panel, "_on_analyze"))

        on_analyze()

        assert _pump_until(qapp, lambda: "aaaa" in recorder.commands)
        assert "aaaa" in recorder.commands

    @staticmethod
    def test_no_bridge_configured_does_not_crash_and_sets_status(qapp: QApplication) -> None:
        """Clicking Analyze with no bridge configured must report status, not raise.

        Falsifiable: if the ``self._bridge is None`` guard were removed from
        ``_on_analyze``, this call would raise ``AttributeError`` on
        ``self._bridge.state`` instead of setting a status message.

        Args:
            qapp: Qt application fixture (unused directly but required so a
                QWidget can be constructed).
        """
        del qapp
        panel = CutterPanel()
        on_analyze = cast(Callable[[], None], getattr(panel, "_on_analyze"))
        on_analyze()
        assert panel.status_label is not None
        assert panel.status_label.text() == "No bridge configured"


@pytest.mark.usefixtures("qapp")
class TestHexdumpWordModeL3:
    """L3 gate: the hexdump mode combo box must dispatch ``hexdump_words`` (``pxw``) in word mode."""

    @staticmethod
    def test_word_mode_selection_issues_pxw_not_px(qapp: QApplication) -> None:
        """Selecting 'Words' mode and dumping must issue rizin's 'pxw', not the byte-mode 'px'.

        Falsifiable: if ``HexdumpTab._dump`` ignored the mode combo box and
        always called ``bridge.hexdump`` (byte mode), 'pxw' would never be
        issued and this assertion would fail. Broken production line: the
        ``coro = self._bridge.hexdump_words(...) if word_mode else self._bridge.hexdump(...)``
        branch in ``HexdumpTab._dump`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "pxw": "0x00001000  0x00000000  0x00000000\n",
            "px": "0x00001000  00 00 00 00\n",
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = HexdumpTab()
        setattr(tab, "_bridge", bridge)
        addr_input = cast(QLineEdit, getattr(tab, "_addr_input"))
        len_input = cast(QLineEdit, getattr(tab, "_len_input"))
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        addr_input.setText("0x1000")
        len_input.setText("16")
        mode_combo.setCurrentText("Words (pxw)")

        on_dump = cast(Callable[[], None], getattr(tab, "_on_dump"))
        on_dump()

        assert _pump_until(qapp, lambda: any(c.startswith(("pxw", "px")) for c in recorder.commands))
        assert any(c.startswith("pxw ") for c in recorder.commands), recorder.commands
        assert not any(c.startswith("px ") for c in recorder.commands), recorder.commands


class TestStaticAnalysisExtrasTabConstruction:
    """L3 gate: ``StaticAnalysisExtrasTab`` really wires all 8 previously-NO-CONTROL sub-tabs."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_all_seven_sub_tabs_exist_and_are_correct_types() -> None:
        """The composite tab must contain real instances of all 8 remediated sub-tab classes.

        Falsifiable: if any sub-tab construction were removed from
        ``StaticAnalysisExtrasTab.__init__``, the corresponding
        ``isinstance`` check would fail. Broken production line: the
        ``self._tabs.addTab(...)`` calls in ``StaticAnalysisExtrasTab.__init__``
        (``cutter_static_extra_tab.py``).
        """
        tab = StaticAnalysisExtrasTab()

        assert isinstance(getattr(tab, "_debug_info_tab"), DebugInfoTab)
        assert isinstance(getattr(tab, "_classes_tab"), ClassesTab)
        assert isinstance(getattr(tab, "_callgraph_tab"), CallGraphTab)
        assert isinstance(getattr(tab, "_vtables_tab"), VtablesTab)
        assert isinstance(getattr(tab, "_syscalls_tab"), SyscallsTab)
        assert isinstance(getattr(tab, "_zignatures_tab"), ZignaturesTab)
        assert isinstance(getattr(tab, "_basic_blocks_tab"), BasicBlocksTab)
        assert isinstance(getattr(tab, "_function_disasm_tab"), FunctionDisasmTab)
        tabs_widget = cast(QTabWidget, getattr(tab, "_tabs"))
        assert tabs_widget.count() == 8


@pytest.mark.usefixtures("qapp")
class TestClassesTabL3:
    """L3 gate: row 19 (Classes/RTTI) -- the tab's refresh must invoke the real ``get_classes`` bridge method."""

    @staticmethod
    def test_refresh_calls_icj_and_populates_tree(qapp: QApplication) -> None:
        """``ClassesTab.refresh`` must issue ``icj`` and populate the tree with the real class/method/field data.

        Falsifiable: if ``ClassesTab.refresh`` called a different bridge
        method or never invoked ``run_bridge_coroutine_logged``, the
        recorder would never see 'icj' and the tree would stay empty.
        Broken production line: ``bridge.get_classes()`` invocation inside
        ``ClassesTab.refresh`` (``cutter_static_extra_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "icj": (
                '[{"classname":"CLicenseValidator","addr":4198400,'
                '"methods":[{"name":"CheckKey","addr":4198464,"type":"method"}],'
                '"fields":[{"name":"m_key","offset":8,"type":"char*"}]}]'
            ),
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ClassesTab()
        tab.refresh(bridge)
        tree = cast(QTreeWidget, getattr(tab, "_tree"))

        assert _pump_until(qapp, lambda: tree.topLevelItemCount() > 0)
        assert "icj" in recorder.commands
        top = tree.topLevelItem(0)
        assert top is not None
        assert top.text(0) == "CLicenseValidator"
        assert top.text(1) == f"0x{4198400:X}"


@pytest.mark.usefixtures("qapp")
class TestCallGraphTabL3:
    """L3 gate: row 8 (call graph) -- the tab's refresh must invoke the real ``get_callgraph`` bridge method."""

    @staticmethod
    def test_refresh_calls_agcj_and_populates_table(qapp: QApplication) -> None:
        """``CallGraphTab.refresh`` must issue ``agcj`` and populate the table with real caller/callee edges.

        Falsifiable: if the tab called a different method or skipped the
        bridge call entirely, 'agcj' would never appear in the recorder and
        the table would stay at zero rows.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "agcj": '[{"name":"main","addr":4198400,"imports":["validate_license","printf"]}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = CallGraphTab()
        tab.refresh(bridge)
        table = cast(QTableWidget, getattr(tab, "_table"))

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "agcj" in recorder.commands
        assert table.rowCount() == 2
        callees: set[str] = set()
        for row in range(table.rowCount()):
            callee_item = table.item(row, 1)
            assert callee_item is not None
            callees.add(callee_item.text())
        assert callees == {"validate_license", "printf"}
        main_item = table.item(0, 0)
        assert main_item is not None
        assert main_item.text() == "main"


@pytest.mark.usefixtures("qapp")
class TestVtablesTabL3:
    """L3 gate: row 22 (vtables) -- the tab's refresh must invoke the real ``get_vtables`` bridge method."""

    @staticmethod
    def test_refresh_calls_avj_and_populates_table(qapp: QApplication) -> None:
        """``VtablesTab.refresh`` must issue ``avj`` and populate the table with real vtable data.

        Falsifiable: if the tab never called ``bridge.get_vtables()``,
        'avj' would never be recorded and the table would remain empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "avj": '[{"name":"vtable_CLicense","offset":4202496,"methods":[{"name":"m0"},{"name":"m1"},{"name":"m2"}]}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = VtablesTab()
        tab.refresh(bridge)
        table = cast(QTableWidget, getattr(tab, "_table"))

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "avj" in recorder.commands
        name_item = table.item(0, 0)
        offset_item = table.item(0, 1)
        method_count_item = table.item(0, 2)
        assert name_item is not None
        assert offset_item is not None
        assert method_count_item is not None
        assert name_item.text() == "vtable_CLicense"
        assert offset_item.text() == f"0x{4202496:X}"
        assert method_count_item.text() == "3"


@pytest.mark.usefixtures("qapp")
class TestSyscallsTabL3:
    """L3 gate: row 23 (syscalls) -- the tab's refresh must invoke the real ``get_syscalls`` bridge method."""

    @staticmethod
    def test_refresh_calls_asj_and_populates_table(qapp: QApplication) -> None:
        """``SyscallsTab.refresh`` must issue ``asj`` and populate the table with the real syscall entry.

        Falsifiable: if the tab called ``get_classes``/``get_vtables``
        instead of ``get_syscalls``, 'asj' would never be recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "asj": '[{"name":"NtCreateFile","swi":85,"addr":4210688}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SyscallsTab()
        tab.refresh(bridge)
        table = cast(QTableWidget, getattr(tab, "_table"))

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "asj" in recorder.commands
        name_item = table.item(0, 0)
        swi_item = table.item(0, 1)
        assert name_item is not None
        assert swi_item is not None
        assert name_item.text() == "NtCreateFile"
        assert swi_item.text() == "85"


@pytest.mark.usefixtures("qapp")
class TestZignaturesTabL3:
    """L3 gate: rows 24/24b/24c/24d (zignatures) -- list/generate/add/search must invoke the real bridge methods."""

    @staticmethod
    def test_list_button_calls_zj_and_populates_table(qapp: QApplication) -> None:
        """Clicking List must issue rizin's ``zj`` and render the real zignature name.

        Falsifiable: if ``ZignaturesTab._on_list`` called a different
        method or never dispatched, 'zj' would never appear in the recorder.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"zj": '[{"name":"sig.license_check","bytes":"8b4508","realname":"check_license"}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ZignaturesTab()
        tab.refresh(bridge)
        table = cast(QTableWidget, getattr(tab, "_table"))

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "zj" in recorder.commands
        name_item = table.item(0, 0)
        realname_item = table.item(0, 2)
        assert name_item is not None
        assert realname_item is not None
        assert name_item.text() == "sig.license_check"
        assert realname_item.text() == "check_license"

    @staticmethod
    def test_generate_button_calls_zg_at_address(qapp: QApplication) -> None:
        """Clicking Generate with an address must issue ``zg @ <addr>``, scoping generation.

        Falsifiable: if ``_on_generate`` failed to pass the parsed address
        through to ``bridge.generate_zignatures``, the recorder would only
        see a bare 'zg' (whole-binary) instead of the address-scoped form.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"zg": "", "zj": "[]"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ZignaturesTab()
        setattr(tab, "_bridge", bridge)
        gen_addr_input = cast(QLineEdit, getattr(tab, "_gen_addr_input"))
        gen_addr_input.setText("0x401000")

        on_generate = cast(Callable[[], None], getattr(tab, "_on_generate"))
        on_generate()

        assert _pump_until(qapp, lambda: any("zg" in c for c in recorder.commands))
        assert any(c.startswith("zg") and "4198400" in c for c in recorder.commands), recorder.commands

    @staticmethod
    def test_add_button_calls_za_with_name_and_data(qapp: QApplication) -> None:
        """Clicking Add with name/data inputs must issue rizin's ``za <name> <data>``.

        Falsifiable: if ``_on_add`` never forwarded the two input fields to
        ``bridge.add_zignature``, the exact 'za check_license 8b4508' command
        would never appear in the recorder.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"za": "", "zj": "[]"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ZignaturesTab()
        setattr(tab, "_bridge", bridge)
        add_name_input = cast(QLineEdit, getattr(tab, "_add_name_input"))
        add_data_input = cast(QLineEdit, getattr(tab, "_add_data_input"))
        add_name_input.setText("check_license")
        add_data_input.setText("8b4508")

        on_add = cast(Callable[[], None], getattr(tab, "_on_add"))
        on_add()

        assert _pump_until(qapp, lambda: any(c.startswith("za ") for c in recorder.commands))
        assert "za check_license 8b4508" in recorder.commands

    @staticmethod
    def test_search_button_calls_zslash_j_and_populates_matches(qapp: QApplication) -> None:
        """Clicking Search Matches must issue rizin's ``z/j`` and render the real match.

        Falsifiable: if ``_on_search`` called ``get_zignatures`` (list)
        instead of ``search_zignatures``, 'z/j' would never appear in the
        recorder and the match count would be wrong.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"z/j": '[{"name":"sig.license_check","bytes":"8b4508","realname":"check_license"}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ZignaturesTab()
        setattr(tab, "_bridge", bridge)

        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        on_search()

        table = cast(QTableWidget, getattr(tab, "_table"))
        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "z/j" in recorder.commands
        name_item = table.item(0, 0)
        assert name_item is not None
        assert name_item.text() == "sig.license_check"


@pytest.mark.usefixtures("qapp")
class TestBasicBlocksTabL3:
    """L3 gate: row 7 (basic blocks) -- ``set_address``/fetch must invoke the real ``get_basic_blocks`` bridge method."""

    @staticmethod
    def test_set_address_calls_afbj_and_populates_table(qapp: QApplication) -> None:
        """``BasicBlocksTab.set_address`` must issue ``afbj @ <addr>`` and render the real block fields.

        Falsifiable: if ``set_address``/``_on_fetch`` never dispatched to
        ``bridge.get_basic_blocks``, 'afbj' would never be recorded and the
        table would remain empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "afbj": '[{"addr":4198400,"size":32,"jump":4198432,"fail":4198448,"ops":[{"offset":4198400}]}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = BasicBlocksTab()
        tab.refresh(bridge)
        tab.set_address(0x401000)
        table = cast(QTableWidget, getattr(tab, "_table"))

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert any(c.startswith("afbj") and "4198400" in c for c in recorder.commands), recorder.commands
        addr_item = table.item(0, 0)
        size_item = table.item(0, 1)
        assert addr_item is not None
        assert size_item is not None
        assert addr_item.text() == f"0x{4198400:X}"
        assert size_item.text() == "32"


@pytest.mark.usefixtures("qapp")
class TestFunctionDisasmTabL3:
    """L3 gate: row 4 (linear function disassembly) -- must invoke the real ``disassemble_function`` bridge method."""

    @staticmethod
    def test_set_address_calls_pdf_and_renders_text(qapp: QApplication) -> None:
        """``FunctionDisasmTab.set_address`` must issue ``pdf @ <addr>`` and render the returned text verbatim.

        Falsifiable: if the tab called ``disassemble`` (range-mode ``pdj``,
        the pre-existing Disassembly tab's method) instead of the new
        ``disassemble_function`` (``pdf``), 'pdf' would never be recorded
        and the text would be wrong or empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        expected_text = "            0x00401000      55             push rbp\n            0x00401001      8bec           mov ebp, esp\n"
        recorder = CommandRecorder({"pdf": expected_text})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = FunctionDisasmTab()
        tab.refresh(bridge)
        tab.set_address(0x401000)
        output = cast(QPlainTextEdit, getattr(tab, "_output"))

        assert _pump_until(qapp, lambda: bool(output.toPlainText()))
        assert any(c.startswith("pdf") and "4198400" in c for c in recorder.commands), recorder.commands
        assert output.toPlainText() == expected_text


@pytest.mark.usefixtures("qapp")
class TestDebugInfoTabL3:
    """L3 gate: row 25 (debug info) -- Refresh must invoke the real ``get_debug_info`` bridge method."""

    @staticmethod
    def test_refresh_calls_idj_and_populates_table(qapp: QApplication) -> None:
        """``DebugInfoTab.refresh`` must issue ``iDj`` and render the real debug-info key/value pairs.

        Falsifiable: if ``DebugInfoTab._on_refresh`` called a different
        bridge method or never invoked ``run_bridge_coroutine_logged``, the
        recorder would never see 'iDj' and the table would stay empty.
        Broken production line: the ``self._bridge.get_debug_info()`` call
        in ``DebugInfoTab._on_refresh`` (``cutter_static_extra_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"iDj": '[{"debug_file":"target.pdb","dwarf":false,"pdb":true}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = DebugInfoTab()
        tab.refresh(bridge)
        table = priv(tab, "_table", QTableWidget)

        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert "iDj" in recorder.commands
        rows = {_item_text(table, row, 0): _item_text(table, row, 1) for row in range(table.rowCount())}
        assert rows["debug_file"] == "target.pdb"
        assert rows["pdb"] == "True"


@pytest.mark.usefixtures("qapp")
class TestESILConsoleTabEmulateAndSetPcL3:
    """L3 gate: rows 40/41 (ESIL emulate function / set PC) -- must invoke the real bridge methods."""

    @staticmethod
    def test_emulate_function_button_calls_aef_at_address(qapp: QApplication) -> None:
        """Clicking "Emulate Function" with an address must issue rizin's ``aef @ <addr>``.

        Falsifiable: if ``_on_emulate_function`` never called
        ``self._bridge.esil_emulate_function(address)``, 'aef @ 4198400'
        would never appear in the recorder and the output console would
        never show the emulation result. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.esil_emulate_function(address), ...)``
        call in ``ESILConsoleTab._on_emulate_function`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"aeim": "", "aef @ 4198400": "0x00401000: eax = 0"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ESILConsoleTab()
        tab.refresh(bridge, _no_op_run_async)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        output = priv(tab, "_output", QPlainTextEdit)
        on_emulate_function = cast(Callable[[], None], getattr(tab, "_on_emulate_function"))
        addr_input.setText("0x401000")

        on_emulate_function()

        assert _pump_until(qapp, lambda: "aef @ 4198400" in recorder.commands)
        assert "aef @ 4198400" in recorder.commands
        assert _pump_until(qapp, lambda: "0x00401000: eax = 0" in output.toPlainText())

    @staticmethod
    def test_set_pc_button_calls_aepc_at_address(qapp: QApplication) -> None:
        """Clicking "Set PC" with an address must issue rizin's ``aepc <addr>``.

        Falsifiable: if ``_on_set_pc`` never called
        ``self._bridge.esil_set_pc(address)``, 'aepc 4198400' would never
        appear in the recorder. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.esil_set_pc(address), ...)``
        call in ``ESILConsoleTab._on_set_pc`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"aeim": "", "aepc 4198400": ""})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ESILConsoleTab()
        tab.refresh(bridge, _no_op_run_async)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        output = priv(tab, "_output", QPlainTextEdit)
        on_set_pc = cast(Callable[[], None], getattr(tab, "_on_set_pc"))
        addr_input.setText("0x401000")

        on_set_pc()

        assert _pump_until(qapp, lambda: "aepc 4198400" in recorder.commands)
        assert "aepc 4198400" in recorder.commands
        assert _pump_until(qapp, lambda: "PC set to 0x401000" in output.toPlainText())


@pytest.mark.usefixtures("qapp")
class TestFlagsTabAddAndResolveL3:
    """L3 gate: rows 42/43 (add flag / resolve flag) -- must invoke the real bridge methods."""

    @staticmethod
    def test_add_flag_button_calls_f_command_and_refreshes_table(qapp: QApplication) -> None:
        """Clicking "Add Flag" must issue rizin's ``f <name> <size> @ <addr>`` and then re-list flags.

        Falsifiable: if ``_on_add_flag`` never called
        ``self._bridge.add_flag(name, size, address)``, 'f license_ok 4 @
        4198400' would never appear in the recorder and the flags table
        would not gain the new row. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.add_flag(name, size, address), ...)``
        call in ``FlagsTab._on_add_flag`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "f license_ok 4 @ 4198400": "",
            "fj": '[{"name":"license_ok","offset":4198400,"size":4}]',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = FlagsTab()
        tab.refresh(bridge, _no_op_run_async)
        add_name_input = priv(tab, "_add_name_input", QLineEdit)
        add_size_input = priv(tab, "_add_size_input", QLineEdit)
        add_addr_input = priv(tab, "_add_addr_input", QLineEdit)
        table = priv(tab, "_table", QTableWidget)
        on_add_flag = cast(Callable[[], None], getattr(tab, "_on_add_flag"))
        add_name_input.setText("license_ok")
        add_size_input.setText("4")
        add_addr_input.setText("0x401000")

        on_add_flag()

        assert _pump_until(qapp, lambda: "f license_ok 4 @ 4198400" in recorder.commands)
        assert "f license_ok 4 @ 4198400" in recorder.commands
        assert _pump_until(qapp, lambda: table.rowCount() > 0)
        assert _item_text(table, 0, 0) == "license_ok"

    @staticmethod
    def test_resolve_flag_button_calls_fdj_and_shows_flag_name(qapp: QApplication) -> None:
        """Clicking "Resolve Flag" with an address must issue rizin's ``fdj @ <addr>`` and display the resolved name.

        Falsifiable: if ``_on_resolve_flag`` never called
        ``self._bridge.resolve_flag(address)``, 'fdj @ 4198400' would never
        appear in the recorder and the result label would not show the
        real flag name. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.resolve_flag(address), ...)``
        call in ``FlagsTab._on_resolve_flag`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "fj": "[]",
            "fdj @ 4198400": '{"name":"license_ok","offset":0}',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = FlagsTab()
        tab.refresh(bridge, _no_op_run_async)
        resolve_addr_input = priv(tab, "_resolve_addr_input", QLineEdit)
        resolve_result_label = priv(tab, "_resolve_result_label", QLabel)
        on_resolve_flag = cast(Callable[[], None], getattr(tab, "_on_resolve_flag"))
        resolve_addr_input.setText("0x401000")

        on_resolve_flag()

        assert _pump_until(qapp, lambda: "fdj @ 4198400" in recorder.commands)
        assert "fdj @ 4198400" in recorder.commands
        assert _pump_until(qapp, lambda: resolve_result_label.text() == "license_ok")


@pytest.mark.usefixtures("qapp")
class TestConfigTabGetAndSetL3:
    """L3 gate: rows 46/47 (config get / set) -- must invoke the real bridge methods."""

    @staticmethod
    def test_get_button_calls_e_command_and_shows_value(qapp: QApplication) -> None:
        """Clicking "Get" with a key must issue rizin's ``e <key>`` and display the real value.

        Falsifiable: if ``_on_get`` never called
        ``self._bridge.get_config(key)``, 'e asm.arch' would never appear
        in the recorder and the output console would never show the real
        configuration value. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.get_config(key), ...)``
        call in ``ConfigTab._on_get`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"e asm.arch": "x86\n"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ConfigTab()
        tab.refresh(bridge, _no_op_run_async)
        get_key_input = priv(tab, "_get_key_input", QLineEdit)
        output = priv(tab, "_output", QPlainTextEdit)
        on_get = cast(Callable[[], None], getattr(tab, "_on_get"))
        get_key_input.setText("asm.arch")

        on_get()

        assert _pump_until(qapp, lambda: "e asm.arch" in recorder.commands)
        assert "e asm.arch" in recorder.commands
        assert _pump_until(qapp, lambda: "asm.arch = x86" in output.toPlainText())

    @staticmethod
    def test_set_button_calls_e_key_equals_value_command(qapp: QApplication) -> None:
        """Clicking "Set" with a key/value pair must issue rizin's ``e <key>=<value>``.

        Falsifiable: if ``_on_set`` never called
        ``self._bridge.set_config(key, value)``, 'e asm.bits=32' would
        never appear in the recorder. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.set_config(key, value), ...)``
        call in ``ConfigTab._on_set`` (``cutter_tabs.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"e asm.bits=32": ""})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ConfigTab()
        tab.refresh(bridge, _no_op_run_async)
        set_key_input = priv(tab, "_set_key_input", QLineEdit)
        set_value_input = priv(tab, "_set_value_input", QLineEdit)
        output = priv(tab, "_output", QPlainTextEdit)
        on_set = cast(Callable[[], None], getattr(tab, "_on_set"))
        set_key_input.setText("asm.bits")
        set_value_input.setText("32")

        on_set()

        assert _pump_until(qapp, lambda: "e asm.bits=32" in recorder.commands)
        assert "e asm.bits=32" in recorder.commands
        assert _pump_until(qapp, lambda: "asm.bits = 32" in output.toPlainText())
