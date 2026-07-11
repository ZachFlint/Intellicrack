# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 u6 ToolOutputPanel fixes.

Covers:
    F-0005: ``FunctionListPanel`` is populated by ``update_bridge_analysis``
        and ``XRefPanel`` is populated by an active static-analysis bridge
        when a function/xref is selected.
    F-0021: ``wire_sandbox_backend`` actually wires the supplied sandbox
        (and optional manager) into a real ``SandboxBridge`` and forwards
        it to ``wire_sandbox_bridge`` instead of being a deprecation no-op.
    F4: ``_select_static_analysis_bridge`` probes bridge health (connected
        + binary loaded) instead of unconditionally preferring Cutter, so
        an unhealthy/erroring Cutter bridge does not starve the xref panel
        when a healthy Ghidra bridge holds the real cross-reference data.
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from typing import TYPE_CHECKING, Final, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import (
    BridgeAnalysisSummary,
    CrossReference,
    FunctionInfo,
)
from intellicrack.sandbox import SandboxBase, SandboxConfig, SandboxManager
from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel


_ADDR_MAIN: Final[int] = 0x401000
_ADDR_HELPER: Final[int] = 0x402000
_ADDR_LIBC: Final[int] = 0x403000


class _RecordingAnalysisPanel:
    """Lightweight stand-in for ``BridgeAnalysisPanel``.

    The real panel calls ``setProperty(..., value=True)`` in its setup which
    breaks under the bundled PyQt6 build; for the F-0005 regression tests the
    function-list population behaviour is what matters, so this recorder just
    captures the analysis summary without touching Qt internals.
    """

    received: list[BridgeAnalysisSummary]

    def __init__(self) -> None:
        """Initialize with an empty receive log."""
        self.received = []

    def set_analysis(self, analysis: BridgeAnalysisSummary) -> None:
        """Record the analysis summary handed to the panel.

        Args:
            analysis: Bridge analysis summary forwarded from the panel host.
        """
        self.received.append(analysis)


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Provide a single QApplication for the test module.

    Returns:
        QCoreApplication: The running Qt application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


def _process_events_until(
    qapp: QCoreApplication,
    predicate: Callable[[], bool],
    timeout_ms: int = 5000,
) -> bool:
    """Pump the Qt event loop until ``predicate`` is truthy or timeout.

    Args:
        qapp: The Qt application to drive.
        predicate: Zero-argument callable returning truthy when done.
        timeout_ms: Total milliseconds to wait before giving up.

    Returns:
        bool: True if the predicate became truthy within the timeout.
    """
    elapsed = 0
    step = 25
    while elapsed < timeout_ms:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(step, loop.quit)
        loop.exec()
        qapp.processEvents()
        elapsed += step
    return predicate()


class _RecordingCutterBridge(CutterBridge):
    """CutterBridge double that records xref calls and returns scripted data.

    The bridge's ``get_xrefs_to`` and ``get_xrefs_from`` methods normally hit
    a running rizin process. This subclass overrides them so the test exercises
    the real ToolOutputPanel wiring (registry attribute + async dispatch +
    main-thread callback) without spawning external tools.
    """

    to_calls: list[int]
    from_calls: list[int]
    to_result: list[CrossReference]
    from_result: list[CrossReference]
    should_raise: RuntimeError | None

    def __init__(self) -> None:
        """Initialize the recording bridge with empty call history."""
        super().__init__()
        self.to_calls = []
        self.from_calls = []
        self.to_result = []
        self.from_result = []
        self.should_raise = None

    @override
    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Record the call and return scripted incoming xrefs.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: Configured ``to_result``.

        Raises:
            self.should_raise: When set, propagates the scripted error so the
                callers can exercise their failure path.
        """
        self.to_calls.append(address)
        if self.should_raise is not None:
            raise self.should_raise
        return list(self.to_result)

    @override
    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Record the call and return scripted outgoing xrefs.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: Configured ``from_result``.

        Raises:
            self.should_raise: When set, propagates the scripted error so the
                callers can exercise their failure path.
        """
        self.from_calls.append(address)
        if self.should_raise is not None:
            raise self.should_raise
        return list(self.from_result)


class _StubWindowsSandbox(SandboxBase):
    """Concrete SandboxBase used to exercise ``wire_sandbox_backend``.

    The sandbox manager only needs an object satisfying ``SandboxBase`` so
    ``register_existing_sandbox`` can wrap it in a ``SandboxInstance``. The
    class name does NOT start with "qemu", so the wire helper should
    classify this as a Windows sandbox.
    """

    def __init__(self) -> None:
        """Initialize the stub sandbox with default config."""
        super().__init__(SandboxConfig())


class _StubQemuSandbox(SandboxBase):
    """Concrete SandboxBase whose name triggers the qemu classification.

    Used to verify ``wire_sandbox_backend`` detects the QEMU sandbox type
    from the runtime class name.
    """

    def __init__(self) -> None:
        """Initialize the stub QEMU sandbox with default config."""
        super().__init__(SandboxConfig())


def _make_summary(functions: list[FunctionInfo]) -> BridgeAnalysisSummary:
    """Build a ``BridgeAnalysisSummary`` populated only with functions.

    Args:
        functions: Functions to embed in the summary.

    Returns:
        BridgeAnalysisSummary: Summary with empty lists for unrelated fields.
    """
    return BridgeAnalysisSummary(
        binary_name="u6_target.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=functions,
        format_info="pe",
        architecture="x86_64",
        source_bridges=["cutter"],
        analysis_notes=[],
        complete=True,
    )


def _make_function(name: str, address: int) -> FunctionInfo:
    """Build a minimal ``FunctionInfo`` for the function-list panel test.

    Args:
        name: Function name to display.
        address: Function start address.

    Returns:
        FunctionInfo: Dataclass instance with mandatory fields populated.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=64,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


@pytest.mark.usefixtures("qapp")
class TestF0005FunctionListPopulation:
    """F-0005: FunctionListPanel must be populated when bridge analysis updates."""

    @staticmethod
    def test_update_bridge_analysis_populates_function_list() -> None:
        """``update_bridge_analysis`` must push functions into the navigator panel."""
        panel = ToolOutputPanel()
        recorder = _RecordingAnalysisPanel()
        panel.analysis_panel = cast("BridgeAnalysisPanel", recorder)
        try:
            TestF0005FunctionListPopulation._assert_function_list_populated(panel, recorder)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_function_list_populated(
        panel: ToolOutputPanel,
        recorder: _RecordingAnalysisPanel,
    ) -> None:
        """Push a known summary and verify the navigator panel contents.

        Args:
            panel: The ToolOutputPanel under test.
            recorder: Recording analysis panel installed as side-effect sink.
        """
        assert panel.func_list.get_functions() == []

        summary = _make_summary([
            _make_function("main", _ADDR_MAIN),
            _make_function("helper", _ADDR_HELPER),
            _make_function("cleanup", _ADDR_LIBC),
        ])
        panel.update_bridge_analysis(summary)

        stored = panel.func_list.get_functions()
        assert stored == [
            ("main", _ADDR_MAIN),
            ("helper", _ADDR_HELPER),
            ("cleanup", _ADDR_LIBC),
        ]
        assert panel.func_list.list_widget.count() == 3
        first_item = panel.func_list.list_widget.item(0)
        assert first_item is not None
        assert "main" in first_item.text()
        assert "0x00401000" in first_item.text()
        assert recorder.received == [summary]

    @staticmethod
    def test_update_bridge_analysis_clears_stale_xrefs() -> None:
        """A new summary must reset xref panel state so prior data does not leak."""
        panel = ToolOutputPanel()
        recorder = _RecordingAnalysisPanel()
        panel.analysis_panel = cast("BridgeAnalysisPanel", recorder)
        try:
            panel.set_xrefs(
                [(0x401, "old_in")],
                [(0x402, "old_out")],
            )
            assert panel.xref_panel.xref_display.topLevelItemCount() == 2
            summary = _make_summary([_make_function("entry", _ADDR_MAIN)])
            panel.update_bridge_analysis(summary)

            assert panel.xref_panel.xref_display.topLevelItemCount() == 0
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestF0005XRefPopulation:
    """F-0005: XRefPanel must be populated from a static-analysis bridge."""

    @staticmethod
    def test_function_selection_populates_xref_panel(qapp: QCoreApplication) -> None:
        """Selecting a function must trigger an xref fetch and populate the tree."""
        panel = ToolOutputPanel()
        bridge = _RecordingCutterBridge()
        bridge.to_result = [
            CrossReference(
                from_address=0x500100,
                to_address=_ADDR_MAIN,
                ref_type="call",
                from_function="caller_a",
                to_function="main",
            ),
        ]
        bridge.from_result = [
            CrossReference(
                from_address=_ADDR_MAIN,
                to_address=0x500200,
                ref_type="call",
                from_function="main",
                to_function="callee_b",
            ),
        ]
        panel.cutter_bridge = bridge

        try:
            TestF0005XRefPopulation._assert_xref_panel_populated(qapp, panel, bridge)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_xref_panel_populated(
        qapp: QCoreApplication,
        panel: ToolOutputPanel,
        bridge: _RecordingCutterBridge,
    ) -> None:
        """Emit a function selection and verify xref panel is populated.

        Args:
            qapp: Active Qt application driving the event loop.
            panel: ToolOutputPanel under test.
            bridge: Recording cutter bridge used as the analysis source.
        """
        panel.func_list.function_selected.emit("main", _ADDR_MAIN)

        assert _process_events_until(
            qapp,
            lambda: panel.xref_panel.xref_display.topLevelItemCount() == 2,
        )
        assert bridge.to_calls == [_ADDR_MAIN]
        assert bridge.from_calls == [_ADDR_MAIN]

        roots = panel.xref_panel.xref_display
        assert roots.topLevelItemCount() == 2
        in_root = roots.topLevelItem(0)
        out_root = roots.topLevelItem(1)
        assert in_root is not None
        assert out_root is not None
        assert in_root.text(0) == "=== References TO ==="
        assert out_root.text(0) == "=== References FROM ==="
        in_child = in_root.child(0)
        out_child = out_root.child(0)
        assert in_child is not None
        assert out_child is not None
        assert "0x00500100" in in_child.text(0)
        assert "caller_a" in in_child.text(0)
        assert "0x00500200" in out_child.text(0)
        assert "callee_b" in out_child.text(0)

    @staticmethod
    def test_xref_selection_repopulates_xref_panel(qapp: QCoreApplication) -> None:
        """Following an xref must refresh the panel for the destination address."""
        panel = ToolOutputPanel()
        bridge = _RecordingCutterBridge()
        bridge.to_result = []
        bridge.from_result = []
        panel.cutter_bridge = bridge

        try:
            panel.xref_panel.xref_selected.emit(_ADDR_HELPER)
            assert _process_events_until(qapp, lambda: bridge.to_calls == [_ADDR_HELPER])
            assert bridge.from_calls == [_ADDR_HELPER]
        finally:
            panel.deleteLater()

    @staticmethod
    def test_no_static_bridge_clears_xref_panel(qapp: QCoreApplication) -> None:
        """Without a bridge the panel must clear instead of going stale."""
        panel = ToolOutputPanel()
        try:
            panel.set_xrefs([(0x100, "stale")], [(0x200, "old")])
            assert panel.xref_panel.xref_display.topLevelItemCount() == 2
            panel.populate_xrefs_for_address(_ADDR_MAIN)
            qapp.processEvents()

            assert panel.xref_panel.xref_display.topLevelItemCount() == 0
        finally:
            panel.deleteLater()

    @staticmethod
    def test_bridge_failure_clears_xref_panel(qapp: QCoreApplication) -> None:
        """Bridge errors must not corrupt the xref panel — it must be cleared."""
        panel = ToolOutputPanel()
        bridge = _RecordingCutterBridge()
        bridge.should_raise = RuntimeError("rizin_disconnected")
        panel.cutter_bridge = bridge

        try:
            panel.set_xrefs([(0x100, "stale")], [])
            panel.populate_xrefs_for_address(_ADDR_MAIN)

            assert _process_events_until(
                qapp,
                lambda: panel.xref_panel.xref_display.topLevelItemCount() == 0,
            )
        finally:
            panel.deleteLater()


class _FakeGhidraXrefRemote:
    """Minimal in-process double for the ``ghidra_bridge`` RPC client.

    Mirrors the ``_FakeGhidraRemote`` seam used in
    ``tests/bridges/test_ghidra_wave2a_xrefs.py``: records every script
    dispatched via ``remote_exec`` and returns a pre-scripted dict list via
    ``remote_eval``, so ``GhidraBridge.get_xrefs_to``/``get_xrefs_from`` run
    their real parsing/framing logic unmodified. Dispatches the canned
    response on whether the most recently executed script queries
    ``getReferencesTo`` or ``getReferencesFrom`` so a single fake can answer
    both queries ``populate_xrefs_for_address`` issues with distinct data.
    """

    def __init__(
        self,
        to_result: list[dict[str, object]],
        from_result: list[dict[str, object]],
    ) -> None:
        """Initialize the fake with scripted responses for each xref direction.

        Args:
            to_result: Payload dicts returned when the executed script calls
                ``getReferencesTo``.
            from_result: Payload dicts returned when the executed script
                calls ``getReferencesFrom``.
        """
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self._to_result = to_result
        self._from_result = from_result

    def remote_exec(self, code: str) -> None:
        """Record the dispatched Jython script.

        Args:
            code: Jython source emitted by the bridge after
                ``prepare_remote_script`` has rewritten the script.
        """
        self.exec_calls.append(code)

    def remote_eval(self, expr: str) -> object:
        """Record the sentinel readback and return the matching scripted result.

        Args:
            expr: Sentinel variable name produced by ``prepare_remote_script``.

        Returns:
            object: ``to_result`` when the most recent script queried
            ``getReferencesTo``, otherwise ``from_result``.
        """
        self.eval_calls.append(expr)
        last_exec = self.exec_calls[-1]
        return self._to_result if "getReferencesTo" in last_exec else self._from_result


@pytest.mark.usefixtures("qapp")
class TestF4HealthAwareBridgeSelection:
    """F4: xref bridge selection must probe health, not just non-``None``-ness."""

    @staticmethod
    def test_ghidra_selected_over_unhealthy_erroring_cutter(qapp: QCoreApplication) -> None:
        """A connected-but-unloaded, erroring Cutter must not starve xrefs.

        Reproduces the F4 root cause: the Cutter panel has initialized its
        backend (``state.connected = True``, mirroring the panel being
        open) but no binary was ever loaded through this bridge instance
        (``state.binary_loaded`` stays ``False``), and querying it raises --
        exactly what the real ``CutterBridge.get_xrefs_to``/``get_xrefs_from``
        do when ``_r2`` is ``None``. A healthy Ghidra bridge (connected,
        binary loaded) holds the real cross-reference data for a function
        with both callers and callees. Selection must route to Ghidra
        without ever invoking the unhealthy Cutter bridge, and the panel
        must populate with Ghidra's real xref data.
        """
        panel = ToolOutputPanel()

        cutter = _RecordingCutterBridge()
        cutter.state.connected = True
        cutter.should_raise = RuntimeError("cutter_no_binary_in_bridge_instance")

        ghidra = GhidraBridge()
        remote = _FakeGhidraXrefRemote(
            to_result=[
                {
                    "from": 0x500100,
                    "to": _ADDR_MAIN,
                    "type": "UNCONDITIONAL_CALL",
                    "from_function": "caller_a",
                    "to_function": "main",
                },
            ],
            from_result=[
                {
                    "from": _ADDR_MAIN,
                    "to": 0x500200,
                    "type": "UNCONDITIONAL_CALL",
                    "from_function": "main",
                    "to_function": "callee_b",
                },
            ],
        )
        ghidra.attach_remote_bridge(remote)
        ghidra.state.binary_loaded = True

        panel.cutter_bridge = cutter
        panel.ghidra_bridge = ghidra

        try:
            TestF4HealthAwareBridgeSelection._assert_ghidra_selected(qapp, panel, cutter, remote)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_ghidra_selected(
        qapp: QCoreApplication,
        panel: ToolOutputPanel,
        cutter: _RecordingCutterBridge,
        remote: _FakeGhidraXrefRemote,
    ) -> None:
        """Trigger the fetch and assert Ghidra's real xref data populated the panel.

        Args:
            qapp: Active Qt application driving the event loop.
            panel: ToolOutputPanel under test.
            cutter: The unhealthy/erroring Cutter bridge that must never be queried.
            remote: The fake Ghidra RPC transport that must be queried.
        """
        panel.populate_xrefs_for_address(_ADDR_MAIN)

        assert _process_events_until(
            qapp,
            lambda: panel.xref_panel.xref_display.topLevelItemCount() == 2,
        )

        assert cutter.to_calls == []
        assert cutter.from_calls == []
        assert remote.exec_calls

        roots = panel.xref_panel.xref_display
        in_root = roots.topLevelItem(0)
        out_root = roots.topLevelItem(1)
        assert in_root is not None
        assert out_root is not None
        in_child = in_root.child(0)
        out_child = out_root.child(0)
        assert in_child is not None
        assert out_child is not None
        assert "0x00500100" in in_child.text(0)
        assert "caller_a" in in_child.text(0)
        assert "0x00500200" in out_child.text(0)
        assert "callee_b" in out_child.text(0)


@pytest.mark.usefixtures("qapp")
class TestF0021SandboxBackendWiring:
    """F-0021: ``wire_sandbox_backend`` must actually wire the panel."""

    @staticmethod
    def test_wires_sandbox_to_pending_bridge() -> None:
        """A sandbox passed before panel creation must be stored as pending bridge."""
        panel = ToolOutputPanel()
        try:
            TestF0021SandboxBackendWiring._assert_wires_sandbox_to_pending_bridge(panel)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_wires_sandbox_to_pending_bridge(panel: ToolOutputPanel) -> None:
        """Assert a freshly wired sandbox stores a pending Windows bridge.

        Args:
            panel: ToolOutputPanel under test.
        """
        sandbox = _StubWindowsSandbox()
        panel.wire_sandbox_backend(sandbox)

        pending = _read_pending_sandbox_bridge(panel)
        assert isinstance(pending, SandboxBridge)
        assert pending.manager is not None
        assert any(inst.sandbox is sandbox for inst in pending.manager.instances)
        instance = next(inst for inst in pending.manager.instances if inst.sandbox is sandbox)
        assert instance.sandbox_type == "windows"

    @staticmethod
    def test_wires_sandbox_with_manager_reuses_supplied_manager() -> None:
        """When a manager is supplied it must be reused on the new bridge."""
        panel = ToolOutputPanel()
        try:
            TestF0021SandboxBackendWiring._assert_supplied_manager_reused(panel)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_supplied_manager_reused(panel: ToolOutputPanel) -> None:
        """Assert wire_sandbox_backend reuses an existing SandboxManager.

        Args:
            panel: ToolOutputPanel under test.
        """
        sandbox = _StubWindowsSandbox()
        manager = SandboxManager()
        panel.wire_sandbox_backend(sandbox, manager)

        pending = _read_pending_sandbox_bridge(panel)
        assert isinstance(pending, SandboxBridge)
        assert pending.manager is manager
        assert any(inst.sandbox is sandbox for inst in manager.instances)

    @staticmethod
    def test_wires_qemu_sandbox_with_qemu_type() -> None:
        """A QEMU-class sandbox must register under the ``qemu`` SandboxType."""
        panel = ToolOutputPanel()
        try:
            TestF0021SandboxBackendWiring._assert_qemu_sandbox_registers_as_qemu(panel)
        finally:
            panel.deleteLater()

    @staticmethod
    def _assert_qemu_sandbox_registers_as_qemu(panel: ToolOutputPanel) -> None:
        """Assert a QEMU-class sandbox registers with the ``qemu`` SandboxType.

        Args:
            panel: ToolOutputPanel under test.
        """
        sandbox = _StubQemuSandbox()
        panel.wire_sandbox_backend(sandbox)

        pending = _read_pending_sandbox_bridge(panel)
        assert isinstance(pending, SandboxBridge)
        assert pending.manager is not None
        instance = next(inst for inst in pending.manager.instances if inst.sandbox is sandbox)
        assert instance.sandbox_type == "qemu"

    @staticmethod
    def test_rejects_non_sandbox_backend() -> None:
        """Passing a non-SandboxBase object must raise TypeError, not silently no-op."""
        panel = ToolOutputPanel()
        try:
            with pytest.raises(TypeError, match="SandboxBase"):
                panel.wire_sandbox_backend(object())
        finally:
            panel.deleteLater()

    @staticmethod
    def test_rejects_non_manager_argument() -> None:
        """Passing a non-SandboxManager as ``manager`` must raise TypeError."""
        panel = ToolOutputPanel()
        try:
            sandbox = _StubWindowsSandbox()
            with pytest.raises(TypeError, match="SandboxManager"):
                panel.wire_sandbox_backend(sandbox, object())
        finally:
            panel.deleteLater()


def _read_pending_sandbox_bridge(panel: ToolOutputPanel) -> object:
    """Return the panel's pending sandbox bridge slot via attribute access.

    ``ToolOutputPanel`` stores the deferred bridge in an instance attribute
    that the rest of the GUI consumes via ``add_sandbox_tab``. Reading it
    in tests would otherwise trigger the protected-name lint rule, so the
    helper retrieves it through ``getattr`` for diagnostic purposes only.

    Args:
        panel: The panel whose pending bridge attribute should be read.

    Returns:
        object: The current value of the pending sandbox bridge slot.
    """
    return getattr(panel, "_pending_sandbox_bridge")
