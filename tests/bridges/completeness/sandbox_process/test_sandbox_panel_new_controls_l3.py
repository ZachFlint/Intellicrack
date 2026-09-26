# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for SANDBOX panel controls (L3).

Covers the six newly-wired ``SandboxPanel`` controls in
``src/intellicrack/ui/panels/sandbox_panel.py``:

* ``_on_refresh_instances`` -> ``SandboxBridge.list`` (no args) and the
  success callback populating ``_instances_tree``.
* ``_on_refresh_snapshots`` -> ``SandboxBridge.snapshot_list(instance_id)``.
* ``_on_pending_messages`` -> ``SandboxBridge.get_pending_messages(instance_id)``.
* ``_on_anti_evasion`` -> ``SandboxBridge.anti_evasion(instance_id, profile=...)``.
* ``_on_detect_c2`` -> ``SandboxBridge.detect_c2(instance_id)``.
* ``_on_diff`` -> ``SandboxBridge.diff(instance_id_a, instance_id_b)``.

Every test wires a real ``SandboxBridge`` into the panel and replaces
``run_bridge_coroutine_logged`` in the panel module under test (not the
bridge) with a recording shim. The shim introspects the real coroutine it
receives -- code object, bound ``self`` and bound arguments -- and closes it
before any bridge body runs, so each gate asserts the handler created its
coroutine from the exact ``SandboxBridge`` method, on the wired bridge, with
the expected arguments -- a genuine gate on the handler's wiring logic. The
bridge bodies have their own dedicated bridge-completeness gates driving the
real backend.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QApplication, QLineEdit, QTreeWidget

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.ui.panels import sandbox_panel as _sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterator
    from types import CodeType

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication.

    Qt requires exactly one QApplication per process.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def sandbox_panel(qapp: QApplication) -> SandboxPanel:
    """Create a SandboxPanel instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        SandboxPanel: A fresh SandboxPanel widget.
    """
    assert isinstance(qapp, QApplication)
    return SandboxPanel()


def _set_private(widget: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute of a widget under test.

    Used to wire collaborators (e.g. a real bridge) into private collaborator
    slots without a direct private-attribute assignment expression that would
    fight the widget's declared attribute type.

    Args:
        widget: Widget instance to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(widget, attr_name, value)


def _get_private(widget: object, attr_name: str) -> object:
    """Read a named private attribute of a widget under test.

    Args:
        widget: Widget instance to read from.
        attr_name: Attribute name to read.

    Returns:
        object: The current value of the attribute.
    """
    return getattr(widget, attr_name)


def _invoke(widget: object, method_name: str) -> None:
    """Invoke a named zero-argument handler method on a widget.

    Args:
        widget: Widget whose handler is invoked.
        method_name: Name of the handler method to call.
    """
    handler = getattr(widget, method_name)
    assert callable(handler), f"{type(widget).__name__}.{method_name} must be callable"
    handler()


@dataclass(frozen=True, slots=True)
class _DispatchedBridgeCall:
    """One ``run_bridge_coroutine_logged`` invocation captured before dispatch.

    The real bridge coroutine is introspected (its code object, bound ``self``
    and bound arguments) and then closed, so no bridge body ever runs and no
    "coroutine was never awaited" warning is emitted.

    Attributes:
        coroutine: The exact coroutine object handed to the dispatcher.
        code: Code object the coroutine executes; identifies the bridge method.
        bound_self: The ``self`` the bridge method was bound to.
        arguments: The bridge method's bound arguments, excluding ``self``.
        dispatch_kwargs: Keyword arguments passed to the dispatcher itself
            (``on_success``, ``on_error``, ``event``, ...).
    """

    coroutine: Coroutine[object, object, object]
    code: CodeType
    bound_self: object
    arguments: dict[str, object]
    dispatch_kwargs: dict[str, object]


def _intercept_dispatch(monkeypatch: pytest.MonkeyPatch, module: object) -> list[_DispatchedBridgeCall]:
    """Replace ``run_bridge_coroutine_logged`` in ``module`` with a recording shim.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        module: The module whose dispatcher symbol is replaced.

    Returns:
        list[_DispatchedBridgeCall]: Live list receiving one entry per dispatch.
    """
    captured: list[_DispatchedBridgeCall] = []

    def _record(coro: object, *args: object, **kwargs: object) -> None:
        del args
        assert inspect.iscoroutine(coro), f"dispatcher must receive a real bridge coroutine; got {coro!r}"
        frame_locals = dict(inspect.getcoroutinelocals(coro))
        bound_self = frame_locals.pop("self", None)
        captured.append(
            _DispatchedBridgeCall(
                coroutine=coro,
                code=coro.cr_code,
                bound_self=bound_self,
                arguments=frame_locals,
                dispatch_kwargs=dict(kwargs),
            ),
        )
        coro.close()

    monkeypatch.setattr(module, "run_bridge_coroutine_logged", _record)
    return captured


def _assert_bridge_call(
    call: _DispatchedBridgeCall,
    bridge: object,
    method_name: str,
    expected_arguments: dict[str, object],
) -> None:
    """Assert a dispatched coroutine came from ``bridge.<method_name>`` with the expected arguments.

    Args:
        call: The captured dispatch.
        bridge: The real bridge instance wired into the widget under test.
        method_name: Name of the bridge coroutine method that must have produced the coroutine.
        expected_arguments: Every bound argument of that method (defaults included), excluding ``self``.
    """
    method: object = getattr(type(bridge), method_name)
    assert inspect.isfunction(method), f"{type(bridge).__name__}.{method_name} must be a plain coroutine function"
    assert call.code is method.__code__, (
        f"dispatched coroutine must come from {type(bridge).__name__}.{method_name}; got {call.code.co_qualname}"
    )
    assert call.bound_self is bridge, "dispatched coroutine must be bound to the bridge wired into the widget"
    assert call.arguments == expected_arguments, (
        f"{method_name} bound arguments mismatch: expected {expected_arguments!r}, got {call.arguments!r}"
    )


class TestSandboxPanelRefreshInstancesWiringL3:
    """SandboxBridge.list: the Refresh Instances button dispatches list() and renders the result."""

    def test_on_refresh_instances_dispatches_real_bridge_list_with_no_args(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_refresh_instances dispatches the coroutine from bridge.list() with no arguments.

        Falsified by: removing/rewiring the ``self._bridge.list()`` call in
        ``_on_refresh_instances`` turns this red, since the captured coroutine
        would no longer come from ``SandboxBridge.list`` or would no longer be
        bound with no args.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_refresh_instances")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when a bridge is configured"
        _assert_bridge_call(dispatch_args[0], bridge, "list", {})

    def test_on_refresh_instances_no_dispatch_without_bridge(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_refresh_instances skips dispatch when no bridge is configured.

        Falsified by: removing the ``self._bridge is None`` guard would let a
        dispatch occur, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", None)

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_refresh_instances")

        assert not dispatch_calls, "list must not be dispatched without a configured bridge"

    def test_success_callback_populates_instances_tree(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The success callback renders each instance dict as a tree row keyed by instance_id.

        Falsified by: breaking ``_populate_instances_tree``'s column mapping
        (or the ``on_success`` wiring) would change the rendered rows,
        turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_refresh_instances")

        captured_on_success = [call.dispatch_kwargs["on_success"] for call in dispatch_args]
        assert captured_on_success, "expected an on_success callback to be captured"
        success_cb = captured_on_success[0]
        assert callable(success_cb)
        success_cb(
            [
                {
                    "instance_id": "sbx-1",
                    "type": "qemu",
                    "status": "running",
                    "created_at": "2026-07-01T00:00:00",
                    "last_used": "2026-07-01T01:00:00",
                    "binary": "sample.exe",
                },
                {
                    "instance_id": "sbx-2",
                    "type": "docker",
                    "status": "stopped",
                    "created_at": "2026-07-01T02:00:00",
                    "last_used": "2026-07-01T03:00:00",
                    "binary": "payload.dll",
                },
            ],
        )

        tree = cast("QTreeWidget", _get_private(sandbox_panel, "_instances_tree"))
        assert tree.topLevelItemCount() == 2
        row0 = tree.topLevelItem(0)
        row1 = tree.topLevelItem(1)
        assert row0 is not None
        assert row1 is not None
        assert [row0.text(col) for col in range(6)] == [
            "sbx-1",
            "qemu",
            "running",
            "2026-07-01T00:00:00",
            "2026-07-01T01:00:00",
            "sample.exe",
        ]
        assert [row1.text(col) for col in range(6)] == [
            "sbx-2",
            "docker",
            "stopped",
            "2026-07-01T02:00:00",
            "2026-07-01T03:00:00",
            "payload.dll",
        ]


class TestSandboxPanelRefreshSnapshotsWiringL3:
    """SandboxBridge.snapshot_list: the Refresh Snapshots button dispatches snapshot_list(instance_id)."""

    def test_on_refresh_snapshots_dispatches_with_active_instance_id(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_refresh_snapshots dispatches bridge.snapshot_list with the active instance id.

        Falsified by: rewiring ``_on_refresh_snapshots`` away from
        ``self._bridge.snapshot_list(self.sandbox_id)`` turns this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)
        sandbox_panel.sandbox_id = "sbx-active"

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_refresh_snapshots")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with an active instance"
        _assert_bridge_call(dispatch_args[0], bridge, "snapshot_list", {"instance_id": "sbx-active"})

    def test_on_refresh_snapshots_no_dispatch_without_active_instance(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_refresh_snapshots skips dispatch when there is no active instance.

        Falsified by: removing the ``self.sandbox_id is None`` guard would let
        a dispatch occur with a ``None`` instance id, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", SandboxBridge())
        sandbox_panel.sandbox_id = None

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_refresh_snapshots")

        assert not dispatch_calls, "snapshot_list must not be dispatched without an active instance"


class TestSandboxPanelPendingMessagesWiringL3:
    """SandboxBridge.get_pending_messages: the Pending Messages button dispatches with the instance id."""

    def test_on_pending_messages_dispatches_with_active_instance_id(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pending_messages dispatches bridge.get_pending_messages with the active instance id.

        Falsified by: rewiring ``_on_pending_messages`` away from
        ``self._bridge.get_pending_messages(self.sandbox_id)`` turns this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)
        sandbox_panel.sandbox_id = "sbx-msg"

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_pending_messages")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with an active instance"
        _assert_bridge_call(dispatch_args[0], bridge, "get_pending_messages", {"instance_id": "sbx-msg"})

    def test_on_pending_messages_no_dispatch_without_active_instance(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pending_messages skips dispatch when there is no active instance.

        Falsified by: removing the ``self.sandbox_id is None`` guard would let
        a dispatch occur, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", SandboxBridge())
        sandbox_panel.sandbox_id = None

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_pending_messages")

        assert not dispatch_calls, "get_pending_messages must not be dispatched without an active instance"


class TestSandboxPanelAntiEvasionWiringL3:
    """SandboxBridge.anti_evasion: the Apply Anti-Evasion button dispatches with instance id and profile."""

    def test_on_anti_evasion_dispatches_with_entered_profile(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_anti_evasion dispatches bridge.anti_evasion with the instance id and entered profile.

        Falsified by: rewiring ``_on_anti_evasion`` away from
        ``self._bridge.anti_evasion(self.sandbox_id, profile=profile)`` or
        reading the profile from the wrong widget turns this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)
        sandbox_panel.sandbox_id = "sbx-evasion"

        profile_input = cast("QLineEdit", _get_private(sandbox_panel, "_anti_evasion_profile_input"))
        profile_input.setText("aggressive")

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with an active instance"
        _assert_bridge_call(dispatch_args[0], bridge, "anti_evasion", {"instance_id": "sbx-evasion", "profile": "aggressive"})

    def test_on_anti_evasion_defaults_profile_when_blank(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_anti_evasion falls back to the "default" profile when the input is blank.

        Falsified by: removing the ``or "default"`` fallback would pass an
        empty profile string, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)
        sandbox_panel.sandbox_id = "sbx-evasion"

        profile_input = cast("QLineEdit", _get_private(sandbox_panel, "_anti_evasion_profile_input"))
        profile_input.setText("   ")

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with an active instance"
        _assert_bridge_call(dispatch_args[0], bridge, "anti_evasion", {"instance_id": "sbx-evasion", "profile": "default"})

    def test_on_anti_evasion_no_dispatch_without_active_instance(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_anti_evasion skips dispatch when there is no active instance.

        Falsified by: removing the ``self.sandbox_id is None`` guard would let
        a dispatch occur, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", SandboxBridge())
        sandbox_panel.sandbox_id = None

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert not dispatch_calls, "anti_evasion must not be dispatched without an active instance"


class TestSandboxPanelDetectC2WiringL3:
    """SandboxBridge.detect_c2: the Detect C2 button dispatches with the instance id."""

    def test_on_detect_c2_dispatches_with_active_instance_id(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_detect_c2 dispatches bridge.detect_c2 with the active instance id.

        Falsified by: rewiring ``_on_detect_c2`` away from
        ``self._bridge.detect_c2(self.sandbox_id)`` turns this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)
        sandbox_panel.sandbox_id = "sbx-c2"

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_detect_c2")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with an active instance"
        _assert_bridge_call(dispatch_args[0], bridge, "detect_c2", {"instance_id": "sbx-c2"})

    def test_on_detect_c2_no_dispatch_without_active_instance(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_detect_c2 skips dispatch when there is no active instance.

        Falsified by: removing the ``self.sandbox_id is None`` guard would let
        a dispatch occur, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", SandboxBridge())
        sandbox_panel.sandbox_id = None

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_detect_c2")

        assert not dispatch_calls, "detect_c2 must not be dispatched without an active instance"


class TestSandboxPanelDiffWiringL3:
    """SandboxBridge.diff: the Compare button dispatches with both entered instance ids."""

    def test_on_diff_dispatches_with_both_entered_instance_ids(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_diff dispatches bridge.diff with the two instance ids parsed from the inputs.

        Falsified by: rewiring ``_on_diff`` away from
        ``self._bridge.diff(instance_a, instance_b)`` or reading the ids from
        the wrong widgets turns this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = SandboxBridge()
        _set_private(sandbox_panel, "_bridge", bridge)

        input_a = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_a_input"))
        input_b = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_b_input"))
        input_a.setText("sbx-A")
        input_b.setText("sbx-B")

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_diff")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when both instance ids are provided"
        _assert_bridge_call(dispatch_args[0], bridge, "diff", {"instance_id_a": "sbx-A", "instance_id_b": "sbx-B"})

    def test_on_diff_no_dispatch_when_second_instance_missing(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_diff skips dispatch when the second instance id is blank.

        Falsified by: removing the ``not instance_a or not instance_b`` guard
        would let a dispatch occur with an empty second id, turning this red.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(sandbox_panel, "_bridge", SandboxBridge())
        sandbox_panel.sandbox_id = None

        input_a = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_a_input"))
        input_b = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_b_input"))
        input_a.setText("sbx-A")
        input_b.setText("")

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(sandbox_panel, "_on_diff")

        assert not dispatch_calls, "diff must not be dispatched when the second instance id is missing"
