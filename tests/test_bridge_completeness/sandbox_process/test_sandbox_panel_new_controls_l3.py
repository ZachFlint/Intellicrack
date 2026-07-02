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

Every test patches ``run_bridge_coroutine_logged`` in the panel module under
test (not the bridge) and asserts the coroutine handed to it is the exact
coroutine object returned by the real bridge-method mock, with the expected
call arguments -- this is a genuine gate on the handler's wiring logic. The
``SandboxBridge`` itself is replaced with a ``MagicMock`` only because the
production code under test here is the *handler*, not the bridge (which has
its own dedicated bridge-completeness gates driving the real backend).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication, QLineEdit, QTreeWidget

from intellicrack.ui.panels import sandbox_panel as _sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Iterator

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

    Used to wire test doubles (e.g. a mock bridge) into private collaborator
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
        would no longer be ``mock_bridge.list.return_value`` or ``list`` would
        no longer be called with no args.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_refresh_instances")

        assert dispatch_args, "run_bridge_coroutine_logged must be called when a bridge is configured"
        assert dispatch_args[0][0] is mock_bridge.list.return_value, (
            f"first positional arg must be the coroutine from bridge.list; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.list.assert_called_once_with()

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

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_refresh_instances")

        assert dispatch_calls == [], "list must not be dispatched without a configured bridge"

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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)

        captured_on_success: list[object] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del args
            captured_on_success.append(kwargs["on_success"])

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_refresh_instances")

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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)
        sandbox_panel.sandbox_id = "sbx-active"

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_refresh_snapshots")

        assert dispatch_args, "run_bridge_coroutine_logged must be called with an active instance"
        assert dispatch_args[0][0] is mock_bridge.snapshot_list.return_value, (
            f"first positional arg must be the coroutine from bridge.snapshot_list; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.snapshot_list.assert_called_once_with("sbx-active")

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
        _set_private(sandbox_panel, "_bridge", MagicMock())
        sandbox_panel.sandbox_id = None

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_refresh_snapshots")

        assert dispatch_calls == [], "snapshot_list must not be dispatched without an active instance"


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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)
        sandbox_panel.sandbox_id = "sbx-msg"

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_pending_messages")

        assert dispatch_args, "run_bridge_coroutine_logged must be called with an active instance"
        assert dispatch_args[0][0] is mock_bridge.get_pending_messages.return_value, (
            f"first positional arg must be the coroutine from bridge.get_pending_messages; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.get_pending_messages.assert_called_once_with("sbx-msg")

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
        _set_private(sandbox_panel, "_bridge", MagicMock())
        sandbox_panel.sandbox_id = None

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_pending_messages")

        assert dispatch_calls == [], "get_pending_messages must not be dispatched without an active instance"


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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)
        sandbox_panel.sandbox_id = "sbx-evasion"

        profile_input = cast("QLineEdit", _get_private(sandbox_panel, "_anti_evasion_profile_input"))
        profile_input.setText("aggressive")

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert dispatch_args, "run_bridge_coroutine_logged must be called with an active instance"
        assert dispatch_args[0][0] is mock_bridge.anti_evasion.return_value, (
            f"first positional arg must be the coroutine from bridge.anti_evasion; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.anti_evasion.assert_called_once_with("sbx-evasion", profile="aggressive")

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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)
        sandbox_panel.sandbox_id = "sbx-evasion"

        profile_input = cast("QLineEdit", _get_private(sandbox_panel, "_anti_evasion_profile_input"))
        profile_input.setText("   ")

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert dispatch_args, "run_bridge_coroutine_logged must be called with an active instance"
        mock_bridge.anti_evasion.assert_called_once_with("sbx-evasion", profile="default")

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
        _set_private(sandbox_panel, "_bridge", MagicMock())
        sandbox_panel.sandbox_id = None

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_anti_evasion")

        assert dispatch_calls == [], "anti_evasion must not be dispatched without an active instance"


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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)
        sandbox_panel.sandbox_id = "sbx-c2"

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_detect_c2")

        assert dispatch_args, "run_bridge_coroutine_logged must be called with an active instance"
        assert dispatch_args[0][0] is mock_bridge.detect_c2.return_value, (
            f"first positional arg must be the coroutine from bridge.detect_c2; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.detect_c2.assert_called_once_with("sbx-c2")

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
        _set_private(sandbox_panel, "_bridge", MagicMock())
        sandbox_panel.sandbox_id = None

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_detect_c2")

        assert dispatch_calls == [], "detect_c2 must not be dispatched without an active instance"


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
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)

        input_a = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_a_input"))
        input_b = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_b_input"))
        input_a.setText("sbx-A")
        input_b.setText("sbx-B")

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(sandbox_panel, "_on_diff")

        assert dispatch_args, "run_bridge_coroutine_logged must be called when both instance ids are provided"
        assert dispatch_args[0][0] is mock_bridge.diff.return_value, (
            f"first positional arg must be the coroutine from bridge.diff; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.diff.assert_called_once_with("sbx-A", "sbx-B")

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
        _set_private(sandbox_panel, "_bridge", MagicMock())
        sandbox_panel.sandbox_id = None

        input_a = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_a_input"))
        input_b = cast("QLineEdit", _get_private(sandbox_panel, "_diff_instance_b_input"))
        input_a.setText("sbx-A")
        input_b.setText("")

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(sandbox_panel, "_on_diff")

        assert dispatch_calls == [], "diff must not be dispatched when the second instance id is missing"
