# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D10b: Memory Dump on Windows Sandbox must use a live process picker.

``SandboxPanel._on_memory_dump`` used to call
``SandboxBridge.memory_dump(self.sandbox_id)`` unconditionally - with no
``target_pid`` - for every backend. ``SandboxBridge.memory_dump`` requires a
positive ``target_pid`` for any Windows Sandbox instance (audit7 F-0021), so
the control could never succeed from the GUI on that backend: every click
failed the bridge-side guard before a single guest command was dispatched.

The fix threads a :class:`~intellicrack.ui.guest_process_picker.GuestProcessPickerDialog`
into the Windows path: the handler first calls the new
``SandboxBridge.list_guest_processes`` bridge method, then opens the picker
with the enumerated processes, and only dispatches ``memory_dump`` with the
PID the user chose. The QEMU path is untouched - it still dispatches
``memory_dump`` directly with no PID, exactly as before this fix.

Each test patches ``run_bridge_coroutine_logged`` in the ``sandbox_panel``
module (not the bridge) and asserts the coroutine handed to it is the exact
coroutine object the mocked bridge method returned, called with the exact
arguments the handler under test computed - a genuine gate on the handler's
wiring logic, matching the convention in
``tests/bridges/completeness/sandbox_process/test_sandbox_panel_l3.py``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QDialog

from intellicrack.ui.panels import sandbox_panel as _sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Sequence

    from PyQt6.QtWidgets import QApplication, QWidget

    from intellicrack.ui.guest_process_picker import GuestProcessRow

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_INSTANCE_ID = "windows-instance-under-test"


class _FakeGuestProcessPickerDialog:
    """Stand-in for ``GuestProcessPickerDialog`` that never blocks on ``exec()``.

    Records the ``processes`` it was constructed with and returns a canned
    ``exec()`` result / ``selected_pid()`` value configured by the test, so
    tests can drive the accept and cancel paths deterministically without a
    real modal event loop.
    """

    last_instance: _FakeGuestProcessPickerDialog | None = None

    def __init__(self, processes: Sequence[GuestProcessRow], parent: QWidget | None = None) -> None:
        """Record the constructor arguments and register as the last instance.

        Args:
            processes: Process rows passed by the production handler.
            parent: Parent widget passed by the production handler.
        """
        self.processes: list[GuestProcessRow] = list(processes)
        self.parent = parent
        self.exec_result: int = int(QDialog.DialogCode.Rejected.value)
        self.pid: int | None = None
        _FakeGuestProcessPickerDialog.last_instance = self

    def exec(self) -> int:
        """Return the canned dialog result instead of blocking on a real modal.

        Returns:
            int: The configured ``QDialog.DialogCode`` value.
        """
        return self.exec_result

    def selected_pid(self) -> int | None:
        """Return the canned selection.

        Returns:
            int | None: The configured selected PID.
        """
        return self.pid


def _set_private(widget: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute of a widget under test.

    Args:
        widget: Widget instance to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(widget, attr_name, value)


@pytest.fixture
def panel(qapp: QApplication) -> SandboxPanel:
    """Create a ``SandboxPanel`` wired to a live, mocked instance id.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        SandboxPanel: A fresh panel with ``sandbox_id`` set and its
        sandbox-active controls (including Memory Dump) enabled.
    """
    assert qapp is not None
    p = SandboxPanel()
    p.sandbox_id = _INSTANCE_ID
    p._set_sandbox_controls_active(active=True)
    return p


def _capture_dispatch(calls: list[tuple[tuple[object, ...], dict[str, object]]]) -> object:
    """Build a ``run_bridge_coroutine_logged`` stand-in that records every call.

    Args:
        calls: List the stand-in appends ``(args, kwargs)`` onto.

    Returns:
        object: A callable usable as a monkeypatched replacement.
    """

    def _fake(*args: object, **kwargs: object) -> None:
        """Record the call instead of dispatching to a real bridge worker.

        Args:
            *args: Positional arguments the production code passed.
            **kwargs: Keyword arguments the production code passed.
        """
        calls.append((args, kwargs))

    return _fake


class TestNonWindowsMemoryDumpUnchanged:
    """QEMU (non-Windows) Memory Dump must keep dispatching directly, with no PID."""

    def test_qemu_dispatches_memory_dump_with_no_target_pid(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Memory Dump on QEMU calls ``bridge.memory_dump(instance_id)`` directly.

        Falsified by: routing the QEMU path through the picker too (e.g.
        removing the ``_effective_sandbox_type() == "windows"`` branch) would
        make ``mock_bridge.list_guest_processes`` get called, failing the
        ``assert_not_called()`` below.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        panel.sandbox_type_combo.setCurrentText("QEMU")
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))

        panel._on_memory_dump()

        mock_bridge.list_guest_processes.assert_not_called()
        mock_bridge.memory_dump.assert_called_once_with(_INSTANCE_ID)
        assert calls, "run_bridge_coroutine_logged must have been called"
        assert calls[0][0][0] is mock_bridge.memory_dump.return_value, (
            "the dispatched coroutine must be the exact object bridge.memory_dump() returned"
        )


class TestWindowsMemoryDumpUsesPicker:
    """Windows Sandbox Memory Dump must enumerate guest processes before dumping."""

    def test_windows_lists_guest_processes_instead_of_dumping_directly(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Memory Dump on Windows Sandbox calls ``list_guest_processes`` first.

        Falsified by: reverting to the pre-fix ``_on_memory_dump`` (a bare
        ``self._bridge.memory_dump(self.sandbox_id)`` for every backend) would
        make ``mock_bridge.list_guest_processes`` never get called, failing
        the ``assert_called_once_with`` below, and would call
        ``mock_bridge.memory_dump`` with no ``target_pid`` instead.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        panel.sandbox_type_combo.setCurrentText("Windows Sandbox")
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))

        panel._on_memory_dump()

        mock_bridge.list_guest_processes.assert_called_once_with(_INSTANCE_ID)
        mock_bridge.memory_dump.assert_not_called()
        assert calls, "run_bridge_coroutine_logged must have been called"
        assert calls[0][0][0] is mock_bridge.list_guest_processes.return_value, (
            "the dispatched coroutine must be the exact object bridge.list_guest_processes() returned"
        )

    def test_picker_selection_dispatches_memory_dump_with_the_chosen_pid(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Accepting the picker with a PID dispatches ``memory_dump(instance_id, target_pid=pid)``.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))
        monkeypatch.setattr(_sandbox_panel_mod, "GuestProcessPickerDialog", _FakeGuestProcessPickerDialog)

        chosen_pid = 4242
        bridge_result = {
            "instance_id": _INSTANCE_ID,
            "processes": [
                {"pid": chosen_pid, "name": "notepad.exe", "path": r"C:\Windows\notepad.exe"},
                {"pid": 999, "name": "svchost.exe", "path": r"C:\Windows\svchost.exe"},
            ],
        }

        def _configure_and_open(result: object) -> None:
            """Wrap the production success handler to configure the fake dialog first.

            The fake dialog class is only instantiated *inside* the production
            handler, so its selection is configured via a small monkeypatched
            constructor wrapper rather than after the fact.

            Args:
                result: Bridge result payload forwarded to the production handler.
            """

            def _factory(processes: Sequence[GuestProcessRow], parent: QWidget | None = None) -> _FakeGuestProcessPickerDialog:
                """Build a fake dialog pre-configured to accept ``chosen_pid``.

                Args:
                    processes: Process rows passed by the production handler.
                    parent: Parent widget passed by the production handler.

                Returns:
                    _FakeGuestProcessPickerDialog: Configured fake dialog.
                """
                dialog = _FakeGuestProcessPickerDialog(processes, parent)
                dialog.exec_result = int(QDialog.DialogCode.Accepted.value)
                dialog.pid = chosen_pid
                return dialog

            monkeypatch.setattr(_sandbox_panel_mod, "GuestProcessPickerDialog", _factory)
            panel._on_list_guest_processes_for_dump_success(result)

        _configure_and_open(bridge_result)

        assert _FakeGuestProcessPickerDialog.last_instance is not None, "the picker dialog must have been constructed"
        assert [row["pid"] for row in _FakeGuestProcessPickerDialog.last_instance.processes] == [chosen_pid, 999], (
            "the picker must be given the exact process rows the bridge reported"
        )
        mock_bridge.memory_dump.assert_called_once_with(_INSTANCE_ID, target_pid=chosen_pid)
        assert calls, "run_bridge_coroutine_logged must have been called for the dump dispatch"
        assert calls[-1][0][0] is mock_bridge.memory_dump.return_value

    def test_cancelling_the_picker_does_not_dispatch_a_dump(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Rejecting the picker must not call ``bridge.memory_dump`` at all.

        Falsified by: dispatching the dump unconditionally after opening the
        picker (ignoring the ``exec()`` result) would make
        ``mock_bridge.memory_dump.assert_not_called()`` fail.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))
        monkeypatch.setattr(_sandbox_panel_mod, "GuestProcessPickerDialog", _FakeGuestProcessPickerDialog)

        bridge_result = {
            "instance_id": _INSTANCE_ID,
            "processes": [{"pid": 111, "name": "a.exe", "path": ""}],
        }
        panel._on_list_guest_processes_for_dump_success(bridge_result)

        assert _FakeGuestProcessPickerDialog.last_instance is not None
        assert _FakeGuestProcessPickerDialog.last_instance.exec_result == int(QDialog.DialogCode.Rejected.value), (
            "test premise: the fake dialog must default to Rejected"
        )
        mock_bridge.memory_dump.assert_not_called()
        assert not calls, "no dump coroutine may be dispatched when the picker was cancelled"
        assert panel.memdump_btn.isEnabled(), "the control must be restored after a cancelled picker"

    def test_accepted_picker_with_no_selection_does_not_dispatch_a_dump(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An accepted dialog with ``selected_pid() is None`` must not dispatch a dump.

        Guards the defensive branch in ``_on_list_guest_processes_for_dump_success``
        against a dialog implementation that could accept without a selection.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))

        def _factory(processes: Sequence[GuestProcessRow], parent: QWidget | None = None) -> _FakeGuestProcessPickerDialog:
            """Build a fake dialog that accepts without a selection.

            Args:
                processes: Process rows passed by the production handler.
                parent: Parent widget passed by the production handler.

            Returns:
                _FakeGuestProcessPickerDialog: Configured fake dialog.
            """
            dialog = _FakeGuestProcessPickerDialog(processes, parent)
            dialog.exec_result = int(QDialog.DialogCode.Accepted.value)
            dialog.pid = None
            return dialog

        monkeypatch.setattr(_sandbox_panel_mod, "GuestProcessPickerDialog", _factory)

        bridge_result = {"instance_id": _INSTANCE_ID, "processes": [{"pid": 111, "name": "a.exe", "path": ""}]}
        panel._on_list_guest_processes_for_dump_success(bridge_result)

        mock_bridge.memory_dump.assert_not_called()
        assert not calls


class TestEmptyGuestProcessList:
    """An empty guest process list must surface clear feedback and not open the picker."""

    def test_empty_process_list_does_not_open_the_picker_or_dispatch_a_dump(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bridge result with zero processes must skip the dialog and dump dispatch entirely.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))
        monkeypatch.setattr(_sandbox_panel_mod, "show_info", lambda *_args, **_kwargs: None)

        opened: list[object] = []
        monkeypatch.setattr(
            _sandbox_panel_mod,
            "GuestProcessPickerDialog",
            lambda processes, parent=None: opened.append(processes) or _FakeGuestProcessPickerDialog(processes, parent),
        )

        bridge_result = {"instance_id": _INSTANCE_ID, "processes": []}
        panel._on_list_guest_processes_for_dump_success(bridge_result)

        assert not opened, "the picker dialog must not be constructed for an empty process list"
        mock_bridge.memory_dump.assert_not_called()
        assert not calls
        assert panel.memdump_btn.isEnabled(), "the control must be restored after an empty process list"

    def test_malformed_processes_payload_is_treated_as_empty(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A non-list, non-dict, or malformed-row bridge payload never crashes and dispatches nothing.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch(calls))
        monkeypatch.setattr(_sandbox_panel_mod, "show_info", lambda *_args, **_kwargs: None)

        for bad_result in (
            None,
            "not a dict",
            {"instance_id": _INSTANCE_ID},
            {"instance_id": _INSTANCE_ID, "processes": "not a list"},
            {"instance_id": _INSTANCE_ID, "processes": [{"name": "no_pid.exe"}]},
            {"instance_id": _INSTANCE_ID, "processes": [{"pid": -1, "name": "bad.exe"}]},
            {"instance_id": _INSTANCE_ID, "processes": ["not a dict either"]},
        ):
            panel._on_list_guest_processes_for_dump_success(bad_result)

        mock_bridge.memory_dump.assert_not_called()
        assert not calls


class TestGuestProcessListingFailure:
    """A failed guest process enumeration must surface an error, not silently do nothing."""

    def test_enumeration_failure_reports_error_and_restores_control(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_list_guest_processes_for_dump_error`` must log and re-enable Memory Dump.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        reported: list[tuple[str, str, object]] = []

        def _fake_report_failure(title: str, summary: str, exc: object) -> None:
            """Record the failure report instead of opening a real modal dialog.

            Args:
                title: Dialog window title.
                summary: Human-readable summary text.
                exc: The exception object reported.
            """
            reported.append((title, summary, exc))

        monkeypatch.setattr(panel, "_report_failure", _fake_report_failure)

        panel.memdump_btn.setEnabled(False)
        error = RuntimeError("guest process listing failed")
        panel._on_list_guest_processes_for_dump_error(error)

        assert reported == [("Memory Dump Failed", "Failed to enumerate guest processes", error)]
        assert panel.memdump_btn.isEnabled(), "the control must be restored after an enumeration failure"


class TestGuestProcessRowParsing:
    """Unit coverage for ``SandboxPanel._parse_guest_process_rows``."""

    def test_parses_well_formed_rows(self) -> None:
        """A well-formed bridge payload parses into matching rows."""
        result = {
            "instance_id": _INSTANCE_ID,
            "processes": [
                {"pid": 10, "name": "a.exe", "path": r"C:\a.exe"},
                {"pid": 20, "name": "b.exe", "path": None},
            ],
        }
        rows = SandboxPanel._parse_guest_process_rows(result)
        assert rows == [
            {"pid": 10, "name": "a.exe", "path": r"C:\a.exe"},
            {"pid": 20, "name": "b.exe", "path": ""},
        ]

    def test_drops_malformed_rows_but_keeps_valid_ones(self) -> None:
        """A mix of malformed and well-formed rows keeps only the well-formed ones."""
        result = {
            "processes": [
                {"pid": 0, "name": "zero_pid.exe", "path": ""},
                {"pid": -5, "name": "negative_pid.exe", "path": ""},
                {"name": "missing_pid.exe", "path": ""},
                "not a dict",
                {"pid": 30, "name": "valid.exe", "path": r"C:\valid.exe"},
            ],
        }
        rows = SandboxPanel._parse_guest_process_rows(result)
        assert rows == [{"pid": 30, "name": "valid.exe", "path": r"C:\valid.exe"}]

    def test_non_dict_result_yields_empty_list(self) -> None:
        """A non-dict bridge result yields an empty row list rather than raising."""
        assert SandboxPanel._parse_guest_process_rows(cast("object", ["not", "a", "dict"])) == []
