# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for SystemTab audit7 findings F-0022 and F-0023.

Validates the user-visible behaviour introduced when:

* No process is attached and the operator clicks Query Mitigations, GUI
  Resources, or Job Info — F-0022 ensures the action surfaces a
  ``QMessageBox.warning`` rather than silently failing.
* The bridge call raises an error — F-0023 ensures the error path shows a
  ``QMessageBox.warning`` with action-specific text rather than only logging.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.ui.panels.process_panel.system_tab import SystemTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from intellicrack.bridges.process import ProcessBridge


_BRIDGE_MODULE_PATH: str = "intellicrack.ui.panels.process_panel.system_tab.run_bridge_coroutine_async"


class _AsyncSuccess:
    """Awaitable bridge method stub that resolves to a fixed value."""

    def __init__(self, value: object) -> None:
        """Initialise with the value the coroutine will return.

        Args:
            value: Return value yielded by the coroutine.
        """
        self._value = value

    async def __call__(self, *_args: object, **_kwargs: object) -> object:
        """Execute the stub and return the configured value.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            object: The configured return value.
        """
        return self._value


class _StubBridge:
    """Minimal ProcessBridge stub for SystemTab tests.

    Each coroutine factory returns a no-op success that resolves to an empty
    container of the expected shape. The tab implementation only depends on
    ``isinstance`` checks against ``list`` and ``dict``, so empty containers are
    enough to exercise the success path without breaking it.
    """

    def get_mitigation_policies(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_mitigation_policies.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def get_gui_resources(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_gui_resources.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def get_job_info(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_job_info.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()


@pytest.fixture
def warning_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    """Replace ``QMessageBox.warning`` with a recorder that returns ``Ok`` synchronously.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[object, ...]]: List that receives positional args of each warning.
    """
    calls: list[tuple[object, ...]] = []

    def _fake_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Capture the positional arguments and return ``Ok``.

        Args:
            *args: Positional arguments passed to ``QMessageBox.warning``.
            **_kwargs: Ignored keyword arguments.

        Returns:
            QMessageBox.StandardButton: ``Ok`` so any caller checking the return value continues normally.
        """
        calls.append(args)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_fake_warning))
    return calls


def _make_tab(*, pid: int | None) -> SystemTab:
    """Create a SystemTab wired to a _StubBridge with the given attached pid.

    Args:
        pid: PID to attach (or None for the unattached scenario).

    Returns:
        SystemTab: A constructed SystemTab ready for direct method invocation.
    """
    tab = SystemTab()
    tab.set_bridge(cast("ProcessBridge", _StubBridge()))
    tab.set_attached_pid(pid)
    return tab


def _capture_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[object, Callable[[object], None] | None, Callable[[object], None] | None]]:
    """Monkeypatch ``run_bridge_coroutine_async`` to capture invocations.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[object, Callable[[object], None] | None, Callable[[object], None] | None]]:
            Captured (coro, on_success, on_error) tuples.
    """
    captured: list[tuple[object, Callable[[object], None] | None, Callable[[object], None] | None]] = []

    def _fake_run(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        _parent: object = None,
    ) -> None:
        """Record the invocation and close the coroutine to avoid resource warnings.

        Args:
            coro: The coroutine that would have been executed.
            on_success: Success callback that would have received the awaited result.
            on_error: Error callback that would have received any exception raised.
            _parent: Ignored parent QObject reference.
        """
        coro.close()
        captured.append((coro, on_success, on_error))

    monkeypatch.setattr(_BRIDGE_MODULE_PATH, _fake_run)
    return captured


@pytest.mark.usefixtures("qapp")
class TestUnattachedPidGuards:
    """F-0022: pid-dependent actions must surface a warning when no PID is attached."""

    def test_refresh_mitigations_unattached_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Query Mitigations with no PID shows a warning and skips dispatch.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=None)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_refresh_mitigations")()

        assert captured == [], "no bridge call must occur when _attached_pid is None"
        assert warning_calls, "QMessageBox.warning must be shown to the user"
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "Mitigations" in title

    def test_on_gui_resources_unattached_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking GUI Resources with no PID shows a warning and skips dispatch.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=None)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_on_gui_resources")()

        assert captured == [], "no bridge call must occur when _attached_pid is None"
        assert warning_calls, "QMessageBox.warning must be shown to the user"
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "GUI Resources" in title

    def test_on_job_info_unattached_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Job Info with no PID shows a warning and skips dispatch.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=None)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_on_job_info")()

        assert captured == [], "no bridge call must occur when _attached_pid is None"
        assert warning_calls, "QMessageBox.warning must be shown to the user"
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "Job Info" in title

    def test_unattached_handlers_do_not_raise(
        self,
        warning_calls: list[tuple[object, ...]],
    ) -> None:
        """The three handlers must not raise when invoked without an attached PID.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
        """
        _ = warning_calls
        tab = _make_tab(pid=None)
        getattr(tab, "_refresh_mitigations")()
        getattr(tab, "_on_gui_resources")()
        getattr(tab, "_on_job_info")()

    def test_require_attached_pid_returns_pid_when_attached(self) -> None:
        """The helper returns the PID and skips the warning when attached."""
        tab = _make_tab(pid=4321)
        assert getattr(tab, "_require_attached_pid")("Query Mitigations") == 4321


@pytest.mark.usefixtures("qapp")
class TestErrorPathsSurfaceToUser:
    """F-0023: error callbacks must show a QMessageBox.warning, not just log."""

    def test_refresh_mitigations_error_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Triggering the mitigation error path shows a warning dialog.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=1234)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_refresh_mitigations")()

        assert len(captured) == 1
        on_error = captured[0][2]
        assert on_error is not None, "on_error must be wired"
        on_error(RuntimeError("mitigation query failed"))

        assert warning_calls, "QMessageBox.warning must be invoked on error"
        message = warning_calls[0][2]
        assert isinstance(message, str)
        assert "mitigation query failed" in message
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "Mitigations" in title

    def test_on_gui_resources_error_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Triggering the GUI resources error path shows a warning dialog.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=1234)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_on_gui_resources")()

        assert len(captured) == 1
        on_error = captured[0][2]
        assert on_error is not None
        on_error(OSError("user32 unavailable"))

        assert warning_calls
        message = warning_calls[0][2]
        assert isinstance(message, str)
        assert "user32 unavailable" in message
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "GUI Resources" in title

    def test_on_job_info_error_shows_warning(
        self,
        warning_calls: list[tuple[object, ...]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Triggering the job info error path shows a warning dialog.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab = _make_tab(pid=1234)
        captured = _capture_callbacks(monkeypatch)

        getattr(tab, "_on_job_info")()

        assert len(captured) == 1
        on_error = captured[0][2]
        assert on_error is not None
        on_error(RuntimeError("job object not accessible"))

        assert warning_calls
        message = warning_calls[0][2]
        assert isinstance(message, str)
        assert "job object not accessible" in message
        title = warning_calls[0][1]
        assert isinstance(title, str)
        assert "Job Info" in title

    def test_show_error_helper_invokes_qmessagebox(
        self,
        warning_calls: list[tuple[object, ...]],
    ) -> None:
        """The shared helper routes errors through ``QMessageBox.warning``.

        Args:
            warning_calls: Recorder fixture for ``QMessageBox.warning`` invocations.
        """
        tab = _make_tab(pid=1234)
        getattr(tab, "_show_error")("Custom Action Error", ValueError("boom"), log_event="custom_action_failed")

        assert warning_calls, "the helper must invoke QMessageBox.warning"
        title = warning_calls[0][1]
        message = warning_calls[0][2]
        assert isinstance(title, str)
        assert "Custom Action" in title
        assert isinstance(message, str)
        assert "boom" in message
