# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for GUI audit finding M5 (sandbox availability probe).

Finding M5: ``tools.py`` constructed a throwaway ``SandboxConfigDialog()`` on the
GUI thread solely to call ``is_sandbox_available()``. That dialog's ``__init__``
ran a blocking ``powershell ... Get-CimInstance`` probe synchronously, and the
leaked dialog was never disposed - repeated on every Sandbox tab add.

These tests assert the fix:

* ``tools.py`` obtains availability via the standalone
  ``is_windows_sandbox_available`` function, without constructing any QDialog.
* ``SandboxConfigDialog.__init__`` computes availability off the GUI thread
  (via a background worker), never running the PowerShell probe synchronously.
* The extracted probe result is cached so repeated queries do not re-spawn the
  subprocess.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from intellicrack.ui import sandbox_config, tools
from intellicrack.ui.sandbox_config import (
    SandboxConfigDialog,
    check_windows_sandbox_availability,
    is_windows_sandbox_available,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest


class _StubSignal:
    """Minimal stand-in for a ``pyqtSignal`` bound signal."""

    def __init__(self) -> None:
        """Initialise the stub with no connected callbacks."""
        self.callbacks: list[Callable[..., object]] = []

    def connect(self, callback: Callable[..., object]) -> None:
        """Record a connected callback.

        Args:
            callback: Slot that would receive the signal.
        """
        self.callbacks.append(callback)


class _StubWorker:
    """Recording stand-in for ``GenericCallableWorker`` that never runs a thread."""

    instances: ClassVar[list[_StubWorker]] = []

    def __init__(
        self,
        func: Callable[..., object],
        /,
        *args: object,
        exceptions: tuple[type[BaseException], ...] | None = None,
        parent: object = None,
        **kwargs: object,
    ) -> None:
        """Capture the callable and connection surface without starting a thread.

        Args:
            func: Callable the real worker would execute off-thread.
            *args: Positional arguments (ignored).
            exceptions: Exception tuple (ignored).
            parent: Qt parent (ignored).
            **kwargs: Keyword arguments (ignored).
        """
        _ = (args, exceptions, parent, kwargs)
        self.func: Callable[..., object] = func
        self.call_finished: _StubSignal = _StubSignal()
        self.call_error: _StubSignal = _StubSignal()
        self.started: bool = False
        _StubWorker.instances.append(self)

    def start(self) -> None:
        """Record that the worker was started without executing the callable."""
        self.started = True


class TestTabAddUsesExtractedCheck:
    """M5: the Sandbox tab-add path must not construct a dialog to probe availability."""

    @staticmethod
    def test_create_sandbox_panel_uses_function_not_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
        """_create_sandbox_panel must call is_windows_sandbox_available, never build a dialog.

        Args:
            monkeypatch: Fixture used to spy the extracted check and dialog ctor.
        """
        check_calls: list[bool] = []

        def _spy_check(*, use_cache: bool = True) -> bool:
            """Record the availability query and report unavailable.

            Args:
                use_cache: Cache flag forwarded by the caller (ignored).

            Returns:
                bool: Always ``False`` to short-circuit tab creation.
            """
            _ = use_cache
            check_calls.append(True)
            return False

        dialog_ctor_calls: list[bool] = []

        def _record_dialog_init(_self: object, *args: object, **kwargs: object) -> None:
            """Record a forbidden dialog construction.

            Args:
                _self: Dialog instance being initialised.
                *args: Positional arguments (ignored).
                **kwargs: Keyword arguments (ignored).
            """
            _ = (args, kwargs)
            dialog_ctor_calls.append(True)

        monkeypatch.setattr(sandbox_config, "is_windows_sandbox_available", _spy_check)
        monkeypatch.setattr(SandboxConfigDialog, "__init__", _record_dialog_init)

        mixin_cls = getattr(tools, "_ToolOutputPanelPanelsMixin")
        create_sandbox_panel = getattr(mixin_cls, "_create_sandbox_panel")
        result = create_sandbox_panel(object())

        assert result is None
        assert check_calls == [True]
        assert not dialog_ctor_calls


class TestDialogInitNonBlocking:
    """M5: the dialog constructor must not run the PowerShell probe synchronously."""

    @staticmethod
    def test_init_dispatches_probe_off_thread(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog __init__ must hand the probe to a worker and not call it synchronously.

        Args:
            qapp: Session QApplication fixture (ensures a Qt app exists).
            monkeypatch: Fixture used to stub the worker and spy the subprocess probe.
        """
        _ = qapp
        _StubWorker.instances.clear()

        probe_calls: list[bool] = []

        def _spy_query() -> tuple[str, int]:
            """Record any synchronous invocation of the subprocess probe.

            Returns:
                tuple[str, int]: A benign ``(install_state, returncode)`` pair.
            """
            probe_calls.append(True)
            return "", 0

        monkeypatch.setattr(sandbox_config, "GenericCallableWorker", _StubWorker)
        monkeypatch.setattr(sandbox_config, "_query_sandbox_optional_feature", _spy_query)

        dialog = SandboxConfigDialog()

        assert len(_StubWorker.instances) == 1
        worker = _StubWorker.instances[0]
        assert worker.started
        assert worker.func is check_windows_sandbox_availability
        assert not probe_calls
        dialog.deleteLater()


class TestAvailabilityFunction:
    """M5: the standalone availability function and its caching."""

    @staticmethod
    def test_is_available_returns_bool_without_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
        """is_windows_sandbox_available must return a bool without constructing a dialog.

        Args:
            monkeypatch: Fixture used to stub the probe and spy the dialog ctor.
        """
        monkeypatch.setattr(getattr(sandbox_config, "_AvailabilityCache"), "value", None)
        monkeypatch.setattr(sandbox_config, "_probe_windows_sandbox", lambda: (True, ""))

        dialog_ctor_calls: list[bool] = []

        def _record_dialog_init(_self: object, *args: object, **kwargs: object) -> None:
            """Record a forbidden dialog construction.

            Args:
                _self: Dialog instance being initialised.
                *args: Positional arguments (ignored).
                **kwargs: Keyword arguments (ignored).
            """
            _ = (args, kwargs)
            dialog_ctor_calls.append(True)

        monkeypatch.setattr(SandboxConfigDialog, "__init__", _record_dialog_init)

        available = is_windows_sandbox_available()

        assert available is True
        assert not dialog_ctor_calls

    @staticmethod
    def test_result_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
        """The probe must run once when cached and re-run when the cache is bypassed.

        Args:
            monkeypatch: Fixture used to count probe invocations.
        """
        monkeypatch.setattr(getattr(sandbox_config, "_AvailabilityCache"), "value", None)

        probe_count = {"n": 0}

        def _counting_probe() -> tuple[bool, str]:
            """Count invocations and report unavailable.

            Returns:
                tuple[bool, str]: A fixed ``(False, reason)`` result.
            """
            probe_count["n"] += 1
            return False, "feature not enabled"

        monkeypatch.setattr(sandbox_config, "_probe_windows_sandbox", _counting_probe)

        first = check_windows_sandbox_availability(use_cache=True)
        second = check_windows_sandbox_availability(use_cache=True)
        assert first == second
        assert probe_count["n"] == 1

        _ = check_windows_sandbox_availability(use_cache=False)
        assert probe_count["n"] == 2
