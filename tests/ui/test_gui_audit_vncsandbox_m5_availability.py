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
  The worker is dispatched through ``run_callable_async``, so it records the
  dialog as its owner without becoming the dialog's Qt child - closing the
  dialog while the probe is still running must not destroy the thread.
* The extracted probe result is cached so repeated queries do not re-spawn the
  subprocess.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QThread

from intellicrack.ui import sandbox_config, tools
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.sandbox_config import (
    SandboxConfigDialog,
    check_windows_sandbox_availability,
    is_windows_sandbox_available,
)


if TYPE_CHECKING:
    import pytest
    from PyQt6.QtWidgets import QApplication


_WORKER_JOIN_MS: Final[int] = 30_000


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
    def test_init_dispatches_probe_off_thread(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog __init__ must hand the probe to a worker and not call it synchronously.

        Drives the real dispatch: the only thing replaced is the subprocess
        boundary, which records the thread it is called on. The dialog must end
        up holding a real, started worker that belongs to it, and the probe must
        never have run on the GUI thread.

        Args:
            qapp: Session QApplication fixture, whose thread the probe must avoid.
            monkeypatch: Fixture used to clear the availability cache and record the probe's thread.
        """
        probe_threads: list[QThread | None] = []

        def _recording_query() -> tuple[str, int]:
            """Record the thread the subprocess probe runs on.

            Returns:
                tuple[str, int]: A benign ``(install_state, returncode)`` pair.
            """
            probe_threads.append(QThread.currentThread())
            return "", 0

        monkeypatch.setattr(getattr(sandbox_config, "_AvailabilityCache"), "value", None)
        monkeypatch.setattr(sandbox_config, "_query_sandbox_optional_feature", _recording_query)

        dialog = SandboxConfigDialog()
        try:
            worker = dialog._availability_worker
            assert isinstance(worker, GenericCallableWorker), "the dialog did not dispatch the availability probe to a worker"
            assert worker.owner() is dialog, "the dialog is not the availability worker's recorded owner"
            assert worker.parent() is None, (
                "the availability worker is a Qt child of the dialog; closing the dialog mid-probe would destroy the running thread"
            )
            assert worker.wait(_WORKER_JOIN_MS), "the availability worker never finished"
            assert worker.isFinished(), "the availability worker was never started, so the probe was not dispatched at all"
            assert qapp.thread() not in probe_threads, "the PowerShell probe ran on the GUI thread inside the dialog constructor"
            cached = getattr(sandbox_config, "_AvailabilityCache").value
            assert cached is not None, "the dispatched callable was not the availability probe: it left the cache unpopulated"
        finally:
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
