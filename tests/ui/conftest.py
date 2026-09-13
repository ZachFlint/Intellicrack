# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pytest configuration and fixtures for UI tests.

Provides shared fixtures including QApplication instance
required for Qt widget testing, signal recording utilities,
and real Config/Orchestrator instances.

Also installs an autouse guard that replaces blocking Qt modal dialog entry
points (``QMessageBox``, ``QInputDialog``, ``QFileDialog``) with non-blocking
stand-ins, so a panel handler that opens one under the headless ``offscreen``
Qt platform cannot stall the whole tree; see :func:`guard_modal_dialogs` for
the full rationale and its narrow compatibility carve-out.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, shutdown_bridge_loop


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path


class SignalRecorder:
    """Records signal emissions for assertion without unittest.mock.

    Construction takes no arguments and initialises an empty call history.
    """

    def __init__(self) -> None:
        """Initialise the signal recorder with an empty call history."""
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: object) -> None:
        """Record a call with its arguments.

        Args:
            *args: Arguments passed to the signal slot.
        """
        self.calls.append(args)

    def verify_single_call(self, *expected: object) -> None:
        """Assert exactly one call with expected arguments.

        Args:
            *expected: Expected arguments.
        """
        assert len(self.calls) == 1, f"Expected 1 call, got {len(self.calls)}"
        assert self.calls[0] == expected, f"Expected {expected}, got {self.calls[0]}"

    def verify_any_call(self, *expected: object) -> None:
        """Assert at least one call with expected arguments.

        Args:
            *expected: Expected arguments to find.
        """
        assert expected in list(self.calls), f"{expected} not found in {self.calls}"

    @property
    def times_called(self) -> int:
        """The number of recorded calls.

        Returns:
            int: Number of times this recorder was called.
        """
        return len(self.calls)


class DialogRecorder:
    """Records dialog invocations for assertion without unittest.mock.

    Construction takes no arguments and initialises an empty call history.
    """

    def __init__(self) -> None:
        """Initialise the dialog recorder with an empty call history."""
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: object, **_kwargs: object) -> None:
        """Record a dialog invocation.

        Args:
            *args: Positional arguments.
            **_kwargs: Keyword arguments (accepted but not stored).
        """
        self.calls.append(args)


class NoOpSandboxManager:
    """No-op replacement for SandboxManager in tests.

    Accepts any constructor arguments and returns no-op callables
    for any attribute access.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Accept and discard all constructor arguments.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.
        """
        del args, kwargs

    def __getattr__(self, name: str) -> Callable[..., None]:
        """Return a no-op callable for any attribute.

        Args:
            name: Attribute name.

        Returns:
            Callable[..., None]: A callable that does nothing and returns None.
        """
        return lambda *_args, **_kwargs: None


class CallRecorder:
    """Records arbitrary function calls for assertion."""

    def __init__(self, result: object = None) -> None:
        """Initialise the call recorder.

        Args:
            result: Value returned by each invocation of this recorder.
        """
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.result: object = result

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Record a call and return the configured value.

        Args:
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            object: The configured result value.
        """
        self.calls.append((args, kwargs))
        return self.result

    @property
    def times_called(self) -> int:
        """The number of recorded calls.

        Returns:
            int: Number of times this recorder was called.
        """
        return len(self.calls)


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process. This fixture
    reuses an existing application when present, otherwise creates one for the
    whole session. On teardown it drains any still-running background bridge
    workers, flushes pending ``deleteLater`` events, and stops the persistent
    bridge event loop so the interpreter can exit cleanly instead of aborting
    with ``QThread: Destroyed while thread is still running``.

    Yields:
        QApplication: QApplication instance for widget testing.
    """
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication([])
    try:
        yield app
    finally:
        drain_bridge_workers()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        app.processEvents()
        shutdown_bridge_loop()


@pytest.fixture(autouse=True)
def _drain_bridge_workers_after_test() -> Generator[None]:
    """Drain in-flight async-bridge worker threads after every UI test.

    UI panels dispatch real ``BridgeCallWorker`` / ``GenericCallableWorker``
    ``QThread`` instances through the async-bridge helpers. With no Qt event
    loop spinning during a unit test, a worker whose OS thread is still running
    when the test ends - and the widget it references is torn down - would be
    destroyed mid-flight, aborting the interpreter. Draining after each test
    guarantees every dispatched worker finishes and its ``deleteLater`` is
    delivered before the next test (or process exit) begins.

    Yields:
        None: Control passes to the test; the drain runs on teardown.
    """
    yield
    drain_bridge_workers()
    app = QApplication.instance()
    if app is not None:
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        app.processEvents()


@pytest.fixture
def real_config(tmp_path: Path) -> Config:
    """Create a real Config instance with tmp_path directories.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Config: Config instance using temporary directories.
    """
    return Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )


@pytest.fixture
def real_orchestrator(tmp_path: Path) -> Orchestrator:
    """Create a real Orchestrator with empty registries.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Orchestrator: Orchestrator instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_REAL_MODAL_FIXTURE_NAMES: frozenset[str] = frozenset(
    {
        "warning_recorder",
        "modal_recorder",
        "dismisser",
        "_release_error_dialogs",
    },
)


def _accept_messagebox(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return ``Yes`` without displaying a ``QMessageBox`` modal.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        QMessageBox.StandardButton: The ``Yes`` button constant, so a handler
        guarding on an affirmative confirmation proceeds as it would if the
        user had accepted the dialog.
    """
    return QMessageBox.StandardButton.Yes


def _cancel_text_dialog(*_args: object, **_kwargs: object) -> tuple[str, bool]:
    """Return a cancelled empty-text result for a ``QInputDialog`` text prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[str, bool]: An empty string paired with ``False`` to signal the
        user dismissed the prompt without entering a value.
    """
    return ("", False)


def _cancel_int_dialog(*_args: object, **_kwargs: object) -> tuple[int, bool]:
    """Return a cancelled result for a ``QInputDialog.getInt`` prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[int, bool]: Zero paired with ``False`` to signal cancellation.
    """
    return (0, False)


def _cancel_double_dialog(*_args: object, **_kwargs: object) -> tuple[float, bool]:
    """Return a cancelled result for a ``QInputDialog.getDouble`` prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[float, bool]: Zero paired with ``False`` to signal cancellation.
    """
    return (0.0, False)


def _no_single_file(*_args: object, **_kwargs: object) -> tuple[str, str]:
    """Return an empty single-file selection for a ``QFileDialog`` picker.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[str, str]: An empty path and empty selected-filter pair,
        matching the shape returned by ``getOpenFileName``/``getSaveFileName``
        when the user cancels.
    """
    return ("", "")


def _no_multiple_files(*_args: object, **_kwargs: object) -> tuple[list[str], str]:
    """Return an empty multi-file selection for ``QFileDialog.getOpenFileNames``.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[list[str], str]: An empty path list and empty selected-filter,
        matching the shape returned when the user cancels.
    """
    return ([], "")


def _no_directory(*_args: object, **_kwargs: object) -> str:
    """Return an empty directory selection for ``QFileDialog.getExistingDirectory``.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        str: An empty string, signalling the user cancelled the picker.
    """
    return ""


@pytest.fixture(autouse=True)
def guard_modal_dialogs(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace blocking Qt modal dialog entry points with non-blocking defaults.

    Panels exercised under ``tests/ui`` surface user feedback and input
    requests through Qt's blocking modal dialogs -- directly via
    ``QMessageBox`` and ``QInputDialog``/``QFileDialog``, and indirectly via
    the ``intellicrack.ui.dialogs_helpers`` wrappers (``show_info``/
    ``show_warning``/``show_error``), each of which delegates to a
    ``QMessageBox`` static method. Under the headless ``offscreen`` Qt
    platform used inside the Docker test sandbox a modal dialog can never be
    dismissed, so any handler that reaches one blocks its test forever and --
    because the whole tree runs in a single process -- stalls the entire
    ``tests/ui`` gate. A faulthandler dump caught exactly this: the main
    thread parked inside ``ModulesTab._on_error``
    (``src/intellicrack/ui/panels/process_panel/modules_tab.py``), which a
    failed async bridge callback drives into a blocking
    ``QMessageBox.warning`` call.

    This installs the same non-blocking stand-ins as
    ``tests/bridges/completeness/conftest.py``: ``QMessageBox`` statics
    (``warning``/``information``/``question``/``critical``) return ``Yes``
    without ever opening a dialog, and ``QInputDialog``/``QFileDialog``
    pickers return a cancelled/empty selection so handlers take their "user
    cancelled" branch. The production handler logic under test still runs in
    full; only the operating system's modal render is bypassed. Patching the
    ``QMessageBox`` statics also covers every ``dialogs_helpers`` call
    transitively, since each helper calls straight through to the same
    static method on the same class object.

    A handful of tests and package conftests under ``tests/ui`` (named in
    :data:`_REAL_MODAL_FIXTURE_NAMES`) instead let the genuine ``QMessageBox``
    modal appear and dismiss it themselves with a polling ``QTimer`` against
    ``QApplication.activeModalWidget()``, then assert on the dialog's real
    ``windowTitle()``/``text()`` -- this is how they prove the production
    warning/error path fires with the exact right content. Faking the
    ``QMessageBox`` statics would mean no such widget is ever constructed,
    silently defeating those assertions instead of exercising them. When any
    such fixture is active for the current test (autouse or explicitly
    requested), this guard leaves the ``QMessageBox`` statics untouched and
    defers to it entirely; the ``QInputDialog``/``QFileDialog`` stand-ins
    still apply unconditionally, since none of those existing mechanisms
    touch input or file pickers. Individual tests that assert on a specific
    dialog invocation, or that need a concrete picker result, can still
    override the relevant entry point with their own ``monkeypatch.setattr``
    inside the test body, which takes precedence over this fixture because it
    runs after fixture setup completes.

    Args:
        request: Pytest fixture request, used to detect whether one of the
            tree's existing real-modal-dismissal fixtures is already active
            for the current test.
        monkeypatch: pytest monkeypatch fixture used to install the guards.
    """
    if _REAL_MODAL_FIXTURE_NAMES.isdisjoint(request.fixturenames):
        for name in ("warning", "information", "question", "critical"):
            monkeypatch.setattr(QMessageBox, name, _accept_messagebox)
    monkeypatch.setattr(QInputDialog, "getText", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getMultiLineText", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getItem", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getInt", _cancel_int_dialog)
    monkeypatch.setattr(QInputDialog, "getDouble", _cancel_double_dialog)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _no_single_file)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _no_single_file)
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", _no_multiple_files)
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _no_directory)
