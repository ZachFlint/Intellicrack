# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the sandbox, preferences, theme, tool-panel, process-memory, provider-switch and close handlers of the main window.

Every test drives a real ``MainWindow`` built over a real ``Orchestrator``, ``SessionManager`` with a SQLite store, ``ProviderRegistry`` and
``ToolRegistry``. Per-user state (``providers.json``, ``config.toml``, credentials) is redirected into the test's temporary directory.
Modal dialogs the window opens itself (preferences, memory-region picker, provider prompt) are real dialogs closed from inside their own
event loop by a polling timer with a hard deadline. Collaborators are real product classes, some of them subclassed to script one outcome:
the sandbox bridge, the hex editor bridge, the sandbox manager and the tool panels. Expected values come from the strings the handlers are
documented to show, from files the tests write themselves, and from independent computations on the standard library.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import time
import tomllib
import types
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn, cast, override

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import QEvent, QSignalBlocker, QTimer
from PyQt6.QtGui import QSyntaxHighlighter, QTextDocument
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from structlog.testing import capture_logs

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.config import Config, UIConfig, get_config_file
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BridgeAnalysisSummary, ModelInfo, ProviderCredentials, ToolName
from intellicrack.credentials.env_loader import unregister_instance_mapping
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.sandbox import SandboxConfig, SandboxManager
from intellicrack.sandbox.manager import SandboxInstance
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.ui import sandbox_config
from intellicrack.ui.app import MainWindow
from intellicrack.ui.highlighter import CSyntaxHighlighter
from intellicrack.ui.log_viewer import LogViewerWindow
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, run_bridge_coroutine
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.hex_editor import HexEditorPanel
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel
from intellicrack.ui.preferences import PreferencesDialog
from intellicrack.ui.resources import ThemeManager
from intellicrack.ui.sandbox_config import SandboxMonitorWidget
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_WAIT_MS: int = 30_000
_BRIDGE_TIMEOUT_S: float = 60.0
_MODAL_POLL_MS: int = 5
_MODAL_DEADLINE_S: float = 45.0
_GATEWAY_ID: str = "my-gw"
_MODEL_A: str = "alpha-model"
_MODEL_B: str = "beta-model"
_BAD_PID: int = 0x7FFFFFFF
_PID: int = 4321
_COMMITTED_BASE: int = 0x7FF600000000
_COMMITTED_SIZE: int = 0x2000
_MEM_FREE_STATE: int = 0x10000
_MEM_COMMIT_STATE: int = 0x1000
_PAGE_NOACCESS: int = 0x01
_PAGE_EXECUTE_READWRITE: int = 0x40
_REGIONS: list[tuple[int, int, int, int]] = [
    (0, 0x1000, _PAGE_NOACCESS, _MEM_FREE_STATE),
    (_COMMITTED_BASE, _COMMITTED_SIZE, _PAGE_EXECUTE_READWRITE, _MEM_COMMIT_STATE),
]
_OK: QMessageBox.StandardButton = QMessageBox.StandardButton.Ok
_WORK_STATE: bytes = b"\x01\x02\x03\x04"
_EDITED_STATE: bytes = b"\xff\x02\x03\x04"


class _Rig(NamedTuple):
    """A real main window together with the collaborators a test inspects.

    Attributes:
        window: The constructed, unshown main window.
        orchestrator: The orchestrator the window drives.
        config: The configuration the window was built with.
        statuses: Every status message the window emitted since construction.
        information: Recorder installed over ``QMessageBox.information``.
        warning: Recorder installed over ``QMessageBox.warning``.
        critical: Recorder installed over ``QMessageBox.critical``.
        tmp_path: The test's private directory.
    """

    window: MainWindow
    orchestrator: Orchestrator
    config: Config
    statuses: list[str]
    information: DialogRecorder
    warning: DialogRecorder
    critical: DialogRecorder
    tmp_path: Path


class _ToolCase(NamedTuple):
    """One embedded tool the main window opens through a toolbar or menu handler.

    Attributes:
        method: Name of the window handler that opens the tool.
        attribute: Name of the tool panel's private slot holding the tool widget.
        panel_class: Real panel class built for the slot.
        title: Tool name used in the error dialog title (``"<title> Error"``).
        failure: Tool wording used in the failure message (``"Failed to open <failure> panel: ..."``).
    """

    method: str
    attribute: str
    panel_class: type[QWidget]
    title: str
    failure: str


_TOOL_CASES: list[Any] = [
    pytest.param(_ToolCase("_on_open_x64dbg", "_x64dbg_widget", X64DbgPanel, "x64dbg", "x64dbg"), id="x64dbg"),
    pytest.param(_ToolCase("_on_open_ghidra", "_ghidra_widget", GhidraPanel, "Ghidra", "Ghidra"), id="ghidra"),
    pytest.param(_ToolCase("_on_open_frida", "_frida_panel", FridaPanel, "Frida", "Frida"), id="frida"),
    pytest.param(_ToolCase("_on_open_cutter", "_cutter_widget", CutterPanel, "Cutter", "Cutter"), id="cutter"),
    pytest.param(_ToolCase("_on_open_hex_editor", "_hex_editor_panel", HexEditorPanel, "Hex Editor", "hex editor"), id="hex-editor"),
]


class _RefusingManager(SandboxManager):
    """A real sandbox manager whose teardown always fails."""

    @override
    async def destroy_all(self) -> None:
        """Refuse to tear anything down.

        Raises:
            RuntimeError: Always, standing in for a backend that cannot stop.
        """
        message = "teardown refused"
        raise RuntimeError(message)


class _ScriptedSandboxBridge(SandboxBridge):
    """A real sandbox bridge whose backend availability and creation outcome are scripted.

    Attributes:
        available: What ``is_available`` reports.
        payload: What ``create`` returns on success.
        failure: Message of the error ``create`` raises, or an empty string to succeed.
    """

    available: bool
    payload: dict[str, Any]
    failure: str

    def __init__(self, *, available: bool, payload: dict[str, Any], failure: str = "") -> None:
        """Build the bridge with its scripted outcome.

        Args:
            available: What ``is_available`` reports.
            payload: What ``create`` returns on success.
            failure: Message of the error ``create`` raises, or an empty string to succeed.
        """
        super().__init__()
        self.available = available
        self.payload = payload
        self.failure = failure

    @override
    async def is_available(self) -> bool:
        """Report the scripted availability.

        Returns:
            bool: The scripted availability.
        """
        return self.available

    @override
    async def create(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Create nothing and return the scripted payload, or fail as scripted.

        Args:
            *args: Ignored creation arguments.
            **kwargs: Ignored creation keyword arguments.

        Returns:
            dict[str, Any]: A copy of the scripted payload.

        Raises:
            RuntimeError: When a failure message is scripted.
        """
        del args, kwargs
        if self.failure:
            raise RuntimeError(self.failure)
        return dict(self.payload)


class _RecordingHexBridge(HexEditorBridge):
    """A real hex editor bridge that records the process-memory regions it is asked to open.

    Attributes:
        opened: Every ``(pid, address, size)`` the bridge was asked to open.
    """

    opened: list[tuple[int, int, int]]

    def __init__(self) -> None:
        """Build the bridge with an empty call record."""
        super().__init__()
        self.opened = []

    @override
    async def open_process_memory(self, pid: int, address: int, size: int) -> dict[str, Any]:
        """Record the request and report a document of the requested size.

        Args:
            pid: Process id to read from.
            address: Base address of the region.
            size: Number of bytes in the region.

        Returns:
            dict[str, Any]: A payload shaped like the real bridge's.
        """
        self.opened.append((pid, address, size))
        return {"pid": pid, "address": address, "size": size, "document_length": size}


class _CountingHighlighter(CSyntaxHighlighter):
    """A real C highlighter that counts the blocks it is asked to highlight.

    Attributes:
        blocks_seen: Number of ``highlightBlock`` calls since construction or the last reset.
    """

    blocks_seen: int

    def __init__(self, document: QTextDocument) -> None:
        """Attach the highlighter to a document.

        Args:
            document: The document to highlight.
        """
        super().__init__(document)
        self.blocks_seen = 0

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Count the block, then highlight it as the real highlighter does.

        Args:
            text: The text of the block.
        """
        self.blocks_seen += 1
        super().highlightBlock(text)


def _raise_runtime_error(_owner: object) -> NoReturn:
    """Behave as a property that fails with a runtime error.

    Args:
        _owner: The object the property is read from.

    Raises:
        RuntimeError: Always.
    """
    message = "instances unavailable"
    raise RuntimeError(message)


def _raise_attribute_error(_owner: object) -> NoReturn:
    """Behave as a property that fails with an attribute error.

    Args:
        _owner: The object the property is read from.

    Raises:
        AttributeError: Always.
    """
    message = "instances unavailable"
    raise AttributeError(message)


def _refuse_start(_owner: object) -> NoReturn:
    """Behave as a tool panel whose ``start_tool`` fails.

    Args:
        _owner: The panel.

    Raises:
        RuntimeError: Always.
    """
    message = "start refused"
    raise RuntimeError(message)


def _list_settings(_owner: object) -> list[str]:
    """Behave as a ``get_settings`` that returns something other than a mapping.

    Args:
        _owner: The object the method is called on.

    Returns:
        list[str]: A list.
    """
    return ["not", "a", "mapping"]


def _unlistable_manager(raiser: Callable[[object], NoReturn]) -> SandboxManager:
    """Build a real sandbox manager whose ``instances`` property fails.

    Args:
        raiser: Function the property calls.

    Returns:
        SandboxManager: A manager of a subclass whose ``instances`` raises.
    """

    def _populate(namespace: dict[str, Any]) -> None:
        """Replace the property in the class body.

        Args:
            namespace: The class namespace being built.
        """
        namespace["instances"] = property(raiser)

    manager_class = cast("type[SandboxManager]", types.new_class("_UnlistableManager", (SandboxManager,), None, _populate))
    return manager_class()


def _refusing_panel(panel_class: type[QWidget]) -> QWidget:
    """Build a real tool panel whose ``start_tool`` fails.

    Args:
        panel_class: Real panel class to subclass.

    Returns:
        QWidget: An instance of the subclass.
    """

    def _populate(namespace: dict[str, Any]) -> None:
        """Replace ``start_tool`` in the class body.

        Args:
            namespace: The class namespace being built.
        """
        namespace["start_tool"] = _refuse_start

    refusing_class = cast("type[QWidget]", types.new_class(f"_Refusing{panel_class.__name__}", (panel_class,), None, _populate))
    return refusing_class()


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _call(obj: object, name: str, *args: object, **kwargs: object) -> _Dynamic:
    """Call a private method of a product object.

    Args:
        obj: Object that owns the method.
        name: Method name.
        *args: Positional arguments for the method.
        **kwargs: Keyword arguments for the method.

    Returns:
        _Dynamic: What the method returns.
    """
    return getattr(obj, name)(*args, **kwargs)


def _combo(window: MainWindow, name: str) -> QComboBox:
    """Fetch one of the window's combo boxes by attribute name.

    Args:
        window: The main window.
        name: Attribute name of the combo.

    Returns:
        QComboBox: The combo box.
    """
    found: object = getattr(window, name)
    assert isinstance(found, QComboBox)
    return found


def _select_provider(window: MainWindow, provider_id: str) -> None:
    """Make a provider the toolbar's current one without firing the user-switch handler.

    Args:
        window: The main window.
        provider_id: Provider id that must be listed in the toolbar combo.
    """
    combo = _combo(window, "_provider_combo")
    index = combo.findData(provider_id)
    assert index >= 0, f"{provider_id!r} is not listed in the provider combo"
    with QSignalBlocker(combo):
        combo.setCurrentIndex(index)


def _model_items(window: MainWindow) -> list[str]:
    """List the model combo's items.

    Args:
        window: The main window.

    Returns:
        list[str]: Item texts in display order.
    """
    return [window.model_combo.itemText(index) for index in range(window.model_combo.count())]


def _model(model_id: str) -> ModelInfo:
    """Build a model record.

    Args:
        model_id: Identifier of the model.

    Returns:
        ModelInfo: A tool-capable model with a fixed context window.
    """
    return ModelInfo(
        id=model_id,
        name=model_id.upper(),
        provider="test",
        context_window=8192,
        supports_tools=True,
        supports_vision=False,
        supports_streaming=True,
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
    )


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structured-log entries by event name.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The entries logged under that event.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _assert_in_order(statuses: Sequence[str], expected: Sequence[str]) -> None:
    """Assert that messages appear in the status history in the given order.

    Args:
        statuses: Recorded status messages.
        expected: Messages that must appear, earliest first.
    """
    position = -1
    for item in expected:
        assert item in list(statuses)[position + 1 :], f"{item!r} missing or out of order in {list(statuses)!r}"
        position = list(statuses).index(item, position + 1)


def _dialog_returning(path: str) -> Callable[..., tuple[str, str]]:
    """Build a stand-in for a ``QFileDialog`` picker that returns a fixed path.

    Args:
        path: Path the picker reports; empty for a cancelled dialog.

    Returns:
        Callable[..., tuple[str, str]]: A function with the shape of ``getSaveFileName``.
    """

    def _picker(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the chosen path.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty selected filter.
        """
        return path, ""

    return _picker


def _answer(button: QMessageBox.StandardButton) -> Callable[..., QMessageBox.StandardButton]:
    """Build a stand-in for ``QMessageBox.question`` that always gives one answer.

    Args:
        button: The button the user presses.

    Returns:
        Callable[..., QMessageBox.StandardButton]: A function with the shape of ``QMessageBox.question``.
    """

    def _question(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Report the pressed button.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            QMessageBox.StandardButton: The configured answer.
        """
        return button

    return _question


@contextlib.contextmanager
def _drive_modals(action: Callable[[QDialog], None]) -> Generator[list[QDialog]]:
    """Run an action on each modal dialog that opens while the context is active.

    A polling timer stands in for the user, so the handler under test runs its real modal loop. A dialog the action leaves open past the
    deadline is rejected so a failing test ends instead of hanging.

    Args:
        action: Called once per modal dialog; it must close the dialog.

    Yields:
        list[QDialog]: The dialogs the action has been run on so far.
    """
    seen: list[QDialog] = []
    started = time.monotonic()

    def _tick() -> None:
        """Hand a newly opened modal dialog to the action, or reject one that outlived the deadline."""
        modal = QApplication.activeModalWidget()
        if not isinstance(modal, QDialog):
            return
        if modal not in seen:
            seen.append(modal)
            action(modal)
        elif time.monotonic() - started > _MODAL_DEADLINE_S:
            modal.reject()

    timer = QTimer()
    timer.setInterval(_MODAL_POLL_MS)
    _ = timer.timeout.connect(_tick)
    timer.start()
    try:
        yield seen
    finally:
        timer.stop()
        timer.timeout.disconnect(_tick)


def _press(role: QMessageBox.ButtonRole, record: dict[str, object] | None = None) -> Callable[[QDialog], None]:
    """Build a modal action that presses the button of one role in a message box.

    Args:
        role: Role of the button to press.
        record: Optional dictionary that receives the box's title, text, icon and default-button text before the press.

    Returns:
        Callable[[QDialog], None]: The action.
    """

    def _action(dialog: QDialog) -> None:
        """Press the button, or reject the dialog when it has none of that role.

        Args:
            dialog: The message box.
        """
        if not isinstance(dialog, QMessageBox):
            dialog.reject()
            return
        if record is not None:
            default = dialog.defaultButton()
            record["title"] = dialog.windowTitle()
            record["text"] = dialog.text()
            record["icon"] = dialog.icon()
            record["default"] = default.text() if default is not None else None
        for button in dialog.findChildren(QPushButton):
            if dialog.buttonRole(button) == role:
                button.click()
                return
        dialog.reject()

    return _action


def _reject_dialog(dialog: QDialog) -> None:
    """Reject a dialog.

    Args:
        dialog: The dialog.
    """
    dialog.reject()


def _accept_dialog(dialog: QDialog) -> None:
    """Accept a dialog.

    Args:
        dialog: The dialog.
    """
    dialog.accept()


def _empty_table_then_accept(dialog: QDialog) -> None:
    """Remove every row of the dialog's table so nothing is selected, then accept.

    Args:
        dialog: The memory-region dialog.
    """
    dialog.findChild(QTableWidget).setRowCount(0)
    dialog.accept()


def _choose_light_theme_and_confirm(dialog: QDialog) -> None:
    """Pick the light theme in the preferences dialog and press OK.

    Args:
        dialog: The preferences dialog.
    """
    for combo in dialog.findChildren(QComboBox):
        if combo.findData("dark2") >= 0:
            combo.setCurrentIndex(combo.findData("light"))
    ok = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok)
    if ok is None:
        dialog.reject()
        return
    ok.click()


def _dialog_titles(seen: Sequence[QDialog]) -> list[str]:
    """List the window titles of the dialogs a modal driver has handled.

    Args:
        seen: Dialogs handled so far.

    Returns:
        list[str]: Their titles.
    """
    return [dialog.windowTitle() for dialog in seen]


@contextlib.contextmanager
def _sandbox_unavailable() -> Generator[None]:
    """Make the process-wide Windows Sandbox availability probe report an unavailable host, then restore it.

    Yields:
        None: Control passes to the body; the previous cached probe result is restored afterwards.
    """
    cache = cast("type[Any]", getattr(sandbox_config, "_AvailabilityCache"))
    previous = cache.value
    cache.value = (False, "Windows Sandbox is not enabled")
    try:
        yield
    finally:
        cache.value = previous


def _write_binary(path: Path) -> Path:
    """Write a small file the window can treat as the loaded binary.

    Args:
        path: Destination.

    Returns:
        Path: The same path.
    """
    _ = path.write_bytes(b"MZ" + bytes(range(16)))
    return path


def _loopback_instance(base_url: str = "http://127.0.0.1:9/v1") -> ProviderInstance:
    """Build an instance that needs no key and points at a loopback address.

    Args:
        base_url: The endpoint the instance talks to.

    Returns:
        ProviderInstance: The instance, id ``my-gw``.
    """
    return ProviderInstance(instance_id=_GATEWAY_ID, display_name="Corp Gateway", api_base=base_url, requires_api_key=False)


def _add_to_tabs(window: MainWindow, attribute: str, panel: QWidget, title: str) -> None:
    """Install a real panel in one of the tool panel's tool slots and its tab strip.

    Args:
        window: The main window.
        attribute: Name of the tool panel's private slot.
        panel: The panel to install.
        title: Tab title.
    """
    _set_priv(window.tool_panel, attribute, panel)
    _ = window.tool_panel.tab_widget.addTab(panel, title)


def _summary(*, complete: bool) -> BridgeAnalysisSummary:
    """Build an empty analysis summary.

    Args:
        complete: Whether the summary reports that a backend contributed data.

    Returns:
        BridgeAnalysisSummary: The summary.
    """
    return BridgeAnalysisSummary(
        binary_name="sample.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="PE32+",
        architecture="x64",
        source_bridges=["ghidra"],
        analysis_notes=[],
        complete=complete,
    )


@pytest.fixture
def state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Redirect the per-user state root into the test directory with no provider variables set.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    for suffix in ("API_KEY", "API_BASE", "ORGANIZATION", "PROJECT"):
        monkeypatch.delenv(f"MY_GW_{suffix}", raising=False)
    with redirected_state_root(monkeypatch, tmp_path) as root:
        yield root
    unregister_instance_mapping(_GATEWAY_ID)


@pytest.fixture
def rig(qapp: QApplication, tmp_path: Path, state_root: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[_Rig]:
    """Build a real main window over a real orchestrator and record its dialogs and status messages.

    Args:
        qapp: The shared offscreen application.
        tmp_path: Per-test temporary directory.
        state_root: The redirected state root.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        _Rig: The window with its collaborators.
    """
    del state_root
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        ui=UIConfig(theme="dark"),
    )
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
    )
    window = MainWindow(config, orchestrator)
    statuses: list[str] = []
    _ = window.status_update.connect(statuses.append)
    information = DialogRecorder()
    warning = DialogRecorder()
    critical = DialogRecorder()
    monkeypatch.setattr(QMessageBox, "information", staticmethod(information))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(warning))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(critical))
    try:
        yield _Rig(window, orchestrator, config, statuses, information, warning, critical, tmp_path)
    finally:
        window.close()
        _ = drain_bridge_workers()
        qapp.processEvents()


@pytest.fixture
def gateway(rig: _Rig) -> Generator[ConfigurableProvider]:
    """Register a connected provider that lists two models from a loopback endpoint.

    Args:
        rig: The window rig.

    Yields:
        ConfigurableProvider: The connected provider, registered as ``my-gw`` and listed in the toolbar.
    """
    with OpenAIModelsServer(model_ids=[_MODEL_B, _MODEL_A]) as server:
        provider = ConfigurableProvider(_loopback_instance(server.base_url))
        _ = run_bridge_coroutine(provider.connect(ProviderCredentials()), timeout_s=_BRIDGE_TIMEOUT_S)
        assert provider.is_connected
        rig.orchestrator.provider_registry.register(provider)
        _call(rig.window, "_populate_provider_combo")
        try:
            yield provider
        finally:
            _ = run_bridge_coroutine(provider.disconnect(), timeout_s=_BRIDGE_TIMEOUT_S)


def test_sandbox_settings_update_without_a_sender_is_ignored(rig: _Rig) -> None:
    """Calling the Apply slot directly, with no signal behind it, applies nothing.

    Args:
        rig: The window rig.
    """
    manager = rig.window.sandbox_manager

    with capture_logs() as captured:
        _call(rig.window, "_on_sandbox_settings_updated")
    _ = drain_bridge_workers()

    assert len(_events(captured, "sandbox_settings_updated_without_sender")) == 1
    assert rig.window.sandbox_manager is manager
    assert rig.statuses == []


def test_sandbox_settings_update_from_a_sender_without_get_settings_is_ignored(rig: _Rig) -> None:
    """A signal from an object that cannot report settings applies nothing.

    Args:
        rig: The window rig.
    """
    manager = rig.window.sandbox_manager
    timer = QTimer()
    try:
        _ = timer.timeout.connect(_priv(rig.window, "_on_sandbox_settings_updated"))
        with capture_logs() as captured:
            timer.timeout.emit()
        _ = drain_bridge_workers()
    finally:
        timer.deleteLater()

    assert len(_events(captured, "sandbox_settings_updated_sender_missing_get_settings")) == 1
    assert rig.window.sandbox_manager is manager
    assert rig.statuses == []


def test_sandbox_settings_update_with_a_payload_that_is_not_a_mapping_is_ignored(rig: _Rig) -> None:
    """A sender whose settings are not a dictionary applies nothing.

    Args:
        rig: The window rig.
    """

    def _populate(namespace: dict[str, Any]) -> None:
        """Give the monitor class a ``get_settings`` that returns a list.

        Args:
            namespace: The class namespace being built.
        """
        namespace["get_settings"] = _list_settings

    monitor_class = cast("type[SandboxMonitorWidget]", types.new_class("_ListSettingsMonitor", (SandboxMonitorWidget,), None, _populate))
    manager = rig.window.sandbox_manager
    monitor = monitor_class()
    try:
        _ = monitor.sandbox_stopped.connect(_priv(rig.window, "_on_sandbox_settings_updated"))
        with capture_logs() as captured:
            monitor.sandbox_stopped.emit()
        _ = drain_bridge_workers()
    finally:
        monitor.deleteLater()

    assert len(_events(captured, "sandbox_settings_updated_invalid_payload")) == 1
    assert rig.window.sandbox_manager is manager
    assert rig.statuses == []


@pytest.mark.parametrize("raiser", [_raise_runtime_error, _raise_attribute_error], ids=["runtime-error", "attribute-error"])
def test_apply_sandbox_settings_survives_a_manager_that_cannot_list_instances(
    rig: _Rig,
    qtbot: QtBot,
    raiser: Callable[[object], NoReturn],
) -> None:
    """A manager that cannot list its instances is treated as having none and is still rebuilt from the new settings.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the rebuild is reported.
        raiser: The failure the manager's ``instances`` property raises.
    """
    broken = _unlistable_manager(raiser)
    rig.window.sandbox_manager = broken

    with capture_logs() as captured:
        _call(rig.window, "_apply_sandbox_settings", {"timeout_seconds": 111})
        qtbot.waitUntil(lambda: "Sandbox settings applied" in rig.statuses, timeout=_WAIT_MS)

    assert len(_events(captured, "sandbox_instances_listing_failed")) == 1
    rebuilt = rig.window.sandbox_manager
    assert rebuilt is not broken
    assert _priv(rebuilt, "_default_config").timeout_seconds == 111


@pytest.mark.parametrize(
    ("kinds", "expected"),
    [
        (("match",), "Sandbox settings applied (0 of 1 instance(s) had stale config)"),
        (("match", "stale", "bare"), "Sandbox settings applied (2 of 3 instance(s) had stale config)"),
    ],
    ids=["all-current", "mixed"],
)
def test_apply_sandbox_settings_counts_the_instances_whose_config_is_stale(
    rig: _Rig,
    qtbot: QtBot,
    kinds: tuple[str, ...],
    expected: str,
) -> None:
    """The status line says how many live instances were built from a configuration other than the new one.

    An instance whose sandbox holds no configuration counts as stale. Every instance is torn down either way.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the rebuild is reported.
        kinds: ``"match"`` (same isolation settings), ``"stale"`` (other timeout) or ``"bare"`` (no configuration) per instance.
        expected: The status line the window must show.
    """
    matching = SandboxConfig(timeout_seconds=111, memory_limit_mb=1024, network_enabled=True, block_telemetry=False)
    other = SandboxConfig(timeout_seconds=222, memory_limit_mb=1024, network_enabled=True, block_telemetry=False)
    old_manager = SandboxManager()
    for kind in kinds:
        sandbox = WindowsSandbox(other if kind == "stale" else matching)
        if kind == "bare":
            _set_priv(sandbox, "_config", None)
        instance = SandboxInstance(sandbox, "windows")
        _priv(old_manager, "_instances")[instance.id] = instance
    rig.window.sandbox_manager = old_manager
    settings: dict[str, object] = {"timeout_seconds": 111, "memory_limit_mb": 1024, "network_enabled": True, "block_telemetry": False}

    _call(rig.window, "_apply_sandbox_settings", settings)
    qtbot.waitUntil(lambda: expected in rig.statuses, timeout=_WAIT_MS)

    assert old_manager.instances == []
    assert rig.window.sandbox_manager is not old_manager
    assert _priv(rig.window.sandbox_manager, "_default_config") == matching


def test_apply_sandbox_settings_still_rebuilds_when_the_teardown_fails(rig: _Rig, qtbot: QtBot) -> None:
    """A teardown that raises is logged and the manager is rebuilt from the new settings anyway.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the rebuild is reported.
    """
    rig.window.sandbox_manager = _RefusingManager()

    with capture_logs() as captured:
        _call(rig.window, "_apply_sandbox_settings", {"timeout_seconds": 111})
        qtbot.waitUntil(lambda: "Sandbox settings applied" in rig.statuses, timeout=_WAIT_MS)

    failures = _events(captured, "sandbox_manager_teardown_failed")
    assert [entry["error"] for entry in failures] == ["teardown refused"]
    assert type(rig.window.sandbox_manager) is SandboxManager
    assert _priv(rig.window.sandbox_manager, "_default_config").timeout_seconds == 111


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        (True, 7, 1),
        (False, 7, 0),
        (3.9, 7, 3),
        (42, 7, 42),
        ("  42 ", 5, 42),
        ("", 5, 5),
        ("   ", 5, 5),
        (None, 9, 9),
        (["x"], 9, 9),
    ],
)
def test_coerce_int_converts_what_it_can_and_defaults_the_rest(value: object, default: int, expected: int) -> None:
    """Booleans, numbers and numeric text become integers; anything else gives the default.

    Args:
        value: The raw setting.
        default: The fallback.
        expected: The integer ``int()`` of the same value gives, or the fallback.
    """
    assert _call(MainWindow, "_coerce_int", value, default) == expected


def test_coerce_int_logs_text_that_is_not_a_number() -> None:
    """Text that is not an integer gives the default and leaves a warning naming the text and the default."""
    with capture_logs() as captured:
        result = _call(MainWindow, "_coerce_int", "abc", 5)

    assert result == 5
    failures = _events(captured, "setting_int_coerce_failed")
    assert [(entry["raw_value"], entry["default"]) for entry in failures] == [("abc", 5)]


def test_sandbox_toggle_handler_sets_the_button_label(rig: _Rig) -> None:
    """The toggle handler writes ON or OFF into the toolbar button.

    Args:
        rig: The window rig.
    """
    button: QPushButton = _priv(rig.window, "_sandbox_btn")

    _call(rig.window, "_on_sandbox_toggled", checked=True)
    on_text = button.text()
    _call(rig.window, "_on_sandbox_toggled", checked=False)

    assert on_text == "Sandbox: ON"
    assert button.text() == "Sandbox: OFF"


@pytest.mark.parametrize(
    ("payload", "logged"),
    [
        ({"instance_id": "sb-1", "status": "running"}, ["sb-1"]),
        ({"status": "running"}, []),
    ],
    ids=["with-instance-id", "without-instance-id"],
)
def test_open_sandbox_wires_the_created_sandbox_into_the_window(
    rig: _Rig,
    qtbot: QtBot,
    payload: dict[str, Any],
    logged: list[str],
) -> None:
    """A created sandbox switches the toolbar button on, hands the bridge to the tool panel and reports it.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the sandbox is reported open.
        payload: What the bridge's ``create`` returns.
        logged: The instance ids the window is expected to log as opened.
    """
    bridge = _ScriptedSandboxBridge(available=True, payload=payload)
    rig.orchestrator.tool_registry.register_bridge(ToolName.SANDBOX, bridge)

    with capture_logs() as captured:
        _call(rig.window, "_on_open_sandbox")
        qtbot.waitUntil(lambda: "Sandbox opened" in rig.statuses, timeout=_WAIT_MS)

    assert rig.statuses == ["Opening sandbox...", "Sandbox opened"]
    button: QPushButton = _priv(rig.window, "_sandbox_btn")
    assert button.isChecked()
    assert button.text() == "Sandbox: ON"
    assert _priv(rig.window.tool_panel, "_pending_sandbox_bridge") is bridge
    assert [entry["instance_id"] for entry in _events(captured, "sandbox_opened_via_bridge")] == logged
    assert rig.warning.calls == []


def test_open_sandbox_without_a_backend_warns_and_leaves_the_button_off(rig: _Rig, qtbot: QtBot) -> None:
    """When no backend is available the operator is told so and nothing is wired.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the outcome is reported.
    """
    bridge = _ScriptedSandboxBridge(available=False, payload={})
    rig.orchestrator.tool_registry.register_bridge(ToolName.SANDBOX, bridge)

    _call(rig.window, "_on_open_sandbox")
    qtbot.waitUntil(lambda: "No sandbox available" in rig.statuses, timeout=_WAIT_MS)

    assert len(rig.warning.calls) == 1
    owner, title, text = rig.warning.calls[0]
    assert (owner, title) == (rig.window, "Sandbox Unavailable")
    assert text.startswith("No sandbox environment is available.")
    button: QPushButton = _priv(rig.window, "_sandbox_btn")
    assert not button.isChecked()
    assert _priv(rig.window.tool_panel, "_pending_sandbox_bridge") is None


def test_open_sandbox_failure_is_shown_as_an_error_dialog(rig: _Rig, qtbot: QtBot) -> None:
    """A sandbox that fails to be created is reported through a critical dialog with the error text.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the dialog is requested.
    """
    bridge = _ScriptedSandboxBridge(available=True, payload={}, failure="no hypervisor")
    rig.orchestrator.tool_registry.register_bridge(ToolName.SANDBOX, bridge)

    _call(rig.window, "_on_open_sandbox")
    qtbot.waitUntil(lambda: bool(rig.critical.calls), timeout=_WAIT_MS)

    assert rig.critical.calls == [(rig.window, "Error", "no hypervisor")]
    assert rig.statuses == ["Opening sandbox..."]
    button: QPushButton = _priv(rig.window, "_sandbox_btn")
    assert not button.isChecked()


def test_preferences_changed_with_a_new_theme_applies_it(rig: _Rig) -> None:
    """Applying preferences that name another theme switches the application to it and announces the change.

    Args:
        rig: The window rig.
    """
    manager = ThemeManager.get_instance()
    assert manager.apply_theme("dark")
    new_config = dataclasses.replace(rig.config, ui=dataclasses.replace(rig.config.ui, theme="light"))

    with capture_logs() as captured:
        _call(rig.window, "_on_preferences_changed", new_config)

    assert manager.current_theme == "light"
    assert [entry["theme"] for entry in _events(captured, "preferences_theme_changed")] == ["light"]
    assert _priv(rig.window, "_config") is new_config
    assert rig.statuses == ["Preferences applied"]


def test_preferences_changed_with_the_same_theme_leaves_the_theme_alone(rig: _Rig) -> None:
    """Applying preferences with an unchanged theme does not re-apply it.

    Args:
        rig: The window rig.
    """
    manager = ThemeManager.get_instance()
    assert manager.apply_theme("dark")
    new_config = dataclasses.replace(rig.config, ui=dataclasses.replace(rig.config.ui, font_size=rig.config.ui.font_size + 1))

    with capture_logs() as captured:
        _call(rig.window, "_on_preferences_changed", new_config)

    assert manager.current_theme == "dark"
    assert _events(captured, "preferences_theme_changed") == []
    assert rig.statuses == ["Preferences applied"]


def test_preferences_dialog_ok_saves_the_chosen_theme(rig: _Rig) -> None:
    """Pressing OK in the preferences dialog applies the chosen theme, saves it to ``config.toml`` and announces it.

    Args:
        rig: The window rig.
    """
    manager = ThemeManager.get_instance()
    assert manager.apply_theme("dark")

    with _drive_modals(_choose_light_theme_and_confirm) as seen:
        _call(rig.window, "_on_preferences")

    assert len(seen) == 1
    assert isinstance(seen[0], PreferencesDialog)
    assert manager.current_theme == "light"
    assert _priv(rig.window, "_config").ui.theme == "light"
    _assert_in_order(rig.statuses, ["Preferences applied", "Preferences saved"])
    saved = tomllib.loads(get_config_file("config.toml").read_text(encoding="utf-8"))
    assert saved["ui"]["theme"] == "light"


def test_toggle_theme_switches_between_dark_and_light(rig: _Rig) -> None:
    """The Toggle Theme action flips dark to light and back, announcing each result.

    Args:
        rig: The window rig.
    """
    manager = ThemeManager.get_instance()
    assert manager.apply_theme("dark")

    _call(rig.window, "_on_toggle_theme")
    first = manager.current_theme
    _call(rig.window, "_on_toggle_theme")

    assert first == "light"
    assert manager.current_theme == "dark"
    assert rig.statuses == ["Theme switched to light", "Theme switched to dark"]


def test_theme_change_rehighlights_the_code_on_the_active_tab(rig: _Rig) -> None:
    """When the theme changes, the highlighter of the code display on the active tab is asked to highlight the whole document again.

    Args:
        rig: The window rig.
    """
    container = QWidget()
    layout = QVBoxLayout(container)
    editor = QPlainTextEdit(container)
    layout.addWidget(editor)
    document = editor.document()
    assert document is not None
    highlighter = _CountingHighlighter(document)
    editor.setPlainText("int a;\nint b;")
    _ = rig.window.tool_panel.tab_widget.addTab(container, "Code")
    rig.window.tool_panel.tab_widget.setCurrentWidget(container)
    assert isinstance(rig.window.tool_panel.get_code_highlighter(), QSyntaxHighlighter)
    highlighter.blocks_seen = 0

    _call(rig.window, "_on_theme_changed", "dark")

    assert highlighter.blocks_seen >= document.blockCount()


def test_focus_chat_input_moves_focus_to_the_chat_text_box(rig: _Rig, qapp: QApplication) -> None:
    """The Focus Chat Input action makes the chat text box the window's focus widget.

    Args:
        rig: The window rig.
        qapp: The shared offscreen application.
    """
    rig.window.show()
    qapp.processEvents()
    chat_input = rig.window.findChild(QTextEdit, "chat_input_textedit")
    assert chat_input is not None
    rig.window.model_combo.setFocus()
    assert rig.window.focusWidget() is not chat_input

    _call(rig.window, "_on_focus_chat_input")

    assert rig.window.focusWidget() is chat_input


def test_log_viewer_slot_opens_the_viewer(rig: _Rig) -> None:
    """The Help menu's Log Viewer slot opens a visible viewer window.

    Args:
        rig: The window rig.
    """
    assert rig.window.log_viewer_window is None

    _call(rig.window, "_on_log_viewer")

    viewer = rig.window.log_viewer_window
    assert isinstance(viewer, LogViewerWindow)
    assert viewer.isVisible()


@pytest.mark.parametrize("case", _TOOL_CASES)
def test_opening_a_tool_starts_it(rig: _Rig, qtbot: QtBot, case: _ToolCase) -> None:
    """Opening an embedded tool whose panel exists starts that panel and shows no error.

    Args:
        rig: The window rig.
        qtbot: Waits for the panel's started signal.
        case: The tool under test.
    """
    panel = case.panel_class()
    _add_to_tabs(rig.window, case.attribute, panel, case.title)

    with qtbot.waitSignal(_priv(panel, "tool_started"), timeout=_WAIT_MS):
        _call(rig.window, case.method)
    _ = drain_bridge_workers()

    assert rig.warning.calls == []


@pytest.mark.parametrize("case", _TOOL_CASES)
def test_opening_a_tool_whose_panel_cannot_start_shows_an_error(rig: _Rig, case: _ToolCase) -> None:
    """A panel that refuses to start is reported in a warning titled after the tool, with the panel's own error text.

    Args:
        rig: The window rig.
        case: The tool under test.
    """
    panel = _refusing_panel(case.panel_class)
    _add_to_tabs(rig.window, case.attribute, panel, case.title)

    with capture_logs() as captured:
        _call(rig.window, case.method)
    _ = drain_bridge_workers()

    assert rig.warning.calls == [
        (rig.window, f"{case.title} Error", f"Failed to open {case.failure} panel: start refused", _OK),
    ]
    assert [entry["tool_name"] for entry in _events(captured, "tool_open_failed")] == [case.title.replace("Hex Editor", "HexEditor")]


def test_opening_cutter_hands_it_the_loaded_binary(rig: _Rig) -> None:
    """With a binary loaded, a freshly opened Cutter panel is offered that binary.

    Args:
        rig: The window rig.
    """
    binary = _write_binary(rig.tmp_path / "sample.bin")
    rig.window.current_binary = binary
    panel = CutterPanel()
    _add_to_tabs(rig.window, "_cutter_widget", panel, "Cutter")

    with capture_logs() as captured:
        _call(rig.window, "_on_open_cutter")

    offered = [entry for entry in _events(captured, "cutter_inherit_app_binary") if "binary" in entry]
    assert [entry["binary"] for entry in offered] == [str(binary)]
    received = [entry for entry in _events(captured, "cutter_inherit_app_binary") if "path" in entry]
    assert [entry["path"] for entry in received] == [str(binary)]
    assert rig.warning.calls == []


@pytest.mark.parametrize("binary_loaded", [True, False], ids=["binary-loaded", "no-binary"])
def test_inheriting_the_binary_needs_both_a_binary_and_the_hook(rig: _Rig, *, binary_loaded: bool) -> None:
    """A panel without the inherit hook, or an application without a binary, is left alone.

    Args:
        rig: The window rig.
        binary_loaded: Whether the application has a loaded binary.
    """
    if binary_loaded:
        rig.window.current_binary = _write_binary(rig.tmp_path / "sample.bin")
    hookless = QWidget()
    cutter = CutterPanel()
    try:
        with capture_logs() as captured:
            _call(rig.window, "_inherit_app_binary_into_cutter", hookless)
            _call(rig.window, "_inherit_app_binary_into_cutter", cutter if not binary_loaded else hookless)
    finally:
        hookless.deleteLater()
        cutter.deleteLater()

    assert _events(captured, "cutter_inherit_app_binary") == []


def test_opening_the_process_panel_wires_attach_once(rig: _Rig, qtbot: QtBot) -> None:
    """Opening the Process panel twice connects its attach signal once, so one attach starts one region listing.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the failed listing is reported.
    """
    panel = ProcessPanel()
    _add_to_tabs(rig.window, "_process_panel", panel, "Process")

    _call(rig.window, "_on_open_process")
    _call(rig.window, "_on_open_process")

    wired = list(_priv(rig.window, "_process_attached_wired"))
    assert wired == [panel]
    with capture_logs() as captured:
        panel.process_attached.emit(_BAD_PID)
        qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
        _ = drain_bridge_workers()
    assert len(_events(captured, "generic_callable_worker_failed")) == 1
    assert len(rig.warning.calls) == 1


def test_open_sandbox_panel_reports_an_unavailable_sandbox(rig: _Rig) -> None:
    """On a host without Windows Sandbox the Sandbox panel cannot be built and the operator is told.

    Args:
        rig: The window rig.
    """
    with _sandbox_unavailable():
        _call(rig.window, "_on_open_sandbox_panel")

    assert rig.window.tool_panel.sandbox_panel is None
    assert rig.warning.calls == [(rig.window, "Sandbox Error", "Failed to initialize Sandbox panel", _OK)]


def test_sandbox_monitor_is_wired_only_once(rig: _Rig) -> None:
    """Wiring the same sandbox panel twice connects each monitor's stop signal once.

    Args:
        rig: The window rig.
    """
    container = QWidget()
    try:
        monitor = SandboxMonitorWidget(parent=container)
        _call(rig.window, "_wire_sandbox_monitor_widgets", container)
        _call(rig.window, "_wire_sandbox_monitor_widgets", container)

        monitor.sandbox_stopped.emit()
    finally:
        container.deleteLater()

    assert rig.statuses == ["Sandbox stopped"]


def test_full_analysis_without_a_binary_asks_for_one(rig: _Rig) -> None:
    """Running the full analysis with nothing loaded shows the no-binary notice and starts nothing.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_run_full_analysis")

    assert rig.information.calls == [
        (rig.window, "No Binary Loaded", "Please load a binary first before attempting to analyze it.", _OK),
    ]
    assert rig.statuses == []


def test_full_analysis_done_with_a_complete_summary_reports_success(rig: _Rig) -> None:
    """A summary that says a backend contributed data is announced as complete, without a warning.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_full_analysis_done", _summary(complete=True))

    assert rig.statuses == ["Full analysis complete"]
    assert rig.warning.calls == []


def test_open_binary_in_ghidra_without_a_binary_asks_for_one(rig: _Rig) -> None:
    """Opening the loaded binary in Ghidra with nothing loaded shows the no-binary notice.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_open_binary_in_ghidra")

    assert rig.information.calls == [
        (rig.window, "No Binary Loaded", "Please load a binary first before attempting to Ghidra analysis it.", _OK),
    ]


def test_open_binary_in_ghidra_reports_a_panel_that_cannot_load_it(rig: _Rig) -> None:
    """A Ghidra panel with no connected bridge cannot take the binary, and the operator is told.

    Args:
        rig: The window rig.
    """
    rig.window.current_binary = _write_binary(rig.tmp_path / "sample.bin")
    _add_to_tabs(rig.window, "_ghidra_widget", GhidraPanel(), "Ghidra")

    with capture_logs() as captured:
        _call(rig.window, "_on_open_binary_in_ghidra")

    assert [entry["binary"] for entry in _events(captured, "open_binary_in_ghidra_requested")] == [str(rig.window.current_binary)]
    assert rig.warning.calls == [(rig.window, "Ghidra Error", "Failed to open binary in Ghidra", _OK)]


@pytest.mark.parametrize(
    "entry",
    [
        [1, 2, 3, 4],
        "regions",
        (1, 2, 3),
        (1, 2, 3, 4, 5),
        (1, 2, "3", 4),
        (1, 2, 3, 4.0),
        None,
    ],
    ids=["list", "string", "too-short", "too-long", "text-member", "float-member", "none"],
)
def test_coerce_memory_region_rejects_what_is_not_four_integers(entry: object) -> None:
    """Only a tuple of exactly four integers is a memory region.

    Args:
        entry: A malformed worker entry.
    """
    assert _call(MainWindow, "_coerce_memory_region", entry) is None


def test_coerce_memory_region_keeps_a_valid_region() -> None:
    """A four-integer tuple is returned unchanged."""
    region = (_COMMITTED_BASE, _COMMITTED_SIZE, _PAGE_EXECUTE_READWRITE, _MEM_COMMIT_STATE)

    assert _call(MainWindow, "_coerce_memory_region", region) == region


def test_failed_region_listing_is_logged_and_shown(rig: _Rig) -> None:
    """A region listing that failed is logged with its error and shown in a warning that names it.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured:
        _call(rig.window, "_on_process_regions_failed", _PID, RuntimeError("scan refused"))

    failures = _events(captured, "process_regions_list_failed")
    assert [(entry["pid"], entry["error"]) for entry in failures] == [(_PID, "scan refused")]
    assert rig.warning.calls == [(rig.window, "Process Memory", "Failed to list memory regions: scan refused")]


@pytest.mark.parametrize(
    "result",
    [object(), [], [(1, 2, 3)], ["junk", (1, "2", 3, 4)]],
    ids=["not-a-list", "empty", "short-tuple", "only-junk"],
)
def test_region_picker_is_not_opened_when_nothing_is_listed(rig: _Rig, result: object) -> None:
    """When no usable region comes back, the operator is told so instead of getting an empty picker.

    Args:
        rig: The window rig.
        result: What the listing worker returned.
    """
    with _drive_modals(_reject_dialog) as seen:
        _call(rig.window, "_on_process_regions_listed", _PID, result)

    assert seen == []
    assert rig.information.calls == [(rig.window, "Process Memory", f"No readable memory regions found for PID {_PID}.")]


def test_cancelling_the_region_picker_opens_nothing(rig: _Rig) -> None:
    """Cancelling the picker never reaches the hex editor.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured, _drive_modals(_reject_dialog) as seen:
        _call(rig.window, "_on_process_regions_listed", _PID, _REGIONS)

    assert _dialog_titles(seen) == [f"Memory Regions - PID {_PID}"]
    assert _events(captured, "hex_bridge_unavailable_for_process_memory") == []


def test_region_picker_with_nothing_selected_opens_nothing(rig: _Rig) -> None:
    """Accepting a picker whose table has no row to select never reaches the hex editor.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured, _drive_modals(_empty_table_then_accept) as seen:
        _call(rig.window, "_on_process_regions_listed", _PID, _REGIONS)

    assert len(seen) == 1
    assert _events(captured, "hex_bridge_unavailable_for_process_memory") == []


def test_accepting_the_region_picker_without_a_hex_bridge_logs_it(rig: _Rig) -> None:
    """Accepting the picker when no hex editor bridge exists logs that and opens nothing.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured, _drive_modals(_accept_dialog):
        _call(rig.window, "_on_process_regions_listed", _PID, _REGIONS)

    assert [entry["pid"] for entry in _events(captured, "hex_bridge_unavailable_for_process_memory")] == [_PID]


def test_accepting_the_region_picker_opens_the_default_committed_region(rig: _Rig, qtbot: QtBot) -> None:
    """Accepting the picker opens the first committed readable region, not the free region listed before it.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the hex editor bridge is asked to open the region.
    """
    bridge = _RecordingHexBridge()
    rig.orchestrator.tool_registry.register_bridge(ToolName.HEX_EDITOR, bridge)

    with _drive_modals(_accept_dialog):
        _call(rig.window, "_on_process_regions_listed", _PID, _REGIONS)
    qtbot.waitUntil(lambda: bool(bridge.opened), timeout=_WAIT_MS)
    _ = drain_bridge_workers()

    assert bridge.opened == [(_PID, _COMMITTED_BASE, _COMMITTED_SIZE)]


def test_opening_process_memory_that_cannot_be_read_warns(rig: _Rig, qtbot: QtBot) -> None:
    """A process the native layer cannot read is reported with the failure text, and the failure is logged.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the warning is shown.
    """
    rig.orchestrator.tool_registry.register_bridge(ToolName.HEX_EDITOR, HexEditorBridge())

    with capture_logs() as captured:
        _call(rig.window, "_open_process_memory", _BAD_PID, 0x1000, 0x10)
        qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
        _ = drain_bridge_workers()

    assert len(rig.warning.calls) == 1
    owner, title, text = rig.warning.calls[0]
    assert (owner, title) == (rig.window, "Process Memory")
    assert text.startswith("Failed to open memory: ")
    assert [entry["pid"] for entry in _events(captured, "process_memory_open_failed")] == [_BAD_PID]


def test_a_superseded_region_listing_is_dropped(rig: _Rig, qtbot: QtBot, qapp: QApplication) -> None:
    """When a second attach replaces a listing still in flight, only the second listing is shown.

    The first listing is for this process and would open the picker; the second is for a process that does not exist and fails. Only
    the failure may reach the operator.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the failure is shown.
        qapp: The shared offscreen application.
    """
    with _drive_modals(_reject_dialog) as seen:
        _call(rig.window, "_on_process_attached", os.getpid())
        _call(rig.window, "_on_process_attached", _BAD_PID)
        qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
        _ = drain_bridge_workers()
        qapp.processEvents()

    assert seen == []
    assert len(rig.warning.calls) == 1
    assert rig.warning.calls[0][:2] == (rig.window, "Process Memory")
    assert rig.information.calls == []


def test_a_superseded_region_failure_is_dropped(rig: _Rig, qtbot: QtBot, qapp: QApplication) -> None:
    """When a second attach replaces a failing listing still in flight, only the second listing is shown.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the picker opens.
        qapp: The shared offscreen application.
    """
    own_pid = os.getpid()
    with _drive_modals(_reject_dialog) as seen:
        _call(rig.window, "_on_process_attached", _BAD_PID)
        _call(rig.window, "_on_process_attached", own_pid)
        qtbot.waitUntil(lambda: bool(seen), timeout=_WAIT_MS)
        _ = drain_bridge_workers()
        qapp.processEvents()

    assert _dialog_titles(seen) == [f"Memory Regions - PID {own_pid}"]
    assert rig.warning.calls == []


def test_provider_prompt_offers_configure_and_cancel(rig: _Rig) -> None:
    """The not-connected prompt names the provider, defaults to Configure Now, and returns the pressed choice.

    Args:
        rig: The window rig.
    """
    configure_view: dict[str, object] = {}
    with _drive_modals(_press(QMessageBox.ButtonRole.AcceptRole, configure_view)):
        configure = _call(rig.window, "_prompt_provider_not_connected", "Acme")
    with _drive_modals(_press(QMessageBox.ButtonRole.RejectRole)):
        cancel = _call(rig.window, "_prompt_provider_not_connected", "Acme")

    assert configure == "configure"
    assert cancel == "cancel"
    assert configure_view == {
        "title": "Provider Not Connected",
        "text": "Provider 'Acme' is not connected.\n\nConfigure its credentials now, or cancel and stay on the previously active provider.",
        "icon": QMessageBox.Icon.Warning,
        "default": "Configure Now...",
    }


def test_provider_change_with_invalid_toolbar_data_is_ignored(rig: _Rig) -> None:
    """A toolbar entry whose data is not a provider id changes nothing.

    Args:
        rig: The window rig.
    """
    combo = _combo(rig.window, "_provider_combo")
    combo.addItem("Odd provider", 5)
    with QSignalBlocker(combo):
        combo.setCurrentIndex(combo.count() - 1)

    with capture_logs() as captured:
        _call(rig.window, "_on_provider_changed", combo.currentIndex())

    assert len(_events(captured, "provider_changed_invalid_data")) == 1
    assert rig.orchestrator.provider_registry.active is None
    assert rig.statuses == []


def test_cancelling_the_not_connected_prompt_restores_the_active_provider(rig: _Rig, gateway: ConfigurableProvider) -> None:
    """Choosing a provider that is not connected and then cancelling puts the toolbar back on the active provider.

    Args:
        rig: The window rig.
        gateway: The connected loopback provider, listed in the toolbar.
    """
    registry = rig.orchestrator.provider_registry
    idle = ConfigurableProvider(
        ProviderInstance(instance_id="idle-gw", display_name="Idle Gateway", api_base="http://127.0.0.1:9/v1", requires_api_key=False),
    )
    try:
        registry.register(idle)
        _call(rig.window, "_populate_provider_combo")
        registry.set_active(_GATEWAY_ID)
        combo = _combo(rig.window, "_provider_combo")
        assert not idle.is_connected
        _select_provider(rig.window, "idle-gw")
        shown_name = combo.currentText()

        with _drive_modals(_press(QMessageBox.ButtonRole.RejectRole)) as seen:
            _call(rig.window, "_on_provider_changed", combo.currentIndex())

        assert len(seen) == 1
        assert combo.currentData() == _GATEWAY_ID
        assert registry.active is gateway
        assert rig.statuses == [f"Provider {shown_name} selected but not connected. Configure credentials in Providers menu."]
    finally:
        unregister_instance_mapping("idle-gw")


@pytest.mark.parametrize("editable", [True, False], ids=["editable-combo", "plain-combo"])
def test_provider_change_fills_the_model_combo_from_the_cache(rig: _Rig, gateway: ConfigurableProvider, *, editable: bool) -> None:
    """Switching to a connected provider with a cached catalog replaces the model list, editable combo or not.

    Args:
        rig: The window rig.
        gateway: The connected loopback provider, listed in the toolbar.
        editable: Whether the model combo accepts typed text.
    """
    del gateway
    discovery = ModelDiscovery(rig.orchestrator.provider_registry)
    rig.window.set_model_discovery(discovery)
    _set_priv(rig.window, "_initial_discovery_triggered", value=True)
    discovery.cache.set(_GATEWAY_ID, [_model("zz-model-a"), _model("zz-model-b")])
    rig.window.model_combo.addItem("outgoing-model")
    rig.window.model_combo.setEditable(editable)
    _select_provider(rig.window, _GATEWAY_ID)

    _call(rig.window, "_on_provider_changed", _combo(rig.window, "_provider_combo").currentIndex())

    assert _model_items(rig.window) == ["zz-model-a", "zz-model-b"]
    assert rig.window.model_combo.currentText() == "zz-model-a"
    line_edit = rig.window.model_combo.lineEdit()
    assert (line_edit is not None) is editable
    if line_edit is not None:
        assert line_edit.cursorPosition() == 0
    assert rig.statuses == [f"Active provider: {_GATEWAY_ID}"]


def _load_hex_panel(rig: _Rig) -> HexEditorPanel:
    """Install a real hex editor panel holding a document with an unsaved edit.

    Args:
        rig: The window rig.

    Returns:
        HexEditorPanel: The panel, now installed as the tool panel's hex editor.
    """
    panel = HexEditorPanel()
    document = intellicrack_hexcore.HexDocument.open_bytes(_WORK_STATE)
    document.write_bytes(0, b"\xff")
    panel.document = document
    _add_to_tabs(rig.window, "_hex_editor_panel", panel, "Hex Editor")
    assert rig.window.tool_panel.has_unsaved_changes()
    return panel


def test_closing_with_unsaved_hex_edits_can_be_cancelled(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answering Cancel to the unsaved-changes question keeps the window open and everything running.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_hex_panel(rig)
    target = rig.tmp_path / "never.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Cancel))

    closed = rig.window.close()

    assert closed is False
    assert _priv(rig.window, "_shutting_down") is False
    assert rig.window.tool_panel.has_unsaved_changes()
    assert not target.exists()
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Discard))
    assert rig.window.close()


def test_close_handler_without_an_event_object_still_honors_the_answer(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Called with no event object, the close handler still stops on Cancel and still shuts down on Discard.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_hex_panel(rig)
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Cancel))

    rig.window.closeEvent(None)

    assert _priv(rig.window, "_shutting_down") is False
    assert rig.window.tool_panel.has_unsaved_changes()
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Discard))

    rig.window.closeEvent(None)

    assert _priv(rig.window, "_shutting_down") is True
    assert not rig.window.tool_panel.has_unsaved_changes()


def test_closing_and_discarding_hex_edits_writes_nothing(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answering Discard closes the window without saving the edit.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_hex_panel(rig)
    target = rig.tmp_path / "discarded.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Discard))

    closed = rig.window.close()

    assert closed is True
    assert _priv(rig.window, "_shutting_down") is True
    assert not target.exists()


def test_closing_and_saving_hex_edits_writes_the_edited_bytes(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answering Save writes the edited document to the chosen file before the window closes.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_hex_panel(rig)
    target = rig.tmp_path / "saved.bin"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Save))

    closed = rig.window.close()

    assert closed is True
    assert target.read_bytes() == _EDITED_STATE


def test_closing_survives_a_viewer_whose_window_is_already_gone(rig: _Rig, qapp: QApplication) -> None:
    """A log viewer that was destroyed behind the window's back is logged, not raised, when the window closes.

    Args:
        rig: The window rig.
        qapp: The shared offscreen application.
    """
    viewer = rig.window.open_log_viewer()
    viewer.deleteLater()
    qapp.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)

    with capture_logs() as captured:
        closed = rig.window.close()

    assert closed is True
    failures = _events(captured, "log_viewer_close_failed")
    assert len(failures) == 1
    assert "has been deleted" in str(failures[0]["error"])
    assert rig.window.log_viewer_window is None


def test_closing_survives_a_sandbox_manager_that_cannot_tear_down(rig: _Rig) -> None:
    """A sandbox manager whose teardown fails is logged, and the window still closes.

    Args:
        rig: The window rig.
    """
    rig.window.sandbox_manager = _RefusingManager()

    with capture_logs() as captured:
        closed = rig.window.close()

    assert closed is True
    failures = _events(captured, "sandbox_manager_destroy_all_failed")
    assert [entry["error"] for entry in failures] == ["teardown refused"]
