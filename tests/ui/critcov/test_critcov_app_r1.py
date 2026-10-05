# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the main window: startup faults, status refresh faults, tool-panel failures and accepted settings dialogs.

Every test drives a real ``MainWindow`` over a real ``Orchestrator``, ``SessionManager`` with a SQLite store and ``ProviderRegistry``. State
that production binds to the user's configuration (the state root, the Qt settings store, the provider-settings file, and the
``SandboxConfigDialog`` class attributes ``CONFIG_DIR`` and ``CONFIG_FILE``) is redirected into the test's temporary directory before any
window or dialog is built. Collaborators that must fail are real product classes subclassed to fail once (a provider whose connection drops
between two reads, a model cache that refuses to resize or report its usage, a model-discovery service and an MCP service that raise, and a
tool panel that cannot build its tabs). The modal dialogs the window opens itself are real dialogs closed from inside their own event loop by
the ``DialogWatcher`` helper, which rejects or accepts them, and every worker is drained before a dialog is deleted.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Any, NamedTuple, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QShowEvent
from PyQt6.QtWidgets import QApplication, QDialog, QLabel, QMessageBox, QSplitter, QWidget
from structlog.testing import capture_logs

from intellicrack.bridges.base import BridgeState
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.config import Config, UIConfig
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import Message, ModelInfo, ProviderCredentials, ToolCall
from intellicrack.mcp.errors import McpError
from intellicrack.providers import (
    ids as provider_ids,
    model_loader,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.model_loader import ModelCache
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import sandbox_config
from intellicrack.ui.app import MainWindow
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_service import McpService
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, ensure_loop, run_bridge_coroutine
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.provider_config import ProviderConfigDialog
from intellicrack.ui.sandbox_config import SandboxConfigDialog
from intellicrack.ui.tools import ToolOutputPanel
from tests._helpers.mcp_ui_support import DialogWatcher
from tests._helpers.private_keyring import installed_keyring, private_file_keyring
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Generator, Mapping, Sequence
    from pathlib import Path

    from keyring.backend import KeyringBackend
    from pytestqt.qtbot import QtBot

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition
    from intellicrack.sandbox import SandboxConfig


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_BRIDGE_TIMEOUT_S: float = 60.0
_WAIT_MS: int = 30_000
_WINDOW_WIDTH: int = 1600
_WINDOW_HEIGHT: int = 900
_SETTLE_PASSES: int = 8
_OK: QMessageBox.StandardButton = QMessageBox.StandardButton.Ok
_SELECTED_PID: int = 4242
_TIMEOUT_SECONDS: int = 123
_MEMORY_MB: int = 1024
_PAIR_OF_APPLIES: int = 2
_SENTINEL_MODEL: str = "sentinel-model"


class _ScriptedProvider(LLMProviderBase):
    """Real provider that connects and lists no models."""

    def __init__(self, provider_name: str) -> None:
        """Create the provider.

        Args:
            provider_name: Instance id the provider reports.
        """
        super().__init__()
        self._name = provider_name

    @property
    @override
    def name(self) -> str:
        """The instance id this provider reports.

        Returns:
            str: The instance id.
        """
        return self._name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect with the given credentials.

        Args:
            credentials: Credentials the caller connects with.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Advertise no models.

        Returns:
            list[ModelInfo]: An empty list.
        """
        return []

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return a fixed assistant reply.

        Args:
            messages: Conversation history (unused).
            model: Model id (unused).
            tools: Tool definitions (unused).
            temperature: Sampling temperature (unused).
            max_tokens: Token limit (unused).
            tool_choice: Tool selection directive (unused).
            thinking: Thinking configuration (unused).
            enable_cache: Prompt caching flag (unused).

        Returns:
            tuple[Message, list[ToolCall] | None]: A reply and no tool calls.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        return Message(role="assistant", content="reply"), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield one fixed chunk.

        Args:
            messages: Conversation history (unused).
            model: Model id (unused).
            tools: Tool definitions (unused).
            temperature: Sampling temperature (unused).
            max_tokens: Token limit (unused).
            tool_choice: Tool selection directive (unused).
            thinking: Thinking configuration (unused).
            enable_cache: Prompt caching flag (unused).

        Yields:
            str: One text chunk.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        yield "reply"

    @override
    def _convert_tools_to_provider_format(self, tools: list[ToolDefinition]) -> list[dict[str, object]]:
        """Convert no tools.

        Args:
            tools: Tool definitions (unused).

        Returns:
            list[dict[str, object]]: An empty list.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(self, messages: list[Message]) -> list[dict[str, object]]:
        """Pass role and content through.

        Args:
            messages: Conversation history.

        Returns:
            list[dict[str, object]]: Role and content dictionaries.
        """
        return [{"role": message.role, "content": message.content} for message in messages]


class _FlakyProvider(_ScriptedProvider):
    """A scripted provider that reports itself connected for one read after connecting, then reports a dropped connection.

    Attributes:
        reads_before_drop: Reads of ``is_connected`` still answered from the real state, or ``None`` before the provider has connected.
    """

    reads_before_drop: int | None

    def __init__(self, provider_name: str) -> None:
        """Create the provider.

        Args:
            provider_name: Instance id the provider reports.
        """
        super().__init__(provider_name)
        self.reads_before_drop = None

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect, then arm the dropped connection.

        Args:
            credentials: Credentials the caller connects with.
        """
        await super().connect(credentials)
        self.reads_before_drop = 1

    @property
    @override
    def is_connected(self) -> bool:
        """Report the connection, which drops after the armed number of reads.

        Returns:
            bool: The real state while reads remain, otherwise ``False``.
        """
        if self.reads_before_drop is None:
            return self.connected
        if self.reads_before_drop > 0:
            self.reads_before_drop -= 1
            return self.connected
        return False


class _FaultyCache(ModelCache):
    """A real model cache that refuses to be resized and cannot report its usage."""

    @property
    @override
    def max_memory_bytes(self) -> int:
        """The maximum memory limit.

        Returns:
            int: The limit the cache was built with.
        """
        return self._max_memory_bytes

    @max_memory_bytes.setter
    def max_memory_bytes(self, value: int) -> None:
        """Refuse every resize.

        Args:
            value: Requested limit.

        Raises:
            ValueError: Always.
        """
        message = f"cache size {value} refused"
        raise ValueError(message)

    @override
    def get_memory_usage(self) -> int:
        """Refuse to report usage.

        Returns:
            int: Never returned.

        Raises:
            RuntimeError: Always.
        """
        message = "usage unavailable"
        raise RuntimeError(message)


class _BrokenDiscovery(ModelDiscovery):
    """A real model-discovery service whose event history cannot be read."""

    @override
    def get_discovery_events(self, limit: int | None = None) -> list[Any]:
        """Refuse to return the history.

        Args:
            limit: Maximum number of events (unused).

        Returns:
            list[Any]: Never returned.

        Raises:
            RuntimeError: Always.
        """
        del limit
        message = "history unavailable"
        raise RuntimeError(message)


class _FaultyMcpService(McpService):
    """A real MCP service whose shutdown fails and whose tool sources cannot be resolved."""

    @override
    async def stop(self) -> None:
        """Refuse to stop.

        Raises:
            RuntimeError: Always.
        """
        message = "stop refused"
        raise RuntimeError(message)

    @override
    def generation_for(self, call: ToolCall) -> str | None:
        """Refuse to resolve the approval key.

        Args:
            call: The tool call (unused).

        Returns:
            str | None: Never returned.

        Raises:
            McpError: Always.
        """
        del call
        message = "server registry unreadable"
        raise McpError(message)


class _PanelWithoutTabs(ToolOutputPanel):
    """A real tool output panel whose Ghidra, Frida and Process tabs cannot be built."""

    @override
    def add_ghidra_tab(self) -> None:
        """Report that the tab could not be created."""

    @override
    def add_frida_tab(self) -> None:
        """Report that the tab could not be created."""

    @override
    def add_process_tab(self) -> None:
        """Report that the tab could not be created."""


class _Recorders(NamedTuple):
    """Recorders installed over the static message-box functions.

    Attributes:
        information: Recorder over ``QMessageBox.information``.
        warning: Recorder over ``QMessageBox.warning``.
        critical: Recorder over ``QMessageBox.critical``.
    """

    information: DialogRecorder
    warning: DialogRecorder
    critical: DialogRecorder


class _ToolCase(NamedTuple):
    """One tool whose panel cannot be built.

    Attributes:
        method: Name of the window handler that opens the tool.
        title: Tool name used in the error dialog title.
        text: Message the error dialog shows.
    """

    method: str
    title: str
    text: str


_TOOL_CASES: list[Any] = [
    pytest.param(_ToolCase("_on_open_ghidra", "Ghidra", "Failed to initialize Ghidra panel"), id="ghidra"),
    pytest.param(_ToolCase("_on_open_frida", "Frida", "Failed to initialize Frida panel"), id="frida"),
    pytest.param(_ToolCase("_on_open_process", "Process", "Failed to initialize Process panel"), id="process"),
]


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, *, value: object) -> None:
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


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structured-log entries by event name.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The entries logged under that event.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _status_log(window: MainWindow) -> list[str]:
    """Record every status message the window emits from now on.

    Args:
        window: The window.

    Returns:
        list[str]: The list the messages are appended to.
    """
    statuses: list[str] = []
    _ = window.status_update.connect(statuses.append)
    return statuses


def _settings() -> QSettings:
    """Open the same user-scope store the main window persists to.

    Returns:
        QSettings: The ``Intellicrack/MainWindow`` store.
    """
    return QSettings(QSettings.defaultFormat(), QSettings.Scope.UserScope, "Intellicrack", "MainWindow")


def _settle(qapp: QApplication) -> None:
    """Pump the event loop until a cascaded resize has propagated.

    Args:
        qapp: The application.
    """
    for _ in range(_SETTLE_PASSES):
        qapp.processEvents()


def _show(window: MainWindow, qapp: QApplication) -> None:
    """Size a window, show it and let its layout settle.

    Args:
        window: The window.
        qapp: The application.
    """
    window.resize(_WINDOW_WIDTH, _WINDOW_HEIGHT)
    window.show()
    _settle(qapp)


async def _new_future() -> asyncio.Future[bool]:
    """Create a pending future on the running loop.

    Returns:
        asyncio.Future[bool]: The future.
    """
    await asyncio.sleep(0)
    return asyncio.get_running_loop().create_future()


async def _await_future(future: asyncio.Future[bool]) -> bool:
    """Wait for a future.

    Args:
        future: The future.

    Returns:
        bool: Its result.
    """
    return await future


def _add_to_tabs(window: MainWindow, attribute: str, panel: QWidget, title: str) -> None:
    """Install a real panel in one of the tool panel's tool slots and its tab strip.

    Args:
        window: The main window.
        attribute: Name of the tool panel's private slot.
        panel: The panel to install.
        title: Tab title.
    """
    _set_priv(window.tool_panel, attribute, value=panel)
    _ = window.tool_panel.tab_widget.addTab(panel, title)


@contextlib.contextmanager
def _installed_cache(cache: ModelCache) -> Generator[None]:
    """Make a model cache the process-wide one, then restore the previous one.

    Args:
        cache: The cache to install.

    Yields:
        None: Control passes to the body.
    """
    state = cast("dict[str, ModelCache]", getattr(model_loader, "_cache_state"))
    previous = state.get("cache")
    state["cache"] = cache
    try:
        yield
    finally:
        if previous is None:
            _ = state.pop("cache", None)
        else:
            state["cache"] = previous


@contextlib.contextmanager
def _sandbox_unavailable() -> Generator[None]:
    """Make the Windows Sandbox availability probe report an unavailable host, then restore it.

    Yields:
        None: Control passes to the body.
    """
    cache = cast("type[Any]", getattr(sandbox_config, "_AvailabilityCache"))
    previous = cache.value
    cache.value = (False, "Windows Sandbox is not enabled")
    try:
        yield
    finally:
        cache.value = previous


@contextlib.contextmanager
def _mcp_service_installed(window: MainWindow, service: McpService | None) -> Generator[None]:
    """Replace the window's MCP service, then put the real one back so the window can stop it on close.

    Args:
        window: The window.
        service: The service to install.

    Yields:
        None: Control passes to the body.
    """
    real = _priv(window, "_mcp_service")
    _set_priv(window, "_mcp_service", value=service)
    try:
        yield
    finally:
        _set_priv(window, "_mcp_service", value=real)


@contextlib.contextmanager
def _tabless_tool_panel(window: MainWindow) -> Generator[None]:
    """Replace the window's tool panel with one that cannot build tool tabs, then restore the real one.

    Args:
        window: The window.

    Yields:
        None: Control passes to the body.
    """
    original = window.tool_panel
    replacement = _PanelWithoutTabs()
    window.tool_panel = replacement
    try:
        yield
    finally:
        window.tool_panel = original
        replacement.deleteLater()


def _release_dialogs(dialogs: Sequence[QDialog]) -> None:
    """Stop a provider dialog's timer, drain the workers it started, then delete the dialogs.

    Args:
        dialogs: The dialogs a watcher handled.
    """
    for dialog in dialogs:
        timer = getattr(dialog, "_update_status_timer", None)
        if timer is not None and not sip.isdeleted(dialog):
            timer.stop()
    _ = drain_bridge_workers()
    for dialog in dialogs:
        if not sip.isdeleted(dialog):
            sip.delete(dialog)


class _WindowBuilder:
    """Callable that builds real main windows around real providers."""

    def __init__(self, tmp_path: Path, windows: list[MainWindow]) -> None:
        """Remember where windows are rooted and where they are collected.

        Args:
            tmp_path: The test's private directory.
            windows: List every built window is appended to.
        """
        self._tmp_path = tmp_path
        self._windows = windows

    def __call__(
        self,
        *providers: LLMProviderBase,
        restore_layout: bool = False,
        cache_bytes: int | None = None,
    ) -> MainWindow:
        """Build a window over connected providers.

        Args:
            *providers: Providers to register and connect before the window opens.
            restore_layout: Value of ``ui.restore_layout`` on the window's configuration.
            cache_bytes: Value stored as the configuration's ``max_model_cache_bytes`` attribute, or ``None`` to leave it unset.

        Returns:
            MainWindow: The constructed window.
        """
        tools_dir = self._tmp_path / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)
        config = Config(
            tools_directory=tools_dir,
            logs_directory=self._tmp_path / "logs",
            data_directory=self._tmp_path / "data",
            ui=UIConfig(restore_layout=restore_layout),
        )
        if cache_bytes is not None:
            setattr(config, "max_model_cache_bytes", cache_bytes)
        registry = ProviderRegistry()
        for provider in providers:
            registry.register(provider)
            _ = run_bridge_coroutine(registry.connect_provider(provider.name, ProviderCredentials()), timeout_s=_BRIDGE_TIMEOUT_S)
        orchestrator = Orchestrator(
            provider_registry=registry,
            tool_registry=ToolRegistry(tools_dir=tools_dir),
            session_manager=SessionManager(store=SessionStore(db_path=self._tmp_path / "sessions.db"), auto_save=False),
        )
        window = MainWindow(config, orchestrator)
        self._windows.append(window)
        return window


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Point the state root below ``tmp_path`` and clear provider variables from the environment.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: The test's monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    with redirected_state_root(monkeypatch, tmp_path / "home") as root:
        yield root


@pytest.fixture
def private_keyring(tmp_path: Path) -> Generator[KeyringBackend]:
    """Install a real file keyring that lives in ``tmp_path`` as the process keyring.

    Args:
        tmp_path: Per-test temporary directory.

    Yields:
        KeyringBackend: The installed backend.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring.cfg")) as backend:
        yield backend


@pytest.fixture
def recorders(monkeypatch: pytest.MonkeyPatch) -> _Recorders:
    """Replace the static message-box functions with recorders.

    Args:
        monkeypatch: The test's monkeypatch fixture.

    Returns:
        _Recorders: The recorders.
    """
    found = _Recorders(DialogRecorder(), DialogRecorder(), DialogRecorder())
    monkeypatch.setattr(QMessageBox, "information", staticmethod(found.information))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(found.warning))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(found.critical))
    return found


@pytest.fixture
def build_window(qapp: QApplication, tmp_path: Path) -> Generator[_WindowBuilder]:
    """Provide a factory for real main windows that closes every window it built.

    Args:
        qapp: The application.
        tmp_path: Per-test temporary directory.

    Yields:
        _WindowBuilder: The factory.
    """
    windows: list[MainWindow] = []
    try:
        yield _WindowBuilder(tmp_path, windows)
    finally:
        for window in windows:
            window.close()
        _ = drain_bridge_workers()
        qapp.processEvents()


def test_a_provider_that_drops_during_startup_is_reported_and_not_made_active(build_window: _WindowBuilder) -> None:
    """A connected provider that drops between listing and activation is logged, leaves no active provider and does not stop startup.

    Args:
        build_window: Factory for real main windows.
    """
    provider = _FlakyProvider(provider_ids.ANTHROPIC)

    with capture_logs() as captured:
        window = build_window(provider)

    failures = _events(captured, "startup_active_provider_set_failed")
    assert len(failures) == 1
    assert "Not connected" in str(failures[0]["error"])
    assert _events(captured, "startup_active_provider_set") == []
    assert _priv(window, "_orchestrator").provider_registry.active is None


def test_show_event_without_a_native_window_wires_nothing_until_the_window_is_shown(
    build_window: _WindowBuilder,
    qapp: QApplication,
) -> None:
    """A show event delivered before the window has a native handle connects nothing; the real show connects the watcher once.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window()
    assert window.windowHandle() is None

    window.showEvent(QShowEvent())

    assert _priv(window, "_screen_watcher_connected") is False
    _show(window, qapp)
    assert window.windowHandle() is not None
    assert _priv(window, "_screen_watcher_connected") is True


def test_restore_ignores_saved_splitter_sizes_with_the_wrong_pane_count(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """Saved splitter sizes for three panes cannot describe the two-pane splitter, so the splitter keeps its sizes.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window(restore_layout=True)
    _show(window, qapp)
    splitter = cast("QSplitter", _priv(window, "_splitter"))
    splitter.setSizes([400, 1100])
    _settle(qapp)
    before = splitter.sizes()
    settings = _settings()
    settings.clear()
    settings.setValue("splitter_sizes", [1, 1, 1])
    settings.sync()

    _call(window, "_restore_window_state")
    _settle(qapp)

    assert splitter.sizes() == before


def test_a_cache_size_the_cache_refuses_does_not_stop_startup(build_window: _WindowBuilder) -> None:
    """A configured cache size the global cache refuses is logged as skipped and the window still opens.

    Args:
        build_window: Factory for real main windows.
    """
    cache = _FaultyCache()
    with _installed_cache(cache), capture_logs() as captured:
        window = build_window(cache_bytes=4096)

    assert len(_events(captured, "model_cache_init_skipped")) == 1
    assert cache.max_memory_bytes != 4096
    assert window.windowTitle() == "Intellicrack"


def test_memory_label_is_cleared_when_the_cache_cannot_report_its_usage(build_window: _WindowBuilder) -> None:
    """When the cache cannot report its usage the status-bar memory label is emptied, logged, and its tooltip emptied too.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    label = cast("QLabel", _priv(window, "_memory_label"))
    label.setText("Cache: 5MB")
    label.setToolTip("Cache: 5MB")

    with _installed_cache(_FaultyCache()), capture_logs() as captured:
        _call(window, "_refresh_memory_status")

    assert len(_events(captured, "memory_label_update_failed")) >= 1
    assert not label.text()
    assert not label.toolTip()


def test_discovery_status_failure_is_logged_and_leaves_the_status_label(build_window: _WindowBuilder) -> None:
    """A discovery service whose history cannot be read is logged and the model-status label is left as it was.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    window.set_model_discovery(_BrokenDiscovery(_priv(window, "_orchestrator").provider_registry))
    _set_priv(window, "_initial_discovery_triggered", value=True)
    window.model_status_label.setText("old status")

    with capture_logs() as captured:
        _call(window, "_refresh_model_discovery_status")

    assert len(_events(captured, "model_discovery_status_refresh_failed")) == 1
    assert window.model_status_label.text() == "old status"


def test_a_failing_mcp_stop_is_logged_and_the_service_is_released(build_window: _WindowBuilder) -> None:
    """A service that cannot stop is logged with its error, and the window forgets it so shutdown can go on.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    faulty = _FaultyMcpService.__new__(_FaultyMcpService)

    with _mcp_service_installed(window, faulty), capture_logs() as captured:
        _call(window, "_stop_mcp_service")
        assert _priv(window, "_mcp_service") is None

    stops = _events(captured, "mcp_service_stop_failed")
    assert [entry["error"] for entry in stops] == ["stop refused"]


def test_confirmation_is_still_asked_when_the_mcp_source_cannot_be_resolved(build_window: _WindowBuilder) -> None:
    """A tool call whose MCP source cannot be resolved is logged, still shown to the operator, and a dismissal answers it with a denial.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    call = ToolCall(id="k-1", tool_name="ghidra", function_name="decompile", arguments={})
    future = run_bridge_coroutine(_new_future(), timeout_s=_BRIDGE_TIMEOUT_S)
    assert future is not None

    def _dismiss(dialog: QDialog) -> None:
        """Dismiss the dialog without deciding.

        Args:
            dialog: The confirmation dialog.
        """
        dialog.reject()

    watcher = DialogWatcher(ToolConfirmationDialog, _dismiss)
    try:
        with _mcp_service_installed(window, _FaultyMcpService.__new__(_FaultyMcpService)), capture_logs() as captured:
            _call(window, "_show_confirmation_dialog", (call, future, ensure_loop()))
    finally:
        watcher.stop()

    assert len(watcher.seen) == 1
    unresolved = _events(captured, "mcp_confirmation_source_unresolved")
    assert [(entry["tool"], entry["error"]) for entry in unresolved] == [("ghidra", "server registry unreadable")]
    assert run_bridge_coroutine(_await_future(future), timeout_s=_BRIDGE_TIMEOUT_S) is False


@pytest.mark.usefixtures("private_keyring")
def test_a_message_sent_with_a_process_selected_logs_that_process(
    build_window: _WindowBuilder,
    recorders: _Recorders,
    qtbot: QtBot,
) -> None:
    """Sending a message while a process is selected in the Process panel records that process as the message context.

    Args:
        build_window: Factory for real main windows.
        recorders: Message-box recorders.
        qtbot: pytest-qt bot used to wait for the send to settle.
    """
    window = build_window()
    panel = ProcessPanel()
    _add_to_tabs(window, "_process_panel", panel, "Process")
    _set_priv(_priv(panel, "_process_tab"), "_selected_pid", value=_SELECTED_PID)
    window.model_combo.setCurrentText("some-model")
    statuses = _status_log(window)

    with capture_logs() as captured:
        _call(window, "_on_user_message", "hello")
    qtbot.waitUntil(lambda: statuses[-1:] in (["Ready"], ["Error"]), timeout=_WAIT_MS)
    _ = drain_bridge_workers()

    context = _events(captured, "user_message_process_context")
    assert [entry["pid"] for entry in context] == [_SELECTED_PID]
    assert recorders.warning.calls == []


def test_a_refresh_with_nothing_to_restore_does_not_consult_a_remembered_model(build_window: _WindowBuilder) -> None:
    """With no model and no provider to restore, a successful refresh fills the combo and does not apply a remembered model.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    statuses = _status_log(window)
    settings = _settings()
    settings.setValue(f"last_model/{None}", _SENTINEL_MODEL)
    settings.sync()
    assert not _priv(window, "_pending_model_restore")
    assert _priv(window, "_pending_model_restore_provider") is None

    _call(window, "_on_models_refresh_finished", success=True, models=["m-a", "m-b"], message="")

    items = [window.model_combo.itemText(index) for index in range(window.model_combo.count())]
    assert items == ["m-a", "m-b"]
    assert window.model_combo.currentText() != _SENTINEL_MODEL
    assert statuses == ["Found 2 models"]


def test_a_theme_change_before_the_tool_panel_exists_only_refreshes_the_icons(build_window: _WindowBuilder) -> None:
    """A theme change that arrives while the window is still being built is logged and does not need the tool panel.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    del window.tool_panel
    try:
        with capture_logs() as captured:
            _call(window, "_on_theme_changed", "dark")
    finally:
        window.tool_panel = panel

    assert [entry["resolved"] for entry in _events(captured, "theme_refreshed")] == ["dark"]


@pytest.mark.parametrize("case", _TOOL_CASES)
def test_a_tool_whose_panel_cannot_be_built_is_reported(build_window: _WindowBuilder, recorders: _Recorders, case: _ToolCase) -> None:
    """A tool panel that cannot be created shows an error titled after the tool and starts nothing.

    Args:
        build_window: Factory for real main windows.
        recorders: Message-box recorders.
        case: The tool under test.
    """
    window = build_window()

    with _tabless_tool_panel(window):
        _call(window, case.method)
    _ = drain_bridge_workers()

    assert recorders.warning.calls == [(window, f"{case.title} Error", case.text, _OK)]


def test_opening_the_loaded_binary_in_a_ready_ghidra_panel_shows_no_error(
    build_window: _WindowBuilder,
    recorders: _Recorders,
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """A Ghidra panel whose bridge is ready accepts the load request, is brought to the front and no failure dialog is shown.

    Args:
        build_window: Factory for real main windows.
        recorders: Message-box recorders.
        qtbot: pytest-qt bot used to wait for the bridge's answer.
        tmp_path: Per-test temporary directory.
    """
    window = build_window()
    binary = tmp_path / "missing.bin"
    window.current_binary = binary
    bridge = GhidraBridge()
    bridge.state = BridgeState(connected=True, tool_running=True)
    panel = GhidraPanel()
    panel.set_bridge(bridge)
    _add_to_tabs(window, "_ghidra_widget", panel, "Ghidra")
    other = QWidget()
    _ = window.tool_panel.tab_widget.addTab(other, "Other")
    window.tool_panel.tab_widget.setCurrentWidget(other)
    assert window.tool_panel.tab_widget.currentWidget() is other

    with capture_logs() as captured:
        _call(window, "_on_open_binary_in_ghidra")
        qtbot.waitUntil(lambda: bool(_events(captured, "ghidra_load_failed")), timeout=_WAIT_MS)
    _ = drain_bridge_workers()

    assert recorders.warning.calls == []
    assert window.tool_panel.tab_widget.currentWidget() is panel
    assert [entry["path"] for entry in _events(captured, "ghidra_load_failed")] == ["missing.bin"]


@pytest.mark.usefixtures("private_keyring")
def test_accepting_the_provider_settings_applies_them(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """Accepting the provider dialog applies what it holds: a provider the operator disabled there is disconnected and counted.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the disconnect.
    """
    provider = _ScriptedProvider(provider_ids.OPENAI)
    window = build_window(provider)
    statuses = _status_log(window)
    configured: list[int] = []

    def _disable_everything_and_accept(dialog: QDialog) -> None:
        """Untick every provider's enabled box, as the operator would, then press OK.

        Args:
            dialog: The provider settings dialog.
        """
        pages = cast("dict[str, QWidget]", _priv(dialog, "_provider_widgets"))
        configured.append(len(pages))
        for page in pages.values():
            _priv(page, "_enabled_checkbox").setChecked(False)
        _call(dialog, "_on_accept")

    watcher = DialogWatcher(ProviderConfigDialog, _disable_everything_and_accept)
    try:
        _call(window, "_on_configure_providers")
    finally:
        watcher.stop()
        _release_dialogs(watcher.seen)

    assert len(watcher.seen) == 1
    assert configured[0] >= 1
    assert f"Provider settings applied ({configured[0]} providers configured, 1 disabled)" in statuses
    qtbot.waitUntil(lambda: provider.is_connected is False, timeout=_WAIT_MS)


def test_accepting_the_sandbox_settings_applies_them(
    build_window: _WindowBuilder,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Accepting the sandbox dialog saves the chosen limits and applies them to the window's sandbox manager once more after the dialog's own apply.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for both applies.
        monkeypatch: The test's monkeypatch fixture, used to move the dialog's configuration paths under ``tmp_path``.
        tmp_path: Per-test temporary directory.
    """
    config_dir = tmp_path / "sandbox-config"
    config_file = config_dir / "sandbox.json"
    shared = tmp_path / "shared"
    monkeypatch.setattr(SandboxConfigDialog, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(SandboxConfigDialog, "CONFIG_FILE", config_file)
    window = build_window()
    statuses = _status_log(window)

    def _choose_limits_and_accept(dialog: QDialog) -> None:
        """Type limits and a shared folder into the dialog, as the operator would, then press OK.

        Args:
            dialog: The sandbox settings dialog.
        """
        _priv(dialog, "_timeout_spin").setValue(_TIMEOUT_SECONDS)
        _priv(dialog, "_memory_spin").setValue(_MEMORY_MB)
        _priv(dialog, "_network_enabled_checkbox").setChecked(True)
        _priv(dialog, "_shared_folder_input").setText(str(shared))
        _call(dialog, "_on_accept")

    with _sandbox_unavailable():
        watcher = DialogWatcher(SandboxConfigDialog, _choose_limits_and_accept)
        try:
            _call(window, "_on_configure_sandbox")
        finally:
            watcher.stop()
            _release_dialogs(watcher.seen)

    assert len(watcher.seen) == 1
    qtbot.waitUntil(lambda: statuses.count("Sandbox settings applied") == _PAIR_OF_APPLIES, timeout=_WAIT_MS)
    saved = cast("dict[str, object]", json.loads(config_file.read_text(encoding="utf-8")))
    assert (saved["timeout_seconds"], saved["memory_limit_mb"], saved["network_enabled"], saved["shared_folder"]) == (
        _TIMEOUT_SECONDS,
        _MEMORY_MB,
        True,
        str(shared),
    )
    assert shared.is_dir()
    applied = cast("SandboxConfig", _priv(window.sandbox_manager, "_default_config"))
    assert (applied.timeout_seconds, applied.memory_limit_mb, applied.network_enabled) == (_TIMEOUT_SECONDS, _MEMORY_MB, True)
    assert [(folder, mount) for folder, mount, _read_only in applied.shared_folders] == [(shared, "C:\\Shared")]
