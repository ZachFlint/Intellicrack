# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the startup, layout, status, tool-event, session and dialog-driven paths of the main window.

Every test drives a real ``MainWindow`` over a real ``Orchestrator``, a real ``ProviderRegistry`` and real providers (subclasses of the
production ``LLMProviderBase``). The window's state root, provider settings and user settings live under ``tmp_path``. Modal dialogs the
window opens itself (settings, new session, session manager, tool confirmation) are real dialogs closed by the ``DialogWatcher`` helper from
inside their own event loop; Qt's static message-box functions are replaced by recorders that note what the operator would have seen.
Expected values come from the documented contract of each handler, hand arithmetic, and the Python standard library.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, cast, override

import pytest
from PyQt6.QtCore import QSettings, QSignalBlocker
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTextEdit,
    QToolBar,
    QWidget,
)
from structlog.testing import capture_logs

from intellicrack.core.config import Config, UIConfig, get_config_dir, get_config_file
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.script_gen import ScriptGenerator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.template_manager import TemplateManager
from intellicrack.core.tool_progress import ToolProgress
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import Message, ModelInfo, ProviderCredentials, ToolCall, ToolName, ToolResult
from intellicrack.credentials.provider_settings import PROVIDER_SETTINGS_FILENAME, ProviderSettingsStore
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.discovery import DiscoveryEvent, ModelDiscovery
from intellicrack.providers.model_loader import get_global_model_cache
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, ensure_loop, run_bridge_coroutine
from intellicrack.ui.panels.base_panel import compute_toolbar_height
from intellicrack.ui.session_manager import NewSessionDialog, SessionManagerDialog
from tests._helpers.mcp_ui_support import DialogWatcher
from tests._helpers.private_keyring import installed_keyring, private_file_keyring
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Generator
    from pathlib import Path

    from keyring.backend import KeyringBackend
    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition
    from intellicrack.ui.tool_config import ToolStatusEntry


pytestmark = pytest.mark.usefixtures("qapp")


_BRIDGE_TIMEOUT_S: float = 60.0
_WAIT_MS: int = 20_000
_NEGATIVE_WAIT_MS: int = 2_000
_MIB: int = 1024 * 1024
_RESTORE_WIDTH: int = 780
_RESTORE_HEIGHT: int = 560
_WINDOW_WIDTH: int = 1600
_WINDOW_HEIGHT: int = 900
_SETTLE_PASSES: int = 8
_PREVIEW_LIMIT: int = 500
_ELLIPSIS_LENGTH: int = 3
_PIXEL_TOOLBAR_HEIGHT: int = 10
_GENERATED_CACHE_BYTES: int = 3 * 1024 * _MIB
_SAVED_TIMEOUT_SECONDS: int = 42
_EM_DASH: str = "—"


class _ScriptedProvider(LLMProviderBase):
    """Real provider whose connection outcome the test chooses.

    Attributes:
        received: Every credentials object ``connect`` was called with, in call order.
    """

    received: list[ProviderCredentials]

    def __init__(self, provider_name: str, *, connect_error: Exception | None = None) -> None:
        """Create the provider.

        Args:
            provider_name: Instance id the provider reports.
            connect_error: Exception ``connect`` raises instead of connecting, or ``None`` to connect.
        """
        super().__init__()
        self._name = provider_name
        self._connect_error = connect_error
        self.received = []

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
        """Record the credentials, then connect, or fail with the scripted error when one was given.

        Args:
            credentials: Credentials the caller connects with.

        Raises:
            self._connect_error: The scripted error, when one was given.
        """
        self.received.append(credentials)
        if self._connect_error is not None:
            raise self._connect_error
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


class _WindowBuilder(Protocol):
    """Callable that builds a real main window around real providers."""

    def __call__(
        self,
        *providers: _ScriptedProvider,
        connect: bool = True,
        restore_layout: bool = False,
        cache_bytes: int | None = None,
    ) -> MainWindow:
        """Build a window.

        Args:
            *providers: Providers to register in the window's registry.
            connect: Whether every provider is connected before the window opens.
            restore_layout: Value of ``ui.restore_layout`` on the window's configuration.
            cache_bytes: Value stored as the configuration's ``max_model_cache_bytes`` attribute, or ``None`` to leave it unset.

        Returns:
            MainWindow: The constructed window.
        """
        ...


def _attr[T](owner: object, name: str, kind: type[T]) -> T:
    """Read a private attribute of ``owner`` and check its type.

    Args:
        owner: Object holding the attribute.
        name: Attribute name.
        kind: Type the attribute must have.

    Returns:
        T: The attribute value.
    """
    value: object = getattr(owner, name)
    assert isinstance(value, kind)
    return value


def _call(owner: object, name: str, *args: object) -> object:
    """Call a private method of ``owner``.

    Args:
        owner: Object (or class) holding the method.
        name: Method name.
        *args: Positional arguments for the call.

    Returns:
        object: What the method returned.
    """
    method: Callable[..., object] = getattr(owner, name)
    return method(*args)


def _invoke(owner: object, name: str, *args: object) -> None:
    """Call a private method of ``owner`` and discard its result.

    Args:
        owner: Object (or class) holding the method.
        name: Method name.
        *args: Positional arguments for the call.
    """
    _ = _call(owner, name, *args)


def _put(owner: object, name: str, *, value: object) -> None:
    """Assign a private data attribute on a real product object.

    Args:
        owner: Object holding the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(owner, name, value)


def _run(owner: object, name: str, *args: object) -> object:
    """Call a private coroutine method of ``owner`` on the bridge loop and wait for it.

    Args:
        owner: Object holding the coroutine method.
        name: Method name.
        *args: Positional arguments for the call.

    Returns:
        object: What the coroutine returned.
    """
    coro = _call(owner, name, *args)
    assert inspect.iscoroutine(coro)
    return run_bridge_coroutine(coro, timeout_s=_BRIDGE_TIMEOUT_S)


def _orchestrator(window: MainWindow) -> Orchestrator:
    """Return the orchestrator a window drives.

    Args:
        window: The window.

    Returns:
        Orchestrator: Its orchestrator.
    """
    return _attr(window, "_orchestrator", Orchestrator)


def _settings() -> QSettings:
    """Open the same user-scope store the main window persists to.

    Returns:
        QSettings: The ``Intellicrack/MainWindow`` store.
    """
    return QSettings(QSettings.defaultFormat(), QSettings.Scope.UserScope, "Intellicrack", "MainWindow")


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


def _record_dialog(monkeypatch: pytest.MonkeyPatch, name: str) -> DialogRecorder:
    """Replace one static ``QMessageBox`` function with a recorder.

    Args:
        monkeypatch: The test's monkeypatch fixture.
        name: Name of the static function.

    Returns:
        DialogRecorder: The recorder holding the arguments of every call.
    """
    recorder = DialogRecorder()
    monkeypatch.setattr(QMessageBox, name, recorder)
    return recorder


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


def _events_of(discovery: ModelDiscovery) -> list[DiscoveryEvent]:
    """Reach the event history a discovery object keeps.

    Args:
        discovery: The discovery object.

    Returns:
        list[DiscoveryEvent]: The live history list.
    """
    return cast("list[DiscoveryEvent]", getattr(discovery, "_events"))


async def _new_future(*, value: bool | None) -> asyncio.Future[bool]:
    """Create a future on the running loop, optionally already resolved.

    Args:
        value: Result to resolve it with, or ``None`` to leave it pending.

    Returns:
        asyncio.Future[bool]: The future.
    """
    await asyncio.sleep(0)
    future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
    if value is not None:
        future.set_result(value)
    return future


async def _await_future(future: asyncio.Future[bool]) -> bool:
    """Wait for a future.

    Args:
        future: The future.

    Returns:
        bool: Its result.
    """
    return await future


async def _collect_loop_errors(sink: list[dict[str, object]] | None) -> None:
    """Route the running loop's unhandled callback errors into a list, or restore the default handler.

    Args:
        sink: List that receives each error context, or ``None`` to restore the default handler.
    """
    await asyncio.sleep(0)
    loop = asyncio.get_running_loop()
    if sink is None:
        loop.set_exception_handler(None)
        return

    def _handler(_loop: asyncio.AbstractEventLoop, context: dict[str, object]) -> None:
        """Keep an error context.

        Args:
            _loop: The loop that reported it.
            context: The error context.
        """
        sink.append(context)

    loop.set_exception_handler(_handler)


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
def build_window(qapp: QApplication, tmp_path: Path) -> Generator[_WindowBuilder]:
    """Provide a factory for real main windows that closes every window it built.

    Args:
        qapp: The application.
        tmp_path: Per-test temporary directory.

    Yields:
        _WindowBuilder: The factory.
    """
    windows: list[MainWindow] = []

    def _build(
        *providers: _ScriptedProvider,
        connect: bool = True,
        restore_layout: bool = False,
        cache_bytes: int | None = None,
    ) -> MainWindow:
        """Build a window over real collaborators rooted in ``tmp_path``.

        Args:
            *providers: Providers to register in the window's registry.
            connect: Whether every provider is connected before the window opens.
            restore_layout: Value of ``ui.restore_layout`` on the window's configuration.
            cache_bytes: Value stored as the configuration's ``max_model_cache_bytes`` attribute, or ``None`` to leave it unset.

        Returns:
            MainWindow: The constructed window.
        """
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)
        config = Config(
            tools_directory=tools_dir,
            logs_directory=tmp_path / "logs",
            data_directory=tmp_path / "data",
            ui=UIConfig(restore_layout=restore_layout),
        )
        if cache_bytes is not None:
            setattr(config, "max_model_cache_bytes", cache_bytes)
        registry = ProviderRegistry()
        for provider in providers:
            registry.register(provider)
            if connect:
                _ = run_bridge_coroutine(registry.connect_provider(provider.name, ProviderCredentials()), timeout_s=_BRIDGE_TIMEOUT_S)
        orchestrator = Orchestrator(
            provider_registry=registry,
            tool_registry=ToolRegistry(tools_dir=tools_dir),
            session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
        )
        window = MainWindow(config, orchestrator)
        windows.append(window)
        return window

    try:
        yield _build
    finally:
        for window in windows:
            window.close()
        _ = drain_bridge_workers()
        qapp.processEvents()


@pytest.mark.parametrize("provider_id", [provider_ids.OLLAMA, provider_ids.LOCAL_TRANSFORMERS])
def test_local_runtime_providers_need_no_api_key(build_window: _WindowBuilder, provider_id: str) -> None:
    """A built-in local runtime may connect without an API key even when nothing is registered for it.

    Args:
        build_window: Factory for real main windows.
        provider_id: Built-in local runtime id.
    """
    window = build_window()
    assert _call(window, "_api_key_optional", provider_id) is True


def test_remembered_provider_ignores_a_stored_id_that_is_not_valid() -> None:
    """A stored last provider that breaks the id grammar is dropped; a valid one is normalized."""
    settings = _settings()
    settings.setValue("last_provider", "Not A Valid Id!")
    settings.sync()
    assert _call(MainWindow, "_remembered_provider") is None

    settings.setValue("last_provider", " OpenAI ")
    settings.sync()
    assert _call(MainWindow, "_remembered_provider") == "openai"


def test_persist_current_model_without_a_provider_selection_stores_nothing(build_window: _WindowBuilder) -> None:
    """With no provider selected there is nothing to key the model under, so nothing is persisted.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    combo = _attr(window, "_provider_combo", QComboBox)
    with QSignalBlocker(combo):
        combo.clear()
    window.model_combo.setCurrentText("some-model")
    settings = _settings()
    settings.clear()
    settings.sync()

    _invoke(window, "_persist_current_model")

    settings.sync()
    assert settings.allKeys() == []


def test_kickoff_skips_a_toolbar_provider_id_that_is_not_valid(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """A provider entry whose id breaks the grammar never starts a session.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window()
    combo = _attr(window, "_provider_combo", QComboBox)
    with QSignalBlocker(combo):
        combo.addItem("Broken", "Bad Id!")
        combo.setCurrentIndex(combo.count() - 1)
    window.model_combo.setCurrentText("some-model")
    statuses = _status_log(window)

    _invoke(window, "_kickoff_initial_session")
    _ = drain_bridge_workers()
    qapp.processEvents()

    assert _orchestrator(window).current_session is None
    assert statuses == []


@pytest.mark.parametrize("registered", [True, False], ids=["registered-but-disconnected", "not-registered"])
def test_kickoff_waits_while_the_provider_is_not_connected(build_window: _WindowBuilder, qapp: QApplication, *, registered: bool) -> None:
    """A provider that is missing or not connected defers the initial session and is not connected on the operator's behalf.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
        registered: Whether the provider is registered (but disconnected) in the registry.
    """
    provider = _ScriptedProvider(provider_ids.ANTHROPIC)
    window = build_window(provider, connect=False) if registered else build_window()
    window.model_combo.setCurrentText("some-model")
    assert _call(window, "_selected_provider_model") == (provider_ids.ANTHROPIC, "some-model")
    statuses = _status_log(window)

    _invoke(window, "_kickoff_initial_session")
    _ = drain_bridge_workers()
    qapp.processEvents()

    assert _orchestrator(window).current_session is None
    assert provider.received == []
    assert statuses == []


def test_kickoff_creates_the_initial_session_for_the_toolbar_selection(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """With a connected provider and a model chosen, the kickoff creates a session bound to that provider and model.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the asynchronous creation.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    window.model_combo.setCurrentText("claude-test")

    _invoke(window, "_kickoff_initial_session")

    orchestrator = _orchestrator(window)
    qtbot.waitUntil(lambda: orchestrator.current_session is not None, timeout=_WAIT_MS)
    session = orchestrator.current_session
    assert session is not None
    assert (session.provider, session.model) == (provider_ids.ANTHROPIC, "claude-test")


def test_ensure_active_session_keeps_a_matching_binding_without_reconnecting(build_window: _WindowBuilder) -> None:
    """A session already bound to the requested provider and model is returned untouched, even if the provider has since dropped.

    Args:
        build_window: Factory for real main windows.
    """
    provider = _ScriptedProvider(provider_ids.ANTHROPIC)
    window = build_window(provider)
    orchestrator = _orchestrator(window)
    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-1")
    session = orchestrator.current_session
    assert session is not None
    _ = run_bridge_coroutine(orchestrator.provider_registry.disconnect_provider(provider_ids.ANTHROPIC), timeout_s=_BRIDGE_TIMEOUT_S)
    assert provider.is_connected is False

    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-1")

    assert orchestrator.current_session is session
    assert provider.is_connected is False
    assert len(provider.received) == 1


@pytest.mark.usefixtures("private_keyring")
def test_ensure_active_session_connects_a_provider_that_is_not_connected(build_window: _WindowBuilder) -> None:
    """A disconnected provider is connected with its saved request timeout before the session is created.

    Args:
        build_window: Factory for real main windows.
    """
    ProviderSettingsStore(get_config_file(PROVIDER_SETTINGS_FILENAME)).write_section(
        provider_ids.ANTHROPIC,
        {"timeout_seconds": _SAVED_TIMEOUT_SECONDS},
    )
    provider = _ScriptedProvider(provider_ids.ANTHROPIC)
    window = build_window(provider, connect=False)

    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-2")

    assert provider.is_connected is True
    assert [credentials.timeout for credentials in provider.received] == [float(_SAVED_TIMEOUT_SECONDS)]
    session = _orchestrator(window).current_session
    assert session is not None
    assert (session.provider, session.model) == (provider_ids.ANTHROPIC, "m-2")


@pytest.mark.usefixtures("private_keyring")
def test_connect_provider_for_session_wraps_a_failed_connection_in_guidance(build_window: _WindowBuilder) -> None:
    """A provider that refuses to connect surfaces as a RuntimeError that names the provider and carries the cause.

    Args:
        build_window: Factory for real main windows.
    """
    refusal = ConnectionError("refused by peer")
    provider = _ScriptedProvider(provider_ids.OPENAI, connect_error=refusal)
    window = build_window(provider, connect=False)

    with pytest.raises(RuntimeError) as failure:
        _ = _run(window, "_connect_provider_for_session", provider_ids.OPENAI)

    message = str(failure.value)
    assert message.startswith("Could not connect to provider 'openai'. Configure its credentials in Preferences, then try again.")
    assert message.endswith("Details: refused by peer")
    assert failure.value.__cause__ is refusal


def test_restore_window_state_applies_the_saved_splitter_tabs_and_detached_panels(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """With layout restore on, the saved tab order, active tab and detached panels come back, and the saved geometry and splitter sizes are applied.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window(restore_layout=True)
    window.resize(_RESTORE_WIDTH, _RESTORE_HEIGHT)
    window.show()
    _settle(qapp)
    splitter = _attr(window, "_splitter", QSplitter)
    settings = _settings()
    settings.setValue("geometry", window.saveGeometry())
    settings.setValue("splitter_sizes", splitter.sizes())
    settings.setValue("tab_state/tab_names", ["Analysis", "Scripts", "Stack"])
    settings.setValue("tab_state/active_index", "1")
    settings.setValue("tab_state/splitter_sizes", [250, 450])
    settings.setValue("detached_panels", ["Stack", "Missing Tab"])
    settings.sync()

    _invoke(window, "_restore_window_state")

    panel = window.tool_panel
    assert panel.get_detached_state() == ["Stack"]
    assert panel.tab_widget.count() == 2
    assert panel.find_tab_by_title("Analysis") == 0
    assert panel.find_tab_by_title("Stack") == -1
    assert panel.tab_widget.tabText(panel.tab_widget.currentIndex()) == "Scripts"


def test_second_show_does_not_connect_the_screen_watcher_again(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """Showing a hidden window again must leave exactly one screen-change connection.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window()
    _show(window, qapp)
    assert _attr(window, "_screen_watcher_connected", bool) is True
    window.hide()
    window.show()
    _settle(qapp)
    handle = window.windowHandle()
    assert handle is not None

    with capture_logs() as logs:
        handle.screenChanged.emit(window.screen())

    assert [entry["event"] for entry in logs].count("screen_changed_relayout_applied") == 1


def test_screen_change_rederives_the_toolbar_height(build_window: _WindowBuilder) -> None:
    """A screen change recomputes the toolbar height from the window's font metrics.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    toolbar = _attr(window, "_toolbar", QToolBar)
    toolbar.setFixedHeight(_PIXEL_TOOLBAR_HEIGHT)

    _invoke(window, "_on_screen_changed", None)

    assert toolbar.maximumHeight() > _PIXEL_TOOLBAR_HEIGHT
    assert toolbar.maximumHeight() == compute_toolbar_height(window)


def test_screen_change_without_a_central_widget_still_rederives_the_toolbar(build_window: _WindowBuilder) -> None:
    """A window with no central widget survives a screen change and still updates its toolbar.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    toolbar = _attr(window, "_toolbar", QToolBar)
    original = window.takeCentralWidget()
    assert original is not None
    try:
        assert window.centralWidget() is None
        toolbar.setFixedHeight(_PIXEL_TOOLBAR_HEIGHT)

        _invoke(window, "_on_screen_changed", None)

        assert toolbar.maximumHeight() == compute_toolbar_height(window)
    finally:
        window.setCentralWidget(original)


def test_screen_change_with_a_central_widget_that_has_no_layout(build_window: _WindowBuilder) -> None:
    """A central widget without a layout is skipped rather than activated.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    toolbar = _attr(window, "_toolbar", QToolBar)
    original = window.takeCentralWidget()
    assert original is not None
    bare = QWidget()
    window.setCentralWidget(bare)
    try:
        assert bare.layout() is None
        toolbar.setFixedHeight(_PIXEL_TOOLBAR_HEIGHT)

        _invoke(window, "_on_screen_changed", None)

        assert toolbar.maximumHeight() == compute_toolbar_height(window)
    finally:
        _ = window.takeCentralWidget()
        window.setCentralWidget(original)


def test_wiring_an_unrecognised_script_manager_leaves_the_orchestrator_manager_alone(build_window: _WindowBuilder) -> None:
    """Only a real ``ScriptManager`` re-points the orchestrator; any other object is stored on the window alone.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    orchestrator = _orchestrator(window)
    before = getattr(orchestrator, "_script_manager")
    assert before is not None
    other = object()

    window.wire_script_manager(other)

    assert _attr(window, "_script_manager", object) is other
    assert getattr(orchestrator, "_script_manager") is before


def test_script_generator_and_template_manager_are_kept_on_the_window(build_window: _WindowBuilder, tmp_path: Path) -> None:
    """The application-scoped generator and template manager are stored for later panels to reach.

    Args:
        build_window: Factory for real main windows.
        tmp_path: Per-test temporary directory.
    """
    window = build_window()
    generator = ScriptGenerator(output_dir=tmp_path / "generated")
    manager = TemplateManager(tmp_path / "templates-root")

    window.set_script_generator(generator)
    window.set_template_manager(manager)

    assert _attr(window, "_script_generator", ScriptGenerator) is generator
    assert window.template_manager is manager


def test_model_cache_limit_is_taken_from_the_configuration(build_window: _WindowBuilder) -> None:
    """A positive cache size on the configuration becomes the global model cache limit at startup.

    Args:
        build_window: Factory for real main windows.
    """
    cache = get_global_model_cache()
    previous = cache.max_memory_bytes
    try:
        _ = build_window(cache_bytes=_GENERATED_CACHE_BYTES)
        assert cache.max_memory_bytes == _GENERATED_CACHE_BYTES
    finally:
        cache.max_memory_bytes = previous


def test_analysis_view_activates_the_analysis_tab(build_window: _WindowBuilder) -> None:
    """The View menu's Analysis entry brings the analysis panel to the front, creating it on demand.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    _ = panel.add_script_panel()
    assert panel.analysis_panel is None

    _invoke(window, "_on_view_analysis")

    assert panel.analysis_panel is not None
    assert panel.tab_widget.currentWidget() is panel.analysis_panel


def test_stack_view_activates_the_stack_tab(build_window: _WindowBuilder) -> None:
    """The View menu's Stack Viewer entry brings the stack panel to the front, creating it on demand.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    _ = panel.add_script_panel()
    assert panel.stack_panel is None

    _invoke(window, "_on_view_stack")

    assert panel.stack_panel is not None
    assert panel.tab_widget.currentWidget() is panel.stack_panel


def test_scripts_view_reports_the_selected_script_when_none_is_being_edited(build_window: _WindowBuilder) -> None:
    """With a script highlighted in the list but no draft open, the status names the selected script.

    ``ToolOutputPanel.get_script_panel_state`` asks the script panel for ``get_selected_id``, which only the panel's inner list defines, so
    the panel never reports a selection and this contract (``app.py`` lines 902-903) is unreachable: this test is red until that is fixed.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    _ = panel.add_script_panel()
    script_panel = panel.script_panel
    assert script_panel is not None
    script_list = _attr(script_panel, "_script_list", QListWidget)
    _invoke(script_list, "add_script", "sid-1", "Alpha", "frida")
    script_list.setCurrentRow(0)
    statuses = _status_log(window)

    _invoke(window, "_on_view_scripts")

    assert statuses == ["Scripts: selected 'sid-1'"]


def test_detach_current_floats_the_active_tab(build_window: _WindowBuilder) -> None:
    """The View menu's Detach Current Panel entry moves the active tab into its own window.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    _ = panel.add_analysis_panel()
    assert panel.tab_widget.tabText(panel.tab_widget.currentIndex()) == "Analysis"

    _invoke(window, "_on_detach_current")

    assert panel.get_detached_state() == ["Analysis"]
    assert panel.tab_widget.count() == 0


def test_toggle_chat_panel_leaves_a_splitter_with_extra_panes_alone(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """The collapse toggle only acts on a two-pane splitter.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window()
    _show(window, qapp)
    splitter = _attr(window, "_splitter", QSplitter)
    splitter.addWidget(QWidget())
    _settle(qapp)
    chat = _attr(window, "_chat_panel", QWidget)
    sizes_before = splitter.sizes()
    minimum_before = chat.minimumWidth()
    assert len(sizes_before) == 3

    _invoke(window, "_on_toggle_chat_panel")

    assert splitter.sizes() == sizes_before
    assert chat.minimumWidth() == minimum_before


def test_model_combo_cursor_reset_tolerates_a_combo_without_a_line_edit(build_window: _WindowBuilder) -> None:
    """Changing the model index of a non-editable combo must not raise out of the cursor-reset slot.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    combo = window.model_combo
    combo.setEditable(False)
    assert combo.lineEdit() is None

    with capture_logs() as logs:
        combo.addItems(["alpha", "beta"])
        combo.setCurrentIndex(1)

    assert [entry for entry in logs if entry["event"] == "unhandled_exception"] == []
    assert combo.currentText() == "beta"


def test_sandbox_toolbar_toggle_updates_its_label(build_window: _WindowBuilder) -> None:
    """Checking and unchecking the Sandbox toolbar button flips its ON/OFF label.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    button = _attr(window, "_sandbox_btn", QPushButton)
    assert button.text() == "Sandbox: OFF"

    button.setChecked(True)
    assert button.text() == "Sandbox: ON"

    button.setChecked(False)
    assert button.text() == "Sandbox: OFF"


def test_status_refresh_does_nothing_while_the_window_is_closing(build_window: _WindowBuilder) -> None:
    """No status fetch is started once shutdown has begun.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    _put(window, "_shutting_down", value=True)

    _invoke(window, "_refresh_system_status")

    assert _attr(window, "_status_refresh_in_flight", bool) is False


def test_status_refresh_does_not_overlap_a_fetch_in_flight(build_window: _WindowBuilder, qapp: QApplication) -> None:
    """A tick that arrives while a fetch is still pending is skipped, so the pending flag is never cleared by a second fetch.

    Args:
        build_window: Factory for real main windows.
        qapp: The application.
    """
    window = build_window()
    _put(window, "_status_refresh_in_flight", value=True)

    _invoke(window, "_refresh_system_status")
    _ = drain_bridge_workers()
    qapp.processEvents()

    assert _attr(window, "_status_refresh_in_flight", bool) is True


def test_status_payload_that_is_not_a_mapping_only_clears_the_failure_state(build_window: _WindowBuilder) -> None:
    """A malformed status payload resets the in-flight flag and failure count but changes no label.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    _put(window, "_status_refresh_in_flight", value=True)
    _put(window, "_status_failure_count", value=3)
    status_label = window.status_label
    status_label.setText("untouched")

    _invoke(window, "_on_system_status_fetched", "not a mapping")

    assert _attr(window, "_status_refresh_in_flight", bool) is False
    assert _attr(window, "_status_failure_count", int) == 0
    assert status_label.text() == "untouched"
    assert not _attr(window, "_token_label", QLabel).text()


def test_status_payload_updates_the_token_label_only_for_a_new_positive_total(build_window: _WindowBuilder) -> None:
    """The token label follows the provider total with thousands separators and ignores totals that are unchanged, zero or not integers.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    token_label = _attr(window, "_token_label", QLabel)

    _invoke(window, "_on_system_status_fetched", {"state": "idle", "session_id": None, "metrics": {"provider_total_tokens": 1234}})

    assert window.status_label.text() == "State: idle"
    assert token_label.text() == "Tokens: 1,234"
    assert token_label.toolTip() == "Tokens: 1,234"
    assert _attr(window, "_session_token_total", int) == 1234

    token_label.setText("sentinel")
    for ignored in (1234, 0, "99"):
        _invoke(window, "_on_system_status_fetched", {"state": "idle", "metrics": {"provider_total_tokens": ignored}})
        assert token_label.text() == "sentinel"
    assert _attr(window, "_session_token_total", int) == 1234


def test_memory_label_reports_the_model_cache_in_whole_megabytes(build_window: _WindowBuilder) -> None:
    """The memory label text is the cache size in MiB rounded to a whole number, or empty when the cache is empty.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    cache = get_global_model_cache()
    previous = getattr(cache, "_current_memory_bytes")
    memory_label = _attr(window, "_memory_label", QLabel)
    try:
        setattr(cache, "_current_memory_bytes", 3 * _MIB + 100)
        assert _call(MainWindow, "_compute_memory_label_text") == "Cache: 3MB"
        _invoke(window, "_refresh_memory_status")
        assert memory_label.text() == "Cache: 3MB"
        assert memory_label.toolTip() == "Cache: 3MB"

        setattr(cache, "_current_memory_bytes", 0)
        assert not _call(MainWindow, "_compute_memory_label_text")
        _invoke(window, "_refresh_memory_status")
        assert not memory_label.text()
        assert not memory_label.toolTip()
    finally:
        setattr(cache, "_current_memory_bytes", previous)


def test_discovery_status_stays_blank_until_a_discovery_object_is_wired(build_window: _WindowBuilder) -> None:
    """Without a discovery object the status label is left exactly as it was.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    window.model_status_label.setText("stale")

    _invoke(window, "_refresh_model_discovery_status")

    assert window.model_status_label.text() == "stale"


def test_discovery_status_summarizes_the_latest_event_of_each_provider(build_window: _WindowBuilder) -> None:
    """The status counts providers whose latest discovery succeeded, and is blank before any discovery ran.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    discovery = ModelDiscovery(_orchestrator(window).provider_registry)
    window.set_model_discovery(discovery)
    window.model_status_label.setText("stale")

    _invoke(window, "_refresh_model_discovery_status")
    assert not window.model_status_label.text()

    events = _events_of(discovery)
    events.append(
        DiscoveryEvent(provider="openai", timestamp=datetime(2026, 1, 1, tzinfo=UTC), model_count=0, success=False, error_message="old"),
    )
    events.append(DiscoveryEvent(provider="openai", timestamp=datetime(2026, 1, 2, tzinfo=UTC), model_count=3, success=True))
    events.append(DiscoveryEvent(provider="google", timestamp=datetime(2026, 1, 1, tzinfo=UTC), model_count=0, success=False))

    _invoke(window, "_refresh_model_discovery_status")

    assert window.model_status_label.text() == "Discovery: 1/2 providers OK"
    assert window.model_status_label.toolTip() == "Discovery: 1/2 providers OK"


def test_discovery_status_names_the_failure_of_the_active_provider(build_window: _WindowBuilder) -> None:
    """When the active provider's latest discovery failed, its display name and error are appended to the summary.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window(_ScriptedProvider(provider_ids.OPENAI))
    discovery = ModelDiscovery(_orchestrator(window).provider_registry)
    window.set_model_discovery(discovery)
    _events_of(discovery).append(
        DiscoveryEvent(
            provider="openai",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            model_count=0,
            success=False,
            error_message="bad key",
        ),
    )

    _invoke(window, "_refresh_model_discovery_status")

    assert window.model_status_label.text() == f"Discovery: 0/1 providers OK {_EM_DASH} OpenAI: bad key"


def test_unwritable_scripts_and_tools_directories_do_not_stop_startup(build_window: _WindowBuilder) -> None:
    """When the script and tool directories cannot be created the window still opens, without a tool installer.

    Args:
        build_window: Factory for real main windows.
    """
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "scripts").write_text("occupied", encoding="utf-8")
    (config_dir / "tools").write_text("occupied", encoding="utf-8")

    with capture_logs() as logs:
        window = build_window()

    events = [entry["event"] for entry in logs]
    assert "script_manager_init_skipped" in events
    assert "tool_installer_init_skipped" in events
    assert "tool_installer_initialized" not in events
    assert not hasattr(window, "_tool_installer")
    assert _run(window, "_refresh_tool_status") == {}


@pytest.mark.spawns_process
def test_refresh_tool_status_describes_every_installable_tool(build_window: _WindowBuilder) -> None:
    """Every tool except the dynamic-loading meta-tool gets an entry whose message matches its availability and path.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()

    result = _run(window, "_refresh_tool_status")

    assert isinstance(result, dict)
    statuses = cast("dict[str, ToolStatusEntry]", result)
    assert set(statuses) == {tool.value for tool in ToolName if tool is not ToolName.TOOLS}
    for entry in statuses.values():
        if not entry["available"]:
            assert entry["path"] is None
            assert entry["message"] == "Not installed"
        elif entry["path"] is None:
            assert entry["message"] == "Available"
        else:
            assert entry["message"] == f"Installed at {entry['path']}"


def test_configure_mcp_without_a_service_tells_the_operator(
    build_window: _WindowBuilder,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """With no MCP service running, both settings entry points explain that instead of opening a dialog.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
        qtbot: pytest-qt bot owning the stand-in parent widget.
    """
    window = build_window()
    _invoke(window, "_stop_mcp_service")
    information = _record_dialog(monkeypatch, "information")
    other_parent = QWidget()
    qtbot.addWidget(other_parent)

    _invoke(window, "_on_configure_mcp")
    _invoke(window, "_on_configure_mcp_from", other_parent)
    _invoke(window, "_on_browse_mcp_context")

    assert len(information.calls) == 3
    assert information.calls[0][:2] == (window, "MCP Servers")
    assert information.calls[1][:2] == (other_parent, "MCP Servers")
    assert information.calls[2][:2] == (window, "MCP resources and prompts")
    for call in information.calls:
        assert "The MCP client is not available in this session." in str(call[2])


def test_configure_mcp_opens_the_settings_dialog_over_the_requested_parent(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """The MCP settings dialog opens over the window, or over another dialog when the request came from one.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot owning the stand-in parent widget.
    """
    window = build_window()
    other_parent = QWidget()
    qtbot.addWidget(other_parent)
    parents: list[object] = []

    def _close(dialog: QDialog) -> None:
        """Note the dialog's parent and close it as the Close button would.

        Args:
            dialog: The settings dialog that opened.
        """
        parents.append(dialog.parent())
        dialog.reject()

    watcher = DialogWatcher(McpConfigDialog, _close)
    try:
        _invoke(window, "_on_configure_mcp")
        _invoke(window, "_on_configure_mcp_from", other_parent)
    finally:
        watcher.stop()

    assert parents == [window, other_parent]


def test_mcp_context_change_notices_name_the_server_and_what_changed(build_window: _WindowBuilder) -> None:
    """Resource-list and prompt-list announcements reach the chat as one-line notices naming the server.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    chat = _attr(window, "_chat_panel", ChatPanel)

    _invoke(window, "_on_mcp_context_changed", McpContextEvent("files", McpContextChange.RESOURCES_LISTED))
    assert chat.notice.splitlines()[-1] == "MCP server 'files' changed its list of resources."

    _invoke(window, "_on_mcp_context_changed", McpContextEvent("files", McpContextChange.PROMPTS_LISTED))
    assert chat.notice.splitlines()[-1] == "MCP server 'files' changed its list of prompts."


def test_progress_that_is_not_a_tool_progress_is_ignored(build_window: _WindowBuilder) -> None:
    """A payload that is not a ``ToolProgress`` neither updates the activity panel nor emits a status.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    statuses = _status_log(window)

    _invoke(window, "_on_tool_progress", "not progress")

    assert statuses == []


def test_progress_for_a_call_that_is_not_running_emits_no_status(build_window: _WindowBuilder) -> None:
    """Progress that names no running call is not announced in the status bar.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    statuses = _status_log(window)

    _invoke(window, "_on_tool_progress", ToolProgress(call_id="ghost", progress=1.0))

    assert statuses == []


def test_successful_tool_result_logs_a_preview_cut_to_the_display_limit(build_window: _WindowBuilder) -> None:
    """A long successful result is logged as a preview of exactly the display limit ending in an ellipsis, and its activity row is removed.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    chat = _attr(window, "_chat_panel", ChatPanel)
    _invoke(window, "_on_tool_call", ToolCall(id="c-1", tool_name="ghidra", function_name="decompile", arguments={}))
    assert chat.tool_activity.running == ["c-1"]
    result = ToolResult(call_id="c-1", success=True, result="A" * (_PREVIEW_LIMIT + 100), error=None, duration_ms=12.5)

    with capture_logs() as logs:
        _invoke(window, "_on_tool_result", result)

    by_event = {entry["event"]: entry for entry in logs}
    assert by_event["orchestrator_tool_result"]["duration_ms"] == pytest.approx(12.5)
    assert by_event["orchestrator_tool_result_payload"]["result_preview"] == "A" * (_PREVIEW_LIMIT - _ELLIPSIS_LENGTH) + "..."
    assert "orchestrator_tool_error" not in by_event
    assert chat.tool_activity.running == []


def test_successful_tool_result_within_the_limit_is_logged_whole(build_window: _WindowBuilder) -> None:
    """A short successful result is logged verbatim.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    result = ToolResult(call_id="c-2", success=True, result="short text", error=None, duration_ms=1.0)

    with capture_logs() as logs:
        _invoke(window, "_on_tool_result", result)

    previews = [entry["result_preview"] for entry in logs if entry["event"] == "orchestrator_tool_result_payload"]
    assert previews == ["short text"]


def test_successful_tool_result_with_nothing_in_it_logs_no_payload_and_no_error(build_window: _WindowBuilder) -> None:
    """An empty successful result produces neither a payload preview nor an error entry.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    result = ToolResult(call_id="c-3", success=True, result={}, error=None, duration_ms=1.0)

    with capture_logs() as logs:
        _invoke(window, "_on_tool_result", result)

    tool_events = [entry["event"] for entry in logs if str(entry["event"]).startswith("orchestrator_tool")]
    assert tool_events == ["orchestrator_tool_result"]


def test_failed_tool_result_is_logged_as_a_failure_with_its_error(build_window: _WindowBuilder) -> None:
    """A failed result is logged twice, as a failed result and as a tool error, each carrying the error text, and no payload preview.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    result = ToolResult(call_id="c-4", success=False, result=None, error="exploded", duration_ms=3.0)

    with capture_logs() as logs:
        _invoke(window, "_on_tool_result", result)

    by_event = {entry["event"]: entry for entry in logs}
    assert by_event["orchestrator_tool_result_failed"]["error"] == "exploded"
    assert by_event["orchestrator_tool_error"]["error"] == "exploded"
    assert "orchestrator_tool_result_payload" not in by_event


def test_patch_binary_result_registers_a_manual_patch_on_the_session(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """A successful ``patch_binary`` call's result is registered as an applied manual patch on the active session.

    The call is announced through the window's own tool-call handler, as the orchestrator does, so the window knows the result belongs to
    ``patch_binary``.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the asynchronous registration.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-1")
    session = _orchestrator(window).current_session
    assert session is not None
    _invoke(window, "_on_tool_call", ToolCall(id="p-1", tool_name="patch_binary", function_name="apply_patch", arguments={}))
    payload = {"offset": 16, "original": b"\x90\x90", "patched": b"\xcc\xcc", "description": "NOP to int3"}
    result = ToolResult(call_id="p-1", success=True, result=payload, error=None, duration_ms=1.0)

    _invoke(window, "_on_tool_result", result)

    qtbot.waitUntil(lambda: len(session.patches) == 1, timeout=_NEGATIVE_WAIT_MS)
    patch = session.patches[0]
    assert (patch.address, patch.original_bytes, patch.new_bytes, patch.description, patch.applied) == (
        16,
        b"\x90\x90",
        b"\xcc\xcc",
        "NOP to int3",
        True,
    )


@pytest.mark.parametrize(
    ("payload", "expected_total", "expected_label"),
    [
        pytest.param("not a mapping", 0, "", id="not-a-mapping"),
        pytest.param({"result": 1}, 0, "", id="no-usage"),
        pytest.param({"usage": "x"}, 0, "", id="usage-not-a-mapping"),
        pytest.param({"usage": {"total_tokens": 1234}}, 1234, "Tokens: 1,234", id="total"),
        pytest.param({"usage": {"input_tokens": 100, "output_tokens": 23}}, 123, "Tokens: 123", id="input-plus-output"),
        pytest.param({"usage": {"input_tokens": "9", "output_tokens": 5}}, 5, "Tokens: 5", id="non-integer-input-counts-as-zero"),
        pytest.param({"usage": {"total_tokens": 0}}, 0, "", id="zero-total"),
        pytest.param({"usage": {"total_tokens": "7"}}, 0, "", id="non-integer-total-and-no-parts"),
    ],
)
def test_usage_payload_adds_to_the_session_token_total(
    build_window: _WindowBuilder,
    payload: object,
    expected_total: int,
    expected_label: str,
) -> None:
    """Only positive integer token counts, taken from the total or from input plus output, change the running total and its label.

    Args:
        build_window: Factory for real main windows.
        payload: Payload handed to the accumulator.
        expected_total: Session total expected afterwards.
        expected_label: Token label text expected afterwards.
    """
    window = build_window()

    _invoke(window, "_accumulate_usage_from_payload", payload)

    assert _attr(window, "_session_token_total", int) == expected_total
    assert _attr(window, "_token_label", QLabel).text() == expected_label


def test_usage_payloads_accumulate_across_calls(build_window: _WindowBuilder) -> None:
    """Each payload's tokens are added to what was counted before.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()

    _invoke(window, "_accumulate_usage_from_payload", {"usage": {"total_tokens": 10}})
    _invoke(window, "_accumulate_usage_from_payload", {"usage": {"total_tokens": 15}})

    assert _attr(window, "_session_token_total", int) == 25
    assert _attr(window, "_token_label", QLabel).toolTip() == "Tokens: 25"


@pytest.mark.parametrize(
    ("error", "shown"),
    [
        pytest.param(RuntimeError("worker blew up"), "worker blew up", id="exception"),
        pytest.param("plain failure", "'plain failure'", id="non-exception"),
    ],
)
def test_async_error_restores_the_chat_and_reports_the_failure(
    build_window: _WindowBuilder,
    monkeypatch: pytest.MonkeyPatch,
    error: object,
    shown: str,
) -> None:
    """A failed background operation re-enables input, clears running-call state and tells the operator what went wrong.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
        error: Error payload handed to the handler.
        shown: Text the error dialog is expected to show.
    """
    window = build_window()
    chat = _attr(window, "_chat_panel", ChatPanel)
    send_button = _attr(_attr(chat, "_input", QFrame), "_send_button", QPushButton)
    chat.set_input_enabled(enabled=False)
    _invoke(window, "_on_tool_call", ToolCall(id="c-9", tool_name="ghidra", function_name="decompile", arguments={}))
    _put(window, "_stream_append", value=chat.add_streaming_message())
    critical = _record_dialog(monkeypatch, "critical")
    statuses = _status_log(window)
    assert send_button.isEnabled() is False

    _invoke(window, "_on_async_error", error)

    assert send_button.isEnabled() is True
    assert chat.tool_activity.running == []
    assert _attr(window, "_running_call_names", dict) == {}
    assert getattr(window, "_stream_append") is None
    assert statuses[-1] == "Error"
    assert critical.calls == [(window, "Error", shown)]


def test_hex_context_is_placed_in_the_chat_input(build_window: _WindowBuilder) -> None:
    """Context from the hex editor is loaded into the chat input for the operator to review, with a status message.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    chat = _attr(window, "_chat_panel", ChatPanel)
    statuses = _status_log(window)

    _invoke(window, "_on_hex_context_ready", "00 01 02 03")

    text_edit = _attr(_attr(chat, "_input", QFrame), "_text_edit", QTextEdit)
    assert text_edit.toPlainText() == "00 01 02 03"
    assert statuses == ["Hex context loaded into chat input"]


def test_analysis_that_is_not_a_summary_is_not_displayed(build_window: _WindowBuilder) -> None:
    """Only a real analysis summary reaches the analysis panel; anything else creates no tab.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    panel = window.tool_panel
    count_before = panel.tab_widget.count()

    _invoke(window, "_on_bridge_analysis_displayed", "not a summary")

    assert "analysis" not in panel.tabs
    assert panel.tab_widget.count() == count_before


def test_sending_without_a_model_asks_for_one_and_starts_nothing(build_window: _WindowBuilder, monkeypatch: pytest.MonkeyPatch) -> None:
    """A message sent with no model selected is refused with a prompt to choose one.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
    """
    window = build_window()
    warning = _record_dialog(monkeypatch, "warning")
    statuses = _status_log(window)
    assert not window.model_combo.currentText()

    _invoke(window, "_on_user_message", "hello")

    assert statuses == ["Select a model before sending"]
    assert warning.calls == [(window, "No Model Selected", "Select a model in the toolbar before sending a message.")]


def test_binary_load_result_without_metadata_is_reported_as_a_failed_load(
    build_window: _WindowBuilder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A load that returns something other than binary metadata rolls the tool buttons back and reports the failure.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
    """
    window = build_window()
    critical = _record_dialog(monkeypatch, "critical")
    statuses = _status_log(window)
    window.x64dbg_btn.setEnabled(True)

    _invoke(window, "_on_binary_loaded", object())

    assert window.x64dbg_btn.isEnabled() is False
    assert window.current_binary is None
    assert _attr(window, "_binary_label", QLabel).text() == "No binary loaded"
    assert statuses == ["Binary load failed"]
    assert critical.calls == [(window, "Load Failed", "Failed to load binary: binary load returned no metadata")]


def test_session_load_result_without_a_session_is_reported_as_a_failed_load(
    build_window: _WindowBuilder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session load that returns no session is reported to the operator and leaves the chat usable.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
    """
    window = build_window()
    warning = _record_dialog(monkeypatch, "warning")
    statuses = _status_log(window)

    _invoke(window, "_on_session_loaded", "sid-9", object())

    assert statuses == ["Session load failed"]
    assert warning.calls == [(window, "Load Session", "Could not load session sid-9: session load returned no session")]


def test_deleting_the_active_session_cancels_the_work_tied_to_it(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """Deleting the session the orchestrator is using announces that its work is being cancelled, and the cancellation completes.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the cancellation to finish.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-1")
    session = _orchestrator(window).current_session
    assert session is not None
    statuses = _status_log(window)

    _invoke(window, "_on_session_deleted", session.id)

    assert statuses[0] == f"Active session {session.id} deleted; cancelling work"
    qtbot.waitUntil(lambda: statuses[-1] == "Ready", timeout=_WAIT_MS)


def test_new_session_dialog_name_and_description_reach_the_new_session(build_window: _WindowBuilder, qtbot: QtBot) -> None:
    """The name and description typed into the New Session dialog are stored on the session created for the toolbar selection.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the asynchronous creation.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    window.model_combo.setCurrentText("model-x")
    chat = _attr(window, "_chat_panel", ChatPanel)
    chat.add_message(Message(role="user", content="old question"))
    window.tool_panel.address_label.setText("0x1000")
    statuses = _status_log(window)

    def _fill_and_accept(dialog: QDialog) -> None:
        """Type a name and description into the dialog and accept it.

        Args:
            dialog: The New Session dialog.
        """
        _attr(dialog, "_name_input", QLineEdit).setText("  Case Alpha  ")
        _attr(dialog, "_description_input", QLineEdit).setText("  first pass  ")
        dialog.accept()

    watcher = DialogWatcher(NewSessionDialog, _fill_and_accept)
    try:
        _invoke(window, "_on_new_session")
    finally:
        watcher.stop()

    assert chat.get_messages() == []
    assert not window.tool_panel.address_label.text()
    assert statuses[0] == "Creating new session..."
    orchestrator = _orchestrator(window)
    qtbot.waitUntil(lambda: orchestrator.current_session is not None, timeout=_WAIT_MS)
    session = orchestrator.current_session
    assert session is not None
    assert (session.name, session.notes, session.provider, session.model) == ("Case Alpha", "first pass", provider_ids.ANTHROPIC, "model-x")


def test_cancelled_new_session_dialog_changes_nothing(build_window: _WindowBuilder) -> None:
    """Dismissing the New Session dialog leaves the chat, the status bar and the session as they were.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    window.model_combo.setCurrentText("model-x")
    chat = _attr(window, "_chat_panel", ChatPanel)
    chat.add_message(Message(role="user", content="keep me"))
    statuses = _status_log(window)

    def _cancel(dialog: QDialog) -> None:
        """Dismiss the dialog as the Cancel button would.

        Args:
            dialog: The New Session dialog.
        """
        dialog.reject()

    watcher = DialogWatcher(NewSessionDialog, _cancel)
    try:
        _invoke(window, "_on_new_session")
    finally:
        watcher.stop()

    assert len(watcher.seen) == 1
    assert [message.content for message in chat.get_messages()] == ["keep me"]
    assert statuses == []
    assert _orchestrator(window).current_session is None


def test_new_session_without_a_model_asks_for_one(build_window: _WindowBuilder, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting the New Session dialog with no model selected warns instead of clearing the chat or creating a session.

    Args:
        build_window: Factory for real main windows.
        monkeypatch: The test's monkeypatch fixture.
    """
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    chat = _attr(window, "_chat_panel", ChatPanel)
    chat.add_message(Message(role="user", content="keep me"))
    warning = _record_dialog(monkeypatch, "warning")
    statuses = _status_log(window)

    def _accept(dialog: QDialog) -> None:
        """Accept the dialog as the OK button would.

        Args:
            dialog: The New Session dialog.
        """
        dialog.accept()

    watcher = DialogWatcher(NewSessionDialog, _accept)
    try:
        _invoke(window, "_on_new_session")
    finally:
        watcher.stop()

    assert warning.calls == [(window, "Warning", "Please select a model first.")]
    assert [message.content for message in chat.get_messages()] == ["keep me"]
    assert statuses == []
    assert _orchestrator(window).current_session is None


def test_load_session_dialog_selection_loads_the_chosen_session(
    build_window: _WindowBuilder,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Choosing a row in the Session Manager dialog and accepting it loads that session through the orchestrator.

    Args:
        build_window: Factory for real main windows.
        qtbot: pytest-qt bot used to wait for the asynchronous load.
        monkeypatch: The test's monkeypatch fixture, used to move the dialog's sidecar directory under ``tmp_path``.
        tmp_path: Per-test temporary directory.
    """
    monkeypatch.setattr(SessionManagerDialog, "SESSIONS_DIR", tmp_path / "sidecar-sessions")
    window = build_window(_ScriptedProvider(provider_ids.ANTHROPIC))
    _ = _run(window, "_ensure_active_session", provider_ids.ANTHROPIC, "m-1")
    session = _orchestrator(window).current_session
    assert session is not None
    session_id, session_name = session.id, session.name
    statuses = _status_log(window)

    def _select_and_accept(dialog: QDialog) -> None:
        """Select the first row of the session table and accept the dialog.

        Args:
            dialog: The Session Manager dialog.
        """
        _attr(dialog, "_session_table", QTableWidget).selectRow(0)
        dialog.accept()

    watcher = DialogWatcher(SessionManagerDialog, _select_and_accept)
    try:
        _invoke(window, "_on_load_session")
    finally:
        watcher.stop()

    qtbot.waitUntil(lambda: f"Session loaded: {session_name}" in statuses, timeout=_WAIT_MS)
    assert f"Loading session {session_id}..." in statuses


def test_confirmation_without_a_mcp_service_is_denied_when_the_dialog_is_dismissed(build_window: _WindowBuilder) -> None:
    """With no MCP service the dialog is built without a server label, and dismissing it answers the waiting call with a denial.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    _invoke(window, "_stop_mcp_service")
    call = ToolCall(id="k-1", tool_name="ghidra", function_name="decompile", arguments={})
    future = run_bridge_coroutine(_new_future(value=None), timeout_s=_BRIDGE_TIMEOUT_S)
    assert future is not None

    def _dismiss(dialog: QDialog) -> None:
        """Dismiss the dialog without deciding.

        Args:
            dialog: The confirmation dialog.
        """
        dialog.reject()

    watcher = DialogWatcher(ToolConfirmationDialog, _dismiss)
    try:
        _invoke(window, "_show_confirmation_dialog", (call, future, ensure_loop()))
    finally:
        watcher.stop()

    assert len(watcher.seen) == 1
    assert run_bridge_coroutine(_await_future(future), timeout_s=_BRIDGE_TIMEOUT_S) is False


def test_confirmation_does_not_overwrite_a_future_that_is_already_resolved(build_window: _WindowBuilder) -> None:
    """A call whose future already holds an answer keeps it, and delivering the dismissal does not raise on the loop.

    Args:
        build_window: Factory for real main windows.
    """
    window = build_window()
    _invoke(window, "_stop_mcp_service")
    call = ToolCall(id="k-2", tool_name="ghidra", function_name="decompile", arguments={})
    future = run_bridge_coroutine(_new_future(value=True), timeout_s=_BRIDGE_TIMEOUT_S)
    assert future is not None
    problems: list[dict[str, object]] = []
    _ = run_bridge_coroutine(_collect_loop_errors(problems), timeout_s=_BRIDGE_TIMEOUT_S)

    def _dismiss(dialog: QDialog) -> None:
        """Dismiss the dialog without deciding.

        Args:
            dialog: The confirmation dialog.
        """
        dialog.reject()

    watcher = DialogWatcher(ToolConfirmationDialog, _dismiss)
    try:
        _invoke(window, "_show_confirmation_dialog", (call, future, ensure_loop()))
        _ = run_bridge_coroutine(asyncio.sleep(0), timeout_s=_BRIDGE_TIMEOUT_S)
    finally:
        watcher.stop()
        _ = run_bridge_coroutine(_collect_loop_errors(None), timeout_s=_BRIDGE_TIMEOUT_S)

    assert future.result() is True
    assert problems == []
