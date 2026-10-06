# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the session, export, tool-settings, provider and model-selection handlers of the main window.

Every test drives a real ``MainWindow`` built over a real ``Orchestrator``, ``SessionManager`` with a SQLite store, ``ProviderRegistry`` and
``ToolRegistry``. Per-user state (``providers.json``, ``tools.json``, credentials) is redirected into the test's temporary directory, so
nothing reads the user's configuration. Provider traffic goes only to a loopback ``OpenAIModelsServer``. Expected values come from files the
tests write themselves (session JSON, tool settings), from the strings the handlers are documented to show, and from the saved state read
back through the real stores.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import time
import types
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn, cast, override

import pytest
from PyQt6.QtCore import QSignalBlocker, QTimer
from PyQt6.QtWidgets import QApplication, QComboBox, QDialog, QFileDialog, QListWidget, QMessageBox, QWidget
from structlog.testing import capture_logs

from intellicrack.core.config import Config, ToolConfig, get_config_file
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BridgeAnalysisSummary, Message, ModelInfo, ProviderCredentials, SectionInfo, ToolName
from intellicrack.credentials.env_loader import unregister_instance_mapping
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, run_bridge_coroutine
from intellicrack.ui.panels.hex_editor import HexEditorPanel
from intellicrack.ui.provider_config import ModelSelectionDialog
from intellicrack.ui.tool_config import ToolConfigDialog
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    import asyncio
    from collections.abc import Callable, Generator, Mapping, Sequence
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_WAIT_MS: int = 30_000
_BRIDGE_TIMEOUT_S: float = 60.0
_WORKER_JOIN_MS: int = 60_000
_MODAL_POLL_MS: int = 5
_MODAL_DEADLINE_S: float = 45.0
_GATEWAY_ID: str = "my-gw"
_MODEL_A: str = "alpha-model"
_MODEL_B: str = "beta-model"
_API_KEY_FIELD: str = "api" + "_key"
_GATEWAY_SECRET: str = "gateway" + "-" + "value"


class _Rig(NamedTuple):
    """A real main window together with the collaborators a test inspects.

    Attributes:
        window: The constructed, unshown main window.
        orchestrator: The orchestrator the window drives.
        store: The SQLite session store behind the orchestrator's session manager.
        config: The configuration the window was built with.
        statuses: Every status message the window emitted since construction.
        information: Recorder installed over ``QMessageBox.information``.
        warning: Recorder installed over ``QMessageBox.warning``.
        tmp_path: The test's private directory.
    """

    window: MainWindow
    orchestrator: Orchestrator
    store: SessionStore
    config: Config
    statuses: list[str]
    information: DialogRecorder
    warning: DialogRecorder
    tmp_path: Path


class _RecordingHexPanel(HexEditorPanel):
    """A real hex editor panel that counts how often it is asked to save.

    Attributes:
        save_calls: Number of ``save`` calls received.
    """

    save_calls: int = 0

    @override
    def save(self) -> bool:
        """Count the call, then defer to the real save.

        Returns:
            bool: What the real panel's save returns.
        """
        self.save_calls += 1
        return super().save()


class _FailingDisconnectProvider(ConfigurableProvider):
    """A real configurable provider whose disconnect always fails."""

    @override
    async def disconnect(self) -> None:
        """Refuse to disconnect.

        Raises:
            RuntimeError: Always, standing in for a transport that cannot be closed.
        """
        message = "disconnect refused"
        raise RuntimeError(message)


def _clear_save_as(namespace: dict[str, Any]) -> None:
    """Fill a class body so the class has no ``save_as`` method.

    Args:
        namespace: The class namespace being built.
    """
    namespace["save_as"] = None


_SaveOnlyHexPanel: type[_RecordingHexPanel] = cast(
    "type[_RecordingHexPanel]",
    types.new_class("_SaveOnlyHexPanel", (_RecordingHexPanel,), None, _clear_save_as),
)


def _raise_missing(_owner: object) -> NoReturn:
    """Behave as an attribute the object does not have.

    Args:
        _owner: The object the property is read from.

    Raises:
        AttributeError: Always.
    """
    message = "attribute hidden for the test"
    raise AttributeError(message)


def _manager_without(*names: str) -> type[SessionManager]:
    """Build a session manager class that has none of the named attributes.

    Args:
        *names: Attribute names the class must not expose.

    Returns:
        type[SessionManager]: A subclass of the real manager whose named attributes raise ``AttributeError``.
    """

    def _populate(namespace: dict[str, Any]) -> None:
        """Hide each name in the class body.

        Args:
            namespace: The class namespace being built.
        """
        for name in names:
            namespace[name] = property(_raise_missing)

    return cast("type[SessionManager]", types.new_class("_HiddenAttributesManager", (SessionManager,), None, _populate))


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


def _dialog_returning(path: str) -> Callable[..., tuple[str, str]]:
    """Build a stand-in for a ``QFileDialog`` picker that returns a fixed path.

    Args:
        path: Path the picker reports; empty for a cancelled dialog.

    Returns:
        Callable[..., tuple[str, str]]: A function with the shape of ``getOpenFileName`` and ``getSaveFileName``.
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


def _write_json(path: Path, payload: object) -> None:
    """Write a JSON file, creating its directory.

    Args:
        path: Destination file.
        payload: JSON-compatible content.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(json.dumps(payload), encoding="utf-8")


def _write_providers(
    instances: Mapping[str, ProviderInstance],
    sections: Mapping[str, Mapping[str, object]] | None = None,
) -> None:
    """Write ``providers.json`` into the redirected state root.

    Args:
        instances: Instance records keyed by id.
        sections: Per-provider sections keyed by provider id.
    """
    payload: dict[str, object] = {name: dict(section) for name, section in (sections or {}).items()}
    payload["instances"] = {instance_id: instance.to_mapping() for instance_id, instance in instances.items()}
    _write_json(get_config_file("providers.json"), payload)


def _write_tools_config(payload: Mapping[str, Mapping[str, object]]) -> None:
    """Write ``tools.json`` into the redirected state root.

    Args:
        payload: Settings keyed by tool id.
    """
    _write_json(get_config_file("tools.json"), payload)


def _loopback_instance(base_url: str = "http://127.0.0.1:9/v1") -> ProviderInstance:
    """Build an instance that needs no key and points at a loopback address.

    Args:
        base_url: The endpoint the instance talks to.

    Returns:
        ProviderInstance: The instance, id ``my-gw``.
    """
    return ProviderInstance(instance_id=_GATEWAY_ID, display_name="Corp Gateway", api_base=base_url, requires_api_key=False)


def _connected_provider(rig: _Rig, provider_class: type[ConfigurableProvider], instance: ProviderInstance) -> ConfigurableProvider:
    """Build, connect and register a provider of a given class.

    Args:
        rig: The window rig whose registry receives the provider.
        provider_class: Class of provider to build.
        instance: The endpoint record the provider is built from.

    Returns:
        ConfigurableProvider: The connected provider.
    """
    provider = provider_class(instance)
    _ = run_bridge_coroutine(provider.connect(ProviderCredentials()), timeout_s=_BRIDGE_TIMEOUT_S)
    assert provider.is_connected
    rig.orchestrator.provider_registry.register(provider)
    return provider


def _release_provider(provider: ConfigurableProvider) -> None:
    """Close a provider's HTTP client on the bridge loop, even when its own disconnect fails.

    Args:
        provider: The connected provider.
    """
    _ = run_bridge_coroutine(ConfigurableProvider.disconnect(provider), timeout_s=_BRIDGE_TIMEOUT_S)


def _load_session(rig: _Rig, *, notes: str = "") -> Session:
    """Store a session and make the orchestrator load it as its current one.

    Args:
        rig: The window rig.
        notes: Notes the stored session carries.

    Returns:
        Session: The session object the orchestrator and its session manager now hold.
    """
    stored = Session.create(provider="openai", model="zz-model", name="Round trip")
    stored.notes = notes
    rig.store.save(stored)
    loaded = run_bridge_coroutine(rig.orchestrator.load_session(stored.id), timeout_s=_BRIDGE_TIMEOUT_S)
    assert loaded is not None
    return loaded


def _attach_discovery(rig: _Rig) -> ModelDiscovery:
    """Give the window a model discovery service and keep its start-up kickoff from firing.

    Args:
        rig: The window rig.

    Returns:
        ModelDiscovery: The discovery service now attached to the window.
    """
    discovery = ModelDiscovery(rig.orchestrator.provider_registry)
    rig.window.set_model_discovery(discovery)
    _set_priv(rig.window, "_initial_discovery_triggered", value=True)
    return discovery


@contextlib.contextmanager
def _auto_accept(dialog_type: type[QDialog], configure: Callable[[QDialog], None] | None = None) -> Generator[list[QDialog]]:
    """Accept the first modal dialog of a type that opens while the context is active.

    A polling timer stands in for the user pressing OK, so the handler under test runs its real modal loop.

    Args:
        dialog_type: Class of dialog to accept.
        configure: Optional action run on the dialog just before it is accepted.

    Yields:
        list[QDialog]: The dialogs accepted so far.
    """
    seen: list[QDialog] = []
    started = time.monotonic()

    def _tick() -> None:
        """Accept the awaited dialog once it is the active modal window."""
        modal = QApplication.activeModalWidget()
        if not isinstance(modal, QDialog):
            return
        if isinstance(modal, dialog_type) and modal not in seen:
            seen.append(modal)
            if configure is not None:
                configure(modal)
            modal.accept()
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
    config = Config(tools_directory=tools_dir, logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
    store = SessionStore(db_path=tmp_path / "sessions.db")
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=store, auto_save=False),
    )
    window = MainWindow(config, orchestrator)
    statuses: list[str] = []
    _ = window.status_update.connect(statuses.append)
    information = DialogRecorder()
    warning = DialogRecorder()
    monkeypatch.setattr(QMessageBox, "information", staticmethod(information))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(warning))
    try:
        yield _Rig(window, orchestrator, store, config, statuses, information, warning, tmp_path)
    finally:
        window.close()
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
        provider = _connected_provider(rig, ConfigurableProvider, _loopback_instance(server.base_url))
        _call(rig.window, "_populate_provider_combo")
        try:
            yield provider
        finally:
            _ = run_bridge_coroutine(provider.disconnect(), timeout_s=_BRIDGE_TIMEOUT_S)


def test_session_deleted_for_current_session_cancels_orchestrator_work(rig: _Rig, qtbot: QtBot) -> None:
    """Deleting the active session runs the orchestrator's cancel, which clears a stray cancel flag.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop while the cancel runs.
    """
    session = _load_session(rig)
    cancel_event = cast("asyncio.Event", _priv(rig.orchestrator, "_cancel_event"))
    cancel_event.set()

    _call(rig.window, "_on_session_deleted", session.id)

    assert rig.statuses[0] == f"Active session {session.id} deleted; cancelling work"
    qtbot.waitUntil(lambda: not cancel_event.is_set(), timeout=_WAIT_MS)
    qtbot.waitUntil(lambda: "Ready" in rig.statuses, timeout=_WAIT_MS)


def test_save_session_persists_the_current_session(rig: _Rig, qtbot: QtBot) -> None:
    """Save writes the orchestrator's in-memory session to the store.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop while the save runs.
    """
    session = _load_session(rig)
    session.notes = "edited after load"

    _call(rig.window, "_on_save_session")

    assert rig.statuses[0] == "Saving session..."
    qtbot.waitUntil(lambda: "Ready" in rig.statuses, timeout=_WAIT_MS)
    stored = rig.store.load(session.id)
    assert stored is not None
    assert stored.notes == "edited after load"


def test_export_chat_without_messages_reports_nothing_to_export(rig: _Rig) -> None:
    """An empty conversation shows an information dialog and offers no file dialog.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_export_chat")

    assert rig.information.calls == [(rig.window, "Export", "No messages to export.")]


def test_export_chat_cancelled_dialog_writes_nothing(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the save dialog leaves no file and shows no confirmation.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _call(_priv(rig.window, "_chat_panel"), "add_message", Message(role="user", content="hello"))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(""))

    _call(rig.window, "_on_export_chat")

    assert rig.information.calls == []
    assert list(rig.tmp_path.glob("*.txt")) == []


def test_export_chat_writes_each_message_with_role_and_time(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """The export holds one block per message: upper-case role, wall-clock time, then the content.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    chat = _priv(rig.window, "_chat_panel")
    _call(chat, "add_message", Message(role="user", content="hello", timestamp=datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)))
    _call(
        chat,
        "add_message",
        Message(role="assistant", content="world\nsecond line", timestamp=datetime(2026, 3, 4, 11, 12, 13, tzinfo=UTC)),
    )
    target = rig.tmp_path / "chat.txt"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))

    _call(rig.window, "_on_export_chat")

    assert target.read_text(encoding="utf-8") == "[USER] 05:06:07\nhello\n\n[ASSISTANT] 11:12:13\nworld\nsecond line\n\n"
    assert rig.information.calls == [(rig.window, "Export", f"Chat exported to {target}")]


def test_export_session_without_active_session_reports_it(rig: _Rig) -> None:
    """Exporting with no current session shows an information dialog.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_export_session")

    assert rig.information.calls == [(rig.window, "Export", "No active session to export.")]


def test_export_session_cancelled_dialog_exports_nothing(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the save dialog starts no export.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_session(rig)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(""))

    _call(rig.window, "_on_export_session")

    assert "Exporting session..." not in rig.statuses
    assert rig.information.calls == []
    assert rig.warning.calls == []


def test_export_session_without_session_manager_warns(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """An orchestrator with no session manager makes the export warn instead of start.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_session(rig)
    _set_priv(rig.orchestrator, "_sessions", None)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(rig.tmp_path / "out.json")))

    _call(rig.window, "_on_export_session")

    assert rig.warning.calls == [(rig.window, "Export", "Session manager unavailable.")]
    assert "Exporting session..." not in rig.statuses


def test_export_session_writes_current_session_file(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """Export writes the current session to the chosen file and confirms only after the write.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the export completes.
    """
    session = _load_session(rig)
    target = rig.tmp_path / "exported.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))

    _call(rig.window, "_on_export_session")

    assert rig.statuses[-1] == "Exporting session..."
    qtbot.waitUntil(lambda: bool(rig.information.calls), timeout=_WAIT_MS)
    assert rig.information.calls == [(rig.window, "Export", f"Session exported to {target}")]
    _assert_in_order(rig.statuses, ["Exporting session...", "Session exported"])
    exported = json.loads(target.read_text(encoding="utf-8"))
    assert exported["session"]["id"] == session.id
    assert exported["session"]["provider"] == "openai"
    assert exported["session"]["model"] == "zz-model"


def test_export_session_falls_back_to_export_json(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """A session manager without ``export_current`` still exports through ``export_json`` using the session id.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the export completes.
    """
    session = _load_session(rig)
    _set_priv(rig.orchestrator, "_sessions", _manager_without("export_current")(store=rig.store, auto_save=False))
    target = rig.tmp_path / "fallback.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))

    _call(rig.window, "_on_export_session")

    qtbot.waitUntil(lambda: bool(rig.information.calls), timeout=_WAIT_MS)
    assert rig.information.calls == [(rig.window, "Export", f"Session exported to {target}")]
    assert json.loads(target.read_text(encoding="utf-8"))["session"]["id"] == session.id


def test_export_session_without_any_export_method_warns(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """A session manager with neither export method makes the export warn instead of start.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = _load_session(rig)
    _set_priv(rig.orchestrator, "_sessions", _manager_without("export_current", "export_json")(store=rig.store, auto_save=False))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(rig.tmp_path / "none.json")))

    _call(rig.window, "_on_export_session")

    assert rig.warning.calls == [(rig.window, "Export", "Session manager unavailable.")]
    assert "Exporting session..." not in rig.statuses


def test_export_session_failure_reports_the_error(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """A failing export shows the manager's error and writes no file.

    The orchestrator reports a current session while its session manager holds none, so the manager refuses the export.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the failure is reported.
    """
    _set_priv(rig.orchestrator, "_current_session", Session.create(provider="openai", model="zz-model"))
    target = rig.tmp_path / "never.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))

    _call(rig.window, "_on_export_session")

    qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
    assert rig.warning.calls == [(rig.window, "Export", "Failed to export session: no current session")]
    _assert_in_order(rig.statuses, ["Exporting session...", "Session export failed"])
    assert not target.exists()


def test_import_session_cancelled_dialog_imports_nothing(rig: _Rig) -> None:
    """Cancelling the open dialog starts no import.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_import_session")

    assert "Importing session..." not in rig.statuses
    assert rig.warning.calls == []


def test_import_session_without_session_manager_warns(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """An orchestrator with no session manager makes the import warn instead of start.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _set_priv(rig.orchestrator, "_sessions", None)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(rig.tmp_path / "in.json")))

    _call(rig.window, "_on_import_session")

    assert rig.warning.calls == [(rig.window, "Import", "Session manager unavailable.")]
    assert "Importing session..." not in rig.statuses


def test_import_session_manager_without_import_support_warns(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """A session manager with no ``import_json`` makes the import warn instead of start.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _set_priv(rig.orchestrator, "_sessions", _manager_without("import_json")(store=rig.store, auto_save=False))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(rig.tmp_path / "in.json")))

    _call(rig.window, "_on_import_session")

    assert rig.warning.calls == [(rig.window, "Import", "Session manager does not support import.")]
    assert "Importing session..." not in rig.statuses


def test_import_session_stores_the_exported_session(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """Importing a session file stores that session and confirms only after it is stored.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the import completes.
    """
    fresh = Session.create(provider="openai", model="zz-model", name="Imported once")
    source = rig.tmp_path / "fresh.json"
    rig.store.export_to_json(fresh, source)
    assert rig.store.load(fresh.id) is None
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(source)))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: bool(rig.information.calls), timeout=_WAIT_MS)
    assert rig.information.calls == [(rig.window, "Import", "Session imported successfully.")]
    _assert_in_order(rig.statuses, ["Importing session...", "Session imported"])
    stored = rig.store.load(fresh.id)
    assert stored is not None
    assert stored.name == "Imported once"
    assert stored.provider == "openai"


def test_import_session_invalid_json_reports_a_parse_error(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """A file that is not JSON gets the friendly parse-error dialog.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the failure is reported.
    """
    source = rig.tmp_path / "broken.json"
    _ = source.write_text('{"id": ', encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(source)))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
    assert len(rig.warning.calls) == 1
    owner, title, text = rig.warning.calls[0]
    assert (owner, title) == (rig.window, "Import")
    assert text.startswith("Invalid session file: could not parse JSON.\n\n")
    _assert_in_order(rig.statuses, ["Importing session...", "Session import failed"])


def test_import_session_invalid_format_reports_the_reason(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """A JSON file that is not a session is refused with the manager's reason.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the failure is reported.
    """
    source = rig.tmp_path / "not_a_session.json"
    _write_json(source, {"session": {"name": "no identifier"}})
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(source)))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
    assert rig.warning.calls == [(rig.window, "Import", "Failed to import session: invalid session file format")]
    _assert_in_order(rig.statuses, ["Importing session...", "Session import failed"])


def test_import_session_missing_file_reports_the_error(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """A path that no longer exists is reported with the manager's error text.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the failure is reported.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(rig.tmp_path / "gone.json")))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
    assert rig.warning.calls == [(rig.window, "Import", "Failed to import session: session file not found")]
    _assert_in_order(rig.statuses, ["Importing session...", "Session import failed"])


def test_import_session_duplicate_declined_keeps_the_stored_session(rig: _Rig, monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    """Declining the replace prompt cancels the import and leaves the stored session unchanged.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the import is cancelled.
    """
    original = Session.create(provider="openai", model="zz-model")
    rig.store.save(original)
    source = rig.tmp_path / "duplicate.json"
    rig.store.export_to_json(dataclasses.replace(original, notes="replacement notes"), source)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(source)))
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.No))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: "Session import cancelled" in rig.statuses, timeout=_WAIT_MS)
    assert "Session import failed" not in rig.statuses
    assert rig.information.calls == []
    stored = rig.store.load(original.id)
    assert stored is not None
    assert not stored.notes


def test_import_session_duplicate_confirmed_replaces_the_stored_session(
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """Confirming the replace prompt imports again with replacement and stores the file's version.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the replacement import completes.
    """
    original = Session.create(provider="openai", model="zz-model")
    rig.store.save(original)
    source = rig.tmp_path / "duplicate.json"
    rig.store.export_to_json(dataclasses.replace(original, notes="replacement notes"), source)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _dialog_returning(str(source)))
    monkeypatch.setattr(QMessageBox, "question", _answer(QMessageBox.StandardButton.Yes))

    _call(rig.window, "_on_import_session")

    qtbot.waitUntil(lambda: bool(rig.information.calls), timeout=_WAIT_MS)
    assert rig.information.calls == [(rig.window, "Import", "Session imported successfully.")]
    assert rig.statuses.count("Importing session...") == 2
    _assert_in_order(rig.statuses, ["Importing session...", "Importing session...", "Session imported"])
    stored = rig.store.load(original.id)
    assert stored is not None
    assert stored.notes == "replacement notes"


def test_save_patched_binary_without_save_support_reports_it(rig: _Rig) -> None:
    """An embedded hex editor that can neither save as nor save gets an information dialog.

    Args:
        rig: The window rig.
    """
    bare = QWidget()
    rig.window.tool_panel.embedded_tools["hex_editor"] = bare
    try:
        _call(rig.window, "_on_save_patched_binary")
    finally:
        bare.deleteLater()

    assert rig.information.calls == [(rig.window, "Save", "Hex editor does not support saving.")]


def test_save_patched_binary_uses_save_when_there_is_no_save_as(rig: _Rig) -> None:
    """An embedded hex editor without ``save_as`` is asked to ``save`` and no dialog appears.

    Args:
        rig: The window rig.
    """
    panel = _SaveOnlyHexPanel()
    rig.window.tool_panel.embedded_tools["hex_editor"] = panel
    try:
        _call(rig.window, "_on_save_patched_binary")
        saved = panel.save_calls
    finally:
        _ = panel.stop_tool()
        panel.close()
        panel.deleteLater()

    assert saved == 1
    assert rig.information.calls == []


def test_export_analysis_without_panel_reports_it(rig: _Rig) -> None:
    """Exporting before any analysis panel exists shows an information dialog.

    Args:
        rig: The window rig.
    """
    assert rig.window.tool_panel.get_panel("analysis") is None

    _call(rig.window, "_on_export_analysis")

    assert rig.information.calls == [(rig.window, "Export", "No analysis available.")]


def test_export_analysis_without_data_reports_it(rig: _Rig) -> None:
    """An analysis panel that holds no analysis shows an information dialog.

    Args:
        rig: The window rig.
    """
    _ = rig.window.tool_panel.add_analysis_panel()

    _call(rig.window, "_on_export_analysis")

    assert rig.information.calls == [(rig.window, "Export", "No analysis data available.")]


def _analysis_summary() -> BridgeAnalysisSummary:
    """Build a small analysis summary holding one section.

    Returns:
        BridgeAnalysisSummary: A completed summary for ``sample.exe``.
    """
    return BridgeAnalysisSummary(
        binary_name="sample.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=4096,
                virtual_size=512,
                raw_size=512,
                characteristics=0x60000020,
                entropy=6.5,
                raw_offset=1024,
            ),
        ],
        functions=[],
        format_info="PE32+",
        architecture="x64",
        source_bridges=["ghidra"],
        analysis_notes=["first note"],
        complete=True,
    )


def test_export_analysis_cancelled_dialog_writes_nothing(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling the save dialog leaves no file and shows no confirmation.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    rig.window.tool_panel.add_analysis_panel().set_analysis(_analysis_summary())
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(""))

    _call(rig.window, "_on_export_analysis")

    assert rig.information.calls == []
    assert list(rig.tmp_path.glob("*.json")) == []


def test_export_analysis_writes_nested_json(rig: _Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """The exported file is structured JSON, with the section as an object rather than its repr.

    Args:
        rig: The window rig.
        monkeypatch: Pytest monkeypatch fixture.
    """
    rig.window.tool_panel.add_analysis_panel().set_analysis(_analysis_summary())
    target = rig.tmp_path / "analysis.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _dialog_returning(str(target)))

    _call(rig.window, "_on_export_analysis")

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "binary_name": "sample.exe",
        "strings": [],
        "imports": [],
        "exports": [],
        "sections": [
            {
                "name": ".text",
                "virtual_address": 4096,
                "virtual_size": 512,
                "raw_size": 512,
                "characteristics": 0x60000020,
                "entropy": 6.5,
                "raw_offset": 1024,
            },
        ],
        "functions": [],
        "format_info": "PE32+",
        "architecture": "x64",
        "source_bridges": ["ghidra"],
        "analysis_notes": ["first note"],
        "complete": True,
    }
    assert rig.information.calls == [(rig.window, "Export", f"Analysis exported to {target}")]


def test_configure_tools_accepted_dialog_reinitializes_enabled_tools(rig: _Rig, qtbot: QtBot) -> None:
    """Accepting the tool settings dialog applies its settings: only enabled tools with a path are re-initialized.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the re-initialization finishes.
    """
    _write_tools_config(
        {
            "ghidra": {"enabled": True, "path": "ghidra-home"},
            "x64dbg": {"enabled": False, "path": "x64dbg-home"},
            "frida": {"enabled": True, "path": ""},
            "cutter": {"enabled": True, "path": "cutter-home"},
            "process": {"enabled": False, "path": ""},
            "binary": {"enabled": False, "path": ""},
        },
    )

    with capture_logs() as captured, _auto_accept(ToolConfigDialog) as seen:
        _call(rig.window, "_on_configure_tools")
        qtbot.waitUntil(lambda: "Tool re-initialization complete" in rig.statuses, timeout=_WAIT_MS)

    assert len(seen) == 1
    assert [entry["tool_id"] for entry in _events(captured, "tool_reinitialized")] == ["ghidra", "cutter"]
    _assert_in_order(rig.statuses, ["Tool settings applied (6 tools configured)", "Tool re-initialization complete"])


def test_tool_config_updated_reports_the_tool(rig: _Rig) -> None:
    """A per-tool settings save is announced in the status bar.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_tool_config_updated", "ghidra")

    assert rig.statuses == ["Tool configuration updated: ghidra"]


def test_apply_tool_settings_reinitializes_only_enabled_configured_tools(rig: _Rig, qtbot: QtBot) -> None:
    """A tool is re-initialized only when the dialog enables it, gives it a path and the configuration enables it too.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the re-initialization finishes.
    """
    rig.config.tools[ToolName.PROCESS] = ToolConfig(enabled=False)
    settings: dict[str, dict[str, object]] = {
        "ghidra": {"enabled": True, "path": "ghidra-home"},
        "x64dbg": {"enabled": True, "path": ""},
        "frida": {"enabled": False, "path": "frida-home"},
        "cutter": {"enabled": True, "path": "cutter-home"},
        "process": {"enabled": True, "path": "process-home"},
    }

    with capture_logs() as captured:
        _call(rig.window, "_apply_tool_settings", settings)
        qtbot.waitUntil(lambda: "Tool re-initialization complete" in rig.statuses, timeout=_WAIT_MS)

    assert [entry["tool_id"] for entry in _events(captured, "tool_reinitialized")] == ["ghidra", "cutter"]
    _assert_in_order(rig.statuses, ["Tool settings applied (5 tools configured)", "Tool re-initialization complete"])


def test_apply_tool_settings_unknown_tool_id_fails_in_isolation(rig: _Rig, qtbot: QtBot) -> None:
    """A tool id the orchestrator does not know is logged as a failed re-initialization and does not abort the batch.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the batch finishes.
    """
    settings: dict[str, dict[str, object]] = {"bogus": {"enabled": True, "path": "bogus-home"}}

    with capture_logs() as captured:
        _call(rig.window, "_apply_tool_settings", settings)
        qtbot.waitUntil(lambda: "Tool re-initialization complete" in rig.statuses, timeout=_WAIT_MS)

    failures = _events(captured, "tool_reinit_failed")
    assert [entry["tool_id"] for entry in failures] == ["bogus"]
    assert _events(captured, "tool_reinitialized") == []


def test_apply_tool_settings_without_candidates_schedules_nothing(rig: _Rig, qapp: QApplication) -> None:
    """Settings that enable no tool with a path schedule no re-initialization.

    Args:
        rig: The window rig.
        qapp: The shared offscreen application.
    """
    settings: dict[str, dict[str, object]] = {"ghidra": {"enabled": False, "path": ""}}

    _call(rig.window, "_apply_tool_settings", settings)
    _ = drain_bridge_workers()
    qapp.processEvents()

    assert rig.statuses == ["Tool settings applied (1 tools configured)"]


def test_tool_reinit_finished_reports_completion(rig: _Rig) -> None:
    """A finished re-initialization batch is announced in the status bar.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_tool_reinit_finished", object())

    assert rig.statuses == ["Tool re-initialization complete"]


def test_tool_reinit_error_reports_failure(rig: _Rig) -> None:
    """A re-initialization batch that raised is logged and announced in the status bar.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured:
        _call(rig.window, "_on_tool_reinit_error", RuntimeError("bridge exploded"))

    assert rig.statuses == ["Tool re-initialization failed"]
    assert [entry["error"] for entry in _events(captured, "tool_reinit_batch_failed")] == ["bridge exploded"]


def test_active_provider_changed_rejects_an_invalid_id(rig: _Rig) -> None:
    """An id that breaks the provider-id grammar is ignored: nothing is selected, remembered or announced.

    Args:
        rig: The window rig.
    """
    combo = _combo(rig.window, "_provider_combo")
    before = combo.currentData()

    _call(rig.window, "_on_active_provider_changed", "Not Valid!")

    assert combo.currentData() == before
    assert not any(message.startswith("Active provider") for message in rig.statuses)
    assert _call(MainWindow, "_remembered_provider") is None


def test_active_provider_changed_unlisted_provider_is_still_remembered(rig: _Rig) -> None:
    """A valid id the toolbar does not list is remembered and announced but changes no selection.

    Args:
        rig: The window rig.
    """
    combo = _combo(rig.window, "_provider_combo")
    before = combo.currentData()

    _call(rig.window, "_on_active_provider_changed", _GATEWAY_ID)

    assert combo.findData(_GATEWAY_ID) == -1
    assert combo.currentData() == before
    assert rig.statuses == [f"Active provider: {_GATEWAY_ID}"]
    assert _call(MainWindow, "_remembered_provider") == _GATEWAY_ID


def test_active_provider_changed_uses_cached_models(rig: _Rig) -> None:
    """Switching to a provider with a cached catalog fills the model combo from the cache and shows each id from its start.

    Args:
        rig: The window rig.
    """
    discovery = _attach_discovery(rig)
    discovery.cache.set("openai", [_model("zz-model-a"), _model("zz-model-b")])
    rig.window.model_combo.addItem("outgoing-model")

    _call(rig.window, "_on_active_provider_changed", "openai")

    assert _combo(rig.window, "_provider_combo").currentData() == "openai"
    assert _model_items(rig.window) == ["zz-model-a", "zz-model-b"]
    assert rig.window.model_combo.currentText() == "zz-model-a"
    line_edit = rig.window.model_combo.lineEdit()
    assert line_edit is not None
    assert line_edit.cursorPosition() == 0
    assert _call(MainWindow, "_remembered_provider") == "openai"
    assert rig.statuses == ["Active provider: openai"]


def test_active_provider_changed_with_a_non_editable_model_combo_fills_it(rig: _Rig) -> None:
    """A model combo without a line edit is still filled from the cached catalog.

    Args:
        rig: The window rig.
    """
    discovery = _attach_discovery(rig)
    discovery.cache.set("openai", [_model("zz-model-a"), _model("zz-model-b")])
    rig.window.model_combo.setEditable(False)

    _call(rig.window, "_on_active_provider_changed", "openai")

    assert rig.window.model_combo.lineEdit() is None
    assert _model_items(rig.window) == ["zz-model-a", "zz-model-b"]
    assert rig.window.model_combo.currentText() == "zz-model-a"


def test_active_provider_changed_without_cache_refreshes_with_the_remembered_model(
    rig: _Rig,
    gateway: ConfigurableProvider,
    qtbot: QtBot,
) -> None:
    """Switching to a provider with no cached catalog refreshes it and restores that provider's own remembered model.

    Args:
        rig: The window rig.
        gateway: The connected loopback provider, listed in the toolbar.
        qtbot: Pumps the event loop until the refresh finishes.
    """
    del gateway
    _ = _attach_discovery(rig)
    _select_provider(rig.window, _GATEWAY_ID)
    rig.window.model_combo.setEditText(_MODEL_B)
    _call(rig.window, "_persist_current_model")
    rig.window.model_combo.setEditText("outgoing-model")

    _call(rig.window, "_on_active_provider_changed", _GATEWAY_ID)

    qtbot.waitUntil(lambda: "Found 2 models" in rig.statuses, timeout=_WAIT_MS)
    assert _model_items(rig.window) == [_MODEL_A, _MODEL_B]
    assert rig.window.model_combo.currentText() == _MODEL_B
    assert rig.window.model_combo.isEnabled()


def test_register_saved_instance_registers_the_saved_provider(rig: _Rig) -> None:
    """A saved instance the registry has never seen is built and registered under its id.

    Args:
        rig: The window rig.
    """
    _write_providers({_GATEWAY_ID: _loopback_instance("http://127.0.0.1:9/v1")})

    provider = _call(rig.window, "_register_saved_instance", _GATEWAY_ID)

    assert isinstance(provider, ConfigurableProvider)
    assert provider.name == _GATEWAY_ID
    assert provider.instance.api_base == "http://127.0.0.1:9/v1"
    assert rig.orchestrator.provider_registry.get(_GATEWAY_ID) is provider


def test_register_saved_instance_without_record_returns_none(rig: _Rig) -> None:
    """An id with no saved record registers nothing.

    Args:
        rig: The window rig.
    """
    assert _call(MainWindow, "_saved_provider_instance", "ghost") is None
    assert _call(rig.window, "_register_saved_instance", "ghost") is None
    assert rig.orchestrator.provider_registry.list_registered() == []


def test_saved_provider_instance_invalid_record_is_none(rig: _Rig) -> None:
    """A record that names no valid instance id yields no instance, and nothing is registered.

    Args:
        rig: The window rig.
    """
    _write_json(get_config_file("providers.json"), {"instances": {_GATEWAY_ID: {"instance_id": 7}}})

    with capture_logs() as captured:
        instance = _call(MainWindow, "_saved_provider_instance", _GATEWAY_ID)
        registered = _call(rig.window, "_register_saved_instance", _GATEWAY_ID)

    assert instance is None
    assert registered is None
    assert rig.orchestrator.provider_registry.list_registered() == []
    assert [entry["instance_id"] for entry in _events(captured, "provider_instance_record_invalid")] == [_GATEWAY_ID, _GATEWAY_ID]


def test_current_instance_provider_without_record_keeps_the_existing_provider(rig: _Rig) -> None:
    """With no saved record the registered provider is used as it is and nothing is replaced.

    Args:
        rig: The window rig.
    """
    existing = ConfigurableProvider(_loopback_instance())
    rig.orchestrator.provider_registry.register(existing)

    selected, stale = _call(rig.window, "_current_instance_provider", _GATEWAY_ID)

    assert selected is existing
    assert stale is None
    assert rig.orchestrator.provider_registry.get(_GATEWAY_ID) is existing


def test_current_instance_provider_unchanged_record_keeps_the_existing_provider(rig: _Rig) -> None:
    """A registered provider built from the saved record as it is now is kept.

    Args:
        rig: The window rig.
    """
    instance = _loopback_instance()
    existing = ConfigurableProvider(instance)
    rig.orchestrator.provider_registry.register(existing)
    _write_providers({_GATEWAY_ID: instance})

    selected, stale = _call(rig.window, "_current_instance_provider", _GATEWAY_ID)

    assert selected is existing
    assert stale is None


def test_current_instance_provider_rebuilds_with_saved_model_overrides(rig: _Rig) -> None:
    """A record the registry has not seen is registered with the capability overrides saved for it.

    Args:
        rig: The window rig.
    """
    _write_providers({_GATEWAY_ID: _loopback_instance()}, {_GATEWAY_ID: {"model_overrides": {"model-one": {"context_window": 4242}}}})

    selected, stale = _call(rig.window, "_current_instance_provider", _GATEWAY_ID)

    assert stale is None
    assert isinstance(selected, ConfigurableProvider)
    assert rig.orchestrator.provider_registry.get(_GATEWAY_ID) is selected
    assert selected.capability_overrides()["model-one"].context_window == 4242


def test_apply_provider_settings_skips_invalid_and_unconnected_entries(rig: _Rig, qapp: QApplication) -> None:
    """An invalid id is skipped, a disabled provider with nothing connected needs no work, and no reconnect is scheduled.

    Args:
        rig: The window rig.
        qapp: The shared offscreen application.
    """
    settings: dict[str, dict[str, object]] = {"Not Valid!": {"enabled": True}, "openai": {"enabled": False}}

    _call(rig.window, "_apply_provider_settings", settings)
    _ = drain_bridge_workers()
    qapp.processEvents()

    assert rig.statuses == ["Provider settings applied (2 providers configured, 0 disabled)"]


def test_apply_provider_settings_isolates_a_stale_provider_disconnect_failure(rig: _Rig, qtbot: QtBot) -> None:
    """A replaced provider that cannot disconnect is logged and the rebuilt provider still connects.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the batch finishes.
    """
    stale = _connected_provider(rig, _FailingDisconnectProvider, _loopback_instance())
    edited = dataclasses.replace(_loopback_instance(), headers={"X-Tenant": "new"})
    _write_providers({_GATEWAY_ID: edited})
    settings: dict[str, dict[str, object]] = {_GATEWAY_ID: {"enabled": True, _API_KEY_FIELD: "", "api_base": ""}}
    try:
        with capture_logs() as captured:
            _call(rig.window, "_apply_provider_settings", settings)
            qtbot.waitUntil(lambda: "Provider connections updated" in rig.statuses, timeout=_WAIT_MS)

        current = rig.orchestrator.provider_registry.get(_GATEWAY_ID)
        assert current is not None
        assert current is not stale
        assert current.is_connected
        failures = _events(captured, "provider_disconnect_failed")
        assert [(entry["provider"], entry["error"]) for entry in failures] == [(_GATEWAY_ID, "disconnect refused")]
        _ = run_bridge_coroutine(current.disconnect(), timeout_s=_BRIDGE_TIMEOUT_S)
    finally:
        _release_provider(stale)


def test_apply_provider_settings_isolates_a_disable_disconnect_failure(rig: _Rig, qtbot: QtBot) -> None:
    """Disabling a connected provider whose disconnect fails is logged and the batch still completes.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the batch finishes.
    """
    provider = _connected_provider(rig, _FailingDisconnectProvider, _loopback_instance())
    settings: dict[str, dict[str, object]] = {_GATEWAY_ID: {"enabled": False}}
    try:
        with capture_logs() as captured:
            _call(rig.window, "_apply_provider_settings", settings)
            qtbot.waitUntil(lambda: "Provider connections updated" in rig.statuses, timeout=_WAIT_MS)

        failures = _events(captured, "provider_disconnect_failed")
        assert [(entry["provider"], entry["error"]) for entry in failures] == [(_GATEWAY_ID, "disconnect refused")]
        assert "Provider settings applied (1 providers configured, 1 disabled)" in rig.statuses
    finally:
        _release_provider(provider)


def test_provider_reconnect_error_reports_failure(rig: _Rig) -> None:
    """A reconnect batch that raised is logged and announced in the status bar.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured:
        _call(rig.window, "_on_provider_reconnect_error", RuntimeError("link down"))

    assert rig.statuses == ["Provider reconnection failed"]
    assert [entry["error"] for entry in _events(captured, "provider_reconnect_batch_failed")] == ["link down"]


def test_refresh_models_without_a_provider_warns(rig: _Rig) -> None:
    """With no provider in the toolbar, refreshing asks the user to pick one and starts nothing.

    Args:
        rig: The window rig.
    """
    _combo(rig.window, "_provider_combo").clear()

    _call(rig.window, "_on_refresh_models")

    assert rig.warning.calls == [(rig.window, "Warning", "Please select a provider first.")]
    assert rig.window.model_refresh_worker is None
    assert "Refreshing models..." not in rig.statuses


def test_refresh_models_for_a_disabled_provider_warns(rig: _Rig) -> None:
    """A provider the configuration disables is not refreshed.

    Args:
        rig: The window rig.
    """
    rig.config.providers["openai"].enabled = False
    _select_provider(rig.window, "openai")

    _call(rig.window, "_on_refresh_models")

    assert rig.warning.calls == [(rig.window, "Warning", "Provider openai is disabled in configuration.")]
    assert rig.window.model_refresh_worker is None


@pytest.mark.parametrize("saved_key", [True, False])
def test_refresh_models_reads_the_key_saved_in_provider_settings(
    rig: _Rig,
    gateway: ConfigurableProvider,
    qtbot: QtBot,
    *,
    saved_key: bool,
) -> None:
    """A key stored in ``providers.json`` counts as credentials for the refresh, and the connected provider lists the models.

    Args:
        rig: The window rig.
        gateway: The connected loopback provider, listed in the toolbar.
        qtbot: Pumps the event loop until the refresh finishes.
        saved_key: Whether the settings file holds a key for the provider.
    """
    del gateway
    if saved_key:
        _write_providers({_GATEWAY_ID: _loopback_instance()}, {_GATEWAY_ID: {_API_KEY_FIELD: _GATEWAY_SECRET}})
    _select_provider(rig.window, _GATEWAY_ID)

    with capture_logs() as captured:
        _call(rig.window, "_on_refresh_models")

    requested = _events(captured, "models_refresh_requested")
    assert [(entry["provider"], entry["has_credentials"], entry["reuse_connected_instance"]) for entry in requested] == [
        (_GATEWAY_ID, saved_key, True),
    ]
    worker = rig.window.model_refresh_worker
    assert worker is not None
    qtbot.waitUntil(lambda: "Found 2 models" in rig.statuses, timeout=_WAIT_MS)
    assert worker.wait(_WORKER_JOIN_MS)
    assert _model_items(rig.window) == [_MODEL_A, _MODEL_B]
    assert rig.window.model_combo.isEnabled()


def test_refresh_models_for_a_non_string_provider_reports_the_failure(rig: _Rig, qtbot: QtBot) -> None:
    """A toolbar entry whose data is not a provider id is refreshed by its text form and the failure is reported.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until the refresh finishes.
    """
    combo = _combo(rig.window, "_provider_combo")
    combo.addItem("Odd provider", 5)
    with QSignalBlocker(combo):
        combo.setCurrentIndex(combo.count() - 1)

    _call(rig.window, "_on_refresh_models")

    worker = rig.window.model_refresh_worker
    assert worker is not None
    qtbot.waitUntil(lambda: bool(rig.warning.calls), timeout=_WAIT_MS)
    assert worker.wait(_WORKER_JOIN_MS)
    assert rig.warning.calls == [(rig.window, "Model Refresh Failed", "No base URL is configured for this provider instance")]
    assert "Failed to refresh models" in rig.statuses
    assert rig.window.model_combo.isEnabled()
    assert _priv(rig.window, "_pending_model_restore_provider") is None


def test_models_refresh_finished_restores_a_typed_model_missing_from_the_catalog(rig: _Rig) -> None:
    """A model id typed before the refresh stays in the combo even when the refreshed catalog lacks it.

    Args:
        rig: The window rig.
    """
    _set_priv(rig.window, "_pending_model_restore", "typed-model")
    _set_priv(rig.window, "_pending_model_restore_provider", "openai")

    _call(rig.window, "_on_models_refresh_finished", success=True, models=["m1", "m2"], message="")

    assert _model_items(rig.window) == ["m1", "m2"]
    assert rig.window.model_combo.currentText() == "typed-model"
    assert rig.statuses == ["Found 2 models"]
    assert not _priv(rig.window, "_pending_model_restore")
    assert _priv(rig.window, "_pending_model_restore_provider") is None


def test_models_refresh_finished_selects_the_remembered_model_of_the_new_provider(rig: _Rig) -> None:
    """With no typed model to restore, the provider's remembered model is selected from the refreshed catalog.

    Args:
        rig: The window rig.
    """
    _select_provider(rig.window, "openai")
    rig.window.model_combo.setEditText("m2")
    _call(rig.window, "_persist_current_model")
    _set_priv(rig.window, "_pending_model_restore", "")
    _set_priv(rig.window, "_pending_model_restore_provider", "openai")

    _call(rig.window, "_on_models_refresh_finished", success=True, models=["m1", "m2", "m3"], message="")

    assert rig.window.model_combo.currentText() == "m2"
    assert rig.window.model_combo.currentIndex() == 1


@pytest.mark.parametrize(("success", "models"), [(False, ["m1"]), (True, [])])
def test_models_refresh_finished_failure_reports_the_message(rig: _Rig, *, success: bool, models: list[str]) -> None:
    """A failed refresh, or one that found no models, re-enables the combo and shows the worker's message.

    Args:
        rig: The window rig.
        success: Whether the worker reported success.
        models: Models the worker reported.
    """
    rig.window.model_combo.setEnabled(False)

    _call(rig.window, "_on_models_refresh_finished", success=success, models=models, message="catalog unavailable")

    assert rig.window.model_combo.isEnabled()
    assert rig.statuses == ["Failed to refresh models"]
    assert rig.warning.calls == [(rig.window, "Model Refresh Failed", "catalog unavailable")]


def test_browse_models_without_an_active_provider_informs(rig: _Rig) -> None:
    """Browsing with no active provider shows an information dialog.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_browse_models")

    assert rig.information.calls == [(rig.window, "Browse Models", "No active provider connected.")]
    assert "Fetching models..." not in rig.statuses


def test_browse_models_result_ignores_a_non_list(rig: _Rig) -> None:
    """A result that is not a model list opens no dialog.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_browse_models_result", "not a list")

    assert rig.statuses == ["Ready"]
    assert rig.information.calls == []


def test_browse_models_result_empty_list_informs(rig: _Rig) -> None:
    """An empty model list shows an information dialog instead of an empty picker.

    Args:
        rig: The window rig.
    """
    _call(rig.window, "_on_browse_models_result", [])

    assert rig.information.calls == [(rig.window, "Browse Models", "No models available.")]


def test_browse_models_selection_updates_the_model_combo(rig: _Rig, gateway: ConfigurableProvider, qtbot: QtBot) -> None:
    """Browsing lists the active provider's models and picking one in the dialog selects it in the toolbar.

    Args:
        rig: The window rig.
        gateway: The connected loopback provider, listed in the toolbar.
        qtbot: Pumps the event loop until the selection is applied.
    """
    del gateway
    rig.orchestrator.provider_registry.set_active(_GATEWAY_ID)

    def _pick_second_model(dialog: QDialog) -> None:
        """Select the dialog's second model row.

        Args:
            dialog: The model selection dialog.
        """
        dialog.findChildren(QListWidget)[0].setCurrentRow(1)

    with _auto_accept(ModelSelectionDialog, _pick_second_model) as seen:
        _call(rig.window, "_on_browse_models")
        qtbot.waitUntil(lambda: f"Model selected: {_MODEL_B}" in rig.statuses, timeout=_WAIT_MS)

    assert len(seen) == 1
    _assert_in_order(rig.statuses, ["Fetching models...", "Ready", f"Model selected: {_MODEL_B}"])
    assert rig.window.model_combo.currentText() == _MODEL_B
    provider = _combo(rig.window, "_provider_combo").currentData()
    assert _call(MainWindow, "_remembered_model_for", provider) == _MODEL_B


def test_sync_model_combo_selects_an_existing_model_without_duplicating_it(rig: _Rig) -> None:
    """Selecting a model already in the combo selects that entry, remembers it and announces it.

    Args:
        rig: The window rig.
    """
    rig.window.model_combo.addItems(["m1", "m2"])

    _call(rig.window, "_sync_model_combo", "m2")

    assert _model_items(rig.window) == ["m1", "m2"]
    assert rig.window.model_combo.currentIndex() == 1
    assert rig.statuses == ["Model selected: m2"]
    provider = _combo(rig.window, "_provider_combo").currentData()
    assert _call(MainWindow, "_remembered_model_for", provider) == "m2"


def test_model_text_committed_without_a_line_edit_does_nothing(rig: _Rig) -> None:
    """A model combo that is not editable has no typed text to commit.

    Args:
        rig: The window rig.
    """
    rig.window.model_combo.setEditable(False)

    _call(rig.window, "_on_model_combo_text_committed")

    assert rig.statuses == []


def test_model_text_committed_blank_text_does_nothing(rig: _Rig) -> None:
    """Blank typed text is neither warned about nor remembered.

    Args:
        rig: The window rig.
    """
    rig.window.model_combo.setEditText("   ")

    _call(rig.window, "_on_model_combo_text_committed")

    assert rig.statuses == []
    provider = _combo(rig.window, "_provider_combo").currentData()
    assert not _call(MainWindow, "_remembered_model_for", provider)


def test_model_text_committed_unknown_model_warns_and_is_remembered(rig: _Rig) -> None:
    """A typed model id missing from the catalog is flagged in the status bar and still remembered.

    Args:
        rig: The window rig.
    """
    rig.window.model_combo.setEditText("custom-model-x")

    _call(rig.window, "_on_model_combo_text_committed")

    assert rig.statuses == ["Custom model id 'custom-model-x' not present in provider catalog - request may fail"]
    provider = _combo(rig.window, "_provider_combo").currentData()
    assert _call(MainWindow, "_remembered_model_for", provider) == "custom-model-x"


def test_kickoff_initial_discovery_runs_once(rig: _Rig, qtbot: QtBot) -> None:
    """The start-up discovery runs a single time however often it is requested.

    Args:
        rig: The window rig.
        qtbot: Pumps the event loop until discovery completes.
    """
    rig.window.set_model_discovery(ModelDiscovery(rig.orchestrator.provider_registry))

    with capture_logs() as captured:
        _call(rig.window, "_kickoff_initial_discovery")
        qtbot.waitUntil(lambda: bool(_events(captured, "initial_model_discovery_completed")), timeout=_WAIT_MS)
        _call(rig.window, "_kickoff_initial_discovery")
        _ = drain_bridge_workers()

    assert _priv(rig.window, "_initial_discovery_triggered") is True
    assert len(_events(captured, "initial_model_discovery_kickoff")) == 1
    completed = _events(captured, "initial_model_discovery_completed")
    assert len(completed) == 1
    assert completed[0]["per_provider_counts"] == {}


def test_initial_discovery_result_populates_the_model_combo(rig: _Rig) -> None:
    """The discovered catalog of the selected provider replaces the combo's models and the first one is shown.

    Args:
        rig: The window rig.
    """
    _ = _attach_discovery(rig)
    _select_provider(rig.window, "openai")
    result = {"anthropic": [_model("other-1")], "openai": [_model("zz-a"), _model("zz-b")]}

    _call(rig.window, "_on_initial_discovery_done", result)

    assert _model_items(rig.window) == ["zz-a", "zz-b"]
    assert rig.window.model_combo.currentText() == "zz-a"
    line_edit = rig.window.model_combo.lineEdit()
    assert line_edit is not None
    assert line_edit.cursorPosition() == 0
    assert not _priv(rig.window, "_pending_model_restore")


def test_initial_discovery_without_a_result_uses_the_cached_catalog(rig: _Rig) -> None:
    """When discovery returns nothing usable, the provider's cached catalog fills the combo.

    Args:
        rig: The window rig.
    """
    discovery = _attach_discovery(rig)
    discovery.cache.set("openai", [_model("zz-a"), _model("zz-b")])
    _select_provider(rig.window, "openai")

    _call(rig.window, "_on_initial_discovery_done", None)

    assert _model_items(rig.window) == ["zz-a", "zz-b"]
    assert rig.window.model_combo.currentText() == "zz-a"


@pytest.mark.parametrize(("pending", "expected_index"), [("zz-b", 1), ("typed-model", -1)])
def test_initial_discovery_restores_the_pending_model(rig: _Rig, pending: str, expected_index: int) -> None:
    """A model waiting to be restored is selected, or typed in when the catalog does not list it, and is then cleared.

    Args:
        rig: The window rig.
        pending: The model waiting to be restored.
        expected_index: Where that model sits in the catalog, or ``-1`` when it is not listed.
    """
    _ = _attach_discovery(rig)
    _select_provider(rig.window, "openai")
    _set_priv(rig.window, "_pending_model_restore", pending)
    _set_priv(rig.window, "_pending_model_restore_provider", "openai")

    _call(rig.window, "_on_initial_discovery_done", {"openai": [_model("zz-a"), _model("zz-b")]})

    assert _model_items(rig.window) == ["zz-a", "zz-b"]
    assert rig.window.model_combo.currentText() == pending
    assert rig.window.model_combo.findText(pending) == expected_index
    assert not _priv(rig.window, "_pending_model_restore")
    assert _priv(rig.window, "_pending_model_restore_provider") is None


def test_initial_discovery_with_a_non_editable_model_combo_fills_it(rig: _Rig) -> None:
    """A model combo without a line edit is still filled from the discovered catalog.

    Args:
        rig: The window rig.
    """
    _ = _attach_discovery(rig)
    _select_provider(rig.window, "openai")
    rig.window.model_combo.setEditable(False)

    _call(rig.window, "_on_initial_discovery_done", {"openai": [_model("zz-a"), _model("zz-b")]})

    assert rig.window.model_combo.lineEdit() is None
    assert _model_items(rig.window) == ["zz-a", "zz-b"]
    assert rig.window.model_combo.currentText() == "zz-a"


def test_initial_discovery_without_models_for_the_provider_leaves_the_combo(rig: _Rig) -> None:
    """A discovery result with no models for the selected provider and an empty cache changes nothing.

    Args:
        rig: The window rig.
    """
    _ = _attach_discovery(rig)
    _select_provider(rig.window, "openai")
    rig.window.model_combo.addItem("keep-me")

    _call(rig.window, "_on_initial_discovery_done", {"anthropic": [_model("other-1")]})

    assert _model_items(rig.window) == ["keep-me"]


def test_initial_discovery_without_a_selected_provider_leaves_the_combo(rig: _Rig) -> None:
    """With no provider in the toolbar there is no catalog to show.

    Args:
        rig: The window rig.
    """
    _ = _attach_discovery(rig)
    _combo(rig.window, "_provider_combo").clear()
    rig.window.model_combo.addItem("keep-me")

    _call(rig.window, "_on_initial_discovery_done", {"openai": [_model("zz-a")]})

    assert _model_items(rig.window) == ["keep-me"]


def test_initial_discovery_error_is_logged(rig: _Rig) -> None:
    """A failed start-up discovery is logged with its error.

    Args:
        rig: The window rig.
    """
    with capture_logs() as captured:
        _call(rig.window, "_on_initial_discovery_error", RuntimeError("probe failed"))

    assert [entry["error"] for entry in _events(captured, "initial_model_discovery_failed")] == ["probe failed"]
