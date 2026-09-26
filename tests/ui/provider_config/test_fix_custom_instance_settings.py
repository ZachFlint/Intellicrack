# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider Settings gates for user-defined provider instances.

Each gate drives the real settings widgets, the real Provider Settings dialog
or the real main window against a redirected per-user state root holding real
``.env`` and ``providers.json`` files, a real :class:`ProviderRegistry`, and a
loopback OpenAI-compatible endpoint. They fail when:

* a custom instance's API key typed into its page is not written to ``.env``,
  so the next launch starts without it;
* a keyless preset instance cannot be tested or refreshed without a key;
* Test Connection, Refresh Models or the automatic refresh when the page opens
  send the key over plain HTTP to a public host without acknowledgement;
* a provider error from a connected instance's model listing kills the refresh
  instead of falling back to a direct listing;
* adding an instance throws away unsaved edits on other pages;
* an import silently overwrites an existing instance or accepts a built-in id;
* deleting an instance leaves its ``<ID>_API_BASE`` in ``.env`` to hijack an
  instance re-added under the same id, or leaves it registered and connected;
* Set Active on an unconnected instance raises out of the button handler;
* an instance cannot be renamed, or shows its id instead of its name;
* the toolbar provider selector ignores added and deleted instances;
* applying settings keeps the stale provider built before the instance was
  edited, or disconnects a keyless instance for want of a key.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QCoreApplication, Qt, QThread
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QCheckBox, QComboBox, QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton, QWidget

from intellicrack.core.config import Config, get_config_file
from intellicrack.core.logging import get_logger
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialLoader, unregister_instance_mapping
from intellicrack.credentials.provider_settings import ProviderSettingsStore
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.ids import BUILTIN_PROVIDER_IDS
from intellicrack.providers.instances import ProviderInstance, instance_from_preset_id
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.provider_config import ModelRefreshWorker, ProviderConfigDialog, ProviderInstanceDialog, ProviderSettingsWidget
from tests._helpers.openai_models_server import MODELS_PATH, OpenAIModelsServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator
    from pathlib import Path

    from pytestqt.qtbot import QtBot
    from structlog.stdlib import BoundLogger

    from intellicrack.credentials.provider_settings import ProviderConnectPolicy


_main_module = importlib.import_module("intellicrack.main")
_initialize_providers = cast(
    "Callable[[ProviderRegistry, CredentialLoader, BoundLogger, ProviderConnectPolicy | None], Coroutine[object, object, None]]",
    _main_module._initialize_providers,
)
_load_provider_connect_policy = cast(
    "Callable[[Config, CredentialLoader, BoundLogger], ProviderConnectPolicy]",
    _main_module._load_provider_connect_policy,
)
_resolve_env_path = cast("Callable[[], Path]", _main_module._resolve_env_path)

_KEY = "sk-gateway-" + ("g" * 32)
_MODEL_ID = "served-model"
_WAIT_MS = 20_000
_SETTLE_MS = 500
_WORKER_JOIN_MS = 60_000
_INSTANCE_IDS: tuple[str, ...] = ("my-gw", "local-vllm", "fresh", "renamed-gw")
_OFFLINE_SECTIONS: dict[str, dict[str, object]] = {
    "ollama": {"enabled": False, "schema_version": 3},
    "local_transformers": {"enabled": False, "schema_version": 3},
}


@pytest.fixture
def state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Redirect the per-user state root into the test directory with no provider variables set.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    for instance_id in _INSTANCE_IDS:
        prefix = instance_id.upper().replace("-", "_")
        for suffix in ("API_KEY", "API_BASE", "ORGANIZATION", "PROJECT"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    with redirected_state_root(monkeypatch, tmp_path) as root:
        _write_settings({}, _OFFLINE_SECTIONS)
        yield root
    for instance_id in _INSTANCE_IDS:
        unregister_instance_mapping(instance_id)


@pytest.fixture
def keyed_endpoint() -> Iterator[OpenAIModelsServer]:
    """Provide a loopback OpenAI-compatible endpoint accepting only ``_KEY``.

    Yields:
        OpenAIModelsServer: The running server.
    """
    with OpenAIModelsServer(model_ids=[_MODEL_ID], accepted_key=_KEY) as server:
        yield server


@pytest.fixture
def keyless_endpoint() -> Iterator[OpenAIModelsServer]:
    """Provide a loopback OpenAI-compatible endpoint accepting requests without a key.

    Yields:
        OpenAIModelsServer: The running server.
    """
    with OpenAIModelsServer(model_ids=[_MODEL_ID]) as server:
        yield server


def _store() -> ProviderSettingsStore:
    """Return the settings store for the redirected state root.

    Returns:
        ProviderSettingsStore: The store.
    """
    return ProviderSettingsStore(get_config_file("providers.json"))


def _write_settings(instances: dict[str, ProviderInstance], sections: dict[str, dict[str, object]] | None = None) -> None:
    """Write ``providers.json`` with these instances and sections.

    Args:
        instances: Instance records keyed by id.
        sections: Provider sections.
    """
    path = get_config_file("providers.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {**_OFFLINE_SECTIONS, **(sections or {})}
    payload["instances"] = {instance_id: instance.to_mapping() for instance_id, instance in instances.items()}
    _ = path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _env_text() -> str:
    """Return the redirected ``.env`` content.

    Returns:
        str: The file content, or empty when it does not exist.
    """
    path = _resolve_env_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _child[T](owner: QWidget, name: str, expected_type: type[T]) -> T:
    """Fetch a named child control with a runtime type check.

    Args:
        owner: The widget holding the control.
        name: Attribute name of the control.
        expected_type: The control's expected type.

    Returns:
        T: The control.
    """
    control: object = getattr(owner, name)
    assert isinstance(control, expected_type), f"{name} is {type(control).__name__}, expected {expected_type.__name__}"
    return control


def _join_workers(widget: QWidget) -> None:
    """Join a settings page's refresh and test workers and deliver their results.

    Args:
        widget: The settings page.
    """
    for worker_name in ("_refresh_worker", "_test_worker"):
        worker: object = getattr(widget, worker_name, None)
        if isinstance(worker, QThread):
            assert worker.wait(_WORKER_JOIN_MS), f"{worker_name} did not finish"
    QCoreApplication.processEvents()


def _settle_page(widget: QWidget) -> None:
    """Let a page's scheduled refresh start and finish before the page closes.

    Args:
        widget: The settings page.
    """
    QTest.qWait(_SETTLE_MS)
    _join_workers(widget)


def _settle_dialog(dialog: QWidget) -> None:
    """Let every page of a Provider Settings dialog settle before it closes.

    Args:
        dialog: The dialog.
    """
    QTest.qWait(_SETTLE_MS)
    pages: dict[str, ProviderSettingsWidget] = getattr(dialog, "_provider_widgets", {})
    for page in pages.values():
        _join_workers(page)


def _make_page(qtbot: QtBot, provider_id: str) -> ProviderSettingsWidget:
    """Build a settings page bound to the redirected state root.

    Args:
        qtbot: pytest-qt bot.
        provider_id: The provider to configure.

    Returns:
        ProviderSettingsWidget: The live page.
    """
    page = ProviderSettingsWidget(provider_id, config_path=get_config_file("providers.json"))
    qtbot.addWidget(page, before_close_func=_settle_page)
    return page


def _make_dialog(qtbot: QtBot, registry: ProviderRegistry | None) -> ProviderConfigDialog:
    """Build the Provider Settings dialog bound to the redirected state root.

    Args:
        qtbot: pytest-qt bot.
        registry: The provider registry the dialog manages, if any.

    Returns:
        ProviderConfigDialog: The live dialog.
    """
    dialog = ProviderConfigDialog(provider_registry=registry)
    qtbot.addWidget(dialog, before_close_func=_settle_dialog)
    return dialog


def _select(dialog: ProviderConfigDialog, provider_id: str) -> None:
    """Select a provider in the dialog's list the way a click does.

    Args:
        dialog: The dialog.
        provider_id: The provider to select.
    """
    provider_list = _child(dialog, "_provider_list", QListWidget)
    for row in range(provider_list.count()):
        item = provider_list.item(row)
        if item is not None and item.data(Qt.ItemDataRole.UserRole) == provider_id:
            provider_list.setCurrentRow(row)
            return
    pytest.fail(f"{provider_id} is not listed")


def _listed_ids(dialog: ProviderConfigDialog) -> list[str]:
    """Return the provider ids the dialog lists, in order.

    Args:
        dialog: The dialog.

    Returns:
        list[str]: Listed ids.
    """
    provider_list = _child(dialog, "_provider_list", QListWidget)
    listed: list[str] = []
    for row in range(provider_list.count()):
        item = provider_list.item(row)
        if item is not None:
            listed.append(str(item.data(Qt.ItemDataRole.UserRole)))
    return listed


def _connected(instance: ProviderInstance, credentials: ProviderCredentials) -> ConfigurableProvider:
    """Build and connect a configurable provider on the bridge loop.

    Args:
        instance: The instance to connect.
        credentials: The connect credentials.

    Returns:
        ConfigurableProvider: The connected provider.
    """
    provider = ConfigurableProvider(instance)
    _ = run_bridge_coroutine(provider.connect(credentials))
    assert provider.is_connected
    return provider


def _run_startup() -> ProviderRegistry:
    """Run the production provider startup sequence against the redirected state root.

    Returns:
        ProviderRegistry: The populated registry.
    """

    async def _startup() -> ProviderRegistry:
        logger: BoundLogger = get_logger(__name__)
        credentials = CredentialLoader(_resolve_env_path())
        registry = ProviderRegistry()
        policy = _load_provider_connect_policy(Config(), credentials, logger)
        await _initialize_providers(registry, credentials, logger, policy)
        return registry

    return asyncio.run(_startup())


def _list_model_ids(provider: ConfigurableProvider) -> list[str]:
    """List a connected provider's models on a fresh loop.

    Args:
        provider: The connected provider.

    Returns:
        list[str]: Model ids.
    """

    async def _list() -> list[str]:
        try:
            return [model.id for model in await provider.list_models()]
        finally:
            await provider.disconnect()

    return asyncio.run(_list())


@pytest.mark.usefixtures("state_root")
def test_custom_instance_key_is_saved_to_env_and_used_at_startup(qtbot: QtBot, keyed_endpoint: OpenAIModelsServer) -> None:
    """A key typed into a custom instance's page lands in ``.env`` and the next launch connects with it.

    Args:
        qtbot: pytest-qt bot.
        keyed_endpoint: Loopback endpoint accepting only ``_KEY``.
    """
    _write_settings({"my-gw": ProviderInstance(instance_id="my-gw", display_name="My Gateway", api_base=keyed_endpoint.base_url)})
    page = _make_page(qtbot, "my-gw")
    _settle_page(page)

    _child(page, "_api_key_input", QLineEdit).setText(_KEY)
    page.save_settings()

    assert f"MY_GW_API_KEY={_KEY}" in _env_text().splitlines()
    registry = _run_startup()
    provider = registry.get("my-gw")
    assert isinstance(provider, ConfigurableProvider)
    assert provider.is_connected, "the saved key was not loaded at startup"
    assert _list_model_ids(provider) == [_MODEL_ID]
    assert keyed_endpoint.requests()[-1].headers["authorization"] == f"Bearer {_KEY}"


@pytest.mark.usefixtures("state_root")
def test_keyless_preset_instance_tests_and_refreshes_without_a_key(qtbot: QtBot, keyless_endpoint: OpenAIModelsServer) -> None:
    """Test Connection and Refresh Models work for a vLLM instance that has no key.

    Args:
        qtbot: pytest-qt bot.
        keyless_endpoint: Keyless loopback endpoint.
    """
    instance = instance_from_preset_id("vllm", instance_id="local-vllm")
    assert instance is not None
    instance.api_base = keyless_endpoint.base_url
    _write_settings({"local-vllm": instance})
    page = _make_page(qtbot, "local-vllm")
    combo = _child(page, "_model_combo", QComboBox)
    status = _child(page, "_status_label", QLabel)

    qtbot.waitUntil(lambda: combo.findText(_MODEL_ID) >= 0, timeout=_WAIT_MS)
    _join_workers(page)
    QTest.mouseClick(_child(page, "_test_btn", QPushButton), Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: status.text().startswith("Connected to"), timeout=_WAIT_MS)
    _join_workers(page)

    assert all("authorization" not in request.headers for request in keyless_endpoint.requests())


@pytest.mark.usefixtures("state_root")
def test_probes_withhold_the_key_from_a_public_plaintext_host(
    qtbot: QtBot,
    keyed_endpoint: OpenAIModelsServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening the page, Test Connection and Refresh send no key over plain HTTP to a public host until acknowledged.

    The loopback server also acts as the HTTP proxy, so every request addressed
    to the public host reaches it and every header that would have left the
    machine is recorded.

    Args:
        qtbot: pytest-qt bot.
        keyed_endpoint: Loopback endpoint and proxy accepting only ``_KEY``.
        monkeypatch: Pytest monkeypatch fixture.
    """
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, keyed_endpoint.origin)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "")
    public_base = "http://gateway.example.com/v1"
    _write_settings({"my-gw": ProviderInstance(instance_id="my-gw", api_base=public_base)})
    _ = _resolve_env_path().write_text(f"MY_GW_API_KEY={_KEY}\n", encoding="utf-8")

    page = _make_page(qtbot, "my-gw")
    _settle_page(page)
    QTest.mouseClick(_child(page, "_test_btn", QPushButton), Qt.MouseButton.LeftButton)
    _settle_page(page)
    QTest.mouseClick(_child(page, "_refresh_models_btn", QPushButton), Qt.MouseButton.LeftButton)
    _settle_page(page)

    leaked = [request for request in keyed_endpoint.requests() if "authorization" in request.headers]
    assert leaked == [], f"the key was sent over plain HTTP to a public host: {leaked}"

    _child(page, "_insecure_ack_checkbox", QCheckBox).setChecked(True)
    QTest.mouseClick(_child(page, "_test_btn", QPushButton), Qt.MouseButton.LeftButton)
    status = _child(page, "_status_label", QLabel)
    qtbot.waitUntil(lambda: status.text().startswith("Connected to"), timeout=_WAIT_MS)
    _join_workers(page)
    sent = keyed_endpoint.requests()[-1]
    assert sent.target == f"{public_base}/models"
    assert sent.headers["authorization"] == f"Bearer {_KEY}"


@pytest.mark.usefixtures("state_root")
def test_model_refresh_falls_back_when_the_connected_provider_errors(qapp: object, keyless_endpoint: OpenAIModelsServer) -> None:
    """A ``ProviderError`` from the connected provider's listing falls back to a direct listing.

    Args:
        qapp: Qt application fixture.
        keyless_endpoint: Keyless loopback endpoint.
    """
    del qapp
    broken = ProviderInstance(instance_id="my-gw", api_base=keyless_endpoint.broken_base_url, requires_api_key=False)
    provider = _connected(broken, ProviderCredentials())
    results: list[tuple[bool, list[str], str]] = []
    worker = ModelRefreshWorker("my-gw", "", keyless_endpoint.base_url, provider=provider)
    worker.refresh_finished.connect(lambda success, models, message: results.append((bool(success), list(models), str(message))))

    worker.run()

    assert results, "the refresh ended without reporting a result"
    assert results[-1][0] is True
    assert results[-1][1] == [_MODEL_ID]

    failing = ModelRefreshWorker("my-gw", "", keyless_endpoint.broken_base_url, provider=provider)
    failing.refresh_finished.connect(lambda success, models, message: results.append((bool(success), list(models), str(message))))
    failing.run()
    assert results[-1][0] is False
    _ = run_bridge_coroutine(provider.disconnect())


@pytest.mark.usefixtures("state_root")
def test_adding_an_instance_keeps_unsaved_edits_on_other_pages(qtbot: QtBot) -> None:
    """A page with unsaved edits survives an instance being added.

    Args:
        qtbot: pytest-qt bot.
    """
    dialog = _make_dialog(qtbot, None)
    pages: dict[str, ProviderSettingsWidget] = dialog._provider_widgets
    openai_page = pages["openai"]
    _child(openai_page, "_api_key_input", QLineEdit).setText("sk-typed-not-saved")

    dialog._persist_instance(ProviderInstance(instance_id="fresh", api_base="https://fresh.example/v1"))

    assert pages["openai"] is openai_page
    assert _child(openai_page, "_api_key_input", QLineEdit).text() == "sk-typed-not-saved"
    assert _listed_ids(dialog)[-1] == "fresh"
    assert dialog._settings_stack.currentWidget() is pages["fresh"]


@pytest.mark.usefixtures("state_root")
def test_import_refuses_builtin_ids_and_asks_before_replacing(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An import never stores a built-in id, and replaces an existing instance only when confirmed.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _write_settings({"my-gw": ProviderInstance(instance_id="my-gw", api_base="https://api.together.xyz/v1", display_name="Original")})
    export = tmp_path / "import.json"
    incoming = {
        "openai": ProviderInstance(instance_id="openai", api_base="https://api.together.xyz/v1").to_mapping(),
        "my-gw": ProviderInstance(instance_id="my-gw", api_base="https://api.groq.com/openai/v1", display_name="Imported").to_mapping(),
        "fresh": ProviderInstance(instance_id="fresh", api_base="https://api.cerebras.ai/v1").to_mapping(),
    }
    _ = export.write_text(json.dumps({"instances": incoming}), encoding="utf-8")
    monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *_args, **_kwargs: (str(export), ""))
    questions: list[str] = []
    answer = {"replace": QMessageBox.StandardButton.No}

    def _question(_parent: object, title: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        questions.append(title)
        return answer["replace"] if title == "Replace Provider Instance" else QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", _question)
    dialog = _make_dialog(qtbot, None)

    QTest.mouseClick(_child(dialog, "_import_instances_btn", QPushButton), Qt.MouseButton.LeftButton)

    stored = _store().load_instances()
    assert "openai" not in _store().stored_instance_ids()
    assert stored["my-gw"]["display_name"] == "Original"
    assert "fresh" in stored
    assert questions.count("Replace Provider Instance") == 1

    answer["replace"] = QMessageBox.StandardButton.Yes
    QTest.mouseClick(_child(dialog, "_import_instances_btn", QPushButton), Qt.MouseButton.LeftButton)
    assert _store().load_instances()["my-gw"]["display_name"] == "Imported"


@pytest.mark.usefixtures("state_root")
def test_delete_removes_the_base_url_override_and_the_registered_provider(
    qtbot: QtBot,
    keyless_endpoint: OpenAIModelsServer,
) -> None:
    """Deleting an instance clears ``MY_GW_API_BASE`` and unregisters its connected provider.

    Without that, the stale base URL overrides the one given to an instance
    re-added under the same id.

    Args:
        qtbot: pytest-qt bot.
        keyless_endpoint: Keyless loopback endpoint.
    """
    old = ProviderInstance(instance_id="my-gw", api_base=keyless_endpoint.broken_base_url, requires_api_key=False)
    _write_settings({"my-gw": old})
    registry = ProviderRegistry()
    connected = _connected(old, ProviderCredentials())
    registry.register(connected)
    dialog = _make_dialog(qtbot, registry)
    _settle_dialog(dialog)
    dialog._on_apply()
    assert CredentialLoader(_resolve_env_path()).get_saved_var("MY_GW_API_BASE") == keyless_endpoint.broken_base_url

    _select(dialog, "my-gw")
    QTest.mouseClick(_child(dialog, "_delete_instance_btn", QPushButton), Qt.MouseButton.LeftButton)

    assert "MY_GW_API_BASE" not in _env_text()
    assert registry.get("my-gw") is None
    qtbot.waitUntil(lambda: not connected.is_connected, timeout=_WAIT_MS)
    assert "my-gw" not in _listed_ids(dialog)

    dialog._persist_instance(ProviderInstance(instance_id="my-gw", api_base=keyless_endpoint.base_url, requires_api_key=False))
    credentials = CredentialLoader(_resolve_env_path()).get_connect_credentials("my-gw", api_key_optional=True)
    assert credentials is not None
    assert credentials.api_base is None
    readded_instance = ProviderInstance.from_mapping(dict(_store().load_instances()["my-gw"]))
    assert readded_instance is not None
    readded = ConfigurableProvider(readded_instance)

    async def _connect_and_list() -> list[str]:
        await readded.connect(credentials)
        try:
            return [model.id for model in await readded.list_models()]
        finally:
            await readded.disconnect()

    assert asyncio.run(_connect_and_list()) == [_MODEL_ID]


@pytest.mark.parametrize(
    ("typed_id", "variable"),
    [
        ("my_gw", "MY_GW_API_KEY"),
        ("xai", "XAI_API_KEY"),
        ("gemini", "GEMINI_API_KEY"),
        ("google_cloud", "GOOGLE_CLOUD_PROJECT"),
        ("1gw", "1GW_API_KEY"),
    ],
)
@pytest.mark.usefixtures("state_root")
def test_add_instance_refuses_ids_whose_variables_are_not_their_own(qtbot: QtBot, typed_id: str, variable: str) -> None:
    """The Add dialog refuses an id that would read another provider's variable or an invalid one.

    Args:
        qtbot: pytest-qt bot.
        typed_id: The id typed into the dialog.
        variable: The variable the refusal must name.
    """
    dialog = ProviderInstanceDialog(existing_ids=frozenset({*BUILTIN_PROVIDER_IDS, "my-gw"}))
    qtbot.addWidget(dialog)
    _child(dialog, "_id_input", QLineEdit).setText(typed_id)
    _child(dialog, "_base_url_input", QLineEdit).setText("https://gw.example/v1")

    dialog._on_accept()

    assert dialog.instance() is None
    assert variable in _child(dialog, "_error_label", QLabel).text()


@pytest.mark.usefixtures("state_root")
def test_set_active_on_an_unconnected_instance_reports_instead_of_raising(qtbot: QtBot, monkeypatch: pytest.MonkeyPatch) -> None:
    """Set Active on a just-added instance explains it is not connected.

    Args:
        qtbot: pytest-qt bot.
        monkeypatch: Pytest monkeypatch fixture.
    """
    warnings: list[str] = []

    def _warning(_parent: object, title: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        warnings.append(title)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _warning)
    registry = ProviderRegistry()
    dialog = _make_dialog(qtbot, registry)
    dialog._persist_instance(ProviderInstance(instance_id="fresh", api_base="https://fresh.example/v1"))

    QTest.mouseClick(_child(dialog, "_set_active_btn", QPushButton), Qt.MouseButton.LeftButton)

    assert registry.active_name is None
    assert warnings == ["Provider Not Connected"]


@pytest.mark.usefixtures("state_root")
def test_instance_display_name_is_editable_and_shown(qtbot: QtBot) -> None:
    """Renaming an instance on its page renames it in the list and the page title.

    Args:
        qtbot: pytest-qt bot.
    """
    _write_settings({"renamed-gw": ProviderInstance(instance_id="renamed-gw", display_name="Before", api_base="https://gw.example/v1")})
    dialog = _make_dialog(qtbot, None)
    page = dialog._provider_widgets["renamed-gw"]
    provider_list = _child(dialog, "_provider_list", QListWidget)
    item = dialog._provider_items["renamed-gw"]
    assert "Before" in item.text()

    _child(page, "_display_name_input", QLineEdit).setText("Corp Gateway")
    dialog._on_apply()

    assert _store().load_instances()["renamed-gw"]["display_name"] == "Corp Gateway"
    assert "Corp Gateway" in provider_list.item(provider_list.row(item)).text()
    assert "Corp Gateway" in _child(page, "_title_label", QLabel).text()


def _build_window(tmp_path: Path, registry: ProviderRegistry) -> MainWindow:
    """Construct a real main window around a registry.

    Args:
        tmp_path: Per-test temporary directory.
        registry: The provider registry.

    Returns:
        MainWindow: The window.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(tools_directory=tools_dir, logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
    orchestrator = Orchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
        config=OrchestratorConfig(stream_responses=False),
    )
    return MainWindow(config, orchestrator)


@pytest.fixture
def window(qapp: object, tmp_path: Path, state_root: Path) -> Iterator[MainWindow]:
    """Provide a real main window over an empty registry.

    Args:
        qapp: Qt application fixture.
        tmp_path: Per-test temporary directory.
        state_root: The redirected state root.

    Yields:
        MainWindow: The window.
    """
    del qapp, state_root
    built = _build_window(tmp_path, ProviderRegistry())
    yield built
    built.close()


def _combo_items(window: MainWindow) -> dict[str, str]:
    """Return the toolbar provider combo's items.

    Args:
        window: The main window.

    Returns:
        dict[str, str]: Label keyed by provider id.
    """
    combo = _child(window, "_provider_combo", QComboBox)
    return {str(combo.itemData(index)): combo.itemText(index) for index in range(combo.count())}


def test_toolbar_follows_instances_added_and_deleted_in_provider_settings(window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
    """The toolbar selector gains an added instance under its name and loses a deleted one.

    Args:
        window: The main window.
        monkeypatch: Pytest monkeypatch fixture.
    """
    actions: list[Callable[[ProviderConfigDialog], None]] = []

    def _exec(dialog: ProviderConfigDialog) -> int:
        actions.pop(0)(dialog)
        _settle_dialog(dialog)
        return 0

    def _add(dialog: ProviderConfigDialog) -> None:
        dialog._persist_instance(ProviderInstance(instance_id="my-gw", display_name="Corp Gateway", api_base="https://gw.example/v1"))

    def _delete(dialog: ProviderConfigDialog) -> None:
        _select(dialog, "my-gw")
        QTest.mouseClick(_child(dialog, "_delete_instance_btn", QPushButton), Qt.MouseButton.LeftButton)

    monkeypatch.setattr(ProviderConfigDialog, "exec", _exec)
    actions.append(_add)
    window._on_configure_providers()
    assert _combo_items(window).get("my-gw") == "Corp Gateway"

    actions.append(_delete)
    window._on_configure_providers()
    assert "my-gw" not in _combo_items(window)
    assert window._orchestrator.provider_registry.get("my-gw") is None


def test_apply_rebuilds_an_edited_instance_and_connects_it_without_a_key(
    window: MainWindow,
    qtbot: QtBot,
    keyless_endpoint: OpenAIModelsServer,
) -> None:
    """Applying settings replaces the stale provider and connects the keyless instance through its new headers.

    Args:
        window: The main window.
        qtbot: pytest-qt bot.
        keyless_endpoint: Keyless loopback endpoint.
    """
    registry = window._orchestrator.provider_registry
    stale_instance = ProviderInstance(
        instance_id="my-gw",
        api_base=keyless_endpoint.base_url,
        requires_api_key=False,
        headers={"X-Tenant": "old"},
    )
    stale = _connected(stale_instance, ProviderCredentials())
    registry.register(stale)
    edited = ProviderInstance(instance_id="my-gw", api_base=keyless_endpoint.base_url, requires_api_key=False, headers={"X-Tenant": "new"})
    _write_settings({"my-gw": edited})

    window._apply_provider_settings({"my-gw": {"enabled": True, "api_key": "", "api_base": keyless_endpoint.base_url}})

    def _rebuilt_and_connected() -> bool:
        current = registry.get("my-gw")
        return current is not None and current is not stale and current.is_connected

    qtbot.waitUntil(_rebuilt_and_connected, timeout=_WAIT_MS)
    qtbot.waitUntil(lambda: not stale.is_connected, timeout=_WAIT_MS)
    current = registry.get("my-gw")
    assert isinstance(current, ConfigurableProvider)
    models = run_bridge_coroutine(current.list_models())
    assert models is not None
    assert [model.id for model in models] == [_MODEL_ID]
    request = keyless_endpoint.requests()[-1]
    assert request.path == MODELS_PATH
    assert request.headers["x-tenant"] == "new"
    _ = run_bridge_coroutine(current.disconnect())
