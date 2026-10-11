# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the model refresh worker, the instance dialog and the credential, instance and OAuth handlers of the provider dialog.

Every test drives real objects. The model fetchers run against loopback HTTP servers (an OpenAI-compatible models server, a scripted route
server) or against a closed loopback port, never the network. Provider state, ``.env`` and the keyring are redirected into the test's temporary
directory, so nothing reads or writes the user's configuration. Modal dialogs the product opens itself are closed from inside their own event
loop by ``DialogWatcher`` under a hard time limit. Expected values come from the strings the handlers are documented to show, the saved
``providers.json`` and ``.env`` files read back from disk, and the loopback servers' recorded requests.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
from typing import TYPE_CHECKING, Any, NamedTuple, cast, override

import httpx
import pytest
from keyring.backends.fail import Keyring as FailKeyring
from PyQt6 import sip
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
)
from structlog.testing import capture_logs

import intellicrack.credentials.env_loader as env_loader_module
import intellicrack.credentials.store as store_module
from intellicrack.core.config import get_config_file, get_env_file
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import unregister_instance_mapping
from intellicrack.credentials.provider_settings import PROVIDER_SETTINGS_FILENAME, ProviderSettingsStore
from intellicrack.credentials.store import get_credential_store
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.dialects.base import ToolNameStyle
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.ids import BUILTIN_PROVIDER_IDS
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.presets import all_presets
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers, drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.provider_config import ModelRefreshWorker, ProviderConfigDialog, ProviderInstanceDialog, ProviderSettingsWidget
from tests._helpers.mcp_ui_support import DialogWatcher
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.private_keyring import installed_keyring, private_file_keyring
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests._helpers.scripted_http_server import ScriptedHttpServer, json_response
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.providers.base import LLMProviderBase


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any
_FetchResult = tuple[bool, list[str], str]

_WAIT_MS: int = 30_000
_BRIDGE_TIMEOUT_S: float = 60.0
_MODAL_LIMIT_MS: int = 30_000
_GW_ID: str = "my-gw"
_CORP_ID: str = "corp-gw"
_TEST_KEY: str = "loop" + "back-" + "credential"
_OTHER_KEY: str = "other" + "-" + "credential"
_CONNECTED: str = "●"
_IDLE: str = "○"
_ACTIVE: str = "★"
_SUCCESS: bool = True
_FAILURE: bool = False
_FETCH_TIMEOUT = httpx.Timeout(10.0)
_INSTANCE_IDS: tuple[str, ...] = (
    "my-gw",
    "corp-gw",
    "corp-gw-copy",
    "new-gw",
    "openai-copy",
    "imp-gw",
    "fresh-gw",
    "bare-gw",
    "blocked-gw",
    "xai",
)


class _Dialogs(NamedTuple):
    """Recorders installed over the message box statics.

    Attributes:
        warning: Recorder over ``QMessageBox.warning``.
        information: Recorder over ``QMessageBox.information``.
        critical: Recorder over ``QMessageBox.critical``.
    """

    warning: DialogRecorder
    information: DialogRecorder
    critical: DialogRecorder


class _Gateway(NamedTuple):
    """A connected provider backed by a loopback models server.

    Attributes:
        provider: The connected provider.
        instance: The endpoint record the provider was built from.
    """

    provider: ConfigurableProvider
    instance: ProviderInstance


class _FailingRegistry(ProviderRegistry):
    """A real registry whose lookups fail the way a corrupted one would."""

    @property
    @override
    def active_name(self) -> str | None:
        """Refuse to name the active provider.

        Returns:
            str | None: Never returns.

        Raises:
            RuntimeError: Always.
        """
        message = "active lookup failed"
        raise RuntimeError(message)

    @override
    def get(self, name: str) -> LLMProviderBase | None:
        """Refuse every lookup.

        Args:
            name: The provider name asked for.

        Returns:
            LLMProviderBase | None: Never returns.

        Raises:
            ValueError: Always.
        """
        message = f"lookup of {name} failed"
        raise ValueError(message)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _call(obj: object, name: str, *args: object) -> _Dynamic:
    """Call a private method of a product object.

    Args:
        obj: Object that owns the method.
        name: Method name.
        *args: Positional arguments for the method.

    Returns:
        _Dynamic: What the method returns.
    """
    return getattr(obj, name)(*args)


def _attr[T](obj: object, name: str, kind: type[T]) -> T:
    """Fetch a private widget attribute and check its type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        kind: Expected class of the attribute.

    Returns:
        T: The attribute.
    """
    found: object = getattr(obj, name)
    assert isinstance(found, kind)
    return found


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structured-log entries by event name.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The entries logged under that event.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _settings_path() -> Path:
    """Locate the redirected ``providers.json``.

    Returns:
        Path: The settings file path.
    """
    return get_config_file(PROVIDER_SETTINGS_FILENAME)


def _store() -> ProviderSettingsStore:
    """Open the redirected provider settings store.

    Returns:
        ProviderSettingsStore: The store over ``providers.json``.
    """
    return ProviderSettingsStore(_settings_path())


def _save_instance(instance: ProviderInstance) -> None:
    """Write an instance record into the redirected ``providers.json``.

    Args:
        instance: The instance to store.
    """
    _store().write_instance(instance.instance_id, instance.to_mapping())


def _corp_instance() -> ProviderInstance:
    """Build a hand-configured endpoint record that needs no loopback server.

    Returns:
        ProviderInstance: The instance, id ``corp-gw``.
    """
    return ProviderInstance(
        instance_id=_CORP_ID,
        display_name="Corp Gateway",
        api_base="https://gw.example.com/v1",
        headers={"X-Tenant": "analysis"},
    )


def _block_settings_writes() -> None:
    """Make the next ``providers.json`` write fail with an ``OSError``.

    The store writes through a temporary file named after the process and thread ids; a directory of that name cannot be written to.
    """
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp").mkdir()


def _closed_origin() -> str:
    """Return a loopback origin nothing is listening on.

    Returns:
        str: ``http://127.0.0.1:<port>`` of a server that has been shut down.
    """
    with ScriptedHttpServer() as server:
        return server.origin


def _fetch(worker: ModelRefreshWorker, name: str) -> _FetchResult:
    """Run one of the worker's synchronous fetchers on the test thread.

    Args:
        worker: The unstarted refresh worker.
        name: Name of the fetch method.

    Returns:
        _FetchResult: What the fetcher returns.
    """
    method = cast("Callable[[httpx.Timeout], _FetchResult]", getattr(worker, name))
    return method(_FETCH_TIMEOUT)


def _pick(monkeypatch: pytest.MonkeyPatch, picker: str, path: Path) -> None:
    """Make a ``QFileDialog`` picker return a fixed path.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        picker: Name of the static picker, ``getOpenFileName`` or ``getSaveFileName``.
        path: Path the picker reports.
    """

    def _chosen(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the chosen path.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty selected filter.
        """
        return str(path), ""

    monkeypatch.setattr(QFileDialog, picker, staticmethod(_chosen))


def _answer_question(
    monkeypatch: pytest.MonkeyPatch,
    button: QMessageBox.StandardButton,
    texts: list[str] | None = None,
) -> None:
    """Make ``QMessageBox.question`` give one answer and record what it asked.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        button: The button the user presses.
        texts: List that receives the text of every question asked.
    """

    def _question(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Report the pressed button.

        Args:
            *args: Dialog arguments: parent, title, text, buttons and default.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            QMessageBox.StandardButton: The configured answer.
        """
        if texts is not None:
            texts.append(str(args[2]))
        return button

    monkeypatch.setattr(QMessageBox, "question", staticmethod(_question))


def _select(dialog: ProviderConfigDialog, provider_id: str) -> None:
    """Select a provider in the dialog's list.

    Args:
        dialog: The provider dialog.
        provider_id: Id of the entry to select.
    """
    items = cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))
    _attr(dialog, "_provider_list", QListWidget).setCurrentItem(items[provider_id])


def _item_text(dialog: ProviderConfigDialog, provider_id: str) -> str:
    """Read the list text of a provider entry.

    Args:
        dialog: The provider dialog.
        provider_id: Id of the entry.

    Returns:
        str: The entry's display text.
    """
    items = cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))
    return items[provider_id].text()


def _reject(dialog: QDialog) -> None:
    """Dismiss a dialog as Cancel would.

    Args:
        dialog: The dialog.
    """
    dialog.reject()


def _accept_without_building(dialog: QDialog) -> None:
    """Close a dialog as accepted without running its form validation.

    Args:
        dialog: The dialog.
    """
    dialog.accept()


def _submit_form(dialog: QDialog) -> None:
    """Press OK on an instance dialog whose form is already filled.

    Args:
        dialog: The instance dialog.
    """
    _call(dialog, "_on_accept")


@contextlib.contextmanager
def _modal(action: Callable[[QDialog], None]) -> Generator[DialogWatcher]:
    """Act on the instance dialog the handler under test opens, under a hard time limit.

    Args:
        action: Called with the dialog once it is visible.

    Yields:
        DialogWatcher: The watcher; ``seen`` lists the dialogs it acted on.
    """
    timed_out: list[bool] = []

    def _expire() -> None:
        """Reject whatever modal dialog is still open and remember that the limit was hit."""
        timed_out.append(True)
        modal = QApplication.activeModalWidget()
        if isinstance(modal, QDialog):
            modal.reject()

    watcher = DialogWatcher(ProviderInstanceDialog, action)
    limit = QTimer()
    limit.setSingleShot(True)
    limit.setInterval(_MODAL_LIMIT_MS)
    _ = limit.timeout.connect(_expire)
    limit.start()
    try:
        yield watcher
    finally:
        limit.stop()
        watcher.stop()
    assert not timed_out, "the instance dialog was never handled before the time limit"


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> _Dialogs:
    """Record the message boxes the product shows instead of opening them.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        _Dialogs: The recorders.
    """
    recorders = _Dialogs(DialogRecorder(), DialogRecorder(), DialogRecorder())
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorders.warning))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(recorders.information))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(recorders.critical))
    return recorders


def _shown(recorder: DialogRecorder) -> list[tuple[str, str]]:
    """List the title and text of every message a recorder saw.

    Args:
        recorder: A message box recorder.

    Returns:
        list[tuple[str, str]]: One ``(title, text)`` pair per call.
    """
    return [(str(call[1]), str(call[2])) for call in recorder.calls]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Redirect provider state, ``.env`` and the keyring into the test directory with no provider variables set.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    holder: _Dynamic = getattr(store_module, "_store_holder")
    with (
        redirected_state_root(monkeypatch, tmp_path) as root,
        installed_keyring(private_file_keyring(tmp_path / "keyring.cfg")),
    ):
        holder.instance = None
        try:
            yield root
        finally:
            holder.instance = None
            for instance_id in _INSTANCE_IDS:
                unregister_instance_mapping(instance_id)


@pytest.fixture
def failing_keyring(env: Path) -> Generator[None]:
    """Install the keyring backend that refuses every operation.

    Args:
        env: The redirected state root.

    Yields:
        None: Control passes to the test.
    """
    del env
    holder: _Dynamic = getattr(store_module, "_store_holder")
    with installed_keyring(FailKeyring()):
        holder.instance = None
        try:
            yield
        finally:
            holder.instance = None


@pytest.fixture
def build_dialog(env: Path) -> Generator[Callable[..., ProviderConfigDialog]]:
    """Build provider dialogs and tear them down without leaving a worker or timer behind.

    Args:
        env: The redirected state root.

    Yields:
        Callable[..., ProviderConfigDialog]: Factory taking optional ``registry`` and ``discovery`` keywords.
    """
    del env
    created: list[ProviderConfigDialog] = []

    def _build(*, registry: ProviderRegistry | None = None, discovery: ModelDiscovery | None = None) -> ProviderConfigDialog:
        """Construct and track a dialog.

        Args:
            registry: Registry the dialog manages, or ``None``.
            discovery: Discovery service the dialog uses, or ``None``.

        Returns:
            ProviderConfigDialog: The dialog.
        """
        dialog = ProviderConfigDialog(provider_registry=registry, model_discovery=discovery)
        created.append(dialog)
        return dialog

    try:
        yield _build
    finally:
        for dialog in created:
            if not sip.isdeleted(dialog):
                _priv(dialog, "_update_status_timer").stop()
                _ = dialog.close()
        _ = drain_bridge_workers()
        for dialog in created:
            if not sip.isdeleted(dialog):
                sip.delete(dialog)


@pytest.fixture
def build_widget(env: Path) -> Generator[Callable[..., ProviderSettingsWidget]]:
    """Build provider settings pages and tear them down without leaving a worker or timer behind.

    Args:
        env: The redirected state root.

    Yields:
        Callable[..., ProviderSettingsWidget]: Factory taking the provider id.
    """
    del env
    created: list[ProviderSettingsWidget] = []

    def _build(provider_id: str) -> ProviderSettingsWidget:
        """Construct and track a settings page.

        Args:
            provider_id: Id of the provider the page configures.

        Returns:
            ProviderSettingsWidget: The page.
        """
        widget = ProviderSettingsWidget(provider_id, None, _settings_path())
        created.append(widget)
        return widget

    try:
        yield _build
    finally:
        _ = drain_bridge_workers()
        for widget in created:
            if not sip.isdeleted(widget):
                sip.delete(widget)


@pytest.fixture
def gateway(env: Path) -> Generator[_Gateway]:
    """Connect a provider to a loopback endpoint that lists two models.

    Args:
        env: The redirected state root.

    Yields:
        _Gateway: The connected provider and its endpoint record.
    """
    del env
    with OpenAIModelsServer(model_ids=["alpha-model", "beta-model"]) as server:
        instance = ProviderInstance(instance_id=_GW_ID, display_name="Corp Gateway", api_base=server.base_url, requires_api_key=False)
        provider = ConfigurableProvider(instance)
        _ = run_bridge_coroutine(provider.connect(ProviderCredentials()), timeout_s=_BRIDGE_TIMEOUT_S)
        assert provider.is_connected
        try:
            yield _Gateway(provider, instance)
        finally:
            _ = run_bridge_coroutine(provider.disconnect(), timeout_s=_BRIDGE_TIMEOUT_S)


def test_ollama_non_ok_status_is_reported_with_its_code() -> None:
    """A non-200 answer from the Ollama tags endpoint becomes a failure that names the status."""
    with ScriptedHttpServer() as server:
        server.script("GET", "/api/tags", json_response(500, {"error": "boom"}))
        worker = ModelRefreshWorker("ollama", "", server.origin)

        assert _fetch(worker, "_fetch_ollama_models") == (False, [], "Ollama error: 500")


def test_ollama_unreachable_host_is_a_failure_with_the_transport_error() -> None:
    """A refused connection to the Ollama host returns the transport error text, not a status message."""
    worker = ModelRefreshWorker("ollama", "", _closed_origin())

    ok, models, message = _fetch(worker, "_fetch_ollama_models")

    assert ok is False
    assert models == []
    assert message
    assert not message.startswith("Ollama error")


def test_openrouter_listing_is_sorted_and_authenticated() -> None:
    """OpenRouter model ids come back sorted, requested from ``<base>/models`` with the key as a bearer token."""
    with ScriptedHttpServer() as server:
        server.script("GET", "/models", json_response(200, {"data": [{"id": "zeta/model"}, {"id": "alpha/model"}]}))
        worker = ModelRefreshWorker("openrouter", _TEST_KEY, server.origin + "/")

        result = _fetch(worker, "_fetch_openrouter_models")

        assert result == (True, ["alpha/model", "zeta/model"], "Found 2 OpenRouter models")
        assert [request.headers["authorization"] for request in server.requests("/models")] == [f"Bearer {_TEST_KEY}"]


def test_openrouter_rejected_key_reports_the_status() -> None:
    """A 401 from OpenRouter becomes an API error carrying the status code."""
    with ScriptedHttpServer() as server:
        server.script("GET", "/models", json_response(401, {"error": {"message": "no"}}))
        worker = ModelRefreshWorker("openrouter", _TEST_KEY, server.origin)

        assert _fetch(worker, "_fetch_openrouter_models") == (False, [], "API error: 401")


def test_openrouter_unreachable_host_is_a_failure_with_the_transport_error() -> None:
    """A refused connection to OpenRouter returns the transport error text."""
    worker = ModelRefreshWorker("openrouter", _TEST_KEY, _closed_origin())

    ok, models, message = _fetch(worker, "_fetch_openrouter_models")

    assert ok is False
    assert models == []
    assert message
    assert not message.startswith("API error")


def test_huggingface_listing_reports_an_unreachable_hub(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the HTTPS proxy pointing at a closed loopback port the Hub request fails and is reported, not raised.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", _closed_origin())
    worker = ModelRefreshWorker("huggingface", _TEST_KEY)

    ok, models, message = _fetch(worker, "_fetch_huggingface_models")

    assert ok is False
    assert models == []
    assert message
    assert not message.startswith("API error")


def test_grok_listing_without_a_key_is_refused() -> None:
    """Listing Grok models with an empty key fails before any request is made."""
    worker = ModelRefreshWorker("grok", "")

    assert _fetch(worker, "_fetch_grok_models") == (False, [], "No Grok API key configured")


def test_grok_listing_returns_sorted_model_ids_through_the_provider() -> None:
    """Grok models are listed through a connected provider, sorted ascending, using the key as a bearer token."""
    with OpenAIModelsServer(model_ids=["grok-4", "grok-3-mini"], accepted_key=_TEST_KEY) as server:
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.base_url)

        result = _fetch(worker, "_fetch_grok_models")

        assert result == (True, ["grok-3-mini", "grok-4"], "Found 2 Grok models")
        assert {request.headers["authorization"] for request in server.requests()} == {f"Bearer {_TEST_KEY}"}


def test_grok_listing_with_a_rejected_key_reports_an_invalid_key() -> None:
    """A 401 while connecting to Grok becomes the ``Invalid API key`` message."""
    with OpenAIModelsServer(model_ids=["grok-4"], accepted_key=_OTHER_KEY) as server:
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.base_url)

        assert _fetch(worker, "_fetch_grok_models") == (False, [], "Invalid API key")


def test_grok_listing_with_no_models_says_so() -> None:
    """An endpoint that lists no models yields ``No models returned``, not an empty success."""
    with OpenAIModelsServer(model_ids=[], accepted_key=_TEST_KEY) as server:
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.base_url)

        assert _fetch(worker, "_fetch_grok_models") == (False, [], "No models returned")


def test_grok_connect_failure_is_reported_with_the_provider_message() -> None:
    """A connect probe answered 404 surfaces the provider's own connect failure message."""
    with OpenAIModelsServer(model_ids=["grok-4"], accepted_key=_TEST_KEY) as server:
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.origin + "/missing")

        ok, models, message = _fetch(worker, "_fetch_grok_models")

        assert ok is False
        assert models == []
        assert message.startswith("Failed to connect to Grok:")


def test_grok_listing_failure_after_connect_is_reported_with_the_provider_message() -> None:
    """A connect that succeeds followed by a failing model listing surfaces the listing failure message."""
    with ScriptedHttpServer() as server:
        server.script(
            "GET",
            "/v1/models",
            json_response(200, {"object": "list", "data": []}),
            json_response(404, {"error": {"message": "gone"}}),
        )
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.origin + "/v1")

        ok, models, message = _fetch(worker, "_fetch_grok_models")

        assert ok is False
        assert models == []
        assert message.startswith("Failed to list Grok models:")
        assert len(server.requests("/v1/models")) == 2


@pytest.mark.asyncio
async def test_grok_listing_inside_a_running_loop_is_scheduled_not_awaited() -> None:
    """Called from a running event loop the Grok listing is scheduled as a task and the caller is told so."""
    with OpenAIModelsServer(model_ids=["grok-4"], accepted_key=_TEST_KEY) as server:
        worker = ModelRefreshWorker("grok", _TEST_KEY, server.base_url)

        result = _fetch(worker, "_fetch_grok_models")
        pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        _ = await asyncio.gather(*pending)

        assert result == (False, [], "Grok fetch scheduled on running loop")
        assert len(server.requests()) == 2


def _instance_dialog(existing: frozenset[str] = frozenset(), seed: ProviderInstance | None = None) -> ProviderInstanceDialog:
    """Build an instance dialog.

    Args:
        existing: Ids already in use.
        seed: Instance to duplicate, if any.

    Returns:
        ProviderInstanceDialog: The dialog.
    """
    return ProviderInstanceDialog(existing_ids=existing, seed=seed)


def test_duplicate_dialog_prefills_from_the_seed_and_copies_the_remaining_fields() -> None:
    """A seeded dialog shows the copy's id, label, preset, dialect and URL, and the built instance carries every other seed field."""
    seed = ProviderInstance(
        instance_id=_CORP_ID,
        display_name="Corp Gateway",
        preset_id="vllm",
        dialect=ApiDialect.MESSAGES,
        api_base="https://gw.example.com/v1",
        headers={"X-Tenant": "analysis"},
        extra_body={"routing": {"order": ["a"]}},
        drop_params=frozenset({"stream_options"}),
        tool_name_style=ToolNameStyle.DOTTED,
        default_model="m-1",
        model_overrides={"m-1": CapabilityOverride(context_window=4096)},
    )
    dialog = _instance_dialog(frozenset({_CORP_ID}), seed)

    assert _attr(dialog, "_id_input", QLineEdit).text() == "corp-gw-copy"
    assert _attr(dialog, "_label_input", QLineEdit).text() == "Corp Gateway (copy)"
    assert _attr(dialog, "_preset_combo", QComboBox).currentData() == "vllm"
    assert _attr(dialog, "_dialect_combo", QComboBox).currentData() == ApiDialect.MESSAGES.value
    assert _attr(dialog, "_base_url_input", QLineEdit).text() == "https://gw.example.com/v1"

    _submit_form(dialog)
    built = dialog.instance()

    assert built is not None
    assert (built.instance_id, built.display_name, built.preset_id) == ("corp-gw-copy", "Corp Gateway (copy)", "vllm")
    assert (built.dialect, built.api_base, built.requires_api_key) == (ApiDialect.MESSAGES, "https://gw.example.com/v1", False)
    assert built.headers == {"X-Tenant": "analysis"}
    assert built.headers is not seed.headers
    assert built.extra_body == seed.extra_body
    assert built.drop_params == frozenset({"stream_options"})
    assert built.tool_name_style is ToolNameStyle.DOTTED
    assert built.default_model == "m-1"
    assert built.model_overrides == seed.model_overrides


@pytest.mark.parametrize("preset_id", [None, "no-such-preset"])
def test_duplicate_dialog_leaves_the_preset_unset_when_the_seed_names_none_the_dialog_lists(preset_id: str | None) -> None:
    """A seed without a listed preset leaves ``None (configure by hand)`` selected and builds an instance with no preset.

    Args:
        preset_id: The seed's preset id, absent or not in the preset list.
    """
    seed = ProviderInstance(instance_id="bare-gw", display_name="Bare", preset_id=preset_id, api_base="https://gw.example.com/v1")
    dialog = _instance_dialog(frozenset({"bare-gw"}), seed)

    assert not _attr(dialog, "_preset_combo", QComboBox).currentData()

    _submit_form(dialog)
    built = dialog.instance()

    assert built is not None
    assert built.preset_id is None
    assert built.requires_api_key is True
    assert built.instance_id == "bare-gw-copy"


def test_choosing_a_preset_fills_dialect_url_and_label() -> None:
    """Picking the vLLM preset in an empty dialog supplies its dialect, base URL and display name."""
    dialog = _instance_dialog()
    combo = _attr(dialog, "_preset_combo", QComboBox)

    combo.setCurrentIndex(combo.findData("vllm"))

    assert _attr(dialog, "_dialect_combo", QComboBox).currentData() == ApiDialect.CHAT_COMPLETIONS.value
    assert _attr(dialog, "_base_url_input", QLineEdit).text() == "http://localhost:8000/v1"
    assert _attr(dialog, "_label_input", QLineEdit).text() == "vLLM"


def test_choosing_a_preset_keeps_what_the_user_already_typed() -> None:
    """A preset never overwrites a label or base URL the user has already entered, but still sets the dialect."""
    dialog = _instance_dialog()
    _attr(dialog, "_label_input", QLineEdit).setText("Mine")
    _attr(dialog, "_base_url_input", QLineEdit).setText("https://mine.example.com/v1")
    combo = _attr(dialog, "_preset_combo", QComboBox)

    combo.setCurrentIndex(combo.findData("anthropic-gateway"))

    assert _attr(dialog, "_label_input", QLineEdit).text() == "Mine"
    assert _attr(dialog, "_base_url_input", QLineEdit).text() == "https://mine.example.com/v1"
    assert _attr(dialog, "_dialect_combo", QComboBox).currentData() == ApiDialect.MESSAGES.value


def test_returning_to_no_preset_changes_nothing() -> None:
    """Switching back to ``None (configure by hand)`` leaves the fields the previous preset filled."""
    dialog = _instance_dialog()
    combo = _attr(dialog, "_preset_combo", QComboBox)
    combo.setCurrentIndex(combo.findData("vllm"))

    combo.setCurrentIndex(combo.findData(""))

    assert _attr(dialog, "_base_url_input", QLineEdit).text() == "http://localhost:8000/v1"
    assert _attr(dialog, "_label_input", QLineEdit).text() == "vLLM"


def test_choosing_a_preset_without_a_dialect_keeps_the_dialect_and_leaves_the_url_blank() -> None:
    """The local Transformers preset has no dialect and no endpoint, so only the label is filled."""
    dialog = _instance_dialog()
    dialect_combo = _attr(dialog, "_dialect_combo", QComboBox)
    dialect_combo.setCurrentIndex(dialect_combo.findData(ApiDialect.GEMINI.value))
    combo = _attr(dialog, "_preset_combo", QComboBox)

    combo.setCurrentIndex(combo.findData("local_transformers"))

    assert dialect_combo.currentData() == ApiDialect.GEMINI.value
    assert not _attr(dialog, "_base_url_input", QLineEdit).text()
    assert _attr(dialog, "_label_input", QLineEdit).text() == "Local Transformers"


def test_invalid_instance_id_is_refused_with_an_explanation() -> None:
    """An id with a space and punctuation is refused, the reason is shown and no instance is built."""
    dialog = _instance_dialog()
    _attr(dialog, "_id_input", QLineEdit).setText("Bad Id!")

    _submit_form(dialog)

    assert _attr(dialog, "_error_label", QLabel).text().startswith("The instance id must start with a lowercase letter or digit")
    assert dialog.instance() is None


def test_instance_id_already_in_use_is_refused_after_normalizing() -> None:
    """An id differing only by case and surrounding spaces from an existing one is refused by name."""
    dialog = _instance_dialog(frozenset({_CORP_ID}))
    _attr(dialog, "_id_input", QLineEdit).setText(" Corp-GW ")

    _submit_form(dialog)

    assert _attr(dialog, "_error_label", QLabel).text() == "'corp-gw' is already in use. Choose another id."
    assert dialog.instance() is None


def test_instance_without_preset_or_label_takes_its_id_as_name_and_a_blank_url_as_none() -> None:
    """A hand-configured instance with only an id gets that id as display name, the first dialect and no base URL."""
    dialog = _instance_dialog()
    _attr(dialog, "_id_input", QLineEdit).setText("new-gw")

    _submit_form(dialog)
    built = dialog.instance()

    assert built is not None
    assert (built.instance_id, built.display_name, built.preset_id) == ("new-gw", "new-gw", None)
    assert (built.dialect, built.api_base, built.requires_api_key) == (ApiDialect.CHAT_COMPLETIONS, None, True)
    assert built.headers == {}


def test_blank_base_url_falls_back_to_the_preset_endpoint() -> None:
    """Clearing the base URL after choosing the Groq preset builds an instance pointing at Groq's endpoint, keyed."""
    dialog = _instance_dialog()
    _attr(dialog, "_id_input", QLineEdit).setText("new-gw")
    combo = _attr(dialog, "_preset_combo", QComboBox)
    combo.setCurrentIndex(combo.findData("groq"))
    _attr(dialog, "_base_url_input", QLineEdit).setText("")

    _submit_form(dialog)
    built = dialog.instance()

    assert built is not None
    assert (built.preset_id, built.display_name, built.api_base) == ("groq", "Groq", "https://api.groq.com/openai/v1")
    assert built.requires_api_key is True


def test_construction_counts_providers_found_in_the_credential_store(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """Building the dialog enumerates stored credentials on the bridge, logs one source per found provider and reports the count.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the enumeration result arrives.
    """
    monkeypatch.setenv("OPENAI_API_KEY", _TEST_KEY)
    with capture_logs() as captured:
        _ = build_dialog()
        qtbot.waitUntil(lambda: bool(_events(captured, "credential_store_loaded")), timeout=_WAIT_MS)

    assert _events(captured, "credential_store_loaded")[0]["store_provider_count"] == 1
    assert [entry["provider"] for entry in _events(captured, "credential_source")] == ["openai"]


def test_reload_logs_every_configured_provider_as_refreshed(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reloading credentials logs ``credential_refreshed`` for each provider that has a key configured.

    The handler asks the loader for an environment variable named like the provider (``openai``) instead of the provider's key variable,
    so the event is never logged.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("OPENAI_API_KEY", _TEST_KEY)
    dialog = build_dialog()

    with capture_logs() as captured:
        dialog.refresh_credentials()

    assert "openai" in [entry["provider"] for entry in _events(captured, "credential_refreshed")]
    overview = cast("dict[str, list[str]]", _priv(dialog, "_credential_overview"))
    assert "openai" in overview["configured"]


def test_reload_provider_list_selects_the_first_row_when_nothing_is_current(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """With no current row, refreshing the list selects the first provider, and an empty selection reads as no id.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    provider_list = _attr(dialog, "_provider_list", QListWidget)
    provider_list.setCurrentRow(-1)

    assert provider_list.currentItem() is None
    assert not _call(dialog, "_selected_provider_id")

    _call(dialog, "_reload_provider_list")

    assert provider_list.currentRow() == 0
    assert _call(dialog, "_selected_provider_id") == BUILTIN_PROVIDER_IDS[0]


def test_selecting_an_entry_without_a_page_keeps_the_current_page(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Selecting a list row whose settings page is gone records the selection but leaves the shown page alone.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    widgets = cast("dict[str, ProviderSettingsWidget]", _priv(dialog, "_provider_widgets"))
    _ = widgets.pop("anthropic")
    provider_list = _attr(dialog, "_provider_list", QListWidget)
    stack = _attr(dialog, "_settings_stack", QStackedWidget)
    provider_list.setCurrentRow(1)
    shown = stack.currentWidget()

    provider_list.setCurrentRow(0)

    assert _priv(dialog, "_current_provider") == "anthropic"
    assert stack.currentWidget() is shown


def test_removing_an_unknown_entry_leaves_the_list_alone(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Removing an id that has neither a list entry nor a page changes nothing.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    provider_list = _attr(dialog, "_provider_list", QListWidget)
    before = provider_list.count()

    _call(dialog, "_remove_provider_entry", "no-such-gw")

    assert provider_list.count() == before == len(BUILTIN_PROVIDER_IDS)


def test_buttons_do_nothing_when_no_provider_is_current(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Discover, OAuth Login and Revoke Token start no work when the dialog has no current provider.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    setattr(dialog, "_current_provider", None)
    before = set(bridge_workers_for(dialog))

    with capture_logs() as captured:
        _call(dialog, "_on_discover_selected_provider")
        _call(dialog, "_on_start_oauth")
        _call(dialog, "_on_revoke_oauth")

    assert captured == []
    assert set(bridge_workers_for(dialog)) == before


def test_add_instance_persists_selects_and_announces_the_new_provider(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Accepting the Add dialog saves the instance, lists and selects it, and announces the change once.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    announced: list[None] = []

    def _on_changed() -> None:
        """Record one ``instances_changed`` emission."""
        announced.append(None)

    _ = dialog.instances_changed.connect(_on_changed)

    def _fill(modal: QDialog) -> None:
        """Fill and submit the Add dialog.

        Args:
            modal: The Add dialog.
        """
        _attr(modal, "_id_input", QLineEdit).setText("new-gw")
        _attr(modal, "_base_url_input", QLineEdit).setText("https://gw.example.com/v1")
        _submit_form(modal)

    with _modal(_fill) as watcher:
        _call(dialog, "_on_add_instance")

    assert len(watcher.seen) == 1
    record = _store().load_instances()["new-gw"]
    assert (record["display_name"], record["api_base"]) == ("new-gw", "https://gw.example.com/v1")
    assert _call(dialog, "_selected_provider_id") == "new-gw"
    assert announced == [None]


@pytest.mark.parametrize("action", [_reject, _accept_without_building], ids=["cancelled", "accepted-without-a-form"])
def test_add_instance_without_an_instance_saves_nothing(
    build_dialog: Callable[..., ProviderConfigDialog],
    action: Callable[[QDialog], None],
) -> None:
    """Cancelling the Add dialog, or closing it accepted with no instance built, stores and announces nothing.

    Args:
        build_dialog: Factory for provider dialogs.
        action: How the dialog is closed.
    """
    dialog = build_dialog()
    announced: list[None] = []

    def _on_changed() -> None:
        """Record one ``instances_changed`` emission."""
        announced.append(None)

    _ = dialog.instances_changed.connect(_on_changed)

    with _modal(action) as watcher:
        _call(dialog, "_on_add_instance")

    assert len(watcher.seen) == 1
    assert _store().stored_instance_ids() == frozenset()
    assert announced == []


def test_add_instance_replaces_a_connected_provider_and_disconnects_it(
    build_dialog: Callable[..., ProviderConfigDialog],
    gateway: _Gateway,
) -> None:
    """Saving an instance under the id of a connected provider registers an unconnected replacement and disconnects the old one.

    Args:
        build_dialog: Factory for provider dialogs.
        gateway: A connected provider registered as ``my-gw``.
    """
    registry = ProviderRegistry()
    registry.register(gateway.provider)
    dialog = build_dialog(registry=registry)

    def _fill(modal: QDialog) -> None:
        """Fill and submit the Add dialog with the connected provider's id.

        Args:
            modal: The Add dialog.
        """
        _attr(modal, "_id_input", QLineEdit).setText(_GW_ID)
        _submit_form(modal)

    with _modal(_fill):
        _call(dialog, "_on_add_instance")

    replacement = registry.get(_GW_ID)
    assert replacement is not None
    assert replacement is not gateway.provider
    assert not replacement.is_connected
    _ = drain_bridge_workers_for(dialog)
    assert not gateway.provider.is_connected


def test_duplicating_a_builtin_saves_a_copy_built_from_its_preset(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Duplicating OpenAI and accepting the prefilled form stores ``openai-copy`` with OpenAI's preset, dialect and endpoint.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    _select(dialog, "openai")

    with _modal(_submit_form) as watcher:
        _call(dialog, "_on_duplicate_instance")

    assert len(watcher.seen) == 1
    record = _store().load_instances()["openai-copy"]
    preset_dialect = all_presets()["openai"].dialect
    assert preset_dialect is not None
    assert record["preset_id"] == "openai"
    assert record["dialect"] == preset_dialect.value
    assert record["api_base"] == "https://api.openai.com/v1"
    assert _call(dialog, "_selected_provider_id") == "openai-copy"


def test_duplicating_a_saved_instance_copies_its_record(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Duplicating a saved instance seeds the copy from its record, headers included.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog()
    _select(dialog, _CORP_ID)

    with _modal(_submit_form):
        _call(dialog, "_on_duplicate_instance")

    record = _store().load_instances()["corp-gw-copy"]
    assert record["headers"] == {"X-Tenant": "analysis"}
    assert record["api_base"] == "https://gw.example.com/v1"
    assert record["display_name"] == "Corp Gateway (copy)"


@pytest.mark.parametrize("action", [_reject, _accept_without_building], ids=["cancelled", "accepted-without-a-form"])
def test_duplicate_without_an_instance_saves_nothing(
    build_dialog: Callable[..., ProviderConfigDialog],
    action: Callable[[QDialog], None],
) -> None:
    """Cancelling the Duplicate dialog, or closing it accepted with no instance built, stores nothing.

    Args:
        build_dialog: Factory for provider dialogs.
        action: How the dialog is closed.
    """
    dialog = build_dialog()
    _select(dialog, "openai")

    with _modal(action) as watcher:
        _call(dialog, "_on_duplicate_instance")

    assert len(watcher.seen) == 1
    assert _store().stored_instance_ids() == frozenset()


def test_duplicate_without_a_selection_asks_for_one(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Pressing Duplicate with nothing selected shows a warning and opens no dialog.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    _attr(dialog, "_provider_list", QListWidget).setCurrentRow(-1)

    _call(dialog, "_on_duplicate_instance")

    assert _shown(dialogs.warning) == [("Duplicate Provider", "Select a provider to duplicate first.")]


def test_duplicate_of_an_entry_with_no_record_or_preset_says_so(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
) -> None:
    """Duplicating a listed instance whose record has since disappeared reports that no configuration was found.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog()
    _select(dialog, _CORP_ID)
    assert _store().delete_instance(_CORP_ID)

    _call(dialog, "_on_duplicate_instance")

    assert _shown(dialogs.warning) == [("Duplicate Provider", "No configuration found for 'corp-gw'.")]


def test_failed_instance_write_is_reported_and_not_listed(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """When ``providers.json`` cannot be written the save failure is shown and the instance is not listed.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    _block_settings_writes()

    _call(dialog, "_persist_instance", ProviderInstance(instance_id="blocked-gw", display_name="Blocked"))

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Save Error"
    assert text.startswith("Failed to save the provider instance:")
    assert "blocked-gw" not in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))
    assert _store().stored_instance_ids() == frozenset()


def test_delete_without_a_selection_asks_for_one(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Pressing Delete with nothing selected shows a warning.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    _attr(dialog, "_provider_list", QListWidget).setCurrentRow(-1)

    _call(dialog, "_on_delete_instance")

    assert _shown(dialogs.warning) == [("Delete Provider", "Select a provider to delete first.")]


def test_deleting_a_builtin_is_refused(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """A built-in provider is never deleted, and the warning says it is restored from its preset instead.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    _select(dialog, "openai")

    _call(dialog, "_on_delete_instance")

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Delete Provider"
    assert text.startswith("'openai' is a built-in provider and is restored from its preset rather than deleted.")
    assert "openai" in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))


def test_declining_the_delete_confirmation_keeps_the_instance(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Answering No to the delete confirmation leaves the saved record and the list entry in place.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog()
    _select(dialog, _CORP_ID)
    texts: list[str] = []
    _answer_question(monkeypatch, QMessageBox.StandardButton.No, texts)

    _call(dialog, "_on_delete_instance")

    assert texts == ["Delete the provider instance 'corp-gw'? Its stored API key is not removed."]
    assert _CORP_ID in _store().stored_instance_ids()
    assert _CORP_ID in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))


def test_failed_delete_write_is_reported_and_keeps_the_instance(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``providers.json`` cannot be rewritten the delete failure is shown and the instance stays listed.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog()
    _select(dialog, _CORP_ID)
    _answer_question(monkeypatch, QMessageBox.StandardButton.Yes)
    _block_settings_writes()

    _call(dialog, "_on_delete_instance")

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Delete Error"
    assert text.startswith("Failed to delete the provider instance:")
    assert _CORP_ID in _store().stored_instance_ids()
    assert _CORP_ID in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))


def test_delete_removes_the_record_the_entry_and_disconnects_the_provider(
    build_dialog: Callable[..., ProviderConfigDialog],
    gateway: _Gateway,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirmed deletion removes the saved record and list entry, unregisters the provider, disconnects it and announces the change.

    Args:
        build_dialog: Factory for provider dialogs.
        gateway: A connected provider registered as ``my-gw``.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _save_instance(gateway.instance)
    registry = ProviderRegistry()
    registry.register(gateway.provider)
    dialog = build_dialog(registry=registry)
    announced: list[None] = []

    def _on_changed() -> None:
        """Record one ``instances_changed`` emission."""
        announced.append(None)

    _ = dialog.instances_changed.connect(_on_changed)
    _answer_question(monkeypatch, QMessageBox.StandardButton.Yes)
    _select(dialog, _GW_ID)

    _call(dialog, "_on_delete_instance")

    assert _GW_ID not in _store().stored_instance_ids()
    assert _GW_ID not in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))
    assert registry.get(_GW_ID) is None
    _ = drain_bridge_workers_for(dialog)
    assert not gateway.provider.is_connected
    assert announced == [None]


def test_delete_of_a_record_that_vanished_still_cleans_the_list(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting an entry whose record was already removed from disk drops the entry and tolerates a registry that never knew it.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog(registry=ProviderRegistry())
    _select(dialog, _CORP_ID)
    assert _store().delete_instance(_CORP_ID)
    _answer_question(monkeypatch, QMessageBox.StandardButton.Yes)

    _call(dialog, "_on_delete_instance")

    assert _CORP_ID not in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))


def test_delete_without_a_registry_removes_the_record(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dialog built without a provider registry still deletes the saved instance.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _save_instance(_corp_instance())
    dialog = build_dialog()
    _select(dialog, _CORP_ID)
    _answer_question(monkeypatch, QMessageBox.StandardButton.Yes)

    _call(dialog, "_on_delete_instance")

    assert _CORP_ID not in _store().stored_instance_ids()
    assert _CORP_ID not in cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))


def test_export_writes_the_saved_instances_without_secrets(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Export writes every saved instance record under ``instances`` and reports the count.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    corp = _corp_instance()
    _save_instance(corp)
    dialog = build_dialog()
    target = tmp_path / "export.json"
    _pick(monkeypatch, "getSaveFileName", target)

    _call(dialog, "_on_export_instances")

    expected = json.loads(json.dumps(corp.to_mapping()))
    assert json.loads(target.read_text(encoding="utf-8")) == {"instances": {_CORP_ID: expected}}
    assert _shown(dialogs.information) == [("Export Complete", "Exported 1 provider instances. No secrets were written.")]


def test_cancelled_export_writes_nothing(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Cancelling the save picker shows no message and writes no file.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()

    _call(dialog, "_on_export_instances")

    assert dialogs.information.calls == []
    assert dialogs.warning.calls == []


def test_export_to_an_unwritable_target_is_reported(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exporting to a path that is a directory shows the export error instead of a success message.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    dialog = build_dialog()
    target = tmp_path / "a-directory"
    target.mkdir()
    _pick(monkeypatch, "getSaveFileName", target)

    _call(dialog, "_on_export_instances")

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Export Error"
    assert text.startswith("Failed to export provider instances:")
    assert dialogs.information.calls == []


def _import_text(dialog: ProviderConfigDialog, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str) -> None:
    """Run the Import handler against a file holding ``text``.

    Args:
        dialog: The provider dialog.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
        text: Content of the file the picker returns.
    """
    source = tmp_path / "import.json"
    source.write_text(text, encoding="utf-8")
    _pick(monkeypatch, "getOpenFileName", source)
    _call(dialog, "_on_import_instances")


def _import_payload(records: Mapping[str, object]) -> str:
    """Serialize an import file.

    Args:
        records: The ``instances`` section.

    Returns:
        str: The JSON text.
    """
    return json.dumps({"instances": records})


def test_cancelled_import_changes_nothing(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Cancelling the open picker shows no message and imports nothing.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()

    _call(dialog, "_on_import_instances")

    assert dialogs.information.calls == []
    assert dialogs.warning.calls == []


@pytest.mark.parametrize("text", [None, "{not json"], ids=["missing-file", "malformed-json"])
def test_import_of_an_unreadable_file_is_reported(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    text: str | None,
) -> None:
    """A file that cannot be read or decoded is reported as an import error.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
        text: Content of the import file, or ``None`` for a file that does not exist.
    """
    dialog = build_dialog()
    if text is None:
        _pick(monkeypatch, "getOpenFileName", tmp_path / "missing.json")
        _call(dialog, "_on_import_instances")
    else:
        _import_text(dialog, monkeypatch, tmp_path, text)

    [(title, message)] = _shown(dialogs.warning)
    assert title == "Import Error"
    assert message.startswith("Failed to read the import file:")
    assert dialogs.information.calls == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[1, 2]", "The import file must contain a JSON object."),
        ('{"other": 1}', "The import file contains no 'instances' section."),
        ('{"instances": []}', "The import file contains no 'instances' section."),
    ],
    ids=["array", "no-section", "section-not-an-object"],
)
def test_import_of_a_wrongly_shaped_file_is_refused(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    text: str,
    expected: str,
) -> None:
    """An import file that is not an object with an ``instances`` object is refused with a specific message.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
        text: Content of the import file.
        expected: The message the warning must carry.
    """
    dialog = build_dialog()

    _import_text(dialog, monkeypatch, tmp_path, text)

    assert _shown(dialogs.warning) == [("Import Error", expected)]
    assert dialogs.information.calls == []


def test_import_skips_malformed_records_and_stores_a_known_host_without_asking(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Records that are not objects or carry no valid id are skipped; a record on a known preset host is imported without a question.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    dialog = build_dialog()
    announced: list[None] = []

    def _on_changed() -> None:
        """Record one ``instances_changed`` emission."""
        announced.append(None)

    _ = dialog.instances_changed.connect(_on_changed)
    texts: list[str] = []
    _answer_question(monkeypatch, QMessageBox.StandardButton.No, texts)
    payload = _import_payload(
        {
            "skip-a": 5,
            "skip-b": {"instance_id": 7},
            "imp-gw": {"instance_id": "imp-gw", "display_name": "Imported", "api_base": "https://api.groq.com/openai/v1"},
        },
    )

    _import_text(dialog, monkeypatch, tmp_path, payload)

    assert texts == []
    assert set(_store().load_instances()) == {"imp-gw"}
    assert _call(dialog, "_selected_provider_id") == "imp-gw"
    assert _shown(dialogs.information) == [("Import Complete", "Imported 1 provider instances. Their API keys were not imported.")]
    assert announced == [None]


def test_import_of_nothing_reports_zero_and_announces_nothing(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An import file with an empty ``instances`` object reports zero imported and emits no change.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    dialog = build_dialog()
    announced: list[None] = []

    def _on_changed() -> None:
        """Record one ``instances_changed`` emission."""
        announced.append(None)

    _ = dialog.instances_changed.connect(_on_changed)

    _import_text(dialog, monkeypatch, tmp_path, _import_payload({}))

    assert _shown(dialogs.information) == [("Import Complete", "Imported 0 provider instances. Their API keys were not imported.")]
    assert announced == []


@pytest.mark.parametrize(
    ("answer", "imported"),
    [(QMessageBox.StandardButton.Yes, True), (QMessageBox.StandardButton.No, False)],
    ids=["confirmed", "declined"],
)
def test_import_of_an_unknown_host_asks_with_the_host_and_headers(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    answer: QMessageBox.StandardButton,
    *,
    imported: bool,
) -> None:
    """A record pointing at no known preset host is imported only after the user confirms, and the question names its host and headers.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
        answer: The button the user presses.
        imported: Whether the instance must end up stored.
    """
    dialog = build_dialog()
    texts: list[str] = []
    _answer_question(monkeypatch, answer, texts)
    record = {
        "instance_id": "imp-gw",
        "api_base": "https://gateway.corp.example/v1",
        "headers": {"Authorization": "Bearer ${apiKey}", "X-Tenant": "analysis"},
    }

    _import_text(dialog, monkeypatch, tmp_path, _import_payload({"imp-gw": record}))

    [asked] = texts
    assert "'imp-gw' points at the unrecognised host 'gateway.corp.example'." in asked
    assert "Headers it will send: Authorization, X-Tenant" in asked
    assert "Headers that would carry the API key: Authorization" in asked
    assert ("imp-gw" in _store().load_instances()) is imported


def test_import_refuses_an_id_that_would_read_a_builtin_providers_variables(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A record whose id would read Grok's ``XAI_API_KEY`` is not imported and is listed with the reason.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    dialog = build_dialog()

    _import_text(dialog, monkeypatch, tmp_path, _import_payload({"xai": {"instance_id": "xai"}}))

    [(title, text)] = _shown(dialogs.information)
    assert title == "Import Complete"
    assert text.startswith("Imported 0 provider instances.")
    assert "Not imported:\nxai: " in text
    assert "XAI_API_KEY" in text
    assert _store().stored_instance_ids() == frozenset()


def test_import_write_failure_is_reported_and_the_instance_skipped(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When saving one imported instance fails, the failure names it and the import carries on with nothing stored.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.
    """
    dialog = build_dialog()
    _block_settings_writes()
    record = {"instance_id": "imp-gw", "api_base": "https://api.groq.com/openai/v1"}

    _import_text(dialog, monkeypatch, tmp_path, _import_payload({"imp-gw": record}))

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Import Error"
    assert text.startswith("Failed to save 'imp-gw':")
    assert _shown(dialogs.information) == [("Import Complete", "Imported 0 provider instances. Their API keys were not imported.")]
    assert _store().stored_instance_ids() == frozenset()


def test_registry_failures_are_logged_and_the_provider_shown_as_inactive(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """A registry whose lookups raise leaves the dialog usable: no active provider, every provider shown disconnected.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    with capture_logs() as captured:
        dialog = build_dialog(registry=_FailingRegistry())

    assert _call(dialog, "_get_active_provider_name") is None
    assert _call(dialog, "_is_provider_connected", "openai") is False
    assert _attr(dialog, "_active_label", QLabel).text() == "<b>Active:</b> None selected"
    assert _item_text(dialog, "openai").startswith(_IDLE)
    assert {entry["error"] for entry in _events(captured, "active_provider_lookup_failed")} == {"active lookup failed"}
    checks = _events(captured, "provider_connection_check_failed")
    assert [entry["error"] for entry in checks if entry["provider_id"] == "openai"] == ["lookup of openai failed"]


def test_set_active_marks_a_connected_provider_active_and_announces_it(
    build_dialog: Callable[..., ProviderConfigDialog],
    gateway: _Gateway,
) -> None:
    """Set Active on a connected provider makes it active in the registry, updates the label and list, and emits the change.

    Args:
        build_dialog: Factory for provider dialogs.
        gateway: A connected provider registered as ``my-gw``.
    """
    _save_instance(gateway.instance)
    registry = ProviderRegistry()
    registry.register(gateway.provider)
    dialog = build_dialog(registry=registry)
    changed: list[str] = []
    _ = dialog.active_provider_changed.connect(changed.append)
    _select(dialog, _GW_ID)

    _call(dialog, "_on_set_active")

    assert registry.active_name == _GW_ID
    assert changed == [_GW_ID]
    assert _attr(dialog, "_active_label", QLabel).text() == "<b>Active:</b> Corp Gateway"
    assert _item_text(dialog, _GW_ID) == f"{_CONNECTED} Corp Gateway {_ACTIVE}"


def test_set_active_without_a_current_provider_asks_for_one(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Set Active with no current provider shows a warning.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog(registry=ProviderRegistry())
    setattr(dialog, "_current_provider", None)

    _call(dialog, "_on_set_active")

    assert _shown(dialogs.warning) == [("No Selection", "Please select a provider first.")]


def test_set_active_without_a_registry_says_it_is_unavailable(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Set Active in a dialog built without a registry shows that the registry is unavailable.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()

    _call(dialog, "_on_set_active")

    assert _shown(dialogs.warning) == [("Registry Error", "Provider registry not available.")]


def test_a_successful_connection_test_refreshes_the_provider_status(
    build_dialog: Callable[..., ProviderConfigDialog],
    gateway: _Gateway,
) -> None:
    """A page's successful connection test refreshes the list marker from the registry; a failed one does not.

    Args:
        build_dialog: Factory for provider dialogs.
        gateway: A connected provider that is not yet in the registry.
    """
    _save_instance(gateway.instance)
    registry = ProviderRegistry()
    dialog = build_dialog(registry=registry)
    assert _item_text(dialog, _GW_ID).startswith(_IDLE)
    registry.register(gateway.provider)
    widgets = cast("dict[str, ProviderSettingsWidget]", _priv(dialog, "_provider_widgets"))
    page = widgets[_GW_ID]

    page.connection_tested.emit(_FAILURE, "refused")
    assert _item_text(dialog, _GW_ID).startswith(_IDLE)

    page.connection_tested.emit(_SUCCESS, "ok")
    assert _item_text(dialog, _GW_ID).startswith(_CONNECTED)


def test_discover_updates_the_model_count_of_the_selected_provider(
    build_dialog: Callable[..., ProviderConfigDialog],
    gateway: _Gateway,
    qtbot: QtBot,
) -> None:
    """Discover runs model discovery for the selected provider against its loopback endpoint and shows the model count.

    Args:
        build_dialog: Factory for provider dialogs.
        gateway: A connected provider listing two models.
        qtbot: Pumps the event loop until discovery completes.
    """
    _save_instance(gateway.instance)
    registry = ProviderRegistry()
    registry.register(gateway.provider)
    dialog = build_dialog(registry=registry, discovery=ModelDiscovery(registry))
    _select(dialog, _GW_ID)

    _call(dialog, "_on_discover_selected_provider")

    qtbot.waitUntil(lambda: "(2)" in _item_text(dialog, _GW_ID), timeout=_WAIT_MS)


def test_discover_without_a_discovery_service_starts_nothing(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Discovering a provider in a dialog built without a discovery service returns without starting a worker.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    before = set(bridge_workers_for(dialog))

    dialog.discover_single_provider("openai")

    assert set(bridge_workers_for(dialog)) == before


def test_discover_of_an_invalid_provider_id_is_logged_and_starts_nothing(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """Discovering an id that is not a valid provider id is logged and no worker is started.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    registry = ProviderRegistry()
    dialog = build_dialog(registry=registry, discovery=ModelDiscovery(registry))
    before = set(bridge_workers_for(dialog))

    with capture_logs() as captured:
        dialog.discover_single_provider("Bad Id!")

    assert [entry["provider"] for entry in _events(captured, "unknown_provider_for_discovery")] == ["Bad Id!"]
    assert set(bridge_workers_for(dialog)) == before


def test_oauth_login_for_a_provider_without_oauth_is_logged_and_does_nothing(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """OAuth Login on OpenAI, which has no OAuth flow, logs the unknown provider and starts nothing.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    _select(dialog, "openai")
    before = set(bridge_workers_for(dialog))

    with capture_logs() as captured:
        _call(dialog, "_on_start_oauth")

    assert [entry["provider"] for entry in _events(captured, "oauth_unknown_provider")] == ["openai"]
    assert _events(captured, "oauth_flow_starting") == []
    assert set(bridge_workers_for(dialog)) == before


def test_revoke_of_an_invalid_provider_id_shows_an_error(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Revoking a credential for an id that is not a valid provider id shows an error naming it.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()

    dialog.revoke_oauth_token("Bad Id!")

    assert _shown(dialogs.critical) == [("Revoke Credential", "Unknown provider: Bad Id!")]


def test_revoke_with_nothing_configured_says_there_is_nothing_to_revoke(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    qtbot: QtBot,
) -> None:
    """Revoke Token for a provider with no stored or configured key reports that nothing was revoked.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        qtbot: Pumps the event loop until the revoke result arrives.
    """
    dialog = build_dialog()
    _select(dialog, "openai")

    _call(dialog, "_on_revoke_oauth")

    qtbot.waitUntil(lambda: bool(dialogs.warning.calls), timeout=_WAIT_MS)
    assert _shown(dialogs.warning) == [("Revoke Credential", "No credential is configured for OpenAI; nothing to revoke.")]


def test_revoke_deletes_a_stored_api_key(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    qtbot: QtBot,
) -> None:
    """Revoke Token for a provider with a key in the credential store removes the key and says so.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        qtbot: Pumps the event loop until the revoke result arrives.
    """
    store = get_credential_store()
    _ = run_bridge_coroutine(store.set("openai", ProviderCredentials(api_key=_TEST_KEY)), timeout_s=_BRIDGE_TIMEOUT_S)
    assert run_bridge_coroutine(store.get_source("openai"), timeout_s=_BRIDGE_TIMEOUT_S) is not None
    dialog = build_dialog()
    _select(dialog, "openai")

    _call(dialog, "_on_revoke_oauth")

    qtbot.waitUntil(lambda: bool(dialogs.information.calls), timeout=_WAIT_MS)
    assert _shown(dialogs.information) == [("Revoke Credential", "Stored API key removed for OpenAI.")]
    assert run_bridge_coroutine(store.get_source("openai"), timeout_s=_BRIDGE_TIMEOUT_S) is None


def test_revoke_of_an_environment_only_key_explains_it_cannot_be_removed(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """Revoke Token for a key defined only in the environment warns that it must be edited directly.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the revoke result arrives.
    """
    monkeypatch.setenv("OPENAI_API_KEY", _TEST_KEY)
    dialog = build_dialog()
    _select(dialog, "openai")

    _call(dialog, "_on_revoke_oauth")

    qtbot.waitUntil(lambda: bool(dialogs.warning.calls), timeout=_WAIT_MS)
    [(title, text)] = _shown(dialogs.warning)
    assert title == "Revoke Credential"
    assert text.startswith("No stored API key could be removed for OpenAI from the secure credential store.")
    assert "defined only via a .env file or environment variable" in text


@pytest.mark.usefixtures("failing_keyring")
def test_revoke_failure_is_reported_as_an_error(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
) -> None:
    """When the keyring cannot be used, Revoke Token shows the failure instead of staying silent.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        monkeypatch: Pytest monkeypatch fixture.
        qtbot: Pumps the event loop until the revoke result arrives.
    """
    monkeypatch.setenv("OPENAI_API_KEY", _TEST_KEY)
    dialog = build_dialog()
    _select(dialog, "openai")

    _call(dialog, "_on_revoke_oauth")

    qtbot.waitUntil(lambda: bool(dialogs.critical.calls), timeout=_WAIT_MS)
    [(title, text)] = _shown(dialogs.critical)
    assert title == "Revoke Credential"
    assert text.startswith("Failed to revoke the credential for OpenAI:")
    assert "Keyring is not available" in text


@pytest.mark.usefixtures("failing_keyring")
def test_migration_failure_is_logged(build_dialog: Callable[..., ProviderConfigDialog], qtbot: QtBot) -> None:
    """When the keyring cannot be used, Migrate logs the failure from its error callback.

    Args:
        build_dialog: Factory for provider dialogs.
        qtbot: Pumps the event loop until the migration result arrives.
    """
    dialog = build_dialog()
    _ = drain_bridge_workers_for(dialog)

    with capture_logs() as captured:
        dialog.migrate_credentials()
        qtbot.waitUntil(lambda: bool(_events(captured, "credential_migration_failed")), timeout=_WAIT_MS)

    assert "Keyring is not available for migration" in str(_events(captured, "credential_migration_failed")[0]["error"])


def test_get_settings_collects_every_page(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """The dialog's settings are one entry per provider page, holding that page's defaults.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()

    settings = dialog.get_settings()

    assert list(settings) == list(BUILTIN_PROVIDER_IDS)
    assert settings["anthropic"]["max_retries"] == 3
    assert settings["anthropic"]["enabled"] is True


def test_ok_saves_every_page_and_announces_each_provider(build_dialog: Callable[..., ProviderConfigDialog]) -> None:
    """OK saves each provider's section to ``providers.json`` and announces every provider as updated.

    Args:
        build_dialog: Factory for provider dialogs.
    """
    dialog = build_dialog()
    updated: list[str] = []
    _ = dialog.provider_updated.connect(updated.append)

    _call(dialog, "_on_accept")

    assert updated == list(BUILTIN_PROVIDER_IDS)
    saved = cast("dict[str, object]", json.loads(_settings_path().read_text(encoding="utf-8")))
    assert set(BUILTIN_PROVIDER_IDS) <= set(saved)


def test_write_env_template_creates_a_new_file(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Write .env Template creates the template in the state root and names the file.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    env_file = get_env_file()

    dialog.create_env_template()

    assert env_file.read_text(encoding="utf-8").startswith("# Intellicrack API Credentials")
    assert _shown(dialogs.information) == [("Write .env Template", f"Created a new .env template at {env_file.resolve()}.")]


def test_write_env_template_merges_into_an_existing_file(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Write .env Template keeps an existing file's content, backs it up and lists the variables it appended.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    env_file = get_env_file()
    env_file.write_text("CUSTOM_SETTING=keep\n", encoding="utf-8")

    dialog.create_env_template()

    assert env_file.read_text(encoding="utf-8").startswith("CUSTOM_SETTING=keep\n")
    backups = list(env_file.parent.glob(".env.*.bak"))
    assert [backup.read_text(encoding="utf-8") for backup in backups] == ["CUSTOM_SETTING=keep\n"]
    [(title, text)] = _shown(dialogs.information)
    assert title == "Write .env Template"
    assert text.startswith(f"Existing .env was preserved (backup: {backups[0].resolve()}).\nAppended missing variables: ANTHROPIC_API_KEY")


def test_write_env_template_reports_when_nothing_is_missing(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """Write .env Template on a file that defines every template variable changes nothing and says so.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    env_file = get_env_file()
    sections = cast("Sequence[_Dynamic]", getattr(env_loader_module, "_ENV_TEMPLATE_SECTIONS"))
    content = "\n".join(f"{variable.key}=x" for section in sections for variable in section.variables) + "\n"
    env_file.write_text(content, encoding="utf-8")

    dialog.create_env_template()

    assert env_file.read_text(encoding="utf-8") == content
    [(title, text)] = _shown(dialogs.information)
    assert title == "Write .env Template"
    assert text.startswith("Existing .env already defines every template variable; no changes were made (backup: ")


def test_write_env_template_failure_is_shown_as_an_error(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """When the ``.env`` path cannot be read, Write .env Template shows the failure and no success message.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog()
    get_env_file().mkdir()

    dialog.create_env_template()

    [(title, text)] = _shown(dialogs.critical)
    assert title == "Write .env Template"
    assert text.startswith("Failed to write .env template:")
    assert dialogs.information.calls == []


def test_key_visibility_button_toggles_the_echo_mode(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """The Show button reveals the key as plain text and relabels itself Hide; toggling again masks it.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("anthropic")
    button = _attr(widget, "_show_key_btn", QPushButton)
    key_input = _attr(widget, "_api_key_input", QLineEdit)

    button.setChecked(True)
    assert (key_input.echoMode(), button.text()) == (QLineEdit.EchoMode.Normal, "Hide")

    button.setChecked(False)
    assert (key_input.echoMode(), button.text()) == (QLineEdit.EchoMode.Password, "Show")


@pytest.mark.parametrize("api_base", [None, "http://gw.public.example.com/v1"], ids=["no-url", "public-plaintext-url"])
def test_instance_page_shows_the_saved_record(
    build_widget: Callable[..., ProviderSettingsWidget],
    api_base: str | None,
) -> None:
    """A custom instance's page shows every field of its saved record, and the plaintext-transport acknowledgement only for a public HTTP URL.

    Args:
        build_widget: Factory for provider settings pages.
        api_base: The saved base URL, or ``None`` for a record without one.
    """
    _save_instance(
        ProviderInstance(
            instance_id="bare-gw",
            display_name="Bare",
            dialect=ApiDialect.MESSAGES,
            api_base=api_base,
            headers={"X-Tenant": "analysis"},
            extra_body={"k": 1},
            drop_params=frozenset({"b", "a"}),
            requires_api_key=False,
            insecure_transport_acknowledged=True,
        ),
    )

    widget = build_widget("bare-gw")

    assert _attr(widget, "_display_name_input", QLineEdit).text() == "Bare"
    assert _attr(widget, "_requires_key_checkbox", QCheckBox).isChecked() is False
    assert _attr(widget, "_dialect_combo", QComboBox).currentData() == ApiDialect.MESSAGES.value
    assert _attr(widget, "_headers_edit", QPlainTextEdit).toPlainText() == "X-Tenant: analysis"
    assert _attr(widget, "_extra_body_edit", QPlainTextEdit).toPlainText() == json.dumps({"k": 1}, indent=2)
    assert _attr(widget, "_drop_params_edit", QLineEdit).text() == "a, b"
    assert _attr(widget, "_insecure_ack_checkbox", QCheckBox).isChecked() is True
    assert _attr(widget, "_insecure_ack_checkbox", QCheckBox).isHidden() is (api_base is None)
    assert _attr(widget, "_api_key_input", QLineEdit).toolTip() == "Saved to .env as BARE_GW_API_KEY."
    assert _attr(widget, "_api_base_input", QLineEdit).text() == (api_base or "")


def test_instance_page_without_a_saved_record_hides_the_transport_notice(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """A custom instance page with no saved record starts with defaults and no transport notice.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("fresh-gw")

    assert not _attr(widget, "_display_name_input", QLineEdit).text()
    assert _attr(widget, "_requires_key_checkbox", QCheckBox).isChecked() is True
    assert _attr(widget, "_transport_notice", QLabel).isHidden()


def test_saving_a_page_without_a_record_creates_the_instance(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """Saving the endpoint fields of a custom page with no record stores a new instance named after its id.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("fresh-gw")

    _call(widget, "_save_instance_fields")

    record = _store().load_instances()["fresh-gw"]
    assert (record["display_name"], record["dialect"], record["requires_api_key"], record["enabled"]) == (
        "fresh-gw",
        ApiDialect.CHAT_COMPLETIONS.value,
        True,
        True,
    )
    assert _attr(widget, "_title_label", QLabel).text() == "<h3>fresh-gw Settings</h3>"


def test_invalid_extra_body_is_reported_and_the_previous_value_kept(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
) -> None:
    """Saving an extra body that is not a JSON object warns and keeps the stored body.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
    """
    _save_instance(ProviderInstance(instance_id="bare-gw", display_name="Bare", extra_body={"keep": 1}))
    widget = build_widget("bare-gw")
    _attr(widget, "_extra_body_edit", QPlainTextEdit).setPlainText("[1, 2]")

    _call(widget, "_save_instance_fields")

    assert _shown(dialogs.warning) == [("Extra Body", "Extra body must be a JSON object. The previous value was kept.")]
    assert _store().load_instances()["bare-gw"]["extra_body"] == {"keep": 1}


def test_endpoint_save_failure_is_reported_and_the_record_left_unchanged(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
) -> None:
    """When ``providers.json`` cannot be written, saving endpoint fields warns and the stored record is unchanged.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
    """
    _save_instance(ProviderInstance(instance_id="bare-gw", display_name="Bare"))
    widget = build_widget("bare-gw")
    _attr(widget, "_display_name_input", QLineEdit).setText("Renamed")
    _block_settings_writes()

    _call(widget, "_save_instance_fields")

    [(title, text)] = _shown(dialogs.warning)
    assert title == "Save Error"
    assert text.startswith("Failed to save endpoint settings:")
    assert _store().load_instances()["bare-gw"]["display_name"] == "Bare"
    assert _attr(widget, "_title_label", QLabel).text() == "<h3>Bare Settings</h3>"


def test_transport_notice_update_without_an_endpoint_field_keeps_the_notice(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """With no base URL field the transport notice is left exactly as it was.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("fresh-gw")
    base_input = _attr(widget, "_api_base_input", QLineEdit)
    base_input.setText("http://gw.public.example.com/v1")
    _call(widget, "_update_transport_notice")
    notice = _attr(widget, "_transport_notice", QLabel)
    shown = notice.text()
    assert shown.startswith("This base URL is plain HTTP to a public host")
    setattr(widget, "_api_base_input", None)
    base_input.setText("https://secure.example.com/v1")

    _call(widget, "_update_transport_notice")

    assert notice.text() == shown
    assert not notice.isHidden()


def test_header_notice_names_the_headers_that_carry_the_key(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """Editing headers lists those whose value contains the key placeholder.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("fresh-gw")

    _attr(widget, "_headers_edit", QPlainTextEdit).setPlainText("Authorization: Bearer ${apiKey}\nX-Tenant: analysis")

    assert _attr(widget, "_header_key_notice", QLabel).text() == "These headers will carry the API key: Authorization"


def test_resource_links_for_a_provider_without_any_add_nothing(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """Asking for resource links for a provider that has none adds no group to the layout.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("fresh-gw")
    layout = QVBoxLayout()

    _call(widget, "_add_provider_resource_links", layout)

    assert layout.count() == 0
    assert not hasattr(widget, "_resource_buttons")


def test_pull_button_without_a_model_name_starts_nothing(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """Pull Model with an empty name leaves the status unchanged, and a page without a pull field ignores the click.

    Args:
        build_widget: Factory for provider settings pages.
    """
    ollama = build_widget("ollama")
    anthropic = build_widget("anthropic")

    _call(ollama, "_on_pull_model")
    _call(anthropic, "_on_pull_model")

    assert not _attr(ollama, "_status_label", QLabel).text()
    assert not _attr(anthropic, "_status_label", QLabel).text()


def test_pull_of_a_model_from_an_unreachable_host_is_reported(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
    qtbot: QtBot,
) -> None:
    """Pull Model against a closed port reports the connect failure in the status line and a warning.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
        qtbot: Pumps the event loop until the pull result arrives.
    """
    widget = build_widget("ollama")
    _attr(widget, "_api_base_input", QLineEdit).setText(_closed_origin())
    _attr(widget, "_pull_model_input", QLineEdit).setText("  llama3.3:latest  ")

    _call(widget, "_on_pull_model")

    qtbot.waitUntil(lambda: bool(dialogs.warning.calls), timeout=_WAIT_MS)
    [(title, text)] = _shown(dialogs.warning)
    assert title == "Ollama Pull Failed"
    assert text.startswith("Connect failed:")


def test_pull_progress_is_shown_in_the_status_line(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """A pull progress update appears in the status line with the model name.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("ollama")

    _call(widget, "_on_ollama_pull_progress", "llama3", "pulling manifest")

    assert _attr(widget, "_status_label", QLabel).text() == "Pulling llama3: pulling manifest"


@pytest.mark.parametrize(
    ("success", "message", "shown"),
    [
        (True, "all done", "all done"),
        (True, "", "Pulled m"),
        (False, "disk full", "disk full"),
        (False, "", "Failed to pull m"),
    ],
    ids=["ok-with-message", "ok-without-message", "failed-with-message", "failed-without-message"],
)
def test_finished_pull_updates_the_status_and_tells_the_user(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
    message: str,
    shown: str,
    *,
    success: bool,
) -> None:
    """A finished pull sets the status line and shows an information box on success or a warning on failure.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
        message: The outcome message the pull reported.
        shown: The text the status line and the message box must carry.
        success: Whether the pull succeeded.
    """
    widget = build_widget("ollama")

    _call(widget, "_on_ollama_pull_finished", success, "m", message)

    assert _attr(widget, "_status_label", QLabel).text() == shown
    if success:
        assert _shown(dialogs.information) == [("Ollama Pull", shown)]
        assert dialogs.warning.calls == []
    else:
        assert _shown(dialogs.warning) == [("Ollama Pull Failed", shown)]
        assert dialogs.information.calls == []
