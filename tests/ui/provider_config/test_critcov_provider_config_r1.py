# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the failure, fallback and missing-control paths of the provider configuration dialog.

Every test drives a real :class:`ProviderConfigDialog` or :class:`ProviderSettingsWidget`. Provider state, ``.env`` and the keyring live in the
test's temporary directory, provider endpoints are loopback servers from ``tests/_helpers``, and the OAuth browser flow is never started:
the two OAuth tests hand the dialog a configuration the manager rejects before it opens a server or a browser. Doubles are subclasses of
real product classes (a registry whose activation fails, a discovery service that recommends a model, a credential loader that names no
variable). Where a control cannot be absent on a real page, the test assigns ``None`` to the private attribute that holds it, which is the
state the code under test guards against; each such test says so.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, NamedTuple, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QThread
from PyQt6.QtWidgets import QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox
from structlog.testing import capture_logs

import intellicrack.credentials.oauth as oauth_module
import intellicrack.credentials.store as store_module
import intellicrack.providers.local_transformers as local_transformers_module
from intellicrack.core.config import get_config_file, get_env_file
from intellicrack.core.types import ModelInfo
from intellicrack.credentials.env_loader import CredentialField, CredentialLoader, get_credential_loader, unregister_instance_mapping
from intellicrack.credentials.oauth import OAuthConfig, OAuthProvider
from intellicrack.credentials.provider_settings import PROVIDER_SETTINGS_FILENAME, ProviderSettingsStore
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.panels.async_bridge import drain_bridge_workers
from intellicrack.ui.provider_config import ConnectionTestWorker, ProviderConfigDialog, ProviderSettingsWidget
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.private_keyring import installed_keyring, private_file_keyring
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests.ui.conftest import DialogRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.providers.base import LLMProviderBase


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_WAIT_MS: int = 30_000
_KEY: str = "loop" + "back-" + "credential"
_MALFORMED_BASE_ENV: str = "OPENAI_API_BASE=http://[bad\n"
_MALFORMED_BASE_ERROR: str = "Invalid IPv6 URL"
_TORCH_MISSING_MESSAGE: str = "torch is required for local model inference"
_INSTANCE_IDS: tuple[str, ...] = ("bare-gw",)
_FRESH_DEVICE_INFO: dict[str, object] = {
    "device_type": "cpu",
    "cuda_available": False,
    "xpu_available": False,
    "is_arc_b580": False,
    "warnings": [],
}


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


class _UnknownProviderRegistry(ProviderRegistry):
    """A real registry whose activation rejects every name as unknown."""

    @override
    def set_active(self, name: str) -> None:
        """Refuse to activate a provider.

        Args:
            name: The provider asked for.

        Raises:
            ValueError: Always.
        """
        message = f"unknown provider {name}"
        raise ValueError(message)


class _BrokenActivationRegistry(ProviderRegistry):
    """A real registry whose activation fails the way a corrupted one would."""

    def __init__(self, *, runtime: bool) -> None:
        """Remember which failure to raise.

        Args:
            runtime: ``True`` to raise ``RuntimeError``, ``False`` to raise ``AttributeError``.
        """
        super().__init__()
        self._runtime = runtime

    @override
    def set_active(self, name: str) -> None:
        """Refuse to activate a provider.

        Args:
            name: The provider asked for.

        Raises:
            RuntimeError: When built to fail with a runtime error.
            AttributeError: Otherwise.
        """
        message = f"cannot activate {name}"
        if self._runtime:
            raise RuntimeError(message)
        raise AttributeError(message)


class _LookupFailingRegistry(ProviderRegistry):
    """A real registry whose lookups fail the way a corrupted one would."""

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


class _RecommendingDiscovery(ModelDiscovery):
    """A real discovery service that recommends one fixed model for any task."""

    @override
    async def get_recommended_model(self, task_type: str) -> ModelInfo | None:
        """Recommend the fixed model.

        Args:
            task_type: The task asked for; ignored.

        Returns:
            ModelInfo | None: The fixed model.
        """
        del task_type
        return ModelInfo(
            id="m2",
            name="Model Two",
            provider="openai",
            context_window=128000,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_cost_per_1m_tokens=None,
            output_cost_per_1m_tokens=None,
        )


class _VariableLessLoader(CredentialLoader):
    """A real credential loader that names no environment variable for any field."""

    @override
    def env_var_for(self, provider: str, field: CredentialField) -> str | None:
        """Report that the provider has no variable for the field.

        Args:
            provider: The provider asked about.
            field: The credential field asked about.

        Returns:
            str | None: Always ``None``.
        """
        del provider, field
        return None


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


def _select(dialog: ProviderConfigDialog, provider_id: str) -> None:
    """Select a provider in the dialog's list.

    Args:
        dialog: The provider dialog.
        provider_id: Id of the entry to select.
    """
    items = cast("dict[str, QListWidgetItem]", _priv(dialog, "_provider_items"))
    _attr(dialog, "_provider_list", QListWidget).setCurrentItem(items[provider_id])


def _shown(recorder: DialogRecorder) -> list[tuple[str, str]]:
    """List the title and text of every message a recorder saw.

    Args:
        recorder: A message box recorder.

    Returns:
        list[tuple[str, str]]: One ``(title, text)`` pair per call.
    """
    return [(str(call[1]), str(call[2])) for call in recorder.calls]


def _untrack_variable(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make the test's monkeypatch remove a variable a credential loader may inject.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        name: The environment variable name.
    """
    monkeypatch.setenv(name, "placeholder")
    monkeypatch.delenv(name)


def _probe(worker: ConnectionTestWorker) -> tuple[bool, str]:
    """Run a connection test's probe on the calling thread.

    Args:
        worker: The worker to run.

    Returns:
        tuple[bool, str]: The probe's ``(success, message)``.
    """
    method = cast("Callable[[], tuple[bool, str]]", getattr(worker, "_test_provider_connection"))
    return method()


def _oauth_config(*, client_id: str, redirect_uri: str) -> OAuthConfig:
    """Build an OAuth configuration that a manager rejects before it opens anything.

    Args:
        client_id: The client id; empty is rejected when the authorization URL is built.
        redirect_uri: The redirect URI; a non-loopback one is rejected before any server starts.

    Returns:
        OAuthConfig: The configuration, for the Google provider.
    """
    return OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id=client_id,
        client_secret=None,
        authorization_url="https://accounts.example.com/authorize",
        token_url="https://accounts.example.com/token",
        scopes=("openid",),
        redirect_uri=redirect_uri,
    )


def _settle(qtbot: QtBot, widget: ProviderSettingsWidget) -> None:
    """Let the page's scheduled model refresh start and finish, then join every worker.

    Args:
        qtbot: pytest-qt bot.
        widget: The freshly built page.
    """
    has_key = bool(_attr(widget, "_api_key_input", QLineEdit).text().strip())
    if has_key or not _call(widget, "_api_key_required"):
        qtbot.waitUntil(lambda: _priv(widget, "_refresh_worker") is not None, timeout=_WAIT_MS)
    worker: object = _priv(widget, "_refresh_worker")
    if isinstance(worker, QThread):
        assert worker.wait(_WAIT_MS)
    _ = drain_bridge_workers()
    QCoreApplication.processEvents()


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Generator[Path]:
    """Redirect provider state, ``.env`` and the keyring into the test directory with no provider variables set.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    store_holder: _Dynamic = getattr(store_module, "_store_holder")
    oauth_holder: _Dynamic = getattr(oauth_module, "_OAuthManagerHolder")
    with (
        redirected_state_root(monkeypatch, tmp_path) as root,
        installed_keyring(private_file_keyring(tmp_path / "keyring.cfg")),
    ):
        store_holder.instance = None
        oauth_holder.instance = None
        try:
            yield root
        finally:
            store_holder.instance = None
            oauth_holder.instance = None
            for instance_id in _INSTANCE_IDS:
                unregister_instance_mapping(instance_id)
            _ = drain_bridge_workers()


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


@pytest.fixture
def build_dialog() -> Generator[Callable[..., ProviderConfigDialog]]:
    """Build provider dialogs and tear them down without leaving a worker or timer behind.

    Yields:
        Callable[..., ProviderConfigDialog]: Factory taking optional ``registry`` and ``discovery`` keywords.
    """
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
def build_widget(qtbot: QtBot) -> Generator[Callable[..., ProviderSettingsWidget]]:
    """Build provider settings pages, settle their scheduled refresh and tear them down without leaving a worker behind.

    Args:
        qtbot: pytest-qt bot.

    Yields:
        Callable[..., ProviderSettingsWidget]: Factory taking the provider id and optional ``registry``, ``discovery`` and ``loader``.
    """
    created: list[ProviderSettingsWidget] = []

    def _build(
        provider_id: str,
        *,
        registry: ProviderRegistry | None = None,
        discovery: ModelDiscovery | None = None,
        loader: CredentialLoader | None = None,
    ) -> ProviderSettingsWidget:
        """Construct, track and settle a settings page.

        Args:
            provider_id: Id of the provider the page configures.
            registry: Provider registry handed to the page, if any.
            discovery: Model discovery service handed to the page, if any.
            loader: Credential loader handed to the page, if any.

        Returns:
            ProviderSettingsWidget: The page.
        """
        widget = ProviderSettingsWidget(provider_id, registry, _settings_path(), None, discovery, credential_loader=loader)
        created.append(widget)
        _settle(qtbot, widget)
        return widget

    try:
        yield _build
    finally:
        _ = drain_bridge_workers()
        for widget in created:
            if not sip.isdeleted(widget):
                sip.delete(widget)


def test_set_active_reports_an_unknown_provider(build_dialog: Callable[..., ProviderConfigDialog], dialogs: _Dialogs) -> None:
    """A registry that rejects the name makes Set Active show an error naming the provider.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
    """
    dialog = build_dialog(registry=_UnknownProviderRegistry())
    _select(dialog, "openai")

    _call(dialog, "_on_set_active")

    assert _shown(dialogs.critical) == [("Error", "Unknown provider: openai")]
    assert dialogs.warning.calls == []


@pytest.mark.parametrize("runtime", [True, False], ids=["runtime-error", "attribute-error"])
def test_set_active_reports_a_registry_failure(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    *,
    runtime: bool,
) -> None:
    """A registry that fails while activating shows the failure's own text.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        runtime: Whether the registry fails with a runtime error rather than an attribute error.
    """
    dialog = build_dialog(registry=_BrokenActivationRegistry(runtime=runtime))
    _select(dialog, "openai")

    _call(dialog, "_on_set_active")

    assert _shown(dialogs.critical) == [("Error", "Failed to set active provider: cannot activate openai")]
    assert dialogs.warning.calls == []


def test_reload_failure_is_logged_and_the_overview_is_still_refreshed(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ``.env`` whose base URL cannot be parsed makes the reload fail; the failure is logged and the overview rebuilt.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    dialog = build_dialog()
    _untrack_variable(monkeypatch, "OPENAI_API_BASE")
    _ = get_env_file().write_text(_MALFORMED_BASE_ENV, encoding="utf-8")

    with capture_logs() as captured:
        dialog.refresh_credentials()

    assert [entry["error"] for entry in _events(captured, "credential_refresh_failed")] == [_MALFORMED_BASE_ERROR]
    assert len(_events(captured, "credential_overview")) == 1


def test_overview_failure_is_skipped_and_logged(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the credential loader cannot be built, the overview keeps its previous content and the skip is logged.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    dialog = build_dialog()
    before = _priv(dialog, "_credential_overview")
    _untrack_variable(monkeypatch, "OPENAI_API_BASE")
    _ = get_env_file().write_text(_MALFORMED_BASE_ENV, encoding="utf-8")
    get_credential_loader.cache_clear()

    with capture_logs() as captured:
        _call(dialog, "_load_credential_overview")

    assert [entry["error"] for entry in _events(captured, "credential_overview_load_skipped")] == [_MALFORMED_BASE_ERROR]
    assert _priv(dialog, "_credential_overview") is before


def test_discovery_failure_is_logged_with_the_provider(build_dialog: Callable[..., ProviderConfigDialog], qtbot: QtBot) -> None:
    """A discovery run that raises is reported from the error callback with the provider and the reason.

    Args:
        build_dialog: Factory for provider dialogs.
        qtbot: Pumps the event loop until the failure is delivered.
    """
    dialog = build_dialog(discovery=ModelDiscovery(_LookupFailingRegistry()))

    with capture_logs() as captured:
        dialog.discover_single_provider("openai")
        qtbot.waitUntil(lambda: bool(_events(captured, "provider_discovery_failed")), timeout=_WAIT_MS)

    [failure] = _events(captured, "provider_discovery_failed")
    assert failure["provider"] == "openai"
    assert failure["error"] == "lookup of openai failed"


def test_oauth_without_a_client_id_tells_the_user_which_variable_to_set(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    qtbot: QtBot,
) -> None:
    """An OAuth configuration without a client id is refused before any browser opens, with the variable to set, and the overview reloads.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        qtbot: Pumps the event loop until the failure is delivered.
    """
    dialog = build_dialog()
    config = _oauth_config(client_id="", redirect_uri="http://localhost:8080/callback")

    with capture_logs() as captured:
        _call(dialog, "_run_oauth_flow", "google", OAuthProvider.GOOGLE, config)
        qtbot.waitUntil(lambda: bool(dialogs.critical.calls), timeout=_WAIT_MS)

    expected = (
        "No OAuth client_id is configured for Google Gemini. Set the GOOGLE_OAUTH_CLIENT_ID environment variable before "
        "starting OAuth login for this provider."
    )
    assert _shown(dialogs.critical) == [("OAuth Login", expected)]
    assert len(_events(captured, "credential_overview")) == 1


def test_oauth_with_a_non_loopback_redirect_reports_the_failure(
    build_dialog: Callable[..., ProviderConfigDialog],
    dialogs: _Dialogs,
    qtbot: QtBot,
) -> None:
    """Any other OAuth failure is shown with its reason, nothing is started, and the overview reloads.

    Args:
        build_dialog: Factory for provider dialogs.
        dialogs: Message box recorders.
        qtbot: Pumps the event loop until the failure is delivered.
    """
    dialog = build_dialog()
    redirect = "https://gateway.example.com/callback"
    config = _oauth_config(client_id="client", redirect_uri=redirect)

    with capture_logs() as captured:
        _call(dialog, "_run_oauth_flow", "google", OAuthProvider.GOOGLE, config)
        qtbot.waitUntil(lambda: bool(dialogs.critical.calls), timeout=_WAIT_MS)

    expected = (
        f"OAuth login failed for Google Gemini: OAuth redirect URI {redirect!r} is not an http loopback address, "
        "so the authorization response could never reach Intellicrack"
    )
    assert _shown(dialogs.critical) == [("OAuth Login", expected)]
    assert len(_events(captured, "credential_overview")) == 1


def test_status_update_without_a_status_label_changes_nothing(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """With no status label to write to, a status update is ignored.

    The label is detached by assigning ``None`` to its private attribute, the state the guard exists for.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("openai")
    label = _attr(widget, "_status_label", QLabel)
    label.setText("kept")
    setattr(widget, "_status_label", None)

    _call(widget, "_set_status", "replaced")

    assert label.text() == "kept"


def test_saving_endpoint_fields_without_a_base_url_editor_keeps_the_saved_url(
    build_widget: Callable[..., ProviderSettingsWidget],
) -> None:
    """A page without a base URL editor leaves the saved base URL as it was when the endpoint fields are saved.

    The editor is detached by assigning ``None`` to its private attribute.

    Args:
        build_widget: Factory for provider settings pages.
    """
    _save_instance(ProviderInstance(instance_id="bare-gw", display_name="Bare", api_base="https://gw.example.com/v1"))
    widget = build_widget("bare-gw")
    _attr(widget, "_api_base_input", QLineEdit).setText("https://other.example.com/v1")
    setattr(widget, "_api_base_input", None)

    _call(widget, "_save_instance_fields")

    assert _store().load_instances()["bare-gw"]["api_base"] == "https://gw.example.com/v1"


def test_loading_settings_without_a_base_url_editor_leaves_no_trace(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """Loading settings into a page without a base URL editor does not touch the detached editor.

    The editor is detached by assigning ``None`` to its private attribute.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("openai")
    editor = _attr(widget, "_api_base_input", QLineEdit)
    editor.setText("kept")
    setattr(widget, "_api_base_input", None)

    _call(widget, "_load_settings")

    assert editor.text() == "kept"


def test_settings_without_a_base_url_editor_omit_the_base_url(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """A page without a base URL editor reports no base URL but still reports its organization.

    The editor is detached by assigning ``None`` to its private attribute.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("openai")
    setattr(widget, "_api_base_input", None)

    settings = widget.get_settings()

    assert "api_base" not in settings
    assert not settings["organization_id"]


@pytest.mark.parametrize(
    ("control", "key"),
    [
        ("_prefer_xpu_cb", "prefer_xpu"),
        ("_device_combo", "device_index"),
        ("_dtype_combo", "dtype_override"),
        ("_cache_spin", "cache_size_mb"),
    ],
)
def test_local_page_settings_omit_a_missing_device_control(
    build_widget: Callable[..., ProviderSettingsWidget],
    control: str,
    key: str,
) -> None:
    """Without one of its device controls, the Local Transformers page drops exactly that setting.

    The control is detached by assigning ``None`` to its private attribute.

    Args:
        build_widget: Factory for provider settings pages.
        control: Private attribute holding the control.
        key: The setting that control supplies.
    """
    widget = build_widget("local_transformers")
    complete = widget.get_settings()
    assert key in complete
    setattr(widget, control, None)

    reduced = widget.get_settings()

    assert key not in reduced
    assert set(reduced) == set(complete) - {key}


def test_cache_limit_is_ignored_by_a_page_without_a_cache_control(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
) -> None:
    """Applying a cache limit on a page that has no cache control shows nothing.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
    """
    widget = build_widget("openai")
    assert not hasattr(widget, "_cache_spin")

    _call(widget, "_on_apply_cache_size")

    assert dialogs.information.calls == []


def test_key_is_not_persisted_when_the_loader_names_no_variable(
    build_widget: Callable[..., ProviderSettingsWidget],
    dialogs: _Dialogs,
) -> None:
    """When the credential loader has no variable for the API key, nothing is written to ``.env`` and nothing is reported.

    Args:
        build_widget: Factory for provider settings pages.
        dialogs: Message box recorders.
    """
    widget = build_widget("openai", loader=_VariableLessLoader(get_env_file()))
    _attr(widget, "_api_key_input", QLineEdit).setText(_KEY)

    _call(widget, "_persist_api_key_to_env")

    assert not get_env_file().exists()
    assert dialogs.warning.calls == []


def test_device_info_without_a_registry_comes_from_a_fresh_provider(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """A Local Transformers page built without a registry reports the device record of a freshly built provider.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("local_transformers")

    assert widget.get_provider_device_info() == _FRESH_DEVICE_INFO


def test_device_info_ignores_a_registered_provider_that_has_no_device_query(
    build_widget: Callable[..., ProviderSettingsWidget],
) -> None:
    """A provider registered under the local id that cannot describe a device is skipped for a freshly built one.

    Args:
        build_widget: Factory for provider settings pages.
    """
    registry = ProviderRegistry()
    registry.register(ConfigurableProvider(ProviderInstance(instance_id="local_transformers")))
    widget = build_widget("local_transformers", registry=registry)

    assert widget.get_provider_device_info() == _FRESH_DEVICE_INFO


def test_local_transformers_connection_test_reports_a_missing_torch() -> None:
    """Without PyTorch the local connection test fails with the provider's own message and logs it.

    The module's private ``_torch`` handle is set to ``None`` for the call, which is the state on a machine without PyTorch, and restored.
    """
    previous: _Dynamic = getattr(local_transformers_module, "_torch")
    setattr(local_transformers_module, "_torch", None)
    try:
        with capture_logs() as captured:
            result = _probe(ConnectionTestWorker("local_transformers", ""))
    finally:
        setattr(local_transformers_module, "_torch", previous)

    assert result == (False, _TORCH_MISSING_MESSAGE)
    [failure] = _events(captured, "provider_test_failed")
    assert failure["provider"] == "local_transformers"
    assert failure["error"] == _TORCH_MISSING_MESSAGE


@pytest.mark.asyncio
async def test_local_transformers_connection_test_inside_a_running_loop_is_scheduled() -> None:
    """Called from a running event loop the local connection test is scheduled as a task and the caller is told so."""
    result = _probe(ConnectionTestWorker("local_transformers", ""))
    pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    _ = await asyncio.gather(*pending)

    assert result == (False, "Local Transformers test scheduled on running loop")
    assert len(pending) == 1


@pytest.mark.asyncio
async def test_grok_connection_test_inside_a_running_loop_is_scheduled() -> None:
    """Called from a running event loop the Grok connection test is scheduled as a task, which still reaches the endpoint."""
    with OpenAIModelsServer(model_ids=["grok-4"], accepted_key=_KEY) as server:
        result = _probe(ConnectionTestWorker("grok", _KEY, server.base_url))
        pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        _ = await asyncio.gather(*pending)

        assert result == (False, "Grok test scheduled on running loop")
        sent = server.requests()
        assert sent
        assert {request.headers["authorization"] for request in sent} == {f"Bearer {_KEY}"}


def test_recommended_model_is_shown_on_the_page(build_widget: Callable[..., ProviderSettingsWidget]) -> None:
    """When the discovery service recommends a model, the page shows its name after ``Recommended:``.

    Args:
        build_widget: Factory for provider settings pages.
    """
    widget = build_widget("openai", discovery=_RecommendingDiscovery(ProviderRegistry()))

    assert _attr(widget, "_recommended_label", QLabel).text() == "Recommended: Model Two"
