# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the device, cache, model-refresh, persistence and pull handlers of the provider settings widget and the model picker.

Every test drives a real ``ProviderSettingsWidget`` or ``ModelSelectionDialog``. The widget's ``.env`` file and ``providers.json`` live in the
test's temporary directory, the process environment is stripped of provider variables, and all provider traffic goes to loopback servers from
``tests/_helpers``. Expected values come from the strings the handlers are documented to show, from files the tests write themselves, and from
the wire requests the loopback servers record.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent, QThread
from PyQt6.QtWidgets import QCheckBox, QComboBox, QDialog, QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton, QSpinBox, QWidget
from structlog.testing import capture_logs

from intellicrack.core.types import ModelInfo
from intellicrack.credentials.env_loader import CredentialField, CredentialLoader
from intellicrack.credentials.provider_settings import MODEL_OVERRIDES_KEY, ProviderSettingsStore
from intellicrack.providers.discovery import DiscoveryEvent, ModelDiscovery
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.providers.xpu_utils import get_optimal_dtype_for_xpu
from intellicrack.ui.panels.async_bridge import drain_bridge_workers
from intellicrack.ui.provider_config import ModelSelectionDialog, ProviderSettingsWidget
from tests._helpers.provider_state import isolate_provider_environment
from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint, ScriptedReply, json_reply
from tests._helpers.stalling_http import StallingServer
from tests.ui.conftest import DialogRecorder, SignalRecorder


if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_AUTO_REFRESH_SETTLE_MS: int = 450
_PULL_REFRESH_WAIT_MS: int = 700
_WORKER_JOIN_MS: int = 60_000
_SIGNAL_TIMEOUT_MS: int = 30_000
_CONNECT_TIMEOUT_MS: int = 20_000
_FOUND: bool = True
_NOT_FOUND: bool = False
_DASH: str = "—"
_LOOPBACK_KEY: str = "loopback" + "-" + "value"
_NO_XPU_DEVICE_INFO: dict[str, object] = {
    "device_type": "cpu",
    "cuda_available": False,
    "xpu_available": False,
    "is_arc_b580": False,
    "warnings": [],
}


class _Dialogs(NamedTuple):
    """Recorders installed over the message boxes the widget opens.

    Attributes:
        information: Recorder installed over ``QMessageBox.information``.
        warning: Recorder installed over ``QMessageBox.warning``.
    """

    information: DialogRecorder
    warning: DialogRecorder


class _WidgetFactory(Protocol):
    """Builds settings widgets bound to the test's ``.env`` and ``providers.json``."""

    def __call__(
        self,
        provider_id: str,
        *,
        registry: ProviderRegistry | None = None,
        discovery: ModelDiscovery | None = None,
    ) -> ProviderSettingsWidget:
        """Build a settings widget that is closed and settled when the test ends.

        Args:
            provider_id: Provider to configure.
            registry: Provider registry handed to the widget, if any.
            discovery: Model discovery service handed to the widget, if any.

        Returns:
            ProviderSettingsWidget: The live widget.
        """
        ...


class _MarkerDeviceProvider(LocalTransformersProvider):
    """A real local transformers provider that reports a recognizable device record."""

    @override
    def get_device_info(self) -> dict[str, object]:
        """Report a record no real device query would produce.

        Returns:
            dict[str, object]: A record carrying only a marker device type.
        """
        return {"device_type": "registry-marker"}


class _BrokenDeviceProvider(LocalTransformersProvider):
    """A real local transformers provider whose device query always fails."""

    @override
    def get_device_info(self) -> dict[str, object]:
        """Refuse to describe the device.

        Returns:
            dict[str, object]: Never returns.

        Raises:
            RuntimeError: Always, standing in for a driver that cannot be queried.
        """
        message = "device query refused"
        raise RuntimeError(message)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute of a product object.

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


def _control[T](owner: object, name: str, expected_type: type[T]) -> T:
    """Fetch a named child control with a runtime type check.

    Args:
        owner: The widget or dialog that owns the control.
        name: Attribute name of the control.
        expected_type: The control's expected type.

    Returns:
        T: The control.
    """
    control: object = getattr(owner, name)
    assert isinstance(control, expected_type), f"{name} is {type(control).__name__}, expected {expected_type.__name__}"
    return control


def _texts(recorder: DialogRecorder) -> list[tuple[str, str]]:
    """List the title and text of every recorded message box.

    Args:
        recorder: Recorder installed over a ``QMessageBox`` static function.

    Returns:
        list[tuple[str, str]]: ``(title, text)`` per call, in call order.
    """
    return [(str(call[1]), str(call[2])) for call in recorder.calls]


def _event_names(captured: list[MutableMapping[str, Any]]) -> list[str]:
    """List the event names a log capture collected.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.

    Returns:
        list[str]: Event names in logging order.
    """
    return [str(entry.get("event")) for entry in captured]


def _model_info(model_id: str, name: str, *, context_window: int, tools: bool, vision: bool) -> ModelInfo:
    """Build a model record.

    Args:
        model_id: Identifier of the model.
        name: Display name of the model.
        context_window: Context window in tokens.
        tools: Whether the model supports tool calling.
        vision: Whether the model supports image input.

    Returns:
        ModelInfo: The record.
    """
    return ModelInfo(
        id=model_id,
        name=name,
        provider="test",
        context_window=context_window,
        supports_tools=tools,
        supports_vision=vision,
        supports_streaming=True,
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
    )


def _event(
    *,
    success: bool,
    model_count: int = 0,
    new_models: list[str] | None = None,
    removed_models: list[str] | None = None,
    error_message: str | None = None,
) -> DiscoveryEvent:
    """Build a discovery event for ``openai`` with a fixed timestamp.

    Args:
        success: Whether the discovery succeeded.
        model_count: Number of models found.
        new_models: Model identifiers added since the previous discovery.
        removed_models: Model identifiers no longer offered.
        error_message: Failure reason, if any.

    Returns:
        DiscoveryEvent: The event, stamped 2026-01-02 03:04:05.
    """
    return DiscoveryEvent(
        provider="openai",
        timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        model_count=model_count,
        success=success,
        error_message=error_message,
        new_models=new_models or [],
        removed_models=removed_models or [],
    )


def _discovery_with(event: DiscoveryEvent | None) -> ModelDiscovery:
    """Build a real discovery service whose history holds at most one event.

    Args:
        event: The event to record, or ``None`` for an empty history.

    Returns:
        ModelDiscovery: The service.
    """
    discovery = ModelDiscovery(ProviderRegistry())
    if event is not None:
        history: list[DiscoveryEvent] = _priv(discovery, "_events")
        history.append(event)
    return discovery


def _loopback_openrouter(base_url: str) -> type[OpenRouterProvider]:
    """Build an OpenRouter provider class that talks to a loopback endpoint.

    Args:
        base_url: The API base URL the class uses instead of the public one.

    Returns:
        type[OpenRouterProvider]: A subclass of the real provider with only its base URL changed.
    """

    class _LoopbackOpenRouter(OpenRouterProvider):
        """The real OpenRouter provider aimed at a loopback endpoint."""

        BASE_URL: str = base_url

    return _LoopbackOpenRouter


def _new_widget(
    tmp_path: Path,
    provider_id: str,
    *,
    registry: ProviderRegistry | None = None,
    discovery: ModelDiscovery | None = None,
) -> ProviderSettingsWidget:
    """Build a settings widget bound to the test's ``.env`` and ``providers.json``.

    Args:
        tmp_path: The test's private directory.
        provider_id: Provider to configure.
        registry: Provider registry handed to the widget, if any.
        discovery: Model discovery service handed to the widget, if any.

    Returns:
        ProviderSettingsWidget: The live widget.
    """
    return ProviderSettingsWidget(
        provider_id,
        registry=registry,
        config_path=tmp_path / "providers.json",
        model_discovery=discovery,
        credential_loader=CredentialLoader(tmp_path / ".env"),
    )


def _signal_args(blocker: object) -> list[object] | None:
    """Return the arguments a waited-for signal carried.

    Args:
        blocker: The object ``qtbot.waitSignal`` yielded.

    Returns:
        list[object] | None: The emitted arguments, or ``None`` when nothing was emitted.
    """
    raw: object = _priv(blocker, "args")
    return None if raw is None else list(cast("list[object]", raw))


def _settle_widget_workers(qtbot: QtBot, widget: QWidget) -> None:
    """Let a widget's scheduled refresh start, finish and be handled, then join every worker.

    Args:
        qtbot: pytest-qt bot.
        widget: The settings widget about to be closed.
    """
    qtbot.wait(_AUTO_REFRESH_SETTLE_MS)
    for worker_name in ("_refresh_worker", "_test_worker"):
        worker: object = getattr(widget, worker_name, None)
        if isinstance(worker, QThread):
            assert worker.wait(_WORKER_JOIN_MS), f"{worker_name} did not finish"
    drain_bridge_workers()
    QCoreApplication.processEvents()


@pytest.fixture(autouse=True)
def clean_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from an environment without provider variables.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    isolate_provider_environment(monkeypatch)


@pytest.fixture
def dialogs(monkeypatch: pytest.MonkeyPatch) -> _Dialogs:
    """Record the information and warning boxes the widget opens instead of showing them.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        _Dialogs: The installed recorders.
    """
    information = DialogRecorder()
    warning = DialogRecorder()
    monkeypatch.setattr(QMessageBox, "information", information)
    monkeypatch.setattr(QMessageBox, "warning", warning)
    return _Dialogs(information=information, warning=warning)


@pytest.fixture
def make_widget(qtbot: QtBot, tmp_path: Path) -> _WidgetFactory:
    """Provide a factory for settings widgets that are settled before they close.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.

    Returns:
        _WidgetFactory: Factory taking a provider id and optional registry and discovery service.
    """

    def _make(
        provider_id: str,
        *,
        registry: ProviderRegistry | None = None,
        discovery: ModelDiscovery | None = None,
    ) -> ProviderSettingsWidget:
        """Build one widget and register it for settling and closing.

        Args:
            provider_id: Provider to configure.
            registry: Provider registry handed to the widget, if any.
            discovery: Model discovery service handed to the widget, if any.

        Returns:
            ProviderSettingsWidget: The live widget.
        """

        def _settle(closing: QWidget) -> None:
            """Settle the widget's workers just before it is closed.

            Args:
                closing: The widget about to be closed.
            """
            _settle_widget_workers(qtbot, closing)

        widget = _new_widget(tmp_path, provider_id, registry=registry, discovery=discovery)
        qtbot.addWidget(widget, before_close_func=_settle)
        return widget

    return _make


def test_memory_refresh_is_a_no_op_without_xpu_controls(make_widget: _WidgetFactory) -> None:
    """A page that has no XPU memory controls ignores a memory refresh.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")

    assert not hasattr(widget, "_xpu_mem_bar")
    _call(widget, "_refresh_xpu_memory")

    assert not _control(widget, "_status_label", QLabel).text()


def test_requirements_check_is_a_no_op_without_xpu_controls(make_widget: _WidgetFactory) -> None:
    """A page that has no XPU warnings label ignores the requirements check.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")

    assert not hasattr(widget, "_xpu_warnings_label")
    _call(widget, "_on_check_requirements")

    assert not _control(widget, "_status_label", QLabel).text()


def test_device_info_button_shows_nothing_for_a_non_local_provider(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """Providers other than Local Transformers have no device record to show.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openai")

    _call(widget, "_on_show_device_info")

    assert dialogs.information.calls == []
    assert _call(widget, "get_provider_device_info") is None


def test_dtype_detection_without_a_dtype_combo_still_reports_the_dtype(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """A page without a dtype selector reports the detected dtype in a message.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openai")
    expected = get_optimal_dtype_for_xpu()

    assert not hasattr(widget, "_dtype_combo")
    _call(widget, "_on_detect_xpu_dtype")

    assert _texts(dialogs.information) == [("XPU Dtype", f"Optimal dtype: {expected}")]


def test_key_visibility_toggle_switches_echo_mode_and_button_text(make_widget: _WidgetFactory) -> None:
    """Checking the Show button reveals the key and unchecking it masks the key again.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    key_input = _control(widget, "_api_key_input", QLineEdit)
    show_button = _control(widget, "_show_key_btn", QPushButton)
    assert key_input.echoMode() == QLineEdit.EchoMode.Password

    show_button.setChecked(True)
    assert key_input.echoMode() == QLineEdit.EchoMode.Normal
    assert show_button.text() == "Hide"

    show_button.setChecked(False)
    assert key_input.echoMode() == QLineEdit.EchoMode.Password
    assert show_button.text() == "Show"


def test_model_refresh_without_a_key_asks_for_one(make_widget: _WidgetFactory) -> None:
    """Refreshing models for a provider that needs a key, with none typed, starts no worker.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    refresh_button = _control(widget, "_refresh_models_btn", QPushButton)

    _call(widget, "_refresh_models")

    assert _control(widget, "_status_label", QLabel).text() == "API key required to refresh models"
    assert refresh_button.isEnabled()
    assert _priv(widget, "_refresh_worker") is None


def test_connection_test_without_a_key_asks_for_one(make_widget: _WidgetFactory) -> None:
    """Testing a connection for a provider that needs a key, with none typed, starts no worker.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    test_button = _control(widget, "_test_btn", QPushButton)

    _call(widget, "_test_connection")

    assert _control(widget, "_status_label", QLabel).text() == "API key required"
    assert test_button.isEnabled()
    assert _priv(widget, "_test_worker") is None


def test_refresh_result_for_a_deleted_widget_is_dropped(qtbot: QtBot, tmp_path: Path) -> None:
    """A model list that arrives after the widget is gone is dropped, not applied to deleted controls.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
    """
    widget = _new_widget(tmp_path, "openai")
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    qtbot.waitUntil(lambda: sip.isdeleted(widget), timeout=5_000)

    with capture_logs() as captured:
        _call(widget, "_on_refresh_worker_finished", 1, ["late-model"], "Found 1 models")

    assert "model_refresh_result_dropped" in _event_names(captured)


def test_connection_result_for_a_deleted_widget_is_dropped(qtbot: QtBot, tmp_path: Path) -> None:
    """A connection-test result that arrives after the widget is gone is dropped.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
    """
    widget = _new_widget(tmp_path, "openai")
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    qtbot.waitUntil(lambda: sip.isdeleted(widget), timeout=5_000)

    with capture_logs() as captured:
        _call(widget, "_on_test_worker_finished", 1, "Connected")

    assert "connection_test_result_dropped" in _event_names(captured)


def test_auto_refresh_is_skipped_while_a_refresh_is_running(qtbot: QtBot, make_widget: _WidgetFactory) -> None:
    """A scheduled refresh does not start a second worker while one is blocked on its request.

    Args:
        qtbot: pytest-qt bot.
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    server = StallingServer()
    worker: QThread | None = None
    try:
        _control(widget, "_api_key_input", QLineEdit).setText(_LOOPBACK_KEY)
        _control(widget, "_api_base_input", QLineEdit).setText(f"{server.url}/v1")
        _call(widget, "_refresh_models")
        started: object = _priv(widget, "_refresh_worker")
        assert isinstance(started, QThread)
        worker = started
        qtbot.waitUntil(lambda: server.connections >= 1, timeout=_CONNECT_TIMEOUT_MS)
        assert worker.isRunning()

        with capture_logs() as captured:
            _call(widget, "_auto_refresh_models")

        names = _event_names(captured)
        assert "model_auto_refresh_skipped" in names
        assert "model_auto_refresh_triggered" not in names
        assert _priv(widget, "_refresh_worker") is worker
    finally:
        server.shutdown()
        if worker is not None:
            assert worker.wait(_WORKER_JOIN_MS)


def test_xpu_settings_are_ignored_by_a_page_without_xpu_controls(make_widget: _WidgetFactory) -> None:
    """Restoring XPU settings on a page that has none leaves the page untouched.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")

    _call(widget, "_load_xpu_settings", {"prefer_xpu": False, "device_index": 3, "dtype_override": "float16", "cache_size_mb": 2048})

    for name in ("_prefer_xpu_cb", "_device_combo", "_dtype_combo", "_cache_spin"):
        assert not hasattr(widget, name)


def test_xpu_settings_of_the_wrong_type_are_ignored(make_widget: _WidgetFactory) -> None:
    """Saved XPU values of the wrong type leave the device, dtype and cache controls as they were.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("local_transformers")
    device_combo = _control(widget, "_device_combo", QComboBox)
    dtype_combo = _control(widget, "_dtype_combo", QComboBox)
    cache_spin = _control(widget, "_cache_spin", QSpinBox)
    device_before = device_combo.currentData()
    dtype_before = dtype_combo.currentText()
    cache_before = cache_spin.value()

    _call(widget, "_load_xpu_settings", {"prefer_xpu": False, "device_index": "first", "dtype_override": 16, "cache_size_mb": "large"})

    assert not _control(widget, "_prefer_xpu_cb", QCheckBox).isChecked()
    assert device_combo.currentData() == device_before
    assert dtype_combo.currentText() == dtype_before
    assert cache_spin.value() == cache_before


def test_xpu_settings_naming_unlisted_entries_are_ignored(make_widget: _WidgetFactory) -> None:
    """A saved device index or dtype that the combos do not list leaves their selection unchanged.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("local_transformers")
    device_combo = _control(widget, "_device_combo", QComboBox)
    dtype_combo = _control(widget, "_dtype_combo", QComboBox)
    device_before = device_combo.currentData()
    dtype_before = dtype_combo.currentText()
    assert device_combo.findData(99) == -1
    assert dtype_combo.findText("float8") == -1

    _call(widget, "_load_xpu_settings", {"device_index": 99, "dtype_override": "float8", "cache_size_mb": 4096})

    assert device_combo.currentData() == device_before
    assert dtype_combo.currentText() == dtype_before
    assert _control(widget, "_cache_spin", QSpinBox).value() == 4096


def test_legacy_endpoint_in_providers_json_is_shown_when_env_holds_none(make_widget: _WidgetFactory) -> None:
    """A base URL an earlier release kept only in ``providers.json`` is shown, trimmed, when ``.env`` has none.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")

    shown = _call(widget, "_resolve_saved_endpoint", CredentialField.API_BASE, {"api_base": "  http://legacy.invalid/v1  "})

    assert shown == "http://legacy.invalid/v1"


def test_refreshed_models_restore_the_saved_model(make_widget: _WidgetFactory) -> None:
    """After a refresh the model saved earlier is selected again from the new list.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    combo = _control(widget, "_model_combo", QComboBox)
    _set_priv(widget, "_pending_saved_model", "m2")

    _call(widget, "_on_models_refreshed", success=True, models=["m1", "m2", "m3"], message="Found 3")

    assert [combo.itemText(index) for index in range(combo.count())] == ["m1", "m2", "m3"]
    assert combo.currentText() == "m2"
    assert not _priv(widget, "_pending_saved_model")
    assert _control(widget, "_status_label", QLabel).text() == "Found 3"
    assert _control(widget, "_refresh_models_btn", QPushButton).isEnabled()


def test_refreshed_models_select_the_first_when_nothing_was_saved(make_widget: _WidgetFactory) -> None:
    """With no saved model and an empty entry, the refreshed list starts at its first model.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    combo = _control(widget, "_model_combo", QComboBox)
    combo.setEditText("")
    assert not combo.currentText()

    _call(widget, "_on_models_refreshed", success=True, models=["a", "b"], message="Found 2")

    assert [combo.itemText(index) for index in range(combo.count())] == ["a", "b"]
    assert combo.currentText() == "a"


def test_failed_connection_test_shows_the_message_and_emits_the_signal(make_widget: _WidgetFactory) -> None:
    """A failed connection test shows its message, re-enables the button and emits ``connection_tested``.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    recorder = SignalRecorder()
    widget.connection_tested.connect(recorder)
    test_button = _control(widget, "_test_btn", QPushButton)
    test_button.setEnabled(False)

    _call(widget, "_on_connection_tested", success=False, message="Invalid API key")

    assert _control(widget, "_status_label", QLabel).text() == "Invalid API key"
    assert test_button.isEnabled()
    assert recorder.calls == [(False, "Invalid API key")]


def _write_overrides(tmp_path: Path, overrides: dict[str, dict[str, object]]) -> None:
    """Save per-model overrides in the test's ``providers.json`` for ``openai``.

    Args:
        tmp_path: The test's private directory.
        overrides: Overrides keyed by model identifier.
    """
    ProviderSettingsStore(tmp_path / "providers.json").write_section("openai", {MODEL_OVERRIDES_KEY: overrides})


def test_settings_record_a_context_window_for_the_selected_model(make_widget: _WidgetFactory) -> None:
    """A context window typed for the selected model is saved as that model's override.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    _control(widget, "_model_combo", QComboBox).setEditText("gpt-test")
    _control(widget, "_context_window_spin", QSpinBox).setValue(4096)

    settings = widget.get_settings()

    assert settings["default_model"] == "gpt-test"
    assert settings[MODEL_OVERRIDES_KEY] == {"gpt-test": {"context_window": 4096}}


def test_settings_keep_other_override_fields_when_the_window_is_set_to_auto(tmp_path: Path, make_widget: _WidgetFactory) -> None:
    """Setting the window back to Auto drops only its field and keeps the model's other overrides.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory for settings widgets.
    """
    _write_overrides(
        tmp_path,
        {"gpt-test": {"context_window": 8192, "max_output": 100}, "other": {"context_window": 1}},
    )
    widget = make_widget("openai")
    _control(widget, "_model_combo", QComboBox).setEditText("gpt-test")
    _control(widget, "_context_window_spin", QSpinBox).setValue(0)

    settings = widget.get_settings()

    assert settings[MODEL_OVERRIDES_KEY] == {"gpt-test": {"max_output": 100}, "other": {"context_window": 1}}


def test_settings_drop_an_override_that_becomes_empty(tmp_path: Path, make_widget: _WidgetFactory) -> None:
    """Setting the window to Auto removes a model's override entirely when nothing else is left in it.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory for settings widgets.
    """
    _write_overrides(tmp_path, {"gpt-test": {"context_window": 8192}})
    widget = make_widget("openai")
    _control(widget, "_model_combo", QComboBox).setEditText("gpt-test")
    _control(widget, "_context_window_spin", QSpinBox).setValue(0)

    settings = widget.get_settings()

    assert MODEL_OVERRIDES_KEY not in settings


def test_saving_reports_a_providers_json_that_cannot_be_written(tmp_path: Path, make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """When ``providers.json`` cannot be replaced, saving warns the user with the reason.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    (tmp_path / "providers.json").mkdir()
    widget = make_widget("openai")

    widget.save_settings()

    texts = _texts(dialogs.warning)
    assert [title for title, _ in texts] == ["Save Error"]
    assert texts[0][1].startswith("Failed to save settings: ")


def test_saving_reports_an_env_file_that_cannot_be_updated(tmp_path: Path, make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """When ``.env`` cannot be read, saving warns about the key and about the base URL.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openai")
    (tmp_path / ".env").mkdir()
    base_variable = CredentialLoader.PROVIDER_MAPPINGS["openai"].api_base_var

    widget.save_settings()

    texts = _texts(dialogs.warning)
    assert [title for title, _ in texts] == ["Save Warning", "Save Warning"]
    assert texts[0][1].startswith("Settings saved but failed to update .env file: ")
    assert texts[1][1].startswith(f"Settings saved but failed to update {base_variable} in the .env file: ")


def test_device_info_comes_from_the_registered_provider(make_widget: _WidgetFactory) -> None:
    """The device record is taken from the provider registered under the local transformers id.

    Args:
        make_widget: Factory for settings widgets.
    """
    registry = ProviderRegistry()
    registry.register(_MarkerDeviceProvider())
    widget = make_widget("local_transformers", registry=registry)

    assert widget.get_provider_device_info() == {"device_type": "registry-marker"}


def test_device_info_falls_back_to_a_fresh_provider_when_the_registered_one_fails(make_widget: _WidgetFactory) -> None:
    """A registered provider that cannot describe its device is replaced by a fresh one's record.

    Args:
        make_widget: Factory for settings widgets.
    """
    registry = ProviderRegistry()
    registry.register(_BrokenDeviceProvider())
    widget = make_widget("local_transformers", registry=registry)

    assert widget.get_provider_device_info() == _NO_XPU_DEVICE_INFO


def test_device_info_falls_back_to_a_fresh_provider_when_none_is_registered(make_widget: _WidgetFactory) -> None:
    """With an empty registry the device record comes from a freshly built provider.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("local_transformers", registry=ProviderRegistry())

    assert widget.get_provider_device_info() == _NO_XPU_DEVICE_INFO


def test_generation_lookup_ignores_a_page_without_a_generation_field(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """A page that has no generation ID field does nothing when the lookup is triggered.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openai")

    _call(widget, "_on_lookup_generation")

    assert dialogs.warning.calls == []
    assert dialogs.information.calls == []


def test_generation_lookup_ignores_a_blank_id(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """A blank generation ID starts no lookup and shows no message.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openrouter")
    _control(widget, "_generation_id_input", QLineEdit).setText("   ")

    _call(widget, "_on_lookup_generation")

    assert dialogs.warning.calls == []
    assert dialogs.information.calls == []


def test_generation_lookup_without_a_key_warns_every_time(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """Looking up a generation with no key typed warns once per request, however often it is repeated.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openrouter")
    _control(widget, "_generation_id_input", QLineEdit).setText("gen-1")

    _call(widget, "_on_lookup_generation")
    _call(widget, "_on_lookup_generation")

    assert _texts(dialogs.warning) == [("Lookup Failed", "No OpenRouter API key configured")] * 2


def test_generation_lookup_is_refused_for_another_provider(make_widget: _WidgetFactory) -> None:
    """Asking a non-OpenRouter page for a generation reports that OpenRouter is not selected.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    recorder = SignalRecorder()
    widget.generation_lookup_finished.connect(recorder)

    widget.get_openrouter_generation("gen-9")

    assert recorder.calls == [(False, "gen-9", "OpenRouter provider is not selected")]


def test_generation_found_message_shows_the_cost_lines(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """A found generation is shown with its ID and the formatted cost lines.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openrouter")

    _call(widget, "_on_generation_lookup_finished", _FOUND, "gen-1", "total_cost: 0.5")

    assert _texts(dialogs.information) == [("Generation Cost", "Generation: gen-1\n\ntotal_cost: 0.5")]
    assert dialogs.warning.calls == []


def test_generation_lookup_failure_without_a_reason_names_the_id(make_widget: _WidgetFactory, dialogs: _Dialogs) -> None:
    """A failed lookup that carries no reason is reported with the ID that was not found.

    Args:
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("openrouter")

    _call(widget, "_on_generation_lookup_finished", _NOT_FOUND, "gen-1", "")

    assert _texts(dialogs.warning) == [("Lookup Failed", "No data found for generation ID: gen-1")]
    assert dialogs.information.calls == []


def test_generation_lookup_reports_a_response_that_is_not_an_object(qtbot: QtBot, make_widget: _WidgetFactory) -> None:
    """A generation endpoint that answers with something other than an object is reported as not found.

    Args:
        qtbot: pytest-qt bot.
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openrouter")
    replies = [json_reply({"data": []}), ScriptedReply(chunks=(b"[]",))]
    with ScriptedHttpEndpoint(replies) as endpoint:
        provider_class = _loopback_openrouter(f"{endpoint.base_url}api/v1")
        try:
            with qtbot.waitSignal(widget.generation_lookup_finished, timeout=_SIGNAL_TIMEOUT_MS) as blocker:
                _call(widget, "_fetch_openrouter_generation", provider_class, _LOOPBACK_KEY, "gen-xyz")
        finally:
            drain_bridge_workers()

    assert _signal_args(blocker) == [False, "gen-xyz", "No data found for generation ID: gen-xyz"]
    assert [request.path for request in endpoint.requests] == ["/api/v1/models", "/api/v1/generation?id=gen-xyz"]


def _pull(
    qtbot: QtBot,
    widget: ProviderSettingsWidget,
    endpoint: ScriptedHttpEndpoint,
    model_name: str,
) -> tuple[list[object] | None, SignalRecorder, list[str]]:
    """Pull a model through the widget against a loopback endpoint and wait for the outcome.

    A successful pull schedules a model refresh half a second later, which rewrites the status label, so the label text is captured at
    the moment the pull finishes, after the widget's own handler has run.

    Args:
        qtbot: pytest-qt bot.
        widget: An Ollama settings widget that has finished its own scheduled refresh.
        endpoint: The loopback endpoint that answers the pull.
        model_name: Model to pull.

    Returns:
        tuple[list[object] | None, SignalRecorder, list[str]]: The arguments of ``ollama_pull_finished``, the recorded progress
        emissions, and the status label text seen when the pull finished.
    """
    status_label = _control(widget, "_status_label", QLabel)
    at_finish: list[str] = []

    def _capture(*_args: object) -> None:
        """Record the status label text when the pull finishes.

        Args:
            *_args: Arguments carried by the signal (unused).
        """
        at_finish.append(status_label.text())

    _control(widget, "_api_base_input", QLineEdit).setText(endpoint.base_url)
    progress = SignalRecorder()
    widget.ollama_pull_progress.connect(progress)
    try:
        with qtbot.waitSignal(widget.ollama_pull_finished, timeout=_SIGNAL_TIMEOUT_MS) as blocker:
            widget.pull_ollama_model(model_name)
            widget.ollama_pull_finished.connect(_capture)
        qtbot.wait(_PULL_REFRESH_WAIT_MS)
    finally:
        drain_bridge_workers()
        _settle_widget_workers(qtbot, widget)
    return _signal_args(blocker), progress, at_finish


def _tags_reply() -> ScriptedReply:
    """Build the reply to the connect probe of a healthy local Ollama.

    Returns:
        ScriptedReply: An empty tag listing.
    """
    return json_reply({"models": []})


def test_pull_streams_progress_and_reports_success(
    qtbot: QtBot,
    make_widget: _WidgetFactory,
    dialogs: _Dialogs,
) -> None:
    """A pull forwards every status line as progress and finishes with the last status.

    Args:
        qtbot: pytest-qt bot.
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("ollama")
    _settle_widget_workers(qtbot, widget)
    stream = ScriptedReply(
        chunks=(b'{"status": "pulling manifest"}\n', b'{"status": "success"}\n'),
        content_type="application/x-ndjson",
    )
    with ScriptedHttpEndpoint([_tags_reply(), stream]) as endpoint:
        finished, progress, status_at_finish = _pull(qtbot, widget, endpoint, "tiny-model")

    assert finished == [True, "tiny-model", "success"]
    assert progress.calls == [("tiny-model", "pulling manifest"), ("tiny-model", "success")]
    assert status_at_finish == ["success"]
    assert _texts(dialogs.information) == [("Ollama Pull", "success")]
    assert [(request.method, request.path) for request in endpoint.requests[:2]] == [("GET", "/api/tags"), ("POST", "/api/pull")]
    assert endpoint.requests[1].body == {"name": "tiny-model"}


def test_pull_reports_a_host_that_cannot_be_reached(
    qtbot: QtBot,
    make_widget: _WidgetFactory,
    dialogs: _Dialogs,
) -> None:
    """A host that fails the connect probe ends the pull with a connect failure.

    Args:
        qtbot: pytest-qt bot.
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("ollama")
    _settle_widget_workers(qtbot, widget)
    with ScriptedHttpEndpoint([json_reply({"error": "down"}, status=500)]) as endpoint:
        finished, progress, _ = _pull(qtbot, widget, endpoint, "tiny-model")

    assert finished is not None
    assert finished[:2] == [False, "tiny-model"]
    message = str(finished[2])
    assert message.startswith("Connect failed: ")
    assert "Could not connect to local or cloud Ollama" in message
    assert progress.calls == []
    assert _texts(dialogs.warning) == [("Ollama Pull Failed", message)]
    assert [request.path for request in endpoint.requests] == ["/api/tags"]


def test_pull_reports_a_server_error_during_the_download(
    qtbot: QtBot,
    make_widget: _WidgetFactory,
    dialogs: _Dialogs,
) -> None:
    """A server that fails the pull request ends the pull with that server's error.

    Args:
        qtbot: pytest-qt bot.
        make_widget: Factory for settings widgets.
        dialogs: Recorders over the message boxes.
    """
    widget = make_widget("ollama")
    _settle_widget_workers(qtbot, widget)
    failure = ScriptedReply(chunks=(b'{"error": "disk full"}',), status=500)
    with ScriptedHttpEndpoint([_tags_reply(), failure]) as endpoint:
        finished, progress, _ = _pull(qtbot, widget, endpoint, "tiny-model")

    assert finished is not None
    assert finished[:2] == [False, "tiny-model"]
    message = str(finished[2])
    assert "Ollama server error (HTTP 500)" in message
    assert progress.calls == []
    assert _texts(dialogs.warning) == [("Ollama Pull Failed", message)]


def test_pull_is_ignored_for_a_provider_other_than_ollama(make_widget: _WidgetFactory) -> None:
    """Asking a non-Ollama page to pull a model starts nothing and changes no status.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    finished = SignalRecorder()
    widget.ollama_pull_finished.connect(finished)

    widget.pull_ollama_model("tiny-model")

    assert not _control(widget, "_status_label", QLabel).text()
    assert finished.calls == []


def test_recommendation_is_skipped_inside_a_running_event_loop(make_widget: _WidgetFactory) -> None:
    """Inside a running event loop the recommendation cannot run and yields an empty label text.

    Args:
        make_widget: Factory for settings widgets.
    """
    widget = make_widget("openai")
    discovery = ModelDiscovery(ProviderRegistry())

    async def _inside_loop() -> str:
        """Ask the widget for its recommendation while this loop is running.

        Returns:
            str: What the widget reports.
        """
        await asyncio.sleep(0)
        text: str = _call(widget, "_compute_recommended_model_text", discovery)
        return text

    assert not asyncio.run(_inside_loop())


def test_recommendation_with_an_empty_registry_does_not_fail(make_widget: _WidgetFactory) -> None:
    """A page given a discovery service with nothing to recommend shows an empty label without logging a failure.

    Args:
        make_widget: Factory for settings widgets.
    """
    discovery = ModelDiscovery(ProviderRegistry())

    with capture_logs() as captured:
        widget = make_widget("openai", discovery=discovery)

    assert "recommended_model_update_failed" not in _event_names(captured)
    assert not _control(widget, "_recommended_label", QLabel).text()


@pytest.fixture
def make_dialog(qtbot: QtBot) -> _DialogFactory:
    """Provide a factory for model pickers that are closed when the test ends.

    Args:
        qtbot: pytest-qt bot.

    Returns:
        _DialogFactory: Factory taking the models and the optional selection and discovery service.
    """

    def _make(
        models: list[ModelInfo],
        *,
        current_model: str | None = None,
        discovery: ModelDiscovery | None = None,
    ) -> ModelSelectionDialog:
        """Build one picker and register it for closing.

        Args:
            models: Models to list.
            current_model: Identifier to preselect.
            discovery: Discovery service whose last event is shown.

        Returns:
            ModelSelectionDialog: The picker.
        """
        dialog = ModelSelectionDialog(models, current_model=current_model, provider_name="openai", discovery=discovery)
        qtbot.addWidget(dialog)
        return dialog

    return _make


class _DialogFactory(Protocol):
    """Builds model pickers for one provider named ``openai``."""

    def __call__(
        self,
        models: list[ModelInfo],
        *,
        current_model: str | None = None,
        discovery: ModelDiscovery | None = None,
    ) -> ModelSelectionDialog:
        """Build a picker.

        Args:
            models: Models to list.
            current_model: Identifier to preselect.
            discovery: Discovery service whose last event is shown.

        Returns:
            ModelSelectionDialog: The picker.
        """
        ...


_PICKER_MODELS: list[ModelInfo] = [
    _model_info("m1", "Model One", context_window=4096, tools=False, vision=False),
    _model_info("m2", "Model Two", context_window=128000, tools=True, vision=True),
]


def test_picker_preselects_the_current_model_and_describes_it(make_dialog: _DialogFactory) -> None:
    """The current model is selected on open and its capabilities are listed in the info label.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, current_model="m2")

    assert dialog.get_selected_model() == "m2"
    assert _control(dialog, "_info_label", QLabel).text() == (
        "<b>Model Two</b><br>ID: m2<br>Context: 128,000 tokens<br>Supports tool calling<br>Supports vision"
    )


def test_picker_omits_capabilities_the_model_lacks(make_dialog: _DialogFactory) -> None:
    """A model without tools or vision shows only its name, ID and context window.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, current_model="m1")

    assert _control(dialog, "_info_label", QLabel).text() == "<b>Model One</b><br>ID: m1<br>Context: 4,096 tokens"


def test_picker_ignores_a_selection_change_to_no_row(make_dialog: _DialogFactory) -> None:
    """A selection change to a row that does not exist leaves the info label as it was.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, current_model="m1")
    label = _control(dialog, "_info_label", QLabel)
    before = label.text()
    assert before

    _call(dialog, "_on_model_selected", -1)
    _call(dialog, "_on_model_selected", len(_PICKER_MODELS))

    assert label.text() == before


def test_picker_without_a_selection_accepts_nothing(make_dialog: _DialogFactory) -> None:
    """With no selected row, accepting emits nothing, closes nothing and reports no model.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog([])
    selected = SignalRecorder()
    dialog.model_selected.connect(selected)

    _call(dialog, "_on_accept")

    assert dialog.get_selected_model() is None
    assert selected.calls == []
    assert dialog.result() == QDialog.DialogCode.Rejected.value


def test_picker_accepts_the_selected_model(make_dialog: _DialogFactory) -> None:
    """Accepting emits the selected model's ID and closes the dialog as accepted.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, current_model="m1")
    selected = SignalRecorder()
    dialog.model_selected.connect(selected)

    _call(dialog, "_on_accept")

    assert selected.calls == [("m1",)]
    assert dialog.result() == QDialog.DialogCode.Accepted.value


def test_picker_double_click_accepts_the_clicked_model(make_dialog: _DialogFactory) -> None:
    """Double-clicking a listed model accepts it like pressing OK.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, current_model="m2")
    selected = SignalRecorder()
    dialog.model_selected.connect(selected)
    model_list = _control(dialog, "_model_list", QListWidget)
    item = model_list.item(1)
    assert item is not None

    model_list.itemDoubleClicked.emit(item)

    assert selected.calls == [("m2",)]
    assert dialog.result() == QDialog.DialogCode.Accepted.value


def test_picker_reports_missing_discovery_data(make_dialog: _DialogFactory) -> None:
    """A provider with no recorded discovery event shows that no data is available.

    Args:
        make_dialog: Factory for model pickers.
    """
    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(None))

    assert _control(dialog, "_discovery_status_label", QLabel).text() == "No discovery data available."


def test_picker_summarizes_new_and_removed_models(make_dialog: _DialogFactory) -> None:
    """A successful discovery lists a preview of the new models and of the removed ones.

    Args:
        make_dialog: Factory for model pickers.
    """
    event = _event(success=True, model_count=7, new_models=["a", "b", "c", "d"], removed_models=["x"])

    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(event))

    assert _control(dialog, "_discovery_status_label", QLabel).text() == (
        f"Last discovery: 2026-01-02 03:04:05 {_DASH} 7 models found | New: a, b, c ... | Removed: x"
    )


def test_picker_summarizes_new_models_only(make_dialog: _DialogFactory) -> None:
    """A successful discovery with only new models lists them without an ellipsis or a removed part.

    Args:
        make_dialog: Factory for model pickers.
    """
    event = _event(success=True, model_count=2, new_models=["a", "b"])

    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(event))

    assert (
        _control(dialog, "_discovery_status_label", QLabel).text()
        == f"Last discovery: 2026-01-02 03:04:05 {_DASH} 2 models found | New: a, b"
    )


def test_picker_summarizes_removed_models_only(make_dialog: _DialogFactory) -> None:
    """A successful discovery with only removed models lists them after the count.

    Args:
        make_dialog: Factory for model pickers.
    """
    event = _event(success=True, model_count=1, removed_models=["x", "y"])

    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(event))

    assert _control(dialog, "_discovery_status_label", QLabel).text() == (
        f"Last discovery: 2026-01-02 03:04:05 {_DASH} 1 models found | Removed: x, y"
    )


def test_picker_shows_a_failed_discovery_with_its_reason(make_dialog: _DialogFactory) -> None:
    """A failed discovery is shown with the reason it recorded.

    Args:
        make_dialog: Factory for model pickers.
    """
    event = _event(success=False, error_message="timed out")

    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(event))

    assert _control(dialog, "_discovery_status_label", QLabel).text() == f"Last discovery: 2026-01-02 03:04:05 {_DASH} Failed: timed out"


def test_picker_shows_a_failed_discovery_without_a_reason(make_dialog: _DialogFactory) -> None:
    """A failed discovery that recorded no reason is shown as an unknown error.

    Args:
        make_dialog: Factory for model pickers.
    """
    event = _event(success=False)

    dialog = make_dialog(_PICKER_MODELS, discovery=_discovery_with(event))

    assert (
        _control(dialog, "_discovery_status_label", QLabel).text() == f"Last discovery: 2026-01-02 03:04:05 {_DASH} Failed: Unknown error"
    )
