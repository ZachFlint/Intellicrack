# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider Settings dialog gates: what the dialog shows and saves is what startup uses.

Each gate drives a real :class:`ProviderSettingsWidget` bound to a real
temporary ``.env`` (through a real :class:`CredentialLoader`) and a real
``providers.json``, with model refreshes served by a loopback provider endpoint
server. They fail when:

* the base URL and organization shown or saved by the dialog live only in
  ``providers.json``, which startup never reads, instead of ``.env``;
* clearing a base URL or API key leaves the old value in ``.env``, or fails to
  let the operating-system value apply again;
* a keyless Ollama host or Local Transformers preferences are discarded on save
  because the provider has no API key, or Local Transformers copies the shared
  HuggingFace token under its own name;
* the timeout control applies the old untouched 120-second default, cannot
  select the provider default, or reports a timeout the dialog does not offer;
* a custom base URL with a trailing slash breaks model refresh or the
  connection test;
* the credential source label inspects a different ``.env`` than the one
  credentials are loaded from.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Protocol, cast

import pytest
from PyQt6.QtCore import QCoreApplication, Qt, QThread
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QPushButton, QSpinBox, QWidget

from intellicrack.core.config import get_env_file
from intellicrack.credentials.env_loader import CredentialField, CredentialLoader, EnvPersistAction
from intellicrack.credentials.provider_settings import ProviderSettingsStore
from intellicrack.providers import ids as provider_ids
from intellicrack.ui.provider_config import (
    ConnectionTestWorker,
    CredentialSource,
    CredentialSourceDetector,
    ModelRefreshWorker,
    ProviderSettingsWidget,
)
from tests._helpers.provider_endpoint_server import OLLAMA_TAGS_PATH, OPENAI_COMPATIBLE_MODELS_PATH, ProviderEndpointServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_ACCEPTED_KEY = "loopback-accepted-" + ("k" * 24)
_MODEL_ID = "loopback-model"
_HF_TOKEN = "hf_" + ("t" * 34)
_REFRESH_TIMEOUT_MS = 20_000
_AUTO_REFRESH_SETTLE_MS = 400
_WORKER_JOIN_TIMEOUT_MS = 60_000


class _WidgetFactory(Protocol):
    """Builds settings widgets bound to the test's ``.env`` and ``providers.json``."""

    def __call__(self, provider_id: str, loader: CredentialLoader | None = None) -> ProviderSettingsWidget:
        """Build a settings widget.

        Args:
            provider_id: Provider to configure.
            loader: Credential loader to share with other widgets, as the dialog
                shares one; a fresh loader for the test's ``.env`` when omitted.

        Returns:
            ProviderSettingsWidget: The live widget.
        """
        ...


class _TimeoutControl(Protocol):
    """Timeout-specific interface the dialog's timeout spin box adds to ``QSpinBox``."""

    def set_timeout_seconds(self, seconds: float | None) -> None:
        """Show a saved timeout.

        Args:
            seconds: Timeout in seconds, or ``None`` for the provider default.
        """
        ...

    def timeout_seconds(self) -> int | None:
        """Return the selected timeout.

        Returns:
            int | None: Timeout in seconds, or ``None`` for the provider default.
        """
        ...


@pytest.fixture(autouse=True)
def clean_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every gate from an environment without provider variables.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    isolate_provider_environment(monkeypatch)


@pytest.fixture
def gateway() -> Iterator[ProviderEndpointServer]:
    """Provide a loopback provider endpoint server.

    Yields:
        ProviderEndpointServer: The running server.
    """
    with ProviderEndpointServer(accepted_key=_ACCEPTED_KEY, model_ids=[_MODEL_ID]) as server:
        yield server


def _child[T](widget: ProviderSettingsWidget, name: str, expected_type: type[T]) -> T:
    """Fetch a named child control from the widget with a runtime type check.

    Args:
        widget: The settings widget.
        name: Attribute name of the control.
        expected_type: The control's expected type.

    Returns:
        T: The control.
    """
    control: object = getattr(widget, name)
    assert isinstance(control, expected_type), f"{name} is {type(control).__name__}, expected {expected_type.__name__}"
    return control


def _timeout_control(widget: ProviderSettingsWidget) -> tuple[QSpinBox, _TimeoutControl]:
    """Return the widget's timeout spin box as a Qt widget and as its timeout interface.

    Args:
        widget: The settings widget.

    Returns:
        tuple[QSpinBox, _TimeoutControl]: The same control under both views.
    """
    spin = _child(widget, "_timeout_spin", QSpinBox)
    return spin, cast("_TimeoutControl", spin)


def _settle_widget_workers(widget: QWidget) -> None:
    """Let a closing settings widget's scheduled refresh start, finish and be handled.

    A widget schedules a model refresh shortly after it is built. Run just
    before pytest-qt closes and deletes the widget, this lets that schedule
    elapse, joins every refresh and connection-test thread, and delivers their
    queued results while the widget still exists -- so a gate that fails early
    reports its failure instead of destroying a running ``QThread``, which
    aborts the process.

    Args:
        widget: The settings widget about to be closed.
    """
    QTest.qWait(_AUTO_REFRESH_SETTLE_MS)
    for worker_name in ("_refresh_worker", "_test_worker"):
        worker: object = getattr(widget, worker_name, None)
        if isinstance(worker, QThread):
            assert worker.wait(_WORKER_JOIN_TIMEOUT_MS), f"{worker_name} did not finish"
    QCoreApplication.processEvents()


@pytest.fixture
def make_widget(qtbot: QtBot, tmp_path: Path) -> _WidgetFactory:
    """Provide a factory for settings widgets bound to the test's ``.env`` and ``providers.json``.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.

    Returns:
        _WidgetFactory: Factory taking a provider id and an optional shared loader.
    """

    def _make(provider_id: str, loader: CredentialLoader | None = None) -> ProviderSettingsWidget:
        widget = ProviderSettingsWidget(
            provider_id,
            config_path=tmp_path / "providers.json",
            credential_loader=loader if loader is not None else CredentialLoader(tmp_path / ".env"),
        )
        qtbot.addWidget(widget, before_close_func=_settle_widget_workers)
        return widget

    return _make


def _wait_for_auto_refresh(qtbot: QtBot, widget: ProviderSettingsWidget) -> None:
    """Wait until the widget's scheduled model refresh has run and been handled.

    Args:
        qtbot: pytest-qt bot.
        widget: The settings widget.
    """
    refresh_button = _child(widget, "_refresh_models_btn", QPushButton)

    def _handled() -> bool:
        worker: ModelRefreshWorker | None = getattr(widget, "_refresh_worker", None)
        return worker is not None and worker.isFinished() and refresh_button.isEnabled()

    qtbot.waitUntil(_handled, timeout=_REFRESH_TIMEOUT_MS)


def _wait_for_models(qtbot: QtBot, widget: ProviderSettingsWidget) -> None:
    """Wait until the widget's model list shows the loopback model.

    Args:
        qtbot: pytest-qt bot.
        widget: The settings widget.
    """
    combo = _child(widget, "_model_combo", QComboBox)
    qtbot.waitUntil(lambda: combo.findText(_MODEL_ID) >= 0, timeout=_REFRESH_TIMEOUT_MS)
    _wait_for_auto_refresh(qtbot, widget)


def _read_sections(tmp_path: Path) -> dict[str, dict[str, object]]:
    """Read the saved ``providers.json``.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        dict[str, dict[str, object]]: Saved provider sections.
    """
    decoded: dict[str, dict[str, object]] = json.loads((tmp_path / "providers.json").read_text(encoding="utf-8"))
    return decoded


def _env_names(tmp_path: Path) -> set[str]:
    """Return the variable names assigned in the test's ``.env``.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        set[str]: Assigned variable names.
    """
    env_path = tmp_path / ".env"
    if not env_path.exists():
        return set()
    return {
        line.split("=", 1)[0].strip()
        for line in env_path.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    }


def test_endpoint_fields_load_from_env_and_model_refresh_uses_them(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """The dialog shows the ``.env`` base URL and organization and refreshes through them.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(
        f'OPENAI_API_KEY={_ACCEPTED_KEY}\nOPENAI_API_BASE="{gateway.openai_compatible_base_url}"\nOPENAI_ORGANIZATION=org-env\n',
        encoding="utf-8",
    )

    widget = make_widget("openai")

    assert _child(widget, "_api_base_input", QLineEdit).text() == gateway.openai_compatible_base_url
    assert _child(widget, "_org_id_input", QLineEdit).text() == "org-env"
    _wait_for_models(qtbot, widget)
    assert gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)[-1].headers["authorization"] == f"Bearer {_ACCEPTED_KEY}"


def test_saving_base_url_and_organization_writes_env_not_providers_json(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """Saved endpoint fields land in ``.env``, where the next launch reads them.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(
        f'OPENAI_API_KEY={_ACCEPTED_KEY}\nOPENAI_API_BASE="{gateway.openai_compatible_base_url}"\n',
        encoding="utf-8",
    )
    widget = make_widget("openai")
    _wait_for_models(qtbot, widget)
    gateway_alt = f"{gateway.origin}/alternate/api/v1"

    _child(widget, "_api_base_input", QLineEdit).setText(gateway_alt)
    _child(widget, "_org_id_input", QLineEdit).setText("org-typed")
    widget.save_settings()

    next_launch = CredentialLoader(tmp_path / ".env").get_credentials(provider_ids.OPENAI)
    assert next_launch is not None
    assert next_launch.api_key == _ACCEPTED_KEY
    assert next_launch.api_base == gateway_alt
    assert next_launch.organization_id == "org-typed"
    openai_section = _read_sections(tmp_path)["openai"]
    assert {"api_key", "api_base", "organization_id"}.isdisjoint(openai_section)
    assert openai_section["schema_version"] == 2


def test_clearing_base_url_removes_the_override_and_os_value_applies(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    monkeypatch: pytest.MonkeyPatch,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """A cleared base URL leaves ``.env`` and the operating-system value applies again.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        monkeypatch: Pytest monkeypatch fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    monkeypatch.setenv("OPENAI_API_BASE", gateway.openai_compatible_base_url)
    saved_base = f"{gateway.origin}/saved/api/v1"
    _ = (tmp_path / ".env").write_text(f'OPENAI_API_KEY={_ACCEPTED_KEY}\nOPENAI_API_BASE="{saved_base}"\n', encoding="utf-8")
    widget = make_widget("openai")
    assert _child(widget, "_api_base_input", QLineEdit).text() == saved_base
    _wait_for_auto_refresh(qtbot, widget)

    _child(widget, "_api_base_input", QLineEdit).clear()
    widget.save_settings()

    assert "OPENAI_API_BASE" not in _env_names(tmp_path)
    assert os.environ["OPENAI_API_BASE"] == gateway.openai_compatible_base_url
    reopened = make_widget("openai")
    assert _child(reopened, "_api_base_input", QLineEdit).text() == gateway.openai_compatible_base_url
    _wait_for_models(qtbot, reopened)


def test_keyless_ollama_host_is_saved_without_an_api_key(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """An Ollama host changed without an API key is saved to ``OLLAMA_HOST`` and its section kept.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(f'OLLAMA_HOST="{gateway.ollama_base_url}"\n', encoding="utf-8")
    widget = make_widget("ollama")
    assert _child(widget, "_api_base_input", QLineEdit).text() == gateway.ollama_base_url
    _wait_for_models(qtbot, widget)
    assert gateway.requests(OLLAMA_TAGS_PATH)
    secondary_host = f"{gateway.origin}/ollama-secondary"

    _child(widget, "_api_base_input", QLineEdit).setText(secondary_host)
    widget.save_settings()

    keyless = CredentialLoader(tmp_path / ".env").get_connect_credentials(provider_ids.OLLAMA, api_key_optional=True)
    assert keyless is not None
    assert keyless.api_base == secondary_host
    assert _read_sections(tmp_path)["ollama"]["enabled"] is True


def test_default_ollama_host_clears_the_saved_override(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """Setting the Ollama host back to the default removes ``OLLAMA_HOST`` from ``.env``.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(f'OLLAMA_HOST="{gateway.ollama_base_url}"\n', encoding="utf-8")
    widget = make_widget("ollama")
    _wait_for_models(qtbot, widget)

    _child(widget, "_api_base_input", QLineEdit).setText("http://localhost:11434")
    widget.save_settings()

    assert "OLLAMA_HOST" not in _env_names(tmp_path)


@pytest.mark.parametrize("env_content", ["", f"HUGGINGFACE_API_TOKEN={_HF_TOKEN}\n"], ids=["no-token", "shared-hf-token"])
def test_local_transformers_preferences_survive_save_without_a_credential(
    qtbot: QtBot,
    tmp_path: Path,
    env_content: str,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """Local Transformers keeps its device preferences and never copies the shared token.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        env_content: ``.env`` content; one case holds HuggingFace's token, which
            Local Transformers reads as a fallback.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(env_content, encoding="utf-8")
    widget = make_widget("local_transformers")
    _wait_for_auto_refresh(qtbot, widget)

    _child(widget, "_prefer_xpu_cb", QCheckBox).setChecked(False)
    dtype_combo = _child(widget, "_dtype_combo", QComboBox)
    dtype_combo.setCurrentIndex(dtype_combo.findText("float32"))
    _child(widget, "_cache_spin", QSpinBox).setValue(20480)
    _child(widget, "_enabled_checkbox", QCheckBox).setChecked(False)
    _, timeout = _timeout_control(widget)
    timeout.set_timeout_seconds(45)
    widget.save_settings()

    section = _read_sections(tmp_path)["local_transformers"]
    assert section["prefer_xpu"] is False
    assert section["dtype_override"] == "float32"
    assert section["cache_size_mb"] == 20480
    assert section["enabled"] is False
    assert section["timeout_seconds"] == 45
    assert "LOCAL_TRANSFORMERS_HF_TOKEN" not in _env_names(tmp_path)

    reopened = make_widget("local_transformers")
    _wait_for_auto_refresh(qtbot, reopened)
    assert _child(reopened, "_prefer_xpu_cb", QCheckBox).isChecked() is False
    assert _child(reopened, "_dtype_combo", QComboBox).currentText() == "float32"
    assert _child(reopened, "_cache_spin", QSpinBox).value() == 20480
    assert _child(reopened, "_enabled_checkbox", QCheckBox).isChecked() is False
    _, reopened_timeout = _timeout_control(reopened)
    assert reopened_timeout.timeout_seconds() == 45


def test_cleared_huggingface_token_is_not_resurrected_by_local_transformers(
    qtbot: QtBot,
    tmp_path: Path,
    make_widget: _WidgetFactory,
) -> None:
    """Saving Local Transformers never writes back the HuggingFace token it only borrows.

    The dialog shares one credential loader across providers. Local
    Transformers' hidden key field still holds the HuggingFace token after
    HuggingFace's own field cleared it, so saving Local Transformers must not
    write that stale token under ``LOCAL_TRANSFORMERS_HF_TOKEN``.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(f"HUGGINGFACE_API_TOKEN={_HF_TOKEN}\n", encoding="utf-8")
    shared_loader = CredentialLoader(tmp_path / ".env")
    local_transformers = make_widget("local_transformers", shared_loader)
    _wait_for_auto_refresh(qtbot, local_transformers)

    assert shared_loader.persist_field(provider_ids.HUGGINGFACE, CredentialField.API_KEY, "") is EnvPersistAction.REMOVED
    local_transformers.save_settings()

    assert _env_names(tmp_path).isdisjoint({"HUGGINGFACE_API_TOKEN", "LOCAL_TRANSFORMERS_HF_TOKEN"})
    assert shared_loader.get_field(provider_ids.LOCAL_TRANSFORMERS, CredentialField.API_KEY) is None


def test_clearing_api_key_removes_it_from_env_and_keeps_the_disabled_section(
    qtbot: QtBot,
    tmp_path: Path,
    gateway: ProviderEndpointServer,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """A cleared key leaves ``.env`` while ``enabled=false`` survives for startup.

    Args:
        qtbot: pytest-qt bot.
        tmp_path: Per-test temporary directory.
        gateway: Loopback server fixture.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / ".env").write_text(
        f'OPENAI_API_KEY={_ACCEPTED_KEY}\nOPENAI_API_BASE="{gateway.openai_compatible_base_url}"\n',
        encoding="utf-8",
    )
    widget = make_widget("openai")
    _wait_for_models(qtbot, widget)

    _child(widget, "_api_key_input", QLineEdit).clear()
    _child(widget, "_enabled_checkbox", QCheckBox).setChecked(False)
    widget.save_settings()

    assert "OPENAI_API_KEY" not in _env_names(tmp_path)
    assert CredentialLoader(tmp_path / ".env").get_credentials(provider_ids.OPENAI) is None
    assert _read_sections(tmp_path)["openai"]["enabled"] is False
    assert ProviderSettingsStore(tmp_path / "providers.json").connect_policy().is_enabled(provider_ids.OPENAI) is False


def test_legacy_untouched_timeout_shows_provider_default(
    tmp_path: Path,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """The 120 seconds every earlier save wrote is shown and saved as the provider default.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / "providers.json").write_text(json.dumps({"anthropic": {"enabled": True, "timeout_seconds": 120}}), encoding="utf-8")

    widget = make_widget("anthropic")
    spin, _ = _timeout_control(widget)

    assert spin.value() == 0
    assert spin.text() == "Provider default"
    assert widget.get_settings()["timeout_seconds"] is None
    widget.save_settings()
    assert _read_sections(tmp_path)["anthropic"]["timeout_seconds"] is None


def test_versioned_120_second_timeout_is_kept(
    tmp_path: Path,
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """A deliberately saved 120-second timeout survives a load and save.

    Args:
        tmp_path: Per-test temporary directory.
        make_widget: Factory building settings widgets bound to the test's files.
    """
    _ = (tmp_path / "providers.json").write_text(
        json.dumps({"anthropic": {"enabled": True, "timeout_seconds": 120, "schema_version": 2}}),
        encoding="utf-8",
    )

    widget = make_widget("anthropic")
    widget.save_settings()

    _, timeout = _timeout_control(widget)
    assert timeout.timeout_seconds() == 120
    saved = _read_sections(tmp_path)["anthropic"]
    assert saved["timeout_seconds"] == 120
    assert saved["schema_version"] == 2


def test_timeout_control_steps_between_provider_default_and_real_timeouts(
    make_widget: Callable[[str], ProviderSettingsWidget],
) -> None:
    """Stepping and typing never leave the timeout between the provider default and 10 seconds.

    Args:
        make_widget: Factory building settings widgets bound to the test's files.
    """
    spin, timeout = _timeout_control(make_widget("anthropic"))
    assert timeout.timeout_seconds() is None

    spin.stepBy(1)
    assert spin.value() == 10
    spin.stepBy(-1)
    assert spin.text() == "Provider default"
    spin.stepBy(10)
    assert timeout.timeout_seconds() == 10
    spin.setValue(600)
    spin.stepBy(5)
    assert timeout.timeout_seconds() == 600

    spin.selectAll()
    QTest.keyClicks(spin, "5")
    QTest.keyClick(spin, Qt.Key.Key_Return)
    assert spin.value() == 10
    assert timeout.timeout_seconds() == 10


def test_trailing_slash_base_url_still_refreshes_and_tests_connection(qapp: QApplication, gateway: ProviderEndpointServer) -> None:
    """Refresh and connection test join custom base URLs without producing ``//models``.

    Args:
        qapp: Qt application fixture.
        gateway: Loopback server fixture.
    """
    del qapp
    fetch_openai = cast(
        "Callable[[], tuple[bool, list[str], str]]",
        getattr(ModelRefreshWorker("openai", _ACCEPTED_KEY, f"{gateway.openai_compatible_base_url}/"), "_fetch_models"),
    )
    fetch_ollama = cast(
        "Callable[[], tuple[bool, list[str], str]]",
        getattr(ModelRefreshWorker("ollama", "", f"{gateway.ollama_base_url}/"), "_fetch_models"),
    )
    test_openrouter = cast(
        "Callable[[], tuple[bool, str]]",
        getattr(ConnectionTestWorker("openrouter", _ACCEPTED_KEY, f"{gateway.openai_compatible_base_url}/"), "_test_provider_connection"),
    )

    openai_ok, openai_models, openai_message = fetch_openai()
    ollama_ok, ollama_models, ollama_message = fetch_ollama()
    openrouter_ok, openrouter_message = test_openrouter()

    assert openai_ok, openai_message
    assert _MODEL_ID in openai_models
    assert ollama_ok, ollama_message
    assert _MODEL_ID in ollama_models
    assert openrouter_ok, openrouter_message


def test_credential_source_label_reads_the_env_file_credentials_come_from(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A key from the state-root ``.env`` is labelled ``.env file`` even with a decoy in the working directory.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    working_dir = tmp_path / "working-directory"
    working_dir.mkdir()
    _ = (working_dir / ".env").write_text(f"OPENAI_API_KEY=sk-{'d' * 48}\n", encoding="utf-8")
    monkeypatch.chdir(working_dir)
    anthropic_key = "sk-ant-" + ("a" * 40)

    with redirected_state_root(monkeypatch, tmp_path) as state_root:
        _ = (state_root / ".env").write_text(f"ANTHROPIC_API_KEY={anthropic_key}\n", encoding="utf-8")
        loader = CredentialLoader(get_env_file())
        assert loader.get_field(provider_ids.ANTHROPIC, CredentialField.API_KEY) == anthropic_key

        detector = CredentialSourceDetector(state_root / ".intellicrack" / "providers.json")

        assert detector.detect_source("anthropic", anthropic_key) == CredentialSource.ENV_FILE
