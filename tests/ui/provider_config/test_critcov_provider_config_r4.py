# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fourth-pass coverage for the credential reload log and the recommended-model label of the provider configuration dialog.

Every test drives a real :class:`ProviderConfigDialog` or :class:`ProviderSettingsWidget`. Provider state, ``.env`` and the keyring live in the
test's temporary directory. Doubles are subclasses of real product classes: a discovery service that recommends one fixed model, and a provider
registry whose listing fails with a chosen exception. The credential environment variables are set only after the dialog is built, so no page
starts a model refresh against a real endpoint.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtWidgets import QLabel
from structlog.testing import capture_logs

import intellicrack.credentials.store as store_module
from intellicrack.core.config import get_config_file
from intellicrack.core.types import ModelInfo
from intellicrack.credentials.env_loader import unregister_instance_mapping
from intellicrack.credentials.provider_settings import PROVIDER_SETTINGS_FILENAME
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.panels.async_bridge import drain_bridge_workers
from intellicrack.ui.provider_config import ProviderConfigDialog, ProviderSettingsWidget
from tests._helpers.private_keyring import installed_keyring, private_file_keyring
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any

_OPENAI_KEY: str = "loop" + "back-" + "credential"
_GEMINI_KEY: str = "gem" + "ini-" + "credential"
_RECOMMENDED_TEXT: str = "Recommended: Model Two"
_RECOMMENDATION_FAILED: str = "recommended_model_update_failed"
_FAILURES: tuple[type[Exception], ...] = (RuntimeError, OSError, ValueError)


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


class _UnlistableRegistry(ProviderRegistry):
    """A real registry whose listing of registered providers fails with a chosen exception."""

    def __init__(self, failure: type[Exception]) -> None:
        """Remember which failure to raise.

        Args:
            failure: The exception class raised by every listing.
        """
        super().__init__()
        self._failure = failure

    @override
    def list_registered(self) -> list[str]:
        """Refuse to list the registered providers.

        Returns:
            list[str]: Never returns.

        Raises:
            self._failure: Always, of the class this registry was built with.
        """
        message = "registry listing failed"
        raise self._failure(message)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structured-log entries by event name.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The entries logged under that event.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _label_text(widget: ProviderSettingsWidget) -> str:
    """Read the text of the page's recommended-model label.

    Args:
        widget: The provider settings page.

    Returns:
        str: The label's current text.
    """
    label: object = _priv(widget, "_recommended_label")
    assert isinstance(label, QLabel)
    return label.text()


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
    store_holder: _Dynamic = getattr(store_module, "_store_holder")
    with (
        redirected_state_root(monkeypatch, tmp_path) as root,
        installed_keyring(private_file_keyring(tmp_path / "keyring.cfg")),
    ):
        store_holder.instance = None
        try:
            yield root
        finally:
            store_holder.instance = None
            unregister_instance_mapping("bare-gw")
            _ = drain_bridge_workers()


@pytest.fixture
def build_dialog() -> Generator[Callable[..., ProviderConfigDialog]]:
    """Build provider dialogs and tear them down without leaving a worker or timer behind.

    Yields:
        Callable[..., ProviderConfigDialog]: Factory taking no arguments.
    """
    created: list[ProviderConfigDialog] = []

    def _build() -> ProviderConfigDialog:
        """Construct and track a dialog.

        Returns:
            ProviderConfigDialog: The dialog.
        """
        dialog = ProviderConfigDialog()
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
def build_widget() -> Generator[Callable[..., ProviderSettingsWidget]]:
    """Build keyless provider settings pages and tear them down without leaving a worker behind.

    Yields:
        Callable[..., ProviderSettingsWidget]: Factory taking the provider id and the discovery service.
    """
    created: list[ProviderSettingsWidget] = []

    def _build(provider_id: str, discovery: ModelDiscovery) -> ProviderSettingsWidget:
        """Construct and track a settings page.

        Args:
            provider_id: Id of the provider the page configures.
            discovery: Model discovery service handed to the page.

        Returns:
            ProviderSettingsWidget: The page.
        """
        widget = ProviderSettingsWidget(provider_id, None, get_config_file(PROVIDER_SETTINGS_FILENAME), None, discovery)
        created.append(widget)
        return widget

    try:
        yield _build
    finally:
        _ = drain_bridge_workers()
        for widget in created:
            if not sip.isdeleted(widget):
                sip.delete(widget)


def test_reload_logs_a_provider_configured_through_an_alias_variable_as_refreshed(
    build_dialog: Callable[..., ProviderConfigDialog],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every provider the loader reports as configured is logged as refreshed, including one whose key arrives through an alias variable.

    OpenAI is configured through its own key variable. Google is configured only through its ``GEMINI_API_KEY`` alias, so the loader reports
    it as configured while the variable named by its mapping (``GOOGLE_API_KEY``) holds no value.

    This test is red until the suspected defect is fixed: the reload asks only for the mapping's primary key variable, so a provider
    configured through an alias is never logged as refreshed. It still runs the ``env_var is None`` branch of the reload loop.

    Args:
        build_dialog: Factory for provider dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """
    dialog = build_dialog()
    monkeypatch.setenv("OPENAI_API_KEY", _OPENAI_KEY)
    monkeypatch.setenv("GEMINI_API_KEY", _GEMINI_KEY)

    with capture_logs() as captured:
        dialog.refresh_credentials()
        _ = drain_bridge_workers()

    overview = cast("dict[str, list[str]]", _priv(dialog, "_credential_overview"))
    assert sorted(overview["configured"]) == ["google", "openai"]
    assert sorted(str(entry["provider"]) for entry in _events(captured, "credential_refreshed")) == ["google", "openai"]
    [summary] = _events(captured, "credentials_reloaded")
    assert summary["configured"] == 2


@pytest.mark.parametrize("failure", _FAILURES, ids=lambda failure: failure.__name__)
def test_a_failing_recommendation_is_logged_and_leaves_the_label_empty(
    build_widget: Callable[..., ProviderSettingsWidget],
    failure: type[Exception],
) -> None:
    """A discovery service that fails while the page is built is logged against the provider and the page shows no recommendation.

    Args:
        build_widget: Factory for provider settings pages.
        failure: The exception the registry raises when discovery lists it.
    """
    discovery = ModelDiscovery(_UnlistableRegistry(failure))

    with capture_logs() as captured:
        widget = build_widget("openai", discovery)

    [event] = _events(captured, _RECOMMENDATION_FAILED)
    assert event["provider"] == "openai"
    assert not _label_text(widget)


@pytest.mark.parametrize("failure", _FAILURES, ids=lambda failure: failure.__name__)
def test_a_failing_recommendation_clears_the_recommendation_shown_before(
    build_widget: Callable[..., ProviderSettingsWidget],
    failure: type[Exception],
) -> None:
    """When a later update fails, the page withdraws the recommendation it showed earlier instead of keeping stale text.

    The page is built with a discovery service that recommends a model, then its private discovery attribute is pointed at a service whose
    registry cannot be listed, which is the state a page reaches when the registry breaks after the first update.

    Args:
        build_widget: Factory for provider settings pages.
        failure: The exception the registry raises when discovery lists it.
    """
    widget = build_widget("openai", _RecommendingDiscovery(ProviderRegistry()))
    assert _label_text(widget) == _RECOMMENDED_TEXT
    setattr(widget, "_discovery", ModelDiscovery(_UnlistableRegistry(failure)))

    with capture_logs() as captured:
        _priv(widget, "_update_recommended_model")()

    [event] = _events(captured, _RECOMMENDATION_FAILED)
    assert event["provider"] == "openai"
    assert not _label_text(widget)
