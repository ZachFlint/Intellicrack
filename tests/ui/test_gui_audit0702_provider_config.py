# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``provider_config``.

Each test targets one audit finding for
:mod:`intellicrack.ui.provider_config` and fails against the pre-fix
behaviour:

* ``test_c3_*``: the OAuth login flow must dispatch onto the async bridge
  (``run_bridge_coroutine_async``) instead of blocking the GUI thread on
  ``run_bridge_coroutine`` for the human-timescale browser wait, and the
  obtained credentials must reach the provider widget through the async
  ``on_success`` callback.
* ``test_h14_*``: credential-store enumeration, at both dialog construction
  and on "Reload Keys", must dispatch via the async bridge, never the
  blocking runner.
* ``test_h15_*``: "Migrate" must dispatch the env-to-store migration via the
  async bridge and reload the credential overview from the success callback.
* ``test_h16_*``: "Discover" must dispatch model discovery via the async
  bridge and must refresh provider status only once discovery actually
  completes, not immediately after dispatch.
* ``test_h17_*``: "Revoke Token" must dispatch the OAuth revoke call via the
  async bridge and reload the credential overview from the success callback.
* ``test_m14_*``: the OpenRouter generation cost lookup must dispatch via the
  async bridge and deliver its outcome through the
  ``generation_lookup_finished`` signal.
* ``test_l18_*``: the provider-list splitter panel must not be collapsible to
  zero width and its left panel must carry a nonzero minimum width.

All tests drive real :class:`~intellicrack.ui.provider_config.ProviderConfigDialog`
and :class:`~intellicrack.ui.provider_config.ProviderSettingsWidget` instances
under an offscreen ``QApplication``. The blocking/async bridge runners are
replaced with small recording or coroutine-driving stand-ins (never
``unittest.mock``) so the real production closures execute and their
observable side effects can be asserted directly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QSplitter

import intellicrack.ui.provider_config as provider_config_module
from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.oauth import OAuthProvider
from intellicrack.ui.provider_config import ProviderConfigDialog, ProviderSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path

    from intellicrack.credentials.oauth import OAuthConfig
    from intellicrack.providers.discovery import ModelDiscovery


class _RecordedDispatch:
    """One recorded ``run_bridge_coroutine_async`` invocation."""

    def __init__(self, coro: object, on_success: object, on_error: object) -> None:
        """Store one recorded ``run_bridge_coroutine_async`` invocation.

        Args:
            coro: The coroutine object that was dispatched.
            on_success: The success callback that was passed, if any.
            on_error: The error callback that was passed, if any.
        """
        self.coro = coro
        self.on_success = on_success
        self.on_error = on_error


def _make_recording_async_dispatcher(sink: list[_RecordedDispatch]) -> Callable[..., None]:
    """Build a ``run_bridge_coroutine_async`` stand-in that records without executing.

    The coroutine is closed immediately (never awaited) so the call site's
    downstream network/browser/keyring work never actually runs, keeping the
    dispatch-site gate deterministic and free of real I/O.

    Args:
        sink: List that receives one :class:`_RecordedDispatch` per call.

    Returns:
        Callable[..., None]: A stand-in matching ``run_bridge_coroutine_async``.
    """

    def _dispatch(
        coro: Coroutine[object, object, object],
        on_success: object = None,
        on_error: object = None,
        parent: object = None,
        **_kwargs: object,
    ) -> None:
        """Record the dispatch and close the coroutine without awaiting it.

        Args:
            coro: Bridge coroutine that would run on the worker.
            on_success: Success callback (recorded, not invoked).
            on_error: Error callback (recorded, not invoked).
            parent: Qt parent (unused here).
            **_kwargs: Remaining wrapper keyword arguments (ignored).
        """
        del parent
        sink.append(_RecordedDispatch(coro, on_success, on_error))
        coro.close()

    return _dispatch


def _make_recording_blocking_runner(sink: list[object]) -> Callable[..., object]:
    """Build a ``run_bridge_coroutine`` stand-in that records any (forbidden) call.

    Args:
        sink: List that receives a marker for every invocation.

    Returns:
        Callable[..., object]: A stand-in matching ``run_bridge_coroutine``.
    """

    def _blocking(*args: object, **kwargs: object) -> object:
        """Record a blocking-runner invocation and return ``None``.

        Args:
            *args: Positional arguments (ignored).
            **kwargs: Keyword arguments (ignored).

        Returns:
            object: Always ``None``.
        """
        sink.append((args, kwargs))
        return None

    return _blocking


def _drive_to_success(
    coro: Coroutine[object, object, object],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Run a bridge coroutine to completion in-thread and invoke ``on_success``.

    Mirrors what ``BridgeCallWorker`` does on a background thread, but
    synchronously, so tests can observe the real ``on_success`` closure's
    side effects deterministically.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Success callback invoked with the coroutine's result.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (ignored).
    """
    del parent, on_error
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    finally:
        loop.close()
    if on_success is not None:
        cast("Callable[[object], None]", on_success)(result)


def _drive_to_error(
    coro: Coroutine[object, object, object],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Run a bridge coroutine expected to raise ``RuntimeError`` and invoke ``on_error``.

    Args:
        coro: Coroutine produced by the bridge call, expected to raise.
        on_success: Unused success callback.
        on_error: Error callback invoked with the raised exception.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (ignored).
    """
    del parent, on_success
    loop = asyncio.new_event_loop()
    try:
        try:
            loop.run_until_complete(coro)
        except RuntimeError as exc:
            if on_error is not None:
                cast("Callable[[object], None]", on_error)(exc)
    finally:
        loop.close()


def _make_dialog(
    monkeypatch: pytest.MonkeyPatch,
    dispatch_sink: list[_RecordedDispatch],
    blocking_sink: list[object],
    *,
    model_discovery: ModelDiscovery | None = None,
) -> ProviderConfigDialog:
    """Construct a ``ProviderConfigDialog`` with both bridge runners patched for observation.

    Args:
        monkeypatch: Fixture used to patch the module-level bridge runners.
        dispatch_sink: List that receives every ``run_bridge_coroutine_async`` call.
        blocking_sink: List that receives every ``run_bridge_coroutine`` call.
        model_discovery: Optional discovery stand-in to inject.

    Returns:
        ProviderConfigDialog: A fully constructed dialog.
    """
    monkeypatch.setattr(
        provider_config_module,
        "run_bridge_coroutine_async",
        _make_recording_async_dispatcher(dispatch_sink),
    )
    monkeypatch.setattr(
        provider_config_module,
        "run_bridge_coroutine",
        _make_recording_blocking_runner(blocking_sink),
    )
    return ProviderConfigDialog(model_discovery=model_discovery)


class _FakeOAuthManager:
    """Stand-in OAuth manager whose async methods avoid any real browser/network I/O."""

    def __init__(self, credentials: ProviderCredentials | None) -> None:
        """Initialise the fake manager with the credentials it will hand back.

        Args:
            credentials: Credentials returned by ``to_provider_credentials``.
        """
        self._credentials = credentials
        self.authorize_calls: list[OAuthConfig] = []
        self.revoke_calls: list[OAuthProvider] = []

    async def run_authorization_flow(self, oauth_config: OAuthConfig) -> None:
        """Record an authorization-flow invocation without opening a browser.

        Args:
            oauth_config: The provider's OAuth configuration.
        """
        self.authorize_calls.append(oauth_config)

    async def to_provider_credentials(self, oauth_provider: OAuthProvider) -> ProviderCredentials | None:
        """Return the configured stand-in credentials.

        Args:
            oauth_provider: The OAuth provider being converted (unused here).

        Returns:
            ProviderCredentials | None: The credentials configured at construction.
        """
        del oauth_provider
        return self._credentials

    async def revoke_token(self, oauth_provider: OAuthProvider) -> None:
        """Record a revoke-token invocation without a real network call.

        Args:
            oauth_provider: The OAuth provider whose token is being revoked.
        """
        self.revoke_calls.append(oauth_provider)


class _FakeModelDiscovery:
    """Stand-in model-discovery service exposing only what ``provider_config`` calls."""

    def __init__(self) -> None:
        """Initialise the fake discovery service with an empty call log."""
        self.discover_calls: list[ProviderName] = []

    async def discover_provider(self, provider_name: ProviderName) -> None:
        """Record a discovery invocation without a real network round-trip.

        Args:
            provider_name: The provider whose models would be discovered.
        """
        self.discover_calls.append(provider_name)

    @staticmethod
    def get_discovery_events() -> list[object]:
        """Return an empty discovery-event log.

        Returns:
            list[object]: Always empty.
        """
        return []

    @staticmethod
    async def get_recommended_model(task_type: str) -> None:
        """Report no recommended model without a real discovery round-trip.

        Args:
            task_type: Task type (or provider identifier) the recommendation
                would be resolved for; ignored because the fake never
                recommends a model, so the recommended-model label stays empty.
        """
        del task_type


class _FakeCredentialStore:
    """Stand-in credential store whose ``migrate_from_env`` avoids real keyring I/O."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Accept and discard any constructor arguments.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.
        """
        del args, kwargs

    async def migrate_from_env(
        self,
        providers: list[ProviderName] | None = None,
        *,
        overwrite: bool = False,
    ) -> dict[ProviderName, bool]:
        """Report an empty migration result without touching the keyring.

        Args:
            providers: Ignored provider filter.
            overwrite: Ignored overwrite flag.

        Returns:
            dict[ProviderName, bool]: Always empty.
        """
        del providers, overwrite
        return {}


class _FakeOpenRouterProvider:
    """Stand-in ``OpenRouterProvider`` whose async methods avoid a real network round-trip."""

    def __init__(self) -> None:
        """Initialise the fake provider with no connection recorded yet."""
        self.connected_creds: ProviderCredentials | None = None
        self.disconnected = False

    async def connect(self, creds: ProviderCredentials) -> None:
        """Record the credentials a caller connected with.

        Args:
            creds: Credentials passed to ``connect``.
        """
        self.connected_creds = creds

    @staticmethod
    async def get_generation(generation_id: str) -> dict[str, Any] | None:
        """Return a deterministic generation-cost payload.

        Args:
            generation_id: The generation ID that was looked up.

        Returns:
            dict[str, Any] | None: A fixed cost payload echoing the ID.
        """
        return {"id": generation_id, "cost": "0.0021"}

    async def disconnect(self) -> None:
        """Record that the fake provider was disconnected."""
        self.disconnected = True


class _FakeFailingOpenRouterProvider(_FakeOpenRouterProvider):
    """Stand-in provider whose ``get_generation`` raises to exercise the error path."""

    @staticmethod
    async def get_generation(generation_id: str) -> dict[str, Any] | None:
        """Raise to simulate a failed generation lookup.

        Args:
            generation_id: The generation ID that was looked up.

        Returns:
            dict[str, Any] | None: Never returns.

        Raises:
            RuntimeError: Always, simulating an API failure.
        """
        del generation_id
        msg = "generation not found"
        raise RuntimeError(msg)


@pytest.mark.usefixtures("qapp")
class TestC3OAuthLoginAsyncDispatch:
    """C3: OAuth login must dispatch via the async bridge, never the blocking one."""

    @staticmethod
    def test_oauth_login_dispatches_via_async_bridge_not_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
        """``start_oauth_flow`` must call ``run_bridge_coroutine_async``, never ``run_bridge_coroutine``.

        Pre-fix, ``_run_oauth_flow`` called
        ``creds = run_bridge_coroutine(_run_oauth())`` directly with no
        timeout, blocking the GUI thread for the human-timescale browser
        wait. Against that code, triggering the OAuth flow would record a
        blocking-runner call and zero async-dispatcher calls, failing both
        assertions below.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            dispatches.clear()
            blocking_calls.clear()

            dialog.start_oauth_flow("google")

            assert not blocking_calls, "OAuth login must never call the blocking run_bridge_coroutine runner"
            assert len(dispatches) == 1, "OAuth login must dispatch exactly one coroutine onto the async bridge"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_oauth_success_updates_widget_api_key_through_the_async_callback(monkeypatch: pytest.MonkeyPatch) -> None:
        """A successful OAuth flow must deliver credentials via the async ``on_success`` callback.

        Drives the real ``_run_oauth_flow`` closures end to end (with a fake
        OAuth manager standing in for the browser/network round-trip) and
        asserts the provider widget's API key field is actually populated,
        and that the credential overview is reloaded afterwards.

        Args:
            monkeypatch: Fixture used to patch the bridge runner, OAuth
                manager, and credential-overview reload.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            fake_manager = _FakeOAuthManager(ProviderCredentials(api_key="oauth-secret-token"))
            monkeypatch.setattr(provider_config_module, "get_oauth_manager", lambda: fake_manager)
            monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _drive_to_success)

            reloads: list[None] = []
            monkeypatch.setattr(dialog, "_load_credential_overview", lambda: reloads.append(None))

            widget = dialog._provider_widgets["google"]
            assert not widget._api_key_input.text()

            dialog.start_oauth_flow("google")

            assert widget._api_key_input.text() == "oauth-secret-token", (
                "OAuth success callback did not deliver the obtained credentials to the provider widget"
            )
            assert fake_manager.authorize_calls, "the authorization flow was never awaited"
            assert reloads, "a successful OAuth flow must reload the credential overview"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestH14CredentialStoreEnumerationAsync:
    """H14: credential-store enumeration at construction and on Reload Keys must be async."""

    @staticmethod
    def test_dialog_construction_loads_credential_store_via_async_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """Constructing the dialog must dispatch the store load via ``run_bridge_coroutine_async``.

        Pre-fix, ``ProviderConfigDialog.__init__`` called
        ``run_bridge_coroutine(_load_store_credentials())`` before the dialog
        was even shown, blocking construction on the OS keyring. Against
        that code this test fails: the blocking sink receives a call and the
        async-dispatch sink stays empty.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            assert not blocking_calls, "dialog construction must never call the blocking bridge runner"
            assert dispatches, "dialog construction did not dispatch credential-store enumeration onto the async bridge"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_reload_keys_dispatches_credential_store_load_via_async_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
        """``refresh_credentials`` (the "Reload Keys" button) must dispatch via the async bridge.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            dispatches.clear()
            blocking_calls.clear()

            dialog.refresh_credentials()

            assert not blocking_calls, "Reload Keys must never call the blocking bridge runner"
            assert dispatches, "Reload Keys did not dispatch credential-store enumeration onto the async bridge"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestH15MigrateCredentialsAsync:
    """H15: "Migrate" must dispatch the env-to-store migration via the async bridge."""

    @staticmethod
    def test_migrate_dispatches_via_async_bridge_not_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
        """``migrate_credentials`` must call ``run_bridge_coroutine_async``, never the blocking runner.

        Pre-fix, ``migrate_credentials`` called
        ``run_bridge_coroutine(store.migrate_from_env())`` synchronously.
        Against that code the blocking sink receives a call and the async
        sink stays empty.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            dispatches.clear()
            blocking_calls.clear()

            dialog.migrate_credentials()

            assert not blocking_calls, "Migrate must never call the blocking bridge runner"
            assert len(dispatches) == 1, "Migrate must dispatch exactly one coroutine onto the async bridge"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_migrate_success_reloads_credential_overview_via_callback(monkeypatch: pytest.MonkeyPatch) -> None:
        """A successful migration must reload the credential overview from the ``on_success`` callback.

        Drives the real ``migrate_credentials`` closures to completion with a
        fake credential store (no real keyring I/O) and asserts the
        credential overview reload actually fires.

        Args:
            monkeypatch: Fixture used to patch the bridge runner, credential
                store class, and credential-overview reload.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            reloads: list[None] = []
            monkeypatch.setattr(dialog, "_load_credential_overview", lambda: reloads.append(None))
            monkeypatch.setattr(provider_config_module, "CredentialStore", _FakeCredentialStore)
            monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _drive_to_success)

            dialog.migrate_credentials()

            assert reloads, "a successful migration must reload the credential overview"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestH16ModelDiscoveryAsync:
    """H16: model discovery for the selected provider must dispatch via the async bridge."""

    @staticmethod
    def test_discover_dispatches_via_async_bridge_not_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
        """``_on_discover_selected_provider`` must dispatch via ``run_bridge_coroutine_async``.

        Pre-fix, ``discover_single_provider`` called
        ``run_bridge_coroutine(_discover())`` synchronously, blocking the GUI
        thread on the network round-trip. Against that code the blocking
        sink receives a call and the async sink stays empty.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        fake_discovery = _FakeModelDiscovery()
        dialog = _make_dialog(
            monkeypatch,
            dispatches,
            blocking_calls,
            model_discovery=cast("ModelDiscovery", fake_discovery),
        )
        try:
            dialog._current_provider = "openai"
            dispatches.clear()
            blocking_calls.clear()

            dialog._on_discover_selected_provider()

            assert not blocking_calls, "Discover must never call the blocking bridge runner"
            assert len(dispatches) == 1, "Discover must dispatch exactly one coroutine onto the async bridge"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_discover_does_not_refresh_status_until_discovery_completes(monkeypatch: pytest.MonkeyPatch) -> None:
        """Provider status must refresh only once the dispatched discovery coroutine completes.

        Regression: pre-fix, ``_on_discover_selected_provider`` called
        ``self._refresh_provider_status()`` immediately after
        ``discover_single_provider(...)`` returned, before the (now async)
        discovery had actually run. Against that code this test fails at the
        first assertion: ``_refresh_provider_status`` is invoked before the
        dispatched coroutine's success callback ever fires.

        Args:
            monkeypatch: Fixture used to patch the bridge runners and spy on
                ``_refresh_provider_status``.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        fake_discovery = _FakeModelDiscovery()
        dialog = _make_dialog(
            monkeypatch,
            dispatches,
            blocking_calls,
            model_discovery=cast("ModelDiscovery", fake_discovery),
        )
        try:
            dialog._current_provider = "openai"
            dispatches.clear()

            refresh_calls: list[None] = []
            monkeypatch.setattr(dialog, "_refresh_provider_status", lambda: refresh_calls.append(None))

            dialog._on_discover_selected_provider()

            assert not refresh_calls, "provider status was refreshed before the dispatched discovery coroutine completed"
            assert len(dispatches) == 1
            pending = dispatches[0]

            assert pending.on_success is not None
            cast("Callable[[object], None]", pending.on_success)(None)

            assert refresh_calls == [None], "provider status was not refreshed once discovery completed"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestH17RevokeTokenAsync:
    """H17: "Revoke Token" must dispatch the OAuth revoke call via the async bridge."""

    @staticmethod
    def test_revoke_dispatches_via_async_bridge_not_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
        """``revoke_oauth_token`` must call ``run_bridge_coroutine_async``, never the blocking runner.

        Pre-fix, ``_do_revoke_oauth_token`` called
        ``run_bridge_coroutine(manager.revoke_token(oauth_provider))``
        synchronously. Against that code the blocking sink receives a call
        and the async sink stays empty.

        Args:
            monkeypatch: Fixture used to patch the bridge runners.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            dispatches.clear()
            blocking_calls.clear()

            dialog.revoke_oauth_token("anthropic")

            assert not blocking_calls, "Revoke Token must never call the blocking bridge runner"
            assert len(dispatches) == 1, "Revoke Token must dispatch exactly one coroutine onto the async bridge"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_revoke_success_reloads_credential_overview_via_callback(monkeypatch: pytest.MonkeyPatch) -> None:
        """A successful revoke must reload the credential overview from the ``on_success`` callback.

        Drives the real revoke closures to completion with a fake OAuth
        manager (no real network call) and asserts both the revoke actually
        reached the manager and the overview reload fires afterwards.

        Args:
            monkeypatch: Fixture used to patch the bridge runner, OAuth
                manager, and credential-overview reload.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            reloads: list[None] = []
            monkeypatch.setattr(dialog, "_load_credential_overview", lambda: reloads.append(None))
            fake_manager = _FakeOAuthManager(None)
            monkeypatch.setattr(provider_config_module, "get_oauth_manager", lambda: fake_manager)
            monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _drive_to_success)

            dialog.revoke_oauth_token("anthropic")

            assert fake_manager.revoke_calls == [OAuthProvider.ANTHROPIC], "the revoke call never reached the OAuth manager"
            assert reloads, "a successful revoke must reload the credential overview"
        finally:
            dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM14OpenRouterGenerationLookupAsync:
    """M14: OpenRouter generation cost lookup must dispatch via the async bridge."""

    @staticmethod
    def test_lookup_dispatches_via_async_bridge_not_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``get_openrouter_generation`` must call ``run_bridge_coroutine_async``, never the blocking runner.

        Pre-fix, ``_fetch_openrouter_generation`` returned
        ``run_bridge_coroutine(_fetch())`` directly, blocking the GUI thread
        on the OpenRouter network round-trip. Against that code the blocking
        sink receives a call and the async sink stays empty.

        Args:
            tmp_path: Per-test temporary directory for the isolated config path.
            monkeypatch: Fixture used to patch the bridge runners and the
                OpenRouter provider class.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        monkeypatch.setattr(
            provider_config_module,
            "run_bridge_coroutine_async",
            _make_recording_async_dispatcher(dispatches),
        )
        monkeypatch.setattr(
            provider_config_module,
            "run_bridge_coroutine",
            _make_recording_blocking_runner(blocking_calls),
        )
        monkeypatch.setattr(provider_config_module, "OpenRouterProvider", _FakeOpenRouterProvider)

        widget = ProviderSettingsWidget("openrouter", config_path=tmp_path / "providers.json")
        try:
            widget._api_key_input.setText("sk-or-test-key")

            widget.get_openrouter_generation("gen-123")

            assert not blocking_calls, "generation cost lookup must never call the blocking bridge runner"
            assert len(dispatches) == 1, "generation cost lookup must dispatch exactly one coroutine onto the async bridge"
        finally:
            widget.deleteLater()

    @staticmethod
    def test_lookup_success_emits_generation_lookup_finished_with_formatted_cost(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful lookup must emit ``generation_lookup_finished`` with the real formatted cost.

        Args:
            tmp_path: Per-test temporary directory for the isolated config path.
            monkeypatch: Fixture used to patch the bridge runner and the
                OpenRouter provider class.
        """
        monkeypatch.setattr(provider_config_module, "OpenRouterProvider", _FakeOpenRouterProvider)
        monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _drive_to_success)

        widget = ProviderSettingsWidget("openrouter", config_path=tmp_path / "providers.json")
        try:
            widget._api_key_input.setText("sk-or-test-key")

            emitted: list[tuple[object, str, str]] = []
            widget.generation_lookup_finished.connect(lambda s, g, m: emitted.append((s, g, m)))

            widget.get_openrouter_generation("gen-123")

            assert len(emitted) == 1
            success, generation_id, message = emitted[0]
            assert bool(success) is True, "a found generation must report success"
            assert generation_id == "gen-123"
            assert "cost: 0.0021" in message, f"formatted cost line missing from message: {message!r}"
        finally:
            widget.deleteLater()

    @staticmethod
    def test_lookup_failure_emits_generation_lookup_finished_with_failure_message(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed lookup must emit ``generation_lookup_finished`` with a failure message, not raise.

        Args:
            tmp_path: Per-test temporary directory for the isolated config path.
            monkeypatch: Fixture used to patch the bridge runner and the
                OpenRouter provider class.
        """
        monkeypatch.setattr(provider_config_module, "OpenRouterProvider", _FakeFailingOpenRouterProvider)
        monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _drive_to_error)

        widget = ProviderSettingsWidget("openrouter", config_path=tmp_path / "providers.json")
        try:
            widget._api_key_input.setText("sk-or-test-key")

            emitted: list[tuple[object, str, str]] = []
            widget.generation_lookup_finished.connect(lambda s, g, m: emitted.append((s, g, m)))

            widget.get_openrouter_generation("gen-404")

            assert len(emitted) == 1
            success, generation_id, message = emitted[0]
            assert bool(success) is False, "a failed lookup must report failure"
            assert generation_id == "gen-404"
            assert "gen-404" in message
        finally:
            widget.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestL18ProviderListSplitterNotCollapsible:
    """L18: the provider-list splitter panel must not collapse to zero width."""

    @staticmethod
    def test_splitter_children_are_not_collapsible(monkeypatch: pytest.MonkeyPatch) -> None:
        """The dialog's splitter must forbid collapsing a pane to zero.

        Pre-fix, ``setChildrenCollapsible(False)`` was never called, so the
        default ``QSplitter`` behaviour (``childrenCollapsible() is True``)
        applied and this assertion fails against that code.

        Args:
            monkeypatch: Fixture used to patch the bridge runners for a
                lightweight dialog construction.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            splitters = dialog.findChildren(QSplitter)
            assert len(splitters) == 1, "expected exactly one provider-list splitter"
            assert splitters[0].childrenCollapsible() is False, "the provider-list splitter allows a pane to be dragged to zero width"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_left_panel_has_the_configured_minimum_width(monkeypatch: pytest.MonkeyPatch) -> None:
        """The splitter's left (provider-list) panel must carry a nonzero minimum width.

        Pre-fix, only the inner ``QListWidget`` had a minimum width; the
        containing ``left_panel`` itself had none, so
        ``left_panel.minimumWidth()`` was ``0`` and this assertion fails
        against that code.

        Args:
            monkeypatch: Fixture used to patch the bridge runners for a
                lightweight dialog construction.
        """
        dispatches: list[_RecordedDispatch] = []
        blocking_calls: list[object] = []
        dialog = _make_dialog(monkeypatch, dispatches, blocking_calls)
        try:
            splitters = dialog.findChildren(QSplitter)
            assert splitters
            left_panel = splitters[0].widget(0)
            assert left_panel is not None

            configured_minimum = cast("int", getattr(provider_config_module, "_LIST_MIN_WIDTH"))
            assert left_panel.minimumWidth() >= configured_minimum > 0, (
                "the provider-list panel has no protective minimum width, so it can still be squeezed to zero"
            )
        finally:
            dialog.deleteLater()
