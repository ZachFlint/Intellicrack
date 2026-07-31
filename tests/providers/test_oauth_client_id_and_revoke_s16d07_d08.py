# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for S16-D07 and S16-D08 in ``provider_config``.

* S16-D07: clicking "OAuth Login" for a provider with no ``client_id``
  configured used to fail silently -- the real
  ``OAuthManager.build_authorization_url`` already raised
  ``OAuthConfigurationError`` for a missing ``client_id``, but the flow's
  ``_on_error`` callback in ``ProviderConfigDialog._run_oauth_flow`` only
  logged the failure and never told the user. The gate below drives the
  real ``_run_oauth_flow`` error-handling closure, with a real
  ``OAuthManager`` and a real (empty-``client_id``) ``OAuthConfig``, and
  asserts a user-facing error is actually raised through ``show_error``.

* S16-D08: "Revoke Token" only ever called the OAuth manager, so for a
  provider that ``OAuthProvider`` does not recognise (OpenAI, OpenRouter,
  Grok, Ollama, local Transformers, ...) the handler silently returned
  without touching the stored API key. The gate below drives the real,
  private ``provider_config._revoke_credential`` coroutine against a real
  ``CredentialStore`` backed by an in-memory ``keyring`` backend (so the
  host's real OS credential manager is never touched) and asserts the
  stored API key is actually deleted.

Neither production unit under test is mocked: the OAuth failure comes from
the real ``OAuthManager.build_authorization_url`` client_id guard, and the
credential deletion comes from the real ``CredentialStore.delete`` running
against a real (in-memory) ``keyring.backend.KeyringBackend``. Doubles are
used only for Qt-widget/UI plumbing (a ``SimpleNamespace`` standing in for
the dialog, and dispatch-recording stand-ins for the async bridge runner),
mirroring the pattern used by the other ``provider_config`` regression
suites in this repository.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Protocol, cast

import keyring
import keyring.backend
import pytest
from keyring.compat import properties
from keyring.errors import PasswordDeleteError

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.oauth import (
    OAUTH_CONFIGS,
    OAuthConfig,
    OAuthConfigurationError,
    OAuthManager,
    OAuthProvider,
)
from intellicrack.credentials.store import CredentialStore
from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import ProviderConfigDialog


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator


# ---------------------------------------------------------------------------
# S16-D07: OAuth Login must not fail silently for a missing client_id
# ---------------------------------------------------------------------------


def _drive_and_capture_configuration_error(
    coro: Coroutine[object, object, object],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Run a bridge coroutine expected to raise ``OAuthConfigurationError`` and invoke ``on_error``.

    Mirrors what ``BridgeCallWorker`` does on a background thread (catch the
    coroutine's exception, hand it to the ``on_error`` callback) but
    synchronously, in-thread, so the test can observe the real ``on_error``
    closure's side effects deterministically.

    Args:
        coro: Coroutine produced by the bridge call, expected to raise
            ``OAuthConfigurationError``.
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
        except OAuthConfigurationError as exc:
            if on_error is not None:
                cast("Callable[[object], None]", on_error)(exc)
    finally:
        loop.close()


class TestOAuthLoginMissingClientId:
    """S16-D07: "OAuth Login" must surface an actionable error for a missing client_id."""

    @staticmethod
    def test_missing_client_id_surfaces_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
        """Drive the real ``_run_oauth_flow`` error path for an empty ``client_id``.

        Builds a real ``OAuthConfig`` with ``client_id=""`` (mirroring the
        production ``OAUTH_CONFIGS`` entry when no ``*_OAUTH_CLIENT_ID``
        environment variable is set) and a real ``OAuthManager``. Driving
        the coroutine to completion exercises the genuine
        ``OAuthManager.build_authorization_url`` guard, which raises
        ``OAuthConfigurationError``; the test then asserts the dialog's
        ``_on_error`` closure actually surfaces that failure to the user via
        ``show_error`` instead of only logging it.

        Without the fix, ``_on_error`` only called ``_logger.warning(...)``
        and reloaded the credential overview -- ``show_error`` was never
        invoked, so this test goes red against the pre-fix code because
        ``errors`` stays empty.

        Args:
            monkeypatch: Pytest fixture used to patch the module-level OAuth
                manager factory, the async bridge dispatcher, and the error
                dialog helper.
        """
        base = OAUTH_CONFIGS[OAuthProvider.GOOGLE]
        empty_client_id_config = OAuthConfig(
            provider=OAuthProvider.GOOGLE,
            client_id="",
            client_secret=None,
            authorization_url=base.authorization_url,
            token_url=base.token_url,
            scopes=base.scopes,
            use_pkce=True,
            revoke_url=base.revoke_url,
        )

        errors: list[tuple[object, str, str]] = []

        def _record_show_error(parent: object, title: str, message: str, *, exc: BaseException | None = None) -> None:
            """Record a ``show_error`` invocation instead of popping a real dialog.

            Args:
                parent: The dialog/widget the call site passed as the modal parent.
                title: The dialog title the call site passed.
                message: The dialog message the call site passed.
                exc: Optional exception the call site attached (unused).
            """
            del exc
            errors.append((parent, title, message))

        reload_calls: list[None] = []
        holder = SimpleNamespace(
            _provider_widgets={},
            _load_credential_overview=lambda: reload_calls.append(None),
        )

        monkeypatch.setattr(provider_config, "show_error", _record_show_error)
        monkeypatch.setattr(provider_config, "get_oauth_manager", lambda: OAuthManager(credential_store=None))
        monkeypatch.setattr(provider_config, "run_bridge_coroutine_async", _drive_and_capture_configuration_error)

        getattr(ProviderConfigDialog, "_run_oauth_flow")(holder, "google", OAuthProvider.GOOGLE, empty_client_id_config)

        assert len(errors) == 1, f"expected exactly one show_error call for the missing client_id, got {errors!r}"
        _, title, message = errors[0]
        assert title == "OAuth Login"
        assert "client_id" in message, f"the error message must mention the missing client_id, got {message!r}"
        assert "GOOGLE_OAUTH_CLIENT_ID" in message, (
            f"the error message must name the environment variable the user needs to set, got {message!r}"
        )
        assert reload_calls, "the credential overview must still be reloaded after a failed OAuth flow"


# ---------------------------------------------------------------------------
# S16-D08: Revoke Token must delete a stored API key, not silently no-op
# ---------------------------------------------------------------------------


class _InMemoryKeyringBackend(keyring.backend.KeyringBackend):
    """A real, in-memory ``keyring.backend.KeyringBackend`` for isolated tests.

    Registered as the active backend for the duration of one test via
    ``keyring.set_keyring`` so ``CredentialStore`` drives its genuine
    ``keyring.get_password`` / ``set_password`` / ``delete_password``
    dispatch against process memory instead of the host OS credential
    manager, so the user's real keyring is never touched.
    """

    @properties.classproperty
    @classmethod
    def priority(cls) -> float:
        """Report a positive priority so ``CredentialStore`` treats this backend as usable.

        Returns:
            float: A fixed, positive priority.
        """
        return 1.0

    def __init__(self) -> None:
        """Initialise the backend with an empty in-memory credential map."""
        super().__init__()
        self._entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        """Return the stored value for ``service``/``username``, if any.

        Args:
            service: The keyring service name.
            username: The keyring username/key.

        Returns:
            str | None: The stored value, or ``None`` if absent.
        """
        return self._entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        """Store ``password`` under ``service``/``username``.

        Args:
            service: The keyring service name.
            username: The keyring username/key.
            password: The value to store.
        """
        self._entries[service, username] = password

    def delete_password(self, service: str, username: str) -> None:
        """Delete the stored entry for ``service``/``username``.

        Args:
            service: The keyring service name.
            username: The keyring username/key.

        Raises:
            PasswordDeleteError: If no entry exists for the given key.
        """
        try:
            del self._entries[service, username]
        except KeyError as exc:
            msg = f"no entry for {service!r}/{username!r}"
            raise PasswordDeleteError(msg) from exc

    def contains(self, service: str, username: str) -> bool:
        """Report whether an entry currently exists for ``service``/``username``.

        Args:
            service: The keyring service name.
            username: The keyring username/key.

        Returns:
            bool: True if an entry is currently stored.
        """
        return (service, username) in self._entries


@pytest.fixture
def isolated_keyring_backend() -> Iterator[_InMemoryKeyringBackend]:
    """Install an in-memory keyring backend for the duration of one test.

    Saves and restores the process-wide active ``keyring`` backend so the
    substitution never leaks into other tests or touches the host's real OS
    credential manager.

    Yields:
        _InMemoryKeyringBackend: The active in-memory backend.
    """
    previous = keyring.get_keyring()
    backend = _InMemoryKeyringBackend()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)


def _isolated_store() -> CredentialStore:
    """Build a ``CredentialStore`` whose env-file fallback never resolves.

    Points the fallback ``CredentialLoader`` at a nonexistent path so only
    the active keyring backend (installed by ``isolated_keyring_backend``)
    can supply or clear credentials -- the real project ``.env`` and the
    process environment are never consulted.

    Returns:
        CredentialStore: A freshly constructed, env-isolated credential store.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_s16d08_gate__/.env"))
    return CredentialStore(fallback_loader=loader)


class _RevokeOutcomeLike(Protocol):
    """Structural type for the private ``provider_config._revoke_credential`` result.

    Attributes:
        kind: What kind of credential was targeted (``"oauth"``,
            ``"api_key"``, or ``"none"``).
        success: Whether the revoke/delete actually removed a credential.
    """

    kind: str
    success: bool


class _RevokeCredentialFn(Protocol):
    """Structural type for the private ``provider_config._revoke_credential`` coroutine function."""

    def __call__(
        self,
        provider_name: ProviderName,
        oauth_provider: OAuthProvider | None,
        *,
        store: CredentialStore | None = None,
    ) -> Coroutine[object, object, object]:
        """Revoke the OAuth token or delete the API key for a provider.

        Args:
            provider_name: Canonical provider identifier used by the credential store.
            oauth_provider: OAuth provider enum, or ``None`` for API-key-only providers.
            store: Credential store override, for isolated testing.

        Returns:
            Coroutine[object, object, object]: Coroutine resolving to the revoke outcome.
        """
        ...


def _revoke_credential_fn() -> _RevokeCredentialFn:
    """Fetch the real, private ``provider_config._revoke_credential`` coroutine function.

    Returns:
        _RevokeCredentialFn: The production coroutine function under test.
    """
    return cast("_RevokeCredentialFn", getattr(provider_config, "_revoke_credential"))


class TestRevokeApiKeyProvider:
    """S16-D08: "Revoke Token" must delete a stored API key instead of silently no-opping."""

    @staticmethod
    def test_revoke_deletes_api_key_from_real_credential_store(isolated_keyring_backend: _InMemoryKeyringBackend) -> None:
        """Revoking a non-OAuth provider must delete its API key from the credential store.

        Ollama is not recognised by ``OAuthProvider`` (only Google, Anthropic,
        and HuggingFace support OAuth), so ``oauth_provider=None`` here
        mirrors exactly what ``_do_revoke_oauth_token`` resolves for it. A
        real API key is written through the real ``CredentialStore.set``
        into the in-memory keyring backend, then the real
        ``_revoke_credential`` coroutine is awaited directly.

        Without the fix, ``_revoke_credential`` (or its caller) either does
        not exist or unconditionally routes through the OAuth manager and
        returns without ever calling ``CredentialStore.delete``, so the
        in-memory backend would still ``contains`` the entry afterward and
        this test goes red.

        Args:
            isolated_keyring_backend: The in-memory keyring backend fixture.
        """
        store = _isolated_store()
        assert store.keyring_available, "the in-memory backend must report itself as a usable keyring"

        provider = ProviderName.OLLAMA
        marker = f"s16d08-{uuid.uuid4().hex}"
        key_id = getattr(store, "_get_keyring_key")(provider)

        async def _run() -> _RevokeOutcomeLike:
            """Store a real API key, then revoke it through the production coroutine.

            Returns:
                _RevokeOutcomeLike: The outcome returned by ``_revoke_credential``.
            """
            await store.set(provider, ProviderCredentials(api_key=marker))
            assert isolated_keyring_backend.contains(CredentialStore.SERVICE_NAME, key_id), (
                "precondition failed: the API key was not actually written to the keyring backend"
            )
            revoke = _revoke_credential_fn()
            return cast("_RevokeOutcomeLike", await revoke(provider, None, store=store))

        outcome = asyncio.run(_run())

        assert outcome.kind == "api_key", f"expected the API-key revoke path, got kind={outcome.kind!r}"
        assert outcome.success is True, "the API key deletion must be reported as successful"
        assert not isolated_keyring_backend.contains(CredentialStore.SERVICE_NAME, key_id), (
            "the stored API key must actually be removed from the credential store, not just reported as revoked"
        )

    @staticmethod
    def test_revoke_reports_nothing_configured_without_touching_keyring(
        isolated_keyring_backend: _InMemoryKeyringBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Revoking a non-OAuth provider with nothing configured must not silently report success.

        Guards against a trivial (still-broken) implementation that always
        returns ``success=True`` regardless of whether anything was actually
        stored.

        ``_isolated_store`` only points the env-*file* fallback at a
        nonexistent path; ``CredentialLoader._get_var`` still falls back to
        ``os.environ`` unconditionally (by design, for real .env-less
        deployments), and the sandbox this suite runs in ships real provider
        keys directly in the process environment. ``OPENROUTER_API_KEY``
        must therefore be cleared explicitly so the "nothing configured"
        precondition genuinely holds, mirroring the ambient-credential
        isolation pattern used elsewhere in this test suite (e.g.
        ``tests/providers/credentials/test_store_wave5.py``'s
        ``_clear_ollama_env``).

        Args:
            isolated_keyring_backend: The in-memory keyring backend fixture (unused directly;
                present so the store never touches the host's real keyring).
            monkeypatch: Pytest fixture used to clear the ambient ``OPENROUTER_API_KEY``
                environment variable for the duration of this test.
        """
        del isolated_keyring_backend
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        store = _isolated_store()
        assert store.keyring_available

        async def _run() -> _RevokeOutcomeLike:
            """Revoke a provider with nothing stored for it.

            Returns:
                _RevokeOutcomeLike: The outcome returned by ``_revoke_credential``.
            """
            revoke = _revoke_credential_fn()
            return cast("_RevokeOutcomeLike", await revoke(ProviderName.OPENROUTER, None, store=store))

        outcome = asyncio.run(_run())

        assert outcome.kind == "none", f"expected no credential to be found, got kind={outcome.kind!r}"
        assert outcome.success is False
