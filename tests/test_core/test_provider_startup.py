# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for provider startup initialization in main."""

from __future__ import annotations

import asyncio
import importlib
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials, ProviderError, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path

    from structlog.stdlib import BoundLogger


_initialize_providers = cast(
    "Callable[[ProviderRegistry, CredentialLoader, BoundLogger], Coroutine[object, object, None]]",
    importlib.import_module("intellicrack.main")._initialize_providers,
)
"""Production startup helper resolved through :func:`importlib.import_module`.

Imported via the module object rather than ``from intellicrack.main import X``
because ``intellicrack.__init__`` ships a lazy ``__getattr__`` that aliases
``intellicrack.main`` to the ``main()`` function during collection-time
``from``-imports, hiding the underscored helpers.
"""


def _loader_without_credentials(env_path: Path, monkeypatch: pytest.MonkeyPatch) -> CredentialLoader:
    """Build a real ``CredentialLoader`` that resolves no credentials for any provider.

    Points the loader at a non-existent ``.env`` file (so its parsed variable
    map is empty) and removes every provider's API-key environment variable and
    alias - sourced directly from ``CredentialLoader.PROVIDER_MAPPINGS`` so the
    set cannot drift - from the process environment. The sandbox runner injects
    real provider keys into ``os.environ``; without these deletions the loader's
    genuine ``os.environ`` fallback would surface live keys, causing keyed
    providers to attempt real network connections at startup instead of
    registering credential-less.

    Args:
        env_path: Path used as the loader's ``.env`` source; it must not exist.
        monkeypatch: Fixture used to remove provider environment variables.

    Returns:
        CredentialLoader: A real loader whose ``get_credentials`` returns ``None``
        for every provider.
    """
    for mapping in CredentialLoader.PROVIDER_MAPPINGS.values():
        monkeypatch.delenv(mapping.api_key_var, raising=False)
        for alias in mapping.api_key_aliases:
            monkeypatch.delenv(alias, raising=False)
    return CredentialLoader(env_path=env_path)


@pytest.mark.asyncio
async def test_initialize_providers_connects_no_key_provider_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No-key providers must attempt connect with empty credentials at startup.

    Args:
        monkeypatch: Fixture used to patch the provider connect coroutine.
        tmp_path: Temporary directory supplying a non-existent ``.env`` path.
    """
    connect_calls: list[ProviderCredentials] = []

    async def _fake_connect(
        self: LocalTransformersProvider,
        credentials: ProviderCredentials,
    ) -> None:
        await asyncio.sleep(0)
        connect_calls.append(credentials)
        self.connected = True

    monkeypatch.setattr(LocalTransformersProvider, "connect", _fake_connect)

    registry = ProviderRegistry()
    logger: BoundLogger = get_logger(__name__)
    loader = _loader_without_credentials(tmp_path / "absent.env", monkeypatch)
    assert loader.get_credentials(ProviderName.LOCAL_TRANSFORMERS) is None
    await _initialize_providers(registry, loader, logger)

    assert len(connect_calls) == 1
    assert connect_calls[0].api_key is None
    registered = registry.get(ProviderName.LOCAL_TRANSFORMERS)
    assert registered is not None
    assert registered.is_connected is True


@pytest.mark.asyncio
async def test_initialize_providers_registers_no_key_provider_after_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No-key providers remain registered when connect fails so discovery can report status.

    Args:
        monkeypatch: Fixture used to patch the provider connect coroutine.
        tmp_path: Temporary directory supplying a non-existent ``.env`` path.
    """

    async def _failing_connect(
        self: LocalTransformersProvider,
        credentials: ProviderCredentials,
    ) -> None:
        await asyncio.sleep(0)
        del self, credentials
        failure_message = "connect failure against unreachable transformers backend"
        raise ProviderError(failure_message, provider_name="local_transformers")

    monkeypatch.setattr(LocalTransformersProvider, "connect", _failing_connect)

    registry = ProviderRegistry()
    logger: BoundLogger = get_logger(__name__)
    loader = _loader_without_credentials(tmp_path / "absent.env", monkeypatch)
    await _initialize_providers(registry, loader, logger)

    registered = registry.get(ProviderName.LOCAL_TRANSFORMERS)
    assert registered is not None
    assert registered.is_connected is False
