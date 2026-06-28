# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for provider startup initialization in main."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials, ProviderError, ProviderName
from intellicrack.main import _initialize_providers
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from structlog.stdlib import BoundLogger


class _RecordingCredentialLoader:
    """Credential loader stub that always reports missing credentials."""

    @staticmethod
    def get_credentials(provider: ProviderName) -> ProviderCredentials | None:
        """Return no credentials for any provider.

        Args:
            provider: Provider being queried.

        Returns:
            ProviderCredentials | None: Always ``None``.
        """
        del provider
        return None


@pytest.mark.asyncio
async def test_initialize_providers_connects_no_key_provider_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No-key providers must attempt connect with empty credentials at startup."""
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
    await _initialize_providers(registry, _RecordingCredentialLoader(), logger)

    assert len(connect_calls) == 1
    assert connect_calls[0].api_key is None
    registered = registry.get(ProviderName.LOCAL_TRANSFORMERS)
    assert registered is not None
    assert registered.is_connected is True


@pytest.mark.asyncio
async def test_initialize_providers_registers_no_key_provider_after_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No-key providers remain registered when connect fails so discovery can report status."""
    async def _failing_connect(
        self: LocalTransformersProvider,
        credentials: ProviderCredentials,
    ) -> None:
        await asyncio.sleep(0)
        del self, credentials
        failure_message = "simulated connect failure"
        raise ProviderError(failure_message, provider_name="local_transformers")

    monkeypatch.setattr(LocalTransformersProvider, "connect", _failing_connect)

    registry = ProviderRegistry()
    logger: BoundLogger = get_logger(__name__)
    await _initialize_providers(registry, _RecordingCredentialLoader(), logger)

    registered = registry.get(ProviderName.LOCAL_TRANSFORMERS)
    assert registered is not None
    assert registered.is_connected is False
