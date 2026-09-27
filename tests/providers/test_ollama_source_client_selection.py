# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for ``OllamaProvider._get_source_client`` source selection.

The method turns an explicit source name into the HTTP client and base URL that
serve it, and each way it can refuse (not connected, source unavailable, source
unknown) carries a different message the caller surfaces to the user. These
gates drive the real, unmodified method over real ``httpx.AsyncClient`` objects
bound to the running loop, so the branch that runs is decided by the provider's
own state and a selection that returns the wrong client, or reports the wrong
refusal, fails an assertion directly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ProviderError
from intellicrack.providers.ollama import OllamaProvider


if TYPE_CHECKING:
    import httpx


class _ArmedOllamaProvider(OllamaProvider):
    """``OllamaProvider`` whose source availability is set directly for selection gates."""

    def arm(self, *, connected: bool, local: bool, cloud: bool) -> None:
        """Set the provider's connection state and build a real client per available source.

        Must be called from a running event loop so each client is bound to it,
        which is what keeps :meth:`_ensure_clients_on_loop` from rebuilding them.

        Args:
            connected: Whether the provider reports itself connected.
            local: Whether the local Ollama source is available.
            cloud: Whether the Ollama cloud source is available.
        """
        loop = asyncio.get_running_loop()
        self.connected = connected
        self._local_available = local
        self._cloud_available = cloud
        self._local_client = self._build_local_client() if local else None
        self._local_client_loop = loop if local else None
        self._cloud_client = self._build_cloud_client() if cloud else None
        self._cloud_client_loop = loop if cloud else None

    def select(self, source: str) -> tuple[httpx.AsyncClient, str]:
        """Forward to :meth:`OllamaProvider._get_source_client`.

        Args:
            source: Source name to resolve.

        Returns:
            tuple[httpx.AsyncClient, str]: The selected client and its base URL.
        """
        return self._get_source_client(source)

    def clients(self) -> tuple[httpx.AsyncClient | None, httpx.AsyncClient | None]:
        """Return the local and cloud clients currently held.

        Returns:
            tuple[httpx.AsyncClient | None, httpx.AsyncClient | None]: The
            ``(local, cloud)`` clients, ``None`` for an unavailable source.
        """
        return self._local_client, self._cloud_client

    def local_base_url(self) -> str:
        """Return the local Ollama base URL the selection is expected to pair with.

        Returns:
            str: The provider's configured local URL.
        """
        return self._local_url

    async def release(self) -> None:
        """Close every client :meth:`arm` built."""
        for client in self.clients():
            if client is not None:
                await client.aclose()


class TestGetSourceClientReturnsTheNamedSource:
    """An available source is returned together with the URL that belongs to it."""

    @pytest.mark.asyncio
    async def test_cloud_returns_the_cloud_client_and_cloud_url(self) -> None:
        """``"cloud"`` pairs the cloud client with the cloud API URL, not the local one."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=True, cloud=True)
        try:
            local_client, cloud_client = provider.clients()

            client, url = provider.select("cloud")

            assert client is cloud_client, "the cloud source returned a client other than the cloud client"
            assert client is not local_client, "the cloud source returned the local client"
            assert url == OllamaProvider.CLOUD_API_URL, f"the cloud source came back with url={url!r}"
        finally:
            await provider.release()

    @pytest.mark.asyncio
    async def test_local_returns_the_local_client_and_local_url(self) -> None:
        """``"local"`` pairs the local client with the configured local URL, not the cloud one."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=True, cloud=True)
        try:
            local_client, cloud_client = provider.clients()

            client, url = provider.select("local")

            assert client is local_client, "the local source returned a client other than the local client"
            assert client is not cloud_client, "the local source returned the cloud client"
            assert url == provider.local_base_url(), f"the local source came back with url={url!r}"
        finally:
            await provider.release()

    @pytest.mark.asyncio
    async def test_source_name_is_matched_case_insensitively(self) -> None:
        """Mixed-case source names select the same clients as their lower-case forms."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=True, cloud=True)
        try:
            local_client, cloud_client = provider.clients()

            assert provider.select("CLOUD")[0] is cloud_client, "'CLOUD' did not select the cloud client"
            assert provider.select("Local")[0] is local_client, "'Local' did not select the local client"
        finally:
            await provider.release()


class TestGetSourceClientRefusesWithTheReasonThatApplies:
    """Each way the selection can fail names its own cause."""

    @pytest.mark.asyncio
    async def test_cloud_requested_but_unavailable_reports_cloud_unavailable(self) -> None:
        """A cloud request with only the local source up must not be reported as an unknown source."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=True, cloud=False)
        try:
            with pytest.raises(ProviderError, match="Ollama cloud not available"):
                provider.select("cloud")
        finally:
            await provider.release()

    @pytest.mark.asyncio
    async def test_local_requested_but_unavailable_reports_local_unavailable(self) -> None:
        """A local request with only the cloud source up must not be reported as an unknown source."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=False, cloud=True)
        try:
            with pytest.raises(ProviderError, match="Local Ollama not available"):
                provider.select("local")
        finally:
            await provider.release()

    @pytest.mark.asyncio
    async def test_unrecognised_source_is_reported_by_name(self) -> None:
        """A source that is neither cloud nor local is refused as unknown, naming it."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=True, local=True, cloud=True)
        try:
            with pytest.raises(ProviderError, match=r"Unknown Ollama source: 'gpu'"):
                provider.select("gpu")
        finally:
            await provider.release()

    @pytest.mark.asyncio
    async def test_selection_while_disconnected_reports_not_connected(self) -> None:
        """A provider that is not connected refuses before it looks at the source name."""
        provider = _ArmedOllamaProvider()
        provider.arm(connected=False, local=True, cloud=True)
        try:
            with pytest.raises(ProviderError, match="Not connected"):
                provider.select("local")
        finally:
            await provider.release()
