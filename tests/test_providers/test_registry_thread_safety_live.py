# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live thread-safety tests for the provider registry singleton.

These tests drive the real :func:`get_provider_registry` double-checked-locking
singleton end to end. Isolation is achieved through the production
:func:`reset_provider_registry` helper rather than ``importlib.reload`` so that
no module-wide state is rebuilt and no residual import side effects leak into
other tests.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderError, ProviderName
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.registry import (
    ProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


_THREAD_COUNT = 32


class _RecordingCredentialLoader:
    """Real credential loader that records which providers were requested.

    Satisfies :class:`~intellicrack.providers.registry.CredentialLoaderProtocol`
    without any mocking framework; the registry stores it verbatim on first
    construction, letting a test assert identity of the single constructed
    singleton.
    """

    def __init__(self) -> None:
        """Initialize an empty record of requested providers."""
        self.requested: list[ProviderName] = []

    def get_credentials(self, provider: ProviderName) -> ProviderCredentials | None:
        """Record the request and return no credentials.

        Args:
            provider: The provider whose credentials were requested.

        Returns:
            ProviderCredentials | None: Always ``None`` for this recorder.
        """
        self.requested.append(provider)
        return None


@pytest.fixture
def reset_registry_singleton() -> Iterator[None]:
    """Reset the provider-registry singleton before and after each test.

    Uses the production :func:`reset_provider_registry` so only the singleton
    holder is cleared; the module itself is never reloaded, keeping the test
    order-independent and free of residual import side effects.

    Yields:
        None: Control returns to the test with a cleared singleton holder.
    """
    reset_provider_registry()
    yield
    reset_provider_registry()


@pytest.mark.usefixtures("reset_registry_singleton")
def test_concurrent_first_access_returns_single_shared_instance() -> None:
    """Verify concurrent first access yields exactly one shared registry instance.

    Thirty-two threads block on a barrier and then race into
    ``get_provider_registry()`` for the very first (lazy) construction. If the
    double-checked-locking were broken, competing threads could each construct
    and observe their own :class:`ProviderRegistry`, producing more than one
    distinct object identity. The gate asserts the set of returned ``id``
    values collapses to exactly one, that the shared instance is a real
    :class:`ProviderRegistry`, and that a subsequent plain call returns that
    same object - proving the singleton is genuinely cached, not rebuilt.
    """
    barrier = threading.Barrier(_THREAD_COUNT)
    results: list[ProviderRegistry] = []
    results_lock = threading.Lock()

    def worker() -> None:
        """Wait on the barrier then fetch and record the registry singleton."""
        barrier.wait()
        instance = get_provider_registry()
        with results_lock:
            results.append(instance)

    with ThreadPoolExecutor(max_workers=_THREAD_COUNT) as executor:
        futures = [executor.submit(worker) for _ in range(_THREAD_COUNT)]
        for future in futures:
            future.result()

    assert len(results) == _THREAD_COUNT
    distinct_ids = {id(instance) for instance in results}
    assert len(distinct_ids) == 1
    shared = results[0]
    assert isinstance(shared, ProviderRegistry)
    assert all(instance is shared for instance in results)
    assert get_provider_registry() is shared


@pytest.mark.usefixtures("reset_registry_singleton")
def test_first_construction_honors_loader_and_ignores_later_loaders() -> None:
    """Verify only the first construction's credential loader is bound to the singleton.

    The first ``get_provider_registry`` call injects a real recording loader; a
    later call passing a different loader must return the same singleton object
    and leave the original loader bound. Binding is proven through public
    behaviour: registering the real ``OllamaProvider`` class and calling
    ``connect_provider`` with no credentials drives the registry into its
    credential-loader fallback, which invokes ``get_credentials`` on the bound
    loader. The first loader therefore records the lookup while the second never
    does, and the loader's ``None`` result surfaces as ``ProviderError`` rather
    than being swallowed.
    """
    first_loader = _RecordingCredentialLoader()
    second_loader = _RecordingCredentialLoader()

    registry_first = get_provider_registry(credential_loader=first_loader)
    registry_second = get_provider_registry(credential_loader=second_loader)

    assert registry_first is registry_second
    registry_first.register_class(ProviderName.OLLAMA, OllamaProvider)

    with pytest.raises(ProviderError, match="No credentials"):
        asyncio.run(registry_first.connect_provider(ProviderName.OLLAMA))

    assert first_loader.requested == [ProviderName.OLLAMA]
    assert second_loader.requested == []


@pytest.mark.usefixtures("reset_registry_singleton")
def test_reset_provider_registry_rebuilds_distinct_instance() -> None:
    """Verify reset clears the holder so the next call builds a fresh distinct instance.

    Acquiring the singleton, resetting, and acquiring again must yield two
    different real :class:`ProviderRegistry` objects. This proves the reset
    helper genuinely clears the holder (rather than returning the stale
    instance) and that the singleton is rebuilt lazily, which is the property
    the isolation fixture depends on.
    """
    instance_before = get_provider_registry()
    assert isinstance(instance_before, ProviderRegistry)

    reset_provider_registry()

    instance_after = get_provider_registry()
    assert isinstance(instance_after, ProviderRegistry)
    assert instance_after is not instance_before
    assert id(instance_after) != id(instance_before)
