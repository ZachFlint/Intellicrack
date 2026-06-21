# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live thread-safety tests for the provider registry singleton."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from intellicrack.providers.registry import (
    ProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)


@pytest.mark.skipif(
    os.environ.get("INTELLICRACK_LOCAL_TESTS") != "1",
    reason="Requires INTELLICRACK_LOCAL_TESTS=1 to run live threaded tests.",
)
def test_get_provider_registry_thread_safe_singleton() -> None:
    """Verify concurrent calls to get_provider_registry return the same instance.

    Uses the module-provided reset_provider_registry() to clear the singleton
    holder without the side effects of importlib.reload (which can invalidate
    isinstance checks, disrupt module-level state shared across imports, and
    produce hard-to-diagnose test interactions). Spawns 32 threads that
    simultaneously call get_provider_registry() behind a barrier and asserts
    every thread receives the exact same ProviderRegistry instance via id()
    equality. This validates the double-checked locking pattern prevents race
    conditions during lazy singleton initialization. The test is fully
    deterministic across runs because reset_provider_registry() and the
    re-creation race are isolated from all other module state.
    """
    reset_provider_registry()

    barrier = threading.Barrier(32)
    results: list[ProviderRegistry] = []
    results_lock = threading.Lock()

    def worker() -> ProviderRegistry:
        """Wait on the barrier then fetch the registry.

        Returns:
            ProviderRegistry: The singleton instance returned by this thread.
        """
        barrier.wait()
        instance = get_provider_registry()
        with results_lock:
            results.append(instance)
        return instance

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(worker) for _ in range(32)]
        for future in futures:
            future.result()

    assert len(results) == 32
    first_id = id(results[0])
    for instance in results:
        assert id(instance) == first_id, (
            f"all 32 threads must receive the same singleton instance; "
            f"expected id {first_id}, got id {id(instance)}"
        )
        assert isinstance(instance, ProviderRegistry), (
            f"every returned instance must be a ProviderRegistry, got {type(instance)}"
        )
