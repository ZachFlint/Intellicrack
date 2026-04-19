# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live thread-safety tests for the provider registry singleton (Unit 6, C25a)."""

from __future__ import annotations

import importlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.mark.skipif(
    os.environ.get("INTELLICRACK_LOCAL_TESTS") != "1",
    reason="Requires INTELLICRACK_LOCAL_TESTS=1 to run live threaded tests.",
)
def test_get_provider_registry_thread_safe_singleton() -> None:
    """Verify concurrent calls to get_provider_registry return the same instance.

    Uses importlib.reload to reset the module-level singleton holder without
    accessing private attributes directly. Spawns 32 threads that simultaneously
    call get_provider_registry() behind a barrier and asserts every thread
    receives the exact same ProviderRegistry instance via id() equality. This
    validates the double-checked locking pattern prevents race conditions during
    lazy singleton initialization.
    """
    registry_module = importlib.import_module("intellicrack.providers.registry")
    registry_module = importlib.reload(registry_module)

    get_provider_registry = registry_module.get_provider_registry
    provider_registry_type = registry_module.ProviderRegistry

    barrier = threading.Barrier(32)
    results: list[object] = []
    results_lock = threading.Lock()

    def worker() -> object:
        """Wait on the barrier then fetch the registry.

        Returns:
            object: The singleton instance returned by this thread.
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
        assert id(instance) == first_id
        assert isinstance(instance, provider_registry_type)
