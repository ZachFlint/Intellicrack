# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for FridaBridge scan-memory and stop-all-scripts defects.

Covers two real defects fixed in ``FridaBridge``:

* S14-D06 -- ``scan_memory`` used a single synchronous ``Memory.scanSync``
  RPC call that could block past Frida's transport timeout and raise an
  unhandled ``frida.TransportError`` the worker never surfaced, leaving the
  UI's Scan button stuck with no ``memory_scan_completed``. The fix drives
  the scan through a chunked, async ``Memory.scan`` RPC agent so the
  coroutine always resolves.
* S14-D10 -- ``unload_all_scripts`` ("Stop All Scripts") could leave a
  script's bookkeeping behind when the underlying Frida ``unload()`` call
  raised for an already-destroyed/detached script. The fix tolerates that
  state as a no-op and always clears the registry.

Both tests drive a REAL Frida runtime attached to the current test process
(no external process is spawned, so no ``spawns_process`` marker is needed --
matching the ``self_attached_bridge`` idiom already used in
``tests/bridges/test_frida_bridge.py``). Requires frida-python and a Windows
host.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
from typing import TYPE_CHECKING, Final, cast


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from intellicrack.bridges.base import MemorySearchResult

import pytest

from intellicrack.core.types import ToolError


frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402


_logger = logging.getLogger(__name__)

_SCAN_MARKER: Final[bytes] = b"INTELLICRACK_S14D06_MEMSCAN_PROBE__"
_SCAN_TIMEOUT_S: Final[float] = 60.0
_PERSISTENT_SCRIPT_JS: Final[str] = "rpc.exports = { ping: function () { return 1; } };"
_STOP_ALL_SCRIPT_COUNT: Final[int] = 4


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _get(target: object, name: str) -> object:
    """Read an attribute from *target* via getattr to avoid private-access diagnostics.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        object: The attribute value.
    """
    return getattr(target, name)


def _get_dict(target: object, name: str) -> dict[object, object]:
    """Read a dict-typed attribute for registry inspection.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        dict[object, object]: The mapping at ``target.<name>``.
    """
    return cast("dict[object, object]", _get(target, name))


async def _unload_script_handle_directly(script: object) -> None:
    """Call ``.unload()`` on an opaque Frida script handle off the event loop thread.

    Used to force one script into Frida's real already-destroyed state
    *before* ``unload_all_scripts`` runs, independently of the bridge's own
    unload path, so the test exercises the exact "already gone" condition
    Stop-All must tolerate.

    Args:
        script: A ``frida.core.Script`` instance accessed as ``object`` to
            avoid depending on frida's stub types in this test module.
    """
    unload_fn = cast("Callable[[], None]", _get(script, "unload"))
    await asyncio.to_thread(unload_fn)


@pytest.fixture
def self_attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        FridaBridge: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(os.getpid()))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except ToolError:
        _logger.debug("self_attached_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_scan_memory_resolves_within_timeout_and_finds_known_pattern(self_attached_bridge: FridaBridge) -> None:
    """Verify scan_memory finds a known pattern and always resolves within a bounded timeout.

    Regression test for S14-D06: the previous implementation ran a single
    synchronous ``Memory.scanSync`` RPC across every readable range, which
    could block past Frida's transport timeout and raise an unhandled
    ``frida.TransportError`` that the UI worker never caught -- the Scan
    button stayed disabled forever with no ``memory_scan_completed``. The
    fix chunks the scan through an async ``Memory.scan`` RPC agent so the
    coroutine always resolves. Wrapping the call in ``asyncio.wait_for`` is
    the falsifiable gate here: a real hang fails this test loudly with a
    ``TimeoutError`` instead of hanging the whole suite, and a broken scan
    (e.g. one that silently returns no results) fails the match assertion.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    buf = ctypes.create_string_buffer(_SCAN_MARKER)
    buf_addr = ctypes.addressof(buf)

    async def _scan() -> list[MemorySearchResult]:
        """Run the bounded scan against the real attached process.

        Returns:
            list[MemorySearchResult]: Matches reported by the bridge.
        """
        return await asyncio.wait_for(self_attached_bridge.scan_memory(_SCAN_MARKER), timeout=_SCAN_TIMEOUT_S)

    results = _run_async(_scan())

    assert isinstance(results, list), f"scan_memory must return a list, got {type(results)}"
    exact_matches = [r for r in results if r.address == buf_addr]
    assert exact_matches, f"expected a scan hit at 0x{buf_addr:X} for the known marker among {len(results)} matches"
    expected_hex = " ".join(f"{b:02x}" for b in _SCAN_MARKER)
    assert exact_matches[0].matched_bytes == expected_hex, f"matched_bytes must be {expected_hex!r}, got {exact_matches[0].matched_bytes!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_unload_all_scripts_clears_every_script_even_when_one_is_already_destroyed(
    self_attached_bridge: FridaBridge,
) -> None:
    """Verify Stop-All unloads every script and clears bookkeeping even when one is already gone.

    Regression test for S14-D10: some scripts raised ``InvalidOperationError``
    when unloaded a second time (already destroyed/detached), and that
    failure used to leave the script's handle behind instead of being
    treated as a tolerated no-op. This test loads several persistent
    scripts, pre-destroys one of them out-of-band via the real Frida
    ``.unload()`` call (the exact "already gone" state Stop-All must
    tolerate), then calls ``unload_all_scripts`` and asserts every script --
    including the pre-destroyed one -- ends up removed from the bridge's
    internal registry and reports ``is_destroyed`` on the real Frida side,
    with no early abort of the sweep.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    script_ids = [_run_async(self_attached_bridge.execute_persistent_script(_PERSISTENT_SCRIPT_JS)) for _ in range(_STOP_ALL_SCRIPT_COUNT)]
    scripts_registry = _get_dict(self_attached_bridge, "_scripts")
    assert len(scripts_registry) == _STOP_ALL_SCRIPT_COUNT, (
        f"expected {_STOP_ALL_SCRIPT_COUNT} tracked scripts after loading, got {len(scripts_registry)}"
    )
    handles = {sid: scripts_registry[sid] for sid in script_ids}

    pre_destroyed_id = script_ids[0]
    _run_async(_unload_script_handle_directly(handles[pre_destroyed_id]))
    assert bool(_get(handles[pre_destroyed_id], "is_destroyed")), "pre-destroy step must actually tear down the script"

    _run_async(self_attached_bridge.unload_all_scripts())

    remaining = _get_dict(self_attached_bridge, "_scripts")
    assert remaining == {}, f"unload_all_scripts must leave the registry empty, found {list(remaining)}"
    for sid, handle in handles.items():
        assert bool(_get(handle, "is_destroyed")), f"script {sid} must be destroyed on the real Frida side after Stop-All"
