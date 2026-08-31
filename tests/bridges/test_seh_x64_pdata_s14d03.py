# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real x64 exception-handler enumeration tests for S14-D03.

``ProcessBridge.get_seh_chain`` used to raise ``ToolError`` for every native
x64 target because x64 Windows has no per-thread SEH linked list. These
tests prove the replacement behavior is genuine: the bridge now parses each
loaded module's PE ``.pdata`` (``IMAGE_DIRECTORY_ENTRY_EXCEPTION``) directory
straight out of remote process memory and returns the ``RUNTIME_FUNCTION``
entries whose ``UNWIND_INFO`` carries a real ``EHANDLER``/``UHANDLER``.

The target is the live 64-bit Python test-runner process itself (attached
via ``os.getpid()``), so this exercises real ``ReadProcessMemory`` calls
against real PE headers -- no mocking of the behavior under test. Because it
needs a live x64 process and raw memory access, it is registered as
``host_native`` in ``tests/_helpers/host_native.py`` and only runs on the
host, not inside the sandbox container.
"""

from __future__ import annotations

import os
import struct
import sys
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.core.types import ModuleInfo

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.skipif(struct.calcsize("P") != 8, reason="requires a native 64-bit test process"),
    pytest.mark.asyncio,
]

_VALID_HANDLER_FLAGS: frozenset[str] = frozenset({"EHANDLER", "UHANDLER", "EHANDLER|UHANDLER"})
_NTDLL_MODULE_NAME = "ntdll.dll"


@pytest_asyncio.fixture(scope="module")
async def attached_bridge() -> AsyncGenerator[ProcessBridge]:
    """Attach a fresh ``ProcessBridge`` to the current (native x64) Python test process.

    Yields:
        ProcessBridge: Initialized bridge with an open handle on the
        current process, closed and shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    await bridge.open_process(os.getpid(), "all")
    yield bridge
    await bridge.close()
    await bridge.shutdown()


@pytest_asyncio.fixture(scope="module")
async def main_thread_tid(attached_bridge: ProcessBridge) -> int:
    """Get the TID of the first thread in the current process.

    Args:
        attached_bridge: ProcessBridge fixture pre-attached to the current process.

    Returns:
        int: Windows thread id of the first thread enumerated in the current process.
    """
    threads = await attached_bridge.get_threads(os.getpid())
    return threads[0].tid


def _find_owning_module(modules: list[ModuleInfo], address: int) -> ModuleInfo | None:
    """Find the loaded module whose address range contains ``address``.

    Args:
        modules: Loaded modules of the target process.
        address: Virtual address to locate.

    Returns:
        ModuleInfo | None: The module whose ``[base_address,
        base_address + size)`` range contains ``address``, or ``None``
        if no module covers it.
    """
    for module in modules:
        if module.base_address <= address < module.base_address + module.size:
            return module
    return None


async def test_seh_chain_x64_target_returns_nonempty_pdata_handlers(
    attached_bridge: ProcessBridge,
    main_thread_tid: int,
) -> None:
    """``get_seh_chain`` on a native x64 target returns real ``.pdata`` handler entries.

    Per S14-D03, the bridge must no longer raise ``ToolError("SEH chain not
    applicable to x64 target")`` on native x64 targets; it must instead
    return genuine handler-carrying ``RUNTIME_FUNCTION`` entries parsed from
    the target's own loaded-module exception directories.

    Falsifiability: reverting ``get_seh_chain`` to raise on x64 (the old
    S14-D03 defect) makes this ``await`` raise ``ToolError`` instead of
    returning a list, failing immediately. Returning an empty list (for
    example from a broken data-directory index, or reading the wrong
    ``RUNTIME_FUNCTION`` field as the unwind-info RVA) fails the
    non-empty assertion. Every entry's structural fields and flag values
    are checked, so a parse that produces malformed dicts also fails.

    Args:
        attached_bridge: ProcessBridge fixture pre-attached to the current (native x64) process.
        main_thread_tid: Windows thread id of the first thread enumerated in the current process.
    """
    chain = await attached_bridge.get_seh_chain(main_thread_tid)

    assert isinstance(chain, list)
    assert len(chain) > 0, "a native x64 process must expose at least one .pdata exception handler"

    for entry in chain:
        assert isinstance(entry, dict)
        module_name = entry.get("module")
        address = entry.get("address")
        end_address = entry.get("end_address")
        handler_address = entry.get("handler_address")
        flags = entry.get("flags")

        assert isinstance(module_name, str)
        assert module_name
        assert isinstance(address, int)
        assert address > 0
        assert isinstance(end_address, int)
        assert end_address >= address
        assert isinstance(handler_address, int)
        assert handler_address > 0
        assert isinstance(flags, str)
        assert flags in _VALID_HANDLER_FLAGS


async def test_seh_chain_x64_addresses_resolve_within_loaded_modules(
    attached_bridge: ProcessBridge,
    main_thread_tid: int,
) -> None:
    """Every ``.pdata`` handler entry's addresses fall inside a real loaded module.

    This proves the RVA-plus-module-base arithmetic is genuine rather than
    garbage: both the function start address and the resolved handler
    address must land inside some module's real ``[base, base + size)``
    range, and at least one entry must be attributed to ``ntdll.dll``
    (every modern Windows x64 build's ``ntdll.dll`` carries SEH-using
    routines with real ``.pdata`` handler entries).

    Falsifiability: breaking the RVA-to-VA math (for example adding the
    wrong module's base, or using a stale/incorrect exception-directory
    RVA) produces addresses outside every enumerated module's range,
    failing the bounds assertions. Reverting to the old raise-on-x64
    behavior fails at the initial ``await`` before any assertion runs.

    Args:
        attached_bridge: ProcessBridge fixture pre-attached to the current (native x64) process.
        main_thread_tid: Windows thread id of the first thread enumerated in the current process.
    """
    chain = await attached_bridge.get_seh_chain(main_thread_tid)
    assert len(chain) > 0

    modules = await attached_bridge.get_modules(os.getpid())
    assert len(modules) > 0

    saw_ntdll = False
    for entry in chain:
        assert isinstance(entry, dict)
        module_name = entry.get("module")
        address = entry.get("address")
        handler_address = entry.get("handler_address")
        assert isinstance(module_name, str)
        assert isinstance(address, int)
        assert isinstance(handler_address, int)

        function_module = _find_owning_module(modules, address)
        assert function_module is not None, f"handler function address 0x{address:X} is outside every loaded module"

        handler_module = _find_owning_module(modules, handler_address)
        assert handler_module is not None, f"handler_address 0x{handler_address:X} is outside every loaded module"

        if module_name.lower() == _NTDLL_MODULE_NAME:
            saw_ntdll = True

    assert saw_ntdll, "expected at least one x64 .pdata handler entry attributed to ntdll.dll"
