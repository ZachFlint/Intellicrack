# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for the Ghidra read-path accessors that call PyGhidra/jfx_bridge APIs.

Four user-facing ``GhidraBridge`` read accessors depend on a PyGhidra/jfx_bridge API call whose real behavior must match what the remote script assumes:

* :meth:`GhidraBridge.get_basic_blocks` must iterate the ``CodeBlock[]`` Java array returned by ``BasicBlockModel.getCodeBlocksContaining(Address, TaskMonitor)``. That overload returns an array, not an iterator, and arrays have no ``hasNext`` method.
* :meth:`GhidraBridge.get_memory_map` and :meth:`GhidraBridge.get_segments` must resolve memory through ``currentProgram``. The bare name ``getMemory()`` does not exist in the PyGhidra script namespace; only ``currentProgram.getMemory()`` resolves.
* :meth:`GhidraBridge.search_symbols` must match glob patterns in Python over ``SymbolTable.getAllSymbols(boolean)`` using :mod:`fnmatch`. ``SymbolTable.getSymbolIterator(name, True)`` returns an empty iterator against a real Ghidra 12 program and is not used for matching.
* :meth:`GhidraBridge.get_properties` must enumerate map names through ``UsrPropertyManager.propertyManagers()``. The ``PropertyMapManager`` interface has no ``propertyNames()`` method.

These gates drive a real headless Ghidra 12.x instance through PyGhidra against a real PE (the running interpreter's own ``python.exe``) through the actual ``ghidra_bridge`` RPC client and Ghidra API calls. Each test performs the read through the corresponding public bridge method and asserts on the returned data (basic block counts, real memory block names and permissions, real symbol addresses, a real round-tripped property value), so each gate fails if the matching accessor regresses in ``src/intellicrack/bridges/ghidra.py``.

Host-native only: the Docker sandbox has no JVM/Ghidra install, so this module skips itself (via ``pytestmark``) unless ``ghidra_bridge``, ``jpype`` and ``pyghidra`` are importable *and* a real Ghidra installation is named by ``GHIDRA_INSTALL_DIR`` or ``GHIDRA_HOME``. Run explicitly on a host with Ghidra installed via::

    python scripts/host_native_tests.py -- -k "s15_readonly_api" -v

or as part of the orchestrated host-native pass via ``python scripts/host_native_tests.py``.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
import pytest_asyncio

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import FunctionInfo


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def _resolve_ghidra_install() -> Path | None:
    """Resolve a real Ghidra installation directory from the environment.

    Checks ``GHIDRA_INSTALL_DIR`` then ``GHIDRA_HOME`` for a directory that
    actually contains the platform's ``support/analyzeHeadless`` launcher.

    Returns:
        Path | None: The Ghidra install root when a real installation is
        found, otherwise ``None``.
    """
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        raw = os.environ.get(var, "").strip()
        if not raw:
            continue
        root = Path(raw)
        launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        launcher = root / "support" / launcher_name
        if launcher.is_file():
            return root
    return None


_GHIDRA_INSTALL: Final[Path | None] = _resolve_ghidra_install()
_PACKAGES_AVAILABLE: Final[bool] = (
    importlib.util.find_spec("ghidra_bridge") is not None
    and importlib.util.find_spec("jpype") is not None
    and importlib.util.find_spec("pyghidra") is not None
)
_SKIP_REASON: Final[str] = (
    ""
    if _PACKAGES_AVAILABLE and _GHIDRA_INSTALL is not None
    else (
        "Requires the ghidra_bridge/jpype/pyghidra packages and a real Ghidra "
        "install named by GHIDRA_INSTALL_DIR or GHIDRA_HOME (host-native only)"
    )
)

pytestmark = [
    pytest.mark.host_native,
    pytest.mark.skipif(bool(_SKIP_REASON), reason=_SKIP_REASON),
    pytest.mark.asyncio,
]

# The running interpreter's own executable is a real, always-present PE
# usable as an analysis target without shipping a binary fixture, matching
# the pattern used by the transaction-mutator gates.
_TARGET_BINARY: Final[Path] = Path(sys.executable)

_MIN_CFG_BLOCKS: Final[int] = 2
_MAX_FUNCTION_CANDIDATES: Final[int] = 25
_MEM_SEARCH_GLOB: Final[str] = "mem*"
_EXPECTED_MEM_FUNCTION_NAMES: Final[frozenset[str]] = frozenset({"memset", "memcpy", "memmove", "memcmp"})
_PROPERTY_MAP_NAME: Final[str] = "IntellicrackS15D12Audit"
_PROPERTY_VALUE: Final[str] = "intellicrack_s15_d12_audit_value"
_PROPERTY_ADDR_OFFSET: Final[int] = 0x8


def _reserve_free_port() -> int:
    """Reserve an ephemeral loopback TCP port and release it immediately.

    Returns:
        int: A port number free at the moment of the call, for the headless
        bridge server to bind.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


@pytest_asyncio.fixture(scope="module")
async def real_bridge(tmp_path_factory: pytest.TempPathFactory) -> AsyncGenerator[GhidraBridge]:
    """Boot a real, fully-analyzed headless Ghidra bridge on a real PE.

    Launches ``analyzeHeadless`` through PyGhidra against the Ghidra
    installation resolved by :func:`_resolve_ghidra_install`, imports the
    current interpreter's own executable, and runs full auto-analysis so
    real functions, basic blocks, and symbols exist for the read-path gates
    below. Shared across every test in this module so the (slow, cold-JVM
    plus full-analysis) boot happens once. Shuts the headless process down
    once the module is done.

    Args:
        tmp_path_factory: Pytest factory for a module-scoped temp directory.

    Yields:
        GhidraBridge: A connected, fully-analyzed bridge with a real program
        loaded.
    """
    assert _GHIDRA_INSTALL is not None
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = _GHIDRA_INSTALL
    project_dir = tmp_path_factory.mktemp("ghidra_s15_readonly_project")
    await bridge.start_headless(project_dir, "intellicrack_s15_readonly")
    _ = await bridge.load_binary(_TARGET_BINARY)
    await bridge.analyze()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture(scope="module")
async def entry_point(real_bridge: GhidraBridge) -> int:
    """Resolve the loaded program's entry point address.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed
            program loaded.

    Returns:
        int: The entry point address of the currently loaded program,
        guaranteed to sit inside a real, mapped memory block.
    """
    raw = await real_bridge.execute_script(
        "entry_points = currentProgram.getSymbolTable().getExternalEntryPointIterator()\n"
        "entry_points.next().getOffset() if entry_points.hasNext() else 0",
    )
    resolved = int(raw)
    assert resolved != 0
    return resolved


async def test_get_basic_blocks_iterates_code_block_array(real_bridge: GhidraBridge) -> None:
    """get_basic_blocks must iterate the ``CodeBlock[]`` array Ghidra returns.

    A Java array has no ``hasNext`` attribute, so the accessor must not call ``hasNext()`` on the value returned by ``BasicBlockModel.getCodeBlocksContaining(Address, TaskMonitor)``. Calling it would raise ``AttributeError`` for every candidate function's address range, which the bridge wraps as ``ToolError``. This test walks the largest analyzed functions (biggest byte size correlates with real branching control flow) until it finds one whose CFG has at least two blocks, and asserts every returned block dict has a sane start/end pair inside the function.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed program loaded.
    """
    functions = await real_bridge.get_functions()
    assert functions, "expected at least one analyzed function after analyze()"
    assert all(isinstance(f, FunctionInfo) for f in functions)

    candidates: list[FunctionInfo] = sorted(functions, key=lambda f: f.size, reverse=True)[:_MAX_FUNCTION_CANDIDATES]

    matched_function: FunctionInfo | None = None
    matched_blocks: list[dict[str, Any]] = []
    for candidate in candidates:
        result = await real_bridge.get_basic_blocks(candidate.address)
        blocks = result.get("blocks", [])
        if len(blocks) >= _MIN_CFG_BLOCKS:
            matched_function = candidate
            matched_blocks = blocks
            break

    assert matched_function is not None, (
        f"no function among the {len(candidates)} largest analyzed functions produced >= {_MIN_CFG_BLOCKS} basic blocks"
    )
    assert len(matched_blocks) >= _MIN_CFG_BLOCKS
    for block in matched_blocks:
        assert block["end"] >= block["start"] >= matched_function.address


async def test_get_memory_map_and_segments_return_real_blocks(real_bridge: GhidraBridge) -> None:
    """get_memory_map and get_segments must resolve memory via currentProgram.

    The bare name ``getMemory()`` does not exist in the PyGhidra script namespace, so both remote scripts must call ``currentProgram.getMemory()``. This test confirms both accessors return real, non-empty memory block lists for the loaded PE, with at least one block that is an initialized, executable code section (the PE ``.text`` section) and real (non-string-null) permission flags.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed program loaded.
    """
    memory_map = await real_bridge.get_memory_map()
    assert memory_map, "expected at least one real memory block"
    assert any(block.get("execute") and block.get("initialized") for block in memory_map)
    for block in memory_map:
        assert isinstance(block["read"], bool)
        assert isinstance(block["write"], bool)
        assert isinstance(block["execute"], bool)
        assert block["end"] >= block["start"]

    segments = await real_bridge.get_segments()
    assert segments, "expected at least one real segment"
    assert any(segment.get("execute") and segment.get("initialized") for segment in segments)


async def test_search_symbols_glob_returns_mem_functions(real_bridge: GhidraBridge) -> None:
    """search_symbols must resolve real symbols for a glob pattern.

    The search must not depend on ``SymbolTable.getSymbolIterator(name, True)``, which returns no results against a real analyzed program even for a valid glob. This test searches ``mem*`` against the real, analyzed ``python.exe`` (which imports the Universal CRT string functions) and asserts real results come back with real, non-zero addresses whose names match the glob and that at least one of the well-known CRT ``mem*`` functions is present.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed program loaded.
    """
    results = await real_bridge.search_symbols(_MEM_SEARCH_GLOB)
    assert results, "expected at least one symbol matching 'mem*'"

    for symbol in results:
        name = str(symbol["name"])
        assert name.lower().startswith("mem")
        assert isinstance(symbol["address"], int)
        assert symbol["address"] > 0

    matched_names = {str(symbol["name"]).lower() for symbol in results}
    assert matched_names & _EXPECTED_MEM_FUNCTION_NAMES, (
        f"expected one of {sorted(_EXPECTED_MEM_FUNCTION_NAMES)} among search results, got {sorted(matched_names)}"
    )


async def test_get_properties_reads_back_real_user_property(
    real_bridge: GhidraBridge,
    entry_point: int,
) -> None:
    """get_properties must enumerate real UsrPropertyManager maps.

    The accessor must enumerate map names through ``propertyManagers()``, because ``PropertyMapManager`` has no ``propertyNames()`` method. This test first writes a real ``StringPropertyMap`` entry directly through ``execute_script`` (independent of the method under test) under a real transaction, then calls the public :meth:`GhidraBridge.get_properties` accessor and asserts the real value round-trips.

    Args:
        real_bridge: Module-scoped bridge fixture with a real, analyzed program loaded.
        entry_point: The loaded program's entry point address.
    """
    prop_addr = entry_point + _PROPERTY_ADDR_OFFSET

    setup_script = textwrap.dedent(
        f"""
        addr = toAddr({prop_addr})
        tx_id = currentProgram.startTransaction('intellicrack_s15_d12_test_setup')
        try:
            upm = currentProgram.getUsrPropertyManager()
            prop_map = upm.getStringPropertyMap({_PROPERTY_MAP_NAME!r})
            if prop_map is None:
                prop_map = upm.createStringPropertyMap({_PROPERTY_MAP_NAME!r})
            prop_map.add(addr, {_PROPERTY_VALUE!r})
        finally:
            currentProgram.endTransaction(tx_id, True)
        True
        """,
    )
    _ = await real_bridge.execute_script(setup_script)

    result = await real_bridge.get_properties(prop_addr)
    assert result["address"] == prop_addr
    raw_properties = result["properties"]
    assert isinstance(raw_properties, dict)
    properties = cast("dict[str, Any]", raw_properties)
    assert properties.get(_PROPERTY_MAP_NAME) == _PROPERTY_VALUE
