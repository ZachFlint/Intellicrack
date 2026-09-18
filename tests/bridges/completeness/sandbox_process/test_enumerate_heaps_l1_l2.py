# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness gate tests for finding T2-8d (``ProcessBridge.enumerate_heaps`` orphan fix).

``ProcessBridge.enumerate_heaps`` (a real, budget/cap-bounded per-block heap
walker distinct from the shallower ``get_heaps`` heap-list-only sibling) had
no ``ToolFunction`` registration and no caller anywhere in the codebase. The
fix registers it as ``process.enumerate_heaps`` in ``_PROCESS_FUNCTIONS`` so
``ToolRegistry.execute_tool_call`` can dispatch to it (L2), and adds a
reachable "Walk Heap Blocks" GUI control in ``ModulesTab`` (covered
separately by the L3 wiring gate in
``tests/ui/process_panel/modules_tab/test_enumerate_heaps_walk_l3.py``).

Every test drives the real ``ProcessBridge`` against live Windows APIs
against the test-runner's own process, per project convention (see
``tests/bridges/test_process_bridge.py``).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path


pytestmark = [
    pytest.mark.skipif(os.name != "nt", reason="Windows only"),
    pytest.mark.asyncio,
]


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, and shutdown a ProcessBridge for the module.

    Yields:
        ProcessBridge: Initialized bridge that will be shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process.

    Args:
        process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.

    Yields:
        ProcessBridge: The shared bridge with an open handle on the current Python process.
    """
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


class TestEnumerateHeapsDistinctFromGetHeapsL1:
    """P-T2-8d: enumerate_heaps walks real per-block data that get_heaps never surfaces."""

    async def test_enumerate_heaps_returns_real_per_block_data(self, attached_bridge: ProcessBridge) -> None:
        """enumerate_heaps must return the same heap set as get_heaps, plus real per-block address/size/flags.

        Falsifiable: if ``enumerate_heaps`` were a thin alias for
        ``get_heaps`` (or its block-walking loop were removed/short-
        circuited), every heap's ``blocks`` list would be empty and this
        test's assertion that at least one heap has a non-empty,
        well-shaped block list would fail.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        pid = os.getpid()
        shallow = await attached_bridge.get_heaps(pid)
        deep = await attached_bridge.enumerate_heaps(pid)

        assert len(shallow) > 0, "the live Python process must have at least one heap"
        assert len(deep) > 0

        assert all(set(h.keys()) == {"heap_id", "flags", "is_default"} for h in shallow), (
            "get_heaps must keep its shallow id/flags/is_default schema"
        )
        assert all(set(h.keys()) == {"id", "flags", "blocks"} for h in deep), (
            "enumerate_heaps must expose id/flags/blocks, distinct from get_heaps's schema"
        )

        shallow_ids = {h["heap_id"] for h in shallow}
        deep_ids = {h["id"] for h in deep}
        assert len(deep_ids & shallow_ids) > 0, (
            f"enumerate_heaps and get_heaps must walk the same real heap list; shallow={shallow_ids!r} deep={deep_ids!r} share no ids"
        )

        heaps_with_blocks = [h for h in deep if h["blocks"]]
        assert heaps_with_blocks, f"at least one real heap must yield a non-empty block walk on a live process; got {deep!r}"

        blocks_raw = cast("list[object]", heaps_with_blocks[0]["blocks"])
        first_block = blocks_raw[0]
        assert isinstance(first_block, dict)
        sample_block = cast("dict[str, object]", first_block)
        assert set(sample_block.keys()) == {"address", "size", "flags"}

        address_val = sample_block["address"]
        size_val = sample_block["size"]
        assert isinstance(address_val, int)
        assert isinstance(size_val, int)
        assert address_val > 0, "a real walked block must report a non-null address"

    async def test_unknown_pid_returns_empty_list_not_raise(self, process_bridge: ProcessBridge) -> None:
        """enumerate_heaps returns an empty list (matching its own snapshot-failure handling) for a dead pid.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        result = await process_bridge.enumerate_heaps(999_999_999)
        assert result == []


class TestEnumerateHeapsToolDefRegistrationL2:
    """L2: process.enumerate_heaps is registered with a schema matching its real signature."""

    def test_tool_function_registered_with_matching_schema(self, process_bridge: ProcessBridge) -> None:
        """process.enumerate_heaps must appear in the tool definition with a pid-only parameter set.

        Falsifiable: before the fix, ``process.enumerate_heaps`` was absent
        from ``_PROCESS_FUNCTIONS`` entirely, so ``functions_by_name``
        would not contain the key and the membership assertion would fail.
        Broken production line: the missing ``ToolFunction(name="process.enumerate_heaps", ...)``
        entry in ``_PROCESS_FUNCTIONS`` (``process.py``).

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        functions_by_name = {f.name: f for f in process_bridge.tool_definition.functions}
        assert "process.enumerate_heaps" in functions_by_name, "process.enumerate_heaps must appear in the registered tool definitions"
        func = functions_by_name["process.enumerate_heaps"]
        actual_params = {p.name for p in func.parameters}
        assert actual_params == {"pid"}, f"process.enumerate_heaps's tool-def parameters {actual_params} do not match {{'pid'}}"

        method = getattr(process_bridge, "enumerate_heaps", None)
        assert callable(method), "tool-def process.enumerate_heaps has no matching callable method enumerate_heaps"

    def test_description_distinguishes_from_get_heaps(self, process_bridge: ProcessBridge) -> None:
        """The registered description must call out the distinction from get_heaps, not just restate it.

        Falsifiable: a description that merely says "enumerate heaps"
        without mentioning ``get_heaps`` or block-level walking would fail
        either substring assertion.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        functions_by_name = {f.name: f for f in process_bridge.tool_definition.functions}
        description = functions_by_name["process.enumerate_heaps"].description.lower()
        assert "get_heaps" in description, "the description must reference get_heaps to make the distinction discoverable"
        assert "block" in description, "the description must call out block-level walking as the distinguishing feature"


class TestEnumerateHeapsDispatchL2:
    """L2: process.enumerate_heaps dispatches through the real ToolRegistry."""

    async def test_execute_tool_call_dispatches_enumerate_heaps(self, tmp_path: Path) -> None:
        """execute_tool_call reaches the real enumerate_heaps implementation for the current process.

        Falsifiable: before the fix, dispatching ``process.enumerate_heaps``
        raised ``ToolError`` (unknown function) because no ``ToolFunction``
        named it; this call would raise instead of returning real heap data.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()
        try:
            process_bridge = registry.get_process_bridge()
            await process_bridge.open_process(os.getpid(), "all")
            try:
                result = await registry.execute_tool_call("process", "process.enumerate_heaps", {"pid": os.getpid()})
            finally:
                await process_bridge.close()

            assert isinstance(result, list)
            heaps = cast("list[dict[str, object]]", result)
            assert len(heaps) > 0, "dispatched call must reach the real bridge method, observing this process's heaps"
            assert all("blocks" in h for h in heaps), "dispatched result must carry the real per-block enumerate_heaps schema"
        finally:
            await registry.shutdown()

    async def test_execute_tool_call_rejects_unknown_tool_name(self, tmp_path: Path) -> None:
        """Dispatching with a bogus tool name must still raise, confirming the dispatch path itself is exercised.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()
        try:
            with pytest.raises(ToolError):
                await registry.execute_tool_call("not_a_real_tool", "not_a_real_tool.enumerate_heaps", {})
        finally:
            await registry.shutdown()
