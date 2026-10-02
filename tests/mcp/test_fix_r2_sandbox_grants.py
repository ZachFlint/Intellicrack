# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 6: a sandboxed server's write access lasts only as long as the server, covers only what it must, and never stalls the loop.

Windows gives a directory Low integrity write access through its mandatory label, so every gate here reads and writes real labels on real
directories, and the end-to-end gates run a real ``MCPServer`` confined at Low integrity. They can only run on Windows and are skipped
elsewhere with the behaviour they cover named in the reason. The ledger file every grant is recorded in is pointed at the test's own
directory, so no gate touches the developer's configuration.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.mcp.config import McpSandboxSpec
from intellicrack.mcp.sandbox_launch import (
    GRANTS_FILENAME,
    WriteGrantLedger,
    read_mandatory_label,
    revert_stale_write_grants,
)
from tests._helpers.mcp_lifecycle_support import approving_gate, call_text, connection_for, stdio_config


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows mandatory integrity labels: a Low label granted on a sandbox write path for the server's lifetime and reverted after",
)

_LOW: Final[str] = "LW"
_CONNECT_TIMEOUT_S: Final[float] = 120.0
_TEARDOWN_TIMEOUT_S: Final[float] = 60.0
_TREE_FILES: Final[int] = 4000
_MAX_LOOP_STALL_S: Final[float] = 0.5


@pytest.fixture(autouse=True)
def private_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point Intellicrack's configuration directory at the test's own directory.

    Args:
        tmp_path: Per-test directory, which Windows places under the user's local application data.
        monkeypatch: Restores the environment afterwards.

    Returns:
        Path: The state directory.
    """
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state))
    return state


def _work(tmp_path: Path) -> Path:
    """Create the sandbox's writable directory with one file already in it.

    Args:
        tmp_path: Per-test directory.

    Returns:
        Path: The directory.
    """
    work = tmp_path / "work"
    work.mkdir()
    (work / "before.txt").write_text("the operator's file", encoding="utf-8")
    return work


def _sandbox(work: Path, *, existing: bool = False) -> McpSandboxSpec:
    """Build a sandbox writing only to one directory.

    Args:
        work: The writable directory.
        existing: Whether content already there becomes writable.

    Returns:
        McpSandboxSpec: The sandbox.
    """
    return McpSandboxSpec(enabled=True, allow_write=(str(work),), write_existing=existing)


async def _probe(tmp_path: Path, server_id: str, sandbox: McpSandboxSpec, paths: list[Path]) -> list[str]:
    """Run a confined server, ask it to write each path, and stop it.

    Args:
        tmp_path: Per-test directory.
        server_id: The server id.
        sandbox: The sandbox it runs in.
        paths: The files it tries to write.

    Returns:
        list[str]: ``written`` or ``denied: ...`` for each path.
    """
    connection = connection_for(stdio_config(server_id, sandbox=sandbox), approving_gate(tmp_path / f"{server_id}-trust.json"))
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        return [await call_text(connection, "write_probe", {"path": str(path)}) for path in paths]
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


class TestGrantLastsOnlyAsLongAsTheServer:
    """The label is on while the server runs and gone when it stops."""

    def test_new_files_are_writable_and_the_label_is_reverted(self, tmp_path: Path) -> None:
        """The server can add a file but not change one already there, and afterwards nothing carries a Low label.

        Args:
            tmp_path: Per-test directory.
        """
        work = _work(tmp_path)
        original = read_mandatory_label(str(work))
        before_file = read_mandatory_label(str(work / "before.txt"))

        added, changed = asyncio.run(_probe(tmp_path, "grants", _sandbox(work), [work / "added.txt", work / "before.txt"]))

        assert added == "written"
        assert changed.startswith("denied"), "a file that existed before the server started was writable to it"
        assert (work / "before.txt").read_text(encoding="utf-8") == "the operator's file"
        assert read_mandatory_label(str(work)) == original
        assert _LOW not in read_mandatory_label(str(work / "added.txt"))
        assert read_mandatory_label(str(work / "before.txt")) == before_file

    def test_write_existing_reaches_existing_files_and_is_reverted(self, tmp_path: Path) -> None:
        """With ``writeExisting`` the server may change what was there; afterwards every label is back.

        Args:
            tmp_path: Per-test directory.
        """
        work = _work(tmp_path)
        original = read_mandatory_label(str(work))
        before_file = read_mandatory_label(str(work / "before.txt"))

        [changed] = asyncio.run(_probe(tmp_path, "existing", _sandbox(work, existing=True), [work / "before.txt"]))

        assert changed == "written"
        assert read_mandatory_label(str(work)) == original
        assert read_mandatory_label(str(work / "before.txt")) == before_file

    def test_another_low_process_cannot_write_after_the_server_stops(self, tmp_path: Path) -> None:
        """Once the first server has stopped, a second Low integrity server cannot write to the first one's folder.

        Args:
            tmp_path: Per-test directory.
        """
        work = _work(tmp_path)
        other = tmp_path / "other"
        other.mkdir()
        _ = asyncio.run(_probe(tmp_path, "first", _sandbox(work), [work / "first.txt"]))

        [late] = asyncio.run(_probe(tmp_path, "second", _sandbox(other), [work / "late.txt"]))

        assert late.startswith("denied"), "a Low integrity process could still write where an earlier server was allowed to"
        assert not (work / "late.txt").exists()

    def test_the_ledger_is_empty_after_the_server_stops(self, tmp_path: Path, private_state_dir: Path) -> None:
        """No grant stays recorded once the server has stopped.

        Args:
            tmp_path: Per-test directory.
            private_state_dir: The redirected state directory.
        """
        work = _work(tmp_path)
        _ = asyncio.run(_probe(tmp_path, "ledger", _sandbox(work), [work / "x.txt"]))

        ledger = private_state_dir / ".intellicrack" / GRANTS_FILENAME
        assert json.loads(ledger.read_text(encoding="utf-8")) == {}


class TestLedger:
    """Grants are counted per directory and survive a crash on disk."""

    def test_shared_directory_reverts_only_when_the_last_holder_releases(self, tmp_path: Path) -> None:
        """Two holders of one directory keep the label until both have let go.

        Args:
            tmp_path: Per-test directory.
        """
        work = _work(tmp_path)
        original = read_mandatory_label(str(work))
        ledger = WriteGrantLedger(tmp_path / "grants.json")

        first = ledger.acquire(str(work), existing=False)
        second = ledger.acquire(str(work), existing=False)
        ledger.release(first)
        assert _LOW in read_mandatory_label(str(work))
        ledger.release(second)

        assert read_mandatory_label(str(work)) == original

    def test_a_grant_left_by_a_crash_is_reverted_at_the_next_start(self, tmp_path: Path, private_state_dir: Path) -> None:
        """A grant recorded by a process that never released it is reverted by the next one.

        Args:
            tmp_path: Per-test directory.
            private_state_dir: The redirected state directory.
        """
        work = _work(tmp_path)
        original = read_mandatory_label(str(work))
        crashed = WriteGrantLedger(private_state_dir / ".intellicrack" / GRANTS_FILENAME)
        _ = crashed.acquire(str(work), existing=True)
        assert _LOW in read_mandatory_label(str(work / "before.txt"))

        reverted = revert_stale_write_grants()

        assert reverted == 1
        assert read_mandatory_label(str(work)) == original
        assert _LOW not in read_mandatory_label(str(work / "before.txt"))


def test_labelling_a_large_tree_never_stalls_the_event_loop(tmp_path: Path) -> None:
    """Relabelling thousands of files happens off the loop, which keeps ticking throughout.

    Args:
        tmp_path: Per-test directory.
    """
    work = _work(tmp_path)
    for index in range(_TREE_FILES):
        (work / f"f{index:05}.txt").write_text("x", encoding="utf-8")
    sandbox = _sandbox(work, existing=True)

    async def _run() -> float:
        """Connect while a ticker measures the longest gap between ticks.

        Returns:
            float: The longest gap, in seconds.
        """
        stop = asyncio.Event()
        longest = 0.0

        async def _tick() -> None:
            nonlocal longest
            last = time.perf_counter()
            while not stop.is_set():
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                longest = max(longest, now - last)
                last = now

        ticker = asyncio.create_task(_tick())
        try:
            _ = await _probe(tmp_path, "tree", sandbox, [work / "new.txt"])
        finally:
            stop.set()
            await ticker
        return longest

    assert asyncio.run(_run()) < _MAX_LOOP_STALL_S
