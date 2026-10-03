# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: a write grant held by a running process is not reverted by another process's start.

Every start reverts the write grants a previous run left behind. "Left behind"
was decided as "recorded, and not held by this process", which also describes
every grant held by a second Intellicrack running beside this one: starting one
took the Low integrity label off the directories the other's sandboxed servers
were writing to, and those servers were refused from then on. On CI two test
workers share one state directory, and a manager starting in one worker made a
confined server in the other fail its write with "Permission denied".

A recorded grant now names the process that made it, and a grant whose owner is
still running is left alone. The gate holds a real grant in a real second
process, runs the stale sweep beside it, and then lets that process end without
reverting.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.mcp.sandbox_launch import WriteGrantLedger, read_mandatory_label
from tests._helpers.child_python import run_child_json


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows mandatory integrity labels: a Low label granted on a sandbox write path and reverted when its owner is gone",
)

_LOW: Final[str] = "LW"
_CHILD_TIMEOUT_S: Final[float] = 120.0
_HOLDER_START_TIMEOUT_S: Final[float] = 60.0
_POLL_S: Final[float] = 0.05


def test_a_grant_held_by_a_running_process_outlives_another_processes_sweep(tmp_path: Path) -> None:
    """A stale sweep leaves a running process's grant in force and reverts it once that process is gone.

    Falsifiable: a sweep that reverts everything this process does not hold
    takes the Low label off the directory while the process that granted it
    is still running.

    Args:
        tmp_path: Per-test directory holding the granted directory and the ledger.
    """
    work = tmp_path / "work"
    work.mkdir()
    ledger_path = tmp_path / "grants.json"
    holding = tmp_path / "holding.marker"
    finish = tmp_path / "finish.marker"
    original = read_mandatory_label(str(work))
    code = f"""
        import json
        import time
        from pathlib import Path

        from intellicrack.mcp.sandbox_launch import WriteGrantLedger

        ledger = WriteGrantLedger(Path({str(ledger_path)!r}))
        ledger.acquire({str(work)!r}, existing=False)
        Path({str(holding)!r}).write_text("held", encoding="utf-8")
        deadline = time.monotonic() + {_CHILD_TIMEOUT_S!r}
        while not Path({str(finish)!r}).exists() and time.monotonic() < deadline:
            time.sleep({_POLL_S!r})
        print(json.dumps({{"ended_without_reverting": True}}))
    """
    outcomes: list[dict[str, object]] = []
    failures: list[AssertionError] = []

    def _run_holder() -> None:
        """Run the process that holds the grant."""
        try:
            outcomes.append(run_child_json(code, timeout_s=_CHILD_TIMEOUT_S))
        except AssertionError as exc:
            failures.append(exc)

    holder = threading.Thread(target=_run_holder)
    holder.start()
    try:
        deadline = time.monotonic() + _HOLDER_START_TIMEOUT_S
        while not holding.exists() and time.monotonic() < deadline:
            time.sleep(_POLL_S)
        assert holding.exists(), f"the holding process never made its grant: {failures}"

        reverted_while_held = WriteGrantLedger(ledger_path).revert_stale()
        label_while_held = read_mandatory_label(str(work))
    finally:
        finish.write_text("go", encoding="utf-8")
        holder.join(timeout=_CHILD_TIMEOUT_S)

    assert failures == []
    assert outcomes == [{"ended_without_reverting": True}]
    assert reverted_while_held == 0, "a sweep reverted a grant whose owner was still running"
    assert _LOW in label_while_held, "the Low label was taken off a directory a running process had been granted"

    assert WriteGrantLedger(ledger_path).revert_stale() == 1
    assert read_mandatory_label(str(work)) == original
