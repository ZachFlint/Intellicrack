# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the concurrent-run admission governor.

The host driver may be launched by several agents at once. Without a governor
each launch would start a Windows container unconditionally, and oversubscribing
the shared Host Compute Service has bugchecked this host. :mod:`scripts.sandbox.admission`
adds two guarantees these tests exercise against real files, real processes, and
a real cross-process lock -- nothing is mocked:

* :func:`plan_capacity` derives a concurrency budget and a per-run memory/CPU
  share from host resources, so a set of concurrent runs fits with headroom.
* :class:`SlotGate` never lets more than ``budget`` runs hold a slot at once,
  blocks callers until a slot frees, and reclaims slots stranded by a driver
  that died before releasing.

The crown jewel spawns four genuine subprocesses that each take a slot through
the real lock against one shared reservations directory with a budget of two,
and proves that no more than two ever held a slot simultaneously. Break the
budget bookkeeping and the observed overlap exceeds two, reddening the gate.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from scripts.sandbox import docker_sandbox
from scripts.sandbox.admission import (
    AdmissionError,
    Reservation,
    SlotGate,
    count_active_reservations,
    count_occupied_slots,
    pid_from_token,
    plan_capacity,
    select_stale_reservations,
)
from scripts.sandbox.docker_sandbox import SandboxError


if TYPE_CHECKING:
    from collections.abc import Callable


_refuse_rebuild_with_live_siblings = cast(
    "Callable[..., None]",
    vars(docker_sandbox)["_refuse_rebuild_with_live_siblings"],
)

_GIB = 1024**3
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _reservation(dir_path: Path, token: str) -> Reservation:
    """Materialize a reservation file on disk and return its record.

    Args:
        dir_path: Directory the reservation file is written to.
        token: The run token naming the reservation file.

    Returns:
        Reservation: The record describing the written file.
    """
    dir_path.mkdir(parents=True, exist_ok=True)
    path = dir_path / token
    path.write_text("0\n", encoding="utf-8")
    return Reservation(token=token, pid=pid_from_token(token), path=path)


def test_plan_gives_a_large_host_several_slots_that_fit() -> None:
    """A 96 GiB / 24-core host admits multiple runs whose shares fit in RAM."""
    plan = plan_capacity(96 * _GIB, 24)

    assert plan.slots >= 2, f"a 96 GiB host should permit concurrent runs, got {plan.slots}"
    per_run_gib = int(plan.memory.removesuffix("g"))
    assert plan.slots * per_run_gib <= 96, f"{plan.slots} runs of {plan.memory} exceed host memory"
    assert per_run_gib >= 12, f"per-run memory {plan.memory} is below the healthy floor"


def test_plan_gives_a_small_host_a_single_slot() -> None:
    """A 16 GiB / 8-core host is capped at one run so it is not oversubscribed."""
    plan = plan_capacity(16 * _GIB, 8)

    assert plan.slots == 1, f"a 16 GiB host must not run several containers at once, got {plan.slots}"


def test_pinned_memory_shrinks_the_budget_and_is_honoured() -> None:
    """A large explicit --memory both is preserved and reduces the slot count."""
    auto = plan_capacity(96 * _GIB, 24)
    pinned = plan_capacity(96 * _GIB, 24, requested_memory="48g")

    assert pinned.memory == "48g", "an explicit --memory must be forwarded verbatim"
    assert pinned.slots < auto.slots, "a larger per-run reservation must permit fewer concurrent runs"
    assert pinned.slots * 48 <= 96, "pinned runs must still fit within host memory"


def test_budget_is_capped_regardless_of_host_size() -> None:
    """A very large host is still capped: extra HCS tenants are the real risk."""
    plan = plan_capacity(512 * _GIB, 128)

    assert plan.slots <= 4, f"the concurrency budget must stay bounded, got {plan.slots}"


def test_pid_round_trips_through_a_run_token() -> None:
    """The launching pid encoded in a run token is recovered exactly."""
    assert pid_from_token("module_08-06-2026_14-22_p20164-9fa3c1") == 20164
    assert pid_from_token("custom_08-06-2026_14-22_p7-ab.def") == 7
    assert pid_from_token("not-a-token") is None
    assert pid_from_token("module_08-06-2026_14-22_xyz-9fa3c1") is None


def test_dead_owner_reservations_are_classified_stale() -> None:
    """A reservation is stale once neither its pid nor its container is live."""
    live = Reservation(token="module_ts_p100-aaaaaa", pid=100, path=Path("a"))
    container = Reservation(token="module_ts_p200-bbbbbb", pid=200, path=Path("b"))
    dead = Reservation(token="module_ts_p300-cccccc", pid=300, path=Path("c"))

    stale = select_stale_reservations(
        (live, container, dead),
        frozenset({"module_ts_p200-bbbbbb"}),
        frozenset({100}),
    )

    assert stale == (dead,), f"only the dead-owner reservation should be stale: {stale!r}"


def test_active_count_excludes_own_token_and_dead_owners() -> None:
    """Occupancy counts only in-flight siblings, never one's own reservation."""
    own = Reservation(token="module_ts_p1-aaaaaa", pid=1, path=Path("a"))
    sibling = Reservation(token="module_ts_p2-bbbbbb", pid=2, path=Path("b"))
    dead = Reservation(token="module_ts_p3-cccccc", pid=3, path=Path("c"))

    count = count_active_reservations(
        (own, sibling, dead),
        frozenset(),
        frozenset({1, 2}),
        exclude_token="module_ts_p1-aaaaaa",
    )

    assert count == 1, f"only the live sibling should count against the budget, got {count}"


def test_occupancy_counts_a_live_container_without_a_reservation() -> None:
    """A running container that owns no reservation still consumes a slot.

    This is the transition and bypass case: a run started by a driver that
    predates the gate, or otherwise outside it, owns a live container but no
    reservation file. Counting only reservations would let the budget be
    exceeded; the union with running-container tokens keeps it a true ceiling.
    """
    legacy_token = "unit_08-16-2026_03-04_p27184-7f96c9"
    own_reservation = Reservation(token="custom_ts_p1-aaaaaa", pid=1, path=Path("a"))

    occupied = count_occupied_slots(
        (own_reservation,),
        frozenset({legacy_token}),
        frozenset({1}),
        exclude_token="custom_ts_p1-aaaaaa",
    )

    assert occupied == 1, f"a live container without a reservation must count against the budget, got {occupied}"


def test_gate_refuses_admission_when_an_untracked_container_fills_the_host(tmp_path: Path) -> None:
    """With one untracked live container and a budget of one, no new run is admitted.

    Args:
        tmp_path: Pytest-provided temporary directory holding the reservations.
    """
    slots_dir = tmp_path / "slots"
    legacy_token = "unit_08-16-2026_03-04_p27184-7f96c9"
    gate = SlotGate(
        slots_dir,
        budget=1,
        live_tokens=lambda: frozenset({legacy_token}),
        alive_pids=frozenset,
        wait_timeout=0.4,
        poll=0.05,
    )

    with pytest.raises(AdmissionError):
        gate.acquire("custom_ts_p999-bbbbbb")


def test_gate_blocks_when_full_then_admits_after_release(tmp_path: Path) -> None:
    """A single-slot gate refuses a second run until the first releases.

    Args:
        tmp_path: Pytest-provided temporary directory holding the reservations.
    """
    slots_dir = tmp_path / "slots"
    busy_token = "module_ts_p424242-aaaaaa"
    _reservation(slots_dir, busy_token)
    gate = SlotGate(
        slots_dir,
        budget=1,
        live_tokens=frozenset,
        alive_pids=lambda: frozenset({424242}),
        wait_timeout=0.4,
        poll=0.05,
    )

    with pytest.raises(AdmissionError):
        gate.acquire("module_ts_p999-bbbbbb")

    # The busy owner exits: its pid is no longer alive, so its slot is reclaimed.
    freed_gate = SlotGate(
        slots_dir,
        budget=1,
        live_tokens=frozenset,
        alive_pids=frozenset,
        wait_timeout=0.4,
        poll=0.05,
    )
    handle = freed_gate.acquire("module_ts_p999-bbbbbb")

    assert handle.path.is_file(), "an admitted run must leave a reservation on disk"
    assert not (slots_dir / busy_token).exists(), "the stale busy reservation should have been reaped"
    handle.release()
    assert not handle.path.exists(), "releasing a slot must remove its reservation file"


def test_gate_reclaims_a_slot_stranded_by_a_dead_driver(tmp_path: Path) -> None:
    """A reservation whose owner died never permanently consumes a slot.

    Args:
        tmp_path: Pytest-provided temporary directory holding the reservations.
    """
    slots_dir = tmp_path / "slots"
    stranded = "module_ts_p777777-dddddd"
    _reservation(slots_dir, stranded)
    gate = SlotGate(
        slots_dir,
        budget=1,
        live_tokens=frozenset,
        alive_pids=frozenset,
        wait_timeout=1.0,
        poll=0.05,
    )

    handle = gate.acquire("module_ts_p888-eeeeee")

    assert not (slots_dir / stranded).exists(), "the dead driver's reservation should be reaped"
    assert handle.path.is_file()
    handle.release()


_CHILD_SCRIPT = textwrap.dedent(
    """\
    import sys
    import time
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])

    import psutil

    from scripts.sandbox.admission import SlotGate
    from scripts.sandbox.test_types import TestRunSpec, TestType, run_token

    slots_dir = Path(sys.argv[2])
    budget = int(sys.argv[3])
    hold = float(sys.argv[4])
    out_file = Path(sys.argv[5])

    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp="00-00-0000_00-00")
    gate = SlotGate(
        slots_dir,
        budget=budget,
        live_tokens=frozenset,
        alive_pids=lambda: frozenset(psutil.pids()),
        wait_timeout=120.0,
        poll=0.05,
        lock_poll=0.02,
    )

    handle = gate.acquire(run_token(spec))
    acquired = time.time()
    time.sleep(hold)
    released = time.time()
    handle.release()
    out_file.write_text(f"{acquired} {released}\\n", encoding="utf-8")
    """,
)


def _max_overlap(intervals: list[tuple[float, float]]) -> int:
    """Return the greatest number of intervals overlapping at any instant.

    Args:
        intervals: ``(start, end)`` pairs of wall-clock hold windows.

    Returns:
        int: The peak simultaneous count.
    """
    events: list[tuple[float, int]] = []
    for start, end in intervals:
        events.extend(((start, 1), (end, -1)))
    events.sort()
    current = 0
    peak = 0
    for _, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


@pytest.mark.skipif(sys.platform != "win32", reason="the admission lock uses the Windows msvcrt byte-range lock")
def test_four_processes_never_exceed_a_budget_of_two(tmp_path: Path) -> None:
    """Four real drivers contending for a two-slot host never run three at once.

    This is the guarantee the whole governor exists to provide: independent
    processes, coordinating only through the shared lock and reservation files,
    must be bounded to the budget. If the counting or the lock were broken, all
    four would overlap and the observed peak would exceed two.

    Args:
        tmp_path: Pytest-provided temporary directory holding the reservations
            and each child's recorded hold window.
    """
    script = tmp_path / "child.py"
    script.write_text(_CHILD_SCRIPT, encoding="utf-8")
    slots_dir = tmp_path / "slots"
    budget = 2
    hold = 1.5
    child_count = 4

    processes: list[tuple[subprocess.Popen[bytes], Path]] = []
    for index in range(child_count):
        out_file = tmp_path / f"child_{index}.txt"
        proc = subprocess.Popen(
            [sys.executable, str(script), str(_REPO_ROOT), str(slots_dir), str(budget), str(hold), str(out_file)],
            cwd=str(_REPO_ROOT),
        )
        processes.append((proc, out_file))

    deadline = time.monotonic() + 180.0
    for proc, _ in processes:
        remaining = max(1.0, deadline - time.monotonic())
        assert proc.wait(timeout=remaining) == 0, "a contending child driver exited non-zero"

    intervals: list[tuple[float, float]] = []
    for _, out_file in processes:
        assert out_file.is_file(), f"a child never recorded its hold window: {out_file}"
        start_text, end_text = out_file.read_text(encoding="utf-8").split()
        intervals.append((float(start_text), float(end_text)))

    peak = _max_overlap(intervals)
    assert peak <= budget, f"more than {budget} runs held a slot at once (peak {peak}) -- the budget was not enforced"
    assert peak == budget, f"the gate serialized runs it should have allowed to overlap (peak {peak})"


def test_rebuild_is_refused_while_a_sibling_container_runs() -> None:
    """A forced rebuild is rejected while any sandbox container is running."""
    running = frozenset({"intellicrack-sandbox-module_ts_p1-aaaaaa"})

    with pytest.raises(SandboxError, match="rebuild"):
        _refuse_rebuild_with_live_siblings(rebuild=True, running_containers=running)

    # No siblings, or no rebuild requested: the call is a no-op.
    _refuse_rebuild_with_live_siblings(rebuild=True, running_containers=frozenset())
    _refuse_rebuild_with_live_siblings(rebuild=False, running_containers=running)
