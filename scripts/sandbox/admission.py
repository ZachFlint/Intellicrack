# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Host-wide admission control for concurrent sandbox container runs.

Several independent :mod:`scripts.sandbox.docker_sandbox` processes -- one per
agent or session -- may drive the Windows test container at the same time on a
single host. Windows containers, WHPX virtual machines, and Windows Sandbox all
share the Host Compute Service, so oversubscribing the host does not merely slow
a run down: interleaving too many at once has bugchecked this machine. The
per-run identity work already keeps concurrent runs from clobbering each other's
artifacts; this module adds the missing governor that bounds *how many* run at
once and sizes each run's memory and CPU share so the concurrent set fits.

Two concerns live here, each expressed as pure, testable logic:

* :func:`plan_capacity` derives, from the host's total memory and CPU count, how
  many containers may run concurrently and the per-run ``docker run --memory`` /
  ``--cpus`` share that lets that many coexist with headroom for the host and
  Docker's own utility VM.
* :class:`SlotGate` enforces that budget across processes. Admission is
  serialized by a cross-process lock; occupancy is tracked with per-run
  reservation files whose liveness is judged by the owning process id and by the
  set of running sandbox containers, so a driver killed abruptly never strands a
  slot. When every slot is occupied the gate blocks and waits -- agents queue
  naturally rather than failing -- until a slot frees or a bounded deadline
  expires.

The gate takes its Docker and process-liveness inputs as injected callables so
it carries no dependency on the driver module and can be exercised end to end
against real files and real concurrent processes.
"""

from __future__ import annotations

import math
import msvcrt
import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path
    from typing import IO


_BYTES_PER_GIB = 1024**3

# A single run needs at least this much to keep the Windows Python/Qt/LIEF stack
# from thrashing or being OOM-killed mid-suite; measured healthy on this host.
_PER_RUN_MEMORY_FLOOR_GIB = 12
_PER_RUN_CPU_FLOOR = 4

# Leave the host OS and Docker Desktop's utility VM room to breathe. The reserve
# is the larger of a flat floor and a fraction of total memory so it scales with
# the machine.
_MEMORY_RESERVE_FRACTION = 0.15
_MEMORY_RESERVE_FLOOR_GIB = 8
_CPU_HEADROOM = 2

# Even on a very large box, keep the concurrent container count sane: every
# extra Windows container is another Host Compute Service tenant, and the crash
# this whole module guards against was about HCS pressure, not raw RAM.
_MAX_SLOTS_HARD_CAP = 4

_DEFAULT_RESERVATIONS_DIRNAME = ".sandbox_slots"
_DEFAULT_LOCK_FILENAME = "gate.lock"

_SLOT_WAIT_TIMEOUT_SECONDS = 14400.0
_SLOT_POLL_INTERVAL_SECONDS = 5.0
_LOCK_ACQUIRE_TIMEOUT_SECONDS = 120.0
_LOCK_POLL_INTERVAL_SECONDS = 0.1

_MEMORY_UNIT_MULTIPLIERS: dict[str, int] = {
    "b": 1,
    "k": 1024,
    "m": 1024**2,
    "g": 1024**3,
}


class AdmissionError(RuntimeError):
    """Raised when a run cannot be admitted within its wait budget.

    Signals that every concurrency slot stayed occupied until the deadline
    expired, or that the cross-process admission lock could not be acquired.
    Distinct from a container failure: no test ran.
    """


@dataclass(frozen=True, slots=True)
class CapacityPlan:
    """Resolved concurrency budget and per-run resource share for this host.

    Attributes:
        slots: Maximum number of sandbox containers permitted to run at once.
        memory: Per-run ``docker run --memory`` value, for example ``"20g"``.
        cpus: Per-run ``docker run --cpus`` value, for example ``"5"``.
    """

    slots: int
    memory: str
    cpus: str


@dataclass(frozen=True, slots=True)
class Reservation:
    """One run's claim on a concurrency slot, recovered from a reservation file.

    Attributes:
        token: The run token identifying the claiming run.
        pid: The launching driver's process id, or ``None`` when it could not be
            recovered from the token.
        path: Absolute path of the reservation file on disk.
    """

    token: str
    pid: int | None
    path: Path


def _memory_string_to_gib(value: str) -> int:
    """Convert a Docker-style memory size to whole gibibytes.

    Args:
        value: A size string such as ``"32g"``, ``"512m"``, or a plain byte
            count. A trailing ``b``/``k``/``m``/``g`` unit (case-insensitive) is
            honoured; a bare number is read as bytes.

    Returns:
        int: The size floored to whole gibibytes, never below 1.

    Raises:
        ValueError: If ``value`` is empty or not a parseable size.
    """
    text = value.strip().lower()
    if not text:
        message = "memory size string is empty"
        raise ValueError(message)
    unit = text[-1]
    if unit in _MEMORY_UNIT_MULTIPLIERS:
        magnitude = text[:-1]
        multiplier = _MEMORY_UNIT_MULTIPLIERS[unit]
    else:
        magnitude = text
        multiplier = 1
    try:
        number = float(magnitude)
    except ValueError as exc:
        message = f"unparseable memory size: {value!r}"
        raise ValueError(message) from exc
    gib = int(number * multiplier) // _BYTES_PER_GIB
    return max(1, gib)


def plan_capacity(
    total_memory_bytes: int,
    cpu_count: int,
    *,
    requested_memory: str | None = None,
    requested_cpus: str | None = None,
) -> CapacityPlan:
    """Derive the concurrency budget and per-run resource share for a host.

    The budget is the largest number of runs that fit once a reserve is set
    aside for the host OS and Docker's utility VM, bounded by
    :data:`_MAX_SLOTS_HARD_CAP`. When the operator does not pin the per-run size
    it defaults to a healthy floor for the budget calculation and is then grown
    to tile the usable capacity across the chosen slots, so a lightly loaded host
    gives each run a generous share while a fully loaded one still fits. When the
    operator pins ``--memory`` or ``--cpus`` that value is honoured verbatim and
    the budget shrinks to whatever number of such runs fits.

    Args:
        total_memory_bytes: Total physical memory reported for the host.
        cpu_count: Logical CPU count reported for the host.
        requested_memory: Operator-pinned ``--memory`` value, or ``None`` to
            size memory automatically.
        requested_cpus: Operator-pinned ``--cpus`` value, or ``None`` to size
            CPU share automatically.

    Returns:
        CapacityPlan: The resolved slot budget and per-run memory/CPU share.
    """
    total_gib = max(1, total_memory_bytes // _BYTES_PER_GIB)
    reserve_gib = max(_MEMORY_RESERVE_FLOOR_GIB, math.ceil(total_gib * _MEMORY_RESERVE_FRACTION))
    usable_memory_gib = max(_PER_RUN_MEMORY_FLOOR_GIB, total_gib - reserve_gib)
    usable_cpus = max(_PER_RUN_CPU_FLOOR, cpu_count - _CPU_HEADROOM)

    pinned_memory = requested_memory is not None
    pinned_cpus = requested_cpus is not None
    per_run_memory_gib = _memory_string_to_gib(requested_memory) if requested_memory is not None else _PER_RUN_MEMORY_FLOOR_GIB
    per_run_cpus = _positive_int(requested_cpus, _PER_RUN_CPU_FLOOR) if requested_cpus is not None else _PER_RUN_CPU_FLOOR

    slots_by_memory = max(1, usable_memory_gib // per_run_memory_gib)
    slots_by_cpus = max(1, usable_cpus // per_run_cpus)
    slots = max(1, min(slots_by_memory, slots_by_cpus, _MAX_SLOTS_HARD_CAP))

    if not pinned_memory:
        per_run_memory_gib = max(_PER_RUN_MEMORY_FLOOR_GIB, usable_memory_gib // slots)
    if not pinned_cpus:
        per_run_cpus = max(_PER_RUN_CPU_FLOOR, usable_cpus // slots)

    memory_value = requested_memory if requested_memory is not None else f"{per_run_memory_gib}g"
    cpus_value = requested_cpus if requested_cpus is not None else str(per_run_cpus)
    return CapacityPlan(slots=slots, memory=memory_value, cpus=cpus_value)


def _positive_int(value: str, fallback: int) -> int:
    """Parse a positive integer from a CLI string, falling back when invalid.

    Args:
        value: The raw string to parse (for example a ``--cpus`` value).
        fallback: Value returned when ``value`` is not a positive integer.

    Returns:
        int: The parsed positive integer, or ``fallback``.
    """
    try:
        parsed = int(float(value))
    except ValueError:
        return fallback
    return parsed if parsed > 0 else fallback


def pid_from_token(token: str) -> int | None:
    """Recover the launching driver's process id encoded in a run token.

    A run token ends in the run id ``p<pid>-<hex>`` produced by
    :func:`scripts.sandbox.test_types.new_run_id`, so the owning process id can
    be read back without opening the reservation file.

    Args:
        token: The run token, for example
            ``module_08-06-2026_14-22_p20164-9fa3c1``.

    Returns:
        int | None: The process id, or ``None`` when the token does not carry a
            recoverable one.
    """
    _, separator, run_id = token.rpartition("_")
    if not separator or not run_id.startswith("p"):
        return None
    digits = run_id[1:].split("-", 1)[0]
    return int(digits) if digits.isdigit() else None


def _reservation_is_active(
    reservation: Reservation,
    live_tokens: frozenset[str],
    alive_pids: frozenset[int],
) -> bool:
    """Report whether a reservation still represents an in-flight run.

    A reservation is active while either its launching driver is alive or its
    container is running. Both checks are needed: a driver stays alive across the
    whole ``docker run`` it supervises, but a driver killed abruptly leaves the
    detached container running, so neither signal alone is sufficient.

    Args:
        reservation: The reservation to classify.
        live_tokens: Tokens of runs whose container is currently running.
        alive_pids: Process ids currently alive on the host.

    Returns:
        bool: ``True`` when the reservation is still in flight.
    """
    if reservation.token in live_tokens:
        return True
    return reservation.pid is not None and reservation.pid in alive_pids


def select_stale_reservations(
    reservations: Iterable[Reservation],
    live_tokens: frozenset[str],
    alive_pids: frozenset[int],
) -> tuple[Reservation, ...]:
    """Return reservations left behind by runs that are no longer in flight.

    Args:
        reservations: Reservations recovered from the reservations directory.
        live_tokens: Tokens of runs whose container is currently running.
        alive_pids: Process ids currently alive on the host.

    Returns:
        tuple[Reservation, ...]: Reservations whose owning run has ended, safe to
            delete so their slot is reclaimed.
    """
    return tuple(
        reservation
        for reservation in reservations
        if not _reservation_is_active(reservation, live_tokens, alive_pids)
    )


def count_active_reservations(
    reservations: Iterable[Reservation],
    live_tokens: frozenset[str],
    alive_pids: frozenset[int],
    *,
    exclude_token: str,
) -> int:
    """Count reservations representing in-flight runs other than one's own.

    Args:
        reservations: Reservations recovered from the reservations directory.
        live_tokens: Tokens of runs whose container is currently running.
        alive_pids: Process ids currently alive on the host.
        exclude_token: The caller's own run token, never counted against it.

    Returns:
        int: The number of occupied slots.
    """
    return sum(
        1
        for reservation in reservations
        if reservation.token != exclude_token
        and _reservation_is_active(reservation, live_tokens, alive_pids)
    )


def count_occupied_slots(
    reservations: Iterable[Reservation],
    live_tokens: frozenset[str],
    alive_pids: frozenset[int],
    *,
    exclude_token: str,
) -> int:
    """Count the distinct runs occupying a slot, however they were started.

    Occupancy is the union of two independent signals so the budget bounds the
    real number of Host Compute Service tenants, not merely the runs that passed
    through this gate:

    * every active reservation (an admitted run, whose container may not have
      appeared yet), and
    * every running sandbox container -- including one started by a driver that
      predates this gate or that bypassed it, which owns no reservation file.

    A run counted by both signals is counted once. The caller's own token is
    always excluded.

    Args:
        reservations: Reservations recovered from the reservations directory.
        live_tokens: Tokens of runs whose container is currently running.
        alive_pids: Process ids currently alive on the host.
        exclude_token: The caller's own run token, never counted against it.

    Returns:
        int: The number of distinct runs holding a slot.
    """
    occupied = {token for token in live_tokens if token != exclude_token}
    for reservation in reservations:
        if reservation.token == exclude_token:
            continue
        if _reservation_is_active(reservation, live_tokens, alive_pids):
            occupied.add(reservation.token)
    return len(occupied)


class _CrossProcessLock:
    """A bounded, cross-process mutual-exclusion lock backed by a lock file.

    The lock is held on an open file handle, so the operating system releases it
    automatically if the holding process dies mid-critical-section -- no stale
    lock can wedge the host. On Windows the lock is a ``msvcrt`` byte-range lock;
    elsewhere it is an ``fcntl`` exclusive lock.
    """

    def __init__(self, path: Path) -> None:
        """Initialize the lock over a given lock-file path.

        Args:
            path: Path to the lock file; created on first acquire.
        """
        self._path = path
        self._handle: IO[bytes] | None = None

    def acquire(self, *, timeout: float, poll: float, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        """Acquire the lock, blocking until it is free or the deadline expires.

        Args:
            timeout: Maximum seconds to wait for the lock.
            poll: Seconds between acquisition attempts.
            clock: Monotonic clock used to measure the deadline.
            sleep: Sleep function invoked between attempts.

        Raises:
            AdmissionError: If the lock cannot be acquired within ``timeout``.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("a+b")
        deadline = clock() + timeout
        while True:
            if self._try_lock(handle):
                self._handle = handle
                return
            if clock() >= deadline:
                handle.close()
                message = f"could not acquire the sandbox admission lock within {timeout:.0f}s"
                raise AdmissionError(message)
            sleep(poll)

    @staticmethod
    def _try_lock(handle: IO[bytes]) -> bool:
        """Attempt a single non-blocking lock of the handle's first byte.

        Args:
            handle: The open binary file handle to lock.

        Returns:
            bool: ``True`` when the lock was taken, ``False`` when it is held
                elsewhere.
        """
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def release(self) -> None:
        """Release the lock and close its file handle.

        Safe to call when the lock is not held; does nothing in that case.
        """
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()


class SlotHandle:
    """A held concurrency slot, released when its run's container exits.

    Attributes:
        token: The run token this slot was granted to.
        path: Path of the reservation file backing the slot.
    """

    token: str
    path: Path

    def __init__(self, token: str, path: Path) -> None:
        """Initialize a handle over a granted reservation.

        Args:
            token: The run token the slot was granted to.
            path: Path of the reservation file backing the slot.
        """
        self.token = token
        self.path = path
        self._released = False

    def release(self) -> None:
        """Release the slot by removing its reservation file.

        Idempotent and tolerant of a file already gone, so it is safe to call
        from a ``finally`` block after any run outcome.
        """
        if self._released:
            return
        self._released = True
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            # A slot whose file cannot be removed is reclaimed later by the
            # stale-reservation reaper on the owning pid's death; never fail a
            # completed run over cleanup.
            return


class SlotGate:
    """Serialized, budget-bounded admission control for sandbox runs.

    The gate admits a run only while fewer than ``budget`` slots are occupied.
    Admission decisions are serialized by a cross-process lock so two processes
    cannot both observe a free slot and both take it. Occupancy is derived from
    reservation files, and stale reservations are reclaimed on every admission
    attempt, so a driver killed abruptly cannot permanently consume a slot.
    """

    def __init__(
        self,
        reservations_dir: Path,
        budget: int,
        *,
        live_tokens: Callable[[], frozenset[str]],
        alive_pids: Callable[[], frozenset[int]],
        wait_timeout: float = _SLOT_WAIT_TIMEOUT_SECONDS,
        poll: float = _SLOT_POLL_INTERVAL_SECONDS,
        lock_timeout: float = _LOCK_ACQUIRE_TIMEOUT_SECONDS,
        lock_poll: float = _LOCK_POLL_INTERVAL_SECONDS,
        lock_path: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize the gate with a reservations directory and a slot budget.

        Args:
            reservations_dir: Directory holding one reservation file per active
                run; created on first use.
            budget: Maximum number of slots that may be occupied at once.
            live_tokens: Callable returning the tokens of runs whose container is
                currently running.
            alive_pids: Callable returning the process ids currently alive.
            wait_timeout: Maximum seconds to wait for a slot before giving up.
            poll: Seconds between slot-availability checks while waiting.
            lock_timeout: Maximum seconds to wait for the admission lock.
            lock_poll: Seconds between admission-lock acquisition attempts.
            lock_path: Path of the admission lock file; defaults to a file inside
                ``reservations_dir``.
            clock: Monotonic clock used for all deadlines.
            sleep: Sleep function used while waiting.
        """
        self._dir = reservations_dir
        self._budget = max(1, budget)
        self._live_tokens = live_tokens
        self._alive_pids = alive_pids
        self._wait_timeout = wait_timeout
        self._poll = poll
        self._lock_timeout = lock_timeout
        self._lock_poll = lock_poll
        self._lock_path = lock_path if lock_path is not None else reservations_dir / _DEFAULT_LOCK_FILENAME
        self._clock = clock
        self._sleep = sleep

    @property
    def budget(self) -> int:
        """Maximum number of slots this gate permits.

        Returns:
            int: The slot budget.
        """
        return self._budget

    def _read_reservations(self) -> tuple[Reservation, ...]:
        """Read every reservation currently recorded in the directory.

        Returns:
            tuple[Reservation, ...]: One entry per reservation file, excluding the
                admission lock file itself.
        """
        if not self._dir.is_dir():
            return ()
        reservations: list[Reservation] = []
        for entry in self._dir.iterdir():
            if not entry.is_file() or entry == self._lock_path:
                continue
            token = entry.name
            reservations.append(Reservation(token=token, pid=pid_from_token(token), path=entry))
        return tuple(reservations)

    @staticmethod
    def _reap_stale(reservations: Iterable[Reservation], live_tokens: frozenset[str], alive_pids: frozenset[int]) -> None:
        """Delete reservation files whose owning run has ended.

        Args:
            reservations: Reservations recovered from the directory.
            live_tokens: Tokens of runs whose container is currently running.
            alive_pids: Process ids currently alive on the host.
        """
        for stale in select_stale_reservations(reservations, live_tokens, alive_pids):
            try:
                stale.path.unlink(missing_ok=True)
            except OSError:
                continue

    def _try_admit(self, token: str) -> SlotHandle | None:
        """Attempt one admission under the cross-process lock.

        Reclaims stale reservations, counts occupied slots, and -- if the budget
        has room -- writes this run's reservation and returns a handle. Returns
        ``None`` when every slot is occupied.

        Args:
            token: The caller's run token.

        Returns:
            SlotHandle | None: A granted slot, or ``None`` when the host is full.
        """
        lock = _CrossProcessLock(self._lock_path)
        lock.acquire(timeout=self._lock_timeout, poll=self._lock_poll, clock=self._clock, sleep=self._sleep)
        try:
            live_tokens = self._live_tokens()
            alive_pids = self._alive_pids()
            self._dir.mkdir(parents=True, exist_ok=True)
            reservations = self._read_reservations()
            self._reap_stale(reservations, live_tokens, alive_pids)
            reservations = self._read_reservations()
            occupied = count_occupied_slots(reservations, live_tokens, alive_pids, exclude_token=token)
            if occupied >= self._budget:
                return None
            path = self._dir / token
            path.write_text(f"{os.getpid()}\n", encoding="utf-8")
            return SlotHandle(token, path)
        finally:
            lock.release()

    def acquire(self, token: str) -> SlotHandle:
        """Acquire a concurrency slot, blocking until one is free.

        Args:
            token: The run token requesting a slot.

        Returns:
            SlotHandle: The granted slot; the caller must release it once its
                container has exited.

        Raises:
            AdmissionError: If no slot frees within the configured wait timeout.
        """
        deadline = self._clock() + self._wait_timeout
        announced = False
        while True:
            handle = self._try_admit(token)
            if handle is not None:
                return handle
            if not announced:
                print(
                    f"[sandbox] All {self._budget} concurrency slot(s) are busy; "
                    f"waiting up to {self._wait_timeout:.0f}s for one to free ...",
                    file=sys.stderr,
                )
                announced = True
            if self._clock() >= deadline:
                message = (
                    f"no sandbox concurrency slot became free within {self._wait_timeout:.0f}s "
                    f"({self._budget} slot(s) stayed occupied)"
                )
                raise AdmissionError(message)
            self._sleep(self._poll)
