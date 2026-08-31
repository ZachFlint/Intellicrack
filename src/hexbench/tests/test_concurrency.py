# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Eight threads at one document, and the ordering that keeps two from deadlocking.

``HexDocument`` used to be a PyO3 class without interior mutability. Twenty-eight
of its methods took a mutable Rust borrow, and several of its analyses release
the GIL part way through, so two Python threads inside one document did not
merely interleave -- the second got ``RuntimeError: Already borrowed`` and the
operation was lost. The engine is now frozen and carries its own reader-writer
lock, so what the guarded run below claims has changed from "the slot suppresses
the error" to "concurrent use is survived": the same eight threads, the same
document, and nothing raised.

A test that only shows the guarded path staying quiet proves nothing on its own:
it would pass equally well if the race were impossible to provoke on this
machine, on this build, at this document size. So every guarded run here is
paired with a control that removes the slot and nothing else --
:meth:`UnguardedRaceControl.test_the_unguarded_race_really_does_overlap_one_document`
drives the identical operations at the identical thread count against a document
of the identical size, and fails the suite if the calls never actually overlap
inside it. The two together are the gate: the control establishes that the race
is live, and the guarded run establishes that contention is survived.

The second invariant is structural, and it survived the engine change intact.
:func:`~hexbench.dispatch.resolve_references` runs as a pre-pass: it finishes
with every referenced document before the receiver is engaged at all. That
ordering is the only reason two invocations naming each other's documents cannot
deadlock, and it is one edit away from being lost -- moving the pre-pass inside
the receiver's ``with`` block would leave a thread inside two documents at once
and reinstate the lock-ordering hazard the moment a read ever takes a lock again.

Counting locks would no longer measure this. Reads take none, so a lock counter
sees at most the single exclusive hold a mutation makes and reports depth one
whatever the dispatcher does. :class:`_TrackingSlot` therefore records both
access paths and the tracker counts *documents a thread is inside*, exclusive or
shared. :class:`AccessTrackerFalsifiability` shows the instrument reporting two
for a hand-nested pair, including the read-inside-a-hold shape that is exactly
what the regression would look like, so a depth of one everywhere else means
something.

Assertions are made through the package's shared vocabulary in
:class:`hexbench.tests._support.Assertions`, which every case here inherits and
which documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Final

from intellicrack_hexcore import HexDocument

from hexbench import registry as registry_module
from hexbench.dispatch import Invocation, invoke, operation_for
from hexbench.registry import DocumentSlot, Registry

from ._support import HexbenchTestCase


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence

    from hexbench.codec import JsonValue


_DOCUMENT_SIZE: Final = 1 << 24
"""Bytes in the contended document.

Sixteen mebibytes is not arbitrary. ``entropy`` over this much data takes long
enough, with the GIL released, that a writer reliably arrives mid-borrow; the
control below measures that rather than assuming it.
"""

_BYTE_VALUES: Final = 256
"""Distinct byte values used to fill the contended document."""

_READERS: Final = 4
"""Threads calling the long, GIL-releasing analysis."""

_WRITERS: Final = 4
"""Threads calling the mutating operation that needs an exclusive borrow."""

_THREADS: Final = _READERS + _WRITERS
"""Total threads in one race, half reading and half writing."""

_RACE_SECONDS: Final = 3.0
"""How long the guarded race runs; the control needed under a tenth of this."""

_CONTROL_SECONDS: Final = 30.0
"""Ceiling on the control, which stops the moment it reproduces the error."""

_INVOKE_TIMEOUT: Final = 20.0
"""Seconds an invocation waits for the document, so a hang becomes a failure."""

_JOIN_TIMEOUT: Final = 45.0
"""Seconds to wait for a race thread to finish before calling it stuck."""

_BARRIER_TIMEOUT: Final = 30.0
"""Seconds a thread waits at the starting line for its peers."""

_MINIMUM_CALLS: Final = 20
"""Calls each side must complete before a quiet race counts as evidence."""

_PAYLOAD: Final[bytes] = b"\xde\xad\xbe\xef"
"""Bytes the writers put into the document over and over."""

_PAYLOAD_HEX: Final = _PAYLOAD.hex()
"""The writers' payload as the dispatcher's clients would send it."""

_WRITE_SPAN: Final = 4096
"""Region the writers cycle through, kept small so their offsets collide."""

_ALREADY_BORROWED: Final = "Already borrowed"
"""The exact text PyO3 raised when a second thread reached one document.

The engine no longer produces this. The guarded run still asserts its absence
because that is the property being claimed, not because the lock is what
suppresses it.
"""

_OVERLAPPING_CALLS: Final = 2
"""Calls inside one document at once that count as the race having overlapped."""

_READER: Final = "reader"
"""Label recorded against failures raised by an analysis thread."""

_WRITER: Final = "writer"
"""Label recorded against failures raised by a mutating thread."""

_ENTROPY: Final = "entropy"
"""The long analysis the readers run; it takes a shared borrow."""

_WRITE_BYTES: Final = "write_bytes"
"""The mutation the writers run; it takes an exclusive borrow."""

_EXPORT_BPS: Final = "export_patches_bps"
"""A read-only document operation whose argument may name another open document."""

_DIFF_BYTES: Final = "diff_bytes"
"""A module operation taking two binary arguments and no receiver."""

_SOURCE_ARGUMENT: Final = "source_data"
"""Name of the binary parameter the patch exports read their source from."""

_DATA_ARGUMENT: Final = "data"
"""Name of the binary parameter the mutation writes into the document."""

_OFFSET_ARGUMENT: Final = "offset"
"""Name of the parameter saying where that mutation writes."""

_ORIGIN_OFFSET: Final = 0
"""Where the crossed mutations write, so a whole document fits what it replaces."""

_REFERENCE_TAG: Final = "__document__"
"""Key that turns a binary argument into a reference to an open document."""

_ORIGIN: Final = "open_bytes"
"""Origin recorded for every document these tests register by hand."""

_SMALL_SIZE: Final = 512
"""Bytes in the documents used for the lock-nesting tests."""

_CROSS_ITERATIONS: Final = 200
"""Crossed invocations each thread performs while looking for a deadlock.

Measured against a deliberately broken dispatcher that resolves references
inside the receiver's borrow: forty crossings were not enough to make the
lock-ordering deadlock appear, two hundred were.
"""

_EXCLUSIVE: Final = "exclusive hold"
"""How the tracker names an access taken through the slot's write lock."""

_SHARED: Final = "shared read"
"""How the tracker names an access taken through the slot's lock-free read."""

_ONE_DOCUMENT: Final = 1
"""The greatest number of documents one thread may ever be inside at once."""

_TWO_DOCUMENTS: Final = 2
"""The depth the tracker must report when a thread genuinely is inside two."""

_NO_DOCUMENTS: Final = 0
"""The depth a tracker reports before any document has been reached."""

_NO_CALLS: Final = 0
"""The call count a race that never got started would report."""

_ONE_OVERLAP: Final = 1
"""How many overlaps the deliberate two-lock nesting is expected to record."""

_NO_FAILURES: Final[tuple[str, ...]] = ()
"""What a clean race reports."""

_WAIT_FOREVER: Final = -1.0
"""Borrow timeout meaning no timeout, matching the slot this module subclasses."""

_RACE_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    ArithmeticError,
    AttributeError,
    LookupError,
    MemoryError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)
"""Everything a racing thread could raise, listed so nothing is swallowed blind."""


def _contended_bytes(size: int) -> bytes:
    """Build a document body with a flat spread of byte values.

    Args:
        size: Number of bytes to produce, which must be a multiple of 256.

    Returns:
        bytes: The body, repeating every byte value in turn.
    """
    return bytes(range(_BYTE_VALUES)) * (size // _BYTE_VALUES)


@dataclass(frozen=True, slots=True)
class _RaceReport:
    """What one race produced.

    Attributes:
        reader_calls: Analyses that returned normally.
        writer_calls: Mutations that returned normally.
        failures: One line per thread that raised, in the order they were seen.
    """

    reader_calls: int
    writer_calls: int
    failures: tuple[str, ...]

    @property
    def borrow_failures(self) -> tuple[str, ...]:
        """List only the failures PyO3 raised for a concurrent borrow.

        Returns:
            tuple[str, ...]: Failures naming the already-borrowed error.
        """
        return tuple(line for line in self.failures if _ALREADY_BORROWED in line)


class _InFlight:
    """Counts how many wrapped calls are inside the document at one moment."""

    def __init__(self) -> None:
        """Start with nothing in flight."""
        self._state = threading.Lock()
        self._current = 0
        self._peak = 0

    @property
    def peak(self) -> int:
        """The most calls ever inside the document at the same time.

        Returns:
            int: One when nothing ever overlapped, more when calls did.
        """
        with self._state:
            return self._peak

    @contextmanager
    def entered(self) -> Generator[None]:
        """Mark one call as being inside the document for the duration.

        Yields:
            None: While the wrapped call runs.
        """
        with self._state:
            self._current += 1
            self._peak = max(self._peak, self._current)
        try:
            yield
        finally:
            with self._state:
                self._current -= 1


def _race(reader: Callable[[int], None], writer: Callable[[int], None], *, seconds: float, stop_on_failure: bool) -> _RaceReport:
    """Drive readers and writers at one document until the clock runs out.

    Every thread waits at a barrier first, so the contention starts at once
    rather than ramping up while earlier threads finish.

    Args:
        reader: Called by each reading thread with its iteration number.
        writer: Called by each writing thread with its iteration number.
        seconds: How long the threads keep going.
        stop_on_failure: Whether the first failure ends the race early, which is
            what keeps the control fast once it has proved its point.

    Returns:
        _RaceReport: Completed call counts and every failure raised.
    """
    barrier = threading.Barrier(_THREADS)
    stop = threading.Event()
    state = threading.Lock()
    failures: list[str] = []
    tally: dict[str, int] = {_READER: 0, _WRITER: 0}

    def drive(kind: str, action: Callable[[int], None]) -> None:
        completed = 0
        try:
            barrier.wait(_BARRIER_TIMEOUT)
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and not stop.is_set():
                action(completed)
                completed += 1
        except _RACE_EXCEPTIONS as exc:
            with state:
                failures.append(f"{kind} call {completed}: {type(exc).__name__}: {exc}")
            if stop_on_failure:
                stop.set()
        finally:
            with state:
                tally[kind] += completed

    threads = [
        threading.Thread(target=drive, args=(_READER, reader), name=f"hexbench-{_READER}-{index}", daemon=True) for index in range(_READERS)
    ]
    threads.extend(
        threading.Thread(target=drive, args=(_WRITER, writer), name=f"hexbench-{_WRITER}-{index}", daemon=True) for index in range(_WRITERS)
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(_JOIN_TIMEOUT)
    stuck = [thread.name for thread in threads if thread.is_alive()]
    with state:
        if stuck:
            failures.append(f"still running after {_JOIN_TIMEOUT} seconds: {', '.join(stuck)}")
        return _RaceReport(reader_calls=tally[_READER], writer_calls=tally[_WRITER], failures=tuple(failures))


def _run_together(actions: Sequence[Callable[[], None]], *, timeout: float) -> tuple[str, ...]:
    """Start every action on its own thread and report anything that went wrong.

    A thread still running when the wait expires is reported as stuck, which is
    how a deadlock between two invocations would surface here.

    Args:
        actions: One callable per thread, each performing its own whole workload.
        timeout: Seconds to wait at the barrier and then for each thread.

    Returns:
        tuple[str, ...]: One line per failure, empty when every thread finished
        cleanly.
    """
    barrier = threading.Barrier(len(actions))
    state = threading.Lock()
    failures: list[str] = []

    def drive(index: int, action: Callable[[], None]) -> None:
        try:
            barrier.wait(timeout)
            action()
        except _RACE_EXCEPTIONS as exc:
            with state:
                failures.append(f"thread {index}: {type(exc).__name__}: {exc}")

    threads = [
        threading.Thread(target=drive, args=(index, action), name=f"hexbench-crossed-{index}", daemon=True)
        for index, action in enumerate(actions)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout)
    stuck = [thread.name for thread in threads if thread.is_alive()]
    with state:
        if stuck:
            failures.append(f"still running after {timeout} seconds: {', '.join(stuck)}")
        return tuple(failures)


@dataclass(frozen=True, slots=True)
class _Access:
    """One document a thread is currently inside.

    Attributes:
        handle: Document being accessed.
        kind: Which path reached it, :data:`_EXCLUSIVE` or :data:`_SHARED`.
    """

    handle: str
    kind: str

    def described(self) -> str:
        """Name this access the way a failure message should.

        Returns:
            str: The access path and the document it applies to.
        """
        return f"{self.kind} of {self.handle}"


class _AccessTracker:
    """Records which documents each thread is inside at the same moment.

    Both paths into a document are counted, because only one of them takes a
    lock. Reads are lock free, so a tracker that watched borrows alone would
    report a depth of one however deeply the dispatcher nested its accesses and
    would stop being able to fail.
    """

    def __init__(self) -> None:
        """Start a tracker that has seen no accesses."""
        self._state = threading.Lock()
        self._held: dict[int, list[_Access]] = {}
        self._peak = 0
        self._handles: set[str] = set()
        self._overlaps: list[str] = []

    def enter(self, access: _Access) -> None:
        """Record that the calling thread has entered one more document.

        Args:
            access: The document just entered, and how.
        """
        thread = threading.get_ident()
        with self._state:
            stack = self._held.setdefault(thread, [])
            stack.append(access)
            self._handles.add(access.handle)
            self._peak = max(self._peak, len(stack))
            if len(stack) > _ONE_DOCUMENT:
                already = ", ".join(held.described() for held in stack[:-1])
                self._overlaps.append(f"thread {thread} began {access.described()} while already inside {already}")

    def leave(self) -> None:
        """Record that the calling thread has left its innermost document."""
        thread = threading.get_ident()
        with self._state:
            stack = self._held.get(thread)
            if stack:
                stack.pop()

    @property
    def peak(self) -> int:
        """Report the greatest number of documents any one thread was inside at once.

        Returns:
            int: The peak depth reached on any thread.
        """
        with self._state:
            return self._peak

    @property
    def handles(self) -> frozenset[str]:
        """List every document that has been reached through this tracker.

        Returns:
            frozenset[str]: Handles of the documents seen.
        """
        with self._state:
            return frozenset(self._handles)

    @property
    def overlaps(self) -> tuple[str, ...]:
        """Describe every moment a thread was inside more than one document.

        Returns:
            tuple[str, ...]: One line per overlap, empty when none occurred.
        """
        with self._state:
            return tuple(self._overlaps)


class _TrackingSlot(DocumentSlot):
    """The real slot, with both ways into the document reported to a tracker.

    Attributes:
        tracker: Tracker the slots created under the current patch report to.
    """

    tracker: ClassVar[_AccessTracker] = _AccessTracker()

    @contextmanager
    def borrow(self, *, timeout: float = _WAIT_FOREVER) -> Generator[HexDocument]:
        """Borrow the document and record the hold for as long as it lasts.

        Propagates :class:`~hexbench.registry.BusyError` from the slot it
        subclasses when the document does not come free in time.

        Args:
            timeout: Seconds to wait for exclusive access. Any negative value
                waits indefinitely.

        Yields:
            HexDocument: The borrowed document, exactly as the base slot yields
            it.
        """
        with super().borrow(timeout=timeout) as document:
            _TrackingSlot.tracker.enter(_Access(handle=self.handle, kind=_EXCLUSIVE))
            try:
                yield document
            finally:
                _TrackingSlot.tracker.leave()

    @contextmanager
    def read(self) -> Generator[HexDocument]:
        """Use the document for a read and record that use for its duration.

        This path takes no lock, which is precisely why it has to be recorded:
        an access the instrument cannot see is an access the nesting checks
        below cannot fail on.

        Yields:
            HexDocument: The document, exactly as the base slot yields it.
        """
        with super().read() as document:
            _TrackingSlot.tracker.enter(_Access(handle=self.handle, kind=_SHARED))
            try:
                yield document
            finally:
                _TrackingSlot.tracker.leave()


@contextmanager
def _tracked_registry() -> Generator[tuple[Registry, _AccessTracker]]:
    """Provide a registry whose documents report every access.

    The registry class is left untouched; only the slot type it instantiates is
    swapped, and it is put back before the block returns.

    Yields:
        tuple[Registry, _AccessTracker]: The registry and the tracker its
        documents report to, both discarded when the block ends.
    """
    tracker = _AccessTracker()
    _TrackingSlot.tracker = tracker
    previous = registry_module.DocumentSlot
    registry_module.DocumentSlot = _TrackingSlot
    registry = Registry()
    try:
        yield (registry, tracker)
    finally:
        registry_module.DocumentSlot = previous
        registry.shutdown()


def _reference(handle: str) -> JsonValue:
    """Build the argument that names another open document.

    Args:
        handle: Document the argument should read its bytes from.

    Returns:
        JsonValue: A reference covering the whole of that document.
    """
    return {_REFERENCE_TAG: handle}


def _small_document(registry: Registry, label: str) -> str:
    """Register a small in-memory document with a registry.

    Args:
        registry: Registry to register it with.
        label: Tab label for the new document.

    Returns:
        str: Handle of the new document.
    """
    return registry.create(HexDocument.open_bytes(_contended_bytes(_SMALL_SIZE)), origin=_ORIGIN, label=label).handle


class _ConcurrencyCase(HexbenchTestCase):
    """A session plus the shared assertion vocabulary.

    The ``equal`` and ``unequal`` helpers come from
    :class:`~hexbench.tests._support.Assertions`, which every case in the
    package inherits.
    """

    def require_work(self, report: _RaceReport) -> None:
        """Insist a race actually ran enough calls to have proved anything.

        Args:
            report: The race to check.
        """
        if report.reader_calls < _MINIMUM_CALLS or report.writer_calls < _MINIMUM_CALLS:
            self.fail(
                f"the race completed only {report.reader_calls} analyses and {report.writer_calls} writes "
                f"in {_RACE_SECONDS} seconds, which is too few to say anything about contention",
            )


class GuardedConcurrency(_ConcurrencyCase):
    """Eight threads at one document, every one of them through the registry."""

    def test_eight_threads_through_dispatch_never_see_already_borrowed(self) -> None:
        """Four analyses and four mutations contend for three seconds, cleanly."""
        registry = self.session.registry
        handle = self.session.open_bytes(_contended_bytes(_DOCUMENT_SIZE)).handle
        analysis = operation_for(_ENTROPY)
        mutation = operation_for(_WRITE_BYTES)

        def read(_iteration: int) -> None:
            invoke(registry, Invocation(operation=analysis, handle=handle, arguments={}), timeout=_INVOKE_TIMEOUT)

        def write(iteration: int) -> None:
            arguments: dict[str, JsonValue] = {"offset": (iteration * len(_PAYLOAD)) % _WRITE_SPAN, "data": _PAYLOAD_HEX}
            invoke(registry, Invocation(operation=mutation, handle=handle, arguments=arguments), timeout=_INVOKE_TIMEOUT)

        report = _race(read, write, seconds=_RACE_SECONDS, stop_on_failure=False)
        self.equal(report.borrow_failures, _NO_FAILURES)
        self.equal(report.failures, _NO_FAILURES)
        self.require_work(report)

    def test_the_contended_document_survives_the_race_intact(self) -> None:
        """The document is still the right size and still holds what was written."""
        registry = self.session.registry
        handle = self.session.open_bytes(_contended_bytes(_DOCUMENT_SIZE)).handle
        analysis = operation_for(_ENTROPY)
        mutation = operation_for(_WRITE_BYTES)

        def read(_iteration: int) -> None:
            invoke(registry, Invocation(operation=analysis, handle=handle, arguments={}), timeout=_INVOKE_TIMEOUT)

        def write(iteration: int) -> None:
            arguments: dict[str, JsonValue] = {"offset": (iteration * len(_PAYLOAD)) % _WRITE_SPAN, "data": _PAYLOAD_HEX}
            invoke(registry, Invocation(operation=mutation, handle=handle, arguments=arguments), timeout=_INVOKE_TIMEOUT)

        report = _race(read, write, seconds=_RACE_SECONDS, stop_on_failure=False)
        self.equal(report.failures, _NO_FAILURES)
        self.require_work(report)
        state = registry.slot(handle).info()
        self.equal(state.length, _DOCUMENT_SIZE)
        with registry.slot(handle).borrow() as document:
            self.equal(document.read(0, len(_PAYLOAD)), _PAYLOAD)
        if state.generation < report.writer_calls:
            self.fail(f"generation reached {state.generation} after {report.writer_calls} writes; mutations went unrecorded")


class UnguardedRaceControl(_ConcurrencyCase):
    """The same workload with the lock removed, proving the race is real."""

    def test_the_unguarded_race_really_does_overlap_one_document(self) -> None:
        """The race puts several calls inside one document at the same time.

        This replaces a control that proved the point the other way round. It
        used to drive the same race with no slot in the way and require that
        PyO3 raised ``Already borrowed``, on the argument that until the defect
        reproduced, the guarded test was not evidence the lock did anything.

        That defect no longer exists to reproduce. ``HexDocument`` is now a
        frozen class holding its own reader-writer lock, so a second thread
        reaching one document is what the engine is built for rather than an
        error, and no arrangement of callers can provoke the old message.

        What still has to be shown is that the race is a race. A guarded run
        that raised nothing would look identical to one where the threads never
        actually met, so this drives the document with no slot in the way and
        measures the overlap directly: the peak count of calls inside the
        document at once must exceed one, and nothing may raise.
        """
        document = HexDocument.open_bytes(_contended_bytes(_DOCUMENT_SIZE))
        in_flight = _InFlight()

        def read(_iteration: int) -> None:
            with in_flight.entered():
                document.entropy()

        def write(iteration: int) -> None:
            with in_flight.entered():
                document.write_bytes((iteration * len(_PAYLOAD)) % _WRITE_SPAN, _PAYLOAD)

        report = _race(read, write, seconds=_CONTROL_SECONDS, stop_on_failure=True)
        self.equal(report.failures, _NO_FAILURES)
        self.unequal(report.reader_calls + report.writer_calls, _NO_CALLS)
        if in_flight.peak < _OVERLAPPING_CALLS:
            self.fail(
                f"the race ran {report.reader_calls} analyses and {report.writer_calls} writes over "
                f"{_CONTROL_SECONDS} seconds against a {_DOCUMENT_SIZE} byte document but never had more "
                f"than {in_flight.peak} call inside the document at once. Until it overlaps, the guarded "
                f"test above is not evidence that concurrent use is safe.",
            )


class AccessTrackerFalsifiability(_ConcurrencyCase):
    """The instrument the next class relies on, shown to detect a violation."""

    def test_the_tracker_notices_two_documents_held_at_once(self) -> None:
        """Nesting two borrows by hand makes the tracker report a depth of two."""
        with _tracked_registry() as (registry, tracker):
            first = _small_document(registry, "first")
            second = _small_document(registry, "second")
            self.equal(tracker.peak, _NO_DOCUMENTS)
            with registry.slot(first).borrow(), registry.slot(second).borrow():
                self.equal(tracker.peak, _TWO_DOCUMENTS)
            self.equal(tracker.peak, _TWO_DOCUMENTS)
            self.equal(tracker.handles, {first, second})
            self.equal(len(tracker.overlaps), _ONE_OVERLAP)

    def test_the_tracker_notices_a_read_taken_inside_a_hold(self) -> None:
        """The shape a regression would take is exactly the shape it must catch.

        Reference resolution moving inside the receiver's ``with`` block would
        read one document while the other was held, and that read takes no lock
        for the instrument to notice. Unless this fires, every nesting check
        below is passing on a blind spot rather than on the dispatcher.
        """
        with _tracked_registry() as (registry, tracker):
            held = _small_document(registry, "held")
            referenced = _small_document(registry, "referenced")
            with registry.slot(held).borrow(), registry.slot(referenced).read():
                self.equal(tracker.peak, _TWO_DOCUMENTS)
            self.equal(tracker.handles, {held, referenced})
            self.equal(len(tracker.overlaps), _ONE_OVERLAP)
            self.contains(_SHARED, tracker.overlaps[0])

    def test_a_single_access_leaves_the_tracker_at_one(self) -> None:
        """The instrument does not cry overlap when nothing overlaps."""
        with _tracked_registry() as (registry, tracker):
            handle = _small_document(registry, "only")
            with registry.slot(handle).borrow():
                self.equal(tracker.peak, _ONE_DOCUMENT)
            with registry.slot(handle).read():
                self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.overlaps, _NO_FAILURES)


class DocumentAccessNesting(_ConcurrencyCase):
    """Reference resolution, measured with the instrument proved out above."""

    def test_a_cross_document_reference_is_finished_with_before_the_receiver(self) -> None:
        """The referenced document is read and released before the receiver is entered."""
        with _tracked_registry() as (registry, tracker):
            source = _small_document(registry, "source")
            target = _small_document(registry, "target")
            arguments: dict[str, JsonValue] = {_SOURCE_ARGUMENT: _reference(source)}
            invoke(registry, Invocation(operation=operation_for(_EXPORT_BPS), handle=target, arguments=arguments))
            self.equal(tracker.handles, {source, target})
            self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.overlaps, _NO_FAILURES)

    def test_two_references_on_one_module_call_are_read_in_turn(self) -> None:
        """``diff_bytes`` reads both documents without ever being inside both."""
        with _tracked_registry() as (registry, tracker):
            first = _small_document(registry, "first")
            second = _small_document(registry, "second")
            arguments: dict[str, JsonValue] = {"data_a": _reference(first), "data_b": _reference(second)}
            result = invoke(registry, Invocation(operation=operation_for(_DIFF_BYTES), handle=None, arguments=arguments))
            self.unequal(result.value, None)
            self.equal(tracker.handles, {first, second})
            self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.overlaps, _NO_FAILURES)

    def test_a_mutation_reading_its_own_document_does_not_nest_the_access(self) -> None:
        """A write whose source is the document it writes to reads it first, then holds it.

        This is the sharpest case the dispatcher has to get right. The receiver
        is a mutation, so it takes the exclusive hold, and the argument names
        the very document being held. Resolving that reference a moment later
        would put the thread inside one document twice over.
        """
        with _tracked_registry() as (registry, tracker):
            handle = _small_document(registry, "self")
            arguments: dict[str, JsonValue] = {_OFFSET_ARGUMENT: _ORIGIN_OFFSET, _DATA_ARGUMENT: _reference(handle)}
            invoke(registry, Invocation(operation=operation_for(_WRITE_BYTES), handle=handle, arguments=arguments))
            self.equal(tracker.handles, {handle})
            self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.overlaps, _NO_FAILURES)

    def test_invocations_that_reference_each_other_do_not_deadlock(self) -> None:
        """The classic lock-ordering deadlock cannot form, because it takes two.

        Both receivers here are mutations, so both take the exclusive hold that
        a deadlock needs. What stops the cycle closing is that neither thread is
        inside the other's document while holding its own.
        """
        with _tracked_registry() as (registry, tracker):
            first = _small_document(registry, "first")
            second = _small_document(registry, "second")
            mutation = operation_for(_WRITE_BYTES)

            def crossed(receiver: str, referenced: str) -> Callable[[], None]:
                def run() -> None:
                    arguments: dict[str, JsonValue] = {_OFFSET_ARGUMENT: _ORIGIN_OFFSET, _DATA_ARGUMENT: _reference(referenced)}
                    for _ in range(_CROSS_ITERATIONS):
                        invoke(registry, Invocation(operation=mutation, handle=receiver, arguments=arguments), timeout=_INVOKE_TIMEOUT)

                return run

            failures = _run_together((crossed(first, second), crossed(second, first)), timeout=_JOIN_TIMEOUT)
            self.equal(failures, _NO_FAILURES)
            self.equal(tracker.handles, {first, second})
            self.equal(tracker.peak, _ONE_DOCUMENT)
            self.equal(tracker.overlaps, _NO_FAILURES)
