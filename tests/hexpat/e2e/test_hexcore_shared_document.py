# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for sharing one HexDocument across threads, and for the buffer API.

``HexDocument`` used to be a plain ``#[pyclass]`` whose 28 mutating methods took
``&mut self``, so PyO3 held an exclusive borrow for the length of every call.
The long analyses keep that borrow across ``Python::detach``, which meant a
second thread touching the same document raised
``RuntimeError: Already borrowed``. Callers papered over it by serialising every
call behind a lock of their own, which also serialised the read-only analyses
that could safely have overlapped.

The class is now ``frozen`` with a ``RwLock`` inside, so these tests assert both
halves of that claim: that concurrent access no longer raises, and that reads
genuinely run at the same time rather than merely queueing politely.

The remaining tests cover the accessors added alongside it -- the little-endian
buffer variants, the windowed read, and the generation counter -- each checked
against the existing accessor it must agree with rather than against a restated
constant.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest


if TYPE_CHECKING:
    import types
    from collections.abc import Callable

    from intellicrack_hexcore import HexDocument


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

_READER_THREADS: Final = 6
"""Threads hammering read-only operations at one shared document."""

_WRITER_THREADS: Final = 2
"""Threads mutating that same document at the same time."""

_OPERATIONS_PER_THREAD: Final = 40
"""Calls each thread makes. Enough interleaving to surface a borrow conflict."""

_JOIN_TIMEOUT: Final = 120.0
"""Seconds to wait for a thread. Exceeding it means the run deadlocked."""

_PARALLEL_THREADS: Final = 4
"""Threads used to show that reads overlap."""

_PARALLEL_ITERATIONS: Final = 20
"""Calls the overlap test starts calibrating from, doubling until timeable."""

_PARALLEL_MARGIN: Final = 0.7
"""How much of the serialised time the concurrent run must beat.

Perfect overlap finishes in roughly the baseline; full serialisation takes
``_PARALLEL_THREADS`` times it. Requiring less than 70% of the serialised time
sits far from both, so ordinary scheduling noise cannot decide the outcome.
"""

_MIN_CPUS: Final = 2
"""Cores below which nothing can overlap and the timing proves nothing."""

_ENTROPY_BLOCK: Final = 1024
"""Block size for the entropy and classification accessors."""

_DIGRAM_CELLS: Final = 65536
"""Cells in the 256x256 digram grid."""

_DISTRIBUTION_CELLS: Final = 256
"""Cells in a full byte distribution."""

_WINDOW_LENGTH: Final = 4096
"""Bytes requested by the windowed-read tests."""

_WORKERS: Final = _READER_THREADS + _WRITER_THREADS
"""Threads contending for the one document."""

_SKEW_SAMPLES: Final = 2000
"""Reader samples taken while a writer changes the byte underneath them."""

_SKEW_WRITE_CAP: Final = _SKEW_SAMPLES * 4
"""Writes the flipping thread may make before giving up on being stopped."""

_SKEW_MARKS: Final = (0x00, 0xFF)
"""The two values the writer alternates, distinct so a skew is visible."""

_ONE_WRITER: Final = 1
"""Threads flipping the byte."""

_ONE_BYTE: Final = 1
"""Bytes each sample reads. Only the first byte is being watched."""

_EXTENSION_SUFFIX: Final = ".pyd"
"""Suffix of a compiled Python extension on Windows."""

_MIN_ANALYSIS_BYTES: Final = 1 << 20
"""Smallest binary the timing tests can draw a conclusion from."""

_MIN_BASELINE: Final = 0.20
"""Seconds the serial run must last before comparing it to anything.

Starting :data:`_PARALLEL_THREADS` threads costs on the order of a millisecond,
so a baseline of a few hundred microseconds would be a measurement of thread
creation wearing the costume of a measurement of overlap.
"""

_CALIBRATION_CAP: Final = 1 << 20
"""Scans to give up at, so calibration cannot spin forever."""


@pytest.fixture
def engine_binary(hexcore: types.ModuleType) -> str:
    """Locate a real compiled binary that is always present.

    The extension module itself is a genuine multi-megabyte PE, which makes it a
    real target for the analyses under test without committing a fixture. Which
    file ``__file__`` names depends on how the wheel was installed: an editable
    install points straight at the ``.pyd``, while a packaged one can point at a
    few-hundred-byte package ``__init__.py``. Analysing that instead leaves the
    timing tests measuring their own thread overhead and still passing, so the
    compiled extension is located explicitly and its size is checked rather than
    assumed.

    Args:
        hexcore: The imported native module.

    Returns:
        str: Filesystem path to the compiled extension.
    """
    reported: str | None = getattr(hexcore, "__file__", None)
    if reported is None:
        pytest.fail("the native module reports no __file__ to analyse")
    located = Path(reported)
    if located.suffix.lower() != _EXTENSION_SUFFIX:
        beside = sorted(located.parent.glob(f"*{_EXTENSION_SUFFIX}"), key=lambda candidate: candidate.stat().st_size)
        if not beside:
            pytest.fail(f"no compiled extension found beside {located}, so there is nothing real to analyse")
        located = beside[-1]
    size = located.stat().st_size
    if size < _MIN_ANALYSIS_BYTES:
        pytest.fail(f"{located} is {size} bytes, too small for these analyses to measure anything")
    return str(located)


def _drive_readers(doc: HexDocument) -> int:
    """Run read-only operations against the shared document.

    Nothing is caught here on purpose. The caller collects the result through a
    future, so anything raised -- a borrow conflict, or an attribute error from
    an engine that predates these accessors -- surfaces in the test rather than
    quietly killing the worker and leaving the assertions with nothing to see.

    Args:
        doc: The shared document.

    Returns:
        int: Operations completed, which is every one of them or the call raised.
    """
    for _ in range(_OPERATIONS_PER_THREAD):
        doc.entropy()
        doc.byte_statistics()
        doc.read_window(0, _WINDOW_LENGTH)
        doc.byte_type_distribution()
    return _OPERATIONS_PER_THREAD


def _drive_writers(doc: HexDocument) -> int:
    """Mutate the shared document, letting any failure propagate.

    Args:
        doc: The shared document.

    Returns:
        int: Operations completed, which is every one of them or the call raised.
    """
    for index in range(_OPERATIONS_PER_THREAD):
        doc.write_bytes(index, bytes([index % 256]))
    return _OPERATIONS_PER_THREAD


def test_concurrent_readers_and_writers_share_one_document(
    hexcore: types.ModuleType,
    engine_binary: str,
) -> None:
    """Eight threads share one document without a borrow conflict or a deadlock.

    This is the regression the ``frozen`` rewrite exists for. Against the old
    class this raised ``RuntimeError: Already borrowed`` as soon as a reader
    overlapped a writer.

    Args:
        hexcore: The imported native module.
        engine_binary: A real binary to analyse.
    """
    doc = hexcore.HexDocument.open(engine_binary)

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        pending: list[Future[int]] = [pool.submit(_drive_readers, doc) for _ in range(_READER_THREADS)]
        pending += [pool.submit(_drive_writers, doc) for _ in range(_WRITER_THREADS)]
        completed = [future.result(timeout=_JOIN_TIMEOUT) for future in pending]

    assert completed == [_OPERATIONS_PER_THREAD] * _WORKERS, (
        f"only {sum(completed)} of {_OPERATIONS_PER_THREAD * _WORKERS} operations ran to completion"
    )


def _measurable_serial_run(doc: HexDocument) -> tuple[int, float]:
    """Find a scan count whose serial run lasts long enough to compare against.

    The count is calibrated rather than fixed because how long one scan takes
    depends on the machine and on how large the located binary is. A count that
    is generous on one machine is noise on another, and noise here does not fail
    honestly: four threads each doing half a millisecond of work take about as
    long as four threads starting, whether or not they overlapped.

    Args:
        doc: Document to scan.

    Returns:
        tuple[int, float]: Scans performed, and the seconds they took.
    """
    scans = _PARALLEL_ITERATIONS
    while scans <= _CALIBRATION_CAP:
        started = time.perf_counter()
        for _ in range(scans):
            doc.byte_statistics()
        elapsed = time.perf_counter() - started
        if elapsed >= _MIN_BASELINE:
            return scans, elapsed
        scans *= 2
    pytest.fail(f"{_CALIBRATION_CAP} scans still finished inside {_MIN_BASELINE}s, so no timing here decides anything")


def test_reads_of_one_document_overlap(
    hexcore: types.ModuleType,
    engine_binary: str,
) -> None:
    """Concurrent reads finish far sooner than the same reads run back to back.

    Not raising would also be satisfied by a lock that serialised every call, so
    this measures that readers genuinely proceed together. ``byte_statistics``
    is the instrument because it is a sequential scan inside the engine that
    releases the GIL, so any speed-up comes from the reads overlapping and not
    from the engine's own use of rayon.

    Args:
        hexcore: The imported native module.
        engine_binary: A real binary to analyse.
    """
    available = os.cpu_count() or 1
    if available < _MIN_CPUS:
        pytest.skip(f"{available} core cannot overlap anything, so timing decides nothing")

    doc = hexcore.HexDocument.open(engine_binary)
    doc.byte_statistics()

    scans, baseline = _measurable_serial_run(doc)

    def scan() -> None:
        """Run the same number of scans this thread's share requires."""
        for _ in range(scans):
            doc.byte_statistics()

    threads = [threading.Thread(target=scan, name=f"scan-{index}") for index in range(_PARALLEL_THREADS)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=_JOIN_TIMEOUT)
    concurrent = time.perf_counter() - started

    assert not [thread for thread in threads if thread.is_alive()], "the concurrent scans deadlocked"

    serialised = baseline * _PARALLEL_THREADS
    assert concurrent < serialised * _PARALLEL_MARGIN, (
        f"{_PARALLEL_THREADS} concurrent scans took {concurrent:.3f}s against a serialised "
        f"{serialised:.3f}s, so the reads are not overlapping"
    )


def test_entropy_map_bytes_matches_entropy_map(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """The packed entropy map decodes to exactly the list form.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    listed: list[float] = doc.entropy_map(_ENTROPY_BLOCK)
    packed: bytes = doc.entropy_map_bytes(_ENTROPY_BLOCK)

    assert len(packed) == len(listed) * struct.calcsize("<d")
    assert list(struct.unpack(f"<{len(listed)}d", packed)) == listed


def test_byte_distribution_bytes_matches_byte_distribution_full(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """The packed distribution decodes to exactly the list form.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    listed: list[int] = doc.byte_distribution_full()
    packed: bytes = doc.byte_distribution_bytes()

    assert len(packed) == _DISTRIBUTION_CELLS * struct.calcsize("<Q")
    assert list(struct.unpack(f"<{_DISTRIBUTION_CELLS}Q", packed)) == listed
    assert sum(listed) == len(sample_bytes)


def test_digram_matrix_bytes_matches_digram_matrix(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """The packed digram grid decodes to exactly the list form.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    listed: list[int] = doc.digram_matrix()
    packed: bytes = doc.digram_matrix_bytes()

    assert len(packed) == _DIGRAM_CELLS * struct.calcsize("<Q")
    assert list(struct.unpack(f"<{_DIGRAM_CELLS}Q", packed)) == listed
    assert sum(listed) == max(len(sample_bytes) - 1, 0)


def test_read_window_returns_the_bytes_read_says(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """A window holds the same bytes the ordinary read returns.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    window, tags, _, total = doc.read_window(0, len(sample_bytes))

    assert window == doc.read(0, len(sample_bytes))
    assert window == sample_bytes
    assert len(tags) == len(window)
    assert total == doc.length()


def test_read_window_tags_agree_with_byte_type_distribution(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """Each tag counts into the class the distribution accessor counts it into.

    The oracle is the engine's own ``byte_type_distribution`` over exactly the
    windowed bytes, so the two cannot disagree about any byte value without this
    failing.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    window, tags, _, _ = doc.read_window(0, len(sample_bytes))

    expected = hexcore.HexDocument.open_bytes(window).byte_type_distribution()
    counted = (tags.count(0), tags.count(1), tags.count(2), tags.count(3))

    assert counted == expected
    assert sum(counted) == len(window)


def test_generation_advances_only_when_the_bytes_change(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """Content edits move the counter; reads and metadata leave it alone.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)
    start = doc.generation()

    doc.entropy()
    doc.byte_statistics()
    doc.read(0, 16)
    doc.read_window(0, 16)
    assert doc.generation() == start, "a read advanced the generation"

    doc.add_bookmark(0, 4, "label", "#ffffff")
    doc.add_va_mapping(0, 0x400000, 16)
    assert doc.generation() == start, "annotating the document advanced the generation"

    doc.write_bytes(0, b"\x00")
    after_write = doc.generation()
    assert after_write > start, "a write did not advance the generation"

    doc.set_bit(1, 0, value=True)
    assert doc.generation() > after_write, "a bit edit did not advance the generation"

    before_undo = doc.generation()
    assert doc.undo() is True
    assert doc.generation() > before_undo, "undo changed the bytes without advancing the generation"


def test_read_window_reports_the_generation_of_the_bytes_it_returns(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """The generation a window carries is the one the document is at.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)

    _, _, before, _ = doc.read_window(0, 16)
    assert before == doc.generation()

    doc.write_bytes(0, b"\xff")
    window, _, after, _ = doc.read_window(0, 16)

    assert after == doc.generation()
    assert after > before
    assert window[0] == 0xFF


def _flip_until(doc: HexDocument, stop: threading.Event) -> int:
    """Alternate the document's first byte until the reader has finished.

    Args:
        doc: The shared document.
        stop: Set by the reader once it has taken every sample it wants.

    Returns:
        int: Writes performed, which the caller checks is not zero.
    """
    writes = 0
    while not stop.is_set() and writes < _SKEW_WRITE_CAP:
        doc.write_bytes(0, bytes((_SKEW_MARKS[writes % len(_SKEW_MARKS)],)))
        writes += 1
    return writes


def _first_skew(samples: list[tuple[int, int]]) -> str | None:
    """Find a sample whose byte is not the one its generation implies.

    The writer alternates deterministically and every write advances the counter
    by one, so the byte standing at a given generation is fixed: the write that
    produced generation ``g`` was the ``g``-th, and wrote ``_SKEW_MARKS[(g - 1)
    % 2]``. That makes the expected value derived from the writer's own rule
    rather than restated here, and it is checked per sample -- comparing samples
    against each other instead would almost never find two to compare, because a
    writer this fast gives nearly every sample a generation of its own.

    Generation zero is skipped: it is the document as opened, before any write.

    Args:
        samples: Observed ``(generation, first byte)`` pairs, in the order taken.

    Returns:
        str | None: Description of the first disagreement, or ``None`` when every
        sample carried the byte its generation calls for.
    """
    for generation, value in samples:
        if generation == 0:
            continue
        expected = _SKEW_MARKS[(generation - 1) % len(_SKEW_MARKS)]
        if value != expected:
            return f"generation {generation} should carry byte {expected:#04x} but carried {value:#04x}"
    return None


def _sample_paired(doc: HexDocument, stop: threading.Event) -> list[tuple[int, int]]:
    """Sample the first byte and its generation from one windowed read.

    Args:
        doc: The shared document.
        stop: Set once sampling is done, releasing the writer.

    Returns:
        list[tuple[int, int]]: The ``(generation, first byte)`` pairs observed.
    """
    samples: list[tuple[int, int]] = []
    for _ in range(_SKEW_SAMPLES):
        window, _, generation, _ = doc.read_window(0, _ONE_BYTE)
        samples.append((generation, window[0]))
    stop.set()
    return samples


def _sample_unpaired(doc: HexDocument, stop: threading.Event) -> list[tuple[int, int]]:
    """Sample the same two facts the way the window route used to, in two calls.

    Args:
        doc: The shared document.
        stop: Set once sampling is done, releasing the writer.

    Returns:
        list[tuple[int, int]]: The ``(generation, first byte)`` pairs observed.
    """
    samples: list[tuple[int, int]] = []
    for _ in range(_SKEW_SAMPLES):
        generation = doc.generation()
        samples.append((generation, doc.read(0, _ONE_BYTE)[0]))
    stop.set()
    return samples


def _sample_under_a_writer(
    doc: HexDocument,
    sampler: Callable[[HexDocument, threading.Event], list[tuple[int, int]]],
) -> list[tuple[int, int]]:
    """Run a sampler while another thread rewrites the byte it is watching.

    Args:
        doc: The shared document.
        sampler: Takes the samples and sets the stop event when finished.

    Returns:
        list[tuple[int, int]]: Whatever the sampler observed.
    """
    stop = threading.Event()
    with ThreadPoolExecutor(max_workers=_ONE_WRITER) as pool:
        writing = pool.submit(_flip_until, doc, stop)
        try:
            samples = sampler(doc, stop)
        finally:
            stop.set()
        assert writing.result(timeout=_JOIN_TIMEOUT) > 0, "the writer never ran, so nothing could skew"
    return samples


def test_a_window_never_reports_a_generation_its_bytes_did_not_have(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """The generation and the bytes come from one acquisition, so they agree.

    A client caches decoded windows against the generation they arrived with, so
    a window carrying a generation its bytes never had is served from cache long
    after it stopped being true. Watching one byte that a second thread rewrites
    to a known schedule makes that visible: every generation implies exactly one
    byte value, and any other value is a pairing the document never held.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)

    samples = _sample_under_a_writer(doc, _sample_paired)

    skew = _first_skew(samples)
    assert skew is None, skew
    assert len({value for _, value in samples}) > 1, "the byte never changed, so no skew could have shown"


def test_the_unpaired_control_really_does_skew_the_generation(
    hexcore: types.ModuleType,
    sample_bytes: bytes,
) -> None:
    """Reading the two facts separately produces the pairing the window prevents.

    Without this the test above would pass just as well against a document
    nobody was writing to, or one whose lock happened to serialise every sample.
    Asking for the generation and the bytes in two calls is exactly what the
    window route did before it was given ``read_window``, and it must be caught
    skewing for the atomic version's clean result to mean anything.

    Args:
        hexcore: The imported native module.
        sample_bytes: A known payload.
    """
    doc = hexcore.HexDocument.open_bytes(sample_bytes)

    samples = _sample_under_a_writer(doc, _sample_unpaired)

    assert _first_skew(samples) is not None, (
        f"{_SKEW_SAMPLES} unpaired samples never caught the generation disagreeing with the bytes, "
        "so this control cannot show that the paired read is what keeps them together"
    )
