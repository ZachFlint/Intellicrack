# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit7 F-0042 regression tests for streaming BPS/UPS patch export.

These tests verify that ``HexEditorBridge.export_patches_bps`` and
``HexEditorBridge.export_patches_ups`` never materialise the full
source file as a Python ``bytes`` value on the Python heap, regardless
of which underlying code path is taken:

1. The native Rust path-based exporter (``export_patches_bps_from_path``
   / ``export_patches_ups_from_path``) memory-maps the source inside
   Rust and hands the slice straight to the encoder; the Python heap
   sees only the returned patch bytes.
2. The legacy byte-slice Rust path (``export_patches_bps`` /
   ``export_patches_ups``) receives an :class:`mmap.mmap` object via
   the buffer protocol, so the source pages flow through Rust without
   first being copied to a Python ``bytes`` value.
3. The pure-Python fallback exposed via
   :meth:`HexEditorBridge._export_patches_bps_pyfallback` (and the UPS
   sibling) walks the source through an :class:`mmap.mmap` view and
   never calls ``bytes(mm)``.

The principal load-bearing assertion is that the source object handed
to the encoder is an :class:`mmap.mmap` view rather than a
:class:`bytes` materialisation of the source file. This invariant is
verified end-to-end against a multi-gigabyte sparse source file: the
file size is large enough that the previous ``bytes(self._load_source_via_mmap(...))``
materialisation would have allocated a multi-GiB :class:`bytes` value
on the Python heap (and would also have required multi-GiB of
contiguous physical disk on the temp volume to back the read). The
streaming implementation completes the source-handoff portion of the
export without that allocation.

The BPS / UPS algorithms' own per-byte hash-index data structures
scale linearly with the source size and are not part of the F-0042
remediation surface; tests that need to verify end-to-end roundtrip
correctness do so on small inputs instead.
"""

from __future__ import annotations

import asyncio
import base64
import mmap
import os
import tempfile
import tracemalloc
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


intellicrack_hexcore: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


_LARGE_SOURCE_BYTES: Final[int] = 2 * 1024 * 1024 * 1024 + 4096
"""Synthetic multi-GiB source file size used in streaming tests.

Sized at slightly more than 2 GiB so any code path that tried to
allocate a Python ``bytes`` value for the whole source would
immediately push the Python interpreter's heap well past the bounds
allowed by the assertions below. The file is created sparse via
:func:`io.IOBase.truncate` so it consumes negligible real disk on
NTFS / ext4 / APFS.
"""

_SMALL_SOURCE_BYTES: Final[int] = 4 * 1024 * 1024
"""Small source size for end-to-end roundtrip correctness tests.

Bounded well below the per-byte memory cost of the BPS/UPS encoder
indices so the roundtrip tests run in a few hundred milliseconds.
"""

_MAX_PEAK_BYTES: Final[int] = 64 * 1024 * 1024
"""Upper bound on tracemalloc peak during the source-handoff phase.

Comfortably exceeds the small Python-heap working set involved in
opening the source mmap and dispatching to the encoder, but is an
order of magnitude smaller than :data:`_LARGE_SOURCE_BYTES` so a
regression that re-introduces a ``bytes(mm)`` materialisation of the
multi-GiB source would push the peak above this threshold.
"""

_TARGET_PAYLOAD: Final[bytes] = b"\x00" * 4096
"""Document payload used as the BPS/UPS target.

A small all-zero buffer keeps the encoder's emitted patch tiny so
test runtimes stay bounded.
"""


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _call_apply(bridge: HexEditorBridge, attr: str, patch: bytes, source: bytes) -> bytes:
    """Invoke a protected ``_apply_*_patch`` method via ``getattr``.

    Args:
        bridge: Bridge whose method is invoked.
        attr: Attribute name of the protected applier.
        patch: Encoded BPS / UPS patch bytes.
        source: Original source bytes the patch applies against.

    Returns:
        bytes: Bytes produced by applying ``patch`` to ``source``.
    """
    fn = getattr(bridge, attr)
    if not callable(fn):
        pytest.fail(f"{attr} is not callable")
    result = fn(patch, source)
    if not isinstance(result, (bytes, bytearray)):
        pytest.fail(f"{attr} did not return bytes")
    return bytes(result)


def _make_sparse_source(path: Path, size: int) -> None:
    """Create a sparse file of ``size`` bytes at ``path``.

    On Windows NTFS and POSIX filesystems alike, opening a file in
    truncate mode and calling :meth:`io.IOBase.truncate` to a larger
    size yields a logically zero-filled file whose physical disk
    footprint is the size of any explicitly written data (here zero),
    because the trailing zero region is allocated lazily.

    Args:
        path: Destination filesystem path; overwritten if it exists.
        size: Logical length, in bytes, that the file should report.
    """
    with path.open("wb") as fh:
        fh.truncate(size)


def _open_bridge_with_target(payload: bytes) -> tuple[HexEditorBridge, Path]:
    """Return a bridge whose document holds ``payload``.

    Args:
        payload: Raw bytes the bridge's document should expose.

    Returns:
        tuple[HexEditorBridge, Path]: The bridge instance and the
        backing temp-file path the caller is responsible for unlinking.
    """
    fd, path_str = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(payload)
    bridge = HexEditorBridge()
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
    return bridge, path


class _SourceCapture:
    """Records the type of source passed to a patched encoder.

    Used to assert the encoder receives an :class:`mmap.mmap` object
    rather than a :class:`bytes` value, which is the load-bearing
    F-0042 invariant for the Python fallback paths.
    """

    def __init__(self) -> None:
        """Initialise an empty capture record."""
        self.source_type: type | None = None
        self.source_len: int | None = None

    def capture(self, source: bytes | mmap.mmap) -> None:
        """Record ``source``'s runtime type and length.

        Args:
            source: The buffer the encoder would have consumed.
        """
        self.source_type = type(source)
        self.source_len = len(source)


def _patch_builder(
    bridge: HexEditorBridge,
    attr: str,
    capture: _SourceCapture,
) -> Callable[[], None]:
    """Replace ``bridge.attr`` with a recording stub.

    Args:
        bridge: Bridge whose internal patch builder is replaced.
        attr: Attribute name of the builder method
            (``_build_bps_patch`` or ``_build_ups_patch``).
        capture: Receiver for the recorded source type / length.

    Returns:
        Callable[[], None]: A restore callable that puts the original
        method back when invoked.
    """
    original = getattr(bridge, attr)

    def _stub(source: bytes | mmap.mmap, target: bytes | mmap.mmap) -> bytes:
        """Capture the source type and emit a minimal valid patch.

        Args:
            source: Source buffer the real encoder would index.
            target: Target buffer (unused; recorded only via length).

        Returns:
            bytes: A short placeholder patch with the correct magic so
            the calling bridge logic accepts it.
        """
        del target
        capture.capture(source)
        if attr == "_build_bps_patch":
            return b"BPS1" + b"\x00" * 32
        return b"UPS1" + b"\x00" * 32

    setattr(bridge, attr, _stub)

    def _restore() -> None:
        """Restore the original encoder method on ``bridge``."""
        setattr(bridge, attr, original)

    return _restore


class TestBpsStreamingPyfallback:
    """The pure-Python BPS fallback streams the source through mmap."""

    def test_pyfallback_passes_mmap_not_bytes(self, tmp_path: Path) -> None:
        """The fallback hands the encoder an mmap, not a bytes copy.

        Patches :meth:`HexEditorBridge._build_bps_patch` so the test
        records the runtime type of the source argument; this is the
        precise object the encoder would consume. The expected type
        is :class:`mmap.mmap`, because the F-0042 fix replaced the
        ``bytes(self._load_source_via_mmap(...))`` call with a
        buffer-protocol pass-through.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "small_bps_source.bin"
        _make_sparse_source(source_path, _SMALL_SOURCE_BYTES)
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        capture = _SourceCapture()
        restore = _patch_builder(bridge, "_build_bps_patch", capture)
        try:
            fn = getattr(bridge, "_export_patches_bps_pyfallback")
            if not callable(fn):
                pytest.fail("_export_patches_bps_pyfallback is not callable")
            fn(str(source_path))
        finally:
            restore()
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        assert capture.source_type is mmap.mmap, (
            f"BPS fallback handed encoder source of type {capture.source_type}; expected mmap.mmap (F-0042 regression)"
        )
        assert capture.source_len == _SMALL_SOURCE_BYTES

    def test_pyfallback_peak_heap_below_source_size_multi_gib(
        self,
        tmp_path: Path,
    ) -> None:
        """Multi-GiB source never crosses the Python heap boundary.

        Creates a 2 GiB sparse source and replaces the BPS encoder
        with a stub. The source-handoff phase covers the entire
        ``_export_patches_bps_pyfallback`` body up to the encoder
        call; if that phase materialised the source as a Python
        ``bytes`` value, tracemalloc would observe a 2 GiB peak.
        With the F-0042 fix in place the peak is bounded by the
        encoder's stub plus the open-file machinery.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "large_bps_source.bin"
        _make_sparse_source(source_path, _LARGE_SOURCE_BYTES)
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        capture = _SourceCapture()
        restore = _patch_builder(bridge, "_build_bps_patch", capture)
        try:
            tracemalloc.start()
            tracemalloc.clear_traces()
            try:
                fn = getattr(bridge, "_export_patches_bps_pyfallback")
                if not callable(fn):
                    pytest.fail("_export_patches_bps_pyfallback is not callable")
                fn(str(source_path))
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        finally:
            restore()
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        assert capture.source_type is mmap.mmap, (
            f"BPS fallback materialised source as {capture.source_type} instead of mmap.mmap (F-0042 regression)"
        )
        assert capture.source_len == _LARGE_SOURCE_BYTES
        assert peak < _MAX_PEAK_BYTES, (
            f"BPS pyfallback source-handoff peak {peak} bytes exceeds bound "
            f"{_MAX_PEAK_BYTES} for {_LARGE_SOURCE_BYTES}-byte source - "
            "source is being copied onto the Python heap"
        )

    def test_pyfallback_handles_empty_source(self, tmp_path: Path) -> None:
        """The Python fallback handles a zero-length source file.

        :func:`mmap.mmap` refuses zero-length mappings on Windows, so
        :meth:`HexEditorBridge._open_source_mmap` short-circuits empty
        files to ``b""``. The encoder must still produce a valid BPS1
        patch when handed that empty source.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "empty_bps_source.bin"
        source_path.write_bytes(b"")
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        try:
            fn = getattr(bridge, "_export_patches_bps_pyfallback")
            if not callable(fn):
                pytest.fail("_export_patches_bps_pyfallback is not callable")
            raw_obj = fn(str(source_path))
            if not isinstance(raw_obj, (bytes, bytearray)):
                pytest.fail("BPS fallback did not return bytes")
            raw = bytes(raw_obj)
            assert raw[:4] == b"BPS1"
        finally:
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)

    def test_pyfallback_small_source_roundtrip(self, tmp_path: Path) -> None:
        """A small source produces an applicable BPS patch end-to-end.

        Verifies the end-to-end BPS export still works correctly when
        the source is fed via the buffer protocol; the produced patch
        must decode and apply cleanly with the bridge's import path.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source = b"".join(bytes((i & 0xFF, (i >> 8) & 0xFF)) for i in range(2048))
        target = bytearray(source)
        target[100:108] = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
        source_path = tmp_path / "small_bps_roundtrip_source.bin"
        source_path.write_bytes(source)
        bridge, target_path = _open_bridge_with_target(bytes(target))
        try:
            fn = getattr(bridge, "_export_patches_bps_pyfallback")
            if not callable(fn):
                pytest.fail("_export_patches_bps_pyfallback is not callable")
            raw_obj = fn(str(source_path))
            if not isinstance(raw_obj, (bytes, bytearray)):
                pytest.fail("BPS fallback did not return bytes")
            raw = bytes(raw_obj)
            assert raw[:4] == b"BPS1"
            applied = _call_apply(bridge, "_apply_bps_patch", raw, source)
            assert applied == bytes(target)
        finally:
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)


class TestUpsStreamingPyfallback:
    """The pure-Python UPS fallback streams the source through mmap."""

    def test_pyfallback_passes_mmap_not_bytes(self, tmp_path: Path) -> None:
        """The UPS fallback hands the encoder an mmap, not a bytes copy.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "small_ups_source.bin"
        _make_sparse_source(source_path, _SMALL_SOURCE_BYTES)
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        capture = _SourceCapture()
        restore = _patch_builder(bridge, "_build_ups_patch", capture)
        try:
            fn = getattr(bridge, "_export_patches_ups_pyfallback")
            if not callable(fn):
                pytest.fail("_export_patches_ups_pyfallback is not callable")
            fn(str(source_path))
        finally:
            restore()
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        assert capture.source_type is mmap.mmap, (
            f"UPS fallback handed encoder source of type {capture.source_type}; expected mmap.mmap (F-0042 regression)"
        )
        assert capture.source_len == _SMALL_SOURCE_BYTES

    def test_pyfallback_peak_heap_below_source_size_multi_gib(
        self,
        tmp_path: Path,
    ) -> None:
        """Multi-GiB UPS source never crosses the Python heap boundary.

        Mirrors :meth:`TestBpsStreamingPyfallback.test_pyfallback_peak_heap_below_source_size_multi_gib`
        for the UPS path: a 2 GiB sparse source is fed through the
        pure-Python UPS fallback whose encoder has been stubbed out;
        the F-0042 fix means the source-handoff phase never crosses
        the Python heap boundary, so tracemalloc peak stays bounded.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "large_ups_source.bin"
        _make_sparse_source(source_path, _LARGE_SOURCE_BYTES)
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        capture = _SourceCapture()
        restore = _patch_builder(bridge, "_build_ups_patch", capture)
        try:
            tracemalloc.start()
            tracemalloc.clear_traces()
            try:
                fn = getattr(bridge, "_export_patches_ups_pyfallback")
                if not callable(fn):
                    pytest.fail("_export_patches_ups_pyfallback is not callable")
                fn(str(source_path))
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        finally:
            restore()
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        assert capture.source_type is mmap.mmap, (
            f"UPS fallback materialised source as {capture.source_type} instead of mmap.mmap (F-0042 regression)"
        )
        assert capture.source_len == _LARGE_SOURCE_BYTES
        assert peak < _MAX_PEAK_BYTES, (
            f"UPS pyfallback source-handoff peak {peak} bytes exceeds bound "
            f"{_MAX_PEAK_BYTES} for {_LARGE_SOURCE_BYTES}-byte source - "
            "source is being copied onto the Python heap"
        )


class TestBpsStreamingBackend:
    """The native Rust BPS exporters consume the source without copy."""

    def test_path_based_backend_binding_is_present(self) -> None:
        """The Rust ``HexDocument`` exposes the path-based exporter.

        F-0042's primary remediation introduces a Rust binding that
        memory-maps the source inside Rust so the source never crosses
        the Python heap. This test pins that binding's presence; if
        the binding is removed the bridge would silently fall back to
        the byte-slice path and the regression would slip through.
        """
        doc = intellicrack_hexcore.HexDocument()
        assert hasattr(doc, "export_patches_bps_from_path"), (
            "Rust backend lacks export_patches_bps_from_path - F-0042 binding was not built"
        )
        assert hasattr(doc, "export_patches_ups_from_path"), (
            "Rust backend lacks export_patches_ups_from_path - F-0042 binding was not built"
        )

    def test_path_based_bps_export_returns_valid_patch(
        self,
        tmp_path: Path,
    ) -> None:
        """The path-based BPS exporter produces a valid BPS1 patch.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source = b"".join(bytes((i & 0xFF,)) for i in range(8192))
        target = bytearray(source)
        target[200:204] = b"\xff\xfe\xfd\xfc"
        source_path = tmp_path / "rust_path_bps_source.bin"
        source_path.write_bytes(source)
        bridge, target_path = _open_bridge_with_target(bytes(target))
        try:
            b64 = _run(bridge.export_patches_bps(str(source_path)))
            decoded = base64.b64decode(b64)
            assert decoded[:4] == b"BPS1"
            applied = _call_apply(bridge, "_apply_bps_patch", decoded, source)
            assert applied == bytes(target)
        finally:
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)

    def test_path_based_ups_export_returns_valid_patch(
        self,
        tmp_path: Path,
    ) -> None:
        """The path-based UPS exporter produces a valid UPS1 patch.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source = b"".join(bytes((i & 0xFF,)) for i in range(8192))
        target = bytearray(source)
        target[300:308] = b"\x10\x11\x12\x13\x14\x15\x16\x17"
        source_path = tmp_path / "rust_path_ups_source.bin"
        source_path.write_bytes(source)
        bridge, target_path = _open_bridge_with_target(bytes(target))
        try:
            b64 = _run(bridge.export_patches_ups(str(source_path)))
            decoded = base64.b64decode(b64)
            assert decoded[:4] == b"UPS1"
            applied = _call_apply(bridge, "_apply_ups_patch", decoded, source)
            assert applied == bytes(target)
        finally:
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)

    def test_legacy_byte_slice_path_accepts_mmap(self, tmp_path: Path) -> None:
        """The legacy byte-slice fallback receives an mmap, not bytes.

        Forces the fallback within
        :meth:`HexEditorBridge._export_patches_bps_via_backend` by
        wrapping the document in a shim that hides the path-based
        entrypoint and intercepts the byte-slice call so the test can
        confirm the source object's runtime type. The bridge must
        hand the inner backend an :class:`mmap.mmap` view rather than
        a :class:`bytes` materialisation of the source.

        Args:
            tmp_path: Pytest-provided temp directory.
        """
        source_path = tmp_path / "rust_legacy_bps_source.bin"
        _make_sparse_source(source_path, _SMALL_SOURCE_BYTES)
        bridge, target_path = _open_bridge_with_target(_TARGET_PAYLOAD)
        captured: list[type] = []

        class _LegacyDoc:
            """Shim that hides the path-based BPS exporter.

            Forwards the legacy byte-slice ``export_patches_bps``
            call to the real Rust document but deliberately omits
            ``export_patches_bps_from_path`` so
            :meth:`HexEditorBridge._export_patches_bps_via_backend`
            falls through to the mmap pass-through branch.
            """

            def __init__(self, inner: object) -> None:
                """Capture the wrapped backend document.

                Args:
                    inner: The real Rust ``HexDocument`` instance.
                """
                self._inner = inner

            def export_patches_bps(self, source: object) -> bytes:
                """Record the runtime type of ``source`` and emit a stub patch.

                Args:
                    source: Buffer-protocol source data the encoder
                        would normally read.

                Returns:
                    bytes: Minimal valid-magic BPS patch with all-zero
                    payload so the bridge's logging path treats it as
                    a successful export.
                """
                captured.append(type(source))
                return b"BPS1" + b"\x00" * 32

            def length(self) -> int:
                """Forward the document length to the inner backend.

                Returns:
                    int: Number of bytes in the document.
                """
                fn = getattr(self._inner, "length")
                if not callable(fn):
                    pytest.fail("inner backend lacks length")
                result = fn()
                if not isinstance(result, int):
                    pytest.fail("inner backend length returned non-int")
                return result

        bridge.document = _LegacyDoc(bridge.document)
        assert not hasattr(bridge.document, "export_patches_bps_from_path")
        try:
            _run(bridge.export_patches_bps(str(source_path)))
        finally:
            target_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        assert captured, "legacy byte-slice path was not exercised"
        assert captured[-1] is mmap.mmap, (
            f"Legacy byte-slice backend received source of type {captured[-1]}; expected mmap.mmap (F-0042 regression)"
        )
