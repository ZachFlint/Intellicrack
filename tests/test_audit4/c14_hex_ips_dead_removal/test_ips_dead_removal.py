# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
"""Regression tests for F-0008: dead _ips.py module removal.

Verifies that the dead-code module is gone, and that both live IPS code
paths (bridge._build_ips_from_patches and HexDocument.export_patches_ips)
remain functional and produce valid IPS payloads.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import struct
import sys
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    import types
    from collections.abc import Callable, Coroutine
    from pathlib import Path

_build_ips: Callable[..., bytes] = getattr(HexEditorBridge, "_build_ips_from_patches")


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

_IPS_MAGIC = b"PATCH"
_IPS_FOOTER = b"EOF"
_IPS32_MAGIC = b"IPS32"
_IPS32_FOOTER = b"EEOF"


def _expected_ips_record(offset: int, data: bytes) -> bytes:
    """Encode one standard-IPS patch record per the IPS specification.

    An IPS record is a 3-byte big-endian offset followed by a 2-byte
    big-endian size and the literal patch bytes. This is recomputed
    independently of the production code so it can serve as an oracle
    for a single non-RLE record whose size fits the 16-bit field and
    whose offset does not collide with the ``EOF`` terminator value.

    Args:
        offset: The byte offset the record patches (``0..0xFFFFFE``).
        data: The replacement bytes (``1..0xFFFF`` bytes).

    Returns:
        bytes: The encoded offset, size, and data bytes of the record.
    """
    return struct.pack(">I", offset)[1:] + struct.pack(">H", len(data)) + data


def _expected_ips_payload(offset: int, data: bytes) -> bytes:
    """Build the full standard-IPS blob for a single patch record.

    Args:
        offset: The byte offset the record patches (``0..0xFFFFFE``).
        data: The replacement bytes (``1..0xFFFF`` bytes).

    Returns:
        bytes: ``PATCH`` + the encoded record + ``EOF``.
    """
    return _IPS_MAGIC + _expected_ips_record(offset, data) + _IPS_FOOTER


@pytest.fixture
def hexcore() -> types.ModuleType:
    """Return the imported intellicrack_hexcore native module.

    Returns:
        types.ModuleType: The intellicrack_hexcore native module.
    """
    return hexcore_mod


@pytest.fixture
def sample_bytes() -> bytes:
    """Provide a 256-byte test payload.

    Returns:
        bytes: 256 bytes from 0x00 through 0xFF.
    """
    return bytes(range(256))


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Create and initialize a HexEditorBridge instance.

    Returns:
        HexEditorBridge: An initialized HexEditorBridge.
    """
    b = HexEditorBridge()
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    loop.run_until_complete(b.initialize())
    return b


def _run_async(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class _FakeDocument:
    """Minimal document stub that drives the real search functions without Qt.

    Only implements the subset of the document interface that the pure
    ``execute_text_search`` and ``execute_numeric_search`` fallback paths
    actually call.  No behaviour of the unit-under-test is replaced — the
    stub only supplies the *external* document dependency.
    """

    def __init__(self, data: bytes) -> None:
        """Initialise the stub with a fixed byte payload.

        Args:
            data: The bytes backing this fake document.
        """
        self._data = data

    def search_hex(self, query: str, max_results: int) -> list[tuple[int, int]]:
        """Return matches for ``query`` (space-separated hex bytes) in ``_data``.

        Args:
            query: Hex bytes to search for, e.g. ``"DE AD BE EF"``.
            max_results: Maximum number of matches to return.

        Returns:
            list[tuple[int, int]]: ``(offset, length)`` pairs for each match.
        """
        needle = bytes.fromhex(query.replace(" ", ""))
        results: list[tuple[int, int]] = []
        start = 0
        while len(results) < max_results:
            idx = self._data.find(needle, start)
            if idx == -1:
                break
            results.append((idx, len(needle)))
            start = idx + 1
        return results

    def length(self) -> int:
        """Return the total byte length of the document.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Read a slice of the document at ``offset``.

        Args:
            offset: Start position in bytes.
            length: Number of bytes to read.

        Returns:
            bytes: The requested byte slice.
        """
        return self._data[offset : offset + length]


class TestDeadModuleRemoved:
    """Regression guard: importing the deleted _ips module must raise ModuleNotFoundError."""

    def test_ips_module_import_raises_module_not_found(self) -> None:
        """Verify that importing the deleted module raises ModuleNotFoundError."""
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("intellicrack.ui.panels.hex_editor._ips")

    def test_ips_module_not_in_sys_modules(self) -> None:
        """Verify that the deleted module is absent from sys.modules after a failed import."""
        with contextlib.suppress(ModuleNotFoundError):
            importlib.import_module("intellicrack.ui.panels.hex_editor._ips")
        assert "intellicrack.ui.panels.hex_editor._ips" not in sys.modules

    def test_hex_editor_package_execute_text_search_returns_correct_offsets(self) -> None:
        """Verify execute_text_search from the package finds known hex bytes at the right offset.

        Imports ``execute_text_search`` directly from the package's public
        namespace (via ``__all__``), drives it against a ``_FakeDocument``
        whose ``search_hex`` delegates to the real needle-scan logic, and
        asserts both the *offset* and *length* of the single expected match.

        The oracle is independent: ``bytes.find`` on the same payload locates
        the needle at offset 8; the production function must return exactly
        ``[(8, 3)]``.

        Falsifiability proof — one-line mutation that makes this test FAIL:
            In ``src/intellicrack/ui/panels/hex_editor/search.py``, change
            ``return [(r[0], r[1]) for r in raw]`` to
            ``return [(r[0] + 1, r[1]) for r in raw]`` — the offset 9 != 8
            assertion fails immediately.
        """
        mod = importlib.import_module("intellicrack.ui.panels.hex_editor")
        execute_text_search = getattr(mod, "execute_text_search")

        payload = bytes(range(16))
        needle_bytes = b"\x08\x09\x0a"
        doc = _FakeDocument(payload)

        oracle_offset = payload.find(needle_bytes)
        assert oracle_offset == 8

        results: list[tuple[int, int]] = execute_text_search(doc, "Hex", "08 09 0A", "utf-8", 10)

        assert len(results) == 1
        assert results[0][0] == oracle_offset
        assert results[0][1] == len(needle_bytes)

    def test_hex_editor_package_execute_numeric_search_locates_known_value(self) -> None:
        """Verify execute_numeric_search from the package finds a known 32-bit LE value.

        Imports ``execute_numeric_search`` directly from the package's public
        namespace (via ``__all__``), drives the pure Python fallback path
        (``use_native=False``) against a ``_FakeDocument`` containing a
        known 32-bit little-endian value, and asserts that the returned
        offset matches the independently computed expected position.

        The oracle is independent: ``struct.pack`` places the value at a
        known byte offset; the production fallback must find it there.

        Falsifiability proof — one-line mutation that makes this test FAIL:
            In ``src/intellicrack/ui/panels/hex_editor/search.py``, change
            ``if min_val <= fval <= max_val:`` to
            ``if min_val < fval <= max_val:`` — the exact-value equality
            case is excluded, no match is returned, ``len(results) == 0``
            and the assertion ``results[0][0] == 4`` fails.
        """
        mod = importlib.import_module("intellicrack.ui.panels.hex_editor")
        execute_numeric_search = getattr(mod, "execute_numeric_search")

        target_value = 0xDEAD_BEEF
        prefix = b"\x00\x00\x00\x00"
        payload = prefix + struct.pack("<I", target_value) + b"\xff\xff\xff\xff"
        doc = _FakeDocument(payload)

        oracle_offset = len(prefix)
        assert oracle_offset == 4

        results: list[tuple[int, int]] = execute_numeric_search(
            doc,
            float(target_value),
            float(target_value),
            "<I",
            4,
            1,
            10,
            use_native=False,
            size=4,
            signed=False,
            big_endian=False,
            is_range=False,
        )

        assert len(results) >= 1
        assert results[0][0] == oracle_offset
        assert results[0][1] == 4

    def test_hex_editor_package_does_not_expose_dead_ips_symbol(self) -> None:
        """Verify the hex_editor package does not re-export the deleted _ips symbol.

        Checks that the live package namespace contains no ``_ips`` attribute,
        proving the dead module was not accidentally re-introduced as a binding.

        This is intentionally a namespace-absence check and is kept as a
        companion to the two behavioral gates above, not as a standalone
        behavioral test.  It remains falsifiable: adding
        ``from intellicrack.ui.panels.hex_editor import _ips`` to any file
        re-imported by the package ``__init__`` will cause this assertion to
        fail.
        """
        mod = importlib.import_module("intellicrack.ui.panels.hex_editor")
        assert not hasattr(mod, "_ips")


class TestBridgeBuildIpsFromPatches:
    """Tests for the live IPS path on _build_ips."""

    def test_single_patch_encodes_exact_ips_bytes(self) -> None:
        """Verify the builder emits the exact spec-encoded IPS blob for one patch.

        The expected bytes are recomputed independently from the IPS
        specification (3-byte big-endian offset, 2-byte big-endian size,
        literal data, wrapped in ``PATCH``/``EOF``) so a stub returning
        ``b""`` or any other shape fails.
        """
        offset = 0x123456
        data = b"\xaa\xbb\xcc"
        result = _build_ips([(offset, data)])
        assert result == _expected_ips_payload(offset, data)

    def test_static_call_form_emits_exact_bytes(self) -> None:
        """Verify the builder is invocable off the class and yields the spec blob.

        Exercises the documented call shape (no instance) and asserts
        the resulting bytes equal the independently recomputed IPS blob,
        so the call shape is gated through real output rather than the
        descriptor type.
        """
        offset = 0x0042
        data = b"\xde\xad\xbe\xef"
        result = _build_ips([(offset, data)])
        assert result == _expected_ips_payload(offset, data)

    def test_offset_size_data_field_layout(self) -> None:
        """Verify the offset, size, and data fields decode back to the inputs.

        Decodes the produced record fields with ``struct`` (an oracle
        independent of the builder) and asserts each field round-trips
        to the original offset, length, and data bytes.
        """
        offset = 0x00ABCD
        data = b"\x10\x20\x30\x40\x50"
        result = _build_ips([(offset, data)])
        body = result[len(_IPS_MAGIC) : -len(_IPS_FOOTER)]
        decoded_offset = struct.unpack(">I", b"\x00" + body[0:3])[0]
        decoded_size = struct.unpack(">H", body[3:5])[0]
        decoded_data = body[5 : 5 + decoded_size]
        assert decoded_offset == offset
        assert decoded_size == len(data)
        assert decoded_data == data

    def test_ips_header_is_patch_magic(self) -> None:
        """Verify that the IPS payload begins with the PATCH magic header."""
        patches: list[tuple[int, bytes]] = [(0x00, b"\xde\xad\xbe\xef")]
        result = _build_ips(patches)
        assert result[:5] == _IPS_MAGIC

    def test_ips_footer_is_eof_marker(self) -> None:
        """Verify that the IPS payload ends with the EOF marker."""
        patches: list[tuple[int, bytes]] = [(0x20, b"\x11\x22\x33")]
        result = _build_ips(patches)
        assert result[-3:] == _IPS_FOOTER

    def test_ips32_header_is_ips32_magic(self) -> None:
        """Verify that the IPS32 payload begins with the IPS32 magic header."""
        patches: list[tuple[int, bytes]] = [(0x100, b"\xca\xfe")]
        result = _build_ips(patches, ips32=True)
        assert result[:5] == _IPS32_MAGIC

    def test_ips32_footer_is_eeof_marker(self) -> None:
        """Verify that the IPS32 payload ends with the EEOF marker."""
        patches: list[tuple[int, bytes]] = [(0x200, b"\xba\xbe")]
        result = _build_ips(patches, ips32=True)
        assert result[-4:] == _IPS32_FOOTER

    def test_minimum_ips_payload_size(self) -> None:
        """Verify that a single-byte patch produces at least 14 bytes of IPS payload.

        The minimum is: 5 (PATCH) + 3 (offset) + 2 (size) + 1 (data) + 3 (EOF) = 14.
        """
        patches: list[tuple[int, bytes]] = [(0x01, b"\xff")]
        result = _build_ips(patches)
        assert len(result) >= 14

    def test_multi_patch_ips_payload(self) -> None:
        """Verify that multiple patches produce a valid IPS payload with correct header and footer."""
        patches: list[tuple[int, bytes]] = [
            (0x00, b"\xaa\xbb"),
            (0x50, b"\xcc\xdd\xee"),
            (0xA0, b"\x11"),
        ]
        result = _build_ips(patches)
        assert result[:5] == _IPS_MAGIC
        assert result[-3:] == _IPS_FOOTER

    def test_empty_patches_list_produces_header_and_footer_only(self) -> None:
        """Verify that an empty patch list produces a payload of header plus footer only.

        The expected result is exactly PATCH + EOF = 8 bytes.
        """
        result = _build_ips([])
        assert result == _IPS_MAGIC + _IPS_FOOTER

    def test_overflow_on_negative_offset(self) -> None:
        """Verify that a negative patch offset raises OverflowError."""
        with pytest.raises(OverflowError):
            _build_ips([(-1, b"\x00")])

    def test_overflow_on_offset_exceeding_ips_max(self) -> None:
        """Verify that an offset exceeding the 24-bit IPS maximum raises OverflowError."""
        with pytest.raises(OverflowError):
            _build_ips([(0x1000000, b"\x00")])


class TestDocumentExportPatchesIps:
    """Tests for the live IPS path on HexDocument.export_patches_ips."""

    def test_export_patches_ips_emits_exact_spec_blob(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify export_patches_ips emits the exact spec-encoded IPS blob.

        Opens a real document, performs one contiguous overwrite, and
        asserts the produced bytes equal the independently recomputed
        IPS blob for that single record. A binding returning empty or
        malformed bytes fails.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        offset = 10
        data = b"\xaa\xbb\xcc"
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(offset, data)
        result = doc.export_patches_ips()
        assert bytes(result) == _expected_ips_payload(offset, data)

    def test_export_patches_ips_returns_bytes(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that export_patches_ips returns a bytes object.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(10, b"\xaa\xbb\xcc")
        result = doc.export_patches_ips()
        assert isinstance(result, bytes)

    def test_export_patches_ips_starts_with_patch_magic(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that the IPS payload from export_patches_ips begins with PATCH magic.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(0, b"\xde\xad\xbe\xef")
        result = doc.export_patches_ips()
        assert result[:5] == _IPS_MAGIC

    def test_export_patches_ips_ends_with_eof_marker(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that the IPS payload from export_patches_ips ends with the EOF marker.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(5, b"\x11\x22")
        result = doc.export_patches_ips()
        assert result[-3:] == _IPS_FOOTER

    def test_export_patches_ips_minimum_size(
        self,
        hexcore: types.ModuleType,
        sample_bytes: bytes,
    ) -> None:
        """Verify that a single-byte patch produces at least 14 bytes from export_patches_ips.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        doc.write_bytes(0, b"\xff")
        result = doc.export_patches_ips()
        assert len(result) >= 14

    def test_bridge_export_patches_ips_via_open_bytes(
        self,
        bridge: HexEditorBridge,
        sample_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        """Verify that the bridge export_patches path produces valid IPS for a modified document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            sample_bytes: The 256-byte payload fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bridge_ips_test.bin"
        f.write_bytes(sample_bytes)
        _run_async(bridge.open_file(str(f)))
        _run_async(bridge.write_bytes(0, "DE AD BE EF"))
        b64_result: str = str(_run_async(bridge.export_patches("ips")))
        decoded = base64.b64decode(b64_result)
        assert decoded[:5] == _IPS_MAGIC
        assert decoded[-3:] == _IPS_FOOTER
