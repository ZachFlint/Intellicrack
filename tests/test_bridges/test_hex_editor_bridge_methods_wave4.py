# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""P3-HEX-BRIDGE wave-4 gates.

Covers inspect_data_at, get_byte_statistics, get_content_classification,
insert_bytes, delete_bytes, and test_in_sandbox.

Every assertion uses an independent oracle derived from struct.unpack,
Shannon-entropy formula, known byte-sequence arithmetic, or documented
content-classification constants -- never from the same production
code under test.
"""

from __future__ import annotations

import asyncio
import math
import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore
import pytest

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolDefinition, ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")

_KNOWN_8: bytes = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
_DOC_DATA: bytes = _KNOWN_8 + bytes(10)

_ORACLE_UINT8: int = struct.unpack("<B", _KNOWN_8[:1])[0]
_ORACLE_INT8: int = struct.unpack("<b", _KNOWN_8[:1])[0]
_ORACLE_UINT16_LE: int = struct.unpack("<H", _KNOWN_8[:2])[0]
_ORACLE_INT16_LE: int = struct.unpack("<h", _KNOWN_8[:2])[0]
_ORACLE_UINT16_BE: int = struct.unpack(">H", _KNOWN_8[:2])[0]
_ORACLE_INT16_BE: int = struct.unpack(">h", _KNOWN_8[:2])[0]
_ORACLE_UINT32_LE: int = struct.unpack("<I", _KNOWN_8[:4])[0]
_ORACLE_INT32_LE: int = struct.unpack("<i", _KNOWN_8[:4])[0]
_ORACLE_UINT32_BE: int = struct.unpack(">I", _KNOWN_8[:4])[0]
_ORACLE_INT32_BE: int = struct.unpack(">i", _KNOWN_8[:4])[0]
_ORACLE_UINT64_LE: int = struct.unpack("<Q", _KNOWN_8[:8])[0]
_ORACLE_INT64_LE: int = struct.unpack("<q", _KNOWN_8[:8])[0]
_ORACLE_UINT64_BE: int = struct.unpack(">Q", _KNOWN_8[:8])[0]
_ORACLE_INT64_BE: int = struct.unpack(">q", _KNOWN_8[:8])[0]
_ORACLE_IPV4: str = ".".join(str(b) for b in _KNOWN_8[:4])
_ORACLE_RGBA8: str = f"#{_KNOWN_8[:4].hex()}"

_STATS_DATA: bytes = b"\x41\x41\x41\x42\x42\x43"

_NULL_64: bytes = b"\x00" * 64
_PLAINTEXT_64: bytes = b"Hello World Hello World Hello World Hello World Hello World !!!!"
_PE_HEADER_64: bytes = b"MZ" + b"\x90" * 62
_HIGH_ENTROPY_256: bytes = bytes(range(256))

assert len(_PLAINTEXT_64) == 64
assert len(_PE_HEADER_64) == 64
assert len(_HIGH_ENTROPY_256) == 256


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _open_doc(bridge: HexEditorBridge, data: bytes) -> Path:
    """Write ``data`` to a temp file and open it as the bridge's document.

    Args:
        bridge: Target bridge whose ``document`` attribute is assigned.
        data: Raw bytes to write to the temp file.

    Returns:
        Path: Path of the temp file holding the document data.
    """
    fd, path_str = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(data)
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
    return path


def _release_and_unlink(bridge: HexEditorBridge, path: Path) -> None:
    """Release the bridge document handle then delete the temp file.

    On Windows, ``HexDocument`` holds the backing file open via a
    memory-map maintained by the Rust piece-table.  Setting
    ``bridge.document`` to ``None`` drops the Python reference so the
    Rust ``Drop`` impl runs synchronously (CPython reference-counting)
    and the OS handle is closed before the unlink, preventing
    ``PermissionError: [WinError 5] Access is denied`` at teardown.

    Args:
        bridge: Bridge whose ``document`` attribute is cleared first.
        path: Temp file to delete after the handle is released.
    """
    bridge.document = None
    path.unlink(missing_ok=True)


def _oracle_shannon_entropy(histogram: dict[int, int]) -> float:
    """Compute Shannon entropy from a byte-value histogram.

    This function is the independent oracle used to verify that
    :meth:`get_byte_statistics` returns a correct histogram.  It does
    not call any production code.

    Args:
        histogram: Mapping from byte value (0-255) to occurrence count.

    Returns:
        float: Shannon entropy in bits per symbol (0.0 to 8.0).
    """
    total = sum(histogram.values())
    if total == 0:
        return 0.0
    h = 0.0
    for count in histogram.values():
        if count > 0:
            p = count / total
            h -= p * math.log2(p)
    return h


class _FakeSandboxBridge(ToolBridgeBase):
    """Minimal sandbox bridge that records ``run_binary`` invocations.

    Implements every abstract method of ``ToolBridgeBase`` with no-ops or
    stubs and exposes ``run_binary`` so the
    :meth:`HexEditorBridge.test_in_sandbox` dispatch path is exercised
    end-to-end against a real routing contract.
    """

    def __init__(self) -> None:
        """Initialise empty call ledger and default result payload."""
        super().__init__()
        self.calls: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {"exit_code": 0, "stdout": "ok", "stderr": ""}

    @property
    def name(self) -> ToolName:
        """The sandbox tool name.

        Returns:
            ToolName: ``ToolName.SANDBOX``.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """A minimal tool definition for type compliance.

        Returns:
            ToolDefinition: Stub definition with no functions.
        """
        return ToolDefinition(tool_name=ToolName.SANDBOX, description="fake", functions=[])

    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initializer satisfying the abstract contract.

        Args:
            tool_path: Ignored.
        """

    async def shutdown(self) -> None:
        """Delegate to base-class finaliser."""
        await super().shutdown()

    async def is_available(self) -> bool:
        """Report that the fake bridge is always available.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def run_binary(
        self,
        binary_path: str,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        time_limit: int = 30,
    ) -> dict[str, Any]:
        """Record the invocation and return the pre-configured result.

        Args:
            binary_path: Path to the binary submitted for execution.
            args: Command-line arguments list or ``None``.
            sandbox_type: Sandbox flavour string.
            time_limit: Execution timeout in seconds.

        Returns:
            dict[str, Any]: The ``result`` attribute set on this instance.
        """
        self.calls.append({
            "binary_path": binary_path,
            "args": args,
            "sandbox_type": sandbox_type,
            "time_limit": time_limit,
        })
        return self.result


class _FakeSandboxBridgeNoRunBinary(ToolBridgeBase):
    """Sandbox bridge that deliberately omits ``run_binary``.

    Used to exercise the ``TypeError`` path in
    :meth:`HexEditorBridge.test_in_sandbox` where the resolved
    ``run_binary`` attribute is not callable.
    """

    @property
    def name(self) -> ToolName:
        """The sandbox tool name.

        Returns:
            ToolName: ``ToolName.SANDBOX``.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """A minimal tool definition.

        Returns:
            ToolDefinition: Stub definition with no functions.
        """
        return ToolDefinition(tool_name=ToolName.SANDBOX, description="no-run-binary", functions=[])

    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initializer.

        Args:
            tool_path: Ignored.
        """

    async def shutdown(self) -> None:
        """Delegate to base-class finaliser."""
        await super().shutdown()

    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: Always ``True``.
        """
        return True


def _make_registry_with(bridge: ToolBridgeBase) -> ToolRegistry:
    """Build a real ``ToolRegistry`` with ``bridge`` registered as the sandbox.

    Args:
        bridge: Bridge instance to register under ``ToolName.SANDBOX``.

    Returns:
        ToolRegistry: A registry whose ``get(ToolName.SANDBOX)`` returns
        ``bridge``.
    """
    td = tempfile.mkdtemp()
    registry = ToolRegistry(Path(td))
    registry.register_bridge(ToolName.SANDBOX, bridge)
    return registry


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Construct a fresh ``HexEditorBridge`` with no document attached.

    Returns:
        HexEditorBridge: Uninitialised bridge ready for per-test setup.
    """
    return HexEditorBridge()


class TestInspectDataAt:
    """Exact struct-unpack oracle gates for :meth:`inspect_data_at`."""

    def test_unsigned_integer_decodes(self, bridge: HexEditorBridge) -> None:
        """Unsigned integer fields match struct.unpack oracle values.

        Mutation caught: swapping uint32_le with uint32_be returns wrong result.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _DOC_DATA)
        try:
            result = _run(bridge.inspect_data_at(0))
            assert result["uint8"] == str(_ORACLE_UINT8)
            assert result["uint16_le"] == str(_ORACLE_UINT16_LE)
            assert result["uint16_be"] == str(_ORACLE_UINT16_BE)
            assert result["uint32_le"] == str(_ORACLE_UINT32_LE)
            assert result["uint32_be"] == str(_ORACLE_UINT32_BE)
            assert result["uint64_le"] == str(_ORACLE_UINT64_LE)
            assert result["uint64_be"] == str(_ORACLE_UINT64_BE)
        finally:
            _release_and_unlink(bridge, path)

    def test_signed_integer_decodes(self, bridge: HexEditorBridge) -> None:
        """Signed integer fields match struct.unpack oracle values.

        Mutation caught: using unsigned unpack for a negative int8 yields wrong sign.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _DOC_DATA)
        try:
            result = _run(bridge.inspect_data_at(0))
            assert result["int8"] == str(_ORACLE_INT8)
            assert result["int16_le"] == str(_ORACLE_INT16_LE)
            assert result["int16_be"] == str(_ORACLE_INT16_BE)
            assert result["int32_le"] == str(_ORACLE_INT32_LE)
            assert result["int32_be"] == str(_ORACLE_INT32_BE)
            assert result["int64_le"] == str(_ORACLE_INT64_LE)
            assert result["int64_be"] == str(_ORACLE_INT64_BE)
        finally:
            _release_and_unlink(bridge, path)

    def test_ipv4_dotted_quad(self, bridge: HexEditorBridge) -> None:
        """IPv4 field is the dotted-quad of the first four bytes.

        Mutation caught: big-endian vs little-endian byte order in IPv4 render.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _DOC_DATA)
        try:
            result = _run(bridge.inspect_data_at(0))
            assert result["ipv4"] == _ORACLE_IPV4
        finally:
            _release_and_unlink(bridge, path)

    def test_rgba8_hex_color(self, bridge: HexEditorBridge) -> None:
        """RGBA8 field is a lower-case hex colour string of the first four bytes.

        Mutation caught: RGBA byte order swap (ARGB vs RGBA) changes the value.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _DOC_DATA)
        try:
            result = _run(bridge.inspect_data_at(0))
            assert result["rgba8"] == _ORACLE_RGBA8
        finally:
            _release_and_unlink(bridge, path)

    def test_all_values_are_strings(self, bridge: HexEditorBridge) -> None:
        """Bridge converts every interpretation value to str.

        Mutation caught: omitting the str() call returns raw numeric types.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _DOC_DATA)
        try:
            result = _run(bridge.inspect_data_at(0))
            assert all(isinstance(v, str) for v in result.values()), "Non-string value found in inspect_data_at result"
        finally:
            _release_and_unlink(bridge, path)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the document-None guard silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.inspect_data_at(0))

    def test_signed_negative_byte(self, bridge: HexEditorBridge) -> None:
        """int8 for 0xFF is -1 (two's complement), not 255.

        Mutation caught: using unsigned B format gives 255, not -1.

        Args:
            bridge: Fresh bridge fixture.
        """
        data = bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + bytes(10)
        path = _open_doc(bridge, data)
        try:
            result = _run(bridge.inspect_data_at(0))
            expected_int8 = str(struct.unpack("<b", bytes([0xFF]))[0])
            assert result["int8"] == expected_int8
            assert result["int8"] == "-1"
        finally:
            _release_and_unlink(bridge, path)


class TestGetByteStatistics:
    """Exact histogram and entropy oracle gates for :meth:`get_byte_statistics`."""

    def test_exact_histogram_entry_count(self, bridge: HexEditorBridge) -> None:
        """Returns exactly 256 entries, one per possible byte value.

        Mutation caught: returning only non-zero entries gives fewer than 256.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _STATS_DATA)
        try:
            result = _run(bridge.get_byte_statistics())
            assert len(result) == 256
        finally:
            _release_and_unlink(bridge, path)

    def test_exact_nonzero_counts(self, bridge: HexEditorBridge) -> None:
        """Non-zero byte counts match the independently known histogram.

        Oracle: _STATS_DATA has 3 bytes 0x41, 2 bytes 0x42, 1 byte 0x43.

        Mutation caught: swapping byte and count fields returns wrong values.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _STATS_DATA)
        try:
            result = _run(bridge.get_byte_statistics())
            histogram: dict[int, int] = {d["byte"]: d["count"] for d in result}
            assert histogram[0x41] == 3
            assert histogram[0x42] == 2
            assert histogram[0x43] == 1
        finally:
            _release_and_unlink(bridge, path)

    def test_all_other_bytes_are_zero(self, bridge: HexEditorBridge) -> None:
        """Every byte value not present in the document has count zero.

        Mutation caught: incorrect initialization would leave non-zero counts.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _STATS_DATA)
        try:
            result = _run(bridge.get_byte_statistics())
            histogram: dict[int, int] = {d["byte"]: d["count"] for d in result}
            for byte_val in range(256):
                if byte_val not in {0x41, 0x42, 0x43}:
                    assert histogram.get(byte_val, 0) == 0, f"Expected count 0 for byte {byte_val:#04x}, got {histogram.get(byte_val)}"
        finally:
            _release_and_unlink(bridge, path)

    def test_entropy_from_histogram_matches_oracle(self, bridge: HexEditorBridge) -> None:
        """Shannon entropy computed from returned histogram equals oracle.

        Oracle entropy (nats→bits): H = -(3/6 log2(3/6) + 2/6 log2(2/6) + 1/6 log2(1/6))
        computed independently from the known data distribution.

        Mutation caught: wrong count for any byte shifts entropy off the oracle.

        Args:
            bridge: Fresh bridge fixture.
        """
        known_histogram: dict[int, int] = {0x41: 3, 0x42: 2, 0x43: 1}
        oracle_h = _oracle_shannon_entropy(known_histogram)

        path = _open_doc(bridge, _STATS_DATA)
        try:
            result = _run(bridge.get_byte_statistics())
            histogram: dict[int, int] = {d["byte"]: d["count"] for d in result}
            computed_h = _oracle_shannon_entropy(histogram)
            assert abs(computed_h - oracle_h) < 1e-9, f"Entropy {computed_h} differs from oracle {oracle_h}"
        finally:
            _release_and_unlink(bridge, path)

    def test_single_byte_value_uniform(self, bridge: HexEditorBridge) -> None:
        """A document of 100 identical bytes has entropy zero.

        Oracle: one byte value with p=1.0 → H = -1.0 * log2(1.0) = 0.

        Mutation caught: incorrect count accumulation gives entropy > 0.

        Args:
            bridge: Fresh bridge fixture.
        """
        data = b"\xab" * 100
        path = _open_doc(bridge, data)
        try:
            result = _run(bridge.get_byte_statistics())
            histogram: dict[int, int] = {d["byte"]: d["count"] for d in result}
            assert histogram[0xAB] == 100
            oracle_h = _oracle_shannon_entropy({0xAB: 100})
            computed_h = _oracle_shannon_entropy(histogram)
            assert abs(computed_h - oracle_h) < 1e-9
            assert abs(oracle_h) < 1e-15
        finally:
            _release_and_unlink(bridge, path)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the document-None guard silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_byte_statistics())


class TestGetContentClassification:
    """Exact content-type oracle gates for :meth:`get_content_classification`."""

    def test_null_block_classifies_as_zero(self, bridge: HexEditorBridge) -> None:
        """A 64-byte null block is classified as 0 (null).

        Oracle: constant 0 from documented classification table.

        Mutation caught: returning 1 instead of 0 for null data.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _NULL_64)
        try:
            result = _run(bridge.get_content_classification(block_size=64))
            assert result == [0]
        finally:
            _release_and_unlink(bridge, path)

    def test_plaintext_ascii_classifies_as_one(self, bridge: HexEditorBridge) -> None:
        """A 64-byte printable ASCII block is classified as 1 (plaintext).

        Oracle: constant 1 from documented classification table.

        Mutation caught: returning 4 instead of 1 for plaintext.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _PLAINTEXT_64)
        try:
            result = _run(bridge.get_content_classification(block_size=64))
            assert result == [1]
        finally:
            _release_and_unlink(bridge, path)

    def test_pe_header_classifies_as_structured(self, bridge: HexEditorBridge) -> None:
        """A 64-byte PE-header block (MZ magic) is classified as 2 (structured).

        Oracle: constant 2 from documented classification table.

        Mutation caught: returning 1 instead of 2 for structured binary headers.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _PE_HEADER_64)
        try:
            result = _run(bridge.get_content_classification(block_size=64))
            assert result == [2]
        finally:
            _release_and_unlink(bridge, path)

    def test_high_entropy_classifies_as_encrypted(self, bridge: HexEditorBridge) -> None:
        """A 256-byte block spanning all byte values is classified as 3 (encrypted).

        Oracle: constant 3 from documented classification table.

        Mutation caught: returning 4 instead of 3 for high-entropy data.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _HIGH_ENTROPY_256)
        try:
            result = _run(bridge.get_content_classification(block_size=256))
            assert result == [3]
        finally:
            _release_and_unlink(bridge, path)

    def test_multi_block_classification(self, bridge: HexEditorBridge) -> None:
        """Two-block document yields per-block classifications [0, 1].

        Oracle: null block → 0, plaintext block → 1.

        Mutation caught: returning a single merged classification flattens blocks.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _NULL_64 + _PLAINTEXT_64)
        try:
            result = _run(bridge.get_content_classification(block_size=64))
            assert result == [0, 1]
        finally:
            _release_and_unlink(bridge, path)

    def test_result_elements_are_ints(self, bridge: HexEditorBridge) -> None:
        """All classification values are Python ints.

        Mutation caught: returning raw C integers that lack Python int identity.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, _NULL_64)
        try:
            result = _run(bridge.get_content_classification(block_size=64))
            assert all(isinstance(v, int) for v in result)
        finally:
            _release_and_unlink(bridge, path)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the document-None guard silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_content_classification())


class TestInsertBytes:
    """Exact byte-sequence oracle gates for :meth:`insert_bytes`."""

    def _read_all(self, bridge: HexEditorBridge) -> bytes:
        """Read the entire document as bytes.

        Args:
            bridge: Bridge whose document is read.

        Returns:
            bytes: Raw document bytes.
        """
        doc = bridge.document
        assert doc is not None
        raw = doc.read(0, doc.length())
        return bytes(raw)

    def test_insert_at_middle(self, bridge: HexEditorBridge) -> None:
        """Inserting 3 bytes at offset 2 into 4-byte doc produces correct 7-byte sequence.

        Oracle: [AA, BB, <11, 22, 33>, CC, DD] = aabb112233ccdd (independent concatenation).

        Mutation caught: off-by-one in insert position shifts the result.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabbccdd"))
        try:
            result = _run(bridge.insert_bytes(2, "11 22 33"))
            assert result is True
            assert self._read_all(bridge) == bytes.fromhex("aabb112233ccdd")
        finally:
            _release_and_unlink(bridge, path)

    def test_insert_at_start(self, bridge: HexEditorBridge) -> None:
        """Inserting 2 bytes at offset 0 prepends them to the document.

        Oracle: [<11, 22>, AA, BB, CC] = 1122aabbcc.

        Mutation caught: treating offset 0 as offset 1 shifts the inserted bytes.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabbcc"))
        try:
            _run(bridge.insert_bytes(0, "1122"))
            assert self._read_all(bridge) == bytes.fromhex("1122aabbcc")
        finally:
            _release_and_unlink(bridge, path)

    def test_insert_at_end(self, bridge: HexEditorBridge) -> None:
        """Inserting 2 bytes at the end appends them.

        Oracle: [AA, BB, <CC, DD>] = aabbccdd.

        Mutation caught: using write instead of insert overwrites existing bytes.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabb"))
        try:
            _run(bridge.insert_bytes(2, "ccdd"))
            assert self._read_all(bridge) == bytes.fromhex("aabbccdd")
        finally:
            _release_and_unlink(bridge, path)

    def test_insert_increases_length(self, bridge: HexEditorBridge) -> None:
        """Document length increases by the number of inserted bytes.

        Mutation caught: insert that overwrites instead of inserts leaves length unchanged.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabb"))
        try:
            assert bridge.document is not None
            before = bridge.document.length()
            _run(bridge.insert_bytes(1, "112233"))
            assert bridge.document is not None
            assert bridge.document.length() == before + 3
        finally:
            _release_and_unlink(bridge, path)

    def test_returns_true(self, bridge: HexEditorBridge) -> None:
        """Successful insert returns True.

        Mutation caught: returning False on success breaks caller contracts.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aa"))
        try:
            result = _run(bridge.insert_bytes(0, "bb"))
            assert result is True
        finally:
            _release_and_unlink(bridge, path)

    def test_hex_string_with_spaces_parsed(self, bridge: HexEditorBridge) -> None:
        """A hex string with embedded spaces is parsed identically to compact form.

        Oracle: "11 22 33" is equivalent to "112233" (same bytes).

        Mutation caught: not stripping spaces causes hex decode failure or skipped bytes.

        Args:
            bridge: Fresh bridge fixture.
        """
        path_spaced = _open_doc(bridge, bytes.fromhex("aa"))
        try:
            _run(bridge.insert_bytes(1, "11 22 33"))
            result_spaced = self._read_all(bridge)
        finally:
            _release_and_unlink(bridge, path_spaced)

        bridge.document = None
        path_compact = _open_doc(bridge, bytes.fromhex("aa"))
        try:
            _run(bridge.insert_bytes(1, "112233"))
            result_compact = self._read_all(bridge)
        finally:
            _release_and_unlink(bridge, path_compact)

        assert result_spaced == result_compact

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the document-None guard silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.insert_bytes(0, "aa"))


class TestDeleteBytes:
    """Exact byte-sequence oracle gates for :meth:`delete_bytes`."""

    def _read_all(self, bridge: HexEditorBridge) -> bytes:
        """Read the entire document as bytes.

        Args:
            bridge: Bridge whose document is read.

        Returns:
            bytes: Raw document bytes.
        """
        doc = bridge.document
        assert doc is not None
        raw = doc.read(0, doc.length())
        return bytes(raw)

    def test_delete_from_middle(self, bridge: HexEditorBridge) -> None:
        """Deleting 3 bytes at offset 1 from a 6-byte doc leaves 3 bytes.

        Oracle: [AA, <BB, CC, DD>, EE, FF] → [AA, EE, FF] = aaeeff.

        Mutation caught: wrong offset or length leaves extra or missing bytes.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabbccddeeff"))
        try:
            result = _run(bridge.delete_bytes(1, 3))
            assert result is True
            assert self._read_all(bridge) == bytes.fromhex("aaeeff")
        finally:
            _release_and_unlink(bridge, path)

    def test_delete_from_start(self, bridge: HexEditorBridge) -> None:
        """Deleting 2 bytes at offset 0 removes the leading bytes.

        Oracle: [<01, 02>, 03, 04] → [03, 04] = 0304.

        Mutation caught: treating offset 0 as offset 1 leaves the first byte.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("01020304"))
        try:
            _run(bridge.delete_bytes(0, 2))
            assert self._read_all(bridge) == bytes.fromhex("0304")
        finally:
            _release_and_unlink(bridge, path)

    def test_delete_reduces_length(self, bridge: HexEditorBridge) -> None:
        """Document length decreases by the number of deleted bytes.

        Mutation caught: delete that overwrites instead of removes leaves length unchanged.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabbccddeeff"))
        try:
            assert bridge.document is not None
            before = bridge.document.length()
            _run(bridge.delete_bytes(2, 2))
            assert bridge.document is not None
            assert bridge.document.length() == before - 2
        finally:
            _release_and_unlink(bridge, path)

    def test_returns_true(self, bridge: HexEditorBridge) -> None:
        """Successful delete returns True.

        Mutation caught: returning False on success breaks caller contracts.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = _open_doc(bridge, bytes.fromhex("aabb"))
        try:
            result = _run(bridge.delete_bytes(0, 1))
            assert result is True
        finally:
            _release_and_unlink(bridge, path)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the document-None guard silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.delete_bytes(0, 1))


class TestTestInSandbox:
    """Routing oracle gates for :meth:`test_in_sandbox`."""

    def _make_file_doc(self, bridge: HexEditorBridge) -> Path:
        """Open a real file-backed document on the bridge.

        Args:
            bridge: Bridge whose ``document`` attribute is assigned.

        Returns:
            Path: Temp file path (caller must unlink).
        """
        return _open_doc(bridge, b"\x90" * 16)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without an open document raises RuntimeError.

        Mutation caught: removing the None-check silences the error.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.test_in_sandbox())

    def test_no_file_path_raises(self, bridge: HexEditorBridge) -> None:
        """An in-memory document (no file path) raises RuntimeError.

        Mutation caught: not checking file_path() allows sandbox routing on unsaved docs.

        Args:
            bridge: Fresh bridge fixture.
        """
        bridge.document = intellicrack_hexcore.HexDocument.open_bytes(b"\x90" * 16)
        with pytest.raises(RuntimeError, match="no file path"):
            _run(bridge.test_in_sandbox())

    def test_no_registry_raises(self, bridge: HexEditorBridge) -> None:
        """Calling without a tool registry raises RuntimeError.

        Mutation caught: accessing registry without check causes AttributeError.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            with pytest.raises(RuntimeError, match="tool registry not set"):
                _run(bridge.test_in_sandbox())
        finally:
            _release_and_unlink(bridge, path)

    def test_no_sandbox_bridge_raises(self, bridge: HexEditorBridge) -> None:
        """An empty registry (no SANDBOX bridge registered) raises RuntimeError.

        Mutation caught: using a fallback value instead of raising hides missing bridge.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            td = tempfile.mkdtemp()
            bridge.tool_registry = ToolRegistry(Path(td))
            with pytest.raises(RuntimeError, match="sandbox bridge not available"):
                _run(bridge.test_in_sandbox())
        finally:
            _release_and_unlink(bridge, path)

    def test_bridge_without_run_binary_raises_type_error(self, bridge: HexEditorBridge) -> None:
        """A sandbox bridge that lacks run_binary raises TypeError.

        Mutation caught: using getattr fallback without check skips the TypeError.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridgeNoRunBinary()
            bridge.tool_registry = _make_registry_with(fake)
            with pytest.raises(TypeError, match="run_binary"):
                _run(bridge.test_in_sandbox())
        finally:
            _release_and_unlink(bridge, path)

    def test_routes_to_run_binary_with_exact_binary_path(self, bridge: HexEditorBridge) -> None:
        """run_binary receives the exact file path reported by the document.

        Mutation caught: passing a different path breaks sandbox routing.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridge()
            bridge.tool_registry = _make_registry_with(fake)
            _run(bridge.test_in_sandbox())
            assert len(fake.calls) == 1
            assert fake.calls[0]["binary_path"] == str(path)
        finally:
            _release_and_unlink(bridge, path)

    def test_args_string_split_correctly(self, bridge: HexEditorBridge) -> None:
        """Space-separated args string is split into a list for run_binary.

        Mutation caught: passing the raw string instead of a list misrepresents args.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridge()
            bridge.tool_registry = _make_registry_with(fake)
            _run(bridge.test_in_sandbox(args="--flag value --other"))
            assert fake.calls[0]["args"] == ["--flag", "value", "--other"]
        finally:
            _release_and_unlink(bridge, path)

    def test_empty_args_string_passes_none(self, bridge: HexEditorBridge) -> None:
        """Empty args string results in None being passed to run_binary.

        Mutation caught: splitting "" gives [""] instead of None.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridge()
            bridge.tool_registry = _make_registry_with(fake)
            _run(bridge.test_in_sandbox(args=""))
            assert fake.calls[0]["args"] is None
        finally:
            _release_and_unlink(bridge, path)

    def test_sandbox_type_and_time_limit_forwarded(self, bridge: HexEditorBridge) -> None:
        """sandbox_type and time_limit are forwarded verbatim to run_binary.

        Mutation caught: hardcoding "windows" or 30 ignores caller-supplied values.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridge()
            bridge.tool_registry = _make_registry_with(fake)
            _run(bridge.test_in_sandbox(sandbox_type="qemu", time_limit=120))
            assert fake.calls[0]["sandbox_type"] == "qemu"
            assert fake.calls[0]["time_limit"] == 120
        finally:
            _release_and_unlink(bridge, path)

    def test_returns_dict_from_run_binary(self, bridge: HexEditorBridge) -> None:
        """Result dict from run_binary is returned verbatim by test_in_sandbox.

        Mutation caught: wrapping the result in an extra dict loses keys.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = self._make_file_doc(bridge)
        try:
            fake = _FakeSandboxBridge()
            fake.result = {"exit_code": 42, "stdout": "hello", "stderr": "warn"}
            bridge.tool_registry = _make_registry_with(fake)
            result = _run(bridge.test_in_sandbox())
            assert result["exit_code"] == 42
            assert result["stdout"] == "hello"
            assert result["stderr"] == "warn"
        finally:
            _release_and_unlink(bridge, path)
