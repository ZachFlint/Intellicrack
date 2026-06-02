# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge apply_pipeline and deep apply_transform coverage.

Every test drives a real :class:`HexEditorBridge` over the real Rust
``intellicrack_hexcore`` transform backend against a real on-disk binary, then
asserts the exact transformed bytes. Expected values are computed independently
(closed-form XOR/ROT/byte-order arithmetic or a different trusted oracle such as
the stdlib ``base64``/``binascii`` modules), never frozen from the bridge's own
output. Error and edge paths assert the specific exception type rather than
swallowing failures, and the transform names used are the ones the native
backend actually exports, so no test is gated behind a capability skip.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.transform_pipeline import get_all_transform_nodes


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")


_REQUIRED_TRANSFORMS: frozenset[str] = frozenset(
    {"xor_single", "xor_repeating", "bit_invert", "byte_reverse", "rot_n", "base64_encode"},
)


def _assert_backend_capabilities() -> None:
    """Fail loudly if the native backend lacks a transform these tests rely on.

    The transforms exercised here are core capabilities of the bundled
    ``intellicrack_hexcore`` build. If one is missing the bridge surface has
    regressed and the suite must fail rather than silently skip.
    """
    available = {node.name for node in get_all_transform_nodes()}
    missing = _REQUIRED_TRANSFORMS - available
    assert not missing, f"native backend is missing required transforms: {sorted(missing)}"


_assert_backend_capabilities()


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
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


def _open_with_payload(bridge: HexEditorBridge, path: Path, data: bytes) -> None:
    """Write data to a temporary file and open it in the bridge.

    Args:
        bridge: An initialized HexEditorBridge.
        path: A Path object pointing to the file to write.
        data: Bytes to write.
    """
    path.write_bytes(data)
    _run(bridge.open_file(str(path)))


def _xor(data: bytes, key: int) -> bytes:
    """Compute the XOR of every byte with a single-byte key (independent oracle).

    Args:
        data: Source bytes.
        key: Single-byte XOR key in range 0-255.

    Returns:
        bytes: The XOR-transformed bytes.
    """
    return bytes(b ^ key for b in data)


class TestApplyPipelineSingleStep:
    """Tests for apply_pipeline with exactly one transform step."""

    def test_single_xor_step_produces_exact_known_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A single-step XOR pipeline yields the closed-form XOR of every byte.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x10, 0x20, 0x30, 0x40])
        _open_with_payload(bridge, tmp_path / "p.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "AA"}}])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == _xor(payload, 0xAA).hex()
        assert result == "ba8a9aea"

    def test_single_xor_with_ff_inverts_all_ones(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """XOR-ing 0xFF bytes with 0xFF yields all-zero output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xff\xff\xff\xff"
        _open_with_payload(bridge, tmp_path / "xorknown.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "FF"}}])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == "00000000"

    def test_empty_pipeline_returns_original_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """An empty pipeline returns the original bytes unchanged.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x01\x02\x03\x04"
        _open_with_payload(bridge, tmp_path / "empty.bin", payload)

        result = _run(bridge.apply_pipeline(json.dumps([]), 0, 4, in_place=False))

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_zero_length_pipeline_returns_empty_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Applying a pipeline over a zero-length range returns an empty hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_with_payload(bridge, tmp_path / "zero.bin", b"\x01\x02\x03\x04")

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "FF"}}])
        result = _run(bridge.apply_pipeline(pipeline, 0, 0, in_place=False))

        assert result == b"".hex()
        assert len(result) == 0


class TestApplyPipelineMultiStep:
    """Tests for apply_pipeline with two or more transform steps."""

    def test_double_xor_same_key_is_identity(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """XOR-ing the same key twice restores the original bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xaa\xbb\xcc\xdd"
        _open_with_payload(bridge, tmp_path / "double_xor.bin", payload)

        pipeline = json.dumps([
            {"name": "xor_single", "params": {"key": "3C"}},
            {"name": "xor_single", "params": {"key": "3C"}},
        ])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_step_order_changes_result_for_non_commuting_steps(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A position-dependent xor_repeating before vs after byte_reverse gives distinct, known outputs.

        With payload ``10 20 30 40`` and repeating key ``AA BB``:
        xor_repeating then byte_reverse is ``fb9a9bba``; byte_reverse then
        xor_repeating is ``ea8b8aab``. Both are computed by hand below.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x10, 0x20, 0x30, 0x40])
        _open_with_payload(bridge, tmp_path / "order.bin", payload)

        xor_then_reverse = json.dumps([
            {"name": "xor_repeating", "params": {"key": "AABB"}},
            {"name": "byte_reverse", "params": {}},
        ])
        reverse_then_xor = json.dumps([
            {"name": "byte_reverse", "params": {}},
            {"name": "xor_repeating", "params": {"key": "AABB"}},
        ])

        result_xr = _run(bridge.apply_pipeline(xor_then_reverse, 0, 4, in_place=False))
        result_rx = _run(bridge.apply_pipeline(reverse_then_xor, 0, 4, in_place=False))

        key = bytes.fromhex("AABB")
        xored = bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))
        expected_xr = xored[::-1].hex()
        reversed_payload = payload[::-1]
        expected_rx = bytes(reversed_payload[i] ^ key[i % len(key)] for i in range(len(reversed_payload))).hex()

        assert result_xr == expected_xr == "fb9a9bba"
        assert result_rx == expected_rx == "ea8b8aab"
        assert result_xr != result_rx

    def test_three_xor_steps_collapse_to_single_xor(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """XOR(k1) then XOR(k2) then XOR(k3) equals XOR(k1 ^ k2 ^ k3) on every byte.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x00, 0x11, 0x22, 0x33])
        _open_with_payload(bridge, tmp_path / "three_step.bin", payload)

        k1, k2, k3 = 0xFF, 0x0F, 0xF0
        pipeline = json.dumps([
            {"name": "xor_single", "params": {"key": f"{k1:02X}"}},
            {"name": "xor_single", "params": {"key": f"{k2:02X}"}},
            {"name": "xor_single", "params": {"key": f"{k3:02X}"}},
        ])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == _xor(payload, k1 ^ k2 ^ k3).hex()

    def test_pipeline_on_subrange_leaves_other_bytes_untouched(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """An in-place pipeline over a subrange transforms only that range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 8 + b"\xff" * 4 + b"\x00" * 8
        path = tmp_path / "subrange.bin"
        _open_with_payload(bridge, path, payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "FF"}}])
        result = _run(bridge.apply_pipeline(pipeline, 8, 4, in_place=True))

        assert result == "00000000"
        full_hex = _run(bridge.read_bytes(0, len(payload)))
        assert bytes.fromhex(full_hex) == b"\x00" * 20


class TestApplyPipelineErrorPaths:
    """Tests for apply_pipeline failure and adversarial-input handling."""

    def test_unknown_step_is_skipped_yielding_original_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """An unknown step name is dropped, so the output equals the untouched input.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xab\xcd\xef\x01"
        _open_with_payload(bridge, tmp_path / "invalid_step.bin", payload)

        pipeline = json.dumps([{"name": "nonexistent_transform_xyzzy", "params": {}}])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_known_step_after_unknown_step_still_applies(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """An unknown step is skipped while a following real XOR step still runs.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x01, 0x02, 0x03, 0x04])
        _open_with_payload(bridge, tmp_path / "mixed_steps.bin", payload)

        pipeline = json.dumps([
            {"name": "nonexistent_transform_xyzzy", "params": {}},
            {"name": "xor_single", "params": {"key": "0F"}},
        ])
        result = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert result == _xor(payload, 0x0F).hex()

    def test_malformed_pipeline_json_raises_json_decode_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Invalid pipeline JSON surfaces a JSONDecodeError rather than being swallowed.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_with_payload(bridge, tmp_path / "badjson.bin", b"\x01\x02\x03\x04")

        with pytest.raises(json.JSONDecodeError):
            _run(bridge.apply_pipeline("{not valid json", 0, 4, in_place=False))


class TestApplyTransformDeep:
    """Deeper tests for bridge.apply_transform across transforms and ranges."""

    def test_xor_with_key_produces_exact_bytes(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """apply_transform xor_single with a known key produces the closed-form result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x41\x41\x41\x41"
        _open_with_payload(bridge, tmp_path / "xorkey.bin", payload)

        result = _run(bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "41"}), in_place=False))

        assert result == _xor(payload, 0x41).hex()
        assert result == "00000000"

    def test_xor_identity_key_zero_leaves_bytes_unchanged(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """XOR-ing with key 0x00 leaves bytes unchanged.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        _open_with_payload(bridge, tmp_path / "xor_id.bin", payload)

        result = _run(bridge.apply_transform("xor_single", 0, 8, json.dumps({"key": "00"}), in_place=False))

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_transform_on_offset_range_yields_range_only_result(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """apply_transform at a non-zero offset transforms exactly the bytes in that range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\x00" * 4 + b"\x12\x34\x56\x78" + b"\x00" * 4
        _open_with_payload(bridge, tmp_path / "subrange_transform.bin", payload)

        result = _run(bridge.apply_transform("xor_single", 4, 4, json.dumps({"key": "FF"}), in_place=False))

        assert result == _xor(b"\x12\x34\x56\x78", 0xFF).hex()
        assert result == "edcba987"

    def test_bit_invert_matches_byte_complement(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """bit_invert produces the bitwise complement of each byte (equivalent to XOR 0xFF).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x0F, 0xF0, 0x00, 0xFF, 0xA5])
        _open_with_payload(bridge, tmp_path / "invert.bin", payload)

        result = _run(bridge.apply_transform("bit_invert", 0, len(payload), "{}", in_place=False))

        assert result == bytes((~b) & 0xFF for b in payload).hex()
        assert result == "f00fff005a"

    def test_byte_reverse_reverses_range_order(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """byte_reverse emits the source bytes in reverse order.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
        _open_with_payload(bridge, tmp_path / "reverse.bin", payload)

        result = _run(bridge.apply_transform("byte_reverse", 0, len(payload), "{}", in_place=False))

        assert result == payload[::-1].hex()
        assert result == "0504030201"

    def test_rot_n_rotates_alphabetic_ascii(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """rot_n with shift 13 rotates ASCII letters by 13 (HELLO -> URYYB).

        The shift parameter is passed as the hex byte string ``"0D"`` (decimal
        13); the bridge converts hex-string params to bytes for the backend.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "HELLO"
        payload = text.encode("ascii") + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "rot13.bin", payload)

        result = _run(bridge.apply_transform("rot_n", 0, len(text), json.dumps({"shift": "0D"}), in_place=False))

        assert bytes.fromhex(result).decode("ascii") == "URYYB"

    def test_base64_encode_matches_stdlib_base64(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """base64_encode output decodes back to the source bytes and equals stdlib base64.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        source = b"TestData"
        payload = source + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "b64.bin", payload)

        result = _run(bridge.apply_transform("base64_encode", 0, len(source), "{}", in_place=False))

        b64_bytes = bytes.fromhex(result)
        assert b64_bytes == base64.b64encode(source)
        assert base64.b64decode(b64_bytes) == source

    def test_base64_encode_in_place_raises_value_error_on_length_change(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """In-place base64_encode is rejected because the output length differs from the range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"TestData" + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "b64_inplace.bin", payload)

        with pytest.raises(ValueError, match="in-place application requires equal length"):
            _run(bridge.apply_transform("base64_encode", 0, 8, "{}", in_place=True))

    def test_apply_transform_without_open_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """apply_transform with no document open raises RuntimeError, not a silent default.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "FF"}), in_place=False))

    def test_pipeline_and_transform_single_step_agree(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A single-step pipeline and a direct apply_transform with equal params match exactly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        payload = b"\xde\xad\xbe\xef"
        _open_with_payload(bridge, tmp_path / "compare.bin", payload)

        direct = _run(bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "CA"}), in_place=False))
        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "CA"}}])
        via_pipeline = _run(bridge.apply_pipeline(pipeline, 0, 4, in_place=False))

        assert direct == via_pipeline == _xor(payload, 0xCA).hex()
        assert direct == "14677425"

    def test_apply_transform_on_real_pe_header_bytes(self, loaded_bridge: HexEditorBridge) -> None:
        """apply_transform reads and returns real PE header bytes (MZ magic) intact under XOR 0x00.

        Args:
            loaded_bridge: A bridge with the PE file already opened.
        """
        result = _run(loaded_bridge.apply_transform("xor_single", 0, 2, json.dumps({"key": "00"}), in_place=False))

        assert result == "4d5a"
        assert bytes.fromhex(result) == b"MZ"
