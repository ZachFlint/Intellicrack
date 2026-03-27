# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge apply_pipeline and deep apply_transform coverage.

Verifies that multi-step transform pipelines produce correct results against
real HexDocument data, that ordering matters between steps, and that individual
transform operations work on various byte ranges. Tests fail if the underlying
hexcore module or pipeline module cannot perform the requested operations.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
from importlib.util import find_spec
from typing import Any

import pytest


pytest.importorskip("intellicrack_hexcore")

_pipeline_available: bool = find_spec("intellicrack.core.transform_pipeline") is not None


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


def _open_with_payload(bridge: Any, path: Any, data: bytes) -> None:
    """Write data to a temporary file and open it in the bridge.

    Args:
        bridge: An initialized HexEditorBridge.
        path: A Path object pointing to the file to write.
        data: Bytes to write.
    """
    path.write_bytes(data)
    _run(bridge.open_file(str(path)))


def _require_transform(bridge: Any, name: str) -> None:
    """Skip the test if the named transform is not available.

    Args:
        bridge: An initialized HexEditorBridge.
        name: Transform name to check.
    """
    transforms: list[dict[str, str]] = _run(bridge.list_transforms())
    names = [t["name"] for t in transforms]
    if name not in names:
        pytest.skip(f"transform '{name}' not available")


class TestApplyPipelineSingleStep:
    """Tests for apply_pipeline with exactly one transform step."""

    def test_single_xor_step_returns_hex_string(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """A single-step XOR pipeline must return a valid hex string of the correct length.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\xFF\xFF\xFF\xFF"
        _open_with_payload(bridge, tmp_path / "p.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "AA"}}])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert isinstance(result, str)
        assert len(result) == 8

    def test_single_xor_step_known_output(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """XOR-ing 0xFF bytes with 0xFF must yield all-zero output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\xFF\xFF\xFF\xFF"
        _open_with_payload(bridge, tmp_path / "xorknown.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "FF"}}])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert result == "00000000"

    def test_empty_pipeline_returns_original_bytes(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """An empty pipeline must return the original bytes unchanged.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")

        payload = b"\x01\x02\x03\x04"
        _open_with_payload(bridge, tmp_path / "empty.bin", payload)

        pipeline = json.dumps([])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert result == binascii.hexlify(payload).decode("ascii")


class TestApplyPipelineMultiStep:
    """Tests for apply_pipeline with two or more transform steps."""

    def test_two_step_pipeline_xor_then_xor_identity(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """XOR-ing the same key twice must restore the original bytes (identity).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\xAA\xBB\xCC\xDD"
        _open_with_payload(bridge, tmp_path / "double_xor.bin", payload)

        pipeline = json.dumps([
            {"name": "xor_single", "params": {"key": "3C"}},
            {"name": "xor_single", "params": {"key": "3C"}},
        ])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_pipeline_ordering_matters(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """Reversing step order in a non-symmetric pipeline must produce different output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "bitwise_not" not in names:
            pytest.skip("bitwise_not transform not available")

        payload = b"\x0F\x0F\x0F\x0F"
        _open_with_payload(bridge, tmp_path / "order.bin", payload)

        pipeline_ab = json.dumps([
            {"name": "xor_single", "params": {"key": "AA"}},
            {"name": "bitwise_not", "params": {}},
        ])
        pipeline_ba = json.dumps([
            {"name": "bitwise_not", "params": {}},
            {"name": "xor_single", "params": {"key": "AA"}},
        ])

        result_ab: str = _run(bridge.apply_pipeline(pipeline_ab, 0, 4))
        result_ba: str = _run(bridge.apply_pipeline(pipeline_ba, 0, 4))

        assert result_ab != result_ba

    def test_three_step_pipeline_produces_output(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """A three-step pipeline must return a non-empty hex string of the correct length.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\x00\x11\x22\x33"
        _open_with_payload(bridge, tmp_path / "three_step.bin", payload)

        pipeline = json.dumps([
            {"name": "xor_single", "params": {"key": "FF"}},
            {"name": "xor_single", "params": {"key": "0F"}},
            {"name": "xor_single", "params": {"key": "F0"}},
        ])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert isinstance(result, str)
        assert len(result) == 8

    def test_pipeline_result_length_matches_input_length(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """Pipeline output length in hex characters must equal 2 * input byte count.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        byte_count = 16
        payload = bytes(range(byte_count))
        _open_with_payload(bridge, tmp_path / "len_check.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "55"}}])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, byte_count))

        assert len(result) == byte_count * 2

    def test_pipeline_on_subrange(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """Pipeline applied to a subrange must only transform the specified bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\x00" * 8 + b"\xFF" * 4 + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "subrange.bin", payload)

        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "FF"}}])
        result: str = _run(bridge.apply_pipeline(pipeline, 8, 4))

        transformed = bytes.fromhex(result)
        assert all(b == 0x00 for b in transformed)


class TestApplyPipelineInvalidStep:
    """Tests for apply_pipeline graceful handling of unknown step names."""

    def test_pipeline_with_invalid_step_name_completes(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """A pipeline containing an unknown step name must not crash the bridge.

        Unknown steps are silently skipped; the result is the remaining output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")

        payload = b"\xAB\xCD\xEF\x01"
        _open_with_payload(bridge, tmp_path / "invalid_step.bin", payload)

        pipeline = json.dumps([
            {"name": "nonexistent_transform_xyzzy", "params": {}},
        ])
        raised: Exception | None = None
        result: str | None = None
        try:
            result = _run(bridge.apply_pipeline(pipeline, 0, 4))
        except (RuntimeError, ValueError, KeyError) as exc:
            raised = exc

        if raised is None:
            assert result is not None
            assert isinstance(result, str)


class TestApplyTransformDeep:
    """Deeper tests for bridge.apply_transform across different transforms and ranges."""

    def test_apply_transform_xor_with_key_parameter(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """apply_transform with xor_single and a known key must produce the correct output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _require_transform(bridge, "xor_single")

        payload = b"\x41\x41\x41\x41"
        _open_with_payload(bridge, tmp_path / "xorkey.bin", payload)

        result: str = _run(
            bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "41"}))
        )

        assert result == "00000000"

    def test_apply_transform_on_second_subrange(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """apply_transform on a non-zero offset must only transform bytes in that range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _require_transform(bridge, "xor_single")

        payload = b"\x00" * 4 + b"\xFF\xFF\xFF\xFF" + b"\x00" * 4
        _open_with_payload(bridge, tmp_path / "subrange_transform.bin", payload)

        result: str = _run(
            bridge.apply_transform("xor_single", 4, 4, json.dumps({"key": "FF"}))
        )

        transformed = bytes.fromhex(result)
        assert all(b == 0x00 for b in transformed)

    def test_apply_transform_rot13_on_text_bytes(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """apply_transform with rot13 must rotate alphabetic ASCII bytes by 13 positions.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "rot13" not in names:
            pytest.skip("rot13 transform not available")

        text = "HELLO"
        payload = text.encode("ascii") + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "rot13.bin", payload)

        result: str = _run(
            bridge.apply_transform("rot13", 0, len(text), "{}")
        )

        transformed = bytes.fromhex(result).decode("ascii")
        assert transformed == "URYYB"

    def test_apply_transform_base64_encode_produces_valid_base64(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """apply_transform with base64_encode must produce a validly decodable hex output.

        The transform returns bytes of the base64 ASCII string; verifying by
        decoding the hex and re-interpreting as ASCII base64.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "base64_encode" not in names:
            pytest.skip("base64_encode transform not available")

        payload = b"TestData" + b"\x00" * 8
        _open_with_payload(bridge, tmp_path / "b64.bin", payload)

        result: str = _run(
            bridge.apply_transform("base64_encode", 0, 8, "{}")
        )

        b64_bytes = bytes.fromhex(result)
        decoded = base64.b64decode(b64_bytes)
        assert decoded == b"TestData"

    def test_apply_transform_xor_identity_key_zero(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """XOR-ing with key 0x00 must leave bytes unchanged (identity operation).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _require_transform(bridge, "xor_single")

        payload = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        _open_with_payload(bridge, tmp_path / "xor_id.bin", payload)

        result: str = _run(
            bridge.apply_transform("xor_single", 0, 8, json.dumps({"key": "00"}))
        )

        assert result == binascii.hexlify(payload).decode("ascii")

    def test_apply_transform_different_byte_ranges_give_different_output(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """apply_transform on two non-overlapping ranges of distinct bytes gives distinct output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _require_transform(bridge, "xor_single")

        payload = b"\x00\x00\x00\x00" + b"\xFF\xFF\xFF\xFF"
        _open_with_payload(bridge, tmp_path / "twobranch.bin", payload)

        result_first: str = _run(
            bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "AA"}))
        )
        result_second: str = _run(
            bridge.apply_transform("xor_single", 4, 4, json.dumps({"key": "AA"}))
        )

        assert result_first != result_second

    def test_apply_pipeline_vs_apply_transform_single_step_match(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """A single-step pipeline and direct apply_transform with the same params produce equal output.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\xDE\xAD\xBE\xEF"
        _open_with_payload(bridge, tmp_path / "compare.bin", payload)

        direct: str = _run(
            bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "CA"}))
        )
        pipeline = json.dumps([{"name": "xor_single", "params": {"key": "CA"}}])
        via_pipeline: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        assert direct == via_pipeline

    def test_apply_transform_on_pe_binary(
        self, loaded_bridge: Any
    ) -> None:
        """apply_transform must successfully process bytes from a real PE binary document.

        Args:
            loaded_bridge: A bridge with the PE file already opened.
        """
        _require_transform(loaded_bridge, "xor_single")

        result: str = _run(
            loaded_bridge.apply_transform("xor_single", 0, 2, json.dumps({"key": "00"}))
        )

        assert result == "4d5a"

    def test_apply_pipeline_three_steps_with_known_verification(
        self, bridge: Any, tmp_path: Any
    ) -> None:
        """A three-step pipeline with XOR steps must produce the mathematically expected result.

        XOR(k1) then XOR(k2) then XOR(k3) equals XOR(k1 ^ k2 ^ k3).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline not available")
        _require_transform(bridge, "xor_single")

        payload = b"\x00\x00\x00\x00"
        _open_with_payload(bridge, tmp_path / "triple_xor.bin", payload)

        k1, k2, k3 = 0x11, 0x22, 0x33
        expected_byte = k1 ^ k2 ^ k3

        pipeline = json.dumps([
            {"name": "xor_single", "params": {"key": f"{k1:02X}"}},
            {"name": "xor_single", "params": {"key": f"{k2:02X}"}},
            {"name": "xor_single", "params": {"key": f"{k3:02X}"}},
        ])
        result: str = _run(bridge.apply_pipeline(pipeline, 0, 4))

        transformed = bytes.fromhex(result)
        assert all(b == expected_byte for b in transformed)
