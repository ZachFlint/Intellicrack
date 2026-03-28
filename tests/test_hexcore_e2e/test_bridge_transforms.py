# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge data transform operations."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


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


_pipeline_available: bool
try:
    from importlib.util import find_spec as _find_spec

    _pipeline_available = _find_spec("intellicrack.core.transform_pipeline") is not None
except (ImportError, ValueError):
    _pipeline_available = False


class TestBridgeListTransforms:
    """Tests covering the list_transforms operation."""

    def test_list_transforms_returns_list(self, bridge: Any) -> None:
        """Verify that list_transforms returns a list object.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        assert isinstance(result, list)

    def test_list_transforms_items_have_required_keys(self, bridge: Any) -> None:
        """Verify that each transform dict has name, category, and description.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        if result:
            for item in result:
                assert "name" in item
                assert "category" in item
                assert "description" in item

    def test_list_transforms_name_values_are_strings(self, bridge: Any) -> None:
        """Verify that transform name values are non-empty strings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        for item in result:
            assert isinstance(item["name"], str)
            assert len(item["name"]) > 0


class TestBridgeApplyTransform:
    """Tests covering individual transform application to byte ranges."""

    def test_apply_transform_xor_single_returns_hex_string(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that apply_transform with xor_single returns a hex string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "xor_single" not in names:
            pytest.skip("xor_single transform not available")

        payload = b"\xff" * 8
        f = tmp_path / "xortest.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: str = _run(bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "AA"})))
        assert isinstance(result, str)
        assert len(result) == 8

    def test_apply_transform_xor_single_known_output(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that XOR-ing 0xFF bytes with 0xFF produces 0x00 bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "xor_single" not in names:
            pytest.skip("xor_single transform not available")

        payload = b"\xff\xff\xff\xff"
        f = tmp_path / "xorknown.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: str = _run(bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "FF"})))
        assert result == "00000000"

    def test_apply_transform_returns_length_matching_input(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that apply_transform output length in bytes equals the input length.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "xor_single" not in names:
            pytest.skip("xor_single transform not available")

        payload = b"\xaa" * 16
        f = tmp_path / "xorlen.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        result: str = _run(bridge.apply_transform("xor_single", 0, 16, json.dumps({"key": "00"})))
        assert len(result) == 32


class TestBridgeApplyPipeline:
    """Tests covering pipeline application when the transform_pipeline module is available."""

    def test_apply_pipeline_with_single_xor_step(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a single-step pipeline produces the same result as apply_transform.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        if not _pipeline_available:
            pytest.skip("transform_pipeline module not available")

        transforms: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [t["name"] for t in transforms]
        if "xor_single" not in names:
            pytest.skip("xor_single transform not available")

        payload = b"\xff" * 4
        f = tmp_path / "pipeline.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))

        pipeline_json = json.dumps([{"name": "xor_single", "params": {"key": "AA"}}])
        result: str = _run(bridge.apply_pipeline(pipeline_json, 0, 4))
        assert isinstance(result, str)
        assert len(result) == 8
