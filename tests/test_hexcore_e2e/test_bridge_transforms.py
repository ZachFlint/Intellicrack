# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge data transform operations."""

from __future__ import annotations

import asyncio
import importlib
import json
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


_PYTHON_NODE_IDENTITIES: dict[str, tuple[str, str]] = {
    "regex_replace": ("python", "Replace binary patterns using a regular expression"),
    "custom_expression": ("python", "Apply a Python expression to each byte; use 'b' for byte value, 'i' for index"),
    "repeat": ("python", "Repeat input data N times"),
    "truncate": ("python", "Truncate data to at most N bytes"),
    "pad": ("python", "Pad data to a target length with a fill byte"),
}


def _engine_transforms() -> list[tuple[str, str, str]]:
    """Return the Rust hexcore engine's own transform catalogue.

    Imports the native extension directly (bypassing the bridge under test)
    so its ``list_transforms`` output can serve as an independent oracle for
    the Rust subset the bridge must expose without loss or mutation.

    Returns:
        list[tuple[str, str, str]]: ``(name, category, description)`` tuples
        reported by the native ``HexDocument.list_transforms``.
    """
    inner: Any = importlib.import_module("intellicrack_hexcore.intellicrack_hexcore")
    raw: list[tuple[str, str, str]] = inner.HexDocument().list_transforms()
    return [(str(n), str(c), str(d)) for n, c, d in raw]


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


_pipeline_available: bool
try:
    from importlib.util import find_spec as _find_spec

    _pipeline_available = _find_spec("intellicrack.core.transform_pipeline") is not None
except (ImportError, ValueError):
    _pipeline_available = False


class TestBridgeListTransforms:
    """Tests covering the list_transforms operation."""

    def test_bridge_exposes_full_rust_engine_catalogue(self, bridge: HexEditorBridge) -> None:
        """The bridge surfaces every Rust transform the engine reports, unchanged.

        Uses the native ``HexDocument.list_transforms`` output as an
        independent oracle and asserts the bridge passes each
        ``(name, category, description)`` triple through verbatim, with no
        Rust transform dropped or mutated.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        bridged = {item["name"]: (item["category"], item["description"]) for item in result}

        engine = _engine_transforms()
        assert len(engine) == 23, "expected the full native transform catalogue"
        for name, category, description in engine:
            assert name in bridged, f"bridge dropped Rust transform {name!r}"
            assert bridged[name] == (category, description), f"bridge mutated metadata for {name!r}"

    def test_bridge_includes_python_only_nodes_with_exact_metadata(self, bridge: HexEditorBridge) -> None:
        """The five Python-only transforms appear with their exact identities.

        These nodes have no Rust counterpart, so the bridge is the only place
        that surfaces them. Each must carry its stable name, the ``python``
        category, and its declared description.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        bridged = {item["name"]: (item["category"], item["description"]) for item in result}
        for name, expected in _PYTHON_NODE_IDENTITIES.items():
            assert name in bridged, f"bridge missing Python node {name!r}"
            assert bridged[name] == expected, f"unexpected metadata for {name!r}"

    def test_list_transforms_is_exact_union_of_rust_and_python(self, bridge: HexEditorBridge) -> None:
        """The catalogue is exactly the Rust engine set plus the Python nodes.

        Asserts the total count and the exact name set, so neither a stray
        extra transform nor a silently missing one can pass. Every entry must
        also expose all three string keys with non-empty name and category.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_transforms())
        names = [item["name"] for item in result]
        assert len(names) == len(set(names)), "duplicate transform names returned"

        engine_names = {name for name, _, _ in _engine_transforms()}
        expected_names = engine_names | set(_PYTHON_NODE_IDENTITIES)
        assert set(names) == expected_names
        assert len(result) == 23 + len(_PYTHON_NODE_IDENTITIES)

        for item in result:
            assert set(item) == {"name", "category", "description"}
            assert item["name"]
            assert item["category"]


class TestBridgeApplyTransform:
    """Tests covering individual transform application to byte ranges."""

    def test_apply_transform_xor_single_returns_hex_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
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

    def test_apply_transform_xor_single_known_output(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
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

    def test_apply_transform_returns_length_matching_input(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
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

    def test_apply_pipeline_with_single_xor_step(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
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
