# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-level regression tests for audit5 F-0007 (HexPat ``std::print`` sink).

The pre-audit ``HexEditorBridge`` never wired the HexPat ``std::print``
output to any consumer, so AI / CLI callers had no observable channel for
``std::print`` payloads emitted by the pattern under evaluation. These
regressions verify two distinct contracts:

* :meth:`HexEditorBridge.execute_pattern` (and its ``_file`` sibling)
  must accept an optional ``print_sink`` callback and route every
  ``std::print`` message through it.
* :meth:`HexEditorBridge.execute_pattern_with_output` and
  :meth:`HexEditorBridge.execute_pattern_file_with_output` must capture
  ``std::print`` output via an in-memory sink and return it in the
  response payload as a ``hexpat_print`` string.

All tests drive the real :class:`HexEditorBridge` and the real HexPat
interpreter; only the document is replaced with a minimal stub so the
suite can exercise the production pipeline without depending on the
optional ``intellicrack_hexcore`` native build. The suite skips only
when the pure-Python ``intellicrack.core.hexpat`` package itself fails
to import.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


class _StubDocument:
    """Minimal HexDocument-compatible stub backed by an in-memory ``bytes`` buffer.

    The HexPat interpreter only requires the ``read(offset, length) -> list[int]``
    and ``length`` shape exposed by ``intellicrack.core.hexpat.data_reader.
    _resolve_length``. The stub fulfils that contract so the bridge tests can
    exercise the full pattern engine without depending on the native
    ``intellicrack_hexcore`` build.
    """

    def __init__(self, data: bytes) -> None:
        """Capture the byte buffer the stub exposes via ``read`` / ``length``.

        Args:
            data: Underlying bytes the stub returns from ``read``.
        """
        self._data: bytes = bytes(data)

    def length(self) -> int:
        """Return the byte length of the stub buffer.

        Returns:
            int: Size of the stub buffer in bytes.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> list[int]:
        """Return a slice of the stub buffer as a list of integers.

        Mirrors the PyO3 binding shape used by the production hexcore
        ``HexDocument`` so the HexPat interpreter's ``DataReader.from_document``
        adapter accepts the stub without modification.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to return.

        Returns:
            list[int]: The requested byte slice as a list of integers.
        """
        return list(self._data[offset : offset + length])


_PRINT_PATTERN: str = """
fn __ping() {
    builtin::std::io::print("hello-from-print-sink");
    return 0;
};
u8 __mark @ __ping();
"""


_PRINT_PATTERN_MULTI: str = """
fn __ping() {
    builtin::std::io::print("line-one");
    builtin::std::io::print("line-two");
    builtin::std::io::print("line-three");
    return 0;
};
u8 __mark @ __ping();
"""


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine on a session-stable event loop.

    Args:
        coro: Coroutine to drive to completion.

    Returns:
        T: The coroutine's return value.
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


@pytest.fixture
def loaded_bridge() -> HexEditorBridge:
    """Construct a fresh ``HexEditorBridge`` with a stub document attached.

    The bridge's HexPat methods only require ``self.document`` to be a
    ``HexDocument``-shaped object. Using :class:`_StubDocument` keeps the
    suite independent of the optional ``intellicrack_hexcore`` build.

    The fixture probes the real HexPat interpreter by executing a minimal
    pattern before returning. A broken or missing hexpat package raises
    ``RuntimeError`` (from the bridge's ``_get_interpreter`` guard) rather
    than silently skipping at import time. A genuine
    ``ImportError`` / ``ModuleNotFoundError`` inside the interpreter package
    itself is the only condition that permits a legitimate skip.

    Returns:
        HexEditorBridge: Initialized bridge with a stub document attached.
    """
    bridge = HexEditorBridge()
    _run(bridge.initialize())
    bridge.document = _StubDocument(b"\x00" * 256)
    try:
        _run(bridge.execute_pattern("u8 x @ 0x00;"))
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.skip(f"hexpat interpreter package unavailable: {exc}")
    return bridge


class TestExecutePatternForwardsPrintSink:
    """``execute_pattern`` must invoke the supplied ``print_sink`` callback."""

    def test_print_sink_receives_pattern_output(self, loaded_bridge: HexEditorBridge) -> None:
        """A pattern that calls ``std::print`` must reach the bridge's print sink.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        captured: list[str] = []
        _run(loaded_bridge.execute_pattern(_PRINT_PATTERN, print_sink=captured.append))
        assert any("hello-from-print-sink" in line for line in captured), (
            f"expected 'hello-from-print-sink' in captured sink output; got {captured!r}"
        )

    def test_omitting_print_sink_does_not_raise(self, loaded_bridge: HexEditorBridge) -> None:
        """Omitting print_sink must still return a non-empty decoded field list.

        The pattern declares ``u8 __mark @ __ping()``; the no-sink path must
        produce the same structural output as the sink path.  Asserting the
        ``__mark`` anchor field is present gates the entire execute pipeline,
        not merely the call shape.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        fields: list[dict[str, Any]] = _run(loaded_bridge.execute_pattern(_PRINT_PATTERN))
        assert fields, "expected at least one decoded field from _PRINT_PATTERN without a sink"
        field_names: list[str] = [str(f.get("name", "")) for f in fields]
        assert any("__mark" in name for name in field_names), (
            f"expected '__mark' anchor field in decoded output; got field names {field_names!r}"
        )


class TestExecutePatternWithOutputCapturesPrint:
    """``execute_pattern_with_output`` must return both fields and printed text."""

    def test_response_payload_contains_hexpat_print_key(self, loaded_bridge: HexEditorBridge) -> None:
        """The bridge response must expose ``hexpat_print`` with captured text.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        payload: dict[str, Any] = _run(loaded_bridge.execute_pattern_with_output(_PRINT_PATTERN))
        assert isinstance(payload, dict)
        assert "fields" in payload
        assert "hexpat_print" in payload
        assert "hello-from-print-sink" in payload["hexpat_print"]

    def test_response_payload_preserves_fields_list_shape(self, loaded_bridge: HexEditorBridge) -> None:
        """The ``fields`` entry must match a direct ``execute_pattern`` call and contain ``__mark``.

        The independent oracle is a direct invocation of ``execute_pattern`` on the
        same source.  ``execute_pattern_with_output`` must return exactly the same
        number of fields and must include the ``__mark`` anchor declared at the top
        level of ``_PRINT_PATTERN``.  A regression that breaks print-sink wiring
        but leaves the fields pipeline intact still passes ``test_omitting_print_sink_does_not_raise``;
        this test gates the *with_output* wrapper's fields forwarding specifically.

        Concrete mutation that makes this fail:
            In ``execute_pattern_with_output`` change
            ``fields: list[dict[str, Any]] = await self.execute_pattern(source, offset, print_sink=captured.append)``
            to ``fields: list[dict[str, Any]] = []`` — the ``len(fields) == len(direct_fields)``
            assertion fails because ``direct_fields`` is non-empty and ``fields`` is empty.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        payload: dict[str, Any] = _run(loaded_bridge.execute_pattern_with_output(_PRINT_PATTERN))
        fields: list[dict[str, Any]] = payload["fields"]

        direct_fields: list[dict[str, Any]] = _run(loaded_bridge.execute_pattern(_PRINT_PATTERN))

        assert isinstance(fields, list), "fields must be a list"
        assert len(fields) == len(direct_fields), (
            f"execute_pattern_with_output returned {len(fields)} fields but "
            f"execute_pattern returned {len(direct_fields)} for the same source"
        )
        field_names: list[str] = [str(f.get("name", "")) for f in fields]
        assert any("__mark" in name for name in field_names), (
            f"expected '__mark' anchor field in execute_pattern_with_output fields; got field names {field_names!r}"
        )

    def test_multiple_prints_are_newline_joined(self, loaded_bridge: HexEditorBridge) -> None:
        """All ``std::print`` invocations must appear in the captured text.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        payload: dict[str, Any] = _run(loaded_bridge.execute_pattern_with_output(_PRINT_PATTERN_MULTI))
        captured_text: str = payload["hexpat_print"]
        assert "line-one" in captured_text
        assert "line-two" in captured_text
        assert "line-three" in captured_text

    def test_pattern_without_print_returns_empty_hexpat_print(self, loaded_bridge: HexEditorBridge) -> None:
        """A silent pattern yields empty output while a printing pattern is captured.

        The silent-pattern empty result alone is not falsifiable: the pre-fix
        broken state (no print sink wired) ALSO produced an empty string for
        every pattern.  This test therefore first drives a printing pattern
        through the same bridge/sink path and asserts the captured text is the
        expected non-empty content - anchoring that the sink IS wired - then
        asserts the silent pattern yields exactly the empty string, proving the
        bridge does not fabricate output rather than that the sink is missing.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
        """
        printing: dict[str, Any] = _run(loaded_bridge.execute_pattern_with_output(_PRINT_PATTERN))
        assert "hello-from-print-sink" in printing["hexpat_print"], (
            "the print sink must capture std::print output; an unwired sink would also "
            "yield empty output, so this positive case anchors the silent-pattern assertion"
        )

        silent: dict[str, Any] = _run(loaded_bridge.execute_pattern_with_output("u32 silent @ 0x00;"))
        assert isinstance(silent["hexpat_print"], str)
        assert not silent["hexpat_print"]


class TestExecutePatternFileWithOutputCapturesPrint:
    """``execute_pattern_file_with_output`` must capture prints from a file pattern."""

    def test_response_payload_contains_captured_print_text(
        self,
        loaded_bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """The bridge response from a pattern file must include ``std::print`` text.

        Args:
            loaded_bridge: Bridge fixture with a 256-byte zero document open.
            tmp_path: Pytest temporary directory for the pattern file.
        """
        pattern_file = tmp_path / "u12_print.hexpat"
        pattern_file.write_text(_PRINT_PATTERN, encoding="utf-8")
        payload: dict[str, Any] = _run(loaded_bridge.execute_pattern_file_with_output(str(pattern_file)))
        assert "hello-from-print-sink" in payload["hexpat_print"]
        assert isinstance(payload["fields"], list)


class TestExecutePatternToolFunctionRegistration:
    """The new ``*_with_output`` tools must be registered in the tool catalogue."""

    def test_execute_pattern_with_output_is_registered(self, loaded_bridge: HexEditorBridge) -> None:
        """``hex_editor.execute_pattern_with_output`` is registered with a real schema.

        Beyond mere name presence (which a stub could satisfy), asserts the
        registered ``ToolFunction`` carries a non-empty description and return
        text, declares its required ``source`` parameter, and that the bare
        method name resolves to a real callable on the bridge - so the registry
        entry genuinely points at the implementation.

        Args:
            loaded_bridge: Bridge fixture (used for its tool catalogue and method).
        """
        functions = {fn.name: fn for fn in loaded_bridge.tool_definition.functions}
        fn = functions.get("hex_editor.execute_pattern_with_output")
        assert fn is not None, "hex_editor.execute_pattern_with_output must be registered"
        assert fn.description.strip(), "registered function must carry a description"
        assert fn.returns.strip(), "registered function must document its return value"
        param_names = {param.name for param in fn.parameters}
        assert "source" in param_names, f"registered function must expose its required 'source' parameter; got {sorted(param_names)}"
        method = getattr(loaded_bridge, "execute_pattern_with_output", None)
        assert callable(method), "the registered tool name must resolve to a real bridge method"

    def test_execute_pattern_file_with_output_is_registered(self, loaded_bridge: HexEditorBridge) -> None:
        """``hex_editor.execute_pattern_file_with_output`` is registered with a real schema.

        Asserts the registered ``ToolFunction`` carries a non-empty description
        and return text, declares its required ``pattern_path`` parameter, and
        that the bare method name resolves to a real callable on the bridge.

        Args:
            loaded_bridge: Bridge fixture (used for its tool catalogue and method).
        """
        functions = {fn.name: fn for fn in loaded_bridge.tool_definition.functions}
        fn = functions.get("hex_editor.execute_pattern_file_with_output")
        assert fn is not None, "hex_editor.execute_pattern_file_with_output must be registered"
        assert fn.description.strip(), "registered function must carry a description"
        assert fn.returns.strip(), "registered function must document its return value"
        param_names = {param.name for param in fn.parameters}
        assert "pattern_path" in param_names, (
            f"registered function must expose its required 'pattern_path' parameter; got {sorted(param_names)}"
        )
        method = getattr(loaded_bridge, "execute_pattern_file_with_output", None)
        assert callable(method), "the registered tool name must resolve to a real bridge method"
