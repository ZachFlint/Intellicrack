# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass critical-coverage tests for ``intellicrack.bridges.hex_editor``.

The first pass and the earlier suites already drive every branch that a real
``intellicrack_hexcore.HexDocument`` can reach. What is left here is small: the
probe-failure path of ``initialize``, the unavailable transform-pipeline guard, the
ASCII scanner when the buffer ends on a non-printable byte, the no-document guard of
``export_patches_ups``, the PDF hex-row renderer (driven through a real subclass of
the bridge's own ``_FPDFProtocol``), and a red test for the PE checksum contract.
Expectations are written out literally from the documented layouts.
"""

from __future__ import annotations

import gc
import re
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest

from intellicrack.bridges import hex_editor as hex_editor_module
from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterator
    from pathlib import Path


type _Call = tuple[str, tuple[object, ...]]

_PROTOCOL_NAME = "_FPDFProtocol"
_FpdfBase: Any = getattr(hex_editor_module, _PROTOCOL_NAME)
_HIGHLIGHT_RGB = (230, 240, 255)
_ROW_HEIGHT = 3.5
_ASCII_RUN = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")


class _RecordingPdf(_FpdfBase):
    """Real subclass of the bridge's ``_FPDFProtocol`` that records the drawing calls it receives.

    Every override forwards to the protocol's own method first, so the inherited behavior
    still runs, and then appends one entry to :attr:`calls`.
    """

    def __init__(self, **kwargs: str) -> None:
        """Start with no recorded calls.

        Args:
            **kwargs: Constructor keyword arguments forwarded to the protocol initializer.
        """
        _method(super(), "__init__")(**kwargs)
        self.calls: list[_Call] = []

    def set_font(self, family: str, style: str = "", size: float = 0) -> None:
        """Record a font selection.

        Args:
            family: Font family name.
            style: Font style.
            size: Font size in points.
        """
        _method(super(), "set_font")(family, style, size)
        self.calls.append(("font", (family, style, size)))

    def set_fill_color(self, r: int, g: int = 0, b: int = 0) -> None:
        """Record a fill color selection.

        Args:
            r: Red component.
            g: Green component.
            b: Blue component.
        """
        _method(super(), "set_fill_color")(r, g, b)
        self.calls.append(("fill_color", (r, g, b)))

    def cell(
        self,
        w: float,
        h: float = 0,
        txt: str = "",
        *,
        fill: bool = False,
        new_x: str = "RIGHT",
        new_y: str = "TOP",
    ) -> None:
        """Record one drawn cell.

        Args:
            w: Cell width.
            h: Cell height.
            txt: Cell text.
            fill: Whether the cell background is filled.
            new_x: Cursor X advance directive.
            new_y: Cursor Y advance directive.
        """
        _method(super(), "cell")(w, h, txt, fill=fill, new_x=new_x, new_y=new_y)
        self.calls.append(("cell", (w, h, txt, fill)))

    def ln(self, h: float = 0) -> None:
        """Record a line break.

        Args:
            h: Line height.
        """
        _method(super(), "ln")(h)
        self.calls.append(("ln", (h,)))


def _method(owner: object, name: str) -> Callable[..., object]:
    """Look up a private attribute of ``owner`` that must be callable.

    Args:
        owner: Object or class owning the attribute.
        name: Attribute name.

    Returns:
        Callable[..., object]: The bound or static callable.

    Raises:
        TypeError: If the attribute is not callable.
    """
    value: object = getattr(owner, name)
    if not callable(value):
        msg = f"{owner!r}.{name} is not callable"
        raise TypeError(msg)
    return value


async def _await_object(awaitable: object) -> object:
    """Await the coroutine returned by an async bridge method looked up by name.

    Args:
        awaitable: Coroutine object returned by the call.

    Returns:
        object: The coroutine's result.
    """
    return await cast("Awaitable[object]", awaitable)


def _open_bytes(bridge: HexEditorBridge, data: bytes) -> intellicrack_hexcore.HexDocument:
    """Attach an in-memory ``HexDocument`` holding ``data`` to ``bridge``.

    Args:
        bridge: Bridge receiving the document.
        data: Document contents.

    Returns:
        intellicrack_hexcore.HexDocument: The attached document.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(data)
    bridge.document = document
    return document


@contextmanager
def _module_attribute_cleared(name: str) -> Generator[None]:
    """Set a private data attribute of the hex editor module to ``None``, restoring it on exit.

    Args:
        name: Attribute name on ``intellicrack.bridges.hex_editor``.

    Yields:
        None: Control while the attribute is ``None``.
    """
    original: object = getattr(hex_editor_module, name)
    setattr(hex_editor_module, name, None)
    try:
        yield
    finally:
        setattr(hex_editor_module, name, original)


def _hex_row(offset_text: str, hex_text: str, ascii_text: str, *, highlighted: bool) -> list[_Call]:
    """Build the calls one rendered hex row must produce, using the column widths 11, 12 and 13.

    Args:
        offset_text: Expected offset column text.
        hex_text: Expected hex column text.
        ascii_text: Expected ASCII column text.
        highlighted: Whether the row carries a bookmark highlight.

    Returns:
        list[_Call]: Expected calls in order.
    """
    calls: list[_Call] = []
    if highlighted:
        calls.append(("fill_color", _HIGHLIGHT_RGB))
    calls.extend([
        ("cell", (11.0, _ROW_HEIGHT, offset_text, highlighted)),
        ("cell", (12.0, _ROW_HEIGHT, hex_text, highlighted)),
        ("cell", (13.0, _ROW_HEIGHT, ascii_text, highlighted)),
        ("ln", (_ROW_HEIGHT,)),
    ])
    return calls


def _render_rows(data: bytes, start_offset: int, bookmark_offsets: set[int]) -> list[_Call]:
    """Run the bridge's PDF hex-row renderer against a recording PDF with 4 bytes per row.

    Args:
        data: Bytes to render.
        start_offset: Absolute offset of the first byte.
        bookmark_offsets: Absolute offsets that carry a bookmark.

    Returns:
        list[_Call]: Calls the renderer made, in order.
    """
    pdf = _RecordingPdf()
    bookmark_map: dict[int, dict[str, object]] = {offset: {"label": "mark"} for offset in bookmark_offsets}
    _method(hex_editor_module, "_pdf_render_hex_rows")(pdf, data, start_offset, 4, bookmark_map, (11.0, 12.0, 13.0))
    return pdf.calls


@pytest.fixture
def hex_bridge() -> Iterator[HexEditorBridge]:
    """Provide an uninitialized ``HexEditorBridge`` and release any document afterwards.

    Yields:
        HexEditorBridge: A bridge with no document attached.
    """
    bridge = HexEditorBridge()
    try:
        yield bridge
    finally:
        bridge.document = None
        gc.collect()


@pytest.mark.asyncio
async def test_initialize_reports_probe_failure_when_the_hexcore_module_reference_is_missing(hex_bridge: HexEditorBridge) -> None:
    """A bridge that believes hexcore is importable but holds no module reference reports a failed probe.

    The module-level ``_hexcore_mod`` reference is set to ``None`` for the first call and
    restored for the second, which must then connect normally.

    Args:
        hex_bridge: Bridge under test.
    """
    with _module_attribute_cleared("_hexcore_mod"):
        await hex_bridge.initialize()
        probe_connected = hex_bridge.state.connected
        probe_running = hex_bridge.state.tool_running
        probe_error = hex_bridge.state.last_error

    await hex_bridge.initialize()

    assert probe_connected is False
    assert probe_running is False
    assert probe_error == "hex_editor backend probe failed"
    assert hex_bridge.state.connected is True
    assert hex_bridge.state.tool_running is True


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(b"\x00hello\x00", [(1, 5, "hello")], id="run-closed-by-the-last-byte"),
        pytest.param(b"abc\x00defgh\x01", [(4, 5, "defgh")], id="short-run-then-long-run-then-control-byte"),
        pytest.param(b"ab\x00cd\x00", [], id="only-short-runs"),
    ],
)
def test_ascii_scan_of_a_buffer_ending_on_a_non_printable_byte_adds_no_trailing_run(
    data: bytes,
    expected: list[tuple[int, int, str]],
) -> None:
    """When the last byte ends a run there is no pending run to flush, so only the closed runs are reported.

    The oracle is a regular expression over the printable ASCII range plus tab, line feed and carriage return.

    Args:
        data: Buffer to scan.
        expected: ``(offset, length, content)`` of the runs of four or more printable bytes.
    """
    scan = _method(HexEditorBridge, "_extract_strings_fallback")
    rows = cast("list[dict[str, Any]]", scan(data, 4, 10, include_ascii=True, include_utf16=False))
    oracle = [(m.start(), m.end() - m.start(), m.group().decode("ascii")) for m in _ASCII_RUN.finditer(data)]

    assert [(int(r["offset"]), int(r["length"]), str(r["content"])) for r in rows] == expected
    assert expected == oracle
    assert {str(r["encoding"]) for r in rows} <= {"ascii"}


@pytest.mark.asyncio
async def test_export_patches_ups_requires_an_open_document(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Exporting a UPS patch with no document raises ``RuntimeError`` before touching the original file.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(b"abcd")

    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.export_patches_ups(str(original))

    assert original.read_bytes() == b"abcd"


@pytest.mark.asyncio
async def test_apply_pipeline_reports_a_missing_pipeline_module_and_leaves_the_bytes_alone(hex_bridge: HexEditorBridge) -> None:
    """Without the transform-pipeline class the call fails explicitly and the document is not changed.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x01\x02\x03\x04")

    with (
        _module_attribute_cleared("_TransformPipeline"),
        pytest.raises(RuntimeError, match="transform_pipeline module not available"),
    ):
        await hex_bridge.apply_pipeline('[{"name": "xor", "params": {}}]', 0, 4)

    assert document.read(0, 4) == b"\x01\x02\x03\x04"


def test_pdf_rows_render_offset_hex_and_ascii_columns_with_their_own_widths() -> None:
    """Each row draws an eight-digit upper-case offset, upper-case hex bytes and a dotted ASCII column.

    Bytes outside 0x20-0x7E (0x1F, 0x7F, 0x80) print as dots; a short last row is not padded.
    """
    data = bytes([0x41, 0x42, 0x1F, 0x7E, 0x7F, 0x80, 0x61])

    calls = _render_rows(data, 0xABC0, set())

    assert calls == [
        *_hex_row("0000ABC0", "41 42 1F 7E", "AB.~", highlighted=False),
        *_hex_row("0000ABC4", "7F 80 61", "..a", highlighted=False),
    ]


@pytest.mark.parametrize(
    ("bookmark_offsets", "highlighted_rows"),
    [
        pytest.param({0xABC2}, (True, False), id="middle-of-first-row"),
        pytest.param({0xABC7}, (False, True), id="last-byte-of-second-row"),
        pytest.param({0xABC0, 0xABC5}, (True, True), id="both-rows"),
        pytest.param({0xABBF, 0xABC8}, (False, False), id="just-outside-the-range"),
    ],
)
def test_pdf_rows_highlight_exactly_the_rows_that_contain_a_bookmarked_offset(
    bookmark_offsets: set[int],
    highlighted_rows: tuple[bool, bool],
) -> None:
    """A row gets the light-blue fill only when one of its own absolute offsets carries a bookmark.

    Args:
        bookmark_offsets: Absolute offsets that carry a bookmark.
        highlighted_rows: Whether the first and second rows must be highlighted.
    """
    data = b"ABCDEFGH"

    calls = _render_rows(data, 0xABC0, bookmark_offsets)

    assert calls == [
        *_hex_row("0000ABC0", "41 42 43 44", "ABCD", highlighted=highlighted_rows[0]),
        *_hex_row("0000ABC4", "45 46 47 48", "EFGH", highlighted=highlighted_rows[1]),
    ]


def test_pdf_rows_draw_nothing_for_empty_data() -> None:
    """With no bytes there are no rows, so the renderer makes no drawing call at all."""
    assert _render_rows(b"", 0, {0}) == []


def test_pdf_bookmark_legend_lists_each_label_once_and_skips_empty_labels() -> None:
    """The legend names a label at its first offset only, ignores empty labels, and ends with a four-unit break."""
    pdf = _RecordingPdf()
    bookmarks: list[dict[str, object]] = [
        {"offset": 0x10, "length": 4, "label": "Header", "color": "#ff0000"},
        {"offset": 0x20, "length": 2, "label": "Header", "color": "#ff0000"},
        {"offset": 0x30, "length": 1, "label": "", "color": "#00ff00"},
        {"offset": 0x40, "length": 8, "label": "Body", "color": "#0000ff"},
    ]

    _method(hex_editor_module, "_pdf_render_bookmarks")(pdf, bookmarks)

    assert pdf.calls == [
        ("font", ("Courier", "B", 10)),
        ("cell", (0, 6, "Bookmarks:", False)),
        ("font", ("Courier", "", 8)),
        ("cell", (0, 5, "  Header: 0x10 (4 bytes)", False)),
        ("cell", (0, 5, "  Body: 0x40 (8 bytes)", False)),
        ("ln", (4,)),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", ["verify_pe_checksum", "repair_pe_checksum"])
async def test_pe_checksum_methods_raise_runtime_error_for_a_document_that_is_not_a_pe(
    hex_bridge: HexEditorBridge,
    method_name: str,
) -> None:
    """Both methods document ``RuntimeError`` for a file that is not a PE, whatever backend is in use.

    Args:
        hex_bridge: Bridge under test.
        method_name: Name of the checksum method.
    """
    _open_bytes(hex_bridge, b"this is plain text, not an executable".ljust(0x100, b" "))

    with pytest.raises(RuntimeError):
        await _await_object(_method(hex_bridge, method_name)())


def test_native_document_returns_the_types_the_bridge_branches_on() -> None:
    """The native document hands back ``bytes``, ``dict`` and list-of-``dict`` values, never the alternates the bridge tolerates."""
    document = intellicrack_hexcore.HexDocument.open_bytes(b"\x00\x01hello world\x02")

    raw = document.read(0, 4)
    inspection = document.inspect_at(0)
    strings = document.extract_strings(min_length=4, include_ascii=True, include_utf16=False, max_results=10)

    assert type(raw) is bytes
    assert raw == b"\x00\x01he"
    assert isinstance(inspection, dict)
    assert strings
    assert all(isinstance(row, dict) for row in strings)
    assert all(set(row) == {"offset", "length", "encoding", "content"} for row in strings)
