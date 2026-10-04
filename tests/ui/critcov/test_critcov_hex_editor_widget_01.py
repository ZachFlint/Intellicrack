# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the painting, cursor, keyboard-editing and cached-scan paths of the hex editor widget.

Every test drives a real ``HexEditorWidget`` that displays a genuine ``intellicrack_hexcore.HexDocument``. Keyboard behavior is exercised
with real key events, the minimap with real mouse events, and painting by rendering the viewport into a ``QImage`` and reading pixels. The
background entropy and content-classification scans run on the real asynchronous worker used by the application. Expected values come
from byte arithmetic (Shannon entropy of uniform byte sets, struct layouts written out by hand, row and column geometry derived from the
widget's own font metrics) and never from re-running the code under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import QLineF, QPoint, Qt
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.panels.async_bridge import drain_bridge_workers, drain_bridge_workers_for
from intellicrack.ui.panels.hex_editor_widget import EntropyMiniMap, HexEditorWidget, HighlightRule
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_WAIT_MS: int = 20_000
_ROW: int = 16
_BIG_LEN: int = 1595
_BIG: bytes = bytes(i % 251 for i in range(_BIG_LEN))
_LAST: int = _BIG_LEN - 1
_WIDTH: int = 800
_HEIGHT: int = 400
_MINIMAP_WIDTH: int = 32
_MINIMAP_HEIGHT: int = 100
_ENTROPY_MIN_BLOCK: int = 256
_HEX8_STRIDE: int = 4
_HEX32_STRIDE: int = 10
_HEX32_DIGITS: int = 8

_ENTROPY_DOC: bytes = bytes(256) + bytes(range(256)) + bytes(range(32)) * 8 + b"AB" * 128
_ENTROPY_VALUES: list[float] = [0.0, 8.0, 5.0, 1.0]

_CLASS_DOC: bytes = bytes(256) + b"ABCD" * 64 + b"\x01" * 256 + bytes(range(256)) + bytes(range(0x80, 0xC0)) * 4
_CLASS_CODES: list[int] = [0, 1, 2, 3, 4]
_CLASS_COLOR_KEYS: list[str] = ["content_null", "content_text", "content_generic", "content_compressed", "content_code"]

_MODIFIED_MARKS: set[int] = {2, 5, 9}
_Dynamic = Any


class _Rig(NamedTuple):
    """A hex editor widget together with the real document it displays.

    Attributes:
        widget: Shown widget with the document attached.
        document: Hexcore document attached to the widget.
    """

    widget: HexEditorWidget
    document: intellicrack_hexcore.HexDocument


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _rgb(color: QColor) -> tuple[int, int, int]:
    """Reduce a color to its red, green and blue components.

    Args:
        color: Color to reduce.

    Returns:
        tuple[int, int, int]: Red, green and blue components.
    """
    return (color.red(), color.green(), color.blue())


def _px(image: QImage, x: int, y: int) -> tuple[int, int, int]:
    """Read one pixel of an image as red, green and blue components.

    Args:
        image: Image to read.
        x: Pixel column.
        y: Pixel row.

    Returns:
        tuple[int, int, int]: Red, green and blue components of the pixel.
    """
    return _rgb(image.pixelColor(x, y))


def _blend(source: QColor, alpha: int, backdrop: QColor) -> tuple[float, float, float]:
    """Compute the source-over blend of a translucent color onto an opaque backdrop.

    Args:
        source: Color painted on top.
        alpha: Opacity of the painted color, 0 to 255.
        backdrop: Opaque color underneath.

    Returns:
        tuple[float, float, float]: Blended red, green and blue components.
    """
    return (
        (source.red() * alpha + backdrop.red() * (255 - alpha)) / 255,
        (source.green() * alpha + backdrop.green() * (255 - alpha)) / 255,
        (source.blue() * alpha + backdrop.blue() * (255 - alpha)) / 255,
    )


def _render(widget: HexEditorWidget) -> QImage:
    """Render the widget's viewport into an image through its real paint handler.

    Args:
        widget: Widget to render.

    Returns:
        QImage: The rendered viewport.
    """
    viewport = widget.viewport()
    assert viewport is not None
    image = QImage(viewport.width(), viewport.height(), QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    try:
        viewport.render(painter)
    finally:
        painter.end()
    return image


def _strip_differs(first: QImage, second: QImage, y: int, x_start: int, x_end: int) -> bool:
    """Report whether two images differ anywhere along one pixel row segment.

    Args:
        first: First image.
        second: Second image.
        y: Pixel row to compare.
        x_start: First pixel column of the segment.
        x_end: Pixel column after the segment.

    Returns:
        bool: True when at least one pixel in the segment differs.
    """
    return any(first.pixel(x, y) != second.pixel(x, y) for x in range(x_start, x_end))


def _region_inked(image: QImage, background: QColor, x_start: int, x_end: int, y_start: int, y_end: int) -> bool:
    """Report whether any pixel of a region differs from the background color.

    Args:
        image: Image to scan.
        background: Background color of the region.
        x_start: First pixel column of the region.
        x_end: Pixel column after the region.
        y_start: First pixel row of the region.
        y_end: Pixel row after the region.

    Returns:
        bool: True when at least one pixel has a different color from the background.
    """
    expected = _rgb(background)
    return any(_px(image, x, y) != expected for y in range(y_start, y_end) for x in range(x_start, x_end))


def _viewport_rows(widget: HexEditorWidget) -> int:
    """Count the rows that fit into the widget's viewport.

    Args:
        widget: Widget to measure.

    Returns:
        int: Whole rows that fit into the viewport height.
    """
    viewport = widget.viewport()
    assert viewport is not None
    line_height: int = _priv(widget, "_line_height")
    return viewport.height() // line_height


def _color_at(widget: HexEditorWidget, offset: int) -> tuple[int, int, int]:
    """Resolve the color-mode background of a byte as red, green and blue components.

    Args:
        widget: Widget whose color mode is active.
        offset: Byte offset to resolve.

    Returns:
        tuple[int, int, int]: Red, green and blue components of the background.
    """
    color = _priv(widget, "_color_mode_background")(offset, 0)
    assert isinstance(color, QColor)
    return _rgb(color)


def _wait_until(qtbot: QtBot, predicate: Callable[[], bool]) -> None:
    """Spin the event loop until a condition holds.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        predicate: Condition to wait for.
    """
    qtbot.waitUntil(predicate, timeout=_WAIT_MS)


def _press(
    qtbot: QtBot,
    widget: QWidget,
    key: Qt.Key | str,
    modifier: Qt.KeyboardModifier = Qt.KeyboardModifier.NoModifier,
) -> None:
    """Deliver one real key press and release to a widget.

    Args:
        qtbot: pytest-qt fixture that sends the event.
        widget: Widget that receives the key.
        key: Key to press, or a single character.
        modifier: Modifiers held while the key is pressed.
    """
    _priv(qtbot, "keyClick")(widget, key, modifier)


def _type(qtbot: QtBot, widget: QWidget, text: str) -> None:
    """Deliver a sequence of real character key events to a widget.

    Args:
        qtbot: pytest-qt fixture that sends the events.
        widget: Widget that receives the characters.
        text: Characters to type.
    """
    _priv(qtbot, "keyClicks")(widget, text)


def _click(qtbot: QtBot, widget: QWidget, y: int) -> None:
    """Deliver a real left mouse click at a point five pixels from the left edge of a widget.

    Args:
        qtbot: pytest-qt fixture that sends the event.
        widget: Widget that receives the click.
        y: Vertical click position in widget coordinates.
    """
    _priv(qtbot, "mouseClick")(widget, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(5, y))


@pytest.fixture
def rig_factory(qtbot: QtBot) -> Generator[Callable[[bytes], _Rig]]:
    """Provide a factory of shown hex editor widgets whose background workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns every widget the factory builds.

    Yields:
        Callable[[bytes], _Rig]: Factory that opens a document over given bytes and shows a widget on it.
    """
    created: list[HexEditorWidget] = []

    def _make(data: bytes) -> _Rig:
        """Build a shown widget over a document holding the given bytes.

        Args:
            data: Content of the document.

        Returns:
            _Rig: The widget and its document.
        """
        document = intellicrack_hexcore.HexDocument.open_bytes(data)
        widget = HexEditorWidget()
        qtbot.addWidget(widget)
        widget.resize(_WIDTH, _HEIGHT)
        widget.set_document(document)
        widget.show()
        qtbot.waitExposed(widget)
        widget.clearFocus()
        QApplication.processEvents()
        created.append(widget)
        return _Rig(widget, document)

    try:
        yield _make
    finally:
        for widget in created:
            drain_bridge_workers_for(widget)
        drain_bridge_workers()


@pytest.fixture
def rig(rig_factory: Callable[[bytes], _Rig]) -> _Rig:
    """Build a shown widget over the shared 1595-byte sample document.

    Args:
        rig_factory: Factory of shown widgets.

    Returns:
        _Rig: Widget and document over ``_BIG``.
    """
    return rig_factory(_BIG)


@pytest.fixture
def bare(qtbot: QtBot) -> Generator[HexEditorWidget]:
    """Provide a shown hex editor widget that has no document attached.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        HexEditorWidget: Widget without a document.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.resize(_WIDTH, _HEIGHT)
    widget.show()
    qtbot.waitExposed(widget)
    widget.clearFocus()
    QApplication.processEvents()
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)
        drain_bridge_workers()


@pytest.fixture
def minimap(qtbot: QtBot) -> EntropyMiniMap:
    """Provide a shown entropy minimap of known size.

    Args:
        qtbot: pytest-qt fixture that owns the minimap.

    Returns:
        EntropyMiniMap: Minimap 32 pixels wide and 100 pixels tall.
    """
    widget = EntropyMiniMap()
    qtbot.addWidget(widget)
    widget.resize(_MINIMAP_WIDTH, _MINIMAP_HEIGHT)
    widget.show()
    qtbot.waitExposed(widget)
    assert widget.height() == _MINIMAP_HEIGHT
    return widget


def test_minimap_without_viewport_paints_bars_and_no_indicator(minimap: EntropyMiniMap) -> None:
    """With an empty viewport range the minimap shows only the entropy bars.

    Args:
        minimap: Shown minimap.
    """
    colors: dict[str, QColor] = _priv(minimap, "_colors")
    minimap.set_entropy_data([0.0, 8.0], _MINIMAP_HEIGHT)
    image = minimap.grab().toImage()
    low = _rgb(colors["entropy_low"])
    high = _rgb(colors["entropy_high"])
    assert _px(image, 10, 0) == low
    assert _px(image, 10, 10) == low
    assert _px(image, 10, 90) == high


def test_minimap_draws_indicator_over_the_visible_region(minimap: EntropyMiniMap) -> None:
    """A non-empty viewport range tints that part of the strip and outlines it.

    Args:
        minimap: Shown minimap.
    """
    colors: dict[str, QColor] = _priv(minimap, "_colors")
    indicator = colors["minimap_indicator"]
    minimap.set_entropy_data([0.0, 8.0], _MINIMAP_HEIGHT)
    minimap.set_viewport(0, 50)
    image = minimap.grab().toImage()
    assert _px(image, 10, 25) == pytest.approx(_blend(indicator, indicator.alpha(), colors["entropy_low"]), abs=2)
    assert _px(image, 10, 75) == _rgb(colors["entropy_high"])
    assert _px(image, 0, 25) == _rgb(colors["minimap_indicator_border"])


@pytest.mark.parametrize(
    ("click_y", "expected_offset"),
    [(50, 500), (0, 0), (99, 990), (150, 999), (-20, 0)],
    ids=["middle", "top", "bottom-edge", "below-clamped-to-last", "above-clamped-to-zero"],
)
def test_minimap_click_requests_proportional_offset(
    qtbot: QtBot,
    minimap: EntropyMiniMap,
    click_y: int,
    expected_offset: int,
) -> None:
    """Clicking at a fraction of the strip height requests the same fraction of the file, clamped to the file.

    Args:
        qtbot: pytest-qt fixture used to deliver the click.
        minimap: Shown minimap, 100 pixels tall, describing a 1000-byte file.
        click_y: Vertical position of the click in widget coordinates.
        expected_offset: Offset the click must request.
    """
    requested = SignalRecorder()
    minimap.navigation_requested.connect(requested)
    minimap.set_entropy_data([1.0, 2.0], 1000)
    _click(qtbot, minimap, click_y)
    assert requested.calls == [(expected_offset,)]


def test_minimap_click_without_data_requests_nothing(qtbot: QtBot, minimap: EntropyMiniMap) -> None:
    """A minimap that describes no file ignores clicks.

    Args:
        qtbot: pytest-qt fixture used to deliver the click.
        minimap: Shown minimap holding no entropy data.
    """
    requested = SignalRecorder()
    minimap.navigation_requested.connect(requested)
    _click(qtbot, minimap, 50)
    assert requested.times_called == 0


def test_minimap_press_without_event_requests_nothing(minimap: EntropyMiniMap) -> None:
    """A press handler invoked without an event does nothing even when the minimap has data.

    Args:
        minimap: Shown minimap.
    """
    requested = SignalRecorder()
    minimap.navigation_requested.connect(requested)
    minimap.set_entropy_data([1.0], 1000)
    minimap.mousePressEvent(None)
    assert requested.times_called == 0


def test_unknown_display_mode_is_rejected(rig: _Rig) -> None:
    """An unrecognized display mode raises and leaves the current mode in place.

    Args:
        rig: Widget over the sample document.
    """
    with pytest.raises(ValueError, match="Unknown display mode: 'bogus'"):
        rig.widget.set_display_mode("bogus")
    assert _priv(rig.widget, "_display_mode") == "hex8"


def test_entropy_block_size_is_the_minimum_without_a_document(bare: HexEditorWidget) -> None:
    """A widget without a document uses the minimum entropy block size.

    Args:
        bare: Widget without a document.
    """
    assert _priv(bare, "_entropy_block_size")() == _ENTROPY_MIN_BLOCK


def test_scan_requests_do_nothing_without_a_document(bare: HexEditorWidget) -> None:
    """Requesting a scan with no document attached starts nothing.

    Args:
        bare: Widget without a document.
    """
    _priv(bare, "_request_entropy_scan")()
    _priv(bare, "_request_content_class_scan")()
    assert _priv(bare, "_entropy_scan_active") is False
    assert _priv(bare, "_content_class_scan_active") is False
    assert _priv(bare, "_color_mode_background")(0, 0) is None
    bare.set_color_mode("entropy")
    assert _priv(bare, "_color_mode_background")(0, 0) is None
    bare.set_color_mode("content_type")
    assert _priv(bare, "_color_mode_background")(0, 0) is None


def test_scan_requests_do_nothing_for_documents_without_scan_support(bare: HexEditorWidget) -> None:
    """A document that cannot compute entropy or classify content starts no background scan.

    Args:
        bare: Widget to attach a plain byte buffer to.
    """
    bare.set_document(bytearray(b"abcdef"))
    _priv(bare, "_request_entropy_scan")()
    _priv(bare, "_request_content_class_scan")()
    assert _priv(bare, "_entropy_scan_active") is False
    assert _priv(bare, "_content_class_scan_active") is False
    assert _priv(bare, "_entropy_block_size")() == _ENTROPY_MIN_BLOCK
    bare.set_color_mode("entropy")
    assert _priv(bare, "_color_mode_background")(0, 0) is None
    bare.set_color_mode("content_type")
    assert _priv(bare, "_color_mode_background")(0, 0) is None


@pytest.mark.parametrize(
    "document",
    [bytearray(b"abc"), QLineF(0.0, 0.0, 3.0, 4.0)],
    ids=["no-length-method", "non-integer-length"],
)
def test_document_without_integer_length_reports_zero(bare: HexEditorWidget, document: object) -> None:
    """A document with no usable integer length counts as empty.

    Args:
        bare: Widget to attach the document to.
        document: Real object that either has no ``length`` method or whose ``length`` returns a float.
    """
    bare.set_document(document)
    assert _priv(bare, "_doc_length")() == 0


def test_refreshing_the_minimap_without_a_document_clears_it(bare: HexEditorWidget) -> None:
    """Refreshing the minimap with no document resets its data.

    Args:
        bare: Widget without a document.
    """
    minimap: EntropyMiniMap = _priv(bare, "_minimap")
    minimap.set_entropy_data([1.0, 2.0], 5)
    _priv(bare, "_refresh_minimap_entropy")()
    assert _priv(minimap, "_entropy_values") == []
    assert _priv(minimap, "_total_size") == 0


def test_attaching_a_document_to_a_visible_minimap_refreshes_and_repositions_it(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
) -> None:
    """Attaching a new document while the minimap is shown pushes its entropy and re-seats the strip.

    Args:
        qtbot: pytest-qt fixture used to wait for the background scan.
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(_BIG).widget
    widget.show_minimap(visible=True)
    minimap: EntropyMiniMap = _priv(widget, "_minimap")
    assert minimap.isVisible()
    _wait_until(qtbot, lambda: bool(_priv(minimap, "_entropy_values")))
    minimap.setGeometry(0, 0, _MINIMAP_WIDTH, 10)

    widget.set_document(intellicrack_hexcore.HexDocument.open_bytes(_ENTROPY_DOC[:768]))

    assert _priv(minimap, "_total_size") == 768
    viewport = widget.viewport()
    assert viewport is not None
    assert minimap.x() == viewport.geometry().right() + 1
    assert minimap.y() == viewport.geometry().top()
    assert minimap.width() == _MINIMAP_WIDTH
    assert minimap.height() == viewport.geometry().height()
    _wait_until(qtbot, lambda: _priv(minimap, "_entropy_values") == _priv(widget, "_entropy_cache") != [])
    assert _priv(minimap, "_entropy_values") == pytest.approx([0.0, 8.0, 5.0])


def test_entropy_color_mode_colors_blocks_after_the_background_scan(qtbot: QtBot, rig_factory: Callable[[bytes], _Rig]) -> None:
    """Entropy mode paints each 256-byte block with the ramp color of its measured entropy.

    The four blocks hold zeros (0 bits), all 256 byte values (8 bits), 32 distinct values (5 bits) and two alternating values (1 bit).

    Args:
        qtbot: pytest-qt fixture used to wait for the background scan.
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(_ENTROPY_DOC).widget
    colors: dict[str, QColor] = _priv(widget, "_colors")
    low, mid, high = colors["entropy_low"], colors["entropy_mid"], colors["entropy_high"]
    widget.set_color_mode("entropy")

    assert _priv(widget, "_color_mode_background")(0, 0) is None
    assert _priv(widget, "_entropy_scan_active") is True
    _priv(widget, "_request_entropy_scan")()
    assert _priv(widget, "_entropy_scan_active") is True

    _wait_until(qtbot, lambda: bool(_priv(widget, "_entropy_cache")))
    assert _priv(widget, "_entropy_cache") == pytest.approx(_ENTROPY_VALUES)
    assert _color_at(widget, 10) == _rgb(low)
    assert _color_at(widget, 300) == _rgb(high)
    halfway = (
        int(low.red() + 0.5 * (mid.red() - low.red())),
        int(low.green() + 0.5 * (mid.green() - low.green())),
        int(low.blue() + 0.5 * (mid.blue() - low.blue())),
    )
    assert _color_at(widget, 600) == halfway
    assert _color_at(widget, 900) == _rgb(low)
    assert _priv(widget, "_color_mode_background")(len(_ENTROPY_DOC) + 5000, 0) is None

    image = _render(widget)
    hex_x: int = _priv(widget, "_hex_col_x")
    line_height: int = _priv(widget, "_line_height")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    assert _px(image, hex_x - 1, line_height) == _rgb(low)
    assert _px(image, ascii_x - 1, line_height) == _rgb(low)


def test_stale_entropy_scan_is_discarded_and_rerun(qtbot: QtBot, rig_factory: Callable[[bytes], _Rig]) -> None:
    """A scan that finishes after an edit invalidated the caches is thrown away and started again.

    Args:
        qtbot: pytest-qt fixture used to wait for the background scans.
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(bytes(512)).widget
    _priv(widget, "_request_entropy_scan")()
    generation: int = _priv(widget, "_entropy_scan_generation")
    _priv(widget, "_invalidate_color_caches")()
    assert _priv(widget, "_entropy_scan_generation") == generation + 1

    _wait_until(qtbot, lambda: bool(_priv(widget, "_entropy_cache")) and not _priv(widget, "_entropy_scan_active"))
    assert _priv(widget, "_entropy_scan_request_generation") == generation + 1
    assert _priv(widget, "_entropy_cache") == pytest.approx([0.0, 0.0])


def test_content_type_color_mode_colors_blocks_by_classification(qtbot: QtBot, rig_factory: Callable[[bytes], _Rig]) -> None:
    """Content-type mode paints each 256-byte block with the tint of its class.

    The five blocks are null padding, repeated text, control bytes, all 256 byte values and 64 high bytes, which classify as null, text,
    generic, compressed and code.

    Args:
        qtbot: pytest-qt fixture used to wait for the background scan.
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(_CLASS_DOC).widget
    colors: dict[str, QColor] = _priv(widget, "_colors")
    widget.set_color_mode("content_type")

    assert _priv(widget, "_color_mode_background")(0, 0) is None
    assert _priv(widget, "_content_class_scan_active") is True
    _priv(widget, "_request_content_class_scan")()
    assert _priv(widget, "_content_class_scan_active") is True

    _wait_until(qtbot, lambda: bool(_priv(widget, "_content_class_cache")))
    assert _priv(widget, "_content_class_cache") == _CLASS_CODES
    for block, key in enumerate(_CLASS_COLOR_KEYS):
        assert _color_at(widget, block * 256 + 7) == _rgb(colors[key])
    assert _priv(widget, "_color_mode_background")(len(_CLASS_DOC) + 5000, 0) is None

    _set_priv(widget, "_content_class_cache", [9])
    assert _priv(widget, "_color_mode_background")(0, 0) is None

    _set_priv(widget, "_content_class_cache", _CLASS_CODES)
    image = _render(widget)
    hex_x: int = _priv(widget, "_hex_col_x")
    line_height: int = _priv(widget, "_line_height")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    assert _px(image, hex_x - 1, line_height) == _rgb(colors["content_null"])
    assert _px(image, ascii_x - 1, line_height) == _rgb(colors["content_null"])


def test_stale_content_scan_is_discarded_and_rerun(qtbot: QtBot, rig_factory: Callable[[bytes], _Rig]) -> None:
    """A classification that finishes after an edit invalidated the caches is thrown away and started again.

    Args:
        qtbot: pytest-qt fixture used to wait for the background scans.
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(bytes(512)).widget
    _priv(widget, "_request_content_class_scan")()
    generation: int = _priv(widget, "_content_class_scan_generation")
    _priv(widget, "_invalidate_color_caches")()
    assert _priv(widget, "_content_class_scan_generation") == generation + 1

    _wait_until(qtbot, lambda: bool(_priv(widget, "_content_class_cache")) and not _priv(widget, "_content_class_scan_active"))
    assert _priv(widget, "_content_class_scan_request_generation") == generation + 1
    assert _priv(widget, "_content_class_cache") == [0, 0]


@pytest.mark.parametrize(
    ("request_name", "finished_name", "active_name", "cache_name"),
    [
        ("_request_entropy_scan", "_on_entropy_scan_finished", "_entropy_scan_active", "_entropy_cache"),
        ("_request_content_class_scan", "_on_content_class_scan_finished", "_content_class_scan_active", "_content_class_cache"),
    ],
    ids=["entropy", "content-class"],
)
@pytest.mark.parametrize("bad_result", [None, ["not-a-number"]], ids=["not-iterable", "not-numeric"])
def test_unusable_scan_result_leaves_an_empty_cache(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    request_name: str,
    finished_name: str,
    active_name: str,
    cache_name: str,
    bad_result: object,
) -> None:
    """A scan result that cannot be read as numbers empties the cache instead of raising.

    Args:
        qtbot: pytest-qt fixture used to wait for the first, genuine scan.
        rig_factory: Factory of shown widgets.
        request_name: Name of the method that starts the scan.
        finished_name: Name of the completion handler.
        active_name: Name of the in-flight flag.
        cache_name: Name of the cache attribute.
        bad_result: Result handed to the completion handler.
    """
    widget = rig_factory(bytes(512)).widget
    _priv(widget, request_name)()
    _wait_until(qtbot, lambda: bool(_priv(widget, cache_name)) and not _priv(widget, active_name))

    _priv(widget, finished_name)(bad_result)

    assert _priv(widget, cache_name) == []
    assert _priv(widget, active_name) is False


@pytest.mark.parametrize(
    ("failed_name", "active_name", "cache_name"),
    [
        ("_on_entropy_scan_failed", "_entropy_scan_active", "_entropy_cache"),
        ("_on_content_class_scan_failed", "_content_class_scan_active", "_content_class_cache"),
    ],
    ids=["entropy", "content-class"],
)
def test_failed_scan_resets_the_scan_state(
    bare: HexEditorWidget,
    failed_name: str,
    active_name: str,
    cache_name: str,
) -> None:
    """A failed background scan clears the in-flight flag and the cache.

    Args:
        bare: Widget to put into the mid-scan state.
        failed_name: Name of the failure handler.
        active_name: Name of the in-flight flag.
        cache_name: Name of the cache attribute.
    """
    _set_priv(bare, active_name, value=True)
    _set_priv(bare, cache_name, [1])

    _priv(bare, failed_name)(RuntimeError("scan failed"))

    assert _priv(bare, active_name) is False
    assert _priv(bare, cache_name) == []


def test_row_data_reader_without_a_reader_is_empty() -> None:
    """A row cannot be read when the document offers no reader."""
    reader = _priv(HexEditorWidget, "_read_row_data")
    assert reader(None, 0, 4) == b""


def test_row_data_reader_ignores_results_that_are_not_bytes_or_lists() -> None:
    """A reader that returns neither bytes nor a list yields an empty row."""
    reader = _priv(HexEditorWidget, "_read_row_data")
    assert reader(divmod, 7, 2) == b""


@pytest.mark.parametrize(
    ("mode", "group", "size", "expected"),
    [
        ("hexii", b"A", 1, "A"),
        ("hexii", b"\x01", 1, "01"),
        ("hexii", b"\x7f", 1, "7F"),
        ("hexii", b"", 1, "00"),
        ("binary", b"\xa5", 1, "10100101"),
        ("binary", b"", 1, "00000000"),
        ("dec_u8", b"\x05", 1, "5".rjust(3)),
        ("dec_u8", b"\xff", 1, "255"),
        ("dec_s8", b"\xff", 1, "-1".rjust(4)),
        ("dec_s8", b"\x7f", 1, "127".rjust(4)),
        ("dec_s8", b"\x80", 1, "-128"),
        ("hex16_le", b"\x34\x12", 2, "1234"),
        ("hex16_le", b"\x34", 2, "0034"),
        ("hex16_be", b"\x34\x12", 2, "3412"),
        ("hex16_be", b"\x34", 2, "3400"),
        ("hex32_le", b"\x78\x56\x34\x12", 4, "12345678"),
        ("hex32_be", b"\x78\x56\x34\x12", 4, "78563412"),
        ("rgba8", b"\x11\x22\x33\x44", 4, "44332211"),
        ("hex64_le", bytes(range(1, 9)), 8, "0807060504030201"),
        ("hex64_be", bytes(range(1, 9)), 8, "0102030405060708"),
        ("dec_u16", b"\x00\x01", 2, "256".rjust(5)),
        ("dec_u32", b"\x00\x00\x01\x00", 4, "65536".rjust(10)),
        ("dec_s16", b"\xff\xff", 2, "-1".rjust(6)),
        ("dec_s32", b"\xff\xff\xff\xff", 4, "-1".rjust(11)),
        ("not-a-mode", b"\xab", 1, "AB"),
        ("not-a-mode", b"", 1, ".."),
    ],
)
def test_group_formatting_per_display_mode(bare: HexEditorWidget, mode: str, group: bytes, size: int, expected: str) -> None:
    """Each display mode renders a byte group the way its width and byte order dictate.

    Args:
        bare: Widget whose display mode is switched.
        mode: Display mode name, or a name the widget does not know.
        group: Bytes of the group.
        size: Group size the mode pads to.
        expected: Text written out by hand from the mode's definition.
    """
    _set_priv(bare, "_display_mode", mode)
    assert _priv(bare, "_format_group")(group, size) == expected


@pytest.mark.parametrize(
    ("mode", "width"),
    [("float32", 10), ("float64", 22)],
)
def test_float_group_shorter_than_its_type_renders_a_question_mark(bare: HexEditorWidget, mode: str, width: int) -> None:
    """A float group too short to unpack shows a right-aligned question mark.

    Args:
        bare: Widget whose display mode is switched.
        mode: Float display mode.
        width: Width of the placeholder text.
    """
    _set_priv(bare, "_display_mode", mode)
    assert _priv(bare, "_format_group")(b"\x00", 2) == "?".rjust(width)


@pytest.mark.parametrize(
    ("group_offset", "size", "sel_start", "sel_end"),
    [(16, 4, 18, 30), (16, 4, 19, 19), (16, 4, 10, 16)],
    ids=["overlaps-tail", "single-byte-inside", "touches-first-byte"],
)
def test_group_touching_the_selection_counts_as_selected(group_offset: int, size: int, sel_start: int, sel_end: int) -> None:
    """A group is selected when any of its bytes lies inside the inclusive selection range.

    Args:
        group_offset: Offset of the group's first byte.
        size: Number of bytes in the group.
        sel_start: First selected offset.
        sel_end: Last selected offset.
    """
    assert _priv(HexEditorWidget, "_is_group_selected")(group_offset, size, sel_start, sel_end) is True


@pytest.mark.parametrize(
    ("group_offset", "size", "sel_start", "sel_end"),
    [(16, 2, 18, 30), (16, 4, 20, 30), (16, 4, -1, -1)],
    ids=["ends-before-selection", "starts-after-group", "no-selection"],
)
def test_group_clear_of_the_selection_is_not_selected(group_offset: int, size: int, sel_start: int, sel_end: int) -> None:
    """A group none of whose bytes lies inside the selection, or any group without a selection, is not selected.

    Args:
        group_offset: Offset of the group's first byte.
        size: Number of bytes in the group.
        sel_start: First selected offset, or -1 for no selection.
        sel_end: Last selected offset, or -1 for no selection.
    """
    assert _priv(HexEditorWidget, "_is_group_selected")(group_offset, size, sel_start, sel_end) is False


def test_group_highlight_returns_the_first_matching_rule_color_unless_selected(bare: HexEditorWidget) -> None:
    """A group takes the color of the first byte a rule matches, and none at all while it is selected.

    Args:
        bare: Widget that receives the rule.
    """
    bare.add_highlight_rule(HighlightRule("letter-a", "byte_value", {"value": 0x41}, "#FF0000", 1))
    finder = _priv(bare, "_find_group_highlight")
    assert finder(b"xAz", 3, 0, any_selected=False) == "#FF0000"
    assert finder(b"xyz", 3, 0, any_selected=False) is None
    assert finder(b"xAz", 3, 0, any_selected=True) is None


def test_highlight_rules_resolve_by_priority_and_condition(bare: HexEditorWidget) -> None:
    """The highest-priority matching rule wins, whichever condition type it uses, and unknown conditions never match.

    Args:
        bare: Widget that receives the rules.
    """
    bare.add_highlight_rule(HighlightRule("value", "byte_value", {"value": 0x41}, "#111111", 1))
    bare.add_highlight_rule(HighlightRule("range", "byte_range", {"min": 0x50, "max": 0x5A}, "#222222", 5))
    bare.add_highlight_rule(HighlightRule("offsets", "pattern", {"offsets": {3}}, "#333333", 3))
    bare.add_highlight_rule(HighlightRule("other", "no_such_condition", {}, "#444444", 0))
    lookup = _priv(bare, "_get_highlight_color")
    assert lookup(0x41, 99) == "#111111"
    assert lookup(0x55, 3) == "#222222"
    assert lookup(0x41, 3) == "#333333"
    assert lookup(0x30, 3) == "#333333"
    assert lookup(0x30, 99) is None


def test_removing_an_unknown_highlight_rule_changes_nothing(bare: HexEditorWidget) -> None:
    """Removing a rule id that does not exist reports False and keeps every rule.

    Args:
        bare: Widget that receives the rules.
    """
    bare.add_highlight_rule(HighlightRule("keep", "byte_value", {"value": 1}, "#111111", 1))
    assert bare.remove_highlight_rule("missing") is False
    assert [rule.rule_id for rule in bare.get_highlight_rules()] == ["keep"]
    assert bare.remove_highlight_rule("keep") is True
    assert bare.get_highlight_rules() == []


@pytest.mark.parametrize(
    ("encoding", "data", "expected"),
    [
        ("utf-16le", b"A\x00B\x00C\x00D\x00", ["A", ".", "B", ".", "C", ".", "D", "."]),
        ("utf-16le", b"A\x00\x01\x00", ["A", ".", ".", "."]),
        ("cp1252", b"Hi\xe9\x01", ["H", "i", "é", "."]),
        ("x-no-such-encoding", b"abcd", [".", ".", ".", "."]),
    ],
    ids=["utf16-glyphs-anchored-at-leading-byte", "utf16-control-glyph-masked", "single-byte-codec", "unknown-codec"],
)
def test_decode_row_chars_uses_the_document_decoder(
    rig_factory: Callable[[bytes], _Rig],
    encoding: str,
    data: bytes,
    expected: list[str],
) -> None:
    """Non-ASCII encodings anchor each glyph at its first byte and mask what is not printable.

    Args:
        rig_factory: Factory of shown widgets.
        encoding: Encoding set on the widget.
        data: Content of the document, which is also the row.
        expected: ASCII-column characters, one per byte.
    """
    widget = rig_factory(data).widget
    widget.encoding = encoding
    assert _priv(widget, "_decode_row_chars")(0, len(data), data) == expected


@pytest.mark.parametrize("document", [None, bytearray(b"A\x00B\x00")], ids=["no-document", "document-without-decoder"])
def test_decode_row_chars_falls_back_to_the_python_codec(bare: HexEditorWidget, document: object) -> None:
    """Without a document decoder the row is decoded with the Python codec of the same name.

    Args:
        bare: Widget whose encoding is switched.
        document: Absent document, or a plain byte buffer that has no ``decode_text`` method.
    """
    if document is not None:
        bare.set_document(document)
    bare.encoding = "utf-16-le"
    assert _priv(bare, "_decode_row_chars")(0, 4, b"A\x00B\x00") == ["A", ".", "B", "."]


def test_alignment_grid_stops_after_the_last_row_of_the_document(rig_factory: Callable[[bytes], _Rig]) -> None:
    """Grid lines are drawn for rows up to the end of the data and not for the empty rows below it.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(bytes(range(1, 33))).widget
    plain = _render(widget)
    widget.set_alignment_grid_size(_ROW)
    gridded = _render(widget)
    line_height: int = _priv(widget, "_line_height")
    x_start: int = _priv(widget, "_offset_col_x")
    x_end = x_start + _priv(widget, "_offset_col_width")
    for row in range(3):
        assert _strip_differs(plain, gridded, row * line_height, x_start, x_end)
    assert not _strip_differs(plain, gridded, 3 * line_height, x_start, x_end)


def test_short_last_row_stops_painting_groups_at_the_end_of_the_data(rig_factory: Callable[[bytes], _Rig]) -> None:
    """In a wide display mode the groups past the last byte of the final row are left blank.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(bytes(range(1, 19))).widget
    widget.set_display_mode("hex32_le")
    image = _render(widget)
    colors: dict[str, QColor] = _priv(widget, "_colors")
    background = colors["editor_bg"]
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    hex_x: int = _priv(widget, "_hex_col_x")
    hex_end = hex_x + _priv(widget, "_hex_col_width")
    second_group = hex_x + _HEX32_STRIDE * char_width

    assert _region_inked(image, background, second_group, hex_end, 0, line_height)
    assert _region_inked(image, background, hex_x, hex_x + _HEX32_DIGITS * char_width, line_height, 2 * line_height)
    assert not _region_inked(image, background, second_group, hex_end, line_height, 2 * line_height)


def test_rgba_mode_paints_each_group_with_its_own_color(rig_factory: Callable[[bytes], _Rig]) -> None:
    """RGBA mode fills each group cell with the color its bytes describe, including a three-byte tail group.

    Args:
        rig_factory: Factory of shown widgets.
    """
    data = bytes([0x10, 0x20, 0x30, 0xFF, 0x40, 0x50, 0x60, 0xFF, 0x70, 0x80, 0x90, 0xFF, 0xA0, 0xB0, 0xC0, 0xFF, 0x11, 0x22, 0x33])
    widget = rig_factory(data).widget
    widget.set_display_mode("rgba8")
    image = _render(widget)
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    hex_x: int = _priv(widget, "_hex_col_x")

    assert _px(image, hex_x + 6 * char_width, 0) == (0x10, 0x20, 0x30)
    assert _px(image, hex_x + _HEX32_STRIDE * char_width - 1, 0) == (0x40, 0x50, 0x60)
    assert _px(image, hex_x - 1, line_height) == (0x11, 0x22, 0x33)


def test_group_background_with_no_bytes_paints_nothing(bare: HexEditorWidget) -> None:
    """A group that holds no bytes receives no background fill.

    Args:
        bare: Widget whose group painter is invoked directly.
    """
    colors: dict[str, QColor] = _priv(bare, "_colors")
    image = QImage(120, 40, QImage.Format.Format_ARGB32)
    image.fill(colors["editor_bg"])
    reference = image.copy()
    painter = QPainter(image)
    try:
        _priv(bare, "_paint_hex_group_background")(painter, image.rect(), b"", 0, None, 0, any_selected=False)
    finally:
        painter.end()
    assert image == reference


def test_highlight_rule_tints_the_hex_and_ascii_cells_of_matching_bytes(rig_factory: Callable[[bytes], _Rig]) -> None:
    """A matching rule fills both the hex cell and the ASCII cell, and neighbouring cells stay untouched.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(b"ABCDEFGHIJKLMNOP" * 2).widget
    widget.add_highlight_rule(HighlightRule("letter-a", "byte_value", {"value": 0x41}, "#FF0000", 1))
    image = _render(widget)
    colors: dict[str, QColor] = _priv(widget, "_colors")
    background = colors["editor_bg"]
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    hex_x: int = _priv(widget, "_hex_col_x")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    tint = _blend(QColor("#FF0000"), 120, background)

    assert _px(image, hex_x - 1, line_height) == pytest.approx(tint, abs=2)
    assert _px(image, ascii_x - 1, line_height) == pytest.approx(tint, abs=2)
    assert _px(image, hex_x + _HEX8_STRIDE * char_width - 1, line_height) == _rgb(background)
    assert _px(image, ascii_x + char_width, line_height) == _rgb(background)


def test_selection_fills_the_hex_and_ascii_cells_of_selected_bytes(rig_factory: Callable[[bytes], _Rig]) -> None:
    """Selected bytes get the selection color in both columns, and a rule color is suppressed there.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(b"A" * 32).widget
    widget.add_highlight_rule(HighlightRule("letter-a", "byte_value", {"value": 0x41}, "#FF0000", 1))
    widget.set_selection_range(17, 18)
    image = _render(widget)
    colors: dict[str, QColor] = _priv(widget, "_colors")
    background = colors["editor_bg"]
    selection = colors["selection_bg"]
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    hex_x: int = _priv(widget, "_hex_col_x")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    selected = _blend(selection, selection.alpha(), background)
    tinted = _blend(QColor("#FF0000"), 120, background)

    assert _px(image, hex_x + _HEX8_STRIDE * char_width - 1, line_height) == pytest.approx(selected, abs=2)
    assert _px(image, ascii_x + char_width + 1, line_height) == pytest.approx(selected, abs=2)
    assert _px(image, hex_x - 1, line_height) == pytest.approx(tinted, abs=2)
    assert _px(image, ascii_x - 1, line_height) == pytest.approx(tinted, abs=2)


def test_hex_group_pen_follows_selection_and_modification_state(bare: HexEditorWidget) -> None:
    """The text color of a hex group depends on whether it is selected, modified, all zero, or ordinary.

    Args:
        bare: Widget whose pen setter is invoked directly.
    """
    colors: dict[str, QColor] = _priv(bare, "_colors")
    image = QImage(10, 10, QImage.Format.Format_ARGB32)
    painter = QPainter(image)
    try:
        setter = _priv(bare, "_set_hex_group_pen")
        setter(painter, b"AB", 2, any_selected=True, any_modified=True)
        assert _rgb(painter.pen().color()) == _rgb(colors["cursor_text"])
        setter(painter, b"AB", 2, any_selected=False, any_modified=True)
        assert _rgb(painter.pen().color()) == _rgb(colors["hex_modified"])
        setter(painter, b"\x00\x00", 2, any_selected=False, any_modified=False)
        assert _rgb(painter.pen().color()) == _rgb(colors["hex_zero"])
        setter(painter, b"AB", 2, any_selected=False, any_modified=False)
        assert _rgb(painter.pen().color()) == _rgb(colors["hex_normal"])
    finally:
        painter.end()


def test_single_byte_painter_draws_one_cell_and_honors_the_selection(rig_factory: Callable[[bytes], _Rig]) -> None:
    """The compatibility single-byte painter draws a two-digit cell and fills it when its byte is selected.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(b"AAAAAAAAAAAAAAAA").widget
    colors: dict[str, QColor] = _priv(widget, "_colors")
    background = colors["editor_bg"]
    selection = colors["selection_bg"]
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    ascent: int = _priv(widget, "_font_ascent")
    hex_x: int = _priv(widget, "_hex_col_x")
    image = QImage(_WIDTH, line_height * 2, QImage.Format.Format_ARGB32)
    image.fill(background)
    painter = QPainter(image)
    try:
        painter.setFont(widget.font())
        _priv(widget, "_paint_hex_byte")(painter, 0, ascent, 0, 0x41, 0, -1, -1)
    finally:
        painter.end()

    assert _region_inked(image, background, hex_x, hex_x + 2 * char_width + 1, 0, line_height)
    assert not _region_inked(image, background, hex_x + 3 * char_width, _WIDTH, 0, line_height)

    image.fill(background)
    painter = QPainter(image)
    try:
        painter.setFont(widget.font())
        _priv(widget, "_paint_hex_byte")(painter, 0, ascent, 0, 0x41, 0, 0, 0)
    finally:
        painter.end()
    assert _px(image, hex_x + 2 * char_width, 0) == pytest.approx(_blend(selection, selection.alpha(), background), abs=2)


def test_highlight_overlays_cover_visible_rows_only(rig_factory: Callable[[bytes], _Rig]) -> None:
    """A bookmark highlight tints its hex cells, and highlights above or below the viewport change nothing.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(_BIG).widget
    colors: dict[str, QColor] = _priv(widget, "_colors")
    background = colors["editor_bg"]
    char_width: int = _priv(widget, "_char_width")
    line_height: int = _priv(widget, "_line_height")
    hex_x: int = _priv(widget, "_hex_col_x")
    green = QColor("#00FF00")
    tint = _blend(green, 60, background)

    widget.highlight_offsets([(_ROW, 2, "#00FF00")])
    image = _render(widget)
    assert _px(image, hex_x - 1, line_height) == pytest.approx(tint, abs=2)
    assert _px(image, hex_x + _HEX8_STRIDE * char_width - 1, line_height) == pytest.approx(tint, abs=2)
    assert _px(image, hex_x + 2 * _HEX8_STRIDE * char_width - 1, line_height) == _rgb(background)

    widget.highlight_offsets([(_ROW, 2, "#00FF00"), (1500, 4, "#00FF00")])
    assert _render(widget) == image

    scrollbar = widget.verticalScrollBar()
    assert scrollbar is not None
    scrollbar.setValue(5)
    scrolled = _render(widget)
    widget.clear_highlights("default")
    assert _render(widget) == scrolled


def test_ascii_caret_is_outlined_only_while_the_ascii_column_has_focus(qtbot: QtBot, rig: _Rig) -> None:
    """The cursor outline appears in the ASCII column once Tab activates it and the widget has focus.

    Args:
        qtbot: pytest-qt fixture used to deliver keys and wait for focus.
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.setFocus(Qt.FocusReason.OtherFocusReason)
    _wait_until(qtbot, widget.hasFocus)
    colors: dict[str, QColor] = _priv(widget, "_colors")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    line_height: int = _priv(widget, "_line_height")
    probe = (ascii_x - 1, line_height // 2)

    assert _px(_render(widget), *probe) == _rgb(colors["editor_bg"])
    _press(qtbot, widget, Qt.Key.Key_Tab)
    assert _priv(widget, "_active_column") == "ascii"
    assert _px(_render(widget), *probe) == _rgb(colors["cursor_text"])


def test_keys_do_nothing_without_a_document(qtbot: QtBot, bare: HexEditorWidget) -> None:
    """Navigation and editing keys are ignored when no document is attached, as is a missing key event.

    Args:
        qtbot: pytest-qt fixture used to deliver keys.
        bare: Widget without a document.
    """
    cursor = SignalRecorder()
    bare.cursor_moved.connect(cursor)
    _press(qtbot, bare, Qt.Key.Key_Right)
    _press(qtbot, bare, Qt.Key.Key_Z, Qt.KeyboardModifier.ControlModifier)
    _press(qtbot, bare, "4")
    bare.keyPressEvent(None)
    assert cursor.times_called == 0
    assert _priv(bare, "_cursor_offset") == 0


@pytest.mark.parametrize(
    ("start", "key", "expected"),
    [
        (50, Qt.Key.Key_Left, 49),
        (50, Qt.Key.Key_Right, 51),
        (50, Qt.Key.Key_Up, 34),
        (50, Qt.Key.Key_Down, 66),
    ],
    ids=["left", "right", "up", "down"],
)
def test_arrow_keys_move_the_cursor_and_clear_the_selection(rig: _Rig, qtbot: QtBot, start: int, key: Qt.Key, expected: int) -> None:
    """Arrow keys move by one byte or one 16-byte row and drop any selection.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        start: Cursor offset before the key.
        key: Arrow key to press.
        expected: Cursor offset after the key.
    """
    widget = rig.widget
    widget.goto_offset(start)
    widget.set_selection_range(1, 3)
    cursor = SignalRecorder()
    widget.cursor_moved.connect(cursor)
    _press(qtbot, widget, key)
    assert cursor.calls == [(expected,)]
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_selection_end") == -1


@pytest.mark.parametrize(
    ("start", "key", "modifier", "expected"),
    [
        (37, Qt.Key.Key_Home, Qt.KeyboardModifier.NoModifier, 32),
        (37, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier, 0),
        (37, Qt.Key.Key_End, Qt.KeyboardModifier.NoModifier, 47),
        (1590, Qt.Key.Key_End, Qt.KeyboardModifier.NoModifier, _LAST),
        (37, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier, _LAST),
    ],
    ids=["home", "ctrl-home", "end", "end-of-short-last-row", "ctrl-end"],
)
def test_home_and_end_keys(rig: _Rig, qtbot: QtBot, start: int, key: Qt.Key, modifier: Qt.KeyboardModifier, expected: int) -> None:
    """Home and End jump to the row or document boundaries, stopping at the last byte of a short final row.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        start: Cursor offset before the key.
        key: Home or End.
        modifier: Modifier held with the key.
        expected: Cursor offset after the key.
    """
    widget = rig.widget
    widget.goto_offset(start)
    cursor = SignalRecorder()
    widget.cursor_moved.connect(cursor)
    _press(qtbot, widget, key, modifier)
    assert cursor.calls == [(expected,)]


@pytest.mark.parametrize(
    ("start", "key", "modifier", "expected"),
    [
        (10, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier, (10, 11)),
        (10, Qt.Key.Key_Left, Qt.KeyboardModifier.ShiftModifier, (9, 10)),
        (10, Qt.Key.Key_Down, Qt.KeyboardModifier.ShiftModifier, (10, 26)),
        (40, Qt.Key.Key_Up, Qt.KeyboardModifier.ShiftModifier, (24, 40)),
        (37, Qt.Key.Key_Home, Qt.KeyboardModifier.ShiftModifier, (32, 37)),
        (37, Qt.Key.Key_End, Qt.KeyboardModifier.ShiftModifier, (37, 47)),
        (37, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier, (0, 37)),
        (37, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier, (37, _LAST)),
    ],
    ids=["right", "left", "down", "up", "home", "end", "ctrl-home", "ctrl-end"],
)
def test_shift_navigation_extends_the_selection(
    rig: _Rig,
    qtbot: QtBot,
    start: int,
    key: Qt.Key,
    modifier: Qt.KeyboardModifier,
    expected: tuple[int, int],
) -> None:
    """Navigation keys held with Shift select from the starting offset to the new cursor, reported lowest offset first.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        start: Cursor offset before the key.
        key: Navigation key.
        modifier: Modifiers held with the key.
        expected: Selection range reported by ``selection_changed``.
    """
    widget = rig.widget
    widget.goto_offset(start)
    selection = SignalRecorder()
    widget.selection_changed.connect(selection)
    _press(qtbot, widget, key, modifier)
    assert selection.calls == [expected]


def test_repeated_shift_arrow_keeps_the_selection_anchor(rig: _Rig, qtbot: QtBot) -> None:
    """Pressing Shift+Right twice grows the selection from the same anchor.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    widget.goto_offset(10)
    selection = SignalRecorder()
    widget.selection_changed.connect(selection)
    _press(qtbot, widget, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
    _press(qtbot, widget, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
    assert selection.calls == [(10, 11), (10, 12)]


@pytest.mark.parametrize(
    ("start", "key", "direction"),
    [(0, Qt.Key.Key_PageDown, 1), (800, Qt.Key.Key_PageUp, -1)],
    ids=["page-down", "page-up"],
)
def test_page_keys_move_by_one_viewport_of_rows(rig: _Rig, qtbot: QtBot, start: int, key: Qt.Key, direction: int) -> None:
    """Page Up and Page Down move the cursor by the number of visible rows times 16 bytes.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        start: Cursor offset before the key.
        key: Page Up or Page Down.
        direction: 1 for a forward move, -1 for a backward move.
    """
    widget = rig.widget
    widget.goto_offset(start)
    cursor = SignalRecorder()
    widget.cursor_moved.connect(cursor)
    _press(qtbot, widget, key)
    assert cursor.calls == [(start + direction * _viewport_rows(widget) * _ROW,)]


def test_ctrl_a_selects_the_whole_document(rig: _Rig, qtbot: QtBot) -> None:
    """Ctrl+A selects from the first to the last byte and reports that range.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
    """
    widget = rig.widget
    selection = SignalRecorder()
    widget.selection_changed.connect(selection)
    _press(qtbot, widget, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
    assert selection.calls == [(0, _LAST)]
    assert _priv(widget, "_selection_start") == 0
    assert _priv(widget, "_selection_end") == _LAST


def test_ctrl_c_copies_the_selection_as_hex(rig: _Rig, qtbot: QtBot) -> None:
    """Ctrl+C puts the selected bytes on the clipboard as space-separated hex.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
    """
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    clipboard.clear()
    rig.widget.set_selection_range(2, 4)
    _press(qtbot, rig.widget, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert clipboard.text() == "02 03 04"


def test_ctrl_c_without_a_selection_copies_the_byte_at_the_cursor(rig: _Rig, qtbot: QtBot) -> None:
    """With no selection Ctrl+C copies the byte under the cursor.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
    """
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    clipboard.clear()
    rig.widget.goto_offset(10)
    _press(qtbot, rig.widget, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert clipboard.text() == "0A"


def test_copy_with_nothing_to_copy_leaves_the_clipboard_alone(rig: _Rig) -> None:
    """When the cursor lies past the data and nothing is selected, copying does not touch the clipboard.

    Args:
        rig: Widget over the sample document.
    """
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    clipboard.setText("sentinel")
    _set_priv(rig.widget, "_cursor_offset", _BIG_LEN + 100)
    _priv(rig.widget, "_do_copy")()
    assert clipboard.text() == "sentinel"


def test_undo_and_redo_keys_restore_the_bytes_and_their_modified_marks(rig: _Rig, qtbot: QtBot) -> None:
    """Ctrl+Z reverts a typed byte and its modified mark, and Ctrl+Y applies both again.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    _type(qtbot, widget, "41")
    assert rig.document.read(0, 2) == bytes([0x41, 1])
    assert _priv(widget, "_modified_offsets") == {0}

    changed = SignalRecorder()
    widget.data_changed.connect(changed)
    _press(qtbot, widget, Qt.Key.Key_Z, Qt.KeyboardModifier.ControlModifier)
    assert rig.document.read(0, 2) == bytes([0, 1])
    assert _priv(widget, "_modified_offsets") == set()
    _press(qtbot, widget, Qt.Key.Key_Y, Qt.KeyboardModifier.ControlModifier)
    assert rig.document.read(0, 2) == bytes([0x41, 1])
    assert _priv(widget, "_modified_offsets") == {0}
    assert changed.times_called == 2


def test_undo_and_redo_keys_with_empty_history_change_nothing(rig: _Rig, qtbot: QtBot) -> None:
    """Ctrl+Z and Ctrl+Y on a document with no edit history leave it alone and announce no change.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    with qtbot.assertNotEmitted(rig.widget.data_changed):
        _press(qtbot, rig.widget, Qt.Key.Key_Z, Qt.KeyboardModifier.ControlModifier)
        _press(qtbot, rig.widget, Qt.Key.Key_Y, Qt.KeyboardModifier.ControlModifier)
    assert rig.document.read(0, _BIG_LEN) == _BIG


def test_undo_and_redo_of_unmarked_edits_clear_the_modified_marks(rig: _Rig, qtbot: QtBot) -> None:
    """Undoing or redoing an edit the widget never recorded cannot restore marks, so it clears them.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    rig.document.write_bytes(0, b"\x99")
    _set_priv(widget, "_modified_offsets", {0})
    _press(qtbot, widget, Qt.Key.Key_Z, Qt.KeyboardModifier.ControlModifier)
    assert rig.document.read(0, 1) == bytes([0])
    assert _priv(widget, "_modified_offsets") == set()

    _set_priv(widget, "_modified_offsets", {5})
    _press(qtbot, widget, Qt.Key.Key_Y, Qt.KeyboardModifier.ControlModifier)
    assert rig.document.read(0, 1) == b"\x99"
    assert _priv(widget, "_modified_offsets") == set()


def test_tab_switches_between_the_hex_and_ascii_columns(rig: _Rig, qtbot: QtBot) -> None:
    """Tab toggles the active column and abandons a half-typed byte.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    _press(qtbot, widget, "4")
    assert _priv(widget, "_nibble_index") == 1
    _press(qtbot, widget, Qt.Key.Key_Tab)
    assert _priv(widget, "_active_column") == "ascii"
    assert _priv(widget, "_nibble_index") == 0
    _press(qtbot, widget, Qt.Key.Key_Tab)
    assert _priv(widget, "_active_column") == "hex"


def test_insert_key_toggles_the_edit_mode(rig: _Rig, qtbot: QtBot) -> None:
    """Insert alternates between overwrite and insert mode and announces each mode.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    modes = SignalRecorder()
    rig.widget.edit_mode_changed.connect(modes)
    _press(qtbot, rig.widget, Qt.Key.Key_Insert)
    _press(qtbot, rig.widget, Qt.Key.Key_Insert)
    assert modes.calls == [("insert",), ("overwrite",)]


def test_delete_key_removes_the_byte_at_the_cursor(rig: _Rig, qtbot: QtBot) -> None:
    """Delete removes the byte under the cursor and leaves the cursor in place.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
    """
    widget = rig.widget
    widget.goto_offset(5)
    modify = SignalRecorder()
    changed = SignalRecorder()
    widget.about_to_modify.connect(modify)
    widget.data_changed.connect(changed)
    _press(qtbot, widget, Qt.Key.Key_Delete)
    assert rig.document.length() == _BIG_LEN - 1
    assert rig.document.read(0, 8) == bytes([0, 1, 2, 3, 4, 6, 7, 8])
    assert _priv(widget, "_cursor_offset") == 5
    assert modify.calls == [(5,)]
    assert changed.times_called == 1


@pytest.mark.parametrize(
    ("start", "removed", "cursor", "head"),
    [(5, 4, 4, [0, 1, 2, 3, 5, 6, 7, 8]), (0, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8])],
    ids=["previous-byte", "at-start-removes-first-byte"],
)
def test_backspace_key_removes_the_previous_byte(
    rig: _Rig,
    qtbot: QtBot,
    start: int,
    removed: int,
    cursor: int,
    head: list[int],
) -> None:
    """Backspace removes the byte before the cursor and moves onto its position, or the first byte at offset 0.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        start: Cursor offset before the key.
        removed: Offset of the byte that disappears.
        cursor: Cursor offset after the key.
        head: First eight bytes of the document afterwards.
    """
    widget = rig.widget
    widget.goto_offset(start)
    modify = SignalRecorder()
    widget.about_to_modify.connect(modify)
    _press(qtbot, widget, Qt.Key.Key_Backspace)
    assert rig.document.length() == _BIG_LEN - 1
    assert rig.document.read(0, 8) == bytes(head)
    assert _priv(widget, "_cursor_offset") == cursor
    assert modify.calls == [(removed,)]


def test_delete_key_removes_the_selection_and_remaps_marks(rig: _Rig, qtbot: QtBot) -> None:
    """Deleting a selection announces every byte, closes the gap, and moves or drops the modified marks.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
    """
    widget = rig.widget
    _set_priv(widget, "_modified_offsets", set(_MODIFIED_MARKS))
    widget.set_selection_range(4, 6)
    modify = SignalRecorder()
    changed = SignalRecorder()
    widget.about_to_modify.connect(modify)
    widget.data_changed.connect(changed)
    _press(qtbot, widget, Qt.Key.Key_Delete)
    assert modify.calls == [(4,), (5,), (6,)]
    assert rig.document.length() == _BIG_LEN - 3
    assert rig.document.read(0, 8) == bytes([0, 1, 2, 3, 7, 8, 9, 10])
    assert _priv(widget, "_cursor_offset") == 4
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_modified_offsets") == {2, 6}
    assert changed.times_called == 1


@pytest.mark.parametrize("selected", [True, False], ids=["selection", "single-byte"])
def test_failed_delete_leaves_the_document_untouched(rig: _Rig, qtbot: QtBot, selected: object) -> None:
    """A delete the document rejects is contained: nothing is removed and no change is announced.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the key.
        selected: Whether the out-of-range target is a selection or the cursor byte.
    """
    widget = rig.widget
    if selected:
        _set_priv(widget, "_selection_start", _BIG_LEN + 10)
        _set_priv(widget, "_selection_end", _BIG_LEN + 13)
    else:
        _set_priv(widget, "_cursor_offset", _BIG_LEN + 10)
    with qtbot.assertNotEmitted(widget.data_changed):
        _press(qtbot, widget, Qt.Key.Key_Delete)
    assert rig.document.length() == _BIG_LEN
    assert rig.document.read(0, _BIG_LEN) == _BIG


def test_hex_digits_overwrite_a_byte_after_two_keys(rig: _Rig, qtbot: QtBot) -> None:
    """Two hex digits typed in the hex column replace the byte under the cursor and advance the cursor.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    modify = SignalRecorder()
    changed = SignalRecorder()
    cursor = SignalRecorder()
    widget.about_to_modify.connect(modify)
    widget.data_changed.connect(changed)
    widget.cursor_moved.connect(cursor)

    _press(qtbot, widget, "d")
    assert _priv(widget, "_nibble_index") == 1
    assert _priv(widget, "_pending_nibble") == 0xD
    assert rig.document.read(0, 1) == bytes([0])
    _press(qtbot, widget, "E")

    assert rig.document.read(0, 2) == bytes([0xDE, 1])
    assert modify.calls == [(0,)]
    assert changed.times_called == 1
    assert cursor.calls[-1] == (1,)
    assert _priv(widget, "_modified_offsets") == {0}
    assert _priv(widget, "_nibble_index") == 0


def test_hex_digits_in_insert_mode_insert_a_byte_and_shift_marks(rig: _Rig, qtbot: QtBot) -> None:
    """In insert mode a typed byte is inserted, pushing later modified marks forward.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    _set_priv(widget, "_modified_offsets", {2, 5})
    _press(qtbot, widget, Qt.Key.Key_Insert)
    widget.goto_offset(2)
    _type(qtbot, widget, "ab")
    assert rig.document.length() == _BIG_LEN + 1
    assert rig.document.read(0, 6) == bytes([0, 1, 0xAB, 2, 3, 4])
    assert _priv(widget, "_modified_offsets") == {2, 3, 6}
    assert _priv(widget, "_cursor_offset") == 3


def test_characters_that_are_not_hex_digits_are_ignored_in_the_hex_column(rig: _Rig, qtbot: QtBot) -> None:
    """A letter outside 0-9 and A-F, Return, and a bare modifier key edit nothing in the hex column.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    with qtbot.assertNotEmitted(widget.data_changed):
        _press(qtbot, widget, "g")
        _press(qtbot, widget, Qt.Key.Key_Return)
        _press(qtbot, widget, Qt.Key.Key_Shift)
    assert _priv(widget, "_nibble_index") == 0
    assert rig.document.read(0, _BIG_LEN) == _BIG


def test_unprintable_text_is_ignored_in_the_ascii_column(rig: _Rig, qtbot: QtBot) -> None:
    """Return produces a carriage-return character, which the ASCII column refuses to write.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    _press(qtbot, rig.widget, Qt.Key.Key_Tab)
    with qtbot.assertNotEmitted(rig.widget.data_changed):
        _press(qtbot, rig.widget, Qt.Key.Key_Return)
    assert rig.document.read(0, _BIG_LEN) == _BIG


def test_ascii_characters_overwrite_bytes_and_mark_them(rig: _Rig, qtbot: QtBot) -> None:
    """Printable characters typed in the ASCII column overwrite consecutive bytes and mark each as modified.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    modify = SignalRecorder()
    changed = SignalRecorder()
    widget.about_to_modify.connect(modify)
    widget.data_changed.connect(changed)
    _press(qtbot, widget, Qt.Key.Key_Tab)
    _type(qtbot, widget, "Hi!")
    assert rig.document.read(0, 4) == b"Hi!" + bytes([3])
    assert modify.calls == [(0,), (1,), (2,)]
    assert changed.times_called == 3
    assert _priv(widget, "_modified_offsets") == {0, 1, 2}
    assert _priv(widget, "_cursor_offset") == 3


def test_ascii_characters_in_insert_mode_insert_bytes_and_shift_marks(rig: _Rig, qtbot: QtBot) -> None:
    """In insert mode each character typed in the ASCII column is inserted and later marks move forward.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    widget = rig.widget
    _set_priv(widget, "_modified_offsets", {3, 8})
    _press(qtbot, widget, Qt.Key.Key_Tab)
    _press(qtbot, widget, Qt.Key.Key_Insert)
    widget.goto_offset(3)
    _type(qtbot, widget, "QZ")
    assert rig.document.length() == _BIG_LEN + 2
    assert rig.document.read(0, 7) == b"\x00\x01\x02QZ\x03\x04"
    assert _priv(widget, "_modified_offsets") == {3, 4, 5, 10}
    assert _priv(widget, "_cursor_offset") == 5


def test_first_insert_without_marks_just_marks_the_new_byte(rig: _Rig, qtbot: QtBot) -> None:
    """An insertion into a document with no modified marks only marks the inserted byte.

    Args:
        rig: Widget over the sample document.
        qtbot: pytest-qt fixture used to deliver the keys.
    """
    _press(qtbot, rig.widget, Qt.Key.Key_Tab)
    _press(qtbot, rig.widget, Qt.Key.Key_Insert)
    _press(qtbot, rig.widget, "Q")
    assert rig.document.read(0, 2) == b"Q\x00"
    assert _priv(rig.widget, "_modified_offsets") == {0}


def test_mark_shifts_ignore_empty_edits(bare: HexEditorWidget) -> None:
    """Shifting marks for an edit of zero bytes, or with no marks present, changes nothing.

    Args:
        bare: Widget whose mark helpers are invoked directly.
    """
    _set_priv(bare, "_modified_offsets", {3})
    _priv(bare, "_shift_modified_offsets_for_insert")(1, 0)
    _priv(bare, "_shift_modified_offsets_for_delete")(1, 0)
    assert _priv(bare, "_modified_offsets") == {3}
    _set_priv(bare, "_modified_offsets", set[int]())
    _priv(bare, "_shift_modified_offsets_for_insert")(1, 2)
    _priv(bare, "_shift_modified_offsets_for_delete")(1, 2)
    assert _priv(bare, "_modified_offsets") == set()


@pytest.mark.parametrize("mode", ["overwrite", "insert"])
def test_rejected_typed_edits_leave_the_document_untouched(rig: _Rig, mode: str) -> None:
    """Typing at an offset the document rejects is contained in both columns and both edit modes.

    Args:
        rig: Widget over the sample document.
        mode: Edit mode to type in.
    """
    widget = rig.widget
    _set_priv(widget, "_edit_mode", mode)
    _set_priv(widget, "_cursor_offset", _BIG_LEN + 500)
    _priv(widget, "_handle_ascii_input")("A")
    _set_priv(widget, "_cursor_offset", _BIG_LEN + 500)
    _priv(widget, "_handle_hex_input")("4")
    _priv(widget, "_handle_hex_input")("1")
    assert rig.document.length() == _BIG_LEN
    assert rig.document.read(0, _BIG_LEN) == _BIG
    assert _priv(widget, "_modified_offsets") == set()


@pytest.mark.parametrize("mode", ["overwrite", "insert"])
def test_typed_edits_are_skipped_for_documents_without_write_support(bare: HexEditorWidget, mode: str) -> None:
    """A document that cannot write or insert bytes is left as it was, while the edit is still announced.

    Args:
        bare: Widget to attach a plain byte buffer to.
        mode: Edit mode to type in.
    """
    buffer = bytearray(b"abcdef")
    bare.set_document(buffer)
    _set_priv(bare, "_edit_mode", mode)
    changed = SignalRecorder()
    bare.data_changed.connect(changed)
    _priv(bare, "_handle_ascii_input")("Z")
    _priv(bare, "_handle_hex_input")("4")
    _priv(bare, "_handle_hex_input")("1")
    assert buffer == bytearray(b"abcdef")
    assert _priv(bare, "_modified_offsets") == set()
    assert changed.times_called == 2


def test_edit_operations_do_nothing_without_a_capable_document(bare: HexEditorWidget) -> None:
    """Deleting, undoing and redoing are no-ops without a document, or with one that lacks the operation.

    Args:
        bare: Widget to attach a plain byte buffer to.
    """
    changed = SignalRecorder()
    bare.data_changed.connect(changed)
    _priv(bare, "_do_delete")(backspace=False)
    _priv(bare, "_do_undo")()
    _priv(bare, "_do_redo")()
    _priv(bare, "_handle_ascii_input")("Z")
    _priv(bare, "_handle_hex_input")("4")
    assert changed.times_called == 0

    buffer = bytearray(b"abcdef")
    bare.set_document(buffer)
    _priv(bare, "_do_delete")(backspace=True)
    _priv(bare, "_do_undo")()
    _priv(bare, "_do_redo")()
    assert buffer == bytearray(b"abcdef")
    assert changed.times_called == 0
