# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for defect A7 (S14-D19 residual): the System Function Call result row.

``SystemFunctionCallControls.__init__`` builds its "Value / errno / GetLastError"
result row (``frida_instrumentation_tab.py``, ``result_row``) from three
caption+value ``QLabel`` pairs added directly to a ``QHBoxLayout`` with only a
single trailing ``addStretch()``. ``make_control_row`` (``base_panel.py``)
wraps that row in a fixed-width, horizontally-scrollable ``QScrollArea`` by
snapshotting the row's ``sizeHint()`` once, at construction time -- while the
three value labels are still empty. Once a real system-function call
populates those labels with the call's actual value/errno/GetLastError text,
the row's true content needs far more width than the frozen snapshot
reserved, so later layout passes compress the value labels below their
``sizeHint`` -- clipping the text outright (no ellipsis), with the default
~6px inter-widget spacing left unchanged, so the clipped value runs directly
into the next caption with no visible separation.

The fix reserves a sensible minimum width on each of the three dynamic value
labels (sized from a representative worst-case sample via
``QFontMetrics.horizontalAdvance``, the same reservation strategy
``make_control_row`` itself relies on for the row1/row2 controls that never
exhibited this bug) so the frozen snapshot already accounts for real content,
adds explicit spacing between the three caption+value groups so a future
narrowing degrades to a scrollbar rather than to zero visual separation, and
right-elides (with a full-text tooltip) any value that still exceeds its
reserved width, mirroring the existing ``_set_elided_detail`` idiom already
used in ``session_manager.py``.

These tests build the real ``SystemFunctionCallControls`` widget, resize it
to a narrow docked-style width, populate the three value labels through the
real ``_on_call_system_function_done`` handler with realistic result text,
force layout activation, and assert on the labels' real rendered geometry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QLabel, QScrollArea

from intellicrack.ui.panels.frida_instrumentation_tab import SystemFunctionCallControls


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QWidget

pytestmark = pytest.mark.usefixtures("qapp")

_NARROW_WIDTH: Final[int] = 340
_NARROW_HEIGHT: Final[int] = 200

_MIN_READABLE_GAP_PX: Final[int] = 10
"""Minimum acceptable horizontal gap between a value label and the next caption.

Set above the ~6px default ``QHBoxLayout`` inter-widget spacing so the check
is falsifiable against the pre-fix row, which never adds spacing beyond that
Qt default regardless of content or width.
"""


class _RealSystemCallResult:
    """A minimal, real (non-mock) stand-in for the bridge's ``SystemCallResult``.

    ``_on_call_system_function_done`` only reads ``value``/``errno``/``last_error``
    via ``getattr``, so a plain attribute-bearing object exercises the real
    handler code path without depending on ``frida-python`` being installed.
    """

    def __init__(self, value: int, errno: int, last_error: int) -> None:
        """Initialize the result stand-in with realistic call-result fields.

        Args:
            value: The system function's raw return value.
            errno: The captured C library ``errno``.
            last_error: The captured Win32 ``GetLastError()`` code.
        """
        self.value = value
        self.errno = errno
        self.last_error = last_error


def _enclosing_scroll_area(widget: QWidget) -> QScrollArea | None:
    """Return the nearest ancestor ``QScrollArea`` of ``widget``, if any.

    Args:
        widget: The widget whose ancestry is walked.

    Returns:
        QScrollArea | None: The closest enclosing scroll area, or ``None``.
    """
    node = widget.parentWidget()
    while node is not None:
        if isinstance(node, QScrollArea):
            return node
        node = node.parentWidget()
    return None


def _rect_in(widget: QWidget, reference: QWidget) -> tuple[int, int, int, int]:
    """Return ``widget``'s geometry as ``(left, top, right, bottom)`` mapped into ``reference``'s coordinate space.

    Args:
        widget: Widget whose rendered geometry to read.
        reference: Common ancestor widget to map the geometry into.

    Returns:
        tuple[int, int, int, int]: ``(left, top, right, bottom)`` in ``reference``'s coordinates.
    """
    top_left = widget.mapTo(reference, widget.rect().topLeft())
    size = widget.size()
    return (top_left.x(), top_left.y(), top_left.x() + size.width(), top_left.y() + size.height())


def _rects_intersect(rect_a: tuple[int, int, int, int], rect_b: tuple[int, int, int, int]) -> bool:
    """Return whether two ``(left, top, right, bottom)`` rectangles overlap.

    Args:
        rect_a: First rectangle.
        rect_b: Second rectangle.

    Returns:
        bool: True if the rectangles' interiors intersect.
    """
    overlap_x = rect_a[0] < rect_b[2] and rect_b[0] < rect_a[2]
    overlap_y = rect_a[1] < rect_b[3] and rect_b[1] < rect_a[3]
    return overlap_x and overlap_y


def _result_row_widgets(controls: SystemFunctionCallControls) -> list[QLabel]:
    """Return the result row's six caption/value ``QLabel`` widgets, in layout order.

    Args:
        controls: The ``SystemFunctionCallControls`` widget to inspect.

    Returns:
        list[QLabel]: The row's labels in the order they were added to its ``QHBoxLayout``:
        "Value:", the value label, "errno:", the errno label, "GetLastError:", the last-error label.
    """
    scroll = _enclosing_scroll_area(controls._syscall_value_label)
    assert scroll is not None, "the result row must be hosted in a scroll area (make_control_row)"
    inner = scroll.widget()
    assert inner is not None
    row_layout = inner.layout()
    assert row_layout is not None
    labels: list[QLabel] = []
    for i in range(row_layout.count()):
        item = row_layout.itemAt(i)
        widget = item.widget() if item is not None else None
        if isinstance(widget, QLabel):
            labels.append(widget)
    return labels


def _build_narrow_populated_controls(qapp: QApplication) -> SystemFunctionCallControls:
    """Build a real ``SystemFunctionCallControls`` widget, narrowed and populated with a realistic result.

    Args:
        qapp: Session QApplication fixture, used to pump the event loop so
            deferred layout requests are actually processed.

    Returns:
        SystemFunctionCallControls: The realized, laid-out widget.
    """
    controls = SystemFunctionCallControls()
    controls.resize(_NARROW_WIDTH, _NARROW_HEIGHT)
    controls.show()
    qapp.processEvents()
    qapp.processEvents()

    result = _RealSystemCallResult(value=0xFFFFFFFFFFFFFFFF, errno=2, last_error=1314)
    controls._on_call_system_function_done(result)

    for _ in range(4):
        qapp.processEvents()

    return controls


class TestSystemFunctionCallResultRowLayout:
    """A7 / S14-D19 gate: populated result-row labels must stay readable and separated when docked narrow."""

    @staticmethod
    def test_populated_value_labels_do_not_intersect(qapp: QApplication) -> None:
        """The three result value labels' rendered geometries must never intersect.

        A plain ``QHBoxLayout`` never overlaps sibling widgets by
        construction, so this is a cheap structural invariant -- it exists to
        catch any future refactor (e.g. a switch to absolute positioning)
        that would break that guarantee.

        Args:
            qapp: Session QApplication fixture.
        """
        controls = _build_narrow_populated_controls(qapp)
        try:
            scroll = _enclosing_scroll_area(controls._syscall_value_label)
            assert scroll is not None, "the result row must be hosted in a scroll area (make_control_row)"

            labels: list[QLabel] = [
                controls._syscall_value_label,
                controls._syscall_errno_label,
                controls._syscall_last_error_label,
            ]
            rects = [_rect_in(label, scroll) for label in labels]
            for i in range(len(rects)):
                for j in range(i + 1, len(rects)):
                    assert not _rects_intersect(rects[i], rects[j]), (
                        f"{labels[i].text()!r} at {rects[i]} intersects {labels[j].text()!r} at {rects[j]}"
                    )
        finally:
            controls.close()
            qapp.processEvents()

    @staticmethod
    def test_populated_value_labels_keep_their_natural_width(qapp: QApplication) -> None:
        """A populated result value label must not render narrower than its own text needs.

        Regression test for A7: before the fix, ``make_control_row`` froze
        the result row's minimum width from the *empty* value labels at
        construction time, so once real call-result text landed, later
        layout passes compressed the value labels below their ``sizeHint``,
        clipping the text outright with no ellipsis. Falsifiable: reverting
        the reserved-width fix reproduces exactly that compression.

        Args:
            qapp: Session QApplication fixture.
        """
        controls = _build_narrow_populated_controls(qapp)
        try:
            for label in (
                controls._syscall_value_label,
                controls._syscall_errno_label,
                controls._syscall_last_error_label,
            ):
                required = label.sizeHint().width()
                assert label.width() >= required, (
                    f"{label.objectName() or label.text()!r} rendered {label.width()}px wide, "
                    f"narrower than its {required}px natural size -- text is being clipped"
                )
        finally:
            controls.close()
            qapp.processEvents()

    @staticmethod
    def test_populated_result_groups_keep_a_readable_gap(qapp: QApplication) -> None:
        """Each value label must keep a real visual gap before the next caption, not just the bare layout default.

        Regression test for A7: before the fix, the three caption+value
        groups in ``result_row`` had no spacing beyond the ~6px default
        ``QHBoxLayout`` inter-widget gap, so a compressed value label's
        clipped text ran directly into the next caption with no visible
        separation. Falsifiable: reverting the explicit ``addSpacing()``
        calls between groups leaves every value-label-to-next-caption gap at
        the bare ~6px default, below ``_MIN_READABLE_GAP_PX``.

        Args:
            qapp: Session QApplication fixture.
        """
        controls = _build_narrow_populated_controls(qapp)
        try:
            scroll = _enclosing_scroll_area(controls._syscall_value_label)
            assert scroll is not None

            row_labels = _result_row_widgets(controls)
            assert len(row_labels) == 6, f"expected 6 labels (3 caption/value pairs) in the result row, got {len(row_labels)}"

            # Layout order: "Value:", value, "errno:", errno, "GetLastError:", last_error.
            # The gaps that matter are value->"errno:" and errno->"GetLastError:".
            value_to_errno_caption = (row_labels[1], row_labels[2])
            errno_to_last_error_caption = (row_labels[3], row_labels[4])
            for left_label, right_label in (value_to_errno_caption, errno_to_last_error_caption):
                left_rect = _rect_in(left_label, scroll)
                right_rect = _rect_in(right_label, scroll)
                gap = right_rect[0] - left_rect[2]
                assert gap >= _MIN_READABLE_GAP_PX, (
                    f"gap between {left_label.text()!r} and {right_label.text()!r} is only {gap}px, "
                    f"below the {_MIN_READABLE_GAP_PX}px readability floor -- the groups visually run together"
                )
        finally:
            controls.close()
            qapp.processEvents()
