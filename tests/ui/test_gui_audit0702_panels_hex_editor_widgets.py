# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding M55 in ``hex_editor.widgets``.

``M55`` — ``CustomCrcDialog._result_label`` is a plain ``QLabel`` that is
repeatedly set to unbounded, variable-length text (parse-error messages,
worker exceptions, streaming I/O errors). Pre-fix the label had no
``setWordWrap(True)`` and no tooltip, so a long message either forced the
360px-minimum dialog to grow wide or was clipped, with no way to recover the
full text. The fix enables word wrap on the label and mirrors every text
update into the label's tooltip so the complete message is always
accessible regardless of the dialog's rendered width.

All tests drive a real :class:`CustomCrcDialog` under an offscreen
``QApplication`` (no mocks); each asserts the concrete Qt layout mechanism
(``wordWrap`` / ``heightForWidth``) or the real tooltip content produced by
the dialog's own error/result handlers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.ui.panels.hex_editor.widgets import CustomCrcDialog


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def _make_dialog() -> CustomCrcDialog:
    """Build a real, unparented ``CustomCrcDialog`` for label-behaviour tests.

    ``file_path``/``document`` are never touched by the paths under test
    (input-validation and result/error rendering happen before the worker
    would read either), so ``None``/``0`` stand-ins are sufficient to
    exercise the real dialog without spawning a background worker thread.

    Returns:
        CustomCrcDialog: A constructed, unparented dialog instance.
    """
    return CustomCrcDialog(
        file_path=None,
        document=None,
        length=0,
        parent=None,
        worker_parent=None,
    )


def test_m55_result_label_has_word_wrap_enabled(qapp: QApplication) -> None:
    """The result label must have word wrap enabled at construction time.

    Pre-fix, ``QLabel`` defaults to ``wordWrap() is False`` and
    ``hasHeightForWidth() is False`` since ``setWordWrap`` was never called
    anywhere in the file. The fix calls ``setWordWrap(True)`` in
    ``CustomCrcDialog.__init__``, which flips both properties.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        label = dialog._result_label
        assert label.wordWrap() is True, "result label does not have word wrap enabled"
        assert label.hasHeightForWidth() is True, "label does not participate in height-for-width layout; word wrap is not really active"
    finally:
        dialog.deleteLater()


def test_m55_long_error_text_wraps_within_bounded_width(qapp: QApplication) -> None:
    """A long message must wrap into multiple lines instead of a single wide line.

    Exercises the real Qt layout mechanism enabled by the fix: with word
    wrap on, ``heightForWidth`` for a width narrower than the unwrapped text
    reports several line-heights; pre-fix (``wordWrap`` unset) a ``QLabel``
    is not height-for-width aware and the dialog could only grow wider or
    clip the text.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        label = dialog._result_label
        long_message = "Error: " + "x" * 400
        label.setText(long_message)

        bounded_width = 360
        single_line_height = label.fontMetrics().height()
        wrapped_height = label.heightForWidth(bounded_width)

        assert wrapped_height > single_line_height * 2, (
            f"label did not wrap {len(long_message)} chars of text within "
            f"{bounded_width}px (wrapped_height={wrapped_height}, "
            f"single_line_height={single_line_height})"
        )
    finally:
        dialog.deleteLater()


def test_m55_invalid_input_mirrors_full_message_into_tooltip(qapp: QApplication) -> None:
    """A parse error from user input must set the full message as the tooltip too.

    Drives the real ``_calculate`` -> ``_read_crc_inputs`` failure path with
    a non-hex polynomial, matching the ``int(..., 16)`` ``ValueError`` this
    finding calls out. Pre-fix, ``_result_label.setToolTip`` was never
    called anywhere in the file, so the tooltip stayed at Qt's default
    empty string no matter what error text was shown.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        dialog._poly_edit.setText("not-a-hex-value")
        dialog._calculate()

        label = dialog._result_label
        assert label.text().startswith("Error: "), "invalid input did not set an error message"
        assert label.toolTip() == label.text(), (
            "tooltip does not mirror the displayed error text; full message is not recoverable when clipped"
        )
        assert "not-a-hex-value" in label.toolTip(), "tooltip lost the specific parse-error detail"
    finally:
        dialog.deleteLater()


def test_m55_worker_error_mirrors_message_into_tooltip(qapp: QApplication) -> None:
    """A worker-thread exception must set the full message as the tooltip too.

    Calls the real ``_on_worker_error`` handler with a long, path-bearing
    ``OSError`` (representative of the streaming CRC read failures this
    finding describes). Pre-fix the label text carried the message but the
    tooltip was never populated.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        long_path = "D:\\" + "\\".join(["very_long_directory_name_segment"] * 8) + "\\target.bin"
        error = OSError(f"could not read '{long_path}': permission denied")

        dialog._on_worker_error(error)

        label = dialog._result_label
        expected = f"Error: {error}"
        assert label.text() == expected
        assert label.toolTip() == expected, "worker error text was not mirrored into the tooltip"
        assert dialog.worker() is None, "worker handle was not cleared after the error callback"
    finally:
        dialog.deleteLater()


def test_m55_non_integer_result_mirrors_message_into_tooltip(qapp: QApplication) -> None:
    """A malformed worker result must set the fixed error text as the tooltip too.

    Calls the real ``_on_worker_finished`` handler with a non-``int``
    payload, exercising the ``isinstance`` guard's fixed error string.
    Pre-fix that string reached ``setText`` only; the tooltip stayed empty.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        dialog._on_worker_finished("not-an-int")

        label = dialog._result_label
        assert label.text() == "Error: worker returned non-integer result"
        assert label.toolTip() == label.text(), "non-integer-result error text was not mirrored into the tooltip"
    finally:
        dialog.deleteLater()


def test_m55_successful_result_mirrors_message_into_tooltip(qapp: QApplication) -> None:
    """A successful CRC result must also mirror its text into the tooltip.

    Confirms the fix applies uniformly to the success path, not just error
    paths: ``_on_worker_finished`` with a real integer result must set the
    same tooltip text as label text, and still emit ``crc_computed``.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    dialog = _make_dialog()
    try:
        emitted: list[int] = []
        _ = dialog.crc_computed.connect(emitted.append)

        dialog._width_spin.setValue(32)
        dialog._on_worker_finished(0xDEADBEEF)

        label = dialog._result_label
        assert label.text() == "Result: 0xDEADBEEF"
        assert label.toolTip() == label.text(), "successful result text was not mirrored into the tooltip"
        assert emitted == [0xDEADBEEF], "crc_computed was not emitted with the real result"
    finally:
        dialog.deleteLater()
