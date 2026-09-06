# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for S19 D10: inclusive-selection off-by-one in hex transforms.

``HexEditorWidget._selection_end`` is the *inclusive* index of the last
selected byte (see ``select_range``/Ctrl+A in ``hex_editor_widget.py``, which
sets ``_selection_end = doc_len - 1``), and the hexcore bridge's own
``apply_arithmetic_to_selection`` agrees: it computes
``length = end - start + 1``. Three call sites in
:mod:`intellicrack.ui.panels.hex_editor.transforms` previously treated
``_selection_end`` as *exclusive* instead, silently dropping the last
selected byte from every arithmetic/transform/pipeline operation:

1. Quick Arithmetic (:meth:`TransformsMixin._on_apply_arithmetic`) shifted the
   bridge selection down by one (``bridge_end = sel_end - 1``) before calling
   ``bridge.select_range``.
2. Top Transform Apply (:meth:`TransformsMixin._on_transform_apply`) computed
   ``apply_len = sel_end - sel_start`` (one byte short).
3. Pipeline Execute (:meth:`TransformsMixin._on_pipeline_execute`, via
   :meth:`TransformsMixin._resolve_pipeline_region`) made the same
   ``sel_end - sel_start`` mistake.

Each test below selects exactly ``_SEL_COUNT`` bytes at a known offset in a
*real* ``intellicrack_hexcore.HexDocument``, drives one of the three
production call sites unmodified, and asserts that every byte in the
inclusive selection - including the last one - was transformed, while the
byte immediately following the selection was left untouched. All three tests
apply a bitwise NOT (hexcore's parameterless ``bit_invert`` transform),
which is bit-for-bit identical to XOR with key ``0xFF`` (``!b == b ^ 0xFF``
for an 8-bit value) but needs no key parameter, so the assertions isolate the
selection-range regression from unrelated parameter-encoding differences
between the three call sites.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QComboBox, QLineEdit, QSpinBox

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.transform_pipeline import RustTransformNode, TransformPipeline
from intellicrack.ui.panels.hex_editor.transforms import TransformDescriptor, TransformsMixin


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack_hexcore import HexDocument
    from PyQt6.QtWidgets import QApplication


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


_DOC_LEN: Final[int] = 64
_SEL_OFFSET: Final[int] = 20
_SEL_COUNT: Final[int] = 8
_SEL_END: Final[int] = _SEL_OFFSET + _SEL_COUNT - 1
_XOR_MASK: Final[int] = 0xFF
_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.01


def _make_doc() -> HexDocument:
    """Build a fresh 64-byte in-memory ``HexDocument`` with bytes 0..63.

    Returns:
        HexDocument: New document whose byte at index ``i`` equals ``i``, so
            every selected byte has a known, distinct original value.
    """
    doc: HexDocument = hexcore_mod.HexDocument.open_bytes(bytes(range(_DOC_LEN)))
    return doc


def _assert_inclusive_selection_inverted(doc: HexDocument) -> None:
    """Assert the full inclusive selection was inverted and its neighbor was not.

    Args:
        doc: Document that was subjected to one of the three production
            transform call sites over the ``[_SEL_OFFSET, _SEL_END]``
            inclusive selection.
    """
    transformed = bytes(doc.read(_SEL_OFFSET, _SEL_COUNT))
    expected = bytes((original ^ _XOR_MASK) & 0xFF for original in range(_SEL_OFFSET, _SEL_OFFSET + _SEL_COUNT))
    assert transformed == expected, (
        f"inclusive selection [{_SEL_OFFSET}, {_SEL_END}] must all be inverted "
        f"(including the last byte at offset {_SEL_END}); got {transformed.hex()}, expected {expected.hex()}"
    )
    boundary_offset = _SEL_OFFSET + _SEL_COUNT
    boundary = bytes(doc.read(boundary_offset, 1))
    assert boundary == bytes([boundary_offset]), (
        f"byte at offset {boundary_offset} (just past the selection) must remain unchanged, got {boundary.hex()}"
    )


class _StubHexWidget:
    """Minimal hex-widget stand-in exposing cursor offset and an inclusive selection."""

    def __init__(self, cursor_offset: int, selection_start: int, selection_end: int) -> None:
        """Initialise the stub with a fixed cursor offset and inclusive selection.

        Args:
            cursor_offset: Byte offset reported as the current cursor position.
            selection_start: First selected byte offset.
            selection_end: Last selected byte offset, inclusive.
        """
        self._cursor_offset: int = cursor_offset
        self._selection_start: int = selection_start
        self._selection_end: int = selection_end
        self.update_count: int = 0

    def _update_viewport(self) -> None:
        """Record a viewport refresh request."""
        self.update_count += 1


class _TransformsHarness(TransformsMixin):
    """Concrete, non-``QWidget`` host exposing :class:`TransformsMixin` for a real document.

    Provides exactly the attributes the mixin's handlers read, wired to a
    real ``HexDocument`` so the production hexcore FFI executes end to end.
    Callers populate only the fields relevant to the call site under test;
    everything else defaults to an inert value.
    """

    def __init__(self, document: HexDocument) -> None:
        """Construct the harness wired to a real document.

        Args:
            document: Real ``HexDocument`` used as the panel's document.
        """
        self.document: HexDocument | None = document
        self._document: Any = document
        self._hex_widget: _StubHexWidget | None = None
        self._transform_node_combo: QComboBox | None = None
        self._transform_params_form: Any = None
        self._transform_params_widget: Any = None
        self._transform_preview_pane: Any = None
        self._transform_pipeline_list: Any = None
        self._transform_pipeline: Any = None
        self._transform_nodes_cache: list[TransformDescriptor] = []
        self._bridge: Any = None
        self.state_holder: Any = None
        self._selection_start: int = -1
        self._selection_end: int = -1
        self._arith_op_combo: QComboBox | None = None
        self._arith_key_edit: QLineEdit | None = None
        self._arith_count_spin: QSpinBox | None = None


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], *, timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Args:
        qapp: The shared offscreen ``QApplication``.
        predicate: Zero-argument callable polled after each event-loop pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout,
            ``False`` otherwise.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


@pytest.mark.usefixtures("qapp")
class TestQuickArithmeticInclusiveSelection:
    """D10 path 1: Quick Arithmetic must invert the full inclusive selection."""

    @staticmethod
    def test_not_operation_inverts_last_selected_byte(qapp: QApplication) -> None:
        """``_on_apply_arithmetic`` (NOT) must invert every byte through ``_SEL_END``.

        Pre-fix, ``bridge_end = sel_end - 1`` meant the bridge selection (and
        therefore ``apply_arithmetic_to_selection``'s ``length = end - start +
        1``) covered only ``_SEL_COUNT - 1`` bytes, leaving the byte at
        ``_SEL_END`` unmodified.

        Args:
            qapp: The shared offscreen ``QApplication`` fixture.
        """
        doc = _make_doc()
        bridge = HexEditorBridge()
        bridge.document = doc

        harness = _TransformsHarness(doc)
        harness._bridge = bridge
        harness._hex_widget = _StubHexWidget(_SEL_OFFSET, _SEL_OFFSET, _SEL_END)
        harness._selection_start = _SEL_OFFSET
        harness._selection_end = _SEL_END

        op_combo = QComboBox()
        op_combo.addItem("NOT")
        harness._arith_op_combo = op_combo
        harness._arith_key_edit = QLineEdit("")
        count_spin = QSpinBox()
        count_spin.setRange(1, 64)
        count_spin.setValue(1)
        harness._arith_count_spin = count_spin

        harness._on_apply_arithmetic()

        widget = harness._hex_widget
        assert isinstance(widget, _StubHexWidget)
        completed = _pump_until(qapp, lambda: widget.update_count >= 1)
        assert completed, "the arithmetic bridge chain never completed on the background loop"

        _assert_inclusive_selection_inverted(doc)


@pytest.mark.usefixtures("qapp")
class TestTransformApplyInclusiveSelection:
    """D10 path 2: top Transform Apply must invert the full inclusive selection."""

    @staticmethod
    def test_apply_inverts_last_selected_byte() -> None:
        """``_on_transform_apply`` must write ``_SEL_COUNT`` bytes, not ``_SEL_COUNT - 1``.

        Pre-fix, ``apply_len = sel_end - sel_start`` read and wrote one byte
        short of the actual selection, leaving the byte at ``_SEL_END``
        unmodified. Uses hexcore's parameterless ``bit_invert`` transform so
        no parameter-form plumbing is needed.
        """
        doc = _make_doc()
        harness = _TransformsHarness(doc)
        harness._hex_widget = _StubHexWidget(_SEL_OFFSET, _SEL_OFFSET, _SEL_END)
        harness._transform_nodes_cache = [
            TransformDescriptor(name="bit_invert", category="bitops", description="Invert all bits"),
        ]
        node_combo = QComboBox()
        node_combo.addItem("bit_invert [bitops]")
        harness._transform_node_combo = node_combo

        harness._on_transform_apply()

        _assert_inclusive_selection_inverted(doc)


@pytest.mark.usefixtures("qapp")
class TestPipelineExecuteInclusiveSelection:
    """D10 path 3: Pipeline Execute must invert the full inclusive selection."""

    @staticmethod
    def test_execute_inverts_last_selected_byte() -> None:
        """``_on_pipeline_execute`` must read/write ``_SEL_COUNT`` bytes, not ``_SEL_COUNT - 1``.

        Pre-fix, ``_resolve_pipeline_region`` computed
        ``apply_len = sel_end - sel_start``, one byte short of the actual
        selection, leaving the byte at ``_SEL_END`` unmodified. Uses a real
        ``TransformPipeline`` with a single ``RustTransformNode("bit_invert")``
        step so no parameter-form plumbing is needed.
        """
        doc = _make_doc()
        harness = _TransformsHarness(doc)
        harness._hex_widget = _StubHexWidget(_SEL_OFFSET, _SEL_OFFSET, _SEL_END)

        pipeline = TransformPipeline()
        pipeline.add_step(RustTransformNode("bit_invert", "bitops", "Invert all bits"), {})
        harness._transform_pipeline = pipeline

        harness._on_pipeline_execute()

        _assert_inclusive_selection_inverted(doc)
