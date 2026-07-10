# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for GUI audit finding H24 in ``hex_editor/calculator.py``.

H24 -- The calculator tab's "Signed" checkbox (``_calc_signed_check``) was
instantiated and added to the options row but never read anywhere: both
the bridge-backed conversion path (``_on_convert_success``) and the
local, no-bridge fallback path (``_convert_local`` ->
``_add_sized_int_results``) unconditionally rendered every signed *and*
unsigned sized-integer representation regardless of the checkbox's
state. The fix reads ``self._calc_signed_check.isChecked()`` once, at
convert time, in ``_on_convert`` and threads the resulting
``signed_only`` flag through every one of those call sites so ticking
the box hides the unsigned rows from the results tree.

Every test below drives the real ``CalculatorMixin`` wiring on a real
``HexEditorPanel``, exercising the genuine ``QCheckBox``/``QLineEdit``/
``QComboBox`` controls plus either the real, unmodified
``HexEditorBridge`` (dispatched asynchronously through
``run_bridge_coroutine_logged`` and pumped through the Qt event loop) or
the synchronous local fallback. No mock or stub stands in for the
filtering logic under test.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit, QTreeWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Callable


pytestmark = pytest.mark.integration


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a runtime-checked, statically narrowed type.

    Args:
        obj: The object whose private attribute is being read.
        name: The attribute name to look up.
        typ: The expected runtime type of the attribute.

    Returns:
        T: The attribute value, narrowed to ``typ``.

    Raises:
        TypeError: If the attribute's runtime type does not match ``typ``.
    """
    value = getattr(obj, name)
    if not isinstance(value, typ):
        msg = f"{obj!r}.{name} is {type(value).__name__}, expected {typ.__name__}"
        raise TypeError(msg)
    return value


def priv_method(obj: object, name: str) -> Callable[..., object]:
    """Read a private bound method off an object.

    Args:
        obj: The object whose private method is being looked up.
        name: The method name to look up.

    Returns:
        Callable[..., object]: The bound method.

    Raises:
        TypeError: If the attribute's runtime value is not callable.
    """
    value = getattr(obj, name)
    if not callable(value):
        msg = f"{obj!r}.{name} is not callable"
        raise TypeError(msg)
    return value


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Cross-thread results delivered via ``run_bridge_coroutine_logged`` /
    ``BridgeCallWorker`` signals from the background asyncio thread only
    reach their Qt slots while the main-thread event loop is processing
    events, so the bridge-backed tests must pump the loop while waiting
    for ``_on_convert_success`` to run.

    Args:
        qapp: The active QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(0.02)
    return predicate()


def _tree_fully_populated(tree: QTreeWidget) -> bool:
    """Detect whether a conversion has fully repopulated the results tree.

    ``_on_convert`` clears the results tree *synchronously*, on the
    calling (main) thread, before ever dispatching the bridge coroutine
    asynchronously. That means immediately after a second
    ``_run_convert`` call returns, ``tree.topLevelItemCount()`` is
    already back to 0 -- a transient, just-cleared empty state that a
    naive "is something different yet?" predicate (e.g. "target key
    absent") can satisfy trivially, before ``_pump_until`` ever pumps
    the event loop, so it would read the tree while it is still empty
    from the ``clear()`` rather than after the async result actually
    lands.

    ``float64_LE``/``float64_BE`` is always the very last row
    ``_on_convert_success`` adds -- regardless of the "Signed" checkbox
    state or a caught ``struct.error``/``OverflowError`` along the way
    (those fall back to rendering ``"N/A"`` rather than skipping the
    row) -- and the whole render happens synchronously within a single
    Qt slot invocation with no intervening ``processEvents``. So its
    presence is an unambiguous, non-trivial signal that the *complete*
    post-clear render for the current conversion has landed, decoupled
    from whatever row-presence assertions the caller makes afterwards.

    Args:
        tree: The calculator's results ``QTreeWidget``.

    Returns:
        bool: ``True`` once a full render (little- or big-endian) has
        landed in ``tree``; ``False`` while it is still cleared/empty
        or mid-render.
    """
    rows = _tree_row_map(tree)
    return "float64_LE" in rows or "float64_BE" in rows


def _tree_row_map(tree: QTreeWidget) -> dict[str, str]:
    """Read a results tree's top-level rows into a ``{label: value}`` dict.

    Args:
        tree: The calculator's results ``QTreeWidget``.

    Returns:
        dict[str, str]: Mapping from representation label (column 0) to
        its rendered value (column 1), one entry per top-level row.

    Raises:
        TypeError: If a top-level index within ``topLevelItemCount()``
            yields ``None``.
    """
    rows: dict[str, str] = {}
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item is None:
            msg = f"{tree!r}.topLevelItem({i}) is None within topLevelItemCount()"
            raise TypeError(msg)
        rows[item.text(0)] = item.text(1)
    return rows


def _make_panel(*, with_bridge: bool) -> HexEditorPanel:
    """Build a real ``HexEditorPanel``, optionally with a real bridge attached.

    Args:
        with_bridge: When ``True``, attach a fresh, unmodified
            ``HexEditorBridge`` via ``set_bridge`` so ``_on_convert``
            takes the async bridge-dispatch path; when ``False`` the
            panel is left without a bridge so ``_on_convert`` falls back
            to the synchronous local computation.

    Returns:
        HexEditorPanel: A panel with its calculator tab constructed.
    """
    panel = HexEditorPanel()
    if with_bridge:
        panel.set_bridge(HexEditorBridge())
    return panel


def _run_convert(
    panel: HexEditorPanel,
    text: str,
    *,
    signed: bool,
    big_endian: bool = False,
) -> None:
    """Configure the calculator controls and trigger a real ``Convert``.

    Args:
        panel: The panel whose calculator tab controls are driven.
        text: Value string typed into the calculator input.
        signed: Checked state to set on the "Signed" checkbox before
            converting.
        big_endian: Whether to select "Big Endian" in the endianness
            combo before converting; defaults to "Little Endian".
    """
    priv(panel, "_calc_input", QLineEdit).setText(text)
    priv(panel, "_calc_signed_check", QCheckBox).setChecked(signed)
    priv(panel, "_calc_endian_combo", QComboBox).setCurrentText("Big Endian" if big_endian else "Little Endian")
    priv_method(panel, "_on_convert")()


class TestH24BridgePathSignedCheckboxFiltersResults:
    """H24: the bridge-backed (little-endian) dict path honours the "Signed" checkbox."""

    def test_h24_bridge_signed_checked_hides_unsigned_rows(self, qapp: QApplication) -> None:
        """Ticking "Signed" before Convert hides every unsigned row from the bridge path.

        Pre-fix, ``_on_convert_success``'s little-endian branch
        unconditionally added ``uint8``/``uint16_LE``/``uint32_LE``/
        ``uint64_LE`` regardless of the checkbox, so this would fail
        because those keys would still be present. Post-fix, they are
        only added when ``signed_only`` is ``False``.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = _make_panel(with_bridge=True)
        try:
            _run_convert(panel, "0xFF", signed=True)
            tree = priv(panel, "_calc_results_tree", QTreeWidget)
            completed = _pump_until(qapp, lambda: _tree_fully_populated(tree), timeout_s=5.0)
            assert completed, "base_convert dispatch never completed after pumping the Qt event loop"

            rows = _tree_row_map(tree)
            assert rows["int8"] == "-1"
            assert "uint8" not in rows, "uint8 row rendered even though the Signed checkbox was checked"
            assert "int16_LE" in rows
            assert "uint16_LE" not in rows, "uint16_LE row rendered even though the Signed checkbox was checked"
            assert "int32_LE" in rows
            assert "uint32_LE" not in rows, "uint32_LE row rendered even though the Signed checkbox was checked"
            assert "int64_LE" in rows
            assert "uint64_LE" not in rows, "uint64_LE row rendered even though the Signed checkbox was checked"
            assert "float32_LE" in rows
            assert "float64_LE" in rows
        finally:
            panel.deleteLater()

    def test_h24_bridge_checkbox_toggle_live_between_conversions(self, qapp: QApplication) -> None:
        """Flipping "Signed" between two Converts changes the bridge path's rendered rows live.

        Runs the same panel through two conversions of the same input
        over the real bridge dispatch path, toggling only the "Signed"
        checkbox between them. This is the genuine falsifiable gate for
        the bridge path: pre-fix, ``_on_convert_success`` never read the
        checkbox at all, so both runs would render an identical set of
        rows (``uint8`` present in both); post-fix, the second run's
        ``uint8`` row disappears solely because the checkbox was ticked.
        A test that only ever exercises one checkbox state cannot show
        this -- it would pass unchanged on the pre-fix code -- so both
        states must be observed within the same test to gate the fix.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = _make_panel(with_bridge=True)
        try:
            _run_convert(panel, "0xFF", signed=False)
            tree = priv(panel, "_calc_results_tree", QTreeWidget)
            completed = _pump_until(qapp, lambda: _tree_fully_populated(tree), timeout_s=5.0)
            assert completed, "base_convert dispatch never completed after pumping the Qt event loop"

            unchecked_rows = _tree_row_map(tree)
            assert unchecked_rows["int8"] == "-1"
            assert unchecked_rows["uint8"] == "255"
            assert unchecked_rows["uint16_LE"] == "255"
            assert unchecked_rows["uint32_LE"] == "255"
            assert unchecked_rows["uint64_LE"] == "255"

            _run_convert(panel, "0xFF", signed=True)
            completed = _pump_until(qapp, lambda: _tree_fully_populated(tree), timeout_s=5.0)
            assert completed, "base_convert dispatch never completed for the second (signed) conversion"

            checked_rows = _tree_row_map(tree)
            assert checked_rows["int8"] == "-1"
            assert "uint8" not in checked_rows, (
                "uint8 row still rendered after checking Signed and re-converting over the bridge "
                "path; the checkbox state is not being read on this Convert call"
            )
            assert "uint16_LE" not in checked_rows
            assert "uint32_LE" not in checked_rows
            assert "uint64_LE" not in checked_rows
        finally:
            panel.deleteLater()


class TestH24LocalFallbackSignedCheckboxFiltersResults:
    """H24: the synchronous no-bridge fallback path honours the "Signed" checkbox."""

    def test_h24_local_big_endian_signed_checked_hides_unsigned_rows(self, qapp: QApplication) -> None:
        """Ticking "Signed" with no bridge attached hides unsigned rows in the big-endian path.

        Uses ``0xFFFFFFFF``, whose signed/unsigned interpretations
        genuinely differ at every width up to 32 bits (``-1`` vs a large
        positive number), so the assertions verify real computed values
        rather than only key presence. Pre-fix, ``_add_sized_int_results``
        had no ``signed_only`` parameter at all and always emitted both
        rows for every width; this test fails against that code both
        because the unsigned keys would still be present and because the
        call would raise a ``TypeError`` for the unsupported keyword.

        Args:
            qapp: The shared QApplication fixture, required so the
                widgets constructed by ``HexEditorPanel`` have a running
                application instance even though this test never pumps
                the event loop.
        """
        _ = qapp
        panel = _make_panel(with_bridge=False)
        try:
            _run_convert(panel, "0xFFFFFFFF", signed=True, big_endian=True)
            tree = priv(panel, "_calc_results_tree", QTreeWidget)
            rows = _tree_row_map(tree)

            assert rows["int8"] == "-1"
            assert "uint8" not in rows, "uint8 row rendered even though the Signed checkbox was checked"
            assert rows["int16_BE"] == "-1"
            assert "uint16_BE" not in rows, "uint16_BE row rendered even though the Signed checkbox was checked"
            assert rows["int32_BE"] == "-1"
            assert "uint32_BE" not in rows, "uint32_BE row rendered even though the Signed checkbox was checked"
            assert "int64_BE" in rows
            assert "uint64_BE" not in rows, "uint64_BE row rendered even though the Signed checkbox was checked"
            assert "float32_BE" in rows
            assert "float64_BE" in rows
        finally:
            panel.deleteLater()

    def test_h24_local_be_checkbox_toggle_live_between_conversions(self, qapp: QApplication) -> None:
        """Flipping "Signed" between two Converts changes the local BE path's rendered rows live.

        Runs the same panel through two conversions of ``0xFFFFFFFF``
        over the synchronous no-bridge, big-endian path, toggling only
        the "Signed" checkbox between them. This is the genuine
        falsifiable gate for the local BE path: pre-fix,
        ``_add_sized_int_results`` had no ``signed_only`` parameter at
        all and always emitted both rows for every width, so both runs
        would render an identical row set; post-fix, the second run's
        unsigned rows disappear solely because the checkbox was ticked.
        Exercising only the unchecked state would pass unchanged on the
        pre-fix code, so both states must be observed within the same
        test to gate the fix.

        Args:
            qapp: The shared QApplication fixture, required so the
                widgets constructed by ``HexEditorPanel`` have a running
                application instance even though this test never pumps
                the event loop.
        """
        _ = qapp
        panel = _make_panel(with_bridge=False)
        try:
            _run_convert(panel, "0xFFFFFFFF", signed=False, big_endian=True)
            tree = priv(panel, "_calc_results_tree", QTreeWidget)
            unchecked_rows = _tree_row_map(tree)

            assert unchecked_rows["int8"] == "-1"
            assert unchecked_rows["uint8"] == "255"
            assert unchecked_rows["int16_BE"] == "-1"
            assert unchecked_rows["uint16_BE"] == "65535"
            assert unchecked_rows["int32_BE"] == "-1"
            assert unchecked_rows["uint32_BE"] == "4294967295"

            _run_convert(panel, "0xFFFFFFFF", signed=True, big_endian=True)
            checked_rows = _tree_row_map(tree)

            assert checked_rows["int8"] == "-1"
            assert "uint8" not in checked_rows, (
                "uint8 row still rendered after checking Signed and re-converting over the local "
                "big-endian path; the checkbox state is not being read on this Convert call"
            )
            assert checked_rows["int16_BE"] == "-1"
            assert "uint16_BE" not in checked_rows
            assert checked_rows["int32_BE"] == "-1"
            assert "uint32_BE" not in checked_rows
        finally:
            panel.deleteLater()

    def test_h24_checkbox_state_read_live_between_conversions(self, qapp: QApplication) -> None:
        """The checkbox is read fresh on every Convert, not cached or ignored.

        Runs the same panel through two conversions of the same input
        value, toggling only the "Signed" checkbox between them. Pre-fix
        (the checkbox never read at all), the second run would render
        identically to the first -- ``uint8`` would still be present.
        Post-fix, checking the box removes it.

        Args:
            qapp: The shared QApplication fixture, required so the
                widgets constructed by ``HexEditorPanel`` have a running
                application instance even though this test never pumps
                the event loop.
        """
        _ = qapp
        panel = _make_panel(with_bridge=False)
        try:
            _run_convert(panel, "0xFF", signed=False)
            tree = priv(panel, "_calc_results_tree", QTreeWidget)
            first_rows = _tree_row_map(tree)
            assert "uint8" in first_rows
            assert first_rows["int8"] == "-1"

            _run_convert(panel, "0xFF", signed=True)
            second_rows = _tree_row_map(tree)
            assert "uint8" not in second_rows, (
                "uint8 row still rendered after checking Signed and re-converting; the checkbox "
                "state is not being read on this Convert call"
            )
            assert second_rows["int8"] == "-1"
        finally:
            panel.deleteLater()
