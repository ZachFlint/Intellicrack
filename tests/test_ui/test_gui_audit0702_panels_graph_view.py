# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding in ``graph_view`` (M35).

M35: ``CFGGraphView``, ``BasicBlockItem`` and ``EdgeItem`` resolved CFG colors
once at construction time via ``_get_graph_colors()`` and never re-resolved
them on a live application theme switch, so a long-lived CFG tab kept
painting with the stale theme's palette until the scene was rebuilt from
scratch. The fix adds ``refresh_theme_colors()`` to the item classes and
subscribes ``CFGGraphView`` to ``ThemeManager.theme_changed`` so the
background brush and every already-rendered item re-resolve live.

All tests drive real Qt objects under an offscreen ``QApplication`` -- no
mocks stand in for the theme-refresh behaviour under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QPointF

from intellicrack.ui.panels.graph_view import (
    BasicBlockItem,
    CFGGraphView,
    EdgeItem,
    _get_graph_colors,
)
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


if TYPE_CHECKING:
    from PyQt6.QtGui import QColor
    from PyQt6.QtWidgets import QApplication


def _restore_theme() -> None:
    """Restore the shared theme manager to the default dark theme."""
    ThemeManager.get_instance().apply_theme(THEME_DARK)


def test_m35_block_item_refresh_theme_colors_updates_brush_and_pen(qapp: QApplication) -> None:
    """``BasicBlockItem.refresh_theme_colors`` re-resolves brush and pen colors.

    Pre-fix, ``BasicBlockItem`` had no ``refresh_theme_colors`` method at all
    (colors were only ever set once in ``__init__``), so this call would
    raise ``AttributeError``. Post-fix it must re-query
    ``_get_graph_colors()`` and repaint the cached brush/pen to match the
    newly active theme.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        item = BasicBlockItem(0x1000, [{"disasm": "nop"}])
        dark_colors = _get_graph_colors()
        assert item.brush().color() == dark_colors["block_bg"]
        assert item.pen().color() == dark_colors["block_border"]

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)
        light_colors = _get_graph_colors()
        assert light_colors["block_bg"] != dark_colors["block_bg"], "test premise: dark and light block_bg must differ"
        assert item.brush().color() == dark_colors["block_bg"], "brush changed without an explicit refresh_theme_colors() call"

        item.refresh_theme_colors()
        assert item.brush().color() == light_colors["block_bg"], "brush did not re-resolve to the light theme"
        assert item.pen().color() == light_colors["block_border"], "pen did not re-resolve to the light theme"
        assert item._colors == light_colors, "cached _colors dict was not replaced"
    finally:
        _restore_theme()


def test_m35_edge_item_refresh_theme_colors_updates_pen_and_arrow_brush(qapp: QApplication) -> None:
    """``EdgeItem.refresh_theme_colors`` re-resolves the pen and arrow brush.

    Pre-fix, ``EdgeItem`` resolved ``colors = _get_graph_colors()`` once in
    ``__init__`` and baked it into ``setPen``/``self._arrow_brush``, with no
    method to re-derive it later, so this call would raise
    ``AttributeError``. Post-fix the pen and arrow brush must both track a
    live theme switch.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        edge = EdgeItem(QPointF(0, 0), QPointF(0, 100), edge_type="unconditional")
        dark_colors = _get_graph_colors()
        assert edge.pen().color() == dark_colors["edge_uncond"]
        assert edge._arrow_brush.color() == dark_colors["edge_uncond"]

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)
        light_colors = _get_graph_colors()
        assert light_colors["edge_uncond"] != dark_colors["edge_uncond"], "test premise: dark and light edge_uncond must differ"
        assert edge.pen().color() == dark_colors["edge_uncond"], "pen changed without an explicit refresh call"

        edge.refresh_theme_colors()
        assert edge.pen().color() == light_colors["edge_uncond"], "pen did not re-resolve to the light theme"
        assert edge._arrow_brush.color() == light_colors["edge_uncond"], "arrow brush did not re-resolve to the light theme"
    finally:
        _restore_theme()


def test_m35_cfg_view_subscribes_and_updates_background_on_theme_change(qapp: QApplication) -> None:
    """``CFGGraphView`` re-applies its background brush on ``theme_changed``.

    Pre-fix, ``CFGGraphView.__init__`` baked ``_get_graph_colors()["background"]``
    into the viewport once and never connected to
    ``ThemeManager.theme_changed``, so ``apply_theme`` afterwards left the
    background brush unchanged. Post-fix the view subscribes in ``__init__``
    and the brush must track a live switch with no further action from the
    caller.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    view: CFGGraphView | None = None
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        view = CFGGraphView()
        dark_colors = _get_graph_colors()
        assert view.backgroundBrush().color() == dark_colors["background"]

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)
        light_colors = _get_graph_colors()
        assert light_colors["background"] != dark_colors["background"], "test premise: dark and light background must differ"
        assert view.backgroundBrush().color() == light_colors["background"], (
            "CFGGraphView background brush did not track the live theme switch"
        )

        ThemeManager.get_instance().apply_theme(THEME_DARK)
        assert view.backgroundBrush().color() == dark_colors["background"]
    finally:
        if view is not None:
            view.deleteLater()
        _restore_theme()


def test_m35_cfg_view_theme_change_repaints_existing_blocks_and_edges(qapp: QApplication) -> None:
    """A live theme switch re-colors already-rendered blocks and edges in place.

    Builds one ``CFGGraphView``, loads a two-block CFG once (mirroring how
    ``cutter_panel.py`` builds a single long-lived view and repeatedly calls
    ``load_graph`` on it), then switches the theme *without* calling
    ``load_graph`` again. Pre-fix, the already-constructed
    ``BasicBlockItem``/``EdgeItem`` instances kept their construction-time
    colors because nothing in ``CFGGraphView`` observed
    ``ThemeManager.theme_changed``, so this would fail: the block brush and
    edge pen would still report the stale (dark) colors after switching to
    light. Post-fix, ``_on_theme_changed`` walks ``scene.items()`` and calls
    ``refresh_theme_colors()`` on each item, so both must resolve to the new
    theme's colors.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    view: CFGGraphView | None = None
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        view = CFGGraphView()
        blocks: list[dict[str, Any]] = [
            {"offset": 0x1000, "jump": 0x2000, "fail": None, "ops": [{"disasm": "mov eax, 1"}]},
            {"offset": 0x2000, "jump": None, "fail": None, "ops": [{"disasm": "ret"}]},
        ]
        view.graph_scene().load_graph(blocks)

        block_item = view.graph_scene().block_items[0x1000]
        edge_items = [item for item in view.graph_scene().items() if isinstance(item, EdgeItem)]
        assert edge_items, "expected at least one EdgeItem between the two loaded blocks"
        edge_item = edge_items[0]

        dark_colors = _get_graph_colors()
        assert block_item.brush().color() == dark_colors["block_bg"]
        assert edge_item.pen().color() == dark_colors["edge_uncond"]

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)
        light_colors = _get_graph_colors()
        assert light_colors["block_bg"] != dark_colors["block_bg"], "test premise: dark and light block_bg must differ"
        assert light_colors["edge_uncond"] != dark_colors["edge_uncond"], "test premise: dark and light edge_uncond must differ"

        assert view.graph_scene().block_items[0x1000] is block_item, (
            "scene was rebuilt instead of live-refreshed; the pre-existing item identity was lost"
        )
        assert block_item.brush().color() == light_colors["block_bg"], (
            "pre-existing BasicBlockItem kept the stale theme color after theme_changed"
        )
        assert block_item.pen().color() == light_colors["block_border"]
        assert edge_item.pen().color() == light_colors["edge_uncond"], (
            "pre-existing EdgeItem kept the stale theme color after theme_changed"
        )
        assert edge_item._arrow_brush.color() == light_colors["edge_uncond"]
    finally:
        if view is not None:
            view.deleteLater()
        _restore_theme()


def test_m35_cfg_view_theme_change_round_trips_repeatedly(qapp: QApplication) -> None:
    """Repeated theme switches keep re-resolving colors rather than sticking once.

    Pre-fix there was no subscription at all, so every one of these switches
    would leave the background brush at its construction-time (dark) value.
    Post-fix each ``apply_theme`` call must independently drive a fresh
    ``_on_theme_changed`` invocation that re-derives the color for whichever
    theme is now active, proving this is a live subscription and not a
    one-shot post-construction correction.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    view: CFGGraphView | None = None
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        view = CFGGraphView()
        dark_colors = _get_graph_colors()
        light_colors_expected: dict[str, QColor] | None = None

        for _ in range(3):
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            if light_colors_expected is None:
                light_colors_expected = _get_graph_colors()
            assert view.backgroundBrush().color() == light_colors_expected["background"], (
                "background did not re-resolve to light on a repeated switch"
            )

            ThemeManager.get_instance().apply_theme(THEME_DARK)
            assert view.backgroundBrush().color() == dark_colors["background"], "background did not re-resolve to dark on a repeated switch"
    finally:
        if view is not None:
            view.deleteLater()
        _restore_theme()
