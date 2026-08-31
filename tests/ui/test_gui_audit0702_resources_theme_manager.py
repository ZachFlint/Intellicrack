# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding in ``theme_manager``.

* ``M37``: ``LIGHT_THEME_FALLBACK`` must carry the same widget-rule selectors
  as ``DARK_THEME_FALLBACK`` -- in particular ``QLabel[heading="true"]``,
  plus the ``QScrollArea``, ``QTreeWidget``/``QTreeView``, ``QRadioButton``,
  ``QSpinBox``/``QDoubleSpinBox``, ``QSlider`` and ``QFrame[frameShape]``
  base rules -- so that a widget styled through the fallback sheet (used
  when the bundled ``.qss`` file for the active theme is missing or
  unreadable) renders identically under light and dark. Tests drive real
  ``QLabel`` widgets through the real style engine (dynamic-property
  selectors, font resolution) rather than only inspecting the stylesheet
  text, and one test drives the real :class:`ThemeManager` routing logic
  that selects the fallback when a theme's ``.qss`` file is missing.

* ``D33``: the fallback rewrite that made ``.qss`` the single source of
  truth for ``DARK_THEME_FALLBACK`` / ``LIGHT_THEME_FALLBACK`` replaced the
  independently hand-authored fallback text with the live contents of
  ``dark_theme.qss`` / ``light_theme.qss``. Two assumptions that only ever
  held for the old, hand-authored text no longer apply and are removed here:
  a ``QLabel[subheading="true"]`` rule that was never part of the shipped
  ``.qss`` assets, and a points-based (``pointSizeF``) heading size -- the
  real ``.qss`` sets ``font-size: 16px``, which Qt resolves as a pixel size
  rather than a point size. See
  ``tests/ui/test_theme_manager_d33_fallback_drift.py`` for the drift gate
  covering that rewrite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QApplication, QLabel

from intellicrack.ui.resources.theme_manager import (
    DARK_THEME_FALLBACK,
    LIGHT_THEME_FALLBACK,
    THEME_DARK,
    THEME_LIGHT,
    ThemeManager,
)


if TYPE_CHECKING:
    import pytest


_PARITY_SELECTORS: list[str] = [
    "QScrollArea {",
    "QTreeWidget, QTreeView {",
    "QRadioButton {",
    "QRadioButton::indicator {",
    "QSpinBox, QDoubleSpinBox {",
    "QSlider::groove:horizontal {",
    'QFrame[frameShape="4"], QFrame[frameShape="5"] {',
    'QLabel[heading="true"] {',
]

_HEADING_PIXEL_SIZE: int = 16


def _repolished_label(
    stylesheet: str,
    *,
    heading: bool = False,
) -> QLabel:
    """Build a real ``QLabel`` styled by ``stylesheet`` with dynamic properties applied.

    Mirrors the production pattern used by widgets such as
    ``analysis_panel.py`` (``setProperty("heading", "true")``) and the
    ``unpolish``/``polish`` re-evaluation cycle used throughout the
    Intellicrack UI (e.g. ``xpu_status.py``, ``chat.py``) to force the style
    engine to recompute dynamic-property selectors after the stylesheet is
    applied.

    Args:
        stylesheet: The QSS text to apply to the label.
        heading: When True, sets the ``heading`` dynamic property to
            ``"true"`` before polishing.

    Returns:
        QLabel: A polished label whose font reflects the resolved style.
    """
    label = QLabel("Sample")
    if heading:
        label.setProperty("heading", "true")
    label.setStyleSheet(stylesheet)
    style = label.style()
    assert style is not None
    style.unpolish(label)
    style.polish(label)
    label.ensurePolished()
    return label


def test_m37_light_fallback_has_selector_parity_with_dark_fallback() -> None:
    """M37: LIGHT_THEME_FALLBACK defines every selector DARK_THEME_FALLBACK defines.

    Before the fix, ``LIGHT_THEME_FALLBACK``'s ``/* Label */`` block and the
    rest of the sheet were missing ``QLabel[heading="true"]``, and complete
    ``QScrollArea``, ``QTreeWidget``/``QTreeView``, ``QRadioButton``,
    ``QSpinBox``/``QDoubleSpinBox``, ``QSlider`` and ``QFrame[frameShape]``
    base rules that ``DARK_THEME_FALLBACK`` has -- only leftover
    ``:disabled``/``:focus`` pseudo-state rules survived for some of them,
    with no base style.
    """
    for selector in _PARITY_SELECTORS:
        assert selector in DARK_THEME_FALLBACK, f"test fixture selector {selector!r} unexpectedly absent from DARK_THEME_FALLBACK"

    missing = [selector for selector in _PARITY_SELECTORS if selector not in LIGHT_THEME_FALLBACK]
    assert not missing, f"LIGHT_THEME_FALLBACK is missing selectors present in DARK_THEME_FALLBACK: {missing}"


def test_m37_heading_label_renders_bold_sixteen_pixel_under_light_fallback(
    qapp: QApplication,
) -> None:
    """M37: a real QLabel with ``heading=true`` resolves bold 16px text under the light fallback.

    Args:
        qapp: Shared offscreen QApplication fixture required to construct
            widgets.
    """
    _ = qapp
    plain_label = _repolished_label(LIGHT_THEME_FALLBACK)
    heading_label = _repolished_label(LIGHT_THEME_FALLBACK, heading=True)

    assert plain_label.font().bold() is False, "sanity check: a label without the heading property must not be bold"
    assert heading_label.font().bold() is True, "QLabel[heading='true'] must resolve to bold text under the light fallback"
    assert heading_label.font().pixelSize() == _HEADING_PIXEL_SIZE, (
        f"QLabel[heading='true'] must resolve to {_HEADING_PIXEL_SIZE}px under the light fallback, got {heading_label.font().pixelSize()}px"
    )


def test_m37_missing_light_theme_file_routes_to_feature_complete_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M37: a missing ``light_theme.qss`` file routes to the now-feature-complete fallback.

    Simulates the exact scenario from the finding: the styles directory and
    ``dark_theme.qss`` remain present and readable, but ``light_theme.qss``
    is unreadable/missing. Drives the real ``ThemeManager._load_stylesheet``
    routing logic (not a re-implementation of it) and asserts the light
    theme falls back to the constant that now carries full selector parity.

    Args:
        monkeypatch: Pytest fixture used to force the per-file read for
            ``light_theme.qss`` to report "missing" while leaving the real
            file reader in place for every other file.
    """
    ThemeManager.reset_instance()
    manager = ThemeManager.get_instance()
    assert manager.styles_available, "styles directory must exist on disk for this scenario to be meaningful"

    real_read = ThemeManager._read_stylesheet_file

    def _simulate_missing_light_file(filename: str) -> str | None:
        """Report ``light_theme.qss`` as unreadable while reading everything else for real.

        Args:
            filename: Stylesheet file name requested by ``_load_stylesheet``.

        Returns:
            str | None: ``None`` for ``light_theme.qss``, otherwise the real
            file contents.
        """
        if filename == "light_theme.qss":
            return None
        return real_read(filename)

    monkeypatch.setattr(
        ThemeManager,
        "_read_stylesheet_file",
        staticmethod(_simulate_missing_light_file),
    )

    light_stylesheet = manager.get_stylesheet(THEME_LIGHT)
    dark_stylesheet = manager.get_stylesheet(THEME_DARK)

    assert light_stylesheet == LIGHT_THEME_FALLBACK, (
        "with light_theme.qss unreadable, get_stylesheet(THEME_LIGHT) must return the LIGHT_THEME_FALLBACK constant verbatim"
    )
    assert light_stylesheet != DARK_THEME_FALLBACK
    assert dark_stylesheet != LIGHT_THEME_FALLBACK, (
        "dark_theme.qss is still readable in this scenario, so THEME_DARK must not fall back to the light constant"
    )

    for selector in _PARITY_SELECTORS:
        assert selector in light_stylesheet, f"the fallback actually served for THEME_LIGHT is missing selector {selector!r}"
