# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the app-wide input-field vertical-clipping fix (R02 + R03).

These gates lock in the two-pronged remediation of the systemic defect where
small ``QLineEdit`` / editable ``QComboBox`` fields dropped into fixed-height
toolbars had their glyph bottoms clipped:

* **Container fix (R03)** -- every Process-panel sub-tab toolbar now derives its
  height from :func:`compute_toolbar_height` (font-metric driven) instead of the
  retired hardcoded ``_TOOLBAR_HEIGHT = 32``. Reverting any container back to
  ``setFixedHeight(32)`` drives the toolbar below both the helper's output and
  its hosted fields' size hints, turning :func:`test_process_panel_toolbars_are_font_metric_derived`
  RED.
* **QSS floor (R03)** -- the shared ``QLineEdit`` rule now carries a
  ``min-height`` so a bare field keeps enough height even when a legacy
  fixed-height container tries to squeeze it. Removing the floor lets a short
  container clip the field, turning :func:`test_qss_line_edit_floor_prevents_squeeze`
  RED.
* **Editable-combo centering (R02)** -- the main toolbar's editable Model combo
  and the static Provider combo now share one derived height and the inner
  line-edit fills the combo, so the model text is vertically centered rather than
  bottom-low. Reverting the combo min-height / QSS rules turns
  :func:`test_toolbar_model_combo_centered_and_matches_provider` RED.

Every gate builds the real widgets under the real bundled stylesheet in an
offscreen ``QApplication`` and asserts on real rendered geometry; thresholds are
anchored on the live :func:`compute_toolbar_height` / :func:`compute_control_min_height`
outputs and :class:`QFontMetrics`, never on restated literals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QAbstractSpinBox,
    QComboBox,
    QLineEdit,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.base_panel import compute_control_min_height, compute_toolbar_height
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab
from intellicrack.ui.panels.process_panel.system_tab import SystemTab
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab
from intellicrack.ui.resources.theme_manager import ThemeManager

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


# The styled QLineEdit chrome that must sit *around* the glyphs:
# padding 6px top + 6px bottom + 1px border top + 1px border bottom.
_LINE_EDIT_CHROME_PX: int = 14

_PROCESS_TAB_FACTORIES: tuple[type[QWidget], ...] = (
    SystemTab,
    MemoryTab,
    ThreadsTab,
    ModulesTab,
    ProcessTab,
)


@pytest.fixture
def themed_qapp(qapp: QApplication) -> Generator[QApplication]:
    """Yield the shared QApplication and restore its stylesheet on teardown.

    Individual tests install the real bundled dark/light stylesheet on the
    application so QSS padding, borders, and ``min-height`` rules take effect on
    real geometry. Restoring the prior stylesheet keeps these theme installs from
    leaking into other tests sharing the session-scoped application.

    Args:
        qapp: The session-scoped QApplication from the shared fixtures.

    Yields:
        QApplication: The application with its stylesheet snapshotted for restore.
    """
    previous = qapp.styleSheet()
    try:
        yield qapp
    finally:
        qapp.setStyleSheet(previous)


def _apply_theme(app: QApplication, theme: str) -> None:
    """Install the real bundled stylesheet for ``theme`` on the application.

    Args:
        app: The QApplication to style.
        theme: Theme name (``"dark"`` or ``"light"``).
    """
    app.setStyleSheet(ThemeManager.get_instance().get_stylesheet(theme))
    app.processEvents()


def _cycle_tab_pages(root: QWidget, app: QApplication) -> None:
    """Make every page of every nested ``QTabWidget`` current at least once.

    A ``QTabWidget`` only lays out its current page, so a field on a
    non-current sub-tab never receives real geometry. Cycling each page to the
    front (processing events after each switch) forces every hosted field to be
    laid out so its rendered height can be measured.

    Args:
        root: Widget whose descendant tab widgets should be cycled.
        app: The QApplication whose event loop is flushed after each switch.
    """
    for tab_widget in root.findChildren(QTabWidget):
        for index in range(tab_widget.count()):
            tab_widget.setCurrentIndex(index)
            app.processEvents()


def _assert_visible_fields_not_clipped(container: QWidget, threshold: int, label: str) -> int:
    """Assert every currently visible target field on ``container`` clears ``threshold``.

    Args:
        container: Widget whose visible toolbar input fields are checked.
        threshold: Minimum acceptable rendered field height in pixels.
        label: Human-readable source name used in the failure message.

    Returns:
        int: Number of visible fields asserted.
    """
    count = 0
    for toolbar in container.findChildren(QToolBar):
        for field in _toolbar_input_fields(toolbar):
            if field.isVisible():
                assert field.height() >= threshold, f"{label} field height {field.height()} clips glyphs (needs >= {threshold})"
                count += 1
    return count


def _toolbar_input_fields(toolbar: QToolBar) -> list[QWidget]:
    """Return the user-facing text inputs a toolbar hosts.

    Targets standalone ``QLineEdit`` widgets and the inner line-edit of editable
    combo boxes -- the field types the clipping defect affected -- while
    excluding the internal line-edit of spin boxes and non-editable combos, whose
    height is governed by their owning control rather than the ``QLineEdit`` rule.

    Args:
        toolbar: The toolbar to inspect.

    Returns:
        list[QWidget]: The hosted input widgets whose height must fit their glyphs.
    """
    fields: list[QWidget] = [
        line_edit for line_edit in toolbar.findChildren(QLineEdit) if not isinstance(line_edit.parent(), (QAbstractSpinBox, QComboBox))
    ]
    for combo in toolbar.findChildren(QComboBox):
        inner = combo.lineEdit()
        if combo.isEditable() and inner is not None:
            fields.append(inner)
    return fields


def test_process_panel_toolbars_are_font_metric_derived(themed_qapp: QApplication) -> None:
    """Every Process-panel toolbar is tall enough for its font and hosted fields.

    Builds each real Process-panel sub-tab under the real dark stylesheet and
    asserts that every toolbar's rendered height is at least the live
    :func:`compute_toolbar_height` output and at least the size-hint height of
    every input it hosts. Reverting any container to ``setFixedHeight(32)`` drops
    the toolbar to 32 px -- below both the derived height and the ~34 px field
    hint -- turning this gate RED.

    Args:
        themed_qapp: The QApplication with stylesheet restore.
    """
    _apply_theme(themed_qapp, "dark")

    checked_toolbars = 0
    checked_input_hosting = 0
    for factory in _PROCESS_TAB_FACTORIES:
        tab = factory()
        tab.resize(1100, 750)
        tab.show()
        tab.ensurePolished()
        themed_qapp.processEvents()
        _cycle_tab_pages(tab, themed_qapp)

        derived = compute_toolbar_height(tab)
        assert derived > _LINE_EDIT_CHROME_PX, "font-metric toolbar height collapsed below the field chrome"

        toolbars = tab.findChildren(QToolBar)
        assert toolbars, f"{factory.__name__} built no toolbars to verify"
        for toolbar in toolbars:
            assert toolbar.height() >= derived, (
                f"{factory.__name__} toolbar height {toolbar.height()} is below the font-derived "
                f"{derived} px -- a hardcoded fixed height would clip its controls"
            )
            checked_toolbars += 1
            for field in _toolbar_input_fields(toolbar):
                assert toolbar.height() >= field.sizeHint().height(), (
                    f"{factory.__name__} toolbar {toolbar.height()} px cannot contain its "
                    f"{field.sizeHint().height()} px input without clipping"
                )
                checked_input_hosting += 1
        tab.close()

    assert checked_toolbars >= len(_PROCESS_TAB_FACTORIES), "enumeration found no toolbars to gate"
    assert checked_input_hosting > 0, "no input-hosting toolbar was exercised -- gate would be vacuous"


def test_process_panel_input_fields_not_vertically_clipped(themed_qapp: QApplication) -> None:
    """Visible Process-panel input fields render tall enough for full glyphs.

    Cycles every sub-tab to the front and, for each currently visible input,
    asserts the rendered field height leaves room for the font's full ascent and
    descent plus the styled chrome (``fontHeight + 14``). This is the end-state
    invariant the user reported violated on the Device Path field.

    Args:
        themed_qapp: The QApplication with stylesheet restore.
    """
    _apply_theme(themed_qapp, "dark")

    measured = 0
    for factory in _PROCESS_TAB_FACTORIES:
        tab = factory()
        tab.resize(1100, 750)
        tab.show()
        tab.ensurePolished()
        themed_qapp.processEvents()
        threshold = QFontMetrics(tab.font()).height() + _LINE_EDIT_CHROME_PX

        for tab_widget in tab.findChildren(QTabWidget):
            for index in range(tab_widget.count()):
                tab_widget.setCurrentIndex(index)
                themed_qapp.processEvents()
                measured += _assert_visible_fields_not_clipped(tab, threshold, factory.__name__)
        tab.close()

    assert measured >= 10, f"expected to measure the real input fields, only saw {measured}"


@pytest.mark.parametrize("theme", ["dark", "dark2", "light", "light2"])
def test_qss_line_edit_floor_prevents_squeeze(themed_qapp: QApplication, theme: str) -> None:
    """The QSS ``QLineEdit`` min-height floor keeps a short toolbar from clipping.

    Places a bare styled ``QLineEdit`` inside a deliberately short (30 px)
    fixed-height toolbar -- standing in for a legacy un-migrated container the
    Python fix does not touch -- and asserts the field still renders at least
    ``fontHeight + 14`` px. The bundled ``QLineEdit { min-height }`` rule holds it
    open; deleting that rule from the theme lets the short container squeeze the
    field below the threshold, turning this gate RED.

    Args:
        themed_qapp: The QApplication with stylesheet restore.
        theme: Theme whose real stylesheet is exercised (``"dark"`` / ``"dark2"`` /
            ``"light"`` / ``"light2"``).
    """
    _apply_theme(themed_qapp, theme)

    host = QWidget()
    layout = QVBoxLayout(host)
    toolbar = QToolBar()
    toolbar.setMovable(False)
    toolbar.setFixedHeight(30)
    field = QLineEdit()
    field.setMaximumWidth(200)
    field.setPlaceholderText(r"\\.\MyDriver")
    toolbar.addWidget(field)
    layout.addWidget(toolbar)
    host.resize(600, 200)
    host.show()
    host.ensurePolished()
    themed_qapp.processEvents()

    threshold = QFontMetrics(field.font()).height() + _LINE_EDIT_CHROME_PX
    assert field.height() >= threshold, (
        f"[{theme}] line edit height {field.height()} clips glyphs inside a short toolbar "
        f"(needs >= {threshold}); the QLineEdit min-height floor is missing"
    )
    host.close()


@pytest.mark.parametrize("theme", ["dark", "dark2", "light", "light2"])
def test_editable_toolbar_combo_centered_under_theme(themed_qapp: QApplication, theme: str) -> None:
    """An editable ``#toolbar_combo`` centers its text and matches a static combo.

    Rebuilds the toolbar Provider/Model combo pair exactly as the main window
    does (shared derived min-height, editable Model combo) under each real theme
    stylesheet and asserts the editable combo's inner line-edit is vertically
    centered within the combo and both combos share one height. Removing the
    ``QComboBox#toolbar_combo`` min-height or the inner ``QLineEdit`` rule from a
    theme pushes the text low and desynchronises the heights, turning the matching
    theme case RED.

    Args:
        themed_qapp: The QApplication with stylesheet restore.
        theme: Theme whose real stylesheet is exercised (``"dark"`` / ``"dark2"`` /
            ``"light"`` / ``"light2"``).
    """
    _apply_theme(themed_qapp, theme)

    host = QWidget()
    layout = QVBoxLayout(host)
    toolbar = QToolBar()
    toolbar.setFixedHeight(compute_toolbar_height(host))

    provider = QComboBox()
    provider.setObjectName("toolbar_combo")
    provider.setMinimumHeight(compute_control_min_height(host))
    provider.addItem("HuggingFace")
    toolbar.addWidget(provider)

    model = QComboBox()
    model.setObjectName("toolbar_combo")
    model.setMinimumHeight(compute_control_min_height(host))
    model.setEditable(True)
    model.addItem("google/gemma-2-2b-it")
    model.setCurrentText("google/gemma-2-2b-it")
    toolbar.addWidget(model)

    layout.addWidget(toolbar)
    host.resize(900, 120)
    host.show()
    host.ensurePolished()
    themed_qapp.processEvents()

    inner = model.lineEdit()
    assert inner is not None
    combo_center = model.rect().center().y()
    inner_center = inner.geometry().center().y()
    assert abs(inner_center - combo_center) <= 1, (
        f"[{theme}] editable combo text center {inner_center} is offset from combo center {combo_center}; the text renders bottom-low (R02)"
    )
    assert model.height() == provider.height(), (
        f"[{theme}] editable Model combo {model.height()} px differs from static Provider combo "
        f"{provider.height()} px; the toolbar combos no longer share one height"
    )
    host.close()


@pytest.fixture
def main_window(
    themed_qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real, unshown ``MainWindow`` under the real applied theme.

    Args:
        themed_qapp: QApplication with stylesheet restore.
        real_config: Real Config instance from the shared fixtures.
        real_orchestrator: Real Orchestrator instance from the shared fixtures.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed MainWindow whose toolbar combos are built.
    """
    _ = themed_qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    window.show()
    themed_qapp.processEvents()
    try:
        yield window
    finally:
        window.close()


def test_toolbar_model_combo_centered_and_matches_provider(
    main_window: MainWindow,
    themed_qapp: QApplication,
) -> None:
    """The real main-window Model combo centers its text and matches the Provider combo.

    Drives the widgets built by ``MainWindow._setup_toolbar`` and asserts the
    editable Model combo's inner line-edit is vertically centered within the combo
    and shares the Provider combo's height. This gates the R02 fix on the real
    toolbar, not a reconstruction.

    Args:
        main_window: The real MainWindow under test.
        themed_qapp: QApplication used to flush pending layout events.
    """
    model_combo = main_window.model_combo
    provider_candidates = [
        combo for combo in main_window.findChildren(QComboBox) if combo.objectName() == "toolbar_combo" and not combo.isEditable()
    ]
    assert provider_candidates, "the static Provider toolbar combo was not found"
    provider_combo = provider_candidates[0]
    model_combo.setCurrentText("google/gemma-2-2b-it")
    themed_qapp.processEvents()

    inner = model_combo.lineEdit()
    assert inner is not None, "the editable model combo lost its line edit"
    combo_center = model_combo.rect().center().y()
    inner_center = inner.geometry().center().y()
    assert abs(inner_center - combo_center) <= 1, (
        f"model combo text center {inner_center} is offset from combo center {combo_center}; the editable text renders bottom-low (R02)"
    )
    assert model_combo.height() == provider_combo.height(), (
        f"Model combo {model_combo.height()} px differs from Provider combo "
        f"{provider_combo.height()} px; the two toolbar combos no longer share one height"
    )
