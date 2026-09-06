# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared base class for Intellicrack analysis panels.

Provides common layout scaffolding, toolbar construction, async bridge integration, and lifecycle signals used by all native analysis panels
(Frida, Ghidra, Cutter, x64dbg, Sandbox).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, NamedTuple, override

from PyQt6.QtCore import QEvent, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QFontMetrics
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.overflow_toolbar import OverflowToolBar
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Sequence

    import structlog


_logger = get_logger(__name__)

_BASE_MARGIN: Final[int] = 4
_BASE_SPACING: Final[int] = 4
_MIN_PANEL_WIDTH: Final[int] = 200
_MIN_PANEL_HEIGHT: Final[int] = 150
_CONTROL_SCROLL_MIN_HEIGHT: Final[int] = 88
_CONTROL_ROW_SCROLLBAR_ALLOWANCE: Final[int] = 16

# Derived from the styled QPushButton/QToolBar rules in theme_manager.py:
# QPushButton { padding: 6px 16px; min-height: 24px; } and
# QToolBar { padding: 4px; }. A fixed toolbar height smaller than this clips
# the bottom of every styled button placed in it (D38/D08/D03).
_BUTTON_MIN_CONTENT_HEIGHT: Final[int] = 24
_BUTTON_VERTICAL_PADDING: Final[int] = 12
_TOOLBAR_CHROME_PADDING: Final[int] = 8
# Derived from the styled QLineEdit rule: QLineEdit { padding: 6px 8px; }.
_LINE_EDIT_VERTICAL_PADDING: Final[int] = 12


def compute_toolbar_height(widget: QWidget) -> int:
    """Derive the toolbar height needed so styled buttons are not clipped.

    Combines ``widget``'s current font metrics (so larger fonts or DPI/
    accessibility scaling grow the toolbar) with the styled QPushButton's
    minimum content height and vertical padding, plus the toolbar's own
    chrome padding, all pulled from the shared stylesheet rules in
    :mod:`intellicrack.ui.resources.theme_manager` rather than a
    hardcoded magic number. Shared by :class:`AnalysisPanelBase` and
    :class:`intellicrack.ui.app.MainWindow` so both toolbars use one
    derivation (D38/D08/D03).

    Args:
        widget: The widget whose font metrics anchor the computation
            (typically the toolbar's owning panel or window).

    Returns:
        int: The toolbar height, in pixels, that fits a styled button
        without clipping its bottom edge.
    """
    content_height = max(QFontMetrics(widget.font()).height(), _BUTTON_MIN_CONTENT_HEIGHT)
    return content_height + _BUTTON_VERTICAL_PADDING + _TOOLBAR_CHROME_PADDING


def compute_control_min_height(widget: QWidget) -> int:
    """Derive the minimum height for a toolbar line edit so glyphs are not clipped.

    Args:
        widget: The widget whose font metrics anchor the computation
            (typically the toolbar hosting the line edit).

    Returns:
        int: The minimum line-edit height, in pixels, that fits its text
        and the styled QLineEdit's vertical padding without clipping.
    """
    content_height = max(QFontMetrics(widget.font()).height(), _BUTTON_MIN_CONTENT_HEIGHT)
    return content_height + _LINE_EDIT_VERTICAL_PADDING


def make_scrollable(
    inner: QWidget,
    *,
    min_height: int = _CONTROL_SCROLL_MIN_HEIGHT,
) -> QScrollArea:
    """Wrap a control cluster in a scroll area so it scrolls instead of clipping.

    The scroll area resizes ``inner`` to fill the available width when
    there is room, but honours ``inner``'s minimum size: when the panel is
    narrower or shorter than the controls require, scrollbars appear as
    needed instead of the rows being squeezed until their text is cut off.

    Module-level so it can be reused by standalone control-cluster widgets
    that are not :class:`AnalysisPanelBase` subclasses (for example the
    Frida instrumentation-tab helper widgets); :meth:`AnalysisPanelBase._make_scrollable`
    is a thin wrapper kept for existing subclass call sites.

    Args:
        inner: The control-cluster widget to make scrollable.
        min_height: Minimum height reserved for the scroll viewport so the
            controls stay usable when the surrounding splitter is short.

    Returns:
        QScrollArea: A frameless, transparent scroll area wrapping ``inner``.
    """
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setMinimumHeight(min_height)
    scroll.setWidget(inner)
    return scroll


def make_control_row(row: QHBoxLayout) -> QScrollArea:
    """Wrap a dense horizontal control row so it scrolls sideways instead of crushing its controls.

    A packed toolbar row -- labels, inputs, and several buttons in a plain
    ``QHBoxLayout`` -- lets Qt shrink every control below its natural width
    when the panel is narrow, eliding button captions down to unreadable
    fragments such as ``ble``/``ible`` in place of ``Enable``/``Disable``.
    Hosting the row in a horizontally scrollable viewport whose inner widget
    keeps its natural minimum width means the controls stay full size and a
    horizontal scrollbar appears when the panel is too narrow, which also
    lets the panel -- and the window hosting it -- shrink freely.

    Module-level so it can be reused by standalone control-cluster widgets
    that are not :class:`AnalysisPanelBase` subclasses (for example the
    Frida instrumentation-tab helper widgets); :meth:`AnalysisPanelBase._make_control_row`
    is a thin wrapper kept for existing subclass call sites.

    Args:
        row: The populated horizontal layout to host.

    Returns:
        QScrollArea: A frameless, fixed-height scroll area wrapping the row.
    """
    inner = QWidget()
    inner.setLayout(row)
    inner.ensurePolished()
    natural = inner.sizeHint()
    inner.setMinimumWidth(natural.width())
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    scroll.setWidget(inner)
    scroll.setFixedHeight(natural.height() + _CONTROL_ROW_SCROLLBAR_ALLOWANCE)
    return scroll


class _ContentScrollArea(QScrollArea):
    """A resizable scroll area whose minimum size hint tracks its content's width, not its height.

    A plain :class:`QScrollArea` reports a small, content-independent minimum size hint on both axes, which is exactly what makes it absorb
    tall content instead of clipping it (D28) -- but wrapping a panel's *entire* content in one would also silence the width demand that
    :meth:`AnalysisPanelBase._wrap_content`'s callers rely on elsewhere (a docked tab's ``minimumSizeHint`` protects it from being squeezed
    narrower than its controls can render). This subclass keeps that width signal flowing through to :meth:`minimumSizeHint` while still
    reporting a small, fixed minimum height so the panel can shrink vertically behind a scrollbar instead of being pinned to the content's
    full height.
    """

    @override
    def minimumSizeHint(self) -> QSize:
        """Report the wrapped content's minimum width with a small fixed height.

        Returns:
            QSize: ``(content.minimumSizeHint().width(), _CONTROL_SCROLL_MIN_HEIGHT)``,
            or the base class's hint when no content widget is set.
        """
        content = self.widget()
        if content is None:
            return super().minimumSizeHint()
        return QSize(content.minimumSizeHint().width(), _CONTROL_SCROLL_MIN_HEIGHT)


class ToolMenuEntry(NamedTuple):
    """A single entry in a grouped toolbar dropdown menu.

    Attributes:
        label: Text shown for the menu action.
        handler: Zero-argument callback invoked when the action triggers.
        enabled: Initial enabled state of the action.
    """

    label: str
    handler: Callable[[], None]
    enabled: bool = True


class AnalysisPanelBase(QWidget):
    """Base class for analysis panels with shared toolbar and layout scaffolding.

    Provides the standard layout (``QVBoxLayout`` with 4 px margins),
    toolbar construction, factory helpers for toolbar widgets, async
    bridge coroutine execution, and ``start_tool``/``stop_tool``
    lifecycle methods.

    Subclasses override ``_populate_toolbar`` to add controls and
    ``_create_content`` to build the main display area.  Override
    ``_cleanup`` for panel-specific teardown in ``stop_tool``.

    Attributes:
        tool_started: Signal emitted when the tool starts.
        tool_closed: Signal emitted when the tool closes.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the BaseToolPanel widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.status_label: QLabel | None = None
        self._toolbar: QToolBar | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the standard panel layout with toolbar and content."""
        self.setMinimumSize(_MIN_PANEL_WIDTH, _MIN_PANEL_HEIGHT)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_BASE_MARGIN, _BASE_MARGIN, _BASE_MARGIN, _BASE_MARGIN)
        layout.setSpacing(_BASE_SPACING)
        layout.addWidget(self._build_toolbar())
        layout.addWidget(self._wrap_content(self._create_content()))

    @staticmethod
    def _wrap_content(content: QWidget) -> QScrollArea:
        """Wrap the panel's content widget in a vertically scrollable viewport.

        A docked analysis tab's content is often taller than the primary
        monitor's usable height (dense forms, stacked control clusters,
        multi-row tables). Hosting it in a resizable scroll area means the
        content still fills the available space exactly as before when
        there is room, and only grows a scrollbar -- instead of clipping --
        when the panel is shorter than the content needs (D28). Uses
        :class:`_ContentScrollArea` rather than a plain ``QScrollArea`` so the
        panel's own ``minimumSizeHint`` keeps reporting ``content``'s real
        minimum width -- the signal :meth:`_sync_left_panel_min_width` in
        ``intellicrack.ui.tools`` relies on to keep a docked tab from being
        squeezed narrower than its controls can render (D02).

        Args:
            content: The content widget returned by ``_create_content``.

        Returns:
            QScrollArea: A frameless, resizable scroll area wrapping ``content``.
        """
        scroll = _ContentScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(content)
        return scroll

    def _build_toolbar(self) -> QToolBar:
        """Create and configure the panel toolbar.

        Uses :class:`OverflowToolBar` so that when the panel is too narrow to
        show every control, the clipped buttons remain reachable through a
        populated overflow popup instead of Qt's built-in popup, which renders
        empty for the button widgets these panels add via ``addWidget``.
        The height is derived from font metrics via :func:`compute_toolbar_height`
        rather than a fixed constant, so styled buttons are never clipped
        (D38/D08/D03), and is re-derived in :meth:`changeEvent` when the
        panel's font changes.

        Returns:
            QToolBar: Toolbar populated by ``_populate_toolbar``.
        """
        toolbar = OverflowToolBar("Panel Tools", self)
        toolbar.setMovable(False)
        toolbar.setFixedHeight(compute_toolbar_height(self))
        self._toolbar = toolbar
        self._populate_toolbar(toolbar)
        return toolbar

    @override
    def changeEvent(self, a0: QEvent | None) -> None:
        """Re-derive the toolbar height when the panel's font changes.

        Args:
            a0: The change event.
        """
        super().changeEvent(a0)
        if a0 is not None and a0.type() == QEvent.Type.FontChange and self._toolbar is not None:
            self._toolbar.setFixedHeight(compute_toolbar_height(self))

    def _populate_toolbar(self, _toolbar: QToolBar) -> None:
        """Add panel-specific controls to the toolbar.

        Override in subclasses to populate with buttons, labels, and
        inputs.  The toolbar is already configured with fixed height
        and immovable.

        Args:
            _toolbar: The toolbar to populate.
        """

    def _create_content(self) -> QWidget:
        """Create the main content widget below the toolbar.

        Override in subclasses to build splitters, tabs, and views.

        Returns:
            QWidget: The content widget.
        """
        return QWidget(self)

    def _cleanup(self) -> None:
        """Perform panel-specific cleanup during ``stop_tool``.

        Override in subclasses to shut down bridges, stop timers, or release resources.
        """

    @staticmethod
    def _add_tool_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
        *,
        enabled: bool = True,
    ) -> QPushButton:
        """Create a primary action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.
            enabled: Initial enabled state.

        Returns:
            QPushButton: The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("tool_button")
        btn.setEnabled(enabled)
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_secondary_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
    ) -> QPushButton:
        """Create a secondary action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.

        Returns:
            QPushButton: The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("secondary_button")
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_danger_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
        *,
        enabled: bool = True,
    ) -> QPushButton:
        """Create a danger/destructive action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.
            enabled: Initial enabled state.

        Returns:
            QPushButton: The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("danger_button")
        btn.setEnabled(enabled)
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_toolbar_label(
        toolbar: QToolBar,
        text: str,
    ) -> QLabel:
        """Create a label and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Label text.

        Returns:
            QLabel: The created label.
        """
        label = QLabel(text)
        label.setObjectName("toolbar_label")
        toolbar.addWidget(label)
        return label

    @staticmethod
    def _add_toolbar_input(
        toolbar: QToolBar,
        hint_text: str,
        *,
        max_width: int = 200,
    ) -> QLineEdit:
        """Create a line edit with hint text and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            hint_text: Greyed-out hint shown when the field is empty.
            max_width: Maximum widget width in pixels.

        Returns:
            QLineEdit: The created line edit.
        """
        line_edit = QLineEdit()
        line_edit.setPlaceholderText(hint_text)
        line_edit.setMaximumWidth(max_width)
        line_edit.setMinimumHeight(compute_control_min_height(toolbar))
        toolbar.addWidget(line_edit)
        return line_edit

    @staticmethod
    def _make_scrollable(
        inner: QWidget,
        *,
        min_height: int = _CONTROL_SCROLL_MIN_HEIGHT,
    ) -> QScrollArea:
        """Wrap a control cluster in a scroll area so it scrolls instead of clipping.

        Thin wrapper around :func:`make_scrollable` kept for existing subclass
        call sites (``self._make_scrollable(...)``).

        Args:
            inner: The control-cluster widget to make scrollable.
            min_height: Minimum height reserved for the scroll viewport so the
                controls stay usable when the surrounding splitter is short.

        Returns:
            QScrollArea: A frameless, transparent scroll area wrapping ``inner``.
        """
        return make_scrollable(inner, min_height=min_height)

    @staticmethod
    def _make_control_row(row: QHBoxLayout) -> QScrollArea:
        """Wrap a dense horizontal control row so it scrolls sideways instead of crushing its controls.

        Thin wrapper around :func:`make_control_row` kept for existing
        subclass call sites (``self._make_control_row(...)``).

        Args:
            row: The populated horizontal layout to host.

        Returns:
            QScrollArea: A frameless, fixed-height scroll area wrapping the row.
        """
        return make_control_row(row)

    @staticmethod
    def _add_tool_menu(
        toolbar: QToolBar,
        title: str,
        entries: Sequence[ToolMenuEntry],
    ) -> dict[str, QAction]:
        """Group related actions under a single dropdown tool button.

        Replaces a run of individual toolbar buttons with one compact
        ``QToolButton`` whose menu exposes each entry, reducing the number of
        top-level toolbar items so fewer controls spill into the overflow
        popup. Each returned action supports ``setEnabled``/``setText`` so
        callers can keep driving enable-state and label toggles exactly as they
        did with the original buttons.

        Args:
            toolbar: Target toolbar.
            title: Text shown on the dropdown button.
            entries: Ordered menu entries to expose under the button.

        Returns:
            dict[str, QAction]: Mapping of entry label to its created action.
        """
        button = QToolButton()
        button.setText(title)
        button.setObjectName("tool_menu_button")
        button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(button)
        actions: dict[str, QAction] = {}
        for entry in entries:
            action = QAction(entry.label, menu)
            action.setEnabled(entry.enabled)
            action.setToolTip(entry.label)
            action.triggered.connect(entry.handler)
            menu.addAction(action)
            actions[entry.label] = action
        button.setMenu(menu)
        toolbar.addWidget(button)
        return actions

    def _set_status(self, text: str) -> None:
        """Update the status label text (null-safe).

        Args:
            text: New status text.
        """
        if self.status_label is not None:
            self.status_label.setText(text)

    def _invalid_input(
        self,
        event: str,
        *,
        input_text: str,
        console_msg: str,
        logger: structlog.stdlib.BoundLogger,
        **context: object,
    ) -> None:
        """Log a structured user-input parse failure and surface a message on the panel console.

        Centralises the pattern used across analysis panels where a ``ValueError`` raised
        while parsing user input must both be logged structurally for diagnostics and
        surfaced as a human-readable line on the panel console widget. The console widget
        is discovered by attribute name (``_console_output``, ``_console``, ``_output``)
        so panels with differing naming conventions can share this helper. If none of
        those attributes exist or the resolved attribute is not a ``QPlainTextEdit``,
        the message is logged but no console line is appended.

        Args:
            event: Snake_case structured-log event name
                (e.g. ``"x64dbg_run_to_invalid_address"``).
            input_text: The raw input text that failed to parse. Stored under the
                ``input_text`` structured key for later querying.
            console_msg: Human-readable message appended verbatim to the resolved
                panel console widget.
            logger: The calling module's ``_logger`` instance. Passed explicitly so the
                emitted event is attributed to the call site, not to ``base_panel``.
            **context: Additional structured kwargs (``operation``, ``field``,
                ``trace_id``, etc.) forwarded to the logger as keyword arguments.
        """
        logger.warning("panel_validation_failed", op_event=event, input_text=input_text, **context)
        console: object | None = getattr(self, "_console_output", None) or getattr(self, "_console", None) or getattr(self, "_output", None)
        if isinstance(console, QPlainTextEdit):
            console.appendPlainText(console_msg)

    def _run_async(
        self,
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
    ) -> None:
        """Run a bridge coroutine asynchronously with signal-based delivery.

        Args:
            coro: Coroutine to execute.
            on_success: Callback receiving the result on the main thread.
            on_error: Callback receiving the exception on the main thread.
        """
        _logger.debug("run_async_dispatched", panel=type(self).__name__)
        run_bridge_coroutine_async(coro, on_success, on_error, self)

    def start_tool(self) -> bool:
        """Start the panel and emit the ``tool_started`` signal.

        Returns:
            bool: True always since native panels are always ready.
        """
        _logger.debug("tool_started", panel=type(self).__name__)
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop the panel, run cleanup, and emit ``tool_closed``.

        Returns:
            bool: True if cleanup completed.
        """
        _logger.debug("tool_stopping", panel=type(self).__name__)
        self._cleanup()
        self.tool_closed.emit()
        return True
