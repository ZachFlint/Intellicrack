# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Session manager dialog for Intellicrack.

This module provides the UI for managing analysis sessions, including listing, loading, saving, and deleting sessions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Literal, cast, override

from PyQt6.QtCore import QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLayoutItem,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.config import get_config_dir
from intellicrack.core.logging import get_logger
from intellicrack.core.types import BinaryInfo, Message
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged


_logger = get_logger(__name__)

_DIALOG_WIDTH: Final[int] = 800
_DIALOG_HEIGHT: Final[int] = 500
_SPLIT_LEFT: Final[int] = 450
_SPLIT_RIGHT: Final[int] = 350
_CONFIRM_DIALOG_WIDTH: Final[int] = 400
_CONFIRM_DIALOG_HEIGHT: Final[int] = 200

if TYPE_CHECKING:
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.session import Session, SessionManager, SessionMetadata

MESSAGE_PREVIEW_MAX_LENGTH = 100


class _FlowLayout(QLayout):
    """Simple horizontal flow layout used to lay out tag chips.

    Qt does not ship a flow layout out of the box; this implementation wraps child widgets onto additional rows when the available width is
    exceeded so a long list of tag chips renders cleanly inside the session manager dialog without horizontal scrolling.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        margin: int = 0,
        horizontal_spacing: int = 6,
        vertical_spacing: int = 6,
    ) -> None:
        """Initialize the flow layout.

        Args:
            parent: Parent widget owning the layout, if any.
            margin: Outer margin in pixels applied uniformly on all
                sides.
            horizontal_spacing: Horizontal gap between adjacent items.
            vertical_spacing: Vertical gap between adjacent rows.
        """
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self._items: list[QLayoutItem] = []
        self._horizontal_spacing: int = horizontal_spacing
        self._vertical_spacing: int = vertical_spacing

    @override
    def addItem(self, a0: QLayoutItem | None) -> None:
        """Append a layout item to the flow.

        Args:
            a0: ``QLayoutItem`` to append. ``None`` is ignored.
        """
        if a0 is None:
            return
        self._items.append(a0)

    @override
    def count(self) -> int:
        """Return the number of items currently managed by the layout.

        Returns:
            int: Item count.
        """
        return len(self._items)

    @override
    def itemAt(self, index: int) -> QLayoutItem | None:
        """Return the item at ``index``.

        Args:
            index: Zero-based item index.

        Returns:
            QLayoutItem | None: Item at ``index`` or ``None`` when the
            index is out of range.
        """
        return self._items[index] if 0 <= index < len(self._items) else None

    @override
    def takeAt(self, index: int) -> QLayoutItem | None:
        """Remove and return the item at ``index``.

        Args:
            index: Zero-based item index.

        Returns:
            QLayoutItem | None: The removed item, or ``None`` when the
            index is out of range.
        """
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    @override
    def expandingDirections(self) -> Qt.Orientation:
        """Indicate that the layout does not expand in any direction.

        Returns:
            Qt.Orientation: Empty orientation flag set.
        """
        return Qt.Orientation(0)

    @override
    def hasHeightForWidth(self) -> bool:
        """Report that height depends on width.

        Returns:
            bool: Always ``True``.
        """
        return True

    @override
    def heightForWidth(self, a0: int) -> int:
        """Compute the height needed when the layout is constrained to ``a0``.

        Args:
            a0: Width budget, in pixels.

        Returns:
            int: Height required to fit every chip given ``a0``.
        """
        return self._do_layout(QRect(0, 0, a0, 0), test_only=True)

    @override
    def setGeometry(self, a0: QRect) -> None:
        """Apply ``a0`` as the layout area and place every child item.

        Args:
            a0: Rectangle to lay items out within.
        """
        super().setGeometry(a0)
        self._do_layout(a0, test_only=False)

    @override
    def sizeHint(self) -> QSize:
        """Return the preferred size of the layout.

        Returns:
            QSize: Minimum size that fits every chip.
        """
        return self.minimumSize()

    @override
    def minimumSize(self) -> QSize:
        """Return the minimum size required to fit every chip.

        Returns:
            QSize: Bounding size of all chip items including margins.
        """
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def _do_layout(self, rect: QRect, *, test_only: bool) -> int:
        """Lay out child items inside ``rect``.

        Args:
            rect: Available rectangle.
            test_only: When ``True``, geometry is not assigned; only
                the resulting height is computed.

        Returns:
            int: Height (in pixels) consumed by the laid-out items.
        """
        margins = self.contentsMargins()
        effective_rect = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x = effective_rect.x()
        y = effective_rect.y()
        line_height = 0

        for item in self._items:
            widget = item.widget()
            if widget is None:
                continue
            item_size = item.sizeHint()
            next_x = x + item_size.width() + self._horizontal_spacing
            if next_x - self._horizontal_spacing > effective_rect.right() and line_height > 0:
                x = effective_rect.x()
                y = y + line_height + self._vertical_spacing
                next_x = x + item_size.width() + self._horizontal_spacing
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(x, y, item_size.width(), item_size.height()))
            x = next_x
            line_height = max(line_height, item_size.height())

        return y + line_height - rect.y() + margins.bottom()


class TagChipsWidget(QWidget):
    """Widget that renders session tags as click-to-remove chips.

    Provides an inline editor for adding new tags and exposes signals so
    callers can react to tag changes (for example, to persist the
    session). Each tag renders as a horizontal pill containing the tag
    text and a small "x" button that removes the tag.

    Attributes:
        tag_added: Signal emitted with the new tag string after a tag
            has been added to the wired session.
        tag_removed: Signal emitted with the tag string after a tag has
            been removed from the wired session.
        tags_changed: Convenience signal emitted with the full list of
            current tags whenever a tag is added or removed.
    """

    tag_added: ClassVar[pyqtSignal] = pyqtSignal(str)
    tag_removed: ClassVar[pyqtSignal] = pyqtSignal(str)
    tags_changed: ClassVar[pyqtSignal] = pyqtSignal(list)

    def __init__(
        self,
        session: Session | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tag chips widget.

        Args:
            session: Optional ``Session`` whose tags will be rendered
                and mutated. When ``None`` the widget renders an empty
                state until :meth:`set_session` is called.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._session: Session | None = session
        self._chip_buttons: dict[str, QPushButton] = {}
        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        """Construct the chip flow area and the inline add-tag editor."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        chips_frame = QFrame()
        chips_frame.setObjectName("tagChipsFrame")
        chips_frame.setFrameShape(QFrame.Shape.StyledPanel)
        chips_frame.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        self._chips_layout = _FlowLayout(chips_frame, margin=4)
        chips_frame.setLayout(self._chips_layout)
        self._chips_frame = chips_frame
        layout.addWidget(chips_frame)

        self._empty_label = QLabel("No tags. Add one below.")
        self._empty_label.setStyleSheet("color: palette(mid); font-style: italic;")
        layout.addWidget(self._empty_label)

        editor_row = QHBoxLayout()
        editor_row.setContentsMargins(0, 0, 0, 0)
        editor_row.setSpacing(6)
        self._tag_input = QLineEdit()
        self._tag_input.setPlaceholderText("Add tag…")
        self._tag_input.returnPressed.connect(self._on_add_clicked)
        editor_row.addWidget(self._tag_input)
        self._add_btn = QPushButton("Add Tag")
        self._add_btn.clicked.connect(self._on_add_clicked)
        editor_row.addWidget(self._add_btn)
        layout.addLayout(editor_row)

    def set_session(self, session: Session | None) -> None:
        """Wire this widget to a different ``Session`` instance.

        Args:
            session: Session whose tags should be rendered, or ``None``
                to clear the widget.
        """
        self._session = session
        self.refresh()

    def session(self) -> Session | None:
        """Return the currently wired session.

        Returns:
            Session | None: The session this widget mutates, or ``None``
            when no session is wired.
        """
        return self._session

    def refresh(self) -> None:
        """Rebuild the chip layout from the wired session's tags."""
        for chip_btn in list(self._chip_buttons.values()):
            self._chips_layout.removeWidget(chip_btn)
            chip_btn.setParent(None)
            chip_btn.deleteLater()
        self._chip_buttons.clear()

        tags: list[str] = list(self._session.tags) if self._session is not None else []
        for tag in tags:
            self._add_chip(tag)

        self._empty_label.setVisible(not tags)
        self._add_btn.setEnabled(self._session is not None)
        self._tag_input.setEnabled(self._session is not None)

    def _add_chip(self, tag: str) -> None:
        """Create and insert a chip button for ``tag``.

        Args:
            tag: Tag value to display.
        """
        chip = QPushButton()
        style = self.style()
        if style is not None:
            chip.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DialogCloseButton))
        chip.setText(f" {tag} ")
        chip.setObjectName("tagChip")
        chip.setProperty("tag", tag)
        chip.setCursor(Qt.CursorShape.PointingHandCursor)
        chip.setToolTip(f"Remove tag '{tag}'")
        chip.setStyleSheet(
            "QPushButton#tagChip { "
            "padding: 2px 8px; "
            "border: 1px solid palette(mid); "
            "border-radius: 10px; "
            "background: palette(button); "
            "}"
            "QPushButton#tagChip:hover { background: palette(highlight); color: palette(highlighted-text); }",
        )
        bound_tag: str = tag

        def _on_clicked(_state: int = 0, t: str = bound_tag) -> None:
            """Handle a tag-chip click and forward the bound tag text.

            Args:
                _state: Unused Qt checked/clicked state.
                t: Tag string captured when the chip was created.
            """
            self._on_chip_clicked(t)

        chip.clicked.connect(_on_clicked)
        self._chips_layout.addWidget(chip)
        self._chip_buttons[tag] = chip

    def _on_add_clicked(self) -> None:
        """Add the text in the input box as a new tag on the session."""
        raw_text = self._tag_input.text()
        text = raw_text.strip()
        if not text or self._session is None:
            return
        try:
            added = self._session.add_tag(text)
        except ValueError as exc:
            _logger.warning("tag_add_rejected", tag=raw_text, error=str(exc))
            QMessageBox.warning(self, "Invalid Tag", str(exc))
            return
        self._tag_input.clear()
        if added:
            self._add_chip(text)
            self._empty_label.setVisible(False)
            self.tag_added.emit(text)
            self.tags_changed.emit(list(self._session.tags))
            _logger.debug("tag_added", tag=text, session_id=self._session.id)

    def _on_chip_clicked(self, tag: str) -> None:
        """Remove ``tag`` from the wired session and update the chips.

        Args:
            tag: Tag whose chip was clicked.
        """
        if self._session is None:
            return
        removed = self._session.remove_tag(tag)
        if not removed:
            return
        chip_btn = self._chip_buttons.pop(tag, None)
        if chip_btn is not None:
            self._chips_layout.removeWidget(chip_btn)
            chip_btn.setParent(None)
            chip_btn.deleteLater()
        self._empty_label.setVisible(not self._session.tags)
        self.tag_removed.emit(tag)
        self.tags_changed.emit(list(self._session.tags))
        _logger.info("tag_removed", tag=tag, session_id=self._session.id)


class SessionManagerDialog(QDialog):
    """Dialog for managing analysis sessions.

    Allows users to:
    - View list of saved sessions
    - Load previous sessions
    - Save current session
    - Delete old sessions
    - Export/import sessions

    Attributes:
        session_loaded: Signal emitted when a session is loaded.
        session_deleted: Signal emitted when a session is deleted.
        SESSIONS_DIR: Directory where serialized session files are stored.
    """

    session_loaded: ClassVar[pyqtSignal] = pyqtSignal(str)
    session_deleted: ClassVar[pyqtSignal] = pyqtSignal(str)

    SESSIONS_DIR: ClassVar[Path] = get_config_dir() / "sessions"

    def __init__(
        self,
        session_manager: SessionManager | None = None,
        current_session_id: str | None = None,
        parent: QWidget | None = None,
        current_session: Session | None = None,
    ) -> None:
        """Initialize the SessionManagerDialog with session state.

        Args:
            session_manager: Session manager for loading and saving sessions.
            current_session_id: ID of the currently active session. When
                omitted but ``current_session`` is supplied, this is derived
                from ``current_session.id`` so the active-session-protection
                guard and the bold row highlighting always agree with the
                session actually wired into the Tags panel.
            parent: Parent widget.
            current_session: Currently active in-memory ``Session``
                instance, when known. When supplied, the tag chips
                widget is wired directly to this session so add/remove
                operations mutate the live session object.
        """
        super().__init__(parent)
        self._manager = session_manager
        self._current_session = current_session
        self._current_session_id = (
            current_session_id if current_session_id is not None else (current_session.id if current_session is not None else None)
        )
        self._sessions: list[dict[str, object]] = []
        self._orchestrator: Orchestrator | None = None

        if self._manager is None and self._current_session is None:
            self._adopt_parent_orchestrator(parent)

        if self._manager is None:
            _logger.warning(
                "session_manager_dialog_no_manager_wired",
                message=(
                    "SessionManagerDialog was constructed without a session_manager; falling back to the "
                    "on-disk sidecar store at SESSIONS_DIR instead of the live SessionStore, and the tag "
                    "editor will remain disabled unless current_session is also supplied."
                ),
                sessions_dir=str(self.SESSIONS_DIR),
                current_session_supplied=self._current_session is not None,
            )

        was_present = self.SESSIONS_DIR.exists()
        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        if not was_present:
            _logger.info("session_manager_sessions_dir_created", path=str(self.SESSIONS_DIR))
        else:
            _logger.debug("session_manager_sessions_dir_present", path=str(self.SESSIONS_DIR))

        self._setup_ui()
        self._load_sessions()

        self.setWindowTitle("Session Manager")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

    @classmethod
    def from_orchestrator(cls, orchestrator: Orchestrator, parent: QWidget | None = None) -> SessionManagerDialog:
        """Build a dialog wired to ``orchestrator``'s live session manager and active session.

        Reads the ``SessionManager`` and active ``Session`` off
        ``orchestrator`` so callers do not need to reach into orchestrator
        internals themselves. This keeps the dialog backed by the same
        SQLite-backed ``SessionStore`` the rest of the application uses
        instead of silently falling back to the on-disk sidecar store, and
        ensures the active-session-protection guard and the tags editor are
        wired to the true active session rather than being permanently
        disabled.

        Args:
            orchestrator: Orchestrator instance whose session manager and
                active session should be used to construct the dialog.
            parent: Parent widget.

        Returns:
            SessionManagerDialog: Dialog instance wired to
            ``orchestrator``'s live session manager and active session.
        """
        session_manager, current_session = cls._extract_orchestrator_state(orchestrator)
        dialog = cls(
            session_manager=session_manager,
            current_session_id=current_session.id if current_session is not None else None,
            parent=parent,
            current_session=current_session,
        )
        dialog._orchestrator = orchestrator
        return dialog

    @staticmethod
    def _extract_orchestrator_state(orchestrator: Orchestrator) -> tuple[SessionManager | None, Session | None]:
        """Read the live session manager and active session off ``orchestrator``.

        Args:
            orchestrator: Orchestrator instance whose internal session
                manager and active session should be read.

        Returns:
            tuple[SessionManager | None, Session | None]: The
            orchestrator's internal ``SessionManager`` (when present) and
            its current active ``Session``.
        """
        session_manager = cast("SessionManager | None", getattr(orchestrator, "_sessions", None))
        return session_manager, orchestrator.current_session

    def _adopt_parent_orchestrator(self, parent: QWidget | None) -> None:
        """Wire this dialog to ``parent``'s live orchestrator, when available.

        Production call sites that construct this dialog with only
        ``SessionManagerDialog(parent=self)`` (for example
        ``MainWindow._on_load_session``) rely on ``parent`` exposing the
        application's ``Orchestrator`` through a private ``_orchestrator``
        attribute, the pattern used throughout ``MainWindow``. When present,
        this wires the dialog to the orchestrator's SQLite-backed
        ``SessionManager`` and active ``Session`` instead of silently
        falling back to the empty/stale on-disk sidecar store, so the
        active-session-protection guard and the tags editor operate on the
        real session state.

        Args:
            parent: Parent widget to inspect for an ``_orchestrator``
                attribute. When ``None`` or the attribute is absent, this
                is a no-op and the dialog keeps its disk-fallback
                behaviour.
        """
        orchestrator = getattr(parent, "_orchestrator", None)
        if orchestrator is None:
            return
        typed_orchestrator = cast("Orchestrator", orchestrator)
        session_manager, current_session = self._extract_orchestrator_state(typed_orchestrator)
        self._manager = session_manager
        self._current_session = current_session
        self._orchestrator = typed_orchestrator
        if current_session is not None:
            self._current_session_id = current_session.id

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._create_left_panel())
        splitter.addWidget(self._create_right_panel())
        splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        layout.addWidget(splitter)
        layout.addLayout(self._create_bottom_buttons())

    def _create_left_panel(self) -> QWidget:
        """Create the left panel with session table.

        Returns:
            QWidget: Widget containing the session table and action buttons.
        """
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        self._setup_session_table()
        panel_layout.addWidget(self._session_table)
        panel_layout.addLayout(self._create_table_buttons())
        return panel

    def _setup_session_table(self) -> None:
        """Initialize and configure the session table widget."""
        self._session_table = QTableWidget()
        self._session_table.setColumnCount(4)
        self._session_table.setHorizontalHeaderLabels(["Name", "Created", "Modified", "Messages"])
        self._session_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._session_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._session_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        sm_v_header = self._session_table.verticalHeader()
        if sm_v_header is not None:
            sm_v_header.setVisible(False)
        header = self._session_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._session_table.itemSelectionChanged.connect(self._on_selection_changed)
        self._session_table.itemDoubleClicked.connect(self._on_double_click)

    def _create_table_buttons(self) -> QHBoxLayout:
        """Create refresh and delete buttons for the table.

        Returns:
            QHBoxLayout: Layout containing the table action buttons.
        """
        layout = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._load_sessions)
        layout.addWidget(self._refresh_btn)
        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._delete_session)
        layout.addWidget(self._delete_btn)
        layout.addStretch()
        return layout

    def _create_right_panel(self) -> QWidget:
        """Create the right panel with details and preview.

        Returns:
            QWidget: Widget containing session details and preview.
        """
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.addWidget(self._create_details_group())
        panel_layout.addWidget(self._create_tags_group())
        panel_layout.addWidget(self._create_preview_group())
        return panel

    def _create_tags_group(self) -> QGroupBox:
        """Create the tags group box backed by ``TagChipsWidget``.

        Returns:
            QGroupBox: Group box containing the tag chips widget.
        """
        group = QGroupBox("Tags")
        layout = QVBoxLayout()
        self._tag_chips = TagChipsWidget(self._current_session)
        self._tag_chips.tags_changed.connect(self._on_tags_changed)
        layout.addWidget(self._tag_chips)
        group.setLayout(layout)
        return group

    def _on_tags_changed(self, _tags: list[str]) -> None:
        """Persist the current session after a tag was added/removed.

        Args:
            _tags: New list of tags on the wired session (unused; the
                widget exposes it for consumers that want to mirror the
                state).
        """
        manager = self._manager
        session = self._current_session
        if manager is None or session is None:
            return
        run_bridge_coroutine_logged(
            manager.update(session),
            on_success=None,
            on_error=None,
            parent=self,
            event="session_tag_persist",
            logger=_logger,
            level="info",
            session_id=session.id,
        )

    @staticmethod
    def _set_elided_detail(label: QLabel, text: str) -> None:
        """Set a detail label's text with a full-text tooltip and elision.

        The full value is always preserved as the label's tooltip so long
        provider names or model identifiers remain discoverable, while the
        displayed text is right-elided to the label's current width to avoid
        silently clipping without an ellipsis indicator.

        Args:
            label: Detail label to update.
            text: Full text value to display and expose as the tooltip.
        """
        label.setToolTip(text)
        width = label.width()
        if width > 0:
            metrics = QFontMetrics(label.font())
            label.setText(metrics.elidedText(text, Qt.TextElideMode.ElideRight, width))
        else:
            label.setText(text)

    def _create_details_group(self) -> QGroupBox:
        """Create the session details group box.

        Returns:
            QGroupBox: Group box containing session detail labels.
        """
        group = QGroupBox("Session Details")
        form = QFormLayout()
        self._id_label = QLabel("-")
        self._id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("ID:", self._id_label)
        self._created_label = QLabel("-")
        form.addRow("Created:", self._created_label)
        self._modified_label = QLabel("-")
        form.addRow("Modified:", self._modified_label)
        self._provider_label = QLabel("-")
        form.addRow("Provider:", self._provider_label)
        self._model_label = QLabel("-")
        form.addRow("Model:", self._model_label)
        self._messages_label = QLabel("-")
        form.addRow("Messages:", self._messages_label)
        self._binaries_label = QLabel("-")
        form.addRow("Binaries:", self._binaries_label)
        group.setLayout(form)
        return group

    def _create_preview_group(self) -> QGroupBox:
        """Create the preview group box.

        Returns:
            QGroupBox: Group box containing the preview text widget.
        """
        group = QGroupBox("Preview")
        layout = QVBoxLayout()
        self._preview_text = QTextEdit()
        self._preview_text.setReadOnly(True)
        self._preview_text.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 10px;")
        layout.addWidget(self._preview_text)
        group.setLayout(layout)
        return group

    def _create_bottom_buttons(self) -> QHBoxLayout:
        """Create the bottom button row.

        Returns:
            QHBoxLayout: Layout containing export, import, load and close buttons.
        """
        layout = QHBoxLayout()
        export_btn = QPushButton("Export...")
        export_btn.clicked.connect(self._export_session)
        layout.addWidget(export_btn)
        import_btn = QPushButton("Import...")
        import_btn.clicked.connect(self._import_session)
        layout.addWidget(import_btn)
        layout.addStretch()
        self._load_btn = QPushButton("Load Session")
        self._load_btn.setEnabled(False)
        self._load_btn.clicked.connect(self._load_selected_session)
        layout.addWidget(self._load_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        layout.addWidget(close_btn)
        return layout

    def _load_sessions(self) -> None:
        """Load sessions from the session manager or filesystem."""
        self._session_table.setRowCount(0)
        self._sessions = []

        if self._manager is not None:
            try:
                metadata_list = self._manager.list_sessions()
                for metadata in metadata_list:
                    session_data = self._metadata_to_dict(metadata)
                    self._sessions.append(session_data)
            except (AttributeError, TypeError) as e:
                _logger.warning("session_list_failed_using_disk_fallback", error=str(e))
                self._load_sessions_from_disk()
        else:
            self._load_sessions_from_disk()

        for session in self._sessions:
            row = self._session_table.rowCount()
            self._session_table.insertRow(row)

            name_item = QTableWidgetItem(str(session["name"]))
            name_item.setData(Qt.ItemDataRole.UserRole, session["id"])
            self._session_table.setItem(row, 0, name_item)

            created_at = session.get("created_at")
            if isinstance(created_at, datetime):
                created_str = created_at.strftime("%Y-%m-%d %H:%M")
            elif isinstance(created_at, str):
                created_str = created_at[:16]
            else:
                created_str = "-"
            self._session_table.setItem(row, 1, QTableWidgetItem(created_str))

            updated_at = session.get("updated_at")
            if isinstance(updated_at, datetime):
                modified_str = updated_at.strftime("%Y-%m-%d %H:%M")
            elif isinstance(updated_at, str):
                modified_str = updated_at[:16]
            else:
                modified_str = "-"
            self._session_table.setItem(row, 2, QTableWidgetItem(modified_str))

            msg_count = str(session.get("message_count", 0))
            self._session_table.setItem(row, 3, QTableWidgetItem(msg_count))

            if session["id"] == self._current_session_id:
                for col in range(4):
                    if item := self._session_table.item(row, col):
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)

        _logger.info("session_list_refreshed", count=len(self._sessions))

    @staticmethod
    def _read_session_file(session_file: Path) -> dict[str, object]:
        """Read and normalise a single session JSON file.

        Args:
            session_file: Path to the session JSON file.

        Returns:
            dict[str, object]: Session payload dictionary with id, name, and
            datetime fields normalised.
        """
        with session_file.open(encoding="utf-8") as f:
            session_data: dict[str, object] = json.load(f)

        if "id" not in session_data:
            session_data["id"] = session_file.stem

        if "name" not in session_data:
            session_data["name"] = session_file.stem

        SessionManagerDialog._normalise_session_datetime(session_data, "created_at")
        SessionManagerDialog._normalise_session_datetime(session_data, "updated_at")
        return session_data

    @staticmethod
    def _normalise_session_datetime(session_data: dict[str, object], field: str) -> None:
        """Convert an ISO-format datetime string in ``session_data`` to a ``datetime``.

        Args:
            session_data: Session payload dictionary to mutate in place.
            field: Name of the datetime field to normalise.
        """
        raw = session_data.get(field)
        if not isinstance(raw, str):
            return
        try:
            session_data[field] = datetime.fromisoformat(raw)
        except ValueError:
            _logger.warning("session_datetime_parse_failed", field=field, session_id=session_data.get("id"))
            session_data[field] = datetime.now(tz=UTC)

    def _load_sessions_from_disk(self) -> None:
        """Load sessions from disk storage."""
        if not self.SESSIONS_DIR.exists():
            return

        for session_file in self.SESSIONS_DIR.glob("*.json"):
            try:
                session_data = self._read_session_file(session_file)
            except (json.JSONDecodeError, OSError) as e:
                _logger.warning(
                    "session_file_load_failed",
                    file=str(session_file),
                    error=str(e),
                )
                continue
            self._sessions.append(session_data)

        sort_sentinel = datetime.min.replace(tzinfo=UTC)

        def _sort_key(s: dict[str, object]) -> datetime:
            """Extract a session's sort timestamp, defaulting when missing.

            Args:
                s: Session metadata dictionary loaded from disk.

            Returns:
                datetime: ``updated_at`` when present, otherwise the sort sentinel.
            """
            val = s.get("updated_at")
            return val if isinstance(val, datetime) else sort_sentinel

        self._sessions.sort(key=_sort_key, reverse=True)

    @staticmethod
    def _metadata_to_dict(metadata: SessionMetadata) -> dict[str, object]:
        """Convert a SessionMetadata object to a dictionary.

        Args:
            metadata: SessionMetadata object to convert.

        Returns:
            dict[str, object]: Dictionary representation of the session metadata.
        """
        try:
            return {
                "id": metadata.id,
                "name": metadata.name,
                "created_at": metadata.created_at,
                "updated_at": metadata.updated_at,
                "message_count": metadata.message_count,
                "provider": str(metadata.provider.value) if hasattr(metadata.provider, "value") else str(metadata.provider),
                "model": metadata.model,
                "binaries": [],
                "binary_count": metadata.binary_count,
            }
        except (AttributeError, TypeError) as e:
            _logger.warning("metadata_conversion_failed", error=str(e))
            return {
                "id": str(metadata) if metadata else "unknown",
                "name": "Unknown Session",
                "created_at": datetime.now(tz=UTC),
                "updated_at": datetime.now(tz=UTC),
                "message_count": 0,
                "provider": "-",
                "model": "-",
                "binaries": [],
                "binary_count": 0,
            }

    def _on_selection_changed(self) -> None:
        """Handle session selection change."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        if selected_rows := sel_model.selectedRows():
            row = selected_rows[0].row()
            name_item = self._session_table.item(row, 0)
            if name_item is None:
                return
            session_id = name_item.data(Qt.ItemDataRole.UserRole)

            if session := next((s for s in self._sessions if s["id"] == session_id), None):
                self._update_details(session)
                self._load_btn.setEnabled(True)
                self._delete_btn.setEnabled(session["id"] != self._current_session_id)
                _logger.info("session_selected", session_id=session_id)
        else:
            self._clear_details()
            self._load_btn.setEnabled(False)
            self._delete_btn.setEnabled(False)

    def _on_double_click(self, _item: QTableWidgetItem) -> None:
        """Handle double-click on session.

        Args:
            _item: The double-clicked item.
        """
        self._load_selected_session()

    def _update_details(self, session: dict[str, object]) -> None:
        """Update the details panel with session info.

        Args:
            session: Session data dictionary.
        """
        self._id_label.setText(str(session["id"]))

        created_at = session.get("created_at")
        if isinstance(created_at, datetime):
            self._created_label.setText(created_at.strftime("%Y-%m-%d %H:%M:%S"))
        elif isinstance(created_at, str):
            self._created_label.setText(created_at)
        else:
            self._created_label.setText("-")

        updated_at = session.get("updated_at")
        if isinstance(updated_at, datetime):
            self._modified_label.setText(updated_at.strftime("%Y-%m-%d %H:%M:%S"))
        elif isinstance(updated_at, str):
            self._modified_label.setText(updated_at)
        else:
            self._modified_label.setText("-")

        provider_val = session.get("provider")
        self._set_elided_detail(self._provider_label, str(provider_val) if isinstance(provider_val, str) else "-")
        model_val = session.get("model")
        self._set_elided_detail(self._model_label, str(model_val) if isinstance(model_val, str) else "-")
        self._messages_label.setText(str(session.get("message_count", 0)))

        binaries_raw = session.get("binaries")
        binaries: list[str] = [str(b) for b in cast("list[object]", binaries_raw)] if isinstance(binaries_raw, list) else []
        self._binaries_label.setText(", ".join(binaries) if binaries else "-")

        preview_text = f"Session: {session['name']}\n"
        preview_text += f"Provider: {provider_val or 'N/A'}\n"
        preview_text += f"Model: {model_val or 'N/A'}\n"
        preview_text += "\nBinaries analyzed:\n"
        for binary in binaries:
            preview_text += f"  - {binary}\n"
        preview_text += f"\nTotal messages: {session.get('message_count', 0)}"

        messages_raw = session.get("messages")
        if isinstance(messages_raw, list) and messages_raw:
            preview_text += "\n\nRecent messages:\n"
            recent_messages = cast("list[object]", messages_raw[-3:])
            for msg_obj in recent_messages:
                if isinstance(msg_obj, dict):
                    msg_dict = cast("dict[str, object]", msg_obj)
                    role = str(msg_dict.get("role", "unknown"))
                    content_raw = msg_dict.get("content", "")
                    content_str = str(content_raw) if content_raw else ""
                    if len(content_str) > MESSAGE_PREVIEW_MAX_LENGTH:
                        content_str = f"{content_str[:MESSAGE_PREVIEW_MAX_LENGTH]}..."
                    preview_text += f"  [{role}]: {content_str}\n"

        self._preview_text.setText(preview_text)

    def _clear_details(self) -> None:
        """Clear the details panel."""
        self._id_label.setText("-")
        self._created_label.setText("-")
        self._modified_label.setText("-")
        self._provider_label.setText("-")
        self._model_label.setText("-")
        self._messages_label.setText("-")
        self._binaries_label.setText("-")
        self._preview_text.clear()

    def _load_selected_session(self) -> None:
        """Load the currently selected session and restore it into the live UI."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)

        if session_id == self._current_session_id:
            QMessageBox.information(
                self,
                "Session Active",
                "This session is already active.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Load Session",
            "Load this session? Current session progress will be saved.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        _logger.info("session_load_requested", session_id=session_id)
        if self._manager is not None:
            self._load_session_via_manager(session_id)
        else:
            self._load_session_from_disk(session_id)

    def _load_session_via_manager(self, session_id: str) -> None:
        """Load ``session_id`` through the session manager without blocking the GUI thread.

        Validates ``session_id`` against the already-listed ``self._sessions``
        first -- mirroring the same synchronous guard ``_load_session_from_disk``
        already applies -- so a stale selection (the row was listed, but the
        backing session was removed by a concurrent delete before the load
        click landed) surfaces a warning immediately instead of dispatching a
        bridge coroutine that can only report "not found" after a cross-thread
        round trip. Once validated, prefers ``Orchestrator.load_session`` when
        this dialog was wired to a live orchestrator (via ``from_orchestrator``
        or the parent-adoption path), since that also updates the
        orchestrator's own ``current_session`` pointer, tool-bridge session
        binding, and state -- bookkeeping that calling ``SessionManager.load``
        directly would skip, leaving the orchestrator pointed at the stale
        session even though the UI now shows the newly loaded one. Falls back
        to ``SessionManager.load`` directly when no orchestrator is wired (for
        example, a dialog embedded with only a bare ``SessionManager``). Both
        are dispatched through the non-blocking bridge worker, matching the
        pattern already used for delete/import/tag-persist so the Qt event
        loop stays responsive while the backing ``SessionStore`` performs its
        SQLite read. Either path persists the previously-current session
        before switching, honouring the confirmation prompt's "Current
        session progress will be saved" promise.

        Args:
            session_id: Session identifier.
        """
        if not any(s["id"] == session_id for s in self._sessions):
            _logger.warning("session_load_selection_stale", session_id=session_id)
            QMessageBox.warning(self, "Load Failed", f"Session no longer exists: {session_id}")
            return

        orchestrator = self._orchestrator
        if orchestrator is not None:
            coro = orchestrator.load_session(session_id)
        else:
            manager = self._manager
            if manager is None:
                return
            coro = manager.load(session_id)
        run_bridge_coroutine_logged(
            coro,
            on_success=lambda result: self._on_load_session_succeeded(session_id, result),
            on_error=lambda exc: self._on_load_session_failed(session_id, exc),
            parent=self,
            event="session_load",
            logger=_logger,
            level="info",
            session_id=session_id,
        )

    def _on_load_session_succeeded(self, session_id: str, result: object) -> None:
        """Restore a successfully loaded session into the live UI.

        Args:
            session_id: Identifier of the session that was requested to load.
            result: ``Session`` (from ``Orchestrator.load_session``) or
                ``Session | None`` (from ``SessionManager.load``) returned by
                the bridge call. ``None`` means the session id was not found
                in the store.
        """
        if result is None:
            _logger.warning("session_load_not_found", session_id=session_id)
            QMessageBox.warning(self, "Load Failed", f"Session not found: {session_id}")
            return

        messages_raw = getattr(result, "messages", None)
        if not isinstance(messages_raw, list):
            _logger.warning("session_load_malformed", session_id=session_id)
            QMessageBox.warning(self, "Load Failed", f"Session file is malformed: {session_id}")
            return
        messages = cast("list[Message]", messages_raw)

        active_binary = cast("BinaryInfo | None", getattr(result, "active_binary", None))
        self._restore_session_to_ui(messages, active_binary)

        self._current_session = cast("Session", result)
        self._current_session_id = session_id
        _logger.info("session_restored", session_id=session_id, message_count=len(messages))
        self.session_loaded.emit(session_id)
        self.accept()

    def _on_load_session_failed(self, session_id: str, exc: object) -> None:
        """Handle a failed ``SessionManager.load`` bridge call.

        Args:
            session_id: Identifier of the session that failed to load.
            exc: Exception object emitted by the bridge worker on failure.
        """
        error_obj = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
        _logger.warning("session_load_failed", session_id=session_id, error=str(error_obj))
        QMessageBox.warning(self, "Load Failed", f"Failed to load session:\n{error_obj}")

    def _load_session_from_disk(self, session_id: str) -> None:
        """Restore a disk-sidecar session's chat history and active binary into the live UI.

        Used only when no session manager has been wired into the dialog
        (the on-disk sidecar fallback store). Reconstructs ``Message`` and
        ``BinaryInfo`` objects from the already-parsed sidecar dict in
        ``self._sessions`` -- re-reading the file would duplicate the parsing
        already performed by ``_load_sessions_from_disk`` /
        ``_read_session_file`` -- and restores them through the same
        UI-population path used for the manager-backed load.

        Args:
            session_id: Identifier of the session to restore.
        """
        session_data = next((s for s in self._sessions if s["id"] == session_id), None)
        if session_data is None:
            _logger.warning("session_load_from_disk_not_found", session_id=session_id)
            QMessageBox.warning(self, "Load Failed", f"Session not found: {session_id}")
            return

        messages_raw = session_data.get("messages")
        messages: list[Message] = []
        if isinstance(messages_raw, list):
            for item in cast("list[object]", messages_raw):
                if isinstance(item, dict):
                    message = self._message_from_disk_dict(cast("dict[str, object]", item))
                    if message is not None:
                        messages.append(message)
        elif messages_raw is not None:
            _logger.warning("session_load_from_disk_messages_malformed", session_id=session_id)

        active_binary = self._active_binary_from_disk_session(session_data)

        self._restore_session_to_ui(messages, active_binary)
        self._current_session_id = session_id
        _logger.info("session_restored", session_id=session_id, message_count=len(messages))
        self.session_loaded.emit(session_id)
        self.accept()

    @staticmethod
    def _message_from_disk_dict(data: dict[str, object]) -> Message | None:
        """Reconstruct a ``Message`` from a disk-sidecar message dictionary.

        Args:
            data: Raw message dictionary as stored in a sidecar session JSON
                file, matching the ``role``/``content``/``timestamp`` shape
                written for the manager-backed store.

        Returns:
            Message | None: Reconstructed message, or ``None`` when ``data``
            is missing a valid ``role``/``content`` pair.
        """
        role = data.get("role")
        content = data.get("content")
        if role not in {"user", "assistant", "system", "tool"} or not isinstance(content, str):
            return None

        timestamp = datetime.now(tz=UTC)
        timestamp_raw = data.get("timestamp")
        if isinstance(timestamp_raw, str):
            try:
                timestamp = datetime.fromisoformat(timestamp_raw)
            except ValueError:
                _logger.warning("session_load_message_timestamp_invalid", raw=timestamp_raw)

        return Message(role=cast("Literal['user', 'assistant', 'system', 'tool']", role), content=content, timestamp=timestamp)

    @classmethod
    def _active_binary_from_disk_session(cls, session_data: dict[str, object]) -> BinaryInfo | None:
        """Reconstruct the active ``BinaryInfo`` from a disk-sidecar session dictionary.

        Args:
            session_data: Raw session dictionary as parsed by
                ``_read_session_file``.

        Returns:
            BinaryInfo | None: The active binary, or ``None`` when the
            session has no binaries or the active index is out of range.
        """
        binaries_raw = session_data.get("binaries")
        if not isinstance(binaries_raw, list) or not binaries_raw:
            return None
        binaries = cast("list[object]", binaries_raw)

        index_raw = session_data.get("active_binary_index")
        index = index_raw if isinstance(index_raw, int) else len(binaries) - 1
        if not (0 <= index < len(binaries)):
            return None

        candidate = binaries[index]
        if not isinstance(candidate, dict):
            return None
        return cls._binary_info_from_disk_dict(cast("dict[str, object]", candidate))

    @staticmethod
    def _binary_info_from_disk_dict(data: dict[str, object]) -> BinaryInfo | None:
        """Reconstruct a ``BinaryInfo`` from a disk-sidecar binary dictionary.

        Args:
            data: Raw binary dictionary as stored in a sidecar session JSON
                file, matching the ``path``/``name``/``file_type`` shape
                written for the manager-backed store.

        Returns:
            BinaryInfo | None: Reconstructed binary info, or ``None`` when
            ``data`` is missing the required ``path``/``name`` fields.
        """
        path_raw = data.get("path")
        name_raw = data.get("name")
        if not isinstance(path_raw, str) or not isinstance(name_raw, str):
            return None

        size_raw = data.get("size")
        sha256_raw = data.get("sha256")
        file_type_raw = data.get("file_type")
        architecture_raw = data.get("architecture")
        is_64bit_raw = data.get("is_64bit")
        entry_point_raw = data.get("entry_point")

        return BinaryInfo(
            path=Path(path_raw),
            name=name_raw,
            size=size_raw if isinstance(size_raw, int) else 0,
            sha256=sha256_raw if isinstance(sha256_raw, str) else "",
            file_type=file_type_raw if isinstance(file_type_raw, str) else "unknown",
            architecture=architecture_raw if isinstance(architecture_raw, str) else "unknown",
            is_64bit=is_64bit_raw if isinstance(is_64bit_raw, bool) else False,
            entry_point=entry_point_raw if isinstance(entry_point_raw, int) else 0,
            sections=[],
            imports=[],
            exports=[],
        )

    def _restore_session_to_ui(self, messages: list[Message], active_binary: BinaryInfo | None) -> None:
        """Push a loaded session's chat history and active binary into the live UI.

        Drives restoration through the parent window's own UI-population
        methods -- ``ChatPanel.add_message``, the exact call path used for
        live conversation turns, and ``_on_binary_loaded``, the exact call
        path used after a normal binary load completes -- so a restored
        session renders identically to one built up interactively instead of
        duplicating chat-bubble rendering or binary-activation UI logic here.
        A no-op when the dialog has no parent window wired (for example, a
        dialog constructed for the on-disk sidecar fallback without a
        ``MainWindow`` parent).

        Args:
            messages: Ordered conversation history from the loaded session.
            active_binary: Active binary from the loaded session, or
                ``None`` when the session has no binaries.
        """
        parent = self.parent()

        chat_panel = getattr(parent, "_chat_panel", None)
        if chat_panel is not None:
            clear_messages = getattr(chat_panel, "clear_messages", None)
            if callable(clear_messages):
                clear_messages()
            add_message = getattr(chat_panel, "add_message", None)
            if callable(add_message):
                for message in messages:
                    add_message(message)

        if active_binary is not None:
            on_binary_loaded = getattr(parent, "_on_binary_loaded", None)
            if callable(on_binary_loaded):
                on_binary_loaded(active_binary)

    def _delete_session(self) -> None:
        """Delete the currently selected session."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)
        session_name: str = name_item.text()

        if session_id == self._current_session_id:
            QMessageBox.warning(
                self,
                "Cannot Delete",
                "Cannot delete the currently active session.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Delete Session",
            f"Delete session '{session_name}'?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        if self._manager is not None:
            self._delete_session_via_manager(session_id)
        elif self._delete_session_from_disk(session_id):
            self._on_session_deleted(session_id)

    def _delete_session_via_manager(self, session_id: str) -> None:
        """Delete a session through the session manager without blocking the GUI thread.

        Routes the deletion through ``SessionManager.delete`` via the
        non-blocking bridge worker so the Qt event loop stays responsive
        while the backing ``SessionStore`` performs its SQLite write.

        Args:
            session_id: Session identifier.
        """
        manager = self._manager
        if manager is None:
            return
        run_bridge_coroutine_logged(
            manager.delete(session_id),
            on_success=lambda result: self._on_delete_session_succeeded(session_id, result),
            on_error=lambda exc: self._on_delete_session_failed(session_id, exc),
            parent=self,
            event="session_delete",
            logger=_logger,
            level="info",
            session_id=session_id,
        )

    def _on_delete_session_succeeded(self, session_id: str, result: object) -> None:
        """Handle a successful ``SessionManager.delete`` bridge call.

        Args:
            session_id: Identifier of the session that was requested for deletion.
            result: Boolean-ish result returned by ``SessionManager.delete``.
        """
        deleted = True if result is None else bool(result)
        if not deleted:
            QMessageBox.warning(
                self,
                "Delete Failed",
                "Session could not be deleted.",
            )
            return
        self._on_session_deleted(session_id)

    def _on_delete_session_failed(self, _session_id: str, exc: object) -> None:
        """Handle a failed ``SessionManager.delete`` bridge call.

        Args:
            _session_id: Identifier of the session that was requested for
                deletion (unused; retained for signature symmetry with
                :meth:`_on_delete_session_succeeded`).
            exc: Exception object emitted by the bridge worker on failure.
        """
        error_obj = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
        QMessageBox.warning(
            self,
            "Delete Failed",
            f"Failed to delete session:\n{error_obj}",
        )

    def _on_session_deleted(self, session_id: str) -> None:
        """Finish a successful session deletion by refreshing the dialog state.

        Args:
            session_id: Identifier of the session that was deleted.
        """
        _logger.info("session_deleted", session_id=session_id)
        self.session_deleted.emit(session_id)
        self._load_sessions()

    def _delete_session_from_disk(self, session_id: str) -> bool:
        """Delete a session's on-disk sidecar JSON file.

        Used only when no session manager has been wired into the dialog.

        Args:
            session_id: Session identifier.

        Returns:
            bool: True if deleted successfully.
        """
        session_file = self.SESSIONS_DIR / f"{session_id}.json"
        if session_file.exists():
            _logger.info("session_file_unlinking", session_id=session_id, path=str(session_file))
            try:
                session_file.unlink()
            except OSError as e:
                _logger.warning(
                    "session_delete_failed",
                    session_id=session_id,
                    error=str(e),
                )
                QMessageBox.warning(
                    self,
                    "Delete Failed",
                    f"Failed to delete session file:\n{e}",
                )
                return False
            else:
                _logger.info("session_file_deleted", session_id=session_id, path=str(session_file))
                return True
        return True

    def _export_session(self) -> None:
        """Export selected session to file."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            QMessageBox.information(
                self,
                "Export Session",
                "Please select a session to export.",
            )
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)
        session_name: str = name_item.text()

        session_data = next((s for s in self._sessions if s["id"] == session_id), None)
        if session_data is None:
            QMessageBox.warning(
                self,
                "Export Failed",
                "Could not find session data.",
            )
            return

        safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in session_name)
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Session",
            f"{safe_name}.json",
            "JSON Files (*.json);;All Files (*)",
        )

        if path:
            try:
                self._write_session_export(session_id, session_data, path)
            except (OSError, TypeError) as e:
                _logger.warning(
                    "session_export_failed",
                    session_id=session_id,
                    error=str(e),
                )
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    f"Failed to export session:\n{e}",
                )
            else:
                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Session exported to:\n{path}",
                )

    def _write_session_export(self, session_id: str, session_data: dict[str, object], path: str) -> None:
        """Serialise ``session_data`` as JSON to ``path``.

        Args:
            session_id: Identifier of the session being exported.
            session_data: Raw session payload to export.
            path: Destination file path for the exported JSON.
        """
        export_data = self._prepare_export_data(session_data)

        _logger.info("session_export_started", session_id=session_id, path=path)
        with Path(path).open("w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        _logger.info(
            "session_exported",
            session_id=session_id,
            path=path,
        )

    @staticmethod
    def _prepare_export_data(session_data: dict[str, object]) -> dict[str, object]:
        """Prepare session data for export.

        Args:
            session_data: Raw session data.

        Returns:
            dict[str, object]: Cleaned session data suitable for JSON export.
        """
        export_data = {
            "id": session_data.get("id"),
            "name": session_data.get("name"),
            "provider": session_data.get("provider"),
            "model": session_data.get("model"),
            "message_count": session_data.get("message_count", 0),
            "binaries": session_data.get("binaries", []),
            "export_version": "1.0",
            "exported_at": datetime.now(tz=UTC).isoformat(),
        }

        created_at = session_data.get("created_at")
        if isinstance(created_at, datetime):
            export_data["created_at"] = created_at.isoformat()
        elif created_at:
            export_data["created_at"] = str(created_at)

        updated_at = session_data.get("updated_at")
        if isinstance(updated_at, datetime):
            export_data["updated_at"] = updated_at.isoformat()
        elif updated_at:
            export_data["updated_at"] = str(updated_at)

        messages_export_raw = session_data.get("messages")
        if isinstance(messages_export_raw, list):
            messages_export: list[dict[str, object]] = []
            msg_items = cast("list[object]", messages_export_raw)
            for msg_item in msg_items:
                if isinstance(msg_item, dict):
                    messages_export.append(cast("dict[str, object]", msg_item))
                elif hasattr(msg_item, "__dict__"):
                    messages_export.append(cast("dict[str, object]", msg_item.__dict__))
            export_data["messages"] = messages_export

        if "tool_states" in session_data:
            export_data["tool_states"] = session_data["tool_states"]

        if "patches" in session_data:
            export_data["patches"] = session_data["patches"]

        return export_data

    def _import_session(self) -> None:
        """Import session from file.

        When a session manager is available, the import is routed through ``SessionManager.import_json`` so the imported session lands in
        the backing ``SessionStore``. Without a manager, the legacy disk-sidecar fallback is used.
        """
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Import Session",
            "",
            "JSON Files (*.json);;All Files (*)",
        )

        if not path_str:
            return

        path = Path(path_str)

        if self._manager is not None:
            self._import_via_manager(path)
        else:
            self._import_to_disk(path)

    def _import_via_manager(self, path: Path) -> None:
        """Import a session JSON file through the session manager.

        Handles duplicate-ID prompts, malformed JSON, missing files and
        manager-level errors with user-facing dialogs.

        Args:
            path: Path to the session JSON file to import.
        """
        manager = self._manager
        if manager is None:
            return

        valid, import_id = self._peek_session_id(path)
        if not valid:
            return

        replace = False
        if import_id is not None and self._session_id_exists(import_id):
            if not self._confirm_replace(import_id):
                return
            replace = True

        run_bridge_coroutine_logged(
            manager.import_json(path, replace=replace),
            on_success=lambda result: self._on_import_via_manager_succeeded(path, import_id, result),
            on_error=lambda exc: self._on_import_via_manager_failed(path, exc),
            parent=self,
            event="session_import",
            logger=_logger,
            level="info",
            path=str(path),
            replace=replace,
        )

    def _on_import_via_manager_succeeded(self, path: Path, import_id: str | None, _result: object) -> None:
        """Finish a successful ``SessionManager.import_json`` bridge call.

        Args:
            path: Path to the session JSON file that was imported.
            import_id: Session identifier extracted from the file before
                import, when one could be determined.
            _result: Imported ``Session`` instance returned by the bridge
                call (unused; the dialog reloads from ``list_sessions``
                instead of trusting the raw bridge payload).
        """
        _logger.info("session_imported", session_id=import_id, path=str(path))
        QMessageBox.information(self, "Import Complete", f"Session imported from:\n{path}")
        self._load_sessions()

    def _on_import_via_manager_failed(self, path: Path, exc: object) -> None:
        """Handle a failed ``SessionManager.import_json`` bridge call.

        Args:
            path: Path to the session JSON file that failed to import.
            exc: Exception object emitted by the bridge worker on failure.
        """
        error_obj = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
        if isinstance(error_obj, FileNotFoundError):
            QMessageBox.warning(self, "Import Failed", f"File not found:\n{path}")
        elif isinstance(error_obj, ValueError):
            QMessageBox.warning(self, "Import Failed", f"Invalid session file:\n{error_obj}")
        else:
            QMessageBox.warning(self, "Import Failed", f"Failed to import session:\n{error_obj}")

    def _session_id_exists(self, session_id: str) -> bool:
        """Check whether a session ID is already present in the listed sessions.

        Args:
            session_id: Candidate session identifier.

        Returns:
            bool: True if the ID already exists in ``self._sessions``.
        """
        return any(s["id"] == session_id for s in self._sessions)

    def _confirm_replace(self, session_id: str) -> bool:
        """Prompt the user to confirm replacement of an existing session.

        Args:
            session_id: Identifier of the conflicting session.

        Returns:
            bool: True if the user confirmed replacement.
        """
        reply = QMessageBox.question(
            self,
            "Session Exists",
            f"A session with ID '{session_id}' already exists.\n\nDo you want to replace it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _peek_session_id(self, path: Path) -> tuple[bool, str | None]:
        """Peek at a session JSON file to extract its session identifier.

        Handles both wrapped (``{"session": {...}}``) and unwrapped top-level
        session forms consistent with ``SessionStore.import_from_json``.

        Args:
            path: Path to the session JSON file.

        Returns:
            tuple[bool, str | None]: ``(True, session_id)`` when the file is
                valid and a string ID could be extracted, ``(True, None)``
                when the file is valid but has no recognizable ID, and
                ``(False, None)`` when the file is missing or malformed. In
                the ``False`` case, a user-facing error dialog has already
                been shown.
        """
        try:
            with path.open(encoding="utf-8") as f:
                raw_data: object = json.load(f)
        except FileNotFoundError as e:
            _logger.warning("session_import_file_missing", path=str(path), error=str(e))
            QMessageBox.warning(self, "Import Failed", f"File not found:\n{path}")
            return False, None
        except json.JSONDecodeError as e:
            _logger.warning("session_import_json_invalid", path=str(path), error=str(e))
            QMessageBox.warning(self, "Import Failed", f"Invalid JSON file:\n{e}")
            return False, None
        except OSError as e:
            _logger.warning("session_import_read_failed", path=str(path), error=str(e))
            QMessageBox.warning(self, "Import Failed", f"Failed to read file:\n{e}")
            return False, None

        if not isinstance(raw_data, dict):
            QMessageBox.warning(self, "Import Failed", "Invalid session file format.")
            return False, None

        outer = cast("dict[str, object]", raw_data)
        inner_raw = outer.get("session", outer)
        if not isinstance(inner_raw, dict):
            return True, None

        inner = cast("dict[str, object]", inner_raw)
        id_val = inner.get("id")
        return True, (id_val if isinstance(id_val, str) else None)

    def _import_to_disk(self, path: Path) -> None:
        """Import a session JSON file into the on-disk sidecar store.

        This fallback is only used when no session manager has been wired
        into the dialog; it preserves the sidecar JSON purely as an
        export-compatible artifact for non-managed instances.

        Args:
            path: Path to the session JSON file to import.
        """
        try:
            with path.open(encoding="utf-8") as f:
                raw_data: object = json.load(f)
        except json.JSONDecodeError as e:
            _logger.warning("session_import_failed", path=str(path), error=str(e), reason="invalid_json")
            QMessageBox.warning(self, "Import Failed", f"Invalid JSON file:\n{e}")
            return
        except OSError as e:
            _logger.warning("session_import_failed", path=str(path), error=str(e), reason="read_failed")
            QMessageBox.warning(self, "Import Failed", f"Failed to read file:\n{e}")
            return

        if not isinstance(raw_data, dict):
            QMessageBox.warning(self, "Import Failed", "Invalid session file format.")
            return

        import_data = cast("dict[str, object]", raw_data)

        required_fields = {"id", "name"}
        if not required_fields.issubset(import_data.keys()):
            import_data["id"] = path.stem
            import_data["name"] = path.stem

        candidate_id = import_data["id"]
        if isinstance(candidate_id, str) and self._session_id_exists(candidate_id) and not self._confirm_replace(candidate_id):
            return

        import_data["imported_at"] = datetime.now(tz=UTC).isoformat()

        try:
            self._save_session_to_disk(import_data)
        except OSError as e:
            _logger.warning("session_import_failed", path=str(path), error=str(e), reason="write_failed")
            QMessageBox.warning(self, "Import Failed", f"Failed to write session file:\n{e}")
            return

        _logger.info("session_imported", session_id=import_data.get("id"), path=str(path))
        QMessageBox.information(self, "Import Complete", f"Session imported from:\n{path}")
        self._load_sessions()

    def _save_session_to_disk(self, session_data: dict[str, object]) -> None:
        """Save session data to disk.

        Args:
            session_data: Session data to save.
        """
        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        session_id = session_data.get("id", datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S"))
        session_file = self.SESSIONS_DIR / f"{session_id}.json"

        with session_file.open("w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, default=str)

        _logger.debug(
            "session_saved_to_disk",
            session_id=session_id,
            file=str(session_file),
        )

    def get_selected_session_id(self) -> str | None:
        """Get the ID of the currently selected session.

        Returns:
            str | None: Selected session ID or None.
        """
        sel_model = self._session_table.selectionModel()
        if sel_model is not None and (selected_rows := sel_model.selectedRows()):
            row = selected_rows[0].row()
            item = self._session_table.item(row, 0)
            if item is not None:
                session_id: str | None = item.data(Qt.ItemDataRole.UserRole)
                return session_id
        return None


class NewSessionDialog(QDialog):
    """Dialog for creating a new session.

    Allows users to specify session name and initial settings.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the NewSessionDialog.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)

        self._setup_ui()

        self.setWindowTitle("New Session")
        self.resize(_CONFIRM_DIALOG_WIDTH, _CONFIRM_DIALOG_HEIGHT)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        form_layout = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setText(f"Session {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M')}")
        form_layout.addRow("Session Name:", self._name_input)

        self._description_input = QLineEdit()
        form_layout.addRow("Description:", self._description_input)

        layout.addLayout(form_layout)
        layout.addStretch()

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._on_accepted)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_accepted(self) -> None:
        """Handle dialog acceptance and log session creation."""
        session_name = self.get_session_name()
        _logger.info("session_created", session_id=session_name)
        self.accept()

    def get_session_name(self) -> str:
        """Get the entered session name.

        Returns:
            str: Session name.
        """
        return str(self._name_input.text()).strip()

    def get_description(self) -> str:
        """Get the entered description.

        Returns:
            str: Session description.
        """
        return str(self._description_input.text()).strip()
