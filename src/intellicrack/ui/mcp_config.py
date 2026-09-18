# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Settings for third-party Model Context Protocol servers.

Everything the operator decides about a server is decided here: whether it
exists, how it is reached, whether it runs, which of its tools the model may
see, and what each of those tools costs in context. Nothing on this screen
guesses -- *Test connection* actually connects and reports the tool count the
server really published, and the token costs are measured from the schemas the
server really sent.

Every call that touches a server runs on the persistent background loop via a
tracked :class:`~intellicrack.ui.panels.async_bridge.BridgeCallWorker`. Closing
the dialog releases a still-running worker instead of destroying it: a
``QThread`` deleted mid-run aborts the process, and a connection attempt can
easily outlive the operator's patience with the window.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, Final, TypeGuard, override

from PyQt6.QtCore import QAbstractListModel, QModelIndex, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.mcp.auth import has_stored_credentials, issuer_for, sign_out
from intellicrack.mcp.config import (
    SERVER_ID_PATTERN,
    HttpServerSpec,
    McpConfigDocument,
    McpInputSpec,
    McpSandboxSpec,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
    missing_input_ids,
)
from intellicrack.mcp.connection import McpHealth, McpServerStatus
from intellicrack.mcp.errors import McpError
from intellicrack.mcp.policy import estimate_tool_cost, total_cost
from intellicrack.mcp.resources import list_resources, read_resource, summarize_parts
from intellicrack.mcp.tool_source import map_tool_to_function
from intellicrack.ui.dialogs_helpers import show_error, show_info, show_warning
from intellicrack.ui.panels.async_bridge import BridgeCallWorker, discard_worker, worker_is_running
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtCore import QObject
    from PyQt6.QtGui import QCloseEvent

    from intellicrack.mcp.catalog import McpToolEntry
    from intellicrack.mcp.connection import McpConnectionManager
    from intellicrack.mcp.secrets import McpSecretResolver


_logger = get_logger(__name__)


_DIALOG_WIDTH: Final[int] = 980
_DIALOG_HEIGHT: Final[int] = 680
_LIST_MIN_WIDTH: Final[int] = 220
_SPLIT_LEFT: Final[int] = 260
_SPLIT_RIGHT: Final[int] = 700
_LOG_MIN_HEIGHT: Final[int] = 220
_CODE_FONT_POINT_SIZE: Final[int] = 9
_STDERR_TAIL_LINES: Final[int] = 400
_RESOURCE_PREVIEW_CHARS: Final[int] = 4000
_MIN_TIMEOUT_S: Final[int] = 1
_MAX_TIMEOUT_S: Final[int] = 3600

_HEALTH_CAPTIONS: Final[dict[McpHealth, str]] = {
    McpHealth.DISABLED: "off",
    McpHealth.DISCONNECTED: "not running",
    McpHealth.CONNECTING: "connecting",
    McpHealth.READY: "running",
    McpHealth.FAILED: "failed",
}


def _status_caption(status: McpServerStatus) -> str:
    """Render one server's state as a single readable line.

    Args:
        status: The server's current state.

    Returns:
        str: The server id followed by what it is doing.
    """
    caption = _HEALTH_CAPTIONS.get(status.health, status.health.value)
    if status.health is McpHealth.READY:
        return f"{status.server_id} - {caption}, {status.tool_count} tools"
    return f"{status.server_id} - {caption}"


class McpServerListModel(QAbstractListModel):
    """Lists configured servers alongside what each is currently doing."""

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize an empty model.

        Args:
            parent: Parent object.
        """
        super().__init__(parent)
        self._rows: list[tuple[McpServerConfig, McpServerStatus]] = []

    def set_rows(self, rows: list[tuple[McpServerConfig, McpServerStatus]]) -> None:
        """Replace every row.

        Args:
            rows: The configured servers paired with their current state.
        """
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def config_at(self, row: int) -> McpServerConfig | None:
        """Read the configuration at one row.

        Args:
            row: The row index.

        Returns:
            McpServerConfig | None: The configuration, or ``None`` when the
            row does not exist.
        """
        if 0 <= row < len(self._rows):
            return self._rows[row][0]
        return None

    def status_at(self, row: int) -> McpServerStatus | None:
        """Read the state at one row.

        Args:
            row: The row index.

        Returns:
            McpServerStatus | None: The state, or ``None`` when the row does
            not exist.
        """
        if 0 <= row < len(self._rows):
            return self._rows[row][1]
        return None

    def row_for(self, server_id: str) -> int:
        """Find the row a server occupies.

        Args:
            server_id: The server to locate.

        Returns:
            int: The row index, or ``-1`` when the server is not listed.
        """
        return next((index for index, (config, _) in enumerate(self._rows) if config.server_id == server_id), -1)

    @override
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Report how many servers are listed.

        Args:
            parent: Parent index; a list model has no children, so a valid
                parent reports zero.

        Returns:
            int: The row count.
        """
        if parent is not None and parent.isValid():
            return 0
        return len(self._rows)

    @override
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        """Supply one row's display text or tooltip.

        Args:
            index: The row to describe.
            role: The Qt item-data role being requested.

        Returns:
            Any: The caption for the display role, the last error for the
            tooltip role, and ``None`` otherwise.
        """
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        config, status = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return _status_caption(status)
        if role == Qt.ItemDataRole.ToolTipRole:
            return status.last_error or f"{config.kind.value} server"
        return None


class McpInputPromptDialog(QDialog):
    """Collects the value behind one ``${input:id}`` reference."""

    def __init__(self, spec: McpInputSpec, parent: QWidget | None = None) -> None:
        """Initialize the prompt.

        Args:
            spec: The input declaration being filled in.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._spec = spec
        self._value = ""
        self.setWindowTitle(f"Value for '{spec.id}'")
        self.setModal(True)
        self.setMinimumWidth(_LIST_MIN_WIDTH * 2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        description = QLabel(spec.description or f"Enter the value for '{spec.id}'.")
        description.setObjectName("mcp_input_description")
        description.setWordWrap(True)
        layout.addWidget(description)

        self._edit = QLineEdit()
        self._edit.setObjectName("mcp_input_value")
        if spec.password:
            self._edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._edit)

        note = QLabel("Stored in your operating system keyring. It is never written to mcp.json.")
        note.setObjectName("mcp_input_note")
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def value(self) -> str:
        """The value the operator entered.

        Returns:
            str: The entered value, empty when cancelled.
        """
        return self._value

    def _on_accept(self) -> None:
        """Capture the entered value and close."""
        self._value = self._edit.text()
        self.accept()


class McpServerEditor(QWidget):
    """Edits one server's transport and connection settings.

    Emits ``changed()`` whenever a field is edited, so the dialog knows there
    is something unsaved.
    """

    changed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the editor with empty fields.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._server_id = ""
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the shared fields and the two transport-specific pages."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        shared = QFormLayout()
        shared.setSpacing(8)

        self._id_edit = QLineEdit()
        self._id_edit.setObjectName("mcp_server_id")
        self._id_edit.setPlaceholderText("lower-case letters, digits and hyphens")
        self._id_edit.textChanged.connect(self.changed)
        shared.addRow("Server id", self._id_edit)

        self._kind_combo = QComboBox()
        self._kind_combo.setObjectName("mcp_server_kind")
        for kind in McpTransportKind:
            self._kind_combo.addItem(kind.value, kind)
        self._kind_combo.currentIndexChanged.connect(self._on_kind_changed)
        shared.addRow("Transport", self._kind_combo)

        self._enabled_box = QCheckBox("Enabled")
        self._enabled_box.setObjectName("mcp_server_enabled")
        self._enabled_box.toggled.connect(self.changed)
        shared.addRow("", self._enabled_box)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setObjectName("mcp_server_timeout")
        self._timeout_spin.setRange(_MIN_TIMEOUT_S, _MAX_TIMEOUT_S)
        self._timeout_spin.valueChanged.connect(self.changed)
        shared.addRow("Call timeout (s)", self._timeout_spin)
        layout.addLayout(shared)

        self._pages = QStackedWidget()
        self._pages.addWidget(self._build_stdio_page())
        self._pages.addWidget(self._build_http_page())
        layout.addWidget(self._pages)
        layout.addStretch()

    def _build_stdio_page(self) -> QWidget:
        """Build the editor for a local child-process server.

        Returns:
            QWidget: The stdio page.
        """
        page = QGroupBox("Local program")
        form = QFormLayout(page)
        form.setSpacing(8)

        self._command_edit = QLineEdit()
        self._command_edit.setObjectName("mcp_stdio_command")
        self._command_edit.setPlaceholderText("npx")
        self._command_edit.textChanged.connect(self.changed)
        form.addRow("Command", self._command_edit)

        self._args_edit = QPlainTextEdit()
        self._args_edit.setObjectName("mcp_stdio_args")
        self._args_edit.setPlaceholderText("one argument per line")
        self._args_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._args_edit.textChanged.connect(self.changed)
        form.addRow("Arguments", self._args_edit)

        self._cwd_edit = QLineEdit()
        self._cwd_edit.setObjectName("mcp_stdio_cwd")
        self._cwd_edit.setPlaceholderText("inherited from Intellicrack")
        self._cwd_edit.textChanged.connect(self.changed)
        form.addRow("Working directory", self._cwd_edit)

        self._env_edit = QPlainTextEdit()
        self._env_edit.setObjectName("mcp_stdio_env")
        self._env_edit.setPlaceholderText("NAME=${input:my-token}, one per line")
        self._env_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._env_edit.textChanged.connect(self.changed)
        form.addRow("Environment", self._env_edit)

        self._env_file_edit = QLineEdit()
        self._env_file_edit.setObjectName("mcp_stdio_env_file")
        self._env_file_edit.textChanged.connect(self.changed)
        form.addRow("Environment file", self._env_file_edit)
        return page

    def _build_http_page(self) -> QWidget:
        """Build the editor for a remote HTTP server.

        Returns:
            QWidget: The HTTP page.
        """
        page = QGroupBox("Remote endpoint")
        form = QFormLayout(page)
        form.setSpacing(8)

        self._url_edit = QLineEdit()
        self._url_edit.setObjectName("mcp_http_url")
        self._url_edit.setPlaceholderText("https://example.com/mcp")
        self._url_edit.textChanged.connect(self.changed)
        form.addRow("URL", self._url_edit)

        self._headers_edit = QPlainTextEdit()
        self._headers_edit.setObjectName("mcp_http_headers")
        self._headers_edit.setPlaceholderText("Authorization=Bearer ${input:my-token}, one per line")
        self._headers_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._headers_edit.textChanged.connect(self.changed)
        form.addRow("Headers", self._headers_edit)

        self._query_edit = QPlainTextEdit()
        self._query_edit.setObjectName("mcp_http_query")
        self._query_edit.setPlaceholderText("toolsets=repos,issues, one per line")
        self._query_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._query_edit.textChanged.connect(self.changed)
        form.addRow("Query parameters", self._query_edit)

        self._client_id_edit = QLineEdit()
        self._client_id_edit.setObjectName("mcp_http_client_id")
        self._client_id_edit.setPlaceholderText("pre-registered OAuth client id, if you have one")
        self._client_id_edit.textChanged.connect(self.changed)
        form.addRow("OAuth client id", self._client_id_edit)

        self._metadata_url_edit = QLineEdit()
        self._metadata_url_edit.setObjectName("mcp_http_metadata_url")
        self._metadata_url_edit.setPlaceholderText("https://example.com/mcp/client.json")
        self._metadata_url_edit.textChanged.connect(self.changed)
        form.addRow("Client metadata URL", self._metadata_url_edit)
        return page

    def _on_kind_changed(self) -> None:
        """Show the page matching the selected transport."""
        kind = self.selected_kind()
        self._pages.setCurrentIndex(0 if kind is McpTransportKind.STDIO else 1)
        self.changed.emit()

    def selected_kind(self) -> McpTransportKind:
        """Read the transport the operator selected.

        Returns:
            McpTransportKind: The selected transport.
        """
        data: object = self._kind_combo.currentData()
        return data if isinstance(data, McpTransportKind) else McpTransportKind.STDIO

    @staticmethod
    def _parse_pairs(text: str) -> dict[str, str]:
        """Parse a ``NAME=VALUE`` block into a mapping.

        Args:
            text: The block the operator typed.

        Returns:
            dict[str, str]: The parsed pairs, skipping blank and malformed
            lines.
        """
        pairs: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if separator and name.strip():
                pairs[name.strip()] = value.strip()
        return pairs

    @staticmethod
    def _render_pairs(pairs: dict[str, str]) -> str:
        """Render a mapping back into a ``NAME=VALUE`` block.

        Args:
            pairs: The mapping to render.

        Returns:
            str: One ``NAME=VALUE`` line per entry.
        """
        return "\n".join(f"{name}={value}" for name, value in pairs.items())

    def load(self, config: McpServerConfig) -> None:
        """Fill every field from one server configuration.

        Args:
            config: The server to display.
        """
        self._server_id = config.server_id
        self._id_edit.setText(config.server_id)
        index = self._kind_combo.findData(config.kind)
        if index >= 0:
            self._kind_combo.setCurrentIndex(index)
        self._enabled_box.setChecked(config.enabled)
        self._timeout_spin.setValue(int(config.request_timeout_s))

        stdio = config.stdio
        self._command_edit.setText(stdio.command if stdio else "")
        self._args_edit.setPlainText("\n".join(stdio.args) if stdio else "")
        self._cwd_edit.setText((stdio.cwd or "") if stdio else "")
        self._env_edit.setPlainText(self._render_pairs(dict(stdio.env)) if stdio else "")
        self._env_file_edit.setText((stdio.env_file or "") if stdio else "")

        http = config.http
        self._url_edit.setText(http.url if http else "")
        self._headers_edit.setPlainText(self._render_pairs(dict(http.headers)) if http else "")
        self._query_edit.setPlainText(self._render_pairs(dict(http.query)) if http else "")
        self._client_id_edit.setText((http.oauth_client_id or "") if http else "")
        self._metadata_url_edit.setText((http.oauth_metadata_url or "") if http else "")

    def build(self, existing: McpServerConfig | None) -> McpServerConfig:
        """Build a configuration from the current field values.

        Args:
            existing: The configuration being edited, whose per-tool
                switches and sandbox settings are carried over. ``None`` for
                a brand new server.

        Returns:
            McpServerConfig: The configuration the operator described. It is
            not validated here; the caller validates so it can report the
            failure against the right field.
        """
        kind = self.selected_kind()
        stdio: StdioServerSpec | None = None
        http: HttpServerSpec | None = None
        if kind is McpTransportKind.STDIO:
            stdio = StdioServerSpec(
                command=self._command_edit.text().strip(),
                args=tuple(line for line in self._args_edit.toPlainText().splitlines() if line.strip()),
                cwd=self._cwd_edit.text().strip() or None,
                env=self._parse_pairs(self._env_edit.toPlainText()),
                env_file=self._env_file_edit.text().strip() or None,
            )
        else:
            http = HttpServerSpec(
                url=self._url_edit.text().strip(),
                headers=self._parse_pairs(self._headers_edit.toPlainText()),
                query=self._parse_pairs(self._query_edit.toPlainText()),
                oauth_client_id=self._client_id_edit.text().strip() or None,
                oauth_metadata_url=self._metadata_url_edit.text().strip() or None,
            )
        return McpServerConfig(
            server_id=self._id_edit.text().strip(),
            kind=kind,
            stdio=stdio,
            http=http,
            enabled=self._enabled_box.isChecked(),
            disabled_tools=existing.disabled_tools if existing is not None else frozenset(),
            sandbox=existing.sandbox if existing is not None else McpSandboxSpec(),
            request_timeout_s=float(self._timeout_spin.value()),
        )


class McpToolToggleView(QWidget):
    """Lists one server's tools with a switch and a context cost for each.

    Emits ``toggled()`` whenever a tool is switched on or off.
    """

    toggled = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize an empty view.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._summary = QLabel("Connect a server to see its tools.")
        self._summary.setObjectName("mcp_tools_summary")
        self._summary.setWordWrap(True)
        layout.addWidget(self._summary)

        self._loading = False
        self._list = QListWidget()
        self._list.setObjectName("mcp_tools_list")
        self._list.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._list)

    def clear(self, message: str) -> None:
        """Empty the list and explain why it is empty.

        Args:
            message: What to show in place of the tools.
        """
        self._list.clear()
        self._summary.setText(message)

    def load(self, entries: tuple[McpToolEntry, ...], disabled: frozenset[str]) -> None:
        """Populate the list from a server's catalog.

        Args:
            entries: Every tool the server published.
            disabled: Names of the tools currently switched off.
        """
        self._loading = True
        self._list.clear()
        costs = [estimate_tool_cost(map_tool_to_function(entry)) for entry in entries]
        for entry, cost in zip(entries, costs, strict=True):
            item = QListWidgetItem(f"{entry.display_name}  ({cost.total_tokens} tokens)")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked if entry.name in disabled else Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, entry.name)
            item.setToolTip(entry.description[:512] or entry.name)
            self._list.addItem(item)
        self._loading = False

        enabled_costs = [cost for entry, cost in zip(entries, costs, strict=True) if entry.name not in disabled]
        self._summary.setText(
            f"{len(enabled_costs)} of {len(entries)} tools enabled, costing about "
            f"{total_cost(enabled_costs)} tokens of context when advertised.",
        )

    def disabled_tools(self) -> frozenset[str]:
        """Read which tools the operator has switched off.

        Returns:
            frozenset[str]: Names of the unchecked tools.
        """
        names: set[str] = set()
        for row in range(self._list.count()):
            item = self._list.item(row)
            if item is None or item.checkState() == Qt.CheckState.Checked:
                continue
            value: object = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(value, str):
                names.add(value)
        return frozenset(names)

    def _on_item_changed(self, item: QListWidgetItem) -> None:
        """Report that a tool was switched on or off.

        Changes made while the list is being populated are not reported: they
        are this view writing its own state, not the operator changing it.

        Args:
            item: The item that changed.
        """
        del item
        if self._loading:
            return
        self.toggled.emit()


class McpConfigDialog(QDialog):
    """The MCP settings screen.

    Owns the configuration document while it is open, applies the operator's
    edits to it, and hands each server operation to the connection manager on
    the background loop.

    Emits ``resource_attached(text)`` when the operator sends a server
    resource to the conversation. The dialog does not reach into the chat
    itself: it fetches the resource and forwards the rendered text, leaving
    the main window to decide where a conversation attachment goes.
    """

    resource_attached = pyqtSignal(str)

    def __init__(
        self,
        manager: McpConnectionManager,
        resolver: McpSecretResolver,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the settings dialog.

        Args:
            manager: The connection manager owning every server.
            resolver: Resolver used to store ``${input:id}`` values.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = manager
        self._resolver = resolver
        self._document: McpConfigDocument = manager.document
        self._current_id: str | None = None
        self._workers: list[BridgeCallWorker] = []
        self._dirty = False

        self.setWindowTitle("MCP Servers")
        self.setMinimumSize(_DIALOG_WIDTH, _DIALOG_HEIGHT)
        self._build_ui()
        self._reload_document()

    def _build_ui(self) -> None:
        """Build the split list-and-detail layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_server_list())
        splitter.addWidget(self._build_detail_tabs())
        splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        layout.addWidget(splitter)

        layout.addLayout(self._build_action_row())

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Close)
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)

    def _build_server_list(self) -> QWidget:
        """Build the server list and its add/remove buttons.

        Returns:
            QWidget: The left-hand pane.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)

        self._model = McpServerListModel(self)
        self._list_view = QListView()
        self._list_view.setObjectName("mcp_server_list")
        self._list_view.setModel(self._model)
        self._list_view.setMinimumWidth(_LIST_MIN_WIDTH)
        selection = self._list_view.selectionModel()
        if selection is not None:
            selection.currentRowChanged.connect(self._on_selection_changed)
        column.addWidget(self._list_view)

        row = QHBoxLayout()
        row.setSpacing(8)
        add_button = QPushButton("Add")
        add_button.setObjectName("mcp_add_server")
        add_button.clicked.connect(self._on_add_server)
        row.addWidget(add_button)

        remove_button = QPushButton("Remove")
        remove_button.setObjectName("mcp_remove_server")
        remove_button.clicked.connect(self._on_remove_server)
        row.addWidget(remove_button)

        import_button = QPushButton("Import JSON...")
        import_button.setObjectName("mcp_import_json")
        import_button.clicked.connect(self._on_import_json)
        row.addWidget(import_button)
        column.addLayout(row)
        return pane

    def _build_detail_tabs(self) -> QWidget:
        """Build the connection, tools and log tabs.

        Returns:
            QWidget: The right-hand pane.
        """
        self._tabs = QTabWidget()

        self._editor = McpServerEditor()
        self._editor.changed.connect(self._on_editor_changed)
        self._tabs.addTab(self._editor, "Connection")

        self._tool_view = McpToolToggleView()
        self._tool_view.toggled.connect(self._on_tools_toggled)
        self._tabs.addTab(self._tool_view, "Tools")

        log_pane = QWidget()
        log_column = QVBoxLayout(log_pane)
        log_column.setContentsMargins(0, 0, 0, 0)
        log_column.setSpacing(8)

        self._status_label = QLabel("Select a server.")
        self._status_label.setObjectName("mcp_status_label")
        self._status_label.setWordWrap(True)
        log_column.addWidget(self._status_label)

        self._log_view = QPlainTextEdit()
        self._log_view.setObjectName("mcp_stderr_view")
        self._log_view.setReadOnly(True)
        self._log_view.setMinimumHeight(_LOG_MIN_HEIGHT)
        self._log_view.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        log_column.addWidget(self._log_view)

        refresh_button = QPushButton("Refresh log")
        refresh_button.setObjectName("mcp_refresh_log")
        refresh_button.clicked.connect(self._refresh_log)
        log_column.addWidget(refresh_button)
        self._tabs.addTab(log_pane, "Status and log")
        self._tabs.addTab(self._build_resources_pane(), "Resources")
        return self._tabs

    def _build_resources_pane(self) -> QWidget:
        """Build the resource browser for the selected server.

        Returns:
            QWidget: The resources pane.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)

        note = QLabel(
            "Resources are documents a server offers. Reading one does not run anything, and what it "
            "returns is the server's own content, so it is attached to the conversation as quoted data.",
        )
        note.setObjectName("mcp_resources_note")
        note.setWordWrap(True)
        column.addWidget(note)

        self._resource_list = QListWidget()
        self._resource_list.setObjectName("mcp_resource_list")
        column.addWidget(self._resource_list)

        self._resource_preview = QPlainTextEdit()
        self._resource_preview.setObjectName("mcp_resource_preview")
        self._resource_preview.setReadOnly(True)
        self._resource_preview.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        column.addWidget(self._resource_preview)

        row = QHBoxLayout()
        row.setSpacing(8)
        refresh = QPushButton("List resources")
        refresh.setObjectName("mcp_list_resources")
        refresh.clicked.connect(self._on_list_resources)
        row.addWidget(refresh)

        read = QPushButton("Read selected")
        read.setObjectName("mcp_read_resource")
        read.clicked.connect(self._on_read_resource)
        row.addWidget(read)

        attach = QPushButton("Attach to chat")
        attach.setObjectName("mcp_attach_resource")
        attach.clicked.connect(self._on_attach_resource)
        row.addWidget(attach)
        row.addStretch()
        column.addLayout(row)
        return pane

    def _on_list_resources(self) -> None:
        """Fetch the selected server's resource listing."""
        config = self._selected_config()
        connection = self._manager.connection(config.server_id) if config is not None else None
        if config is None or connection is None or not connection.is_ready:
            show_info(self, "Resources", "Start the server before listing what it offers.")
            return
        self._resource_list.clear()

        def _listed(result: object) -> None:
            """Populate the list from the server's listing.

            Args:
                result: The list of resource summaries.
            """
            if not isinstance(result, list):
                return
            for summary in result:
                item = QListWidgetItem(f"{getattr(summary, 'title', None) or summary.name} - {summary.uri}")
                item.setData(Qt.ItemDataRole.UserRole, summary.uri)
                item.setToolTip(getattr(summary, "description", None) or summary.uri)
                self._resource_list.addItem(item)
            if not result:
                show_info(self, "Resources", "This server offers no resources.")

        self._start_worker(list_resources(connection), _listed, self._on_worker_error)

    def _selected_resource_uri(self) -> str | None:
        """Read the URI of the selected resource.

        Returns:
            str | None: The URI, or ``None`` when nothing is selected.
        """
        item = self._resource_list.currentItem()
        if item is None:
            return None
        value: object = item.data(Qt.ItemDataRole.UserRole)
        return value if isinstance(value, str) else None

    def _fetch_resource(self, on_text: Callable[[str], None]) -> None:
        """Read the selected resource and hand its rendered text to a callback.

        Args:
            on_text: Called on the GUI thread with the rendered content.
        """
        config = self._selected_config()
        connection = self._manager.connection(config.server_id) if config is not None else None
        uri = self._selected_resource_uri()
        if connection is None or uri is None or not connection.is_ready:
            show_info(self, "Resources", "Select a resource on a running server first.")
            return

        def _read(result: object) -> None:
            """Render the fetched parts.

            Args:
                result: The list of result parts the read produced.
            """
            if not isinstance(result, list):
                return
            on_text(summarize_parts(result))

        self._start_worker(read_resource(connection, uri), _read, self._on_worker_error)

    def _on_read_resource(self) -> None:
        """Read the selected resource into the preview."""

        def _show(text: str) -> None:
            """Put the rendered content in the preview.

            Args:
                text: The rendered content.
            """
            self._resource_preview.setPlainText(text[:_RESOURCE_PREVIEW_CHARS])

        self._fetch_resource(_show)

    def _on_attach_resource(self) -> None:
        """Send the selected resource's content to the conversation."""

        def _attach(text: str) -> None:
            """Forward the rendered content to whoever is listening.

            Args:
                text: The rendered content.
            """
            self._resource_preview.setPlainText(text[:_RESOURCE_PREVIEW_CHARS])
            self.resource_attached.emit(text)
            _logger.info("mcp_resource_attached", length=len(text))

        self._fetch_resource(_attach)

    def _build_action_row(self) -> QHBoxLayout:
        """Build the per-server action buttons.

        Returns:
            QHBoxLayout: The action row.
        """
        row = QHBoxLayout()
        row.setSpacing(8)

        self._test_button = QPushButton("Test connection")
        self._test_button.setObjectName("mcp_test_connection")
        self._test_button.clicked.connect(self._on_test_connection)
        row.addWidget(self._test_button)

        self._start_button = QPushButton("Start")
        self._start_button.setObjectName("mcp_start_server")
        self._start_button.clicked.connect(self._on_start_server)
        row.addWidget(self._start_button)

        self._stop_button = QPushButton("Stop")
        self._stop_button.setObjectName("mcp_stop_server")
        self._stop_button.clicked.connect(self._on_stop_server)
        row.addWidget(self._stop_button)

        self._inputs_button = QPushButton("Set input values...")
        self._inputs_button.setObjectName("mcp_set_inputs")
        self._inputs_button.clicked.connect(self._on_set_inputs)
        row.addWidget(self._inputs_button)

        self._sign_out_button = QPushButton("Sign out")
        self._sign_out_button.setObjectName("mcp_sign_out")
        self._sign_out_button.clicked.connect(self._on_sign_out)
        row.addWidget(self._sign_out_button)

        row.addStretch()
        return row

    def _start_worker(
        self,
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None],
        on_error: Callable[[object], None],
    ) -> None:
        """Run one coroutine on the background loop and track its worker.

        Args:
            coro: The coroutine to run.
            on_success: Called on the GUI thread with the result.
            on_error: Called on the GUI thread with the exception.
        """
        worker = BridgeCallWorker(coro, self)
        _ = worker.call_finished.connect(on_success)
        _ = worker.call_error.connect(on_error)
        self._workers.append(worker)
        worker.start()

    def _release_workers(self) -> None:
        """Let go of every worker without destroying one that is still running.

        A worker whose ``QThread`` is destroyed while its OS thread runs
        aborts the process. The async bridge keeps its own strong reference to
        every started worker, so detaching a running one from this dialog is
        enough: it finishes on its own and cleans itself up, while its signals
        are disconnected so nothing calls back into a dialog that is going
        away.
        """
        for worker in self._workers:
            if worker_is_running(worker):
                with contextlib.suppress(RuntimeError, TypeError):
                    worker.call_finished.disconnect()
                with contextlib.suppress(RuntimeError, TypeError):
                    worker.call_error.disconnect()
                with contextlib.suppress(RuntimeError):
                    worker.setParent(None)
                _logger.debug("mcp_config_worker_detached")
            else:
                discard_worker(worker)
        self._workers.clear()

    def _reload_document(self) -> None:
        """Re-read the configuration and refresh every view."""
        try:
            self._document = self._manager.reload()
        except McpError as exc:
            show_error(self, "MCP configuration", f"The configuration could not be read: {exc}")
            self._document = McpConfigDocument()
        self._refresh_list()

    def _refresh_list(self) -> None:
        """Rebuild the server list from the document and live statuses."""
        statuses = {status.server_id: status for status in self._manager.statuses()}
        rows = [
            (config, statuses[config.server_id])
            for config in self._document.servers
            if config.server_id in statuses
        ]
        rows.extend(
            (config, self._offline_status(config))
            for config in self._document.servers
            if config.server_id not in statuses
        )
        self._model.set_rows(rows)
        if self._current_id is not None:
            row = self._model.row_for(self._current_id)
            if row >= 0:
                self._list_view.setCurrentIndex(self._model.index(row, 0))
        self._refresh_detail()

    @staticmethod
    def _offline_status(config: McpServerConfig) -> McpServerStatus:
        """Build a placeholder status for a server that has never run.

        Args:
            config: The configured server.

        Returns:
            McpServerStatus: A status reporting it as off or not running.
        """
        return McpServerStatus(
            server_id=config.server_id,
            health=McpHealth.DISCONNECTED if config.enabled else McpHealth.DISABLED,
        )

    def _selected_config(self) -> McpServerConfig | None:
        """Read the configuration of the selected server.

        Returns:
            McpServerConfig | None: The selection, or ``None``.
        """
        if self._current_id is None:
            return None
        return self._document.server(self._current_id)

    def _on_selection_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        """Switch the detail pane to the newly selected server.

        Args:
            current: The newly selected row.
            previous: The previously selected row.
        """
        del previous
        config = self._model.config_at(current.row())
        self._current_id = config.server_id if config is not None else None
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        """Refresh the editor, tool list and status for the selection."""
        config = self._selected_config()
        if config is None:
            self._tool_view.clear("Select a server.")
            self._status_label.setText("Select a server.")
            self._log_view.setPlainText("")
            return
        self._editor.load(config)
        self._refresh_tools(config)
        self._refresh_status(config)
        self._refresh_log()

    def _refresh_tools(self, config: McpServerConfig) -> None:
        """Refresh the per-tool switches for one server.

        Args:
            config: The server whose tools to show.
        """
        connection = self._manager.connection(config.server_id)
        catalog = connection.catalog if connection is not None else None
        if catalog is None:
            self._tool_view.clear("Start this server to see the tools it publishes.")
            return
        self._tool_view.load(catalog.entries, config.disabled_tools)

    def _refresh_status(self, config: McpServerConfig) -> None:
        """Refresh the status line for one server.

        Args:
            config: The server whose status to show.
        """
        row = self._model.row_for(config.server_id)
        status = self._model.status_at(row)
        if status is None:
            self._status_label.setText("Not started.")
            return
        lines = [_status_caption(status)]
        if status.generation:
            lines.append(f"Tool listing generation: {status.generation}")
        if status.connected_at is not None:
            lines.append(f"Connected at {status.connected_at.isoformat(timespec='seconds')}")
        if status.last_error:
            lines.append(f"Last error: {status.last_error}")
        undeclared = missing_input_ids(self._document, [config])
        if undeclared:
            lines.append(f"Undeclared inputs referenced: {', '.join(undeclared)}")
        self._status_label.setText("\n".join(lines))

    def _refresh_log(self) -> None:
        """Refresh the captured stderr for the selected server."""
        config = self._selected_config()
        if config is None:
            self._log_view.setPlainText("")
            return
        lines = self._manager.stderr_tail(config.server_id, _STDERR_TAIL_LINES)
        self._log_view.setPlainText("\n".join(lines) if lines else "(no output captured)")

    def _on_editor_changed(self) -> None:
        """Record that the editor has unsaved changes."""
        self._dirty = True

    def _on_tools_toggled(self) -> None:
        """Apply a per-tool switch to the in-memory document."""
        config = self._selected_config()
        if config is None:
            return
        updated = McpServerConfig(
            server_id=config.server_id,
            kind=config.kind,
            stdio=config.stdio,
            http=config.http,
            enabled=config.enabled,
            disabled_tools=self._tool_view.disabled_tools(),
            sandbox=config.sandbox,
            request_timeout_s=config.request_timeout_s,
        )
        self._document = self._document.with_server(updated)
        self._dirty = True
        self._refresh_tools(updated)

    def _apply_editor(self) -> McpServerConfig | None:
        """Fold the editor's current values into the document.

        Returns:
            McpServerConfig | None: The updated configuration, or ``None``
            when the fields do not describe a valid server. The failure is
            reported to the operator before returning.
        """
        existing = self._selected_config()
        candidate = self._editor.build(existing)
        if not SERVER_ID_PATTERN.match(candidate.server_id):
            show_warning(
                self,
                "Server id",
                f"'{candidate.server_id}' is not a usable server id. Use lower-case letters, digits and "
                f"hyphens, up to 32 characters.",
            )
            return None
        try:
            candidate.validate()
        except McpError as exc:
            show_warning(self, "Server settings", str(exc))
            return None
        if existing is not None and existing.server_id != candidate.server_id:
            self._document = self._document.without_server(existing.server_id)
        self._document = self._document.with_server(candidate)
        self._current_id = candidate.server_id
        return candidate

    def _on_add_server(self) -> None:
        """Add a new, disabled stdio server and select it."""
        existing = {config.server_id for config in self._document.servers}
        index = 1
        server_id = "server-1"
        while server_id in existing:
            index += 1
            server_id = f"server-{index}"
        config = McpServerConfig(
            server_id=server_id,
            kind=McpTransportKind.STDIO,
            stdio=StdioServerSpec(command=""),
            enabled=False,
        )
        self._document = self._document.with_server(config)
        self._current_id = server_id
        self._dirty = True
        self._refresh_list()

    def _on_remove_server(self) -> None:
        """Stop and forget the selected server."""
        config = self._selected_config()
        if config is None:
            return
        server_id = config.server_id
        self._document = self._document.without_server(server_id)
        self._current_id = None
        self._dirty = True

        def _stopped(result: object) -> None:
            """Refresh the list once the server has stopped.

            Args:
                result: Ignored; stopping reports nothing.
            """
            del result
            self._refresh_list()

        self._start_worker(self._manager.stop_server(server_id), _stopped, self._on_worker_error)

    def _on_import_json(self) -> None:
        """Import servers from pasted ``mcp.json`` text."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Import MCP configuration")
        dialog.setModal(True)
        dialog.setMinimumSize(_SPLIT_RIGHT, _LOG_MIN_HEIGHT * 2)
        column = QVBoxLayout(dialog)
        label = QLabel("Paste an mcp.json document. Both the 'servers' and the 'mcpServers' shape are accepted.")
        label.setWordWrap(True)
        column.addWidget(label)
        editor = QTextEdit()
        editor.setObjectName("mcp_import_text")
        editor.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        column.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        column.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            imported = self._manager.store.import_document(editor.toPlainText())
        except McpError as exc:
            show_error(self, "Import failed", str(exc))
            return
        for config in imported.servers:
            self._document = self._document.with_server(config)
        for spec in imported.inputs:
            self._document = self._document.with_input(spec)
        self._dirty = True
        self._refresh_list()
        show_info(self, "Imported", f"Imported {len(imported.servers)} server(s).")

    def _on_save(self) -> None:
        """Persist the document and re-register it with the manager."""
        if self._selected_config() is not None and self._apply_editor() is None:
            return
        try:
            self._manager.store.save(self._document)
        except McpError as exc:
            show_error(self, "Save failed", str(exc))
            return
        self._dirty = False
        self._document = self._manager.reload()
        self._refresh_list()
        show_info(self, "Saved", "MCP settings saved. Start or restart a server for the changes to take effect.")

    def _on_test_connection(self) -> None:
        """Connect once to the edited server and report what it published."""
        config = self._apply_editor()
        if config is None:
            return
        self._test_button.setEnabled(False)
        self._status_label.setText(f"Connecting to '{config.server_id}'...")

        def _finished(result: object) -> None:
            """Report the probe's outcome.

            Args:
                result: The :class:`McpServerStatus` the probe produced.
            """
            self._test_button.setEnabled(True)
            if not _is_status(result):
                show_warning(self, "Test connection", "The server did not report a usable status.")
                return
            status = result
            if status.health is McpHealth.READY:
                show_info(
                    self,
                    "Test connection",
                    f"Connected to '{status.server_id}'. It published {status.tool_count} tool(s).",
                )
            else:
                show_warning(
                    self,
                    "Test connection",
                    f"Could not connect to '{status.server_id}': {status.last_error or 'no detail reported'}",
                )
            self._refresh_list()

        def _failed(error: object) -> None:
            """Report a probe that raised.

            Args:
                error: The exception the worker caught.
            """
            self._test_button.setEnabled(True)
            self._on_worker_error(error)

        self._start_worker(self._manager.test_connection(config), _finished, _failed)

    def _on_start_server(self) -> None:
        """Start the selected server, saving the edits first."""
        config = self._apply_editor()
        if config is None:
            return
        try:
            self._manager.store.save(self._document)
        except McpError as exc:
            show_error(self, "Save failed", str(exc))
            return
        _ = self._manager.reload()
        self._status_label.setText(f"Starting '{config.server_id}'...")

        def _started(result: object) -> None:
            """Refresh after a start attempt.

            Args:
                result: The resulting status.
            """
            del result
            self._reload_document()

        self._start_worker(self._manager.start_server(config.server_id), _started, self._on_worker_error)

    def _on_stop_server(self) -> None:
        """Stop the selected server."""
        config = self._selected_config()
        if config is None:
            return

        def _stopped(result: object) -> None:
            """Refresh after the server has stopped.

            Args:
                result: Ignored.
            """
            del result
            self._refresh_list()

        self._start_worker(self._manager.stop_server(config.server_id), _stopped, self._on_worker_error)

    def _on_set_inputs(self) -> None:
        """Prompt for every input the selected server references."""
        config = self._apply_editor()
        if config is None:
            return
        referenced = config.input_ids()
        if not referenced:
            show_info(self, "Inputs", "This server references no ${input:...} values.")
            return
        for input_id in referenced:
            spec = self._document.input_spec(input_id) or McpInputSpec(
                id=input_id,
                description=f"Value for ${{input:{input_id}}} used by server '{config.server_id}'.",
                password=True,
            )
            self._document = self._document.with_input(spec)
            prompt = McpInputPromptDialog(spec, self)
            if prompt.exec() != QDialog.DialogCode.Accepted or not prompt.value:
                continue
            self._store_input(input_id, prompt.value)
        self._dirty = True

    def _store_input(self, input_id: str, value: str) -> None:
        """Write one input value to the keyring.

        Args:
            input_id: The input being set.
            value: The value to store.
        """

        def _stored(result: object) -> None:
            """Report that the value was stored.

            Args:
                result: Ignored.
            """
            del result
            _logger.info("mcp_input_saved", input_id=input_id)

        self._start_worker(self._resolver.set_input(input_id, value), _stored, self._on_worker_error)

    def _on_sign_out(self) -> None:
        """Remove the selected HTTP server's stored OAuth credentials."""
        config = self._selected_config()
        if config is None or config.http is None:
            show_info(self, "Sign out", "Only a server reached over HTTP holds OAuth credentials.")
            return
        issuer = issuer_for(config.http)

        def _done(result: object) -> None:
            """Report whether anything was removed.

            Args:
                result: ``True`` when a credential was removed.
            """
            if result is True:
                show_info(self, "Sign out", f"Signed out of '{config.server_id}'. Start it again to sign back in.")
            else:
                show_info(self, "Sign out", f"No stored credentials were found for '{config.server_id}'.")

        self._start_worker(sign_out(self._resolver.store, config.server_id, issuer), _done, self._on_worker_error)

    def refresh_auth_state(self) -> None:
        """Update the sign-out button from what the keyring actually holds."""
        config = self._selected_config()
        if config is None or config.http is None:
            self._sign_out_button.setEnabled(False)
            return

        def _checked(result: object) -> None:
            """Enable the button only when a credential exists.

            Args:
                result: ``True`` when a token is stored.
            """
            self._sign_out_button.setEnabled(result is True)

        self._start_worker(
            has_stored_credentials(self._resolver.store, config.server_id, issuer_for(config.http)),
            _checked,
            self._on_worker_error,
        )

    def _on_worker_error(self, error: object) -> None:
        """Report a background failure to the operator.

        Args:
            error: The exception the worker caught.
        """
        _logger.warning("mcp_config_operation_failed", error=str(error))
        show_error(self, "MCP", str(error))
        self._refresh_list()

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Release background workers and warn about unsaved edits.

        Args:
            a0: The close event.
        """
        if self._dirty:
            show_warning(self, "Unsaved changes", "Your MCP settings were not saved. Reopen the dialog and press Save to keep them.")
        self._release_workers()
        super().closeEvent(a0)


def _is_status(value: object) -> TypeGuard[McpServerStatus]:
    """Narrow a worker result to a server status.

    A worker delivers its result as a plain object, so the type has to be
    re-established on arrival rather than assumed.

    Args:
        value: The value the worker produced.

    Returns:
        TypeGuard[McpServerStatus]: ``True`` when the value is a status.
    """
    return isinstance(value, McpServerStatus)
