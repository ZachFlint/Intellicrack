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
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Final, TypeGuard, cast, override

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
from intellicrack.core.types import Message, ToolResultPart
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
from intellicrack.mcp.connection import McpConnection, McpHealth, McpServerStatus
from intellicrack.mcp.consent import ConsentAnswer, TrustState, server_identity
from intellicrack.mcp.errors import McpError
from intellicrack.mcp.policy import enabled_entries, estimate_tool_cost, total_cost
from intellicrack.mcp.resources import (
    PromptSummary,
    ResourceSummary,
    get_prompt,
    list_prompts,
    list_resources,
    read_resource,
    summarize_parts,
)
from intellicrack.mcp.tool_source import map_tool_to_function
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.dialogs_helpers import plain_tooltip, show_error, show_info, show_warning
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.panels.async_bridge import BridgeCallWorker, discard_worker, worker_is_running
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtCore import QObject
    from PyQt6.QtGui import QCloseEvent

    from intellicrack.mcp.catalog import McpToolEntry
    from intellicrack.mcp.connection import McpConnectionManager
    from intellicrack.mcp.consent import ApprovalStore
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
_LIVE_HEALTH: Final[frozenset[McpHealth]] = frozenset({McpHealth.READY, McpHealth.CONNECTING})
_TRUST_CAPTIONS: Final[dict[TrustState, str]] = {
    TrustState.UNTRUSTED: "not trusted: every tool call it offers is confirmed",
    TrustState.TRUSTED: "trusted: tools it marks read-only skip confirmation",
    TrustState.DENIED: "never started: it is refused without asking",
}

_HEALTH_CAPTIONS: Final[dict[McpHealth, str]] = {
    McpHealth.DISABLED: "off",
    McpHealth.DISCONNECTED: "not running",
    McpHealth.CONNECTING: "connecting",
    McpHealth.READY: "running",
    McpHealth.FAILED: "failed",
}


def _status_caption(status: McpServerStatus, config: McpServerConfig | None = None, offered: int | None = None) -> str:
    """Render one server's state as a single readable line.

    A running server is described by what the model is actually offered,
    not only by what the server published: a server switched off still
    publishes its tools but offers none of them, and saying "running, 5
    tools" about it would claim the model can use tools it cannot.

    Args:
        status: The server's current state.
        config: The server's configuration, or ``None`` when unknown.
        offered: How many of its tools are offered to the model, or ``None``
            when every published tool is.

    Returns:
        str: The server id followed by what it is doing.
    """
    caption = _HEALTH_CAPTIONS.get(status.health, status.health.value)
    if status.health is not McpHealth.READY:
        return f"{status.server_id} - {caption}"
    if config is not None and not config.enabled:
        return f"{status.server_id} - {caption}, but switched off: none of its {status.tool_count} tools are offered"
    if offered is not None and offered != status.tool_count:
        return f"{status.server_id} - {caption}, {offered} of {status.tool_count} tools offered"
    return f"{status.server_id} - {caption}, {status.tool_count} tools"


class McpServerListModel(QAbstractListModel):
    """Lists configured servers alongside what each is currently doing."""

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize an empty model.

        Args:
            parent: Parent object.
        """
        super().__init__(parent)
        self._rows: list[tuple[McpServerConfig, McpServerStatus]] = []
        self._offered: dict[str, int] = {}

    def set_rows(self, rows: list[tuple[McpServerConfig, McpServerStatus]], offered: dict[str, int] | None = None) -> None:
        """Replace every row.

        Args:
            rows: The configured servers paired with their current state.
            offered: For each running server, how many of its tools are
                offered to the model. A server missing from it offers every
                tool it published.
        """
        self.beginResetModel()
        self._rows = list(rows)
        self._offered = dict(offered or {})
        self.endResetModel()

    def caption_at(self, row: int) -> str | None:
        """Read the caption shown for one row.

        Args:
            row: The row index.

        Returns:
            str | None: The caption, or ``None`` when the row does not exist.
        """
        if not 0 <= row < len(self._rows):
            return None
        config, status = self._rows[row]
        return _status_caption(status, config, self._offered.get(config.server_id))

    def config_at(self, row: int) -> McpServerConfig | None:
        """Read the configuration at one row.

        Args:
            row: The row index.

        Returns:
            McpServerConfig | None: The configuration, or ``None`` when the
            row does not exist.
        """
        return self._rows[row][0] if 0 <= row < len(self._rows) else None

    def status_at(self, row: int) -> McpServerStatus | None:
        """Read the state at one row.

        Args:
            row: The row index.

        Returns:
            McpServerStatus | None: The state, or ``None`` when the row does
            not exist.
        """
        return self._rows[row][1] if 0 <= row < len(self._rows) else None

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
        return 0 if parent is not None and parent.isValid() else len(self._rows)

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
            return self.caption_at(index.row())
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
        description.setTextFormat(Qt.TextFormat.PlainText)
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

    Emits ``changed()`` whenever a field is edited, so the dialog knows there is something unsaved.
    """

    changed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the editor with empty fields.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._server_id = ""
        self._loading = False
        self._modified = False
        self._build_ui()

    @property
    def loaded_server_id(self) -> str:
        """The id of the server last loaded into the editor.

        Returns:
            str: The id as it was loaded, before any edit, or an empty
            string when nothing has been loaded.
        """
        return self._server_id

    @property
    def modified(self) -> bool:
        """Whether the operator has edited a field since the last load.

        Returns:
            bool: ``True`` once any field was changed by the operator.
        """
        return self._modified

    def _emit_changed(self) -> None:
        """Report an edit, unless the editor is filling its own fields."""
        if self._loading:
            return
        self._modified = True
        self.changed.emit()

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
        self._id_edit.textChanged.connect(self._emit_changed)
        shared.addRow("Server id", self._id_edit)

        self._kind_combo = QComboBox()
        self._kind_combo.setObjectName("mcp_server_kind")
        for kind in McpTransportKind:
            self._kind_combo.addItem(kind.value, kind)
        self._kind_combo.currentIndexChanged.connect(self._on_kind_changed)
        shared.addRow("Transport", self._kind_combo)

        self._enabled_box = QCheckBox("Enabled")
        self._enabled_box.setObjectName("mcp_server_enabled")
        self._enabled_box.toggled.connect(self._emit_changed)
        shared.addRow("", self._enabled_box)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setObjectName("mcp_server_timeout")
        self._timeout_spin.setRange(_MIN_TIMEOUT_S, _MAX_TIMEOUT_S)
        self._timeout_spin.valueChanged.connect(self._emit_changed)
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
        self._command_edit.textChanged.connect(self._emit_changed)
        form.addRow("Command", self._command_edit)

        self._args_edit = QPlainTextEdit()
        self._args_edit.setObjectName("mcp_stdio_args")
        self._args_edit.setPlaceholderText("one argument per line")
        self._args_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._args_edit.textChanged.connect(self._emit_changed)
        form.addRow("Arguments", self._args_edit)

        self._cwd_edit = QLineEdit()
        self._cwd_edit.setObjectName("mcp_stdio_cwd")
        self._cwd_edit.setPlaceholderText("inherited from Intellicrack")
        self._cwd_edit.textChanged.connect(self._emit_changed)
        form.addRow("Working directory", self._cwd_edit)

        self._env_edit = QPlainTextEdit()
        self._env_edit.setObjectName("mcp_stdio_env")
        self._env_edit.setPlaceholderText("NAME=${input:my-token}, one per line")
        self._env_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._env_edit.textChanged.connect(self._emit_changed)
        form.addRow("Environment", self._env_edit)

        self._env_file_edit = QLineEdit()
        self._env_file_edit.setObjectName("mcp_stdio_env_file")
        self._env_file_edit.textChanged.connect(self._emit_changed)
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
        self._url_edit.textChanged.connect(self._emit_changed)
        form.addRow("URL", self._url_edit)

        self._headers_edit = QPlainTextEdit()
        self._headers_edit.setObjectName("mcp_http_headers")
        self._headers_edit.setPlaceholderText("Authorization=Bearer ${input:my-token}, one per line")
        self._headers_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._headers_edit.textChanged.connect(self._emit_changed)
        form.addRow("Headers", self._headers_edit)

        self._query_edit = QPlainTextEdit()
        self._query_edit.setObjectName("mcp_http_query")
        self._query_edit.setPlaceholderText("toolsets=repos,issues, one per line")
        self._query_edit.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._query_edit.textChanged.connect(self._emit_changed)
        form.addRow("Query parameters", self._query_edit)

        self._client_id_edit = QLineEdit()
        self._client_id_edit.setObjectName("mcp_http_client_id")
        self._client_id_edit.setPlaceholderText("pre-registered OAuth client id, if you have one")
        self._client_id_edit.textChanged.connect(self._emit_changed)
        form.addRow("OAuth client id", self._client_id_edit)

        self._metadata_url_edit = QLineEdit()
        self._metadata_url_edit.setObjectName("mcp_http_metadata_url")
        self._metadata_url_edit.setPlaceholderText("https://example.com/mcp/client.json")
        self._metadata_url_edit.textChanged.connect(self._emit_changed)
        form.addRow("Client metadata URL", self._metadata_url_edit)
        return page

    def _on_kind_changed(self) -> None:
        """Show the page matching the selected transport."""
        kind = self.selected_kind()
        self._pages.setCurrentIndex(0 if kind is McpTransportKind.STDIO else 1)
        self._emit_changed()

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

        Loading is not an edit: it clears :attr:`modified` and reports no
        change.

        Args:
            config: The server to display.
        """
        self._loading = True
        try:
            self._fill(config)
        finally:
            self._loading = False
        self._modified = False

    def _fill(self, config: McpServerConfig) -> None:
        """Write one configuration into every field.

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

    def set_enabled(self, *, enabled: bool) -> None:
        """Tick or clear the enabled box without reporting an edit.

        Used when the dialog itself changes the configuration, such as
        switching a server on because the operator asked to start it.

        Args:
            enabled: Whether the box is ticked.
        """
        self._loading = True
        try:
            self._enabled_box.setChecked(enabled)
        finally:
            self._loading = False

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
        self._summary.setTextFormat(Qt.TextFormat.PlainText)
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
            item.setToolTip(plain_tooltip(entry.description[:512] or entry.name))
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
    resource to the conversation, and ``prompt_attached(text)`` when they
    send one of a server's prompt templates. The dialog does not reach into
    the chat itself: it fetches the content and forwards the rendered text,
    leaving the main window to decide where a conversation attachment goes.

    Edits are kept per server while the dialog is open: switching to
    another server folds the editor's changes into the document first, and
    Save writes every server's changes, not only the selected one's.
    """

    resource_attached = pyqtSignal(str)
    prompt_attached = pyqtSignal(str)

    def __init__(
        self,
        manager: McpConnectionManager,
        resolver: McpSecretResolver,
        parent: QWidget | None = None,
        *,
        approvals: ApprovalStore | None = None,
    ) -> None:
        """Initialize the settings dialog.

        Args:
            manager: The connection manager owning every server.
            resolver: Resolver used to store ``${input:id}`` values.
            parent: Parent widget.
            approvals: Store of persisted tool-call answers, listed and
                revocable on the trust tab. ``None`` lists only the answers
                remembered for this session.
        """
        super().__init__(parent)
        self._manager = manager
        self._resolver = resolver
        self._approvals = approvals
        self._document: McpConfigDocument = manager.document
        self._current_id: str | None = None
        self._workers: list[BridgeCallWorker] = []
        self._dirty = False
        self._syncing_selection = False
        self._retired: set[str] = set()
        self._prompt_arguments: dict[str, QLineEdit] = {}
        self._prompt_required: frozenset[str] = frozenset()

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
        self._status_label.setTextFormat(Qt.TextFormat.PlainText)
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
        self._tabs.addTab(self._build_prompts_pane(), "Prompts")
        self._tabs.addTab(self._build_trust_pane(), "Trust and approvals")
        return self._tabs

    def _build_prompts_pane(self) -> QWidget:
        """Build the prompt-template browser for the selected server.

        Returns:
            QWidget: The prompts pane.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)

        note = QLabel(
            "Prompts are message templates a server suggests. Fetching one runs nothing; the messages it returns are the "
            "server's own words, so they are attached to the conversation as quoted text.",
        )
        note.setObjectName("mcp_prompts_note")
        note.setWordWrap(True)
        column.addWidget(note)

        self._prompt_list = QListWidget()
        self._prompt_list.setObjectName("mcp_prompt_list")
        self._prompt_list.currentItemChanged.connect(self._on_prompt_selected)
        column.addWidget(self._prompt_list)

        self._prompt_form_host = QWidget()
        self._prompt_form = QFormLayout(self._prompt_form_host)
        self._prompt_form.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self._prompt_form_host)

        self._prompt_preview = QPlainTextEdit()
        self._prompt_preview.setObjectName("mcp_prompt_preview")
        self._prompt_preview.setReadOnly(True)
        self._prompt_preview.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        column.addWidget(self._prompt_preview)

        row = QHBoxLayout()
        row.setSpacing(8)
        list_button = QPushButton("List prompts")
        list_button.setObjectName("mcp_list_prompts")
        list_button.clicked.connect(self._on_list_prompts)
        row.addWidget(list_button)

        preview_button = QPushButton("Preview")
        preview_button.setObjectName("mcp_preview_prompt")
        preview_button.clicked.connect(self._on_preview_prompt)
        row.addWidget(preview_button)

        attach_button = QPushButton("Attach to chat")
        attach_button.setObjectName("mcp_attach_prompt")
        attach_button.clicked.connect(self._on_attach_prompt)
        row.addWidget(attach_button)
        row.addStretch()
        column.addLayout(row)
        return pane

    def _on_list_prompts(self) -> None:
        """Fetch the selected server's prompt listing."""
        connection = self._ready_connection()
        if connection is None:
            show_info(self, "Prompts", "Start the server before listing what it offers.")
            return
        self._prompt_list.clear()
        self._clear_prompt_form()

        def _listed(result: object) -> None:
            """Populate the list from the server's listing.

            Args:
                result: The list of prompt summaries.
            """
            summaries = [entry for entry in _as_object_list(result) if isinstance(entry, PromptSummary)]
            for summary in summaries:
                item = QListWidgetItem(summary.title or summary.name)
                item.setData(Qt.ItemDataRole.UserRole, summary)
                item.setToolTip(plain_tooltip(summary.description or summary.name))
                self._prompt_list.addItem(item)
            if not summaries:
                show_info(self, "Prompts", "This server offers no prompts.")

        self._start_worker(list_prompts(connection), _listed, self._on_worker_error)

    def _selected_prompt(self) -> PromptSummary | None:
        """Read the prompt selected in the list.

        Returns:
            PromptSummary | None: The selection, or ``None``.
        """
        item = self._prompt_list.currentItem()
        value: object = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return value if isinstance(value, PromptSummary) else None

    def _clear_prompt_form(self) -> None:
        """Remove every argument field from the prompt form."""
        while self._prompt_form.rowCount():
            self._prompt_form.removeRow(0)
        self._prompt_arguments = {}
        self._prompt_required = frozenset()

    def _on_prompt_selected(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        """Show an argument field for each argument the selected prompt takes.

        Args:
            current: The newly selected item.
            previous: The previously selected item.
        """
        del current, previous
        self._clear_prompt_form()
        summary = self._selected_prompt()
        if summary is None:
            return
        self._prompt_required = summary.required_arguments
        for name in summary.arguments:
            edit = QLineEdit()
            edit.setObjectName(f"mcp_prompt_argument_{name}")
            self._prompt_arguments[name] = edit
            self._prompt_form.addRow(f"{name} *" if name in summary.required_arguments else name, edit)

    def _fetch_prompt(self, on_text: Callable[[str], None]) -> None:
        """Fetch the selected prompt with the entered arguments and render it.

        Args:
            on_text: Called on the GUI thread with the rendered messages.
        """
        connection = self._ready_connection()
        summary = self._selected_prompt()
        if connection is None or summary is None:
            show_info(self, "Prompts", "Select a prompt on a running server first.")
            return
        arguments = {name: edit.text() for name, edit in self._prompt_arguments.items() if edit.text()}
        if missing := sorted(self._prompt_required - arguments.keys()):
            show_warning(self, "Prompts", f"Fill in the required argument(s): {', '.join(missing)}.")
            return

        def _fetched(result: object) -> None:
            """Render the fetched messages.

            Args:
                result: The list of messages the prompt produced.
            """
            on_text(_render_prompt_messages(_as_object_list(result)))

        self._start_worker(get_prompt(connection, summary.name, arguments), _fetched, self._on_worker_error)

    def _on_preview_prompt(self) -> None:
        """Fetch the selected prompt into the preview."""
        self._fetch_prompt(self._prompt_preview.setPlainText)

    def _on_attach_prompt(self) -> None:
        """Send the selected prompt's messages to the conversation."""

        def _attach(text: str) -> None:
            """Preview the messages and forward them to whoever is listening.

            Args:
                text: The rendered messages.
            """
            self._prompt_preview.setPlainText(text)
            self.prompt_attached.emit(text)
            _logger.info("mcp_prompt_attached", length=len(text))

        self._fetch_prompt(_attach)

    def _ready_connection(self) -> McpConnection | None:
        """Resolve the selected server's connection when it can serve requests.

        Returns:
            McpConnection | None: The connection, or ``None`` when nothing is
            selected or the server is not running.
        """
        config = self._selected_config()
        connection = self._manager.connection(config.server_id) if config is not None else None
        return connection if connection is not None and connection.is_ready else None

    def _build_trust_pane(self) -> QWidget:
        """Build the trust controls and the list of remembered tool-call answers.

        Returns:
            QWidget: The trust pane.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)

        trust_group = QGroupBox("This server")
        trust_column = QVBoxLayout(trust_group)
        self._trust_label = QLabel("Select a server.")
        self._trust_label.setObjectName("mcp_trust_state")
        self._trust_label.setTextFormat(Qt.TextFormat.PlainText)
        self._trust_label.setWordWrap(True)
        trust_column.addWidget(self._trust_label)

        trust_row = QHBoxLayout()
        trust_row.setSpacing(8)
        for caption, name, handler in (
            ("Trust", "mcp_trust_grant", self._on_trust_grant),
            ("Stop trusting", "mcp_trust_revoke", self._on_trust_revoke),
            ("Never start", "mcp_trust_block", self._on_trust_block),
            ("Forget consent and trust", "mcp_trust_reset", self._on_trust_reset),
            ("Review launch...", "mcp_trust_review", self._on_review_launch),
        ):
            button = QPushButton(caption)
            button.setObjectName(name)
            button.clicked.connect(handler)
            trust_row.addWidget(button)
        trust_row.addStretch()
        trust_column.addLayout(trust_row)
        column.addWidget(trust_group)

        approvals_group = QGroupBox("Remembered tool-call answers")
        approvals_column = QVBoxLayout(approvals_group)
        self._approvals_list = QListWidget()
        self._approvals_list.setObjectName("mcp_approvals_list")
        approvals_column.addWidget(self._approvals_list)
        approvals_row = QHBoxLayout()
        approvals_row.setSpacing(8)
        forget = QPushButton("Forget selected")
        forget.setObjectName("mcp_approvals_forget")
        forget.clicked.connect(self._on_forget_approval)
        approvals_row.addWidget(forget)
        forget_all = QPushButton("Forget all")
        forget_all.setObjectName("mcp_approvals_forget_all")
        forget_all.clicked.connect(self._on_forget_all_approvals)
        approvals_row.addWidget(forget_all)
        approvals_row.addStretch()
        approvals_column.addLayout(approvals_row)
        column.addWidget(approvals_group)
        return pane

    def _refresh_trust(self) -> None:
        """Show the selected server's trust state and whether its launch is approved."""
        config = self._selected_config()
        if config is None:
            self._trust_label.setText("Select a server.")
            return
        trust = self._manager.consent.trust
        state = trust.state_for(config)
        lines = [f"Trust: {_TRUST_CAPTIONS[state]}."]
        if config.stdio is not None:
            approved = trust.belongs_to(config) and trust.launch_digest(config.server_id) is not None
            lines.append("Launch: approved; a changed command is asked about again." if approved else "Launch: asked before it starts.")
        self._trust_label.setText("\n".join(lines))

    def _set_trust(self, state: TrustState) -> None:
        """Record a trust decision about the selected server.

        Args:
            state: The state the operator chose.
        """
        config = self._selected_config()
        if config is None:
            show_info(self, "Trust", "Select a server first.")
            return
        self._manager.consent.trust.set_state(config.server_id, state, identity=server_identity(config))
        self._refresh_trust()

    def _on_trust_grant(self) -> None:
        """Trust the selected server's claims about its own tools."""
        self._set_trust(TrustState.TRUSTED)

    def _on_trust_revoke(self) -> None:
        """Stop believing the selected server's claims about its own tools."""
        self._set_trust(TrustState.UNTRUSTED)

    def _on_trust_block(self) -> None:
        """Refuse the selected server from now on, stopping it if it runs."""
        config = self._selected_config()
        self._set_trust(TrustState.DENIED)
        if config is not None and self._manager.connection(config.server_id) is not None:
            self._start_worker(self._manager.stop_server(config.server_id), self._after_stop, self._on_worker_error)

    def _on_trust_reset(self) -> None:
        """Forget every consent and trust decision about the selected server."""
        config = self._selected_config()
        if config is None:
            show_info(self, "Trust", "Select a server first.")
            return
        self._manager.consent.trust.reset(config.server_id)
        self._refresh_trust()
        show_info(self, "Trust", f"'{config.server_id}' is untrusted again, and its launch will be asked about the next time it starts.")

    def _on_review_launch(self) -> None:
        """Show exactly what the selected local server would run, and record the answer."""
        config = self._selected_config()
        if config is None or config.stdio is None:
            show_info(self, "Review launch", "Only a local server is launched, so only a local server has a launch to review.")
            return
        probe = McpConnection(config, self._resolver)

        def _resolved(result: object) -> None:
            """Ask about the launch with the environment it would receive.

            Args:
                result: The resolved environment mapping.
            """
            env = (
                {str(name): str(value) for name, value in cast("dict[object, object]", result).items()} if isinstance(result, dict) else {}
            )
            dialog = McpServerConsentDialog.for_config(config, env, self)
            try:
                _ = dialog.exec()
                answer = ConsentAnswer(approved=dialog.approved, trusted=dialog.trusted, blocked=dialog.blocked)
            finally:
                dialog.deleteLater()
            if dialog.result() == QDialog.DialogCode.Accepted.value or answer.blocked:
                _ = self._manager.consent.record_answer(config, env, answer)
            self._refresh_trust()

        self._start_worker(probe.resolved_environment(), _resolved, self._on_worker_error)

    def _remembered_answers(self) -> list[tuple[str, str, str | None, bool, str]]:
        """Gather every remembered tool-call answer, persisted and session-only.

        Returns:
            list[tuple[str, str, str | None, bool, str]]: ``(tool, function,
            generation, approved, scope)`` for each answer, an answer kept
            both ways appearing once as ``always``.
        """
        answers: dict[tuple[str, str, str | None], tuple[bool, str]] = {
            (tool, function, generation): (approved, "this session")
            for tool, function, generation, approved in ToolConfirmationDialog.session_decisions()
        }
        if self._approvals is not None:
            for record in self._approvals.entries():
                key = (record.namespace, record.function_name, record.generation or None)
                scope = "always" if record.scope.value == "always" else "this session"
                answers[key] = (record.approved, scope)
        return [
            (tool, function, generation, approved, scope)
            for (tool, function, generation), (approved, scope) in sorted(
                answers.items(),
                key=lambda entry: (entry[0][0], entry[0][1], entry[0][2] or ""),
            )
        ]

    def _refresh_approvals(self) -> None:
        """List every remembered tool-call answer."""
        self._approvals_list.clear()
        for tool, function, generation, approved, scope in self._remembered_answers():
            verdict = "allowed" if approved else "refused"
            item = QListWidgetItem(f"{tool}.{function} - {verdict}, {scope}")
            item.setData(Qt.ItemDataRole.UserRole, (tool, function, generation))
            self._approvals_list.addItem(item)
        if not self._approvals_list.count():
            self._approvals_list.addItem(QListWidgetItem("No tool-call answers are remembered."))

    def _forget(self, tool: str, function: str, generation: str | None) -> None:
        """Forget one remembered tool-call answer everywhere it is kept.

        Args:
            tool: The tool namespace.
            function: The function name.
            generation: The generation it was recorded under.
        """
        _ = ToolConfirmationDialog.forget_decision(tool, function, generation)
        if self._approvals is not None:
            _ = self._approvals.revoke(tool, function, generation or "")

    def _on_forget_approval(self) -> None:
        """Forget the selected remembered answer."""
        item = self._approvals_list.currentItem()
        value: object = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(value, tuple):
            return
        tool, function, generation = cast("tuple[str, str, str | None]", value)
        self._forget(tool, function, generation)
        self._refresh_approvals()

    def _on_forget_all_approvals(self) -> None:
        """Forget every remembered answer."""
        for tool, function, generation, _approved, _scope in self._remembered_answers():
            self._forget(tool, function, generation)
        self._refresh_approvals()

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
        connection = self._ready_connection()
        if connection is None:
            show_info(self, "Resources", "Start the server before listing what it offers.")
            return
        self._resource_list.clear()

        def _listed(result: object) -> None:
            """Populate the list from the server's listing.

            Args:
                result: The list of resource summaries.
            """
            summaries = [entry for entry in _as_object_list(result) if isinstance(entry, ResourceSummary)]
            for summary in summaries:
                item = QListWidgetItem(f"{summary.title or summary.name} - {summary.uri}")
                item.setData(Qt.ItemDataRole.UserRole, summary.uri)
                item.setToolTip(plain_tooltip(summary.description or summary.uri))
                self._resource_list.addItem(item)
            if not summaries:
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
            parts = [entry for entry in _as_object_list(result) if isinstance(entry, ToolResultPart)]
            on_text(summarize_parts(parts))

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
        rows = [(config, statuses[config.server_id]) for config in self._document.servers if config.server_id in statuses]
        rows.extend((config, self._offline_status(config)) for config in self._document.servers if config.server_id not in statuses)
        offered: dict[str, int] = {}
        for config, _status in rows:
            connection = self._manager.connection(config.server_id)
            catalog = connection.catalog if connection is not None else None
            if catalog is not None:
                offered[config.server_id] = len(enabled_entries(config, catalog))
        self._model.set_rows(rows, offered)
        self._select(self._current_id)
        self._refresh_detail()

    def _select(self, server_id: str | None) -> None:
        """Move the list's selection to one server without treating it as a switch.

        Args:
            server_id: The server to select, or ``None`` to select nothing.
        """
        row = self._model.row_for(server_id) if server_id is not None else -1
        self._syncing_selection = True
        try:
            if row >= 0:
                self._list_view.setCurrentIndex(self._model.index(row, 0))
            else:
                self._list_view.clearSelection()
        finally:
            self._syncing_selection = False

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

        Edits made to the server being left are folded into the document
        first, so they are kept until Save rather than discarded. Edits that
        do not describe a valid server keep the selection where it is, with
        the reason shown.

        Args:
            current: The newly selected row.
            previous: The previously selected row.
        """
        del previous
        if self._syncing_selection:
            return
        config = self._model.config_at(current.row())
        target = config.server_id if config is not None else None
        if target == self._current_id:
            return
        if self._editor.modified and self._selected_config() is not None:
            if self._apply_editor() is None:
                self._select(self._current_id)
                return
            self._dirty = True
        self._current_id = target
        self._refresh_list()

    def _refresh_detail(self) -> None:
        """Refresh the editor, tool list, status, trust and sign-in state for the selection.

        An editor holding unsaved edits for the selected server is left as it
        is, so a background refresh never throws away what the operator typed.
        """
        config = self._selected_config()
        if config is None:
            self._tool_view.clear("Select a server.")
            self._status_label.setText("Select a server.")
            self._log_view.setPlainText("")
        else:
            if not (self._editor.modified and self._editor.loaded_server_id == config.server_id):
                self._editor.load(config)
            self._refresh_tools(config)
            self._refresh_status(config)
            self._refresh_log()
        self._refresh_trust()
        self._refresh_approvals()
        self.refresh_auth_state()

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
        lines = [self._model.caption_at(row) or _status_caption(status, config)]
        if status.generation:
            lines.append(f"Tool listing generation: {status.generation}")
        if status.connected_at is not None:
            lines.append(f"Connected at {status.connected_at.isoformat(timespec='seconds')}")
        if status.last_error:
            lines.append(f"Last error: {status.last_error}")
        if undeclared := missing_input_ids(self._document, [config]):
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
                f"'{candidate.server_id}' is not a usable server id. Use lower-case letters, digits and hyphens, up to 32 characters.",
            )
            return None
        try:
            candidate.validate()
        except McpError as exc:
            show_warning(self, "Server settings", str(exc))
            return None
        if existing is not None and existing.server_id != candidate.server_id:
            self._document = self._document.without_server(existing.server_id)
            self._retired.add(existing.server_id)
        self._retired.discard(candidate.server_id)
        self._document = self._document.with_server(candidate)
        self._current_id = candidate.server_id
        self._editor.load(candidate)
        return candidate

    def _persist(self) -> bool:
        """Save the document and bring running servers in line with it.

        A server that was renamed or removed is stopped under its old id --
        otherwise its process would run on, invisible in the list, until the
        application exits -- and the consent and trust recorded under that
        id are forgotten along with its remembered answers. A running server
        that is now switched off is stopped too, so the list never shows a
        server running whose tools the model is not offered.

        Returns:
            bool: ``True`` when the document was saved.
        """
        try:
            self._manager.store.save(self._document)
        except McpError as exc:
            show_error(self, "Save failed", str(exc))
            return False
        retired = sorted(self._retired - {config.server_id for config in self._document.servers})
        self._retired.clear()
        for server_id in retired:
            self._manager.consent.trust.reset(server_id)
            ToolConfirmationDialog.clear_decisions_for_source(f"mcp-{server_id}")
            if self._manager.connection(server_id) is not None:
                self._start_worker(self._manager.stop_server(server_id), self._after_stop, self._on_worker_error)
        for config in self._document.servers:
            connection = self._manager.connection(config.server_id)
            if not config.enabled and connection is not None and connection.status.health in _LIVE_HEALTH:
                self._start_worker(self._manager.stop_server(config.server_id), self._after_stop, self._on_worker_error)
        self._dirty = False
        return True

    def _after_stop(self, result: object) -> None:
        """Refresh the list once a server has stopped.

        Args:
            result: Ignored; stopping reports nothing.
        """
        del result
        self._refresh_list()

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
        self._retired.add(server_id)
        self._current_id = None
        self._dirty = True
        self._start_worker(self._manager.stop_server(server_id), self._after_stop, self._on_worker_error)

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
        if self._selected_config() is not None and self._editor.modified and self._apply_editor() is None:
            return
        if not self._persist():
            return
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
        """Start the selected server, saving the edits first.

        Starting is an explicit request to use the server, so a server that
        is switched off -- which every newly added server is -- is switched
        on first. Otherwise it would either refuse to start or run while
        offering the model nothing.
        """
        config = self._apply_editor()
        if config is None:
            return
        if not config.enabled:
            config = replace(config, enabled=True)
            self._document = self._document.with_server(config)
            self._editor.set_enabled(enabled=True)
        if not self._persist():
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
            self.refresh_auth_state()
            if result is True:
                show_info(self, "Sign out", f"Signed out of '{config.server_id}'. Start it again to sign back in.")
            else:
                show_info(self, "Sign out", f"No stored credentials were found for '{config.server_id}'.")

        self._start_worker(sign_out(self._resolver.store, config.server_id, issuer), _done, self._on_worker_error)

    def refresh_auth_state(self) -> None:
        """Update the sign-out button from what the keyring actually holds.

        Runs whenever the selection or the server's state changes, so the
        button follows the server being looked at rather than whichever one
        was selected when the dialog opened.
        """
        config = self._selected_config()
        self._sign_out_button.setEnabled(False)
        if config is None or config.http is None:
            return
        server_id = config.server_id

        def _checked(result: object) -> None:
            """Enable the button only when a credential exists for the server still selected.

            Args:
                result: ``True`` when a token is stored.
            """
            self._sign_out_button.setEnabled(result is True and self._current_id == server_id)

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

    @override
    def done(self, a0: int) -> None:
        """Release background workers on every way this dialog is dismissed.

        ``closeEvent`` covers the window being closed, but ``accept``,
        ``reject`` and the Escape key all route through here without sending a
        close event. A worker left attached at that point is destroyed with the
        dialog while its OS thread still runs, which aborts the process rather
        than failing anything. Releasing is idempotent, so the close path
        running both is harmless.

        Args:
            a0: The dialog result code.
        """
        self._release_workers()
        super().done(a0)


def _render_prompt_messages(messages: list[object]) -> str:
    """Render a fetched prompt's messages as one quoted block of text.

    Args:
        messages: The messages the prompt produced.

    Returns:
        str: Each message headed by its role, separated by blank lines.
    """
    return "\n\n".join(f"[{entry.role}]\n{entry.content}" for entry in messages if isinstance(entry, Message))


def _as_object_list(value: object) -> list[object]:
    """Narrow a background worker's result to a list of individually-checked items.

    A worker delivers whatever its coroutine returned as a plain ``object``,
    so the element type has to be re-established on arrival. Returning
    ``list[object]`` keeps every element explicitly unchecked until the
    caller tests it, rather than assuming what the worker produced.

    Args:
        value: The value the worker produced.

    Returns:
        list[object]: The elements, or an empty list when the result was not
        a list at all.
    """
    return cast("list[object]", value) if isinstance(value, list) else []


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
