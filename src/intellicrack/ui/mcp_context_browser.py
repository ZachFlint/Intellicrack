# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Browse a running server's resources and prompts from the chat, and insert them into the message being written.

The browser lists the running servers that offer resources or prompts. For the chosen server it lists its resources and resource
templates, and its prompts. A template's variables and a prompt's arguments each get a field, and as the operator types the server is
asked to complete the value, when it offers completions, the suggestions dropping down under the field. A resource can be read and a
prompt fetched into the preview, with the server's progress shown as it goes, and either inserted into the chat input; a resource can
also be subscribed to, so the operator hears when it changes, and the lists are read again whenever the server says they changed. Everything a server returns is cleaned and fenced by the functions this
module calls, the same ones the settings dialog and the model's own tools use.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtCore import QStringListModel, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.types import Message, ToolResultPart
from intellicrack.core.untrusted_text import clean_untrusted_label
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.mcp.progress import McpProgress
from intellicrack.mcp.resources import (
    CompletionSummary,
    PromptSummary,
    ResourceSummary,
    ResourceTemplateSummary,
    complete_argument,
    get_prompt,
    list_prompts,
    list_resource_templates,
    list_resources,
    read_resource,
    summarize_parts,
)
from intellicrack.mcp.uri_template import expand_uri_template, template_variables
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from intellicrack.mcp.connection import McpConnection, McpConnectionManager


_logger = get_logger(__name__)

_COMPLETION_DELAY_MS: Final[int] = 250
_SELECTION_FIELDS: Final[int] = 2
_DIALOG_WIDTH: Final[int] = 760
_DIALOG_HEIGHT: Final[int] = 560


def render_prompt_messages(messages: list[Message]) -> str:
    """Render a fetched prompt's messages for the preview and the chat.

    Args:
        messages: The prompt's messages, already fenced.

    Returns:
        str: One ``role: content`` block per message.
    """
    return "\n\n".join(f"{message.role}: {message.content}" for message in messages)


def _restart(timer: QTimer, _text: str) -> None:
    """Start a field's completion timer again after the operator typed.

    Args:
        timer: The field's timer.
        _text: What is in the field now.
    """
    timer.start()


class _ArgumentForm(QWidget):
    """One field per argument, each completed by the server as it is typed."""

    def __init__(self, request_completion: Callable[[str, str, dict[str, str], QCompleter], None], parent: QWidget | None = None) -> None:
        """Build an empty form.

        Args:
            request_completion: Asks the server to complete one argument,
                given its name, what is typed so far, the other arguments'
                values and the completer to fill.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._request_completion = request_completion
        self._layout = QFormLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._fields: dict[str, QLineEdit] = {}

    def show_arguments(self, names: list[str], required: frozenset[str]) -> None:
        """Replace the fields with one per argument.

        Args:
            names: The arguments, in order.
            required: Those that must be filled.
        """
        while self._layout.rowCount():
            self._layout.removeRow(0)
        self._fields = {}
        for name in names:
            field = QLineEdit()
            field.setObjectName(f"mcp_context_argument_{name}")
            completer = QCompleter(QStringListModel([], field), field)
            completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
            field.setCompleter(completer)
            timer = QTimer(field)
            timer.setSingleShot(True)
            timer.setInterval(_COMPLETION_DELAY_MS)
            timer.timeout.connect(partial(self._complete, name, field, completer))
            field.textEdited.connect(partial(_restart, timer))
            label = f"{clean_untrusted_label(name)}{' *' if name in required else ''}"
            self._layout.addRow(label, field)
            self._fields[name] = field

    def _complete(self, argument: str, field: QLineEdit, completer: QCompleter) -> None:
        """Ask for completions of one argument.

        Args:
            argument: The argument.
            field: Its field.
            completer: The completer to fill.
        """
        context = {name: edit.text() for name, edit in self._fields.items() if name != argument and edit.text()}
        self._request_completion(argument, field.text(), context, completer)

    def values(self) -> dict[str, str]:
        """Read the filled-in arguments.

        Returns:
            dict[str, str]: Each argument with a value.
        """
        return {name: field.text() for name, field in self._fields.items() if field.text()}


class McpContextBrowser(QDialog):
    """Browses one running server's resources and prompts and inserts them into the chat.

    Emits ``inserted(text)`` with the rendered resource or prompt the
    operator chose to insert.
    """

    inserted = pyqtSignal(str)
    _progressed = pyqtSignal(object)

    def __init__(self, manager: McpConnectionManager, parent: QWidget | None = None) -> None:
        """Build the browser over the running servers.

        Args:
            manager: The connection manager.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("MCP resources and prompts")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)
        self._manager = manager
        self._resources: list[ResourceSummary] = []
        self._templates: list[ResourceTemplateSummary] = []
        self._prompts: list[PromptSummary] = []
        self._progressed.connect(self._on_progress)
        self._build_ui()
        self._fill_servers()

    def _build_ui(self) -> None:
        """Lay out the server choice, the two tabs, the progress line and the buttons."""
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Server:"))
        self._server_combo = QComboBox()
        self._server_combo.setObjectName("mcp_context_server")
        self._server_combo.currentIndexChanged.connect(self._on_server_chosen)
        row.addWidget(self._server_combo, 1)
        layout.addLayout(row)
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_resources_tab(), "Resources")
        self._tabs.addTab(self._build_prompts_tab(), "Prompts")
        layout.addWidget(self._tabs, 1)
        self._progress = QLabel("")
        self._progress.setObjectName("mcp_context_progress")
        self._progress.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._progress)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_resources_tab(self) -> QWidget:
        """Build the resources tab.

        Returns:
            QWidget: The tab.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        self._resource_list = QListWidget()
        self._resource_list.setObjectName("mcp_context_resources")
        self._resource_list.currentItemChanged.connect(self._on_resource_row_changed)
        column.addWidget(self._resource_list, 1)
        self._template_form = _ArgumentForm(self._complete_template_argument)
        column.addWidget(self._template_form)
        self._resource_preview = QPlainTextEdit()
        self._resource_preview.setObjectName("mcp_context_resource_preview")
        self._resource_preview.setReadOnly(True)
        column.addWidget(self._resource_preview, 1)
        buttons = QHBoxLayout()
        read = QPushButton("Read")
        read.setObjectName("mcp_context_read")
        read.clicked.connect(self._on_read)
        buttons.addWidget(read)
        insert = QPushButton("Insert into message")
        insert.setObjectName("mcp_context_insert_resource")
        insert.clicked.connect(lambda: self._insert(self._resource_preview.toPlainText()))
        buttons.addWidget(insert)
        self._subscribe_button = QPushButton("Subscribe")
        self._subscribe_button.setObjectName("mcp_context_subscribe")
        self._subscribe_button.setToolTip("Be told when this resource changes.")
        self._subscribe_button.clicked.connect(self._on_toggle_subscription)
        buttons.addWidget(self._subscribe_button)
        buttons.addStretch(1)
        column.addLayout(buttons)
        return pane

    def _build_prompts_tab(self) -> QWidget:
        """Build the prompts tab.

        Returns:
            QWidget: The tab.
        """
        pane = QWidget()
        column = QVBoxLayout(pane)
        self._prompt_list = QListWidget()
        self._prompt_list.setObjectName("mcp_context_prompts")
        self._prompt_list.currentItemChanged.connect(self._on_prompt_row_changed)
        column.addWidget(self._prompt_list, 1)
        self._prompt_form = _ArgumentForm(self._complete_prompt_argument)
        column.addWidget(self._prompt_form)
        self._prompt_preview = QPlainTextEdit()
        self._prompt_preview.setObjectName("mcp_context_prompt_preview")
        self._prompt_preview.setReadOnly(True)
        column.addWidget(self._prompt_preview, 1)
        buttons = QHBoxLayout()
        fetch = QPushButton("Preview")
        fetch.setObjectName("mcp_context_preview_prompt")
        fetch.clicked.connect(self._on_fetch_prompt)
        buttons.addWidget(fetch)
        insert = QPushButton("Insert into message")
        insert.setObjectName("mcp_context_insert_prompt")
        insert.clicked.connect(lambda: self._insert(self._prompt_preview.toPlainText()))
        buttons.addWidget(insert)
        buttons.addStretch(1)
        column.addLayout(buttons)
        return pane

    def _on_server_chosen(self, _index: int) -> None:
        """List the newly chosen server's resources and prompts.

        Args:
            _index: The chosen row.
        """
        self._load_server()

    def _on_resource_row_changed(self, _current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        """Follow the resource selection.

        Args:
            _current: The newly selected row.
            _previous: The row selected before.
        """
        self._on_resource_selected()

    def _on_prompt_row_changed(self, _current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        """Follow the prompt selection.

        Args:
            _current: The newly selected row.
            _previous: The row selected before.
        """
        self._on_prompt_selected()

    def _fill_servers(self) -> None:
        """List the running servers that offer resources or prompts."""
        for status in self._manager.statuses():
            connection = self._manager.connection(status.server_id)
            client = connection.client if connection is not None and connection.is_ready else None
            if client is None:
                continue
            capabilities = client.server_capabilities
            if capabilities.resources is not None or capabilities.prompts is not None:
                self._server_combo.addItem(status.server_id, status.server_id)
        if self._server_combo.count() == 0:
            self._progress.setText("No running server offers resources or prompts.")

    def _connection(self) -> McpConnection | None:
        """Find the chosen server's connection, while it is running.

        Returns:
            McpConnection | None: The connection, or ``None``.
        """
        server_id: object = self._server_combo.currentData()
        if not isinstance(server_id, str):
            return None
        connection = self._manager.connection(server_id)
        return connection if connection is not None and connection.is_ready else None

    def _run(self, coro: Coroutine[object, object, object], on_success: Callable[[object], None]) -> None:
        """Run one request on the background loop.

        Args:
            coro: The request.
            on_success: Called on the GUI thread with its result.
        """
        run_bridge_coroutine_async(coro, on_success, self._on_error, self)

    def _on_error(self, error: object) -> None:
        """Show why a request failed.

        Args:
            error: The exception.
        """
        _logger.warning("mcp_context_request_failed", error=str(error))
        self._progress.setText(f"Failed: {clean_untrusted_label(str(error))}")

    def _load_server(self) -> None:
        """List the chosen server's resources, templates and prompts."""
        self._resource_list.clear()
        self._prompt_list.clear()
        connection = self._connection()
        if connection is None:
            return
        capabilities = connection.client.server_capabilities if connection.client is not None else None
        if capabilities is not None and capabilities.resources is not None:
            self._run(list_resources(connection), self._show_resources)
            self._run(list_resource_templates(connection), self._show_templates)
        if capabilities is not None and capabilities.prompts is not None:
            self._run(list_prompts(connection), self._show_prompts)

    def _show_resources(self, result: object) -> None:
        """List the resources.

        Args:
            result: The resources.
        """
        self._resources = [entry for entry in _as_list(result) if isinstance(entry, ResourceSummary)]
        for entry in self._resources:
            item = QListWidgetItem(f"{entry.name}  {clean_untrusted_label(entry.uri)}")
            item.setData(Qt.ItemDataRole.UserRole, ("resource", entry.uri))
            self._resource_list.addItem(item)

    def _show_templates(self, result: object) -> None:
        """List the resource templates after the resources.

        Args:
            result: The templates.
        """
        self._templates = [entry for entry in _as_list(result) if isinstance(entry, ResourceTemplateSummary)]
        for entry in self._templates:
            item = QListWidgetItem(f"{entry.name}  {clean_untrusted_label(entry.uri_template)}  (template)")
            item.setData(Qt.ItemDataRole.UserRole, ("template", entry.uri_template))
            self._resource_list.addItem(item)

    def _show_prompts(self, result: object) -> None:
        """List the prompts.

        Args:
            result: The prompts.
        """
        self._prompts = [entry for entry in _as_list(result) if isinstance(entry, PromptSummary)]
        for entry in self._prompts:
            item = QListWidgetItem(clean_untrusted_label(entry.title or entry.name))
            item.setData(Qt.ItemDataRole.UserRole, entry.name)
            self._prompt_list.addItem(item)

    def _selected_resource(self) -> tuple[str, str] | None:
        """Read what the selected resource row is.

        Returns:
            tuple[str, str] | None: ``("resource", uri)`` or
            ``("template", uri_template)``, or ``None``.
        """
        item = self._resource_list.currentItem()
        data: object = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if isinstance(data, tuple) and len(entries := cast("tuple[object, ...]", data)) == _SELECTION_FIELDS:
            kind, value = entries
            if isinstance(kind, str) and isinstance(value, str):
                return kind, value
        return None

    def _on_resource_selected(self) -> None:
        """Show fields for a template's variables, or none for a plain resource."""
        selected = self._selected_resource()
        if selected is not None and selected[0] == "template":
            try:
                names = template_variables(selected[1])
            except ValueError as exc:
                self._progress.setText(f"The template cannot be filled in: {exc}")
                names = []
            self._template_form.show_arguments(names, frozenset(names))
        else:
            self._template_form.show_arguments([], frozenset())
        self._update_subscribe_button()

    def _selected_uri(self) -> str | None:
        """Work out the URI the selection reads.

        Returns:
            str | None: The resource's URI, or the template filled in, or
            ``None`` when nothing usable is selected.
        """
        selected = self._selected_resource()
        if selected is None:
            return None
        kind, value = selected
        if kind == "resource":
            return value
        try:
            return expand_uri_template(value, self._template_form.values())
        except ValueError as exc:
            self._progress.setText(f"The template cannot be filled in: {exc}")
            return None

    def _on_read(self) -> None:
        """Read the selected resource into the preview."""
        connection = self._connection()
        uri = self._selected_uri()
        if connection is None or uri is None:
            self._progress.setText("Select a resource on a running server first.")
            return
        self._progress.setText(f"Reading {clean_untrusted_label(uri)}...")

        def _show(result: object) -> None:
            """Show what was read.

            Args:
                result: The resource's parts.
            """
            parts = [entry for entry in _as_list(result) if isinstance(entry, ToolResultPart)]
            self._resource_preview.setPlainText(summarize_parts(parts))

        self._run(read_resource(connection, uri, on_progress=self._progressed.emit), _show)

    def _update_subscribe_button(self) -> None:
        """Offer to subscribe or unsubscribe, for a server that allows subscriptions."""
        connection = self._connection()
        uri = self._selected_uri()
        client = connection.client if connection is not None else None
        resources = client.server_capabilities.resources if client is not None else None
        allowed = uri is not None and resources is not None and bool(resources.subscribe)
        self._subscribe_button.setEnabled(allowed)
        subscribed = connection is not None and uri is not None and uri in connection.subscriptions
        self._subscribe_button.setText("Unsubscribe" if subscribed else "Subscribe")

    def _on_toggle_subscription(self) -> None:
        """Subscribe to the selected resource, or stop."""
        connection = self._connection()
        uri = self._selected_uri()
        if connection is None or uri is None:
            return
        subscribed = uri in connection.subscriptions
        action = connection.unsubscribe_resource(uri) if subscribed else connection.subscribe_resource(uri)

        def _done(_result: object) -> None:
            """Show the new state.

            Args:
                _result: Nothing.
            """
            self._progress.setText(f"{'Unsubscribed from' if subscribed else 'Subscribed to'} {clean_untrusted_label(uri)}.")
            self._update_subscribe_button()

        self._run(action, _done)

    def _selected_prompt(self) -> PromptSummary | None:
        """Find the selected prompt.

        Returns:
            PromptSummary | None: The prompt, or ``None``.
        """
        item = self._prompt_list.currentItem()
        name: object = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return next((entry for entry in self._prompts if entry.name == name), None)

    def _on_prompt_selected(self) -> None:
        """Show fields for the selected prompt's arguments."""
        prompt = self._selected_prompt()
        if prompt is None:
            self._prompt_form.show_arguments([], frozenset())
            return
        self._prompt_form.show_arguments(list(prompt.arguments), prompt.required_arguments)

    def _on_fetch_prompt(self) -> None:
        """Fetch the selected prompt into the preview."""
        connection = self._connection()
        prompt = self._selected_prompt()
        if connection is None or prompt is None:
            self._progress.setText("Select a prompt on a running server first.")
            return
        values = self._prompt_form.values()
        if missing := sorted(prompt.required_arguments - values.keys()):
            self._progress.setText(f"Fill in the required argument(s): {', '.join(clean_untrusted_label(name) for name in missing)}.")
            return
        self._progress.setText(f"Fetching {clean_untrusted_label(prompt.name)}...")

        def _show(result: object) -> None:
            """Show the fetched messages.

            Args:
                result: The prompt's messages.
            """
            self._prompt_preview.setPlainText(render_prompt_messages([entry for entry in _as_list(result) if isinstance(entry, Message)]))

        self._run(get_prompt(connection, prompt.name, values, on_progress=self._progressed.emit), _show)

    def _complete_template_argument(self, argument: str, value: str, context: dict[str, str], completer: QCompleter) -> None:
        """Ask the server to complete one of a template's variables.

        Args:
            argument: The variable.
            value: What is typed so far.
            context: The other variables' values.
            completer: The completer to fill.
        """
        selected = self._selected_resource()
        if selected is not None and selected[0] == "template":
            self._request_completion(argument, value, context, completer, prompt=False, reference=selected[1])

    def _complete_prompt_argument(self, argument: str, value: str, context: dict[str, str], completer: QCompleter) -> None:
        """Ask the server to complete one of a prompt's arguments.

        Args:
            argument: The argument.
            value: What is typed so far.
            context: The other arguments' values.
            completer: The completer to fill.
        """
        prompt = self._selected_prompt()
        if prompt is not None:
            self._request_completion(argument, value, context, completer, prompt=True, reference=prompt.name)

    def _request_completion(
        self,
        argument: str,
        value: str,
        context: dict[str, str],
        completer: QCompleter,
        *,
        prompt: bool,
        reference: str,
    ) -> None:
        """Ask the server for completions and drop them down under the field.

        A server that does not offer completions is not asked.

        Args:
            argument: The argument.
            value: What is typed so far.
            context: The other arguments' values.
            completer: The completer to fill.
            prompt: Whether the argument is a prompt's rather than a template's.
            reference: The prompt's name or the template's URI template.
        """
        connection = self._connection()
        client = connection.client if connection is not None else None
        if connection is None or client is None or client.server_capabilities.completions is None:
            return

        def _offer(result: object) -> None:
            """Offer the suggestions.

            Args:
                result: The completion.
            """
            values = list(result.values) if isinstance(result, CompletionSummary) else []
            model = completer.model()
            if isinstance(model, QStringListModel):
                model.setStringList(values)
            if values:
                completer.complete()

        self._run(
            complete_argument(connection, prompt=prompt, reference=reference, argument=argument, value=value, context=context),
            _offer,
        )

    def _insert(self, text: str) -> None:
        """Hand the previewed text to the chat.

        Args:
            text: The rendered resource or prompt.
        """
        if not text:
            self._progress.setText("Read or preview something first.")
            return
        self.inserted.emit(text)
        self._progress.setText("Inserted into the message.")

    def on_context_event(self, payload: object) -> None:
        """Follow a change the chosen server announced.

        A changed list of resources or prompts is listed again; an updated
        resource is named, so the operator can read it again.

        Args:
            payload: The :class:`~intellicrack.mcp.context_events.McpContextEvent`.
        """
        if not isinstance(payload, McpContextEvent) or payload.server_id != self._server_combo.currentData():
            return
        if payload.change is McpContextChange.RESOURCE_UPDATED:
            self._progress.setText(f"{clean_untrusted_label(payload.uri or '')} changed; read it again to see the new contents.")
            return
        self._load_server()
        self._progress.setText("The server changed its resources or prompts; listed them again.")

    def _on_progress(self, progress: object) -> None:
        """Show how far a read or fetch has got.

        Args:
            progress: The :class:`~intellicrack.mcp.progress.McpProgress`.
        """
        if isinstance(progress, McpProgress):
            self._progress.setText(f"{progress.subject}: {progress.describe()}")


def _as_list(result: object) -> list[object]:
    """Treat a background result as a list.

    Args:
        result: The result.

    Returns:
        list[object]: Its entries, or none when it is not a list.
    """
    return list(cast("list[object]", result)) if isinstance(result, list) else []
