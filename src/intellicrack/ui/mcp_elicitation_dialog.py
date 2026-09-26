# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Dialog answering an MCP server's request for information from the operator.

A server may pause mid-call and ask for something it needs: a directory to work in, a confirmation, a choice between options. The protocol
calls this elicitation, and it arrives in one of two shapes. A form request carries a small JSON Schema describing the fields it wants; a
URL request asks the operator to go somewhere and come back.

Three answers exist and they are not interchangeable. Accepting returns the values. Declining says no to the request while leaving the call
running. Cancelling abandons the exchange. Closing the window is a cancel, never an accept, so a dismissed dialog can never be read as
consent.

A server must never ask for a credential this way. The dialog says so, every time, because the operator is the only one who can tell whether
a field labelled "API key" is a legitimate request.
"""

from __future__ import annotations

import asyncio
import enum
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Final, override
from urllib.parse import urlsplit

from mcp_types import ElicitResult
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.mcp.tool_source import sanitize_untrusted_text
from intellicrack.mcp.transport import open_web_url
from intellicrack.mcp.validation import validate_against_schema
from intellicrack.ui.dialogs_helpers import plain_tooltip, show_warning


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from mcp_types import ElicitRequestParams
    from PyQt6.QtGui import QCloseEvent


_logger = get_logger(__name__)


ElicitValue = str | int | float | bool | list[str] | None
"""What one answered field may carry, matching the protocol's content type."""

_DIALOG_MIN_WIDTH: Final[int] = 560
_MESSAGE_MAX_CHARS: Final[int] = 4096
_MAX_FIELDS: Final[int] = 32
_MAX_CHOICES: Final[int] = 256
_CHOICE_LIST_MAX_HEIGHT: Final[int] = 160
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class _FieldKind(enum.Enum):
    """The editor a requested field is answered with.

    Attributes:
        TEXT: Free text, bounded by the schema's length and pattern.
        INTEGER: A whole number, bounded by the schema's range.
        NUMBER: Any number, bounded by the schema's range.
        BOOLEAN: A yes-or-no switch.
        CHOICE: One value from a fixed list.
        MULTI_CHOICE: Any number of values from a fixed list.
    """

    TEXT = "text"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    CHOICE = "choice"
    MULTI_CHOICE = "multi_choice"


@dataclass(eq=False)
class _Field:
    """One requested field, its schema, and the widgets answering it.

    Attributes:
        name: The property name from the schema.
        schema: The field's schema node.
        kind: The editor it is answered with.
        required: Whether the schema requires an answer.
        editor: The widget holding the answer.
        error: The label showing what is wrong with the answer.
    """

    name: str
    schema: Mapping[str, Any]
    kind: _FieldKind
    required: bool
    editor: QWidget
    error: QLabel


def _choices(options: object, *, legacy_names: object = None) -> list[tuple[str, str]]:
    """Read the values a single- or multi-select field offers, with captions.

    Two shapes are accepted: a plain ``enum`` of strings, optionally paired
    with the legacy ``enumNames`` captions, and a titled ``oneOf``/``anyOf``
    list of ``{"const": value, "title": caption}`` entries.

    Args:
        options: The ``enum`` array, or the ``oneOf``/``anyOf`` array.
        legacy_names: The ``enumNames`` array paired with a plain ``enum``.

    Returns:
        list[tuple[str, str]]: ``(value, caption)`` pairs in schema order,
        empty when the node offers no usable choices.
    """
    if not is_json_array(options):
        return []
    names: list[Any] = legacy_names if is_json_array(legacy_names) and len(legacy_names) == len(options) else []
    pairs: list[tuple[str, str]] = []
    for index, option in enumerate(options[:_MAX_CHOICES]):
        if isinstance(option, str):
            caption: object = names[index] if names else option
            pairs.append((option, caption if isinstance(caption, str) and caption else option))
        elif is_json_object(option) and isinstance(option.get("const"), str):
            value = str(option["const"])
            title = option.get("title")
            pairs.append((value, title if isinstance(title, str) and title else value))
    return pairs


def _single_choices(definition: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Read the choices a single-select field offers.

    Args:
        definition: The field's schema node.

    Returns:
        list[tuple[str, str]]: ``(value, caption)`` pairs, empty for a field
        that is not a single-select.
    """
    if "enum" in definition:
        return _choices(definition.get("enum"), legacy_names=definition.get("enumNames"))
    return _choices(definition.get("oneOf"))


def _multi_choices(definition: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Read the choices a multi-select field offers.

    Args:
        definition: The field's schema node.

    Returns:
        list[tuple[str, str]]: ``(value, caption)`` pairs, empty for a field
        that is not a multi-select.
    """
    if definition.get("type") != "array":
        return []
    items = definition.get("items")
    if not is_json_object(items):
        return []
    if "enum" in items:
        return _choices(items.get("enum"))
    return _choices(items.get("anyOf") if "anyOf" in items else items.get("oneOf"))


def _field_kind(definition: Mapping[str, Any]) -> _FieldKind:
    """Decide which editor answers a field.

    Args:
        definition: The field's schema node.

    Returns:
        _FieldKind: The editor kind. Anything unrecognised is answered as
        text, which the schema check then judges.
    """
    if _multi_choices(definition):
        return _FieldKind.MULTI_CHOICE
    if _single_choices(definition):
        return _FieldKind.CHOICE
    declared = definition.get("type")
    if declared == "boolean":
        return _FieldKind.BOOLEAN
    if declared == "integer":
        return _FieldKind.INTEGER
    if declared == "number":
        return _FieldKind.NUMBER
    return _FieldKind.TEXT


def _format_problem(value: str, declared_format: object) -> str | None:
    """Check a text answer against the schema's ``format``.

    Args:
        value: The answer.
        declared_format: The schema's ``format`` keyword.

    Returns:
        str | None: What is wrong with the answer, or ``None`` when it fits.
    """
    if declared_format == "email" and _EMAIL_PATTERN.fullmatch(value) is None:
        return "must be an email address"
    if declared_format == "uri":
        parts = urlsplit(value)
        if not parts.scheme or not (parts.netloc or parts.path):
            return "must be a full address, including its scheme"
    if declared_format == "date":
        try:
            _ = date.fromisoformat(value)
        except ValueError:
            return "must be a date written as YYYY-MM-DD"
    if declared_format == "date-time":
        try:
            _ = datetime.fromisoformat(value)
        except ValueError:
            return "must be a date and time written as YYYY-MM-DDTHH:MM:SS"
    return None


def _is_number(value: object) -> bool:
    """Report whether a schema value is a JSON number.

    Args:
        value: The value to test.

    Returns:
        bool: ``True`` for an ``int`` or ``float`` that is not a ``bool``.
    """
    return isinstance(value, int | float) and not isinstance(value, bool)


def _range_hint(definition: Mapping[str, Any]) -> str:
    """Describe the bounds a numeric field accepts.

    Args:
        definition: The field's schema node.

    Returns:
        str: A short hint, empty for an unbounded field.
    """
    minimum = definition.get("minimum")
    maximum = definition.get("maximum")
    if _is_number(minimum) and _is_number(maximum):
        return f"from {minimum} to {maximum}"
    if _is_number(minimum):
        return f"at least {minimum}"
    if _is_number(maximum):
        return f"at most {maximum}"
    return ""


def _parse_number(text: str, kind: _FieldKind) -> int | float | None:
    """Read a numeric answer as the type its field declares.

    Args:
        text: The text the operator entered.
        kind: :attr:`_FieldKind.INTEGER` or :attr:`_FieldKind.NUMBER`.

    Returns:
        int | float | None: The number, or ``None`` when the text is not one.
    """
    if kind is _FieldKind.INTEGER:
        try:
            return int(text)
        except ValueError:
            return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return None


class McpElicitationDialog(QDialog):
    """Collects one server's requested values, or refuses on the operator's behalf.

    The form follows the schema the server sent: each field gets the editor its type calls for, an optional field left alone is omitted
    rather than sent with an invented value, and every bound the schema states -- length, range, pattern, format, item count -- is checked
    before anything is sent. A field that fails says why beside itself.

    Emits ``answered(action: str)`` with ``accept``, ``decline`` or ``cancel`` once the operator has decided.
    """

    answered = pyqtSignal(str)

    def __init__(
        self,
        server_id: str,
        params: ElicitRequestParams,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the elicitation dialog.

        Args:
            server_id: The server asking.
            params: The form or URL request the server sent.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._server_id = server_id
        self._params = params
        self._action = "cancel"
        self._content: dict[str, ElicitValue] = {}
        self._fields: dict[str, _Field] = {}
        self._required: set[str] = set()
        self._url = ""
        self._setup_ui()

    @property
    def action(self) -> str:
        """The operator's answer.

        Returns:
            str: ``accept``, ``decline``, or ``cancel``. A dialog that was
            closed without an answer reports ``cancel``.
        """
        return self._action

    @property
    def content(self) -> dict[str, ElicitValue]:
        """The values the operator supplied.

        Returns:
            dict[str, ElicitValue]: The answered fields, empty unless the
            operator accepted a form.
        """
        return dict(self._content)

    @property
    def is_url_request(self) -> bool:
        """Whether the server asked the operator to visit an address.

        Returns:
            bool: ``True`` for a URL-mode request.
        """
        return self._params.mode == "url"

    def to_result(self) -> ElicitResult:
        """Render the operator's answer as a protocol result.

        Returns:
            ElicitResult: The result to return to the server. Content is
            attached only when a form was accepted; a URL-mode acceptance
            carries none, because the interaction happens out of band.
        """
        if self._action == "accept":
            if self.is_url_request:
                return ElicitResult(action="accept")
            return ElicitResult(action="accept", content=dict(self._content))
        return ElicitResult(action="decline" if self._action == "decline" else "cancel")

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle(f"MCP server '{self._server_id}' needs information")
        self.setMinimumWidth(_DIALOG_MIN_WIDTH)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QLabel(f"The MCP server '{self._server_id}' is asking you for information.")
        header.setObjectName("mcp_elicit_header")
        header.setWordWrap(True)
        layout.addWidget(header)

        message = QLabel(sanitize_untrusted_text(self._params.message, limit=_MESSAGE_MAX_CHARS))
        message.setTextFormat(Qt.TextFormat.PlainText)
        message.setObjectName("mcp_elicit_message")
        message.setWordWrap(True)
        message.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(message)

        caution = QLabel(
            "A server must never ask you for a password, an API key or any other credential this way. If it is asking for one, decline.",
        )
        caution.setObjectName("mcp_elicit_caution")
        caution.setWordWrap(True)
        layout.addWidget(caution)

        if self.is_url_request:
            layout.addWidget(self._build_url_section())
        else:
            layout.addLayout(self._build_form())

        self._summary = QLabel("")
        self._summary.setObjectName("mcp_elicit_errors")
        self._summary.setTextFormat(Qt.TextFormat.PlainText)
        self._summary.setWordWrap(True)
        self._summary.setVisible(False)
        layout.addWidget(self._summary)

        layout.addLayout(self._build_buttons())

    def _build_url_section(self) -> QWidget:
        """Build the body for a URL-mode request.

        Returns:
            QWidget: A widget showing the destination and an open button.
        """
        container = QWidget()
        row = QVBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)

        url = str(getattr(self._params, "url", ""))
        label = QLabel(f"It wants you to visit:\n{url}")
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setObjectName("mcp_elicit_url")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(label)

        open_button = QPushButton("Open in browser")
        open_button.setObjectName("mcp_elicit_open")
        open_button.clicked.connect(self._on_open_url)
        row.addWidget(open_button)
        self._url = url
        return container

    def _build_form(self) -> QFormLayout:
        """Build editors for each field the server's schema requests.

        Returns:
            QFormLayout: The populated form.
        """
        form = QFormLayout()
        form.setSpacing(10)
        schema: object = getattr(self._params, "requested_schema", None)
        properties: object = schema.get("properties") if is_json_object(schema) else None
        required: object = schema.get("required") if is_json_object(schema) else None
        if is_json_array(required):
            self._required = {name for name in required if isinstance(name, str)}
        if not is_json_object(properties):
            form.addRow(QLabel("The server requested no specific fields."))
            return form

        for index, (name, definition) in enumerate(properties.items()):
            if index >= _MAX_FIELDS:
                form.addRow(QLabel(f"[{len(properties) - _MAX_FIELDS} further field(s) not shown]"))
                break
            if not is_json_object(definition):
                continue
            form.addRow(self._field_label(name, definition), self._build_field(name, definition))
        return form

    def _build_field(self, name: str, definition: Mapping[str, Any]) -> QWidget:
        """Build one field's editor and the label reporting its problems.

        Args:
            name: The field name from the schema.
            definition: The field's schema node.

        Returns:
            QWidget: A cell holding the editor above its error label.
        """
        kind = _field_kind(definition)
        required = name in self._required
        editor = self._build_editor(kind, definition, required=required)
        editor.setObjectName(f"mcp_elicit_field_{name}")
        error = QLabel("")
        error.setObjectName(f"mcp_elicit_error_{name}")
        error.setTextFormat(Qt.TextFormat.PlainText)
        error.setWordWrap(True)
        error.setVisible(False)
        self._fields[name] = _Field(name=name, schema=definition, kind=kind, required=required, editor=editor, error=error)

        cell = QWidget()
        column = QVBoxLayout(cell)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        column.addWidget(editor)
        column.addWidget(error)
        return cell

    def _field_label(self, name: str, definition: Mapping[str, Any]) -> QLabel:
        """Build the caption for one requested field.

        Args:
            name: The field name from the schema.
            definition: The field's schema node.

        Returns:
            QLabel: A caption carrying the title, the required marker, and
            the server's description as a tooltip.
        """
        title = definition.get("title")
        caption = title if isinstance(title, str) and title else name
        if name in self._required:
            caption = f"{caption} *"
        label = QLabel(caption)
        label.setTextFormat(Qt.TextFormat.PlainText)
        description = definition.get("description")
        if isinstance(description, str) and description:
            label.setToolTip(plain_tooltip(sanitize_untrusted_text(description, limit=_MESSAGE_MAX_CHARS)))
        return label

    @staticmethod
    def _build_editor(kind: _FieldKind, definition: Mapping[str, Any], *, required: bool) -> QWidget:
        """Build the editor widget for one requested field.

        Args:
            kind: The editor kind the field calls for.
            definition: The field's schema node.
            required: Whether the field must be answered.

        Returns:
            QWidget: A list of check boxes for a multi-select, a combo box
            for a single-select, a check box for a boolean, and a line edit
            for text and numbers, pre-filled from the schema's default.
        """
        default = definition.get("default")
        if kind is _FieldKind.MULTI_CHOICE:
            chosen = {item for item in default if isinstance(item, str)} if is_json_array(default) else set[str]()
            listing = QListWidget()
            listing.setMaximumHeight(_CHOICE_LIST_MAX_HEIGHT)
            for value, caption in _multi_choices(definition):
                item = QListWidgetItem(caption)
                item.setData(Qt.ItemDataRole.UserRole, value)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked if value in chosen else Qt.CheckState.Unchecked)
                listing.addItem(item)
            return listing
        if kind is _FieldKind.CHOICE:
            combo = QComboBox()
            combo.addItem("(choose one)" if required else "(no answer)", None)
            for value, caption in _single_choices(definition):
                combo.addItem(caption, value)
            if isinstance(default, str) and (index := combo.findData(default)) >= 0:
                combo.setCurrentIndex(index)
            return combo
        if kind is _FieldKind.BOOLEAN:
            box = QCheckBox()
            box.setChecked(default is True)
            return box

        line = QLineEdit()
        if kind in {_FieldKind.INTEGER, _FieldKind.NUMBER}:
            if _is_number(default):
                line.setText(str(default))
            noun = "a whole number" if kind is _FieldKind.INTEGER else "a number"
            hint = f"{noun} {_range_hint(definition)}".strip()
            line.setPlaceholderText(hint if required else f"optional, {hint}")
            return line
        if isinstance(default, str):
            line.setText(default)
        max_length = definition.get("maxLength")
        if isinstance(max_length, int) and not isinstance(max_length, bool) and max_length > 0:
            line.setMaxLength(max_length)
        declared_format = definition.get("format")
        if isinstance(declared_format, str) and declared_format in {"uri", "email", "date", "date-time"}:
            line.setPlaceholderText(declared_format)
        return line

    def _build_buttons(self) -> QHBoxLayout:
        """Build the answer buttons.

        Returns:
            QHBoxLayout: The button row.
        """
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addStretch()

        cancel = QPushButton("Cancel")
        cancel.setObjectName("mcp_elicit_cancel")
        cancel.clicked.connect(self._on_cancel)
        cancel.setDefault(True)
        row.addWidget(cancel)

        decline = QPushButton("Decline")
        decline.setObjectName("mcp_elicit_decline")
        decline.clicked.connect(self._on_decline)
        row.addWidget(decline)

        accept = QPushButton("Send")
        accept.setObjectName("mcp_elicit_accept")
        accept.clicked.connect(self._on_accept)
        row.addWidget(accept)
        return row

    @staticmethod
    def _read_choices(editor: QListWidget) -> list[str]:
        """Read the values ticked in a multi-select.

        Args:
            editor: The list of check boxes.

        Returns:
            list[str]: The ticked values, in schema order.
        """
        chosen: list[str] = []
        for row in range(editor.count()):
            item = editor.item(row)
            if item is None or item.checkState() != Qt.CheckState.Checked:
                continue
            value: object = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(value, str):
                chosen.append(value)
        return chosen

    def _read_field(self, field: _Field) -> tuple[bool, ElicitValue, str | None]:
        """Read one field's answer from its editor.

        Args:
            field: The field to read.

        Returns:
            tuple[bool, ElicitValue, str | None]: Whether the field was
            answered, the answer, and what is wrong with the text entered
            when it could not be read as the field's type.
        """
        editor = field.editor
        if isinstance(editor, QListWidget):
            chosen = self._read_choices(editor)
            return bool(chosen) or field.required, chosen, None
        if isinstance(editor, QComboBox):
            data: object = editor.currentData()
            return (True, data, None) if isinstance(data, str) else (False, None, None)
        if isinstance(editor, QCheckBox):
            return True, editor.isChecked(), None
        text = editor.text() if isinstance(editor, QLineEdit) else ""
        if not text.strip():
            return False, None, None
        if field.kind in {_FieldKind.INTEGER, _FieldKind.NUMBER}:
            number = _parse_number(text.strip(), field.kind)
            if number is None:
                return True, None, "must be a whole number" if field.kind is _FieldKind.INTEGER else "must be a number"
            return True, number, None
        return True, text, None

    @staticmethod
    def _problem(field: _Field, value: ElicitValue) -> str | None:
        """Judge one answered value against its field's schema.

        Args:
            field: The field answered.
            value: The answer.

        Returns:
            str | None: What is wrong with the answer, or ``None`` when it
            satisfies every bound the schema states.
        """
        if violations := validate_against_schema(value, field.schema):
            return "; ".join(violation.message for violation in violations)
        if isinstance(value, str):
            return _format_problem(value, field.schema.get("format"))
        return None

    def _collect(self) -> tuple[dict[str, ElicitValue], dict[str, str]]:
        """Read and check every field.

        Returns:
            tuple[dict[str, ElicitValue], dict[str, str]]: The answers to
            send, and a message per field that cannot be sent as it is. An
            optional field left unanswered is omitted rather than sent.
        """
        values: dict[str, ElicitValue] = {}
        problems: dict[str, str] = {}
        for name, field in self._fields.items():
            answered, value, unreadable = self._read_field(field)
            if unreadable is not None:
                problems[name] = unreadable
            elif not answered:
                if field.required:
                    problems[name] = "an answer is required"
            elif problem := self._problem(field, value):
                problems[name] = problem
            else:
                values[name] = value
        return values, problems

    def _show_problems(self, problems: Mapping[str, str]) -> None:
        """Show each field's problem beside it, and a summary above the buttons.

        Args:
            problems: The message for every field that cannot be sent.
        """
        for name, field in self._fields.items():
            message = problems.get(name)
            field.error.setText(message or "")
            field.error.setVisible(message is not None)
        captions = [str(self._fields[name].schema.get("title") or name) for name in problems if name in self._fields]
        self._summary.setText(f"Fix these before sending: {', '.join(captions)}." if captions else "")
        self._summary.setVisible(bool(captions))

    def _on_open_url(self) -> None:
        """Open the server's URL in the operator's browser.

        The address is the server's, not the operator's, so it goes through :func:`~intellicrack.mcp.transport.open_web_url`, which opens
        only ``http`` and ``https``. A refusal is shown rather than swallowed: a button that does nothing reads as a bug, and the operator
        should know the server asked for something other than a web page.
        """
        if not self._url:
            return
        if not open_web_url(self._url):
            _logger.warning("mcp_elicit_url_refused", server_id=self._server_id)
            show_warning(
                self,
                "Address not opened",
                f"The server '{self._server_id}' asked you to open an address that is not a web page, "
                f"so Intellicrack did not open it. Opening it could have started a program rather than "
                f"shown you a page.",
            )
            return
        _logger.info("mcp_elicit_url_opened", server_id=self._server_id)

    def _on_accept(self) -> None:
        """Handle the send button."""
        values: dict[str, ElicitValue] = {}
        if not self.is_url_request:
            values, problems = self._collect()
            self._show_problems(problems)
            if problems:
                _logger.debug("mcp_elicit_invalid_fields", server_id=self._server_id, fields=sorted(problems))
                return
        self._action = "accept"
        self._content = values
        _logger.info("mcp_elicit_accepted", server_id=self._server_id, field_count=len(values))
        self.answered.emit(self._action)
        self.accept()

    def _on_decline(self) -> None:
        """Handle the decline button."""
        self._action = "decline"
        _logger.info("mcp_elicit_declined", server_id=self._server_id)
        self.answered.emit(self._action)
        self.reject()

    def _on_cancel(self) -> None:
        """Handle the cancel button."""
        self._action = "cancel"
        _logger.info("mcp_elicit_cancelled", server_id=self._server_id)
        self.answered.emit(self._action)
        self.reject()

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Treat closing the window as a cancellation.

        Args:
            a0: The close event.
        """
        if self._action == "cancel":
            self.answered.emit(self._action)
        super().closeEvent(a0)


def build_declined_result() -> ElicitResult:
    """Build the answer used when no operator is available to ask.

    Returns:
        ElicitResult: A declining result. Declining is the safe answer: it
        refuses the request without pretending the operator supplied
        anything.
    """
    return ElicitResult(action="decline")


async def resolve_elicitation(
    future: asyncio.Future[ElicitResult],
    timeout_s: float,
    *,
    on_abandon: Callable[[], None] | None = None,
) -> ElicitResult:
    """Await the operator's answer, declining if they never give one.

    Args:
        future: Future the GUI thread resolves once the dialog is answered.
        timeout_s: How long to wait before giving up.
        on_abandon: Called when the wait is given up on, by timing out or by
            the caller being cancelled, so the question can be taken off the
            screen rather than left open for an answer nobody will read.

    Returns:
        ElicitResult: The operator's answer, or a decline on timeout.

    Raises:
        asyncio.CancelledError: If the caller is cancelled while the operator
            is still deciding.
    """
    try:
        async with asyncio.timeout(timeout_s):
            return await future
    except TimeoutError:
        _logger.warning("mcp_elicit_timeout", timeout_s=timeout_s)
        _abandon(future, on_abandon)
        return build_declined_result()
    except asyncio.CancelledError:
        _abandon(future, on_abandon)
        raise


def _abandon(future: asyncio.Future[ElicitResult], on_abandon: Callable[[], None] | None) -> None:
    """Stop waiting for an answer.

    Args:
        future: The future that will no longer be read.
        on_abandon: Called so the question is taken off the screen.
    """
    if not future.done():
        _ = future.cancel()
    if on_abandon is not None:
        on_abandon()
