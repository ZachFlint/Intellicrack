# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Dialog answering an MCP server's request for information from the operator.

A server may pause mid-call and ask for something it needs: a directory to
work in, a confirmation, a choice between options. The protocol calls this
elicitation, and it arrives in one of two shapes. A form request carries a
small JSON Schema describing the fields it wants; a URL request asks the
operator to go somewhere and come back.

Three answers exist and they are not interchangeable. Accepting returns the
values. Declining says no to the request while leaving the call running.
Cancelling abandons the exchange. Closing the window is a cancel, never an
accept, so a dismissed dialog can never be read as consent.

A server must never ask for a credential this way. The dialog says so, every
time, because the operator is the only one who can tell whether a field
labelled "API key" is a legitimate request.
"""

from __future__ import annotations

import asyncio
import webbrowser
from typing import TYPE_CHECKING, Any, Final, override

from mcp_types import ElicitResult
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.mcp.tool_source import sanitize_untrusted_text
from intellicrack.ui.dialogs_helpers import plain_tooltip


if TYPE_CHECKING:
    from collections.abc import Mapping

    from mcp_types import ElicitRequestParams
    from PyQt6.QtGui import QCloseEvent


_logger = get_logger(__name__)


ElicitValue = str | int | float | bool | list[str] | None
"""What one answered field may carry, matching the protocol's content type."""

_DIALOG_MIN_WIDTH: Final[int] = 560
_MESSAGE_MAX_CHARS: Final[int] = 4096
_NUMBER_RANGE: Final[float] = 1e12
_INTEGER_RANGE: Final[int] = 2**31 - 1
_DECIMALS: Final[int] = 6
_MAX_FIELDS: Final[int] = 32


class McpElicitationDialog(QDialog):
    """Collects one server's requested values, or refuses on the operator's behalf.

    Emits ``answered(action: str)`` with ``accept``, ``decline`` or
    ``cancel`` once the operator has decided.
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
        self._editors: dict[str, QWidget] = {}
        self._required: set[str] = set()
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
            operator accepted.
        """
        return dict(self._content)

    def to_result(self) -> ElicitResult:
        """Render the operator's answer as a protocol result.

        Returns:
            ElicitResult: The result to return to the server. Content is
            attached only on acceptance.
        """
        if self._action == "accept":
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

        if self._params.mode == "url":
            layout.addWidget(self._build_url_section())
        else:
            layout.addLayout(self._build_form())

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
            editor = self._build_editor(definition)
            self._editors[name] = editor
            form.addRow(self._field_label(name, definition), editor)
        return form

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
    def _build_editor(definition: Mapping[str, Any]) -> QWidget:
        """Build the editor widget for one requested field.

        Args:
            definition: The field's schema node.

        Returns:
            QWidget: A combo box for an enumeration, a check box for a
            boolean, a spin box for a number, and a line edit otherwise.
        """
        choices: object = definition.get("enum")
        if is_json_array(choices) and choices:
            combo = QComboBox()
            names: object = definition.get("enumNames")
            labels: list[Any] = names if is_json_array(names) and len(names) == len(choices) else choices
            for value, caption in zip(choices, labels, strict=False):
                combo.addItem(str(caption), value)
            return combo

        declared = definition.get("type")
        if declared == "boolean":
            box = QCheckBox()
            box.setChecked(definition.get("default") is True)
            return box
        if declared == "integer":
            spin = QSpinBox()
            spin.setRange(-_INTEGER_RANGE, _INTEGER_RANGE)
            default = definition.get("default")
            if isinstance(default, int) and not isinstance(default, bool):
                spin.setValue(default)
            return spin
        if declared == "number":
            number = QDoubleSpinBox()
            number.setDecimals(_DECIMALS)
            number.setRange(-_NUMBER_RANGE, _NUMBER_RANGE)
            default = definition.get("default")
            if isinstance(default, int | float) and not isinstance(default, bool):
                number.setValue(float(default))
            return number

        line = QLineEdit()
        default = definition.get("default")
        if isinstance(default, str):
            line.setText(default)
        if definition.get("format") in {"uri", "email", "date", "date-time"}:
            line.setPlaceholderText(str(definition.get("format")))
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

    def _collect(self) -> dict[str, ElicitValue]:
        """Read every editor's current value.

        Returns:
            dict[str, ElicitValue]: The answered fields. A field left empty
            that the schema does not require is omitted rather than sent as
            an empty string.
        """
        values: dict[str, ElicitValue] = {}
        for name, editor in self._editors.items():
            if isinstance(editor, QComboBox):
                data: object = editor.currentData()
                values[name] = data if isinstance(data, str | int | float | bool) else editor.currentText()
            elif isinstance(editor, QCheckBox):
                values[name] = editor.isChecked()
            elif isinstance(editor, QSpinBox | QDoubleSpinBox):
                values[name] = editor.value()
            elif isinstance(editor, QLineEdit):
                text = editor.text()
                if text or name in self._required:
                    values[name] = text
        return values

    def _missing_required(self, values: Mapping[str, ElicitValue]) -> list[str]:
        """List required fields the operator left blank.

        Args:
            values: The collected values.

        Returns:
            list[str]: Names of required fields with no value.
        """
        return [name for name in self._required if not str(values.get(name, "")).strip()]

    def _on_open_url(self) -> None:
        """Open the server's URL in the operator's browser."""
        if self._url:
            _logger.info("mcp_elicit_url_opened", server_id=self._server_id)
            _ = webbrowser.open(self._url)

    def _on_accept(self) -> None:
        """Handle the send button."""
        values = self._collect()
        missing = self._missing_required(values)
        if missing:
            _logger.debug("mcp_elicit_missing_required", server_id=self._server_id, fields=missing)
            self.setWindowTitle(f"Fill in: {', '.join(missing)}")
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
) -> ElicitResult:
    """Await the operator's answer, declining if they never give one.

    Args:
        future: Future the GUI thread resolves once the dialog is answered.
        timeout_s: How long to wait before giving up.

    Returns:
        ElicitResult: The operator's answer, or a decline on timeout.
    """
    try:
        async with asyncio.timeout(timeout_s):
            return await future
    except TimeoutError:
        _logger.warning("mcp_elicit_timeout", timeout_s=timeout_s)
        if not future.done():
            _ = future.cancel()
        return build_declined_result()
