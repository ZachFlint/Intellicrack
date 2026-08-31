# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C11 (F-0005): hex process memory bridge routing.

The defect: ``ProcessMemoryMixin._on_open_process_memory`` previously called
``HexDocument.from_process_memory`` directly and assigned the result to
``self.document``. The bridge's ``document`` attribute, ``binary_loaded``
state, ``_cursor_offset`` reset, and the shared state holder's
``DOCUMENT_OPENED`` event were all skipped. AI tools, peer GUIs, and any
other consumer that asks the bridge what it has open would see the prior
file (or ``None``) until something else triggered a bridge-side mutation.

The fix routes the panel through ``HexEditorBridge.open_process_memory``
via ``run_bridge_coroutine_async``. The success handler then mirrors the
new ``bridge.document`` into the panel-local attributes the GUI reads
from, so the hex view repaints correctly even when the panel's own
state-holder subscription filters its own bridge source for loop-guard.

These tests verify:

- the success handler adopts the bridge's document into the panel,
- the success handler propagates the document to the hex widget,
- the success handler is robust to a missing bridge document (logs only),
- the error handler does not modify the panel document.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.panels.hex_editor.process_memory import ProcessMemoryMixin


if TYPE_CHECKING:
    from collections.abc import Generator


_PID: Final[int] = 4096
_ADDR: Final[int] = 0x10000000
_SIZE: Final[int] = 0x1000


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _SetDocumentRecorder:
    """Hex widget stand-in that records every ``set_document`` call."""

    def __init__(self) -> None:
        """Initialise the recorder with no observed documents."""
        self.documents: list[object] = []

    def set_document(self, document: object) -> None:
        """Record the document the panel hands over.

        Args:
            document: Document object adopted from the bridge.
        """
        self.documents.append(document)


class _FakeBridge:
    """Minimal bridge stand-in exposing only the attribute the panel reads.

    The real ``HexEditorBridge.open_process_memory`` mutates internal state
    and updates ``bridge.document``. The fake follows the same contract:
    callers set ``document`` to the value the production bridge would have
    after a successful call, then drive the panel handler.
    """

    def __init__(self, document: object | None) -> None:
        """Initialise the fake bridge with the document the panel will read.

        Args:
            document: Document the bridge has already adopted (or ``None``).
        """
        self.document: object | None = document


class _PanelHarness(ProcessMemoryMixin, QWidget):
    """Minimal :class:`QWidget` that mixes :class:`ProcessMemoryMixin` for tests."""

    def __init__(self, bridge: _FakeBridge | None) -> None:
        """Initialise the harness with the supplied bridge stub.

        Args:
            bridge: Stub bridge published to the mixin via ``_bridge``.
        """
        super().__init__()
        self.document: Any | None = None
        self._hex_widget: _SetDocumentRecorder = _SetDocumentRecorder()
        self._bridge: Any | None = bridge

    def trigger_success_for_test(self, payload: dict[str, Any]) -> None:
        """Drive the bridge success handler exactly as the worker would.

        Args:
            payload: ``open_process_memory`` result payload.
        """
        self._on_process_memory_success(payload)

    def trigger_error_for_test(self, exc: Exception) -> None:
        """Drive the bridge error handler exactly as the worker would.

        Args:
            exc: Exception raised by the bridge worker.
        """
        self._on_process_memory_error(exc)

    def hex_widget_documents_for_test(self) -> list[object]:
        """Return every document the harness's stub hex widget observed.

        Returns:
            list[object]: Documents observed in dispatch order.
        """
        return list(self._hex_widget.documents)


@pytest.mark.usefixtures("qapp")
class TestSuccessHandlerAdoptsBridgeDocument:
    """The success handler must adopt the bridge's document into the panel."""

    @staticmethod
    def test_panel_document_mirrors_bridge_document(qapp: QApplication) -> None:
        """Success handler copies ``bridge.document`` into ``panel.document``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        sentinel = object()
        bridge = _FakeBridge(document=sentinel)
        harness = _PanelHarness(bridge)
        assert harness.document is None

        harness.trigger_success_for_test({
            "pid": _PID,
            "address": _ADDR,
            "size": _SIZE,
            "document_length": _SIZE,
        })

        assert harness.document is sentinel, "panel must adopt the bridge's freshly-opened document"

    @staticmethod
    def test_hex_widget_receives_document(qapp: QApplication) -> None:
        """Success handler forwards the document to the hex widget.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        sentinel = object()
        bridge = _FakeBridge(document=sentinel)
        harness = _PanelHarness(bridge)

        harness.trigger_success_for_test({
            "pid": _PID,
            "address": _ADDR,
            "size": _SIZE,
            "document_length": _SIZE,
        })

        observed = harness.hex_widget_documents_for_test()
        assert observed == [sentinel], "hex widget must receive the bridge document exactly once"


@pytest.mark.usefixtures("qapp")
class TestSuccessHandlerToleratesMissingBridgeDocument:
    """If the bridge has no document the handler must log and not crash."""

    @staticmethod
    def test_no_document_no_panel_mutation(qapp: QApplication) -> None:
        """Bridge with ``document=None`` must leave the panel untouched.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        bridge = _FakeBridge(document=None)
        harness = _PanelHarness(bridge)

        harness.trigger_success_for_test({
            "pid": _PID,
            "address": _ADDR,
            "size": _SIZE,
            "document_length": _SIZE,
        })

        assert harness.document is None
        assert harness.hex_widget_documents_for_test() == []


@pytest.mark.usefixtures("qapp")
class TestSuccessHandlerToleratesMissingBridge:
    """If the bridge attribute is gone the handler must short-circuit cleanly."""

    @staticmethod
    def test_no_bridge_no_panel_mutation(qapp: QApplication) -> None:
        """Handler must not mutate panel state when ``self._bridge`` is ``None``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _PanelHarness(bridge=None)

        harness.trigger_success_for_test({
            "pid": _PID,
            "address": _ADDR,
            "size": _SIZE,
            "document_length": _SIZE,
        })

        assert harness.document is None
        assert harness.hex_widget_documents_for_test() == []


@pytest.fixture
def silence_message_box(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub ``QMessageBox.warning`` so error-path tests do not block on a real dialog.

    Args:
        monkeypatch: pytest monkeypatch fixture.
    """

    def _no_dialog(*_args: object, **_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor.process_memory.QMessageBox.warning",
        _no_dialog,
    )


@pytest.mark.usefixtures("qapp", "silence_message_box")
class TestErrorHandlerDoesNotMutateDocument:
    """The error handler must surface the failure but never adopt a document."""

    @staticmethod
    def test_error_keeps_panel_document_unchanged(qapp: QApplication) -> None:
        """Error handler must leave a previously-adopted document in place.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        original = object()
        bridge = _FakeBridge(document=original)
        harness = _PanelHarness(bridge)
        harness.document = original

        harness.trigger_error_for_test(RuntimeError("simulated bridge failure"))

        assert harness.document is original
