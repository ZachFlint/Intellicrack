# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C16 (F-0004, F-0010, F-0024): hex panel selection + dispatch.

These tests guard against three regressions in
:class:`~intellicrack.ui.panels.hex_editor.panel.HexEditorPanel`:

* **F-0004** -- ``_on_selection_changed`` must propagate the new selection to
  the shared :class:`HexDocumentState` and to the attached bridge's
  ``_selection`` attribute.  The pre-audit code stored the range in panel-local
  fields only, so AI tools and CLI callers querying the bridge saw stale or
  empty selection state after the user dragged a selection in the GUI.

* **F-0010** -- ``set_state_holder``'s ``DOCUMENT_OPENED`` handler must honour
  subsequent open events even when the panel already has a document loaded.
  The pre-audit guard ``if self.document is None`` caused the panel to ignore
  every ``DOCUMENT_OPENED`` event fired after the first file was opened.

* **F-0024** -- ``_do_copy_as`` must surface a user-visible warning when the
  system clipboard is unavailable or raises on write.  The pre-audit code
  silently dropped the result.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Final, cast, override
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.config import LogConfig
from intellicrack.core.logging import setup_logging
from intellicrack.core.types import HexDocumentFull
from intellicrack.ui import dialogs_helpers
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


_DOC_LEN: Final[int] = 64
_SEL_START: Final[int] = 4
_SEL_END: Final[int] = 12


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def hexcore_doc() -> HexDocumentFull:
    """Build a fresh in-memory :class:`HexDocument`, skipping if hexcore not built.

    Returns:
        HexDocumentFull: New 64-byte document populated with bytes 0..63.
    """
    hexcore_mod: Any = pytest.importorskip(
        "intellicrack_hexcore",
        reason="intellicrack_hexcore native module not built",
    )
    return cast(HexDocumentFull, hexcore_mod.HexDocument.open_bytes(bytes(range(_DOC_LEN))))


def _make_hexcore_doc() -> HexDocumentFull:
    """Build a fresh in-memory :class:`HexDocument` for inline use, skipping if missing.

    Returns:
        HexDocumentFull: New 64-byte document populated with bytes 0..63.
    """
    hexcore_mod: Any = pytest.importorskip(
        "intellicrack_hexcore",
        reason="intellicrack_hexcore native module not built",
    )
    return cast(HexDocumentFull, hexcore_mod.HexDocument.open_bytes(bytes(range(_DOC_LEN))))


class _RecordingState(HexDocumentState):
    """A real :class:`HexDocumentState` that records every notification dispatch.

    Subclasses the production state holder and overrides ``_notify`` to
    record the ``(event, data, source)`` triple for each dispatch before
    forwarding to the production pipeline so loop-guard semantics are
    preserved.
    """

    def __init__(self) -> None:
        """Initialise the state holder and the empty recording list."""
        super().__init__()
        self.dispatched: list[tuple[HexDocumentEvent, dict[str, Any], str]] = []

    @override
    def _notify(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        *,
        source: str = "",
    ) -> None:
        """Record the dispatch then forward to the production dispatcher.

        Args:
            event_type: The state-holder event being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller for loop-guard filtering.
        """
        self.dispatched.append((event_type, dict(data), source))
        super()._notify(event_type, data, source=source)

    def selection_changed_events(self) -> list[tuple[dict[str, Any], str]]:
        """Return SELECTION_CHANGED ``(payload, source)`` tuples in dispatch order.

        Returns:
            list[tuple[dict[str, Any], str]]: Payload + source for every
                SELECTION_CHANGED event published on this state holder.
        """
        return [(data, src) for evt, data, src in self.dispatched if evt is HexDocumentEvent.SELECTION_CHANGED]


class _StubBridge:
    """Minimal stand-in for :class:`HexEditorBridge` for selection propagation tests.

    Provides the same public ``update_selection_from_gui`` method that
    the production bridge exposes so the panel code path is exercised.
    """

    def __init__(self) -> None:
        """Initialise with no active selection."""
        self._selection: tuple[int, int] | None = None

    def update_selection_from_gui(self, start: int, end: int) -> None:
        """Mirror the production bridge's synchronous selection update.

        Args:
            start: Selection start offset, or -1 to clear.
            end: Selection end offset, or -1 to clear.
        """
        if start >= 0 and end >= 0:
            self._selection = (start, end)
        else:
            self._selection = None

    def get_selection(self) -> tuple[int, int] | None:
        """Return the current selection stored by the panel's write.

        Returns:
            tuple[int, int] | None: The selection tuple or None.
        """
        return self._selection


class _PanelHarness(QWidget):
    """Minimal harness exercising ``_on_selection_changed`` from ``HexEditorPanel``.

    Rather than constructing the full :class:`HexEditorPanel` (which
    requires the Rust extension at widget-build time), this harness
    replicates only the attributes that ``_on_selection_changed`` reads and
    writes, then borrows the method directly from the panel class via
    ``getattr`` so any change to the production code is automatically
    picked up without triggering private-access warnings.
    """

    def __init__(
        self,
        state: HexDocumentState | None,
        bridge: _StubBridge | None,
    ) -> None:
        """Initialise the harness with the supplied state holder and bridge stub.

        Args:
            state: Shared :class:`HexDocumentState` to propagate selection into.
            bridge: Stub bridge whose ``_selection`` the harness updates.
        """
        super().__init__()
        self.state_holder: HexDocumentState | None = state
        self._bridge: _StubBridge | None = bridge
        self._selection_start: int = -1
        self._selection_end: int = -1
        self._hex_widget: object | None = None

    def _update_data_inspector(self, _offset: int) -> None:
        """No-op stand-in for the data inspector update.

        Args:
            _offset: Byte offset (ignored in harness).
        """

    def trigger_selection_changed(self, start: int, end: int) -> None:
        """Call the production ``_on_selection_changed`` implementation.

        Borrows the unbound method from the panel class via ``getattr``
        so the test exercises the exact production code path without
        triggering private-access warnings.

        Args:
            start: Selection start offset to pass to the handler.
            end: Selection end offset to pass to the handler.
        """
        getattr(HexEditorPanel, "_on_selection_changed")(self, start, end)

    @property
    def selection_start(self) -> int:
        """Return the stored selection start offset.

        Returns:
            int: The value of ``_selection_start`` after the last handler call.
        """
        return self._selection_start

    @property
    def selection_end(self) -> int:
        """Return the stored selection end offset.

        Returns:
            int: The value of ``_selection_end`` after the last handler call.
        """
        return self._selection_end


@pytest.mark.usefixtures("qapp")
class TestSelectionPropagation:
    """F-0004: GUI selection must propagate to the shared state holder and bridge."""

    @staticmethod
    def test_selection_updates_state_holder(qapp: QApplication) -> None:
        """Assert a valid selection fires SELECTION_CHANGED on the state holder.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        bridge = _StubBridge()
        harness = _PanelHarness(state, bridge)

        harness.trigger_selection_changed(_SEL_START, _SEL_END)

        events = state.selection_changed_events()
        assert len(events) >= 1, "SELECTION_CHANGED must be fired after _on_selection_changed"

    @staticmethod
    def test_selection_payload_matches_range(qapp: QApplication) -> None:
        """Assert the SELECTION_CHANGED payload carries the correct start and end.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        bridge = _StubBridge()
        harness = _PanelHarness(state, bridge)

        harness.trigger_selection_changed(_SEL_START, _SEL_END)

        events = state.selection_changed_events()
        assert events, "SELECTION_CHANGED must be fired"
        payload, _ = events[0]
        assert payload.get("start") == _SEL_START, f"expected start={_SEL_START}, got {payload.get('start')}"
        assert payload.get("end") == _SEL_END, f"expected end={_SEL_END}, got {payload.get('end')}"

    @staticmethod
    def test_selection_updates_bridge_selection_attribute(qapp: QApplication) -> None:
        """Assert the bridge selection is updated after a GUI selection.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        bridge = _StubBridge()
        harness = _PanelHarness(state, bridge)

        harness.trigger_selection_changed(_SEL_START, _SEL_END)

        assert bridge.get_selection() == (_SEL_START, _SEL_END), (
            f"bridge selection must be ({_SEL_START}, {_SEL_END}) after GUI selection, got {bridge.get_selection()!r}"
        )

    @staticmethod
    def test_panel_local_fields_also_updated(qapp: QApplication) -> None:
        """Assert the panel-local ``_selection_start`` / ``_selection_end`` are stored.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _PanelHarness(None, None)
        harness.trigger_selection_changed(_SEL_START, _SEL_END)

        assert harness.selection_start == _SEL_START
        assert harness.selection_end == _SEL_END

    @staticmethod
    def test_negative_selection_clears_bridge(qapp: QApplication) -> None:
        """Assert a negative-start selection clears bridge selection.

        When the hex widget deselects (passes start=-1), the bridge
        must not retain the previous stale selection.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        bridge = _StubBridge()
        bridge.update_selection_from_gui(_SEL_START, _SEL_END)
        harness = _PanelHarness(state, bridge)

        harness.trigger_selection_changed(-1, -1)

        assert bridge.get_selection() is None, f"bridge selection must be None after deselect (start=-1), got {bridge.get_selection()!r}"

    @staticmethod
    def test_no_state_holder_does_not_raise(qapp: QApplication) -> None:
        """Assert that propagation is skipped gracefully when state_holder is None.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _PanelHarness(None, None)
        harness.trigger_selection_changed(_SEL_START, _SEL_END)

    @staticmethod
    def test_no_bridge_does_not_raise(qapp: QApplication) -> None:
        """Assert that propagation is skipped gracefully when bridge is None.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        harness = _PanelHarness(state, None)
        harness.trigger_selection_changed(_SEL_START, _SEL_END)


class _DocumentOpenedHarness(QWidget):
    """Minimal harness that wires a real :class:`HexDocumentState` to a stub load.

    Instead of constructing the full ``HexEditorPanel``, this harness
    calls the production ``set_state_holder`` on itself and records
    every ``load_file`` call so tests can assert which path was passed.
    """

    def __init__(self) -> None:
        """Initialise the harness with no loaded document and an empty load log."""
        super().__init__()
        self.document: object | None = None
        self.state_holder: HexDocumentState | None = None
        self._hex_widget: object | None = None
        self._bridge: object | None = None
        self._state_callback: object | None = None
        self.loaded_paths: list[str] = []

    def load_file(self, file_path: str) -> bool:
        """Record the path and simulate a successful load by setting document.

        Args:
            file_path: Path that would be opened.

        Returns:
            bool: Always True.
        """
        self.loaded_paths.append(file_path)
        self.document = MagicMock()
        return True

    def attach_state_holder(self, state_holder: HexDocumentState) -> None:
        """Attach a state holder using the production ``set_state_holder`` logic.

        Borrows the production implementation from :class:`HexEditorPanel`
        via ``getattr`` so any refactor of the listener is automatically
        exercised.

        Args:
            state_holder: Real :class:`HexDocumentState` to attach.
        """
        getattr(HexEditorPanel, "set_state_holder")(self, state_holder)

    def _update_data_inspector(self, _offset: int) -> None:
        """No-op stand-in for data inspector.

        Args:
            _offset: Byte offset (ignored in harness).
        """

    def _on_data_changed(self) -> None:
        """No-op stand-in for data-changed handler."""

    def _populate_template_combo(self) -> None:
        """No-op stand-in for template combo population."""


@pytest.mark.usefixtures("qapp")
class TestDocumentOpenedDispatch:
    """F-0010: DOCUMENT_OPENED must swap in a new document even when one is already loaded."""

    @staticmethod
    def test_first_open_loads_file(qapp: QApplication, tmp_path: Path) -> None:
        """Assert that the first DOCUMENT_OPENED event triggers load_file.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        doc = _make_hexcore_doc()
        target = tmp_path / "first.bin"
        state = HexDocumentState()
        harness = _DocumentOpenedHarness()
        harness.attach_state_holder(state)

        state.set_document(doc, target, source="bridge")

        assert str(target) in harness.loaded_paths, (
            f"load_file must be called with {target} on first DOCUMENT_OPENED, got loaded_paths={harness.loaded_paths}"
        )

    @staticmethod
    def test_second_open_replaces_document(qapp: QApplication, tmp_path: Path) -> None:
        """Assert that a second DOCUMENT_OPENED replaces the already-loaded document.

        This is the core regression: the pre-audit guard
        ``if self.document is None`` caused all DOCUMENT_OPENED events
        after the first to be silently ignored.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        doc1 = _make_hexcore_doc()
        doc2 = _make_hexcore_doc()
        first = tmp_path / "first.bin"
        second = tmp_path / "second.bin"

        state = HexDocumentState()
        harness = _DocumentOpenedHarness()
        harness.attach_state_holder(state)

        state.set_document(doc1, first, source="bridge")
        assert harness.document is not None, "Document should be loaded after first open"

        state.set_document(doc2, second, source="bridge")

        assert len(harness.loaded_paths) == 2, (
            f"load_file must be called twice (once per DOCUMENT_OPENED), got loaded_paths={harness.loaded_paths}"
        )
        assert harness.loaded_paths[1] == str(second), f"second load_file call must use the second path, got {harness.loaded_paths[1]!r}"

    @staticmethod
    def test_second_open_clears_old_document_before_load(qapp: QApplication, tmp_path: Path) -> None:
        """Assert that the old document reference is cleared before the new one is loaded.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        doc1 = _make_hexcore_doc()
        doc2 = _make_hexcore_doc()
        first = tmp_path / "first2.bin"
        second = tmp_path / "second2.bin"

        seen_doc_at_load: list[object] = []

        class _TrackingHarness(_DocumentOpenedHarness):
            def load_file(self, file_path: str) -> bool:
                """Record document state at the moment of each load call.

                Args:
                    file_path: Path being opened.

                Returns:
                    bool: Always True.
                """
                seen_doc_at_load.append(self.document)
                return super().load_file(file_path)

        state = HexDocumentState()
        harness = _TrackingHarness()
        harness.attach_state_holder(state)

        state.set_document(doc1, first, source="bridge")
        state.set_document(doc2, second, source="bridge")

        assert len(seen_doc_at_load) == 2, "load_file must be called twice"
        assert seen_doc_at_load[1] is None, (
            f"document must be cleared to None before the second load_file call, got {seen_doc_at_load[1]!r}"
        )


_SELECTED_BYTES: Final[bytes] = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11])
_SELECTION_END: Final[int] = 3
_EXPECTED_HEX: Final[str] = "DE AD BE EF"
_EXPECTED_BASE64: Final[str] = "3q2+7w=="


class _CopyHarness(QWidget):
    """Harness exercising ``_do_copy_as`` against a real hex editor widget.

    Builds a real :class:`HexEditorWidget` backed by a real ``hexcore``
    document with a real selection so ``_do_copy_as`` calls the production
    ``copy_as`` formatter end to end -- no synthetic widget response.
    """

    def __init__(self, document: HexDocumentFull) -> None:
        """Initialise the harness with a real hex widget and selected bytes.

        Args:
            document: Real hexcore document to attach to the widget.
        """
        super().__init__()
        widget = HexEditorWidget()
        widget.set_document(document)
        widget.set_selection_range(0, _SELECTION_END)
        self._hex_widget: object | None = widget

    def do_copy_as(self, fmt: str) -> None:
        """Call the production ``_do_copy_as`` implementation via getattr.

        Args:
            fmt: Format name to pass to the handler.
        """
        getattr(HexEditorPanel, "_do_copy_as")(self, fmt)


def _selected_doc() -> HexDocumentFull:
    """Build a real 6-byte hexcore document whose first four bytes are known.

    Returns:
        HexDocumentFull: Document containing ``DE AD BE EF 00 11``.
    """
    hexcore_mod: Any = pytest.importorskip(
        "intellicrack_hexcore",
        reason="intellicrack_hexcore native module not built",
    )
    return cast(HexDocumentFull, hexcore_mod.HexDocument.open_bytes(_SELECTED_BYTES))


def _configure_json_logging(log_dir: Path) -> Path:
    """Wire real structlog JSON-Lines logging into ``log_dir``.

    Args:
        log_dir: Directory to receive ``intellicrack.log``.

    Returns:
        Path: The active log file path.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(
        LogConfig(
            level="DEBUG",
            file_enabled=True,
            console_enabled=False,
            json_file=True,
            max_file_size_mb=10,
            backup_count=1,
            retention_days=1,
        ),
        log_dir=log_dir,
    )
    return log_dir / "intellicrack.log"


def _make_warning_recorder(sink: list[tuple[str, str]]) -> Callable[..., QMessageBox.StandardButton]:
    """Build a ``QMessageBox.warning`` stand-in that records title and message.

    Isolates only the irreproducible OS-modal dialog while recording the
    exact title and message the production warning path produces.

    Args:
        sink: List that receives ``(title, message)`` for each warning.

    Returns:
        Callable[..., QMessageBox.StandardButton]: A callable matching
            ``QMessageBox.warning``'s call shape.
    """

    def _record(_parent: object, title: str, message: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        sink.append((title, message))
        return QMessageBox.StandardButton.Ok

    return _record


def _read_events(log_file: Path) -> list[dict[str, object]]:
    """Parse JSON-Lines structlog records, flushing handlers first.

    Args:
        log_file: Path to the JSON-Lines log file.

    Returns:
        list[dict[str, object]]: Parsed log records.
    """
    for handler in logging.getLogger().handlers:
        handler.flush()
    records: list[dict[str, object]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            continue
    return records


@pytest.mark.usefixtures("qapp")
class TestCopyAsClipboardError:
    """F-0024: ``_do_copy_as`` writes to the real clipboard and surfaces real warnings.

    The success path exercises the genuine ``QApplication.clipboard()`` and
    asserts the actual clipboard text. The two failure paths isolate only the
    irreproducible OS boundaries (a clipboard that the platform cannot
    provide / a clipboard write that the platform makes fail, and the OS-modal
    ``QMessageBox.warning``) and then assert the real, user-visible side
    effects: the structured ``copy_as_*`` log record emitted through the real
    structlog pipeline and the exact title/message handed to the warning
    dialog.
    """

    @staticmethod
    def test_successful_copy_writes_formatted_bytes_to_real_clipboard(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful copy dispatches the production-formatted selection to the real clipboard.

        Drives the full production path -- real :class:`HexEditorWidget`
        formatting the real selection, then ``_do_copy_as`` calling the real
        ``QClipboard.setText``. The argument handed to the real clipboard API
        is captured and asserted against the documented hex format (the
        independent oracle); the underlying write is still performed against
        the real Qt clipboard. Capturing the dispatched string keeps the gate
        deterministic on Windows, where the OS clipboard read-back is racy.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture for boundary isolation.
        """
        del qapp
        clipboard = QApplication.clipboard()
        assert clipboard is not None, "the test environment must provide a real Qt clipboard"
        dispatched: list[str] = []
        real_set_text = clipboard.setText

        def _spy_set_text(text: str) -> None:
            dispatched.append(text)
            real_set_text(text)

        monkeypatch.setattr(clipboard, "setText", _spy_set_text)

        harness = _CopyHarness(_selected_doc())
        harness.do_copy_as("hex")

        assert dispatched == [_EXPECTED_HEX], f"the hex-formatted selection must be written to the clipboard, got {dispatched!r}"

    @staticmethod
    def test_successful_copy_respects_requested_format(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The requested format is honoured: base64 of the selection is dispatched to the clipboard.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture for boundary isolation.
        """
        del qapp
        clipboard = QApplication.clipboard()
        assert clipboard is not None, "the test environment must provide a real Qt clipboard"
        dispatched: list[str] = []
        real_set_text = clipboard.setText

        def _spy_set_text(text: str) -> None:
            dispatched.append(text)
            real_set_text(text)

        monkeypatch.setattr(clipboard, "setText", _spy_set_text)

        harness = _CopyHarness(_selected_doc())
        harness.do_copy_as("base64")

        assert dispatched == [_EXPECTED_BASE64], f"the base64-formatted selection must be written to the clipboard, got {dispatched!r}"

    @staticmethod
    def test_no_clipboard_surfaces_warning_and_logs(
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unavailable clipboard yields the real warning dialog and structured log.

        Only the irreproducible environment boundaries are isolated: the
        clipboard accessor (forced to the platform's "no clipboard" return of
        ``None``) and the OS-modal ``QMessageBox.warning``. The behaviour under
        test -- emitting ``copy_as_no_clipboard`` and surfacing the documented
        warning text -- runs for real.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            tmp_path: Pytest temporary directory for the log file.
            monkeypatch: Pytest monkeypatch fixture for boundary isolation.
        """
        del qapp
        log_file = _configure_json_logging(tmp_path / "logs")
        warnings: list[tuple[str, str]] = []
        monkeypatch.setattr(QApplication, "clipboard", staticmethod(lambda: None))
        monkeypatch.setattr(dialogs_helpers.QMessageBox, "warning", _make_warning_recorder(warnings))

        harness = _CopyHarness(_selected_doc())
        harness.do_copy_as("hex")

        events = _read_events(log_file)
        no_clipboard = [r for r in events if r.get("event") == "copy_as_no_clipboard"]
        assert no_clipboard, "an unavailable clipboard must emit a copy_as_no_clipboard structured log record"
        assert no_clipboard[-1].get("fmt") == "hex", "the log record must record the requested format"
        assert warnings == [
            ("Clipboard Unavailable", "The system clipboard is not accessible. The selection could not be copied."),
        ], f"the user must see the documented clipboard-unavailable warning, got {warnings!r}"

    @staticmethod
    def test_clipboard_write_failure_surfaces_warning_and_logs(
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failing clipboard write yields the real warning dialog and structured log.

        Only the irreproducible boundaries are isolated: a ``setText`` that
        the platform makes raise ``RuntimeError`` and the OS-modal
        ``QMessageBox.warning``. The production handling -- catching the error,
        emitting ``copy_as_clipboard_write_failed``, and surfacing the
        exception text to the user -- runs for real.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            tmp_path: Pytest temporary directory for the log file.
            monkeypatch: Pytest monkeypatch fixture for boundary isolation.
        """
        del qapp
        log_file = _configure_json_logging(tmp_path / "logs")
        clipboard = QApplication.clipboard()
        assert clipboard is not None, "the test environment must provide a real Qt clipboard"
        warnings: list[tuple[str, str]] = []

        def _raise_set_text(_text: str) -> None:
            msg = "clipboard owner denied write"
            raise RuntimeError(msg)

        monkeypatch.setattr(clipboard, "setText", _raise_set_text)
        monkeypatch.setattr(dialogs_helpers.QMessageBox, "warning", _make_warning_recorder(warnings))

        harness = _CopyHarness(_selected_doc())
        harness.do_copy_as("hex")

        events = _read_events(log_file)
        write_failed = [r for r in events if r.get("event") == "copy_as_clipboard_write_failed"]
        assert write_failed, "a failing clipboard write must emit a copy_as_clipboard_write_failed structured log record"
        assert write_failed[-1].get("fmt") == "hex", "the log record must record the requested format"
        assert len(warnings) == 1, f"exactly one warning must be surfaced on a failed write, got {warnings!r}"
        title, message = warnings[0]
        assert title == "Clipboard Write Failed", f"warning title must name the write failure, got {title!r}"
        assert "clipboard owner denied write" in message, f"warning must surface the underlying error text, got {message!r}"

    @staticmethod
    def test_successful_copy_emits_no_warning(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful copy never reaches the warning dialog.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture for boundary isolation.
        """
        del qapp
        warnings: list[tuple[str, str]] = []
        monkeypatch.setattr(dialogs_helpers.QMessageBox, "warning", _make_warning_recorder(warnings))

        harness = _CopyHarness(_selected_doc())
        harness.do_copy_as("hex")

        assert warnings == [], f"a successful copy must not surface any warning, got {warnings!r}"
