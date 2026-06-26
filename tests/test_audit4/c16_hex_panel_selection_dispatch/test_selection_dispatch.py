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

from typing import TYPE_CHECKING, Any, Final, cast, override
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.types import HexDocumentFull
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Iterator
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
    def test_no_state_holder_stores_local_fields(qapp: QApplication) -> None:
        """Assert that panel-local selection fields are updated even when state_holder is None.

        When no state holder is attached, the panel must still record the
        selection range in its own fields so other panel-local operations
        (e.g. hashing the selection) see the correct range.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _PanelHarness(None, None)
        harness.trigger_selection_changed(_SEL_START, _SEL_END)
        assert harness.selection_start == _SEL_START, (
            f"_selection_start must be {_SEL_START} even without a state_holder, got {harness.selection_start}"
        )
        assert harness.selection_end == _SEL_END, (
            f"_selection_end must be {_SEL_END} even without a state_holder, got {harness.selection_end}"
        )

    @staticmethod
    def test_no_bridge_fires_selection_changed_on_state(qapp: QApplication) -> None:
        """Assert SELECTION_CHANGED is still dispatched on the state holder when bridge is None.

        The state holder must receive the event regardless of whether a
        bridge is attached; the bridge is an optional downstream consumer.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        harness = _PanelHarness(state, None)
        harness.trigger_selection_changed(_SEL_START, _SEL_END)

        events = state.selection_changed_events()
        assert len(events) >= 1, "SELECTION_CHANGED must be fired on the state holder even when bridge is None"
        payload, _ = events[0]
        assert payload.get("start") == _SEL_START, f"expected start={_SEL_START}, got {payload.get('start')}"
        assert payload.get("end") == _SEL_END, f"expected end={_SEL_END}, got {payload.get('end')}"


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


class _StubHexWidget:
    """Minimal stand-in for the hex editor widget for clipboard tests."""

    def copy_as(self, _fmt: str) -> str:
        """Return stub copy data for any format.

        Args:
            _fmt: Format name (ignored).

        Returns:
            str: Fixed test bytes string.
        """
        return "DEADBEEF"


class _CopyHarness(QWidget):
    """Minimal harness exercising ``_do_copy_as`` from ``HexEditorPanel``."""

    def __init__(self) -> None:
        """Initialise the harness with a stub hex widget."""
        super().__init__()
        self._hex_widget: object | None = _StubHexWidget()

    def do_copy_as(self, fmt: str) -> None:
        """Call the production ``_do_copy_as`` implementation via getattr.

        Args:
            fmt: Format name to pass to the handler.
        """
        getattr(HexEditorPanel, "_do_copy_as")(self, fmt)


_CLIPBOARD_UNAVAILABLE_TITLE: Final[str] = "Clipboard Unavailable"
_CLIPBOARD_UNAVAILABLE_MSG: Final[str] = "The system clipboard is not accessible. The selection could not be copied."
_CLIPBOARD_WRITE_FAILED_TITLE: Final[str] = "Clipboard Write Failed"


@pytest.mark.usefixtures("qapp")
class TestCopyAsClipboardError:
    """F-0024: ``_do_copy_as`` must surface a warning when the clipboard is unavailable.

    Tests validate that the production ``show_warning`` call path is fully
    exercised: ``show_warning`` runs as real production code; only
    ``QMessageBox.warning`` (the Qt dialog sink) is intercepted to prevent
    interactive dialogs during CI and to capture the exact title/message
    arguments that reach the user.
    """

    @staticmethod
    def test_no_clipboard_shows_warning_with_correct_title_and_message(qapp: QApplication) -> None:
        """Assert the exact title and message surfaced when QApplication.clipboard() returns None.

        The production path calls ``show_warning(self, title, message)`` which
        in turn calls ``QMessageBox.warning``.  Intercepting at ``QMessageBox``
        level lets ``show_warning`` execute as real code while preventing
        interactive dialogs, and lets us verify the exact strings the user sees.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _CopyHarness()
        dialog_calls: list[tuple[str, str]] = []

        def _capture_dialog(_parent: object, title: str, message: str) -> int:
            dialog_calls.append((title, message))
            return 0

        with (
            patch("intellicrack.ui.panels.hex_editor.panel.QApplication") as mock_app,
            patch("intellicrack.ui.dialogs_helpers.QMessageBox") as mock_msgbox,
        ):
            mock_app.clipboard.return_value = None
            mock_msgbox.warning.side_effect = _capture_dialog
            harness.do_copy_as("hex")

        assert len(dialog_calls) == 1, f"QMessageBox.warning must be called exactly once when clipboard is None, got {len(dialog_calls)}"
        title, message = dialog_calls[0]
        assert title == _CLIPBOARD_UNAVAILABLE_TITLE, f"warning title must be {_CLIPBOARD_UNAVAILABLE_TITLE!r}, got {title!r}"
        assert message == _CLIPBOARD_UNAVAILABLE_MSG, f"warning message must be {_CLIPBOARD_UNAVAILABLE_MSG!r}, got {message!r}"

    @staticmethod
    def test_clipboard_write_error_shows_warning_with_exception_text(qapp: QApplication) -> None:
        r"""Assert the exception message is embedded in the warning when clipboard.setText raises.

        The production code formats the warning message as
        ``f"Could not write to the clipboard:\n{exc}"``.  This test verifies
        that exact structure so a regression that drops the exception text or
        changes the sentinel title string goes red immediately.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _CopyHarness()
        dialog_calls: list[tuple[str, str]] = []

        def _capture_dialog(_parent: object, title: str, message: str) -> int:
            dialog_calls.append((title, message))
            return 0

        exc_text = "write operation rejected by OS"
        mock_clipboard = MagicMock()
        mock_clipboard.setText.side_effect = RuntimeError(exc_text)

        with (
            patch("intellicrack.ui.panels.hex_editor.panel.QApplication") as mock_app,
            patch("intellicrack.ui.dialogs_helpers.QMessageBox") as mock_msgbox,
        ):
            mock_app.clipboard.return_value = mock_clipboard
            mock_msgbox.warning.side_effect = _capture_dialog
            harness.do_copy_as("hex")

        assert len(dialog_calls) == 1, f"QMessageBox.warning must be called exactly once when setText raises, got {len(dialog_calls)}"
        title, message = dialog_calls[0]
        assert title == _CLIPBOARD_WRITE_FAILED_TITLE, f"warning title must be {_CLIPBOARD_WRITE_FAILED_TITLE!r}, got {title!r}"
        assert exc_text in message, f"exception text {exc_text!r} must appear in warning message, got {message!r}"
        assert "Could not write to the clipboard:" in message, f"sentinel prefix must appear in warning message, got {message!r}"

    @staticmethod
    def test_successful_copy_does_not_show_warning(qapp: QApplication) -> None:
        """Assert no warning dialog is shown when clipboard.setText succeeds.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _CopyHarness()
        dialog_calls: list[tuple[str, str]] = []

        def _capture_dialog(_parent: object, title: str, message: str) -> int:
            dialog_calls.append((title, message))
            return 0

        mock_clipboard = MagicMock()
        mock_clipboard.setText.return_value = None

        with (
            patch("intellicrack.ui.panels.hex_editor.panel.QApplication") as mock_app,
            patch("intellicrack.ui.dialogs_helpers.QMessageBox") as mock_msgbox,
        ):
            mock_app.clipboard.return_value = mock_clipboard
            mock_msgbox.warning.side_effect = _capture_dialog
            harness.do_copy_as("hex")

        assert dialog_calls == [], f"no warning dialog should fire on successful copy, got {dialog_calls}"

    @staticmethod
    def test_copy_as_passes_widget_output_verbatim_to_clipboard_set_text(qapp: QApplication) -> None:
        r"""Assert the exact string from ``copy_as`` reaches ``clipboard.setText`` unchanged.

        ``_do_copy_as`` must call ``clipboard.setText(str(copy_as(fmt)))`` with the
        verbatim result from the hex widget's ``copy_as`` method.  This test intercepts
        ``QApplication.clipboard()`` to return a controlled stub whose ``setText`` call
        is captured, then asserts the exact argument.  No real OS clipboard is touched,
        so the test is deterministic across headless, CI, and sandboxed environments.

        The format string itself must also be forwarded unchanged to ``copy_as``, which
        is validated by using a format-recording widget.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        expected_text = "DEADBEEF_verbatim_gate"
        expected_fmt = "c_array"
        set_text_calls: list[str] = []
        copy_as_fmt_calls: list[str] = []

        class _RecordingHexWidget:
            def copy_as(self, fmt: str) -> str:
                """Record the format and return the sentinel text.

                Args:
                    fmt: Format name passed by the production code.

                Returns:
                    str: Sentinel value representing widget output.
                """
                copy_as_fmt_calls.append(fmt)
                return expected_text

        class _RecordingHarness(QWidget):
            def __init__(self) -> None:
                """Initialise the harness with a recording hex widget."""
                super().__init__()
                self._hex_widget: object | None = _RecordingHexWidget()

            def do_copy_as(self, fmt: str) -> None:
                """Call the production ``_do_copy_as`` implementation via getattr.

                Args:
                    fmt: Format name to pass to the handler.
                """
                getattr(HexEditorPanel, "_do_copy_as")(self, fmt)

        def _capture_set_text(text: str) -> None:
            set_text_calls.append(text)

        mock_clipboard = MagicMock()
        mock_clipboard.setText.side_effect = _capture_set_text

        harness = _RecordingHarness()

        with patch("intellicrack.ui.panels.hex_editor.panel.QApplication") as mock_app:
            mock_app.clipboard.return_value = mock_clipboard
            harness.do_copy_as(expected_fmt)

        assert copy_as_fmt_calls == [expected_fmt], f"copy_as must receive the format {expected_fmt!r} unchanged, got {copy_as_fmt_calls!r}"
        assert set_text_calls == [expected_text], f"clipboard.setText must be called once with {expected_text!r}, got {set_text_calls!r}"

    @staticmethod
    def test_no_hex_widget_does_not_show_warning_or_raise(qapp: QApplication) -> None:
        """Assert that _do_copy_as exits silently and shows no warning when _hex_widget is None.

        The production guard is ``if self._hex_widget is None: return``.
        No warning should be surfaced to the user in this case, since it
        represents an uninitialised panel (not a clipboard problem).

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        dialog_calls: list[tuple[str, str]] = []

        def _capture_dialog(_parent: object, title: str, message: str) -> int:
            dialog_calls.append((title, message))
            return 0

        class _NoWidgetHarness(QWidget):
            def __init__(self) -> None:
                """Initialise the harness with _hex_widget set to None."""
                super().__init__()
                self._hex_widget: object | None = None

            def do_copy_as(self, fmt: str) -> None:
                """Call the production ``_do_copy_as`` implementation via getattr.

                Args:
                    fmt: Format name to pass to the handler.
                """
                getattr(HexEditorPanel, "_do_copy_as")(self, fmt)

        harness = _NoWidgetHarness()
        with patch("intellicrack.ui.dialogs_helpers.QMessageBox") as mock_msgbox:
            mock_msgbox.warning.side_effect = _capture_dialog
            harness.do_copy_as("hex")

        assert dialog_calls == [], f"_do_copy_as must not show any warning when _hex_widget is None, got {dialog_calls}"
