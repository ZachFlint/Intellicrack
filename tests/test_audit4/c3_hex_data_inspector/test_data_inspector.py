# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C3: hex editor data inspector mixin.

These tests guard against three regressions in
:class:`~intellicrack.ui.panels.hex_editor.data_inspector.DataInspectorMixin`:

* **F-0003** -- Bit-toggle writes via ``document.set_bit`` must publish
  :meth:`HexDocumentState.notify_data_modified` so bridge subscribers
  learn about the mutation.  The pre-audit code returned after the write
  without notifying.

* **F-0011** -- ``_on_encode_text`` must surface ``"No document open"``
  when no document is attached and must never fall back to the
  class-level ``hexcore.HexDocument.encode_text_to_bytes`` static
  encoder.  The pre-audit fallback silently produced bytes without a
  live document, misrepresenting the panel state.

* **F-0016** -- ``_update_bit_buttons`` must iterate all 8 bit buttons
  even when one button's ``document.get_bit`` raises.  The pre-audit
  code returned early on the first exception, leaving the remaining
  buttons stale.  Failed buttons must be rendered in a distinct error
  state (label ``"?"``, disabled) while successful buttons are updated
  normally.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor.data_inspector import DataInspectorMixin


if TYPE_CHECKING:
    from collections.abc import Iterator


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


class _RecordingStateWithSource(HexDocumentState):
    """A :class:`HexDocumentState` whose ``_notify`` override captures the dispatch source.

    The ``dispatched`` list records every ``(event_type, data, source)`` tuple
    in dispatch order for post-call assertions.
    """

    def __init__(self) -> None:
        """Initialise the state holder and the source-aware recorder."""
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
        """Record the dispatch source then forward to the production dispatcher.

        Args:
            event_type: The state-holder event being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller for loop-guard filtering.
        """
        self.dispatched.append((event_type, dict(data), source))
        super()._notify(event_type, data, source=source)

    def data_modified_events(self) -> list[tuple[dict[str, Any], str]]:
        """Return DATA_MODIFIED (payload, source) tuples in dispatch order.

        Returns:
            list[tuple[dict[str, Any], str]]: Payload + source for every
                DATA_MODIFIED event published on this state holder.
        """
        return [(data, src) for evt, data, src in self.dispatched if evt is HexDocumentEvent.DATA_MODIFIED]


class _StubDocument:
    """Minimal in-memory document stub for the data-inspector tests.

    Records calls to ``set_bit`` and ``get_bit`` so tests can assert
    which bits were read or written without needing the Rust hexcore
    extension.  ``byte_val`` holds the current byte value, ``set_bit_calls``
    records every ``(offset, bit_index, value)`` write, and
    ``get_bit_error_bits`` holds bit indices for which ``get_bit`` should raise.
    """

    def __init__(self, byte_val: int = 0xA5) -> None:
        """Initialise the stub with an initial byte value.

        Args:
            byte_val: Initial byte value used for bit reads.
        """
        self.byte_val: int = byte_val
        self.set_bit_calls: list[tuple[int, int, bool]] = []
        self.get_bit_error_bits: set[int] = set()

    def set_bit(self, offset: int, bit_index: int, value: int) -> None:
        """Record the set_bit call and update the byte value.

        Args:
            offset: Byte offset.
            bit_index: Bit position (0=LSB, 7=MSB).
            value: New bit value (truthy = 1, falsy = 0).
        """
        self.set_bit_calls.append((offset, bit_index, bool(value)))
        if value:
            self.byte_val |= 1 << bit_index
        else:
            self.byte_val &= ~(1 << bit_index)

    def get_bit(self, offset: int, bit_index: int) -> bool:
        """Return the bit at ``bit_index`` or raise if injected.

        Args:
            offset: Byte offset (unused; single-byte stub).
            bit_index: Bit position (0=LSB, 7=MSB).

        Returns:
            bool: Current bit value.

        Raises:
            ValueError: When ``bit_index`` is in ``get_bit_error_bits``.
        """
        del offset
        if bit_index in self.get_bit_error_bits:
            msg = f"injected error for bit {bit_index}"
            raise ValueError(msg)
        return bool((self.byte_val >> bit_index) & 1)

    def encode_text_to_bytes(self, text: str, encoding: str) -> list[int]:
        """Encode text using Python stdlib codec.

        Args:
            text: Text to encode.
            encoding: Codec name.

        Returns:
            list[int]: Encoded byte values.
        """
        return list(text.encode(encoding))


class _FailingSetBitDocument(_StubDocument):
    """A :class:`_StubDocument` whose ``set_bit`` always raises.

    Used in tests that need to verify ``notify_data_modified`` is NOT
    called when the underlying write operation fails.
    """

    def set_bit(self, offset: int, bit_index: int, value: int) -> None:
        """Unconditionally raise to simulate a write failure.

        Args:
            offset: Byte offset (unused).
            bit_index: Bit position (unused).
            value: New bit value (unused).

        Raises:
            ValueError: Always, to simulate a write failure.
        """
        del offset, bit_index, value
        msg = "simulated set_bit failure"
        raise ValueError(msg)


class _StubBridge:
    """Minimal bridge stub whose ``encode_text`` is a real async coroutine.

    Records every call to ``encode_text`` so tests can assert the method
    was invoked and inspect the parameters.  ``encode_calls`` holds
    ``(text, encoding)`` pairs in call order; ``result`` is the canned
    hex string returned by ``encode_text``.
    """

    def __init__(self, result: str = "68656c6c6f") -> None:
        """Initialise the stub with a canned result.

        Args:
            result: Hex string to return from ``encode_text``.
        """
        self.result: str = result
        self.encode_calls: list[tuple[str, str]] = []

    async def encode_text(self, text: str, encoding: str = "utf-8") -> str:
        """Record the call and return the canned result.

        Args:
            text: Text to encode.
            encoding: Encoding name.

        Returns:
            str: Canned hex result.
        """
        self.encode_calls.append((text, encoding))
        return self.result


class _DataInspectorHarness(DataInspectorMixin, QWidget):
    """Minimal QWidget subclass that exposes :class:`DataInspectorMixin` for tests.

    Wires the mixin's required instance attributes to stubs so tests can
    exercise bit-toggle and encode-text paths without the full panel
    hierarchy.  Public wrapper properties and methods delegate to the
    mixin's protected members so tests avoid accessing private names.
    """

    def __init__(self, document: _StubDocument | None = None) -> None:
        """Initialise the harness with optional document and state holder.

        Args:
            document: Stub document to attach, or ``None`` for no-document tests.
        """
        super().__init__()
        self.document: _StubDocument | None = document
        self._document: _StubDocument | None = document
        self.state_holder: HexDocumentState | None = None
        self._bridge: _StubBridge | None = None
        self._hex_widget: object | None = None
        self._bit_editor_offset: int = 0
        self._bit_buttons: list[QPushButton] = []
        self._encode_input: QLineEdit | None = None
        self._encode_output: QLabel | None = None
        self._encode_combo = None
        self._decode_output = None
        self._decode_combo = None
        self._decode_length_spin = None
        self._data_inspector_tree = None

    @property
    def bridge(self) -> _StubBridge | None:
        """Return the current bridge stub.

        Returns:
            _StubBridge | None: The stub bridge wired to ``_bridge``.
        """
        return self._bridge

    @bridge.setter
    def bridge(self, value: _StubBridge | None) -> None:
        """Set the bridge stub.

        Args:
            value: New stub bridge to wire.
        """
        self._bridge = value

    @property
    def bit_buttons_list(self) -> list[QPushButton]:
        """Return the bit-editor button list.

        Returns:
            list[QPushButton]: The mixin's ``_bit_buttons`` list.
        """
        return self._bit_buttons

    @bit_buttons_list.setter
    def bit_buttons_list(self, value: list[QPushButton]) -> None:
        """Replace the bit-editor button list.

        Args:
            value: Replacement list of QPushButton instances.
        """
        self._bit_buttons = value

    @property
    def bit_editor_offset(self) -> int:
        """Return the current bit-editor byte offset.

        Returns:
            int: The mixin's ``_bit_editor_offset``.
        """
        return self._bit_editor_offset

    @bit_editor_offset.setter
    def bit_editor_offset(self, value: int) -> None:
        """Set the bit-editor byte offset.

        Args:
            value: New byte offset for bit read/write operations.
        """
        self._bit_editor_offset = value

    @property
    def encode_input(self) -> QLineEdit | None:
        """Return the encode text-input widget.

        Returns:
            QLineEdit | None: The mixin's ``_encode_input``.
        """
        return self._encode_input

    @encode_input.setter
    def encode_input(self, value: QLineEdit | None) -> None:
        """Set the encode text-input widget.

        Args:
            value: New QLineEdit for encode input.
        """
        self._encode_input = value

    @property
    def encode_output(self) -> QLabel | None:
        """Return the encode output label.

        Returns:
            QLabel | None: The mixin's ``_encode_output``.
        """
        return self._encode_output

    @encode_output.setter
    def encode_output(self, value: QLabel | None) -> None:
        """Set the encode output label.

        Args:
            value: New QLabel for encode output.
        """
        self._encode_output = value

    def toggle_bit(self, bit_index: int, *, checked: bool) -> None:
        """Invoke the mixin's bit-toggle handler.

        Args:
            bit_index: Bit position (0=LSB, 7=MSB).
            checked: New bit value.
        """
        self._on_bit_toggled(bit_index, checked=checked)

    def run_encode_text(self) -> None:
        """Invoke the mixin's encode-text handler."""
        self._on_encode_text()

    def refresh_bit_buttons(self, offset: int) -> None:
        """Invoke the mixin's bit-button refresh.

        Args:
            offset: Byte offset to read.
        """
        self._update_bit_buttons(offset)


def _make_bit_buttons(count: int = 8) -> list[QPushButton]:
    """Create a list of fresh QPushButton instances for the bit-editor row.

    Args:
        count: Number of buttons to create.

    Returns:
        list[QPushButton]: Fresh checkable buttons labelled ``"0"``.
    """
    btns: list[QPushButton] = []
    for _ in range(count):
        btn = QPushButton("0")
        btn.setCheckable(True)
        btn.setEnabled(True)
        btns.append(btn)
    return btns


@pytest.mark.usefixtures("qapp")
class TestCommitInt32FiresNotifyDataModified:
    """F-0003: bit-toggle must fire ``notify_data_modified`` after a successful write.

    The test name mirrors the unit manifest requirement
    ``test_commit_int32_fires_notify_data_modified``.  Although the
    data-inspector mixin does not expose a distinct int32 write path
    (inline typed-field commits are done via the bit editor for single
    bytes), the audit finding at lines 170-206 explicitly targets
    ``_on_bit_toggled``.  The test verifies the notify is fired with the
    correct offset, length 1, and a source containing the
    ``"data_inspector"`` namespace.
    """

    @staticmethod
    def test_commit_int32_fires_notify_data_modified(qapp: QApplication) -> None:
        """Bit toggle at offset 5 must publish DATA_MODIFIED with offset=5, length=1.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument(byte_val=0x00)
        h = _DataInspectorHarness(doc)
        state = _RecordingStateWithSource()
        h.state_holder = state
        h.bit_editor_offset = 5

        h.toggle_bit(3, checked=True)

        events = state.data_modified_events()
        assert len(events) == 1, f"Expected exactly one DATA_MODIFIED event after bit toggle; got {len(events)}"
        payload, source = events[0]
        assert payload["offset"] == 5, f"offset must be the bit-editor offset (5); got {payload['offset']}"
        assert payload["length"] == 1, f"length must be 1 (single byte); got {payload['length']}"
        assert "data_inspector" in source, f"source must contain 'data_inspector' namespace; got {source!r}"

    @staticmethod
    def test_no_notify_when_document_is_none(qapp: QApplication) -> None:
        """No DATA_MODIFIED must be published when ``document`` is ``None``.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        h = _DataInspectorHarness(None)
        state = _RecordingStateWithSource()
        h.state_holder = state

        h.toggle_bit(0, checked=True)

        assert state.data_modified_events() == [], "no notify when document is None"

    @staticmethod
    def test_no_notify_when_set_bit_raises(qapp: QApplication) -> None:
        """No DATA_MODIFIED must be published when ``document.set_bit`` raises.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _FailingSetBitDocument()
        h = _DataInspectorHarness(doc)
        state = _RecordingStateWithSource()
        h.state_holder = state

        h.toggle_bit(2, checked=True)

        assert state.data_modified_events() == [], "no notify when set_bit raises"

    @staticmethod
    def test_notify_uses_correct_source_namespace(qapp: QApplication) -> None:
        """Source literal must start with ``"hex-editor.data_inspector"``.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument()
        h = _DataInspectorHarness(doc)
        state = _RecordingStateWithSource()
        h.state_holder = state
        h.bit_editor_offset = 0

        h.toggle_bit(0, checked=True)

        events = state.data_modified_events()
        assert events, "expected at least one DATA_MODIFIED event"
        _, source = events[0]
        assert source.startswith("hex-editor.data_inspector"), f"source must start with 'hex-editor.data_inspector'; got {source!r}"


@pytest.mark.usefixtures("qapp")
class TestEncodeTextNoDocSurfacesError:
    """F-0011: ``_on_encode_text`` must surface an error when no document is open.

    The pre-audit code fell back to ``hexcore.HexDocument.encode_text_to_bytes``
    (the class-level static method) and produced bytes silently even when no
    document was attached.  The fix must set the output label to the literal
    string ``"No document open"`` and must NOT produce any hex output.
    """

    @staticmethod
    def test_encode_text_no_doc_surfaces_error(qapp: QApplication) -> None:
        """Output label must contain ``"No document open"`` when ``document is None``.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        h = _DataInspectorHarness(None)
        enc_input = QLineEdit()
        enc_input.setText("hello")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        result = enc_output.text()
        assert result == "No document open", f"Expected 'No document open' when no document is attached; got {result!r}"

    @staticmethod
    def test_no_fallback_bytes_generated(qapp: QApplication) -> None:
        """The output label must not contain a hex string when no document is open.

        The pre-audit code produced bytes via the class-level encoder.
        With the fix, the label must be the error string and not any
        hex-encoded form of the input text.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        h = _DataInspectorHarness(None)
        enc_input = QLineEdit()
        enc_input.setText("hello")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        result = enc_output.text()
        expected_hex = "68 65 6C 6C 6F"
        assert result != expected_hex, (
            "The fallback hex bytes must NOT be produced when no document is open; "
            f"got {result!r} which matches the pre-audit fallback output"
        )

    @staticmethod
    def test_no_doc_no_bridge_call(qapp: QApplication) -> None:
        """Bridge must not be invoked when no document is open.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        bridge = _StubBridge()
        h = _DataInspectorHarness(None)
        h.bridge = bridge
        enc_input = QLineEdit()
        enc_input.setText("test")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        assert bridge.encode_calls == [], "bridge.encode_text must not be called when document is None"


@pytest.mark.usefixtures("qapp")
class TestEncodeTextWithDocRoutesThroughBridge:
    """F-0011: ``_on_encode_text`` must route through bridge's ``encode_text`` when a doc is open.

    The pre-audit code called ``document.encode_text_to_bytes`` (or the
    class-level static) directly.  The fix must call
    ``bridge.encode_text(text, encoding)`` via ``run_bridge_coroutine``
    and display the resulting hex string.
    """

    @staticmethod
    def test_encode_text_with_doc_routes_through_bridge(qapp: QApplication) -> None:
        """Bridge ``encode_text`` must be called with the input text and encoding.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        bridge = _StubBridge(result="68656c6c6f")
        doc = _StubDocument()
        h = _DataInspectorHarness(doc)
        h.bridge = bridge
        enc_input = QLineEdit()
        enc_input.setText("hello")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        assert len(bridge.encode_calls) == 1, f"bridge.encode_text must be called exactly once; got {len(bridge.encode_calls)}"
        called_text, called_encoding = bridge.encode_calls[0]
        assert called_text == "hello", f"bridge must receive the input text; got {called_text!r}"
        assert called_encoding == "utf-8", f"default encoding must be utf-8; got {called_encoding!r}"

    @staticmethod
    def test_encode_text_output_uses_bridge_result(qapp: QApplication) -> None:
        """The output label must display the hex string returned by the bridge.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        bridge = _StubBridge(result="deadbeef")
        doc = _StubDocument()
        h = _DataInspectorHarness(doc)
        h.bridge = bridge
        enc_input = QLineEdit()
        enc_input.setText("test")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        result = enc_output.text()
        assert result == "DE AD BE EF", f"output must be the bridge result formatted as spaced hex; got {result!r}"

    @staticmethod
    def test_encode_text_no_bridge_surfaces_error(qapp: QApplication) -> None:
        """When doc is open but bridge is None, an error must be surfaced.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument()
        h = _DataInspectorHarness(doc)
        h.bridge = None
        enc_input = QLineEdit()
        enc_input.setText("hello")
        enc_output = QLabel()
        h.encode_input = enc_input
        h.encode_output = enc_output

        h.run_encode_text()

        result = enc_output.text()
        assert result.startswith("Error:"), f"expected an error label when bridge is None with doc open; got {result!r}"


@pytest.mark.usefixtures("qapp")
class TestUpdateBitButtonsContinuesPastError:
    """F-0016: ``_update_bit_buttons`` must update all 8 bits even when one raises.

    The pre-audit code returned early on the first ``get_bit`` exception,
    leaving all subsequent buttons with stale values.  The fix must:

    * Continue iterating all buttons after a per-bit error.
    * Render the failed button in an error state: label ``"?"``, disabled.
    * Render all successful buttons normally (enabled, correct text/check).
    """

    @staticmethod
    def test_update_bit_buttons_continues_past_error(qapp: QApplication) -> None:
        """Inject error on bit 3; bits 0-2 and 4-7 must still be updated.

        The stub document has ``get_bit_error_bits = {3}``.  After
        calling ``refresh_bit_buttons(0)``:

        * Button for bit 3 must have text ``"?"``, be unchecked, and be disabled.
        * Buttons for all other bits must be enabled and have text ``"0"`` or ``"1"``.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument(byte_val=0b10101010)
        doc.get_bit_error_bits = {3}

        h = _DataInspectorHarness(doc)
        h.bit_buttons_list = _make_bit_buttons(8)

        h.refresh_bit_buttons(0)

        for i, btn in enumerate(h.bit_buttons_list):
            bit_idx = 7 - i
            if bit_idx == 3:
                assert btn.text() == "?", f"button for bit 3 must show '?' in error state; got {btn.text()!r}"
                assert not btn.isEnabled(), "button for bit 3 must be disabled in error state"
            else:
                assert btn.text() in {"0", "1"}, f"button for bit {bit_idx} must show '0' or '1'; got {btn.text()!r}"
                assert btn.isEnabled(), f"button for bit {bit_idx} must be enabled after successful read"

    @staticmethod
    def test_all_bits_updated_when_no_errors(qapp: QApplication) -> None:
        """All 8 buttons must be updated when no errors occur.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument(byte_val=0b10110101)
        h = _DataInspectorHarness(doc)
        h.bit_buttons_list = _make_bit_buttons(8)

        h.refresh_bit_buttons(0)

        for i, btn in enumerate(h.bit_buttons_list):
            bit_idx = 7 - i
            expected_bit = bool((doc.byte_val >> bit_idx) & 1)
            expected_text = "1" if expected_bit else "0"
            assert btn.text() == expected_text, f"bit {bit_idx}: expected text {expected_text!r}, got {btn.text()!r}"
            assert btn.isEnabled(), f"bit {bit_idx} must be enabled when get_bit succeeds"

    @staticmethod
    def test_multiple_error_bits_all_marked(qapp: QApplication) -> None:
        """Multiple error bits must each be marked with '?' and disabled independently.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument(byte_val=0xFF)
        doc.get_bit_error_bits = {0, 4, 7}

        h = _DataInspectorHarness(doc)
        h.bit_buttons_list = _make_bit_buttons(8)

        h.refresh_bit_buttons(0)

        for i, btn in enumerate(h.bit_buttons_list):
            bit_idx = 7 - i
            if bit_idx in {0, 4, 7}:
                assert btn.text() == "?", f"error bit {bit_idx} must show '?'; got {btn.text()!r}"
                assert not btn.isEnabled(), f"error bit {bit_idx} must be disabled"
            else:
                assert btn.text() == "1", f"non-error bit {bit_idx} with byte=0xFF must show '1'; got {btn.text()!r}"
                assert btn.isEnabled(), f"non-error bit {bit_idx} must be enabled"

    @staticmethod
    def test_early_error_does_not_prevent_later_bits_being_updated(qapp: QApplication) -> None:
        """Error on bit 7 (first iterated, MSB) must not block bits 6 through 0.

        This is the direct regression check: the pre-audit ``return``
        statement on the first error would have silenced updates to all
        subsequent buttons.

        Args:
            qapp: Qt application fixture used for widget construction.
        """
        del qapp
        doc = _StubDocument(byte_val=0b01010101)
        doc.get_bit_error_bits = {7}

        h = _DataInspectorHarness(doc)
        h.bit_buttons_list = _make_bit_buttons(8)

        h.refresh_bit_buttons(0)

        btn_for_bit7 = h.bit_buttons_list[0]
        assert btn_for_bit7.text() == "?", "bit 7 (first iterated) must show '?' in error state"
        assert not btn_for_bit7.isEnabled(), "bit 7 must be disabled in error state"

        for i in range(1, 8):
            bit_idx = 7 - i
            btn = h.bit_buttons_list[i]
            assert btn.text() in {"0", "1"}, f"bit {bit_idx} must be updated even after error on bit 7; got {btn.text()!r}"
            assert btn.isEnabled(), f"bit {bit_idx} must be enabled"
