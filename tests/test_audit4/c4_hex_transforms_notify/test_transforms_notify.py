# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for F-0003: TransformsMixin notify_data_modified on every byte mutation.

Verifies that every document mutation path in TransformsMixin fires
``state_holder.notify_data_modified(offset, length, source=...)`` with the
correct arguments AFTER a successful write, and that failed transforms (empty
selection / read_len <= 0) do NOT fire the notification.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
from PyQt6.QtWidgets import QDialog

import intellicrack.ui.panels.hex_editor.transforms as _t_mod
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor.transforms import TransformsMixin


class _SpyDoc:
    """Minimal in-memory document that records write/fill/copy/move/swap calls."""

    def __init__(self, data: bytearray) -> None:
        """Construct the spy document with initial bytes.

        Args:
            data: Initial document content.
        """
        self._data = bytearray(data)
        self.write_calls: list[tuple[int, bytes]] = []
        self.fill_calls: list[tuple[int, int, bytes]] = []
        self.copy_calls: list[tuple[int, int, int]] = []
        self.move_calls: list[tuple[int, int, int]] = []
        self.swap_calls: list[tuple[int, int, int, int]] = []

    def length(self) -> int:
        """Return the document length.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Read bytes from the document.

        Args:
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            bytes: Slice of document data.
        """
        return bytes(self._data[offset : offset + length])

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes into the document.

        Args:
            offset: Write start offset.
            data: Bytes to write.
        """
        self.write_calls.append((offset, data))
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(bytes(end - len(self._data)))
        self._data[offset:end] = data

    def transform_data(
        self,
        node_name: str,
        offset: int,
        length: int,
        params: dict[str, bytes],
    ) -> bytes:
        """Return the document bytes unchanged (identity transform).

        Args:
            node_name: Name of the transform node (unused).
            offset: Start offset.
            length: Number of bytes.
            params: Transform parameters (unused).

        Returns:
            bytes: Original document bytes.
        """
        _ = (node_name, params)
        return bytes(self._data[offset : offset + length])

    def fill_block(self, offset: int, length: int, pattern: bytes) -> None:
        """Fill a block with a repeating pattern.

        Args:
            offset: Start offset.
            length: Number of bytes to fill.
            pattern: Pattern bytes to repeat.
        """
        self.fill_calls.append((offset, length, pattern))
        fill_data = (pattern * (length // max(len(pattern), 1) + 1))[:length]
        self._data[offset : offset + length] = fill_data

    def copy_block(self, src: int, length: int, dst: int) -> None:
        """Copy bytes from src to dst.

        Args:
            src: Source offset.
            length: Number of bytes to copy.
            dst: Destination offset.
        """
        self.copy_calls.append((src, length, dst))
        data = bytearray(self._data[src : src + length])
        self._data[dst : dst + length] = data

    def move_block(self, src: int, length: int, dst: int) -> None:
        """Move bytes from src to dst, zeroing the source region.

        Args:
            src: Source offset.
            length: Number of bytes to move.
            dst: Destination offset.
        """
        self.move_calls.append((src, length, dst))
        data = bytearray(self._data[src : src + length])
        self._data[src : src + length] = bytes(length)
        self._data[dst : dst + length] = data

    def swap_blocks(self, off_a: int, len_a: int, off_b: int, len_b: int) -> None:
        """Swap two equal-length blocks.

        Args:
            off_a: Offset of block A.
            len_a: Length of block A.
            off_b: Offset of block B.
            len_b: Length of block B.
        """
        self.swap_calls.append((off_a, len_a, off_b, len_b))
        data_a = bytearray(self._data[off_a : off_a + len_a])
        data_b = bytearray(self._data[off_b : off_b + len_b])
        self._data[off_a : off_a + len_a] = data_b
        self._data[off_b : off_b + len_b] = data_a


class _ConcreteTransforms(TransformsMixin):
    """Concrete TransformsMixin subclass for testing without a Qt window."""

    def __init__(self, doc: _SpyDoc, state: HexDocumentState | None) -> None:
        """Construct with a document and state holder.

        Args:
            doc: Spy document to mutate.
            state: HexDocumentState to receive notifications, or None.
        """
        self.document: _SpyDoc | None = doc
        self._document: Any = None
        self._hex_widget: Any = None
        self._transform_node_combo = None
        self._transform_params_form = None
        self._transform_params_widget = None
        self._transform_preview_pane = None
        self._transform_pipeline_list = None
        self._transform_pipeline: Any = None
        self._transform_nodes_cache: list[Any] = []
        self._bridge: Any = None
        self.state_holder: HexDocumentState | None = state
        self._selection_start: int = -1
        self._selection_end: int = -1
        self._arith_op_combo: Any = None
        self._arith_key_edit: Any = None
        self._arith_count_spin: Any = None
        self._data_changed_calls: int = 0

    def _on_data_changed(self) -> None:
        """Count data-changed callbacks."""
        self._data_changed_calls += 1


def _subscribe(state: HexDocumentState) -> list[tuple[int, int, str]]:
    """Register a DATA_MODIFIED subscriber on state.

    Args:
        state: State holder to subscribe to.

    Returns:
        list[tuple[int, int, str]]: Mutable list appended with
            ``(offset, length, source)`` on each DATA_MODIFIED event.
    """
    captured: list[tuple[int, int, str]] = []

    def _cb(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        if event_type is HexDocumentEvent.DATA_MODIFIED:
            captured.append((
                int(data["offset"]),
                int(data["length"]),
                str(data.get("source", "")),
            ))

    state.register_callback(_cb, source_id="test-subscriber")
    return captured


@pytest.fixture
def doc_state_events() -> tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]]:
    """Create a fresh SpyDoc, HexDocumentState, and capture list.

    Returns:
        tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]]:
            The spy document, state holder, and captured-events list.
    """
    state = HexDocumentState()
    doc = _SpyDoc(bytearray(range(256)))
    events = _subscribe(state)
    return doc, state, events


class TestTransformApplyNotify:
    """_on_transform_apply must fire notify_data_modified after a successful write."""

    def test_fires_at_cursor_offset(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """Notify fires at cursor offset when no selection is set.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)
        mixin._on_transform_apply()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 0
        assert length > 0
        assert source == "hex-editor.transforms.apply"

    def test_fires_with_selection_extent(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """Notify carries the actual selection start and length.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        class _FakeWidget:
            _cursor_offset: int = 10
            _selection_start: int = 10
            _selection_end: int = 30

        mixin._hex_widget = _FakeWidget()
        mixin._on_transform_apply()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 10
        assert length == 20
        assert source == "hex-editor.transforms.apply"

    def test_no_notify_when_document_none(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """No DATA_MODIFIED fires when document is None.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        _doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(_SpyDoc(bytearray(0)), state)
        mixin.document = None

        mixin._on_transform_apply()

        assert events == []

    def test_no_notify_when_selection_beyond_document(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """No DATA_MODIFIED fires when the cursor is past end of document.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        class _FakeWidget:
            _cursor_offset: int = 256
            _selection_start: int = 256
            _selection_end: int = 256

        mixin._hex_widget = _FakeWidget()
        mixin._on_transform_apply()

        assert events == []


class TestPipelineExecuteNotify:
    """_on_pipeline_execute must fire notify_data_modified after a successful write."""

    def test_fires_with_selection_extent(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """Notify fires with the correct offset and length after pipeline write.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        class _FakePipeline:
            steps: ClassVar[list[object]] = [object()]

            @staticmethod
            def execute(data: bytes) -> bytes:
                """Return data unchanged.

                Args:
                    data: Input bytes.

                Returns:
                    bytes: The same input bytes.
                """
                return data

        mixin._transform_pipeline = _FakePipeline()

        class _FakeWidget:
            _cursor_offset: int = 4
            _selection_start: int = 4
            _selection_end: int = 20

        mixin._hex_widget = _FakeWidget()
        mixin._on_pipeline_execute()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 4
        assert length == 16
        assert source == "hex-editor.transforms.pipeline"

    def test_no_notify_when_pipeline_none(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """No DATA_MODIFIED fires when pipeline is None.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)
        mixin._transform_pipeline = None

        mixin._on_pipeline_execute()

        assert events == []

    def test_no_notify_when_pipeline_has_no_steps(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
    ) -> None:
        """No DATA_MODIFIED fires when the pipeline has zero steps.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        class _EmptyPipeline:
            steps: ClassVar[list[object]] = []

        mixin._transform_pipeline = _EmptyPipeline()
        mixin._on_pipeline_execute()

        assert events == []


class TestBlockFillNotify:
    """_on_block_fill must fire notify_data_modified after a successful fill."""

    def test_fires_with_dialog_offset_and_length(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Notify fires with the offset and length from the fill dialog.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
            monkeypatch: pytest monkeypatch fixture.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        monkeypatch.setattr(
            _t_mod._BlockFillDialog,
            "exec",
            lambda _self: QDialog.DialogCode.Accepted,
        )
        monkeypatch.setattr(
            _t_mod._BlockFillDialog,
            "get_values",
            lambda _self: (8, 16, bytes([0xAA])),
        )

        mixin._on_block_fill()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 8
        assert length == 16
        assert source == "hex-editor.transforms.fill"

    def test_no_notify_when_dialog_rejected(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No DATA_MODIFIED fires when the fill dialog is cancelled.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
            monkeypatch: pytest monkeypatch fixture.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        monkeypatch.setattr(
            _t_mod._BlockFillDialog,
            "exec",
            lambda _self: QDialog.DialogCode.Rejected,
        )

        mixin._on_block_fill()

        assert events == []


class TestBlockCopyNotify:
    """_on_block_copy must fire notify_data_modified at the destination offset."""

    def test_fires_at_destination(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Notify fires with the destination offset and copy length.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
            monkeypatch: pytest monkeypatch fixture.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        monkeypatch.setattr(
            _t_mod._BlockCopyMoveDialog,
            "exec",
            lambda _self: QDialog.DialogCode.Accepted,
        )
        monkeypatch.setattr(
            _t_mod._BlockCopyMoveDialog,
            "get_values",
            lambda _self: (0, 8, 64),
        )

        mixin._on_block_copy()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 64
        assert length == 8
        assert source == "hex-editor.transforms.copy"


class TestBlockMoveNotify:
    """_on_block_move must fire notify_data_modified after a successful move."""

    def test_fires_after_move(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Notify fires with the move length after a successful move.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
            monkeypatch: pytest monkeypatch fixture.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        monkeypatch.setattr(
            _t_mod._BlockCopyMoveDialog,
            "exec",
            lambda _self: QDialog.DialogCode.Accepted,
        )
        monkeypatch.setattr(
            _t_mod._BlockCopyMoveDialog,
            "get_values",
            lambda _self: (0, 16, 64),
        )

        mixin._on_block_move()

        assert len(events) == 1
        _offset, length, source = events[0]
        assert length == 16
        assert source == "hex-editor.transforms.move"


class TestBlockSwapNotify:
    """_on_block_swap must fire notify_data_modified spanning both swapped blocks."""

    def test_fires_spanning_both_blocks(
        self,
        doc_state_events: tuple[_SpyDoc, HexDocumentState, list[tuple[int, int, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Notify fires with offset of lower block and combined length.

        Args:
            doc_state_events: Fixture providing spy doc, state, and events.
            monkeypatch: pytest monkeypatch fixture.
        """
        doc, state, events = doc_state_events
        mixin = _ConcreteTransforms(doc, state)

        monkeypatch.setattr(
            _t_mod._BlockSwapDialog,
            "exec",
            lambda _self: QDialog.DialogCode.Accepted,
        )
        monkeypatch.setattr(
            _t_mod._BlockSwapDialog,
            "get_values",
            lambda _self: (0, 8, 16, 8),
        )

        mixin._on_block_swap()

        assert len(events) == 1
        offset, length, source = events[0]
        assert offset == 0
        assert length == 16
        assert source == "hex-editor.transforms.swap"


class TestNoStateHolderSafety:
    """Operations must not raise and must still write data when state_holder is None."""

    def test_transform_apply_no_state_holder_still_writes(self) -> None:
        """_on_transform_apply writes to document even with no state holder.

        The absence of a state_holder must not prevent the actual mutation.
        """
        doc = _SpyDoc(bytearray(32))
        mixin = _ConcreteTransforms(doc, HexDocumentState())
        mixin.state_holder = None

        mixin._on_transform_apply()

        assert doc.write_calls, "document.write_bytes must still be called"

    def test_pipeline_execute_no_state_holder_still_writes(self) -> None:
        """_on_pipeline_execute writes to document even with no state holder.

        The absence of a state_holder must not prevent the actual mutation.
        """
        doc = _SpyDoc(bytearray(32))
        mixin = _ConcreteTransforms(doc, HexDocumentState())
        mixin.state_holder = None

        class _IdentityPipeline:
            steps: ClassVar[list[object]] = [object()]

            @staticmethod
            def execute(data: bytes) -> bytes:
                """Return data unchanged.

                Args:
                    data: Input bytes.

                Returns:
                    bytes: The same input bytes.
                """
                return data

        mixin._transform_pipeline = _IdentityPipeline()
        mixin._on_pipeline_execute()

        assert doc.write_calls, "document.write_bytes must still be called"
