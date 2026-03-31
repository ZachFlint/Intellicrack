# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge and HexDocumentState synchronization.

Verifies that bridge operations emit the correct HexDocumentEvent values
to registered callbacks via the shared state holder, and that all
callback management semantics (multi-callback, unregister, source-id
filtering) work correctly end-to-end through real bridge operations.
"""

from __future__ import annotations

import asyncio
import json
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import (
    HexDocumentEvent,
    HexDocumentState,
    StateCallbackFn,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


_hexpat_available: bool = find_spec("intellicrack.core.hexpat") is not None

pytest.importorskip("intellicrack_hexcore")


def _run(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_collector() -> tuple[list[tuple[HexDocumentEvent, dict[str, Any]]], StateCallbackFn]:
    """Build a fresh event collector and its bound callback.

    Returns:
        tuple[list[tuple[HexDocumentEvent, dict[str, Any]]], StateCallbackFn]: A
            (events_list, callback) pair. The list is appended to on
            every invocation.
    """
    events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def on_event(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
        events.append((evt, data))

    return events, on_event


class TestSetStateHolder:
    """Tests for set_state_holder attachment and initial state."""

    def test_set_state_holder_does_not_raise(self, bridge: HexEditorBridge) -> None:
        """Attaching a fresh HexDocumentState to a bridge must not raise.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        assert bridge.state_holder is state

    def test_state_holder_accessible_after_set(self, bridge: HexEditorBridge) -> None:
        """The _state_holder attribute must reference the attached state.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        assert bridge.state_holder is not None


class TestDocumentOpenedEvent:
    """Tests for DOCUMENT_OPENED event fired by open_file through state holder."""

    def test_open_file_fires_document_opened(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """open_file must fire DOCUMENT_OPENED on the attached state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.open_file(str(pe_binary)))

        assert any(e[0] == HexDocumentEvent.DOCUMENT_OPENED for e in events)

    def test_open_file_document_opened_payload_has_size(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """DOCUMENT_OPENED event data must contain a positive size field.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.open_file(str(pe_binary)))

        opened = [e for e in events if e[0] == HexDocumentEvent.DOCUMENT_OPENED]
        assert len(opened) == 1
        assert opened[0][1]["size"] > 0

    def test_state_holder_document_property_after_open(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """After open_file, state_holder.document must reference the loaded document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)

        _run(bridge.open_file(str(pe_binary)))

        assert state.document is not None


class TestDataModifiedEvent:
    """Tests for DATA_MODIFIED event fired by write_bytes through state holder."""

    def test_write_bytes_fires_data_modified(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """write_bytes must fire DATA_MODIFIED on the attached state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        _run(bridge.open_file(str(pe_binary)))

        events, cb = _make_collector()
        state.register_callback(cb)

        _run(bridge.write_bytes(0, "90"))

        assert any(e[0] == HexDocumentEvent.DATA_MODIFIED for e in events)

    def test_write_bytes_data_modified_contains_offset(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """DATA_MODIFIED event data must contain the write offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        _run(bridge.open_file(str(pe_binary)))

        events, cb = _make_collector()
        state.register_callback(cb)

        _run(bridge.write_bytes(8, "90 91"))

        modified = [e for e in events if e[0] == HexDocumentEvent.DATA_MODIFIED]
        assert modified
        assert modified[0][1]["offset"] == 8


class TestTemplateEvents:
    """Tests for TEMPLATE_REGISTERED and TEMPLATE_REMOVED events via bridge."""

    def test_register_template_fires_template_registered(self, loaded_bridge: HexEditorBridge) -> None:
        """register_template must fire TEMPLATE_REGISTERED on the state holder.

        Args:
            loaded_bridge: A bridge with the PE file already opened.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        loaded_bridge.set_state_holder(state)

        tmpl = json.dumps({
            "name": "TestHdr",
            "description": "",
            "default_endianness": "little",
            "category": "test",
            "fields": [{"name": "sig", "field_type": {"type": "UInt8"}, "description": ""}],
        })
        _run(loaded_bridge.register_template(tmpl))

        assert any(e[0] == HexDocumentEvent.TEMPLATE_REGISTERED for e in events)

    def test_register_template_event_contains_name(self, loaded_bridge: HexEditorBridge) -> None:
        """TEMPLATE_REGISTERED event data must contain the registered template name.

        Args:
            loaded_bridge: A bridge with the PE file already opened.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        loaded_bridge.set_state_holder(state)

        tmpl = json.dumps({
            "name": "SigHdr",
            "description": "",
            "default_endianness": "little",
            "category": "test",
            "fields": [{"name": "v", "field_type": {"type": "UInt8"}, "description": ""}],
        })
        registered_name: str = _run(loaded_bridge.register_template(tmpl))

        reg_events = [e for e in events if e[0] == HexDocumentEvent.TEMPLATE_REGISTERED]
        assert len(reg_events) == 1
        assert reg_events[0][1]["template_name"] == registered_name

    def test_remove_template_fires_template_removed(self, loaded_bridge: HexEditorBridge) -> None:
        """remove_template must fire TEMPLATE_REMOVED on the state holder.

        Args:
            loaded_bridge: A bridge with the PE file already opened.
        """
        state = HexDocumentState()
        loaded_bridge.set_state_holder(state)

        tmpl = json.dumps({
            "name": "TmpRemove",
            "description": "",
            "default_endianness": "little",
            "category": "test",
            "fields": [{"name": "b", "field_type": {"type": "UInt8"}, "description": ""}],
        })
        registered_name = _run(loaded_bridge.register_template(tmpl))

        events, cb = _make_collector()
        state.register_callback(cb)

        _run(loaded_bridge.remove_template(registered_name))

        assert any(e[0] == HexDocumentEvent.TEMPLATE_REMOVED for e in events)


class TestHighlightRuleEvents:
    """Tests for HIGHLIGHT_RULE_ADDED and HIGHLIGHT_RULE_REMOVED events."""

    def test_add_highlight_rule_fires_event(self, bridge: HexEditorBridge) -> None:
        """add_highlight_rule must fire HIGHLIGHT_RULE_ADDED on the state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 0}),
                "#FF0000",
            ),
        )

        assert any(e[0] == HexDocumentEvent.HIGHLIGHT_RULE_ADDED for e in events)

    def test_remove_highlight_rule_fires_event(self, bridge: HexEditorBridge) -> None:
        """remove_highlight_rule must fire HIGHLIGHT_RULE_REMOVED on the state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 255}),
                "#00FF00",
            ),
        )

        events, cb = _make_collector()
        state.register_callback(cb)

        _run(bridge.remove_highlight_rule(rule_id))

        assert any(e[0] == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED for e in events)


class TestDisplayModeEvent:
    """Tests for DISPLAY_MODE_CHANGED event fired by set_display_mode."""

    def test_set_display_mode_fires_event(self, bridge: HexEditorBridge) -> None:
        """set_display_mode must fire DISPLAY_MODE_CHANGED on the state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("hex16_le"))

        assert any(e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED for e in events)

    def test_set_display_mode_event_data_has_mode(self, bridge: HexEditorBridge) -> None:
        """DISPLAY_MODE_CHANGED event data must contain the exact mode string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("binary"))

        mode_events = [e for e in events if e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED]
        assert len(mode_events) == 1
        assert mode_events[0][1]["mode"] == "binary"


class TestPatternExecutedEvent:
    """Tests for PATTERN_EXECUTED event fired by execute_pattern via state holder."""

    def test_execute_pattern_fires_pattern_executed(self, loaded_bridge: HexEditorBridge) -> None:
        """execute_pattern must fire PATTERN_EXECUTED when interpreter is available.

        Args:
            loaded_bridge: A bridge with the PE file already opened.

        Raises:
            RuntimeError: If the interpreter reports an unexpected error.
        """
        if not _hexpat_available:
            pytest.skip("hexpat interpreter not available")

        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        loaded_bridge.set_state_holder(state)

        try:
            _run(loaded_bridge.execute_pattern("u8 sig_byte @ 0x00;"))
        except RuntimeError as exc:
            if "not available" in str(exc):
                pytest.skip("hexpat interpreter not available at runtime")
            raise

        assert any(e[0] == HexDocumentEvent.PATTERN_EXECUTED for e in events)


class TestCallbackSourceFiltering:
    """Tests for source-id loop-guard filtering through real bridge operations."""

    def test_bridge_source_callback_not_called_for_bridge_events(self, bridge: HexEditorBridge) -> None:
        """A callback registered with source_id='bridge' receives no bridge-sourced events.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events_filtered: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def filtered_cb(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
            events_filtered.append((evt, data))

        state.register_callback(filtered_cb, source_id="bridge")
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("hex8"))

        assert not events_filtered

    def test_non_bridge_source_callback_receives_bridge_events(self, bridge: HexEditorBridge) -> None:
        """A callback registered with source_id='gui' receives bridge-sourced events.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events_received: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def gui_cb(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
            events_received.append((evt, data))

        state.register_callback(gui_cb, source_id="gui")
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("hex32_le"))

        assert any(e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED for e in events_received)


class TestMultipleCallbacks:
    """Tests for multi-callback delivery through bridge state holder."""

    def test_multiple_callbacks_all_receive_event(self, bridge: HexEditorBridge) -> None:
        """All registered callbacks must receive the same bridge-fired event.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events_a, cb_a = _make_collector()
        events_b, cb_b = _make_collector()
        events_c, cb_c = _make_collector()

        state.register_callback(cb_a)
        state.register_callback(cb_b)
        state.register_callback(cb_c)
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("dec_u8"))

        assert any(e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED for e in events_a)
        assert any(e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED for e in events_b)
        assert any(e[0] == HexDocumentEvent.DISPLAY_MODE_CHANGED for e in events_c)

    def test_unregistered_callback_no_longer_receives_events(self, bridge: HexEditorBridge) -> None:
        """After unregister_callback, the callback must not receive further events.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.set_display_mode("hex8"))
        assert len(events) >= 1

        state.unregister_callback(cb)
        count_before = len(events)

        _run(bridge.set_display_mode("hex16_le"))
        assert len(events) == count_before


class TestStateCursorUpdate:
    """Tests for cursor_offset updates via state.set_cursor and goto_offset."""

    def test_state_cursor_offset_updates_via_set_cursor(self) -> None:
        """state.set_cursor must update the cursor_offset property.

        No bridge is required; this tests state in isolation.
        """
        state = HexDocumentState()
        state.set_cursor(512)
        assert state.cursor_offset == 512

    def test_goto_offset_fires_cursor_moved_on_state(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """goto_offset must update the state holder cursor_offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        _run(bridge.open_file(str(pe_binary)))

        events, cb = _make_collector()
        state.register_callback(cb)

        _run(bridge.goto_offset(64))

        assert state.cursor_offset == 64
        assert any(e[0] == HexDocumentEvent.CURSOR_MOVED for e in events)


class TestBridgeStateFactory:
    """Tests for constructing a fresh HexEditorBridge with a state holder."""

    def test_fresh_bridge_with_state_holder_open_fires_event(self, pe_binary: Path) -> None:
        """A bridge constructed from scratch with a state holder fires DOCUMENT_OPENED.

        Args:
            pe_binary: Path to the PE binary fixture.
        """
        fresh = HexEditorBridge()
        _run(fresh.initialize())

        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        fresh.set_state_holder(state)

        _run(fresh.open_file(str(pe_binary)))

        assert any(e[0] == HexDocumentEvent.DOCUMENT_OPENED for e in events)

        _run(fresh.shutdown())
