# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ToolCallBufferManager streaming helper."""

from __future__ import annotations

from intellicrack.providers.base import ToolCallBufferManager


_EXPECTED_CONCURRENT_COUNT = 2


def test_empty_finalize() -> None:
    """Finalize with no accumulated data returns empty list."""
    mgr = ToolCallBufferManager()
    assert mgr.finalize() == []


def test_single_complete_call() -> None:
    """A single complete tool call is produced correctly."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="call_abc", name="get_weather", arguments='{"city": "NYC"}')
    result = mgr.finalize()
    assert len(result) == 1
    tc = result[0]
    assert tc.id == "call_abc"
    assert tc.function_name == "get_weather"
    assert tc.tool_name == "get_weather"
    assert tc.arguments == {"city": "NYC"}


def test_multi_delta_argument_concatenation() -> None:
    """Arguments arriving in multiple chunks are concatenated."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="call_1", name="search")
    mgr.accumulate(index=0, arguments='{"q": ')
    mgr.accumulate(index=0, arguments='"hello"}')
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].arguments == {"q": "hello"}


def test_multiple_concurrent_indices() -> None:
    """Multiple tool calls at different indices accumulate independently."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_0", name="func_a", arguments='{"a": 1}')
    mgr.accumulate(index=1, call_id="id_1", name="func_b", arguments='{"b": 2}')
    result = mgr.finalize()
    assert len(result) == _EXPECTED_CONCURRENT_COUNT
    ids = {tc.id for tc in result}
    assert ids == {"id_0", "id_1"}
    names = {tc.function_name for tc in result}
    assert names == {"func_a", "func_b"}


def test_incomplete_entries_filtered() -> None:
    """Entries missing id or name are discarded on finalize."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_0", arguments="{}")
    mgr.accumulate(index=1, name="func_b", arguments="{}")
    mgr.accumulate(index=2, call_id="id_2", name="func_c", arguments="{}")
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].id == "id_2"


def test_finalize_clears_state() -> None:
    """Finalize resets internal buffers so subsequent calls start fresh."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_x", name="fn", arguments="{}")
    first = mgr.finalize()
    assert len(first) == 1
    second = mgr.finalize()
    assert second == []


def test_invalid_json_arguments() -> None:
    """Malformed JSON arguments produce an empty dict."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_bad", name="fn", arguments="not-json")
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].arguments == {}


def test_dotted_function_name() -> None:
    """Dotted function names split correctly into tool_name."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_dot", name="namespace.tool_fn", arguments="{}")
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].tool_name == "namespace"
    assert result[0].function_name == "namespace.tool_fn"


def test_none_values_ignored() -> None:
    """None values for optional fields are silently skipped."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_n", name="fn")
    mgr.accumulate(index=0, call_id=None, name=None, arguments=None)
    mgr.accumulate(index=0, arguments='{"ok": true}')
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].id == "id_n"
    assert result[0].arguments == {"ok": True}


def test_empty_string_arguments() -> None:
    """Empty string arguments produce an empty dict."""
    mgr = ToolCallBufferManager()
    mgr.accumulate(index=0, call_id="id_e", name="fn", arguments="")
    result = mgr.finalize()
    assert len(result) == 1
    assert result[0].arguments == {}
