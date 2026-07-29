# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for provider tool-count-cap enforcement (S16-D15).

Intellicrack's tool registry flattens seven bridge :class:`ToolDefinition`
containers into ~595 individual function schemas when a chat request is sent
with tools enabled. Providers that cap the number of functions accepted in a
single function-calling request -- Grok (250) and OpenAI-compatible backends
routed through OpenRouter (128) -- reject that payload outright, making
tool-enabled chat impossible on those providers regardless of credentials.

These tests build the real, unmodified tool payload from the real concrete
bridges (the same 7-bridge/~595-function surface a live chat request would
send) and drive it through each provider's actual public
``convert_tools_to_provider_format`` entry point -- the exact call
``chat()`` and ``chat_stream()`` make before constructing the wire request.
No mocking of the conversion path is used anywhere, and no private/protected
members are accessed.
"""

from __future__ import annotations

from typing import cast

import pytest

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ProviderError, ToolDefinition
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openrouter import OpenRouterProvider


def _real_bridge_tool_definitions() -> list[ToolDefinition]:
    """Instantiate every concrete bridge and collect its real tool definition.

    Mirrors exactly what ``ToolRegistry.get_tool_definitions`` hands to
    ``LLMProviderBase.chat``/``chat_stream`` in production: one
    ``ToolDefinition`` container per bridge, each bundling many callable
    functions.

    Returns:
        list[ToolDefinition]: One real ToolDefinition per concrete bridge.
    """
    return [
        CutterBridge().tool_definition,
        FridaBridge().tool_definition,
        GhidraBridge().tool_definition,
        HexEditorBridge().tool_definition,
        ProcessBridge().tool_definition,
        SandboxBridge().tool_definition,
        X64DbgBridge().tool_definition,
    ]


def _wire_function_names(wire_tools: list[dict[str, object]]) -> list[str]:
    """Extract the OpenAI-format function names from a converted wire payload.

    Args:
        wire_tools: The ``[{"type": "function", "function": {...}}, ...]``
            payload returned by ``convert_tools_to_provider_format``.

    Returns:
        list[str]: The ``function.name`` of each entry, in order.
    """
    names: list[str] = []
    for entry in wire_tools:
        function_obj = entry["function"]
        assert isinstance(function_obj, dict)
        function_dict = cast("dict[str, object]", function_obj)
        names.append(str(function_dict["name"]))
    return names


_REAL_TOOL_DEFINITIONS: list[ToolDefinition] = _real_bridge_tool_definitions()
_REAL_FLATTENED_FUNCTION_COUNT: int = sum(len(definition.functions) for definition in _REAL_TOOL_DEFINITIONS)


def test_real_bridge_surface_exceeds_both_provider_caps() -> None:
    """Guard against the suite becoming vacuous if the bridge surface shrinks.

    The whole point of this test module is that the real, unmodified tool
    surface is larger than what Grok and OpenRouter accept. If a future
    change shrinks the bridge surface below either cap, the trimming
    assertions below would no longer be exercised and would pass trivially
    -- this test makes that condition loud and explicit instead of silent.
    """
    assert _REAL_FLATTENED_FUNCTION_COUNT > GrokProvider.TOOL_COUNT_CAP, (
        f"real flattened tool surface ({_REAL_FLATTENED_FUNCTION_COUNT}) no longer exceeds "
        f"the Grok cap ({GrokProvider.TOOL_COUNT_CAP}); the trimming tests below would be vacuous"
    )
    assert _REAL_FLATTENED_FUNCTION_COUNT > OpenRouterProvider.TOOL_COUNT_CAP, (
        f"real flattened tool surface ({_REAL_FLATTENED_FUNCTION_COUNT}) no longer exceeds "
        f"the OpenRouter cap ({OpenRouterProvider.TOOL_COUNT_CAP}); the trimming tests below would be vacuous"
    )


def test_grok_conversion_path_trims_real_tool_surface_to_cap() -> None:
    """The real Grok conversion path must never emit more functions than the cap.

    Drives the full, real 595-function bridge surface through
    ``GrokProvider.convert_tools_to_provider_format`` -- the exact call
    ``GrokProvider.chat``/``chat_stream`` make before sending the request --
    and asserts the outgoing OpenAI-format function count never exceeds
    Grok's documented 250-tool limit. Without cap enforcement this sends
    595 functions and X.AI rejects the request with
    ``400 "Maximum tools limit reached. 595 tools ... maximum is 250."``.
    """
    provider = GrokProvider()

    wire_tools = provider.convert_tools_to_provider_format(_REAL_TOOL_DEFINITIONS)

    assert len(wire_tools) <= GrokProvider.TOOL_COUNT_CAP
    assert len(wire_tools) > 0


def test_openrouter_conversion_path_trims_real_tool_surface_to_cap() -> None:
    """The real OpenRouter conversion path must never emit more functions than the cap.

    Drives the full, real 595-function bridge surface through
    ``OpenRouterProvider.convert_tools_to_provider_format`` and asserts the
    outgoing OpenAI-format function count never exceeds the 128-function
    cap shared by the OpenAI-compatible backends OpenRouter routes to
    (e.g. ``gpt-4o-mini``).
    """
    provider = OpenRouterProvider()

    wire_tools = provider.convert_tools_to_provider_format(_REAL_TOOL_DEFINITIONS)

    assert len(wire_tools) <= OpenRouterProvider.TOOL_COUNT_CAP
    assert len(wire_tools) > 0


def test_grok_wire_payload_keeps_leading_functions_in_order() -> None:
    """Trimming must follow deterministic priority, not drop tools arbitrarily.

    Verifies the truncation policy from the outside: the wire payload's
    function names must equal an exact, in-order prefix of the full
    (untrimmed) flattened function list -- proving the cap is enforced by
    keeping the leading functions and dropping the trailing ones
    deterministically, never by skipping or reordering entries.
    """
    provider = GrokProvider()

    wire_tools = provider.convert_tools_to_provider_format(_REAL_TOOL_DEFINITIONS)
    wire_names = _wire_function_names(wire_tools)

    all_function_names = [function.name for definition in _REAL_TOOL_DEFINITIONS for function in definition.functions]
    expected_prefix = all_function_names[: len(wire_names)]

    assert wire_names == expected_prefix
    assert len(wire_names) == GrokProvider.TOOL_COUNT_CAP


def test_wire_payload_within_cap_includes_every_function() -> None:
    """A tool set already within the cap must pass through with nothing dropped.

    Enforcement must be a no-op below the cap: a single bridge's function
    count is far smaller than either provider cap, so every one of its
    functions must appear in the outgoing wire payload, in order.
    """
    single_bridge = [CutterBridge().tool_definition]
    function_count = len(single_bridge[0].functions)
    assert function_count < GrokProvider.TOOL_COUNT_CAP

    provider = GrokProvider()
    wire_tools = provider.convert_tools_to_provider_format(single_bridge)

    expected_names = [function.name for function in single_bridge[0].functions]
    assert _wire_function_names(wire_tools) == expected_names


def test_grok_cap_below_one_raises_named_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unsatisfiable cap must fail early with a message naming the cap and count.

    When even a single tool function cannot fit under the configured cap,
    enforcement must not silently emit an empty tool list (which would make
    tool-enabled chat appear to work while sending no tools); it must raise
    ``ProviderError`` naming both the offending cap and the real function
    count that triggered it.

    Args:
        monkeypatch: Pytest fixture used to force ``GrokProvider.TOOL_COUNT_CAP``
            to an unsatisfiable value for this test only.
    """
    monkeypatch.setattr(GrokProvider, "TOOL_COUNT_CAP", 0)
    provider = GrokProvider()

    with pytest.raises(ProviderError) as exc_info:
        provider.convert_tools_to_provider_format(_REAL_TOOL_DEFINITIONS)

    message = str(exc_info.value)
    assert "0" in message
    assert str(_REAL_FLATTENED_FUNCTION_COUNT) in message
