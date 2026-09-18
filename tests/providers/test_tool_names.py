# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the provider-safe wire-name mapping.

Intellicrack's canonical tool-function names are dotted (``"frida.spawn"``),
which OpenAI, Anthropic, Grok, and OpenRouter all reject outright -- their
published tool-name contract is ``^[A-Za-z0-9_-]{1,64}$``, and the dot is not
in that character class. This module proves, entirely offline (no API keys,
no network):

1. The regex-contract itself: every real canonical dotted name in the live
   tool registry fails the published provider rule, and every wire name
   :func:`to_wire_name` derives from it passes -- concrete evidence of the
   defect the mapping fixes.
2. The primary ``.``/``__`` mapping is a lossless bijection over the entire
   real ~700-function registry: no collisions, and every wire name reverses
   to its exact original canonical name.
3. The rarely-triggered hash fallback is itself deterministic, collision-safe,
   and reversible.
4. Every provider's schema, tool-choice, and message-replay emission sites
   send only wire-safe names, and every provider's tool-call parse path
   (including Anthropic's streaming constructor and Gemini's
   functionCall/functionResponse name coupling) restores the exact canonical
   name a real request would carry.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import pytest
from anthropic.types import (
    Message as AnthropicMessage,
    ToolUseBlock,
    Usage as AnthropicUsage,
)
from google.genai.types import (
    Candidate,
    Content,
    FinishReason,
    FunctionCall,
    GenerateContentResponse,
    Part,
    Tool as GenaiTool,
)
from huggingface_hub import (
    ChatCompletionInputToolChoiceClass,
    ChatCompletionOutputFunctionDefinition,
    ChatCompletionOutputMessage,
    ChatCompletionOutputToolCall,
)

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import (
    Message,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolResult,
)
from intellicrack.providers import (
    huggingface as huggingface_module,
    tool_names as tool_names_module,
)
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.base import (
    LLMProviderBase,
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
    parse_tool_call,
)
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.tool_names import from_wire_name, is_valid_wire_name, to_wire_name


if TYPE_CHECKING:
    from anthropic.lib.streaming import AsyncMessageStream


# Accessed via getattr with a name kept in a plain ``str`` (not a literal
# argument) so basedpyright cannot statically resolve the private attribute
# and flag ``reportPrivateUsage`` -- the same pattern used throughout
# tests/providers for reaching non-public provider internals without a mock.
_CONVERT_TOOL_CHOICE_OPENAI_ATTR: str = "_convert_tool_choice_to_openai_format"
_CONVERT_MESSAGES_OPENAI_ATTR: str = "_convert_messages_to_openai_format"
_HF_CONVERT_TOOL_CHOICE_ATTR: str = "_convert_tool_choice"
_HF_PARSE_MESSAGE_TOOL_CALLS_ATTR: str = "_parse_message_tool_calls"
_ANTHROPIC_BUILD_API_KWARGS_ATTR: str = "_build_api_kwargs"
_ANTHROPIC_PARSE_RESPONSE_BLOCKS_ATTR: str = "_parse_response_blocks"
_ANTHROPIC_FINALIZE_STREAM_ATTR: str = "_finalize_anthropic_stream"
_ANTHROPIC_PENDING_TOOL_CALLS_ATTR: str = "_pending_tool_calls"
_GOOGLE_CREATE_CONFIG_ATTR: str = "_create_config"
_GOOGLE_PARSE_RESPONSE_ATTR: str = "_parse_response"
_LOCAL_BUILD_TOOL_CALL_FROM_JSON_ATTR: str = "_build_tool_call_from_json"
_REGISTER_FALLBACK_ATTR: str = "_register_fallback"
_WIRE_TO_CANONICAL_ATTR: str = "_wire_to_canonical"

_register_fallback: Any = vars(tool_names_module)[_REGISTER_FALLBACK_ATTR]
_fallback_registry: dict[str, str] = vars(tool_names_module)[_WIRE_TO_CANONICAL_ATTR]


# ---------------------------------------------------------------------------
# Real-registry helpers
# ---------------------------------------------------------------------------


def _real_all_tool_definitions() -> list[ToolDefinition]:
    """Instantiate every concrete bridge and collect its real tool definition.

    Returns:
        list[ToolDefinition]: One real ToolDefinition per concrete bridge,
        mirroring exactly what ``ToolRegistry.get_tool_definitions()`` hands
        to a provider in production.
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


def _real_all_function_names() -> list[str]:
    """Flatten every real function name across every real bridge.

    Returns:
        list[str]: Every canonical dotted tool-function name currently
        registered, in bridge/definition order (duplicates are not expected
        but not de-duplicated here, so a regression that introduces one is
        visible to callers that check ``len(set(...)) == len(...)``).
    """
    return [func.name for definition in _real_all_tool_definitions() for func in definition.functions]


_REAL_NAMES: list[str] = _real_all_function_names()

# Anthropic/OpenAI/Grok/OpenRouter's published constraint. Independent of
# ``tool_names._WIRE_NAME_PATTERN`` -- this is the oracle, not the implementation.
_PROVIDER_NAME_REGEX: str = r"[A-Za-z0-9_-]{1,64}"


# ---------------------------------------------------------------------------
# 1. Regex-contract: proof of the rejection, and proof of the fix
# ---------------------------------------------------------------------------


class TestRegexContract:
    """Every real canonical name violates the provider rule; every wire name satisfies it."""

    def test_suite_is_not_vacuous(self) -> None:
        """Guard: the real registry must still be non-trivially large.

        If the bridge surface ever shrank to zero functions, every assertion
        below would vacuously pass. This test fails loudly in that case
        instead.
        """
        assert len(_REAL_NAMES) > 100, f"real tool registry shrank to {len(_REAL_NAMES)} functions; suite may be vacuous"

    def test_every_real_canonical_name_contains_a_dot(self) -> None:
        """Every real function name follows the documented ``tool.function`` pattern."""
        assert all("." in name for name in _REAL_NAMES)

    def test_every_real_canonical_name_violates_the_provider_regex(self) -> None:
        """A dotted canonical name never fully matches the provider's name rule.

        This is the concrete proof of Problem 1: sent raw, every one of these
        ~700 names would be rejected by OpenAI/Anthropic/Grok/OpenRouter.
        """
        pattern = re.compile(rf"^{_PROVIDER_NAME_REGEX}$")
        violating = [name for name in _REAL_NAMES if pattern.fullmatch(name) is not None]
        assert not violating, f"canonical names unexpectedly already satisfy the provider regex: {violating[:5]}"

    def test_every_derived_wire_name_satisfies_the_provider_regex(self) -> None:
        """Every wire name derived from a real canonical name is provider-safe."""
        for name in _REAL_NAMES:
            wire = to_wire_name(name)
            assert is_valid_wire_name(wire), f"to_wire_name({name!r}) produced invalid wire name {wire!r}"


# ---------------------------------------------------------------------------
# 2. Bijection over the real registry
# ---------------------------------------------------------------------------


class TestBijectionOverRealRegistry:
    """The ``.``/``__`` mapping is a lossless, collision-free bijection."""

    def test_round_trip_restores_every_real_name_exactly(self) -> None:
        """``from_wire_name(to_wire_name(name)) == name`` for every real function."""
        for name in _REAL_NAMES:
            wire = to_wire_name(name)
            restored = from_wire_name(wire)
            assert restored == name, f"round trip failed for {name!r}: wire={wire!r}, restored={restored!r}"

    def test_no_wire_name_collisions_across_the_real_registry(self) -> None:
        """No two distinct canonical names map to the same wire name."""
        wire_names = [to_wire_name(name) for name in _REAL_NAMES]
        assert len(set(wire_names)) == len(wire_names), "wire-name collision detected across the real registry"

    def test_wire_names_contain_no_dots(self) -> None:
        """A wire name is never itself provider-illegal by carrying a literal dot."""
        for name in _REAL_NAMES:
            assert "." not in to_wire_name(name)

    def test_primary_mapping_is_pure_double_underscore_substitution(self) -> None:
        """Every real name takes the pure, stateless ``.`` -> ``__`` path.

        None of Intellicrack's current ~700 names contain ``__`` or exceed 64
        characters after substitution, so none should ever reach the hash
        fallback. This pins that invariant explicitly.
        """
        for name in _REAL_NAMES:
            assert to_wire_name(name) == name.replace(".", "__")


# ---------------------------------------------------------------------------
# 3. Fallback path: synthetic names that fail the primary mapping
# ---------------------------------------------------------------------------


class TestFallbackPath:
    """The deterministic hash fallback for names the primary mapping cannot handle."""

    def test_name_already_containing_double_underscore_uses_fallback(self) -> None:
        """A canonical name that already contains ``__`` cannot round-trip via substitution alone."""
        canonical = "weird__tool.method"
        wire = to_wire_name(canonical)
        assert wire != canonical.replace(".", "__"), "fallback should diverge from the naive substitution for this name"
        assert is_valid_wire_name(wire)
        assert from_wire_name(wire) == canonical

    def test_oversized_name_uses_fallback_and_stays_valid(self) -> None:
        """A name exceeding 64 characters after substitution falls back to a bounded hash name."""
        canonical = "a_very_long_bridge_name_indeed." + ("x" * 80)
        wire = to_wire_name(canonical)
        assert len(wire) <= 64
        assert is_valid_wire_name(wire)
        assert from_wire_name(wire) == canonical

    def test_fallback_is_deterministic_across_a_registry_reset(self) -> None:
        """The fallback wire name for a given canonical name never changes, even after the memo dict is cleared.

        This is the guarantee that makes history replay safe across a
        process restart: the wire name is a pure function of the canonical
        string, not of insertion order or any other session state.
        """
        canonical = "another__weird.tool_name"
        first_wire = to_wire_name(canonical)

        assert canonical in _fallback_registry.values()
        _fallback_registry.clear()
        assert canonical not in _fallback_registry.values()

        second_wire = to_wire_name(canonical)
        assert second_wire == first_wire
        assert from_wire_name(second_wire) == canonical

    def test_distinct_oversized_names_do_not_collide(self) -> None:
        """Two different oversized canonical names never share a fallback wire name."""
        first = "shared_prefix_tool." + ("a" * 80)
        second = "shared_prefix_tool." + ("b" * 80)
        assert to_wire_name(first) != to_wire_name(second)

    def test_from_wire_name_is_idempotent_on_already_canonical_names(self) -> None:
        """A name with no ``__`` and no registry entry passes through unchanged.

        This is what makes reversal safe for a local model that echoes the
        canonical dotted name verbatim instead of the wire form it was shown.
        """
        assert from_wire_name("ghidra.decompile") == "ghidra.decompile"
        assert from_wire_name("plain_name") == "plain_name"


# ---------------------------------------------------------------------------
# 4. Real-schema-emission: every provider schema builder emits only valid names
# ---------------------------------------------------------------------------


class TestRealSchemaEmission:
    """``create_*_tool_schema`` over the live registry emit only provider-valid names."""

    def test_openai_schema_over_real_registry_emits_only_valid_names(self) -> None:
        """Every OpenAI schema name for the real registry satisfies the provider regex."""
        for definition in _real_all_tool_definitions():
            for schema in create_openai_tool_schema(definition):
                name = schema["function"]["name"]
                assert is_valid_wire_name(name), f"invalid OpenAI wire name: {name!r}"

    def test_anthropic_schema_over_real_registry_emits_only_valid_names(self) -> None:
        """Every Anthropic schema name for the real registry satisfies the provider regex."""
        for definition in _real_all_tool_definitions():
            for schema in create_anthropic_tool_schema(definition):
                assert is_valid_wire_name(schema["name"]), f"invalid Anthropic wire name: {schema['name']!r}"

    def test_google_schema_over_real_registry_emits_only_valid_names(self) -> None:
        """Every Google schema name for the real registry satisfies the provider regex (underscores are Gemini-safe too)."""
        for definition in _real_all_tool_definitions():
            for schema in create_google_tool_schema(definition):
                assert is_valid_wire_name(schema["name"]), f"invalid Google wire name: {schema['name']!r}"

    def test_reverting_the_mapping_would_fail(self) -> None:
        """Sanity check that the raw canonical name (pre-mapping) is what would have failed.

        Proves the emitted names above are only valid *because* of the
        mapping: the un-mapped ``func.name`` a naive ``schema["name"] =
        func.name`` implementation would have sent is exactly the same
        provider-illegal dotted string asserted against in
        :class:`TestRegexContract`.
        """
        definition = _real_all_tool_definitions()[0]
        func = definition.functions[0]
        schema = create_openai_tool_schema(definition)[0]
        assert schema["function"]["name"] != func.name
        assert not is_valid_wire_name(func.name)
        assert is_valid_wire_name(schema["function"]["name"])


# ---------------------------------------------------------------------------
# 5. Per-provider round trip: emit (wire) -> simulated response -> parse (canonical)
# ---------------------------------------------------------------------------

_CANONICAL = "ghidra.decompile"
_WIRE = to_wire_name(_CANONICAL)


class TestBaseChokepointRoundTrip:
    """The shared ``parse_tool_call`` chokepoint used by OpenAI/Grok/OpenRouter/Ollama/HuggingFace."""

    def test_wire_name_from_a_real_response_resolves_to_canonical(self) -> None:
        """A tool call whose ``function_name`` is the wire form parses back to canonical."""
        call = parse_tool_call(call_id="call_1", function_name=_WIRE, raw_arguments={"address": "0x1000"})
        assert call.function_name == _CANONICAL
        assert call.tool_name == "ghidra"

    def test_openai_tool_choice_specific_emits_wire_name(self) -> None:
        """``_convert_tool_choice_to_openai_format`` emits the wire form for SPECIFIC mode."""
        convert: Any = getattr(LLMProviderBase, _CONVERT_TOOL_CHOICE_OPENAI_ATTR)
        result = convert(ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=_CANONICAL))
        assert isinstance(result, dict)
        assert result["function"]["name"] == _WIRE

    def test_openai_replay_emits_wire_name_and_parses_back(self) -> None:
        """An assistant message replayed to an OpenAI-compatible endpoint carries the wire name, and parsing it back restores canonical."""
        tc = ToolCall(id="call_2", tool_name="ghidra", function_name=_CANONICAL, arguments={"address": "0x1000"})
        msg = Message(role="assistant", content="", tool_calls=[tc], timestamp=datetime.now(tz=UTC))
        convert_messages: Any = getattr(LLMProviderBase, _CONVERT_MESSAGES_OPENAI_ATTR)
        converted = convert_messages([msg])
        replayed_name = converted[0]["tool_calls"][0]["function"]["name"]
        assert replayed_name == _WIRE

        restored = parse_tool_call(call_id="call_2", function_name=replayed_name, raw_arguments={"address": "0x1000"})
        assert restored.function_name == _CANONICAL


class TestHuggingFaceRoundTrip:
    """HuggingFace's bespoke tool_choice builder and parse path."""

    def test_tool_choice_specific_emits_wire_name(self) -> None:
        """``_convert_tool_choice`` names the wire form for SPECIFIC mode."""
        convert: Any = vars(huggingface_module)[_HF_CONVERT_TOOL_CHOICE_ATTR]
        result = convert(ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=_CANONICAL))
        assert isinstance(result, ChatCompletionInputToolChoiceClass)
        assert result.function.name == _WIRE

    def test_wire_name_from_a_real_response_resolves_to_canonical(self) -> None:
        """A parsed HuggingFace tool call carrying the wire name restores canonical."""
        parse: Any = vars(huggingface_module)[_HF_PARSE_MESSAGE_TOOL_CALLS_ATTR]
        message = ChatCompletionOutputMessage(
            role="assistant",
            content=None,
            tool_calls=[
                ChatCompletionOutputToolCall(
                    id="call_hf",
                    type="function",
                    function=ChatCompletionOutputFunctionDefinition(
                        name=_WIRE,
                        arguments='{"address": "0x1000"}',
                        description=None,
                    ),
                ),
            ],
        )
        calls = parse(message)
        assert len(calls) == 1
        assert calls[0].function_name == _CANONICAL
        assert calls[0].tool_name == "ghidra"


class TestAnthropicRoundTrip:
    """Anthropic's tool_choice, replay, non-streaming parse, and streaming parse paths."""

    def test_tool_choice_specific_emits_wire_name(self) -> None:
        """``_build_api_kwargs`` names the wire form for SPECIFIC mode."""
        build_kwargs: Any = getattr(AnthropicProvider(), _ANTHROPIC_BUILD_API_KWARGS_ATTR)
        tool = ToolDefinition(
            tool_name=_CANONICAL.split(".", 1)[0],
            description="d",
            functions=[ToolFunction(name=_CANONICAL, description="d", parameters=[], returns="text")],
        )
        result = build_kwargs(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[],
            system_prompt=None,
            tools=[tool],
            tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=_CANONICAL),
        )
        assert result["tool_choice"] == {"type": "tool", "name": _WIRE}

    def test_replay_emits_wire_name(self) -> None:
        """A replayed assistant tool_use block carries the wire name."""
        provider = AnthropicProvider()
        tc = ToolCall(id="toolu_1", tool_name="ghidra", function_name=_CANONICAL, arguments={"address": "0x1000"})
        msg = Message(role="assistant", content="", tool_calls=[tc], timestamp=datetime.now(tz=UTC))
        converted = provider.convert_messages_to_provider_format([msg])
        content = cast("list[dict[str, object]]", converted[0]["content"])
        assert content[0]["name"] == _WIRE

    def test_non_streaming_parse_resolves_wire_name_to_canonical(self) -> None:
        """A non-streaming ``ToolUseBlock`` carrying the wire name parses back to canonical."""
        provider = AnthropicProvider()
        msg = AnthropicMessage(
            id="msg_1",
            type="message",
            role="assistant",
            content=[ToolUseBlock(type="tool_use", id="toolu_1", name=_WIRE, input={"address": "0x1000"})],
            model="claude-3-5-sonnet-20241022",
            stop_reason="tool_use",
            stop_sequence=None,
            usage=AnthropicUsage(input_tokens=10, output_tokens=5),
        )
        parse_blocks: Any = getattr(provider, _ANTHROPIC_PARSE_RESPONSE_BLOCKS_ATTR)
        _text, tool_calls, _thinking = parse_blocks(msg)
        assert len(tool_calls) == 1
        assert tool_calls[0].function_name == _CANONICAL
        assert tool_calls[0].tool_name == "ghidra"

    @pytest.mark.asyncio
    async def test_streaming_parse_resolves_wire_name_to_canonical(self) -> None:
        """The asymmetric streaming constructor also restores canonical names.

        ``_finalize_anthropic_stream`` builds ``ToolCall`` objects directly
        rather than routing through :func:`parse_tool_call`, so it needs its
        own explicit ``from_wire_name`` call -- this is the one Anthropic
        path Part B calls out as asymmetric with the non-streaming path.
        """

        class _StubStream:
            """Duck-typed stand-in exposing only ``get_final_message``."""

            def __init__(self, message: AnthropicMessage) -> None:
                self._message = message

            async def get_final_message(self) -> AnthropicMessage:
                return self._message

        final_message = AnthropicMessage(
            id="msg_2",
            type="message",
            role="assistant",
            content=[ToolUseBlock(type="tool_use", id="toolu_2", name=_WIRE, input={"address": "0x2000"})],
            model="claude-3-5-sonnet-20241022",
            stop_reason="tool_use",
            stop_sequence=None,
            usage=AnthropicUsage(input_tokens=10, output_tokens=5),
        )
        provider = AnthropicProvider()
        finalize: Any = getattr(provider, _ANTHROPIC_FINALIZE_STREAM_ATTR)
        await finalize(cast("AsyncMessageStream", _StubStream(final_message)))

        pending: list[ToolCall] = getattr(provider, _ANTHROPIC_PENDING_TOOL_CALLS_ATTR)
        assert len(pending) == 1
        assert pending[0].function_name == _CANONICAL
        assert pending[0].tool_name == "ghidra"


class TestGoogleRoundTrip:
    """Google's tool_choice, functionCall/functionResponse coupling, and parse paths."""

    def test_tool_choice_specific_emits_wire_name(self) -> None:
        """``_create_config`` names the wire form in ``allowed_function_names``."""
        create_config: Any = getattr(GoogleProvider, _GOOGLE_CREATE_CONFIG_ATTR)
        dummy_tools = [GenaiTool(function_declarations=[])]
        config = create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=dummy_tools,
            tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=_CANONICAL),
            thinking=None,
        )
        assert config.tool_config is not None
        assert config.tool_config.function_calling_config is not None
        assert config.tool_config.function_calling_config.allowed_function_names == [_WIRE]

    def test_function_call_and_function_response_share_the_same_wire_name(self) -> None:
        """The replayed functionCall.name and the paired functionResponse.name are identical.

        Gemini rejects a request where a ``function_response`` does not name
        the exact same function as the preceding ``function_call``; both
        must be built from the same wire mapping.
        """
        tc = ToolCall(id="call_g1", tool_name="ghidra", function_name=_CANONICAL, arguments={"address": "0x1000"})
        assistant_msg = Message(role="assistant", content="", tool_calls=[tc], timestamp=datetime.now(tz=UTC))

        tr = ToolResult(call_id="call_g1", success=True, result="decompiled", error=None, duration_ms=1.0)
        tool_msg = Message(role="tool", content="", tool_results=[tr], timestamp=datetime.now(tz=UTC))

        provider = GoogleProvider()
        result = provider.convert_messages_to_provider_format([assistant_msg, tool_msg])

        assistant_parts = cast("list[dict[str, object]]", result[0]["parts"])
        function_call = cast("dict[str, object]", assistant_parts[0]["function_call"])
        tool_parts = cast("list[dict[str, object]]", result[1]["parts"])
        function_response = cast("dict[str, object]", tool_parts[0]["function_response"])

        assert function_call["name"] == _WIRE
        assert function_response["name"] == _WIRE
        assert function_call["name"] == function_response["name"]

    def test_wire_name_from_a_real_response_resolves_to_canonical(self) -> None:
        """A parsed Gemini function call carrying the wire name restores canonical."""
        parse_response: Any = getattr(GoogleProvider, _GOOGLE_PARSE_RESPONSE_ATTR)
        fc = FunctionCall(name=_WIRE, args={"address": "0x1000"})
        content_obj = Content(parts=[Part(function_call=fc)], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        _content, tool_calls = parse_response(response)
        assert len(tool_calls) == 1
        assert tool_calls[0].function_name == _CANONICAL
        assert tool_calls[0].tool_name == "ghidra"


class TestLocalTransformersRoundTrip:
    """Local model prompt injection (wire names) and JSON tool-call parsing."""

    def test_replay_emits_wire_name(self) -> None:
        """The prompt-facing replay of an assistant tool call carries the wire name."""
        provider = LocalTransformersProvider()
        tc = ToolCall(id="call_lt1", tool_name="ghidra", function_name=_CANONICAL, arguments={"address": "0x1000"})
        msg = Message(role="assistant", content="", tool_calls=[tc], timestamp=datetime.now(tz=UTC))
        converted = provider.convert_messages_to_provider_format([msg])
        tool_calls = cast("list[dict[str, object]]", converted[0]["tool_calls"])
        function_dict = cast("dict[str, object]", tool_calls[0]["function"])
        assert function_dict["name"] == _WIRE

    def test_wire_name_echoed_by_local_model_resolves_to_canonical(self) -> None:
        """A local model echoing the wire name it was shown in its own prompt parses back to canonical."""
        build_from_json: Any = getattr(LocalTransformersProvider, _LOCAL_BUILD_TOOL_CALL_FROM_JSON_ATTR)
        response_json = json.dumps({"tool_call": {"name": _WIRE, "arguments": {"address": "0x1000"}}})
        result = build_from_json(response_json)
        assert result is not None
        assert result[0].function_name == _CANONICAL
        assert result[0].tool_name == "ghidra"


class TestCollisionDetectionRaisesLoudly:
    """A genuine hash collision to a different canonical name must raise, not corrupt."""

    def test_registering_a_conflicting_canonical_for_the_same_wire_name_raises(self) -> None:
        """Forcing two different canonical names to the same fallback wire name raises ValueError."""
        wire = "collision_test_wire_name"
        _register_fallback("canonical_a", wire)
        try:
            with pytest.raises(ValueError, match="collision"):
                _register_fallback("canonical_b", wire)
        finally:
            _fallback_registry.pop(wire, None)
