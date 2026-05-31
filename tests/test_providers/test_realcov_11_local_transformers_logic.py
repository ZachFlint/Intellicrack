# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for ``LocalTransformersProvider`` pure logic.

These tests drive the provider's prompt-formatting, message-building,
tool-call-parsing, device-probe, and device-info helpers with realistic
model-style inputs (the exact ``{"tool_call": ...}`` JSON shape the
provider instructs models to emit, real tool definitions, real
conversation messages). They do not download model weights; instead
they validate the deterministic parsing and formatting logic that runs
on top of any generated text, plus the real CUDA/XPU probe results on
this machine. No operation under test is mocked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from intellicrack.core.types import (
    ToolCall,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.xpu_utils import is_xpu_available


if TYPE_CHECKING:
    from collections.abc import Callable


def _find_tool_call_start(text: str) -> int:
    """Invoke the provider's private tool-call locator with typing intact.

    Args:
        text: Candidate model response text.

    Returns:
        int: Start index of the tool-call object, or -1.
    """
    fn = cast("Callable[[str], int]", vars(LocalTransformersProvider)["_find_tool_call_start"])
    return fn(text)


def _parse_tool_calls(text: str) -> list[ToolCall] | None:
    """Invoke the provider's private tool-call parser with typing intact.

    Args:
        text: Model response text potentially containing a tool call.

    Returns:
        list[ToolCall] | None: Parsed tool calls, or None.
    """
    fn = cast("Callable[[str], list[ToolCall] | None]", vars(LocalTransformersProvider)["_parse_tool_calls"])
    return fn(text)


def _build_tool_call_from_json(json_str: str) -> list[ToolCall] | None:
    """Invoke the provider's private JSON-to-ToolCall builder with typing intact.

    Args:
        json_str: Raw tool-call JSON string.

    Returns:
        list[ToolCall] | None: Parsed tool calls, or None.
    """
    fn = cast("Callable[[str], list[ToolCall] | None]", vars(LocalTransformersProvider)["_build_tool_call_from_json"])
    return fn(json_str)


def _extract_text_before_tool_call(text: str) -> str:
    """Invoke the provider's private preamble extractor with typing intact.

    Args:
        text: Full model response text.

    Returns:
        str: The text preceding the tool call.
    """
    fn = cast("Callable[[str], str]", vars(LocalTransformersProvider)["_extract_text_before_tool_call"])
    return fn(text)


def _format_prompt_chatml_fallback(chat_messages: list[dict[str, str]]) -> str:
    """Invoke the provider's private ChatML fallback formatter.

    Args:
        chat_messages: Normalized chat message list.

    Returns:
        str: ChatML-formatted prompt string.
    """
    fn = cast("Callable[[list[dict[str, str]]], str]", vars(LocalTransformersProvider)["_format_prompt_chatml_fallback"])
    return fn(chat_messages)


def _build_chat_messages(
    provider: LocalTransformersProvider,
    messages: list[dict[str, object]],
    tools: list[ToolDefinition] | None = None,
) -> list[dict[str, str]]:
    """Invoke the provider's private chat-message builder with typing intact.

    Args:
        provider: The provider instance owning the method.
        messages: Provider-format message dictionaries.
        tools: Optional tool definitions to inject.

    Returns:
        list[dict[str, str]]: Normalized chat message dictionaries.
    """
    unbound = cast(
        "Callable[[LocalTransformersProvider, list[dict[str, object]], list[ToolDefinition] | None], list[dict[str, str]]]",
        vars(type(provider))["_build_chat_messages"],
    )
    return unbound(provider, messages, tools)


def _probe_cuda() -> bool:
    """Invoke the provider's private CUDA probe with typing intact.

    Returns:
        bool: True when a CUDA device is available.
    """
    fn = cast("Callable[[], bool]", vars(LocalTransformersProvider)["_probe_cuda"])
    return fn()


def _cuda_device_count() -> int:
    """Invoke the provider's private CUDA device counter with typing intact.

    Returns:
        int: Number of CUDA devices.
    """
    fn = cast("Callable[[], int]", vars(LocalTransformersProvider)["_cuda_device_count"])
    return fn()


def _select_device(provider: LocalTransformersProvider) -> str:
    """Invoke the provider's private device selector with typing intact.

    Args:
        provider: The provider instance owning the method.

    Returns:
        str: The selected backend ("cuda", "xpu", or "cpu").
    """
    unbound = cast("Callable[[LocalTransformersProvider], str]", vars(type(provider))["_select_device"])
    return unbound(provider)


def _set_availability(provider: LocalTransformersProvider, *, cuda: bool, xpu: bool) -> None:
    """Set the provider's private availability flags for selection tests.

    Args:
        provider: The provider instance to configure.
        cuda: Value for the CUDA availability flag.
        xpu: Value for the XPU availability flag.
    """
    instance_state = cast("dict[str, object]", vars(provider))
    instance_state["_cuda_available"] = cuda
    instance_state["_xpu_available"] = xpu


def _xpu_available_flag(provider: LocalTransformersProvider) -> bool:
    """Read the provider's private XPU availability flag.

    Args:
        provider: The provider instance to read from.

    Returns:
        bool: The current XPU availability flag value.
    """
    instance_state = cast("dict[str, object]", vars(provider))
    return bool(instance_state["_xpu_available"])


def _binary_tool() -> ToolDefinition:
    """Build a real tool definition for binary analysis function calling.

    Returns:
        ToolDefinition: A definition exposing ``binary.get_file_size``.
    """
    return ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="Binary analysis tools",
        functions=[
            ToolFunction(
                name="binary.get_file_size",
                description="Get the file size in bytes of the loaded binary.",
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        description="Path to the binary file.",
                        required=True,
                    ),
                ],
                returns="File size in bytes as an integer.",
            ),
        ],
    )


class TestFindToolCallStart:
    """Validate the regex-based tool-call locator over realistic text."""

    @staticmethod
    def test_finds_compact_json() -> None:
        """A compact tool-call object is located at its opening brace."""
        text = 'Sure.{"tool_call": {"name": "binary.get_file_size", "arguments": {}}}'
        assert _find_tool_call_start(text) == text.index("{")

    @staticmethod
    def test_tolerates_whitespace_after_brace_and_around_colon() -> None:
        """Pretty-printed tool-call JSON is still located by the regex."""
        text = 'Reasoning...\n{\n  "tool_call"  :  {"name": "x", "arguments": {}}\n}'
        idx = _find_tool_call_start(text)
        assert idx != -1
        assert text[idx] == "{"

    @staticmethod
    def test_returns_minus_one_when_absent() -> None:
        """Plain prose with no tool call returns the -1 sentinel."""
        assert _find_tool_call_start("just a normal answer") == -1


class TestParseToolCalls:
    """Validate full tool-call parsing including JSON edge cases."""

    @staticmethod
    def test_parses_simple_tool_call() -> None:
        """A simple model-style tool call yields one ToolCall with args."""
        text = 'I will call it.{"tool_call": {"name": "binary.get_file_size", "arguments": {"path": "C:/Windows/System32/kernel32.dll"}}}'
        calls = _parse_tool_calls(text)
        assert calls is not None
        assert len(calls) == 1
        call = calls[0]
        assert call.function_name == "binary.get_file_size"
        assert call.tool_name == "binary"
        assert call.arguments == {"path": "C:/Windows/System32/kernel32.dll"}
        assert call.id.startswith("call_")

    @staticmethod
    def test_parses_nested_arguments() -> None:
        """Nested JSON objects in arguments are preserved exactly."""
        text = '{"tool_call": {"name": "configure", "arguments": {"opts": {"depth": 3, "names": ["a", "b"]}}}}'
        calls = _parse_tool_calls(text)
        assert calls is not None
        assert calls[0].arguments == {"opts": {"depth": 3, "names": ["a", "b"]}}

    @staticmethod
    def test_handles_escaped_quotes_and_braces_in_string() -> None:
        """Escaped quotes and braces inside string values do not break brace matching."""
        text = r'{"tool_call": {"name": "echo", "arguments": {"text": "a \"quoted\" } brace"}}}'
        calls = _parse_tool_calls(text)
        assert calls is not None
        assert calls[0].arguments == {"text": 'a "quoted" } brace'}

    @staticmethod
    def test_no_tool_call_returns_none() -> None:
        """Prose without a tool-call object parses to None."""
        assert _parse_tool_calls("The file is a PE binary.") is None

    @staticmethod
    def test_unbalanced_braces_returns_none() -> None:
        """A truncated object with unbalanced braces yields None."""
        text = '{"tool_call": {"name": "x", "arguments": {"a": 1}'
        assert _parse_tool_calls(text) is None


class TestBuildToolCallFromJson:
    """Validate the JSON-to-ToolCall conversion edge cases."""

    @staticmethod
    def test_missing_name_returns_none() -> None:
        """A tool-call object without a name field yields None."""
        result = _build_tool_call_from_json('{"tool_call": {"arguments": {"a": 1}}}')
        assert result is None

    @staticmethod
    def test_non_dict_arguments_default_to_empty() -> None:
        """A malformed non-dict arguments field defaults to an empty dict."""
        result = _build_tool_call_from_json('{"tool_call": {"name": "f", "arguments": "oops"}}')
        assert result is not None
        assert result[0].arguments == {}

    @staticmethod
    def test_dotted_name_splits_tool_and_function() -> None:
        """A dotted function name splits into tool_name and function_name."""
        result = _build_tool_call_from_json(
            '{"tool_call": {"name": "ghidra.decompile", "arguments": {}}}',
        )
        assert result is not None
        assert result[0].tool_name == "ghidra"
        assert result[0].function_name == "ghidra.decompile"


class TestExtractTextBeforeToolCall:
    """Validate extraction of preamble text preceding a tool call."""

    @staticmethod
    def test_returns_text_before_call_trimmed() -> None:
        """Text before the tool call is returned with whitespace trimmed."""
        text = 'Let me check.  {"tool_call": {"name": "x", "arguments": {}}}'
        assert _extract_text_before_tool_call(text) == "Let me check."

    @staticmethod
    def test_returns_full_text_when_no_call() -> None:
        """With no tool call the full response is returned unchanged."""
        assert _extract_text_before_tool_call("plain answer") == "plain answer"


class TestChatmlFallback:
    """Validate the universal ChatML fallback prompt formatting."""

    @staticmethod
    def test_chatml_wraps_each_message_with_tokens() -> None:
        """Each message is wrapped in ChatML start/end tokens with a trailer."""
        chat_messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hi"},
        ]
        prompt = _format_prompt_chatml_fallback(chat_messages)
        assert "<|im_start|>system\nYou are helpful.<|im_end|>\n" in prompt
        assert "<|im_start|>user\nHi<|im_end|>\n" in prompt
        assert prompt.endswith("<|im_start|>assistant\n")


class TestBuildChatMessages:
    """Validate message normalization including tool injection and results."""

    @staticmethod
    def test_tool_injection_prepends_system_message() -> None:
        """Providing tools prepends a system message describing them."""
        provider = LocalTransformersProvider()
        built = _build_chat_messages(
            provider,
            [{"role": "user", "content": "Inspect kernel32.dll"}],
            [_binary_tool()],
        )
        assert built[0]["role"] == "system"
        assert "binary.get_file_size" in built[0]["content"]
        assert '"tool_call"' in built[0]["content"]
        assert built[-1] == {"role": "user", "content": "Inspect kernel32.dll"}

    @staticmethod
    def test_tool_result_message_becomes_user_turn() -> None:
        """A tool message with results is serialized into a user turn."""
        provider = LocalTransformersProvider()
        built = _build_chat_messages(
            provider,
            [
                {"role": "user", "content": "size?"},
                {"role": "tool", "tool_results": [{"result": "1148416"}]},
            ],
        )
        assert {"role": "user", "content": "[Tool Result]\n1148416"} in built

    @staticmethod
    def test_malformed_tool_results_are_dropped() -> None:
        """A tool message with non-list results contributes no turn."""
        provider = LocalTransformersProvider()
        built = _build_chat_messages(
            provider,
            [
                {"role": "user", "content": "q"},
                {"role": "tool", "tool_results": "not-a-list"},
            ],
        )
        roles = [m["role"] for m in built]
        assert roles == ["user"]

    @staticmethod
    def test_unknown_roles_are_filtered() -> None:
        """Roles outside the known set are excluded from the chat list."""
        provider = LocalTransformersProvider()
        built = _build_chat_messages(
            provider,
            [
                {"role": "user", "content": "a"},
                {"role": "function", "content": "ignored"},
                {"role": "assistant", "content": "b"},
            ],
        )
        assert [m["role"] for m in built] == ["user", "assistant"]


class TestDeviceProbesAndInfo:
    """Validate real CUDA/XPU probes and device-info reporting."""

    @staticmethod
    def test_cuda_probe_returns_bool() -> None:
        """The CUDA probe returns a real bool without raising."""
        assert isinstance(_probe_cuda(), bool)

    @staticmethod
    def test_cuda_device_count_matches_probe() -> None:
        """The CUDA device count is non-negative and consistent with the probe."""
        count = _cuda_device_count()
        assert isinstance(count, int)
        assert count >= 0
        if not _probe_cuda():
            assert count == 0

    @staticmethod
    def test_select_device_orders_cuda_xpu_cpu() -> None:
        """Device selection respects the CUDA -> XPU -> CPU priority order."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        _set_availability(provider, cuda=True, xpu=True)
        assert _select_device(provider) == "cuda"

        _set_availability(provider, cuda=False, xpu=_xpu_available_flag(provider))
        selected = _select_device(provider)
        if _xpu_available_flag(provider):
            assert selected in {"xpu", "cpu"}
        else:
            assert selected == "cpu"

    @staticmethod
    def test_prefer_xpu_false_skips_xpu() -> None:
        """Disabling XPU preference selects CPU even when XPU is available."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        _set_availability(provider, cuda=False, xpu=True)
        assert _select_device(provider) == "cpu"

    @staticmethod
    def test_get_device_info_reports_real_flags() -> None:
        """Device info reports real availability flags and a device type."""
        provider = LocalTransformersProvider()
        info = provider.get_device_info()
        assert info["device_type"] in {"cuda", "xpu", "cpu"}
        assert isinstance(info["cuda_available"], bool)
        assert isinstance(info["xpu_available"], bool)
        assert isinstance(info["warnings"], list)
        if info["device_type"] == "xpu" and is_xpu_available():
            assert "total_memory_gb" in info
            assert isinstance(info["total_memory_gb"], float)
