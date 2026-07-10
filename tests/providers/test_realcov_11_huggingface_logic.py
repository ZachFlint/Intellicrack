# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for ``HuggingFaceProvider`` payload logic.

These tests exercise the provider's request/response translation logic
that the live ``chat`` / ``chat_stream`` integration tests cannot reach
without a paid inference endpoint: 503 error-body extraction, model-list
normalization, tool-choice translation, output tool-call parsing, and
stream-delta extraction. Every input is a *real* object from the
production ``huggingface_hub`` SDK or ``httpx`` (a genuine
``ChatCompletionStreamOutput``, ``ChatCompletionOutputMessage``,
``ModelInfo``, or ``httpx.Response``) rather than a synthetic stand-in
for the capability under test. The provider's own translation code is
never mocked. A live round-trip against the real HuggingFace router is
included and gated on a configured token.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

import httpx
import pytest
from huggingface_hub import (
    ChatCompletionInputToolChoiceClass,
    ChatCompletionOutputFunctionDefinition,
    ChatCompletionOutputMessage,
    ChatCompletionOutputToolCall,
    ChatCompletionStreamOutput,
    ChatCompletionStreamOutputChoice,
    ChatCompletionStreamOutputDelta,
    ChatCompletionStreamOutputDeltaToolCall,
    ChatCompletionStreamOutputFunction,
    ModelInfo as HfModelInfo,
)

from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderError,
    ProviderName,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
)
from intellicrack.providers import huggingface
from intellicrack.providers.huggingface import HuggingFaceProvider


if TYPE_CHECKING:
    from collections.abc import Callable

    from huggingface_hub import ModelInfo as HfModelInfoType


def _convert_tool_choice(
    tool_choice: ToolChoice,
) -> ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"]:
    """Translate a ToolChoice via the module-private converter.

    Args:
        tool_choice: The Intellicrack tool-selection directive.

    Returns:
        ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"]:
            The SDK-format tool choice.
    """
    fn = cast(
        "Callable[[ToolChoice], ChatCompletionInputToolChoiceClass | Literal['auto', 'none', 'required']]",
        vars(huggingface)["_convert_tool_choice"],
    )
    return fn(tool_choice)


def _parse_message_tool_calls(message: ChatCompletionOutputMessage) -> list[ToolCall]:
    """Parse tool calls from an SDK message via the module-private helper.

    Args:
        message: Assistant message returned by the SDK.

    Returns:
        list[ToolCall]: Parsed tool calls.
    """
    fn = cast("Callable[[ChatCompletionOutputMessage], list[ToolCall]]", vars(huggingface)["_parse_message_tool_calls"])
    return fn(message)


def _extract_stream_delta(chunk: ChatCompletionStreamOutput) -> tuple[str, list[dict[str, Any]]]:
    """Extract stream-delta content/tool updates via the module-private helper.

    Args:
        chunk: A single stream-output chunk from the SDK.

    Returns:
        tuple[str, list[dict[str, Any]]]: Content text and tool-update dicts.
    """
    fn = cast(
        "Callable[[ChatCompletionStreamOutput], tuple[str, list[dict[str, Any]]]]",
        vars(huggingface)["_extract_stream_delta"],
    )
    return fn(chunk)


def _extract_503_message(exc: BaseException) -> str:
    """Extract a 503 message via the provider's protected static method.

    Args:
        exc: An exception carrying (or lacking) a response body.

    Returns:
        str: The extracted human-readable message.
    """
    fn = cast("Callable[[BaseException], str]", vars(HuggingFaceProvider)["_extract_503_message"])
    return fn(exc)


def _build_model_info_list(raw_models: list[HfModelInfoType]) -> list[ModelInfo]:
    """Normalize raw HfApi model entries via the protected builder.

    Args:
        raw_models: Raw HuggingFace model metadata objects.

    Returns:
        list[ModelInfo]: Normalized model info list.
    """
    fn = cast("Callable[[list[HfModelInfoType]], list[ModelInfo]]", vars(HuggingFaceProvider)["_build_model_info_list"])
    return fn(raw_models)


async def _run_first_servable_chat(provider: HuggingFaceProvider) -> None:
    """List models and assert a chat round-trip works on the first servable one.

    Skips when no model is listed or none is servable via the router so a
    genuine environment limitation never produces a false pass.

    Args:
        provider: A connected HuggingFace provider.
    """
    models = await provider.list_models()
    if not models:
        pytest.skip("No warm HuggingFace inference models available")
    last_error: str | None = None
    for candidate in models[:12]:
        last_error = await _attempt_chat_round_trip(provider, candidate.id)
        if last_error is None:
            return
    pytest.skip(f"No listed model is servable via the hf-inference router: {last_error}")


async def _attempt_chat_round_trip(provider: HuggingFaceProvider, model_id: str) -> str | None:
    """Attempt one chat round-trip and assert on a successful response.

    Args:
        provider: A connected HuggingFace provider.
        model_id: The model to attempt inference with.

    Returns:
        str | None: ``None`` on success (assertions passed), or the error
        text when the model is not servable via the router.
    """
    try:
        message, tool_calls = await provider.chat(
            messages=[Message(role="user", content="Reply with the single word: ready")],
            model=model_id,
            temperature=0.0,
            max_tokens=16,
        )
    except (ProviderError, ValueError) as exc:
        return str(exc)
    assert isinstance(message.content, str)
    assert len(message.content) > 0
    assert tool_calls is None or isinstance(tool_calls, list)
    usage = provider.get_pending_usage()
    assert usage is not None
    assert usage.total_tokens > 0
    return None


if TYPE_CHECKING:
    from intellicrack.credentials.store import CredentialLoader


class _ResponseCarrierError(Exception):
    """A real exception that carries an ``httpx.Response``.

    HuggingFace's ``HfHubHTTPError`` exposes the originating response via
    a ``response`` attribute; this lightweight carrier reproduces that
    contract for ``_extract_503_message`` without depending on SDK
    constructor internals, while still passing a *real* ``httpx.Response``.
    """

    def __init__(self, response: httpx.Response) -> None:
        """Store the response so the extractor can read its body.

        Args:
            response: The real httpx response to expose.
        """
        super().__init__("service unavailable")
        self.response = response


class TestExtract503Message:
    """Validate 503 body extraction over real httpx responses."""

    @staticmethod
    def test_json_error_with_estimated_time() -> None:
        """A JSON body with error and estimated_time yields a combined message."""
        resp = httpx.Response(503, json={"error": "Model is loading", "estimated_time": 20.0})
        message = _extract_503_message(_ResponseCarrierError(resp))
        assert message == "Model is loading (estimated_time=20.0s)"

    @staticmethod
    def test_json_error_without_estimated_time() -> None:
        """A JSON body with only an error field yields just that error."""
        resp = httpx.Response(503, json={"error": "Still warming up"})
        assert _extract_503_message(_ResponseCarrierError(resp)) == "Still warming up"

    @staticmethod
    def test_invalid_json_body_falls_back() -> None:
        """A non-JSON (HTML) body falls back to the generic loading message."""
        resp = httpx.Response(503, text="<html>gateway</html>")
        assert _extract_503_message(_ResponseCarrierError(resp)) == "Model is loading and not yet ready"

    @staticmethod
    def test_missing_error_field_falls_back() -> None:
        """A JSON body lacking an error field falls back to the generic message."""
        resp = httpx.Response(503, json={"detail": "no error key"})
        assert _extract_503_message(_ResponseCarrierError(resp)) == "Model is loading and not yet ready"

    @staticmethod
    def test_no_response_attribute_falls_back() -> None:
        """An exception without a response attribute yields the generic message."""
        assert _extract_503_message(RuntimeError("boom")) == "Model is loading and not yet ready"


class TestBuildModelInfoList:
    """Validate normalization of real ``HfApi`` model entries."""

    @staticmethod
    def test_tool_and_vision_flags_from_tags() -> None:
        """Tool-use and vision tags are mapped onto capability flags."""
        raw = [
            HfModelInfo(
                id="org/tool-model",
                pipeline_tag="text-generation",
                tags=["tool-use", "text-generation"],
            ),
            HfModelInfo(
                id="org/vision-model",
                pipeline_tag="image-text-to-text",
                tags=["multimodal"],
            ),
        ]
        models = _build_model_info_list(raw)
        by_id = {m.id: m for m in models}
        assert by_id["org/tool-model"].supports_tools is True
        assert by_id["org/tool-model"].supports_vision is False
        assert by_id["org/vision-model"].supports_vision is True
        assert all(m.provider is ProviderName.HUGGINGFACE for m in models)
        assert by_id["org/tool-model"].name == "tool-model"

    @staticmethod
    def test_duplicate_and_empty_ids_are_dropped() -> None:
        """Duplicate model ids are de-duplicated and empty ids dropped."""
        raw = [
            HfModelInfo(id="org/dup", pipeline_tag="text-generation", tags=[]),
            HfModelInfo(id="org/dup", pipeline_tag="text-generation", tags=[]),
            HfModelInfo(id="", pipeline_tag="text-generation", tags=[]),
        ]
        models = _build_model_info_list(raw)
        assert [m.id for m in models] == ["org/dup"]

    @staticmethod
    def test_all_models_stream_capable_with_positive_context() -> None:
        """Every normalized model advertises streaming and a positive window."""
        raw = [HfModelInfo(id="org/m", pipeline_tag="text-generation", tags=[])]
        model = _build_model_info_list(raw)[0]
        assert model.supports_streaming is True
        assert model.context_window > 0


class TestConvertToolChoice:
    """Validate ToolChoice translation to the SDK schema."""

    @staticmethod
    def test_enum_modes_map_to_strings() -> None:
        """AUTO/NONE/REQUIRED map to their SDK string literals."""
        assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.AUTO)) == "auto"
        assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.NONE)) == "none"
        assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.REQUIRED)) == "required"

    @staticmethod
    def test_specific_mode_names_function() -> None:
        """SPECIFIC mode yields a tool-choice object naming the function."""
        result = _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="binary.get_file_size"))
        assert isinstance(result, ChatCompletionInputToolChoiceClass)
        assert result.function.name == "binary.get_file_size"


class TestParseMessageToolCalls:
    """Validate parsing tool calls from a real SDK output message."""

    @staticmethod
    def test_parses_function_call_arguments() -> None:
        """A real output message with a tool call yields a parsed ToolCall."""
        message = ChatCompletionOutputMessage(
            role="assistant",
            content=None,
            tool_calls=[
                ChatCompletionOutputToolCall(
                    id="call_abc",
                    type="function",
                    function=ChatCompletionOutputFunctionDefinition(
                        name="binary.get_file_size",
                        arguments='{"path": "C:/Windows/System32/ntdll.dll"}',
                        description=None,
                    ),
                ),
            ],
        )
        calls = _parse_message_tool_calls(message)
        assert len(calls) == 1
        assert calls[0].function_name == "binary.get_file_size"
        assert calls[0].arguments == {"path": "C:/Windows/System32/ntdll.dll"}

    @staticmethod
    def test_no_tool_calls_yields_empty_list() -> None:
        """An assistant message without tool calls yields an empty list."""
        message = ChatCompletionOutputMessage(role="assistant", content="hello", tool_calls=None)
        assert _parse_message_tool_calls(message) == []


class TestExtractStreamDelta:
    """Validate stream-delta extraction from real SDK chunk objects."""

    @staticmethod
    def _make_chunk(
        *,
        content: str | None,
        tool_calls: list[ChatCompletionStreamOutputDeltaToolCall] | None,
    ) -> ChatCompletionStreamOutput:
        """Construct a real stream-output chunk.

        Args:
            content: Delta content text, or None.
            tool_calls: Delta tool-call list, or None.

        Returns:
            ChatCompletionStreamOutput: A populated single-choice chunk.
        """
        delta = ChatCompletionStreamOutputDelta(role="assistant", content=content, tool_calls=tool_calls)
        choice = ChatCompletionStreamOutputChoice(delta=delta, index=0, finish_reason=None, logprobs=None)
        return ChatCompletionStreamOutput(
            choices=[choice],
            created=0,
            id="chunk-1",
            model="org/m",
            system_fingerprint="fp",
        )

    def test_content_chunk_extracted(self) -> None:
        """A chunk carrying content text yields that text with no tool updates."""
        chunk = self._make_chunk(content="Hello", tool_calls=None)
        content, tool_updates = _extract_stream_delta(chunk)
        assert content == "Hello"
        assert tool_updates == []

    def test_tool_call_delta_extracted(self) -> None:
        """A chunk carrying a tool-call delta yields a normalized update dict."""
        tc_delta = ChatCompletionStreamOutputDeltaToolCall(
            index=0,
            id="call_1",
            type="function",
            function=ChatCompletionStreamOutputFunction(name="decompile", arguments='{"addr":'),
        )
        chunk = self._make_chunk(content=None, tool_calls=[tc_delta])
        content, tool_updates = _extract_stream_delta(chunk)
        assert not content
        assert len(tool_updates) == 1
        assert tool_updates[0]["index"] == 0
        assert tool_updates[0]["id"] == "call_1"
        assert tool_updates[0]["name"] == "decompile"
        assert tool_updates[0]["arguments"] == '{"addr":'

    @staticmethod
    def test_empty_choices_yields_empty_result() -> None:
        """A chunk with no choices yields empty content and no updates."""
        chunk = ChatCompletionStreamOutput(
            choices=[],
            created=0,
            id="empty",
            model="org/m",
            system_fingerprint="fp",
        )
        assert _extract_stream_delta(chunk) == ("", [])


class TestProviderRoutingPolicy:
    """Regression guards for the HuggingFace chat-completion routing policy.

    The dedicated ``hf-inference`` inference provider serves only
    legacy/non-generative models (embeddings, classification, translation,
    and similar) and never supports the conversational task, so pinning the
    SDK client to ``provider="hf-inference"`` makes every chat request fail
    regardless of which model is selected. These tests fail loudly if the
    provider is ever pinned back to ``"hf-inference"`` instead of routing
    through the router's ``"auto"`` policy.
    """

    @staticmethod
    def test_default_provider_is_auto_not_hf_inference() -> None:
        """``DEFAULT_PROVIDER`` must route via "auto", never "hf-inference"."""
        assert HuggingFaceProvider.DEFAULT_PROVIDER == "auto"
        assert HuggingFaceProvider.DEFAULT_PROVIDER != "hf-inference"


@pytest.mark.integration
class TestHuggingFaceLiveChat:
    """Validate real chat inference through the HuggingFace router."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_chat_round_trip_returns_text_and_usage(
        credential_loader: CredentialLoader,
        *,
        has_huggingface_key: bool,
    ) -> None:
        """A live chat call returns assistant text and real token usage.

        Args:
            credential_loader: Credential loader fixture.
            has_huggingface_key: Whether a HuggingFace API token is configured.
        """
        if not has_huggingface_key:
            pytest.skip("HUGGINGFACE_API_TOKEN not configured")

        provider = HuggingFaceProvider()
        credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
        assert credentials is not None
        await provider.connect(credentials)
        try:
            await _run_first_servable_chat(provider)
        finally:
            await provider.disconnect()
