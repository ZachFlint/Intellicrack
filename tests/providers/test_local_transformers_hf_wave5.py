# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 falsifiable test gates for HuggingFaceProvider and LocalTransformersProvider.

Closes group-08-report findings 1-9 (huggingface.py) and 10-19 (local_transformers.py).
Every gate uses an independently-known oracle and is falsifiable by a nameable one-line
production mutation. External boundaries (torch GPU APIs, model/tokenizer loaders, httpx
transport, XPU cache) are monkeypatched; the SUT's own logic is never mocked.
"""

from __future__ import annotations

import asyncio
import gc
import time
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
import torch
from huggingface_hub import (
    AsyncInferenceClient,
    ChatCompletionStreamOutput,
    ChatCompletionStreamOutputChoice,
    ChatCompletionStreamOutputDelta,
)

import intellicrack.providers.local_transformers as lt_mod
from intellicrack.core.types import (
    Message,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers import huggingface
from intellicrack.providers.base import ToolCallBufferManager
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import LoadedModel, ModelCache, ModelConfig


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Callable
    from types import TracebackType
    from typing import Self

    from transformers import PreTrainedModel, PreTrainedTokenizerBase
    from transformers.modeling_outputs import CausalLMOutputWithPast


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class _MinimalStub:
    """Minimal stand-in for model/tokenizer objects in cast-only usage.

    No methods are needed: the SUT's format_prompt only accesses
    ``tokenizer.chat_template`` via ``getattr(..., None)``, which returns
    ``None`` for this class, and ``hasattr(tokenizer, "apply_chat_template")``
    evaluates to ``False``, so the ChatML fallback path is taken.
    """


class _ResponseCarrierError(Exception):
    """Exception that exposes an ``httpx.Response`` as its ``response`` attribute.

    Reproduces the contract of ``huggingface_hub.errors.HfHubHTTPError`` for
    ``_hf_status_code`` tests without depending on SDK constructor internals.

    Attributes:
        response: The real httpx response to expose.
    """

    response: httpx.Response

    def __init__(self, response: httpx.Response) -> None:
        """Attach response to the exception.

        Args:
            response: The real httpx response to expose.
        """
        super().__init__("carrier")
        self.response = response


def _hf_status_code_fn(exc: BaseException) -> int:
    """Call the private module-level HF status-code extractor.

    Args:
        exc: Exception to extract status from.

    Returns:
        int: The extracted HTTP status code, or 0.
    """
    fn = cast("Callable[[BaseException], int]", vars(huggingface)["_hf_status_code"])
    return fn(exc)


def _make_binary_tool() -> ToolDefinition:
    """Build a real binary-analysis ToolDefinition for provider format tests.

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


def _make_text_chunk(content: str) -> ChatCompletionStreamOutput:
    """Build a real HF streaming chunk carrying text content.

    Args:
        content: Delta content text to embed in the chunk.

    Returns:
        ChatCompletionStreamOutput: A single-choice chunk carrying content text.
    """
    delta = ChatCompletionStreamOutputDelta(role="assistant", content=content, tool_calls=None)
    choice = ChatCompletionStreamOutputChoice(delta=delta, index=0, finish_reason=None, logprobs=None)
    return ChatCompletionStreamOutput(
        choices=[choice],
        created=0,
        id="test-chunk",
        model="test/model",
        system_fingerprint="test-fp",
    )


def _make_sentinel_loaded_model(model_id: str) -> LoadedModel:
    """Build a minimal ``LoadedModel`` that satisfies the provider's format_prompt path.

    The ``_MinimalStub`` instances passed as model/tokenizer cause
    ``format_prompt`` to fall through to the ChatML fallback because
    neither ``chat_template`` nor ``apply_chat_template`` is present.

    Args:
        model_id: Model identifier to record in the loaded-model record.

    Returns:
        LoadedModel: A populated record backed by minimal stub objects.
    """
    return LoadedModel(
        model=cast("PreTrainedModel", _MinimalStub()),
        tokenizer=cast("PreTrainedTokenizerBase", _MinimalStub()),
        device=torch.device("cpu"),
        dtype="float16",
        memory_usage_bytes=0,
        model_id=model_id,
        load_time_seconds=0.0,
    )


# ---------------------------------------------------------------------------
# Finding 1 — _hf_status_code extracts HTTP status code
# ---------------------------------------------------------------------------


class TestHfStatusCode:
    """Validate ``_hf_status_code`` extracts the HTTP integer from HF exceptions.

    Oracle: HTTP status codes are documented integers (503, 401, etc.).
    Mutation: removing the ``isinstance(code, int)`` guard returns ``"503"``
    instead of ``0`` for the string case, breaking the second test.
    """

    @staticmethod
    def test_extracts_integer_status_code_from_exception_with_response() -> None:
        """A response with status_code=503 yields 503, not 0."""
        resp = httpx.Response(503)
        carrier = _ResponseCarrierError(resp)
        assert _hf_status_code_fn(carrier) == 503

    @staticmethod
    def test_returns_zero_for_exception_without_response_attribute() -> None:
        """A plain exception with no response attribute returns 0."""
        assert _hf_status_code_fn(RuntimeError("no response")) == 0

    @staticmethod
    def test_returns_zero_when_status_code_is_not_int() -> None:
        """A string status_code on the response returns 0 (not the string)."""

        class _StrStatusError(Exception):
            class _Resp:
                status_code: str = "503"

            def __init__(self) -> None:
                super().__init__()
                self.response = _StrStatusError._Resp()

        assert _hf_status_code_fn(_StrStatusError()) == 0


# ---------------------------------------------------------------------------
# Finding 2 — _close_client sets client to None
# ---------------------------------------------------------------------------


class TestCloseClient:
    """Validate ``_close_client`` releases the AsyncInferenceClient reference.

    Oracle: ``provider.client is None`` after the call.
    Mutation: removing ``self.client = None`` from ``_close_client`` leaves
    ``provider.client`` non-None and fails the assertion.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_client_is_none_after_close_client() -> None:
        """After _close_client, provider.client is set to None."""

        class _FakeClient:
            async def close(self) -> None:
                pass

        provider = HuggingFaceProvider()
        provider.client = cast(AsyncInferenceClient, _FakeClient())
        assert provider.client is not None

        await getattr(provider, "_close_client")()

        assert provider.client is None


# ---------------------------------------------------------------------------
# Finding 3 — disconnect resets _cancel_requested and releases client
# ---------------------------------------------------------------------------


class TestDisconnect:
    """Validate ``disconnect`` resets the cancel flag and releases the client.

    Oracle: base class sets ``_cancel_requested = False``; ``_close_client``
    sets ``client = None``.
    Mutations: removing the ``_cancel_requested = False`` line from base
    ``disconnect`` fails the flag assertion; removing ``self.client = None``
    from ``_close_client`` fails the client assertion.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_flag_reset_and_client_released_after_disconnect() -> None:
        """disconnect() resets cancel flag, nulls client, and marks disconnected."""

        class _FakeClient:
            async def close(self) -> None:
                pass

        provider = HuggingFaceProvider()
        provider.client = cast(AsyncInferenceClient, _FakeClient())
        setattr(provider, "_cancel_requested", True)
        provider.connected = True

        await provider.disconnect()

        assert getattr(provider, "_cancel_requested") is False
        assert provider.client is None
        assert not provider.connected


# ---------------------------------------------------------------------------
# Finding 4 — _prepare_request_payload converts messages and tools
# ---------------------------------------------------------------------------


class TestPrepareRequestPayload:
    """Validate ``_prepare_request_payload`` produces the correct SDK input triple.

    Oracle: OpenAI-compatible format documented by the HF SDK (role/content
    dicts, tool objects with ``type=="function"``).
    Mutation: swapping ``role`` and ``content`` keys in message conversion
    breaks the dict equality assertion.
    """

    @staticmethod
    def test_user_message_converts_to_role_content_dict() -> None:
        """A single user message becomes a list with the correct role/content pair."""
        provider = HuggingFaceProvider()
        messages = [Message(role="user", content="analyse this binary")]

        hf_messages, hf_tools, hf_tool_choice = getattr(provider, "_prepare_request_payload")(messages, None, None)

        assert hf_messages == [{"role": "user", "content": "analyse this binary"}]
        assert hf_tools is None
        assert hf_tool_choice is None

    @staticmethod
    def test_tools_converted_to_openai_function_schema() -> None:
        """Provided tools produce a list with type=='function' and correct name."""
        provider = HuggingFaceProvider()
        messages = [Message(role="user", content="q")]
        tool = _make_binary_tool()

        _hf_messages, hf_tools, _hf_choice = getattr(provider, "_prepare_request_payload")(messages, [tool], None)

        assert hf_tools is not None
        assert len(hf_tools) == 1
        entry = hf_tools[0]
        assert entry["type"] == "function"
        func = cast("dict[str, object]", entry["function"])
        assert func["name"] == "binary.get_file_size"


# ---------------------------------------------------------------------------
# Finding 5 — _consume_stream_chunks yields content and handles cancellation
# ---------------------------------------------------------------------------


class TestConsumeStreamChunks:
    """Validate ``_consume_stream_chunks`` accumulates text and respects cancellation.

    Oracle: the exact list of text pieces yielded from the synthetic stream.
    Mutations: removing ``yield content_piece`` empties the collected list;
    removing the ``_cancel_requested`` break yields all chunks even when cancelled.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_text_chunks_yielded_in_order() -> None:
        """Two text chunks from the stream are yielded in order."""
        provider = HuggingFaceProvider()
        tc_buffer = ToolCallBufferManager()

        async def _stream() -> AsyncGenerator[ChatCompletionStreamOutput]:
            await asyncio.sleep(0)
            yield _make_text_chunk("hello ")
            yield _make_text_chunk("world")

        chunks = [
            piece
            async for piece in getattr(provider, "_consume_stream_chunks")(
                _stream(),
                model="test/m",
                tc_buffer=tc_buffer,
            )
        ]

        assert chunks == ["hello ", "world"]
        assert getattr(provider, "_pending_tool_calls") == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_before_stream_yields_nothing() -> None:
        """Setting _cancel_requested before iteration produces no output chunks."""
        provider = HuggingFaceProvider()
        setattr(provider, "_cancel_requested", True)
        tc_buffer = ToolCallBufferManager()

        async def _endless() -> AsyncGenerator[ChatCompletionStreamOutput]:
            await asyncio.sleep(0)
            for i in range(5):
                yield _make_text_chunk(f"chunk{i}")

        chunks = [
            piece
            async for piece in getattr(provider, "_consume_stream_chunks")(
                _endless(),
                model="test/m",
                tc_buffer=tc_buffer,
            )
        ]

        assert not chunks


# ---------------------------------------------------------------------------
# Finding 6 — chat_stream yields chunks via the httpx/SDK boundary
# ---------------------------------------------------------------------------


class TestChatStream:
    """Validate ``chat_stream`` yields text through a fake chat_completion client.

    Oracle: the exact text yielded by the fake client is what the provider yields.
    Mutation: removing the ``yield piece`` line in the chat_stream consumer produces
    an empty collected list.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_yields_text_chunk_and_stream_ends_cleanly() -> None:
        """At least one text chunk passes through chat_stream to the caller."""

        class _FakeChatClient:
            async def close(self) -> None:
                pass

            async def chat_completion(self, **_kwargs: object) -> AsyncGenerator[ChatCompletionStreamOutput]:
                async def _gen() -> AsyncGenerator[ChatCompletionStreamOutput]:
                    await asyncio.sleep(0)
                    yield _make_text_chunk("ready")

                return _gen()

        provider = HuggingFaceProvider()
        provider.connected = True
        provider.client = cast(AsyncInferenceClient, _FakeChatClient())

        messages = [Message(role="user", content="ping")]
        chunks = [chunk async for chunk in provider.chat_stream(messages, model="test/model")]

        assert chunks == ["ready"]


# ---------------------------------------------------------------------------
# Finding 7 — cancel_request sets _cancel_requested to True
# ---------------------------------------------------------------------------


class TestCancelRequest:
    """Validate ``cancel_request`` transitions the cancel flag.

    Oracle: ``_cancel_requested`` is False before the call and True after.
    Mutation: removing ``self._cancel_requested = True`` leaves the flag False
    and fails the assertion.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_cancel_request_sets_flag_true() -> None:
        """cancel_request() sets _cancel_requested from False to True."""
        provider = HuggingFaceProvider()
        assert getattr(provider, "_cancel_requested") is False

        await provider.cancel_request()

        assert getattr(provider, "_cancel_requested") is True


# ---------------------------------------------------------------------------
# Finding 8 — _convert_messages_to_provider_format (HuggingFace)
# ---------------------------------------------------------------------------


class TestConvertMessagesHF:
    """Validate HuggingFaceProvider message conversion produces OpenAI-format dicts.

    Oracle: the OpenAI chat completions schema documented by OpenAI/HuggingFace
    (``{"role": str, "content": str}`` for user/system messages).
    Mutation: swapping ``"role"`` and ``"content"`` keys breaks the equality
    assertion on the first dict.
    """

    @staticmethod
    def test_single_user_message_produces_role_content_dict() -> None:
        """A user message is converted to the exact OpenAI role/content schema."""
        provider = HuggingFaceProvider()
        messages = [Message(role="user", content="analyse this binary")]

        result = getattr(provider, "_convert_messages_to_provider_format")(messages)

        assert result == [{"role": "user", "content": "analyse this binary"}]

    @staticmethod
    def test_multi_turn_conversation_preserves_all_roles() -> None:
        """System, user, and assistant messages are all converted correctly."""
        provider = HuggingFaceProvider()
        messages = [
            Message(role="system", content="You are an analyst."),
            Message(role="user", content="decompile main"),
            Message(role="assistant", content="Decompiled."),
        ]

        result = getattr(provider, "_convert_messages_to_provider_format")(messages)

        assert len(result) == 3
        assert result[0] == {"role": "system", "content": "You are an analyst."}
        assert result[1] == {"role": "user", "content": "decompile main"}
        assert result[2] == {"role": "assistant", "content": "Decompiled."}


# ---------------------------------------------------------------------------
# Finding 9 — _convert_tools_to_provider_format (HuggingFace)
# ---------------------------------------------------------------------------


class TestConvertToolsHF:
    """Validate HuggingFaceProvider tool conversion produces OpenAI function schemas.

    Oracle: the OpenAI function-calling schema (``type=="function"``, ``name``,
    ``description``, ``parameters`` with ``type=="object"``).
    Mutation: removing ``"type": "function"`` from the output breaks the
    ``entry["type"] == "function"`` assertion.
    """

    @staticmethod
    def test_single_tool_produces_openai_function_schema() -> None:
        """A ToolDefinition converts to a list with one OpenAI-schema tool dict."""
        provider = HuggingFaceProvider()
        tool = _make_binary_tool()

        result = getattr(provider, "_convert_tools_to_provider_format")([tool])

        assert len(result) == 1
        entry = result[0]
        assert entry["type"] == "function"
        func = cast("dict[str, object]", entry["function"])
        assert func["name"] == "binary.get_file_size"
        assert "description" in func
        params = cast("dict[str, object]", func["parameters"])
        assert params["type"] == "object"
        props = cast("dict[str, object]", params["properties"])
        assert "path" in props
        required = cast("list[str]", params["required"])
        assert "path" in required


# ---------------------------------------------------------------------------
# Finding 10 — _fetch_model_config (local_transformers.py)
# ---------------------------------------------------------------------------


class TestFetchModelConfig:
    """Validate ``_fetch_model_config`` branches for success, HTTP error, and connection error.

    Oracle: the parsed JSON dict on 200, ``{}`` on any httpx or connection error.
    Mutations: removing the ``return {}`` in the except block raises instead of
    returning ``{}``; removing ``response.json()`` never populates the result.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_200_returns_parsed_json_dict(monkeypatch: pytest.MonkeyPatch) -> None:
        """A 200 response from the HF Hub returns its JSON payload as a dict.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        canned: dict[str, Any] = {"model_type": "gpt2", "max_position_embeddings": 2048}

        class _Client200:
            def __init__(self, **kwargs: object) -> None:
                pass

            async def __aenter__(self) -> Self:
                return self

            async def __aexit__(
                self,
                exc_type: type[BaseException] | None,
                exc_val: BaseException | None,
                exc_tb: TracebackType | None,
            ) -> bool | None:
                return None

            async def get(self, url: str) -> httpx.Response:
                return httpx.Response(200, json=canned, request=httpx.Request("GET", url))

        monkeypatch.setattr(httpx, "AsyncClient", _Client200)
        result = await getattr(lt_mod, "_fetch_model_config")("test/gpt2")
        assert result == canned

    @pytest.mark.asyncio
    @staticmethod
    async def test_http_error_returns_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
        """An HTTPError during the GET request returns an empty dict, no exception.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """

        class _ClientHTTPError:
            def __init__(self, **kwargs: object) -> None:
                pass

            async def __aenter__(self) -> Self:
                return self

            async def __aexit__(
                self,
                exc_type: type[BaseException] | None,
                exc_val: BaseException | None,
                exc_tb: TracebackType | None,
            ) -> bool | None:
                return None

            async def get(self, _url: str) -> httpx.Response:
                msg = "simulated 404"
                raise httpx.HTTPError(msg)

        monkeypatch.setattr(httpx, "AsyncClient", _ClientHTTPError)
        result = await getattr(lt_mod, "_fetch_model_config")("org/nonexistent")
        assert result == {}

    @pytest.mark.asyncio
    @staticmethod
    async def test_connection_error_returns_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
        """A ConnectionError returns an empty dict, no exception propagates.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """

        class _ClientConnError:
            def __init__(self, **kwargs: object) -> None:
                pass

            async def __aenter__(self) -> Self:
                return self

            async def __aexit__(
                self,
                exc_type: type[BaseException] | None,
                exc_val: BaseException | None,
                exc_tb: TracebackType | None,
            ) -> bool | None:
                return None

            async def get(self, _url: str) -> httpx.Response:
                msg = "offline sandbox"
                raise ConnectionError(msg)

        monkeypatch.setattr(httpx, "AsyncClient", _ClientConnError)
        result = await getattr(lt_mod, "_fetch_model_config")("org/model")
        assert result == {}


# ---------------------------------------------------------------------------
# Finding 11 — _release_device_caches calls gc.collect and clear_xpu_cache
# ---------------------------------------------------------------------------


class TestReleaseDeviceCaches:
    """Validate ``_release_device_caches`` dispatches to the correct cache clear path.

    Oracle: ``gc.collect`` called at least once (always); ``clear_xpu_cache``
    called exactly once when device is xpu.
    Mutations: removing ``gc.collect()`` empties ``gc_calls``; removing the
    ``clear_xpu_cache()`` call empties ``xpu_calls``.
    """

    @staticmethod
    def test_gc_collect_called_on_cpu_device(monkeypatch: pytest.MonkeyPatch) -> None:
        """On cpu device, gc.collect is called and xpu cache is not touched.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        gc_calls: list[int] = []

        def fake_gc_collect(generation: int = 2) -> int:
            gc_calls.append(generation)
            return 0

        monkeypatch.setattr(gc, "collect", fake_gc_collect)

        provider = LocalTransformersProvider()
        setattr(provider, "_device_type", "cpu")
        getattr(provider, "_release_device_caches")()

        assert gc_calls

    @staticmethod
    def test_xpu_cache_cleared_and_gc_called_on_xpu_device(monkeypatch: pytest.MonkeyPatch) -> None:
        """On xpu device, clear_xpu_cache is called once and gc.collect follows.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        gc_calls: list[int] = []
        xpu_calls: list[bool] = []

        def fake_gc_collect(generation: int = 2) -> int:
            gc_calls.append(generation)
            return 0

        def fake_clear_xpu_cache() -> None:
            xpu_calls.append(True)

        monkeypatch.setattr(gc, "collect", fake_gc_collect)
        monkeypatch.setattr(lt_mod, "clear_xpu_cache", fake_clear_xpu_cache)

        provider = LocalTransformersProvider()
        setattr(provider, "_device_type", "xpu")
        getattr(provider, "_release_device_caches")()

        assert xpu_calls == [True]
        assert gc_calls


# ---------------------------------------------------------------------------
# Finding 12 — list_models returns all seven recommended model IDs
# ---------------------------------------------------------------------------


class TestListModels:
    """Validate ``list_models`` includes all seven RECOMMENDED_MODELS_B580 entries.

    Oracle: the seven model identifiers documented in ``RECOMMENDED_MODELS_B580``
    (independently known constants from the model_loader module).
    Mutations: dropping any entry from ``RECOMMENDED_MODELS_B580`` removes its
    model ID from the result, breaking ``model_ids == expected_ids``.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_all_seven_recommended_model_ids_present(monkeypatch: pytest.MonkeyPatch) -> None:
        """All 7 RECOMMENDED_MODELS_B580 model_ids appear in list_models() result.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """

        async def _fake_fetch(_model_id: str, token: str | None = None) -> dict[str, Any]:
            del token
            await asyncio.sleep(0)
            return {}

        monkeypatch.setattr(lt_mod, "_fetch_model_config", _fake_fetch)

        provider = LocalTransformersProvider()
        provider.connected = True
        setattr(provider, "_device_type", "cpu")

        models = await provider.list_models()
        model_ids = {m.id for m in models}

        expected_ids = {
            "microsoft/Phi-3-mini-4k-instruct",
            "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
            "Qwen/Qwen2.5-1.5B-Instruct",
            "Qwen/Qwen2.5-3B-Instruct",
            "meta-llama/Llama-3.2-1B-Instruct",
            "meta-llama/Llama-3.2-3B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
        }
        assert model_ids == expected_ids

    @pytest.mark.asyncio
    @staticmethod
    async def test_context_window_from_config_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
        """Config-supplied max_position_embeddings overrides the 4096 default.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """

        async def _fake_fetch_with_context(model_id: str, token: str | None = None) -> dict[str, Any]:
            del token
            await asyncio.sleep(0)
            return {"max_position_embeddings": 8192} if "Phi" in model_id else {}

        monkeypatch.setattr(lt_mod, "_fetch_model_config", _fake_fetch_with_context)

        provider = LocalTransformersProvider()
        provider.connected = True
        setattr(provider, "_device_type", "cpu")

        models = await provider.list_models()
        by_id = {m.id: m for m in models}

        phi_model = by_id.get("microsoft/Phi-3-mini-4k-instruct")
        assert phi_model is not None
        assert phi_model.context_window == 8192

        tiny_model = by_id.get("TinyLlama/TinyLlama-1.1B-Chat-v1.0")
        assert tiny_model is not None
        assert tiny_model.context_window == 4096


# ---------------------------------------------------------------------------
# Finding 13 — _run_local_chat returns (text, usage) with correct structure
# ---------------------------------------------------------------------------


class TestRunLocalChat:
    """Validate ``_run_local_chat`` returns the correct Message and usage.

    Oracle: the text returned by the monkeypatched ``_generate_sync`` appears
    verbatim in ``msg.content``, and ``_pending_usage`` fields equal the
    known token counts returned by the fake generator.
    Mutations: breaking the ``response_text`` assignment changes ``msg.content``;
    breaking the UsageInfo construction changes the token counts.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_returns_assistant_message_and_usage(monkeypatch: pytest.MonkeyPatch) -> None:
        """_run_local_chat assembles the Message and UsageInfo from _generate_sync output.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        provider = LocalTransformersProvider()
        provider.connected = True
        setattr(provider, "_loaded_model", _make_sentinel_loaded_model("test/model"))

        def fake_generate_sync(_prompt: str, _temperature: float, _max_new: int) -> tuple[str, int, int]:
            return "main() returns 0", 42, 15

        monkeypatch.setattr(provider, "_generate_sync", fake_generate_sync)

        messages = [Message(role="user", content="decompile main")]
        start = time.perf_counter()

        msg, tool_calls = await getattr(provider, "_run_local_chat")(
            messages=messages,
            model_id="test/model",
            tools=None,
            temperature=0.0,
            max_tokens=128,
            start_time=start,
        )

        assert msg.role == "assistant"
        assert msg.content == "main() returns 0"
        assert tool_calls is None
        pending_usage = getattr(provider, "_pending_usage")
        assert pending_usage is not None
        assert pending_usage.prompt_tokens == 42
        assert pending_usage.completion_tokens == 15
        assert pending_usage.total_tokens == 57


# ---------------------------------------------------------------------------
# Finding 14 — _iter_local_stream yields accumulated chunks
# ---------------------------------------------------------------------------


class TestIterLocalStream:
    """Validate ``_iter_local_stream`` accumulates and yields chunks from the generator.

    Oracle: the exact sequence of strings yielded by the monkeypatched
    ``_stream_generate`` is re-yielded unchanged by ``_iter_local_stream``.
    Mutation: removing ``yield chunk`` from ``_iter_local_stream`` empties
    the collected list.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_chunks_yielded_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
        """All chunks from _stream_generate pass through _iter_local_stream in order.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        provider = LocalTransformersProvider()
        provider.connected = True
        setattr(provider, "_loaded_model", _make_sentinel_loaded_model("test/model"))

        async def fake_stream_generate(
            _prompt: str,
            _temperature: float,
            _max_tokens: int,
        ) -> AsyncIterator[str]:
            await asyncio.sleep(0)
            for word in ["hello", " world"]:
                yield word

        monkeypatch.setattr(provider, "_stream_generate", fake_stream_generate)

        messages = [Message(role="user", content="say hello")]
        collected = [
            chunk
            async for chunk in getattr(provider, "_iter_local_stream")(
                messages=messages,
                tools=None,
                temperature=0.0,
                max_tokens=64,
            )
        ]

        assert collected == ["hello", " world"]


# ---------------------------------------------------------------------------
# Finding 15 — _config_device_for translates device strings
# ---------------------------------------------------------------------------


class TestConfigDeviceFor:
    """Validate ``_config_device_for`` maps provider device strings to loader device strings.

    Oracle: the docstring explicitly states: xpu→"xpu", cuda→"cpu" (CUDA uses cpu
    in ModelConfig), anything else→"cpu".
    Mutations: swapping the return value for xpu from "xpu" to "cpu" breaks the
    first assertion; swapping cuda's return from "cpu" to "auto" breaks the second.
    """

    @staticmethod
    def test_xpu_maps_to_xpu() -> None:
        """_config_device_for("xpu") returns "xpu"."""
        assert getattr(LocalTransformersProvider, "_config_device_for")("xpu") == "xpu"

    @staticmethod
    def test_cuda_maps_to_cpu() -> None:
        """_config_device_for("cuda") returns "cpu" (CUDA handled inside provider)."""
        assert getattr(LocalTransformersProvider, "_config_device_for")("cuda") == "cpu"

    @staticmethod
    def test_cpu_maps_to_cpu() -> None:
        """_config_device_for("cpu") returns "cpu"."""
        assert getattr(LocalTransformersProvider, "_config_device_for")("cpu") == "cpu"


# ---------------------------------------------------------------------------
# Finding 16 — _load_for_device dispatches to the correct loader
# ---------------------------------------------------------------------------


class TestLoadForDevice:
    """Validate ``_load_for_device`` routes to the correct per-device loader.

    Oracle: only the expected loader function is called (sentinel tracking),
    and the returned object is the sentinel from that loader.
    For cuda (unavailable in sandbox), the RuntimeError from ``_load_model_for_cuda``
    confirms the cuda branch was dispatched (not xpu or cpu).
    Mutations: swapping the ``if device == "xpu":`` and ``if device == "cuda":``
    branches routes to the wrong loader and fails the ``dispatched_to`` assertions.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_xpu_device_calls_xpu_loader(monkeypatch: pytest.MonkeyPatch) -> None:
        """_load_for_device("xpu", …) calls load_model_for_xpu, not the cpu loader.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        xpu_called: list[bool] = []
        cpu_called: list[bool] = []
        sentinel = _make_sentinel_loaded_model("xpu-model")

        def fake_xpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            xpu_called.append(True)
            return sentinel

        def fake_cpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            cpu_called.append(True)
            return sentinel

        monkeypatch.setattr(lt_mod, "load_model_for_xpu", fake_xpu_loader)
        monkeypatch.setattr(lt_mod, "load_model_for_cpu", fake_cpu_loader)

        provider = LocalTransformersProvider()
        config = ModelConfig(model_id="test/model", dtype="auto", device="xpu")
        result = await getattr(provider, "_load_for_device")("xpu", config)

        assert xpu_called == [True]
        assert not cpu_called
        assert result is sentinel

    @pytest.mark.asyncio
    @staticmethod
    async def test_cpu_device_calls_cpu_loader(monkeypatch: pytest.MonkeyPatch) -> None:
        """_load_for_device("cpu", …) calls load_model_for_cpu, not the xpu loader.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        xpu_called: list[bool] = []
        cpu_called: list[bool] = []
        sentinel = _make_sentinel_loaded_model("cpu-model")

        def fake_xpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            xpu_called.append(True)
            return sentinel

        def fake_cpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            cpu_called.append(True)
            return sentinel

        monkeypatch.setattr(lt_mod, "load_model_for_xpu", fake_xpu_loader)
        monkeypatch.setattr(lt_mod, "load_model_for_cpu", fake_cpu_loader)

        provider = LocalTransformersProvider()
        config = ModelConfig(model_id="test/model", dtype="auto", device="cpu")
        result = await getattr(provider, "_load_for_device")("cpu", config)

        assert cpu_called == [True]
        assert not xpu_called
        assert result is sentinel

    @pytest.mark.asyncio
    @staticmethod
    async def test_cuda_device_routes_to_cuda_loader_not_cpu_or_xpu(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_load_for_device("cuda", …) routes to _load_model_for_cuda (raises on no-CUDA).

        The cuda loader raises RuntimeError with "CUDA" when CUDA is unavailable,
        confirming the dispatch reached _load_model_for_cuda, not xpu or cpu loaders.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        if torch.cuda.is_available():
            pytest.skip("CUDA present; gate requires a CUDA-free environment")

        cpu_called: list[bool] = []
        xpu_called: list[bool] = []
        sentinel = _make_sentinel_loaded_model("cuda-model")

        def fake_cpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            cpu_called.append(True)
            return sentinel

        def fake_xpu_loader(_config: ModelConfig, _cache: ModelCache | None = None) -> LoadedModel:
            xpu_called.append(True)
            return sentinel

        monkeypatch.setattr(lt_mod, "load_model_for_cpu", fake_cpu_loader)
        monkeypatch.setattr(lt_mod, "load_model_for_xpu", fake_xpu_loader)

        provider = LocalTransformersProvider()
        config = ModelConfig(model_id="test/model", dtype="auto", device="cpu")

        with pytest.raises(RuntimeError, match="CUDA"):
            await getattr(provider, "_load_for_device")("cuda", config)

        assert not cpu_called
        assert not xpu_called


# ---------------------------------------------------------------------------
# Finding 17 — _load_model_for_cuda raises on no-CUDA machine
# ---------------------------------------------------------------------------


class TestLoadModelForCuda:
    """Validate ``_load_model_for_cuda`` raises RuntimeError when CUDA is unavailable.

    Oracle: ``_ERR_CUDA_NOT_AVAILABLE = "CUDA is not available on this system"``
    (a named constant in local_transformers.py).
    Mutation: changing the RuntimeError message to not include "CUDA" breaks
    the ``match="CUDA"`` assertion.
    """

    @staticmethod
    def test_raises_runtime_error_with_cuda_in_message_when_cuda_unavailable() -> None:
        """_load_model_for_cuda raises RuntimeError containing "CUDA" on a no-CUDA host."""
        if torch.cuda.is_available():
            pytest.skip("CUDA present; gate requires a CUDA-free environment")

        provider = LocalTransformersProvider()
        config = ModelConfig(model_id="test/model", dtype="auto", device="cpu")

        with pytest.raises(RuntimeError, match="CUDA"):
            getattr(provider, "_load_model_for_cuda")(config)


# ---------------------------------------------------------------------------
# Finding 18 — _iter_local_generation_loop temperature branch
# ---------------------------------------------------------------------------


class _FakeOutput:
    """Minimal causal LM output carrying a fixed logits tensor.

    Attributes:
        logits: The logits tensor from the forward pass.
        past_key_values: Always None (no KV cache in stub).
    """

    logits: torch.Tensor
    past_key_values: tuple[tuple[torch.Tensor, ...], ...] | None

    def __init__(self, logits_: torch.Tensor) -> None:
        """Store the fixed logits tensor.

        Args:
            logits_: Logits tensor of shape [batch, seq_len, vocab_size].
        """
        self.logits = logits_
        self.past_key_values = None


class _FakeTokenizer:
    """Minimal tokenizer stub that records token IDs as strings.

    Attributes:
        eos_token_id: EOS token ID set to 0 so test tokens (2 or 3) never trigger EOS.
    """

    eos_token_id: int = 0

    @staticmethod
    def decode(token: torch.Tensor, *, skip_special_tokens: bool = True) -> str:
        """Return a deterministic string for the given single-element tensor.

        Args:
            token: A 1-D tensor containing one token ID.
            skip_special_tokens: Present for API compatibility; stub strips all tokens.

        Returns:
            str: The string "t<token_id>" where token_id is the integer value.
        """
        _ = skip_special_tokens
        return f"t{int(token.item())}"


class TestIterLocalGenerationLoop:
    """Validate the temperature branch in ``_iter_local_generation_loop``.

    Argmax oracle: the token produced at temperature=0 must equal ``argmax(logits[-1])``,
    which is token 3 when logits[0,-1,3]=100 and all others=0.
    Multinomial oracle: at temperature>0, ``torch.multinomial`` must be called
    (verified by a counting wrapper on the torch function, which is an external boundary).
    Mutations: swapping ``temperature > 0`` and ``temperature == 0`` branches
    produces the wrong token type in each test.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_temperature_zero_selects_argmax_token() -> None:
        """temperature=0 selects the argmax token (3) from a logits tensor."""
        vocab_size = 5
        fixed_logits = torch.zeros(1, 1, vocab_size)
        fixed_logits[0, 0, 3] = 100.0

        def fake_forward(
            _m: PreTrainedModel,
            _gen_ids: torch.Tensor,
            _attn: torch.Tensor | None,
            _past_kv: tuple[tuple[torch.Tensor, ...], ...] | None,
        ) -> CausalLMOutputWithPast:
            return cast("CausalLMOutputWithPast", _FakeOutput(fixed_logits))

        provider = LocalTransformersProvider()
        tokenizer = cast("PreTrainedTokenizerBase", _FakeTokenizer())
        model = cast("PreTrainedModel", _MinimalStub())
        generated_ids = torch.zeros(1, 1, dtype=torch.long)
        counter: list[int] = [0]

        tokens = [
            tok
            async for tok in getattr(provider, "_iter_local_generation_loop")(
                model=model,
                tokenizer=tokenizer,
                generated_ids=generated_ids,
                attention_mask=None,
                past_key_values=None,
                max_tokens=1,
                temperature=0.0,
                forward_pass=fake_forward,
                completion_counter=counter,
            )
        ]

        assert tokens == ["t3"]
        assert counter == [1]

    @pytest.mark.asyncio
    @staticmethod
    async def test_temperature_positive_calls_multinomial(monkeypatch: pytest.MonkeyPatch) -> None:
        """temperature>0 calls torch.multinomial (sampling path), not argmax.

        Args:
            monkeypatch: pytest MonkeyPatch fixture for attribute patching.
        """
        vocab_size = 5
        fixed_logits = torch.zeros(1, 1, vocab_size)
        fixed_logits[0, 0, 2] = 50.0

        multinomial_calls: list[bool] = []
        real_multinomial = torch.multinomial

        def counting_multinomial(
            probs: torch.Tensor,
            num_samples: int,
            *,
            replacement: bool = False,
        ) -> torch.Tensor:
            multinomial_calls.append(True)
            return real_multinomial(probs, num_samples, replacement)

        monkeypatch.setattr(torch, "multinomial", counting_multinomial)

        def fake_forward(
            _m: PreTrainedModel,
            _gen_ids: torch.Tensor,
            _attn: torch.Tensor | None,
            _past_kv: tuple[tuple[torch.Tensor, ...], ...] | None,
        ) -> CausalLMOutputWithPast:
            return cast("CausalLMOutputWithPast", _FakeOutput(fixed_logits))

        provider = LocalTransformersProvider()
        tokenizer = cast("PreTrainedTokenizerBase", _FakeTokenizer())
        model = cast("PreTrainedModel", _MinimalStub())
        generated_ids = torch.zeros(1, 1, dtype=torch.long)
        counter: list[int] = [0]

        async for _tok in getattr(provider, "_iter_local_generation_loop")(
            model=model,
            tokenizer=tokenizer,
            generated_ids=generated_ids,
            attention_mask=None,
            past_key_values=None,
            max_tokens=1,
            temperature=0.7,
            forward_pass=fake_forward,
            completion_counter=counter,
        ):
            pass

        assert multinomial_calls == [True]


# ---------------------------------------------------------------------------
# Finding 19 — _convert_tools_to_provider_format (LocalTransformers)
# ---------------------------------------------------------------------------


class TestConvertToolsLT:
    """Validate LocalTransformersProvider tool conversion for a non-empty list.

    Oracle: the same OpenAI function schema as HuggingFaceProvider (both use
    ``create_openai_tool_schema``), so the expected structure is identical.
    Mutation: removing the ``result.extend(...)`` call returns an empty list
    and breaks the ``len(result) == 1`` assertion.
    """

    @staticmethod
    def test_non_empty_tool_list_produces_openai_schema() -> None:
        """A ToolDefinition converts to a list with a correct OpenAI function schema."""
        provider = LocalTransformersProvider()
        tool = _make_binary_tool()

        result = getattr(provider, "_convert_tools_to_provider_format")([tool])

        assert len(result) == 1
        entry = result[0]
        assert entry["type"] == "function"
        func = cast("dict[str, object]", entry["function"])
        assert func["name"] == "binary.get_file_size"
        assert "description" in func
        params = cast("dict[str, object]", func["parameters"])
        assert params["type"] == "object"
        props = cast("dict[str, object]", params["properties"])
        assert "path" in props
        required = cast("list[str]", params["required"])
        assert "path" in required

    @staticmethod
    def test_empty_tool_list_produces_empty_result() -> None:
        """An empty tool list converts to an empty list (regression guard)."""
        provider = LocalTransformersProvider()
        result = getattr(provider, "_convert_tools_to_provider_format")([])
        assert result == []
