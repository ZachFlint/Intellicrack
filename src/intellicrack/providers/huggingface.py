# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""HuggingFace Inference API provider implementation.

This module provides integration with HuggingFace's Inference API using the official ``huggingface_hub.AsyncInferenceClient`` and its
``chat_completion`` method.  The client targets the HuggingFace first-party router endpoint at
``https://router.huggingface.co/hf-inference``
via the ``provider="hf-inference"``
selector, which replaces the deprecated ``api-inference.huggingface.co`` host
and provides direct access to HuggingFace-hosted serverless endpoints.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Protocol, cast, overload, override

import httpx
from huggingface_hub import (
    AsyncInferenceClient,
    ChatCompletionInputFunctionName,
    ChatCompletionInputToolChoiceClass,
    HfApi,
)
from huggingface_hub.errors import (
    BadRequestError,
    HfHubHTTPError,
    InferenceTimeoutError,
)

from intellicrack.core.logging import get_logger, log_provider_request
from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
)
from intellicrack.providers.base import (
    HttpErrorMessages,
    LLMProviderBase,
    ToolCallBufferManager,
    UsageInfo,
    create_openai_tool_schema,
    parse_tool_call,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterable, AsyncIterator

    from huggingface_hub import (
        ChatCompletionInputMessage,
        ChatCompletionInputTool,
        ChatCompletionOutput,
        ChatCompletionOutputMessage,
        ChatCompletionStreamOutput,
        ModelInfo as HfModelInfo,
    )


class _ChatCompletionCallable(Protocol):
    """Protocol matching the typed subset of ``chat_completion`` we use."""

    @overload
    async def __call__(
        self,
        *,
        messages: list[dict[str, Any] | ChatCompletionInputMessage],
        model: str,
        stream: Literal[False],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionInputTool] | None,
        tool_choice: ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"] | None,
    ) -> ChatCompletionOutput: ...

    @overload
    async def __call__(
        self,
        *,
        messages: list[dict[str, Any] | ChatCompletionInputMessage],
        model: str,
        stream: Literal[True],
        temperature: float,
        max_tokens: int,
        tools: list[ChatCompletionInputTool] | None,
        tool_choice: ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"] | None,
    ) -> AsyncIterable[ChatCompletionStreamOutput]: ...


class _WhoamiCallable(Protocol):
    """Protocol matching the typed subset of ``HfApi.whoami`` we use."""

    def __call__(self) -> dict[str, Any]: ...


_ERR_MODEL_LOADING = "HuggingFace model is loading and not yet ready: %s"

_ERR_NOT_CONNECTED = "Not connected to HuggingFace"
_ERR_CREDENTIAL_REQUIRED = "HuggingFace API token is required"
_ERR_CREDENTIAL_INVALID = "Invalid HuggingFace API token: %s"
_ERR_CONNECT_FAILED = "Failed to connect to HuggingFace: %s"
_ERR_LIST_MODELS_FAILED = "Failed to list HuggingFace models: %s"
_ERR_NO_RESPONSE_CHOICES = "No response choices returned"
_ERR_API_ERROR = "HuggingFace API error: %s"
_ERR_RATE_LIMITED = "HuggingFace rate limit exceeded: %s"
_ERR_BAD_REQUEST = "HuggingFace bad request: %s"
_ERR_TIMEOUT = "HuggingFace inference timeout: %s"
_ERR_STREAM_FAILED = "HuggingFace stream failed: %s"

_MODEL_LIST_LIMIT = 100
_DEFAULT_CONTEXT_WINDOW = 4096

_HF_HTTP_MSGS = HttpErrorMessages(
    auth_invalid=_ERR_CREDENTIAL_INVALID,
    rate_limited=_ERR_RATE_LIMITED,
    service_unavailable=_ERR_MODEL_LOADING,
)

_logger = get_logger(__name__)


def _hf_status_code(exc: BaseException) -> int:
    """Return the HTTP status code associated with a HuggingFace exception.

    HuggingFace's :class:`HfHubHTTPError` exposes the originating
    response via a ``response`` attribute when one is available, but
    transport-level failures or synthetic exceptions can leave it
    unset. Returns ``0`` as a sentinel meaning "no status" so callers
    can pass the result to
    :meth:`LLMProviderBase._raise_typed_for_status` without first
    distinguishing the missing case; ``0`` does not match any of the
    helper's known status codes so the caller's fall-through ``raise``
    is reached unchanged.

    Args:
        exc: The exception raised by the SDK.

    Returns:
        int: The HTTP status code, or ``0`` when the exception does
        not carry a response.
    """
    response = getattr(exc, "response", None)
    code = getattr(response, "status_code", None)
    return code if isinstance(code, int) else 0


class HuggingFaceProvider(LLMProviderBase):
    """HuggingFace Inference API provider implementation.

    Uses ``huggingface_hub.AsyncInferenceClient.chat_completion`` for both
    blocking and streaming requests.  The client is configured with
    ``provider="hf-inference"`` so requests are routed through HuggingFace's
    first-party router at ``https://router.huggingface.co/hf-inference``,
    replacing the deprecated ``api-inference.huggingface.co`` host.

    Attributes:
        DEFAULT_PROVIDER: HuggingFace inference-provider routing strategy.
        MODELS_LIST_LIMIT: Maximum number of models fetched from ``HfApi``.
    """

    DEFAULT_PROVIDER: ClassVar[Literal["hf-inference"]] = "hf-inference"
    MODELS_LIST_LIMIT: ClassVar[int] = _MODEL_LIST_LIMIT

    def __init__(self) -> None:
        """Initialize the HuggingFaceProvider instance."""
        super().__init__()
        self.client: AsyncInferenceClient | None = None
        self._hf_api: HfApi | None = None
        self._api_token: str | None = None
        self._api_base: str | None = None
        self._timeout: float = 120.0
        self._logger = get_logger(__name__).bind(provider="huggingface")
        self._logger.info("huggingface_provider_initialized")

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: The provider name enum value.
        """
        return ProviderName.HUGGINGFACE

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the HuggingFace Inference API.

        Creates an ``AsyncInferenceClient`` and verifies the token with a
        ``whoami()`` probe via ``HfApi`` (executed in a worker thread since
        ``HfApi`` is synchronous). HTTP errors raised by the connect probe
        are translated to Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.

        Args:
            credentials: Must contain ``api_key`` set to a HuggingFace token.

        Raises:
            AuthenticationError: If the API token is missing or invalid.
            ProviderError: If the connection probe fails for other reasons.
        """
        if not credentials.api_key:
            self._logger.warning("huggingface_connect_missing_credential")
            raise AuthenticationError(_ERR_CREDENTIAL_REQUIRED)

        self._api_token = credentials.api_key
        self._api_base = credentials.api_base
        self._timeout = credentials.timeout or 120.0

        self.client = AsyncInferenceClient(
            token=self._api_token,
            timeout=self._timeout,
            provider=self.DEFAULT_PROVIDER,
            base_url=self._api_base,
        )
        self._hf_api = HfApi(token=self._api_token)

        whoami: _WhoamiCallable = cast("_WhoamiCallable", self._hf_api.whoami)

        identity: dict[str, Any] = {}
        try:
            identity = await asyncio.to_thread(whoami)
        except HfHubHTTPError as exc:
            status_code = _hf_status_code(exc)
            self._logger.warning(
                "huggingface_connect_failed",
                status_code=status_code,
                error_type=type(exc).__name__,
            )
            self.connected = False
            await self._close_client()
            self._raise_typed_for_status(status_code, exc, messages=_HF_HTTP_MSGS, extract_503_message=self._extract_503_message)
            raise ProviderError(_ERR_CONNECT_FAILED % exc) from exc
        except (ConnectionError, TimeoutError, OSError) as exc:
            self._logger.warning(
                "huggingface_connect_failed",
                error_type=type(exc).__name__,
            )
            self.connected = False
            await self._close_client()
            raise ProviderError(_ERR_CONNECT_FAILED % exc) from exc

        self._credentials = credentials
        self.connected = True
        user_name = identity.get("name")
        self._logger.info(
            "huggingface_connected",
            user=str(user_name) if user_name else None,
            has_custom_base=credentials.api_base is not None,
        )

    @staticmethod
    def _extract_503_message(exc: BaseException) -> str:
        """Extract a human-readable message from a 503 service-unavailable error.

        HuggingFace returns 503 when a model is still loading.  The body is
        usually JSON (``{"error": "...", "estimated_time": ...}``), but the
        router occasionally returns HTML, which raises ``json.JSONDecodeError``
        / ``httpx.DecodingError`` / ``ValueError``.  This helper guards the
        decode and falls back to a generic "Model is loading" message.
        Accepts any ``BaseException`` so it can be passed to
        :meth:`LLMProviderBase._raise_typed_for_status` as the
        ``extract_503_message`` callable; non-``HfHubHTTPError`` exceptions
        simply lack a ``response`` attribute and produce the fallback message.

        Args:
            exc: The exception raised by the SDK; only ``HfHubHTTPError``
                instances carry a usable ``response`` attribute.

        Returns:
            str: A human-readable error message describing the 503 cause.
        """
        response = getattr(exc, "response", None)
        if response is None:
            return "Model is loading and not yet ready"
        try:
            body = response.json()
        except (json.JSONDecodeError, ValueError, TypeError, httpx.DecodingError) as decode_exc:
            _logger.warning("hf_503_body_decode_failed", error_type=type(decode_exc).__name__)
            return "Model is loading and not yet ready"
        if isinstance(body, dict):
            body_dict = cast("dict[str, Any]", body)
            error_msg = body_dict.get("error")
            estimated = body_dict.get("estimated_time")
            if isinstance(error_msg, str):
                if isinstance(estimated, (int, float)):
                    return f"{error_msg} (estimated_time={estimated}s)"
                return error_msg
        return "Model is loading and not yet ready"

    async def _close_client(self) -> None:
        """Close the inference client if present, ignoring shutdown errors."""
        if self.client is not None:
            self._logger.info("huggingface_client_closing")
            try:
                await self.client.close()
            except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
                self._logger.warning("huggingface_client_close_error", error=str(exc))
            self.client = None

    async def disconnect(self) -> None:
        """Disconnect from the HuggingFace API and clean up resources."""
        was_connected = self.connected
        await super().disconnect()
        await self._close_client()
        self._hf_api = None
        self._api_token = None
        self._api_base = None
        self._pending_usage = None
        self._logger.info(
            "huggingface_disconnected",
            was_connected=was_connected,
        )

    async def list_models(self) -> list[ModelInfo]:
        """Fetch available text-generation models from HuggingFace.

        Queries ``HfApi.list_models`` filtered to text-generation models
        with warm inference endpoints, then normalises the results into
        ``ModelInfo`` objects.  The call is dispatched to a worker thread
        because ``HfApi`` is synchronous. HTTP errors are translated to
        Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.

        Returns:
            list[ModelInfo]: List of available models with their capabilities.

        Raises:
            ProviderError: If not connected or the listing call fails.
        """
        if not self.connected or self._hf_api is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        api = self._hf_api

        def _fetch() -> list[HfModelInfo]:
            """Execute the synchronous ``HfApi.list_models`` call.

            Returns:
                list[HfModelInfo]: Raw model metadata objects from the Hub.
            """
            return list(
                api.list_models(
                    filter="text-generation",
                    inference="warm",
                    sort="downloads",
                    limit=self.MODELS_LIST_LIMIT,
                    cardData=False,
                ),
            )

        try:
            raw_models = await asyncio.to_thread(_fetch)
        except HfHubHTTPError as exc:
            status_code = _hf_status_code(exc)
            self._logger.warning(
                "huggingface_list_models_failed",
                status_code=status_code,
                error_type=type(exc).__name__,
            )
            self._raise_typed_for_status(status_code, exc, messages=_HF_HTTP_MSGS, extract_503_message=self._extract_503_message)
            raise ProviderError(_ERR_LIST_MODELS_FAILED % exc) from exc
        except (ConnectionError, TimeoutError, OSError, ValueError) as exc:
            self._logger.warning(
                "huggingface_list_models_failed",
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_LIST_MODELS_FAILED % exc) from exc

        models = self.build_model_info_list(raw_models)

        self._logger.info(
            "huggingface_models_listed",
            count=len(models),
        )
        return models

    @staticmethod
    def build_model_info_list(raw_models: list[HfModelInfo]) -> list[ModelInfo]:
        """Normalise raw ``HfApi`` model entries into ``ModelInfo`` instances.

        Public entry point to the HuggingFace model-record normalisation used by
        :meth:`list_models`. Exposing it lets callers and tests exercise the
        bridge's record-to-``ModelInfo`` mapping directly without a live API call.

        Args:
            raw_models: Sequence of ``huggingface_hub.ModelInfo`` objects.

        Returns:
            list[ModelInfo]: De-duplicated list preserving input order.
        """
        return HuggingFaceProvider._build_model_info_list(raw_models)

    @staticmethod
    def _build_model_info_list(raw_models: list[HfModelInfo]) -> list[ModelInfo]:
        """Normalise raw ``HfApi`` model entries into ``ModelInfo`` instances.

        Args:
            raw_models: Sequence of ``huggingface_hub.ModelInfo`` objects.

        Returns:
            list[ModelInfo]: De-duplicated list preserving input order.
        """
        models: list[ModelInfo] = []
        seen_ids: set[str] = set()

        for raw in raw_models:
            model_id = str(getattr(raw, "id", "") or "").strip()
            if not model_id or model_id in seen_ids:
                continue

            pipeline_tag = str(getattr(raw, "pipeline_tag", "") or "")
            tags_obj = cast("list[object]", getattr(raw, "tags", None) or [])
            tags: list[str] = [str(t).lower() for t in tags_obj]

            tool_indicators = frozenset({
                "function-calling",
                "tool-use",
                "tool_use",
                "function_calling",
            })
            supports_tools = bool(tool_indicators & set(tags))

            vision_indicators = frozenset({
                "vision",
                "image-text-to-text",
                "multimodal",
                "visual-question-answering",
            })
            supports_vision = bool(vision_indicators & set(tags)) or pipeline_tag in {
                "image-text-to-text",
                "visual-question-answering",
            }

            seen_ids.add(model_id)
            short_name = model_id.rsplit("/", maxsplit=1)[-1] if "/" in model_id else model_id
            models.append(
                ModelInfo(
                    id=model_id,
                    name=short_name,
                    provider=ProviderName.HUGGINGFACE,
                    context_window=_DEFAULT_CONTEXT_WINDOW,
                    supports_tools=supports_tools,
                    supports_vision=supports_vision,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                ),
            )
        return models

    def _prepare_request_payload(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        tool_choice: ToolChoice | None,
    ) -> tuple[
        list[dict[str, Any] | ChatCompletionInputMessage],
        list[ChatCompletionInputTool] | None,
        ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"] | None,
    ]:
        """Convert Intellicrack objects to the SDK's input types.

        Args:
            messages: Conversation history.
            tools: Tool definitions, or ``None``.
            tool_choice: Tool-selection policy, or ``None``.

        Returns:
            tuple[list[dict[str, Any] | ChatCompletionInputMessage], list[ChatCompletionInputTool] | None, ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"] | None]:
                The ``messages``, ``tools``, and ``tool_choice`` arguments
                ready to be passed to ``AsyncInferenceClient.chat_completion``.
        """
        hf_messages = cast(
            "list[dict[str, Any] | ChatCompletionInputMessage]",
            self.convert_messages_to_provider_format(messages),
        )
        hf_tools: list[ChatCompletionInputTool] | None = None
        if tools:
            hf_tools = cast(
                "list[ChatCompletionInputTool]",
                self.convert_tools_to_provider_format(tools),
            )
        hf_tool_choice: ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"] | None = None
        if tool_choice is not None and tools:
            hf_tool_choice = _convert_tool_choice(tool_choice)
        return hf_messages, hf_tools, hf_tool_choice

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request via ``AsyncInferenceClient``.

        HTTP errors are translated to Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.

        Args:
            messages: Conversation history.
            model: Model ID to use (e.g. ``meta-llama/Meta-Llama-3-8B-Instruct``).
            tools: Available tools for function calling, or ``None``.
            temperature: Sampling temperature in the range [0.0, 2.0].
            max_tokens: Maximum tokens in the response.
            tool_choice: How the model should select tools, or ``None``.
            thinking: Extended thinking configuration (ignored by HuggingFace).
            enable_cache: Whether to enable prompt caching (ignored).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of
                (assistant message, parsed tool calls or ``None``).

        Raises:
            ProviderError: If not connected, the response is empty, or the
                underlying SDK raises a non-auth/rate-limit error.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        if thinking is not None and thinking.enabled:
            self._logger.debug("huggingface_thinking_ignored")
        if enable_cache:
            self._logger.debug("huggingface_cache_ignored")

        hf_messages, hf_tools, hf_tool_choice = self._prepare_request_payload(
            messages,
            tools,
            tool_choice,
        )

        log_provider_request(
            provider="huggingface",
            model=model,
            messages_count=len(messages),
            tools_count=len(tools) if tools else 0,
        )

        chat_completion = cast("_ChatCompletionCallable", self.client.chat_completion)

        start_time = time.perf_counter()
        try:
            raw_result: ChatCompletionOutput = await chat_completion(
                messages=hf_messages,
                model=model,
                stream=False,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=hf_tools,
                tool_choice=hf_tool_choice,
            )
        except BadRequestError as exc:
            self._logger.warning("huggingface_bad_request", model=model, error=str(exc))
            raise ProviderError(_ERR_BAD_REQUEST % exc) from exc
        except InferenceTimeoutError as exc:
            self._logger.warning("huggingface_timeout", model=model, error=str(exc))
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except HfHubHTTPError as exc:
            status_code = _hf_status_code(exc)
            self._logger.warning(
                "huggingface_chat_http_error",
                model=model,
                status_code=status_code,
                error_type=type(exc).__name__,
            )
            self._raise_typed_for_status(status_code, exc, messages=_HF_HTTP_MSGS, extract_503_message=self._extract_503_message)
            raise ProviderError(_ERR_API_ERROR % exc) from exc
        except TimeoutError as exc:
            self._logger.warning(
                "huggingface_chat_timeout",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except (ConnectionError, OSError) as exc:
            self._logger.warning(
                "huggingface_chat_transport_error",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_API_ERROR % exc) from exc

        duration_ms = (time.perf_counter() - start_time) * 1000

        choices = raw_result.choices
        if not choices:
            raise ProviderError(_ERR_NO_RESPONSE_CHOICES)

        response_message = choices[0].message
        content = response_message.content or ""
        tool_calls = _parse_message_tool_calls(response_message)

        usage = raw_result.usage
        self._pending_usage = UsageInfo(
            prompt_tokens=int(usage.prompt_tokens),
            completion_tokens=int(usage.completion_tokens),
            total_tokens=int(usage.total_tokens),
        )

        self._logger.info(
            "huggingface_chat_completed",
            model=model,
            messages_count=len(messages),
            tool_calls_count=len(tool_calls),
            duration_ms=round(duration_ms, 2),
            has_tools=tools is not None,
            has_usage=True,
        )

        return self._build_chat_response(
            provider="huggingface",
            model=model,
            content=content,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
        )

    async def _consume_stream_chunks(
        self,
        raw_stream: AsyncIterable[ChatCompletionStreamOutput],
        *,
        model: str,
        tc_buffer: ToolCallBufferManager,
    ) -> AsyncIterator[str]:
        """Consume HuggingFace streaming chunks and yield text content pieces.

        Accumulates tool-call deltas into ``tc_buffer`` and the last seen
        usage payload into ``self._pending_usage``. On cancellation the
        loop breaks early; on natural exhaustion ``tc_buffer.finalize()``
        publishes the assembled tool calls into ``self._pending_tool_calls``
        and a completion log entry is emitted. Exceptions raised by the
        SDK during iteration propagate unchanged so the caller's typed
        exception handlers can translate them.

        Args:
            raw_stream: Async iterable of chunk events from the HF SDK.
            model: Model ID for structured-log context.
            tc_buffer: Tool-call buffer to accumulate streamed deltas into.

        Yields:
            str: Text content pieces, one per chunk that carries content.
        """
        chunk_count = 0
        async for chunk in raw_stream:
            if self._cancel_requested:
                self._logger.info(
                    "huggingface_stream_cancelled",
                    model=model,
                    chunks_received=chunk_count,
                )
                break

            content_piece, tool_updates = _extract_stream_delta(chunk)
            if content_piece:
                chunk_count += 1
                yield content_piece
            for upd in tool_updates:
                tc_buffer.accumulate(
                    index=upd["index"],
                    call_id=upd["id"],
                    name=upd["name"],
                    arguments=upd["arguments"],
                )

            usage = getattr(chunk, "usage", None)
            if usage is not None:
                self._pending_usage = UsageInfo(
                    prompt_tokens=int(usage.prompt_tokens),
                    completion_tokens=int(usage.completion_tokens),
                    total_tokens=int(usage.total_tokens),
                )

        self._pending_tool_calls = tc_buffer.finalize()
        self._logger.info(
            "huggingface_stream_completed",
            model=model,
            chunks_received=chunk_count,
            has_usage=self._pending_usage is not None,
        )

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Stream chat completion chunks from the HuggingFace Inference API.

        HTTP errors are translated to Intellicrack typed errors by
        :meth:`LLMProviderBase._raise_typed_for_status`.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling, or ``None``.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.
            tool_choice: How the model should select tools, or ``None``.
            thinking: Extended thinking configuration (ignored).
            enable_cache: Whether to enable prompt caching (ignored).

        Yields:
            str: Text chunks as they arrive from the stream.

        Raises:
            ProviderError: If not connected or the stream fails transportwise.
        """
        if not self.connected or self.client is None:
            raise ProviderError(_ERR_NOT_CONNECTED)

        self._cancel_requested = False
        self._pending_usage = None
        if thinking is not None and thinking.enabled:
            self._logger.debug("huggingface_stream_thinking_ignored")
        if enable_cache:
            self._logger.debug("huggingface_stream_cache_ignored")

        hf_messages, hf_tools, hf_tool_choice = self._prepare_request_payload(
            messages,
            tools,
            tool_choice,
        )

        self._logger.info(
            "huggingface_stream_started",
            model=model,
            messages_count=len(messages),
            has_tools=tools is not None,
        )

        tc_buffer = ToolCallBufferManager()
        chat_completion = cast("_ChatCompletionCallable", self.client.chat_completion)

        try:
            raw_stream: AsyncIterable[ChatCompletionStreamOutput] = await chat_completion(
                messages=hf_messages,
                model=model,
                stream=True,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=hf_tools,
                tool_choice=hf_tool_choice,
            )
        except BadRequestError as exc:
            self._logger.warning("huggingface_stream_bad_request", model=model, error=str(exc))
            raise ProviderError(_ERR_BAD_REQUEST % exc) from exc
        except InferenceTimeoutError as exc:
            self._logger.warning("huggingface_stream_timeout", model=model, error=str(exc))
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except HfHubHTTPError as exc:
            status_code = _hf_status_code(exc)
            self._logger.warning(
                "huggingface_stream_http_error",
                model=model,
                status_code=status_code,
                error_type=type(exc).__name__,
            )
            self._raise_typed_for_status(status_code, exc, messages=_HF_HTTP_MSGS, extract_503_message=self._extract_503_message)
            raise ProviderError(_ERR_API_ERROR % exc) from exc
        except TimeoutError as exc:
            self._logger.warning(
                "huggingface_stream_timeout",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except (ConnectionError, OSError) as exc:
            self._logger.warning(
                "huggingface_stream_transport_error",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_STREAM_FAILED % exc) from exc

        try:
            async for piece in self._consume_stream_chunks(raw_stream, model=model, tc_buffer=tc_buffer):
                yield piece
        except BadRequestError as exc:
            self._logger.warning(
                "huggingface_stream_bad_request",
                model=model,
                error=str(exc),
            )
            raise ProviderError(_ERR_BAD_REQUEST % exc) from exc
        except InferenceTimeoutError as exc:
            self._logger.warning(
                "huggingface_stream_timeout",
                model=model,
                error=str(exc),
            )
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except HfHubHTTPError as exc:
            status_code = _hf_status_code(exc)
            self._logger.warning(
                "huggingface_stream_http_error",
                model=model,
                status_code=status_code,
                error_type=type(exc).__name__,
            )
            self._raise_typed_for_status(status_code, exc, messages=_HF_HTTP_MSGS, extract_503_message=self._extract_503_message)
            raise ProviderError(_ERR_API_ERROR % exc) from exc
        except TimeoutError as exc:
            if self._cancel_requested:
                self._logger.warning(
                    "huggingface_stream_cancelled_during_timeout",
                    model=model,
                    exc_info=True,
                )
                return
            self._logger.warning(
                "huggingface_stream_timeout_generic",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_TIMEOUT % exc) from exc
        except (ConnectionError, OSError, ValueError) as exc:
            if self._cancel_requested:
                self._logger.warning(
                    "huggingface_stream_cancelled_during_transport",
                    model=model,
                    error_type=type(exc).__name__,
                    exc_info=True,
                )
                return
            self._logger.warning(
                "huggingface_stream_failed",
                model=model,
                error_type=type(exc).__name__,
            )
            raise ProviderError(_ERR_STREAM_FAILED % exc) from exc

    async def cancel_request(self) -> None:
        """Cancel any in-flight request."""
        self._cancel_requested = True
        self._logger.info(
            "huggingface_cancel_requested",
            was_connected=self.connected,
        )

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to HuggingFace's OpenAI-compatible format.

        Args:
            messages: List of ``Message`` objects.

        Returns:
            list[dict[str, object]]: Messages in OpenAI-compatible schema.
        """
        return self._convert_messages_to_openai_format(messages)

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert internal tools to HuggingFace's OpenAI-compatible format.

        Args:
            tools: List of ``ToolDefinition`` objects.

        Returns:
            list[dict[str, object]]: Tools in OpenAI-compatible schema.
        """
        hf_tools: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            hf_tools.extend(dict(schema) for schema in tool_schemas)
        return hf_tools


def _convert_tool_choice(
    tool_choice: ToolChoice,
) -> ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"]:
    """Translate an Intellicrack ``ToolChoice`` into the SDK's schema.

    Args:
        tool_choice: The Intellicrack tool-selection directive.

    Returns:
        ChatCompletionInputToolChoiceClass | Literal["auto", "none", "required"]:
            ``"auto"``/``"none"``/``"required"`` for enum modes, or a
            ``ChatCompletionInputToolChoiceClass`` naming the function to
            invoke for ``SPECIFIC`` mode.
    """
    if tool_choice.mode is ToolChoiceMode.AUTO:
        return "auto"
    if tool_choice.mode is ToolChoiceMode.NONE:
        return "none"
    if tool_choice.mode is ToolChoiceMode.REQUIRED:
        return "required"
    return ChatCompletionInputToolChoiceClass(
        function=ChatCompletionInputFunctionName(name=tool_choice.function_name or ""),
    )


def _parse_message_tool_calls(response_message: ChatCompletionOutputMessage) -> list[ToolCall]:
    """Parse tool calls from a ``ChatCompletionOutputMessage`` instance.

    Args:
        response_message: Assistant message returned by the SDK.

    Returns:
        list[ToolCall]: Parsed ``ToolCall`` instances (possibly empty).
    """
    tool_calls: list[ToolCall] = []
    raw_calls = response_message.tool_calls or []
    for tc in raw_calls:
        func = tc.function
        args_str = func.arguments or "{}"
        tool_calls.append(
            parse_tool_call(
                call_id=tc.id,
                function_name=func.name,
                raw_arguments=args_str,
            ),
        )
    return tool_calls


def _extract_stream_delta(
    chunk: ChatCompletionStreamOutput,
) -> tuple[str, list[dict[str, Any]]]:
    """Extract content text and tool-call updates from a stream chunk.

    Args:
        chunk: A single ``ChatCompletionStreamOutput`` from the SDK stream.

    Returns:
        tuple[str, list[dict[str, Any]]]: Pair of ``(content_text, tool_updates)``
            where ``tool_updates`` is a list of dicts with keys ``index``,
            ``id``, ``name``, ``arguments``.
    """
    choices = chunk.choices
    if not choices:
        return "", []
    delta = choices[0].delta

    content_piece = delta.content or ""
    tool_updates: list[dict[str, Any]] = []
    raw_tc_deltas = delta.tool_calls or []
    for tc_d in raw_tc_deltas:
        func = tc_d.function
        tool_updates.append({
            "index": tc_d.index,
            "id": tc_d.id,
            "name": func.name,
            "arguments": func.arguments,
        })
    return content_piece, tool_updates


__all__ = [
    "HuggingFaceProvider",
    "UsageInfo",
]
