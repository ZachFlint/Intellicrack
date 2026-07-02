# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Local Transformers provider with Intel XPU acceleration.

This module provides a local LLM provider using HuggingFace Transformers with Intel XPU (Arc B580) acceleration via PyTorch 2.5+ native
torch.xpu.
"""

from __future__ import annotations

import asyncio
import gc
import json
import os
import re
import time
import uuid
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, cast, override

import httpx

from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolDefinition,
)
from intellicrack.providers.base import LLMProviderBase, UsageInfo, create_openai_tool_schema
from intellicrack.providers.model_loader import (
    RECOMMENDED_MODELS_B580,
    DtypeOption,
    LoadedModel,
    ModelCache,
    ModelConfig,
    clear_global_cache,
    estimate_model_memory,
    get_global_model_cache,
    load_model_for_cpu,
    load_model_for_xpu,
)
from intellicrack.providers.xpu_utils import (
    check_windows_requirements,
    clear_xpu_cache,
    get_xpu_device_info,
    get_xpu_memory_info,
    is_arc_b580,
    is_xpu_available,
)


try:
    import torch as _torch
except ImportError:
    get_logger(__name__).warning(
        "torch_import_unavailable",
        impact="local transformer inference is disabled; install pytorch to enable",
    )
    _torch = None

try:
    from transformers import (
        AutoModelForCausalLM as _AutoModelForCausalLM,
        AutoTokenizer as _AutoTokenizer,
    )
except ImportError:
    get_logger(__name__).warning(
        "transformers_import_unavailable",
        impact="CUDA model loading is disabled; install the transformers package to enable",
    )
    _AutoModelForCausalLM = None
    _AutoTokenizer = None

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    import torch
    from transformers import PreTrainedModel, PreTrainedTokenizerBase
    from transformers.modeling_outputs import CausalLMOutputWithPast


_logger = get_logger(__name__)

_MSG_NOT_CONNECTED = "Provider not connected"
_MSG_NO_MODEL_LOADED = "No model loaded"
_ERR_EMPTY_MODEL = "model is required and cannot be empty"
_MSG_TORCH_REQUIRED = "torch is required for local model inference"
_MSG_TRANSFORMERS_REQUIRED = "transformers is required for local model inference"
_ERR_LOAD_BOTH_FAILED = "Failed to load model on all attempted devices: %s"
_ERR_LOAD_FAILED = "Failed to load model: %s"
_ERR_INFERENCE_FAILED = "Local inference failed: %s"
_ERR_STREAMING_FAILED = "Local streaming failed: %s"
_ERR_CUDA_NOT_AVAILABLE = "CUDA is not available on this system"

_DEFAULT_MAX_NEW_TOKENS = 2048
_DEFAULT_TEMPERATURE = 0.7

_VISION_ARCHITECTURE_KEYWORDS: frozenset[str] = frozenset({
    "vision",
    "vit",
    "clip",
    "llava",
    "visual",
    "image",
})

_HF_CONFIG_URL = "https://huggingface.co/{model_id}/resolve/main/config.json"

_HF_TOKEN_ENV_VARS: tuple[str, ...] = (
    "LOCAL_TRANSFORMERS_HF_TOKEN",
    "HUGGINGFACE_API_TOKEN",
    "HF_TOKEN",
    "HUGGINGFACE_HUB_TOKEN",
)


def _resolve_hf_token(explicit_token: str | None = None) -> str | None:
    """Resolve a HuggingFace access token from an explicit value or the environment.

    Prefers a token supplied by the caller (typically the provider's
    configured credentials). When none is given, the standard HuggingFace
    environment variables are consulted in priority order so that gated
    repositories remain reachable even when only the Hub-native variables
    are set.

    Args:
        explicit_token: Token supplied by the caller, or None to fall back to the environment.

    Returns:
        str | None: The first non-empty token found, or None when no token is available.
    """
    if explicit_token:
        return explicit_token
    for var in _HF_TOKEN_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return None


async def _fetch_model_config(model_id: str, token: str | None = None) -> dict[str, Any]:
    """Fetch model config.json from HuggingFace Hub.

    Redirects are followed so that the Hub's ``307`` hand-off to its
    resolve-cache CDN succeeds, and a bearer token is attached when one is
    available so that gated repositories can be read.

    Args:
        model_id: HuggingFace model identifier (e.g. "microsoft/Phi-3-mini-4k-instruct").
        token: Optional HuggingFace access token; falls back to the environment when None.

    Returns:
        dict[str, Any]: Parsed config dict, or empty dict on failure.
    """
    url = _HF_CONFIG_URL.format(model_id=model_id)
    resolved_token = _resolve_hf_token(token)
    headers: dict[str, str] = {"Authorization": f"Bearer {resolved_token}"} if resolved_token else {}
    _logger.debug(
        "huggingface_config_fetch_started",
        model_id=model_id,
        url=url,
        authenticated=bool(resolved_token),
    )
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            headers=headers,
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            _logger.debug("huggingface_config_fetch_completed", model_id=model_id, key_count=len(result))
            return result
    except (ConnectionError, TimeoutError, OSError, httpx.HTTPError, ValueError) as exc:
        _logger.warning("huggingface_config_fetch_failed", url=url, error=str(exc))
        return {}


def _classify_model_capabilities(
    config: dict[str, Any],
) -> tuple[int, bool]:
    """Extract context window and vision support from a HuggingFace config.

    Args:
        config: Parsed config.json dict from HuggingFace Hub.

    Returns:
        tuple[int, bool]: Tuple of (context_window, supports_vision).
    """
    context_window = 4096
    for key in ("max_position_embeddings", "max_sequence_length", "n_positions"):
        val = config.get(key)
        if isinstance(val, int) and val > 0:
            context_window = val
            break

    supports_vision = False
    architectures: list[str] = config.get("architectures", [])
    for arch in architectures:
        arch_lower = arch.lower()
        if any(kw in arch_lower for kw in _VISION_ARCHITECTURE_KEYWORDS):
            supports_vision = True
            break

    if not supports_vision and ("vision_config" in config or "image_size" in config):
        supports_vision = True

    return context_window, supports_vision


class LocalTransformersProvider(LLMProviderBase):
    """Local Transformers provider with Intel XPU/CPU inference.

    Provides local LLM inference using HuggingFace Transformers models with automatic Intel XPU acceleration when available, falling back to
    CPU when XPU is unavailable.
    """

    def __init__(
        self,
        model_cache: ModelCache | None = None,
        *,
        prefer_xpu: bool = True,
    ) -> None:
        """Initialize the LocalTransformersProvider with optional cache and device preferences.

        Args:
            model_cache: Optional model cache instance. Uses the global cache if None.
            prefer_xpu: Whether to prefer Intel XPU acceleration over CPU when available.
        """
        super().__init__()
        self._model_cache = model_cache or get_global_model_cache()
        self._prefer_xpu = prefer_xpu
        self._loaded_model: LoadedModel | None = None
        self._device_type: Literal["cuda", "xpu", "cpu"] = "cpu"
        self._cuda_available = False
        self._xpu_available = False
        self._is_arc_b580 = False
        self._windows_warnings: list[str] = []
        self._logger = get_logger(__name__).bind(provider="local_transformers")
        self._logger.info("local_transformers_provider_initialized", prefer_xpu=prefer_xpu)

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName: ProviderName.LOCAL_TRANSFORMERS
        """
        return ProviderName.LOCAL_TRANSFORMERS

    @property
    def device_type(self) -> str:
        """Get the current device type.

        Returns:
            str: "cuda", "xpu", or "cpu" depending on what's being used.
        """
        return self._device_type

    @property
    def cuda_available(self) -> bool:
        """Check if CUDA is available.

        Returns:
            bool: True if at least one CUDA-capable GPU is available.
        """
        return self._cuda_available

    @property
    def xpu_available(self) -> bool:
        """Check if XPU is available.

        Returns:
            bool: True if XPU is available and usable.
        """
        return self._xpu_available

    @property
    def is_b580_detected(self) -> bool:
        """Check if an Arc B580 is detected.

        Returns:
            bool: True if an Arc B580 GPU is detected.
        """
        return self._is_arc_b580

    @property
    def current_model_id(self) -> str | None:
        """Get the currently loaded model ID.

        Returns:
            str | None: Model ID or None if no model is loaded.
        """
        return self._loaded_model.model_id if self._loaded_model else None

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the local transformers provider.

        Probes available compute backends in deterministic order and
        selects the first usable one: CUDA, then XPU (when the Intel
        extension is present and ``prefer_xpu`` is True), then CPU.
        No API key is required for local inference.

        Args:
            credentials: Provider credentials (not used for local inference).

        Raises:
            ProviderError: If ``torch`` is not installed, since local
                inference cannot proceed without it.
        """
        self._credentials = credentials

        if _torch is None:
            self._logger.warning(
                "local_transformers_connect_torch_missing",
                remedy="install pytorch to enable local transformer inference",
            )
            raise ProviderError(_MSG_TORCH_REQUIRED)

        self._cuda_available = await asyncio.to_thread(self._probe_cuda)
        self._xpu_available = await asyncio.to_thread(is_xpu_available)
        self._is_arc_b580 = await asyncio.to_thread(is_arc_b580)

        self._device_type = self._select_device()

        if self._device_type == "cuda":
            self._logger.info(
                "cuda_selected",
                device_type=self._device_type,
                device_count=self._cuda_device_count(),
            )
        elif self._device_type == "xpu":
            _, warnings = await asyncio.to_thread(check_windows_requirements)
            self._windows_warnings = warnings

            for warning in warnings:
                self._logger.warning("xpu_requirement_warning", warning=warning)

            if self._is_arc_b580:
                device_info = await asyncio.to_thread(get_xpu_device_info, 0)
                if device_info:
                    self._logger.info(
                        "xpu_connected_b580",
                        device_name=device_info.device_name,
                        memory_gb=device_info.total_memory_bytes / (1024**3),
                        driver=device_info.driver_version,
                    )
            else:
                self._logger.info("xpu_selected", device_type=self._device_type)
        elif self._xpu_available and not self._prefer_xpu:
            self._logger.info("cpu_selected_preference", device_type="cpu")
        elif self._cuda_available or self._xpu_available:
            self._logger.info("cpu_selected_fallback", device_type="cpu")
        else:
            self._logger.info("cpu_selected_no_accelerator", device_type="cpu")

        self.connected = True
        self._logger.info(
            "local_transformers_connected",
            device_type=self._device_type,
            cuda_available=self._cuda_available,
            xpu_available=self._xpu_available,
            is_arc_b580=self._is_arc_b580,
        )

    def _select_device(self) -> Literal["cuda", "xpu", "cpu"]:
        """Choose the target compute backend in deterministic order.

        The selection order is CUDA first, then XPU (when
        ``prefer_xpu`` is True and the Intel extension exposes
        ``torch.xpu``), then CPU.  XPU availability is guarded by
        ``getattr(torch, "xpu", None)`` because the attribute is only
        present when the Intel extension is installed.

        Returns:
            Literal["cuda", "xpu", "cpu"]: The selected backend.
        """
        if self._cuda_available:
            return "cuda"
        if self._xpu_available and self._prefer_xpu and _torch is not None and getattr(_torch, "xpu", None) is not None:
            return "xpu"
        return "cpu"

    @staticmethod
    def _probe_cuda() -> bool:
        """Safely probe whether CUDA is available.

        Returns:
            bool: True when ``torch`` is importable and at least one
            CUDA-capable device is present; False otherwise or on
            probe failure.
        """
        if _torch is None:
            return False
        try:
            cuda_module = getattr(_torch, "cuda", None)
            if cuda_module is None:
                return False
            is_available = cuda_module.is_available()
            return bool(is_available)
        except (RuntimeError, OSError, AttributeError) as exc:
            _logger.warning("cuda_probe_failed", error=str(exc))
            return False

    @staticmethod
    def _cuda_device_count() -> int:
        """Return the number of CUDA devices available.

        Returns:
            int: The count of CUDA-capable devices, or 0 when CUDA
            cannot be probed.
        """
        if _torch is None:
            return 0
        try:
            cuda_module = getattr(_torch, "cuda", None)
            if cuda_module is None:
                return 0
            count = int(cuda_module.device_count())
        except (RuntimeError, OSError, AttributeError, ValueError) as exc:
            _logger.warning("cuda_device_count_failed", error=str(exc))
            return 0
        else:
            return count

    async def disconnect(self) -> None:
        """Disconnect from the provider and cleanup resources.

        Releases the loaded model, clears any device-side KV caches captured during generation, empties the XPU/CUDA allocator caches when
        applicable, and finally forwards to the base disconnect implementation.  All errors are logged rather than propagated so the caller
        always observes a disconnected state.
        """
        try:
            if self._loaded_model is not None:
                self._loaded_model = None

            await asyncio.to_thread(self._release_device_caches)

            await super().disconnect()
            self._logger.info("local_transformers_disconnected", device_type=self._device_type)
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as exc:
            self._logger.warning("disconnect_cleanup_error", error=str(exc))
            self.connected = False

    def _release_device_caches(self) -> None:
        """Drop device-side allocator caches and run a GC pass.

        Clears the XPU allocator cache when the selected device is XPU, the CUDA allocator cache when the device is CUDA, and always
        triggers a ``gc.collect()`` afterwards so KV-cache tensors referenced by Python objects can be freed.
        """
        if self._device_type == "xpu":
            clear_xpu_cache()
        elif self._device_type == "cuda" and _torch is not None:
            try:
                cuda_module = getattr(_torch, "cuda", None)
                if cuda_module is not None and cuda_module.is_available():
                    empty_cache = getattr(cuda_module, "empty_cache", None)
                    if callable(empty_cache):
                        empty_cache()
            except (RuntimeError, OSError, AttributeError) as exc:
                _logger.warning("cuda_cache_clear_failed", error=str(exc))
        gc.collect()

    async def list_models(self) -> list[ModelInfo]:
        """List local models that fit on the available hardware.

        When running on XPU the total VRAM is queried once and models
        whose estimated memory footprint exceeds 90 % of that VRAM are
        excluded.  On CPU all recommended models are returned because
        system RAM is assumed to be sufficient (the loader will still
        fail gracefully if it is not).

        Returns:
            list[ModelInfo]: List of ``ModelInfo`` objects for models that can be loaded
            on the current device.

        Raises:
            ProviderError: If the provider is not connected.
        """
        if not self.connected:
            self._logger.warning("local_transformers_list_models_not_connected")
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._logger.info("local_list_models_started", device_type=self._device_type)
        vram_utilisation_ceiling: float = 0.9

        total_vram: int = 0
        if self._device_type == "xpu":
            _, total_vram = await asyncio.to_thread(get_xpu_memory_info, 0)

        usable_vram: int = int(total_vram * vram_utilisation_ceiling) if total_vram > 0 else 0

        eligible_models: list[str] = []

        for model_data in RECOMMENDED_MODELS_B580:
            model_id = str(model_data["model_id"])
            recommended_dtype = str(model_data.get("recommended_dtype", "float16"))

            if self._device_type == "xpu" and usable_vram > 0:
                estimated = estimate_model_memory(model_id, cast("DtypeOption", recommended_dtype))
                if estimated > usable_vram:
                    self._logger.debug(
                        "model_excluded_insufficient_vram",
                        model_id=model_id,
                        estimated_bytes=estimated,
                        available_bytes=usable_vram,
                    )
                    continue

            eligible_models.append(model_id)

        hf_token = self._credentials.api_key if self._credentials else None
        configs = await asyncio.gather(
            *(_fetch_model_config(mid, token=hf_token) for mid in eligible_models),
            return_exceptions=True,
        )

        models: list[ModelInfo] = []
        for model_id, config_result in zip(eligible_models, configs, strict=True):
            config = config_result if isinstance(config_result, dict) else {}
            context_window, supports_vision = _classify_model_capabilities(config)

            models.append(
                ModelInfo(
                    id=model_id,
                    name=f"[Local] {model_id.rsplit('/', maxsplit=1)[-1]}",
                    provider=ProviderName.LOCAL_TRANSFORMERS,
                    context_window=context_window,
                    supports_tools=True,
                    supports_vision=supports_vision,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                ),
            )

        return models

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = _DEFAULT_TEMPERATURE,
        max_tokens: int = _DEFAULT_MAX_NEW_TOKENS,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request.

        Args:
            messages: Conversation history.
            model: Model ID to use (HuggingFace model identifier).
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools (ignored locally).
            thinking: Extended thinking configuration (ignored locally).
            enable_cache: Whether to enable prompt caching (ignored locally).

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self.connected:
            self._logger.warning(
                "local_transformers_chat_not_connected",
                provider="local_transformers",
                model=model,
            )
            raise ProviderError(_MSG_NOT_CONNECTED)

        if not model:
            self._logger.warning(
                "local_transformers_chat_empty_model",
                provider="local_transformers",
            )
            raise ProviderError(_ERR_EMPTY_MODEL)

        self._cancel_requested = False
        if tool_choice is not None:
            self._logger.debug("local_transformers_tool_choice_ignored", mode=tool_choice.mode.value)
        if thinking is not None and thinking.enabled:
            self._logger.debug("local_transformers_thinking_ignored")
        if enable_cache:
            self._logger.debug("local_transformers_cache_ignored")

        model_id = model

        await self._ensure_model_loaded(model_id)

        if self._loaded_model is None:
            self._logger.warning(
                "local_transformers_chat_model_missing",
                provider="local_transformers",
                model=model_id,
            )
            raise ProviderError(_MSG_NO_MODEL_LOADED)

        start_time = time.perf_counter()

        try:
            message, tool_calls = await self._run_local_chat(
                messages=messages,
                model_id=model_id,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                start_time=start_time,
            )
        except (RuntimeError, ImportError, ValueError, OSError) as exc:
            self._logger.warning("local_chat_failed", model=model_id, error=str(exc))
            raise ProviderError(_ERR_INFERENCE_FAILED % exc) from exc
        else:
            return message, tool_calls

    async def _run_local_chat(
        self,
        *,
        messages: list[Message],
        model_id: str,
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
        start_time: float,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Generate a non-streaming local chat completion.

        Args:
            messages: Conversation history.
            model_id: Model identifier currently loaded.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            start_time: ``time.perf_counter()`` reference captured before
                generation began.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (assistant
            message, tool calls if any).
        """
        formatted_messages = self._convert_messages_to_provider_format(messages)
        prompt = self._format_prompt(formatted_messages, tools)

        response_text, prompt_tokens, completion_tokens = await asyncio.to_thread(
            self._generate_sync,
            prompt,
            temperature,
            max_tokens,
        )

        self._pending_usage = UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

        tool_calls: list[ToolCall] | None = None
        if tools:
            tool_calls = self._parse_tool_calls(response_text)
            if tool_calls:
                response_text = self._extract_text_before_tool_call(response_text)

        duration_ms = (time.perf_counter() - start_time) * 1000

        message = Message(
            role="assistant",
            content=response_text,
            tool_calls=tool_calls,
            timestamp=datetime.now(tz=UTC),
        )

        self._logger.info(
            "local_chat_completed",
            model=model_id,
            device=self._device_type,
            duration_ms=duration_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            has_tool_calls=tool_calls is not None,
        )
        return message, tool_calls

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = _DEFAULT_TEMPERATURE,
        max_tokens: int = _DEFAULT_MAX_NEW_TOKENS,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response.

        After streaming completes, accumulated text is parsed for tool
        calls when tools are provided.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.
            tool_choice: How the model should select tools (ignored locally).
            thinking: Extended thinking configuration (ignored locally).
            enable_cache: Whether to enable prompt caching (ignored locally).

        Yields:
            str: Text chunks as they are generated.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self.connected:
            self._logger.warning(
                "local_transformers_stream_not_connected",
                provider="local_transformers",
                model=model,
            )
            raise ProviderError(_MSG_NOT_CONNECTED)

        if not model:
            self._logger.warning(
                "local_transformers_stream_empty_model",
                provider="local_transformers",
            )
            raise ProviderError(_ERR_EMPTY_MODEL)

        self._cancel_requested = False
        if tool_choice is not None:
            self._logger.debug("local_stream_tool_choice_ignored", mode=tool_choice.mode.value)
        if thinking is not None and thinking.enabled:
            self._logger.debug("local_stream_thinking_ignored")
        if enable_cache:
            self._logger.debug("local_stream_cache_ignored")

        model_id = model

        await self._ensure_model_loaded(model_id)

        if self._loaded_model is None:
            self._logger.warning(
                "local_transformers_stream_model_missing",
                provider="local_transformers",
                model=model_id,
            )
            raise ProviderError(_MSG_NO_MODEL_LOADED)

        try:
            async for chunk in self._iter_local_stream(
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            ):
                yield chunk
        except (RuntimeError, ImportError, ValueError, OSError) as exc:
            if not self._cancel_requested:
                self._logger.warning("local_stream_failed", model=model_id, error=str(exc))
                raise ProviderError(_ERR_STREAMING_FAILED % exc) from exc

    async def _iter_local_stream(
        self,
        *,
        messages: list[Message],
        tools: list[ToolDefinition] | None,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Generate the local streaming chunks and capture tool calls.

        Updates ``self._pending_tool_calls`` when tool definitions are
        provided and parsed calls are detected in the accumulated text.

        Args:
            messages: Conversation history.
            tools: Available tools for function calling.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Yields:
            str: Text chunks as they are generated.
        """
        formatted_messages = self._convert_messages_to_provider_format(messages)
        prompt = self._format_prompt(formatted_messages, tools)

        accumulated_chunks: list[str] = []
        async for chunk in self._stream_generate(prompt, temperature, max_tokens):
            if self._cancel_requested:
                break
            accumulated_chunks.append(chunk)
            yield chunk

        if tools and not self._cancel_requested:
            full_text = "".join(accumulated_chunks)
            if parsed_calls := self._parse_tool_calls(full_text):
                self._pending_tool_calls = parsed_calls

    async def _ensure_model_loaded(self, model_id: str) -> None:
        """Ensure the specified model is loaded on the selected device.

        Uses the device chosen during ``connect()``.  When the
        selected device fails to load the model, the provider falls
        back one level at a time: CUDA → XPU (if available) → CPU.
        Partial allocations are released on failure before retrying.

        Args:
            model_id: Model to load.

        Raises:
            ProviderError: If model loading fails on all attempted devices.
        """
        if self._loaded_model is not None and self._loaded_model.model_id == model_id:
            return

        config = ModelConfig(
            model_id=model_id,
            dtype="auto",
            device=self._config_device_for(self._device_type),
        )

        try:
            self._loaded_model = await self._load_for_device(self._device_type, config)
            self._logger.info(
                "model_loaded",
                model_id=model_id,
                device=self._device_type,
                dtype=self._loaded_model.dtype,
                load_time_s=self._loaded_model.load_time_seconds,
            )
        except (RuntimeError, ImportError, ValueError, OSError) as exc:
            self._logger.warning("model_load_failed", model_id=model_id, error=str(exc))
            await asyncio.to_thread(self._release_device_caches)

            fallback_chain = self._fallback_chain_for(self._device_type)
            if not fallback_chain:
                raise ProviderError(_ERR_LOAD_FAILED % exc) from exc

            last_error: BaseException = exc
            for next_device in fallback_chain:
                self._logger.warning(
                    "device_fallback",
                    failed_device=self._device_type,
                    next_device=next_device,
                    model_id=model_id,
                )
                self._device_type = next_device
                config = dataclass_replace(config, device=self._config_device_for(next_device))
                try:
                    self._loaded_model = await self._load_for_device(next_device, config)
                except (RuntimeError, ImportError, ValueError, OSError) as fb_exc:
                    last_error = fb_exc
                    await asyncio.to_thread(self._release_device_caches)
                    continue
                self._logger.warning(
                    "model_load_fallback_used",
                    model_id=model_id,
                    device=self._device_type,
                    dtype=self._loaded_model.dtype,
                    load_time_s=self._loaded_model.load_time_seconds,
                )
                return

            self._logger.warning(
                "model_load_all_devices_failed",
                model_id=model_id,
                error=str(last_error),
            )
            raise ProviderError(_ERR_LOAD_BOTH_FAILED % last_error) from last_error

    @staticmethod
    def _config_device_for(device: Literal["cuda", "xpu", "cpu"]) -> Literal["xpu", "cpu", "auto"]:
        """Translate the provider device to the model-loader config device.

        The shared ``ModelConfig`` only understands xpu/cpu/auto values
        that ``load_model_for_xpu`` and ``load_model_for_cpu`` accept.
        CUDA is handled entirely inside the provider by
        ``_load_model_for_cuda``, which reads only the model id, dtype,
        trust_remote_code, and revision fields from the config; the
        config's ``device`` field is therefore reported as ``"cpu"``
        whenever the provider is actually targeting CUDA, so the
        ``ModelConfig`` dataclass validation succeeds.

        Args:
            device: The provider's currently selected backend.

        Returns:
            Literal["xpu", "cpu", "auto"]: The value to place on
            ``ModelConfig.device``.
        """
        return "xpu" if device == "xpu" else "cpu"

    async def _load_for_device(self, device: Literal["cuda", "xpu", "cpu"], config: ModelConfig) -> LoadedModel:
        """Dispatch to the correct model loader for the given device.

        Args:
            device: The target device for loading.
            config: The model configuration to apply.

        Returns:
            LoadedModel: The loaded model bundle ready for inference.
        """
        if device == "xpu":
            return await asyncio.to_thread(load_model_for_xpu, config, self._model_cache)
        if device == "cuda":
            return await asyncio.to_thread(self._load_model_for_cuda, config)
        return await asyncio.to_thread(load_model_for_cpu, config, self._model_cache)

    @staticmethod
    def _fallback_chain_for(current: Literal["cuda", "xpu", "cpu"]) -> list[Literal["cuda", "xpu", "cpu"]]:
        """Return the ordered fallback devices after a load failure.

        Args:
            current: The device that just failed to load the model.

        Returns:
            list[Literal["cuda", "xpu", "cpu"]]: Remaining devices to
            try in order.  CPU is always the terminal fallback.
        """
        if current == "cuda":
            return ["cpu"]
        return ["cpu"] if current == "xpu" else []

    def _load_model_for_cuda(self, config: ModelConfig) -> LoadedModel:
        """Load a causal language model onto a CUDA device.

        Mirrors the structure of ``load_model_for_cpu`` in the model
        loader module but places the model on a CUDA device and
        participates in the provider's shared model cache.  On failure
        the partial CUDA allocation is released before re-raising.

        Args:
            config: Model configuration with ``device`` set to ``"cuda"``.

        Returns:
            LoadedModel: The loaded model bundle.

        Raises:
            ImportError: If torch or transformers are unavailable.
            RuntimeError: If CUDA is not available, or re-raised from
                ``from_pretrained``/``model.to`` when CUDA loading fails.
            OSError: Re-raised from the transformers loader when the model
                files cannot be read or downloaded.
            ValueError: Re-raised from the transformers loader when the
                model configuration is invalid.
        """
        if _torch is None:
            self._logger.error("cuda_load_torch_unavailable", model_id=config.model_id)
            raise ImportError(_MSG_TORCH_REQUIRED)

        cuda_module = getattr(_torch, "cuda", None)
        if cuda_module is None or not cuda_module.is_available():
            self._logger.error("cuda_load_cuda_unavailable", model_id=config.model_id)
            raise RuntimeError(_ERR_CUDA_NOT_AVAILABLE)

        if _AutoModelForCausalLM is None or _AutoTokenizer is None:
            self._logger.error("cuda_load_transformers_unavailable", model_id=config.model_id)
            raise ImportError(_MSG_TRANSFORMERS_REQUIRED)

        cache = self._model_cache
        dtype_str = "float16" if config.dtype == "auto" else config.dtype
        cached = cache.get(config.model_id, dtype_str, "cuda")
        if cached is not None:
            return cached

        torch_dtype_map: dict[str, Any] = {
            "float32": _torch.float32,
            "float16": _torch.float16,
            "bfloat16": _torch.bfloat16,
        }
        torch_dtype = torch_dtype_map.get(dtype_str, _torch.float16)
        device = _torch.device("cuda:0")

        start_time = time.perf_counter()
        tokenizer = _AutoTokenizer.from_pretrained(
            config.model_id,
            trust_remote_code=config.trust_remote_code,
            revision=config.revision,
        )
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        try:
            model = _AutoModelForCausalLM.from_pretrained(
                config.model_id,
                revision=config.revision,
                trust_remote_code=config.trust_remote_code,
                low_cpu_mem_usage=True,
                torch_dtype=torch_dtype,
            )
            model = model.to(device)
            model.eval()
        except (RuntimeError, ImportError, ValueError, OSError) as exc:
            self._logger.warning("cuda_from_pretrained_failed", model_id=config.model_id, error=str(exc))
            try:
                empty_cache = getattr(cuda_module, "empty_cache", None)
                if callable(empty_cache):
                    empty_cache()
            except (RuntimeError, OSError, AttributeError) as cleanup_exc:
                _logger.warning("cuda_cache_clear_after_failure", error=str(cleanup_exc))
            log_passthrough(
                self._logger,
                "cuda_load_model_passthrough",
                exc,
                provider="local_transformers",
                model_id=config.model_id,
            )
            raise

        load_time = time.perf_counter() - start_time
        memory_usage = estimate_model_memory(config.model_id, cast("DtypeOption", dtype_str), include_activations=False)

        loaded_model = LoadedModel(
            model=model,
            tokenizer=tokenizer,
            device=device,
            dtype=dtype_str,
            memory_usage_bytes=memory_usage,
            model_id=config.model_id,
            load_time_seconds=load_time,
        )
        cache.put(loaded_model)
        return loaded_model

    def _generate_sync(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, int, int]:
        """Generate text synchronously.

        Uses ``torch.inference_mode()`` rather than ``no_grad()`` because
        ``inference_mode`` is applied inside the worker thread that
        performs the generation call, ensuring the optimization is
        active for the duration of the forward pass (``no_grad``
        contexts captured on the caller thread do not propagate to
        worker threads).

        Args:
            prompt: Input prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum new tokens.

        Returns:
            tuple[str, int, int]: A tuple of ``(generated text,
            prompt_tokens, completion_tokens)``.

        Raises:
            RuntimeError: If no model is currently loaded.
            ImportError: If torch is not installed.
        """
        if self._loaded_model is None:
            self._logger.error("local_generate_no_model_loaded")
            raise RuntimeError(_MSG_NO_MODEL_LOADED)

        if _torch is None:
            self._logger.error("local_generate_torch_unavailable")
            raise ImportError(_MSG_TORCH_REQUIRED)

        model = self._loaded_model.model
        tokenizer = self._loaded_model.tokenizer
        device = self._loaded_model.device

        inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
        input_ids = inputs["input_ids"].to(device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(device)

        prompt_tokens = int(input_ids.shape[-1])

        with _torch.inference_mode():
            outputs = model.generate(
                input_ids,
                attention_mask=attention_mask,
                max_new_tokens=max_tokens,
                temperature=temperature if temperature > 0 else None,
                do_sample=temperature > 0,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        generated_ids = outputs[0][input_ids.shape[1] :]
        completion_tokens = int(generated_ids.shape[-1])
        response: str = str(tokenizer.decode(generated_ids, skip_special_tokens=True))

        return response.strip(), prompt_tokens, completion_tokens

    async def _stream_generate(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream text generation.

        The per-token forward pass is executed inside
        ``torch.inference_mode()`` within the worker thread itself,
        not on the caller thread.  ``torch.no_grad`` and
        ``inference_mode`` states are thread-local, so they must be
        entered inside the function handed to ``asyncio.to_thread``
        for the optimization to take effect.

        Args:
            prompt: Input prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum new tokens.

        Yields:
            str: Text chunks.

        Raises:
            RuntimeError: If no model is currently loaded.
            ImportError: If torch is not installed.
        """
        if self._loaded_model is None:
            self._logger.error("local_stream_generate_no_model_loaded")
            raise RuntimeError(_MSG_NO_MODEL_LOADED)

        if _torch is None:
            self._logger.error("local_stream_generate_torch_unavailable")
            raise ImportError(_MSG_TORCH_REQUIRED)

        model = self._loaded_model.model
        tokenizer = self._loaded_model.tokenizer
        device = self._loaded_model.device

        inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
        input_ids = inputs["input_ids"].to(device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(device)

        prompt_tokens = int(input_ids.shape[-1])

        generated_ids = input_ids.clone()
        past_key_values: tuple[tuple[torch.Tensor, ...], ...] | None = None

        def _forward_pass(
            fwd_model: PreTrainedModel,
            fwd_gen_ids: torch.Tensor,
            fwd_attn_mask: torch.Tensor | None,
            fwd_past_kv: tuple[tuple[torch.Tensor, ...], ...] | None,
        ) -> CausalLMOutputWithPast:
            """Run a single causal language model forward pass.

            The ``torch.inference_mode`` context is entered inside this
            function so the optimization applies inside the worker
            thread spawned by ``asyncio.to_thread``.

            Args:
                fwd_model: Loaded causal language model to invoke.
                fwd_gen_ids: Token ids generated so far for the sequence.
                fwd_attn_mask: Optional attention mask aligned with the
                    generated ids, or ``None`` to skip masking.
                fwd_past_kv: Cached key/value tensors from prior steps;
                    when present, only the latest token id is evaluated.

            Returns:
                CausalLMOutputWithPast: The model output including logits
                and the updated past key/value cache.

            Raises:
                ImportError: If ``torch`` is not installed.
            """
            if _torch is None:
                _logger.error("forward_pass_torch_unavailable")
                raise ImportError(_MSG_TORCH_REQUIRED)
            use_ids = fwd_gen_ids[:, -1:] if fwd_past_kv else fwd_gen_ids
            with _torch.inference_mode():
                return fwd_model(
                    input_ids=use_ids,
                    attention_mask=fwd_attn_mask,
                    past_key_values=fwd_past_kv,
                    use_cache=True,
                )

        completion_counter = [0]
        try:
            async for token_text in self._iter_local_generation_loop(
                model=model,
                tokenizer=tokenizer,
                generated_ids=generated_ids,
                attention_mask=attention_mask,
                past_key_values=past_key_values,
                max_tokens=max_tokens,
                temperature=temperature,
                forward_pass=_forward_pass,
                completion_counter=completion_counter,
            ):
                yield token_text
        finally:
            past_key_values = None
            self._pending_usage = UsageInfo(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_counter[0],
                total_tokens=prompt_tokens + completion_counter[0],
            )

    async def _iter_local_generation_loop(
        self,
        *,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
        generated_ids: torch.Tensor,
        attention_mask: torch.Tensor | None,
        past_key_values: tuple[tuple[torch.Tensor, ...], ...] | None,
        max_tokens: int,
        temperature: float,
        forward_pass: Callable[
            [
                PreTrainedModel,
                torch.Tensor,
                torch.Tensor | None,
                tuple[tuple[torch.Tensor, ...], ...] | None,
            ],
            CausalLMOutputWithPast,
        ],
        completion_counter: list[int],
    ) -> AsyncIterator[str]:
        """Run the autoregressive decoding loop and yield decoded tokens.

        Args:
            model: The loaded causal LM.
            tokenizer: Tokenizer associated with ``model``.
            generated_ids: Token ids generated so far for the sequence.
            attention_mask: Optional attention mask aligned with the
                generated ids, or ``None`` to skip masking.
            past_key_values: Cached key/value tensors from prior steps.
            max_tokens: Maximum number of new tokens to generate.
            temperature: Sampling temperature; ``0`` selects greedy
                argmax decoding.
            forward_pass: Forward-pass callable invoked via
                ``asyncio.to_thread``.
            completion_counter: Single-element list mutated with the
                number of tokens generated so the caller can populate
                usage in its ``finally`` block.

        Yields:
            str: Decoded token text for each generated token.

        Raises:
            ImportError: If ``torch`` is not installed.
        """
        if _torch is None:
            self._logger.error(
                "local_transformers_generation_torch_unavailable",
                provider="local_transformers",
                max_tokens=max_tokens,
            )
            raise ImportError(_MSG_TORCH_REQUIRED)
        for _ in range(max_tokens):
            if self._cancel_requested:
                break

            outputs = await asyncio.to_thread(
                forward_pass,
                model,
                generated_ids,
                attention_mask,
                past_key_values,
            )

            logits = outputs.logits[:, -1, :]
            past_key_values = outputs.past_key_values

            if temperature > 0:
                probs = _torch.softmax(logits / temperature, dim=-1)
                next_token = _torch.multinomial(probs, num_samples=1)
            else:
                next_token = logits.argmax(dim=-1, keepdim=True)

            if next_token.item() == tokenizer.eos_token_id:
                break

            generated_ids = _torch.cat([generated_ids, next_token], dim=-1)
            completion_counter[0] += 1

            if attention_mask is not None:
                attention_mask = _torch.cat(
                    [attention_mask, _torch.ones((1, 1), device=generated_ids.device)],
                    dim=-1,
                )

            token_text = tokenizer.decode(next_token[0], skip_special_tokens=True)
            if token_text:
                yield token_text

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Convert internal messages to a generic format.

        Args:
            messages: List of Message objects.

        Returns:
            list[dict[str, object]]: List of message dictionaries.
        """
        result: list[dict[str, object]] = []

        for msg in messages:
            msg_dict: dict[str, object] = {
                "role": msg.role,
                "content": msg.content,
            }

            if msg.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "function": {
                            "name": tc.function_name,
                            "arguments": tc.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]

            if msg.tool_results:
                msg_dict["tool_results"] = [
                    {
                        "call_id": tr.call_id,
                        "result": tr.result,
                        "success": tr.success,
                    }
                    for tr in msg.tool_results
                ]

            result.append(msg_dict)

        return result

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Convert tools to a generic format.

        Args:
            tools: List of ToolDefinition objects.

        Returns:
            list[dict[str, object]]: List of tool dictionaries.
        """
        result: list[dict[str, object]] = []
        for tool in tools:
            tool_schemas = create_openai_tool_schema(tool)
            result.extend(dict(schema) for schema in tool_schemas)
        return result

    def _format_prompt(
        self,
        messages: list[dict[str, object]],
        tools: list[ToolDefinition] | None = None,
    ) -> str:
        """Format messages into a prompt string using the tokenizer's chat template.

        Uses ``tokenizer.apply_chat_template`` when available so every
        model family (Phi-3, Llama-3, Mistral, Qwen, TinyLlama/ChatML,
        etc.) receives correctly formatted special tokens.  Falls back
        to a generic ChatML-style template when the tokenizer does not
        ship one.

        Args:
            messages: List of message dictionaries with ``"role"`` and
                ``"content"`` keys as produced by
                ``_convert_messages_to_provider_format``.
            tools: Optional tool definitions to inject into the system
                prompt so the model is aware of callable functions.

        Returns:
            str: Fully formatted prompt string ready for tokenization.
        """
        chat_messages = self._build_chat_messages(messages, tools)

        if self._loaded_model is not None:
            tokenizer = self._loaded_model.tokenizer
            chat_template = getattr(tokenizer, "chat_template", None)
            if hasattr(tokenizer, "apply_chat_template") and chat_template is not None:
                try:
                    result: str | list[int] = tokenizer.apply_chat_template(
                        chat_messages,
                        tokenize=False,
                        add_generation_prompt=True,
                    )
                    return str(result)
                except (ValueError, KeyError, TypeError, AttributeError) as exc:
                    self._logger.warning(
                        "chat_template_failed_using_fallback",
                        error=str(exc),
                    )

        return self._format_prompt_chatml_fallback(chat_messages)

    def _build_chat_messages(
        self,
        messages: list[dict[str, object]],
        tools: list[ToolDefinition] | None = None,
    ) -> list[dict[str, str]]:
        """Build a normalized message list suitable for chat templates.

        Converts the internal message dictionaries into the
        ``[{"role": ..., "content": ...}]`` format that HuggingFace
        ``apply_chat_template`` expects.  Tool schemas are prepended as
        a system message when tools are provided.

        Args:
            messages: List of message dictionaries from
                ``_convert_messages_to_provider_format``.
            tools: Optional tool definitions to expose to the model.

        Returns:
            list[dict[str, str]]: List of ``{"role": str, "content": str}`` dictionaries.
        """
        chat_messages: list[dict[str, str]] = []

        if tools:
            tool_schemas = self._convert_tools_to_provider_format(tools)
            tools_json = json.dumps(tool_schemas, indent=2)
            chat_messages.append({
                "role": "system",
                "content": (
                    "You have access to the following tools:\n"
                    f"{tools_json}\n\n"
                    "To use a tool, respond with JSON in this format:\n"
                    '{"tool_call": {"name": "tool_name", "arguments": {...}}}'
                ),
            })

        for msg in messages:
            role = str(msg.get("role", ""))
            content = str(msg.get("content", ""))

            if role == "tool":
                tool_results_raw = msg.get("tool_results")
                if isinstance(tool_results_raw, list):
                    tool_results_typed = cast("list[dict[str, object]]", tool_results_raw)
                    if parts := [str(tr_dict.get("result", "")) for tr_dict in tool_results_typed]:
                        chat_messages.append({
                            "role": "user",
                            "content": "[Tool Result]\n" + "\n".join(parts),
                        })
            elif role in {"system", "user", "assistant"}:
                chat_messages.append({"role": role, "content": content})

        return chat_messages

    @staticmethod
    def _format_prompt_chatml_fallback(
        chat_messages: list[dict[str, str]],
    ) -> str:
        """Format messages using the ChatML template as a universal fallback.

        ChatML (``<|im_start|>``/``<|im_end|>``) is the most widely
        supported fallback template across open-source models and is
        used when the tokenizer does not ship its own chat template.

        Args:
            chat_messages: Normalized message list from
                ``_build_chat_messages``.

        Returns:
            str: ChatML-formatted prompt string with a trailing generation
            prompt.
        """
        parts: list[str] = []
        for msg in chat_messages:
            role = msg["role"]
            content = msg["content"]
            parts.append(f"<|im_start|>{role}\n{content}<|im_end|>\n")
        parts.append("<|im_start|>assistant\n")
        return "".join(parts)

    _TOOL_CALL_RE: re.Pattern[str] = re.compile(r'\{\s*"tool_call"\s*:')

    @staticmethod
    def _find_tool_call_start(response: str) -> int:
        """Locate the starting index of a ``{"tool_call": ...}`` JSON object.

        Allows whitespace after the opening brace and around the colon so
        instruction-tuned models that pretty-print their JSON output are
        recognised. Returns ``-1`` when no tool-call object is present.

        Args:
            response: Full response text emitted by the local model.

        Returns:
            int: Zero-based index of the opening ``{`` brace, or ``-1``
            when the response does not contain a tool-call object.
        """
        match = LocalTransformersProvider._TOOL_CALL_RE.search(response)
        return -1 if match is None else match.start()

    @staticmethod
    def _parse_tool_calls(response: str) -> list[ToolCall] | None:
        """Parse tool calls from response.

        Args:
            response: Model response text.

        Returns:
            list[ToolCall] | None: List of ToolCall objects or None.
        """
        start_idx = LocalTransformersProvider._find_tool_call_start(response)
        if start_idx == -1:
            return None

        brace_count = 0
        end_idx = start_idx
        in_string = False
        escape_next = False

        for i, char in enumerate(response[start_idx:], start=start_idx):
            if escape_next:
                escape_next = False
                continue
            if char == "\\":
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break

        if brace_count != 0:
            return None

        json_str = response[start_idx:end_idx]

        try:
            return LocalTransformersProvider._build_tool_call_from_json(json_str)
        except json.JSONDecodeError:
            _logger.warning("tool_call_json_decode_failed")
            return None

    @staticmethod
    def _build_tool_call_from_json(json_str: str) -> list[ToolCall] | None:
        """Decode a ``{"tool_call": ...}`` JSON object into ``ToolCall`` entries.

        Any ``json.JSONDecodeError`` raised by the underlying
        ``json.loads`` call propagates to the caller, which handles it.

        Args:
            json_str: Raw JSON string containing the tool-call object.

        Returns:
            list[ToolCall] | None: Single-element list containing the
            parsed tool call, or ``None`` when the object lacks a name.
        """
        data: dict[str, Any] = json.loads(json_str)
        tool_call_data: dict[str, Any] = data.get("tool_call", {})
        name: str = str(tool_call_data.get("name", ""))
        raw_arguments: object = tool_call_data.get("arguments", {})
        parsed_arguments: dict[str, Any] = cast("dict[str, Any]", raw_arguments) if isinstance(raw_arguments, dict) else {}

        if not name:
            return None
        return [
            ToolCall(
                id=f"call_{uuid.uuid4().hex}",
                tool_name=name.split(".", maxsplit=1)[0] if "." in name else name,
                function_name=name,
                arguments=parsed_arguments,
            ),
        ]

    @staticmethod
    def _extract_text_before_tool_call(response: str) -> str:
        """Extract text before tool call JSON.

        Args:
            response: Full response text.

        Returns:
            str: Text before the tool call JSON.
        """
        start_idx = LocalTransformersProvider._find_tool_call_start(response)
        return response if start_idx == -1 else response[:start_idx].strip()

    def get_device_info(self) -> dict[str, object]:
        """Get information about the current device.

        Returns:
            dict[str, object]: Dictionary with device information.
        """
        info: dict[str, object] = {
            "device_type": self._device_type,
            "cuda_available": self._cuda_available,
            "xpu_available": self._xpu_available,
            "is_arc_b580": self._is_arc_b580,
            "warnings": self._windows_warnings,
        }

        if self._device_type == "xpu" and self._xpu_available:
            device_info = get_xpu_device_info(0)
            if device_info is not None:
                info["device_name"] = device_info.device_name
                info["total_memory_gb"] = device_info.total_memory_bytes / (1024**3)
                info["driver_version"] = device_info.driver_version
                info["supports_fp16"] = device_info.supports_fp16
                info["supports_bf16"] = device_info.supports_bf16

            allocated, total = get_xpu_memory_info(0)
            info["allocated_memory_gb"] = allocated / (1024**3)
            if total > 0:
                info["total_memory_gb"] = total / (1024**3)
            elif "total_memory_gb" not in info and device_info is not None:
                info["total_memory_gb"] = device_info.total_memory_bytes / (1024**3)

        if self._loaded_model:
            info["loaded_model"] = self._loaded_model.model_id
            info["model_dtype"] = self._loaded_model.dtype
            info["model_memory_gb"] = self._loaded_model.memory_usage_bytes / (1024**3)

        return info

    async def unload_model(self) -> None:
        """Unload the currently loaded model to free memory.

        Drops the cached model from the shared ``ModelCache``, clears any device-side KV caches (``torch.xpu.empty_cache`` or
        ``torch.cuda.empty_cache``), and triggers a GC pass so tensors that still live in Python frames can be reclaimed.
        """
        if self._loaded_model is not None:
            model_id = self._loaded_model.model_id
            dtype = self._loaded_model.dtype
            device_type = self._device_type
            self._logger.info("unload_model_started", model_id=model_id, dtype=dtype, device_type=device_type)
            self._model_cache.remove(model_id, dtype, device_type)
            self._loaded_model = None

            await asyncio.to_thread(self._release_device_caches)

            self._logger.info("model_unloaded", model_id=model_id)

    def clear_cache(self) -> None:
        """Clear the model cache."""
        clear_global_cache()
        self._logger.info("model_cache_cleared", provider="local_transformers")
