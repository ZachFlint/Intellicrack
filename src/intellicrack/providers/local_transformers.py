# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Local Transformers provider with Intel XPU acceleration.

This module provides a local LLM provider using HuggingFace Transformers
with Intel XPU (Arc B580) acceleration via PyTorch 2.5+ native torch.xpu.
"""

from __future__ import annotations

import asyncio
import gc
import json
import re
import time
import uuid
from dataclasses import replace as dataclass_replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, cast, override

import httpx

from ..core.logging import get_logger
from ..core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
    ToolDefinition,
)
from .base import LLMProviderBase, create_openai_tool_schema
from .model_loader import (
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
from .xpu_utils import (
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
    get_logger("providers.local_transformers").debug("torch_import_unavailable")
    _torch = None

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import torch
    from transformers import PreTrainedModel
    from transformers.modeling_outputs import CausalLMOutputWithPast


_logger = get_logger("providers.local_transformers")

_MSG_NOT_CONNECTED = "Provider not connected"
_MSG_NO_MODEL_LOADED = "No model loaded"
_MSG_TORCH_REQUIRED = "torch is required for local model inference"
_ERR_LOAD_BOTH_FAILED = "Failed to load model on both XPU and CPU: %s"
_ERR_LOAD_FAILED = "Failed to load model: %s"
_ERR_INFERENCE_FAILED = "Local inference failed: %s"
_ERR_STREAMING_FAILED = "Local streaming failed: %s"

_DEFAULT_MODEL = "microsoft/Phi-3-mini-4k-instruct"
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


async def _fetch_model_config(model_id: str) -> dict[str, Any]:
    """Fetch model config.json from HuggingFace Hub.

    Args:
        model_id: HuggingFace model identifier (e.g. "microsoft/Phi-3-mini-4k-instruct").

    Returns:
        Parsed config dict, or empty dict on failure.
    """
    url = _HF_CONFIG_URL.format(model_id=model_id)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            response = await client.get(url)
            response.raise_for_status()
            result: dict[str, Any] = response.json()
            return result
    except Exception:
        _logger.debug("huggingface_config_fetch_failed", exc_info=True, extra={"url": url})
        return {}


def _classify_model_capabilities(
    config: dict[str, Any],
) -> tuple[int, bool]:
    """Extract context window and vision support from a HuggingFace config.

    Args:
        config: Parsed config.json dict from HuggingFace Hub.

    Returns:
        Tuple of (context_window, supports_vision).
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

    Provides local LLM inference using HuggingFace Transformers models
    with automatic Intel XPU acceleration when available, falling back
    to CPU when XPU is unavailable.

    Attributes:
        device_type: Current device type ("xpu" or "cpu").
        xpu_available: Whether XPU is available.
        is_arc_b580: Whether an Arc B580 is detected.
        current_model_id: Currently loaded model ID.
    """

    def __init__(
        self,
        model_cache: ModelCache | None = None,
        prefer_xpu: bool = True,
    ) -> None:
        """Initialize the Local Transformers provider.

        Args:
            model_cache: Optional model cache. Uses global cache if None.
            prefer_xpu: Whether to prefer XPU over CPU when available.
        """
        super().__init__()
        self._model_cache = model_cache or get_global_model_cache()
        self._prefer_xpu = prefer_xpu
        self._loaded_model: LoadedModel | None = None
        self._device_type: Literal["xpu", "cpu"] = "cpu"
        self._xpu_available = False
        self._is_arc_b580 = False
        self._windows_warnings: list[str] = []
        self._logger = _logger

    @property
    def name(self) -> ProviderName:
        """Get the provider's name.

        Returns:
            ProviderName.LOCAL_TRANSFORMERS
        """
        return ProviderName.LOCAL_TRANSFORMERS

    @property
    def device_type(self) -> str:
        """Get the current device type.

        Returns:
            "xpu" or "cpu" depending on what's being used.
        """
        return self._device_type

    @property
    def xpu_available(self) -> bool:
        """Check if XPU is available.

        Returns:
            True if XPU is available and usable.
        """
        return self._xpu_available

    @property
    def is_b580_detected(self) -> bool:
        """Check if an Arc B580 is detected.

        Returns:
            True if an Arc B580 GPU is detected.
        """
        return self._is_arc_b580

    @property
    def current_model_id(self) -> str | None:
        """Get the currently loaded model ID.

        Returns:
            Model ID or None if no model is loaded.
        """
        return self._loaded_model.model_id if self._loaded_model else None

    async def connect(self, credentials: ProviderCredentials) -> None:
        """Connect to the local transformers provider.

        Initializes XPU detection and validates system requirements.
        No API key is required for local inference.

        Args:
            credentials: Provider credentials (not used for local inference).
        """
        self._credentials = credentials

        self._xpu_available = await asyncio.to_thread(is_xpu_available)
        self._is_arc_b580 = await asyncio.to_thread(is_arc_b580)

        if self._xpu_available and self._prefer_xpu:
            self._device_type = "xpu"

            _, warnings = await asyncio.to_thread(check_windows_requirements)
            self._windows_warnings = warnings

            for warning in warnings:
                self._logger.warning("xpu_requirement_warning", extra={"warning": warning})

            if self._is_arc_b580:
                device_info = await asyncio.to_thread(get_xpu_device_info, 0)
                if device_info:
                    self._logger.info(
                        "xpu_connected_b580",
                        extra={
                            "device_name": device_info.device_name,
                            "memory_gb": device_info.total_memory_bytes / (1024**3),
                            "driver": device_info.driver_version,
                        },
                    )
            else:
                self._logger.info("xpu_connected", extra={"device_type": self._device_type})
        else:
            self._device_type = "cpu"
            if not self._xpu_available:
                self._logger.info("xpu_not_available_using_cpu", extra={"device_type": "cpu"})
            else:
                self._logger.info("cpu_preferred_over_xpu", extra={"device_type": "cpu"})

        self._connected = True
        self._logger.info(
            "local_transformers_connected",
            extra={
                "device_type": self._device_type,
                "xpu_available": self._xpu_available,
                "is_arc_b580": self._is_arc_b580,
            },
        )

    async def disconnect(self) -> None:
        """Disconnect from the provider and cleanup resources."""
        try:
            if self._loaded_model is not None:
                self._loaded_model = None

            if self._device_type == "xpu":
                await asyncio.to_thread(clear_xpu_cache)

            await super().disconnect()
            self._logger.info("local_transformers_disconnected", extra={"device_type": self._device_type})
        except Exception as exc:
            self._logger.warning("disconnect_cleanup_error", extra={"error": str(exc)})
            self._connected = False

    async def list_models(self) -> list[ModelInfo]:
        """List local models that fit on the available hardware.

        When running on XPU the total VRAM is queried once and models
        whose estimated memory footprint exceeds 90 % of that VRAM are
        excluded.  On CPU all recommended models are returned because
        system RAM is assumed to be sufficient (the loader will still
        fail gracefully if it is not).

        Returns:
            List of ``ModelInfo`` objects for models that can be loaded
            on the current device.

        Raises:
            ProviderError: If the provider is not connected.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

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
                        extra={
                            "model_id": model_id,
                            "estimated_bytes": estimated,
                            "available_bytes": usable_vram,
                        },
                    )
                    continue

            eligible_models.append(model_id)

        configs = await asyncio.gather(
            *(_fetch_model_config(mid) for mid in eligible_models),
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
                    supports_tools=False,
                    supports_vision=supports_vision,
                    supports_streaming=True,
                    input_cost_per_1m_tokens=None,
                    output_cost_per_1m_tokens=None,
                )
            )

        return models

    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = _DEFAULT_TEMPERATURE,
        max_tokens: int = _DEFAULT_MAX_NEW_TOKENS,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Send a chat completion request.

        Args:
            messages: Conversation history.
            model: Model ID to use (HuggingFace model identifier).
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.

        Returns:
            Tuple of (assistant message, tool calls if any).

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

        model_id = model or _DEFAULT_MODEL

        await self._ensure_model_loaded(model_id)

        if self._loaded_model is None:
            raise ProviderError(_MSG_NO_MODEL_LOADED)

        start_time = time.perf_counter()

        try:
            formatted_messages = self._convert_messages_to_provider_format(messages)
            prompt = self._format_prompt(formatted_messages, tools)

            response_text = await asyncio.to_thread(
                self._generate_sync,
                prompt,
                temperature,
                max_tokens,
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
                timestamp=datetime.now(),
            )

            self._logger.info(
                "local_chat_completed",
                extra={
                    "model": model_id,
                    "device": self._device_type,
                    "duration_ms": duration_ms,
                    "has_tool_calls": tool_calls is not None,
                },
            )
        except Exception as exc:
            self._logger.exception("local_chat_failed", extra={"model": model_id, "error": str(exc)})
            raise ProviderError(_ERR_INFERENCE_FAILED % exc) from exc
        else:
            return message, tool_calls

    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = _DEFAULT_TEMPERATURE,
        max_tokens: int = _DEFAULT_MAX_NEW_TOKENS,
    ) -> AsyncIterator[str]:
        """Stream a chat completion response.

        Args:
            messages: Conversation history.
            model: Model ID to use.
            tools: Available tools for function calling.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in response.

        Yields:
            Text chunks as they are generated.

        Raises:
            ProviderError: If not connected or request fails.
        """
        if not self._connected:
            raise ProviderError(_MSG_NOT_CONNECTED)

        self._cancel_requested = False

        model_id = model or _DEFAULT_MODEL

        await self._ensure_model_loaded(model_id)

        if self._loaded_model is None:
            raise ProviderError(_MSG_NO_MODEL_LOADED)

        try:
            formatted_messages = self._convert_messages_to_provider_format(messages)
            prompt = self._format_prompt(formatted_messages, tools)

            async for chunk in self._stream_generate(prompt, temperature, max_tokens):
                if self._cancel_requested:
                    break
                yield chunk

        except Exception as exc:
            if not self._cancel_requested:
                self._logger.exception("local_stream_failed", extra={"model": model_id, "error": str(exc)})
                raise ProviderError(_ERR_STREAMING_FAILED % exc) from exc

    async def _ensure_model_loaded(self, model_id: str) -> None:
        """Ensure the specified model is loaded.

        Args:
            model_id: Model to load.

        Raises:
            ProviderError: If model loading fails.
        """
        if self._loaded_model is not None and self._loaded_model.model_id == model_id:
            return

        config = ModelConfig(
            model_id=model_id,
            dtype="auto",
            device="xpu" if self._device_type == "xpu" else "cpu",
        )

        try:
            if self._device_type == "xpu":
                self._loaded_model = await asyncio.to_thread(
                    load_model_for_xpu,
                    config,
                    self._model_cache,
                )
            else:
                self._loaded_model = await asyncio.to_thread(
                    load_model_for_cpu,
                    config,
                    self._model_cache,
                )

            self._logger.info(
                "model_loaded",
                extra={
                    "model_id": model_id,
                    "device": self._device_type,
                    "dtype": self._loaded_model.dtype,
                    "load_time_s": self._loaded_model.load_time_seconds,
                },
            )

        except Exception as exc:
            self._logger.exception("model_load_failed", extra={"model_id": model_id, "error": str(exc)})

            if self._device_type == "xpu":
                self._logger.warning("xpu_load_failed_falling_back_to_cpu", extra={"model_id": model_id})
                self._device_type = "cpu"
                config = dataclass_replace(config, device="cpu")
                try:
                    self._loaded_model = await asyncio.to_thread(
                        load_model_for_cpu,
                        config,
                        self._model_cache,
                    )
                except Exception as cpu_exc:
                    raise ProviderError(_ERR_LOAD_BOTH_FAILED % cpu_exc) from cpu_exc
            else:
                raise ProviderError(_ERR_LOAD_FAILED % exc) from exc

    def _generate_sync(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Synchronous text generation.

        Args:
            prompt: Input prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum new tokens.

        Returns:
            Generated text.

        Raises:
            RuntimeError: If no model is currently loaded.
            ImportError: If torch is not installed.
        """
        if self._loaded_model is None:
            raise RuntimeError(_MSG_NO_MODEL_LOADED)

        if _torch is None:
            raise ImportError(_MSG_TORCH_REQUIRED)

        model = self._loaded_model.model
        tokenizer = self._loaded_model.tokenizer
        device = self._loaded_model.device

        inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
        input_ids = inputs["input_ids"].to(device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(device)

        with _torch.no_grad():
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
        response: str = str(tokenizer.decode(generated_ids, skip_special_tokens=True))

        return response.strip()

    async def _stream_generate(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream text generation.

        Args:
            prompt: Input prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum new tokens.

        Yields:
            Text chunks.

        Raises:
            RuntimeError: If no model is currently loaded.
            ImportError: If torch is not installed.
        """
        if self._loaded_model is None:
            raise RuntimeError(_MSG_NO_MODEL_LOADED)

        if _torch is None:
            raise ImportError(_MSG_TORCH_REQUIRED)

        model = self._loaded_model.model
        tokenizer = self._loaded_model.tokenizer
        device = self._loaded_model.device

        inputs = tokenizer(prompt, return_tensors="pt", truncation=True)
        input_ids = inputs["input_ids"].to(device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(device)

        generated_ids = input_ids.clone()
        past_key_values = None

        for _ in range(max_tokens):
            if self._cancel_requested:
                break

            def _forward_pass(
                _model: PreTrainedModel,
                _gen_ids: torch.Tensor,
                _attn_mask: torch.Tensor | None,
                _past_kv: tuple[tuple[torch.Tensor, ...], ...] | None,
            ) -> CausalLMOutputWithPast:
                use_ids = _gen_ids[:, -1:] if _past_kv else _gen_ids
                return _model(
                    input_ids=use_ids,
                    attention_mask=_attn_mask,
                    past_key_values=_past_kv,
                    use_cache=True,
                )

            with _torch.no_grad():
                outputs = await asyncio.to_thread(
                    _forward_pass,
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

            if attention_mask is not None:
                attention_mask = _torch.cat(
                    [attention_mask, _torch.ones((1, 1), device=device)],
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
            List of message dictionaries.
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
            List of tool dictionaries.
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
            Fully formatted prompt string ready for tokenization.
        """
        chat_messages = self._build_chat_messages(messages, tools)

        if self._loaded_model is not None:
            tokenizer = self._loaded_model.tokenizer
            if hasattr(tokenizer, "apply_chat_template") and tokenizer.chat_template is not None:
                try:
                    result: str | list[int] = tokenizer.apply_chat_template(
                        chat_messages,
                        tokenize=False,
                        add_generation_prompt=True,
                    )
                    return str(result)
                except Exception as exc:
                    self._logger.debug(
                        "chat_template_failed_using_fallback",
                        extra={"error": str(exc)},
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
            List of ``{"role": str, "content": str}`` dictionaries.
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
            ChatML-formatted prompt string with a trailing generation
            prompt.
        """
        parts: list[str] = []
        for msg in chat_messages:
            role = msg["role"]
            content = msg["content"]
            parts.append(f"<|im_start|>{role}\n{content}<|im_end|>\n")
        parts.append("<|im_start|>assistant\n")
        return "".join(parts)

    @staticmethod
    def _parse_tool_calls(response: str) -> list[ToolCall] | None:
        """Parse tool calls from response.

        Args:
            response: Model response text.

        Returns:
            List of ToolCall objects or None.
        """
        start_idx = response.find('{"tool_call":')
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
            data: dict[str, Any] = json.loads(json_str)
            tool_call_data: dict[str, Any] = data.get("tool_call", {})
            name: str = str(tool_call_data.get("name", ""))
            raw_arguments: object = tool_call_data.get("arguments", {})
            parsed_arguments: dict[str, Any] = cast("dict[str, Any]", raw_arguments) if isinstance(raw_arguments, dict) else {}

            if name:
                return [
                    ToolCall(
                        id=f"call_{uuid.uuid4().hex}",
                        tool_name=name.split(".", maxsplit=1)[0] if "." in name else name,
                        function_name=name,
                        arguments=parsed_arguments,
                    )
                ]
        except json.JSONDecodeError:
            _logger.warning("tool_call_json_decode_failed")

        return None

    @staticmethod
    def _extract_text_before_tool_call(response: str) -> str:
        """Extract text before tool call JSON.

        Args:
            response: Full response text.

        Returns:
            Text before the tool call JSON.
        """
        if match := re.search(r'\{"tool_call":', response):
            return response[: match.start()].strip()
        return response

    def get_device_info(self) -> dict[str, object]:
        """Get information about the current device.

        Returns:
            Dictionary with device information.
        """
        info: dict[str, object] = {
            "device_type": self._device_type,
            "xpu_available": self._xpu_available,
            "is_arc_b580": self._is_arc_b580,
            "warnings": self._windows_warnings,
        }

        if self._device_type == "xpu" and self._xpu_available:
            if device_info := get_xpu_device_info(0):
                info["device_name"] = device_info.device_name
                info["total_memory_gb"] = device_info.total_memory_bytes / (1024**3)
                info["driver_version"] = device_info.driver_version
                info["supports_fp16"] = device_info.supports_fp16
                info["supports_bf16"] = device_info.supports_bf16

            allocated, total = get_xpu_memory_info(0)
            info["allocated_memory_gb"] = allocated / (1024**3)
            info["total_memory_gb"] = total / (1024**3) if total > 0 else 12.0

        if self._loaded_model:
            info["loaded_model"] = self._loaded_model.model_id
            info["model_dtype"] = self._loaded_model.dtype
            info["model_memory_gb"] = self._loaded_model.memory_usage_bytes / (1024**3)

        return info

    async def unload_model(self) -> None:
        """Unload the currently loaded model to free memory."""
        if self._loaded_model is not None:
            model_id = self._loaded_model.model_id
            dtype = self._loaded_model.dtype
            device_type = self._device_type
            self._model_cache.remove(model_id, dtype, device_type)
            self._loaded_model = None

            if self._device_type == "xpu":
                await asyncio.to_thread(clear_xpu_cache)

            gc.collect()

            self._logger.info("model_unloaded", extra={"model_id": model_id})

    def clear_cache(self) -> None:
        """Clear the model cache."""
        clear_global_cache()
        self._logger.info("model_cache_cleared", extra={"provider": "local_transformers"})
