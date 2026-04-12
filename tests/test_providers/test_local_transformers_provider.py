# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for LocalTransformersProvider with Intel XPU acceleration.

This module provides comprehensive tests for the local transformers provider,
including XPU detection, model loading, inference, and fallback mechanisms.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ProviderError, ProviderName, ToolCall


if TYPE_CHECKING:
    import torch
else:
    try:
        import torch
    except ImportError:
        torch: Any = None

from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import (
    ModelCache,
    ModelConfig,
    estimate_model_memory,
    select_dtype_for_memory,
)
from intellicrack.providers.xpu_utils import (
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    is_arc_b580,
    is_xpu_available,
)


_5_GIB = 5 * 1024 * 1024 * 1024
_1_GIB = 1 * 1024 * 1024 * 1024
_3_GIB = 3 * 1024 * 1024 * 1024
_10_GIB = 10 * 1024 * 1024 * 1024
_15_GIB = 15 * 1024 * 1024 * 1024
_TENSOR_SIZE = 100
_MATRIX_SIZE = 100
_INVALID_DEVICE_INDEX = 999

_ATTR_FORMAT_PROMPT = "_format_prompt"
_ATTR_PARSE_TOOL_CALLS = "_parse_tool_calls"


def _format_prompt_via(
    provider: LocalTransformersProvider,
    messages: list[dict[str, object]],
) -> str:
    """Invoke the provider's protected ``_format_prompt`` method in a type-safe way.

    Args:
        provider: The provider instance exposing the formatting method.
        messages: The list of pre-converted message dictionaries.

    Returns:
        str: The formatted prompt string.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is not a string.
    """
    method: object = getattr(provider, _ATTR_FORMAT_PROMPT)
    if not callable(method):
        msg = f"{_ATTR_FORMAT_PROMPT} is not callable"
        raise TypeError(msg)
    result: object = method(messages)
    if not isinstance(result, str):
        msg = f"Expected str result, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _parse_tool_calls_via(response: str) -> list[ToolCall] | None:
    """Invoke the provider's protected ``_parse_tool_calls`` static method.

    Args:
        response: The raw model response to parse.

    Returns:
        list[ToolCall] | None: Parsed tool calls, or None if no tool call was present.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is neither None nor a list of ToolCall objects.
    """
    method: object = getattr(LocalTransformersProvider, _ATTR_PARSE_TOOL_CALLS)
    if not callable(method):
        msg = f"{_ATTR_PARSE_TOOL_CALLS} is not callable"
        raise TypeError(msg)
    result: object = method(response)
    if result is None:
        return None
    if not isinstance(result, list):
        msg = f"Expected list or None, got {type(result).__name__}"
        raise TypeError(msg)
    for item in cast("list[object]", result):
        if not isinstance(item, ToolCall):
            msg = f"Expected ToolCall items, got {type(item).__name__}"
            raise TypeError(msg)
    return cast("list[ToolCall]", result)


class TestXPUDetection:
    """Tests for XPU detection utilities."""

    @staticmethod
    def test_is_xpu_available_returns_bool() -> None:
        """XPU availability check should return a boolean."""
        result = is_xpu_available()
        assert isinstance(result, bool)

    @staticmethod
    def test_get_xpu_device_count_returns_int() -> None:
        """Device count should return a non-negative integer."""
        count = get_xpu_device_count()
        assert isinstance(count, int)
        assert count >= 0

    @staticmethod
    def test_get_xpu_device_info_returns_none_for_invalid_index() -> None:
        """Device info should return None for invalid index."""
        info = get_xpu_device_info(_INVALID_DEVICE_INDEX)
        assert info is None

    @staticmethod
    def test_is_arc_b580_returns_bool() -> None:
        """B580 detection should return a boolean."""
        result = is_arc_b580()
        assert isinstance(result, bool)

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    @staticmethod
    def test_xpu_device_info_has_required_fields() -> None:
        """Device info should have all required fields when XPU available."""
        info = get_xpu_device_info(0)
        assert info is not None
        assert isinstance(info.device_index, int)
        assert isinstance(info.device_name, str)
        assert isinstance(info.total_memory_bytes, int)
        assert isinstance(info.is_arc_b580, bool)
        assert isinstance(info.supports_fp16, bool)


class TestModelMemoryEstimation:
    """Tests for model memory estimation."""

    @staticmethod
    def test_estimate_memory_small_model() -> None:
        """Small model memory estimate should be reasonable."""
        memory = estimate_model_memory("TinyLlama/TinyLlama-1.1B-Chat-v1.0", "float16")
        assert memory > 0
        assert memory < _5_GIB

    @staticmethod
    def test_estimate_memory_medium_model() -> None:
        """Medium model memory estimate should be reasonable."""
        memory = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", "float16")
        assert memory > _1_GIB
        assert memory < _15_GIB

    @staticmethod
    def test_estimate_memory_int8_smaller_than_fp16() -> None:
        """INT8 should require less memory than FP16."""
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        int8_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int8")
        assert int8_memory < fp16_memory

    @staticmethod
    def test_estimate_memory_int4_smallest() -> None:
        """INT4 should require least memory."""
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        int4_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int4")
        assert int4_memory < fp16_memory / 2

    @staticmethod
    def test_select_dtype_for_memory_chooses_fitting_dtype() -> None:
        """Should select dtype that fits in available memory."""
        available_memory = _3_GIB
        dtype = select_dtype_for_memory(
            "microsoft/Phi-3-mini-4k-instruct",
            available_memory,
            "auto",
        )
        estimated = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", dtype)
        assert estimated < available_memory


class TestModelCache:
    """Tests for model caching."""

    @staticmethod
    def test_cache_initialization() -> None:
        """Cache should initialize with correct defaults."""
        cache = ModelCache()
        assert cache.max_memory_bytes == _10_GIB
        assert cache.get_memory_usage() == 0

    @staticmethod
    def test_cache_custom_size() -> None:
        """Cache should accept custom size."""
        custom_size = _5_GIB
        cache = ModelCache(max_memory_bytes=custom_size)
        assert cache.max_memory_bytes == custom_size

    @staticmethod
    def test_cache_get_returns_none_for_missing() -> None:
        """Get should return None for missing model."""
        cache = ModelCache()
        result = cache.get("nonexistent/model", "float16", "cpu")
        assert result is None

    @staticmethod
    def test_cache_clear() -> None:
        """Clear should reset cache."""
        cache = ModelCache()
        cache.clear()
        assert cache.get_memory_usage() == 0


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    @staticmethod
    def test_model_config_defaults() -> None:
        """ModelConfig should have correct defaults."""
        config = ModelConfig(model_id="test/model")
        assert config.model_id == "test/model"
        assert config.dtype == "auto"
        assert config.device == "auto"
        assert config.trust_remote_code is False

    @staticmethod
    def test_model_config_custom_values() -> None:
        """ModelConfig should accept custom values."""
        config = ModelConfig(
            model_id="test/model",
            dtype="float16",
            device="xpu",
            trust_remote_code=True,
        )
        assert config.dtype == "float16"
        assert config.device == "xpu"
        assert config.trust_remote_code is True


class TestLocalTransformersProviderInitialization:
    """Tests for provider initialization."""

    @staticmethod
    def test_provider_name() -> None:
        """Provider should have correct name."""
        provider = LocalTransformersProvider()
        assert provider.name == ProviderName.LOCAL_TRANSFORMERS

    @staticmethod
    def test_provider_not_connected_initially() -> None:
        """Provider should not be connected initially."""
        provider = LocalTransformersProvider()
        assert not provider.is_connected

    @staticmethod
    def test_provider_default_device_cpu() -> None:
        """Provider should default to CPU device."""
        provider = LocalTransformersProvider()
        assert provider.device_type == "cpu"

    @staticmethod
    def test_provider_no_model_loaded_initially() -> None:
        """Provider should have no model loaded initially."""
        provider = LocalTransformersProvider()
        assert provider.current_model_id is None


class TestLocalTransformersProviderConnection:
    """Tests for provider connection."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_connect_without_credentials() -> None:
        """Provider should connect without credentials for local inference."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        assert provider.is_connected
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_cleans_up() -> None:
        """Disconnect should clean up state."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        await provider.disconnect()
        assert not provider.is_connected

    @pytest.mark.asyncio
    @staticmethod
    async def test_connect_detects_xpu_availability() -> None:
        """Connect should detect XPU availability."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        assert isinstance(provider.xpu_available, bool)
        await provider.disconnect()


_EXPECTED_MESSAGE_COUNT = 3


class TestMessageConversion:
    """Tests for message format conversion."""

    @staticmethod
    def test_convert_user_message() -> None:
        """Should convert user message correctly."""
        provider = LocalTransformersProvider()
        messages = [Message(role="user", content="Hello")]
        converted = provider.convert_messages_to_provider_format(messages)
        assert len(converted) == 1
        assert converted[0]["role"] == "user"
        assert converted[0]["content"] == "Hello"

    @staticmethod
    def test_convert_system_message() -> None:
        """Should convert system message correctly."""
        provider = LocalTransformersProvider()
        messages = [Message(role="system", content="You are helpful")]
        converted = provider.convert_messages_to_provider_format(messages)
        assert len(converted) == 1
        assert converted[0]["role"] == "system"

    @staticmethod
    def test_convert_multiple_messages() -> None:
        """Should convert multiple messages correctly."""
        provider = LocalTransformersProvider()
        messages = [
            Message(role="system", content="System"),
            Message(role="user", content="User"),
            Message(role="assistant", content="Assistant"),
        ]
        converted = provider.convert_messages_to_provider_format(messages)
        assert len(converted) == _EXPECTED_MESSAGE_COUNT


class TestToolConversion:
    """Tests for tool format conversion."""

    @staticmethod
    def test_convert_empty_tools() -> None:
        """Should handle empty tools list."""
        provider = LocalTransformersProvider()
        converted = provider.convert_tools_to_provider_format([])
        assert converted == []


class TestProviderDeviceInfo:
    """Tests for device info retrieval."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_get_device_info_cpu() -> None:
        """Should return device info for CPU."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(ProviderCredentials())
        info = provider.get_device_info()
        assert info["device_type"] == "cpu"
        assert isinstance(info["xpu_available"], bool)
        await provider.disconnect()


class TestXPUTests:
    """Tests that require XPU hardware."""

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    @pytest.mark.xpu
    @pytest.mark.asyncio
    @staticmethod
    async def test_xpu_provider_initialization() -> None:
        """Provider should initialize with XPU when available."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        await provider.connect(ProviderCredentials())
        assert provider.xpu_available
        assert provider.device_type == "xpu"
        await provider.disconnect()

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    @pytest.mark.xpu
    @staticmethod
    def test_xpu_device_info_available() -> None:
        """Should get device info when XPU available."""
        info = get_xpu_device_info(0)
        assert info is not None
        assert info.device_index == 0


class TestB580SpecificTests:
    """Tests specific to Intel Arc B580.

    These tests MUST PASS if B580 is detected. They will skip if no B580,
    but will FAIL if B580 is present but operations fail.
    """

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @staticmethod
    def test_b580_xpu_tensor_creation() -> None:
        """XPU tensor creation must work on B580."""
        tensor = torch.zeros(_TENSOR_SIZE, device="xpu")
        assert tensor.device.type == "xpu"
        del tensor
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @staticmethod
    def test_b580_fp16_operations() -> None:
        """FP16 operations must work on B580."""
        tensor = torch.randn(_MATRIX_SIZE, _MATRIX_SIZE, dtype=torch.float16, device="xpu")
        result = tensor @ tensor.T
        assert result.dtype == torch.float16
        assert result.device.type == "xpu"
        del tensor, result
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @staticmethod
    def test_b580_bf16_operations() -> None:
        """BF16 operations must work on B580."""
        tensor = torch.randn(_MATRIX_SIZE, _MATRIX_SIZE, dtype=torch.bfloat16, device="xpu")
        result = tensor @ tensor.T
        assert result.dtype == torch.bfloat16
        assert result.device.type == "xpu"
        del tensor, result
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @staticmethod
    def test_b580_memory_info() -> None:
        """Memory info must be available for B580."""
        allocated, total = get_xpu_memory_info(0)
        assert isinstance(allocated, int)
        assert isinstance(total, int)
        assert total > _10_GIB

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @staticmethod
    def test_b580_device_detection() -> None:
        """B580 must be properly detected."""
        info = get_xpu_device_info(0)
        assert info is not None
        assert info.is_arc_b580 is True

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @pytest.mark.asyncio
    @staticmethod
    async def test_b580_provider_uses_xpu() -> None:
        """Provider must use XPU on B580."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        await provider.connect(ProviderCredentials())
        assert provider.device_type == "xpu"
        assert provider.is_b580_detected
        await provider.disconnect()


class TestCPUFallback:
    """Tests for CPU fallback functionality."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_cpu_fallback_when_xpu_disabled() -> None:
        """Should use CPU when XPU preference disabled."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(ProviderCredentials())
        assert provider.device_type == "cpu"
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_cpu_device_info() -> None:
        """Should provide device info for CPU."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(ProviderCredentials())
        info = provider.get_device_info()
        assert info["device_type"] == "cpu"
        await provider.disconnect()


class TestProviderListModels:
    """Tests for model listing."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_returns_list() -> None:
        """List models should return a list."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        models = await provider.list_models()
        assert isinstance(models, list)
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_has_recommended_models() -> None:
        """List models should include recommended models."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        models = await provider.list_models()
        assert len(models) > 0
        model_ids = [m.id for m in models]
        assert any("phi" in m.lower() or "tiny" in m.lower() for m in model_ids)
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_model_info_complete() -> None:
        """Model info should have all required fields."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        models = await provider.list_models()
        if models:
            model = models[0]
            assert model.id is not None
            assert model.name is not None
            assert model.provider == ProviderName.LOCAL_TRANSFORMERS
            assert isinstance(model.context_window, int)
            assert isinstance(model.supports_tools, bool)
            assert isinstance(model.supports_streaming, bool)
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_list_models_requires_connection() -> None:
        """List models should raise when not connected."""
        provider = LocalTransformersProvider()
        with pytest.raises(ProviderError):
            await provider.list_models()


class TestPromptFormatting:
    """Tests for prompt formatting."""

    @staticmethod
    def test_format_prompt_simple() -> None:
        """Should format simple prompt."""
        provider = LocalTransformersProvider()
        messages: list[dict[str, object]] = [{"role": "user", "content": "Hello"}]
        prompt = _format_prompt_via(provider, messages)
        assert "<|im_start|>user" in prompt
        assert "Hello" in prompt
        assert "<|im_start|>assistant" in prompt

    @staticmethod
    def test_format_prompt_with_system() -> None:
        """Should include system message."""
        provider = LocalTransformersProvider()
        messages: list[dict[str, object]] = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": "Hi"},
        ]
        prompt = _format_prompt_via(provider, messages)
        assert "<|im_start|>system" in prompt
        assert "Be helpful" in prompt


class TestToolCallParsing:
    """Tests for tool call parsing."""

    @staticmethod
    def test_parse_no_tool_calls() -> None:
        """Should return None for text without tool calls."""
        result = _parse_tool_calls_via("Just a regular response")
        assert result is None

    @staticmethod
    def test_parse_valid_tool_call() -> None:
        """Should parse valid tool call JSON."""
        response = 'Here is the result: {"tool_call": {"name": "test_func", "arguments": {"arg1": "value1"}}}'
        result = _parse_tool_calls_via(response)
        assert result is not None
        assert len(result) == 1
        assert result[0].function_name == "test_func"
        assert result[0].arguments == {"arg1": "value1"}


class TestCacheClear:
    """Tests for cache clearing."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_clear_cache() -> None:
        """Should clear cache without error."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        provider.clear_cache()
        await provider.disconnect()

    @pytest.mark.asyncio
    @staticmethod
    async def test_unload_model() -> None:
        """Should unload model without error."""
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        await provider.unload_model()
        assert provider.current_model_id is None
        await provider.disconnect()
