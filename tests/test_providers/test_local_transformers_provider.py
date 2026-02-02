"""Tests for LocalTransformersProvider with Intel XPU acceleration.

This module provides comprehensive tests for the local transformers provider,
including XPU detection, model loading, inference, and fallback mechanisms.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import Message, ProviderName
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
    is_arc_b580,
    is_xpu_available,
)


class TestXPUDetection:
    """Tests for XPU detection utilities."""

    def test_is_xpu_available_returns_bool(self) -> None:
        """XPU availability check should return a boolean."""
        result = is_xpu_available()
        assert isinstance(result, bool)

    def test_get_xpu_device_count_returns_int(self) -> None:
        """Device count should return a non-negative integer."""
        count = get_xpu_device_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_get_xpu_device_info_returns_none_for_invalid_index(self) -> None:
        """Device info should return None for invalid index."""
        info = get_xpu_device_info(999)
        assert info is None

    def test_is_arc_b580_returns_bool(self) -> None:
        """B580 detection should return a boolean."""
        result = is_arc_b580()
        assert isinstance(result, bool)

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    def test_xpu_device_info_has_required_fields(self) -> None:
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

    def test_estimate_memory_small_model(self) -> None:
        """Small model memory estimate should be reasonable."""
        memory = estimate_model_memory("TinyLlama/TinyLlama-1.1B-Chat-v1.0", "float16")
        assert memory > 0
        assert memory < 5 * 1024 * 1024 * 1024

    def test_estimate_memory_medium_model(self) -> None:
        """Medium model memory estimate should be reasonable."""
        memory = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", "float16")
        assert memory > 1 * 1024 * 1024 * 1024
        assert memory < 15 * 1024 * 1024 * 1024

    def test_estimate_memory_int8_smaller_than_fp16(self) -> None:
        """INT8 should require less memory than FP16."""
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        int8_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int8")
        assert int8_memory < fp16_memory

    def test_estimate_memory_int4_smallest(self) -> None:
        """INT4 should require least memory."""
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        int4_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int4")
        assert int4_memory < fp16_memory / 2

    def test_select_dtype_for_memory_chooses_fitting_dtype(self) -> None:
        """Should select dtype that fits in available memory."""
        available_memory = 3 * 1024 * 1024 * 1024
        dtype = select_dtype_for_memory(
            "microsoft/Phi-3-mini-4k-instruct",
            available_memory,
            "auto",
        )
        estimated = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", dtype)
        assert estimated < available_memory


class TestModelCache:
    """Tests for model caching."""

    def test_cache_initialization(self) -> None:
        """Cache should initialize with correct defaults."""
        cache = ModelCache()
        assert cache.max_memory_bytes == 10 * 1024 * 1024 * 1024
        assert cache.get_memory_usage() == 0

    def test_cache_custom_size(self) -> None:
        """Cache should accept custom size."""
        custom_size = 5 * 1024 * 1024 * 1024
        cache = ModelCache(max_memory_bytes=custom_size)
        assert cache.max_memory_bytes == custom_size

    def test_cache_get_returns_none_for_missing(self) -> None:
        """Get should return None for missing model."""
        cache = ModelCache()
        result = cache.get("nonexistent/model", "float16", "cpu")
        assert result is None

    def test_cache_clear(self) -> None:
        """Clear should reset cache."""
        cache = ModelCache()
        cache.clear()
        assert cache.get_memory_usage() == 0


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    def test_model_config_defaults(self) -> None:
        """ModelConfig should have correct defaults."""
        config = ModelConfig(model_id="test/model")
        assert config.model_id == "test/model"
        assert config.dtype == "auto"
        assert config.device == "auto"
        assert config.trust_remote_code is False

    def test_model_config_custom_values(self) -> None:
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

    def test_provider_name(self) -> None:
        """Provider should have correct name."""
        provider = LocalTransformersProvider()
        assert provider.name == ProviderName.LOCAL_TRANSFORMERS

    def test_provider_not_connected_initially(self) -> None:
        """Provider should not be connected initially."""
        provider = LocalTransformersProvider()
        assert not provider.is_connected

    def test_provider_default_device_cpu(self) -> None:
        """Provider should default to CPU device."""
        provider = LocalTransformersProvider()
        assert provider.device_type == "cpu"

    def test_provider_no_model_loaded_initially(self) -> None:
        """Provider should have no model loaded initially."""
        provider = LocalTransformersProvider()
        assert provider.current_model_id is None


class TestLocalTransformersProviderConnection:
    """Tests for provider connection."""

    @pytest.mark.asyncio
    async def test_connect_without_credentials(self) -> None:
        """Provider should connect without credentials for local inference."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        assert provider.is_connected
        await provider.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_cleans_up(self) -> None:
        """Disconnect should clean up state."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        await provider.disconnect()
        assert not provider.is_connected

    @pytest.mark.asyncio
    async def test_connect_detects_xpu_availability(self) -> None:
        """Connect should detect XPU availability."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        assert isinstance(provider.xpu_available, bool)
        await provider.disconnect()


class TestMessageConversion:
    """Tests for message format conversion."""

    def test_convert_user_message(self) -> None:
        """Should convert user message correctly."""
        provider = LocalTransformersProvider()
        messages = [Message(role="user", content="Hello")]
        converted = provider._convert_messages_to_provider_format(messages)
        assert len(converted) == 1
        assert converted[0]["role"] == "user"
        assert converted[0]["content"] == "Hello"

    def test_convert_system_message(self) -> None:
        """Should convert system message correctly."""
        provider = LocalTransformersProvider()
        messages = [Message(role="system", content="You are helpful")]
        converted = provider._convert_messages_to_provider_format(messages)
        assert len(converted) == 1
        assert converted[0]["role"] == "system"

    def test_convert_multiple_messages(self) -> None:
        """Should convert multiple messages correctly."""
        provider = LocalTransformersProvider()
        messages = [
            Message(role="system", content="System"),
            Message(role="user", content="User"),
            Message(role="assistant", content="Assistant"),
        ]
        converted = provider._convert_messages_to_provider_format(messages)
        assert len(converted) == 3


class TestToolConversion:
    """Tests for tool format conversion."""

    def test_convert_empty_tools(self) -> None:
        """Should handle empty tools list."""
        provider = LocalTransformersProvider()
        converted = provider._convert_tools_to_provider_format([])
        assert converted == []


class TestProviderDeviceInfo:
    """Tests for device info retrieval."""

    @pytest.mark.asyncio
    async def test_get_device_info_cpu(self) -> None:
        """Should return device info for CPU."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(None)
        info = provider.get_device_info()
        assert info["device_type"] == "cpu"
        assert isinstance(info["xpu_available"], bool)
        await provider.disconnect()


class TestXPUTests:
    """Tests that require XPU hardware."""

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    @pytest.mark.xpu
    @pytest.mark.asyncio
    async def test_xpu_provider_initialization(self) -> None:
        """Provider should initialize with XPU when available."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        await provider.connect(None)
        assert provider.xpu_available
        assert provider.device_type == "xpu"
        await provider.disconnect()

    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU available")
    @pytest.mark.xpu
    def test_xpu_device_info_available(self) -> None:
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
    def test_b580_xpu_tensor_creation(self) -> None:
        """XPU tensor creation must work on B580."""
        import torch

        tensor = torch.zeros(100, device="xpu")
        assert tensor.device.type == "xpu"
        del tensor
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    def test_b580_fp16_operations(self) -> None:
        """FP16 operations must work on B580."""
        import torch

        tensor = torch.randn(100, 100, dtype=torch.float16, device="xpu")
        result = tensor @ tensor.T
        assert result.dtype == torch.float16
        assert result.device.type == "xpu"
        del tensor, result
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    def test_b580_bf16_operations(self) -> None:
        """BF16 operations must work on B580."""
        import torch

        tensor = torch.randn(100, 100, dtype=torch.bfloat16, device="xpu")
        result = tensor @ tensor.T
        assert result.dtype == torch.bfloat16
        assert result.device.type == "xpu"
        del tensor, result
        torch.xpu.empty_cache()

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    def test_b580_memory_info(self) -> None:
        """Memory info must be available for B580."""
        from intellicrack.providers.xpu_utils import get_xpu_memory_info

        allocated, total = get_xpu_memory_info(0)
        assert isinstance(allocated, int)
        assert isinstance(total, int)
        assert total > 10 * 1024 * 1024 * 1024

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    def test_b580_device_detection(self) -> None:
        """B580 must be properly detected."""
        info = get_xpu_device_info(0)
        assert info is not None
        assert info.is_arc_b580 is True

    @pytest.mark.skipif(not is_arc_b580(), reason="No Arc B580 detected")
    @pytest.mark.b580
    @pytest.mark.asyncio
    async def test_b580_provider_uses_xpu(self) -> None:
        """Provider must use XPU on B580."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        await provider.connect(None)
        assert provider.device_type == "xpu"
        assert provider.is_b580_detected
        await provider.disconnect()


class TestCPUFallback:
    """Tests for CPU fallback functionality."""

    @pytest.mark.asyncio
    async def test_cpu_fallback_when_xpu_disabled(self) -> None:
        """Should use CPU when XPU preference disabled."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(None)
        assert provider.device_type == "cpu"
        await provider.disconnect()

    @pytest.mark.asyncio
    async def test_cpu_device_info(self) -> None:
        """Should provide device info for CPU."""
        provider = LocalTransformersProvider(prefer_xpu=False)
        await provider.connect(None)
        info = provider.get_device_info()
        assert info["device_type"] == "cpu"
        await provider.disconnect()


class TestProviderListModels:
    """Tests for model listing."""

    @pytest.mark.asyncio
    async def test_list_models_returns_list(self) -> None:
        """List models should return a list."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        models = await provider.list_models()
        assert isinstance(models, list)
        await provider.disconnect()

    @pytest.mark.asyncio
    async def test_list_models_has_recommended_models(self) -> None:
        """List models should include recommended models."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        models = await provider.list_models()
        assert len(models) > 0
        model_ids = [m.id for m in models]
        assert any("phi" in m.lower() or "tiny" in m.lower() for m in model_ids)
        await provider.disconnect()

    @pytest.mark.asyncio
    async def test_list_models_model_info_complete(self) -> None:
        """Model info should have all required fields."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
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
    async def test_list_models_requires_connection(self) -> None:
        """List models should raise when not connected."""
        from intellicrack.core.types import ProviderError

        provider = LocalTransformersProvider()
        with pytest.raises(ProviderError):
            await provider.list_models()


class TestPromptFormatting:
    """Tests for prompt formatting."""

    def test_format_prompt_simple(self) -> None:
        """Should format simple prompt."""
        provider = LocalTransformersProvider()
        messages = [{"role": "user", "content": "Hello"}]
        prompt = provider._format_prompt(messages)
        assert "<|user|>" in prompt
        assert "Hello" in prompt
        assert "<|assistant|>" in prompt

    def test_format_prompt_with_system(self) -> None:
        """Should include system message."""
        provider = LocalTransformersProvider()
        messages = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": "Hi"},
        ]
        prompt = provider._format_prompt(messages)
        assert "<|system|>" in prompt
        assert "Be helpful" in prompt


class TestToolCallParsing:
    """Tests for tool call parsing."""

    def test_parse_no_tool_calls(self) -> None:
        """Should return None for text without tool calls."""
        provider = LocalTransformersProvider()
        result = provider._parse_tool_calls("Just a regular response")
        assert result is None

    def test_parse_valid_tool_call(self) -> None:
        """Should parse valid tool call JSON."""
        provider = LocalTransformersProvider()
        response = 'Here is the result: {"tool_call": {"name": "test_func", "arguments": {"arg1": "value1"}}}'
        result = provider._parse_tool_calls(response)
        assert result is not None
        assert len(result) == 1
        assert result[0].function_name == "test_func"
        assert result[0].arguments == {"arg1": "value1"}


class TestContextWindowEstimation:
    """Tests for context window estimation."""

    def test_estimate_phi3_mini_4k(self) -> None:
        """Should estimate Phi-3-mini-4k context."""
        provider = LocalTransformersProvider()
        window = provider._estimate_context_window("microsoft/Phi-3-mini-4k-instruct")
        assert window == 4096

    def test_estimate_phi3_128k(self) -> None:
        """Should estimate Phi-3-128k context."""
        provider = LocalTransformersProvider()
        window = provider._estimate_context_window("microsoft/Phi-3-mini-128k-instruct")
        assert window == 128000

    def test_estimate_qwen25(self) -> None:
        """Should estimate Qwen2.5 context."""
        provider = LocalTransformersProvider()
        window = provider._estimate_context_window("Qwen/Qwen2.5-1.5B-Instruct")
        assert window == 32768

    def test_estimate_default(self) -> None:
        """Should return default for unknown model."""
        provider = LocalTransformersProvider()
        window = provider._estimate_context_window("unknown/model")
        assert window == 4096


class TestToolSupport:
    """Tests for tool support detection."""

    def test_phi3_supports_tools(self) -> None:
        """Phi-3 should support tools."""
        provider = LocalTransformersProvider()
        assert provider._model_supports_tools("microsoft/Phi-3-mini-4k-instruct")

    def test_qwen_supports_tools(self) -> None:
        """Qwen should support tools."""
        provider = LocalTransformersProvider()
        assert provider._model_supports_tools("Qwen/Qwen2.5-1.5B-Instruct")

    def test_llama3_supports_tools(self) -> None:
        """Llama-3 should support tools."""
        provider = LocalTransformersProvider()
        assert provider._model_supports_tools("meta-llama/Llama-3.2-1B-Instruct")


class TestCacheClear:
    """Tests for cache clearing."""

    @pytest.mark.asyncio
    async def test_clear_cache(self) -> None:
        """Should clear cache without error."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        provider.clear_cache()
        await provider.disconnect()

    @pytest.mark.asyncio
    async def test_unload_model(self) -> None:
        """Should unload model without error."""
        provider = LocalTransformersProvider()
        await provider.connect(None)
        await provider.unload_model()
        assert provider.current_model_id is None
        await provider.disconnect()
