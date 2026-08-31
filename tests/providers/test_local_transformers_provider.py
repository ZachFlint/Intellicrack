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
    get_global_model_cache,
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
_3_GIB = 3 * 1024 * 1024 * 1024
_10_GIB = 10 * 1024 * 1024 * 1024
_TENSOR_SIZE = 100
_MATRIX_SIZE = 100
_INVALID_DEVICE_INDEX = 999

# Independently-known facts used as memory-estimation oracles. These are NOT
# imported from the implementation: they are public properties of the model
# family and of IEEE/quantization storage, so a regression in the estimator
# cannot move them.
#
# * "Mistral-7B" denotes a 7-billion-parameter transformer (model card fact).
# * "Phi-3-mini" is a 3.8-billion-parameter transformer (model card fact).
# * float16 (IEEE half precision) stores 2 bytes per weight; int8 stores 1
#   byte; int4 stores 0.5 byte; float32 stores 4 bytes.
# * The estimator adds a fixed 1.3x activation/runtime overhead by default and
#   omits it when include_activations=False.
_MISTRAL_7B_PARAMS = 7_000_000_000
_PHI3_MINI_PARAMS = 3_800_000_000
_FP16_BYTES_PER_PARAM = 2
_INT8_BYTES_PER_PARAM = 1
_FP32_BYTES_PER_PARAM = 4
_ACTIVATION_OVERHEAD_NUM = 13
_ACTIVATION_OVERHEAD_DEN = 10


def _with_activation_overhead(weight_bytes: int) -> int:
    """Apply the documented 1.3x activation overhead the way the estimator does.

    The production estimator computes ``int(weight_bytes * 1.3)``. Expressing
    the overhead as the exact rational ``13/10`` here reproduces that rounding
    deterministically without importing or re-running production code.

    Args:
        weight_bytes: Raw weight-storage size in bytes.

    Returns:
        int: Weight bytes scaled by the 1.3x activation overhead, truncated to
            an integer exactly as the estimator does.
    """
    return int(weight_bytes * _ACTIVATION_OVERHEAD_NUM / _ACTIVATION_OVERHEAD_DEN)


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
    def test_availability_and_device_count_are_consistent() -> None:
        """Availability must agree with device count via a cross-function invariant.

        ``is_xpu_available()`` and ``get_xpu_device_count()`` are independent
        code paths into the same torch.xpu runtime. The platform invariant they
        must jointly satisfy is: XPU is available iff at least one device is
        enumerable. Asserting that biconditional catches a regression in either
        function without depending on whether the CI host actually has an XPU.
        """
        available = is_xpu_available()
        count = get_xpu_device_count()
        assert isinstance(available, bool)
        assert isinstance(count, int)
        assert count >= 0
        assert available == (count > 0)

    @staticmethod
    def test_get_xpu_device_info_returns_none_for_invalid_index() -> None:
        """Out-of-range device index yields None rather than a fabricated record.

        Index 999 cannot exist on any current host; the lookup must surface
        absence as ``None`` instead of returning a placeholder device.
        """
        info = get_xpu_device_info(_INVALID_DEVICE_INDEX)
        assert info is None

    @staticmethod
    def test_b580_detection_implies_xpu_available() -> None:
        """A detected Arc B580 must also report XPU as available.

        ``is_arc_b580()`` is logically a refinement of ``is_xpu_available()``:
        a B580 is an XPU device, so the implication ``b580 -> xpu_available``
        must hold on every host. This is a real oracle (a logical invariant)
        rather than a bare ``isinstance`` check.
        """
        b580 = is_arc_b580()
        assert isinstance(b580, bool)
        if b580:
            assert is_xpu_available()
            assert get_xpu_device_count() > 0

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
    """Tests for model memory estimation against independently-known oracles."""

    @staticmethod
    def test_estimate_phi3_mini_fp16_matches_known_param_size() -> None:
        """Phi-3-mini fp16 estimate equals 3.8B params x 2 bytes x 1.3 overhead.

        The expected value is derived from the model card parameter count
        (3.8B) and IEEE half-precision storage (2 bytes/param), not from the
        estimator's own output, so a broken estimator that returns a constant
        or the wrong dtype factor fails this exactly.
        """
        weight_bytes = _PHI3_MINI_PARAMS * _FP16_BYTES_PER_PARAM
        expected = _with_activation_overhead(weight_bytes)
        memory = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", "float16")
        assert memory == expected
        assert expected == 9_880_000_000

    @staticmethod
    def test_estimate_mistral_7b_fp16_matches_known_param_size() -> None:
        """Mistral-7B fp16 estimate equals 7B params x 2 bytes x 1.3 overhead.

        Independently anchored to the published 7B parameter count and the
        2-byte float16 weight size.
        """
        weight_bytes = _MISTRAL_7B_PARAMS * _FP16_BYTES_PER_PARAM
        expected = _with_activation_overhead(weight_bytes)
        memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        assert memory == expected
        assert expected == 18_200_000_000

    @staticmethod
    def test_estimate_without_activation_overhead_drops_the_factor() -> None:
        """Disabling activations yields exactly weight bytes with no 1.3x.

        With ``include_activations=False`` the estimate must equal the raw
        weight storage (7B x 2 bytes = 14 GB), proving the overhead factor is
        actually conditional rather than always applied.
        """
        memory = estimate_model_memory(
            "mistralai/Mistral-7B-Instruct-v0.3",
            "float16",
            include_activations=False,
        )
        assert memory == _MISTRAL_7B_PARAMS * _FP16_BYTES_PER_PARAM
        assert memory == 14_000_000_000

    @staticmethod
    def test_estimate_int8_is_exactly_half_of_fp16() -> None:
        """INT8 storage is 1 byte/param vs FP16's 2, so the ratio is exactly 2.

        Rather than merely asserting ``int8 < fp16`` (which any shrink would
        satisfy), this pins the absolute int8 value to the known param count
        and verifies the precise 2:1 theoretical relationship between 1-byte
        and 2-byte weight storage.
        """
        int8_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int8")
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        expected_int8 = _with_activation_overhead(_MISTRAL_7B_PARAMS * _INT8_BYTES_PER_PARAM)
        assert int8_memory == expected_int8
        assert int8_memory == 9_100_000_000
        assert int8_memory * 2 == fp16_memory

    @staticmethod
    def test_estimate_int4_is_a_quarter_of_fp16() -> None:
        """INT4 stores 0.5 byte/param, exactly one quarter of FP16's 2 bytes.

        Pins the int4 absolute value to the known param count and verifies the
        4:1 ratio against fp16, catching a regression that mis-maps the int4
        multiplier.
        """
        int4_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "int4")
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        assert int4_memory == _with_activation_overhead(_MISTRAL_7B_PARAMS // 2)
        assert int4_memory == 4_550_000_000
        assert int4_memory * 4 == fp16_memory

    @staticmethod
    def test_estimate_fp32_is_double_fp16() -> None:
        """FP32 stores 4 bytes/param, exactly double FP16's 2 bytes.

        Confirms the default (non-float16/bfloat16/int) branch resolves to the
        4-byte multiplier rather than silently collapsing to the fp16 path.
        """
        fp32_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float32")
        fp16_memory = estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", "float16")
        assert fp32_memory == _with_activation_overhead(_MISTRAL_7B_PARAMS * _FP32_BYTES_PER_PARAM)
        assert fp32_memory == 36_400_000_000
        assert fp32_memory == fp16_memory * 2

    @staticmethod
    def test_select_dtype_for_memory_chooses_fitting_dtype() -> None:
        """Auto dtype selection must return a dtype whose estimate fits.

        Phi-3-mini cannot fit a 3 GiB budget at fp16 (9.88 GB) but does fit at
        int4 (~2.47 GB); the selector must therefore return ``int4`` and the
        estimate for that dtype must be strictly below the budget.
        """
        available_memory = _3_GIB
        dtype = select_dtype_for_memory(
            "microsoft/Phi-3-mini-4k-instruct",
            available_memory,
            "auto",
        )
        assert dtype == "int4"
        estimated = estimate_model_memory("microsoft/Phi-3-mini-4k-instruct", dtype)
        assert estimated < available_memory
        assert estimated == _with_activation_overhead(_PHI3_MINI_PARAMS // 2)


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
        """Connect should detect XPU availability.

        Verifies that connect() calls the real XPU runtime query and stores the
        result faithfully: provider.xpu_available must equal the independent
        oracle is_xpu_available() evaluated on the same machine.
        """
        expected: bool = is_xpu_available()
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        assert provider.xpu_available == expected, (
            f"provider.xpu_available={provider.xpu_available!r} but "
            f"is_xpu_available()={expected!r}: connect() did not faithfully "
            "query the XPU runtime"
        )
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
        """Model info should have all required fields with correct values.

        Asserts unconditionally that at least one model is returned and that
        every required field on the first model carries an independently-known
        correct value (provider enum) or a structurally correct non-empty value
        (id, name, context_window > 0).  The ``if models:`` guard is forbidden
        because an empty list must surface as a test failure, not a silent pass.
        """
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        models = await provider.list_models()
        assert len(models) > 0, "list_models() returned an empty list; expected at least one model"
        model = models[0]
        assert model.id, f"model.id is falsy: {model.id!r}"
        assert model.name, f"model.name is falsy: {model.name!r}"
        assert model.provider == ProviderName.LOCAL_TRANSFORMERS, f"model.provider={model.provider!r} != ProviderName.LOCAL_TRANSFORMERS"
        assert isinstance(model.context_window, int), f"model.context_window={model.context_window!r} must be int"
        assert model.context_window > 0, f"model.context_window={model.context_window!r} must be positive"
        assert isinstance(model.supports_tools, bool), f"model.supports_tools={model.supports_tools!r} must be bool"
        assert isinstance(model.supports_streaming, bool), f"model.supports_streaming={model.supports_streaming!r} must be bool"
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
        """Clear cache must set global model-cache memory usage to zero.

        Calls clear_cache() and then reads the global cache's reported memory
        usage via get_global_model_cache().get_memory_usage().  The oracle is
        the ModelCache.clear() contract: after clearing, _current_memory_bytes
        is reset to 0.  An implementation that merely logs or no-ops would
        leave memory_usage > 0 (if any model had been registered) or would
        fail to satisfy the zero postcondition checked here.
        """
        provider = LocalTransformersProvider()
        await provider.connect(ProviderCredentials())
        provider.clear_cache()
        cache: ModelCache = get_global_model_cache()
        assert cache.get_memory_usage() == 0, f"After clear_cache(), global cache reports {cache.get_memory_usage()} bytes; expected 0"
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
