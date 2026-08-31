# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for ``intellicrack.providers.model_loader``.

These tests exercise the pure-logic units of the model loader (memory
estimation, dtype selection, parameter-count estimation, quantization
config construction, and the LRU :class:`ModelCache`) against real
``torch`` dtypes and real ``transformers`` quantization-config objects.
No model weights are downloaded; the cache tests build real
:class:`LoadedModel` records around real ``torch.nn`` modules and real
CPU ``torch.device`` instances so eviction frees genuine objects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
import torch

from intellicrack.providers import model_loader
from intellicrack.providers.model_loader import (
    LoadedModel,
    ModelCache,
    ModelConfig,
    estimate_model_memory,
    load_model_for_xpu,
    select_dtype_for_memory,
)
from intellicrack.providers.xpu_utils import is_xpu_available


if TYPE_CHECKING:
    from collections.abc import Callable

    from transformers import PreTrainedModel, PreTrainedTokenizerBase


_GIB: int = 1024 * 1024 * 1024


def _estimate_parameter_count(model_id: str) -> int:
    """Call the module-private parameter-count estimator with typing intact.

    Args:
        model_id: HuggingFace model identifier.

    Returns:
        int: Estimated parameter count.
    """
    fn = cast("Callable[[str], int]", vars(model_loader)["_estimate_parameter_count"])
    return fn(model_id)


def _get_torch_dtype(dtype_str: str) -> torch.dtype:
    """Call the module-private dtype-string mapper with typing intact.

    Args:
        dtype_str: String dtype name.

    Returns:
        torch.dtype: The mapped torch dtype.
    """
    fn = cast("Callable[[str], torch.dtype]", vars(model_loader)["_get_torch_dtype"])
    return fn(dtype_str)


def _get_quantization_config(dtype_str: str) -> object:
    """Call the module-private quantization-config builder with typing intact.

    Args:
        dtype_str: Quantization precision label.

    Returns:
        object: A BitsAndBytesConfig instance or a fallback dict.
    """
    fn = cast("Callable[[str], object]", vars(model_loader)["_get_quantization_config"])
    return fn(dtype_str)


class _TinyModule:
    """A minimal real object standing in for a loaded model.

    The cache only stores and deletes the reference and reads
    ``memory_usage_bytes`` from the wrapper, so a lightweight real
    object is sufficient to validate cache bookkeeping without
    downloading multi-gigabyte weights.
    """

    def __init__(self, payload_size: int) -> None:
        """Allocate a real bytearray so eviction frees real memory.

        Args:
            payload_size: Number of bytes to allocate for the payload.
        """
        self.payload = bytearray(payload_size)


def _make_loaded(model_id: str, dtype: str, memory_bytes: int) -> LoadedModel:
    """Build a real :class:`LoadedModel` around a CPU device.

    Args:
        model_id: Model identifier to record.
        dtype: Dtype label to record.
        memory_bytes: Reported memory footprint used for cache accounting.

    Returns:
        LoadedModel: A populated loaded-model record on the CPU device.
    """
    device = torch.device("cpu")
    module = _TinyModule(1024)
    return LoadedModel(
        model=cast("PreTrainedModel", module),
        tokenizer=cast("PreTrainedTokenizerBase", module),
        device=device,
        dtype=dtype,
        memory_usage_bytes=memory_bytes,
        model_id=model_id,
        load_time_seconds=0.01,
    )


class TestEstimateModelMemory:
    """Validate the real arithmetic of :func:`estimate_model_memory`."""

    @staticmethod
    def test_fp16_matches_two_bytes_per_param_with_overhead() -> None:
        """FP16 memory is exactly (real_param_count * 2 bytes/param * 1.3 overhead).

        The expected value is derived from :func:`_estimate_parameter_count` so
        the test verifies both that the model-ID-to-parameter-count mapping
        resolves to 1 000 000 000 *and* that the memory formula applies the
        correct FP16 multiplier and activation overhead.  If the estimator were
        broken (returning 0 or a wrong value), the expected computation would
        diverge from the hardcoded 1B baseline and the test would fail.
        """
        model_id = "meta-llama/Llama-3.2-1B-Instruct"
        real_param_count = _estimate_parameter_count(model_id)
        assert real_param_count == 1_000_000_000, (
            f"_estimate_parameter_count must map {model_id!r} to 1 000 000 000; got {real_param_count}"
        )
        estimated = estimate_model_memory(model_id, "float16")
        expected = int(int(real_param_count * 2.0) * 1.3)
        assert estimated == expected, f"FP16 memory for {real_param_count} params should be {expected}; got {estimated}"

    @staticmethod
    def test_int4_is_half_byte_per_param() -> None:
        """INT4 halves the byte-per-parameter multiplier versus FP16."""
        fp16 = estimate_model_memory("meta-llama/Llama-3.2-1B-Instruct", "float16", include_activations=False)
        int4 = estimate_model_memory("meta-llama/Llama-3.2-1B-Instruct", "int4", include_activations=False)
        assert int4 == int(1_000_000_000 * 0.5)
        assert fp16 == int(1_000_000_000 * 2.0)
        assert int4 * 4 == fp16

    @staticmethod
    def test_activation_overhead_toggle_changes_result() -> None:
        """Disabling activation overhead removes the 1.3x multiplier."""
        with_act = estimate_model_memory("Qwen/Qwen2.5-3B-Instruct", "bfloat16", include_activations=True)
        without_act = estimate_model_memory("Qwen/Qwen2.5-3B-Instruct", "bfloat16", include_activations=False)
        assert with_act == int(without_act * 1.3)
        assert without_act == int(3_000_000_000 * 2.0)

    @staticmethod
    def test_float32_uses_four_bytes_per_param() -> None:
        """Unmapped/explicit float32 uses the 4-byte multiplier."""
        estimated = estimate_model_memory("gemma-2b", "float32", include_activations=False)
        assert estimated == int(2_000_000_000 * 4.0)


class TestEstimateParameterCount:
    """Validate parameter-count estimation including the 7B fallback."""

    @staticmethod
    def test_size_pattern_in_id_wins() -> None:
        """A size token such as ``13b`` in the id is matched directly."""
        assert _estimate_parameter_count("meta-llama/Llama-2-13b-hf") == 13_000_000_000

    @staticmethod
    def test_named_model_phi3_mini() -> None:
        """A named model without a size token resolves via the named map."""
        assert _estimate_parameter_count("microsoft/Phi-3-mini-4k-instruct") == 3_800_000_000

    @staticmethod
    def test_phi2_named_model_without_size_token() -> None:
        """Phi-2 (no size token in id) resolves via the named model map."""
        assert _estimate_parameter_count("microsoft/phi-2") == 2_700_000_000

    @staticmethod
    def test_size_token_substring_takes_precedence() -> None:
        """A ``1b`` substring in the id matches before the named-model map."""
        assert _estimate_parameter_count("TinyLlama/TinyLlama-1.1B-Chat-v1.0") == 1_000_000_000

    @staticmethod
    def test_unlisted_model_falls_back_to_7b() -> None:
        """A model with no recognizable pattern returns the 7B default."""
        assert _estimate_parameter_count("some-org/totally-unknown-architecture") == 7_000_000_000


class TestSelectDtypeForMemory:
    """Validate dtype selection against real memory budgets."""

    @staticmethod
    def test_preferred_dtype_kept_when_it_fits() -> None:
        """A preferred dtype that fits the budget is returned unchanged."""
        selected = select_dtype_for_memory(
            "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
            8 * _GIB,
            preferred_dtype="float16",
        )
        assert selected == "float16"

    @staticmethod
    def test_auto_downshifts_to_int_when_fp_too_big() -> None:
        """A 7B model in a tiny budget downshifts to a quantized dtype."""
        selected = select_dtype_for_memory("mistralai/Mistral-7B-Instruct-v0.3", 5 * _GIB)
        assert selected in {"int8", "int4"}
        assert estimate_model_memory("mistralai/Mistral-7B-Instruct-v0.3", selected) < 5 * _GIB

    @staticmethod
    def test_no_dtype_fits_falls_back_to_int4() -> None:
        """When nothing fits the budget the function returns ``int4``."""
        selected = select_dtype_for_memory("meta-llama/Llama-2-70b-hf", 1024)
        assert selected == "int4"

    @staticmethod
    def test_preferred_too_big_picks_first_fitting_auto_dtype() -> None:
        """An over-budget preferred dtype is replaced by the first auto fit."""
        selected = select_dtype_for_memory(
            "Qwen/Qwen2.5-3B-Instruct",
            10 * _GIB,
            preferred_dtype="float32",
        )
        assert selected == "bfloat16"
        assert estimate_model_memory("Qwen/Qwen2.5-3B-Instruct", selected) < 10 * _GIB


class TestGetTorchDtype:
    """Validate dtype-string to real ``torch.dtype`` mapping."""

    @staticmethod
    def test_known_dtypes_map_to_real_torch_dtypes() -> None:
        """Each known dtype string maps to the matching ``torch.dtype``."""
        assert _get_torch_dtype("float32") is torch.float32
        assert _get_torch_dtype("float16") is torch.float16
        assert _get_torch_dtype("bfloat16") is torch.bfloat16
        assert _get_torch_dtype("auto") is torch.float16

    @staticmethod
    def test_unmapped_dtype_falls_back_to_float32() -> None:
        """An unmapped dtype string defaults to ``torch.float32``."""
        assert _get_torch_dtype("int4") is torch.float32
        assert _get_torch_dtype("nonsense") is torch.float32


class TestGetQuantizationConfig:
    """Validate quantization-config construction with real transformers."""

    @staticmethod
    def test_int8_returns_real_bitsandbytes_config() -> None:
        """INT8 yields a real ``BitsAndBytesConfig`` with 8-bit enabled."""
        bnb = pytest.importorskip("transformers").BitsAndBytesConfig
        config = _get_quantization_config("int8")
        assert isinstance(config, bnb)
        assert getattr(config, "load_in_8bit", False) is True

    @staticmethod
    def test_int4_config_carries_double_quant_and_compute_dtype() -> None:
        """INT4 yields a real config with double-quant and a compute dtype."""
        transformers = pytest.importorskip("transformers")
        config = _get_quantization_config("int4")
        assert isinstance(config, transformers.BitsAndBytesConfig)
        assert getattr(config, "load_in_4bit", False) is True
        assert getattr(config, "bnb_4bit_use_double_quant", False) is True
        assert getattr(config, "bnb_4bit_compute_dtype", None) is torch.float16

    @staticmethod
    def test_unknown_dtype_returns_default_config() -> None:
        """A non-int dtype produces a default config object, not a crash."""
        transformers = pytest.importorskip("transformers")
        config = _get_quantization_config("float16")
        assert isinstance(config, transformers.BitsAndBytesConfig)


class TestModelCacheBookkeeping:
    """Validate real :class:`ModelCache` get/put/remove/clear/eviction."""

    @staticmethod
    def test_get_returns_none_for_uncached_key() -> None:
        """A key never inserted is reported as a cache miss."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        assert cache.get("not/there", "float16", "cpu") is None

    @staticmethod
    def test_put_then_get_round_trip_same_identity() -> None:
        """A stored model is retrievable by its (id, dtype, device) key."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        loaded = _make_loaded("org/model-a", "float16", 1 * _GIB)
        cache.put(loaded)
        fetched = cache.get("org/model-a", "float16", "cpu")
        assert fetched is loaded
        assert cache.get_memory_usage() == 1 * _GIB

    @staticmethod
    def test_remove_returns_true_then_false() -> None:
        """Removing a cached model returns True; a second removal returns False."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        cache.put(_make_loaded("org/model-b", "float16", 2 * _GIB))
        assert cache.remove("org/model-b", "float16", "cpu") is True
        assert cache.remove("org/model-b", "float16", "cpu") is False
        assert cache.get_memory_usage() == 0

    @staticmethod
    def test_remove_nonexistent_returns_false() -> None:
        """Removing a key that was never present returns False."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        assert cache.remove("org/never", "int8", "cpu") is False

    @staticmethod
    def test_eviction_under_memory_pressure_drops_lru() -> None:
        """Inserting past the limit evicts the least-recently-used model."""
        cache = ModelCache(max_memory_bytes=3 * _GIB)
        first = _make_loaded("org/first", "float16", 2 * _GIB)
        second = _make_loaded("org/second", "float16", 2 * _GIB)
        cache.put(first)
        cache.put(second)
        assert cache.get("org/first", "float16", "cpu") is None
        assert cache.get("org/second", "float16", "cpu") is second
        assert cache.get_memory_usage() == 2 * _GIB

    @staticmethod
    def test_lru_recency_protects_recently_used_model() -> None:
        """A recent ``get`` moves a model to the back so it survives eviction."""
        cache = ModelCache(max_memory_bytes=3 * _GIB)
        first = _make_loaded("org/aaa", "float16", 1 * _GIB)
        second = _make_loaded("org/bbb", "float16", 1 * _GIB)
        cache.put(first)
        cache.put(second)
        assert cache.get("org/aaa", "float16", "cpu") is first
        cache.put(_make_loaded("org/ccc", "float16", 2 * _GIB))
        assert cache.get("org/aaa", "float16", "cpu") is first
        assert cache.get("org/bbb", "float16", "cpu") is None

    @staticmethod
    def test_clear_unloads_all_and_zeroes_usage() -> None:
        """``clear`` drops every entry and resets accounted memory to zero."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        cache.put(_make_loaded("org/x", "float16", 1 * _GIB))
        cache.put(_make_loaded("org/y", "int8", 1 * _GIB))
        cache.clear()
        assert cache.get_memory_usage() == 0
        assert cache.get("org/x", "float16", "cpu") is None
        assert cache.get("org/y", "int8", "cpu") is None

    @staticmethod
    def test_put_same_key_replaces_old_and_adjusts_memory() -> None:
        """Re-putting the same key swaps the model and corrects accounting."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        old = _make_loaded("org/dup", "float16", 1 * _GIB)
        new = _make_loaded("org/dup", "float16", 3 * _GIB)
        cache.put(old)
        cache.put(new)
        assert cache.get("org/dup", "float16", "cpu") is new
        assert cache.get_memory_usage() == 3 * _GIB

    @staticmethod
    def test_lowering_max_memory_triggers_eviction() -> None:
        """Lowering ``max_memory_bytes`` evicts until the cache fits."""
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        cache.put(_make_loaded("org/one", "float16", 4 * _GIB))
        cache.put(_make_loaded("org/two", "float16", 4 * _GIB))
        cache.max_memory_bytes = 5 * _GIB
        assert cache.get_memory_usage() <= 5 * _GIB
        assert cache.get("org/one", "float16", "cpu") is None
        assert cache.get("org/two", "float16", "cpu") is not None


class TestLoadModelForXpuErrorPath:
    """Validate the XPU loader's error path when XPU is genuinely absent."""

    @staticmethod
    def test_raises_runtime_error_when_xpu_unavailable() -> None:
        """Calling the XPU loader without XPU hardware raises RuntimeError."""
        if is_xpu_available():
            pytest.skip("XPU is available; the unavailable error path cannot be exercised")
        config = ModelConfig(model_id="TinyLlama/TinyLlama-1.1B-Chat-v1.0")
        with pytest.raises(RuntimeError, match="XPU is not available"):
            load_model_for_xpu(config)
