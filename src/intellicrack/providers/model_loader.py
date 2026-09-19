# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Model loading utilities with quantization and caching for local transformers.

This module provides model loading, caching, and memory management for HuggingFace Transformers models optimized for Intel XPU and CPU
inference.
"""

from __future__ import annotations

import gc
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Final, Literal, NoReturn, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.types import UnsafeCheckpointError


try:
    import torch as _torch
except ImportError:
    get_logger(__name__).debug("torch_import_unavailable")
    _torch = None

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
except (ImportError, ValueError):
    get_logger(__name__).debug("transformers_automodel_unavailable")
    AutoModelForCausalLM = None
    AutoTokenizer = None

try:
    from transformers import BitsAndBytesConfig
except (ImportError, ValueError):
    get_logger(__name__).debug("bitsandbytes_config_unavailable")
    BitsAndBytesConfig = None

from intellicrack.providers.xpu_utils import clear_xpu_cache, get_xpu_memory_info, initialize_xpu, is_xpu_available


if TYPE_CHECKING:
    import torch
    from transformers import PreTrainedModel, PreTrainedTokenizerBase


_logger = get_logger(__name__)

_ERR_MISSING_DEPS = "transformers and torch are required for model loading"
_ERR_XPU_NOT_AVAILABLE = "XPU is not available. Use load_model_for_cpu instead."
_ERR_LOAD_XPU_FAILED = "Failed to load model %s on XPU: %s"
_ERR_LOAD_CPU_FAILED = "Failed to load model %s on CPU: %s"

# Every sharded-checkpoint index file transformers recognises for a local model
# folder. A checkpoint may carry the safetensors or the PyTorch pair, with an
# optional dtype/variant suffix ("model.fp16.safetensors.index.json"), so the
# folder is scanned for any file whose name ends with one of these suffixes.
_SHARD_INDEX_SUFFIXES: Final[tuple[str, ...]] = (
    ".safetensors.index.json",
    ".bin.index.json",
)
_WEIGHT_MAP_KEY: Final[str] = "weight_map"


def _raise_unsafe_checkpoint(
    checkpoint_dir: str,
    index_name: str,
    entry: object,
    reason: str,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log and raise :class:`UnsafeCheckpointError` for a rejected shard entry.

    Args:
        checkpoint_dir: The local checkpoint directory under inspection.
        index_name: File name of the shard index the entry came from.
        entry: The offending ``weight_map`` value.
        reason: Why the entry was rejected.
        cause: The lower-level exception that triggered the rejection, if any.

    Raises:
        UnsafeCheckpointError: Always; carries the checkpoint and offending entry.
    """
    printable = entry if isinstance(entry, str) else repr(entry)
    message = f"Refusing to load checkpoint {checkpoint_dir!r}: shard index {index_name!r} maps a weight to {printable!r} which {reason}."
    _logger.warning(
        "unsafe_checkpoint_shard_rejected",
        checkpoint_dir=checkpoint_dir,
        index_name=index_name,
        offending_entry=printable,
        reason=reason,
    )
    if cause is not None:
        raise UnsafeCheckpointError(message, checkpoint_dir=checkpoint_dir, offending_entry=printable) from cause
    raise UnsafeCheckpointError(message, checkpoint_dir=checkpoint_dir, offending_entry=printable)


def _validate_shard_entry(folder_norm: str, index_name: str, entry: object) -> None:
    """Validate a single ``weight_map`` shard name against its checkpoint folder.

    A shard name is safe only when it is a relative path that, once joined onto
    the checkpoint folder and normalised, still resolves inside that folder and
    does not name a Windows reserved device. Absolute paths, drive-relative or
    UNC paths, parent-directory traversal, and reserved device names such as CON,
    NUL, COM1 or a named pipe are each rejected on their own.

    Args:
        folder_norm: The normalised absolute checkpoint folder path.
        index_name: File name of the shard index the entry came from.
        entry: A single ``weight_map`` value from the index.
    """
    if not isinstance(entry, str) or not entry.strip():
        _raise_unsafe_checkpoint(folder_norm, index_name, entry, "is not a usable relative file name")
    if PureWindowsPath(entry).drive or PureWindowsPath(entry).root or PurePosixPath(entry).is_absolute():
        _raise_unsafe_checkpoint(folder_norm, index_name, entry, "is an absolute, drive-relative or UNC path")
    joined = str(Path(folder_norm) / entry)
    resolved = os.path.normpath(joined)
    if resolved != folder_norm and not resolved.startswith(folder_norm + os.sep):
        _raise_unsafe_checkpoint(folder_norm, index_name, entry, "points outside the checkpoint folder")
    if os.path.isreserved(joined):
        _raise_unsafe_checkpoint(folder_norm, index_name, entry, "names a Windows reserved device")


def _validate_shard_index(folder_norm: str, index_path: Path) -> None:
    """Validate every ``weight_map`` entry of one shard-index file.

    Args:
        folder_norm: The normalised absolute checkpoint folder path.
        index_path: Path to the shard-index JSON file to inspect.
    """
    try:
        document: object = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _raise_unsafe_checkpoint(folder_norm, index_path.name, str(exc), "could not be parsed as a shard index", cause=exc)
    if not isinstance(document, dict):
        return
    weight_map: object = cast("dict[str, object]", document).get(_WEIGHT_MAP_KEY)
    if not isinstance(weight_map, dict):
        return
    for entry in set(cast("dict[str, object]", weight_map).values()):
        _validate_shard_entry(folder_norm, index_path.name, entry)


def validate_local_checkpoint(model_id: str) -> None:
    """Reject a local checkpoint whose sharded-weight index escapes its folder.

    ``transformers`` resolves the shard file names in a sharded checkpoint's
    ``*.index.json`` by joining each ``weight_map`` value directly onto the
    checkpoint folder, so a hostile checkpoint can point a shard at ``../`` paths,
    absolute paths, or a named pipe and have the loader read arbitrary files or
    block indefinitely (CVE-2026-69112, unreachable in ``accelerate`` here but
    reachable through the transformers local-folder loader). This runs before any
    ``from_pretrained`` call and validates every shard entry of every index found
    in a local checkpoint directory.

    Hugging Face Hub repository ids (anything that is not an existing local
    directory) are left untouched: the SDK resolves and caches those itself.

    Args:
        model_id: The configured model identifier or local checkpoint path.
    """
    if not model_id:
        return
    folder = Path(model_id)
    if not folder.is_dir():
        return
    folder_norm = os.path.normpath(folder.absolute())
    try:
        index_files = sorted(
            child for child in Path(folder_norm).iterdir() if child.name.endswith(_SHARD_INDEX_SUFFIXES) and child.is_file()
        )
    except OSError as exc:
        _logger.warning("checkpoint_dir_listing_failed", checkpoint_dir=folder_norm, error=str(exc))
        return
    for index_path in index_files:
        _validate_shard_index(folder_norm, index_path)


DtypeOption = Literal["auto", "float32", "float16", "bfloat16", "int8", "int4"]
DeviceType = Literal["xpu", "cpu", "auto"]

_DEFAULT_CACHE_SIZE_BYTES: int = 10 * 1024 * 1024 * 1024
_B580_VRAM_BYTES: int = 12 * 1024 * 1024 * 1024
_VRAM_OVERHEAD_BYTES: int = 1024 * 1024 * 1024
_FP16_MULTIPLIER: float = 2.0
_FP32_MULTIPLIER: float = 4.0
_BF16_MULTIPLIER: float = 2.0
_INT8_MULTIPLIER: float = 1.0
_INT4_MULTIPLIER: float = 0.5
_ACTIVATION_OVERHEAD_MULTIPLIER: float = 1.3


@dataclass
class LoadedModel:
    """A loaded model with its tokenizer and metadata."""

    model: PreTrainedModel
    tokenizer: PreTrainedTokenizerBase
    device: torch.device
    dtype: str
    memory_usage_bytes: int
    model_id: str
    load_time_seconds: float


@dataclass
class ModelConfig:
    """Configuration for model loading.

    Attributes:
        model_id: HuggingFace model identifier or local path.
        dtype: Data type for the model.
        device: Target device.
        max_memory_bytes: Maximum memory to use.
        trust_remote_code: Whether to trust remote code.
        use_flash_attention: Whether to use flash attention if available.
        quantization_config: Optional quantization configuration.
        revision: Git revision (commit hash, tag, or branch) to pin
            downloads to a specific snapshot of the model repository.
            When ``None``, HuggingFace defaults to the ``main`` branch.
    """

    model_id: str
    dtype: DtypeOption = "auto"
    device: DeviceType = "auto"
    max_memory_bytes: int = field(default=_B580_VRAM_BYTES)
    trust_remote_code: bool = False
    use_flash_attention: bool = False
    quantization_config: dict[str, object] | None = None
    revision: str | None = None


class ModelCache:
    """LRU cache for loaded models with memory limit enforcement.

    Maintains an LRU cache of loaded models, automatically evicting least recently used models when the memory limit is exceeded.
    """

    def __init__(self, max_memory_bytes: int = _DEFAULT_CACHE_SIZE_BYTES) -> None:
        """Initialize the ModelCache with a memory limit.

        Args:
            max_memory_bytes: Maximum memory in bytes allowed for cached models.
        """
        self._cache: OrderedDict[str, LoadedModel] = OrderedDict()
        self._lock = threading.RLock()
        self._max_memory_bytes = max_memory_bytes
        self._current_memory_bytes: int = 0
        _logger.info("model_cache_initialized", max_memory_bytes=max_memory_bytes)

    @property
    def max_memory_bytes(self) -> int:
        """The maximum memory limit.

        Returns:
            int: Maximum memory in bytes allowed for cached models.
        """
        return self._max_memory_bytes

    @max_memory_bytes.setter
    def max_memory_bytes(self, value: int) -> None:
        """Set the maximum memory limit and evict if needed.

        Args:
            value: New maximum memory limit in bytes.
        """
        with self._lock:
            self._max_memory_bytes = value
            self._evict_to_fit(0)

    def get(self, model_id: str, dtype: str, device_type: str) -> LoadedModel | None:
        """Get a model from cache.

        Args:
            model_id: The model identifier.
            dtype: The data type.
            device_type: The device type.

        Returns:
            LoadedModel | None: The cached LoadedModel or None if not cached.
        """
        cache_key = self._make_key(model_id, dtype, device_type)
        with self._lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                _logger.debug("model_cache_hit", model_id=model_id, dtype=dtype)
                return self._cache[cache_key]
        return None

    def put(self, loaded_model: LoadedModel) -> None:
        """Put a model into cache.

        Args:
            loaded_model: The loaded model to cache.
        """
        device_type = loaded_model.device.type
        cache_key = self._make_key(loaded_model.model_id, loaded_model.dtype, device_type)

        with self._lock:
            if cache_key in self._cache:
                old_model = self._cache.pop(cache_key)
                self._current_memory_bytes -= old_model.memory_usage_bytes
                _unload_model(old_model)

            self._evict_to_fit(loaded_model.memory_usage_bytes)

            self._cache[cache_key] = loaded_model
            self._current_memory_bytes += loaded_model.memory_usage_bytes
            _logger.debug(
                "model_cached",
                model_id=loaded_model.model_id,
                dtype=loaded_model.dtype,
                memory_mb=loaded_model.memory_usage_bytes // (1024 * 1024),
                total_cached_mb=self._current_memory_bytes // (1024 * 1024),
            )

    def remove(self, model_id: str, dtype: str, device_type: str) -> bool:
        """Remove a model from cache.

        Args:
            model_id: The model identifier.
            dtype: The data type.
            device_type: The device type.

        Returns:
            bool: True if model was removed, False if not found.
        """
        cache_key = self._make_key(model_id, dtype, device_type)
        with self._lock:
            if cache_key in self._cache:
                model = self._cache.pop(cache_key)
                self._current_memory_bytes -= model.memory_usage_bytes
                _unload_model(model)
                return True
        return False

    def clear(self) -> None:
        """Clear all cached models."""
        with self._lock:
            for loaded_model in self._cache.values():
                _unload_model(loaded_model)
            self._cache.clear()
            self._current_memory_bytes = 0
            gc.collect()
        _logger.info("model_cache_cleared", cache_size=len(self._cache))

    def get_memory_usage(self) -> int:
        """Get current memory usage.

        Returns:
            int: Current memory usage in bytes.
        """
        with self._lock:
            return self._current_memory_bytes

    @staticmethod
    def _make_key(model_id: str, dtype: str, device_type: str) -> str:
        """Create a cache key.

        Args:
            model_id: The model identifier.
            dtype: The data type.
            device_type: The device type.

        Returns:
            str: Cache key string.
        """
        return f"{model_id}::{dtype}::{device_type}"

    def _evict_to_fit(self, required_bytes: int) -> None:
        """Evict models until there's room for required_bytes.

        Args:
            required_bytes: Bytes needed for new model.
        """
        while self._cache and (self._current_memory_bytes + required_bytes > self._max_memory_bytes):
            _, oldest_model = self._cache.popitem(last=False)
            self._current_memory_bytes -= oldest_model.memory_usage_bytes
            _unload_model(oldest_model)
            _logger.info(
                "model_evicted",
                model_id=oldest_model.model_id,
                memory_freed_mb=oldest_model.memory_usage_bytes // (1024 * 1024),
            )


def _free_model_resources(loaded_model: LoadedModel) -> None:
    """Release model and tokenizer references and clear XPU cache.

    Args:
        loaded_model: The model to free.
    """
    del loaded_model.model
    del loaded_model.tokenizer
    gc.collect()

    try:
        if _torch is not None and hasattr(_torch, "xpu") and _torch.xpu.is_available():
            _torch.xpu.empty_cache()
    except (RuntimeError, OSError) as inner_exc:
        _logger.warning("xpu_cache_clear_on_unload_failed", error=str(inner_exc))


def _unload_model(loaded_model: LoadedModel) -> None:
    """Unload a model and free resources.

    Args:
        loaded_model: The model to unload.
    """
    try:
        _free_model_resources(loaded_model)
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.warning("model_unload_failed", error=str(exc))


def estimate_model_memory(
    model_id: str,
    dtype: DtypeOption = "float16",
    *,
    include_activations: bool = True,
) -> int:
    """Estimate memory required for a model.

    Args:
        model_id: HuggingFace model identifier or path.
        dtype: Data type for the model.
        include_activations: Include activation memory overhead.

    Returns:
        int: Estimated memory in bytes.
    """
    param_count = _estimate_parameter_count(model_id)

    if dtype in {"float16", "bfloat16"}:
        bytes_per_param = _FP16_MULTIPLIER
    elif dtype == "int8":
        bytes_per_param = _INT8_MULTIPLIER
    elif dtype == "int4":
        bytes_per_param = _INT4_MULTIPLIER
    else:
        bytes_per_param = _FP32_MULTIPLIER

    base_memory = int(param_count * bytes_per_param)

    if include_activations:
        base_memory = int(base_memory * _ACTIVATION_OVERHEAD_MULTIPLIER)

    _logger.debug(
        "model_memory_estimated",
        model_id=model_id,
        dtype=dtype,
        param_count=param_count,
        bytes_per_param=bytes_per_param,
        include_activations=include_activations,
        estimated_bytes=base_memory,
        estimated_mb=base_memory // (1024 * 1024),
    )

    return base_memory


def _estimate_parameter_count(model_id: str) -> int:
    """Estimate parameter count from model ID.

    Args:
        model_id: HuggingFace model identifier.

    Returns:
        int: Estimated parameter count.
    """
    model_lower = model_id.lower()

    size_patterns: list[tuple[str, int]] = [
        ("70b", 70_000_000_000),
        ("65b", 65_000_000_000),
        ("34b", 34_000_000_000),
        ("33b", 33_000_000_000),
        ("30b", 30_000_000_000),
        ("13b", 13_000_000_000),
        ("8b", 8_000_000_000),
        ("7b", 7_000_000_000),
        ("6b", 6_000_000_000),
        ("3b", 3_000_000_000),
        ("2.7b", 2_700_000_000),
        ("2b", 2_000_000_000),
        ("1.5b", 1_500_000_000),
        ("1.3b", 1_300_000_000),
        ("1b", 1_000_000_000),
        ("500m", 500_000_000),
        ("350m", 350_000_000),
        ("125m", 125_000_000),
    ]

    for pattern, count in size_patterns:
        if pattern in model_lower:
            _logger.debug(
                "parameter_count_estimated",
                model_id=model_id,
                estimated_params=count,
                estimated_params_b=round(count / 1_000_000_000, 1),
            )
            return count

    named_models: dict[str, int] = {
        "phi-3-mini": 3_800_000_000,
        "phi-3-small": 7_000_000_000,
        "phi-3-medium": 14_000_000_000,
        "phi-2": 2_700_000_000,
        "tinyllama": 1_100_000_000,
        "qwen2.5-0.5b": 500_000_000,
        "qwen2.5-1.5b": 1_500_000_000,
        "qwen2.5-3b": 3_000_000_000,
        "qwen2.5-7b": 7_000_000_000,
        "llama-3.2-1b": 1_000_000_000,
        "llama-3.2-3b": 3_000_000_000,
        "gemma-2b": 2_000_000_000,
        "gemma-7b": 7_000_000_000,
    }

    result = next(
        (count for name, count in named_models.items() if name in model_lower),
        7_000_000_000,
    )

    _logger.debug(
        "parameter_count_estimated",
        model_id=model_id,
        estimated_params=result,
        estimated_params_b=round(result / 1_000_000_000, 1),
    )

    return result


def select_dtype_for_memory(
    model_id: str,
    available_memory_bytes: int,
    preferred_dtype: DtypeOption = "auto",
) -> DtypeOption:
    """Select appropriate dtype to fit model in available memory.

    Args:
        model_id: HuggingFace model identifier.
        available_memory_bytes: Available memory in bytes.
        preferred_dtype: Preferred dtype if it fits.

    Returns:
        DtypeOption: Selected dtype that should fit in memory.
    """
    if preferred_dtype != "auto":
        estimated = estimate_model_memory(model_id, preferred_dtype)
        if estimated < available_memory_bytes:
            _logger.debug(
                "dtype_selected_preferred",
                model_id=model_id,
                selected_dtype=preferred_dtype,
                estimated_bytes=estimated,
                available_bytes=available_memory_bytes,
            )
            return preferred_dtype

    for dtype in ("bfloat16", "float16", "int8", "int4"):
        estimated = estimate_model_memory(model_id, dtype)
        if estimated < available_memory_bytes:
            _logger.debug(
                "dtype_selected_auto",
                model_id=model_id,
                selected_dtype=dtype,
                estimated_bytes=estimated,
                available_bytes=available_memory_bytes,
            )
            return dtype

    _logger.debug(
        "dtype_selected_fallback",
        model_id=model_id,
        selected_dtype="int4",
        available_bytes=available_memory_bytes,
    )
    return "int4"


def load_model_for_xpu(
    config: ModelConfig,
    cache: ModelCache | None = None,
) -> LoadedModel:
    """Load a model optimized for Intel XPU.

    Args:
        config: Model configuration.
        cache: Optional model cache.

    Returns:
        LoadedModel: LoadedModel with model, tokenizer, and metadata.

    Raises:
        RuntimeError: If model loading fails.
        ImportError: If required packages are not installed.
    """
    if _torch is None or AutoModelForCausalLM is None or AutoTokenizer is None:
        _logger.error("xpu_load_missing_dependencies", model_id=config.model_id)
        raise ImportError(_ERR_MISSING_DEPS)

    validate_local_checkpoint(config.model_id)

    if not is_xpu_available():
        _logger.error("xpu_load_xpu_unavailable", model_id=config.model_id)
        raise RuntimeError(_ERR_XPU_NOT_AVAILABLE)

    dtype_str = config.dtype

    if cache is not None:
        device_type = "xpu"
        cached = cache.get(config.model_id, str(dtype_str), device_type)
        if cached is not None:
            return cached

    _, total_memory = get_xpu_memory_info(0)
    available_memory = total_memory - _VRAM_OVERHEAD_BYTES

    dtype_str = select_dtype_for_memory(config.model_id, available_memory) if config.dtype == "auto" else config.dtype

    clear_xpu_cache()

    start_time = time.perf_counter()

    _logger.info(
        "model_loading_xpu",
        model_id=config.model_id,
        dtype=dtype_str,
    )

    try:
        loaded_model = _load_xpu_model_impl(
            config=config,
            dtype_str=dtype_str,
            start_time=start_time,
            cache=cache,
        )
    except (RuntimeError, ImportError, ValueError, OSError) as exc:
        _logger.warning("xpu_model_load_failed", model_id=config.model_id, error=str(exc))
        clear_xpu_cache()
        raise RuntimeError(_ERR_LOAD_XPU_FAILED % (config.model_id, exc)) from exc
    else:
        return loaded_model


def _load_xpu_model_impl(
    *,
    config: ModelConfig,
    dtype_str: DtypeOption,
    start_time: float,
    cache: ModelCache | None,
) -> LoadedModel:
    """Perform the XPU model load and cache insertion.

    Args:
        config: Model configuration.
        dtype_str: Resolved dtype string.
        start_time: ``time.perf_counter()`` reference for load timing.
        cache: Optional cache to populate on success.

    Returns:
        LoadedModel: Loaded model wrapper with metadata.

    Raises:
        ImportError: If required transformers symbols are unavailable.
    """
    if AutoModelForCausalLM is None or AutoTokenizer is None:
        _logger.error(
            "xpu_model_load_transformers_unavailable",
            model_id=config.model_id,
            dtype=dtype_str,
        )
        raise ImportError(_ERR_MISSING_DEPS)
    torch_dtype = _get_torch_dtype(dtype_str)
    device = initialize_xpu(0)

    tokenizer = AutoTokenizer.from_pretrained(
        config.model_id,
        trust_remote_code=config.trust_remote_code,
        revision=config.revision,
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    load_kwargs: dict[str, object] = {
        "trust_remote_code": config.trust_remote_code,
        "low_cpu_mem_usage": True,
    }

    if dtype_str in {"int8", "int4"}:
        load_kwargs["device_map"] = "auto"
        load_kwargs["quantization_config"] = _get_quantization_config(dtype_str)
    else:
        load_kwargs["torch_dtype"] = torch_dtype

    model = AutoModelForCausalLM.from_pretrained(
        config.model_id,
        revision=config.revision,
        **load_kwargs,
    )

    if dtype_str not in {"int8", "int4"}:
        model = model.to(device)

    model.eval()

    load_time = time.perf_counter() - start_time

    memory_usage = estimate_model_memory(config.model_id, dtype_str, include_activations=False)

    loaded_model = LoadedModel(
        model=model,
        tokenizer=tokenizer,
        device=device,
        dtype=dtype_str,
        memory_usage_bytes=memory_usage,
        model_id=config.model_id,
        load_time_seconds=load_time,
    )

    if cache is not None:
        cache.put(loaded_model)

    _logger.info(
        "model_loaded_xpu",
        model_id=config.model_id,
        dtype=dtype_str,
        load_time_seconds=load_time,
        memory_mb=memory_usage // (1024 * 1024),
    )
    return loaded_model


def load_model_for_cpu(
    config: ModelConfig,
    cache: ModelCache | None = None,
) -> LoadedModel:
    """Load a model for CPU inference.

    Args:
        config: Model configuration.
        cache: Optional model cache.

    Returns:
        LoadedModel: LoadedModel with model, tokenizer, and metadata.

    Raises:
        RuntimeError: If model loading fails.
        ImportError: If required packages are not installed.
    """
    if _torch is None or AutoModelForCausalLM is None or AutoTokenizer is None:
        _logger.error("cpu_load_missing_dependencies", model_id=config.model_id)
        raise ImportError(_ERR_MISSING_DEPS)

    validate_local_checkpoint(config.model_id)

    dtype_str = config.dtype

    if cache is not None:
        device_type = "cpu"
        cached = cache.get(config.model_id, str(dtype_str), device_type)
        if cached is not None:
            return cached

    dtype_str = "float32" if config.dtype == "auto" else config.dtype

    start_time = time.perf_counter()

    _logger.info(
        "model_loading_cpu",
        model_id=config.model_id,
        dtype=dtype_str,
    )

    try:
        loaded_model = _load_cpu_model_impl(
            config=config,
            dtype_str=dtype_str,
            start_time=start_time,
            cache=cache,
        )
    except (RuntimeError, ImportError, ValueError, OSError) as exc:
        _logger.warning("cpu_model_load_failed", model_id=config.model_id, error=str(exc))
        gc.collect()
        raise RuntimeError(_ERR_LOAD_CPU_FAILED % (config.model_id, exc)) from exc
    else:
        return loaded_model


def _load_cpu_model_impl(
    *,
    config: ModelConfig,
    dtype_str: DtypeOption,
    start_time: float,
    cache: ModelCache | None,
) -> LoadedModel:
    """Perform the CPU model load and cache insertion.

    Args:
        config: Model configuration.
        dtype_str: Resolved dtype string.
        start_time: ``time.perf_counter()`` reference for load timing.
        cache: Optional cache to populate on success.

    Returns:
        LoadedModel: Loaded model wrapper with metadata.

    Raises:
        ImportError: If required transformers symbols or torch are
            unavailable.
    """
    if AutoModelForCausalLM is None or AutoTokenizer is None or _torch is None:
        raise ImportError(_ERR_MISSING_DEPS)
    torch_dtype = _get_torch_dtype(dtype_str)
    device = _torch.device("cpu")

    tokenizer = AutoTokenizer.from_pretrained(
        config.model_id,
        trust_remote_code=config.trust_remote_code,
        revision=config.revision,
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    load_kwargs: dict[str, object] = {
        "trust_remote_code": config.trust_remote_code,
        "low_cpu_mem_usage": True,
    }

    if dtype_str in {"int8", "int4"}:
        load_kwargs["device_map"] = "cpu"
        load_kwargs["quantization_config"] = _get_quantization_config(dtype_str)
    else:
        load_kwargs["torch_dtype"] = torch_dtype

    model = AutoModelForCausalLM.from_pretrained(
        config.model_id,
        revision=config.revision,
        **load_kwargs,
    )
    model.eval()

    load_time = time.perf_counter() - start_time

    memory_usage = estimate_model_memory(config.model_id, dtype_str, include_activations=False)

    loaded_model = LoadedModel(
        model=model,
        tokenizer=tokenizer,
        device=device,
        dtype=dtype_str,
        memory_usage_bytes=memory_usage,
        model_id=config.model_id,
        load_time_seconds=load_time,
    )

    if cache is not None:
        cache.put(loaded_model)

    _logger.info(
        "model_loaded_cpu",
        model_id=config.model_id,
        dtype=dtype_str,
        load_time_seconds=load_time,
        memory_mb=memory_usage // (1024 * 1024),
    )
    return loaded_model


def _get_torch_dtype(dtype_str: str) -> torch.dtype:
    """Convert dtype string to torch.dtype.

    Args:
        dtype_str: String dtype name.

    Returns:
        torch.dtype: Corresponding torch.dtype.

    Raises:
        ImportError: If torch is not installed.
    """
    if _torch is None:
        _logger.error("get_torch_dtype_torch_unavailable", requested_dtype=dtype_str)
        raise ImportError(_ERR_MISSING_DEPS)

    dtype_map: dict[str, torch.dtype] = {
        "float32": _torch.float32,
        "float16": _torch.float16,
        "bfloat16": _torch.bfloat16,
        "auto": _torch.float16,
    }
    return dtype_map.get(dtype_str, _torch.float32)


def _get_quantization_config(dtype_str: str) -> object:
    """Get a BitsAndBytesConfig for quantized model loading.

    Creates a properly typed ``BitsAndBytesConfig`` object that the
    ``transformers.AutoModelForCausalLM.from_pretrained`` method expects
    for its ``quantization_config`` parameter.  Falls back to a plain
    dictionary when the ``bitsandbytes`` / ``transformers`` packages are
    too old to expose the config class.

    Args:
        dtype_str: Quantization precision, either ``"int8"`` or ``"int4"``.

    Returns:
        object: A ``BitsAndBytesConfig`` instance (preferred) or a plain
        ``dict`` when the config class is unavailable.

    Raises:
        ImportError: If ``torch`` is required for int4 quantization
            but not installed.
    """
    if BitsAndBytesConfig is None:
        _logger.warning(
            "bitsandbytes_config_unavailable",
            dtype=dtype_str,
        )
        if dtype_str == "int8":
            return {"load_in_8bit": True}
        if dtype_str == "int4":
            return {
                "load_in_4bit": True,
                "bnb_4bit_compute_dtype": "float16",
                "bnb_4bit_use_double_quant": True,
            }
        return {}

    if dtype_str == "int8":
        return BitsAndBytesConfig(load_in_8bit=True)

    if dtype_str == "int4":
        if _torch is None:
            raise ImportError(_ERR_MISSING_DEPS)

        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=_torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    return BitsAndBytesConfig()


_cache_state: dict[str, ModelCache] = {}
_cache_lock = threading.Lock()


def get_global_model_cache() -> ModelCache:
    """Get the global model cache singleton.

    Returns:
        ModelCache: The global ModelCache instance.
    """
    with _cache_lock:
        if "cache" not in _cache_state:
            _cache_state["cache"] = ModelCache()
        return _cache_state["cache"]


def set_global_cache_size(max_memory_bytes: int) -> None:
    """Set the global cache size limit.

    Args:
        max_memory_bytes: Maximum memory for the cache.
    """
    cache = get_global_model_cache()
    cache.max_memory_bytes = max_memory_bytes


def clear_global_cache() -> None:
    """Clear the global model cache."""
    cache = get_global_model_cache()
    cache.clear()


RECOMMENDED_MODELS_B580: list[dict[str, object]] = [
    {
        "model_id": "microsoft/Phi-3-mini-4k-instruct",
        "description": "3.8B parameter model, excellent for general tasks",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 7.6,
    },
    {
        "model_id": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        "description": "1.1B parameter model, very fast inference",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 2.2,
    },
    {
        "model_id": "Qwen/Qwen2.5-1.5B-Instruct",
        "description": "1.5B parameter model, good balance of speed and quality",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 3.0,
    },
    {
        "model_id": "Qwen/Qwen2.5-3B-Instruct",
        "description": "3B parameter model, higher quality responses",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 6.0,
    },
    {
        "model_id": "meta-llama/Llama-3.2-1B-Instruct",
        "description": "1B parameter Llama 3.2 model",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 2.0,
    },
    {
        "model_id": "meta-llama/Llama-3.2-3B-Instruct",
        "description": "3B parameter Llama 3.2 model",
        "recommended_dtype": "float16",
        "estimated_memory_gb": 6.0,
    },
    {
        "model_id": "mistralai/Mistral-7B-Instruct-v0.3",
        "description": "7B parameter Mistral, requires INT8 quantization",
        "recommended_dtype": "int8",
        "estimated_memory_gb": 7.0,
    },
]
