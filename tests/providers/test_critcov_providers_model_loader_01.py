# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for ``intellicrack.providers.model_loader``.

These tests drive the guard, fallback and dependency-unavailable paths of the model loader: the local sharded-checkpoint validator's
tolerance of malformed index documents, the empty model identifier short-circuit, the ``ImportError`` raised by every loader entry point
when ``torch`` or ``transformers`` symbols are unavailable, the dictionary fallback returned when ``BitsAndBytesConfig`` is unavailable,
and the XPU loader's refusal to proceed on a host with no XPU device. No model weights are loaded.

The module-level ``torch`` / ``transformers`` bindings of the loader are ``None`` exactly when the optional import failed at import time.
The tests put the loader into that state by assigning ``None`` to the binding for the duration of one ``with`` block and restoring the
original object in ``finally``.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
import torch
from transformers import BitsAndBytesConfig

from intellicrack.core.types import UnsafeCheckpointError
from intellicrack.providers import model_loader
from intellicrack.providers.model_loader import ModelConfig, load_model_for_cpu, load_model_for_xpu, validate_local_checkpoint


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path


_INDEX_NAME: Final[str] = "model.safetensors.index.json"
_MISSING_DEPS_MESSAGE: Final[str] = "transformers and torch are required for model loading"
_UNUSED_MODEL_ID: Final[str] = "intellicrack-unused-model-id"
_ESCAPING_SHARD: Final[str] = "../escape.safetensors"


@contextmanager
def _unavailable(name: str) -> Generator[None]:
    """Put one optional-dependency binding of the loader into its import-failed state.

    Args:
        name: Name of the module-level binding in ``model_loader`` to set to ``None``.

    Yields:
        None: Control while the binding is ``None``; the original object is restored afterwards.
    """
    original = getattr(model_loader, name)
    setattr(model_loader, name, None)
    try:
        yield
    finally:
        setattr(model_loader, name, original)


def _load_cpu_model_impl(config: ModelConfig, dtype_str: str) -> object:
    """Call the module-private CPU load implementation with typing intact.

    Args:
        config: Model configuration to pass through.
        dtype_str: Resolved dtype label to pass through.

    Returns:
        object: Whatever the implementation returns.
    """
    fn = cast("Callable[..., object]", vars(model_loader)["_load_cpu_model_impl"])
    return fn(config=config, dtype_str=dtype_str, start_time=0.0, cache=None)


def _load_xpu_model_impl(config: ModelConfig, dtype_str: str) -> object:
    """Call the module-private XPU load implementation with typing intact.

    Args:
        config: Model configuration to pass through.
        dtype_str: Resolved dtype label to pass through.

    Returns:
        object: Whatever the implementation returns.
    """
    fn = cast("Callable[..., object]", vars(model_loader)["_load_xpu_model_impl"])
    return fn(config=config, dtype_str=dtype_str, start_time=0.0, cache=None)


def _get_torch_dtype(dtype_str: str) -> object:
    """Call the module-private dtype mapper with typing intact.

    Args:
        dtype_str: String dtype name.

    Returns:
        object: The mapped dtype.
    """
    fn = cast("Callable[[str], object]", vars(model_loader)["_get_torch_dtype"])
    return fn(dtype_str)


def _get_quantization_config(dtype_str: str) -> object:
    """Call the module-private quantization-config builder with typing intact.

    Args:
        dtype_str: Quantization precision label.

    Returns:
        object: A ``BitsAndBytesConfig`` or the dictionary fallback.
    """
    fn = cast("Callable[[str], object]", vars(model_loader)["_get_quantization_config"])
    return fn(dtype_str)


def test_empty_model_id_does_not_scan_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty model id returns at once instead of treating ``""`` (the current directory) as a checkpoint.

    ``Path("")`` is ``Path(".")``, an existing directory, so without the early return the hostile index in the working directory would be
    found and rejected. The explicit ``"."`` call first proves that index really is rejected when it is scanned.

    Args:
        tmp_path: Fresh directory used as the working directory.
        monkeypatch: Changes the working directory for the test.
    """
    (tmp_path / _INDEX_NAME).write_text(json.dumps({"weight_map": {"w": _ESCAPING_SHARD}}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(UnsafeCheckpointError):
        validate_local_checkpoint(".")

    validate_local_checkpoint("")


@pytest.mark.parametrize(
    "document_text",
    [
        pytest.param(json.dumps([_ESCAPING_SHARD]), id="list"),
        pytest.param(json.dumps(_ESCAPING_SHARD), id="string"),
        pytest.param("42", id="number"),
        pytest.param("null", id="null"),
    ],
)
def test_index_document_that_is_not_an_object_is_ignored(tmp_path: Path, document_text: str) -> None:
    """A shard index whose top-level JSON value is not an object carries no ``weight_map`` and is skipped.

    Args:
        tmp_path: Fresh checkpoint directory.
        document_text: JSON text of a non-object top-level value.
    """
    (tmp_path / _INDEX_NAME).write_text(document_text, encoding="utf-8")

    validate_local_checkpoint(str(tmp_path))


@pytest.mark.parametrize(
    "weight_map",
    [
        pytest.param([_ESCAPING_SHARD], id="list"),
        pytest.param(_ESCAPING_SHARD, id="string"),
        pytest.param(None, id="null"),
    ],
)
def test_weight_map_that_is_not_an_object_is_ignored(tmp_path: Path, weight_map: object) -> None:
    """A ``weight_map`` that is not an object has no shard entries to validate and is skipped.

    Args:
        tmp_path: Fresh checkpoint directory.
        weight_map: The non-object value stored under ``weight_map``.
    """
    (tmp_path / _INDEX_NAME).write_text(json.dumps({"weight_map": weight_map}), encoding="utf-8")

    validate_local_checkpoint(str(tmp_path))


def test_object_weight_map_with_an_escaping_entry_is_rejected(tmp_path: Path) -> None:
    """The same escaping entry that a non-object ``weight_map`` hides is rejected inside a real mapping.

    Args:
        tmp_path: Fresh checkpoint directory.
    """
    (tmp_path / _INDEX_NAME).write_text(json.dumps({"weight_map": {"w": _ESCAPING_SHARD}}), encoding="utf-8")

    with pytest.raises(UnsafeCheckpointError) as excinfo:
        validate_local_checkpoint(str(tmp_path))

    assert excinfo.value.offending_entry == _ESCAPING_SHARD


@pytest.mark.parametrize("missing", ["_torch", "AutoModelForCausalLM", "AutoTokenizer"])
def test_load_model_for_xpu_reports_missing_dependency(missing: str) -> None:
    """The XPU loader raises ``ImportError`` as soon as any one required binding is unavailable.

    Args:
        missing: Name of the loader binding made unavailable.
    """
    with _unavailable(missing), pytest.raises(ImportError) as excinfo:
        load_model_for_xpu(ModelConfig(model_id=_UNUSED_MODEL_ID))

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE


@pytest.mark.parametrize("missing", ["_torch", "AutoModelForCausalLM", "AutoTokenizer"])
def test_load_model_for_cpu_reports_missing_dependency(missing: str) -> None:
    """The CPU loader raises ``ImportError`` as soon as any one required binding is unavailable.

    Args:
        missing: Name of the loader binding made unavailable.
    """
    with _unavailable(missing), pytest.raises(ImportError) as excinfo:
        load_model_for_cpu(ModelConfig(model_id=_UNUSED_MODEL_ID))

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE


@pytest.mark.parametrize("missing", ["_torch", "AutoModelForCausalLM", "AutoTokenizer"])
def test_cpu_load_implementation_reports_missing_dependency(missing: str) -> None:
    """The CPU load implementation re-checks its own dependencies and raises ``ImportError``.

    Args:
        missing: Name of the loader binding made unavailable.
    """
    with _unavailable(missing), pytest.raises(ImportError) as excinfo:
        _load_cpu_model_impl(ModelConfig(model_id=_UNUSED_MODEL_ID), "float32")

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE


def test_torch_dtype_lookup_requires_torch() -> None:
    """Mapping a dtype string without ``torch`` raises the dependency ``ImportError``, not an ``AttributeError``."""
    with _unavailable("_torch"), pytest.raises(ImportError) as excinfo:
        _get_torch_dtype("float16")

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE


def test_xpu_load_implementation_resolves_dtype_before_touching_the_device() -> None:
    """The XPU implementation maps the dtype first, so a missing ``torch`` surfaces as ``ImportError``.

    The host has no XPU, so were the dtype mapping skipped the device initialization would raise ``RuntimeError`` instead.
    """
    with _unavailable("_torch"), pytest.raises(ImportError) as excinfo:
        _load_xpu_model_impl(ModelConfig(model_id=_UNUSED_MODEL_ID), "float16")

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE


def test_xpu_load_implementation_fails_when_no_xpu_device_exists() -> None:
    """With ``torch`` present but no XPU on the host, device initialization raises ``RuntimeError`` naming the XPU."""
    with pytest.raises(RuntimeError) as excinfo:
        _load_xpu_model_impl(ModelConfig(model_id=_UNUSED_MODEL_ID), "float16")

    assert "XPU" in str(excinfo.value)


def test_int8_fallback_without_bitsandbytes_config_is_the_documented_dictionary() -> None:
    """Without ``BitsAndBytesConfig``, int8 yields a plain dict that the real config class accepts as keyword arguments."""
    with _unavailable("BitsAndBytesConfig"):
        result = _get_quantization_config("int8")

    assert result == {"load_in_8bit": True}
    config = BitsAndBytesConfig(**cast("dict[str, Any]", result))
    assert getattr(config, "load_in_8bit", None) is True
    assert getattr(config, "load_in_4bit", None) is False


def test_int4_fallback_without_bitsandbytes_config_is_the_documented_dictionary() -> None:
    """Without ``BitsAndBytesConfig``, int4 yields a plain dict that the real config class accepts as keyword arguments."""
    with _unavailable("BitsAndBytesConfig"):
        result = _get_quantization_config("int4")

    assert result == {
        "load_in_4bit": True,
        "bnb_4bit_compute_dtype": "float16",
        "bnb_4bit_use_double_quant": True,
    }
    config = BitsAndBytesConfig(**cast("dict[str, Any]", result))
    assert getattr(config, "load_in_4bit", None) is True
    assert getattr(config, "load_in_8bit", None) is False
    assert getattr(config, "bnb_4bit_compute_dtype", None) is torch.float16
    assert getattr(config, "bnb_4bit_use_double_quant", None) is True


@pytest.mark.parametrize("dtype_str", ["float16", "float32", "auto"])
def test_non_quantized_dtype_fallback_without_bitsandbytes_config_is_empty(dtype_str: str) -> None:
    """Without ``BitsAndBytesConfig``, a dtype that is not a quantization precision yields an empty dict.

    Args:
        dtype_str: A non-quantization dtype label.
    """
    with _unavailable("BitsAndBytesConfig"):
        result = _get_quantization_config(dtype_str)

    assert result == {}


def test_int4_quantization_requires_torch_for_the_compute_dtype() -> None:
    """Building the real int4 config needs ``torch.float16``, so a missing ``torch`` raises ``ImportError``."""
    with _unavailable("_torch"), pytest.raises(ImportError) as excinfo:
        _get_quantization_config("int4")

    assert str(excinfo.value) == _MISSING_DEPS_MESSAGE
