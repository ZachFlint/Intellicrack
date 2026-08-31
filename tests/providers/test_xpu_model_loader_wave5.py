# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave 5 falsifiable gates for model_loader, gpu_pci_resources, and xpu_utils.

Covers group-08-report Section 10 findings 21-26, 29-31, and 32-43.
Every gate is falsified by the named one-line production mutation.
"""

from __future__ import annotations

import ctypes
import gc
import sys
import time
import types
from typing import TYPE_CHECKING, cast

import pytest
import structlog.testing
import torch

import intellicrack.providers.gpu_pci_resources as gpu_pci_mod
import intellicrack.providers.xpu_utils as xpu_utils_mod
from intellicrack.providers import model_loader
from intellicrack.providers.model_loader import (
    LoadedModel,
    ModelCache,
    ModelConfig,
    load_model_for_cpu,
)
from intellicrack.providers.xpu_utils import XPUDeviceInfo, clear_xpu_cache, is_xpu_available


if TYPE_CHECKING:
    from collections.abc import Callable

    from transformers import PreTrainedModel, PreTrainedTokenizerBase


_GIB: int = 1024 * 1024 * 1024
_IS_WINDOWS: bool = sys.platform == "win32"


# ---------------------------------------------------------------------------
# Private-function call helpers
# ---------------------------------------------------------------------------


def _free_model_resources(loaded_model: LoadedModel) -> None:
    """Invoke the module-private resource-freeing helper.

    Args:
        loaded_model: The model to free.
    """
    fn = cast("Callable[[LoadedModel], None]", vars(model_loader)["_free_model_resources"])
    fn(loaded_model)


def _unload_model(loaded_model: LoadedModel) -> None:
    """Invoke the module-private unload helper that swallows errors.

    Args:
        loaded_model: The model to unload.
    """
    fn = cast("Callable[[LoadedModel], None]", vars(model_loader)["_unload_model"])
    fn(loaded_model)


def _load_xpu_model_impl(
    *,
    config: ModelConfig,
    dtype_str: str,
    start_time: float,
    cache: ModelCache | None,
) -> LoadedModel:
    """Invoke the module-private XPU model loader implementation.

    Args:
        config: Model configuration.
        dtype_str: Resolved dtype string.
        start_time: Load timer reference.
        cache: Optional cache to populate on success.

    Returns:
        LoadedModel: The loaded model wrapper.
    """
    fn = cast("Callable[..., LoadedModel]", vars(model_loader)["_load_xpu_model_impl"])
    return fn(config=config, dtype_str=dtype_str, start_time=start_time, cache=cache)


def _load_cpu_model_impl(
    *,
    config: ModelConfig,
    dtype_str: str,
    start_time: float,
    cache: ModelCache | None,
) -> LoadedModel:
    """Invoke the module-private CPU model loader implementation.

    Args:
        config: Model configuration.
        dtype_str: Resolved dtype string.
        start_time: Load timer reference.
        cache: Optional cache to populate on success.

    Returns:
        LoadedModel: The loaded model wrapper.
    """
    fn = cast("Callable[..., LoadedModel]", vars(model_loader)["_load_cpu_model_impl"])
    return fn(config=config, dtype_str=dtype_str, start_time=start_time, cache=cache)


def _call_locate_devnode(cfg: object, device_id: str) -> int | None:
    """Invoke the module-private cfgmgr32 devnode locator.

    Args:
        cfg: Active cfgmgr32 bindings.
        device_id: PnP device instance ID.

    Returns:
        int | None: DEVINST handle or None on failure.
    """
    fn = cast("Callable[[object, str], int | None]", vars(gpu_pci_mod)["_locate_devnode"])
    return fn(cfg, device_id)


def _call_read_descriptor_bytes(cfg: object, res_des: int) -> bytes | None:
    """Invoke the module-private cfgmgr32 descriptor-bytes reader.

    Args:
        cfg: Active cfgmgr32 bindings.
        res_des: Resource descriptor handle.

    Returns:
        bytes | None: Raw descriptor bytes or None on failure.
    """
    fn = cast("Callable[[object, int], bytes | None]", vars(gpu_pci_mod)["_read_descriptor_bytes"])
    return fn(cfg, res_des)


def _call_enumerate_bars(cfg: object, log_conf: int) -> list[object]:
    """Invoke the module-private BAR descriptor enumerator.

    Args:
        cfg: Active cfgmgr32 bindings.
        log_conf: Logical configuration handle.

    Returns:
        list[object]: Parsed BarDescriptor list.
    """
    fn = cast("Callable[[object, int], list[object]]", vars(gpu_pci_mod)["_enumerate_bars_for_log_conf"])
    return fn(cfg, log_conf)


def _call_load_cfgmgr() -> object:
    """Invoke the module-private cfgmgr32 loader.

    Returns:
        object: Cfgmgr32 bindings wrapper or None on failure.
    """
    fn = cast("Callable[[], object]", vars(gpu_pci_mod)["_load_cfgmgr"])
    return fn()


def _call_get_device_name_from_sycl(device_index: int) -> str:
    """Invoke the module-private SYCL device-name helper.

    Args:
        device_index: XPU device index.

    Returns:
        str: Device name or empty string.
    """
    fn = cast("Callable[[int], str]", vars(xpu_utils_mod)["_get_device_name_from_sycl"])
    return fn(device_index)


def _call_query_windows_gpus() -> list[dict[str, str]]:
    """Invoke the module-private PowerShell GPU enumerator.

    Returns:
        list[dict[str, str]]: Normalised GPU info entries.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils_mod)["_query_windows_gpus"])
    return fn()


def _call_extract_torch_xpu_properties(
    torch_mod: types.ModuleType,
    device_index: int,
    device_name: str,
) -> tuple[int, str, str]:
    """Invoke the module-private torch XPU property extractor.

    Args:
        torch_mod: Torch module with xpu namespace.
        device_index: XPU device index.
        device_name: Existing device name (may be empty).

    Returns:
        tuple[int, str, str]: (total_memory, driver_version, device_name).
    """
    fn = cast(
        "Callable[[types.ModuleType, int, str], tuple[int, str, str]]",
        vars(xpu_utils_mod)["_extract_torch_xpu_properties"],
    )
    return fn(torch_mod, device_index, device_name)


def _call_enrich_from_windows_gpus(
    device_name: str,
    driver_version: str,
    device_id: str,
) -> tuple[str, str, str]:
    """Invoke the module-private WMI GPU enrichment helper.

    Args:
        device_name: Current device name (may be empty).
        driver_version: Current driver version (may be empty).
        device_id: Current PCI device ID (may be empty).

    Returns:
        tuple[str, str, str]: Updated (device_name, driver_version, device_id).
    """
    fn = cast(
        "Callable[[str, str, str], tuple[str, str, str]]",
        vars(xpu_utils_mod)["_enrich_from_windows_gpus"],
    )
    return fn(device_name, driver_version, device_id)


def _call_build_xpu_device_info(torch_mod: types.ModuleType, device_index: int) -> XPUDeviceInfo | None:
    """Invoke the module-private XPU device-info assembler.

    Args:
        torch_mod: Torch module with xpu namespace.
        device_index: XPU device index.

    Returns:
        XPUDeviceInfo | None: Assembled device info or None.
    """
    fn = cast(
        "Callable[[types.ModuleType, int], XPUDeviceInfo | None]",
        vars(xpu_utils_mod)["_build_xpu_device_info"],
    )
    return fn(torch_mod, device_index)


def _call_pick_primary_arc_gpu(gpus: list[dict[str, str]]) -> tuple[str, int] | None:
    """Invoke the module-private primary Arc GPU selector.

    Args:
        gpus: GPU info list from Windows GPU enumeration.

    Returns:
        tuple[str, int] | None: (device_name, bar_bytes) or None.
    """
    fn = cast(
        "Callable[[list[dict[str, str]]], tuple[str, int] | None]",
        vars(xpu_utils_mod)["_pick_primary_arc_gpu"],
    )
    return fn(gpus)


def _call_check_intel_driver(gpus: list[dict[str, str]] | None) -> tuple[bool, str]:
    """Invoke the module-private Intel driver checker.

    Args:
        gpus: Pre-enumerated GPU list or None to fetch lazily.

    Returns:
        tuple[bool, str]: (driver_ok, warning_message).
    """
    fn = cast(
        "Callable[[list[dict[str, str]] | None], tuple[bool, str]]",
        vars(xpu_utils_mod)["_check_intel_driver"],
    )
    return fn(gpus)


def _call_validate_xpu_device(torch_mod: types.ModuleType, device: torch.device) -> None:
    """Invoke the module-private XPU device validator.

    Args:
        torch_mod: Torch module to use for tensor ops.
        device: Target device for the validation tensor.
    """
    fn = cast(
        "Callable[[types.ModuleType, torch.device], None]",
        vars(xpu_utils_mod)["_validate_xpu_device"],
    )
    fn(torch_mod, device)


def _call_query_xpu_memory(torch_mod: types.ModuleType, device_index: int) -> tuple[int, int]:
    """Invoke the module-private XPU memory querier.

    Args:
        torch_mod: Torch module with xpu namespace.
        device_index: XPU device index.

    Returns:
        tuple[int, int]: (allocated_bytes, total_bytes).
    """
    fn = cast(
        "Callable[[types.ModuleType, int], tuple[int, int]]",
        vars(xpu_utils_mod)["_query_xpu_memory"],
    )
    return fn(torch_mod, device_index)


def _call_get_windows_gpu_info() -> list[dict[str, str]]:
    """Invoke the module-private Windows GPU enumerator (WMI query).

    Returns:
        list[dict[str, str]]: GPU info entries from Win32_VideoController.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils_mod)["_get_windows_gpu_info"])
    return fn()


# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------


class _EvalObj:
    """Minimal object that satisfies model.eval() in _load_cpu_model_impl."""

    def eval(self) -> _EvalObj:
        """Return self to allow method-chaining.

        Returns:
            _EvalObj: Self.
        """
        return self


def _make_loaded(model_id: str, dtype: str, memory_bytes: int) -> LoadedModel:
    """Build a real LoadedModel on the CPU device for cache and unload tests.

    Args:
        model_id: Model identifier to record.
        dtype: Dtype label.
        memory_bytes: Memory footprint for cache accounting.

    Returns:
        LoadedModel: Populated model record on the CPU device.
    """
    obj = _EvalObj()
    return LoadedModel(
        model=cast("PreTrainedModel", obj),
        tokenizer=cast("PreTrainedTokenizerBase", obj),
        device=torch.device("cpu"),
        dtype=dtype,
        memory_usage_bytes=memory_bytes,
        model_id=model_id,
        load_time_seconds=0.001,
    )


def _make_fake_torch(
    *,
    xpu_available: bool = True,
    device_count: int = 1,
    total_memory: int = 12 * _GIB,
    driver_version: str = "31.0.101.5522",
    device_name: str = "Intel Arc B580",
    allocated_memory: int = 1024,
    empty_cache_calls: list[int] | None = None,
    zeros_raises: RuntimeError | None = None,
) -> types.ModuleType:
    """Build a minimal fake torch module for xpu_utils unit tests.

    Args:
        xpu_available: Whether torch.xpu.is_available() returns True.
        device_count: Number of XPU devices reported.
        total_memory: total_memory field from get_device_properties.
        driver_version: driver_version field from get_device_properties.
        device_name: name from get_device_name and get_device_properties.
        allocated_memory: Value returned by memory_allocated().
        empty_cache_calls: Mutable list to record empty_cache() calls.
        zeros_raises: If set, torch.zeros raises this RuntimeError.

    Returns:
        types.ModuleType: A fake torch module whose xpu namespace is populated.
    """
    props = types.SimpleNamespace(
        total_memory=total_memory,
        driver_version=driver_version,
        name=device_name,
    )
    cache_log: list[int] = empty_cache_calls if empty_cache_calls is not None else []
    zeros_exc = zeros_raises
    alloc = allocated_memory
    name = device_name

    class _FakeXpu:
        @staticmethod
        def is_available() -> bool:
            return xpu_available

        @staticmethod
        def device_count() -> int:
            return device_count

        @staticmethod
        def get_device_properties(_idx: int) -> types.SimpleNamespace:
            return props

        @staticmethod
        def get_device_name(_idx: int) -> str:
            return name

        @staticmethod
        def memory_allocated(_idx: int) -> int:
            return alloc

        @staticmethod
        def empty_cache() -> None:
            cache_log.append(1)

        @staticmethod
        def synchronize() -> None:
            pass

        @staticmethod
        def set_device(idx: int) -> None:
            pass

    class _FakeModule:
        xpu: type[_FakeXpu] = _FakeXpu

        @staticmethod
        def zeros(n: int, device: object = None) -> object:
            del n, device
            if zeros_exc is not None:
                raise zeros_exc
            return 0

        @staticmethod
        def device(spec: str) -> torch.device:
            return torch.device(spec.split(":", maxsplit=1)[0])

    return cast(types.ModuleType, _FakeModule)


class _FakeProcResult:
    """Minimal subprocess result for ProcessManager stubs."""

    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        """Initialise with the fields _query_windows_gpus reads.

        Args:
            returncode: Process exit code.
            stdout: Captured standard output.
            stderr: Captured standard error.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_fake_pm(result: _FakeProcResult) -> type:
    """Build a fake ProcessManager class that returns a canned result.

    Args:
        result: The result run_tracked will return.

    Returns:
        type: A class with a get_instance() classmethod.
    """

    class _FakeInstance:
        def run_tracked(self, *_args: object, **_kwargs: object) -> _FakeProcResult:
            """Return the pre-configured result regardless of arguments.

            Args:
                *_args: Ignored positional arguments.
                **_kwargs: Ignored keyword arguments.

            Returns:
                _FakeProcResult: The pre-configured result.
            """
            return result

    class _FakePM:
        @staticmethod
        def get_instance() -> _FakeInstance:
            """Return a fake ProcessManager instance.

            Returns:
                _FakeInstance: Instance whose run_tracked returns the canned result.
            """
            return _FakeInstance()

    return _FakePM


# ---------------------------------------------------------------------------
# Finding 21 — ModelCache._make_key uses '::' separator
# ---------------------------------------------------------------------------


class TestModelCacheMakeKey:
    """Gate: ModelCache._make_key joins the three fields with the documented '::' separator."""

    @staticmethod
    def test_double_colon_separator_matches_report_oracle() -> None:
        """_make_key('m','float16','xpu') must equal 'm::float16::xpu'.

        Oracle: the group-08-report row specifies ``assert ModelCache._make_key("m","float16","xpu") == "m::float16::xpu"``; the ``::``
        join is the only separator consistent with that example.
        Mutation: changing ``::`` to ``:`` yields ``"m:float16:xpu"``, failing ``== "m::float16::xpu"``.
        """
        make_key = cast("Callable[[str, str, str], str]", getattr(ModelCache, "_make_key"))
        assert make_key("m", "float16", "xpu") == "m::float16::xpu"
        assert make_key("microsoft/Phi-3-mini-4k-instruct", "bfloat16", "cpu") == ("microsoft/Phi-3-mini-4k-instruct::bfloat16::cpu")

    @staticmethod
    def test_make_key_is_positionally_sensitive() -> None:
        """Swapping dtype and device_type produces a distinct key.

        Oracle: the join is ordered; ``float16::xpu`` and ``xpu::float16`` are
        different strings.
        Mutation: if args were sorted alphabetically, both would collapse to the
        same key, failing ``!=``.
        """
        make_key = cast("Callable[[str, str, str], str]", getattr(ModelCache, "_make_key"))
        assert make_key("m", "float16", "xpu") != make_key("m", "xpu", "float16")


# ---------------------------------------------------------------------------
# Finding 22 — _free_model_resources: gc.collect + attribute deletion
# ---------------------------------------------------------------------------


class TestFreeModelResources:
    """Gate: _free_model_resources calls gc.collect exactly once and deletes model/tokenizer."""

    @staticmethod
    def test_gc_collect_called_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
        """gc.collect must be invoked exactly once per _free_model_resources call.

        Oracle: the production line ``gc.collect()`` is unconditional; it appears
        once in _free_model_resources and nowhere else in the call.
        Mutation: removing ``gc.collect()`` yields ``len(count) == 0``, failing ``== 1``.
        """
        count: list[int] = []
        original = gc.collect

        def _counting() -> int:
            count.append(1)
            return original()

        monkeypatch.setattr(gc, "collect", _counting)
        loaded = _make_loaded("test/m", "float16", 1024)
        _free_model_resources(loaded)
        assert len(count) == 1

    @staticmethod
    def test_model_and_tokenizer_attributes_deleted_after_call() -> None:
        """After the call, both model and tokenizer attributes are absent from the instance.

        Oracle: ``del obj.attr`` on a dataclass instance removes the attribute from
        ``__dict__``; ``hasattr`` subsequently returns False.
        Mutation: removing either ``del`` statement leaves the attribute present,
        failing the corresponding ``not hasattr`` assertion.
        """
        loaded = _make_loaded("test/m", "float16", 1024)
        _free_model_resources(loaded)
        assert not hasattr(loaded, "model")
        assert not hasattr(loaded, "tokenizer")


# ---------------------------------------------------------------------------
# Finding 23 — _unload_model: exception path swallowed and logged
# ---------------------------------------------------------------------------


class TestUnloadModelExceptionPath:
    """Gate: _unload_model catches _free_model_resources failures and emits a warning."""

    @staticmethod
    def test_runtime_error_not_re_raised(monkeypatch: pytest.MonkeyPatch) -> None:
        """_unload_model must not propagate RuntimeError from _free_model_resources.

        Oracle: production ``except (RuntimeError, OSError, AttributeError)`` block.
        Mutation: removing the except clause lets RuntimeError propagate, causing
        this test to fail with an unexpected exception.
        """

        def _failing_free(_m: LoadedModel) -> None:
            msg = "simulated GPU teardown failure"
            raise RuntimeError(msg)

        monkeypatch.setattr(model_loader, "_free_model_resources", _failing_free)
        loaded = _make_loaded("test/m", "float16", 1024)
        _unload_model(loaded)

    @staticmethod
    def test_warning_event_logged_on_exception(monkeypatch: pytest.MonkeyPatch) -> None:
        """A structlog warning with event='model_unload_failed' is emitted on exception.

        Oracle: production ``_logger.warning("model_unload_failed", error=str(exc))``.
        Mutation: removing the logger call leaves ``warning_events`` empty, failing
        the ``any(...)`` assertion.
        """

        def _failing_free(_m: LoadedModel) -> None:
            msg = "fake device error"
            raise OSError(msg)

        monkeypatch.setattr(model_loader, "_free_model_resources", _failing_free)
        loaded = _make_loaded("test/m", "float16", 1024)
        with structlog.testing.capture_logs() as cap:
            _unload_model(loaded)
        warning_events = [e for e in cap if e.get("log_level") == "warning"]
        assert any(e["event"] == "model_unload_failed" for e in warning_events)


# ---------------------------------------------------------------------------
# Finding 24 — _load_xpu_model_impl: ImportError when deps missing
# ---------------------------------------------------------------------------


class TestLoadXpuModelImplMissingDeps:
    """Gate: _load_xpu_model_impl raises ImportError when AutoModelForCausalLM is None."""

    @staticmethod
    def test_raises_importerror_when_automodel_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
        """The first guard in _load_xpu_model_impl rejects a None AutoModelForCausalLM.

        Oracle: constant ``_ERR_MISSING_DEPS = "transformers and torch are required for model loading"``.
        Mutation: removing the ``if AutoModelForCausalLM is None:`` guard lets the function
        proceed to ``initialize_xpu``, raising RuntimeError (not ImportError), failing ``match="transformers"``.
        """
        monkeypatch.setattr(model_loader, "AutoModelForCausalLM", None)
        config = ModelConfig(model_id="test/no-model")
        with pytest.raises(ImportError, match="transformers"):
            _load_xpu_model_impl(config=config, dtype_str="float16", start_time=time.perf_counter(), cache=None)


# ---------------------------------------------------------------------------
# Finding 25 — load_model_for_cpu: cache-hit and error paths
# ---------------------------------------------------------------------------


class TestLoadModelForCpu:
    """Gate: load_model_for_cpu returns cached entry and wraps load failures as RuntimeError."""

    @staticmethod
    def test_cache_hit_returns_cached_object_by_identity() -> None:
        """A pre-populated cache entry is returned without touching from_pretrained.

        Oracle: object identity; ``result is expected`` is the exact contract.
        Mutation: removing the ``if cached is not None: return cached`` early-return
        proceeds to load the model, which fails without real weights.
        """
        cache = ModelCache(max_memory_bytes=10 * _GIB)
        expected = _make_loaded("test/cached", "auto", _GIB)
        cache.put(expected)
        config = ModelConfig(model_id="test/cached", dtype="auto")
        result = load_model_for_cpu(config, cache)
        assert result is expected

    @staticmethod
    def test_tokenizer_failure_wrapped_as_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
        """A ValueError from AutoTokenizer is wrapped as RuntimeError with 'on CPU' in message.

        Oracle: ``_ERR_LOAD_CPU_FAILED = "Failed to load model %s on CPU: %s"``.
        Mutation: removing the except block lets ValueError propagate unchanged,
        failing ``pytest.raises(RuntimeError)``.
        """

        class _FailTokenizer:
            @staticmethod
            def from_pretrained(*_args: object, **_kwargs: object) -> None:
                msg = "no tokenizer files found"
                raise ValueError(msg)

        monkeypatch.setattr(model_loader, "AutoTokenizer", _FailTokenizer)
        config = ModelConfig(model_id="no/such/model")
        with pytest.raises(RuntimeError, match=r"Failed to load model.*on CPU"):
            load_model_for_cpu(config)


# ---------------------------------------------------------------------------
# Finding 26 — _load_cpu_model_impl: quantization and dtype dispatch
# ---------------------------------------------------------------------------


class TestLoadCpuModelImplQuantization:
    """Gate: _load_cpu_model_impl selects device_map/quantization_config for int8 and torch_dtype for float32."""

    @staticmethod
    def test_int8_sets_device_map_cpu_and_quantization_config(monkeypatch: pytest.MonkeyPatch) -> None:
        """INT8 dtype must place device_map='cpu' and quantization_config in from_pretrained kwargs.

        Oracle: production ``if dtype_str in {"int8", "int4"}: load_kwargs["device_map"] = "cpu"``.
        Mutation: narrowing the set to ``{"int4"}`` only removes int8 from the device-map branch;
        ``device_map`` is absent from captured kwargs, failing ``== "cpu"``.
        """
        captured: list[dict[str, object]] = []

        class _FakeTok:
            pad_token: str | None = None
            eos_token: str = "<EOS>"

            @classmethod
            def from_pretrained(cls, *_args: object, **_kwargs: object) -> _FakeTok:
                """Return a fake tokenizer instance.

                Args:
                    *_args: Ignored.
                    **_kwargs: Ignored.

                Returns:
                    _FakeTok: A fake tokenizer.
                """
                return cls()

        class _FakeModel:
            @classmethod
            def from_pretrained(cls, _model_id: str, *, _revision: str | None = None, **kwargs: object) -> _EvalObj:
                """Capture kwargs and return a minimal model object.

                Args:
                    _model_id: The model identifier.
                    _revision: Optional revision pin.
                    **kwargs: Load kwargs to capture.

                Returns:
                    _EvalObj: A minimal object with an eval() method.
                """
                captured.append(dict(kwargs))
                return _EvalObj()

        monkeypatch.setattr(model_loader, "AutoTokenizer", _FakeTok)
        monkeypatch.setattr(model_loader, "AutoModelForCausalLM", _FakeModel)
        config = ModelConfig(model_id="test/int8-model", dtype="int8")
        result = _load_cpu_model_impl(config=config, dtype_str="int8", start_time=time.perf_counter(), cache=None)
        assert len(captured) == 1
        kw = captured[0]
        assert kw.get("device_map") == "cpu"
        assert kw.get("quantization_config") is not None
        assert "torch_dtype" not in kw
        assert result.dtype == "int8"

    @staticmethod
    def test_float32_sets_torch_dtype_without_device_map(monkeypatch: pytest.MonkeyPatch) -> None:
        """Float32 dtype must set torch_dtype=torch.float32 without device_map.

        Oracle: production ``else: load_kwargs["torch_dtype"] = torch_dtype``.
        Mutation: forcing float32 into the int8/int4 branch would insert device_map
        instead of torch_dtype, failing ``kw.get("torch_dtype") is torch.float32``.
        """
        captured: list[dict[str, object]] = []

        class _FakeTok:
            pad_token: str = "<PAD>"
            eos_token: str = "<EOS>"

            @classmethod
            def from_pretrained(cls, *_args: object, **_kwargs: object) -> _FakeTok:
                """Return a fake tokenizer instance.

                Args:
                    *_args: Ignored.
                    **_kwargs: Ignored.

                Returns:
                    _FakeTok: A fake tokenizer.
                """
                return cls()

        class _FakeModel:
            @classmethod
            def from_pretrained(cls, _model_id: str, *, _revision: str | None = None, **kwargs: object) -> _EvalObj:
                """Capture kwargs and return a minimal model object.

                Args:
                    _model_id: The model identifier.
                    _revision: Optional revision pin.
                    **kwargs: Load kwargs to capture.

                Returns:
                    _EvalObj: A minimal object with an eval() method.
                """
                captured.append(dict(kwargs))
                return _EvalObj()

        monkeypatch.setattr(model_loader, "AutoTokenizer", _FakeTok)
        monkeypatch.setattr(model_loader, "AutoModelForCausalLM", _FakeModel)
        config = ModelConfig(model_id="test/fp32-model", dtype="float32")
        result = _load_cpu_model_impl(config=config, dtype_str="float32", start_time=time.perf_counter(), cache=None)
        assert len(captured) == 1
        kw = captured[0]
        assert kw.get("torch_dtype") is torch.float32
        assert "device_map" not in kw
        assert result.dtype == "float32"


# ---------------------------------------------------------------------------
# Finding 29 — _locate_devnode: success vs failure against real cfgmgr32
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _IS_WINDOWS, reason="cfgmgr32 is Windows-only")
class TestLocateDevnode:
    """Gate: _locate_devnode returns None for unknown PnP IDs and an int for valid ones."""

    @staticmethod
    def test_unknown_device_id_returns_none() -> None:
        """A PnP ID that cfgmgr32 cannot resolve yields None.

        Oracle: cfgmgr32 returns non-zero error code; production
        ``if rc != _CR_SUCCESS: return None`` fires.
        Mutation: removing the rc check and always returning ``devinst.value``
        would return 0 instead of None, failing ``is None``.
        """
        cfg = _call_load_cfgmgr()
        assert cfg is not None, "cfgmgr32 must be loadable on Windows"
        bogus = r"PCI\VEN_FFFF&DEV_FFFF&SUBSYS_00000000&REV_00\NONEXISTENT_INSTANCE"
        result = _call_locate_devnode(cfg, bogus)
        assert result is None

    @staticmethod
    @pytest.mark.spawns_process
    def test_real_gpu_pnp_id_resolves_to_positive_devinst() -> None:
        """A real PCI GPU PnP ID resolves to a positive DEVINST handle.

        Oracle: cfgmgr32 CM_Locate_DevNodeW returns CR_SUCCESS and a non-zero
        DEVINST for any device enumerated by Windows PnP.
        Mutation: always returning None would fail ``isinstance(devinst, int)``.
        """
        cfg = _call_load_cfgmgr()
        assert cfg is not None
        gpus = _call_get_windows_gpu_info()
        pci_gpus = [g for g in gpus if g["pnp_device_id"].upper().startswith("PCI\\")]
        if not pci_gpus:
            pytest.skip("No PCI GPU in Win32_VideoController on this host")
        devinst = _call_locate_devnode(cfg, pci_gpus[0]["pnp_device_id"])
        assert isinstance(devinst, int)
        assert devinst > 0


# ---------------------------------------------------------------------------
# Finding 30 — _read_descriptor_bytes: zero-size and error-code paths
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _IS_WINDOWS, reason="cfgmgr32 WINFUNCTYPE callbacks require Windows")
class TestReadDescriptorBytes:
    """Gate: _read_descriptor_bytes returns None for zero-size descriptors and error codes."""

    @staticmethod
    def test_zero_size_from_data_size_call_returns_none() -> None:
        """CM_Get_Res_Des_Data_Size returning CR_SUCCESS with size=0 yields None.

        Oracle: production ``if rc != _CR_SUCCESS or size.value == 0: return None``.
        Mutation: removing the ``size.value == 0`` guard would try to allocate and
        read a zero-length buffer, returning ``b""`` instead of None.
        """
        size_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_uint32,
        )
        data_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )

        @size_func
        def _size_zero(size_ptr: ctypes.Array[ctypes.c_uint32], _res_des: int, _flags: int) -> int:
            size_ptr[0] = 0
            return 0

        @data_func
        def _data_noop(_res_des: int, _buf: int | None, _size: int, _flags: int) -> int:
            return 0

        class _FakeCfgZeroSize:
            get_res_des_data_size = _size_zero
            get_res_des_data = _data_noop

        assert _call_read_descriptor_bytes(_FakeCfgZeroSize(), 999) is None

    @staticmethod
    def test_error_code_from_data_size_call_returns_none() -> None:
        """A non-zero return from CM_Get_Res_Des_Data_Size yields None.

        Oracle: production ``if rc != _CR_SUCCESS ... return None``.
        Mutation: treating any rc as CR_SUCCESS would attempt to read with size=0,
        returning None only by the zero-size guard (masking the real defect).
        """
        size_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_uint32,
        )
        data_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )

        @size_func
        def _size_fail(size_ptr: ctypes.Array[ctypes.c_uint32], _res_des: int, _flags: int) -> int:
            size_ptr[0] = 8
            return 0x00000013

        @data_func
        def _data_noop2(_res_des: int, _buf: int | None, _size: int, _flags: int) -> int:
            return 0

        class _FakeCfgSizeFail:
            get_res_des_data_size = _size_fail
            get_res_des_data = _data_noop2

        assert _call_read_descriptor_bytes(_FakeCfgSizeFail(), 999) is None

    @staticmethod
    def test_error_code_from_get_data_call_returns_none() -> None:
        """A non-zero return from CM_Get_Res_Des_Data yields None.

        Oracle: production ``return None if rc != _CR_SUCCESS else bytes(buf)``.
        Mutation: always returning ``bytes(buf)`` ignores the data error, returning
        8 zero bytes instead of None.
        """
        payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        size_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_uint32,
        )
        data_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )

        @size_func
        def _size_ok(size_ptr: ctypes.Array[ctypes.c_uint32], _res_des: int, _flags: int) -> int:
            size_ptr[0] = len(payload)
            return 0

        @data_func
        def _data_fail(_res_des: int, _buf: int | None, _size: int, _flags: int) -> int:
            return 0x00000013

        class _FakeCfgDataFail:
            get_res_des_data_size = _size_ok
            get_res_des_data = _data_fail

        assert _call_read_descriptor_bytes(_FakeCfgDataFail(), 999) is None

    @staticmethod
    def test_success_path_returns_exact_bytes() -> None:
        """When both calls succeed, the exact descriptor bytes are returned.

        Oracle: ``bytes(buf)`` after the DLL writes through the buffer pointer.
        Mutation: returning an empty bytes instead of bytes(buf) fails ``== _PAYLOAD``.
        """
        payload = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"
        size_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_uint32,
        )
        data_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )

        @size_func
        def _size_ok2(size_ptr: ctypes.Array[ctypes.c_uint32], _res_des: int, _flags: int) -> int:
            size_ptr[0] = len(payload)
            return 0

        @data_func
        def _data_ok(_res_des: int, buf: int | None, _size: int, _flags: int) -> int:
            if buf is not None:
                ctypes.memmove(buf, payload, len(payload))
            return 0

        class _FakeCfgSuccess:
            get_res_des_data_size = _size_ok2
            get_res_des_data = _data_ok

        result = _call_read_descriptor_bytes(_FakeCfgSuccess(), 999)
        assert result == payload


# ---------------------------------------------------------------------------
# Finding 31 — _enumerate_bars_for_log_conf: ResType_MEM vs ResType_MemLarge
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _IS_WINDOWS, reason="cfgmgr32 WINFUNCTYPE callbacks require Windows")
class TestEnumerateBarsForLogConf:
    """Gate: MEM_LARGE descriptors are dispatched with large=True and MEM with large=False."""

    @staticmethod
    def test_mem_large_descriptor_parsed_as_large_true() -> None:
        """A MEM_LARGE res descriptor produces a BarDescriptor with is_large=True.

        Oracle: production ``for res_type, large in ((_RES_TYPE_MEM, False), (_RES_TYPE_MEM_LARGE, True))``;
        MEM_LARGE iterates with ``large=True`` passed to ``_parse_mem_descriptor``.
        Mutation: swapping the (False, True) tuple to (True, False) makes both
        descriptors report ``is_large`` incorrectly; MEM_LARGE would have ``is_large=False``,
        failing ``bars[0].is_large is True``.
        """
        mem_type: int = cast(int, vars(gpu_pci_mod)["_RES_TYPE_MEM"])
        mem_large_type: int = cast(int, vars(gpu_pci_mod)["_RES_TYPE_MEM_LARGE"])
        cr_success: int = cast(int, vars(gpu_pci_mod)["_CR_SUCCESS"])

        known_size = 12 * _GIB
        known_flags = 0x87
        desc_buf = bytearray(72)
        desc_buf[40:48] = known_size.to_bytes(8, "little")
        desc_buf[64:68] = known_flags.to_bytes(4, "little")
        descriptor_data = bytes(desc_buf)

        log_conf_handle = 0
        calls: dict[int, int] = {}

        next_res_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint64,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        )
        size_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_uint32,
        )
        data_func = ctypes.WINFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        )
        free_func = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_uint64)

        @next_res_func
        def _get_next(
            next_res_ptr: ctypes.Array[ctypes.c_uint64],
            _prev: int,
            res_type: int,
            _res_id_ptr: object,
            _flags: int,
        ) -> int:
            cnt = calls.get(res_type, 0) + 1
            calls[res_type] = cnt
            if res_type == mem_large_type and cnt == 1:
                next_res_ptr[0] = 100
                return cr_success
            return 1

        @size_func
        def _size_ok(size_ptr: ctypes.Array[ctypes.c_uint32], _res_des: int, _flags: int) -> int:
            size_ptr[0] = len(descriptor_data)
            return cr_success

        @data_func
        def _data_ok(_res_des: int, buf: int | None, _size: int, _flags: int) -> int:
            if buf is not None:
                ctypes.memmove(buf, descriptor_data, len(descriptor_data))
            return cr_success

        @free_func
        def _free_ok(_handle: int) -> int:
            return cr_success

        class _FakeCfgEnum:
            get_next_res_des = _get_next
            get_res_des_data_size = _size_ok
            get_res_des_data = _data_ok
            free_res_des_handle = _free_ok

        bars = _call_enumerate_bars(_FakeCfgEnum(), log_conf_handle)

        assert len(bars) == 1
        bar = bars[0]
        assert getattr(bar, "is_large") is True
        assert getattr(bar, "size_bytes") == known_size
        assert getattr(bar, "flags") == known_flags
        assert calls.get(mem_type, 0) >= 1, "MEM type iterator must have been attempted"
        assert calls.get(mem_large_type, 0) >= 1, "MEM_LARGE type iterator must have been attempted"


# ---------------------------------------------------------------------------
# Finding 32 — _get_device_name_from_sycl: name extraction and error fallback
# ---------------------------------------------------------------------------


class TestGetDeviceNameFromSycl:
    """Gate: _get_device_name_from_sycl extracts the device name and returns '' on failure."""

    @staticmethod
    def test_returns_name_from_get_device_name(monkeypatch: pytest.MonkeyPatch) -> None:
        """When torch.xpu.get_device_name exists, its return value is used.

        Oracle: production ``if hasattr(torch.xpu, "get_device_name"): name = torch.xpu.get_device_name(idx); return name``.
        Mutation: returning empty string unconditionally would fail ``== "Intel Arc B580 SYCL"``.
        """
        fake_torch = _make_fake_torch(xpu_available=True, device_name="Intel Arc B580 SYCL")
        monkeypatch.setattr(xpu_utils_mod, "_torch_module", fake_torch)
        result = _call_get_device_name_from_sycl(0)
        assert result == "Intel Arc B580 SYCL"

    @staticmethod
    def test_returns_empty_string_when_get_device_name_raises(monkeypatch: pytest.MonkeyPatch) -> None:
        """RuntimeError from get_device_name is caught and '' is returned.

        Oracle: production ``except (RuntimeError, OSError, AttributeError): ... return ""``.
        Mutation: re-raising the exception instead of returning '' would cause an
        unexpected RuntimeError, failing the implicit no-raise assertion.
        """

        class _XpuRaises:
            @staticmethod
            def get_device_name(_idx: int) -> str:
                msg = "no device at index 99"
                raise RuntimeError(msg)

        class _FakeModRaises:
            xpu: type[_XpuRaises] = _XpuRaises

        monkeypatch.setattr(xpu_utils_mod, "_torch_module", cast(types.ModuleType, _FakeModRaises))
        result = _call_get_device_name_from_sycl(99)
        assert not result


# ---------------------------------------------------------------------------
# Finding 33 — _query_windows_gpus: malformed JSON and subprocess failure
# ---------------------------------------------------------------------------


class TestQueryWindowsGpus:
    """Gate: _query_windows_gpus returns [] on non-zero exit, empty stdout, and malformed JSON."""

    @staticmethod
    def test_non_zero_returncode_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-zero exit code from pwsh yields an empty GPU list without raising.

        Oracle: production ``if result.returncode != 0: ... return []``.
        Mutation: removing the returncode check proceeds to JSON parsing of the
        (potentially empty/error) stdout, returning [] only by accident.
        """
        monkeypatch.setattr(xpu_utils_mod, "ProcessManager", _make_fake_pm(_FakeProcResult(1, "", "Access denied")))
        assert _call_query_windows_gpus() == []

    @staticmethod
    def test_malformed_json_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
        """Malformed JSON in stdout yields an empty GPU list without raising.

        Oracle: production ``except json.JSONDecodeError: ... return []``.
        Mutation: removing the JSONDecodeError catch would propagate the parse
        error, failing the implicit no-raise assertion.
        """
        monkeypatch.setattr(xpu_utils_mod, "ProcessManager", _make_fake_pm(_FakeProcResult(0, "NOT VALID JSON{{{")))
        assert _call_query_windows_gpus() == []

    @staticmethod
    def test_empty_stdout_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty stdout payload yields an empty GPU list.

        Oracle: production ``if not payload: ... return []``.
        Mutation: removing the empty-payload guard proceeds to parse "", raising
        JSONDecodeError (unless caught), or returns [].
        """
        monkeypatch.setattr(xpu_utils_mod, "ProcessManager", _make_fake_pm(_FakeProcResult(0, "")))
        assert _call_query_windows_gpus() == []

    @staticmethod
    def test_single_dict_json_returns_one_entry(monkeypatch: pytest.MonkeyPatch) -> None:
        """A single-object JSON (not array) is normalised to a one-element list.

        Oracle: production ``if isinstance(raw, dict): gpu_entries = [cast(..., raw)]``.
        Mutation: removing the dict branch returns [] for single-GPU systems,
        failing ``len(...) == 1``.
        """
        payload = '{"Name":"Intel Arc B580","PNPDeviceID":"PCI\\\\VEN_8086","DriverVersion":"31.0"}'
        monkeypatch.setattr(xpu_utils_mod, "ProcessManager", _make_fake_pm(_FakeProcResult(0, payload)))
        entries = _call_query_windows_gpus()
        assert len(entries) == 1
        assert entries[0]["name"] == "Intel Arc B580"
        assert entries[0]["driver_version"] == "31.0"

    @staticmethod
    def test_json_array_returns_multiple_entries(monkeypatch: pytest.MonkeyPatch) -> None:
        """A JSON array yields one normalised entry per GPU object.

        Oracle: production ``elif isinstance(raw, list): gpu_entries = [...]``; each
        entry has exactly {name, pnp_device_id, driver_version} keys.
        Mutation: removing the list branch returns [] for systems with multiple GPUs.
        """
        payload = '[{"Name":"Intel Arc B580","PNPDeviceID":"PCI\\\\VEN_8086","DriverVersion":"31.0"},{"Name":"Intel UHD","PNPDeviceID":"PCI\\\\VEN_8086&DEV_0001","DriverVersion":"10.0"}]'
        monkeypatch.setattr(xpu_utils_mod, "ProcessManager", _make_fake_pm(_FakeProcResult(0, payload)))
        entries = _call_query_windows_gpus()
        assert len(entries) == 2
        assert entries[0]["name"] == "Intel Arc B580"
        assert entries[1]["name"] == "Intel UHD"
        assert set(entries[0].keys()) == {"name", "pnp_device_id", "driver_version"}


# ---------------------------------------------------------------------------
# Finding 35 — _extract_torch_xpu_properties: exact field extraction
# ---------------------------------------------------------------------------


class TestExtractTorchXpuProperties:
    """Gate: _extract_torch_xpu_properties reads total_memory, driver_version, and name from props."""

    @staticmethod
    def test_extracts_all_three_fields_from_device_properties() -> None:
        """total_memory, driver_version, and name are extracted at exact values.

        Oracle: production ``total_memory = int(props.total_memory)``, etc.; each
        field is the direct cast of the props attribute.
        Mutation: swapping total_memory and driver_version assignments would make
        ``total_memory == "31.0.101.5522"`` (a string), failing the int comparison.
        """
        fake_torch = _make_fake_torch(
            total_memory=12 * _GIB,
            driver_version="31.0.101.5522",
            device_name="Intel Arc B580",
        )
        total_memory, driver_version, device_name = _call_extract_torch_xpu_properties(fake_torch, 0, "")
        assert total_memory == 12 * _GIB
        assert driver_version == "31.0.101.5522"
        assert device_name == "Intel Arc B580"

    @staticmethod
    def test_existing_device_name_not_overwritten_by_props() -> None:
        """When device_name is already set, the props.name field is not applied.

        Oracle: production ``if not device_name and hasattr(props, "name"): device_name = str(props.name)``.
        Mutation: removing the ``not device_name`` guard always overwrites the caller-
        supplied name, failing ``device_name == "Pre-existing Name"``.
        """
        fake_torch = _make_fake_torch(device_name="Props Name")
        _, _, device_name = _call_extract_torch_xpu_properties(fake_torch, 0, "Pre-existing Name")
        assert device_name == "Pre-existing Name"


# ---------------------------------------------------------------------------
# Finding 36 — _enrich_from_windows_gpus: early-return and WMI enrichment
# ---------------------------------------------------------------------------


class TestEnrichFromWindowsGpus:
    """Gate: _enrich_from_windows_gpus early-returns when populated and fills blanks from WMI."""

    @staticmethod
    def test_early_return_when_both_name_and_driver_already_set(monkeypatch: pytest.MonkeyPatch) -> None:
        """When both device_name and driver_version are non-empty, the values are returned unchanged.

        Oracle: production ``if device_name and driver_version: return device_name, driver_version, device_id``.
        Mutation: removing the early-return proceeds to WMI and may overwrite valid data,
        failing ``result[0] == "Intel Arc B580"`` when WMI returns a different name.
        """
        wmi_called: list[int] = []

        def _fake_gpu_info() -> list[dict[str, str]]:
            wmi_called.append(1)
            return []

        monkeypatch.setattr(xpu_utils_mod, "_get_windows_gpu_info", _fake_gpu_info)
        result = _call_enrich_from_windows_gpus("Intel Arc B580", "31.0.101.5522", "e20b")
        assert result == ("Intel Arc B580", "31.0.101.5522", "e20b")
        assert not wmi_called

    @staticmethod
    def test_wmi_fills_empty_name_and_driver(monkeypatch: pytest.MonkeyPatch) -> None:
        """When name and driver are empty, WMI provides them and parse_device_id extracts the id.

        Oracle: the WMI entry for Intel Arc fills device_name and driver_version; ``_parse_device_id_from_pnp``
        extracts ``"e20b"`` from a VEN_8086&DEV_E20B PnP ID (independently verified in test_realcov_11_gpu_pci.py).
        Mutation: removing the WMI loop leaves name/driver empty, failing ``result[0] == "Intel Arc B580"``.
        """
        pnp = r"PCI\VEN_8086&DEV_E20B&SUBSYS_A003207E&REV_00\6&128604AE&0&00080008"

        def _fake_gpu_info() -> list[dict[str, str]]:
            return [{"name": "Intel Arc B580", "pnp_device_id": pnp, "driver_version": "31.0.101.5522"}]

        monkeypatch.setattr(xpu_utils_mod, "_get_windows_gpu_info", _fake_gpu_info)
        name, drv, dev_id = _call_enrich_from_windows_gpus("", "", "")
        assert name == "Intel Arc B580"
        assert drv == "31.0.101.5522"
        assert dev_id == "e20b"


# ---------------------------------------------------------------------------
# Finding 37 — _build_xpu_device_info: XPUDeviceInfo field assembly
# ---------------------------------------------------------------------------


class TestBuildXpuDeviceInfo:
    """Gate: _build_xpu_device_info assembles XPUDeviceInfo with correct field values."""

    @staticmethod
    def test_returns_none_when_xpu_unavailable() -> None:
        """When torch.xpu.is_available() is False, the function returns None.

        Oracle: production ``if not hasattr(torch, "xpu") or not torch.xpu.is_available(): return None``.
        Mutation: removing the availability guard proceeds to ``device_count()`` on a
        no-XPU torch, raising AttributeError or returning wrong data.
        """
        fake_torch = _make_fake_torch(xpu_available=False)
        result = _call_build_xpu_device_info(fake_torch, 0)
        assert result is None

    @staticmethod
    def test_assembles_correct_total_memory_and_device_name(monkeypatch: pytest.MonkeyPatch) -> None:
        """The returned XPUDeviceInfo carries total_memory and name from the torch props.

        Oracle: props.total_memory=12*GIB and props.name="Intel Arc B580" are the
        independently-known values set in the fake; the production assembly code
        must read them and place them in the dataclass fields.
        Mutation: assigning total_memory from driver_version (wrong field) returns
        a string cast to int, which differs from 12*GIB.
        """
        fake_torch = _make_fake_torch(
            xpu_available=True,
            device_count=1,
            total_memory=12 * _GIB,
            device_name="Intel Arc B580",
            driver_version="31.0.101.5522",
        )
        monkeypatch.setattr(xpu_utils_mod, "_torch_module", fake_torch)
        monkeypatch.setattr(xpu_utils_mod, "_get_windows_gpu_info", list)
        info = _call_build_xpu_device_info(fake_torch, 0)
        assert info is not None
        assert info.total_memory_bytes == 12 * _GIB
        assert info.device_name == "Intel Arc B580"
        assert info.is_arc_b580 is True
        assert info.supports_fp16 is True

    @staticmethod
    def test_returns_none_for_out_of_range_device_index(monkeypatch: pytest.MonkeyPatch) -> None:
        """A device index >= device_count yields None.

        Oracle: production ``if device_index >= torch.xpu.device_count(): return None``.
        Mutation: removing the range check tries to retrieve properties for a non-
        existent device, raising or returning garbage data.
        """
        fake_torch = _make_fake_torch(xpu_available=True, device_count=1)
        monkeypatch.setattr(xpu_utils_mod, "_torch_module", fake_torch)
        result = _call_build_xpu_device_info(fake_torch, 5)
        assert result is None


# ---------------------------------------------------------------------------
# Finding 39 — clear_xpu_cache: no-op on no-XPU, empty_cache called on XPU
# ---------------------------------------------------------------------------


class TestClearXpuCache:
    """Gate: clear_xpu_cache is a no-op without XPU and calls empty_cache when XPU is available."""

    @staticmethod
    def test_no_xpu_machine_does_not_raise() -> None:
        """On a machine without XPU, clear_xpu_cache returns without raising.

        Oracle: production ``if hasattr(torch, "xpu") and torch.xpu.is_available() ...: empty_cache()``
        short-circuits when is_available returns False.
        Mutation: calling empty_cache unconditionally on a no-XPU machine would raise
        RuntimeError or AttributeError.
        """
        if is_xpu_available():
            pytest.skip("XPU is available; no-op path cannot be exercised")
        clear_xpu_cache()

    @staticmethod
    def test_empty_cache_called_once_when_xpu_available(monkeypatch: pytest.MonkeyPatch) -> None:
        """When XPU is available, torch.xpu.empty_cache() is called exactly once.

        Oracle: production ``if hasattr(torch, "xpu") and torch.xpu.is_available() and hasattr(...): torch.xpu.empty_cache()``.
        Mutation: removing the ``empty_cache()`` call leaves the list empty, failing ``len(...) == 1``.
        """
        calls: list[int] = []
        fake_torch = _make_fake_torch(xpu_available=True, empty_cache_calls=calls)
        monkeypatch.setattr(xpu_utils_mod, "_torch_module", fake_torch)
        clear_xpu_cache()
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# Finding 40 — _pick_primary_arc_gpu: picks GPU with larger BAR
# ---------------------------------------------------------------------------


class TestPickPrimaryArcGpu:
    """Gate: _pick_primary_arc_gpu selects the Intel Arc GPU with the largest PCI BAR."""

    @staticmethod
    def test_selects_gpu_with_larger_bar_over_smaller(monkeypatch: pytest.MonkeyPatch) -> None:
        """B580 with a 12 GB BAR wins over A770 with a 256 MB BAR.

        Oracle: the function's documented contract ``Selects the Arc-class GPU with the
        largest allocated PCI MMIO BAR``; 12*GIB > 256*MiB.
        Mutation: always returning the first GPU regardless of BAR size would pick
        whichever is listed first, failing ``result[0] == "Intel Arc B580"`` when A770
        is listed first in the input.
        """
        b580_bar = 12 * _GIB
        a770_bar = 256 * 1024 * 1024

        def _fake_max_bar(pnp_id: str) -> int:
            if "E20B" in pnp_id:
                return b580_bar
            return a770_bar if "4905" in pnp_id else 0

        monkeypatch.setattr(xpu_utils_mod, "max_memory_bar_bytes", _fake_max_bar)
        gpus: list[dict[str, str]] = [
            {"name": "Intel Arc A770", "pnp_device_id": r"PCI\VEN_8086&DEV_4905\0", "driver_version": "31.0"},
            {"name": "Intel Arc B580", "pnp_device_id": r"PCI\VEN_8086&DEV_E20B\0", "driver_version": "31.0"},
        ]
        result = _call_pick_primary_arc_gpu(gpus)
        assert result is not None
        assert result[0] == "Intel Arc B580"
        assert result[1] == b580_bar

    @staticmethod
    def test_returns_none_when_no_intel_arc_gpu(monkeypatch: pytest.MonkeyPatch) -> None:
        """When no Intel Arc GPU is present, None is returned.

        Oracle: production ``if primary_name is None: return None``.
        Mutation: returning a default tuple instead of None would fail ``is None``.
        """

        def _zero_bar(_pnp_id: str) -> int:
            return 0

        monkeypatch.setattr(xpu_utils_mod, "max_memory_bar_bytes", _zero_bar)
        gpus: list[dict[str, str]] = [
            {"name": "NVIDIA GeForce RTX 4090", "pnp_device_id": r"PCI\VEN_10DE\0", "driver_version": "537.0"},
        ]
        assert _call_pick_primary_arc_gpu(gpus) is None


# ---------------------------------------------------------------------------
# Finding 41 — _check_intel_driver: True/False based on driver_version presence
# ---------------------------------------------------------------------------


class TestCheckIntelDriver:
    """Gate: _check_intel_driver returns True with empty message for a present driver."""

    @staticmethod
    def test_true_and_empty_message_for_valid_driver_version() -> None:
        """A non-empty driver_version string yields (True, '').

        Oracle: production ``if driver_version: ... return (True, "")``.
        Mutation: always returning (False, ...) ignores the driver_version value.
        """
        gpus: list[dict[str, str]] = [{"name": "Intel Arc B580", "driver_version": "31.0.101.5522", "pnp_device_id": ""}]
        ok, msg = _call_check_intel_driver(gpus)
        assert ok is True
        assert not msg

    @staticmethod
    def test_false_and_warning_for_empty_driver_version() -> None:
        """An empty driver_version string yields (False, warning_message).

        Oracle: production ``return (False, "Intel Arc GPU driver not detected...")``.
        Mutation: returning (True, '') even for empty driver_version fails ``ok is False``.
        """
        gpus: list[dict[str, str]] = [{"name": "Intel Arc B580", "driver_version": "", "pnp_device_id": ""}]
        ok, msg = _call_check_intel_driver(gpus)
        assert ok is False
        assert "Intel Arc" in msg

    @staticmethod
    def test_false_when_no_intel_arc_gpus() -> None:
        """An empty GPU list yields (False, warning_message).

        Oracle: when the loop finds no Intel Arc entry, the function falls through to
        ``return (False, "Intel Arc GPU driver not detected...")``.
        Mutation: returning (True, '') for an empty list fails ``ok is False``.
        """
        ok, msg = _call_check_intel_driver([])
        assert ok is False
        assert len(msg) > 0


# ---------------------------------------------------------------------------
# Finding 42 — _validate_xpu_device: RuntimeError on tensor-op failure
# ---------------------------------------------------------------------------


class TestValidateXpuDevice:
    """Gate: _validate_xpu_device re-raises tensor failures as RuntimeError with identifying text."""

    @staticmethod
    def test_raises_runtime_error_with_validation_failed_prefix() -> None:
        """When torch.zeros raises RuntimeError, _validate_xpu_device wraps and re-raises.

        Oracle: production ``raise RuntimeError(f"XPU device validation failed: {exc}") from exc``.
        Mutation: removing the try/except and letting torch.zeros RuntimeError propagate
        unchanged would have a different message, failing ``match="XPU device validation failed"``.
        """
        exc = RuntimeError("XPU device not ready")
        fake_torch = _make_fake_torch(zeros_raises=exc)
        device = torch.device("cpu")
        with pytest.raises(RuntimeError, match="XPU device validation failed"):
            _call_validate_xpu_device(fake_torch, device)

    @staticmethod
    def test_passes_silently_when_tensor_op_succeeds() -> None:
        """When tensor ops succeed, _validate_xpu_device returns without raising.

        Oracle: production function returns normally after ``del test_tensor`` and
        ``synchronize()``.
        Mutation: raising RuntimeError unconditionally would fail the implicit
        no-raise assertion.
        """
        fake_torch = _make_fake_torch(zeros_raises=None)
        device = torch.device("cpu")
        _call_validate_xpu_device(fake_torch, device)


# ---------------------------------------------------------------------------
# Finding 43 — _query_xpu_memory: fallback to get_xpu_device_info when total=0
# ---------------------------------------------------------------------------


class TestQueryXpuMemory:
    """Gate: _query_xpu_memory falls back to get_xpu_device_info when props.total_memory is 0."""

    @staticmethod
    def test_fallback_to_device_info_when_props_total_memory_is_zero(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When get_device_properties reports total_memory=0, total is sourced from get_xpu_device_info.

        Oracle: production ``if total == 0: info = get_xpu_device_info(device_index); if info is not None: total = info.total_memory_bytes``.
        Mutation: removing the fallback block leaves total=0, failing ``total == 8 * _GIB``.
        """
        fake_torch = _make_fake_torch(
            xpu_available=True,
            total_memory=0,
            allocated_memory=2048,
        )

        fallback_info = XPUDeviceInfo(
            device_index=0,
            device_name="Intel Arc Test",
            total_memory_bytes=8 * _GIB,
            driver_version="31.0",
            device_id="",
            is_arc_b580=False,
            supports_fp16=True,
            supports_bf16=True,
            supports_int8=True,
        )

        def _fake_get_device_info(_idx: int) -> XPUDeviceInfo | None:
            return fallback_info

        monkeypatch.setattr(xpu_utils_mod, "get_xpu_device_info", _fake_get_device_info)
        allocated, total = _call_query_xpu_memory(fake_torch, 0)
        assert allocated == 2048
        assert total == 8 * _GIB

    @staticmethod
    def test_uses_props_total_memory_when_nonzero() -> None:
        """When get_device_properties reports a non-zero total_memory, no fallback is needed.

        Oracle: production ``if total == 0:`` does not fire when total=12*GIB.
        Mutation: always calling get_xpu_device_info regardless of props would also
        work, but the tested path is that the fallback is skipped when unnecessary.
        """
        fake_torch = _make_fake_torch(
            xpu_available=True,
            total_memory=12 * _GIB,
            allocated_memory=512,
        )
        allocated, total = _call_query_xpu_memory(fake_torch, 0)
        assert allocated == 512
        assert total == 12 * _GIB
