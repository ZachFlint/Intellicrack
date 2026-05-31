# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for ``intellicrack.providers.xpu_utils``.

These tests exercise the public XPU detection surface against the real
machine. Detection helpers (:func:`is_xpu_available`,
:func:`get_xpu_device_count`) run against the genuine ``torch.xpu``
runtime. Windows requirement checks and GPU enumeration spawn a real
PowerShell ``Get-CimInstance`` query (hence the ``spawns_process``
marker) and validate the parsed result. Out-of-range device handling
and the non-Windows short-circuit are validated with precise
assertions. No torch internals are mocked.
"""

from __future__ import annotations

import platform
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.providers import xpu_utils
from intellicrack.providers.xpu_utils import (
    XPUDeviceInfo,
    check_windows_requirements,
    get_optimal_dtype_for_xpu,
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    initialize_xpu,
    is_arc_b580,
    is_xpu_available,
)


if TYPE_CHECKING:
    from collections.abc import Callable


_IS_WINDOWS: bool = platform.system() == "Windows"

_VALID_DTYPES: frozenset[str] = frozenset({"float16", "bfloat16", "float32"})


def _get_windows_gpu_info() -> list[dict[str, str]]:
    """Run the module-private Windows GPU enumeration via a typed wrapper.

    Returns:
        list[dict[str, str]]: Normalized GPU info entries.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils)["_get_windows_gpu_info"])
    return fn()


class TestXpuDetection:
    """Validate XPU availability and device-count detection."""

    @staticmethod
    def test_is_xpu_available_returns_bool_without_raising() -> None:
        """Detection returns a real bool and never raises on this machine."""
        result = is_xpu_available()
        assert isinstance(result, bool)

    @staticmethod
    def test_device_count_consistent_with_availability() -> None:
        """Device count is positive iff XPU is available, else zero."""
        count = get_xpu_device_count()
        assert isinstance(count, int)
        assert count >= 0
        if is_xpu_available():
            assert count >= 1
        else:
            assert count == 0

    @staticmethod
    def test_is_arc_b580_returns_bool() -> None:
        """The Arc B580 probe returns a real bool tied to real detection."""
        result = is_arc_b580()
        assert isinstance(result, bool)
        if result:
            assert is_xpu_available() is True


class TestXpuDeviceInfo:
    """Validate device-info retrieval and out-of-range handling."""

    @staticmethod
    def test_device_zero_info_when_available() -> None:
        """When XPU is present, device 0 yields a populated info record."""
        if not is_xpu_available():
            pytest.skip("XPU is not available on this machine")
        info = get_xpu_device_info(0)
        assert isinstance(info, XPUDeviceInfo)
        assert info.device_index == 0
        assert info.device_name
        assert info.total_memory_bytes > 0
        assert info.supports_fp16 is True

    @staticmethod
    def test_out_of_range_device_returns_none() -> None:
        """A device index beyond the count returns None, not a crash."""
        if not is_xpu_available():
            pytest.skip("XPU is not available on this machine")
        out_of_range = get_xpu_device_count() + 50
        assert get_xpu_device_info(out_of_range) is None


class TestXpuMemoryInfo:
    """Validate memory queries and out-of-range device behaviour."""

    @staticmethod
    def test_memory_info_returns_pair() -> None:
        """Memory info is a (allocated, total) pair of non-negative ints."""
        allocated, total = get_xpu_memory_info(0)
        assert isinstance(allocated, int)
        assert isinstance(total, int)
        assert allocated >= 0
        assert total >= 0
        if is_xpu_available():
            assert total > 0

    @staticmethod
    def test_out_of_range_memory_info_is_zero_pair() -> None:
        """An out-of-range device yields a (0, 0) pair without raising."""
        if not is_xpu_available():
            pytest.skip("XPU is not available on this machine")
        allocated, total = get_xpu_memory_info(get_xpu_device_count() + 50)
        assert (allocated, total) == (0, 0)


class TestInitializeXpu:
    """Validate XPU initialization happy path and invalid-index error."""

    @staticmethod
    def test_initialize_returns_real_device() -> None:
        """Initialization returns a real ``torch.device`` of type ``xpu``."""
        if not is_xpu_available():
            pytest.skip("XPU is not available on this machine")
        device = initialize_xpu(0)
        assert device.type == "xpu"
        assert device.index == 0

    @staticmethod
    def test_out_of_range_index_raises_runtime_error() -> None:
        """An out-of-range device index raises a descriptive RuntimeError."""
        if not is_xpu_available():
            pytest.skip("XPU is not available on this machine")
        with pytest.raises(RuntimeError, match="out of range"):
            initialize_xpu(get_xpu_device_count() + 50)


class TestOptimalDtype:
    """Validate optimal dtype selection on the real runtime."""

    @staticmethod
    def test_optimal_dtype_is_valid_choice() -> None:
        """The selected dtype is one of the supported real dtype strings."""
        dtype = get_optimal_dtype_for_xpu()
        assert dtype in _VALID_DTYPES

    @staticmethod
    def test_cpu_only_machine_reports_float32() -> None:
        """A machine without XPU falls back to float32 for safety."""
        if is_xpu_available():
            pytest.skip("XPU is available; CPU-only fallback path not exercised")
        assert get_optimal_dtype_for_xpu() == "float32"


class TestWindowsRequirements:
    """Validate Windows requirement checks and the non-Windows path."""

    @staticmethod
    def test_non_windows_returns_met_with_no_warnings() -> None:
        """Off Windows the check reports requirements met with no warnings."""
        if _IS_WINDOWS:
            pytest.skip("Non-Windows short-circuit cannot run on Windows")
        met, warnings = check_windows_requirements()
        assert met is True
        assert warnings == []

    @staticmethod
    @pytest.mark.spawns_process
    def test_windows_requirements_returns_typed_result() -> None:
        """On Windows the check returns a (bool, list[str]) from real WMI."""
        if not _IS_WINDOWS:
            pytest.skip("Windows requirement check only runs on Windows")
        met, warnings = check_windows_requirements()
        assert isinstance(met, bool)
        assert isinstance(warnings, list)
        assert all(isinstance(w, str) for w in warnings)


class TestWindowsGpuEnumeration:
    """Validate the real PowerShell GPU enumeration parsing."""

    @staticmethod
    @pytest.mark.spawns_process
    def test_enumeration_returns_normalized_entries() -> None:
        """The WMI query yields entries with name/pnp/driver string keys."""
        if not _IS_WINDOWS:
            pytest.skip("WMI GPU enumeration only runs on Windows")
        gpus = _get_windows_gpu_info()
        assert isinstance(gpus, list)
        for gpu in gpus:
            assert set(gpu) == {"name", "pnp_device_id", "driver_version"}
            assert isinstance(gpu["name"], str)
            assert isinstance(gpu["pnp_device_id"], str)
            assert isinstance(gpu["driver_version"], str)
        assert gpus, "A Windows host with a display adapter should report GPUs"
