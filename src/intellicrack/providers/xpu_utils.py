"""Intel XPU detection and initialization utilities for Intel Arc B580.

This module provides utilities for detecting, initializing, and managing
Intel XPU (eXtreme Performance Unit) devices using PyTorch 2.5+ native
torch.xpu support. Specifically optimized for Intel Arc B580 GPU.
"""

from __future__ import annotations

import json
import platform
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager


try:
    import torch as _torch_module
except ImportError:
    _torch_module = None

if TYPE_CHECKING:
    import types

    import torch


_logger = get_logger("providers.xpu_utils")

_B580_DEVICE_IDS: frozenset[str] = frozenset({"0xe20b", "e20b", "E20B", "0xE20B"})
_ARC_DEVICE_PATTERNS: tuple[str, ...] = ("Arc", "A770", "A750", "A380", "A310", "B580")

_INTEL_VENDOR_ID: str = "8086"

_WIN10_MAJOR_VERSION: int = 10
_WIN10_2004_BUILD: int = 19041

_ERR_PYTORCH_NOT_INSTALLED = "PyTorch is not installed"
_ERR_XPU_NOT_AVAILABLE = "PyTorch XPU support is not available"
_ERR_NO_XPU_DEVICES = "No XPU devices are available"


@dataclass(frozen=True)
class XPUDeviceInfo:
    """Information about an Intel XPU device.

    Attributes:
        device_index: Index of the device (0-based).
        device_name: Human-readable device name.
        total_memory_bytes: Total device memory in bytes.
        driver_version: Driver version string.
        device_id: PCI device ID.
        is_arc_b580: Whether this is an Arc B580 device.
        supports_fp16: Whether device supports FP16.
        supports_bf16: Whether device supports BF16.
        supports_int8: Whether device supports INT8.
    """

    device_index: int
    device_name: str
    total_memory_bytes: int
    driver_version: str
    device_id: str
    is_arc_b580: bool
    supports_fp16: bool
    supports_bf16: bool
    supports_int8: bool


def _import_torch() -> types.ModuleType | None:
    """Safely import torch with XPU support.

    Returns:
        The torch module if available with XPU support, None otherwise.
    """
    if _torch_module is None:
        _logger.debug("xpu_torch_import_failed", extra={"reason": "torch not installed"})
        return None
    return _torch_module


def is_xpu_available() -> bool:
    """Check if Intel XPU is available for computation.

    Uses PyTorch 2.5+ native torch.xpu.is_available() for detection.
    This function never raises exceptions - returns False on any error.

    Returns:
        True if at least one XPU device is available and usable.
    """
    torch = _import_torch()
    if torch is None:
        return False

    try:
        if not hasattr(torch, "xpu"):
            _logger.debug("xpu_not_available", extra={"reason": "torch.xpu module missing"})
            return False

        is_available: bool = torch.xpu.is_available()
        if is_available:
            _logger.debug("xpu_available", extra={"device_count": torch.xpu.device_count()})
    except Exception as exc:
        _logger.debug("xpu_check_failed", extra={"error": str(exc)})
        return False
    else:
        return is_available


def get_xpu_device_count() -> int:
    """Get the number of available XPU devices.

    Returns:
        Number of XPU devices, 0 if XPU is not available.
    """
    torch = _import_torch()
    if torch is None:
        return 0

    try:
        if not hasattr(torch, "xpu") or not torch.xpu.is_available():
            return 0
        count: int = torch.xpu.device_count()
    except Exception as exc:
        _logger.debug("xpu_device_count_failed", extra={"error": str(exc)})
        return 0
    else:
        return count


def _get_device_name_from_sycl(device_index: int) -> str:
    """Get device name using SYCL if available.

    Args:
        device_index: Index of the device.

    Returns:
        Device name string or empty string if unavailable.
    """
    torch = _import_torch()
    if torch is None:
        return ""

    try:
        if hasattr(torch.xpu, "get_device_name"):
            name: str = torch.xpu.get_device_name(device_index)
            return name
        if hasattr(torch.xpu, "get_device_properties"):
            props = torch.xpu.get_device_properties(device_index)
            if hasattr(props, "name"):
                return str(props.name)
    except Exception as exc:
        _logger.debug("sycl_device_name_failed", extra={"error": str(exc)})
    return ""


def _get_windows_gpu_info() -> list[dict[str, str]]:
    """Get GPU information on Windows using WMI.

    Returns:
        List of dictionaries with GPU information.
    """
    if platform.system() != "Windows":
        return []

    gpus: list[dict[str, str]] = []
    try:
        result = ProcessManager.get_instance().run_tracked(
            [
                "pwsh",
                "-Command",
                "Get-WmiObject Win32_VideoController | Select-Object Name,PNPDeviceID,DriverVersion | ConvertTo-Json",
            ],
            name="xpu-gpu-detect",
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            raw: object = json.loads(result.stdout)
            gpu_entries: list[dict[str, str]]
            if isinstance(raw, dict):
                gpu_entries = [cast("dict[str, str]", raw)]
            elif isinstance(raw, list):
                raw_list: list[object] = cast("list[object]", raw)
                gpu_entries = [cast("dict[str, str]", item) for item in raw_list if isinstance(item, dict)]
            else:
                gpu_entries = []
            gpus.extend(
                {
                    "name": str(gpu.get("Name", "")),
                    "pnp_device_id": str(gpu.get("PNPDeviceID", "")),
                    "driver_version": str(gpu.get("DriverVersion", "")),
                }
                for gpu in gpu_entries
            )
    except Exception as exc:
        _logger.debug("windows_gpu_info_failed", extra={"error": str(exc)})

    return gpus


def _parse_device_id_from_pnp(pnp_id: str) -> str:
    r"""Parse device ID from PNP device ID string.

    Args:
        pnp_id: PNP device ID string (e.g., PCI\VEN_8086&DEV_E20B...).

    Returns:
        Extracted device ID or empty string.
    """
    if match := re.search(r"DEV_([0-9A-Fa-f]{4})", pnp_id):
        return match[1].lower()
    return ""


def get_xpu_device_info(device_index: int) -> XPUDeviceInfo | None:
    """Get detailed information about a specific XPU device.

    Args:
        device_index: Index of the XPU device (0-based).

    Returns:
        XPUDeviceInfo containing device details, or None if unavailable.
    """
    torch = _import_torch()
    if torch is None:
        return None

    try:
        if not hasattr(torch, "xpu") or not torch.xpu.is_available():
            return None

        if device_index >= torch.xpu.device_count():
            return None

        device_name = _get_device_name_from_sycl(device_index)
        total_memory: int = 0
        driver_version = ""
        device_id = ""

        try:
            if hasattr(torch.xpu, "get_device_properties"):
                props = torch.xpu.get_device_properties(device_index)
                if hasattr(props, "total_memory"):
                    total_memory = int(props.total_memory)
                if hasattr(props, "driver_version"):
                    driver_version = str(props.driver_version)
                if not device_name and hasattr(props, "name"):
                    device_name = str(props.name)
        except Exception as exc:
            _logger.debug("xpu_properties_failed", extra={"error": str(exc)})

        if not device_name or not driver_version:
            windows_gpus = _get_windows_gpu_info()
            for gpu in windows_gpus:
                if "Intel" in gpu["name"] and any(p in gpu["name"] for p in _ARC_DEVICE_PATTERNS):
                    if not device_name:
                        device_name = gpu["name"]
                    if not driver_version:
                        driver_version = gpu["driver_version"]
                    device_id = _parse_device_id_from_pnp(gpu["pnp_device_id"])
                    break

        if total_memory == 0:
            total_memory = _estimate_memory_from_name(device_name)

        is_arc_b580 = _is_b580_device(device_name, device_id)

        supports_fp16 = True
        supports_bf16 = True
        supports_int8 = True

        return XPUDeviceInfo(
            device_index=device_index,
            device_name=device_name or f"Intel XPU {device_index}",
            total_memory_bytes=total_memory,
            driver_version=driver_version,
            device_id=device_id,
            is_arc_b580=is_arc_b580,
            supports_fp16=supports_fp16,
            supports_bf16=supports_bf16,
            supports_int8=supports_int8,
        )

    except Exception as exc:
        _logger.debug("xpu_device_info_failed", extra={"device_index": device_index, "error": str(exc)})
        return None


def _estimate_memory_from_name(device_name: str) -> int:
    """Estimate device memory from device name.

    Args:
        device_name: Device name string.

    Returns:
        Estimated memory in bytes.
    """
    name_lower = device_name.lower()
    estimated: int
    if "b580" in name_lower:
        estimated = 12 * 1024 * 1024 * 1024
    elif "a770" in name_lower:
        estimated = 16 * 1024 * 1024 * 1024
    elif "a750" in name_lower:
        estimated = 8 * 1024 * 1024 * 1024
    elif "a380" in name_lower:
        estimated = 6 * 1024 * 1024 * 1024
    elif "a310" in name_lower:
        estimated = 4 * 1024 * 1024 * 1024
    else:
        estimated = 8 * 1024 * 1024 * 1024
    _logger.debug(
        "xpu_memory_estimated",
        extra={"device_name": device_name, "estimated_bytes": estimated},
    )
    return estimated


def _is_b580_device(device_name: str, device_id: str) -> bool:
    """Check if device is an Intel Arc B580.

    Args:
        device_name: Device name string.
        device_id: PCI device ID.

    Returns:
        True if device is an Arc B580.
    """
    result = device_id.lower() in {"e20b", "0xe20b"} or "b580" in device_name.lower()
    _logger.debug(
        "xpu_b580_detection",
        extra={"device_name": device_name, "device_id": device_id, "is_b580": result},
    )
    return result


def is_arc_b580() -> bool:
    """Check if an Intel Arc B580 is available.

    Returns:
        True if at least one Arc B580 device is detected.
    """
    if not is_xpu_available():
        _logger.debug("xpu_b580_check_skipped", extra={"reason": "xpu not available"})
        return False

    device_count = get_xpu_device_count()
    _logger.debug("xpu_b580_scan_started", extra={"device_count": device_count})
    for i in range(device_count):
        info = get_xpu_device_info(i)
        if info is not None and info.is_arc_b580:
            _logger.debug("xpu_b580_found", extra={"device_index": i, "device_name": info.device_name})
            return True
    _logger.debug("xpu_b580_not_found", extra={"devices_scanned": device_count})
    return False


def initialize_xpu(device_index: int = 0) -> torch.device:
    """Initialize and return a torch.device for XPU.

    Args:
        device_index: Index of the XPU device to use.

    Returns:
        A torch.device configured for the specified XPU.

    Raises:
        RuntimeError: If XPU initialization fails.
    """
    torch_mod = _import_torch()
    if torch_mod is None:
        raise RuntimeError(_ERR_PYTORCH_NOT_INSTALLED)

    if not hasattr(torch_mod, "xpu"):
        raise RuntimeError(_ERR_XPU_NOT_AVAILABLE)

    if not torch_mod.xpu.is_available():
        raise RuntimeError(_ERR_NO_XPU_DEVICES)

    device_count = torch_mod.xpu.device_count()
    if device_index >= device_count:
        msg = f"XPU device index {device_index} out of range (0-{device_count - 1})"
        raise RuntimeError(msg)

    torch_mod.xpu.set_device(device_index)
    device: torch.device = torch_mod.device(f"xpu:{device_index}")

    _validate_xpu_device(torch_mod, device)

    _logger.info("xpu_initialized", extra={"device_index": device_index, "device": str(device)})
    return device


def _validate_xpu_device(torch_mod: types.ModuleType, device: torch.device) -> None:
    """Validate that XPU device is operational.

    Args:
        torch_mod: The torch module.
        device: The device to validate.

    Raises:
        RuntimeError: If device validation fails.
    """
    _logger.debug("xpu_device_validation_started", extra={"device": str(device)})
    try:
        test_tensor = torch_mod.zeros(10, device=device)
        _ = test_tensor + 1
        del test_tensor
        torch_mod.xpu.synchronize()
        _logger.debug("xpu_device_validation_passed", extra={"device": str(device)})
    except Exception as exc:
        _logger.debug("xpu_device_validation_failed", extra={"device": str(device), "error": str(exc)})
        msg = f"XPU device validation failed: {exc}"
        raise RuntimeError(msg) from exc


def get_xpu_memory_info(device_index: int = 0) -> tuple[int, int]:
    """Get memory information for an XPU device.

    Args:
        device_index: Index of the XPU device.

    Returns:
        Tuple of (allocated_bytes, total_bytes).
    """
    torch = _import_torch()
    if torch is None:
        return (0, 0)

    try:
        if not hasattr(torch, "xpu") or not torch.xpu.is_available():
            return (0, 0)

        allocated: int = 0
        total: int = 0

        if hasattr(torch.xpu, "memory_allocated"):
            allocated = torch.xpu.memory_allocated(device_index)

        if hasattr(torch.xpu, "get_device_properties"):
            props = torch.xpu.get_device_properties(device_index)
            if hasattr(props, "total_memory"):
                total = int(props.total_memory)

        if total == 0:
            info = get_xpu_device_info(device_index)
            if info is not None:
                total = info.total_memory_bytes
    except Exception as exc:
        _logger.debug("xpu_memory_info_failed", extra={"device_index": device_index, "error": str(exc)})
        return (0, 0)
    else:
        return (allocated, total)


def clear_xpu_cache() -> None:
    """Clear the XPU memory cache.

    Frees cached memory that is no longer in use. This does not free
    tensors that are still referenced.
    """
    torch = _import_torch()
    if torch is None:
        return

    try:
        if hasattr(torch, "xpu") and torch.xpu.is_available() and hasattr(torch.xpu, "empty_cache"):
            torch.xpu.empty_cache()
            _logger.debug("xpu_cache_cleared", extra={})
    except Exception as exc:
        _logger.debug("xpu_cache_clear_failed", extra={"error": str(exc)})


def check_windows_requirements() -> tuple[bool, list[str]]:
    """Check Windows-specific requirements for XPU acceleration.

    Verifies:
    - Windows 10/11 version compatibility
    - Intel GPU driver installation
    - Resizable BAR (ReBAR) status

    Returns:
        Tuple of (all_requirements_met, list_of_warning_messages).
    """
    if platform.system() != "Windows":
        _logger.debug("xpu_windows_check_skipped", extra={"platform": platform.system()})
        return (True, [])

    _logger.debug("xpu_windows_requirements_check_started", extra={})
    warnings: list[str] = []
    all_met = True

    win_version = sys.getwindowsversion()
    if win_version.major < _WIN10_MAJOR_VERSION:
        warnings.append("Windows 10 or later is required for Intel XPU support")
        all_met = False
    elif win_version.major == _WIN10_MAJOR_VERSION and win_version.build < _WIN10_2004_BUILD:
        warnings.append("Windows 10 version 2004 (build 19041) or later recommended for optimal XPU support")

    driver_ok, driver_warning = _check_intel_driver()
    if not driver_ok:
        warnings.append(driver_warning)
        all_met = False

    rebar_ok, rebar_warning = _check_rebar_status()
    if not rebar_ok:
        warnings.append(rebar_warning)

    _logger.debug(
        "xpu_windows_requirements_check_complete",
        extra={"all_met": all_met, "warning_count": len(warnings)},
    )
    return (all_met, warnings)


def _check_intel_driver() -> tuple[bool, str]:
    """Check Intel GPU driver status.

    Returns:
        Tuple of (driver_ok, warning_message).
    """
    _logger.debug("xpu_driver_check_started", extra={})
    try:
        result = ProcessManager.get_instance().run_tracked(
            [
                "pwsh",
                "-Command",
                "Get-WmiObject Win32_VideoController | Where-Object {$_.Name -like '*Intel*Arc*'} | Select-Object DriverVersion | ConvertTo-Json",
            ],
            name="xpu-driver-check",
            timeout=10,
            check=False,
        )
    except Exception as exc:
        _logger.debug("xpu_driver_check_failed", extra={"error": str(exc)})
        return (False, "Could not verify Intel GPU driver status")
    else:
        if result.returncode == 0 and result.stdout.strip():
            _logger.debug("xpu_driver_detected", extra={})
            return (True, "")
        _logger.debug("xpu_driver_not_found", extra={"returncode": result.returncode})
        return (False, "Intel Arc GPU driver not detected. Install the latest Intel Arc driver from intel.com")


def _check_rebar_status() -> tuple[bool, str]:
    """Check Resizable BAR status.

    Returns:
        Tuple of (rebar_enabled, warning_message).
    """
    _logger.debug("xpu_rebar_check_started", extra={})
    try:
        result = ProcessManager.get_instance().run_tracked(
            [
                "pwsh",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Video\\*\\*' -ErrorAction SilentlyContinue | Where-Object {$_.RmGpuLdPciResizableBar -eq 1}).Count",
            ],
            name="xpu-rebar-check",
            timeout=10,
            check=False,
        )
    except Exception as exc:
        _logger.debug("xpu_rebar_check_failed", extra={"error": str(exc)})
        return (True, "")
    else:
        if result.returncode == 0:
            count = result.stdout.strip()
            if count and int(count) > 0:
                _logger.debug("xpu_rebar_enabled", extra={"count": count})
                return (True, "")
        _logger.debug("xpu_rebar_not_detected", extra={})
        return (False, "Resizable BAR (ReBAR) may not be enabled. Enable in BIOS for optimal performance")


def get_optimal_dtype_for_xpu() -> str:
    """Get the optimal data type for XPU inference.

    Intel Arc B580 supports FP16 and BF16, but not FP64 on Windows.

    Returns:
        String dtype name ("float16", "bfloat16", or "float32").
    """
    _logger.debug("xpu_dtype_detection_started", extra={})
    torch = _import_torch()
    if torch is None:
        _logger.debug("xpu_dtype_selected", extra={"dtype": "float32", "reason": "torch unavailable"})
        return "float32"

    if not is_xpu_available():
        _logger.debug("xpu_dtype_selected", extra={"dtype": "float32", "reason": "xpu unavailable"})
        return "float32"

    try:
        device = torch.device("xpu:0")
        test_bf16 = torch.zeros(10, dtype=torch.bfloat16, device=device)
        _ = test_bf16 + 1
        del test_bf16
        torch.xpu.synchronize()
    except Exception as exc:
        _logger.debug("bf16_not_supported", extra={"error": str(exc)})
    else:
        _logger.debug("xpu_dtype_selected", extra={"dtype": "bfloat16"})
        return "bfloat16"

    try:
        device = torch.device("xpu:0")
        test_fp16 = torch.zeros(10, dtype=torch.float16, device=device)
        _ = test_fp16 + 1
        del test_fp16
        torch.xpu.synchronize()
    except Exception as exc:
        _logger.debug("fp16_not_supported", extra={"error": str(exc)})
    else:
        _logger.debug("xpu_dtype_selected", extra={"dtype": "float16"})
        return "float16"

    _logger.debug("xpu_dtype_selected", extra={"dtype": "float32", "reason": "fallback"})
    return "float32"
