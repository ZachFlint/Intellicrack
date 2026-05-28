# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Intel XPU detection and initialization utilities for Intel Arc B580.

This module provides utilities for detecting, initializing, and managing Intel XPU (eXtreme Performance Unit) devices using PyTorch 2.5+
native torch.xpu support. Specifically optimized for Intel Arc B580 GPU.
"""

from __future__ import annotations

import json
import platform
import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager
from intellicrack.providers.gpu_pci_resources import max_memory_bar_bytes


try:
    import torch as _torch_module
except ImportError:
    get_logger(__name__).warning(
        "torch_import_unavailable",
        impact="XPU detection is disabled; install pytorch with XPU support to enable",
    )
    _torch_module = None

if TYPE_CHECKING:
    import types

    import torch


_logger = get_logger(__name__)

_B580_DEVICE_IDS: frozenset[str] = frozenset({"0xe20b", "e20b", "E20B", "0xE20B"})
_ARC_DEVICE_PATTERNS: tuple[str, ...] = ("Arc", "A770", "A750", "A380", "A310", "B580")

_INTEL_VENDOR_ID: str = "8086"

_WIN10_MAJOR_VERSION: int = 10
_WIN10_2004_BUILD: int = 19041

_PRE_REBAR_BAR_CEILING_BYTES: int = 256 * 1024 * 1024
_REBAR_RECOMMENDED_MIN_BYTES: int = 512 * 1024 * 1024

_ERR_PYTORCH_NOT_INSTALLED = "PyTorch is not installed"
_ERR_XPU_NOT_AVAILABLE = "PyTorch XPU support is not available"
_ERR_NO_XPU_DEVICES = "No XPU devices are available"


@dataclass(frozen=True)
class XPUDeviceInfo:
    """Information about an Intel XPU device."""

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
        types.ModuleType | None: The torch module if available with XPU support, None otherwise.
    """
    if _torch_module is None:
        _logger.debug("xpu_torch_import_failed", reason="torch not installed")
        return None
    return _torch_module


def is_xpu_available() -> bool:
    """Check if Intel XPU is available for computation.

    Uses PyTorch 2.5+ native torch.xpu.is_available() for detection.
    This function never raises exceptions - returns False on any error.

    Returns:
        bool: True if at least one XPU device is available and usable.
    """
    torch = _import_torch()
    if torch is None:
        return False

    try:
        if not hasattr(torch, "xpu"):
            _logger.debug("xpu_not_available", reason="torch.xpu module missing")
            return False

        is_available: bool = torch.xpu.is_available()
        if is_available:
            _logger.debug("xpu_available", device_count=torch.xpu.device_count())
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.debug("xpu_check_failed", error=str(exc))
        return False
    else:
        return is_available


def get_xpu_device_count() -> int:
    """Get the number of available XPU devices.

    Returns:
        int: Number of XPU devices, 0 if XPU is not available.
    """
    torch = _import_torch()
    if torch is None:
        return 0

    try:
        if not hasattr(torch, "xpu") or not torch.xpu.is_available():
            return 0
        count: int = torch.xpu.device_count()
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.debug("xpu_device_count_failed", error=str(exc))
        return 0
    else:
        return count


def _get_device_name_from_sycl(device_index: int) -> str:
    """Get device name using SYCL if available.

    Args:
        device_index: Index of the device.

    Returns:
        str: Device name string or empty string if unavailable.
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
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.warning("sycl_device_name_failed", error=str(exc))
    return ""


_GPU_ENUM_PWSH_SCRIPT: str = (
    "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
    "Get-CimInstance Win32_VideoController -ErrorAction Stop "
    "| Select-Object Name,PNPDeviceID,DriverVersion "
    "| ConvertTo-Json -Compress -Depth 3"
)


def _strip_pwsh_payload(stdout: str) -> str:
    r"""Strip BOM and surrounding whitespace from a PowerShell stdout payload.

    PowerShell on Windows frequently emits a UTF-8 BOM (``﻿``) which is not whitespace and therefore survives :meth:`str.strip`, causing
    :func:`json.loads` to fail with "Expecting value: line 1 column 1 (char 0)".

    Args:
        stdout: Raw stdout text returned by the subprocess.

    Returns:
        str: Payload with BOM and outer whitespace removed.
    """
    return stdout.lstrip("﻿").strip()


def _query_windows_gpus() -> list[dict[str, str]]:
    """Run a single CIM query and parse GPU entries from JSON output.

    Uses ``Get-CimInstance`` (the supported successor to the deprecated ``Get-WmiObject``), runs pwsh with ``-NoProfile`` /
    ``-NonInteractive`` for a faster cold start, and forces UTF-8 output encoding without BOM. The resulting JSON is robustly stripped of BOM
    bytes before parsing to avoid spurious decode failures on Windows.

    Returns:
        list[dict[str, str]]: Normalized GPU info entries (name/pnp/driver_version).
    """
    result = ProcessManager.get_instance().run_tracked(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _GPU_ENUM_PWSH_SCRIPT,
        ],
        name="xpu-gpu-detect",
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        stderr_text: str = str(result.stderr).strip() if result.stderr else ""
        _logger.warning(
            "xpu_gpu_enum_nonzero_exit",
            returncode=result.returncode,
            stderr=stderr_text,
        )
        return []
    payload = _strip_pwsh_payload(result.stdout)
    if not payload:
        _logger.debug("xpu_gpu_enum_empty_payload")
        return []
    try:
        raw: object = json.loads(payload)
    except json.JSONDecodeError as exc:
        _logger.warning(
            "xpu_gpu_enum_json_parse_failed",
            error=str(exc),
            payload_preview=payload[:160],
        )
        return []
    if isinstance(raw, dict):
        gpu_entries: list[dict[str, str]] = [cast("dict[str, str]", raw)]
    elif isinstance(raw, list):
        raw_list: list[object] = cast("list[object]", raw)
        gpu_entries = [cast("dict[str, str]", item) for item in raw_list if isinstance(item, dict)]
    else:
        gpu_entries = []
    return [
        {
            "name": str(gpu.get("Name", "")),
            "pnp_device_id": str(gpu.get("PNPDeviceID", "")),
            "driver_version": str(gpu.get("DriverVersion", "")),
        }
        for gpu in gpu_entries
    ]


def _get_windows_gpu_info() -> list[dict[str, str]]:
    """Get GPU information on Windows using WMI.

    Returns:
        list[dict[str, str]]: List of dictionaries with GPU information.
    """
    if platform.system() != "Windows":
        return []

    try:
        return _query_windows_gpus()
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        _logger.warning("windows_gpu_info_failed", error=str(exc))
        return []


def _parse_device_id_from_pnp(pnp_id: str) -> str:
    r"""Parse device ID from a PNP device ID string for Intel GPUs only.

    The PNP ID is expected to start with ``PCI\VEN_<vendor>&DEV_<device>``;
    only Intel-vendor entries (vendor ``0x8086``) yield a device ID. Anything
    else returns the empty string so non-Intel GPUs cannot be misclassified
    as Intel Arc devices downstream.

    Args:
        pnp_id: PNP device ID string (e.g., ``PCI\VEN_8086&DEV_E20B...``).

    Returns:
        str: Extracted device ID lower-cased, or empty string when the
        vendor does not match Intel or no ``DEV_`` field is present.
    """
    vendor_match = re.search(r"VEN_([0-9A-Fa-f]{4})", pnp_id)
    if vendor_match is None or vendor_match[1].lower() != _INTEL_VENDOR_ID.lower():
        return ""
    if match := re.search(r"DEV_([0-9A-Fa-f]{4})", pnp_id):
        return match[1].lower()
    return ""


def _extract_torch_xpu_properties(
    torch: types.ModuleType,
    device_index: int,
    device_name: str,
) -> tuple[int, str, str]:
    """Extract memory/driver/name properties from torch.xpu.get_device_properties.

    Args:
        torch: The imported ``torch`` module providing ``xpu`` namespace.
        device_index: Index of the XPU device.
        device_name: Existing best-known device name (may be empty).

    Returns:
        tuple[int, str, str]: ``(total_memory, driver_version, device_name)`` resolved from torch properties.
    """
    total_memory = 0
    driver_version = ""
    if not hasattr(torch.xpu, "get_device_properties"):
        return total_memory, driver_version, device_name
    props = torch.xpu.get_device_properties(device_index)
    if hasattr(props, "total_memory"):
        total_memory = int(props.total_memory)
    if hasattr(props, "driver_version"):
        driver_version = str(props.driver_version)
    if not device_name and hasattr(props, "name"):
        device_name = str(props.name)
    return total_memory, driver_version, device_name


def _enrich_from_windows_gpus(
    device_name: str,
    driver_version: str,
    device_id: str,
) -> tuple[str, str, str]:
    """Fill missing device name/driver/id from Windows WMI GPU info.

    Args:
        device_name: Current device name (may be empty).
        driver_version: Current driver version (may be empty).
        device_id: Current device ID (may be empty).

    Returns:
        tuple[str, str, str]: Updated ``(device_name, driver_version, device_id)`` triple.
    """
    if device_name and driver_version:
        return device_name, driver_version, device_id
    for gpu in _get_windows_gpu_info():
        if "Intel" in gpu["name"] and any(p in gpu["name"] for p in _ARC_DEVICE_PATTERNS):
            if not device_name:
                device_name = gpu["name"]
            if not driver_version:
                driver_version = gpu["driver_version"]
            device_id = _parse_device_id_from_pnp(gpu["pnp_device_id"])
            break
    return device_name, driver_version, device_id


def _build_xpu_device_info(torch: types.ModuleType, device_index: int) -> XPUDeviceInfo | None:
    """Assemble :class:`XPUDeviceInfo` for ``device_index`` using torch and WMI sources.

    Args:
        torch: Imported ``torch`` module with ``xpu`` namespace available.
        device_index: Index of the XPU device.

    Returns:
        XPUDeviceInfo | None: Composed device info, or ``None`` when torch.xpu is unavailable
        or the device index is out of range.
    """
    if not hasattr(torch, "xpu") or not torch.xpu.is_available():
        return None
    if device_index >= torch.xpu.device_count():
        return None

    device_name = _get_device_name_from_sycl(device_index)
    device_id = ""
    try:
        total_memory, driver_version, device_name = _extract_torch_xpu_properties(
            torch,
            device_index,
            device_name,
        )
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.warning("xpu_properties_failed", error=str(exc))
        total_memory = 0
        driver_version = ""

    device_name, driver_version, device_id = _enrich_from_windows_gpus(
        device_name,
        driver_version,
        device_id,
    )
    if total_memory == 0:
        total_memory = _estimate_memory_from_name(device_name)

    return XPUDeviceInfo(
        device_index=device_index,
        device_name=device_name or f"Intel XPU {device_index}",
        total_memory_bytes=total_memory,
        driver_version=driver_version,
        device_id=device_id,
        is_arc_b580=_is_b580_device(device_name, device_id),
        supports_fp16=True,
        supports_bf16=True,
        supports_int8=True,
    )


def get_xpu_device_info(device_index: int) -> XPUDeviceInfo | None:
    """Get detailed information about a specific XPU device.

    Args:
        device_index: Index of the XPU device (0-based).

    Returns:
        XPUDeviceInfo | None: XPUDeviceInfo containing device details, or None if unavailable.
    """
    torch = _import_torch()
    if torch is None:
        return None
    try:
        return _build_xpu_device_info(torch, device_index)
    except (RuntimeError, OSError, AttributeError) as exc:
        _logger.warning("xpu_device_info_failed", device_index=device_index, error=str(exc))
        return None


def _estimate_memory_from_name(device_name: str) -> int:
    """Estimate device memory from device name.

    Args:
        device_name: Device name string.

    Returns:
        int: Estimated memory in bytes.
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
        device_name=device_name,
        estimated_bytes=estimated,
    )
    return estimated


def _is_b580_device(device_name: str, device_id: str) -> bool:
    """Check if device is an Intel Arc B580.

    Args:
        device_name: Device name string.
        device_id: PCI device ID.

    Returns:
        bool: True if device is an Arc B580.
    """
    normalized_device_id = device_id.lower()
    result = normalized_device_id in {value.lower() for value in _B580_DEVICE_IDS} or "b580" in device_name.lower()
    _logger.debug(
        "xpu_b580_detection",
        device_name=device_name,
        device_id=device_id,
        is_b580=result,
    )
    return result


def is_arc_b580() -> bool:
    """Check if an Intel Arc B580 is available.

    Returns:
        bool: True if at least one Arc B580 device is detected.
    """
    if not is_xpu_available():
        _logger.debug("xpu_b580_check_skipped", reason="xpu not available")
        return False

    device_count = get_xpu_device_count()
    _logger.debug("xpu_b580_scan_started", device_count=device_count)
    for i in range(device_count):
        info = get_xpu_device_info(i)
        if info is not None and info.is_arc_b580:
            _logger.debug("xpu_b580_found", device_index=i, device_name=info.device_name)
            return True
    _logger.debug("xpu_b580_not_found", devices_scanned=device_count)
    return False


def initialize_xpu(device_index: int = 0) -> torch.device:
    """Initialize and return a torch.device for XPU.

    Args:
        device_index: Index of the XPU device to use.

    Returns:
        torch.device: Device configured for the specified XPU index.

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

    _logger.info("xpu_initialized", device_index=device_index, device=str(device))
    return device


def _validate_xpu_device(torch_mod: types.ModuleType, device: torch.device) -> None:
    """Validate that XPU device is operational.

    Args:
        torch_mod: The torch module.
        device: The device to validate.

    Raises:
        RuntimeError: If device validation fails.
    """
    _logger.debug("xpu_device_validation_started", device=str(device))
    try:
        test_tensor = torch_mod.zeros(10, device=device)
        _ = test_tensor + 1
        del test_tensor
        torch_mod.xpu.synchronize()
        _logger.debug("xpu_device_validation_passed", device=str(device))
    except (RuntimeError, OSError) as exc:
        _logger.warning("xpu_device_validation_failed", device=str(device), error=str(exc))
        msg = f"XPU device validation failed: {exc}"
        raise RuntimeError(msg) from exc


def _query_xpu_memory(torch: types.ModuleType, device_index: int) -> tuple[int, int]:
    """Query allocated and total XPU memory for ``device_index``.

    Args:
        torch: Imported ``torch`` module with ``xpu`` namespace available.
        device_index: Index of the XPU device.

    Returns:
        tuple[int, int]: ``(allocated_bytes, total_bytes)`` returned from torch and properties.
    """
    if not hasattr(torch, "xpu") or not torch.xpu.is_available():
        return (0, 0)
    allocated = torch.xpu.memory_allocated(device_index) if hasattr(torch.xpu, "memory_allocated") else 0
    total = 0
    if hasattr(torch.xpu, "get_device_properties"):
        props = torch.xpu.get_device_properties(device_index)
        if hasattr(props, "total_memory"):
            total = int(props.total_memory)
    if total == 0:
        info = get_xpu_device_info(device_index)
        if info is not None:
            total = info.total_memory_bytes
    return (allocated, total)


def get_xpu_memory_info(device_index: int = 0) -> tuple[int, int]:
    """Get memory information for an XPU device.

    Args:
        device_index: Index of the XPU device.

    Returns:
        tuple[int, int]: Tuple of (allocated_bytes, total_bytes).
    """
    torch = _import_torch()
    if torch is None:
        return (0, 0)
    try:
        return _query_xpu_memory(torch, device_index)
    except (RuntimeError, OSError, AttributeError):
        _logger.debug("xpu_memory_info_failed", device_index=device_index, exc_info=True)
        return (0, 0)


def clear_xpu_cache() -> None:
    """Clear the XPU memory cache.

    Frees cached memory that is no longer in use. This does not free tensors that are still referenced.
    """
    torch = _import_torch()
    if torch is None:
        return

    try:
        if hasattr(torch, "xpu") and torch.xpu.is_available() and hasattr(torch.xpu, "empty_cache"):
            torch.xpu.empty_cache()
            _logger.info("xpu_cache_cleared")
    except (RuntimeError, OSError) as exc:
        _logger.warning("xpu_cache_clear_failed", error=str(exc))


def check_windows_requirements() -> tuple[bool, list[str]]:
    """Check Windows-specific requirements for XPU acceleration.

    Verifies:
    - Windows 10/11 version compatibility
    - Intel GPU driver installation
    - Resizable BAR (ReBAR) status via PCI BAR enumeration

    A single PowerShell WMI invocation is used to enumerate video controllers; ReBAR status is then derived in-process via cfgmgr32 BAR
    enumeration without spawning additional subprocesses.

    Returns:
        tuple[bool, list[str]]: Tuple of (all_requirements_met, list_of_warning_messages).
    """
    if platform.system() != "Windows":
        _logger.debug("xpu_windows_check_skipped", platform=platform.system())
        return (True, [])

    _logger.debug("xpu_windows_requirements_check_started")
    warnings: list[str] = []
    all_met = True

    win_version = sys.getwindowsversion()
    if win_version.major < _WIN10_MAJOR_VERSION:
        warnings.append("Windows 10 or later is required for Intel XPU support")
        all_met = False
    elif win_version.major == _WIN10_MAJOR_VERSION and win_version.build < _WIN10_2004_BUILD:
        warnings.append("Windows 10 version 2004 (build 19041) or later recommended for optimal XPU support")

    gpus = _get_windows_gpu_info()

    driver_ok, driver_warning = _check_intel_driver(gpus)
    if not driver_ok:
        warnings.append(driver_warning)
        all_met = False

    rebar_ok, rebar_warning = _check_rebar_status(gpus)
    if not rebar_ok and rebar_warning:
        warnings.append(rebar_warning)

    primary_arc = _pick_primary_arc_gpu(gpus)
    if rebar_ok and primary_arc is not None:
        primary_name, primary_bar = primary_arc
        _logger.debug("gpu_bar_size_audited", gpu=primary_name, bar_size=primary_bar)
        if 0 < primary_bar < _REBAR_RECOMMENDED_MIN_BYTES:
            warnings.append(
                f"GPU '{primary_name}' Resizable BAR is enabled but limited to {primary_bar // 1024 // 1024} MB. "
                "Local LLM context profiles exceeding this size will trigger severe CPU-fallback slowdowns.",
            )

    _logger.debug(
        "xpu_windows_requirements_check_complete",
        all_met=all_met,
        warning_count=len(warnings),
    )
    return (all_met, warnings)


def _pick_primary_arc_gpu(gpus: list[dict[str, str]]) -> tuple[str, int] | None:
    """Pick the Intel Arc GPU :mod:`torch.xpu` will most likely use for compute.

    Selects the Arc-class GPU with the largest allocated PCI MMIO BAR; this is the discrete card on systems that also have a Lunar Lake /
    Meteor Lake integrated Arc iGPU, whose 256 MB BAR is architectural rather than a ReBAR failure.

    Args:
        gpus: GPU list returned by :func:`_get_windows_gpu_info`.

    Returns:
        tuple[str, int] | None: ``(device_name, largest_bar_bytes)`` for the selected primary Arc GPU, or ``None`` when no Intel Arc device
        is present.
    """
    primary_name: str | None = None
    primary_bar = 0
    for gpu in gpus:
        name = gpu.get("name", "")
        if "Intel" not in name or not any(p in name for p in _ARC_DEVICE_PATTERNS):
            continue
        pnp_id = gpu.get("pnp_device_id", "")
        if not pnp_id:
            continue
        bar_bytes = max_memory_bar_bytes(pnp_id)
        if bar_bytes > primary_bar:
            primary_bar = bar_bytes
            primary_name = name
    if primary_name is None:
        return None
    return (primary_name, primary_bar)


def _check_intel_driver(gpus: list[dict[str, str]] | None = None) -> tuple[bool, str]:
    """Check Intel GPU driver status from enumerated Win32_VideoController entries.

    Args:
        gpus: Pre-enumerated GPU list from :func:`_get_windows_gpu_info`. When None,
            the GPU list is fetched lazily so the helper remains usable standalone.

    Returns:
        tuple[bool, str]: Tuple of (driver_ok, warning_message). ``driver_ok`` is True when
        at least one Intel Arc-class GPU is present with a non-empty driver version string.
    """
    _logger.debug("xpu_driver_check_started")
    gpu_list = gpus if gpus is not None else _get_windows_gpu_info()
    for gpu in gpu_list:
        name = gpu.get("name", "")
        if "Intel" not in name:
            continue
        if not any(pattern in name for pattern in _ARC_DEVICE_PATTERNS):
            continue
        driver_version = gpu.get("driver_version", "").strip()
        if driver_version:
            _logger.debug("xpu_driver_detected", device=name, driver_version=driver_version)
            return (True, "")
    _logger.debug("xpu_driver_not_found", gpu_count=len(gpu_list))
    return (False, "Intel Arc GPU driver not detected. Install the latest Intel Arc driver from intel.com")


def _check_rebar_status(gpus: list[dict[str, str]] | None = None) -> tuple[bool, str]:
    """Check Resizable BAR status by inspecting allocated PCI BAR sizes.

    ReBAR is detected by walking the cfgmgr32 ``ALLOC_LOG_CONF`` resource list for each Intel Arc PnP device and checking whether the largest
    allocated MEM/MEM_LARGE descriptor exceeds the legacy 256 MB pre-ReBAR ceiling. This is vendor-agnostic and accurate for Intel Arc; the
    previous registry approach relied on NVIDIA-only ``RmGpuLdPciResizableBar`` keys and always reported disabled on Intel hardware.

    Args:
        gpus: Pre-enumerated GPU list from :func:`_get_windows_gpu_info`. When None,
            the GPU list is fetched lazily so the helper remains usable standalone.

    Returns:
        tuple[bool, str]: Tuple of (rebar_enabled, warning_message). ``rebar_enabled`` is True when at least one Intel Arc GPU has a BAR
        larger than 256 MB. The warning string is empty when no warning should be surfaced (including the no-Intel-GPU case, which is already
        reflected by the driver check).
    """
    _logger.debug("xpu_rebar_check_started")
    gpu_list = gpus if gpus is not None else _get_windows_gpu_info()
    intel_gpus = [
        gpu
        for gpu in gpu_list
        if "Intel" in gpu.get("name", "") and any(pattern in gpu.get("name", "") for pattern in _ARC_DEVICE_PATTERNS)
    ]
    if not intel_gpus:
        _logger.debug("xpu_rebar_skipped", reason="no_intel_arc_gpu")
        return (False, "")

    largest_bar = 0
    for gpu in intel_gpus:
        pnp_id = gpu.get("pnp_device_id", "")
        if not pnp_id:
            continue
        bar_bytes = max_memory_bar_bytes(pnp_id)
        largest_bar = max(largest_bar, bar_bytes)

    if largest_bar <= 0:
        _logger.warning("xpu_rebar_check_indeterminate", reason="no_bar_descriptors")
        return (False, "Could not verify Resizable BAR status (PCI resource enumeration returned no data)")

    if largest_bar > _PRE_REBAR_BAR_CEILING_BYTES:
        _logger.debug("xpu_rebar_enabled", largest_bar_bytes=largest_bar)
        return (True, "")

    _logger.debug("xpu_rebar_not_enabled", largest_bar_bytes=largest_bar)
    bar_mb = largest_bar // 1024 // 1024
    return (
        False,
        (
            f"Resizable BAR (ReBAR) is not enabled (PCI BAR limited to {bar_mb} MB). "
            "Enable Resizable BAR in BIOS/UEFI for optimal performance."
        ),
    )


def get_optimal_dtype_for_xpu() -> str:
    """Get the optimal data type for XPU inference.

    Intel Arc B580 supports FP16 and BF16, but not FP64 on Windows.

    Returns:
        str: String dtype name ("float16", "bfloat16", or "float32").
    """
    _logger.debug("xpu_dtype_detection_started")
    torch = _import_torch()
    if torch is None:
        _logger.debug("xpu_dtype_selected", dtype="float32", reason="torch unavailable")
        return "float32"

    if not is_xpu_available():
        _logger.debug("xpu_dtype_selected", dtype="float32", reason="xpu unavailable")
        return "float32"

    try:
        device = torch.device("xpu:0")
        test_bf16 = torch.zeros(10, dtype=torch.bfloat16, device=device)
        _ = test_bf16 + 1
        del test_bf16
        torch.xpu.synchronize()
    except (RuntimeError, OSError) as exc:
        _logger.debug("bf16_not_supported", error=str(exc))
    else:
        _logger.debug("xpu_dtype_selected", dtype="bfloat16")
        return "bfloat16"

    try:
        device = torch.device("xpu:0")
        test_fp16 = torch.zeros(10, dtype=torch.float16, device=device)
        _ = test_fp16 + 1
        del test_fp16
        torch.xpu.synchronize()
    except (RuntimeError, OSError) as exc:
        _logger.debug("fp16_not_supported", error=str(exc))
    else:
        _logger.debug("xpu_dtype_selected", dtype="float16")
        return "float16"

    _logger.debug("xpu_dtype_selected", dtype="float32", reason="fallback")
    return "float32"
