# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Windows PnP PCI resource enumeration for GPU BAR detection.

Uses ``cfgmgr32.dll`` (``CM_Locate_DevNodeW``, ``CM_Get_First_Log_Conf``, ``CM_Get_Next_Res_Des``, ``CM_Get_Res_Des_Data``) to walk the
allocated resource descriptors of a GPU PnP device and read the actual MEM_LARGE (64-bit prefetchable) BAR sizes that Windows allocated to
the device.

This is the canonical user-space, no-admin Windows mechanism for inspecting the resized PCI BAR. ``Win32_DeviceMemoryAddress`` only reports
legacy 32-bit MMIO ranges, so it cannot distinguish ReBAR-enabled (multi-GB BAR) from ReBAR-disabled (256 MB cap) on Intel Arc, AMD Radeon,
or NVIDIA discrete GPUs.

Reference: ``cfgmgr32.h`` and ``cfg.h`` (Windows SDK), MEM_DES / MEM_LARGE_RESOURCE layouts.
"""

from __future__ import annotations

import ctypes
import platform
import struct
from ctypes import POINTER, byref, c_uint32, c_uint64, c_void_p, c_wchar_p
from dataclasses import dataclass
from typing import Any, ClassVar

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)


_CR_SUCCESS: int = 0
_ALLOC_LOG_CONF: int = 0
_BOOT_LOG_CONF: int = 1

_RES_TYPE_MEM: int = 0x00000001
_RES_TYPE_MEM_LARGE: int = 0x00000007

_MEM_DES_SIZE: int = 32
_MEM_RANGE_SIZE: int = 40
_MEM_LARGE_RANGE_SIZE: int = 40

_MEM_RESOURCE_MIN_SIZE: int = _MEM_DES_SIZE + _MEM_RANGE_SIZE
_MEM_LARGE_RESOURCE_MIN_SIZE: int = _MEM_DES_SIZE + _MEM_LARGE_RANGE_SIZE


@dataclass(frozen=True)
class _BarDescriptor:
    """A single allocated PCI memory BAR descriptor.

    Attributes:
        is_large: True if the descriptor came from the ResType_MemLarge list
            (64-bit prefetchable BAR), False for legacy 32-bit MEM descriptors.
        size_bytes: Required allocation length for the BAR.
        flags: PCI resource flags as reported by cfgmgr32 (PCI BAR type bits).
    """

    is_large: bool
    size_bytes: int
    flags: int


class _Cfgmgr32:
    """Bound ctypes wrappers around the cfgmgr32 functions used here."""

    _SIGNATURES: ClassVar[list[tuple[str, Any, list[Any]]]] = [
        ("CM_Locate_DevNodeW", c_uint32, [POINTER(c_uint32), c_wchar_p, c_uint32]),
        ("CM_Get_First_Log_Conf", c_uint32, [POINTER(c_uint64), c_uint32, c_uint32]),
        (
            "CM_Get_Next_Res_Des",
            c_uint32,
            [POINTER(c_uint64), c_uint64, c_uint32, POINTER(c_uint32), c_uint32],
        ),
        ("CM_Get_Res_Des_Data_Size", c_uint32, [POINTER(c_uint32), c_uint64, c_uint32]),
        ("CM_Get_Res_Des_Data", c_uint32, [c_uint64, c_void_p, c_uint32, c_uint32]),
        ("CM_Free_Res_Des_Handle", c_uint32, [c_uint64]),
        ("CM_Free_Log_Conf_Handle", c_uint32, [c_uint64]),
    ]

    locate_devnode: Any
    get_first_log_conf: Any
    get_next_res_des: Any
    get_res_des_data_size: Any
    get_res_des_data: Any
    free_res_des_handle: Any
    free_log_conf_handle: Any

    def __init__(self) -> None:
        """Load cfgmgr32.dll and resolve every function pointer used here."""
        self._lib = ctypes.WinDLL("cfgmgr32.dll")
        for name, restype, argtypes in self._SIGNATURES:
            fn: Any = getattr(self._lib, name)
            fn.restype = restype
            fn.argtypes = argtypes
        self.locate_devnode = self._lib.CM_Locate_DevNodeW
        self.get_first_log_conf = self._lib.CM_Get_First_Log_Conf
        self.get_next_res_des = self._lib.CM_Get_Next_Res_Des
        self.get_res_des_data_size = self._lib.CM_Get_Res_Des_Data_Size
        self.get_res_des_data = self._lib.CM_Get_Res_Des_Data
        self.free_res_des_handle = self._lib.CM_Free_Res_Des_Handle
        self.free_log_conf_handle = self._lib.CM_Free_Log_Conf_Handle
        _logger.debug("cfgmgr32_bindings_loaded", function_count=len(self._SIGNATURES))


def _load_cfgmgr() -> _Cfgmgr32 | None:
    """Load cfgmgr32.dll bindings on Windows, return None elsewhere.

    Returns:
        _Cfgmgr32 | None: Loaded binding wrapper, or None if the platform is
        not Windows or the DLL cannot be loaded.
    """
    if platform.system() != "Windows":
        return None
    try:
        return _Cfgmgr32()
    except OSError as exc:
        _logger.warning("cfgmgr32_load_failed", error=str(exc))
        return None


def _locate_devnode(cfg: _Cfgmgr32, device_id: str) -> int | None:
    r"""Resolve a PnP device instance ID to a cfgmgr DEVINST handle.

    Args:
        cfg: Active cfgmgr32 bindings.
        device_id: PnP instance ID such as ``PCI\VEN_8086&DEV_E20B&...``.

    Returns:
        int | None: DEVINST integer, or None when the device cannot be found.
    """
    devinst = c_uint32(0)
    rc: int = int(cfg.locate_devnode(byref(devinst), device_id, 0))
    if rc != _CR_SUCCESS:
        _logger.debug("cfgmgr_locate_failed", device_id=device_id, rc=rc, rc_hex=hex(rc))
        return None
    return devinst.value


def _read_descriptor_bytes(cfg: _Cfgmgr32, res_des: int) -> bytes | None:
    """Read the raw bytes of a single resource descriptor.

    Args:
        cfg: Active cfgmgr32 bindings.
        res_des: Resource descriptor handle.

    Returns:
        bytes | None: Raw descriptor payload, or None on failure.
    """
    size = c_uint32(0)
    rc: int = int(cfg.get_res_des_data_size(byref(size), res_des, 0))
    if rc != _CR_SUCCESS or size.value == 0:
        return None
    buf = (ctypes.c_uint8 * size.value)()
    rc = int(cfg.get_res_des_data(res_des, buf, size.value, 0))
    return None if rc != _CR_SUCCESS else bytes(buf)


def _parse_mem_descriptor(data: bytes, *, large: bool) -> _BarDescriptor | None:
    """Decode a MEM_RESOURCE or MEM_LARGE_RESOURCE payload into a ``_BarDescriptor``.

    The cfgmgr32 ``MEM_DES`` / ``MEM_LARGE_DES`` header occupies the first 32
    bytes and is followed by a single ``MEM_RANGE`` (40 B, ``MR_nBytes`` =
    uint32) or ``MEM_LARGE_RANGE`` (40 B, ``MLR_nBytes`` = uint64) entry. We
    read the byte count and the flags out of the MEM_RANGE portion.

    Args:
        data: Raw descriptor bytes returned by ``CM_Get_Res_Des_Data``.
        large: True when the source list is ResType_MemLarge.

    Returns:
        _BarDescriptor | None: Parsed descriptor, or None when the buffer is
        too short to be valid.
    """
    minimum = _MEM_LARGE_RESOURCE_MIN_SIZE if large else _MEM_RESOURCE_MIN_SIZE
    if len(data) < minimum:
        return None
    range_offset = _MEM_DES_SIZE
    flags_le = data[range_offset + 32 : range_offset + 36]
    nbytes_le = data[range_offset + 8 : range_offset + 16] if large else data[range_offset + 8 : range_offset + 12]
    size_bytes = int.from_bytes(nbytes_le, byteorder="little", signed=False)
    flags = struct.unpack("<I", flags_le)[0]
    return _BarDescriptor(is_large=large, size_bytes=size_bytes, flags=flags)


def _enumerate_bars_for_log_conf(cfg: _Cfgmgr32, log_conf: int) -> list[_BarDescriptor]:
    """Walk every MEM and MEM_LARGE descriptor under a single log configuration.

    Args:
        cfg: Active cfgmgr32 bindings.
        log_conf: Logical configuration handle.

    Returns:
        list[_BarDescriptor]: All parsed BAR descriptors discovered.
    """
    bars: list[_BarDescriptor] = []
    for res_type, large in ((_RES_TYPE_MEM, False), (_RES_TYPE_MEM_LARGE, True)):
        prev: int = log_conf
        while True:
            next_res = c_uint64(0)
            res_id = c_uint32(0)
            rc: int = int(cfg.get_next_res_des(byref(next_res), prev, res_type, byref(res_id), 0))
            if rc != _CR_SUCCESS:
                break
            data = _read_descriptor_bytes(cfg, next_res.value)
            if data is not None:
                bar = _parse_mem_descriptor(data, large=large)
                if bar is not None:
                    bars.append(bar)
            if prev != log_conf:
                cfg.free_res_des_handle(prev)
            prev = next_res.value
        if prev != log_conf:
            cfg.free_res_des_handle(prev)
    return bars


def enumerate_pci_memory_bars(device_id: str) -> list[_BarDescriptor]:
    r"""Enumerate every allocated memory BAR for a PnP PCI device.

    Reads the ``ALLOC_LOG_CONF`` resource list, which reflects the
    configuration Windows actually allocated to the device after firmware /
    PnP arbitration (i.e. the post-ReBAR-resize values when ReBAR is enabled).

    Args:
        device_id: PnP device instance ID, e.g.
            ``PCI\VEN_8086&DEV_E20B&SUBSYS_A003207E&REV_00\6&128604AE&0&00080008``.

    Returns:
        list[_BarDescriptor]: All MEM and MEM_LARGE BARs for the device.
        Empty when the device is not present, cfgmgr32 cannot be loaded, or
        the platform is not Windows.
    """
    cfg = _load_cfgmgr()
    if cfg is None:
        return []
    devinst = _locate_devnode(cfg, device_id)
    if devinst is None:
        return []

    log_conf = c_uint64(0)
    rc: int = int(cfg.get_first_log_conf(byref(log_conf), devinst, _ALLOC_LOG_CONF))
    if rc != _CR_SUCCESS:
        _logger.debug("cfgmgr_no_alloc_log_conf", device_id=device_id, rc=rc, rc_hex=hex(rc))
        return []

    try:
        return _enumerate_bars_for_log_conf(cfg, log_conf.value)
    finally:
        cfg.free_log_conf_handle(log_conf.value)


def max_memory_bar_bytes(device_id: str) -> int:
    """Return the size (bytes) of the largest allocated memory BAR for a device.

    Args:
        device_id: PnP device instance ID.

    Returns:
        int: Largest BAR size in bytes (across both 32-bit MEM and 64-bit
        MEM_LARGE allocations). Zero when no BARs are reported.
    """
    bars = enumerate_pci_memory_bars(device_id)
    return max(b.size_bytes for b in bars) if bars else 0
