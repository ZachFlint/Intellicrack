# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for PCI BAR enumeration and XPU detection.

These tests drive ``intellicrack.providers.gpu_pci_resources`` and
``intellicrack.providers.xpu_utils`` against the real machine. BAR
enumeration runs against the genuine PnP device instance IDs reported
by ``Win32_VideoController`` (via the production WMI query), so when an
Intel Arc GPU is present the test reads the real allocated BAR size
straight from ``cfgmgr32.dll``. Platform-specific and absent-hardware
paths are validated with explicit, accurate assertions rather than
mocks.
"""

from __future__ import annotations

import platform
import re
from typing import TYPE_CHECKING, Protocol, cast

import pytest

import intellicrack.providers.gpu_pci_resources as gpu_pci
from intellicrack.providers import xpu_utils
from intellicrack.providers.gpu_pci_resources import (
    enumerate_pci_memory_bars,
    max_memory_bar_bytes,
)


if TYPE_CHECKING:
    from collections.abc import Callable


class _BarLike(Protocol):
    """Structural view of a parsed BAR descriptor used by these tests.

    Attributes:
        is_large: True for a 64-bit MEM_LARGE descriptor.
        size_bytes: Allocated BAR byte count.
        flags: PCI resource flags.
    """

    is_large: bool
    size_bytes: int
    flags: int


_IS_WINDOWS: bool = platform.system() == "Windows"


def _load_cfgmgr() -> object:
    """Load the module-private cfgmgr32 bindings.

    Returns:
        object: A bindings wrapper, or None off Windows / on load failure.
    """
    fn = cast("Callable[[], object]", vars(gpu_pci)["_load_cfgmgr"])
    return fn()


def _parse_mem_descriptor(data: bytes, *, large: bool) -> _BarLike | None:
    """Decode a raw MEM/MEM_LARGE descriptor via the module-private parser.

    Args:
        data: Raw descriptor bytes.
        large: True for a MEM_LARGE payload.

    Returns:
        _BarLike | None: A parsed descriptor, or None when too short to parse.
    """
    fn = cast("Callable[..., _BarLike | None]", vars(gpu_pci)["_parse_mem_descriptor"])
    return fn(data, large=large)


def _get_windows_gpu_info() -> list[dict[str, str]]:
    """Run the module-private Windows GPU enumeration.

    Returns:
        list[dict[str, str]]: Normalized GPU info entries.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils)["_get_windows_gpu_info"])
    return fn()


def _parse_device_id_from_pnp(pnp_id: str) -> str:
    """Parse an Intel device id from a PnP id via the module-private helper.

    Args:
        pnp_id: PnP device instance id string.

    Returns:
        str: Lower-cased device id, or empty string for non-Intel ids.
    """
    fn = cast("Callable[[str], str]", vars(xpu_utils)["_parse_device_id_from_pnp"])
    return fn(pnp_id)


_PRE_REBAR_CEILING: int = 256 * 1024 * 1024


def _real_pci_gpu_pnp_ids() -> list[str]:
    r"""Return real PCI GPU PnP instance IDs from the live WMI enumeration.

    Returns:
        list[str]: PnP device instance IDs that start with ``PCI\``.
    """
    if not _IS_WINDOWS:
        return []
    return [
        gpu["pnp_device_id"]
        for gpu in _get_windows_gpu_info()
        if gpu.get("pnp_device_id", "").upper().startswith("PCI\\")
    ]


def _real_intel_arc_pnp_ids() -> list[str]:
    """Return real Intel Arc GPU PnP IDs from the live WMI enumeration.

    Returns:
        list[str]: PnP IDs for Intel-vendor GPUs that match an Arc name.
    """
    if not _IS_WINDOWS:
        return []
    return [
        gpu["pnp_device_id"]
        for gpu in _get_windows_gpu_info()
        if "Intel" in gpu.get("name", "")
        and "Arc" in gpu.get("name", "")
        and gpu.get("pnp_device_id", "").upper().startswith("PCI\\")
    ]


class TestLoadCfgmgr:
    """Validate the cfgmgr32 binding loader per platform."""

    @staticmethod
    def test_returns_none_off_windows() -> None:
        """On non-Windows the loader returns None without raising."""
        if _IS_WINDOWS:
            pytest.skip("cfgmgr32 is a Windows-only DLL")
        assert _load_cfgmgr() is None

    @staticmethod
    def test_loads_real_cfgmgr_on_windows() -> None:
        """On Windows the loader resolves every cfgmgr32 function pointer."""
        if not _IS_WINDOWS:
            pytest.skip("cfgmgr32 is only available on Windows")
        cfg = _load_cfgmgr()
        assert cfg is not None
        for attr in ("locate_devnode", "get_first_log_conf", "get_next_res_des", "get_res_des_data"):
            assert callable(getattr(cfg, attr)), f"{attr} should be a bound cfgmgr32 function"


class TestEnumeratePciMemoryBars:
    """Validate real BAR enumeration against live hardware and edge cases."""

    @staticmethod
    def test_off_windows_returns_empty() -> None:
        """On non-Windows the enumeration short-circuits to an empty list."""
        if _IS_WINDOWS:
            pytest.skip("BAR enumeration is Windows-only")
        result = enumerate_pci_memory_bars(r"PCI\VEN_8086&DEV_E20B\0")
        assert result == []
        assert max_memory_bar_bytes(r"PCI\VEN_8086&DEV_E20B\0") == 0

    @staticmethod
    def test_nonexistent_device_returns_empty() -> None:
        """A device instance ID that does not resolve yields no BARs."""
        if not _IS_WINDOWS:
            pytest.skip("BAR enumeration is Windows-only")
        bogus = r"PCI\VEN_FFFF&DEV_FFFF&SUBSYS_00000000&REV_00\0&00000000&0&00000000"
        assert enumerate_pci_memory_bars(bogus) == []
        assert max_memory_bar_bytes(bogus) == 0

    @staticmethod
    @pytest.mark.spawns_process
    def test_real_gpu_reports_positive_bar() -> None:
        """A real PCI GPU reports at least one allocated memory BAR."""
        if not _IS_WINDOWS:
            pytest.skip("BAR enumeration is Windows-only")
        gpu_ids = _real_pci_gpu_pnp_ids()
        if not gpu_ids:
            pytest.skip("No PCI GPU present in Win32_VideoController enumeration")
        any_bar_found = False
        for pnp_id in gpu_ids:
            bars = enumerate_pci_memory_bars(pnp_id)
            for bar in bars:
                assert isinstance(bar.size_bytes, int)
                assert bar.size_bytes >= 0
                assert isinstance(bar.is_large, bool)
                assert isinstance(bar.flags, int)
            if bars:
                any_bar_found = True
                assert max_memory_bar_bytes(pnp_id) == max(b.size_bytes for b in bars)
        assert any_bar_found, "Expected at least one PCI GPU to report a memory BAR"

    @staticmethod
    @pytest.mark.spawns_process
    def test_intel_arc_bar_is_at_least_pre_rebar_ceiling() -> None:
        """A real Intel Arc GPU reports a BAR at least the legacy 256 MB cap."""
        if not _IS_WINDOWS:
            pytest.skip("BAR enumeration is Windows-only")
        arc_ids = _real_intel_arc_pnp_ids()
        if not arc_ids:
            pytest.skip("No Intel Arc GPU present on this machine")
        largest = max(max_memory_bar_bytes(pnp_id) for pnp_id in arc_ids)
        assert largest >= _PRE_REBAR_CEILING


class TestParseMemDescriptor:
    """Validate descriptor decoding against real byte layouts."""

    @staticmethod
    def test_too_short_buffer_returns_none() -> None:
        """A buffer shorter than the minimum descriptor size returns None."""
        assert _parse_mem_descriptor(b"\x00" * 8, large=False) is None
        assert _parse_mem_descriptor(b"\x00" * 8, large=True) is None

    @staticmethod
    def _build_descriptor(size_bytes: int, flags: int, *, large: bool) -> bytes:
        """Build a 72-byte MEM/MEM_LARGE descriptor at the real field offsets.

        The parser reads the byte count from ``range_offset + 8`` (offset
        40) and the flags from ``range_offset + 32`` (offset 64), where
        ``range_offset`` is the 32-byte MEM_DES header.

        Args:
            size_bytes: BAR byte count to encode at offset 40.
            flags: PCI flags to encode at offset 64.
            large: True to encode an 8-byte count, False for 4 bytes.

        Returns:
            bytes: A descriptor payload at least 72 bytes long.
        """
        buf = bytearray(72)
        count_width = 8 if large else 4
        buf[40 : 40 + count_width] = size_bytes.to_bytes(count_width, "little")
        buf[64:68] = flags.to_bytes(4, "little")
        return bytes(buf)

    def test_large_descriptor_decodes_uint64_size(self) -> None:
        """A MEM_LARGE payload decodes the 64-bit byte count and flags."""
        payload = self._build_descriptor(16 * 1024 * 1024 * 1024, 0x87, large=True)
        bar = _parse_mem_descriptor(payload, large=True)
        assert bar is not None
        assert bar.is_large is True
        assert bar.size_bytes == 16 * 1024 * 1024 * 1024
        assert bar.flags == 0x87

    def test_small_descriptor_decodes_uint32_size(self) -> None:
        """A legacy MEM payload decodes the 32-bit byte count and flags."""
        payload = self._build_descriptor(256 * 1024 * 1024, 0x01, large=False)
        bar = _parse_mem_descriptor(payload, large=False)
        assert bar is not None
        assert bar.is_large is False
        assert bar.size_bytes == 256 * 1024 * 1024
        assert bar.flags == 0x01


class TestParseDeviceIdFromPnp:
    """Validate Intel-only device-id parsing from real PnP id strings."""

    @staticmethod
    def test_intel_arc_b580_device_id() -> None:
        """An Intel-vendor PnP id yields the lower-cased device id."""
        pnp = r"PCI\VEN_8086&DEV_E20B&SUBSYS_A003207E&REV_00\6&128604AE&0&00080008"
        assert _parse_device_id_from_pnp(pnp) == "e20b"

    @staticmethod
    def test_non_intel_vendor_returns_empty() -> None:
        """A non-Intel vendor id is rejected so it cannot be misclassified."""
        nvidia = r"PCI\VEN_10DE&DEV_2684&SUBSYS_00000000&REV_A1\4&abcd&0&0008"
        assert not _parse_device_id_from_pnp(nvidia)

    @staticmethod
    def test_missing_dev_field_returns_empty() -> None:
        """An Intel id without a DEV_ field returns an empty string."""
        assert not _parse_device_id_from_pnp(r"PCI\VEN_8086&SUBSYS_0\0")

    @staticmethod
    @pytest.mark.spawns_process
    def test_real_intel_arc_ids_parse_to_hex_device_id() -> None:
        """Every real Intel Arc PnP id parses to a 4-hex-digit device id."""
        if not _IS_WINDOWS:
            pytest.skip("WMI GPU enumeration is Windows-only")
        arc_ids = _real_intel_arc_pnp_ids()
        if not arc_ids:
            pytest.skip("No Intel Arc GPU present on this machine")
        for pnp_id in arc_ids:
            device_id = _parse_device_id_from_pnp(pnp_id)
            assert re.fullmatch(r"[0-9a-f]{4}", device_id), f"unexpected device id {device_id!r} for {pnp_id}"
