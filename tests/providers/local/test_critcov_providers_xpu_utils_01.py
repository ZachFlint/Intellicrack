# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for ``intellicrack.providers.xpu_utils`` on a machine without an Intel XPU.

Three situations are driven with real objects only:

* The module's torch handle set to ``None`` (the state of an installation without PyTorch), which
  every public entry point must degrade from gracefully.
* The genuine PyTorch XPU build running on a machine with no XPU device.
* The Windows GPU probe, either with ``pwsh`` unreachable on ``PATH`` or with the module's
  PowerShell script constant replaced by a script that prints a chosen JSON payload, so the real
  subprocess machinery and the real JSON parser run end to end.

The container has no XPU device, so every branch that needs one is intentionally not exercised here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.providers import xpu_utils
from intellicrack.providers.xpu_utils import (
    check_windows_requirements,
    clear_xpu_cache,
    get_optimal_dtype_for_xpu,
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    initialize_xpu,
    is_xpu_available,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_ARC_NAME: str = "Intel(R) Arc(TM) B580 Graphics"
_ARC_PNP: str = "PCI\\VEN_8086&DEV_E20B&SUBSYS_00000000&REV_00\\0&00000000&0&00000000"
_ARC_DRIVER: str = "32.0.101.6874"
_ARC_DEVICE_ID: str = "e20b"
_NVIDIA_NAME: str = "NVIDIA GeForce RTX 4090"
_NVIDIA_PNP: str = "PCI\\VEN_10DE&DEV_2684&SUBSYS_00000000&REV_A1\\4&1A2B3C&0&0008"
_NVIDIA_DRIVER: str = "31.0.15.5222"

_DRIVER_MISSING_PREFIX: str = "Intel Arc GPU driver not detected"
_REBAR_UNVERIFIED_PREFIX: str = "Could not verify Resizable BAR status"


def _call_import_torch() -> object:
    """Call the module-private ``_import_torch``.

    Returns:
        object: Whatever ``_import_torch`` returned.
    """
    fn = cast("Callable[[], object]", vars(xpu_utils)["_import_torch"])
    return fn()


def _call_get_device_name_from_sycl(device_index: int) -> str:
    """Call the module-private ``_get_device_name_from_sycl``.

    Args:
        device_index: Device index to look up.

    Returns:
        str: The device name reported by the helper.
    """
    fn = cast("Callable[[int], str]", vars(xpu_utils)["_get_device_name_from_sycl"])
    return fn(device_index)


def _call_query_windows_gpus() -> list[dict[str, str]]:
    """Call the module-private ``_query_windows_gpus``.

    Returns:
        list[dict[str, str]]: Normalized GPU entries.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils)["_query_windows_gpus"])
    return fn()


def _call_get_windows_gpu_info() -> list[dict[str, str]]:
    """Call the module-private ``_get_windows_gpu_info``.

    Returns:
        list[dict[str, str]]: Normalized GPU entries.
    """
    fn = cast("Callable[[], list[dict[str, str]]]", vars(xpu_utils)["_get_windows_gpu_info"])
    return fn()


def _call_enrich(device_name: str, driver_version: str, device_id: str) -> tuple[str, str, str]:
    """Call the module-private ``_enrich_from_windows_gpus``.

    Args:
        device_name: Current device name.
        driver_version: Current driver version.
        device_id: Current device identifier.

    Returns:
        tuple[str, str, str]: The ``(device_name, driver_version, device_id)`` triple after enrichment.
    """
    fn = cast("Callable[[str, str, str], tuple[str, str, str]]", vars(xpu_utils)["_enrich_from_windows_gpus"])
    return fn(device_name, driver_version, device_id)


def _call_pick_primary_arc_gpu(gpus: list[dict[str, str]]) -> tuple[str, int] | None:
    """Call the module-private ``_pick_primary_arc_gpu``.

    Args:
        gpus: GPU entries to choose from.

    Returns:
        tuple[str, int] | None: The chosen ``(name, bar_bytes)`` pair or ``None``.
    """
    fn = cast("Callable[[list[dict[str, str]]], tuple[str, int] | None]", vars(xpu_utils)["_pick_primary_arc_gpu"])
    return fn(gpus)


def _call_check_intel_driver(gpus: list[dict[str, str]]) -> tuple[bool, str]:
    """Call the module-private ``_check_intel_driver``.

    Args:
        gpus: GPU entries to inspect.

    Returns:
        tuple[bool, str]: ``(driver_ok, warning_message)``.
    """
    fn = cast("Callable[[list[dict[str, str]]], tuple[bool, str]]", vars(xpu_utils)["_check_intel_driver"])
    return fn(gpus)


def _call_check_rebar_status(gpus: list[dict[str, str]]) -> tuple[bool, str]:
    """Call the module-private ``_check_rebar_status``.

    Args:
        gpus: GPU entries to inspect.

    Returns:
        tuple[bool, str]: ``(rebar_enabled, warning_message)``.
    """
    fn = cast("Callable[[list[dict[str, str]]], tuple[bool, str]]", vars(xpu_utils)["_check_rebar_status"])
    return fn(gpus)


def _gpu(name: str, pnp_device_id: str, driver_version: str) -> dict[str, str]:
    """Build one normalized GPU entry.

    Args:
        name: Adapter name.
        pnp_device_id: PnP device instance identifier.
        driver_version: Driver version string.

    Returns:
        dict[str, str]: Entry with the keys the product's helpers read.
    """
    return {"name": name, "pnp_device_id": pnp_device_id, "driver_version": driver_version}


def _gpu_json_script(*entries: tuple[str, str, str]) -> str:
    """Build a PowerShell script that prints the given GPUs as a compact JSON array.

    Args:
        *entries: ``(name, pnp_device_id, driver_version)`` triples to print.

    Returns:
        str: Script text accepted by ``pwsh -Command``.
    """
    items = ",".join(f"@{{Name='{name}';PNPDeviceID='{pnp}';DriverVersion='{driver}'}}" for name, pnp, driver in entries)
    return f"ConvertTo-Json -Compress -InputObject @({items})"


def _use_gpu_script(monkeypatch: pytest.MonkeyPatch, script: str) -> None:
    """Make the product's GPU enumeration run ``script`` instead of its Win32_VideoController query.

    Args:
        monkeypatch: Restores the module constant when the test ends.
        script: PowerShell text that prints the payload to parse.
    """
    monkeypatch.setattr(xpu_utils, "_GPU_ENUM_PWSH_SCRIPT", script)


@pytest.fixture
def without_torch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the module in the state of an installation without PyTorch.

    Args:
        monkeypatch: Restores the module's torch handle when the test ends.
    """
    monkeypatch.setattr(xpu_utils, "_torch_module", None)


@pytest.fixture
def pwsh_unreachable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point ``PATH`` at an empty directory so ``pwsh`` cannot be resolved.

    Args:
        monkeypatch: Restores ``PATH`` when the test ends.
        tmp_path: Per-test temporary directory used as the only ``PATH`` entry.
    """
    empty_dir = tmp_path / "empty_path"
    empty_dir.mkdir()
    monkeypatch.setenv("PATH", str(empty_dir))


@pytest.mark.usefixtures("without_torch")
class TestWithoutTorch:
    """Every entry point degrades to its documented neutral value when PyTorch is missing."""

    @staticmethod
    def test_import_torch_returns_none() -> None:
        """The torch accessor reports no module."""
        assert _call_import_torch() is None

    @staticmethod
    def test_xpu_is_not_available() -> None:
        """Availability is False rather than an exception."""
        assert is_xpu_available() is False

    @staticmethod
    def test_device_count_is_zero() -> None:
        """No torch means zero devices."""
        assert get_xpu_device_count() == 0

    @staticmethod
    def test_device_name_is_empty() -> None:
        """The SYCL name lookup yields the empty string."""
        name = _call_get_device_name_from_sycl(0)
        assert isinstance(name, str)
        assert not name

    @staticmethod
    def test_device_info_is_none() -> None:
        """Device info is None, not a populated record."""
        assert get_xpu_device_info(0) is None

    @staticmethod
    def test_initialize_xpu_raises_descriptive_error() -> None:
        """Initialization reports that PyTorch is not installed."""
        with pytest.raises(RuntimeError, match="PyTorch is not installed"):
            initialize_xpu(0)

    @staticmethod
    def test_memory_info_is_zero_pair() -> None:
        """Memory info is the (0, 0) pair for any device index."""
        assert get_xpu_memory_info(0) == (0, 0)
        assert get_xpu_memory_info(3) == (0, 0)

    @staticmethod
    def test_clear_cache_is_a_silent_noop() -> None:
        """Clearing the cache neither raises nor changes detection."""
        clear_xpu_cache()
        assert is_xpu_available() is False

    @staticmethod
    def test_optimal_dtype_is_float32() -> None:
        """The dtype fallback is float32."""
        assert get_optimal_dtype_for_xpu() == "float32"


class TestRealTorchWithoutDevice:
    """The genuine PyTorch XPU build on a machine that has no XPU device."""

    @staticmethod
    def test_initialize_xpu_reports_no_devices() -> None:
        """Initialization fails with the no-devices message rather than a torch error."""
        with pytest.raises(RuntimeError, match="No XPU devices are available"):
            initialize_xpu(0)

    @staticmethod
    def test_device_info_is_none_without_device() -> None:
        """Requesting device 0 returns None because no device exists."""
        assert get_xpu_device_info(0) is None


class TestGpuHelpersWithoutHardware:
    """Pure GPU-list helpers driven with real data and nonexistent PnP instances."""

    @staticmethod
    def test_pick_primary_skips_arc_entry_without_pnp_id() -> None:
        """An Arc adapter with no PnP identifier cannot be chosen as primary."""
        assert _call_pick_primary_arc_gpu([_gpu(_ARC_NAME, "", _ARC_DRIVER)]) is None

    @staticmethod
    def test_pick_primary_ignores_arc_whose_device_node_is_absent() -> None:
        """An Arc adapter without any allocated BAR is never reported as primary."""
        gpus = [_gpu(_NVIDIA_NAME, _NVIDIA_PNP, _NVIDIA_DRIVER), _gpu(_ARC_NAME, _ARC_PNP, _ARC_DRIVER)]
        assert _call_pick_primary_arc_gpu(gpus) is None

    @staticmethod
    def test_driver_check_ignores_intel_adapters_that_are_not_arc() -> None:
        """An integrated Intel adapter with a driver does not satisfy the Arc driver requirement."""
        gpus = [_gpu("Intel(R) UHD Graphics 770", "PCI\\VEN_8086&DEV_4688\\3&11583659&0&10", "31.0.101.4502")]
        driver_ok, message = _call_check_intel_driver(gpus)
        assert driver_ok is False
        assert message.startswith(_DRIVER_MISSING_PREFIX)

    @staticmethod
    def test_rebar_check_skips_entries_without_pnp_id() -> None:
        """An Arc adapter with no PnP identifier leaves ReBAR unverifiable."""
        rebar_ok, message = _call_check_rebar_status([_gpu(_ARC_NAME, "", _ARC_DRIVER)])
        assert rebar_ok is False
        assert message.startswith(_REBAR_UNVERIFIED_PREFIX)


@pytest.mark.spawns_process
@pytest.mark.usefixtures("pwsh_unreachable")
class TestWindowsProbeWithPwshUnreachable:
    """The Windows GPU probe when ``pwsh`` cannot be started."""

    @staticmethod
    def test_gpu_info_is_empty_when_probe_cannot_start() -> None:
        """A failed launch is swallowed and reported as an empty GPU list."""
        assert _call_get_windows_gpu_info() == []

    @staticmethod
    def test_enrich_keeps_inputs_when_no_gpu_is_reported() -> None:
        """With no GPUs to learn from, the incoming triple is returned unchanged."""
        assert _call_enrich("", "", "") == ("", "", "")
        assert _call_enrich("Preset", "", "abcd") == ("Preset", "", "abcd")

    @staticmethod
    def test_requirements_report_missing_arc_driver() -> None:
        """Without any GPU the requirement check fails on the driver and says nothing about ReBAR."""
        met, warnings = check_windows_requirements()
        assert met is False
        assert warnings[-1].startswith(_DRIVER_MISSING_PREFIX)
        assert not any("Resizable BAR" in warning for warning in warnings)


@pytest.mark.spawns_process
class TestWindowsProbeWithScriptedPwsh:
    """The Windows GPU probe running a real ``pwsh`` that prints a chosen payload."""

    @staticmethod
    def test_scalar_json_payload_yields_no_gpus(monkeypatch: pytest.MonkeyPatch) -> None:
        """A JSON document that is neither an object nor an array produces no entries.

        Args:
            monkeypatch: Swaps the enumeration script.
        """
        _use_gpu_script(monkeypatch, "Write-Output 5")
        assert _call_query_windows_gpus() == []

    @staticmethod
    def test_enrich_fills_every_blank_from_the_arc_entry(monkeypatch: pytest.MonkeyPatch) -> None:
        """Blank name, driver and id come from the first Arc adapter, skipping the NVIDIA one before it.

        Args:
            monkeypatch: Swaps the enumeration script.
        """
        _use_gpu_script(
            monkeypatch,
            _gpu_json_script((_NVIDIA_NAME, _NVIDIA_PNP, _NVIDIA_DRIVER), (_ARC_NAME, _ARC_PNP, _ARC_DRIVER)),
        )
        assert _call_enrich("", "", "") == (_ARC_NAME, _ARC_DRIVER, _ARC_DEVICE_ID)

    @staticmethod
    def test_enrich_keeps_an_existing_name(monkeypatch: pytest.MonkeyPatch) -> None:
        """A name already known is not overwritten while the blank driver is filled.

        Args:
            monkeypatch: Swaps the enumeration script.
        """
        _use_gpu_script(monkeypatch, _gpu_json_script((_ARC_NAME, _ARC_PNP, _ARC_DRIVER)))
        assert _call_enrich("Custom Adapter", "", "") == ("Custom Adapter", _ARC_DRIVER, _ARC_DEVICE_ID)

    @staticmethod
    def test_enrich_keeps_an_existing_driver(monkeypatch: pytest.MonkeyPatch) -> None:
        """A driver already known is not overwritten while the blank name is filled.

        Args:
            monkeypatch: Swaps the enumeration script.
        """
        _use_gpu_script(monkeypatch, _gpu_json_script((_ARC_NAME, _ARC_PNP, _ARC_DRIVER)))
        assert _call_enrich("", "99.1.2.3", "") == (_ARC_NAME, "99.1.2.3", _ARC_DEVICE_ID)

    @staticmethod
    def test_requirements_flag_unverifiable_rebar(monkeypatch: pytest.MonkeyPatch) -> None:
        """An Arc adapter with a driver but no readable BAR passes the driver check and warns about ReBAR.

        Args:
            monkeypatch: Swaps the enumeration script.
        """
        _use_gpu_script(monkeypatch, _gpu_json_script((_ARC_NAME, _ARC_PNP, _ARC_DRIVER)))
        met, warnings = check_windows_requirements()
        assert met is True
        assert warnings[-1].startswith(_REBAR_UNVERIFIED_PREFIX)
        assert not any(_DRIVER_MISSING_PREFIX in warning for warning in warnings)
