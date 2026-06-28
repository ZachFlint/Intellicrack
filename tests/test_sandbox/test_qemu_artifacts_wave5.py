# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Real-gate tests for QEMU artifact helpers in qemu.py (Group 06 Wave 5).

Covers:
  S12-05a — ``_parse_ppm_p6`` happy-path and malformed-header error path.
  S12-05b — ``_ppm_p6_to_png`` writes a valid PNG with correct IHDR width/height.
  S12-06  — QEMU PCAP tshark capture (CAPABILITY_SKIP when tshark absent).
  S12-07  — QEMU memory dump (UNTESTABLE: requires running QEMU guest).
  S12-08  — ``_collect_monitoring_logs`` missing-file and None shared-folder paths.
"""
from __future__ import annotations

import asyncio
import shutil
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

import pytest

import intellicrack.sandbox.qemu as _qemu_mod
from intellicrack.sandbox.qemu import QEMUSandbox


_parse_ppm_p6: Callable[[bytes], tuple[int, int, bytes]] = cast(
    Callable[[bytes], tuple[int, int, bytes]],
    getattr(_qemu_mod, "_parse_ppm_p6"),
)
_ppm_p6_to_png: Callable[[Path, Path], None] = cast(
    Callable[[Path, Path], None],
    getattr(_qemu_mod, "_ppm_p6_to_png"),
)
_PNG_SIGNATURE: bytes = cast(bytes, getattr(_qemu_mod, "_PNG_SIGNATURE"))


class _MonitoringLogsProtocol(Protocol):
    """Structural type matching the fields of the private _MonitoringLogs dataclass."""

    file_changes: list[object]
    registry_changes: list[object]
    network_activity: list[object]
    process_activity: list[object]
    api_calls: list[object]
    service_changes: list[object]
    kernel_objects: list[object]
    dll_loads: list[object]
    injection_events: list[object]
    resource_samples: list[object]
    clipboard_events: list[object]


class _TestableQEMUSandbox(QEMUSandbox):
    """QEMUSandbox subclass exposing protected internals for white-box testing."""

    def set_shared_folder(self, path: Path | None) -> None:
        """Set _shared_folder for testing without running QEMU.

        Args:
            path: Shared folder path to inject, or None.
        """
        self._shared_folder = path

    async def collect_monitoring_logs(self) -> _MonitoringLogsProtocol:
        """Expose _collect_monitoring_logs for test assertions.

        Returns:
            _MonitoringLogsProtocol: Aggregate of all parsed monitoring logs.
        """
        return cast(_MonitoringLogsProtocol, await self._collect_monitoring_logs())


def _make_ppm_p6(width: int, height: int, pixels: bytes) -> bytes:
    """Construct a valid PPM P6 binary buffer.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        pixels: Raw RGB pixel data (``width * height * 3`` bytes).

    Returns:
        bytes: Complete PPM P6 binary blob.
    """
    header = f"P6\n{width} {height}\n255\n".encode("ascii")
    return header + pixels


class TestParsePpmP6:
    """Gate for S12-05a: _parse_ppm_p6 extracts width, height, and pixel bytes."""

    def test_minimal_1x1_ppm_parsed_correctly(self) -> None:
        r"""1x1 P6 PPM returns width=1, height=1, pixel=(0xFF, 0x00, 0x80).

        Oracle: PPM P6 format specification — header 'P6\n<W> <H>\n<MAXVAL>\n' followed
        by raw RGB bytes.  Mutation: swapping width/height in the parser swaps the
        returned tuple, failing the equality assertions.
        """
        ppm_data = b"P6\n1 1\n255\n\xff\x00\x80"
        width, height, pixels = _parse_ppm_p6(ppm_data)
        assert width == 1
        assert height == 1
        assert pixels == b"\xff\x00\x80"

    def test_2x2_ppm_parsed_correctly(self) -> None:
        """2x2 P6 PPM returns width=2, height=2, 12 pixel bytes.

        Oracle: 2x2 image needs exactly 2*2*3=12 bytes of pixel data.  Mutation:
        miscounting pixels (e.g. width*height*2 bytes) fails the length assertion.
        """
        pixel_data = bytes(range(12))
        ppm_data = _make_ppm_p6(2, 2, pixel_data)
        width, height, pixels = _parse_ppm_p6(ppm_data)
        assert width == 2
        assert height == 2
        assert len(pixels) == 12
        assert pixels == pixel_data

    def test_invalid_magic_raises_value_error(self) -> None:
        """Invalid PPM magic raises ValueError with a recognisable message.

        Oracle: 'P6' is the mandatory magic bytes for binary PPM; any other value is
        invalid per the format spec.  Mutation: removing the magic check silently
        produces garbage results, not raising ValueError.
        """
        bad_data = b"P3\n1 1\n255\n\xff\x00\x80"
        with pytest.raises(ValueError, match=r"(?i)(invalid|magic|P6)"):
            _parse_ppm_p6(bad_data)

    def test_truncated_pixel_data_raises_value_error(self) -> None:
        """Truncated pixel data raises ValueError.

        Oracle: a 2x2 image needs 12 pixel bytes; providing only 3 is truncation.
        Mutation: allowing short pixel buffers silently returns incomplete data.
        """
        ppm_data = _make_ppm_p6(2, 2, b"\xff\x00\x80")
        with pytest.raises(ValueError, match=r"(?i)(truncat|short|pixel|data)"):
            _parse_ppm_p6(ppm_data)


class TestPpmP6ToPng:
    """Gate for S12-05b: _ppm_p6_to_png writes a valid PNG with correct IHDR."""

    def test_1x1_ppm_produces_valid_png_signature_and_ihdr(self, tmp_path: Path) -> None:
        r"""1x1 PPM converts to PNG with correct 8-byte signature and IHDR W=1, H=1.

        Args:
            tmp_path: Pytest temporary directory.

        The oracle is the PNG specification (ISO 15948:2003 / W3C): the file starts
        with ``\x89PNG\r\n\x1a\n`` and the IHDR chunk stores width and height as
        big-endian uint32 at bytes 16-24.  Mutation: swapping W/H in the IHDR write
        fails the struct.unpack assertions.
        """
        ppm_path = tmp_path / "test.ppm"
        png_path = tmp_path / "output.png"

        ppm_data = b"P6\n1 1\n255\n\xff\x00\x80"
        ppm_path.write_bytes(ppm_data)

        _ppm_p6_to_png(ppm_path, png_path)

        assert png_path.exists(), "PNG output file was not created"
        png_bytes = png_path.read_bytes()

        assert png_bytes[:8] == _PNG_SIGNATURE, (
            f"PNG signature mismatch: {png_bytes[:8]!r} != {_PNG_SIGNATURE!r}"
        )

        width, height = struct.unpack(">II", png_bytes[16:24])
        assert width == 1, f"IHDR width={width}, expected 1"
        assert height == 1, f"IHDR height={height}, expected 1"

    def test_2x2_ppm_produces_png_with_correct_dimensions(self, tmp_path: Path) -> None:
        """2x2 PPM converts to PNG with IHDR W=2, H=2.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: struct.unpack('>II', png_bytes[16:24]) gives (2, 2) per PNG spec.
        Mutation: computing width*3 instead of width in the IHDR pack produces wrong values.
        """
        ppm_path = tmp_path / "test2.ppm"
        png_path = tmp_path / "output2.png"

        pixel_data = bytes(range(12))
        ppm_data = _make_ppm_p6(2, 2, pixel_data)
        ppm_path.write_bytes(ppm_data)

        _ppm_p6_to_png(ppm_path, png_path)

        png_bytes = png_path.read_bytes()
        assert png_bytes[:8] == _PNG_SIGNATURE
        width, height = struct.unpack(">II", png_bytes[16:24])
        assert width == 2
        assert height == 2

    def test_png_signature_constant_value(self) -> None:
        r"""_PNG_SIGNATURE equals the canonical 8-byte PNG magic per the PNG spec.

        Oracle: ISO 15948:2003 / W3C PNG spec section 5.2 specifies
        ``\x89PNG\r\n\x1a\n`` as the PNG file signature.  Mutation: changing any
        byte in _PNG_SIGNATURE breaks this assertion.
        """
        expected: bytes = b"\x89PNG\r\n\x1a\n"
        assert expected == _PNG_SIGNATURE, (
            f"_PNG_SIGNATURE={_PNG_SIGNATURE!r} != PNG spec magic {expected!r}"
        )


class TestCollectMonitoringLogs:
    """Gate for S12-08: _collect_monitoring_logs missing-file and None shared-folder paths."""

    def test_none_shared_folder_returns_empty_collections(self) -> None:
        """_collect_monitoring_logs with shared_folder=None returns all-empty lists.

        Oracle: ``read_log_lines(None, ...)`` returns ``[]`` immediately (the
        ``if shared_folder is None: return []`` guard in ``log_parsers.py``), so
        every parse function returns an empty list, and all ``_MonitoringLogs``
        fields are empty.  Mutation: skipping the None guard and trying to build
        a path from ``None / "logs" / name`` raises ``TypeError`` before returning.
        """
        sandbox = _TestableQEMUSandbox.__new__(_TestableQEMUSandbox)
        sandbox.set_shared_folder(None)

        result = asyncio.run(sandbox.collect_monitoring_logs())

        assert result.file_changes == [], f"file_changes must be empty; got {result.file_changes!r}"
        assert result.network_activity == [], (
            f"network_activity must be empty; got {result.network_activity!r}"
        )
        assert result.registry_changes == [], (
            f"registry_changes must be empty; got {result.registry_changes!r}"
        )
        assert result.process_activity == [], (
            f"process_activity must be empty; got {result.process_activity!r}"
        )
        assert result.api_calls == [], f"api_calls must be empty; got {result.api_calls!r}"
        assert result.dll_loads == [], f"dll_loads must be empty; got {result.dll_loads!r}"
        assert result.injection_events == [], (
            f"injection_events must be empty; got {result.injection_events!r}"
        )
        assert result.resource_samples == [], (
            f"resource_samples must be empty; got {result.resource_samples!r}"
        )

    def test_missing_log_dir_returns_empty_collections(self, tmp_path: Path) -> None:
        """_collect_monitoring_logs with no log files present returns all-empty lists.

        Args:
            tmp_path: Pytest temporary directory with no 'logs' subdirectory.

        Oracle: ``read_log_lines`` returns ``[]`` when the log file does not exist
        (the ``if not log_path.exists(): return []`` guard).  Every collection is
        empty when the shared folder exists but has no log files.  Mutation:
        raising an exception on missing log files would crash before returning.
        """
        sandbox = _TestableQEMUSandbox.__new__(_TestableQEMUSandbox)
        sandbox.set_shared_folder(tmp_path)

        result = asyncio.run(sandbox.collect_monitoring_logs())

        assert result.file_changes == [], f"file_changes must be empty; got {result.file_changes!r}"
        assert result.network_activity == [], (
            f"network_activity must be empty; got {result.network_activity!r}"
        )
        assert result.registry_changes == [], (
            f"registry_changes must be empty; got {result.registry_changes!r}"
        )
        assert result.api_calls == [], f"api_calls must be empty; got {result.api_calls!r}"


@pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark binary not available in this environment",
)
def test_qemu_pcap_capture_skipped_without_live_qemu() -> None:
    """PCAP capture lifecycle (S12-06) requires a live QEMU instance — skipped here.

    This placeholder documents that the gate exists and is capability-skipped when
    tshark is absent.  A real end-to-end PCAP test requires a running QEMU guest VM,
    which is beyond the scope of the CI container.
    """
    pytest.skip("S12-06: QEMU PCAP gate requires a live QEMU guest instance.")
