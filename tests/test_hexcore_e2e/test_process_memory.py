# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument process memory access (Windows-only)."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types


_WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Process memory API is Windows-only",
)

_MEM_COMMIT = 0x1000
_PAGE_NOACCESS = 0x01
_PAGE_GUARD = 0x100
_READABLE_PROTECTIONS = frozenset({0x02, 0x04, 0x08, 0x20, 0x40, 0x80})


def _find_readable_region(
    regions: list[tuple[int, int, int, int]],
    min_size: int,
) -> tuple[int, int, int, int] | None:
    """Return the first committed, readable memory region of sufficient size.

    A region is readable only when its state is ``MEM_COMMIT`` and its page
    protection is one of the read-capable constants without the ``PAGE_GUARD``
    or ``PAGE_NOACCESS`` flags. Selecting on ``protection != 0`` alone is not
    sufficient because ``PAGE_NOACCESS`` and guard pages are non-zero yet are
    rejected by ``ReadProcessMemory``.

    Args:
        regions: Region tuples ``(base_address, size, protection, state)`` as
            returned by ``list_process_memory_regions``.
        min_size: Minimum region size in bytes required.

    Returns:
        tuple[int, int, int, int] | None: The first matching region tuple, or
        ``None`` when no readable region of the requested size exists.
    """
    for region in regions:
        _address, size, protection, state = region
        if size < min_size or state != _MEM_COMMIT:
            continue
        if protection & (_PAGE_GUARD | _PAGE_NOACCESS):
            continue
        base_protection = protection & 0xFF
        if base_protection in _READABLE_PROTECTIONS:
            return region
    return None


@_WIN32_ONLY
class TestListProcessMemoryRegions:
    """Tests covering list_process_memory_regions() against the current process."""

    def test_list_regions_returns_list(self, hexcore: types.ModuleType) -> None:
        """Verify that list_process_memory_regions returns a list for the current PID.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)
        assert isinstance(regions, list)

    def test_list_regions_nonempty_for_current_process(self, hexcore: types.ModuleType) -> None:
        """Verify that at least one memory region exists in the current process.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)
        assert regions

    def test_list_regions_each_entry_has_four_elements(self, hexcore: types.ModuleType) -> None:
        """Verify that every region tuple has exactly 4 integer elements.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)
        for region in regions:
            assert isinstance(region, tuple)
            assert len(region) == 4
            addr_val: int
            size_val: int
            prot_val: int
            rtype_val: int
            addr_val, size_val, prot_val, rtype_val = region
            assert isinstance(addr_val, int)
            assert isinstance(size_val, int)
            assert isinstance(prot_val, int)
            assert isinstance(rtype_val, int)

    def test_list_regions_all_sizes_positive(self, hexcore: types.ModuleType) -> None:
        """Verify that all reported memory region sizes are greater than zero.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)
        for address, size, _protection, _region_type in regions:
            assert size > 0
            assert address >= 0

    def test_list_regions_invalid_pid_raises(self, hexcore: types.ModuleType) -> None:
        """Verify that list_process_memory_regions raises an exception for an invalid PID.

        Args:
            hexcore: The native module fixture.
        """
        with pytest.raises((OSError, RuntimeError, PermissionError)):
            hexcore.HexDocument.list_process_memory_regions(0x7FFFFFFF)


@_WIN32_ONLY
class TestFromProcessMemory:
    """Tests covering from_process_memory() read operations on the current process."""

    def test_read_from_current_process_first_region(self, hexcore: types.ModuleType) -> None:
        """Verify that from_process_memory can read bytes from a readable region.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)
        assert regions

        readable_region = _find_readable_region(regions, 16)
        if readable_region is None:
            pytest.skip("No suitable readable memory region found in current process")

        addr, _size, _prot, _state = readable_region
        doc = hexcore.HexDocument.from_process_memory(pid, addr, 16)
        assert doc is not None
        assert doc.length() == 16

    def test_from_process_memory_returns_hex_document(self, hexcore: types.ModuleType) -> None:
        """Verify that from_process_memory returns an object with HexDocument methods.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)

        accessible = _find_readable_region(regions, 8)
        if accessible is None:
            pytest.skip("No accessible memory region found for read test")

        addr, _sz, _pr, _state = accessible
        doc = hexcore.HexDocument.from_process_memory(pid, addr, 8)
        assert hasattr(doc, "length")
        assert hasattr(doc, "read")
        assert doc.length() == 8

    def test_from_process_memory_invalid_pid_raises(self, hexcore: types.ModuleType) -> None:
        """Verify that from_process_memory raises an exception for a nonexistent PID.

        Args:
            hexcore: The native module fixture.
        """
        with pytest.raises((OSError, RuntimeError, PermissionError)):
            hexcore.HexDocument.from_process_memory(0x7FFFFFFF, 0x1000, 16)

    def test_from_process_memory_zero_size_handled(self, hexcore: types.ModuleType) -> None:
        """Verify that from_process_memory with size=0 raises or returns an empty document.

        Args:
            hexcore: The native module fixture.
        """
        pid = os.getpid()
        regions: list[tuple[int, int, int, int]] = hexcore.HexDocument.list_process_memory_regions(pid)

        accessible: tuple[int, int, int, int] | None = None
        for region in regions:
            _address, size, protection, _region_type = region
            if size > 0 and protection != 0:
                accessible = region
                break

        if accessible is None:
            pytest.skip("No accessible region found for zero-size test")

        addr, _sz, _pr, _rt = accessible
        raised = False
        doc = None
        try:
            doc = hexcore.HexDocument.from_process_memory(pid, addr, 0)
        except OSError:
            raised = True
        if not raised:
            assert doc is not None
            assert doc.length() == 0
