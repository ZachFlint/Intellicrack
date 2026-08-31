# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-backend regression test for CutterBridge ``search_bytes_wildcard``.

This module covers the sibling of defect S15-D05: ``search_bytes_wildcard``
parsed rizin's ``/xj`` wildcard-search JSON hits with the wrong top-level key
(``offset``) instead of the real ``address`` key, so every hit's address
silently collapsed to the ``0`` default even though the hit count was correct.
The fix mirrors the one already applied to the adjacent ``search_bytes``
method.

Exactly like ``test_cutter_rop_project_bytes_s15.py``, these tests drive a
genuine rizin/radare2 backend against a real, on-disk System32 PE binary --
never a mocked or recorded ``rzpipe``/``r2pipe`` response -- so every assertion
is anchored to the actual analysis engine's output. ``where.exe`` (~64KB,
always present on a Windows system) is resolved directly rather than reusing a
larger shared fixture so the wildcard scan completes well within the bridge's
per-command timeout budget.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.cutter import CutterBridge


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = [pytest.mark.spawns_process, pytest.mark.asyncio]

_SMALL_PE_PATH = Path("C:/Windows/System32/where.exe")

_WILDCARD_PATTERN = "48 8b ?? ??"
_ORACLE_DOTTED = "488b...."
_CONCRETE_PREFIX = b"\x48\x8b"
_BYTE_CHECK_SAMPLE = 32


def _resolve_small_pe() -> Path:
    """Resolve a small, real System32 PE binary for a fast wildcard scan.

    Returns:
        Path: Validated path to ``where.exe``.
    """
    if sys.platform != "win32":
        pytest.skip("real PE fixture resolution requires a Windows system")
    if not _SMALL_PE_PATH.is_file():
        pytest.skip(f"required PE fixture not present: {_SMALL_PE_PATH}")
    with _SMALL_PE_PATH.open("rb") as handle:
        magic = handle.read(2)
    if magic != b"MZ":
        pytest.skip(f"fixture {_SMALL_PE_PATH} is not a valid PE binary (magic {magic!r})")
    return _SMALL_PE_PATH


async def _make_bridge_or_skip() -> CutterBridge:
    """Build a bridge whose backend is available, or skip the test.

    Returns:
        CutterBridge: A fresh bridge with a confirmed rizin/radare2 backend.
    """
    bridge = CutterBridge()
    if not await bridge.is_available():
        pytest.skip("rizin/radare2 backend not discoverable on PATH")
    return bridge


@pytest_asyncio.fixture
async def pe_bridge() -> AsyncIterator[CutterBridge]:
    """Load and quick-analyze a small, real System32 PE binary.

    Yields:
        CutterBridge: Bridge with ``where.exe`` loaded and analyzed.
    """
    target = _resolve_small_pe()
    bridge = await _make_bridge_or_skip()
    try:
        await bridge.load_binary(target)
        await bridge.analyze("quick")
        yield bridge
    finally:
        await bridge.shutdown()


class TestSearchBytesWildcardS15D05B:
    """S15-D05 (sibling): wildcard byte-search hits must report real addresses."""

    async def test_wildcard_addresses_are_real_and_match_independent_oracle(
        self,
        pe_bridge: CutterBridge,
    ) -> None:
        """Every wildcard hit is nonzero and equals an independent ``/x`` scan.

        ``search_bytes_wildcard`` consumes rizin's ``/xj`` JSON output; this
        test cross-checks the addresses it returns against a parallel,
        independently-parsed plain-text ``/x`` scan of the identical
        dot-masked pattern. Using the text path -- not the JSON path the
        method itself uses -- means the check is not merely re-validating
        output produced by the same (potentially still-wrong) parser. Under
        the ``offset``-key defect every returned address collapses to ``0``,
        so the nonzero assertion and the set-equality both fail loudly.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
        """
        hits = await pe_bridge.search_bytes_wildcard(_WILDCARD_PATTERN)

        assert hits, f"expected at least one '{_WILDCARD_PATTERN}' wildcard match in where.exe"
        assert all(addr != 0 for addr in hits), "every wildcard hit must report a nonzero address"

        raw_text = await pe_bridge.execute_command(f"/x {_ORACLE_DOTTED}")
        oracle_addresses = {int(line.split()[0], 16) for line in raw_text.splitlines() if line.strip()}

        assert oracle_addresses, "independent plain-text /x oracle found no matches to cross-check against"
        assert set(hits) == oracle_addresses, (
            f"search_bytes_wildcard addresses {sorted(hits)} do not match the independent /x oracle {sorted(oracle_addresses)}"
        )

    async def test_wildcard_hits_point_at_pattern_bytes(self, pe_bridge: CutterBridge) -> None:
        """Each reported hit address genuinely holds the pattern's fixed bytes.

        Reads the raw bytes at each hit address straight from the binary
        image (rizin's ``p8``, an entirely different code path from the
        ``/xj`` search) and confirms they begin with the pattern's two fixed
        leading bytes (``48 8b``). This proves each address names a real
        match location rather than the ``0`` default the ``offset``-key defect
        produced -- reading two bytes at address ``0`` yields the DOS ``MZ``
        magic (``4d 5a``) or no mapped data at all, never ``48 8b``.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
        """
        hits = await pe_bridge.search_bytes_wildcard(_WILDCARD_PATTERN)

        assert hits, f"expected at least one '{_WILDCARD_PATTERN}' wildcard match in where.exe"

        for address in hits[:_BYTE_CHECK_SAMPLE]:
            data = await pe_bridge.read_bytes(address, len(_CONCRETE_PREFIX))
            assert data == _CONCRETE_PREFIX, (
                f"bytes at reported hit {address:#x} are {data!r}, not the pattern's fixed "
                f"prefix {_CONCRETE_PREFIX!r}; the address does not name a real match"
            )
