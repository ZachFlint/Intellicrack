# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-backend regression tests for CutterBridge defects S15-D03/D04/D05.

These tests drive a genuine rizin/radare2 backend against a real, on-disk
System32 PE binary -- never a mocked or recorded ``rzpipe``/``r2pipe``
response -- so every assertion is anchored to the actual analysis engine's
output, matching the idiom established by ``test_realcov_03c_cutter.py`` and
``test_realcov_03d_cutter_decompile_cfg.py``.

The three defects covered:

* S15-D03: ``search_rop_gadgets`` returned every hit with ``address == 0``
  and an empty ``instructions`` string because it read rizin's ``/Rj``
  response using the wrong top-level keys (``addr``/``opcodes`` treated as
  a flat string) instead of the real nested ``opcodes`` instruction-object
  array.
* S15-D04: ``save_project`` reported success unconditionally while
  ``list_projects`` always returned an empty list -- rizin 0.9.1 has no
  ``Pl`` project-listing command at all, and its ``Ps`` command does not
  consult ``dir.projects`` to resolve a bare project name.
* S15-D05: ``search_bytes`` returned a correct hit count with every address
  reported as ``0`` because rizin's ``/xj`` byte-search hits are keyed
  ``address``, not ``offset``.

``search_rop_gadgets`` against a real PE is CPU-bound (a full-binary gadget
scan) and the bridge enforces a 5-second per-command timeout
(``R2_COMMAND_TIMEOUT``). Direct measurement against the real backend showed
kernel32.dll -- the binary the shared ``real_pe_dll`` session fixture
resolves -- and even the much smaller notepad.exe (~360KB) both exceed that
budget for a filtered ``/Rj`` scan. ``where.exe`` (~64KB, always present on a
Windows system) completes the same scan in well under a second, so this
module resolves its own small PE fixture rather than reusing ``real_pe_dll``.
"""

from __future__ import annotations

import asyncio
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


def _resolve_small_pe() -> Path:
    """Resolve a small, real System32 PE binary for fast ROP gadget scans.

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


class TestSearchRopGadgetsS15D03:
    """S15-D03: ROP gadget search must report a real address and instructions."""

    async def test_gadget_address_and_instructions_are_real(self, pe_bridge: CutterBridge) -> None:
        """A known-present gadget reports a nonzero address and real instructions.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
        """
        gadgets = await pe_bridge.search_rop_gadgets("pop rdi")

        assert gadgets, "expected at least one 'pop rdi' gadget in where.exe"
        assert all(gadget.address != 0 for gadget in gadgets), "every gadget address must be nonzero"
        assert all(gadget.instructions for gadget in gadgets), "every gadget must carry a non-empty instruction string"
        assert all("pop" in gadget.instructions for gadget in gadgets), "every gadget must actually contain the filtered mnemonic"
        assert all(gadget.size > 0 for gadget in gadgets)

    async def test_gadget_address_matches_first_instruction(self, pe_bridge: CutterBridge) -> None:
        """The reported address is independently confirmed by disassembling at it.

        Disassembling the exact address ``search_rop_gadgets`` reports for a
        gadget must yield that gadget's own first mnemonic (``pop``), proving
        the address genuinely names the gadget's entry instruction rather
        than a default-zero or otherwise unrelated value.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
        """
        gadgets = await pe_bridge.search_rop_gadgets("pop rdi")
        assert gadgets
        gadget = gadgets[0]

        lines = await pe_bridge.disassemble(gadget.address, 1)

        assert lines
        assert lines[0].address == gadget.address
        assert lines[0].mnemonic.lower() == "pop"


class TestSearchBytesS15D05:
    """S15-D05: byte search hits must report their real match address."""

    async def test_search_bytes_addresses_are_real(self, pe_bridge: CutterBridge) -> None:
        """Every ``search_bytes`` hit reports a nonzero, independently-confirmed address.

        Cross-checks every address returned by ``search_bytes`` against a
        parallel, independently-parsed plain-text ``/x`` scan -- not the
        ``/xj`` JSON path ``search_bytes`` itself uses -- so the check is not
        merely re-validating output produced by the same (potentially
        still-wrong) parser.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
        """
        hits = await pe_bridge.search_bytes("48 8b 05")

        assert hits, "expected at least one '48 8b 05' byte match in where.exe"
        assert all(addr != 0 for addr in hits), "every search_bytes hit must report a nonzero address"

        raw_text = await pe_bridge.execute_command("/x 488b05")
        oracle_addresses = {int(line.split()[0], 16) for line in raw_text.splitlines() if line.strip()}

        assert oracle_addresses, "independent plain-text /x oracle found no matches to cross-check against"
        assert set(hits) == oracle_addresses, (
            f"search_bytes addresses {sorted(hits)} do not match the independent /x oracle {sorted(oracle_addresses)}"
        )


class TestProjectRoundTripS15D04:
    """S15-D04: a saved project must actually be discoverable by list_projects."""

    async def test_save_then_list_round_trips(self, pe_bridge: CutterBridge, tmp_path: Path) -> None:
        """A project saved under a ``tmp_path`` projects directory is listed back.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
            tmp_path: Pytest-managed per-test temporary directory used as the
                rizin ``dir.projects`` storage location.
        """
        await pe_bridge.set_config("dir.projects", str(tmp_path))
        project_name = "s15_d04_roundtrip"

        saved = await pe_bridge.save_project(project_name)
        saved_files = await asyncio.to_thread(lambda: list(tmp_path.glob("*.rzdb")))

        assert saved is True
        assert saved_files, f"save_project reported success but wrote no .rzdb file under {tmp_path}"

        projects = await pe_bridge.list_projects()

        assert project_name in projects, (
            f"list_projects() {projects} does not contain the just-saved project {project_name!r}; "
            "save_project's reported success was not real (false success)"
        )

    async def test_list_projects_reflects_empty_storage(self, pe_bridge: CutterBridge, tmp_path: Path) -> None:
        """A freshly provisioned, empty projects directory lists no projects.

        Falsifies a naive fix that always returns a canned nonempty list
        instead of genuinely reflecting the storage directory's contents.

        Args:
            pe_bridge: Analyzed ``where.exe`` bridge.
            tmp_path: Pytest-managed per-test temporary directory used as the
                rizin ``dir.projects`` storage location.
        """
        await pe_bridge.set_config("dir.projects", str(tmp_path))

        projects = await pe_bridge.list_projects()

        assert projects == []
