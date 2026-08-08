# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D60 on the Windows backend: nothing scanned is not "clean".

``WindowsSandbox.yara_scan`` carried the same three-way ambiguity the QEMU
backend did - see ``tests/sandbox/qemu/test_yara_scan_outcome_s17d60.py`` for
the full account. An empty list meant "the rules matched nothing", "no memory
dump existed to scan", or "the scan target was a typo and the wrong thing was
scanned", and the GUI reports all three as "no threats found".

Both backends now share one set of scan targets, one artifact selector and one
set of messages, so these gates check the Windows implementation answers the
same way over a real shared folder and real files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


_INJECTOR_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 16 + b"CreateRemoteThread\x00VirtualAllocEx\x00"
_PACKED_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 64 + b"UPX!" + b"\x00" * 32


class _ScanSandbox(WindowsSandbox):
    """``WindowsSandbox`` bound to a real shared folder, with no guest running.

    ``yara_scan`` reads the host side of the shared folder and never launches
    or talks to a sandbox, so the production method is reached without a VM.
    """

    def bind_shared_folder(self, shared_folder: Path) -> None:
        """Point the sandbox at a real shared folder on disk.

        Args:
            shared_folder: Directory standing in for the guest's share.
        """
        self._shared_folder = shared_folder


def _make_sandbox(shared_folder: Path) -> _ScanSandbox:
    """Build a sandbox whose shared folder is a real directory with an output dir.

    Args:
        shared_folder: Directory standing in for the guest's share.

    Returns:
        _ScanSandbox: A sandbox ready to scan.
    """
    (shared_folder / "output").mkdir(parents=True, exist_ok=True)
    sandbox = _ScanSandbox(SandboxConfig())
    sandbox.bind_shared_folder(shared_folder)
    return sandbox


class TestTheWindowsScanReportsWhatItReallyScanned:
    """An empty match list must mean "scanned and clean", never "never scanned"."""

    @pytest.mark.asyncio
    async def test_a_file_scan_with_no_collected_artifacts_is_raised_not_returned(self, tmp_path: Path) -> None:
        """With an empty output directory the scan must fail loudly.

        Args:
            tmp_path: Pytest temporary directory.
        """
        sandbox = _make_sandbox(tmp_path / "share")

        with pytest.raises(SandboxError, match="no collected artifacts to scan"):
            await sandbox.yara_scan()

    @pytest.mark.asyncio
    async def test_a_memory_scan_with_no_dump_is_raised_not_returned(self, tmp_path: Path) -> None:
        """Scanning memory that was never dumped must fail loudly.

        Args:
            tmp_path: Pytest temporary directory.
        """
        sandbox = _make_sandbox(tmp_path / "share")

        with pytest.raises(SandboxError, match="no guest memory dump to scan"):
            await sandbox.yara_scan(scan_target="memory")

    @pytest.mark.asyncio
    async def test_an_unknown_scan_target_is_rejected(self, tmp_path: Path) -> None:
        """A target that is neither files nor memory must not silently scan files.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        sandbox = _make_sandbox(shared)
        (shared / "output" / "collected.bin").write_bytes(_INJECTOR_ARTIFACT)

        with pytest.raises(SandboxError, match="unknown scan target"):
            await sandbox.yara_scan(scan_target="registry")

    @pytest.mark.asyncio
    async def test_a_collected_file_outside_an_archive_is_scanned(self, tmp_path: Path) -> None:
        """A guest artifact in the output directory must produce its match.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        sandbox = _make_sandbox(shared)
        artifact = shared / "output" / "collected.bin"
        artifact.write_bytes(_INJECTOR_ARTIFACT)

        matches = await sandbox.yara_scan()

        assert {match["rule"] for match in matches} == {"SuspiciousStrings"}
        assert {match["source"] for match in matches} == {str(artifact)}

    @pytest.mark.asyncio
    async def test_a_real_memory_dump_is_scanned_and_labelled_as_memory(self, tmp_path: Path) -> None:
        """A dump on disk must be scanned, and its matches marked as memory.

        The Windows backend writes ``.dmp`` dumps, so this also pins that the
        shared artifact selector does not hand a memory dump to the file scan.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        sandbox = _make_sandbox(shared)
        (shared / "output" / "memdump_a1b2c3d4.dmp").write_bytes(_PACKED_ARTIFACT)

        matches = await sandbox.yara_scan(scan_target="memory")

        assert {match["rule"] for match in matches} == {"PackedBinary"}
        assert {match["scan_type"] for match in matches} == {"memory"}

        with pytest.raises(SandboxError, match="no collected artifacts to scan"):
            await sandbox.yara_scan()
