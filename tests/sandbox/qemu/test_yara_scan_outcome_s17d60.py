# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D60: a YARA scan that scanned nothing must not report "clean".

``QEMUSandbox.yara_scan`` returned an empty list in three different situations
that a caller cannot tell apart:

* the rules ran over real artifacts and matched nothing - a clean result;
* ``scan_target="files"`` with no ``dropped_files_*.zip`` in the output
  directory, where the file list was hard-coded to ``[]`` and nothing was ever
  opened, even though the guest's collected artifacts were sitting in that same
  directory;
* ``scan_target="memory"`` with no ``memdump_*.raw``, where the loop had no
  iterations at all.

An unknown ``scan_target`` was a fourth: any string other than ``"memory"``
silently fell into the files branch, so a typo scanned the wrong thing and
still reported success.

That matters because the empty list is what the GUI shows as "no threats
found". A scan that never reached the guest's artifacts looked exactly like a
guest that was clean.

These gates run the real ``yara-python`` compiler over real files on disk. The
artifacts are genuine byte content written into a genuine shared-folder output
directory, and the matches come back from the real rule engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


_PACKED_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 64 + b"UPX!" + b"\x00" * 32
_INJECTOR_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 16 + b"CreateRemoteThread\x00VirtualAllocEx\x00"
_BENIGN_ARTIFACT: Final[bytes] = b"MZ\x90\x00" + b"\x00" * 128 + b"this artifact holds nothing the rules look for\x00"


class _ScanSandbox(QEMUSandbox):
    """``QEMUSandbox`` bound to a real shared folder, with no guest attached.

    ``yara_scan`` reads the host side of the shared folder and never touches the
    monitor, so the production method under test is reached without booting a
    machine. The scanning itself is the unmodified implementation.
    """

    def bind_shared_folder(self, shared_folder: Path) -> None:
        """Point the sandbox at a real shared folder on disk.

        Args:
            shared_folder: Directory standing in for the guest's share.
        """
        self._shared_folder = shared_folder


def _make_sandbox(shared_folder: Path) -> _ScanSandbox:
    """Build a sandbox whose shared folder is a real directory.

    Args:
        shared_folder: Directory standing in for the guest's share.

    Returns:
        _ScanSandbox: A sandbox ready to scan.
    """
    config = QEMUConfig(guest_os=GuestOS.LINUX)
    sandbox = _ScanSandbox(config=SandboxConfig(), qemu_config=config)
    sandbox.bind_shared_folder(shared_folder)
    return sandbox


def _output_dir(shared_folder: Path) -> Path:
    """Create and return the output directory the backend scans.

    Args:
        shared_folder: Directory standing in for the guest's share.

    Returns:
        Path: The created output directory.
    """
    output_dir = shared_folder / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


class TestAScanThatFoundNothingMustHaveScannedSomething:
    """An empty match list must mean "scanned and clean", never "never scanned"."""

    @pytest.mark.asyncio
    async def test_a_file_scan_with_no_collected_artifacts_is_raised_not_returned(self, tmp_path: Path) -> None:
        """With an empty output directory the scan must fail loudly.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        _output_dir(shared)
        sandbox = _make_sandbox(shared)

        with pytest.raises(SandboxError, match="no collected artifacts to scan"):
            await sandbox.yara_scan()

    @pytest.mark.asyncio
    async def test_a_memory_scan_with_no_dump_is_raised_not_returned(self, tmp_path: Path) -> None:
        """Scanning memory that was never dumped must fail loudly.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        _output_dir(shared)
        sandbox = _make_sandbox(shared)

        with pytest.raises(SandboxError, match="no guest memory dump to scan"):
            await sandbox.yara_scan(scan_target="memory")

    @pytest.mark.asyncio
    async def test_an_unknown_scan_target_is_rejected(self, tmp_path: Path) -> None:
        """A target that is neither files nor memory must not silently scan files.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        (_output_dir(shared) / "collected.bin").write_bytes(_INJECTOR_ARTIFACT)
        sandbox = _make_sandbox(shared)

        with pytest.raises(SandboxError, match="unknown scan target"):
            await sandbox.yara_scan(scan_target="registry")


class TestAScanReadsTheArtifactsTheGuestReallyLeft:
    """Artifacts outside a dropped-file archive must still be scanned."""

    @pytest.mark.asyncio
    async def test_a_collected_file_outside_an_archive_is_scanned(self, tmp_path: Path) -> None:
        """A guest artifact sitting in the output directory must produce its match.

        This is the false-green at its sharpest: the file is right there, the
        rules match its bytes, and the scan used to report nothing because no
        zip archive happened to exist beside it.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        artifact = _output_dir(shared) / "collected.bin"
        artifact.write_bytes(_INJECTOR_ARTIFACT)
        sandbox = _make_sandbox(shared)

        matches = await sandbox.yara_scan()

        rules = {match["rule"] for match in matches}
        assert "SuspiciousStrings" in rules, f"the rules did not reach a real artifact on disk: {matches}"
        sources = {match["source"] for match in matches}
        assert str(artifact) in sources, f"the match does not name the artifact it came from: {sources}"

    @pytest.mark.asyncio
    async def test_monitor_transcripts_are_not_mistaken_for_guest_artifacts(self, tmp_path: Path) -> None:
        """A directory holding only the sandbox's own logs has nothing to scan.

        The monitor transcripts are Intellicrack's output, not the guest's, so
        their presence must not turn "nothing was collected" into a clean scan.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        output_dir = _output_dir(shared)
        (output_dir / "monitor.log").write_text("process started\n", encoding="utf-8")
        (output_dir / "report.txt").write_text("no events\n", encoding="utf-8")
        sandbox = _make_sandbox(shared)

        with pytest.raises(SandboxError, match="no collected artifacts to scan"):
            await sandbox.yara_scan()

    @pytest.mark.asyncio
    async def test_a_real_memory_dump_is_scanned_and_labelled_as_memory(self, tmp_path: Path) -> None:
        """A dump on disk must be scanned, and its matches marked as memory.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        dump = _output_dir(shared) / "memdump_a1b2c3d4.raw"
        dump.write_bytes(_PACKED_ARTIFACT)
        sandbox = _make_sandbox(shared)

        matches = await sandbox.yara_scan(scan_target="memory")

        assert matches, "a real dump carrying rule content produced no matches"
        assert {match["rule"] for match in matches} == {"PackedBinary"}
        assert {match["scan_type"] for match in matches} == {"memory"}

    @pytest.mark.asyncio
    async def test_a_scanned_clean_artifact_still_reports_no_matches(self, tmp_path: Path) -> None:
        """A real scan of a real artifact that matches nothing must return empty.

        Without this the fix could satisfy every other gate by raising
        unconditionally, and a clean guest would become an error.

        Args:
            tmp_path: Pytest temporary directory.
        """
        shared = tmp_path / "share"
        (_output_dir(shared) / "collected.bin").write_bytes(_BENIGN_ARTIFACT)
        sandbox = _make_sandbox(shared)

        assert await sandbox.yara_scan() == []
