# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D72: a target that needs a file beside it must get it.

``run_binary`` staged exactly one file. That is not what a real target looks
like - a DLL sits next to the executable, a resource or locale subtree under
it, a config file beside it - and a target staged without those does not fail.
It launches, exits ``0``, and does nothing, which the sandbox reports as a
successful run with an empty report.

The measurement that produced this defect is reproduced here rather than
described. ``ipconfig.exe`` keeps every string it prints in
``en-US\ipconfig.exe.mui`` beside itself, so a copy staged alone runs perfectly
and prints nothing at all. Holding the location fixed and varying only the
sidecar inverts the result completely:

===========  ===========================================  ==================
Step         Layout in the sandbox's ``input``            ``ipconfig /all``
===========  ===========================================  ==================
control      ``ipconfig.exe`` alone                       exit 0, no output
treatment    ``ipconfig.exe`` + ``en-US\ipconfig.exe.mui``  exit 0, real output
===========  ===========================================  ==================

So the assertion is on what the target *does*, not on a directory listing: a
test that only checked the file arrived would still pass if it arrived
somewhere the target never looks.

The staging is the production one. :class:`_StagingSandbox` is the real
:class:`WindowsSandbox` with only ``run_command`` replaced, because Windows
Sandbox needs a virtual machine this container does not have - so the guest is
this machine, and the guest-side path the production code composed is mapped
back onto the share it was composed from. Everything else on the path -
``run_binary``, ``stage_companions``, ``copy_to_sandbox`` - is production code
running unmodified.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import ExecutionReport, SandboxConfig
from intellicrack.sandbox.windows import SandboxError, WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Sequence

    from intellicrack.sandbox.base import SandboxStatus

_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_TARGET_NAME: Final[str] = "ipconfig.exe"
_SIDECAR_DIRECTORY: Final[str] = "en-US"
_SIDECAR_NAME: Final[str] = "ipconfig.exe.mui"

# A string ipconfig can only produce by reading its own resource sidecar, so an
# empty answer and a wrong-file answer are both distinguishable from success.
_OUTPUT_MARKER: Final[str] = "Windows IP Configuration"
_TARGET_ARGUMENTS: Final[list[str]] = ["/all"]

_SUCCESS: Final[int] = 0
_RUNNING: Final[SandboxStatus] = "running"


class _StagingSandbox(WindowsSandbox):
    """The production Windows backend with this machine standing in as its guest."""

    def __init__(self, config: SandboxConfig, share: Path) -> None:
        """Adopt an existing share and present as running, without booting one.

        Args:
            config: Sandbox configuration.
            share: Directory standing in for the sandbox's shared folder.
        """
        super().__init__(config)
        share.mkdir(parents=True, exist_ok=True)
        self._shared_folder = share
        self.state.status = _RUNNING

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Run the command line production composed, against the real share.

        The path in ``command`` was built by ``run_binary`` from
        ``SANDBOX_SHARED_PATH``, which only exists inside a running Windows
        Sandbox. Mapping that same constant back onto the host share is the one
        substitution made here; the command line itself is production's.

        Args:
            command: Command line as ``run_binary`` composed it.
            time_limit: Optional timeout in seconds.
            working_directory: Ignored - the command carries an absolute path.

        Returns:
            tuple[int, str, str]: Exit code, standard output, standard error.

        Raises:
            SandboxError: If the share is not initialised, or the command does
                not finish within ``time_limit``.
        """
        del working_directory
        if self._shared_folder is None:
            msg = "the sandbox share was never created"
            raise SandboxError(msg)

        translated = command.replace(self.SANDBOX_SHARED_PATH, str(self._shared_folder))
        # The interpreter has to receive this line exactly as production wrote
        # it. Passing it as an argument instead would put Python's argv quoting
        # in between, and that renders an embedded quote as backslash-quote,
        # which cmd reads literally - the very confusion S17-D73 was about.
        process = await asyncio.create_subprocess_shell(
            translated,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=time_limit)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            msg = f"the staged target did not exit within {time_limit}s"
            raise SandboxError(msg) from exc

        return (
            process.returncode or 0,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )


async def _run_target(share: Path, companions: Sequence[Path] | None) -> ExecutionReport:
    """Stage the target with ``companions`` and report what it produced.

    Args:
        share: Directory standing in for the sandbox's shared folder.
        companions: Companions to place beside the target, if any.

    Returns:
        ExecutionReport: The report production built for the run.
    """
    sandbox = _StagingSandbox(SandboxConfig(timeout_seconds=120), share)
    return await sandbox.run_binary(
        _SYSTEM32 / _TARGET_NAME,
        _TARGET_ARGUMENTS,
        companions=companions,
        monitor=False,
    )


def _describe(report: ExecutionReport) -> str:
    """Summarise a run for a failure message.

    Args:
        report: Report to describe.

    Returns:
        str: Exit code with both output streams, truncated.
    """
    return f"exit={report.exit_code} stdout={report.stdout[:300]!r} stderr={report.stderr[:300]!r}"


def _assemble_sidecar(tmp_path: Path) -> Path:
    """Assemble the resource directory the target needs, holding only its own file.

    Args:
        tmp_path: Directory to build it under.

    Returns:
        Path: A real ``en-US`` directory carrying the target's resource sidecar.

    Raises:
        AssertionError: If this machine has no such sidecar, which would leave
            the comparison below unable to show anything either way.
    """
    original = _SYSTEM32 / _SIDECAR_DIRECTORY / _SIDECAR_NAME
    if not original.is_file():
        msg = (
            f"{original} is missing, so this machine cannot show the difference a companion makes; "
            f"the measurement, not the fix, is what is unavailable here"
        )
        raise AssertionError(msg)
    directory = tmp_path / "resources" / _SIDECAR_DIRECTORY
    directory.mkdir(parents=True)
    shutil.copy2(original, directory / _SIDECAR_NAME)
    return directory


@pytest.mark.asyncio
class TestCompanionFilesReachTheTarget:
    """A target must be able to run the way it runs on a real machine."""

    async def test_the_target_says_nothing_when_staged_alone(self, tmp_path: Path) -> None:
        """The control: this is what a one-file staging really produces.

        Without it the treatment below proves nothing - a target that printed
        its output either way would make the companion irrelevant and the gate
        unfalsifiable.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        report = await _run_target(tmp_path / "alone", companions=None)

        assert report.exit_code == _SUCCESS, f"the staged target failed outright: {_describe(report)}"
        assert _OUTPUT_MARKER not in report.stdout, (
            f"staged alone the target still produced its output ({_describe(report)}), so this machine "
            f"cannot demonstrate S17-D72 and the companion test below would pass for the wrong reason"
        )

    async def test_a_companion_directory_makes_the_target_speak(self, tmp_path: Path) -> None:
        """The treatment: same target, same place, its resources beside it.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        report = await _run_target(tmp_path / "accompanied", companions=[_assemble_sidecar(tmp_path)])

        assert report.exit_code == _SUCCESS, f"the staged target failed outright: {_describe(report)}"
        assert _OUTPUT_MARKER in report.stdout, (
            f"the target produced {_describe(report)} with its resource directory staged beside it; "
            f"the companion never reached the place the target looks (S17-D72)"
        )

    async def test_the_companion_lands_beside_the_target_not_somewhere_else(self, tmp_path: Path) -> None:
        """The tree under a companion directory must arrive whole.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "layout"
        await _run_target(share, companions=[_assemble_sidecar(tmp_path)])

        staged = share / "input" / _SIDECAR_DIRECTORY / _SIDECAR_NAME
        assert staged.is_file(), f"{staged} was never written; the companion's tree was flattened or dropped"
        assert staged.read_bytes() == (_SYSTEM32 / _SIDECAR_DIRECTORY / _SIDECAR_NAME).read_bytes(), (
            "the staged companion is not the file that was asked for"
        )

    async def test_a_companion_that_does_not_exist_stops_the_run(self, tmp_path: Path) -> None:
        """A companion that cannot be placed must fail loudly, not silently.

        Running anyway is the false green this defect is a member of: the
        target would launch, exit ``0``, and report success over an analysis
        of a program that was never assembled.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        missing = tmp_path / "no-such-companion.dll"

        with pytest.raises(SandboxError):
            await _run_target(tmp_path / "incomplete", companions=[missing])

    async def test_a_companion_may_not_overwrite_the_target(self, tmp_path: Path) -> None:
        """A companion sharing the target's name must be refused, not staged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        impostor = tmp_path / "impostor" / _TARGET_NAME
        impostor.parent.mkdir(parents=True)
        impostor.write_bytes(b"not the target")

        with pytest.raises(SandboxError):
            await _run_target(tmp_path / "shadowed", companions=[impostor])
