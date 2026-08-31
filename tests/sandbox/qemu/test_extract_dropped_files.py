# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0007: ``QEMUSandbox.extract_dropped_files``.

The audit7 fix introduces two requirements:

1. **Allowlist-safe agent dispatch.** When the guest agent is connected, the
   sandbox must wrap the platform-specific copy command in an allowed shell
   (``cmd.exe /c "..."`` on Windows, ``/bin/bash -c "..."`` on Linux) instead
   of sending a bare ``xcopy`` / ``cp -r``. Bare commands are rejected by the
   Windows agent's ``Test-AllowedCommand`` allowlist and yield no files.
2. **Host-side fallback.** When the agent is disconnected, the sandbox must
   collect files from ``<shared>/output/dropped/`` (the guest watcher's
   continuous mirror) host-side via ``shutil.copy2``.

When both paths produce zero files, the call must raise ``SandboxError`` rather
than returning an empty zip and a misleading success.

Both requirements belong to the virtio-9p transport, which is what carries the
share wherever QEMU supports it. S17-D69 made the FAT transport - every Windows
host, and every Windows guest - expose the share read-only, because vvfat's
write-back path aborts the whole machine. A guest that cannot write to the share
cannot mirror anything host-visible into it, so on that transport there is no
host-side fallback to reach for and the gathered tree comes back over the guest
agent's file commands instead. The tests below therefore run the 9p transport on
a POSIX host, which is the configuration those two requirements describe, and
pin the FAT transport separately to the contract it really has.
"""

from __future__ import annotations

import asyncio
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


_ALLOWED_NAMES: frozenset[str] = frozenset({"powershell", "powershell.exe", "cmd", "cmd.exe"})
_ALLOWED_ROOTS_WIN: tuple[str, ...] = ("z:\\", "c:\\windows\\system32\\", "c:\\windows\\syswow64\\")
_ALLOWED_POSIX_SHELLS: frozenset[str] = frozenset({"/bin/bash", "/bin/sh"})
_HOST_PLATFORM_FLAG: str = "_IS_WINDOWS"
_GUEST_WORK_ROOT_WINDOWS: str = "C:\\intellicrack"
# The watcher's own mirror is gathered alongside the watched roots, so a file
# the sample created and then deleted is still collected.
_GATHERED_MIRRORS: int = 1


@pytest.fixture
def posix_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the sandbox as if the host were POSIX, so 9p carries the share.

    ``_uses_fat_shared_transport`` reads the module-level platform constant on
    every call, so redirecting it selects the transport under test without
    touching any behaviour: virtio-9p is compiled out of QEMU's Windows builds,
    which is the only reason a Windows host takes the FAT path at all.

    Args:
        monkeypatch: Fixture used to redirect the platform constant.
    """
    monkeypatch.setattr(qemu_module, _HOST_PLATFORM_FLAG, False)


def _is_windows_allowlisted(command: str) -> bool:
    """Replicate the Windows guest agent ``Test-AllowedCommand`` decision.

    Args:
        command: Executable name or absolute path sent to the agent.

    Returns:
        bool: ``True`` if the command would be accepted by the in-guest
            PowerShell allowlist.
    """
    if not command:
        return False
    lowered = command.lower()
    if lowered in _ALLOWED_NAMES:
        return True
    if not lowered.endswith(".exe"):
        return False
    return any(lowered.startswith(root) for root in _ALLOWED_ROOTS_WIN)


class _TestQEMUSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing test-only state setters.

    The setters keep ``basedpyright``'s ``reportPrivateUsage`` rule satisfied
    by performing private-attribute mutation from inside the class hierarchy.
    """

    def set_accelerator(self, accel: AcceleratorType) -> None:
        """Pre-populate the accelerator cache so no real detection runs.

        Args:
            accel: Accelerator type to record as cached.
        """
        self._accelerator = accel
        self._accelerator_cached = True

    def set_shared_folder(self, path: Path | None) -> None:
        """Override the shared folder path for tests.

        Args:
            path: Shared folder location, or ``None`` to clear.
        """
        self._shared_folder = path

    def set_agent(self, agent: GuestAgentClient | None) -> None:
        """Override the guest agent client.

        Args:
            agent: Agent instance, or ``None`` to disable the agent path.
        """
        self._agent = agent

    def drop_watch_roots(self) -> list[str]:
        """Return the guest directories the real implementation gathers from.

        Returns:
            list[str]: Absolute in-guest directories for the configured guest.
        """
        return self._drop_watch_roots()


class _RecordingAgent(GuestAgentClient):
    """``GuestAgentClient`` subclass that records every ``send_command`` call.

    The agent also simulates the in-guest copy by writing a sentinel file into
    the wrapped command's host-visible destination, so that the surrounding
    ``extract_dropped_files`` call can complete and produce a real zip after a
    successful agent-path dispatch.

    Attributes:
        sent_commands: Ordered list of ``(command, args)`` tuples observed.
        simulate_dest_root: Host-side directory under which the simulated guest
            destinations are interpreted. The agent writes a real file into the
            host-visible mapping of each inner command's destination.
        guest_share_prefix: Guest-side prefix that the agent rewrites to
            ``simulate_dest_root`` when mirroring guest-visible destinations to
            host paths.
        sentinel_payload: Bytes written into each simulated drop file.
    """

    sent_commands: list[tuple[str, list[str]]]
    simulate_dest_root: Path | None
    guest_share_prefix: str
    sentinel_payload: bytes

    def __init__(
        self,
        *,
        connected: bool,
        simulate_dest_root: Path | None = None,
        guest_share_prefix: str = "",
        sentinel_payload: bytes = b"sentinel",
    ) -> None:
        """Initialise without performing any network I/O.

        Args:
            connected: Initial connection state.
            simulate_dest_root: Host-side root to which a guest-side prefix
                resolves; required if ``connected`` is ``True`` and the test
                expects the agent path to populate the staging directory.
            guest_share_prefix: Guest-visible prefix replaced by
                ``simulate_dest_root``.
            sentinel_payload: Bytes written into each simulated dropped file.
        """
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = connected
        self.sent_commands = []
        self.simulate_dest_root = simulate_dest_root
        self.guest_share_prefix = guest_share_prefix
        self.sentinel_payload = sentinel_payload

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Record the dispatched command and emulate a successful in-guest copy.

        Args:
            command: Executable name or absolute path supplied by the caller.
            args: Argument list (recorded as a fresh list copy).
            time_limit: Time limit forwarded by the caller; ignored.

        Returns:
            tuple[int, str, str]: ``(0, "", "")`` indicating success.
        """
        del time_limit
        recorded_args = list(args or [])
        self.sent_commands.append((command, recorded_args))
        self._simulate_drop(recorded_args)
        return (0, "", "")

    def _simulate_drop(self, args: list[str]) -> None:
        """Write a sentinel file into the host-mapped destination of ``args``.

        The inner shell payload is the last element of ``args`` (after ``/c``
        or ``-c``). We parse the destination from that payload, rewrite the
        guest-visible prefix to ``simulate_dest_root``, and write a sentinel
        file there so the staging directory is non-empty after dispatch.

        Args:
            args: Wrapped argument list as observed by the agent.
        """
        if self.simulate_dest_root is None or not args:
            return
        inner = args[-1]
        dest_guest = _extract_destination(inner)
        if dest_guest is None:
            return
        host_dest = _guest_to_host(
            dest_guest,
            guest_prefix=self.guest_share_prefix,
            host_root=self.simulate_dest_root,
        )
        if host_dest is None:
            return
        host_dest.mkdir(parents=True, exist_ok=True)
        (host_dest / "agent_sentinel.bin").write_bytes(self.sentinel_payload)


def _extract_destination(inner_command: str) -> str | None:
    """Return the quoted destination path from an ``xcopy``/``cp`` payload.

    Args:
        inner_command: The ``args[-1]`` payload of the wrapped command.

    Returns:
        str | None: The destination path with surrounding quotes stripped, or
            ``None`` if no quoted destination is present.
    """
    quote = '"'
    parts = inner_command.split(quote)
    quoted = [p for p in parts[1::2] if p]
    return None if len(quoted) < 2 else quoted[1]


def _guest_to_host(
    guest_path: str,
    *,
    guest_prefix: str,
    host_root: Path,
) -> Path | None:
    """Translate a guest-visible share path to its host-side equivalent.

    Args:
        guest_path: Path observed from the guest's perspective.
        guest_prefix: Guest-side prefix replaced by ``host_root``.
        host_root: Host-side root that owns the share.

    Returns:
        Path | None: Host-side path with the prefix rewritten, or ``None`` if
            ``guest_path`` does not begin with ``guest_prefix``.
    """
    if not guest_prefix:
        return None
    if not guest_path.startswith(guest_prefix):
        return None
    suffix = guest_path[len(guest_prefix) :].lstrip("\\/")
    suffix_norm = suffix.replace("\\", "/")
    return host_root.joinpath(*suffix_norm.split("/"))


def _make_sandbox(
    *,
    guest_os: GuestOS,
    shared_folder: Path,
) -> _TestQEMUSandbox:
    """Build a sandbox instance wired up for ``extract_dropped_files``.

    Args:
        guest_os: Guest operating system to configure.
        shared_folder: Shared folder to use as the host-side staging root.

    Returns:
        _TestQEMUSandbox: Configured sandbox in the ``running`` state.
    """
    cfg = QEMUConfig(guest_os=guest_os)
    sb = _TestQEMUSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(AcceleratorType.TCG)
    sb.set_shared_folder(shared_folder)
    sb.state.status = "running"
    return sb


def _run(coro: object) -> object:
    """Synchronously execute ``coro`` via a fresh event loop.

    Args:
        coro: Awaitable to execute.

    Returns:
        object: The coroutine's return value.

    Raises:
        TypeError: If ``coro`` is not a coroutine.
    """
    if not asyncio.iscoroutine(coro):
        msg = "expected a coroutine"
        raise TypeError(msg)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestScenarioAAgentPathWraps:
    """Scenario A: agent path must wrap copy in an allowlisted shell."""

    def test_windows_agent_path_uses_cmd_exe_wrapper(self, tmp_path: Path) -> None:
        """On Windows the agent must receive ``cmd.exe`` plus a ``/c`` arg.

        Both the executable name and the wrapped invocation must pass the
        ``Test-AllowedCommand`` allowlist; bare ``xcopy`` would be rejected.

        A Windows guest is always on the FAT transport, so the gather runs
        against the guest's own work root rather than the share, and the copy
        the guest performs is invisible to the host until it is pulled back
        over the guest agent's file commands. With no such channel open the
        call must fail rather than hand back an archive built from a share the
        guest has not been able to write to since S17-D69.

        Args:
            tmp_path: Pytest temp directory used as the shared folder.
        """
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)
        stale_mirror = shared / "output" / "dropped"
        stale_mirror.mkdir(parents=True)
        (stale_mirror / "stale_from_the_share.bin").write_bytes(b"\x00\x01")

        agent = _RecordingAgent(
            connected=True,
            simulate_dest_root=shared,
            guest_share_prefix=QEMUSandbox.GUEST_SHARED_PATH_WINDOWS,
        )
        sb = _make_sandbox(guest_os=GuestOS.WINDOWS, shared_folder=shared)
        sb.set_agent(agent)

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        with pytest.raises(SandboxError):
            _run(_go())

        assert agent.sent_commands, "agent path must dispatch at least one command"
        for command, args in agent.sent_commands:
            assert command == "cmd.exe", f"agent command must be cmd.exe; got {command!r}"
            assert _is_windows_allowlisted(command), f"{command!r} must pass the in-guest allowlist"
            assert len(args) == 2, f"expected /c + inner_cmd; got {args!r}"
            assert args[0] == "/c", f"first arg must be /c; got {args[0]!r}"

        payloads = [args[1] for _command, args in agent.sent_commands]
        gathers = [payload for payload in payloads if "xcopy" in payload]
        expected_gathers = len(sb.drop_watch_roots()) + _GATHERED_MIRRORS
        assert len(gathers) == expected_gathers, f"every watched root plus the guest's own mirror must be gathered; got {payloads!r}"
        for payload in gathers:
            assert "/S /E /Y /I" in payload, f"inner command must use xcopy flags; got {payload!r}"
            destination = _extract_destination(payload)
            assert destination is not None, f"the gather must name a destination; got {payload!r}"
            assert destination.startswith(_GUEST_WORK_ROOT_WINDOWS), (
                f"the guest must gather onto its own disk, not the read-only share: {destination!r} (S17-D69)"
            )

        listings = [payload for payload in payloads if payload.startswith("dir ")]
        assert listings, f"the gathered tree must be read back out of the guest, not off the share: {payloads!r}"
        assert all(f'"{_GUEST_WORK_ROOT_WINDOWS}\\output\\dropped_' in payload for payload in listings), (
            f"the pull must list the guest's own work root: {listings!r} (S17-D69)"
        )

        produced = list(tmp_path.rglob("*.zip"))
        assert not produced, f"no archive may be built from a share the guest cannot write to: {produced}"

    def test_linux_agent_path_uses_bash_wrapper(self, posix_host: None, tmp_path: Path) -> None:
        """On Linux the agent must receive ``/bin/bash`` plus a ``-c`` arg.

        Args:
            posix_host: Fixture selecting the virtio-9p transport.
            tmp_path: Pytest temp directory used as the shared folder.
        """
        del posix_host
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)

        agent = _RecordingAgent(
            connected=True,
            simulate_dest_root=shared,
            guest_share_prefix=QEMUSandbox.GUEST_SHARED_PATH_LINUX,
        )
        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.set_agent(agent)

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        result = _run(_go())
        assert isinstance(result, Path)
        assert result.exists()

        assert agent.sent_commands, "agent path must dispatch at least one command"
        for command, args in agent.sent_commands:
            assert command in _ALLOWED_POSIX_SHELLS, f"agent command must be a POSIX shell; got {command!r}"
            assert command == "/bin/bash", f"agent command must be /bin/bash; got {command!r}"
            assert len(args) == 2, f"expected -c + inner_cmd; got {args!r}"
            assert args[0] == "-c", f"first arg must be -c; got {args[0]!r}"
            assert "cp -r" in args[1], f"inner command must invoke cp -r; got {args[1]!r}"

        with zipfile.ZipFile(result) as zf:
            assert any("agent_sentinel.bin" in n for n in zf.namelist()), "agent-path dispatch must populate the staging directory"


class TestScenarioBHostFallback:
    """Scenario B: when the agent is absent the host-side fallback collects files."""

    def test_host_fallback_collects_real_files(self, posix_host: None, tmp_path: Path) -> None:
        """Files mirrored under ``output/dropped`` end up in the produced zip.

        Args:
            posix_host: Fixture selecting the virtio-9p transport, the only one
                whose share the guest can mirror into.
            tmp_path: Pytest temp directory used as the shared folder.
        """
        del posix_host
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)

        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        (mirror / "alpha.bin").write_bytes(b"\x01\x02\x03")
        nested = mirror / "subdir"
        nested.mkdir()
        (nested / "beta.txt").write_text("dropped-file-content", encoding="utf-8")

        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.set_agent(None)

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        result = _run(_go())
        assert isinstance(result, Path)
        assert result.exists(), "host fallback must produce a real zip on disk"
        assert result.suffix == ".zip"
        assert zipfile.is_zipfile(result)

        with zipfile.ZipFile(result) as zf:
            names = sorted(zf.namelist())
            alpha_payload = zf.read("alpha.bin")
            beta_payload = zf.read("subdir/beta.txt")

        assert "alpha.bin" in names, f"expected alpha.bin in zip; got {names}"
        assert any(n.endswith("beta.txt") for n in names), f"expected beta.txt in zip; got {names}"
        assert alpha_payload == b"\x01\x02\x03"
        assert beta_payload == b"dropped-file-content"

    def test_output_path_redirect_with_host_fallback(self, posix_host: None, tmp_path: Path) -> None:
        """``output_path`` argument must receive a copy of the host-collected zip.

        Args:
            posix_host: Fixture selecting the virtio-9p transport.
            tmp_path: Pytest temp directory used for both the shared folder and
                the redirect destination.
        """
        del posix_host
        shared = tmp_path / "shared"
        (shared / "output").mkdir(parents=True)
        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        (mirror / "gamma.bin").write_bytes(b"\xff")

        destination = tmp_path / "out" / "result.zip"

        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.set_agent(None)

        async def _go() -> Path:
            return await sb.extract_dropped_files(output_path=destination)

        result = _run(_go())
        assert result == destination
        assert destination.exists()
        assert zipfile.is_zipfile(destination)
        with zipfile.ZipFile(destination) as zf:
            assert any(n.endswith("gamma.bin") for n in zf.namelist())


class TestScenarioCEmptyFailure:
    """Scenario C: missing agent + empty mirror must raise instead of silently succeed."""

    def test_empty_extraction_raises_sandbox_error(self, posix_host: None, tmp_path: Path) -> None:
        """Both paths producing zero files must raise ``SandboxError``.

        Args:
            posix_host: Fixture selecting the virtio-9p transport.
            tmp_path: Pytest temp directory used as the shared folder.
        """
        del posix_host
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)

        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.set_agent(None)

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        with pytest.raises(SandboxError):
            _run(_go())

        leftover = list((shared / "output").glob("dropped_*"))
        assert not leftover, f"empty staging dirs must be cleaned up; found {leftover}"

    def test_disconnected_agent_falls_back_to_host(self, posix_host: None, tmp_path: Path) -> None:
        """An agent reporting ``is_connected == False`` must trigger host fallback.

        Args:
            posix_host: Fixture selecting the virtio-9p transport.
            tmp_path: Pytest temp directory used as the shared folder.
        """
        del posix_host
        shared = tmp_path / "shared"
        (shared / "output").mkdir(parents=True)
        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        (mirror / "delta.bin").write_bytes(b"\x42")

        agent = _RecordingAgent(connected=False)
        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.set_agent(agent)

        async def _go() -> Path:
            return await sb.extract_dropped_files()

        result = _run(_go())
        assert isinstance(result, Path)
        assert agent.sent_commands == [], "no commands must be sent when agent is disconnected"
        with zipfile.ZipFile(result) as zf:
            assert any(n.endswith("delta.bin") for n in zf.namelist())
