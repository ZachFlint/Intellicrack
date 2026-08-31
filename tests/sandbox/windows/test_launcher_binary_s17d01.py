# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D01..D04: Windows Sandbox launcher selection and startup health.

Intellicrack launched ``WindowsSandboxClient.exe``, which on current Windows
builds is only the *connection client*: started on its own it cannot create a
session and fails with ``0x800706d9`` (``EPT_S_NOT_REGISTERED``).
``WindowsSandbox.exe`` is the launcher that creates a session.

Verified on Windows 11 build 26220 from a fully clean process state (nothing
sandbox-related running):

* ``WindowsSandboxClient.exe minimal.wsb`` exited ``-2147023143`` (``0x800706d9``)
  and created no VM and no window.
* ``WindowsSandbox.exe minimal.wsb`` exited ``0`` immediately after spawning
  ``WindowsSandboxRemoteSession.exe`` -- which receives the ``.wsb`` path on its
  own command line -- which in turn spawned ``WindowsSandboxServer.exe`` and a
  ``vmmemWindowsSandbox`` VM with a live rendering window.

That behaviour drives four regressions gated here:

* **S17-D01** the launcher must be the session-creating binary.
* **S17-D02** the launcher exits ``0`` by design, so a clean exit must not be
  reported as a crashed client.
* **S17-D03** the ``0x800706d9`` guidance must name the real causes rather than
  sending users to reboot the host, which is what stalled two audit waves.
* **S17-D04** from a clean state the failure arrives as an *exit code*, not a
  dialog, so the exit code must map to the same actionable message.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest

import intellicrack.sandbox.windows as win_mod
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from intellicrack.core.subprocess_compat import Popen


_ERR_LAUNCH_RPC_ENDPOINT = cast("str", getattr(win_mod, "_ERR_LAUNCH_RPC_ENDPOINT"))
_RPC_EXIT_CODE = cast("int", getattr(win_mod, "_SANDBOX_RPC_ENDPOINT_EXIT_CODE"))


class _LauncherProbe(WindowsSandbox):
    """WindowsSandbox exposing launcher resolution.

    The preference ordering under test is the real implementation; only the
    ``PATH`` lookup is substituted, per instance, by :func:`_with_path`.
    """

    async def resolve_launcher(self) -> str | None:
        """Invoke the protected launcher resolver.

        Returns:
            str | None: Resolved launcher filename.
        """
        return await self._resolve_launcher_exe()


def _with_path(available: set[str]) -> _LauncherProbe:
    """Build a probe whose PATH lookup reports the given executables.

    Args:
        available: Executable names to report as present on ``PATH``.

    Returns:
        _LauncherProbe: Probe with its PATH lookup shadowed on the instance.
    """
    sandbox = _LauncherProbe(SandboxConfig(timeout_seconds=5))

    async def _fake_on_path(exe: str) -> bool:
        await asyncio.sleep(0)
        return exe in available

    setattr(sandbox, "_exe_on_path", _fake_on_path)
    return sandbox


class _HealthSandbox(WindowsSandbox):
    """WindowsSandbox exposing the startup-health check without a real dialog scan."""

    async def run_startup_health(self) -> None:
        """Invoke the protected startup-health check."""
        await self._check_startup_health()

    def bind_session(self, pid: int | None) -> None:
        """Set the resolved session PID.

        Args:
            pid: Session PID to record, or None for "no session yet".
        """
        self._session_pid = pid


def _no_dialog(_pid: int) -> str | None:
    """Dialog detector reporting no failure dialog.

    Args:
        _pid: Ignored PID.

    Returns:
        str | None: Always None.
    """
    return None


def _fake_process(*, poll_result: int | None, pid: int = 4321) -> Popen[bytes]:
    """Create a stand-in launcher process with a chosen exit status.

    Args:
        poll_result: Value returned by ``poll()`` (None means still running).
        pid: Reported process id.

    Returns:
        Popen[bytes]: Object shaped like the launcher process.
    """
    proc = MagicMock()
    proc.poll.return_value = poll_result
    proc.returncode = poll_result
    proc.pid = pid
    return cast("Popen[bytes]", proc)


def _health_sandbox(poll_result: int | None, *, session_pid: int | None = None) -> _HealthSandbox:
    """Build a health-probe sandbox with a launcher in a chosen exit state.

    Args:
        poll_result: Launcher ``poll()`` result to simulate.
        session_pid: Session PID to record as already bound.

    Returns:
        _HealthSandbox: Configured probe with dialog detection neutralised.
    """
    sandbox = _HealthSandbox(SandboxConfig(timeout_seconds=5))
    sandbox.process = _fake_process(poll_result=poll_result)
    sandbox.bind_session(session_pid)
    setattr(sandbox, "_detect_client_failure_dialog", staticmethod(_no_dialog))
    return sandbox


class TestLauncherSelection:
    """S17-D01: the session-creating launcher must win."""

    def test_prefers_session_creating_launcher_when_both_present(self) -> None:
        """WindowsSandbox.exe is chosen when both binaries are on PATH.

        This is the regression: the client-only binary fails 0x800706d9 from a
        clean state, so preferring it makes every create fail.
        """
        sandbox = _with_path({"WindowsSandbox.exe", "WindowsSandboxClient.exe"})
        resolved = asyncio.run(sandbox.resolve_launcher())
        assert resolved == "WindowsSandbox.exe", (
            f"expected the session-creating launcher, got {resolved!r}; "
            "WindowsSandboxClient.exe cannot create a session and exits 0x800706d9"
        )

    def test_falls_back_to_client_when_launcher_absent(self) -> None:
        """Older builds without WindowsSandbox.exe still resolve the client."""
        sandbox = _with_path({"WindowsSandboxClient.exe"})
        assert asyncio.run(sandbox.resolve_launcher()) == "WindowsSandboxClient.exe"

    def test_returns_none_when_neither_present(self) -> None:
        """No launcher on PATH resolves to None rather than a bogus name."""
        sandbox = _with_path(set())
        assert asyncio.run(sandbox.resolve_launcher()) is None


class TestExeOnPathIsReal:
    """The PATH probe must genuinely consult the OS, not always answer True."""

    def test_detects_a_real_executable_and_rejects_a_missing_one(self) -> None:
        """``where`` resolves cmd.exe and rejects a name that cannot exist.

        Without this, the selection tests above could pass against a probe that
        answers True unconditionally.
        """
        probe = cast(
            "Callable[[str], Coroutine[object, object, bool]]",
            getattr(WindowsSandbox, "_exe_on_path"),
        )
        found = asyncio.run(probe("cmd.exe"))
        missing = asyncio.run(probe("intellicrack-no-such-binary.exe"))
        assert found is True, "where cmd.exe should resolve on a Windows host"
        assert missing is False, "a nonexistent executable must not resolve"


class TestStartupHealth:
    """S17-D02/D04: launcher exit handling."""

    def test_clean_launcher_exit_is_not_a_failure(self) -> None:
        """A launcher exiting 0 with a bound session must not raise.

        WindowsSandbox.exe is fire-and-forget: it exits 0 as soon as it has
        handed off to the session host. Treating that as a crash aborts every
        successful launch.
        """
        sandbox = _health_sandbox(0, session_pid=19428)
        asyncio.run(sandbox.run_startup_health())

    def test_nonzero_launcher_exit_raises(self) -> None:
        """A genuine non-zero launcher exit is still reported."""
        sandbox = _health_sandbox(3)
        with pytest.raises(SandboxError, match="launcher exit code 3"):
            asyncio.run(sandbox.run_startup_health())

    def test_rpc_endpoint_exit_code_maps_to_actionable_message(self) -> None:
        """Exit code 0x800706d9 yields the actionable message, not a bare code.

        From a clean process state the failure arrives as an exit code rather
        than a dialog, so without this mapping the user saw only
        "client exit code -2147023143".
        """
        sandbox = _health_sandbox(_RPC_EXIT_CODE)
        with pytest.raises(SandboxError) as excinfo:
            asyncio.run(sandbox.run_startup_health())
        message = str(excinfo.value)
        assert message == _ERR_LAUNCH_RPC_ENDPOINT
        assert str(_RPC_EXIT_CODE) not in message, "the raw exit code is not actionable on its own"

    def test_rpc_exit_code_constant_matches_the_hresult(self) -> None:
        """The mapped exit code is 0x800706d9 as a signed 32-bit value."""
        assert _RPC_EXIT_CODE == 0x800706D9 - (1 << 32)


class TestRpcGuidance:
    """S17-D03: the guidance must point at the real cause."""

    def test_guidance_names_single_instance_and_launcher_causes(self) -> None:
        """The message names the two real causes before any host-state advice.

        The previous text asserted this was "a host-side Hyper-V / Host Compute
        Service state problem" and told the user to reboot -- which was false on
        a host where WindowsSandbox.exe starts a VM fine, and caused two audit
        waves to be abandoned as host-blocked.
        """
        text = _ERR_LAUNCH_RPC_ENDPOINT
        lowered = text.lower()
        assert "only one at a time" in lowered
        assert "windowssandbox.exe" in lowered
        assert "windowssandboxclient.exe" in lowered
        reboot_index = lowered.find("reboot")
        assert reboot_index == -1, "rebooting is not the remedy and must not be advised"

    def test_guidance_does_not_claim_host_state_unconditionally(self) -> None:
        """Host state is qualified as a last resort, not the stated cause."""
        lowered = _ERR_LAUNCH_RPC_ENDPOINT.lower()
        assert "only if neither applies" in lowered
