# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D05: "Test Sandbox" must not pass on a host that cannot start one.

``SandboxTestWorker`` used to treat process liveness as success::

    try:
        self._process.wait(timeout=10)
    except TimeoutExpired:
        self.output.emit("Sandbox is running normally")
        return False  # -> caller emits SUCCESS
    return self._handle_sandbox_exit_status()  # rc == 0 -> SUCCESS

Both branches reported success. ``WindowsSandbox.exe`` is fire-and-forget and
exits ``0`` within a second of handing off, so the ``rc == 0`` path is taken on
every run -- including runs where the session then fails to come up. And a
launch that fails with ``0x800706d9`` leaves a process alive on a modal dialog,
so the ``TimeoutExpired`` path is exactly the broken-host state too.

That is why wave 6H recorded H-09 "Sandbox test passed!" alongside H-01 Create
failing ``0x800706d9`` on the same host: the probe was structurally incapable of
detecting that failure, and the contradiction was read as host flakiness rather
than as a bug for two audit waves.

Success is now defined as a real session host process existing for this
configuration, with no failure dialog on screen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import intellicrack.ui.sandbox_config as sandbox_config_mod
from intellicrack.ui.sandbox_config import SandboxTestWorker


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest

    from intellicrack.core.subprocess_compat import Popen


_RPC_DIALOG_TEXT = (
    "Windows Sandbox\nThe connection to the sandbox could not be initialized.\n"
    "Error 0x800706d9. There are no more endpoints available from the endpoint mapper."
)


class _ExitedProcess:
    """Stand-in for the fire-and-forget launcher after it has exited 0."""

    def __init__(self, pid: int = 5150) -> None:
        """Initialise the stand-in.

        Args:
            pid: Reported process id.
        """
        self.pid = pid
        self.returncode = 0
        self.stderr = None

    def poll(self) -> int:
        """Report the launcher's exit status.

        Returns:
            int: Always ``0`` -- a clean, expected launcher exit.
        """
        return 0


def _worker(tmp_path: Path) -> SandboxTestWorker:
    """Build a test worker with a launched-and-exited launcher.

    Args:
        tmp_path: Pytest temporary directory for the ``.wsb`` file.

    Returns:
        SandboxTestWorker: Worker positioned at the verification step.
    """
    worker = SandboxTestWorker(network_enabled=False, memory_limit_mb=2048)
    wsb = tmp_path / "sandbox-test.wsb"
    wsb.write_text("<Configuration></Configuration>", encoding="utf-8")
    setattr(worker, "_wsb_file", wsb)
    setattr(worker, "_process", cast("Popen[bytes]", _ExitedProcess()))
    return worker


def _run_verify(worker: SandboxTestWorker) -> bool:
    """Invoke the protected session-verification step.

    Args:
        worker: Worker under test.

    Returns:
        bool: True when the worker reported the outcome itself (a failure).
    """
    verify = cast("Callable[[], bool]", getattr(worker, "_verify_sandbox_session"))
    return verify()


def _recorder(sink: list[tuple[bool, str]]) -> Callable[..., None]:
    """Build a ``finished`` slot that records what the worker reported.

    Args:
        sink: List that receives each ``(success, message)`` emission.

    Returns:
        Callable[..., None]: Slot suitable for ``finished.connect``.
    """

    def _slot(*args: object) -> None:
        success, message = args
        sink.append((bool(success), str(message)))

    return _slot


def _no_session(_name: str) -> int | None:
    """Session lookup reporting that no sandbox session exists.

    Args:
        _name: Ignored configuration filename.

    Returns:
        int | None: Always None.
    """
    return None


def _session_present(_name: str) -> int | None:
    """Session lookup reporting a running sandbox session.

    Args:
        _name: Ignored configuration filename.

    Returns:
        int | None: A representative session PID.
    """
    return 19428


def _no_dialog(_pid: int) -> str | None:
    """Dialog detector reporting no failure dialog.

    Args:
        _pid: Ignored PID.

    Returns:
        str | None: Always None.
    """
    return None


def _rpc_dialog(_pid: int) -> str | None:
    """Dialog detector reporting the 0x800706d9 failure dialog.

    Args:
        _pid: Ignored PID.

    Returns:
        str | None: The captured endpoint-mapper dialog text.
    """
    return _RPC_DIALOG_TEXT


class TestTestSandboxVerifiesRealSession:
    """The probe must distinguish a started sandbox from a failed one."""

    def test_clean_launcher_exit_without_a_session_is_reported_as_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """rc==0 with no session must fail, not pass.

        This is the exact shape of a broken host: the launcher hands off and
        exits 0, but no session ever appears. The old implementation returned
        success here.

        Args:
            tmp_path: Temporary directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_TIMEOUT", 2.0)
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_POLL_INTERVAL", 0.1)
        monkeypatch.setattr(sandbox_config_mod, "find_sandbox_session_pid", _no_session)
        monkeypatch.setattr(
            sandbox_config_mod.WindowsSandbox,
            "detect_failure_dialog",
            staticmethod(_no_dialog),
        )

        worker = _worker(tmp_path)
        results: list[tuple[bool, str]] = []
        worker.finished.connect(_recorder(results))

        handled = _run_verify(worker)

        assert handled is True, "verification must own the outcome when no session starts"
        assert results, "a result must be reported"
        success, message = results[0]
        assert success is False, f"a launch that produced no session must FAIL; got success with {message!r}"
        assert "did not start" in message

    def test_failure_dialog_is_reported_with_its_text(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 0x800706d9 dialog fails the test and surfaces the real error.

        Args:
            tmp_path: Temporary directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_TIMEOUT", 5.0)
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_POLL_INTERVAL", 0.1)
        monkeypatch.setattr(sandbox_config_mod, "find_sandbox_session_pid", _no_session)
        monkeypatch.setattr(
            sandbox_config_mod.WindowsSandbox,
            "detect_failure_dialog",
            staticmethod(_rpc_dialog),
        )

        worker = _worker(tmp_path)
        results: list[tuple[bool, str]] = []
        worker.finished.connect(_recorder(results))

        handled = _run_verify(worker)

        assert handled is True
        success, message = results[0]
        assert success is False, "a sandbox showing its failure dialog must FAIL the test"
        assert "0x800706d9" in message, f"the real error must reach the user; got {message!r}"

    def test_a_real_session_passes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A session host process for this config is the success condition.

        Args:
            tmp_path: Temporary directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_TIMEOUT", 5.0)
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_POLL_INTERVAL", 0.1)
        monkeypatch.setattr(sandbox_config_mod, "find_sandbox_session_pid", _session_present)
        monkeypatch.setattr(
            sandbox_config_mod.WindowsSandbox,
            "detect_failure_dialog",
            staticmethod(_no_dialog),
        )

        worker = _worker(tmp_path)
        results: list[tuple[bool, str]] = []
        worker.finished.connect(_recorder(results))

        handled = _run_verify(worker)

        assert handled is False, "a confirmed session must defer to the caller's success path"
        assert not results, "verification must not emit its own result on success"

    def test_session_lookup_matches_this_configuration(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The session is looked up by this instance's own .wsb filename.

        A sandbox started by someone else must not make this probe pass.

        Args:
            tmp_path: Temporary directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_TIMEOUT", 2.0)
        monkeypatch.setattr(sandbox_config_mod, "_TEST_VERIFY_POLL_INTERVAL", 0.1)
        seen: list[str] = []

        def _record(name: str) -> int | None:
            seen.append(name)
            return None

        monkeypatch.setattr(sandbox_config_mod, "find_sandbox_session_pid", _record)
        monkeypatch.setattr(
            sandbox_config_mod.WindowsSandbox,
            "detect_failure_dialog",
            staticmethod(_no_dialog),
        )

        worker = _worker(tmp_path)
        worker.finished.connect(_recorder([]))
        _run_verify(worker)

        assert seen, "the session lookup must actually run"
        assert all(name == "sandbox-test.wsb" for name in seen), f"lookup must key on this instance's config; saw {seen!r}"
