# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real integration tests for the local-process sandbox backend.

Audit shard 11 flagged the sandbox suite for validating only against the
in-memory mock (:class:`InMemorySandbox`), which returns fabricated execution
reports and therefore cannot catch a regression in real process execution or
artefact capture. These tests drive a genuine binary -- the running Python
interpreter executing a deterministic script -- through the real
:class:`~tests.sandbox.conftest.LocalProcessSandbox`, and assert on values
that are independently known (the exact bytes the script writes, the exact
string it prints, the exact exit code it returns), not on anything the sandbox
itself fabricates.

Tests carry ``spawns_process`` because they launch real OS subprocesses and so
run inside the Docker harness that owns that capability.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxError


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from tests.sandbox.conftest import LocalProcessSandbox


pytestmark = [pytest.mark.integration, pytest.mark.spawns_process]


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive a sandbox coroutine to completion on the fixture's event loop.

    Args:
        coro: The coroutine to execute.

    Returns:
        T: The coroutine result.
    """
    return asyncio.get_event_loop().run_until_complete(coro)


def _write_script(workdir: Path, *, filename: str, payload: bytes, message: str, exit_code: int) -> Path:
    """Write a deterministic Python script into ``workdir``.

    The script writes ``payload`` to ``filename`` inside its current directory,
    prints ``message`` to stdout, and exits with ``exit_code``. The caller knows
    every one of these outcomes independently, so they form a trusted oracle.

    Args:
        workdir: Directory the script is written into.
        filename: Name of the artefact the script creates at run time.
        payload: Exact bytes the script writes to the artefact.
        message: Exact text the script prints to stdout (no trailing newline).
        exit_code: Process exit code the script returns.

    Returns:
        Path: Path to the generated script outside the sandbox workdir.
    """
    script = workdir / "driver.py"
    source = f"import sys\ndata = {payload!r}\nopen({filename!r}, 'wb').write(data)\nsys.stdout.write({message!r})\nsys.exit({exit_code})\n"
    script.write_text(source, encoding="utf-8")
    return script


class TestLocalProcessSandboxRealExecution:
    """Validate that the real sandbox executes and captures genuine behaviour."""

    def test_run_binary_captures_real_output_and_artifact(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """A real run reports the exact exit code, stdout, and observed artefact.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        payload = b"INTELLICRACK-REAL-SANDBOX-ARTIFACT-\x00\x01\x02\xff"
        script = _write_script(
            tmp_path,
            filename="dropped.bin",
            payload=payload,
            message="run-ok",
            exit_code=0,
        )

        report = _run(
            local_process_sandbox.run_binary(Path(sys.executable), args=[str(script)], time_limit=60),
        )

        assert report.result == "success"
        assert report.exit_code == 0
        assert report.stdout == "run-ok"
        assert len(report.stderr) == 0
        assert report.duration_seconds > 0.0

        created = [c for c in report.file_changes if c["operation"] == "created"]
        dropped = [c for c in created if c["path"] == "dropped.bin"]
        assert len(dropped) == 1, f"expected exactly one created dropped.bin, got {report.file_changes}"
        assert dropped[0]["size"] == len(payload)

        on_disk = local_process_sandbox.workdir / "dropped.bin"
        assert on_disk.read_bytes() == payload
        assert hashlib.sha256(on_disk.read_bytes()).hexdigest() == hashlib.sha256(payload).hexdigest()

    def test_run_binary_nonzero_exit_is_reported_as_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """A non-zero process exit is surfaced with the exact code and error result.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        script = _write_script(
            tmp_path,
            filename="ignored.bin",
            payload=b"x",
            message="failing-run",
            exit_code=7,
        )

        report = _run(
            local_process_sandbox.run_binary(Path(sys.executable), args=[str(script)], time_limit=60),
        )

        assert report.result == "error"
        assert report.exit_code == 7
        assert report.stdout == "failing-run"

    def test_run_binary_timeout_raises_sandbox_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """A process exceeding the time limit raises ``SandboxError``.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        script = tmp_path / "sleeper.py"
        script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")

        with pytest.raises(SandboxError, match="timed out"):
            _run(
                local_process_sandbox.run_binary(Path(sys.executable), args=[str(script)], time_limit=1),
            )

    def test_run_command_returns_real_exit_and_stdout(
        self,
        local_process_sandbox: LocalProcessSandbox,
    ) -> None:
        """A real shell command returns its genuine exit code and stdout.

        Args:
            local_process_sandbox: Started real sandbox fixture.
        """
        marker = "sandbox-cmd-marker-1357"
        command = f'"{sys.executable}" -c "import sys; sys.stdout.write({marker!r})"'

        exit_code, stdout, stderr = _run(
            local_process_sandbox.run_command(command, time_limit=60),
        )

        assert exit_code == 0
        assert stdout == marker
        assert len(stderr) == 0

    def test_copy_roundtrip_preserves_exact_bytes(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """copy_to/copy_from preserve the exact byte content of a real file.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory.
        """
        original = tmp_path / "input.dat"
        content = bytes(range(256)) * 8
        original.write_bytes(content)

        _run(local_process_sandbox.copy_to_sandbox(original, "input.dat"))
        retrieved = tmp_path / "retrieved.dat"
        _run(local_process_sandbox.copy_from_sandbox("input.dat", retrieved))

        assert retrieved.read_bytes() == content

    def test_copy_from_missing_file_raises_sandbox_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """Exporting a file that does not exist raises ``SandboxError``.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory.
        """
        with pytest.raises(SandboxError, match="not found in sandbox"):
            _run(
                local_process_sandbox.copy_from_sandbox("does_not_exist.bin", tmp_path / "out.bin"),
            )

    def test_snapshot_restore_recovers_exact_state(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """Restoring a snapshot recovers the exact work-directory contents.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory.
        """
        baseline = tmp_path / "base.dat"
        baseline_bytes = b"baseline-state-v1"
        baseline.write_bytes(baseline_bytes)
        _run(local_process_sandbox.copy_to_sandbox(baseline, "base.dat"))

        snapshot_id = _run(local_process_sandbox.take_snapshot("clean"))
        assert snapshot_id == "snap-clean"

        mutation = tmp_path / "mut.dat"
        mutation.write_bytes(b"post-snapshot-mutation")
        _run(local_process_sandbox.copy_to_sandbox(mutation, "mut.dat"))
        assert (local_process_sandbox.workdir / "mut.dat").exists()

        _run(local_process_sandbox.restore_snapshot(snapshot_id))

        assert (local_process_sandbox.workdir / "base.dat").read_bytes() == baseline_bytes
        assert not (local_process_sandbox.workdir / "mut.dat").exists()

    def test_restore_unknown_snapshot_raises_sandbox_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
    ) -> None:
        """Restoring an unknown snapshot id raises ``SandboxError``.

        Args:
            local_process_sandbox: Started real sandbox fixture.
        """
        with pytest.raises(SandboxError, match="Snapshot not found"):
            _run(local_process_sandbox.restore_snapshot("snap-nope"))
