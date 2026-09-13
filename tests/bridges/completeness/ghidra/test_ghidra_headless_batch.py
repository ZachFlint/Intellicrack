# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""L1/L2 gate tests for ``GhidraBridge.run_headless_batch`` (slice 6, "Headless / Scripting").

``run_headless_batch`` launches a real OS subprocess and never touches the
``ghidra_bridge`` RPC transport, so the package's ``FakeGhidraBridge`` (a
double for that RPC client) is the wrong test double here. Instead these
tests spy on the real ``Popen`` call the production method makes -- the
spy records the exact argv/kwargs it was invoked with, then delegates to
the real ``Popen`` against a harmless short-lived placeholder command
instead of the captured (unrunnable-in-CI) ``pyghidra.ghidra_launch``
command. This keeps every test a genuine subprocess launch (a real OS
process is spawned, waited on, and reaped) while still asserting on the
exact argv the production method constructs.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.subprocess_compat import Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from pathlib import Path


def _make_stub_headless(path: Path) -> Path:
    """Create a tiny platform-appropriate ``analyzeHeadless`` stub.

    The stub exists only so :meth:`GhidraBridge._resolve_headless_executable`
    (a filesystem-existence check run before ``run_headless_batch`` builds
    its command) accepts ``path`` as a real Ghidra installation; the stub
    is never itself executed, since the production command launches
    ``pyghidra.ghidra_launch`` instead of this file.

    Args:
        path: Directory in which to create the ``support`` tree.

    Returns:
        Path: Full path to the stub launcher (``.bat`` on Windows).
    """
    support = path / "support"
    support.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        stub = support / "analyzeHeadless.bat"
        stub.write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    else:
        stub = support / "analyzeHeadless"
        stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)

    return stub


class TestRunHeadlessBatch:
    """L1/L2 gates for ``GhidraBridge.run_headless_batch``."""

    @staticmethod
    def test_command_includes_import_targets_and_prescripts(tmp_path: Path) -> None:
        """The built analyzeHeadless command line must include every target and script.

        Falsifiable: dropping the ``*targets`` unpack, or the per-script
        ``-preScript``/``-postScript`` loop, removes the corresponding
        tokens from the captured argv, failing the containment
        assertions.
        """
        _make_stub_headless(tmp_path)
        bridge = GhidraBridge()
        bridge.ghidra_path = tmp_path

        captured: dict[str, Any] = {}
        real_popen = Popen

        def _spy_popen(
            cmd: list[str],
            *,
            stdout: int | None = None,
            stderr: int | None = None,
            cwd: str | None = None,
            env: dict[str, str] | None = None,
            creationflags: int = 0,
        ) -> Popen[bytes]:
            captured["cmd"] = cmd
            placeholder = [sys.executable, "-c", "import time; time.sleep(1)"]
            return real_popen(
                placeholder,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=env,
                creationflags=creationflags,
            )

        async def _run() -> None:
            try:
                with patch("intellicrack.bridges.ghidra.Popen", _spy_popen):
                    await asyncio.wait_for(
                        bridge.run_headless_batch(
                            tmp_path / "proj",
                            [str(tmp_path / "a.exe"), str(tmp_path / "b.exe")],
                            pre_scripts=[{"name": "Setup.java", "args": ["1"]}],
                            post_scripts=[{"name": "Report.py"}],
                            recursive=True,
                            analysis_timeout_seconds=120,
                        ),
                        timeout=8,
                    )
            except (ToolError, TimeoutError):
                pass

        asyncio.run(_run())

        cmd = cast("list[str]", captured["cmd"])
        assert "-import" in cmd
        assert str(tmp_path / "a.exe") in cmd
        assert str(tmp_path / "b.exe") in cmd
        assert "-preScript" in cmd
        assert "Setup.java" in cmd
        assert "-postScript" in cmd
        assert "Report.py" in cmd
        assert "-recursive" in cmd
        assert "-analysisTimeoutPerFile" in cmd
        assert "120" in cmd

    @staticmethod
    def test_nonzero_exit_raises_tool_error(tmp_path: Path) -> None:
        """A real subprocess that exits non-zero must surface as ToolError, not a silent success.

        Falsifiable: if the ``return_code != 0`` check were removed (or
        inverted), this genuinely-failing real subprocess would not
        raise ``ToolError`` and this test would fail.
        """
        _make_stub_headless(tmp_path)
        bridge = GhidraBridge()
        bridge.ghidra_path = tmp_path

        real_popen = Popen

        def _spy_popen(
            _cmd: list[str],
            *,
            stdout: int | None = None,
            stderr: int | None = None,
            cwd: str | None = None,
            env: dict[str, str] | None = None,
            creationflags: int = 0,
        ) -> Popen[bytes]:
            placeholder = [sys.executable, "-c", "import sys; sys.exit(1)"]
            return real_popen(
                placeholder,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=env,
                creationflags=creationflags,
            )

        async def _run() -> None:
            with patch("intellicrack.bridges.ghidra.Popen", _spy_popen):
                await asyncio.wait_for(
                    bridge.run_headless_batch(tmp_path / "proj", [str(tmp_path / "a.exe")]),
                    timeout=8,
                )

        with pytest.raises(ToolError):
            asyncio.run(_run())
