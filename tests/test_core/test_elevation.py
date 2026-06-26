# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for Intellicrack Windows UAC self-elevation.

Tests validate:
- Platform and elevation detection helpers
- Relaunch command construction for interpreter and frozen builds
- ``maybe_elevate`` decision logic (disabled, already-attempted,
  already-elevated, and successful/declined relaunch) without ever invoking a
  real ``ShellExecuteW`` UAC prompt
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

from intellicrack.core import elevation


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


def _call_build_relaunch(original_args: list[str]) -> tuple[str, str]:
    """Invoke the private relaunch-command builder via ``getattr``.

    Mirrors the test convention used elsewhere in the suite to access a
    module-private helper without tripping ``reportPrivateUsage``.

    Args:
        original_args: Command-line arguments to forward to the builder.

    Returns:
        tuple[str, str]: The executable path and parameter string produced by
        :func:`intellicrack.core.elevation._build_relaunch_command`.
    """
    builder = cast("Callable[[list[str]], tuple[str, str]]", getattr(elevation, "_build_relaunch_command"))
    return builder(original_args)


class TestPlatformHelpers:
    """Validate the platform and elevation detection helpers."""

    def test_is_windows_matches_platform(self) -> None:
        """``is_windows`` reflects ``sys.platform``."""
        assert elevation.is_windows() is (sys.platform == "win32")

    def test_is_elevated_matches_oracle(self) -> None:
        """``is_elevated`` agrees with an independent system call.

        On Windows the independent oracle queries ``shell32.IsUserAnAdmin``
        directly through a fresh ``ctypes.WinDLL`` binding that is separate
        from the one constructed inside :func:`intellicrack.core.elevation.is_elevated`.
        On every other platform ``is_elevated`` must unconditionally return
        ``False`` because the Windows API is absent.
        """
        result: bool = elevation.is_elevated()
        if sys.platform == "win32":
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            is_admin_fn = shell32.IsUserAnAdmin
            is_admin_fn.restype = wintypes.BOOL
            is_admin_fn.argtypes = []
            expected: bool = bool(is_admin_fn())
            assert result is expected
        else:
            assert result is False


class TestBuildRelaunchCommand:
    """Validate relaunch command construction."""

    def test_interpreter_launch_uses_module_invocation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-frozen, non-pixi launch relaunches via ``-m intellicrack`` with the guard flag.

        Args:
            monkeypatch: Pytest fixture used to clear any ``sys.frozen`` marker
                and the pixi launcher environment variables so the plain
                interpreter fallback is exercised.
        """
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.delenv("PIXI_EXE", raising=False)
        executable, params = _call_build_relaunch(["--verbose"])
        assert executable == sys.executable
        assert params.startswith(f"-m {elevation.PACKAGE_NAME} --verbose")
        assert params.endswith(elevation.ELEVATED_FLAG)

    def test_arguments_with_spaces_are_quoted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Arguments containing spaces are quoted via ``list2cmdline``.

        Args:
            monkeypatch: Pytest fixture used to clear any ``sys.frozen`` marker
                and the pixi launcher environment variables so the plain
                interpreter fallback is exercised.
        """
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.delenv("PIXI_EXE", raising=False)
        _, params = _call_build_relaunch(["--config", "C:/a b/c.toml"])
        assert '"C:/a b/c.toml"' in params

    def test_pixi_launch_relaunches_through_pixi(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A pixi launch relaunches through ``pixi run`` so the env re-activates.

        The elevated child cannot inherit the activated pixi/conda environment,
        so the relaunch must invoke pixi with the recorded manifest and
        environment name rather than the bare interpreter.

        Args:
            monkeypatch: Pytest fixture used to clear ``sys.frozen`` and set the
                pixi launcher environment variables.
            tmp_path: Pytest fixture providing a real on-disk path to stand in
                for the pixi executable so the file-existence check passes.
        """
        monkeypatch.delattr(sys, "frozen", raising=False)
        fake_pixi = tmp_path / "pixi.exe"
        fake_pixi.write_bytes(b"")
        manifest = tmp_path / "pyproject.toml"
        manifest.write_text("[project]\n", encoding="utf-8")
        monkeypatch.setenv("PIXI_EXE", str(fake_pixi))
        monkeypatch.setenv("PIXI_PROJECT_MANIFEST", str(manifest))
        monkeypatch.setenv("PIXI_ENVIRONMENT_NAME", "default")

        executable, params = _call_build_relaunch(["--verbose"])

        assert executable == str(fake_pixi)
        assert params.startswith("run ")
        assert "--manifest-path" in params
        assert str(manifest) in params
        assert "--environment default" in params
        assert f"python -m {elevation.PACKAGE_NAME} --verbose" in params
        assert params.endswith(elevation.ELEVATED_FLAG)

    def test_missing_pixi_executable_falls_back_to_interpreter(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A stale ``PIXI_EXE`` path falls back to the plain interpreter relaunch.

        Args:
            monkeypatch: Pytest fixture used to clear ``sys.frozen`` and point
                ``PIXI_EXE`` at a non-existent file.
            tmp_path: Pytest fixture providing a base directory for the
                non-existent pixi path.
        """
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.setenv("PIXI_EXE", str(tmp_path / "does-not-exist.exe"))
        executable, params = _call_build_relaunch(["--verbose"])
        assert executable == sys.executable
        assert params.startswith(f"-m {elevation.PACKAGE_NAME} --verbose")

    def test_frozen_launch_uses_executable_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A frozen build relaunches ``sys.executable`` without ``-m``.

        Args:
            monkeypatch: Pytest fixture used to set the ``sys.frozen`` marker.
        """
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        executable, params = _call_build_relaunch(["--quiet"])
        assert executable == sys.executable
        assert "-m" not in params.split()
        assert params == f"--quiet {elevation.ELEVATED_FLAG}"


class TestMaybeElevate:
    """Validate the ``maybe_elevate`` decision logic."""

    def test_non_windows_never_elevates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """On non-Windows platforms no relaunch is attempted.

        Args:
            monkeypatch: Pytest fixture used to force the platform check.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: False)
        assert (
            elevation.maybe_elevate(disabled=False, already_attempted=False, original_args=[], working_dir=".") is False
        )

    def test_disabled_skips_elevation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The ``--no-elevate`` path never relaunches.

        ``_relaunch_elevated`` is replaced with a spy that raises on any call.
        If the ``disabled`` guard were removed from ``maybe_elevate`` the
        unprivileged path (``is_elevated`` returns ``False``) would reach
        ``_relaunch_elevated`` and raise, turning this test red.

        Args:
            monkeypatch: Pytest fixture used to force Windows, an unprivileged
                token, and a raising sentinel for any relaunch attempt.
        """
        spy: MagicMock = MagicMock(side_effect=AssertionError("_relaunch_elevated must not be called when disabled"))
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)
        monkeypatch.setattr(elevation, "_relaunch_elevated", spy)
        result: bool = elevation.maybe_elevate(
            disabled=True, already_attempted=False, original_args=[], working_dir=".",
        )
        assert result is False
        spy.assert_not_called()

    def test_already_attempted_does_not_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A child started with ``--elevated`` never relaunches again.

        ``_relaunch_elevated`` is replaced with a spy that raises on any call.
        If the ``already_attempted`` guard were removed from ``maybe_elevate``
        the unprivileged path (``is_elevated`` returns ``False``) would reach
        ``_relaunch_elevated`` and raise, turning this test red.

        Args:
            monkeypatch: Pytest fixture used to force Windows, simulate an
                unprivileged child, and place a raising sentinel for any
                relaunch attempt.
        """
        spy: MagicMock = MagicMock(
            side_effect=AssertionError("_relaunch_elevated must not be called when already_attempted=True"),
        )
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)
        monkeypatch.setattr(elevation, "_relaunch_elevated", spy)
        result: bool = elevation.maybe_elevate(
            disabled=False, already_attempted=True, original_args=[], working_dir=".",
        )
        assert result is False
        spy.assert_not_called()

    def test_already_elevated_needs_no_relaunch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An already-elevated process does not relaunch.

        ``_relaunch_elevated`` is replaced with a spy that raises on any call.
        If the ``is_elevated()`` short-circuit guard were removed from
        ``maybe_elevate``, the code would call ``_relaunch_elevated`` and
        raise, turning this test red.

        Args:
            monkeypatch: Pytest fixture used to force Windows, an elevated
                token, and place a raising sentinel for any relaunch attempt.
        """
        spy: MagicMock = MagicMock(
            side_effect=AssertionError("_relaunch_elevated must not be called when already elevated"),
        )
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: True)
        monkeypatch.setattr(elevation, "_relaunch_elevated", spy)
        result: bool = elevation.maybe_elevate(
            disabled=False, already_attempted=False, original_args=[], working_dir=".",
        )
        assert result is False
        spy.assert_not_called()

    def test_unelevated_triggers_relaunch_and_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unelevated process relaunches and signals the caller to exit.

        Args:
            monkeypatch: Pytest fixture used to force Windows, an unprivileged
                token, and a successful relaunch.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)
        monkeypatch.setattr(elevation, "_relaunch_elevated", _succeed_relaunch)
        assert (
            elevation.maybe_elevate(disabled=False, already_attempted=False, original_args=[], working_dir=".") is True
        )

    def test_declined_relaunch_continues_unprivileged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A declined UAC prompt lets the current process continue.

        Args:
            monkeypatch: Pytest fixture used to force Windows, an unprivileged
                token, and a failed relaunch.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)
        monkeypatch.setattr(elevation, "_relaunch_elevated", _fail_relaunch)
        assert (
            elevation.maybe_elevate(disabled=False, already_attempted=False, original_args=[], working_dir=".") is False
        )


def _fail_relaunch(original_args: list[str], working_dir: str) -> bool:
    """Stand-in relaunch that reports failure (declined or unavailable).

    Args:
        original_args: Forwarded command-line arguments (unused).
        working_dir: Working directory for the relaunch (unused).

    Returns:
        bool: Always ``False`` to simulate a declined or failed relaunch.
    """
    del original_args, working_dir
    return False


def _succeed_relaunch(original_args: list[str], working_dir: str) -> bool:
    """Stand-in relaunch that reports a successfully started elevated process.

    Args:
        original_args: Forwarded command-line arguments (unused).
        working_dir: Working directory for the relaunch (unused).

    Returns:
        bool: Always ``True`` to simulate a successful relaunch.
    """
    del original_args, working_dir
    return True
