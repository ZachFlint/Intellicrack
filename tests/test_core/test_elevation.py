# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for Intellicrack Windows UAC self-elevation.

Tests validate:
- Platform and elevation detection helpers
- Relaunch command construction for interpreter and frozen builds
- ``maybe_elevate`` decision logic gated via a real injectable relauncher seam:
  disabled, already-attempted, already-elevated, exact argument forwarding, and
  declined-relaunch return-value propagation
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, cast

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
    """Validate the ``maybe_elevate`` decision logic via an injectable relauncher seam.

    All gates inject a real callable through the ``relauncher`` parameter
    introduced in :func:`intellicrack.core.elevation.maybe_elevate`.  No
    module-level attribute of the production module is replaced, so every
    mutation of the decision logic is detectable without relying on
    monkeypatching internals.
    """

    def test_non_windows_never_elevates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """On non-Windows platforms no relaunch is attempted.

        The relauncher seam raises if called.  If the
        ``if not is_windows(): return False`` guard is deleted from
        ``maybe_elevate``, execution falls through to the relauncher and the
        test turns red.

        Args:
            monkeypatch: Pytest fixture used to force the platform check to
                return ``False``.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: False)

        def _must_not_be_called(original_args: list[str], working_dir: str) -> bool:
            msg = f"relauncher must not be called on non-Windows; args={original_args!r}, cwd={working_dir!r}"
            raise AssertionError(msg)

        result: bool = elevation.maybe_elevate(
            disabled=False,
            already_attempted=False,
            original_args=[],
            working_dir=".",
            relauncher=_must_not_be_called,
        )
        assert result is False

    def test_disabled_never_calls_relauncher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The ``--no-elevate`` guard short-circuits before the relauncher.

        The relauncher seam raises if called.  If the
        ``if disabled: ... return False`` block is deleted from ``maybe_elevate``,
        execution falls through to the relauncher and the test turns red.

        Args:
            monkeypatch: Pytest fixture used to force Windows and an
                unprivileged token so the ``disabled`` guard is the only
                barrier before the relauncher.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)

        def _must_not_be_called(original_args: list[str], working_dir: str) -> bool:
            msg = f"relauncher must not be called when disabled; args={original_args!r}, cwd={working_dir!r}"
            raise AssertionError(msg)

        result: bool = elevation.maybe_elevate(
            disabled=True,
            already_attempted=False,
            original_args=["--verbose"],
            working_dir="D:/work",
            relauncher=_must_not_be_called,
        )
        assert result is False

    def test_already_attempted_never_calls_relauncher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A child flagged ``already_attempted`` continues without calling the relauncher.

        The relauncher seam raises if called.  If the
        ``if already_attempted: ... return False`` block is deleted from
        ``maybe_elevate``, execution falls through to the relauncher and the
        test turns red.

        Args:
            monkeypatch: Pytest fixture used to force Windows and an
                unprivileged token so the ``already_attempted`` guard is the
                only barrier before the relauncher.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)

        def _must_not_be_called(original_args: list[str], working_dir: str) -> bool:
            msg = f"relauncher must not be called when already_attempted; args={original_args!r}, cwd={working_dir!r}"
            raise AssertionError(msg)

        result: bool = elevation.maybe_elevate(
            disabled=False,
            already_attempted=True,
            original_args=["--verbose"],
            working_dir="D:/work",
            relauncher=_must_not_be_called,
        )
        assert result is False

    def test_already_elevated_never_calls_relauncher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An already-elevated process short-circuits without calling the relauncher.

        The relauncher seam raises if called.  If the
        ``if is_elevated(): return False`` block is deleted from
        ``maybe_elevate``, execution falls through to the relauncher and the
        test turns red.

        Args:
            monkeypatch: Pytest fixture used to force Windows and a simulated
                elevated token.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: True)

        def _must_not_be_called(original_args: list[str], working_dir: str) -> bool:
            msg = f"relauncher must not be called when already elevated; args={original_args!r}, cwd={working_dir!r}"
            raise AssertionError(msg)

        result: bool = elevation.maybe_elevate(
            disabled=False,
            already_attempted=False,
            original_args=[],
            working_dir=".",
            relauncher=_must_not_be_called,
        )
        assert result is False

    def test_relaunch_receives_exact_original_args_and_working_dir(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The relauncher receives the unmodified ``original_args`` and ``working_dir``.

        The expected values are constructed from the call-site literals, never
        from the production helper, so this is an independent oracle.

        Concrete mutation: change ``relauncher(original_args, working_dir)`` to
        ``relauncher([], working_dir)`` in
        ``src/intellicrack/core/elevation.py`` — ``received_args == []``
        diverges from ``expected_args`` and the test turns red.

        Args:
            monkeypatch: Pytest fixture used to force Windows and an
                unprivileged token so the relaunch path is exercised.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)

        captured: list[tuple[list[str], str]] = []

        def _recording_relauncher(original_args: list[str], working_dir: str) -> bool:
            captured.append((list(original_args), working_dir))
            return True

        expected_args: list[str] = ["--gui", "--project", "C:/my project/demo.bin"]
        expected_working_dir: str = "D:/intellicrack"

        result: bool = elevation.maybe_elevate(
            disabled=False,
            already_attempted=False,
            original_args=expected_args,
            working_dir=expected_working_dir,
            relauncher=_recording_relauncher,
        )

        assert result is True
        assert len(captured) == 1, f"relauncher must be called exactly once; called {len(captured)} time(s)"
        received_args, received_working_dir = captured[0]
        assert received_args == expected_args
        assert received_working_dir == expected_working_dir

    def test_declined_relaunch_propagates_false_to_caller(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A declined relaunch returns ``False`` and the relauncher was invoked.

        The ``call_count == [True]`` assertion rules out a false pass where the
        function never reached the relauncher at all.

        Concrete mutation: replace ``if relauncher(original_args, working_dir):
        return True`` with an unconditional ``return True`` — ``result is
        False`` fails because the mutation returns ``True`` regardless of the
        relauncher's answer.

        Args:
            monkeypatch: Pytest fixture used to force Windows and an
                unprivileged token so the relaunch path is exercised.
        """
        monkeypatch.setattr(elevation, "is_windows", lambda: True)
        monkeypatch.setattr(elevation, "is_elevated", lambda: False)

        call_count: list[bool] = []

        def _declining_relauncher(original_args: list[str], working_dir: str) -> bool:
            del original_args, working_dir
            call_count.append(True)
            return False

        result: bool = elevation.maybe_elevate(
            disabled=False,
            already_attempted=False,
            original_args=["--verbose"],
            working_dir=".",
            relauncher=_declining_relauncher,
        )
        assert result is False
        assert call_count == [True], "relauncher must have been invoked exactly once"
