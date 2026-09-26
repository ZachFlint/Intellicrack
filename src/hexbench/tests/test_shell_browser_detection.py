# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Opera's real per-user layout, and a rejected ``--browser`` override.

Opera's consumer installer places the browser under a version-numbered
subdirectory of ``%LocalAppData%\Programs\Opera``, fronted by a
version-independent ``launcher.exe`` -- a layout none of the other browsers
this module looks for share. The old ``_BROWSERS``/``install_roots`` pairing
could never reach it: it named only ``Opera\opera.exe``, joined onto roots
that never included the extra ``Programs`` path segment, so on a machine where
Opera was the only non-Edge browser installed it was never found.

Separately, an explicit ``--browser`` path that cannot be opened must not read
like ordinary ``--shell none`` output -- the caller asked for something
specific and was refused, and that refusal has to be visible.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Final

from hexbench import shell
from hexbench.tests._support import Assertions


if TYPE_CHECKING:
    from collections.abc import Generator


_TEST_URL: Final = "http://127.0.0.1:1/token"


@contextlib.contextmanager
def _replaced_attribute(owner: object, name: str, replacement: object) -> Generator[None]:
    """Swap one attribute of ``owner`` for the duration of a ``with`` block.

    Args:
        owner: Module or class whose attribute is swapped.
        name: Attribute to swap.
        replacement: Value the attribute holds inside the block.

    Yields:
        None: Control, with the replacement installed; the original is restored on exit.
    """
    original = getattr(owner, name)
    setattr(owner, name, replacement)
    try:
        yield
    finally:
        setattr(owner, name, original)


@contextlib.contextmanager
def _environment_variable(name: str, value: str) -> Generator[None]:
    """Set one environment variable for the duration of a ``with`` block.

    Args:
        name: Variable to set.
        value: Value it holds inside the block.

    Yields:
        None: Control, with the variable set; its previous state is restored on exit.
    """
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            del os.environ[name]
        else:
            os.environ[name] = previous


def _launch_refused(url: str, *, browser: Path, width: int = 0, height: int = 0) -> bool:
    """Stand in for a browser launch that the operating system refuses.

    Args:
        url: Address the window would have opened.
        browser: Executable that would have been launched.
        width: Requested window width.
        height: Requested window height.

    Returns:
        bool: Always ``False``, as a failed launch reports.
    """
    del url, browser, width, height
    return False


def _no_browser_installed(override: Path | None = None) -> Path | None:
    """Report that no browser can be found on this machine.

    Args:
        override: Ignored explicit browser path.

    Returns:
        Path | None: Always ``None``.
    """
    del override
    return None


class InstallRootsIncludePerUserProgramsTests(Assertions, unittest.TestCase):
    """``install_roots`` must offer the directory Opera actually installs under."""

    def test_local_appdata_programs_is_one_of_the_roots(self) -> None:
        """The per-user ``Programs`` directory must be a candidate root when ``LOCALAPPDATA`` is set."""
        with _environment_variable("LOCALAPPDATA", "C:\\Users\\example\\AppData\\Local"):
            roots = shell.install_roots()
        self.contains(Path("C:\\Users\\example\\AppData\\Local\\Programs"), roots, "the per-user Programs directory")


class FindBrowserResolvesOperaLauncherTests(Assertions, unittest.TestCase):
    """``find_browser`` must locate Opera's real per-user launcher on disk."""

    def test_opera_launcher_under_local_appdata_programs_is_found(self) -> None:
        r"""A real ``Programs\Opera\launcher.exe`` file must be found, not skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            opera_dir = Path(tmp) / "Opera"
            opera_dir.mkdir()
            launcher = opera_dir / "launcher.exe"
            launcher.write_bytes(b"MZ")
            with _replaced_attribute(shell, "install_roots", lambda: (Path(tmp),)):
                found = shell.find_browser()
        self.equal(found, launcher, "the browser find_browser located")

    def test_the_old_opera_relative_path_alone_still_resolves_on_its_own(self) -> None:
        r"""A bare ``Opera\opera.exe`` file, with no launcher present, must still be found.

        This is the control for the launcher test above: it proves the
        root-patching setup genuinely exercises real disk lookups rather than
        always returning a fixed answer, by locating a different file through
        a different :data:`_BROWSERS` entry in the same directory tree.
        """
        with tempfile.TemporaryDirectory() as tmp:
            opera_dir = Path(tmp) / "Opera"
            opera_dir.mkdir()
            legacy = opera_dir / "opera.exe"
            legacy.write_bytes(b"MZ")
            with _replaced_attribute(shell, "install_roots", lambda: (Path(tmp),)):
                found = shell.find_browser()
        self.equal(found, legacy, "the browser find_browser located")


class OpenShellOverrideDiagnosticTests(Assertions, unittest.TestCase):
    """A rejected ``--browser`` override must be named, not swallowed."""

    def test_a_nonexistent_override_is_named_on_stderr(self) -> None:
        """An override path that does not exist must be named in a stderr diagnostic."""
        missing = Path(tempfile.gettempdir()) / "hexbench-does-not-exist.exe"
        self.falsy(missing.exists(), "the path chosen for this test unexpectedly exists")
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            opened = shell.open_shell(_TEST_URL, override=missing)
        self.falsy(opened, "open_shell's return for an override that cannot be found")
        self.contains(str(missing), err.getvalue(), "stderr naming the rejected --browser override")

    def test_an_override_that_exists_but_fails_to_launch_is_named_on_stderr(self) -> None:
        """An override that resolves on disk but whose launch fails must still be named."""
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "browser.exe"
            executable.write_bytes(b"MZ")
            out, err = StringIO(), StringIO()
            with _replaced_attribute(shell, "launch_window", _launch_refused), redirect_stdout(out), redirect_stderr(err):
                opened = shell.open_shell(_TEST_URL, override=executable)
        self.falsy(opened, "open_shell's return for an override that fails to launch")
        self.contains(str(executable), err.getvalue(), "stderr naming the override whose launch failed")

    def test_ordinary_auto_detection_failure_carries_no_override_diagnostic(self) -> None:
        """Without an explicit override, the failure path must stay silent on stderr."""
        out, err = StringIO(), StringIO()
        with _replaced_attribute(shell, "find_browser", _no_browser_installed), redirect_stdout(out), redirect_stderr(err):
            opened = shell.open_shell(_TEST_URL)
        self.falsy(opened, "open_shell's return with no browser available at all")
        self.equal(err.getvalue(), "", "stderr must stay empty when no --browser override was given")
        self.contains(_TEST_URL, out.getvalue(), "the announced address")


if __name__ == "__main__":
    unittest.main()
