# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests for the installed Hexbench shortcut path.

The installer ships the Hexbench editor as package *source* under
``{app}\hexbench`` and runs it on the bundled ``{app}\runtime`` rather than
freezing a second interpreter into the payload. Three separate things have to
agree for the Start-menu shortcut to actually open an editor, and each of them
failed silently before:

* The ``.iss`` must install a shortcut target that exists. It previously pointed
  at ``{app}\hexbench\hexbench.exe``, a file no build step has ever produced,
  so the installed shortcut was dead.
* The bootstrapper must put the *parent* of the package on ``PYTHONPATH``. The
  editor resolves its ``static`` tree from its own ``__file__``, so it has to be
  imported as a module of the package; a path pointing inside the package makes
  ``-m hexbench`` fail outright.
* The child must be spawned so that ``sys.stderr`` survives. ``hexbench.__main__``
  writes diagnostics to it unconditionally, so a child started under
  ``DETACHED_PROCESS`` (what the Intellicrack launcher uses) or from
  ``pythonw.exe`` turns the first diagnostic into an ``AttributeError``.

The import contract is proven by running the real editor module out of the real
checkout. The stream contract is asserted against the command line and creation
flags the launcher actually builds, for the reason recorded above those tests:
a spawned probe inherits pytest's own redirected handles and so reports a
healthy ``sys.stderr`` under every flag, including the broken ones.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from tests.packaging.test_stage_matches_iss import iss_section_lines


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_LAUNCHER_PATH: Final[Path] = _REPO_ROOT / "packaging" / "launcher" / "hexbench_launcher.py"
_ISS_PATH: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"
_STAGE_PATH: Final[Path] = _REPO_ROOT / "packaging" / "stage.ps1"
_HEXBENCH_PKG: Final[Path] = _REPO_ROOT / "src" / "hexbench"

_CHILD_TIMEOUT: Final[float] = 120.0


def _load_launcher() -> ModuleType:
    """Load ``packaging/launcher/hexbench_launcher.py`` from its file path.

    The launcher is a standalone build script outside the ``intellicrack``
    package, so it is imported directly from disk the same way the ML-split
    build script is.

    Returns:
        ModuleType: The imported ``hexbench_launcher`` module.
    """
    spec = importlib.util.spec_from_file_location("hexbench_launcher", _LAUNCHER_PATH)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load hexbench_launcher from {_LAUNCHER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hexbench_launcher = _load_launcher()


def _read_iss() -> str:
    """Read the production ``.iss`` script.

    Returns:
        str: The full UTF-8 text of ``packaging/intellicrack.iss``.
    """
    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    return _ISS_PATH.read_text(encoding="utf-8-sig")


def _make_fake_install(root: Path) -> Path:
    """Materialise the installed layout the launcher resolves against.

    Args:
        root: Directory to populate as a fake ``{app}`` install tree.

    Returns:
        Path: The fake install directory (``root`` itself).
    """
    python = root / "runtime" / "python.exe"
    python.parent.mkdir(parents=True, exist_ok=True)
    python.write_bytes(b"stub")
    package = root / "hexbench" / "__init__.py"
    package.parent.mkdir(parents=True, exist_ok=True)
    package.write_text("", encoding="utf-8")
    return root


# --- The stream contract: the spawn must not strip the child's handles --------
#
# This is asserted against the command and flags the launcher actually builds
# rather than by spawning a probe and reading its streams. A probe cannot decide
# it: whether a child keeps ``sys.stderr`` depends on what the *parent* holds,
# and under pytest the parent's handles are already redirected to capture files
# that any child inherits regardless of the flag. Such a probe reports a healthy
# stderr for every flag, including the broken ones, so it would gate nothing.
#
# The behaviour these assertions stand in for was measured directly on Windows,
# spawning the real interpreter from a parent with a console:
#
#     python.exe + CREATE_NO_WINDOW -> sys.stderr valid
#     python.exe + DETACHED_PROCESS -> sys.stderr is None
#     pythonw.exe                   -> sys.stderr is None


def _captured_command(monkeypatch: pytest.MonkeyPatch, install: Path, argv: list[str]) -> tuple[list[str], dict[str, object]]:
    """Run :func:`launch` and capture the process it would have started.

    The real :class:`subprocess.Popen` is replaced for the duration of the call,
    so nothing is spawned, but the command line and keyword arguments captured
    are the ones the launcher genuinely constructed.

    Args:
        monkeypatch: Fixture used to redirect install-dir resolution and Popen.
        install: The fake install directory to resolve against.
        argv: Arguments to forward to :func:`launch`.

    Returns:
        tuple[list[str], dict[str, object]]: The command line and the keyword
            arguments the launcher passed to :class:`subprocess.Popen`.
    """
    commands: list[list[str]] = []
    keywords: list[dict[str, object]] = []

    def fake_popen(command: list[str], **kwargs: object) -> object:
        commands.append(command)
        keywords.append(kwargs)
        return object()

    monkeypatch.setattr(hexbench_launcher, "resolve_install_dir", lambda: install)
    monkeypatch.setattr(hexbench_launcher.subprocess, "Popen", fake_popen)

    assert hexbench_launcher.launch(argv) == 0, "launch reported failure on a complete install tree"
    assert len(commands) == 1, f"expected exactly one spawn, got {len(commands)}"
    return commands[0], keywords[0]


def test_launcher_spawns_the_console_interpreter_not_pythonw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real gate: the child is ``python.exe`` running ``-m hexbench``.

    ``pythonw.exe`` leaves the child with no standard handles, and
    ``hexbench.__main__`` writes to ``sys.stderr`` unconditionally, so switching
    the launcher to the windowed interpreter turns the editor's first diagnostic
    into an ``AttributeError``. Changing the executable or the module here turns
    this red.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Fixture used to redirect resolution and capture the spawn.
    """
    install = _make_fake_install(tmp_path / "app")
    command, kwargs = _captured_command(monkeypatch, install, ["--shell", "none"])

    assert command[0] == str(install / "runtime" / "python.exe"), f"unexpected interpreter: {command[0]}"
    assert not command[0].endswith("pythonw.exe"), "pythonw.exe leaves the child without sys.stderr"
    assert command[1:4] == ["-m", "hexbench", "--shell"], f"unexpected command line: {command}"
    assert command[-1] == "none", "trailing arguments must be forwarded to the editor"
    assert kwargs["cwd"] == str(install)


def test_launcher_uses_create_no_window_and_never_detaches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real gate: the spawn flag is exactly ``CREATE_NO_WINDOW``.

    ``CREATE_NO_WINDOW`` allocates a console the user never sees, which is what
    keeps the child's standard handles valid while showing no window.
    ``DETACHED_PROCESS`` -- the flag the Intellicrack launcher uses -- gives the
    child no handles at all. Substituting it, or adding it to the flag set,
    turns this red.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Fixture used to redirect resolution and capture the spawn.
    """
    install = _make_fake_install(tmp_path / "app")
    _, kwargs = _captured_command(monkeypatch, install, [])

    flags = kwargs["creationflags"]
    assert flags == subprocess.CREATE_NO_WINDOW, f"expected CREATE_NO_WINDOW, got {flags!r}"
    assert isinstance(flags, int)
    assert not flags & subprocess.DETACHED_PROCESS, "DETACHED_PROCESS strips the child's standard handles"
    assert hexbench_launcher.creation_flags() == subprocess.CREATE_NO_WINDOW


# --- The import contract: -m hexbench must resolve from the computed root -----


def test_package_root_is_the_parent_of_the_package(tmp_path: Path) -> None:
    """The path handed to ``PYTHONPATH`` is the directory *containing* ``hexbench``.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    assert hexbench_launcher.package_root(install) == install
    assert (hexbench_launcher.package_root(install) / "hexbench" / "__init__.py").is_file()


def test_package_root_falls_back_to_src_in_a_checkout(tmp_path: Path) -> None:
    """Without a staged package beside it, the launcher looks under ``src``.

    Args:
        tmp_path: Pytest temporary directory used as a bare install root.
    """
    bare = tmp_path / "checkout"
    bare.mkdir()
    assert hexbench_launcher.package_root(bare) == bare / "src"


def test_module_actually_imports_from_the_computed_root() -> None:
    """Real gate: ``-m hexbench`` runs when only the computed root is on the path.

    Drives the real repository checkout through the launcher's own
    :func:`package_root` and starts the real editor module with nothing but that
    directory on ``PYTHONPATH``. Pointing the launcher at the package directory
    itself (rather than its parent) makes ``-m hexbench`` fail to resolve and
    turns this red.
    """
    assert _HEXBENCH_PKG.is_dir(), f"hexbench package missing: {_HEXBENCH_PKG}"

    root = hexbench_launcher.package_root(_REPO_ROOT)
    assert root == _REPO_ROOT / "src", f"expected the checkout to resolve to src, got {root}"

    env = dict(os.environ)
    env["PYTHONPATH"] = str(root)
    completed = subprocess.run(
        [sys.executable, "-m", "hexbench", "--help"],
        env=env,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=_CHILD_TIMEOUT,
        check=False,
    )
    assert completed.returncode == 0, f"-m hexbench failed from {root}:\n{completed.stderr}"
    assert "hex editor" in completed.stdout.lower(), f"unexpected --help output:\n{completed.stdout}"


# --- The environment contract -------------------------------------------------


def test_child_env_points_pythonpath_at_the_package_root(tmp_path: Path) -> None:
    """The assembled environment puts the package root first on ``PYTHONPATH``.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    env = hexbench_launcher.build_child_env(install)
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(install)


def test_child_env_preserves_an_existing_pythonpath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An inherited ``PYTHONPATH`` is kept, appended after the package root.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Fixture used to set the inherited environment variable.
    """
    install = _make_fake_install(tmp_path / "app")
    monkeypatch.setenv("PYTHONPATH", r"C:\existing")
    env = hexbench_launcher.build_child_env(install)
    assert env["PYTHONPATH"].split(os.pathsep) == [str(install), r"C:\existing"]


def test_child_env_prepends_only_runtime_directories_that_exist(tmp_path: Path) -> None:
    """``PATH`` gains existing runtime directories but never the Scripts shims dir.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    (install / "runtime" / "Library" / "bin").mkdir(parents=True, exist_ok=True)
    (install / "runtime" / "Scripts").mkdir(parents=True, exist_ok=True)

    env = hexbench_launcher.build_child_env(install)
    entries = env["PATH"].split(os.pathsep)

    assert str(install / "runtime") in entries
    assert str(install / "runtime" / "Library" / "bin") in entries
    assert str(install / "runtime" / "Scripts") not in entries, (
        "runtime\\Scripts hosts pip console-script shims that embed the build interpreter path; it must never be placed on the child PATH"
    )
    assert str(install / "runtime" / "DLLs") not in entries, "a directory that does not exist must not be added to PATH"


def test_child_env_does_not_mutate_the_process_environment(tmp_path: Path) -> None:
    """Assembling the child environment leaves ``os.environ`` untouched.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    before = dict(os.environ)
    hexbench_launcher.build_child_env(install)
    assert dict(os.environ) == before


# --- Failure reporting --------------------------------------------------------


def test_launch_reports_and_fails_when_the_runtime_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing bundled runtime is reported rather than raising or spawning.

    Args:
        tmp_path: Pytest temporary directory used as an empty install root.
        monkeypatch: Fixture used to redirect install-dir resolution and capture reports.
    """
    empty = tmp_path / "app"
    empty.mkdir()
    reported: list[str] = []
    monkeypatch.setattr(hexbench_launcher, "resolve_install_dir", lambda: empty)
    monkeypatch.setattr(hexbench_launcher, "report_error", reported.append)

    assert hexbench_launcher.launch([]) == 1
    assert reported
    assert "runtime not found" in reported[0]


def test_launch_reports_and_fails_when_the_package_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A staged runtime without the hexbench package is reported, not spawned.

    Args:
        tmp_path: Pytest temporary directory used to build a partial install.
        monkeypatch: Fixture used to redirect install-dir resolution and capture reports.
    """
    install = tmp_path / "app"
    python = install / "runtime" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"stub")

    reported: list[str] = []
    monkeypatch.setattr(hexbench_launcher, "resolve_install_dir", lambda: install)
    monkeypatch.setattr(hexbench_launcher, "report_error", reported.append)

    assert hexbench_launcher.launch([]) == 1
    assert reported
    assert "package not found" in reported[0]


# --- The installer contract ---------------------------------------------------


def test_iss_shortcut_target_is_a_file_the_build_produces() -> None:
    r"""Real gate: the Hexbench shortcut points at the staged launcher exe.

    The regression this replaces shipped a shortcut to
    ``{app}\hexbench\hexbench.exe``, which no build step produces. The target
    must be the ``Hexbench.exe`` the stager builds and drops at the install
    root, and it must be installed by a ``[Files]`` entry gated on the same
    component as the shortcut.
    """
    icon_lines = [line for line in iss_section_lines(_read_iss(), "Icons") if "Hexbench" in line]
    assert icon_lines, "the .iss declares no Hexbench shortcut"

    for line in icon_lines:
        assert "hexbench\\hexbench.exe" not in line.lower(), (
            f"the Hexbench shortcut points at a file no build step produces: {line.strip()}"
        )
        assert "{#HexbenchExeName}" in line or "Hexbench.exe" in line, f"unexpected Hexbench shortcut target: {line.strip()}"
        assert "Components: hexbench" in line, "the Hexbench shortcut must be gated on the hexbench component"

    files_entry = [line for line in iss_section_lines(_read_iss(), "Files") if "HexbenchExeName" in line]
    assert files_entry, "the .iss never installs Hexbench.exe, so its shortcut target would be missing"
    assert all("Components: hexbench" in line for line in files_entry), (
        "the Hexbench.exe [Files] entry must be gated on the hexbench component"
    )


def test_iss_defines_the_hexbench_exe_name() -> None:
    """The ``.iss`` declares ``HexbenchExeName`` so the target is named once."""
    match = re.search(r'(?im)^[ \t]*#define[ \t]+HexbenchExeName[ \t]+"([^"]+)"', _read_iss())
    assert match is not None, "the .iss must #define HexbenchExeName"
    assert match.group(1) == "Hexbench.exe"


def test_stage_builds_and_stages_the_hexbench_launcher() -> None:
    """Real gate: the stager builds the hexbench launcher and stages the exe.

    Without this step the ``.iss`` would reference a ``Hexbench.exe`` that never
    reaches ``build/stage``, and the installer compile would fail.
    """
    stage_text = _STAGE_PATH.read_text(encoding="utf-8-sig")
    assert "packaging/launcher/hexbench_launcher.spec" in stage_text, "stage.ps1 must build the hexbench launcher spec"
    assert "Hexbench.exe" in stage_text, "stage.ps1 must stage Hexbench.exe"


def test_hexbench_launcher_spec_targets_the_bootstrapper_not_the_editor() -> None:
    """The installer's spec freezes the bootstrapper, not a second interpreter.

    Freezing ``src/hexbench/hexbench.spec`` into the installer instead would
    duplicate the interpreter, webview and hexcore the runtime already carries.
    """
    spec_path = _REPO_ROOT / "packaging" / "launcher" / "hexbench_launcher.spec"
    assert spec_path.is_file(), f"missing spec: {spec_path}"
    spec_text = spec_path.read_text(encoding="utf-8")

    assert "hexbench_launcher.py" in spec_text, "the installer spec must freeze the bootstrapper script"
    assert 'name="Hexbench"' in spec_text, "the built exe must be named Hexbench"
    assert "console=False" in spec_text, "the bootstrapper is windowed; it reports failures in a dialog"
