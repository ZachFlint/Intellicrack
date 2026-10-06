# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass critical-coverage tests for ``intellicrack.bridges.installer``.

The first pass left the failure paths that need a hostile or unusual real environment:
files whose byte range is locked by another handle, a tool directory that is a file,
a plugin target that is a directory, an event loop whose default executor has shut
down, and a ``vswhere.exe`` that actually runs. The last one is a real Windows console
launcher shipped inside the ``distlib`` package, with a zip-archive Python script
appended exactly as ``distlib`` writes its own script launchers, so the production code
starts a genuine child process and reads its genuine standard output. The
``pefile``-unavailable guards are reached by flipping the module's availability flag
for the duration of one call.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import msvcrt
import os
import re
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import InstallResult, ToolInfo, ToolInstaller, ToolVersion
from intellicrack.core.types import ToolName
from tests._helpers.real_binaries import resolve_real_pe_exe


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Iterator


pytestmark = pytest.mark.spawns_process

_EXPECTED_VSWHERE_ARGS: Final[tuple[str, ...]] = ("-latest", "-property", "installationPath")
_VS_CMAKE_PARTS: Final[tuple[str, ...]] = ("Common7", "IDE", "CommonExtensions", "Microsoft", "CMake", "CMake", "bin")
_PLUGIN_X64: Final[str] = "intellicrack_bridge_x64.dp64"
_PLUGIN_X32: Final[str] = "intellicrack_bridge_x32.dp32"


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine on a private event loop and join its executor threads.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()


def attr[T](obj: object, name: str, typing_hint: T | None = None) -> T:
    """Read a (possibly private) attribute with the static type the caller expects.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        typing_hint: Unused; ties the return type to the caller's annotation.

    Returns:
        T: The attribute value.
    """
    del typing_hint
    value: T = getattr(obj, name)
    return value


def _triple(version: ToolVersion | None) -> tuple[int, int, int] | None:
    """Reduce a version to its comparable triple.

    Args:
        version: Version to reduce, or None.

    Returns:
        tuple[int, int, int] | None: ``(major, minor, patch)`` or None.
    """
    return None if version is None else (version.major, version.minor, version.patch)


@contextmanager
def _pefile_availability(*, enabled: bool) -> Generator[None]:
    """Force the installer's ``pefile`` availability flag and restore it afterwards.

    Args:
        enabled: Value the flag holds inside the ``with`` block.

    Yields:
        None: Control to the caller while the flag holds ``enabled``.
    """
    original: bool = attr(installer_mod, "_pefile_available")
    setattr(installer_mod, "_pefile_available", enabled)
    try:
        yield
    finally:
        setattr(installer_mod, "_pefile_available", original)


@contextmanager
def _locked_file(path: Path) -> Generator[None]:
    """Lock a file's whole byte range so that reads through another handle fail.

    Args:
        path: Existing, non-empty file to lock.

    Yields:
        None: Control to the caller while the range is locked.
    """
    size = path.stat().st_size
    with path.open("r+b") as handle:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, size)
        try:
            yield
        finally:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, size)


def _launcher_bytes() -> bytes:
    """Return the bytes of the 64-bit console launcher shipped inside ``distlib``.

    Returns:
        bytes: The launcher executable image.
    """
    spec = importlib.util.find_spec("distlib")
    assert spec is not None
    assert spec.origin is not None
    return (Path(spec.origin).parent / "t64.exe").read_bytes()


def _vswhere_source(marker: Path, output: str, sleep_s: int) -> str:
    """Build the script a stand-in ``vswhere.exe`` runs.

    Args:
        marker: File the script creates first, proving that it started.
        output: Text written to standard output when the arguments are the ones
            ``vswhere`` is documented to receive for the latest installation path.
        sleep_s: Seconds the script sleeps before it prints.

    Returns:
        str: Python source text for the archive's ``__main__.py``.
    """
    return (
        "import pathlib\n"
        "import sys\n"
        "import time\n"
        f"pathlib.Path({str(marker)!r}).write_text('started')\n"
        f"time.sleep({sleep_s!r})\n"
        f"if sys.argv[1:] == {list(_EXPECTED_VSWHERE_ARGS)!r}:\n"
        f"    sys.stdout.write({output!r})\n"
    )


def _write_vswhere(program_files: Path, source: str) -> Path:
    """Write a runnable ``vswhere.exe`` where the installer looks for it.

    The file is the ``distlib`` console launcher, then a shebang line naming this
    interpreter, then a zip archive holding ``__main__.py``: the layout ``distlib``
    writes for its own Windows script launchers.

    Args:
        program_files: Directory standing in for ``%ProgramFiles(x86)%``.
        source: Python source text of the script to run.

    Returns:
        Path: The written executable.
    """
    interpreter = sys.executable
    shebang_target = f'"{interpreter}"' if " " in interpreter else interpreter
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("__main__.py", source)
    target = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(_launcher_bytes() + f"#!{shebang_target}\n".encode() + stream.getvalue())
    return target


@pytest.fixture
def vs_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Hide any real cmake and aim the Visual Studio lookup at a temporary tree.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Path: Directory the installer treats as ``%ProgramFiles(x86)%``.
    """
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join([str(empty_bin), str(Path(sys.executable).parent)]))
    program_files = tmp_path / "pf86"
    monkeypatch.setenv("PROGRAMFILES(X86)", str(program_files))
    return program_files


@pytest.fixture
def short_vswhere_timeout() -> Iterator[None]:
    """Shorten the installer's vswhere timeout to one second.

    Yields:
        None: Control to the test while the short timeout is in force.
    """
    original: int = attr(installer_mod, "_VSWHERE_TIMEOUT_S")
    setattr(installer_mod, "_VSWHERE_TIMEOUT_S", 1)
    try:
        yield
    finally:
        setattr(installer_mod, "_VSWHERE_TIMEOUT_S", original)


def test_pe_version_probe_is_none_when_pefile_is_unavailable() -> None:
    """A real executable with version data reads as no version while the flag is off."""
    reader: Callable[[Path], str | None] = attr(installer_mod, "_read_pe_version_info")
    exe = resolve_real_pe_exe()
    available = reader(exe)
    assert available is not None
    assert re.match(r"\d+\.\d+", available) is not None
    with _pefile_availability(enabled=False):
        assert installer_mod.pefile_available() is False
        assert reader(exe) is None
    assert reader(exe) == available


def test_verify_tool_fails_for_x64dbg_when_pefile_is_unavailable(tmp_path: Path) -> None:
    """An x64dbg tree that verifies from its release notes is rejected without ``pefile``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    exe = install / "release" / "x64" / "x64dbg.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ")
    (install / "release-notes.md").write_text("snapshot 2025.01.15\n", encoding="utf-8")
    installer = ToolInstaller(tmp_path / "tools")
    assert _run(installer.verify_tool(ToolName.X64DBG, install)) is True
    with _pefile_availability(enabled=False):
        assert _run(installer.verify_tool(ToolName.X64DBG, install)) is False


@pytest.mark.parametrize(("tool", "display_name"), [(ToolName.X64DBG, "x64dbg"), (ToolName.CUTTER, "Cutter")])
def test_install_tool_refuses_pefile_dependent_tools_without_pefile(tmp_path: Path, tool: ToolName, display_name: str) -> None:
    """Tools whose verification needs ``pefile`` are not downloaded when it is missing.

    Args:
        tmp_path: Pytest temporary directory.
        tool: Tool whose installation is requested.
        display_name: Name the failure message carries for the tool.
    """
    tools = tmp_path / "tools"
    installer = ToolInstaller(tools)
    with _pefile_availability(enabled=False):
        result = _run(installer.install_tool(tool))
    expected = InstallResult(success=False, error=f"Cannot install {display_name} because optional dependency 'pefile' is not available.")
    assert result == expected
    assert not (tools / tool.value).exists()


@pytest.mark.parametrize(
    ("text", "triple", "is_date"),
    [
        ("2024.12.31", (2024, 12, 31), True),
        ("2024.13.05", (2024, 13, 5), False),
        ("2024.00.10", (2024, 0, 10), False),
        ("2024.05.32", (2024, 5, 32), False),
        ("2024.05.00", (2024, 5, 0), False),
        ("1969.06.15", (1969, 6, 15), False),
    ],
)
def test_parse_version_treats_impossible_dates_as_dotted_numbers(text: str, triple: tuple[int, int, int], *, is_date: bool) -> None:
    """A four-digit-year string is a date only when month, day and year are possible.

    Args:
        text: Version text to parse.
        triple: Expected ``(major, minor, patch)``.
        is_date: Whether the text should be recognized as a calendar date.
    """
    version = ToolInstaller.parse_version(text)
    assert version is not None
    assert (version.major, version.minor, version.patch) == triple
    assert version.is_date is is_date
    assert version.raw == text


def test_search_tool_dir_ignores_a_tool_directory_that_is_a_file(tmp_path: Path) -> None:
    """A regular file where the tool directory should be is skipped instead of raising.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tool_path = tmp_path / "cutter"
    tool_path.write_text("not a directory", encoding="utf-8")
    info = ToolInfo(name=ToolName.CUTTER, display_name="Cutter", executables=["cutter.exe"])
    assert _run(ToolInstaller.search_tool_dir(tool_path, info)) is None


def test_x64dbg_notes_fall_through_to_the_next_candidate_when_one_cannot_be_read(tmp_path: Path) -> None:
    """A release-notes file locked by another handle is passed over for the next candidate.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    install.mkdir()
    unreadable = install / "release-notes.md"
    unreadable.write_text("snapshot 2020.01.01\n", encoding="utf-8")
    (tmp_path / "release-notes.md").write_text("snapshot 2023.11.02\n", encoding="utf-8")
    reader: Callable[[Path], ToolVersion | None] = attr(ToolInstaller, "_get_x64dbg_notes_version")
    with _locked_file(unreadable):
        locked = reader(install)
    unlocked = reader(install)
    assert _triple(locked) == (2023, 11, 2)
    assert locked is not None
    assert locked.is_date is True
    assert _triple(unlocked) == (2020, 1, 1)


def test_get_version_for_ghidra_is_none_when_the_properties_file_cannot_be_read(tmp_path: Path) -> None:
    """A locked ``application.properties`` gives no version, and the same file reads once unlocked.

    Args:
        tmp_path: Pytest temporary directory.
    """
    ghidra = tmp_path / "ghidra"
    props = ghidra / "Ghidra" / "application.properties"
    props.parent.mkdir(parents=True)
    props.write_text("application.name=Ghidra\napplication.version=11.2.1\n", encoding="utf-8")
    installer = ToolInstaller(tmp_path / "tools")
    with _locked_file(props):
        locked = _run(installer.get_version(ToolName.GHIDRA, ghidra))
    unlocked = _run(installer.get_version(ToolName.GHIDRA, ghidra))
    assert locked is None
    assert _triple(unlocked) == (11, 2, 1)


def test_install_frida_reports_an_event_loop_whose_executor_has_shut_down(tmp_path: Path) -> None:
    """A ``RuntimeError`` raised while starting pip becomes a failed install result.

    Args:
        tmp_path: Pytest temporary directory.
    """

    async def scenario() -> InstallResult:
        """Shut the loop's default executor down, then ask for a Frida install.

        Returns:
            InstallResult: The installer's result.
        """
        await asyncio.get_running_loop().shutdown_default_executor()
        return await ToolInstaller(tmp_path).install_tool(ToolName.FRIDA)

    result = _run(scenario())
    assert result.success is False
    assert result.kind == "python_package"
    assert result.path is None
    assert result.error is not None
    assert result.error.splitlines()[-1] == "RuntimeError: Executor shutdown has been called"


def test_deploy_reports_a_plugin_target_that_is_a_directory(tmp_path: Path) -> None:
    """A directory squatting on the plugin's file name fails the post-copy check.

    Args:
        tmp_path: Pytest temporary directory.
    """
    x64dbg = tmp_path / "x64dbg"
    source_root = tmp_path / "src"
    plugin_bin = source_root / "x64dbg-plugin" / "bin"
    plugin_bin.mkdir(parents=True)
    (plugin_bin / _PLUGIN_X64).write_bytes(b"x64-plugin")
    (plugin_bin / _PLUGIN_X32).write_bytes(b"x32-plugin")
    squatter = x64dbg / "release" / "x64" / "plugins" / _PLUGIN_X64
    squatter.mkdir(parents=True)
    result = installer_mod.deploy_x64dbg_plugin_detailed(x64dbg, source_root)
    assert result.success is False
    assert [(item.arch, item.status) for item in result.per_arch] == [("x64", "failed"), ("x32", "deployed")]
    assert result.per_arch[0].target == squatter
    assert result.per_arch[0].error == "post-deploy verification: file not found at target"
    assert (x64dbg / "release" / "x32" / "plugins" / _PLUGIN_X32).read_bytes() == b"x32-plugin"


@pytest.mark.usefixtures("short_vswhere_timeout")
def test_find_cmake_gives_up_when_vswhere_hangs(tmp_path: Path, vs_environment: Path) -> None:
    """A vswhere that outlives its timeout is abandoned and no cmake is reported.

    Args:
        tmp_path: Pytest temporary directory.
        vs_environment: Directory standing in for ``%ProgramFiles(x86)%``.
    """
    marker = tmp_path / "started.txt"
    _write_vswhere(vs_environment, _vswhere_source(marker, "", 6))
    assert installer_mod.find_cmake() is None
    assert marker.read_text(encoding="utf-8") == "started"


def test_find_cmake_reports_nothing_when_vswhere_prints_nothing(tmp_path: Path, vs_environment: Path) -> None:
    """A vswhere that finds no installation and prints nothing yields no cmake.

    Args:
        tmp_path: Pytest temporary directory.
        vs_environment: Directory standing in for ``%ProgramFiles(x86)%``.
    """
    marker = tmp_path / "started.txt"
    _write_vswhere(vs_environment, _vswhere_source(marker, "", 0))
    assert installer_mod.find_cmake() is None
    assert marker.read_text(encoding="utf-8") == "started"


def test_find_cmake_reports_nothing_when_the_installation_has_no_bundled_cmake(tmp_path: Path, vs_environment: Path) -> None:
    """An installation path without the bundled cmake yields no cmake.

    Args:
        tmp_path: Pytest temporary directory.
        vs_environment: Directory standing in for ``%ProgramFiles(x86)%``.
    """
    marker = tmp_path / "started.txt"
    vs_root = tmp_path / "VS" / "2022"
    vs_root.mkdir(parents=True)
    _write_vswhere(vs_environment, _vswhere_source(marker, str(vs_root), 0))
    assert installer_mod.find_cmake() is None
    assert marker.read_text(encoding="utf-8") == "started"


def test_find_cmake_returns_the_cmake_bundled_with_visual_studio(tmp_path: Path, vs_environment: Path) -> None:
    """The installation path vswhere prints leads to the cmake inside Visual Studio.

    Args:
        tmp_path: Pytest temporary directory.
        vs_environment: Directory standing in for ``%ProgramFiles(x86)%``.
    """
    marker = tmp_path / "started.txt"
    vs_root = tmp_path / "VS" / "2022"
    bundled = vs_root.joinpath(*_VS_CMAKE_PARTS) / "cmake.exe"
    bundled.parent.mkdir(parents=True)
    bundled.write_bytes(b"MZ")
    _write_vswhere(vs_environment, _vswhere_source(marker, f"{vs_root}\r\n", 0))
    assert installer_mod.find_cmake() == bundled
    assert marker.read_text(encoding="utf-8") == "started"
