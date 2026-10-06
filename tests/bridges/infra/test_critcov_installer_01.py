# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for ``intellicrack.bridges.installer`` (part 1).

The tests drive the real installer against real files and real child processes.
Portable Executables carrying a ``VS_VERSION_INFO`` resource are assembled byte by
byte, release archives are built with :mod:`zipfile`, and the GitHub release API
and asset downloads are served by a loopback HTTP server. A subclass of the real
``httpx`` transport sends every request to that server, so the production
download, extraction and verification code runs end to end. The Frida, pip and
cmake tool paths run real child processes: a stand-in ``pip`` and ``frida`` package
(and a ``cmake.cmd`` batch file) sit in a temporary directory that the child
interpreter finds through its working directory or ``PATH``.
"""

from __future__ import annotations

import asyncio
import io
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx
import pytest

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import (
    TOOL_REGISTRY,
    FoundTool,
    InstallResult,
    ToolInfo,
    ToolInstaller,
    ToolVersion,
)
from intellicrack.core.types import ToolError, ToolName
from tests._helpers.scripted_http_server import ScriptedHttpServer, ScriptedResponse, json_response


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine, Iterator, Sequence


pytestmark = pytest.mark.spawns_process

_SECTION_RVA: Final[int] = 0x1000
_RESOURCE_TREE_SIZE: Final[int] = 88
_RT_VERSION: Final[int] = 16
_DIRECTORY_FLAG: Final[int] = 0x80000000
_GARBAGE_PE: Final[bytes] = b"MZ" + bytes(62)
_CUTTER_ASSET: Final[str] = "Cutter-v2.3.1-Windows-x86_64.zip"
_PROBE_EXE: Final[str] = "critcov_probe_tool.exe"
_FRIDA_IMPORT_ERROR: Final[str] = 'raise ImportError("frida is not installed")\n'
_FRIDA_SLEEPS: Final[str] = 'import time\ntime.sleep(60)\n__version__ = "1.0.0"\n'
_PIP_FAILS: Final[str] = 'import sys\nsys.stderr.write("pip exploded\\n")\nraise SystemExit(3)\n'
_PIP_SUCCEEDS: Final[str] = "pass\n"
_PIP_INSTALLS_FRIDA: Final[str] = (
    "import pathlib\n"
    'target = pathlib.Path("frida")\n'
    "target.mkdir(exist_ok=True)\n"
    '(target / "__init__.py").write_text(\'__version__ = "17.2.1"\\n\')\n'
)
_CMAKE_BATCH: Final[str] = (
    "@echo off\r\n"
    'echo %* >> "%CRITCOV_CMAKE_LOG%"\r\n'
    'if "%~1"=="--help" goto help\r\n'
    'if "%~1"=="--build" goto build\r\n'
    "echo configure output\r\n"
    "echo configure diagnostics 1>&2\r\n"
    'if not "%CRITCOV_CONFIGURE_RC%"=="" exit /b %CRITCOV_CONFIGURE_RC%\r\n'
    "exit /b 0\r\n"
    ":build\r\n"
    'if not "%CRITCOV_BUILD_RC%"=="" exit /b %CRITCOV_BUILD_RC%\r\n'
    "exit /b 0\r\n"
    ":help\r\n"
    "echo Generators\r\n"
    "@@HELP_LINES@@"
    "exit /b 0\r\n"
)
_VS_HELP_LINES: Final[tuple[str, ...]] = (
    "  Visual Studio 16 2019        = Generates Visual Studio 2019 project files.",
    "* Visual Studio 17 2022        = Generates Visual Studio 2022 project files.",
)


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


def _utf16z(text: str) -> bytes:
    """Encode text as NUL-terminated UTF-16.

    Args:
        text: Text to encode.

    Returns:
        bytes: UTF-16LE bytes followed by a two-byte terminator.
    """
    return text.encode("utf-16-le") + b"\x00\x00"


def _pad4(data: bytes) -> bytes:
    """Pad data with zero bytes to a four-byte boundary.

    Args:
        data: Bytes to pad.

    Returns:
        bytes: The padded bytes.
    """
    return data + b"\x00" * (-len(data) % 4)


def _version_node(key: str, value: bytes, value_words: int, node_type: int, children: Sequence[bytes]) -> bytes:
    """Assemble one node of a ``VS_VERSION_INFO`` tree.

    Args:
        key: Node key string.
        value: Raw value bytes, empty for container nodes.
        value_words: Value length field written into the header.
        node_type: ``wType`` field (0 binary, 1 text).
        children: Already assembled child nodes.

    Returns:
        bytes: The node, with its ``wLength`` field filled in.
    """
    body = bytearray(_pad4(struct.pack("<HHH", 0, value_words, node_type) + _utf16z(key)))
    body += value
    if children:
        body = bytearray(_pad4(bytes(body)))
        for child in children[:-1]:
            body += _pad4(child)
        body += children[-1]
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


def _version_blob(version: tuple[int, int, int, int], strings: dict[str, str] | None) -> bytes:
    """Assemble a ``VS_VERSION_INFO`` resource blob.

    Args:
        version: Four-part file version stored in ``VS_FIXEDFILEINFO``.
        strings: Optional ``StringFileInfo`` entries.

    Returns:
        bytes: The resource data.
    """
    major, minor, patch, build = version
    ms = (major << 16) | minor
    ls = (patch << 16) | build
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    children: list[bytes] = []
    if strings:
        entries = [_version_node(key, _utf16z(text), len(text) + 1, 1, ()) for key, text in strings.items()]
        table = _version_node("040904B0", b"", 0, 1, entries)
        children.append(_version_node("StringFileInfo", b"", 0, 1, [table]))
    return _version_node("VS_VERSION_INFO", fixed, len(fixed), 0, children)


def build_pe(version: tuple[int, int, int, int] | None = None, strings: dict[str, str] | None = None) -> bytes:
    """Assemble a PE32+ image, optionally carrying a version resource.

    Args:
        version: Four-part fixed file version; when both arguments are None the
            image has no resource directory at all.
        strings: Optional ``StringFileInfo`` entries.

    Returns:
        bytes: The image bytes.
    """
    content = b""
    resource_size = 0
    if version is not None or strings is not None:
        blob = _version_blob(version or (0, 0, 0, 0), strings)
        header = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
        content = (
            header
            + struct.pack("<II", _RT_VERSION, _DIRECTORY_FLAG | 24)
            + header
            + struct.pack("<II", 1, _DIRECTORY_FLAG | 48)
            + header
            + struct.pack("<II", 0x0409, 72)
            + struct.pack("<IIII", _SECTION_RVA + _RESOURCE_TREE_SIZE, len(blob), 0, 0)
            + blob
        )
        resource_size = len(content)
    raw_size = max(0x200, -(-len(content) // 0x200) * 0x200)
    image_size = 0x1000 + -(-raw_size // 0x1000) * 0x1000
    data_dirs = bytearray(16 * 8)
    if resource_size:
        struct.pack_into("<II", data_dirs, 2 * 8, _SECTION_RVA, resource_size)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        0,
        raw_size,
        0,
        _SECTION_RVA,
        _SECTION_RVA,
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        image_size,
        0x200,
        0,
        3,
        0x100,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    section = struct.pack("<8sIIIIIIHHI", b".rsrc", raw_size, _SECTION_RVA, raw_size, 0x200, 0, 0, 0, 0, 0x40000040)
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + bytes(data_dirs) + section
    return headers.ljust(0x200, b"\x00") + content.ljust(raw_size, b"\x00")


def _write_pe(
    path: Path,
    version: tuple[int, int, int, int] | None = None,
    strings: dict[str, str] | None = None,
) -> Path:
    """Write an assembled PE image to disk, creating parent directories.

    Args:
        path: Destination file.
        version: Fixed file version, or None for an image without resources.
        strings: Optional ``StringFileInfo`` entries.

    Returns:
        Path: The written file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pe(version, strings))
    return path


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    """Build an in-memory zip archive.

    Args:
        members: Archive member name mapped to its contents.

    Returns:
        bytes: The archive bytes.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _cutter_zip(top: str, version: tuple[int, int, int, int]) -> bytes:
    """Build a Cutter-shaped release archive with a versioned ``cutter.exe``.

    Args:
        top: Name of the single top-level directory.
        version: Fixed file version of the contained ``cutter.exe``.

    Returns:
        bytes: The archive bytes.
    """
    return _zip_bytes({f"{top}/cutter.exe": build_pe(version), f"{top}/README.txt": b"readme"})


def _write_package(root: Path, name: str, main_source: str) -> None:
    """Write a stand-in Python package into a directory.

    Args:
        root: Directory that the child interpreter finds through its working directory.
        name: Package name.
        main_source: Source of ``<name>/__init__.py``, or of ``__main__.py`` for ``pip``.
    """
    package = root / name
    package.mkdir(parents=True, exist_ok=True)
    if name == "pip":
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "__main__.py").write_text(main_source, encoding="utf-8")
    else:
        (package / "__init__.py").write_text(main_source, encoding="utf-8")


def _frida_source(version: str) -> str:
    """Return the source of a stand-in ``frida`` package reporting a version.

    Args:
        version: Value of ``frida.__version__``.

    Returns:
        str: Python source text.
    """
    return f'__version__ = "{version}"\n'


class _LoopbackTransport(httpx.AsyncHTTPTransport):
    """Real httpx transport that sends every request to one loopback origin.

    Attributes:
        target: The loopback origin that receives every request.
    """

    target: httpx.URL

    def __init__(self, origin: str) -> None:
        """Remember the loopback origin.

        Args:
            origin: Origin of the loopback server, for example ``http://127.0.0.1:50123``.
        """
        super().__init__()
        self.target = httpx.URL(origin)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Re-aim the request at the loopback origin and send it over a real socket.

        Args:
            request: Request built by the client.

        Returns:
            httpx.Response: The loopback server's response.
        """
        request.url = request.url.copy_with(scheme=self.target.scheme, host=self.target.host, port=self.target.port)
        return await super().handle_async_request(request)


async def _with_loopback[T](installer: ToolInstaller, origin: str, action: Callable[[], Awaitable[T]]) -> T:
    """Run an installer action with its HTTP client routed to a loopback server.

    Args:
        installer: Installer under test.
        origin: Origin of the loopback server.
        action: Zero-argument callable returning the awaitable to run.

    Returns:
        T: The action's result.
    """
    setattr(installer, "_http_client", httpx.AsyncClient(transport=_LoopbackTransport(origin), follow_redirects=True))
    try:
        return await action()
    finally:
        await installer.close()


async def _release_url(installer: ToolInstaller, tool: ToolName) -> str | None:
    """Call the installer's private release-URL lookup.

    Args:
        installer: Installer under test.
        tool: Tool whose release asset to select.

    Returns:
        str | None: The selected download URL, or None.
    """
    method: Callable[[ToolName], Awaitable[str | None]] = attr(installer, "_get_latest_release_url")
    return await method(tool)


def _asset(name: str, origin: str) -> dict[str, object]:
    """Describe one release asset the way the GitHub API does.

    Args:
        name: Asset file name.
        origin: Origin of the loopback server hosting the download.

    Returns:
        dict[str, object]: Asset JSON object.
    """
    return {"name": name, "browser_download_url": f"{origin}/dl/{name}"}


def _serve_release(server: ScriptedHttpServer, repo: str, assets: list[dict[str, object]]) -> None:
    """Script the ``releases/latest`` route of a repository.

    Args:
        server: Loopback server.
        repo: ``owner/name`` of the repository.
        assets: Asset objects to list.
    """
    server.script("GET", f"/repos/{repo}/releases/latest", json_response(200, {"assets": assets}))


def _serve_cutter(server: ScriptedHttpServer, archive: bytes) -> None:
    """Script a Cutter release listing and its archive download.

    Args:
        server: Loopback server.
        archive: Bytes of the Cutter release archive.
    """
    _serve_release(server, "rizinorg/cutter", [_asset(_CUTTER_ASSET, server.origin)])
    server.script(
        "GET",
        f"/dl/{_CUTTER_ASSET}",
        ScriptedResponse(headers=(("content-type", "application/zip"),), chunks=(archive,)),
    )


@pytest.fixture
def server() -> Iterator[ScriptedHttpServer]:
    """Run a loopback HTTP server for one test.

    Yields:
        ScriptedHttpServer: The running server.
    """
    with ScriptedHttpServer() as running:
        yield running


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the Intellicrack state directory at a temporary location.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Path: The ``.intellicrack`` configuration directory the installer reads.
    """
    local = tmp_path / "localappdata"
    state = local / "state"
    config_dir = state / ".intellicrack"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state))
    return config_dir


@pytest.fixture
def download_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the interpreter's temporary directory used for downloads.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Path: The directory that receives downloaded archives.
    """
    directory = tmp_path / "downloads"
    directory.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    return directory


@pytest.fixture
def registry_override() -> Iterator[Callable[[ToolInfo], None]]:
    """Let a test swap tool registry entries and restore them afterwards.

    Yields:
        Callable[[ToolInfo], None]: Function installing a replacement entry.
    """
    saved: dict[ToolName, ToolInfo] = {}

    def apply(info: ToolInfo) -> None:
        """Replace the registry entry of ``info.name``.

        Args:
            info: Replacement entry.
        """
        saved.setdefault(info.name, TOOL_REGISTRY[info.name])
        TOOL_REGISTRY[info.name] = info

    try:
        yield apply
    finally:
        for name, original in saved.items():
            TOOL_REGISTRY[name] = original


@pytest.fixture
def python_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make child interpreters import stand-in packages from a temporary directory.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Path: The working directory every child interpreter starts in.
    """
    root = tmp_path / "pyroot"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    return root


@pytest.fixture
def short_probe_timeout() -> Iterator[None]:
    """Shorten the installer's version-probe timeout to one second.

    Yields:
        None: Control to the test while the short timeout is in force.
    """
    original: int = attr(installer_mod, "_VERSION_PROBE_TIMEOUT_S")
    setattr(installer_mod, "_VERSION_PROBE_TIMEOUT_S", 1)
    try:
        yield
    finally:
        setattr(installer_mod, "_VERSION_PROBE_TIMEOUT_S", original)


def test_tool_version_less_equal_orders_by_triple() -> None:
    """``<=`` compares the (major, minor, patch) triple and accepts equality."""
    assert ToolVersion(1, 2, 3) <= ToolVersion(1, 2, 3)
    assert ToolVersion(1, 2, 3) <= ToolVersion(1, 3, 0)
    assert (ToolVersion(2, 0, 0) <= ToolVersion(1, 9, 9)) is False


def test_tool_version_greater_than_orders_by_triple() -> None:
    """``>`` compares the (major, minor, patch) triple and rejects equality."""
    assert ToolVersion(2, 0, 0) > ToolVersion(1, 9, 9)
    assert (ToolVersion(1, 2, 3) > ToolVersion(1, 2, 3)) is False
    assert (ToolVersion(1, 2, 3) > ToolVersion(1, 2, 4)) is False


def test_env_local_appdata_reflects_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The LOCALAPPDATA helper returns the variable, or None when it is unset.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    reader: Callable[[], str | None] = attr(installer_mod, "_env_local_appdata")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Somewhere\Local")
    assert reader() == r"C:\Somewhere\Local"
    monkeypatch.delenv("LOCALAPPDATA")
    assert reader() is None


def test_default_tools_directory_lives_under_localappdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With LOCALAPPDATA set, tools live in ``%LOCALAPPDATA%/intellicrack_tools``.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    resolver: Callable[[], Path] = attr(installer_mod, "_default_tools_directory")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert resolver() == tmp_path / "intellicrack_tools"


def test_default_tools_directory_falls_back_to_the_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without LOCALAPPDATA, tools live in ``~/.intellicrack_tools``.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    resolver: Callable[[], Path] = attr(installer_mod, "_default_tools_directory")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert resolver() == tmp_path / ".intellicrack_tools"


def test_program_files_x86_prefers_its_variable_then_the_literal_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``ProgramFiles(x86)`` wins; with neither variable the English path is returned.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "x86"))
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "native"))
    assert installer_mod.program_files_x86() == tmp_path / "x86"
    monkeypatch.delenv("PROGRAMFILES(X86)")
    assert installer_mod.program_files_x86() == tmp_path / "native"
    monkeypatch.delenv("PROGRAMFILES")
    assert installer_mod.program_files_x86() == Path(r"C:\Program Files (x86)")


def test_cmake_timeout_ignores_garbage_and_never_drops_below_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-integer value falls back to the default; larger values win, smaller ones do not.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("CRITCOV_CMAKE_TIMEOUT", "not-a-number")
    assert installer_mod.cmake_timeout("CRITCOV_CMAKE_TIMEOUT", 600) == 600
    monkeypatch.setenv("CRITCOV_CMAKE_TIMEOUT", "900")
    assert installer_mod.cmake_timeout("CRITCOV_CMAKE_TIMEOUT", 600) == 900
    monkeypatch.setenv("CRITCOV_CMAKE_TIMEOUT", "5")
    assert installer_mod.cmake_timeout("CRITCOV_CMAKE_TIMEOUT", 600) == 600


def test_module_find_tool_uses_the_given_directory(tmp_path: Path) -> None:
    """The module-level ``find_tool`` builds its installer on the given directory.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools = tmp_path / "tools"
    assert _run(installer_mod.find_tool(ToolName.PROCESS, tools)) is None
    assert tools.is_dir()


def test_module_install_tool_reports_missing_download_url(tmp_path: Path) -> None:
    """The module-level ``install_tool`` returns the installer's failure result.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools = tmp_path / "tools"
    result = _run(installer_mod.install_tool(ToolName.SANDBOX, tools))
    assert result.success is False
    assert result.error == "No download URL configured for Sandbox (QEMU/Docker)"
    assert tools.is_dir()


def test_module_ensure_tool_rejects_a_builtin_tool(tmp_path: Path) -> None:
    """The module-level ``ensure_tool`` raises for a tool without a filesystem path.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools = tmp_path / "tools"
    with pytest.raises(ToolError, match="Process Control is a builtin tool and has no filesystem path"):
        _run(installer_mod.ensure_tool(ToolName.PROCESS, tools))
    assert tools.is_dir()


def test_module_get_version_reads_the_ghidra_version(tmp_path: Path) -> None:
    """The module-level ``get_version`` parses ``application.properties``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    ghidra = tmp_path / "ghidra"
    (ghidra / "Ghidra").mkdir(parents=True)
    (ghidra / "Ghidra" / "application.properties").write_text("application.name=Ghidra\napplication.version=11.2.1\n", encoding="utf-8")
    tools = tmp_path / "tools"
    version = _run(installer_mod.get_version(ToolName.GHIDRA, ghidra, tools))
    assert _triple(version) == (11, 2, 1)
    assert tools.is_dir()


def test_pe_version_comes_from_the_fixed_file_info(tmp_path: Path) -> None:
    """With no string table the four-part version is rebuilt from ``VS_FIXEDFILEINFO``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    reader: Callable[[Path], str | None] = attr(installer_mod, "_read_pe_version_info")
    assert reader(_write_pe(tmp_path / "a.exe", (10, 20, 30, 40))) == "10.20.30.40"
    assert reader(_write_pe(tmp_path / "b.exe", (1, 0, 65535, 7))) == "1.0.65535.7"


def test_pe_version_prefers_file_version_then_product_version(tmp_path: Path) -> None:
    """String-table values win over the fixed info; FileVersion beats ProductVersion.

    Args:
        tmp_path: Pytest temporary directory.
    """
    reader: Callable[[Path], str | None] = attr(installer_mod, "_read_pe_version_info")
    both = _write_pe(tmp_path / "both.exe", (1, 1, 1, 1), {"ProductVersion": "5.5.5.5", "FileVersion": " 4.4.4.4 "})
    product_only = _write_pe(tmp_path / "product.exe", (1, 1, 1, 1), {"ProductVersion": "9.9.9.9 beta"})
    assert reader(both) == "4.4.4.4"
    assert reader(product_only) == "9.9.9.9 beta"


def test_pe_version_falls_back_to_fixed_info_when_strings_lack_version_keys(tmp_path: Path) -> None:
    """A string table without FileVersion or ProductVersion defers to the fixed info.

    Args:
        tmp_path: Pytest temporary directory.
    """
    reader: Callable[[Path], str | None] = attr(installer_mod, "_read_pe_version_info")
    exe = _write_pe(tmp_path / "company.exe", (5, 6, 7, 8), {"CompanyName": "Acme"})
    assert reader(exe) == "5.6.7.8"


def test_pe_version_is_none_for_zero_or_absent_version_resources(tmp_path: Path) -> None:
    """An all-zero fixed version and an image without resources both yield None.

    Args:
        tmp_path: Pytest temporary directory.
    """
    reader: Callable[[Path], str | None] = attr(installer_mod, "_read_pe_version_info")
    assert reader(_write_pe(tmp_path / "zero.exe", (0, 0, 0, 0))) is None
    assert reader(_write_pe(tmp_path / "bare.exe")) is None


def test_get_version_for_cutter_reads_the_pe_resource(tmp_path: Path) -> None:
    """Cutter's version is read from ``cutter.exe`` without launching it.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "cutter"
    _write_pe(install / "cutter.exe", (2, 3, 1, 0))
    version = _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.CUTTER, install))
    assert version is not None
    assert (version.major, version.minor, version.patch, version.raw) == (2, 3, 1, "2.3.1.0")


def test_get_version_for_x64dbg_skips_a_missing_first_executable(tmp_path: Path) -> None:
    """The second registered executable is used when the first one is absent.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    _write_pe(install / "release" / "x32" / "x32dbg.exe", (1, 2, 3, 4))
    assert _triple(_run(ToolInstaller(tmp_path / "tools").get_version(ToolName.X64DBG, install))) == (1, 2, 3)


def test_get_version_for_x64dbg_skips_an_unparseable_version_string(tmp_path: Path) -> None:
    """An executable whose version text has no digits is skipped for the next one.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    _write_pe(install / "release" / "x64" / "x64dbg.exe", (9, 9, 9, 9), {"FileVersion": "unknown build"})
    _write_pe(install / "release" / "x32" / "x32dbg.exe", (4, 5, 6, 7))
    assert _triple(_run(ToolInstaller(tmp_path / "tools").get_version(ToolName.X64DBG, install))) == (4, 5, 6)


def test_get_version_for_x64dbg_reads_the_release_date_from_notes(tmp_path: Path) -> None:
    """A date on a release-notes line becomes a date-style version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    install.mkdir()
    (install / "release-notes.md").write_text("# x64dbg\n\nsnapshot 2024.05.17 build\n", encoding="utf-8")
    version = _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.X64DBG, install))
    assert version is not None
    assert (version.major, version.minor, version.patch, version.is_date) == (2024, 5, 17, True)


def test_x64dbg_release_notes_only_count_the_first_ten_lines(tmp_path: Path) -> None:
    """A date beyond line ten is ignored and the PE version is used instead.

    Args:
        tmp_path: Pytest temporary directory.
    """
    install = tmp_path / "x64dbg"
    _write_pe(install / "release" / "x32" / "x32dbg.exe", (3, 1, 4, 1))
    lines = [f"note line {index}" for index in range(10)] + ["released 2024.01.15"]
    (install / "release-notes.md").write_text("\n".join(lines), encoding="utf-8")
    assert _triple(_run(ToolInstaller(tmp_path / "tools").get_version(ToolName.X64DBG, install))) == (3, 1, 4)


def test_get_version_for_ghidra_without_properties_is_none(tmp_path: Path) -> None:
    """A Ghidra tree without ``application.properties`` has no version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    ghidra = tmp_path / "ghidra"
    ghidra.mkdir()
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.GHIDRA, ghidra)) is None


def test_get_version_for_ghidra_without_a_version_key_is_none(tmp_path: Path) -> None:
    """A properties file lacking ``application.version`` yields no version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    ghidra = tmp_path / "ghidra"
    (ghidra / "Ghidra").mkdir(parents=True)
    (ghidra / "Ghidra" / "application.properties").write_text("application.name=Ghidra\napplication.layout.version=2\n", encoding="utf-8")
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.GHIDRA, ghidra)) is None


def test_get_version_unknown_builtin_and_pathless_cases(tmp_path: Path) -> None:
    """Unknown tools, builtin tools and filesystem tools without a path have no version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path / "tools")
    assert _run(installer.get_version(ToolName.TOOLS, tmp_path)) is None
    assert _run(installer.get_version(ToolName.PROCESS, tmp_path)) is None
    assert _run(installer.get_version(ToolName.GHIDRA, None)) is None


def test_get_version_without_a_version_command_is_none(tmp_path: Path) -> None:
    """A filesystem tool that registers no version command has no version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.SANDBOX, tmp_path)) is None


def test_get_version_runs_the_registered_version_command(tmp_path: Path, registry_override: Callable[[ToolInfo], None]) -> None:
    """A registered version command runs in the install directory and is parsed.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    registry_override(ToolInfo(name=ToolName.SANDBOX, display_name="Probe", version_command=["cmd.exe", "/c", "echo", "7.8.9"]))
    assert _triple(_run(ToolInstaller(tmp_path / "tools").get_version(ToolName.SANDBOX, tmp_path))) == (7, 8, 9)


def test_get_version_is_none_when_the_version_command_fails(tmp_path: Path, registry_override: Callable[[ToolInfo], None]) -> None:
    """A version command that exits non-zero yields no version.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    registry_override(ToolInfo(name=ToolName.SANDBOX, display_name="Probe", version_command=["cmd.exe", "/c", "exit", "3"]))
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.SANDBOX, tmp_path)) is None


def test_get_version_is_none_when_the_version_command_cannot_start(tmp_path: Path, registry_override: Callable[[ToolInfo], None]) -> None:
    """A version command that does not exist is reported as no version, not an error.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    registry_override(ToolInfo(name=ToolName.SANDBOX, display_name="Probe", version_command=["critcov-no-such-binary.exe"]))
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.SANDBOX, tmp_path)) is None


def test_get_version_for_frida_reads_the_package_version(python_root: Path, tmp_path: Path) -> None:
    """The Frida version comes from a child interpreter importing the package.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _frida_source("17.2.1"))
    assert _triple(_run(ToolInstaller(tmp_path / "tools").get_version(ToolName.FRIDA, None))) == (17, 2, 1)


@pytest.mark.usefixtures("short_probe_timeout")
def test_get_version_for_frida_is_none_when_the_probe_times_out(python_root: Path, tmp_path: Path) -> None:
    """A hung interpreter during the Frida probe is reported as no version.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _FRIDA_SLEEPS)
    assert _run(ToolInstaller(tmp_path / "tools").get_version(ToolName.FRIDA, None)) is None


def test_probe_python_package_without_a_command_is_none(tmp_path: Path) -> None:
    """A package entry with no version command cannot be probed.

    Args:
        tmp_path: Pytest temporary directory.
    """
    info = ToolInfo(name=ToolName.FRIDA, display_name="Nothing", kind="python_package")
    assert _run(ToolInstaller(tmp_path).probe_python_package(info)) is None


def test_probe_python_package_with_unparseable_output_is_none(tmp_path: Path) -> None:
    """Probe output without a version number yields no version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    info = ToolInfo(
        name=ToolName.FRIDA,
        display_name="Odd",
        version_command=[sys.executable, "-c", "print('not-a-version')"],
        kind="python_package",
    )
    assert _run(ToolInstaller(tmp_path).probe_python_package(info)) is None


def test_find_tool_detailed_unknown_tool_is_none(tmp_path: Path) -> None:
    """A tool without a registry entry is not found.

    Args:
        tmp_path: Pytest temporary directory.
    """
    assert _run(ToolInstaller(tmp_path).find_tool_detailed(ToolName.TOOLS)) is None


def test_find_tool_detailed_frida_with_unparseable_version_is_none(python_root: Path, tmp_path: Path) -> None:
    """Frida is not reported present when its version output cannot be parsed.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _frida_source("unknown"))
    assert _run(ToolInstaller(tmp_path).find_tool_detailed(ToolName.FRIDA)) is None


@pytest.mark.usefixtures("isolated_state")
def test_find_tool_detailed_skips_common_paths_without_the_executable(
    tmp_path: Path,
    registry_override: Callable[[ToolInfo], None],
) -> None:
    """A common path that exists but lacks the executable is passed over for the next.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    good = tmp_path / "good"
    good.mkdir()
    (good / _PROBE_EXE).write_bytes(b"MZ")
    registry_override(
        ToolInfo(
            name=ToolName.CUTTER,
            display_name="Probe",
            common_paths=[tmp_path / "missing", empty, good],
            executables=[_PROBE_EXE],
        ),
    )
    found = _run(ToolInstaller(tmp_path / "tools").find_tool_detailed(ToolName.CUTTER))
    assert found == FoundTool(kind="filesystem", path=good)


@pytest.mark.usefixtures("isolated_state")
def test_find_tool_detailed_locates_an_executable_on_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    registry_override: Callable[[ToolInfo], None],
) -> None:
    """With no common path or override, the PATH directory holding the executable is reported.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
        registry_override: Fixture that swaps registry entries.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / _PROBE_EXE).write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(bin_dir))
    registry_override(ToolInfo(name=ToolName.CUTTER, display_name="Probe", executables=[_PROBE_EXE]))
    found = _run(ToolInstaller(tmp_path / "tools").find_tool_detailed(ToolName.CUTTER))
    assert found is not None
    assert found.kind == "filesystem"
    assert found.path is not None
    assert found.path.samefile(bin_dir)


@pytest.mark.parametrize("layers", [("a",), ("a", "b"), ("a", "b", "c")])
def test_search_tool_dir_gives_up_without_a_match(tmp_path: Path, layers: tuple[str, ...]) -> None:
    """A tree without the executable yields None at every depth.

    Args:
        tmp_path: Pytest temporary directory.
        layers: Nested directory names to create below the tool directory.
    """
    tool_dir = tmp_path / "tool"
    tool_dir.joinpath(*layers).mkdir(parents=True)
    info = ToolInfo(name=ToolName.CUTTER, display_name="Cutter", executables=["cutter.exe"])
    assert _run(ToolInstaller.search_tool_dir(tool_dir, info)) is None


def test_search_tool_dir_with_no_subdirectories_is_none(tmp_path: Path) -> None:
    """A tool directory holding only files is exhausted after one level.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tool_dir = tmp_path / "tool"
    tool_dir.mkdir()
    (tool_dir / "notes.txt").write_text("x", encoding="utf-8")
    info = ToolInfo(name=ToolName.CUTTER, display_name="Cutter", executables=["cutter.exe"])
    assert _run(ToolInstaller.search_tool_dir(tool_dir, info)) is None


def test_search_tool_dir_stops_two_levels_below_the_root(tmp_path: Path) -> None:
    """An executable two directories down is found; one three down is not.

    Args:
        tmp_path: Pytest temporary directory.
    """
    info = ToolInfo(name=ToolName.CUTTER, display_name="Cutter", executables=["cutter.exe"])
    shallow = tmp_path / "shallow"
    (shallow / "a" / "b").mkdir(parents=True)
    (shallow / "a" / "b" / "cutter.exe").write_bytes(b"MZ")
    deep = tmp_path / "deep"
    (deep / "a" / "b" / "c").mkdir(parents=True)
    (deep / "a" / "b" / "c" / "cutter.exe").write_bytes(b"MZ")
    assert _run(ToolInstaller.search_tool_dir(shallow, info)) == shallow / "a" / "b"
    assert _run(ToolInstaller.search_tool_dir(deep, info)) is None


@pytest.mark.parametrize(
    "content",
    ["{ this is not json", "[1, 2, 3]", '{"cutter": "C:/just/a/string"}'],
)
def test_configured_tool_path_ignores_unusable_config(isolated_state: Path, content: str) -> None:
    """Malformed JSON, a non-object root and a non-object entry all mean no override.

    Args:
        isolated_state: The ``.intellicrack`` directory the installer reads.
        content: Text written to ``tools.json``.
    """
    (isolated_state / "tools.json").write_text(content, encoding="utf-8")
    reader: Callable[[ToolName], Path | None] = attr(installer_mod, "_read_configured_tool_path")
    assert reader(ToolName.CUTTER) is None


def test_configured_tool_path_reads_a_valid_entry(isolated_state: Path) -> None:
    """A well-formed entry returns its trimmed path, proving the cases above are rejections.

    Args:
        isolated_state: The ``.intellicrack`` directory the installer reads.
    """
    (isolated_state / "tools.json").write_text('{"cutter": {"path": "  C:/Tools/MyCutter  "}}', encoding="utf-8")
    reader: Callable[[ToolName], Path | None] = attr(installer_mod, "_read_configured_tool_path")
    assert reader(ToolName.CUTTER) == Path("C:/Tools/MyCutter")


def test_http_client_is_created_once_and_closed(tmp_path: Path) -> None:
    """The lazy HTTP client is created on first use, reused, and dropped by ``close``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path)

    async def scenario() -> tuple[httpx.AsyncClient, httpx.AsyncClient, bool, object]:
        """Create the client twice, close the installer and report its state.

        Returns:
            tuple[httpx.AsyncClient, httpx.AsyncClient, bool, object]: Both clients,
            whether the first is closed, and the installer's client slot afterwards.
        """
        get_client: Callable[[], Awaitable[httpx.AsyncClient]] = attr(installer, "_get_client")
        first = await get_client()
        second = await get_client()
        await installer.close()
        return first, second, first.is_closed, attr(installer, "_http_client")

    first, second, closed, slot = _run(scenario())
    assert first is second
    assert first.follow_redirects is True
    assert first.timeout == httpx.Timeout(60.0)
    assert closed is True
    assert slot is None


def test_close_without_a_client_is_a_no_op(tmp_path: Path) -> None:
    """Closing an installer that never made a request leaves it without a client.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path)
    _run(installer.close())
    assert attr(installer, "_http_client") is None


def test_verify_tool_unknown_or_without_path_is_false(tmp_path: Path) -> None:
    """Unknown tools and filesystem tools without an install path do not verify.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path)
    assert _run(installer.verify_tool(ToolName.TOOLS, tmp_path)) is False
    assert _run(installer.verify_tool(ToolName.GHIDRA, None)) is False


def test_verify_tool_requires_an_executable_under_the_path(tmp_path: Path) -> None:
    """A directory with none of the registered executables does not verify.

    Args:
        tmp_path: Pytest temporary directory.
    """
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.SANDBOX, tmp_path)) is False


def test_verify_tool_accepts_any_registered_executable_without_a_version_floor(tmp_path: Path) -> None:
    """The second registered executable suffices for a tool that sets no minimum version.

    Args:
        tmp_path: Pytest temporary directory.
    """
    (tmp_path / "qemu-system-i386.exe").write_bytes(b"MZ")
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.SANDBOX, tmp_path)) is True


def test_verify_tool_rejects_an_unreadable_version_when_a_floor_is_set(tmp_path: Path) -> None:
    """A Cutter whose version cannot be read fails verification, since Cutter has a floor.

    Args:
        tmp_path: Pytest temporary directory.
    """
    (tmp_path / "cutter.exe").write_bytes(_GARBAGE_PE)
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.CUTTER, tmp_path)) is False


def test_verify_tool_enforces_the_minimum_version(tmp_path: Path) -> None:
    """Cutter passes at the minimum version and fails just below it.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path / "tools")
    old = tmp_path / "old"
    exact = tmp_path / "exact"
    _write_pe(old / "cutter.exe", (2, 2, 9, 0))
    _write_pe(exact / "cutter.exe", (2, 3, 0, 0))
    assert _run(installer.verify_tool(ToolName.CUTTER, old)) is False
    assert _run(installer.verify_tool(ToolName.CUTTER, exact)) is True


def test_verify_tool_for_frida_rejects_a_version_below_the_floor(python_root: Path, tmp_path: Path) -> None:
    """Frida 15.9.9 is below the 16.0.0 floor and does not verify.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _frida_source("15.9.9"))
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.FRIDA, None)) is False


def test_verify_tool_for_frida_accepts_the_floor_itself(python_root: Path, tmp_path: Path) -> None:
    """Frida 16.0.0 equals the floor and verifies.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _frida_source("16.0.0"))
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.FRIDA, None)) is True


def test_verify_tool_for_frida_is_false_for_unparseable_version(python_root: Path, tmp_path: Path) -> None:
    """Frida does not verify when its version output has no version number.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _frida_source("unknown"))
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.FRIDA, None)) is False


@pytest.mark.usefixtures("short_probe_timeout")
def test_verify_tool_for_frida_is_false_when_the_probe_times_out(python_root: Path, tmp_path: Path) -> None:
    """A hung interpreter during verification fails verification instead of raising.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _FRIDA_SLEEPS)
    assert _run(ToolInstaller(tmp_path / "tools").verify_tool(ToolName.FRIDA, None)) is False


def test_meets_min_version_handles_missing_and_unparseable_floors() -> None:
    """No floor always passes; an unparseable floor fails; equality passes."""
    check: Callable[[ToolVersion, ToolInfo], bool] = attr(ToolInstaller, "_meets_min_version")
    version = ToolVersion(1, 2, 3)
    assert check(version, ToolInfo(name=ToolName.CUTTER, display_name="NoFloor")) is True
    assert check(version, ToolInfo(name=ToolName.CUTTER, display_name="Bad", min_version="abc")) is False
    assert check(version, ToolInfo(name=ToolName.CUTTER, display_name="Exact", min_version="1.2.3")) is True
    assert check(version, ToolInfo(name=ToolName.CUTTER, display_name="Higher", min_version="1.2.4")) is False


def test_install_tool_unknown_tool_fails(tmp_path: Path) -> None:
    """Installing a tool without a registry entry reports an unknown tool.

    Args:
        tmp_path: Pytest temporary directory.
    """
    result = _run(ToolInstaller(tmp_path).install_tool(ToolName.TOOLS))
    assert result == InstallResult(success=False, error=f"Unknown tool: {ToolName.TOOLS}")


def test_install_tool_without_a_download_url_fails(tmp_path: Path) -> None:
    """A filesystem tool with no download URL cannot be installed.

    Args:
        tmp_path: Pytest temporary directory.
    """
    result = _run(ToolInstaller(tmp_path).install_tool(ToolName.SANDBOX))
    assert result.success is False
    assert result.error == "No download URL configured for Sandbox (QEMU/Docker)"


def test_install_frida_reports_a_failing_pip(python_root: Path, tmp_path: Path) -> None:
    """A pip run that exits non-zero is reported with its exit code and stderr.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "pip", _PIP_FAILS)
    result = _run(ToolInstaller(tmp_path).install_tool(ToolName.FRIDA))
    assert result.success is False
    assert result.kind == "python_package"
    assert result.path is None
    assert result.error == "pip install failed (rc=3): pip exploded"


@pytest.mark.usefixtures("short_probe_timeout")
def test_install_frida_reports_a_hung_post_install_probe(python_root: Path, tmp_path: Path) -> None:
    """A post-install probe that hangs is reported as a timeout.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "pip", _PIP_SUCCEEDS)
    _write_package(python_root, "frida", _FRIDA_SLEEPS)
    result = _run(ToolInstaller(tmp_path).install_tool(ToolName.FRIDA))
    assert result.success is False
    assert result.kind == "python_package"
    assert result.error == "frida version probe timed out after install"


def test_install_frida_reports_an_unparseable_post_install_version(python_root: Path, tmp_path: Path) -> None:
    """A post-install probe printing no version number fails the install.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "pip", _PIP_SUCCEEDS)
    _write_package(python_root, "frida", _frida_source("unknown"))
    result = _run(ToolInstaller(tmp_path).install_tool(ToolName.FRIDA))
    assert result.success is False
    assert result.error == "frida installed but version probe returned unparseable output: 'unknown'"


def test_ensure_tool_unknown_tool_raises(tmp_path: Path) -> None:
    """Ensuring a tool without a registry entry raises ``ToolError``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    with pytest.raises(ToolError, match=f"Unknown tool: {ToolName.TOOLS}"):
        _run(ToolInstaller(tmp_path).ensure_tool(ToolName.TOOLS))


def test_ensure_tool_builtin_tool_has_no_path(tmp_path: Path) -> None:
    """A builtin tool is available but has no filesystem path to return.

    Args:
        tmp_path: Pytest temporary directory.
    """
    with pytest.raises(ToolError, match="Process Control is a builtin tool and has no filesystem path") as excinfo:
        _run(ToolInstaller(tmp_path).ensure_tool(ToolName.PROCESS))
    assert excinfo.value.tool_name == "process"


def test_ensure_tool_reports_a_failed_python_package_install(python_root: Path, tmp_path: Path) -> None:
    """A missing Frida whose install fails raises with the install error.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _FRIDA_IMPORT_ERROR)
    _write_package(python_root, "pip", _PIP_FAILS)
    with pytest.raises(ToolError, match=r"failed to ensure tool: Frida: pip install failed \(rc=3\): pip exploded") as excinfo:
        _run(ToolInstaller(tmp_path).ensure_tool(ToolName.FRIDA))
    assert excinfo.value.tool_name == "frida"


def test_ensure_tool_installs_a_missing_python_package_but_has_no_path(python_root: Path, tmp_path: Path) -> None:
    """After a successful Frida install, ensure still raises because there is no path.

    Args:
        python_root: Directory the child interpreter imports stand-in packages from.
        tmp_path: Pytest temporary directory.
    """
    _write_package(python_root, "frida", _FRIDA_IMPORT_ERROR)
    _write_package(python_root, "pip", _PIP_INSTALLS_FRIDA)
    with pytest.raises(ToolError, match="Frida is a python_package tool and has no filesystem path"):
        _run(ToolInstaller(tmp_path).ensure_tool(ToolName.FRIDA))
    assert (python_root / "frida" / "__init__.py").read_text(encoding="utf-8") == '__version__ = "17.2.1"\n'


@pytest.mark.usefixtures("isolated_state")
def test_ensure_tool_returns_an_installed_tool_that_verifies(tmp_path: Path) -> None:
    """A tool already in the tools directory at a good version is returned without a download.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools = tmp_path / "tools"
    _write_pe(tools / "cutter" / "cutter.exe", (2, 5, 0, 0))
    assert _run(ToolInstaller(tools).ensure_tool(ToolName.CUTTER)) == tools / "cutter"


@pytest.mark.usefixtures("isolated_state", "download_dir")
def test_ensure_tool_reinstalls_a_tool_whose_version_is_too_old(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """An outdated Cutter is replaced by the release served from the loopback server.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    tools = tmp_path / "tools"
    _write_pe(tools / "cutter" / "cutter.exe", (1, 0, 0, 0))
    _serve_cutter(server, _cutter_zip("Cutter-v2.4.0-Windows-x86_64", (2, 4, 0, 0)))
    installer = ToolInstaller(tools)
    path = _run(_with_loopback(installer, server.origin, lambda: installer.ensure_tool(ToolName.CUTTER)))
    assert path == tools / "cutter" / "Cutter-v2.4.0-Windows-x86_64"
    assert (path / "cutter.exe").read_bytes() == build_pe((2, 4, 0, 0))
    assert len(server.requests(f"/dl/{_CUTTER_ASSET}")) == 1


@pytest.mark.usefixtures("isolated_state")
def test_install_cutter_downloads_extracts_and_verifies(tmp_path: Path, download_dir: Path, server: ScriptedHttpServer) -> None:
    """A Cutter release is downloaded, unpacked, version-checked and the temp archive removed.

    Args:
        tmp_path: Pytest temporary directory.
        download_dir: Directory receiving downloaded archives.
        server: Loopback HTTP server.
    """
    _serve_cutter(server, _cutter_zip("Cutter-v2.3.1-Windows-x86_64", (2, 3, 1, 0)))
    installer = ToolInstaller(tmp_path / "tools")
    result = _run(_with_loopback(installer, server.origin, lambda: installer.install_tool(ToolName.CUTTER)))
    assert result.success is True
    assert result.error is None
    assert result.path == tmp_path / "tools" / "cutter" / "Cutter-v2.3.1-Windows-x86_64"
    assert _triple(result.version) == (2, 3, 1)
    assert not (download_dir / _CUTTER_ASSET).exists()


@pytest.mark.usefixtures("isolated_state", "download_dir")
def test_install_cutter_rejects_a_version_below_the_minimum(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """A downloaded Cutter older than 2.3.0 is reported as below the minimum.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    _serve_cutter(server, _cutter_zip("Cutter-v1.9.0-Windows-x86_64", (1, 9, 0, 0)))
    installer = ToolInstaller(tmp_path / "tools")
    result = _run(_with_loopback(installer, server.origin, lambda: installer.install_tool(ToolName.CUTTER)))
    assert result.success is False
    assert result.error == "installed version 1.9.0 below minimum 2.3.0 for Cutter"
    assert _triple(result.version) == (1, 9, 0)


@pytest.mark.usefixtures("isolated_state", "download_dir")
def test_install_cutter_from_an_empty_archive_reports_no_usable_directory(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """An archive with no members is not a successful install.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    _serve_cutter(server, _zip_bytes({}))
    installer = ToolInstaller(tmp_path / "tools")
    result = _run(_with_loopback(installer, server.origin, lambda: installer.install_tool(ToolName.CUTTER)))
    assert result.success is False
    assert result.error == "archive extracted no usable directory for Cutter"


def test_release_url_is_none_for_tools_without_a_download_url(tmp_path: Path) -> None:
    """Unknown tools and tools without a download URL have no release URL.

    Args:
        tmp_path: Pytest temporary directory.
    """
    installer = ToolInstaller(tmp_path)
    assert _run(_release_url(installer, ToolName.TOOLS)) is None
    assert _run(_release_url(installer, ToolName.SANDBOX)) is None


def test_release_url_for_a_non_github_download_url_is_returned_unchanged(
    tmp_path: Path,
    registry_override: Callable[[ToolInfo], None],
) -> None:
    """A download URL outside GitHub is used as is, with no API lookup.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    registry_override(ToolInfo(name=ToolName.CUTTER, display_name="Mirror", download_url="http://127.0.0.1:9/mirror/cutter.zip"))
    assert _run(_release_url(ToolInstaller(tmp_path), ToolName.CUTTER)) == "http://127.0.0.1:9/mirror/cutter.zip"


def test_release_url_for_a_repository_less_github_url_is_none(
    tmp_path: Path,
    registry_override: Callable[[ToolInfo], None],
) -> None:
    """A GitHub URL naming only an owner cannot be turned into an API request.

    Args:
        tmp_path: Pytest temporary directory.
        registry_override: Fixture that swaps registry entries.
    """
    registry_override(ToolInfo(name=ToolName.CUTTER, display_name="Owner", download_url="https://github.com/onlyowner"))
    assert _run(_release_url(ToolInstaller(tmp_path), ToolName.CUTTER)) is None


def test_release_url_for_ghidra_picks_the_public_zip(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """Of several assets, only a zip named ``public`` is chosen for Ghidra.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    broken: dict[str, object] = {"name": "ghidra_broken.zip", "browser_download_url": None}
    assets = [
        broken,
        _asset("ghidra_11.2.1_src.zip", server.origin),
        _asset("ghidra_notes.txt", server.origin),
        _asset("ghidra_11.2.1_PUBLIC_20241105.zip", server.origin),
    ]
    _serve_release(server, "NationalSecurityAgency/ghidra", assets)
    installer = ToolInstaller(tmp_path)
    url = _run(_with_loopback(installer, server.origin, lambda: _release_url(installer, ToolName.GHIDRA)))
    assert url == f"{server.origin}/dl/ghidra_11.2.1_PUBLIC_20241105.zip"


def test_release_url_for_x64dbg_picks_the_snapshot_zip(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """Of several assets, only a zip named ``snapshot`` is chosen for x64dbg.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    assets = [_asset("x64dbg-extras.zip", server.origin), _asset("snapshot_2024-12-01_10-00.zip", server.origin)]
    _serve_release(server, "x64dbg/x64dbg", assets)
    installer = ToolInstaller(tmp_path)
    url = _run(_with_loopback(installer, server.origin, lambda: _release_url(installer, ToolName.X64DBG)))
    assert url == f"{server.origin}/dl/snapshot_2024-12-01_10-00.zip"


def test_release_url_for_cutter_picks_the_host_architecture(tmp_path: Path, server: ScriptedHttpServer) -> None:
    """Only Windows zips are candidates, and the one matching the x86-64 host wins.

    Args:
        tmp_path: Pytest temporary directory.
        server: Loopback HTTP server.
    """
    assets = [
        _asset("Cutter-v2.3.1-Linux-x86_64.zip", server.origin),
        _asset("Cutter-v2.3.1-Windows-arm64.zip", server.origin),
        _asset("Cutter-v2.3.1-Windows-x86_64.zip", server.origin),
    ]
    _serve_release(server, "rizinorg/cutter", assets)
    installer = ToolInstaller(tmp_path)
    url = _run(_with_loopback(installer, server.origin, lambda: _release_url(installer, ToolName.CUTTER)))
    assert url == f"{server.origin}/dl/Cutter-v2.3.1-Windows-x86_64.zip"


def test_extract_archive_rejects_a_non_zip_suffix(tmp_path: Path) -> None:
    """Only ``.zip`` archives are supported.

    Args:
        tmp_path: Pytest temporary directory.
    """
    archive = tmp_path / "tool.7z"
    archive.write_bytes(b"7z")
    with pytest.raises(ToolError, match="unsupported archive format"):
        _run(ToolInstaller(tmp_path / "tools").extract_archive(archive, ToolName.CUTTER))


def test_extract_archive_wraps_a_corrupt_zip(tmp_path: Path) -> None:
    """A file that is not a zip archive raises ``ToolError`` caused by ``BadZipFile``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"this is not a zip archive")
    with pytest.raises(ToolError, match="failed to extract archive") as excinfo:
        _run(ToolInstaller(tmp_path / "tools").extract_archive(archive, ToolName.CUTTER))
    assert isinstance(excinfo.value.__cause__, zipfile.BadZipFile)


def test_extract_archive_with_only_files_returns_the_tool_directory(tmp_path: Path) -> None:
    """An archive without sub-directories is unpacked straight into the tool directory.

    Args:
        tmp_path: Pytest temporary directory.
    """
    archive = tmp_path / "flat.zip"
    archive.write_bytes(_zip_bytes({"cutter.exe": b"MZ-flat", "readme.txt": b"hello"}))
    result = _run(ToolInstaller(tmp_path / "tools").extract_archive(archive, ToolName.CUTTER))
    assert result == tmp_path / "tools" / "cutter"
    assert (tmp_path / "tools" / "cutter" / "cutter.exe").read_bytes() == b"MZ-flat"


def test_extract_archive_tolerates_empty_and_dot_path_components(tmp_path: Path) -> None:
    """Members named ``/``, ``a//b`` and ``./c`` unpack to the expected files.

    Args:
        tmp_path: Pytest temporary directory.
    """
    archive = tmp_path / "odd.zip"
    archive.write_bytes(_zip_bytes({"/": b"", "pkg//data.bin": b"payload", "./notes.txt": b"notes"}))
    result = _run(ToolInstaller(tmp_path / "tools").extract_archive(archive, ToolName.CUTTER))
    tool_dir = tmp_path / "tools" / "cutter"
    assert result == tool_dir / "pkg"
    assert (tool_dir / "pkg" / "data.bin").read_bytes() == b"payload"
    assert (tool_dir / "notes.txt").read_bytes() == b"notes"


def test_find_cmake_survives_an_unrunnable_vswhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A vswhere that cannot be started is reported as no cmake.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()
    program_files = tmp_path / "pf86"
    vswhere = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    vswhere.parent.mkdir(parents=True)
    vswhere.write_bytes(_GARBAGE_PE)
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(program_files))
    assert installer_mod.find_cmake() is None


def test_detect_vs_generator_survives_an_unrunnable_cmake(tmp_path: Path) -> None:
    """A cmake executable that cannot be started yields no generator.

    Args:
        tmp_path: Pytest temporary directory.
    """
    broken = tmp_path / "cmake.exe"
    broken.write_bytes(_GARBAGE_PE)
    detect: Callable[[Path], str | None] = attr(installer_mod, "_detect_vs_generator")
    assert detect(broken) is None


def _install_fake_cmake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, help_lines: Sequence[str]) -> Path:
    """Put a batch-file ``cmake`` on PATH and point the build at a plugin tree and SDK.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
        help_lines: Lines the fake cmake prints under ``--help``.

    Returns:
        Path: The file the fake cmake appends each invocation's arguments to.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    echoed = "".join(f"echo {line}\r\n" for line in help_lines)
    (bin_dir / "cmake.cmd").write_text(_CMAKE_BATCH.replace("@@HELP_LINES@@", echoed), encoding="utf-8", newline="")
    log = tmp_path / "cmake.log"
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("CRITCOV_CMAKE_LOG", str(log))
    sdk = tmp_path / "x64dbg" / "pluginsdk"
    sdk.mkdir(parents=True)
    (sdk / "bridgemain.h").write_text("", encoding="utf-8")
    (tmp_path / "plugin").mkdir()
    return log


def test_build_plugin_without_cmake_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no cmake on PATH and no Visual Studio installer, nothing is built.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "pf86"))
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    assert installer_mod.build_x64dbg_plugin(plugin, tmp_path / "x64dbg") is False
    assert not (plugin / "build_x64").exists()


def test_build_plugin_without_a_visual_studio_generator_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cmake that lists no Visual Studio generator cannot build the plugin.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    log = _install_fake_cmake(tmp_path, monkeypatch, ["  Ninja = Generates build.ninja files."])
    assert installer_mod.build_x64dbg_plugin(tmp_path / "plugin", tmp_path / "x64dbg") is False
    assert log.read_text(encoding="utf-8").split() == ["--help"]
    assert not (tmp_path / "plugin" / "build_x64").exists()


def test_build_plugin_stops_each_arch_when_configure_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing configure step skips the build step for both architectures.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    log = _install_fake_cmake(tmp_path, monkeypatch, _VS_HELP_LINES)
    monkeypatch.setenv("CRITCOV_CONFIGURE_RC", "1")
    assert installer_mod.build_x64dbg_plugin(tmp_path / "plugin", tmp_path / "x64dbg") is False
    calls = log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 3
    assert not any("--build" in call for call in calls)
    assert (tmp_path / "plugin" / "build_x64").is_dir()
    assert (tmp_path / "plugin" / "build_x32").is_dir()


def test_build_plugin_reports_failure_when_every_build_step_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both architectures configure, both builds fail, and nothing is reported built.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    log = _install_fake_cmake(tmp_path, monkeypatch, _VS_HELP_LINES)
    monkeypatch.setenv("CRITCOV_BUILD_RC", "2")
    assert installer_mod.build_x64dbg_plugin(tmp_path / "plugin", tmp_path / "x64dbg") is False
    calls = log.read_text(encoding="utf-8").splitlines()
    assert sum("--build" in call for call in calls) == 2


def test_build_plugin_uses_the_newest_generator_for_each_arch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean run configures x64 and Win32 with the highest Visual Studio generator.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    log = _install_fake_cmake(tmp_path, monkeypatch, _VS_HELP_LINES)
    assert installer_mod.build_x64dbg_plugin(tmp_path / "plugin", tmp_path / "x64dbg") is True
    configures = [call for call in log.read_text(encoding="utf-8").splitlines() if "-G" in call]
    assert len(configures) == 2
    assert all('-G "Visual Studio 17 2022"' in call for call in configures)
    assert "-A x64" in configures[0]
    assert "-A Win32" in configures[1]


def test_run_cmake_step_logs_output_and_succeeds(tmp_path: Path) -> None:
    """A step that exits cleanly with output on both streams succeeds.

    Args:
        tmp_path: Pytest temporary directory.
    """
    command = [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"]
    assert installer_mod.run_cmake_step(command, cwd=tmp_path, timeout_s=60, arch="x64", phase="configure") is True


def test_run_cmake_step_times_out(tmp_path: Path) -> None:
    """A step that outlives its timeout is killed and reported as failed.

    Args:
        tmp_path: Pytest temporary directory.
    """
    command = [sys.executable, "-c", "import time; time.sleep(60)"]
    assert installer_mod.run_cmake_step(command, cwd=tmp_path, timeout_s=1, arch="x64", phase="build") is False


def test_run_cmake_step_reports_an_unstartable_command(tmp_path: Path) -> None:
    """A step whose executable does not exist fails instead of raising.

    Args:
        tmp_path: Pytest temporary directory.
    """
    command = [str(tmp_path / "missing-cmake.exe"), "--version"]
    assert installer_mod.run_cmake_step(command, cwd=tmp_path, timeout_s=60, arch="x32", phase="configure") is False


def test_deploy_into_program_files_depends_on_administrator_rights(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Deploying under ``%ProgramFiles%`` is refused without elevation and succeeds with it.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    program_files = tmp_path / "Program Files"
    monkeypatch.setenv("PROGRAMFILES", str(program_files))
    x64dbg = program_files / "x64dbg"
    x64dbg.mkdir(parents=True)
    source_root = tmp_path / "src"
    plugin_bin = source_root / "x64dbg-plugin" / "bin"
    plugin_bin.mkdir(parents=True)
    (plugin_bin / "intellicrack_bridge_x64.dp64").write_bytes(b"x64-plugin")
    (plugin_bin / "intellicrack_bridge_x32.dp32").write_bytes(b"x32-plugin")
    result = installer_mod.deploy_x64dbg_plugin_detailed(x64dbg, source_root)
    target64 = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
    if installer_mod.is_user_admin():
        assert result.success is True
        assert [item.status for item in result.per_arch] == ["deployed", "deployed"]
        assert target64.read_bytes() == b"x64-plugin"
    else:
        assert result.success is False
        assert [item.status for item in result.per_arch] == ["failed", "failed"]
        assert all("requires administrator rights" in (item.error or "") for item in result.per_arch)
        assert not target64.exists()
