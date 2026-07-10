# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool installer and detector for Intellicrack.

This module handles automatic detection, downloading, and installation of reverse engineering tools required by the platform.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import platform
import re
import shutil
import sys
import tempfile
import traceback
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import httpx

from intellicrack.core.config import get_project_root
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.subprocess_compat import (
    PIPE,
    CalledProcessError,
    TimeoutExpired,
    run as _subprocess_run,
)
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import IO

    import pefile


_logger = get_logger(__name__)


_pefile_mod: Any = None
_pefile_available: bool = False
try:
    import pefile as _pefile_import

    _pefile_mod = _pefile_import
    _pefile_available = True
except ImportError as _exc:
    _logger.debug("pefile_unavailable", error=str(_exc))


_ERR_UNSUPPORTED_ARCHIVE = "unsupported archive format"
_ERR_EXTRACTION_FAILED = "extraction failed"
_ERR_ENSURE_FAILED = "failed to ensure tool"
_ERR_EXTRACT_FAILED_FMT = "failed to extract archive"
_ERR_UNSAFE_ZIP_MEMBER = "unsafe zip member"
_ERR_EMPTY_ARCHIVE = "archive extracted no usable directory"
_ERR_NO_VERSION_AFTER_INSTALL = "post-install version verification failed"
_ERR_NO_EXE_AFTER_INSTALL = "no expected executable found after install"
_MIN_URL_PARTS = 2
_PROGRESS_CHUNK = 8192
_ONE_MB = 1024 * 1024
_GHIDRA_NESTING_DEPTH = 2
_DEFAULT_CMAKE_TIMEOUT_S = 600
_DEFAULT_BUILD_TIMEOUT_S = 1800
_VSWHERE_TIMEOUT_S = 15
_PIP_TIMEOUT_S = 300
_VERSION_PROBE_TIMEOUT_S = 10

_WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{n}" for n in range(1, 10)),
        *(f"LPT{n}" for n in range(1, 10)),
    },
)


_ARCH_ALIASES: dict[str, frozenset[str]] = {
    "x86_64": frozenset({"x86_64", "amd64", "x64", "win64"}),
    "i686": frozenset({"i686", "i386", "x86", "win32"}),
    "arm64": frozenset({"arm64", "aarch64"}),
}


def _env_program_files() -> str:
    r"""Return the host's Program Files directory.

    Returns:
        str: ``%PROGRAMFILES%`` when the env var is set, otherwise the
        default ``C:\Program Files`` path.
    """
    return os.environ.get("PROGRAMFILES", r"C:\Program Files")


def _env_local_appdata() -> str | None:
    """Return the host's LOCALAPPDATA directory.

    Returns:
        str | None: ``%LOCALAPPDATA%`` when the env var is set, otherwise None.
    """
    return os.environ.get("LOCALAPPDATA")


ToolKind = Literal["filesystem", "builtin", "python_package"]


DeployArchStatus = Literal["deployed", "up_to_date", "missing_source", "failed"]


@dataclass
class ToolInfo:
    """Information about a tool.

    Attributes:
        name: Tool name enum.
        display_name: Human-readable name.
        common_paths: Common installation paths to check.
        executables: Expected executable names.
        download_url: URL pattern for downloading.
        version_command: Command to get version.
        min_version: Minimum required version.
        kind: How the tool is materialised on the host.
    """

    name: ToolName
    display_name: str
    common_paths: list[Path] = field(default_factory=list)
    executables: list[str] = field(default_factory=list)
    download_url: str = ""
    version_command: list[str] = field(default_factory=list)
    min_version: str = ""
    kind: ToolKind = "filesystem"


@dataclass
class ToolVersion:
    """Parsed tool version.

    Supports both classic ``MAJOR.MINOR.PATCH`` semver and ``YYYY.MM.DD``
    date-stamped builds (used by x64dbg snapshots). The :attr:`is_date`
    flag is set when the source string parsed as a calendar date so
    comparisons can use the appropriate ordering rules.

    Attributes:
        major: Major version number (or year for date-style versions).
        minor: Minor version number (or month for date-style versions).
        patch: Patch version number (or day for date-style versions).
        raw: Raw version string.
        is_date: True when the version is a calendar date (YYYY.MM.DD).
    """

    major: int = 0
    minor: int = 0
    patch: int = 0
    raw: str = ""
    is_date: bool = False

    def __str__(self) -> str:
        """Get string representation.

        Returns:
            str: Version string in major.minor.patch format.
        """
        return f"{self.major}.{self.minor}.{self.patch}"

    def __ge__(self, other: ToolVersion) -> bool:
        """Compare versions ordered by the (major, minor, patch) triple.

        Date-style versions (YYYY.MM.DD) and semver versions both end up
        as a 3-tuple in the same numeric domain, so this comparison
        works for like-vs-like in both schemes.

        Args:
            other: Version to compare against.

        Returns:
            bool: True if this version is greater or equal.
        """
        self_tuple = (self.major, self.minor, self.patch)
        other_tuple = (other.major, other.minor, other.patch)
        return self_tuple >= other_tuple


@dataclass
class InstallResult:
    """Result of tool installation.

    The ``kind`` field discriminates between tools that live as files on
    disk (``"filesystem"``), tools that ship inside Intellicrack itself
    (``"builtin"``), and tools that exist as a Python package
    (``"python_package"``). For non-filesystem tools, ``path`` is None
    because no real filesystem location applies.

    Attributes:
        success: Whether installation succeeded.
        path: Path to installed tool, or None for non-filesystem tools.
        version: Installed version.
        error: Error message (with traceback) if failed.
        kind: How the tool is materialised on the host.
    """

    success: bool
    path: Path | None = None
    version: ToolVersion | None = None
    error: str | None = None
    kind: ToolKind = "filesystem"


@dataclass
class FoundTool:
    """Result of a successful :meth:`ToolInstaller.find_tool` lookup.

    Attributes:
        kind: How the tool is materialised on the host.
        path: Filesystem path when ``kind == "filesystem"``; None otherwise.
        version: Detected version when known.
    """

    kind: ToolKind
    path: Path | None = None
    version: ToolVersion | None = None


@dataclass
class ArchDeployResult:
    """Per-arch outcome for x64dbg bridge plugin deployment.

    Attributes:
        arch: Architecture label (``"x64"`` or ``"x32"``).
        filename: Plugin binary filename.
        status: Outcome category for this arch.
        target: Target path inside the x64dbg installation, when known.
        error: Failure detail when ``status == "failed"``.
    """

    arch: str
    filename: str
    status: DeployArchStatus
    target: Path | None = None
    error: str | None = None


@dataclass
class DeployResult:
    """Aggregated result of x64dbg bridge plugin deployment.

    ``success`` is True only when every arch with a source binary
    deployed cleanly (or was already up-to-date) AND at least one arch
    was actually present. Missing-source arches are reported in
    :attr:`per_arch` but do not, on their own, fail the overall result
    because users may have intentionally only built one arch.

    Attributes:
        success: Whether overall deployment is considered successful.
        per_arch: List of per-arch outcomes.
    """

    success: bool
    per_arch: list[ArchDeployResult] = field(default_factory=list)


class ToolProbeTimeoutError(ToolError):
    """Raised when a tool availability probe times out.

    A timeout is materially different from "not installed" - usually it
    signals a hung interpreter, slow first-time import, or AV interference
    - so callers can choose to retry or surface the condition rather than
    silently treating the tool as absent.
    """


TOOL_REGISTRY: dict[ToolName, ToolInfo] = {
    ToolName.GHIDRA: ToolInfo(
        name=ToolName.GHIDRA,
        display_name="Ghidra",
        common_paths=[
            Path("C:/Program Files/ghidra"),
            Path("C:/Tools/ghidra"),
            Path("C:/ghidra"),
            Path("D:/Tools/ghidra"),
            Path("~").expanduser() / "ghidra",
        ],
        executables=(["support/analyzeHeadless.bat"] if sys.platform == "win32" else ["support/analyzeHeadless"]),
        download_url="https://github.com/NationalSecurityAgency/ghidra/releases/latest",
        version_command=[],
        min_version="11.0",
    ),
    ToolName.X64DBG: ToolInfo(
        name=ToolName.X64DBG,
        display_name="x64dbg",
        common_paths=[
            Path("C:/Program Files/x64dbg"),
            Path("C:/Tools/x64dbg"),
            Path("C:/x64dbg"),
            Path("D:/Tools/x64dbg"),
        ],
        executables=["release/x64/x64dbg.exe", "release/x32/x32dbg.exe"],
        download_url="https://github.com/x64dbg/x64dbg/releases/latest",
        version_command=[],
        min_version="2024.01.01",
    ),
    ToolName.CUTTER: ToolInfo(
        name=ToolName.CUTTER,
        display_name="Cutter",
        common_paths=[
            Path("C:/Program Files/Cutter"),
            Path("C:/Tools/Cutter"),
            Path("D:/Tools/Cutter"),
        ],
        executables=["cutter.exe"],
        download_url="https://github.com/rizinorg/cutter/releases/latest",
        version_command=[],
        min_version="2.3.0",
    ),
    ToolName.FRIDA: ToolInfo(
        name=ToolName.FRIDA,
        display_name="Frida",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[
            sys.executable,
            "-c",
            "import frida; print(frida.__version__)",
        ],
        min_version="16.0.0",
        kind="python_package",
    ),
    ToolName.PROCESS: ToolInfo(
        name=ToolName.PROCESS,
        display_name="Process Control",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
        kind="builtin",
    ),
    ToolName.SANDBOX: ToolInfo(
        name=ToolName.SANDBOX,
        display_name="Sandbox (QEMU/Docker)",
        common_paths=[
            Path(_env_program_files()) / "qemu",
            Path(_env_program_files()) / "Docker" / "Docker" / "resources" / "bin",
        ],
        executables=[
            "qemu-system-x86_64.exe",
            "qemu-system-i386.exe",
            "docker.exe",
        ],
        download_url="",
        version_command=[],
        min_version="",
    ),
    ToolName.HEX_EDITOR: ToolInfo(
        name=ToolName.HEX_EDITOR,
        display_name="Hex Editor",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
        kind="builtin",
    ),
}


def _list_dir(directory: Path) -> list[Path]:
    """Return the immediate children of ``directory`` as a list.

    Args:
        directory: Directory to enumerate.

    Returns:
        list[Path]: Child paths produced by ``Path.iterdir``.
    """
    return list(directory.iterdir())


def _format_exception(exc: BaseException) -> str:
    """Render an exception with full traceback for diagnostics.

    Args:
        exc: The exception to format.

    Returns:
        str: Multi-line traceback string suitable for logs and result.error.
    """
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).strip()


def _is_user_admin() -> bool:
    """Check whether the current process has Windows administrator rights.

    Returns:
        bool: True on Windows when ``IsUserAnAdmin`` returns non-zero;
        True on non-Windows platforms (no equivalent gate); False on any
        Win32 error.
    """
    if sys.platform != "win32":
        return True
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return False
    shell32 = getattr(windll, "shell32", None)
    if shell32 is None:
        return False
    is_admin_fn = getattr(shell32, "IsUserAnAdmin", None)
    if is_admin_fn is None:
        return False
    try:
        return bool(is_admin_fn())
    except OSError as exc:
        _logger.warning("is_user_admin_check_failed", error=str(exc))
        return False


def _matches_arch(asset_name: str, host_arch_aliases: Iterable[str]) -> bool:
    """Return True when an asset filename advertises a matching architecture.

    Args:
        asset_name: Lower-cased asset filename.
        host_arch_aliases: Aliases for the host architecture (e.g.
            ``{"x86_64", "amd64", "x64", "win64"}``).

    Returns:
        bool: True when any alias appears as a token in ``asset_name``.
    """
    return any(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", asset_name) for alias in host_arch_aliases)


def _host_arch_aliases() -> frozenset[str]:
    """Return the canonical arch alias set for the current host.

    Falls back to ``x86_64`` when the host arch cannot be determined or
    is not recognised, since that is the dominant Windows desktop arch
    and matches the upstream defaults for all supported tools.

    Returns:
        frozenset[str]: Aliases (e.g. ``{"x86_64", "amd64", ...}``).
    """
    machine = platform.machine().lower()
    proc_arch = os.environ.get("PROCESSOR_ARCHITECTURE", "").lower()
    candidates = {machine, proc_arch}
    for canonical, aliases in _ARCH_ALIASES.items():
        if candidates & aliases:
            _logger.debug("host_arch_detected", machine=machine, canonical=canonical)
            return aliases
    _logger.debug("host_arch_unknown_default_x86_64", machine=machine, proc_arch=proc_arch)
    return _ARCH_ALIASES["x86_64"]


def _read_pe_version_info(exe_path: Path) -> str | None:
    """Read the FileVersion / ProductVersion from a Windows PE binary.

    Parses the ``VS_VERSION_INFO`` resource via ``pefile`` so the GUI
    binary never has to be launched just to learn its version. Returns
    the first non-empty value found in the standard StringFileInfo table
    or falls back to the binary FileVersionLS/FileVersionMS pair from
    the fixed file info structure.

    Args:
        exe_path: Path to a PE (.exe / .dll / .dp64 / ...) file.

    Returns:
        str | None: A version string on success, otherwise None.
    """
    if not _pefile_available or _pefile_mod is None:
        _logger.debug("pefile_module_not_available_for_version_probe", exe=str(exe_path))
        return None

    try:
        pe = _pefile_mod.PE(str(exe_path), fast_load=True)
    except (_pefile_mod.PEFormatError, OSError) as exc:
        _logger.warning("pe_open_failed", exe=str(exe_path), error=str(exc))
        return None

    try:
        return _extract_pe_version_string(pe, exe_path)
    finally:
        pe.close()


def _extract_pe_version_string(pe: pefile.PE, exe_path: Path) -> str | None:
    """Walk the parsed PE structure and return the first usable version string.

    Args:
        pe: A parsed ``pefile.PE`` instance.
        exe_path: Path of the PE on disk, used for logging context.

    Returns:
        str | None: The best version string available, or None when no
        readable version information is present.
    """
    pe.parse_data_directories(directories=[_pefile_mod.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

    file_info_attr: Any = getattr(pe, "FileInfo", None) or []
    file_info: list[Any] = list(file_info_attr) if file_info_attr else []
    flat: list[Any] = []
    for entry in file_info:
        if isinstance(entry, list):
            flat.extend(cast("list[Any]", entry))
        else:
            flat.append(entry)

    preferred_keys = ("FileVersion", "ProductVersion")
    for fi in flat:
        tables_attr: Any = getattr(fi, "StringTable", []) or []
        tables: list[Any] = list(tables_attr) if tables_attr else []
        for st in tables:
            entries_attr: Any = getattr(st, "entries", {}) or {}
            entries: dict[bytes, bytes] = dict(entries_attr) if entries_attr else {}
            for key_name in preferred_keys:
                if raw_value := entries.get(key_name.encode("utf-8")):
                    try:
                        return raw_value.decode("utf-8", errors="replace").strip()
                    except (AttributeError, UnicodeError) as exc:
                        _logger.warning("pe_version_decode_failed", exe=str(exe_path), key=key_name, error=str(exc))
                        continue

    vs_fixed_attr: Any = getattr(pe, "VS_FIXEDFILEINFO", None) or []
    vs_fixed: list[Any] = list(vs_fixed_attr) if vs_fixed_attr else []
    for ffi in vs_fixed:
        ms = int(getattr(ffi, "FileVersionMS", 0))
        ls = int(getattr(ffi, "FileVersionLS", 0))
        if ms or ls:
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    return None


class ToolInstaller:
    """Handles automatic tool detection and installation.

    Records the target directory under which downloaded tools will be laid out, creates it on disk if it is missing, and prepares a lazy
    ``httpx.AsyncClient`` slot that is instantiated on first download.
    """

    def __init__(self, tools_directory: Path) -> None:
        """Initialize the ToolInstaller with the given target directory.

        Args:
            tools_directory: Directory where tools should be installed.
        """
        self.tools_directory = tools_directory
        self._http_client: httpx.AsyncClient | None = None

        self.tools_directory.mkdir(parents=True, exist_ok=True)
        _logger.debug("tools_directory_ready", path=str(self.tools_directory))

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            httpx.AsyncClient: Async HTTP client instance.
        """
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
                follow_redirects=True,
            )
        return self._http_client

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def find_tool(self, tool: ToolName) -> Path | None:
        """Find an installed tool and return its filesystem path if any.

        For ``"builtin"`` and ``"python_package"`` tools this returns
        None - callers that need to know about availability for those
        tools should use :meth:`find_tool_detailed`, :meth:`verify_tool`
        or :meth:`get_all_tool_status`.

        Args:
            tool: The tool to find.

        Returns:
            Path | None: Path to tool installation or None if not found
            / not on the filesystem.
        """
        found = await self.find_tool_detailed(tool)
        return None if found is None else found.path

    async def find_tool_detailed(self, tool: ToolName) -> FoundTool | None:
        """Find an installed tool and return rich availability metadata.

        Searches common installation paths first, then PATH, then the
        tools directory. For builtin and Python-package tools, performs
        the equivalent availability check (e.g. importing ``frida``)
        instead of synthesising a filesystem path.

        Args:
            tool: The tool to find.

        Returns:
            FoundTool | None: Detailed availability information, or None
            when the tool is not present.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            _logger.warning("unknown_tool", tool=str(tool))
            return None

        if tool_info.kind == "builtin":
            return FoundTool(kind="builtin")

        if tool_info.kind == "python_package":
            version = await self._probe_python_package(tool_info)
            if version is None:
                return None
            return FoundTool(kind="python_package", version=version)

        for common_path in tool_info.common_paths:
            if not await asyncio.to_thread(common_path.exists):
                continue
            for exe in tool_info.executables:
                exe_path = common_path / exe
                if await asyncio.to_thread(exe_path.exists):
                    _logger.info(
                        "tool_found",
                        tool=tool_info.display_name,
                        path=str(exe_path),
                    )
                    return FoundTool(kind="filesystem", path=common_path)

        for exe in tool_info.executables:
            found = await asyncio.to_thread(shutil.which, exe)
            if found is not None:
                found_path = Path(found).parent
                _logger.info(
                    "tool_found_in_path",
                    tool=tool_info.display_name,
                    path=str(found_path),
                )
                return FoundTool(kind="filesystem", path=found_path)

        tool_dir: Path = self.tools_directory / str(tool.value)
        nested = await self._search_tool_dir(tool_dir, tool_info)
        if nested is not None:
            return FoundTool(kind="filesystem", path=nested)

        _logger.debug("tool_not_found", tool=tool_info.display_name)
        return None

    @staticmethod
    async def _search_tool_dir(tool_dir: Path, tool_info: ToolInfo) -> Path | None:
        """Search for a tool's executables within ``tool_dir`` (and its sub-trees).

        Caches each level's directory listing so the per-executable loop
        does not re-enter the filesystem repeatedly. Walks two nesting
        levels deep so Ghidra-style ``ghidra_X.Y_PUBLIC/ghidra_X.Y_PUBLIC/...``
        archive layouts are covered.

        Args:
            tool_dir: Tools-directory root for the tool.
            tool_info: Registry entry providing executable names.

        Returns:
            Path | None: Directory containing one of ``tool_info.executables``,
            or None when nothing matches.
        """
        if not await asyncio.to_thread(tool_dir.exists):
            return None

        for exe in tool_info.executables:
            exe_path = tool_dir / exe
            if await asyncio.to_thread(exe_path.exists):
                _logger.info(
                    "tool_found_in_tools_dir",
                    tool=tool_info.display_name,
                    path=str(tool_dir),
                )
                return tool_dir

        directories: list[Path] = [tool_dir]
        for _level in range(_GHIDRA_NESTING_DEPTH):
            next_level: list[Path] = []
            for parent in directories:
                try:
                    children: list[Path] = await asyncio.to_thread(_list_dir, parent)
                except OSError as exc:
                    _logger.warning(
                        "tool_dir_iter_failed",
                        path=str(parent),
                        error=str(exc),
                    )
                    continue
                child_dirs: list[Path] = [c for c in children if c.is_dir()]
                for child in child_dirs:
                    for exe in tool_info.executables:
                        exe_path = child / exe
                        if exe_path.exists():
                            _logger.info(
                                "tool_found",
                                tool=tool_info.display_name,
                                path=str(child),
                            )
                            return child
                next_level.extend(child_dirs)
            directories = next_level
            if not directories:
                break
        return None

    @staticmethod
    async def _probe_python_package(tool_info: ToolInfo) -> ToolVersion | None:
        """Probe a Python package by running its registered version command.

        Distinguishes between absence (FileNotFoundError on the python
        executable, non-zero exit) and a hung interpreter (TimeoutExpired)
        by raising :class:`ToolProbeTimeoutError` on timeout so callers
        can decide whether to surface or retry.

        Args:
            tool_info: Registry entry for the Python-package tool.

        Returns:
            ToolVersion | None: Parsed version on success; None when the
            package is not installed or the version line cannot be parsed.

        Raises:
            ToolProbeTimeoutError: When the version-probe subprocess does
                not return within :data:`_VERSION_PROBE_TIMEOUT_S` seconds.
        """
        if not tool_info.version_command:
            return None
        cmd = list(tool_info.version_command)
        process_manager = ProcessManager.get_instance()
        _logger.debug("python_package_probe_starting", tool=tool_info.display_name, cmd=cmd)
        try:
            result = await process_manager.run_tracked_async(
                cmd,
                name=f"{tool_info.name.value}-version-probe",
                process_timeout=_VERSION_PROBE_TIMEOUT_S,
            )
        except TimeoutExpired as exc:
            _logger.warning(
                "python_package_probe_timeout",
                tool=tool_info.display_name,
                timeout_s=_VERSION_PROBE_TIMEOUT_S,
            )
            timeout_msg = f"version probe for {tool_info.display_name} timed out"
            raise ToolProbeTimeoutError(timeout_msg, tool_name=tool_info.name.value) from exc
        except OSError as exc:
            _logger.warning(
                "python_package_probe_unavailable",
                tool=tool_info.display_name,
                error=str(exc),
            )
            return None

        if result.returncode != 0:
            _logger.debug(
                "python_package_probe_nonzero",
                tool=tool_info.display_name,
                returncode=result.returncode,
            )
            return None

        version = _ToolInstallerVersion.parse(result.stdout.strip())
        if version is None:
            _logger.debug(
                "python_package_probe_unparseable",
                tool=tool_info.display_name,
                stdout=result.stdout.strip(),
            )
        return version

    async def get_version(self, tool: ToolName, path: Path | None) -> ToolVersion | None:
        """Get the version of an installed tool.

        For Ghidra the version is read from ``application.properties``.
        For x64dbg and Cutter the version is read from the PE
        ``VS_VERSION_INFO`` resource on Windows so the GUI never has to
        launch. For Frida the version is obtained by running the python
        ``import frida; print(frida.__version__)`` probe. For
        ``"builtin"`` tools the function returns None because builtin
        tools have no externally observable version line.

        Args:
            tool: The tool to check.
            path: Path to the tool installation. May be None for
                non-filesystem tools.

        Returns:
            ToolVersion | None: Parsed version or None when it could not
            be determined.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return None

        if tool_info.kind == "builtin":
            return None

        if tool_info.kind == "python_package":
            try:
                return await self._probe_python_package(tool_info)
            except ToolProbeTimeoutError:
                _logger.warning("python_package_probe_timeout", tool_name=getattr(tool_info, "name", "unknown"))
                return None

        if path is None:
            return None

        if tool == ToolName.GHIDRA:
            return self._get_ghidra_version(path)

        if tool == ToolName.X64DBG:
            notes_version = await asyncio.to_thread(self._get_x64dbg_notes_version, path)
            if notes_version is not None:
                return notes_version

        if tool in {ToolName.X64DBG, ToolName.CUTTER}:
            return await asyncio.to_thread(self._get_pe_version, path, tool_info)

        if not tool_info.version_command:
            return None

        try:
            return await self._probe_version_command(tool, path, tool_info)
        except (TimeoutExpired, OSError):
            _logger.exception("version_check_failed", tool=str(tool))

        return None

    @staticmethod
    async def _probe_version_command(
        tool: ToolName,
        path: Path,
        tool_info: ToolInfo,
    ) -> ToolVersion | None:
        """Execute the configured version probe and parse its output.

        Both :class:`TimeoutExpired` and :class:`OSError` raised by the
        process manager propagate to the caller, which wraps the call in
        ``try/except`` to convert them into a ``None`` return.

        Args:
            tool: Tool being probed (used for logging and process naming).
            path: Installation root or executable path for the tool.
            tool_info: Registry entry describing the tool, including the
                ``version_command`` to invoke.

        Returns:
            ToolVersion | None: Parsed version when the probe exits
            cleanly with a recognised version string, otherwise None.
        """
        cmd = list(tool_info.version_command)
        process_manager = ProcessManager.get_instance()

        exe = path / cmd[0]
        if await asyncio.to_thread(exe.exists):
            cmd[0] = str(exe)

        is_dir = await asyncio.to_thread(path.is_dir)
        _logger.debug("tool_version_probe_starting", tool=tool.value, cmd=cmd)
        result = await process_manager.run_tracked_async(
            cmd,
            name=f"{tool.value}-version",
            process_timeout=30,
            cwd=str(path) if is_dir else None,
        )

        if result.returncode == 0:
            return _ToolInstallerVersion.parse(result.stdout.strip())
        return None

    @staticmethod
    def _get_x64dbg_notes_version(path: Path) -> ToolVersion | None:
        """Parse the release date from x64dbg release-notes.md.

        Args:
            path: Path to the x64dbg installation.

        Returns:
            ToolVersion | None: Parsed version or None when the file cannot be
            read or no date is parsed.
        """
        for candidate in (
            path / "release-notes.md",
            path.parent / "release-notes.md",
            path / "release" / "release-notes.md",
        ):
            if not candidate.is_file():
                continue
            try:
                content = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                _logger.warning(
                    "failed_to_read_x64dbg_release_notes",
                    path=str(candidate),
                    error=str(exc),
                )
                continue

            for line in content.splitlines()[:10]:
                line_stripped = line.strip()
                if date_match := re.search(
                    r"(\d{4})\.(\d{2})\.(\d{2})",
                    line_stripped,
                ):
                    date_str = date_match[0]
                    version = _ToolInstallerVersion.parse(date_str)
                    if version is not None:
                        _logger.debug(
                            "x64dbg_version_from_release_notes",
                            path=str(candidate),
                            version=date_str,
                        )
                        return version
        return None

    @staticmethod
    def _get_pe_version(path: Path, tool_info: ToolInfo) -> ToolVersion | None:
        """Read a Windows tool's version from its PE VS_VERSION_INFO.

        Args:
            path: Installation root for the tool.
            tool_info: Registry entry describing the tool's executables.

        Returns:
            ToolVersion | None: Parsed version or None when the file
            cannot be opened or no recognisable version string is found.
        """
        for exe_name in tool_info.executables:
            exe_path = path / exe_name
            if not exe_path.is_file():
                continue
            if raw := _read_pe_version_info(exe_path):
                version = _ToolInstallerVersion.parse(raw)
                if version is not None:
                    _logger.debug(
                        "pe_version_detected",
                        tool=tool_info.display_name,
                        exe=str(exe_path),
                        version=raw,
                    )
                    return version
        _logger.debug(
            "pe_version_unavailable",
            tool=tool_info.display_name,
            path=str(path),
        )
        return None

    @staticmethod
    def _get_ghidra_version(path: Path) -> ToolVersion | None:
        """Get Ghidra version by parsing Ghidra/application.properties.

        Reads the application.version property from the properties file
        instead of launching a subprocess, which avoids accidentally
        opening the Ghidra GUI.

        Args:
            path: Path to the Ghidra installation root.

        Returns:
            ToolVersion | None: Parsed ToolVersion or None if the file cannot be read.
        """
        props_path = path / "Ghidra" / "application.properties"
        if not props_path.is_file():
            _logger.debug(
                "ghidra_properties_not_found",
                path=str(props_path),
            )
            return None

        try:
            text = props_path.read_text(encoding="utf-8")
        except OSError:
            _logger.exception(
                "ghidra_properties_read_failed",
                path=str(props_path),
            )
            return None

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("application.version="):
                version_str = stripped.split("=", maxsplit=1)[1].strip()
                version = _ToolInstallerVersion.parse(version_str)
                _logger.debug(
                    "ghidra_version_detected",
                    version=version_str,
                    path=str(props_path),
                )
                return version

        _logger.debug(
            "ghidra_version_key_missing",
            path=str(props_path),
        )
        return None

    @staticmethod
    def _parse_version(version_str: str) -> ToolVersion | None:
        """Parse a version string supporting semver and YYYY.MM.DD.

        Returns None when no recognisable version can be extracted so
        callers no longer silently downgrade to ``ToolVersion(0, 0, 0)``
        for unparseable input.

        Args:
            version_str: Raw version string.

        Returns:
            ToolVersion | None: Parsed ToolVersion, or None when nothing
            usable was found.
        """
        return _ToolInstallerVersion.parse(version_str)

    async def verify_tool(self, tool: ToolName, path: Path | None) -> bool:
        """Verify a tool installation is valid.

        For ``"builtin"`` tools, returns True because availability is
        guaranteed by being shipped inside Intellicrack. For
        ``"python_package"`` tools, runs the version probe and treats
        success as the validity gate. For filesystem tools, requires the
        executable to exist AND, when ``min_version`` is set, the parsed
        version to satisfy the floor.

        Args:
            tool: The tool to verify.
            path: Path to installation. May be None for non-filesystem tools.

        Returns:
            bool: True if installation is valid and meets minimum version.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return False

        if tool in {ToolName.X64DBG, ToolName.CUTTER} and not pefile_available():
            _logger.warning("pefile_unavailable_for_verification", tool=tool.value)
            return False

        if tool_info.kind == "builtin":
            return True

        if tool_info.kind == "python_package":
            try:
                version = await self._probe_python_package(tool_info)
            except ToolProbeTimeoutError:
                _logger.warning("python_package_version_probe_timeout", tool_name=getattr(tool_info, "name", "unknown"))
                return False
            if version is None:
                return False
            return self._meets_min_version(version, tool_info)

        if path is None:
            return False

        for exe in tool_info.executables:
            exe_path = path / exe
            if await asyncio.to_thread(exe_path.exists):
                version = await self.get_version(tool, path)
                if version is None:
                    return not bool(tool_info.min_version)
                return self._meets_min_version(version, tool_info)

        return False

    @staticmethod
    def _meets_min_version(version: ToolVersion, tool_info: ToolInfo) -> bool:
        """Return True when ``version`` satisfies ``tool_info.min_version``.

        Args:
            version: Detected tool version.
            tool_info: Registry entry providing the floor.

        Returns:
            bool: True when no floor is set or the detected version is
            greater than or equal to the floor.
        """
        if not tool_info.min_version:
            return True
        min_ver = _ToolInstallerVersion.parse(tool_info.min_version)
        if min_ver is None:
            _logger.warning(
                "min_version_unparseable",
                tool=tool_info.display_name,
                min_version=tool_info.min_version,
            )
            return False
        if version >= min_ver:
            return True
        _logger.warning(
            "version_below_minimum",
            tool=tool_info.display_name,
            version=str(version),
            min_version=tool_info.min_version,
        )
        return False

    async def install_tool(self, tool: ToolName) -> InstallResult:
        """Download and install a tool.

        Args:
            tool: The tool to install.

        Returns:
            InstallResult: InstallResult with installation status. For
            non-filesystem kinds (``"builtin"`` / ``"python_package"``)
            the ``path`` field is None and ``kind`` is set accordingly.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return InstallResult(success=False, error=f"Unknown tool: {tool}")

        if tool in {ToolName.X64DBG, ToolName.CUTTER} and not pefile_available():
            _logger.warning("pefile_not_available_for_install", tool=tool.value)
            return InstallResult(
                success=False,
                error=f"Cannot install {tool_info.display_name} because optional dependency 'pefile' is not available.",
            )

        if tool_info.kind == "builtin":
            return InstallResult(success=True, path=None, kind="builtin")

        if tool_info.kind == "python_package":
            return await self._install_frida()

        if not tool_info.download_url:
            return InstallResult(
                success=False,
                error=f"No download URL configured for {tool_info.display_name}",
            )

        try:
            return await self._install_archive_tool(tool, tool_info)
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, httpx.HTTPError, ToolError) as e:
            _logger.exception("tool_install_failed", tool=tool_info.display_name)
            return InstallResult(success=False, error=_format_exception(e))

    async def _install_archive_tool(self, tool: ToolName, tool_info: ToolInfo) -> InstallResult:
        """Run the download/extract/verify pipeline for an archive-backed tool.

        Filesystem and network failures (OSError, RuntimeError, ValueError,
        zipfile.BadZipFile, httpx.HTTPError, ToolError) raised by helper
        steps propagate to the caller, which converts them into a
        structured failure :class:`InstallResult`.

        Args:
            tool: Tool registry identifier being installed.
            tool_info: Registry entry describing download and verification
                requirements for ``tool``.

        Returns:
            InstallResult: Final install result. Failures are returned
            inline; only unexpected exceptions propagate to the caller.
        """
        _logger.info("tool_installing", tool=tool_info.display_name)

        download_url = await self._get_latest_release_url(tool)
        if download_url is None:
            return InstallResult(
                success=False,
                error=f"Could not find download URL for {tool_info.display_name}",
            )

        download_path = await self._download_file(download_url)
        if download_path is None:
            return InstallResult(
                success=False,
                error=f"Download failed for {tool_info.display_name}",
            )

        try:
            install_path = await self._extract_archive(download_path, tool)
        finally:
            await asyncio.to_thread(download_path.unlink, missing_ok=True)
            _logger.info("download_temp_unlinked", path=str(download_path))

        if install_path is None:
            return InstallResult(
                success=False,
                error=f"{_ERR_EMPTY_ARCHIVE} for {tool_info.display_name}",
            )

        return await self._finalize_archive_install(tool, tool_info, install_path)

    async def _finalize_archive_install(
        self,
        tool: ToolName,
        tool_info: ToolInfo,
        install_path: Path,
    ) -> InstallResult:
        """Verify executables and version constraints after extraction.

        Args:
            tool: Tool being installed.
            tool_info: Registry entry describing executables and minimum
                version requirements.
            install_path: Directory the archive was extracted into.

        Returns:
            InstallResult: Success when an expected executable and a
            version that meets ``tool_info.min_version`` are present,
            otherwise a structured failure result.
        """
        exe_present = await self._has_expected_executable(install_path, tool_info)
        if not exe_present:
            return InstallResult(
                success=False,
                path=install_path,
                error=f"{_ERR_NO_EXE_AFTER_INSTALL}: {tool_info.display_name}",
            )

        version = await self.get_version(tool, install_path)
        if version is None:
            return InstallResult(
                success=False,
                path=install_path,
                error=f"{_ERR_NO_VERSION_AFTER_INSTALL}: {tool_info.display_name}",
            )
        if not self._meets_min_version(version, tool_info):
            return InstallResult(
                success=False,
                path=install_path,
                version=version,
                error=(f"installed version {version} below minimum {tool_info.min_version} for {tool_info.display_name}"),
            )

        _logger.info(
            "tool_installed",
            tool=tool_info.display_name,
            version=str(version),
            path=str(install_path),
        )

        return InstallResult(
            success=True,
            path=install_path,
            version=version,
        )

    @staticmethod
    async def _has_expected_executable(install_path: Path, tool_info: ToolInfo) -> bool:
        """Return True when at least one expected executable lives under ``install_path``.

        Args:
            install_path: Directory the tool was extracted into.
            tool_info: Registry entry for the tool.

        Returns:
            bool: True when any registered executable is on disk.
        """
        for exe in tool_info.executables:
            if await asyncio.to_thread((install_path / exe).exists):
                return True
        return False

    @staticmethod
    async def _install_frida() -> InstallResult:
        """Install the Frida Python package via pip.

        Uses ``[sys.executable, "-m", "pip", ...]`` so the install
        targets the active interpreter rather than whatever ``pip`` is
        first on PATH. After install, runs the version probe and only
        returns success when the probe exits cleanly with a parseable
        version line.

        Returns:
            InstallResult: InstallResult with installation status. The
            ``kind`` field is always ``"python_package"`` and ``path``
            is None - frida lives inside the python environment, not on
            the filesystem.
        """
        try:
            return await ToolInstaller._install_frida_impl()
        except (OSError, RuntimeError, ValueError, CalledProcessError) as e:
            _logger.exception("pip_install_unexpected_error")
            return InstallResult(
                success=False,
                kind="python_package",
                error=_format_exception(e),
            )

    @staticmethod
    async def _install_frida_impl() -> InstallResult:
        """Run pip-install and the post-install version probe for Frida.

        Subprocess failures (OSError, RuntimeError, ValueError, and
        :class:`CalledProcessError`) raised by the process manager
        propagate to the caller, which converts them into a structured
        failure :class:`InstallResult`.

        Returns:
            InstallResult: Success when both pip and the verification
            probe succeed and emit a parseable version, otherwise a
            structured failure with diagnostic context.
        """
        _logger.info("frida_pip_installing", tool="frida")
        process_manager = ProcessManager.get_instance()

        result = await process_manager.run_tracked_async(
            [sys.executable, "-m", "pip", "install", "--upgrade", "frida", "frida-tools"],
            name="pip-install-frida",
            process_timeout=_PIP_TIMEOUT_S,
        )

        if result.returncode != 0:
            _logger.warning(
                "frida_pip_install_failed",
                returncode=result.returncode,
                stderr=result.stderr.strip(),
            )
            return InstallResult(
                success=False,
                kind="python_package",
                error=f"pip install failed (rc={result.returncode}): {result.stderr.strip()}",
            )

        return await ToolInstaller._verify_frida_install(process_manager)

    @staticmethod
    async def _verify_frida_install(process_manager: ProcessManager) -> InstallResult:
        """Run the post-install version probe and parse its output.

        Args:
            process_manager: Shared :class:`ProcessManager` used to spawn
                the version-probe subprocess.

        Returns:
            InstallResult: Success when the probe exits cleanly with a
            parseable version, otherwise a failure result describing
            which stage failed.
        """
        try:
            version_result = await process_manager.run_tracked_async(
                [sys.executable, "-c", "import frida; print(frida.__version__)"],
                name="frida-version-verify",
                process_timeout=_VERSION_PROBE_TIMEOUT_S,
            )
        except TimeoutExpired:
            _logger.warning("frida_version_probe_timeout_after_install", timeout_s=_VERSION_PROBE_TIMEOUT_S)
            return InstallResult(
                success=False,
                kind="python_package",
                error="frida version probe timed out after install",
            )

        if version_result.returncode != 0:
            _logger.warning(
                "frida_version_verify_failed",
                returncode=version_result.returncode,
                stderr=version_result.stderr.strip(),
            )
            return InstallResult(
                success=False,
                kind="python_package",
                error=(f"frida version probe failed (rc={version_result.returncode}): {version_result.stderr.strip()}"),
            )

        version = _ToolInstallerVersion.parse(version_result.stdout.strip())
        if version is None:
            _logger.warning(
                "frida_version_unparseable",
                stdout=version_result.stdout.strip(),
            )
            return InstallResult(
                success=False,
                kind="python_package",
                error=(f"frida installed but version probe returned unparseable output: {version_result.stdout.strip()!r}"),
            )

        _logger.info("frida_installed", version=str(version))
        return InstallResult(
            success=True,
            path=None,
            version=version,
            kind="python_package",
        )

    async def _get_latest_release_url(self, tool: ToolName) -> str | None:
        """Get the latest release download URL from GitHub.

        Picks the asset that matches the host architecture using the
        canonical alias set returned by :func:`_host_arch_aliases`. When
        no asset matches the host arch, returns None and logs a warning
        rather than silently downloading the wrong-arch binary.

        Args:
            tool: Tool to get release for.

        Returns:
            str | None: Download URL or None if not found.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None or not tool_info.download_url:
            return None

        if "github.com" not in tool_info.download_url:
            return tool_info.download_url

        parts = tool_info.download_url.replace("https://github.com/", "").split("/")
        if len(parts) < _MIN_URL_PARTS:
            return None

        owner = parts[0]
        repo = parts[1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"

        try:
            client = await self._get_client()
            response = await client.get(api_url)
            response.raise_for_status()
            data: dict[str, Any] = cast("dict[str, Any]", response.json())
        except (httpx.HTTPError, OSError, KeyError, ValueError):
            _logger.exception("release_info_fetch_failed", tool=tool.value)
            return None

        host_aliases = _host_arch_aliases()
        assets: list[dict[str, Any]] = data.get("assets", [])
        candidates: list[tuple[str, str]] = []
        for asset in assets:
            name: str = str(asset.get("name", "")).lower()
            url: str | None = cast("str | None", asset.get("browser_download_url"))
            if url is None:
                continue
            if not name.endswith(".zip"):
                continue
            if tool == ToolName.GHIDRA:
                if "public" in name:
                    candidates.append((name, url))
            elif tool == ToolName.X64DBG:
                if "snapshot" in name:
                    candidates.append((name, url))
            elif tool == ToolName.CUTTER and "windows" in name:
                candidates.append((name, url))

        for name, url in candidates:
            if _matches_arch(name, host_aliases):
                _logger.info(
                    "release_asset_selected",
                    tool=tool.value,
                    asset_name=name,
                )
                return url

        if candidates and tool in {ToolName.GHIDRA, ToolName.X64DBG}:
            name, url = candidates[0]
            _logger.info(
                "release_asset_selected_arch_agnostic",
                tool=tool.value,
                asset_name=name,
            )
            return url

        _logger.warning(
            "no_matching_arch_asset",
            tool=tool.value,
            host_aliases=sorted(host_aliases),
            asset_count=len(assets),
        )
        return None

    async def _download_file(self, url: str) -> Path | None:
        """Download a file to a temporary location by streaming to disk.

        Reads the response incrementally and writes each chunk directly
        to the destination file via ``asyncio.to_thread`` so the archive
        never has to be buffered in memory in full. On any error, the
        partial temp file is removed before returning None.

        Args:
            url: URL to download.

        Returns:
            Path | None: Path to downloaded file or None on failure.
        """
        client = await self._get_client()
        filename = url.rsplit("/", maxsplit=1)[-1]
        temp_path = Path(tempfile.gettempdir()) / filename

        _logger.info("download_starting", file_name=filename)
        success = False

        try:
            await self._stream_download_to_path(client, url, temp_path, filename)
            success = True
        except (httpx.HTTPError, OSError, ValueError):
            _logger.exception(
                "download_failed",
                url=url,
            )
            return None
        finally:
            if not success:
                await asyncio.to_thread(temp_path.unlink, missing_ok=True)
                _logger.info("download_partial_removed", path=str(temp_path))

        return temp_path

    @staticmethod
    async def _stream_download_to_path(
        client: httpx.AsyncClient,
        url: str,
        temp_path: Path,
        filename: str,
    ) -> None:
        """Stream a GET response chunk-by-chunk into ``temp_path``.

        ``httpx.HTTPError``, :class:`OSError`, and :class:`ValueError`
        from the underlying transport, filesystem, or response decode
        propagate to the caller, which converts them into a None return
        and removes the partial download.

        Args:
            client: Pre-configured async HTTP client.
            url: URL to GET.
            temp_path: Destination path on disk for the downloaded bytes.
            filename: Display name used in progress and completion logs.
        """

        async with client.stream("GET", url) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            downloaded = 0

            _logger.debug("download_file_opened", path=str(temp_path))
            file_handle = await asyncio.to_thread(temp_path.open, "wb")
            try:
                downloaded = await ToolInstaller._copy_response_chunks(response, file_handle, total)
            finally:
                await asyncio.to_thread(file_handle.close)

        _logger.info("download_completed", file_name=filename, data_size=downloaded)

    @staticmethod
    async def _copy_response_chunks(
        response: httpx.Response,
        file_handle: IO[bytes],
        total: int,
    ) -> int:
        """Copy each non-empty chunk from ``response`` into ``file_handle``.

        Args:
            response: Open streaming HTTP response to consume.
            file_handle: Destination file-like object opened in binary
                write mode.
            total: Expected total byte count from the response headers,
                or 0 when the server did not advertise a length.

        Returns:
            int: Total number of bytes written to disk.
        """
        downloaded = 0
        bytes_since_last_log = 0
        async for chunk in response.aiter_bytes(chunk_size=_PROGRESS_CHUNK):
            if not chunk:
                continue
            await asyncio.to_thread(file_handle.write, chunk)
            downloaded += len(chunk)
            bytes_since_last_log += len(chunk)
            if total > 0 and bytes_since_last_log >= _ONE_MB:
                percent = (downloaded / total) * 100
                _logger.debug(
                    "download_progress",
                    percent=round(percent, 1),
                    downloaded_mb=round(downloaded / _ONE_MB, 1),
                )
                bytes_since_last_log = 0
        return downloaded

    async def _extract_archive(self, archive_path: Path, tool: ToolName) -> Path | None:
        """Extract an archive to the tools directory.

        Returns None when extraction yields no usable subdirectory and
        no executable lives directly under the tool root - that state
        is not a successful install and the caller surfaces it as such.

        Args:
            archive_path: Path to the archive.
            tool: Tool being extracted.

        Returns:
            Path | None: Path to extracted tool, or None when the
            archive contained no usable subdirectory.

        Raises:
            ToolError: If the archive format is unsupported or extraction
                fails.
        """
        if archive_path.suffix != ".zip":
            raise ToolError(_ERR_UNSUPPORTED_ARCHIVE)

        tool_dir = self.tools_directory / tool.value
        await asyncio.to_thread(tool_dir.mkdir, parents=True, exist_ok=True)

        _logger.info("extraction_starting", path=str(tool_dir))

        try:
            await asyncio.to_thread(
                self._extract_zip,
                archive_path,
                tool_dir,
            )
            entries: list[Path] = await asyncio.to_thread(_list_dir, tool_dir)
        except (OSError, zipfile.BadZipFile, ValueError) as e:
            _logger.warning("extraction_failed", archive=str(archive_path), tool=tool.value, error=str(e))
            raise ToolError(_ERR_EXTRACT_FAILED_FMT) from e

        subdirs = [d for d in entries if d.is_dir()]
        files = [f for f in entries if f.is_file()]

        if subdirs:
            return subdirs[0] if len(subdirs) == 1 else tool_dir

        if files:
            return tool_dir

        _logger.warning(
            "archive_yielded_no_content",
            archive=str(archive_path),
            tool=tool.value,
            tool_dir=str(tool_dir),
        )
        return None

    @staticmethod
    def _is_reserved_windows_name(name: str) -> bool:
        """Check whether a path component is a Windows-reserved name.

        Reserved names such as ``CON``, ``PRN``, ``AUX``, ``NUL``,
        ``COM1``-``COM9`` and ``LPT1``-``LPT9`` cannot be created on
        Windows regardless of extension, and any archive that contains
        them must be rejected rather than silently lose files.

        Args:
            name: A single path component (no separators).

        Returns:
            bool: True when ``name`` (ignoring extension) is reserved.
        """
        stem = name.split(".", maxsplit=1)[0].upper()
        return stem in _WINDOWS_RESERVED_NAMES

    @staticmethod
    def _extract_zip(archive_path: Path, dest_dir: Path) -> None:
        """Extract a zip archive with Zip Slip and Windows-name guards.

        Each member's resolved destination must stay inside ``dest_dir``
        (prevents Zip Slip traversal via ``..`` or absolute paths), and
        no path component may match a Windows-reserved device name.

        Args:
            archive_path: Path to zip file.
            dest_dir: Destination directory.

        Raises:
            ToolError: If an archive member escapes ``dest_dir`` or uses
                a reserved Windows name.
        """
        resolved_root = dest_dir.resolve()
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()
            for member in members:
                raw_name = member.filename.replace("\\", "/")
                normalized = raw_name.lstrip("/")
                if not normalized:
                    continue

                candidate = (resolved_root / normalized).resolve()
                try:
                    candidate.relative_to(resolved_root)
                except ValueError as exc:
                    _logger.warning(
                        "zip_member_escapes_dest",
                        member=member.filename,
                        dest=str(resolved_root),
                    )
                    raise ToolError(_ERR_UNSAFE_ZIP_MEMBER) from exc

                for part in normalized.split("/"):
                    if part in {"", "."}:
                        continue
                    if ToolInstaller._is_reserved_windows_name(part):
                        _logger.warning(
                            "zip_member_reserved_name",
                            member=member.filename,
                            component=part,
                        )
                        raise ToolError(_ERR_UNSAFE_ZIP_MEMBER)

            for member in members:
                zf.extract(member, resolved_root)

    async def ensure_tool(self, tool: ToolName) -> Path:
        """Ensure a tool is available, installing if necessary.

        For ``"builtin"`` and ``"python_package"`` tools, raises
        :class:`ToolError` when the call is made because those tools do
        not have a filesystem path - callers should use
        :meth:`find_tool_detailed` for those.

        Args:
            tool: The tool to ensure.

        Returns:
            Path: Path to tool installation.

        Raises:
            ToolError: If tool cannot be found or installed, or has no
                meaningful filesystem path (builtin / python_package).
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            unknown_msg = f"Unknown tool: {tool}"
            raise ToolError(unknown_msg)

        if tool_info.kind != "filesystem":
            found = await self.find_tool_detailed(tool)
            if found is None:
                result = await self.install_tool(tool)
                if not result.success:
                    install_msg = f"{_ERR_ENSURE_FAILED}: {tool_info.display_name}: {result.error}"
                    raise ToolError(install_msg, tool_name=tool.value)
            no_path_msg = f"{tool_info.display_name} is a {tool_info.kind} tool and has no filesystem path"
            raise ToolError(no_path_msg, tool_name=tool.value)

        path = await self.find_tool(tool)

        if path is not None:
            if await self.verify_tool(tool, path):
                return path
            _logger.warning("tool_verification_failed", tool=str(tool))

        result = await self.install_tool(tool)
        if result.success and result.path is not None:
            return result.path

        ensure_msg = f"{_ERR_ENSURE_FAILED}: {tool_info.display_name}: {result.error}"
        raise ToolError(ensure_msg, tool_name=tool.value)

    async def get_all_tool_status(self) -> dict[ToolName, tuple[bool, Path | None]]:
        """Get status of all tools.

        Returns:
            dict[ToolName, tuple[bool, Path | None]]: Dict mapping tool
            name to (available, path) tuples. ``path`` is None for
            non-filesystem tools (builtin / python_package) even when
            they are available.
        """
        status: dict[ToolName, tuple[bool, Path | None]] = {}

        for tool in ToolName:
            found = await self.find_tool_detailed(tool)
            if found is None:
                status[tool] = (False, None)
                continue
            verified = await self.verify_tool(tool, found.path)
            status[tool] = (verified, found.path if verified else None)

        return status

    async def install_frida(self) -> InstallResult:
        """Public wrapper around :meth:`_install_frida` for tests/consumers.

        Returns:
            InstallResult: The same :class:`InstallResult` returned by
            :meth:`_install_frida`.
        """
        return await self._install_frida()

    @staticmethod
    async def search_tool_dir(tool_dir: Path, tool_info: ToolInfo) -> Path | None:
        """Public wrapper around :meth:`_search_tool_dir`.

        Args:
            tool_dir: Tools-directory root for the tool.
            tool_info: Registry entry providing executable names.

        Returns:
            Path | None: Directory containing one of the registered
            executables, or None when nothing matches.
        """
        return await ToolInstaller._search_tool_dir(tool_dir, tool_info)

    @staticmethod
    async def probe_python_package(tool_info: ToolInfo) -> ToolVersion | None:
        """Public wrapper around :meth:`_probe_python_package`.

        Propagates :class:`ToolProbeTimeoutError` from the wrapped
        method when the underlying version-probe subprocess does not
        return within the configured timeout.

        Args:
            tool_info: Registry entry for the Python-package tool.

        Returns:
            ToolVersion | None: Parsed version on success; None when the
            package is not installed or the version line cannot be parsed.
        """
        return await ToolInstaller._probe_python_package(tool_info)

    async def download_file(self, url: str) -> Path | None:
        """Public wrapper around :meth:`_download_file`.

        Args:
            url: URL to download.

        Returns:
            Path | None: Path to the downloaded file or None on failure.
        """
        return await self._download_file(url)

    async def extract_archive(self, archive_path: Path, tool: ToolName) -> Path | None:
        """Public wrapper around :meth:`_extract_archive`.

        Propagates :class:`ToolError` from the wrapped method when the
        archive format is unsupported or extraction fails.

        Args:
            archive_path: Path to the archive.
            tool: Tool being extracted.

        Returns:
            Path | None: Path to the extracted tool, or None when the
            archive contained no usable subdirectory.
        """
        return await self._extract_archive(archive_path, tool)

    @staticmethod
    def parse_version(version_str: str) -> ToolVersion | None:
        """Public wrapper around :meth:`_parse_version`.

        Args:
            version_str: Raw version string.

        Returns:
            ToolVersion | None: Parsed ToolVersion, or None when nothing
            usable was found.
        """
        return ToolInstaller._parse_version(version_str)


_MIN_MONTH = 1
_MAX_MONTH = 12
_MIN_DAY = 1
_MAX_DAY = 31
_MIN_DATE_YEAR = 1970


class _ToolInstallerVersion:
    """Parsing helpers for ToolVersion - kept private to the installer module."""

    _SEMVER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
    _DATE_RE = re.compile(r"^(\d{4})\.(\d{1,2})\.(\d{1,2})$")

    @classmethod
    def parse(cls, version_str: str) -> ToolVersion | None:
        """Parse a version string into a ToolVersion.

        Args:
            version_str: Raw version string.

        Returns:
            ToolVersion | None: Parsed version, or None when nothing
            recognisable was found.
        """
        if not version_str:
            return None
        stripped = version_str.strip()

        date_match = cls._DATE_RE.match(stripped)
        if date_match is not None:
            year = int(date_match.group(1))
            month = int(date_match.group(2))
            day = int(date_match.group(3))
            if _MIN_MONTH <= month <= _MAX_MONTH and _MIN_DAY <= day <= _MAX_DAY and year >= _MIN_DATE_YEAR:
                return ToolVersion(
                    major=year,
                    minor=month,
                    patch=day,
                    raw=stripped,
                    is_date=True,
                )

        match = cls._SEMVER_RE.search(stripped)
        if match is None:
            return None
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return ToolVersion(major=major, minor=minor, patch=patch, raw=stripped)


_PLUGIN_ARCHS: list[tuple[str, str, str]] = [
    ("x64", "intellicrack_bridge_x64.dp64", "release/x64/plugins"),
    ("x32", "intellicrack_bridge_x32.dp32", "release/x32/plugins"),
]


def _program_files_x86() -> Path:
    """Return the 32-bit Program Files directory for the current host.

    Resolves ``ProgramFiles(x86)`` first (covers localised Windows
    installs and 64-bit hosts), falls back to ``ProgramFiles`` on 32-bit
    hosts where that variable is absent, then falls back to the literal
    English path only as a last resort.

    Returns:
        Path: Best-known absolute path to the 32-bit Program Files dir.
    """
    if pfx86 := os.environ.get("PROGRAMFILES(X86)"):
        return Path(pfx86)
    if pf := os.environ.get("PROGRAMFILES"):
        return Path(pf)
    return Path(r"C:\Program Files (x86)")


_X64DBG_SDK_HEADER = "bridgemain.h"


def _resolve_x64dbg_sdk_path(x64dbg_path: Path) -> Path | None:
    """Locate the x64dbg plugin SDK directory inside an installation.

    x64dbg snapshots ship the plugin SDK either directly under
    ``<install>/pluginsdk`` or, on some layouts, under
    ``<install>/release/pluginsdk``. The directory is identified by the
    presence of the ``bridgemain.h`` header that the bridge plugin
    includes, so a stale or partial folder without headers is rejected.

    Args:
        x64dbg_path: Path to the x64dbg installation root.

    Returns:
        Path | None: The resolved ``pluginsdk`` directory containing the
        SDK headers, or None when no SDK headers are found under the
        installation.
    """
    for candidate in (x64dbg_path / "pluginsdk", x64dbg_path / "release" / "pluginsdk"):
        if (candidate / _X64DBG_SDK_HEADER).is_file():
            _logger.debug("x64dbg_sdk_resolved", sdk_path=str(candidate))
            return candidate
    _logger.debug("x64dbg_sdk_not_found", x64dbg_path=str(x64dbg_path))
    return None


def _find_cmake() -> Path | None:
    """Locate the cmake executable.

    Searches PATH first, then falls back to the Visual Studio bundled cmake
    via ``vswhere.exe``. Failures of vswhere are logged at warning level
    rather than silently swallowed.

    Returns:
        Path | None: Path to cmake if found, otherwise None.
    """
    found = shutil.which("cmake")
    if found is not None:
        return Path(found)

    vswhere = _program_files_x86() / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        _logger.debug("vswhere_not_found", path=str(vswhere))
        return None

    try:
        result = _subprocess_run(
            [str(vswhere), "-latest", "-property", "installationPath"],
            capture_output=False,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            timeout=_VSWHERE_TIMEOUT_S,
        )
    except CalledProcessError as exc:
        _logger.warning(
            "vswhere_failed",
            returncode=exc.returncode,
            stderr=str(exc.stderr or "").strip(),
        )
        return None
    except FileNotFoundError as exc:
        _logger.warning("vswhere_not_executable", path=str(vswhere), error=str(exc))
        return None
    except TimeoutExpired:
        _logger.warning("vswhere_timeout", timeout_s=_VSWHERE_TIMEOUT_S)
        return None
    except OSError as exc:
        _logger.warning("vswhere_oserror", error=str(exc))
        return None

    vs_path = (result.stdout or "").strip()
    if not vs_path:
        _logger.warning("vswhere_empty_stdout")
        return None

    cmake_path = Path(vs_path) / "Common7" / "IDE" / "CommonExtensions" / "Microsoft" / "CMake" / "CMake" / "bin" / "cmake.exe"
    if cmake_path.is_file():
        return cmake_path
    _logger.debug("vs_bundled_cmake_missing", path=str(cmake_path))
    return None


def _detect_vs_generator(cmake_path: Path) -> str | None:
    """Detect the highest available Visual Studio CMake generator.

    Runs ``cmake --help`` and parses its output for ``Visual Studio NN YYYY``
    generator lines.

    Args:
        cmake_path: Path to the cmake executable.

    Returns:
        str | None: Generator string (e.g. ``"Visual Studio 18 2026"``) or None.
    """
    try:
        result = _subprocess_run(
            [str(cmake_path), "--help"],
            capture_output=False,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            timeout=_VSWHERE_TIMEOUT_S,
        )
    except (OSError, TimeoutExpired) as exc:
        _logger.warning("cmake_help_failed", cmake_path=str(cmake_path), error=str(exc))
        return None

    best: str | None = None
    best_ver = 0
    for line in result.stdout.splitlines():
        if match := re.search(r"(Visual Studio (\d+) \d{4})", line):
            ver = int(match[2])
            if ver > best_ver:
                best_ver = ver
                best = match[1]
    return best


def _cmake_timeout(env_var: str, default_s: int) -> int:
    """Read a cmake-related timeout from an env var with a sane minimum.

    Args:
        env_var: Environment variable name to consult.
        default_s: Default timeout in seconds when the env var is unset.

    Returns:
        int: Timeout in seconds; never less than the default.
    """
    raw = os.environ.get(env_var)
    if not raw:
        return default_s
    try:
        value = int(raw)
    except ValueError:
        _logger.exception("cmake_timeout_env_invalid", env_var=env_var, value=raw)
        return default_s
    return max(value, default_s)


def build_x64dbg_plugin(plugin_dir: Path, x64dbg_path: Path) -> bool:
    """Build the x64dbg bridge plugin from source using CMake + Visual Studio.

    Attempts to compile both x64 and x32 architectures. Captures stdout
    and stderr from each invocation so failures can be diagnosed from
    the logs. Configure timeout defaults to 600 s and can be overridden
    via the ``INTELLICRACK_CMAKE_TIMEOUT`` env var; build timeout
    defaults to 1800 s and respects ``INTELLICRACK_BUILD_TIMEOUT``.

    Args:
        plugin_dir: Root of the ``x64dbg-plugin`` source tree containing
            ``CMakeLists.txt``.
        x64dbg_path: Path to the x64dbg installation whose bundled plugin
            SDK the plugin is compiled against. The actual SDK directory
            is resolved from this root and passed to CMake via
            ``-DX64DBG_SDK_PATH`` so the plugin links the installed
            build's ``x64dbg.lib`` / ``x64bridge.lib`` and picks up its
            ``PLUG_SDKVERSION``.

    Returns:
        bool: True if at least one architecture built successfully;
        False when the toolchain or the x64dbg plugin SDK is unavailable.
    """
    cmake_path = _find_cmake()
    if cmake_path is None:
        _logger.warning(
            "plugin_build_skipped",
            reason="cmake not found",
        )
        return False

    generator = _detect_vs_generator(cmake_path)
    if generator is None:
        _logger.warning(
            "plugin_build_skipped",
            reason="no Visual Studio generator detected",
        )
        return False

    sdk_path = _resolve_x64dbg_sdk_path(x64dbg_path)
    if sdk_path is None:
        _logger.warning(
            "plugin_build_skipped",
            reason="x64dbg plugin SDK not found under installation",
            x64dbg_path=str(x64dbg_path),
        )
        return False

    configure_timeout = _cmake_timeout("INTELLICRACK_CMAKE_TIMEOUT", _DEFAULT_CMAKE_TIMEOUT_S)
    build_timeout = _cmake_timeout("INTELLICRACK_BUILD_TIMEOUT", _DEFAULT_BUILD_TIMEOUT_S)

    _logger.info(
        "plugin_build_starting",
        generator=generator,
        plugin_dir=str(plugin_dir),
        configure_timeout_s=configure_timeout,
        build_timeout_s=build_timeout,
    )

    archs: list[tuple[str, str, str]] = [
        ("x64", "x64", "ON"),
        ("x32", "Win32", "OFF"),
    ]
    built = False

    for arch_label, target_platform, build_x64_flag in archs:
        build_dir = plugin_dir / f"build_{arch_label}"
        build_dir.mkdir(parents=True, exist_ok=True)

        if not _run_cmake_step(
            [
                str(cmake_path),
                str(plugin_dir),
                "-G",
                generator,
                "-A",
                target_platform,
                f"-DBUILD_X64={build_x64_flag}",
                f"-DX64DBG_SDK_PATH={sdk_path}",
            ],
            cwd=build_dir,
            timeout_s=configure_timeout,
            arch=arch_label,
            phase="configure",
        ):
            continue

        if not _run_cmake_step(
            [str(cmake_path), "--build", ".", "--config", "Release"],
            cwd=build_dir,
            timeout_s=build_timeout,
            arch=arch_label,
            phase="build",
        ):
            continue

        _logger.info(
            "plugin_build_succeeded",
            arch=arch_label,
        )
        built = True

    return built


def _run_cmake_step(
    cmd: list[str],
    *,
    cwd: Path,
    timeout_s: int,
    arch: str,
    phase: str,
) -> bool:
    """Run one cmake invocation and surface stdout/stderr on failure.

    Args:
        cmd: Argument list to pass to subprocess.
        cwd: Working directory for the invocation.
        timeout_s: Hard timeout for this step.
        arch: Architecture label for logging.
        phase: ``"configure"`` or ``"build"``.

    Returns:
        bool: True on a clean exit; False on any error (the failure
        details are logged).
    """
    try:
        result = _subprocess_run(
            cmd,
            capture_output=False,
            stdout=PIPE,
            stderr=PIPE,
            cwd=str(cwd),
            timeout=timeout_s,
            text=True,
            check=True,
        )
    except CalledProcessError as exc:
        _logger.warning(
            "plugin_build_failed",
            arch=arch,
            phase=phase,
            returncode=exc.returncode,
            stdout=str(exc.stdout or "").strip(),
            stderr=str(exc.stderr or "").strip(),
        )
        return False
    except TimeoutExpired as exc:
        _logger.warning(
            "plugin_build_timeout",
            arch=arch,
            phase=phase,
            timeout_s=timeout_s,
            stdout=(str(exc.stdout) if exc.stdout else "").strip(),
            stderr=(str(exc.stderr) if exc.stderr else "").strip(),
        )
        return False
    except OSError as exc:
        _logger.warning(
            "plugin_build_oserror",
            arch=arch,
            phase=phase,
            error=str(exc),
        )
        return False

    if result.stdout:
        _logger.debug("plugin_build_stdout", arch=arch, phase=phase, stdout=result.stdout.strip())
    if result.stderr:
        _logger.debug("plugin_build_stderr", arch=arch, phase=phase, stderr=result.stderr.strip())
    return True


def _find_plugin_source(plugin_dir: Path, filename: str) -> Path | None:
    """Locate a pre-built plugin binary in known build output locations.

    Args:
        plugin_dir: Root of the x64dbg-plugin source tree.
        filename: Plugin filename to search for (e.g. ``intellicrack_bridge_x64.dp64``).

    Returns:
        Path | None: Path to the binary if found, otherwise None.
    """
    arch = "x64" if filename.endswith(".dp64") else "x32"
    candidates: list[Path] = [
        plugin_dir / "bin" / filename,
        plugin_dir / "build" / "plugins" / filename,
        plugin_dir / "build" / "Release" / filename,
        plugin_dir / f"build_{arch}" / "plugins" / filename,
        plugin_dir / f"build_{arch}" / "Release" / filename,
    ]
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def deploy_x64dbg_plugin_detailed(x64dbg_path: Path, source_root: Path | None = None) -> DeployResult:
    """Deploy the Intellicrack bridge plugin into x64dbg's plugins directories.

    Copies pre-built ``.dp64`` / ``.dp32`` binaries from the plugin source tree
    into the corresponding ``release/{arch}/plugins/`` folders inside the x64dbg
    installation. Refuses to attempt copying into ``Program Files`` without
    administrator rights.

    Args:
        x64dbg_path: Path to the x64dbg installation root.
        source_root: Optional root directory containing the ``x64dbg-plugin/``
            source folder. Defaults to ``<project_root>/src`` when omitted.

    Returns:
        DeployResult: Aggregated per-arch outcome. ``success`` is True only
        when every arch with a source binary either deployed cleanly or
        was already up-to-date AND at least one arch was actually present.
    """
    base = source_root if source_root is not None else get_project_root() / "src"
    plugin_dir = base / "x64dbg-plugin"
    if not plugin_dir.is_dir():
        _logger.debug(
            "plugin_source_dir_missing",
            path=str(plugin_dir),
        )
        return DeployResult(success=False)

    any_source_found = any(_find_plugin_source(plugin_dir, fn) is not None for _, fn, _ in _PLUGIN_ARCHS)
    if not any_source_found:
        _logger.info(
            "plugin_binaries_build_starting",
            plugin_dir=str(plugin_dir),
        )
        build_x64dbg_plugin(plugin_dir, x64dbg_path)

    requires_admin = _path_requires_admin(x64dbg_path)
    if requires_admin and not _is_user_admin():
        _logger.warning(
            "plugin_deploy_admin_required",
            x64dbg_path=str(x64dbg_path),
        )
        return DeployResult(
            success=False,
            per_arch=[
                ArchDeployResult(
                    arch=arch,
                    filename=filename,
                    status="failed",
                    target=None,
                    error=(
                        "deployment to "
                        f"{x64dbg_path} requires administrator rights; "
                        "rerun Intellicrack elevated or relocate x64dbg outside Program Files"
                    ),
                )
                for arch, filename, _verify_subdir in _PLUGIN_ARCHS
            ],
        )

    per_arch: list[ArchDeployResult] = []
    deployed_count = 0
    failed_count = 0
    found_count = 0

    for arch, filename, verify_subdir in _PLUGIN_ARCHS:
        source = _find_plugin_source(plugin_dir, filename)
        if source is None:
            _logger.debug(
                "plugin_binary_not_found",
                plugin_filename=filename,
            )
            per_arch.append(
                ArchDeployResult(
                    arch=arch,
                    filename=filename,
                    status="missing_source",
                ),
            )
            continue

        found_count += 1
        target_dir = x64dbg_path / Path(verify_subdir)
        target = target_dir / filename

        if target.is_file() and target.stat().st_mtime >= source.stat().st_mtime:
            _logger.debug(
                "plugin_already_up_to_date",
                target=str(target),
            )
            per_arch.append(
                ArchDeployResult(
                    arch=arch,
                    filename=filename,
                    status="up_to_date",
                    target=target,
                ),
            )
            deployed_count += 1
            continue

        try:
            _logger.debug("plugin_deploy_target_dir_mkdir", target_dir=str(target_dir))
            target_dir.mkdir(parents=True, exist_ok=True)
            _logger.debug("plugin_deploy_copy", source=str(source), target=str(target))
            shutil.copy2(source, target)
        except OSError as exc:
            _logger.warning(
                "plugin_deploy_failed",
                target=str(target),
                error=str(exc),
            )
            per_arch.append(
                ArchDeployResult(
                    arch=arch,
                    filename=filename,
                    status="failed",
                    target=target,
                    error=str(exc),
                ),
            )
            failed_count += 1
            continue

        if not target.is_file():
            _logger.warning(
                "plugin_deploy_post_check_missing",
                target=str(target),
            )
            per_arch.append(
                ArchDeployResult(
                    arch=arch,
                    filename=filename,
                    status="failed",
                    target=target,
                    error="post-deploy verification: file not found at target",
                ),
            )
            failed_count += 1
            continue

        _logger.info(
            "plugin_deployed",
            source=str(source),
            target=str(target),
        )
        per_arch.append(
            ArchDeployResult(
                arch=arch,
                filename=filename,
                status="deployed",
                target=target,
            ),
        )
        deployed_count += 1

    overall_success = found_count > 0 and failed_count == 0 and deployed_count == found_count
    return DeployResult(success=overall_success, per_arch=per_arch)


def deploy_x64dbg_plugin(x64dbg_path: Path, source_root: Path | None = None) -> bool:
    """Backwards-compatible wrapper around :func:`deploy_x64dbg_plugin_detailed`.

    Args:
        x64dbg_path: Path to the x64dbg installation root.
        source_root: Optional root directory containing the ``x64dbg-plugin/``
            source folder. Defaults to ``<project_root>/src`` when omitted.

    Returns:
        bool: True when every arch with a source binary deployed cleanly
        (or was already up-to-date); False otherwise.
    """
    return deploy_x64dbg_plugin_detailed(x64dbg_path, source_root).success


def _path_requires_admin(target: Path) -> bool:
    """Return True when writing to ``target`` typically requires admin rights.

    Conservative heuristic: any path under ``%ProgramFiles%`` or
    ``%ProgramFiles(x86)%`` is treated as needing elevation. Anywhere
    else is assumed writable by the current user.

    Args:
        target: Path being written into.

    Returns:
        bool: True when admin rights are likely required on Windows;
        False otherwise (including non-Windows).
    """
    if sys.platform != "win32":
        return False
    try:
        resolved = target.resolve()
    except OSError as exc:
        _logger.warning("path_requires_admin_resolve_failed", target=str(target), error=str(exc))
        return False
    candidates: list[str] = [
        env_val for env_key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432") if (env_val := os.environ.get(env_key))
    ]
    for prefix in candidates:
        try:
            resolved.relative_to(Path(prefix).resolve())
        except (OSError, ValueError) as exc:
            _logger.warning("path_requires_admin_prefix_check_failed", prefix=prefix, error=str(exc))
            continue
        return True
    return False


path_requires_admin = _path_requires_admin
is_user_admin = _is_user_admin
host_arch_aliases = _host_arch_aliases
matches_arch = _matches_arch
format_exception = _format_exception
program_files_x86 = _program_files_x86
cmake_timeout = _cmake_timeout
run_cmake_step = _run_cmake_step
find_cmake = _find_cmake
resolve_x64dbg_sdk_path = _resolve_x64dbg_sdk_path
PLUGIN_ARCHS = _PLUGIN_ARCHS
ToolInstallerVersion = _ToolInstallerVersion


def pefile_available() -> bool:
    """Return whether the optional ``pefile`` dependency is importable.

    Returns:
        bool: True when ``pefile`` was successfully imported at module
        load time, otherwise False.
    """
    return _pefile_available


_DEFAULT_TOOLS_DIR_NAME = "intellicrack_tools"


def _default_tools_directory() -> Path:
    """Return the default tools directory under the user profile.

    Returns:
        Path: ``%LOCALAPPDATA%/intellicrack_tools`` on Windows when
        defined, otherwise ``~/.intellicrack_tools``.
    """
    if sys.platform == "win32":
        if local_appdata := _env_local_appdata():
            return Path(local_appdata) / _DEFAULT_TOOLS_DIR_NAME
    return Path("~").expanduser() / f".{_DEFAULT_TOOLS_DIR_NAME}"


async def find_tool(tool: ToolName, tools_directory: Path | None = None) -> Path | None:
    """Module-level convenience wrapper around :meth:`ToolInstaller.find_tool`.

    Args:
        tool: The tool to find.
        tools_directory: Optional override for the tools install root;
            defaults to :func:`_default_tools_directory`.

    Returns:
        Path | None: The resolved tool path or None when not found.
    """
    installer = ToolInstaller(tools_directory or _default_tools_directory())
    try:
        return await installer.find_tool(tool)
    finally:
        await installer.close()


async def install_tool(tool: ToolName, tools_directory: Path | None = None) -> InstallResult:
    """Module-level convenience wrapper around :meth:`ToolInstaller.install_tool`.

    Args:
        tool: The tool to install.
        tools_directory: Optional override for the tools install root.

    Returns:
        InstallResult: The install outcome reported by the underlying
        installer instance.
    """
    installer = ToolInstaller(tools_directory or _default_tools_directory())
    try:
        return await installer.install_tool(tool)
    finally:
        await installer.close()


async def ensure_tool(tool: ToolName, tools_directory: Path | None = None) -> Path:
    """Module-level convenience wrapper around :meth:`ToolInstaller.ensure_tool`.

    Args:
        tool: The tool to ensure.
        tools_directory: Optional override for the tools install root.

    Returns:
        Path: Path to the ensured tool installation.
    """
    installer = ToolInstaller(tools_directory or _default_tools_directory())
    try:
        return await installer.ensure_tool(tool)
    finally:
        await installer.close()


async def get_version(
    tool: ToolName,
    path: Path | None,
    tools_directory: Path | None = None,
) -> ToolVersion | None:
    """Module-level convenience wrapper around :meth:`ToolInstaller.get_version`.

    Args:
        tool: The tool to query.
        path: Filesystem path of the install (or None for non-filesystem tools).
        tools_directory: Optional override for the tools install root.

    Returns:
        ToolVersion | None: Detected version or None when undetectable.
    """
    installer = ToolInstaller(tools_directory or _default_tools_directory())
    try:
        return await installer.get_version(tool, path)
    finally:
        await installer.close()
