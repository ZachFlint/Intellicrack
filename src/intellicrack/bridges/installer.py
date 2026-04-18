# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool installer and detector for Intellicrack.

This module handles automatic detection, downloading, and installation of reverse engineering tools required by the platform.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import httpx

from intellicrack.core._subprocess import (
    PIPE,
    CalledProcessError,
    TimeoutExpired,
    run as _subprocess_run,
)
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.types import ToolError, ToolName


_logger = get_logger("bridges.installer")

_ERR_UNSUPPORTED_ARCHIVE = "unsupported archive format"
_ERR_EXTRACTION_FAILED = "extraction failed"
_ERR_ENSURE_FAILED = "failed to ensure tool"
_ERR_EXTRACT_FAILED_FMT = "failed to extract archive"
_ERR_UNSAFE_ZIP_MEMBER = "unsafe zip member"
_MIN_URL_PARTS = 2
_PROGRESS_CHUNK = 8192
_ONE_MB = 1024 * 1024

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
    """

    name: ToolName
    display_name: str
    common_paths: list[Path] = field(default_factory=list)
    executables: list[str] = field(default_factory=list)
    download_url: str = ""
    version_command: list[str] = field(default_factory=list)
    min_version: str = ""


@dataclass
class ToolVersion:
    """Parsed tool version.

    Attributes:
        major: Major version number.
        minor: Minor version number.
        patch: Patch version number.
        raw: Raw version string.
    """

    major: int = 0
    minor: int = 0
    patch: int = 0
    raw: str = ""

    def __str__(self) -> str:
        """Get string representation.

        Returns:
            str: Version string in major.minor.patch format.
        """
        return f"{self.major}.{self.minor}.{self.patch}"

    def __ge__(self, other: ToolVersion) -> bool:
        """Compare versions.

        Args:
            other: Version to compare against.

        Returns:
            bool: True if this version is greater or equal.
        """
        if self.major != other.major:
            return self.major >= other.major
        if self.minor != other.minor:
            return self.minor >= other.minor
        return self.patch >= other.patch


@dataclass
class InstallResult:
    """Result of tool installation.

    Attributes:
        success: Whether installation succeeded.
        path: Path to installed tool.
        version: Installed version.
        error: Error message if failed.
    """

    success: bool
    path: Path | None = None
    version: ToolVersion | None = None
    error: str | None = None


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
        executables=["support/analyzeHeadless.bat", "support/analyzeHeadless"],
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
        executables=["x64dbg.exe", "x96dbg.exe"],
        download_url="https://github.com/x64dbg/x64dbg/releases/latest",
        version_command=["x64dbg.exe", "-v"],
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
        version_command=["cutter.exe", "--version"],
        min_version="2.3.0",
    ),
    ToolName.FRIDA: ToolInfo(
        name=ToolName.FRIDA,
        display_name="Frida",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=["python", "-c", "import frida; print(frida.__version__)"],
        min_version="16.0.0",
    ),
    ToolName.PROCESS: ToolInfo(
        name=ToolName.PROCESS,
        display_name="Process Control",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
    ),
}


class ToolInstaller:
    """Handles automatic tool detection and installation.

    Records the target directory under which downloaded tools will be
    laid out, creates it on disk if it is missing, and prepares a lazy
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
        """Find an installed tool.

        Searches common installation paths first, then PATH,
        then the tools directory.

        Args:
            tool: The tool to find.

        Returns:
            Path | None: Path to tool installation or None if not found.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            _logger.warning("unknown_tool", tool=str(tool))
            return None

        if tool == ToolName.FRIDA:
            return await self._find_frida()

        if tool == ToolName.PROCESS:
            return Path("builtin")

        for common_path in tool_info.common_paths:
            if await asyncio.to_thread(common_path.exists):
                for exe in tool_info.executables:
                    exe_path = common_path / exe
                    if await asyncio.to_thread(exe_path.exists):
                        _logger.info("tool_found", tool=tool_info.display_name, path=str(exe_path))
                        return common_path

        for exe in tool_info.executables:
            found = await asyncio.to_thread(shutil.which, exe)
            if found is not None:
                found_path = Path(found).parent
                _logger.info("tool_found_in_path", tool=tool_info.display_name, path=str(found_path))
                return found_path

        tool_dir: Path = self.tools_directory / str(tool.value)
        if await asyncio.to_thread(tool_dir.exists):
            for exe in tool_info.executables:
                exe_path = tool_dir / exe
                if await asyncio.to_thread(exe_path.exists):
                    _logger.info("tool_found_in_tools_dir", tool=tool_info.display_name, path=str(tool_dir))
                    return tool_dir

                subdir: Path
                for subdir in await asyncio.to_thread(lambda: list(tool_dir.iterdir())):
                    if await asyncio.to_thread(subdir.is_dir):
                        exe_path = subdir / exe
                        if await asyncio.to_thread(exe_path.exists):
                            _logger.info("tool_found", tool=tool_info.display_name, path=str(subdir))
                            return subdir

        _logger.debug("tool_not_found", tool=tool_info.display_name)
        return None

    @staticmethod
    async def _find_frida() -> Path | None:
        """Check if Frida Python package is installed.

        Returns:
            Path | None: Path indicating Frida is installed, or None.
        """
        try:
            process_manager = ProcessManager.get_instance()
            result = await process_manager.run_tracked_async(
                ["python", "-c", "import frida; print(frida.__version__)"],
                name="frida-version-check",
                process_timeout=10,
            )
            if result.returncode == 0:
                _logger.info("frida_installed", version=result.stdout.strip())
                return Path("frida-python")
        except (TimeoutExpired, FileNotFoundError) as e:
            _logger.debug("frida_check_failed", error=str(e))
        return None

    async def get_version(self, tool: ToolName, path: Path) -> ToolVersion | None:
        """Get the version of an installed tool.

        Args:
            tool: The tool to check.
            path: Path to the tool installation.

        Returns:
            ToolVersion | None: Parsed version or None if couldn't determine.
        """
        if tool == ToolName.GHIDRA:
            return self._get_ghidra_version(path)

        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None or not tool_info.version_command:
            return None

        try:
            cmd = list(tool_info.version_command)
            process_manager = ProcessManager.get_instance()

            if tool == ToolName.FRIDA:
                result = await process_manager.run_tracked_async(
                    cmd,
                    name=f"{tool.value}-version",
                    process_timeout=10,
                )
            else:
                if path != Path("builtin"):
                    exe = path / cmd[0]
                    if await asyncio.to_thread(exe.exists):
                        cmd[0] = str(exe)

                is_dir = await asyncio.to_thread(path.is_dir)
                result = await process_manager.run_tracked_async(
                    cmd,
                    name=f"{tool.value}-version",
                    process_timeout=30,
                    cwd=str(path) if is_dir else None,
                )

            if result.returncode == 0:
                version_str = result.stdout.strip()
                return self._parse_version(version_str)

        except (TimeoutExpired, OSError) as e:
            _logger.debug("version_check_failed", tool=str(tool), error=str(e))

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
        except OSError as e:
            _logger.debug(
                "ghidra_properties_read_failed",
                path=str(props_path),
                error=str(e),
            )
            return None

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("application.version="):
                version_str = stripped.split("=", maxsplit=1)[1].strip()
                version = ToolVersion(raw=version_str)
                if match := re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str):
                    version.major = int(match[1])
                    version.minor = int(match[2])
                    if match[3]:
                        version.patch = int(match[3])
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
    def _parse_version(version_str: str) -> ToolVersion:
        """Parse a version string.

        Args:
            version_str: Raw version string.

        Returns:
            ToolVersion: Parsed ToolVersion.
        """
        version = ToolVersion(raw=version_str)

        if match := re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str):
            version.major = int(match[1])
            version.minor = int(match[2])
            if match[3]:
                version.patch = int(match[3])

        return version

    async def verify_tool(self, tool: ToolName, path: Path) -> bool:
        """Verify a tool installation is valid.

        Args:
            tool: The tool to verify.
            path: Path to installation.

        Returns:
            bool: True if installation is valid and meets minimum version.
        """
        if tool == ToolName.PROCESS:
            return True

        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return False

        if tool == ToolName.FRIDA:
            return path == Path("frida-python")

        for exe in tool_info.executables:
            exe_path = path / exe
            if await asyncio.to_thread(exe_path.exists):
                version = await self.get_version(tool, path)
                if version is not None and tool_info.min_version:
                    min_ver = self._parse_version(tool_info.min_version)
                    if version >= min_ver:
                        return True
                    _logger.warning(
                        "version_below_minimum",
                        tool=tool_info.display_name,
                        version=str(version),
                        min_version=tool_info.min_version,
                    )
                    return False
                return True

        return False

    async def install_tool(self, tool: ToolName) -> InstallResult:
        """Download and install a tool.

        Args:
            tool: The tool to install.

        Returns:
            InstallResult: InstallResult with installation status.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return InstallResult(success=False, error=f"Unknown tool: {tool}")

        if tool == ToolName.FRIDA:
            return await self._install_frida()

        if tool == ToolName.PROCESS:
            return InstallResult(success=True, path=Path("builtin"))

        if not tool_info.download_url:
            return InstallResult(
                success=False,
                error=f"No download URL configured for {tool_info.display_name}",
            )

        try:
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

            install_path = await self._extract_archive(download_path, tool)

            await asyncio.to_thread(download_path.unlink, missing_ok=True)

            version = await self.get_version(tool, install_path)
            _logger.info("tool_installed", tool=tool_info.display_name, version=str(version), path=str(install_path))

            return InstallResult(
                success=True,
                path=install_path,
                version=version,
            )

        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, httpx.HTTPError, ToolError) as e:
            _logger.exception("tool_install_failed", tool=tool_info.display_name)
            return InstallResult(success=False, error=str(e))

    async def _install_frida(self) -> InstallResult:
        """Install Frida Python package.

        Returns:
            InstallResult: InstallResult with installation status.
        """
        try:
            _logger.info("frida_pip_installing", tool="frida")
            process_manager = ProcessManager.get_instance()

            result = await process_manager.run_tracked_async(
                ["pip", "install", "--upgrade", "frida", "frida-tools"],
                name="pip-install-frida",
                process_timeout=300,
            )

            if result.returncode == 0:
                version_result = await process_manager.run_tracked_async(
                    ["python", "-c", "import frida; print(frida.__version__)"],
                    name="frida-version-verify",
                    process_timeout=10,
                )
                version = self._parse_version(version_result.stdout.strip())
                _logger.info("frida_installed", version=str(version))
                return InstallResult(
                    success=True,
                    path=Path("frida-python"),
                    version=version,
                )

            return InstallResult(
                success=False,
                error=f"pip install failed: {result.stderr}",
            )

        except (OSError, RuntimeError, ValueError, CalledProcessError) as e:
            _logger.exception("pip_install_unexpected_error")
            return InstallResult(success=False, error=str(e))

    async def _get_latest_release_url(self, tool: ToolName) -> str | None:
        """Get the latest release download URL from GitHub.

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

            assets: list[dict[str, Any]] = data.get("assets", [])
            for asset in assets:
                name: str = str(asset.get("name", "")).lower()
                download_url: str | None = cast("str | None", asset.get("browser_download_url"))
                if tool == ToolName.GHIDRA:
                    if name.endswith(".zip") and "public" in name:
                        return download_url
                elif tool == ToolName.X64DBG:
                    if name.endswith(".zip") and "snapshot" in name:
                        return download_url
                elif tool == ToolName.CUTTER and "windows" in name and name.endswith(".zip"):
                    return download_url

        except (httpx.HTTPError, OSError, KeyError, ValueError):
            _logger.exception("release_info_fetch_failed", tool=tool.value)

        return None

    async def _download_file(self, url: str) -> Path | None:
        """Download a file to a temporary location by streaming to disk.

        Reads the response incrementally and writes each chunk directly to
        the destination file via ``asyncio.to_thread`` so the archive
        never has to be buffered in memory in full.

        Args:
            url: URL to download.

        Returns:
            Path | None: Path to downloaded file or None on failure.
        """
        try:
            client = await self._get_client()

            filename = url.rsplit("/", maxsplit=1)[-1]
            temp_path = Path(tempfile.gettempdir()) / filename

            _logger.info("download_starting", file_name=filename)

            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", 0))
                downloaded = 0

                file_handle = await asyncio.to_thread(temp_path.open, "wb")
                try:
                    async for chunk in response.aiter_bytes(chunk_size=_PROGRESS_CHUNK):
                        if not chunk:
                            continue
                        await asyncio.to_thread(file_handle.write, chunk)
                        downloaded += len(chunk)
                        if total > 0 and downloaded % _ONE_MB < _PROGRESS_CHUNK:
                            percent = (downloaded / total) * 100
                            _logger.debug("download_progress", percent=round(percent, 1))
                finally:
                    await asyncio.to_thread(file_handle.close)

            _logger.info("download_completed", file_name=filename, bytes=downloaded)

        except (httpx.HTTPError, OSError, ValueError):
            _logger.exception("download_failed", url=url)
            return None
        else:
            return temp_path

    async def _extract_archive(self, archive_path: Path, tool: ToolName) -> Path:
        """Extract an archive to the tools directory.

        Args:
            archive_path: Path to the archive.
            tool: Tool being extracted.

        Returns:
            Path: Path to extracted tool.

        Raises:
            ToolError: If extraction fails.
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
            subdirs = await asyncio.to_thread(lambda: [d for d in tool_dir.iterdir() if d.is_dir()])
        except (OSError, zipfile.BadZipFile, ValueError) as e:
            _logger.warning("extraction_failed", archive=str(archive_path), tool=tool.value, error=str(e))
            raise ToolError(_ERR_EXTRACT_FAILED_FMT) from e
        else:
            return subdirs[0] if len(subdirs) == 1 else tool_dir

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

        Args:
            tool: The tool to ensure.

        Returns:
            Path: Path to tool installation.

        Raises:
            ToolError: If tool cannot be found or installed.
        """
        path = await self.find_tool(tool)

        if path is not None:
            if await self.verify_tool(tool, path):
                return path
            _logger.warning("tool_verification_failed", tool=str(tool))

        result = await self.install_tool(tool)
        if result.success and result.path is not None:
            return result.path

        raise ToolError(_ERR_ENSURE_FAILED)

    async def get_all_tool_status(self) -> dict[ToolName, tuple[bool, Path | None]]:
        """Get status of all tools.

        Returns:
            dict[ToolName, tuple[bool, Path | None]]: Dict mapping tool name to (available, path) tuple.
        """
        status: dict[ToolName, tuple[bool, Path | None]] = {}

        for tool in ToolName:
            path = await self.find_tool(tool)
            if path is not None:
                verified = await self.verify_tool(tool, path)
                status[tool] = (verified, path if verified else None)
            else:
                status[tool] = (False, None)

        return status


_PLUGIN_ARCHS: list[tuple[str, str, str]] = [
    ("x64", "intellicrack_bridge_x64.dp64", "x86_64"),
    ("x32", "intellicrack_bridge_x32.dp32", "i686"),
]


def _find_cmake() -> Path | None:
    """Locate the cmake executable.

    Searches PATH first, then falls back to the Visual Studio bundled cmake
    via ``vswhere.exe``.

    Returns:
        Path | None: Path to cmake if found, otherwise None.
    """
    found = shutil.which("cmake")
    if found is not None:
        return Path(found)

    vswhere = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / ("Microsoft Visual Studio/Installer/vswhere.exe")
    if not vswhere.is_file():
        return None

    try:
        result = _subprocess_run(
            [str(vswhere), "-latest", "-property", "installationPath"],
            capture_output=False,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            timeout=15,
        )
        if vs_path := result.stdout.strip():
            cmake_path = Path(vs_path) / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
            if cmake_path.is_file():
                return cmake_path
    except (OSError, TimeoutExpired):
        pass
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
            timeout=15,
        )
    except (OSError, TimeoutExpired):
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


def build_x64dbg_plugin(plugin_dir: Path, x64dbg_path: Path) -> bool:
    """Build the x64dbg bridge plugin from source using CMake + Visual Studio.

    Attempts to compile both x64 and x32 architectures. Succeeds if at least
    one architecture builds successfully.

    Args:
        plugin_dir: Root of the ``x64dbg_plugin`` source tree containing
            ``CMakeLists.txt``.
        x64dbg_path: Path to the x64dbg installation (passed to CMake
            as a hint for SDK headers).

    Returns:
        bool: True if at least one architecture built successfully.
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

    _logger.info(
        "plugin_build_starting",
        generator=generator,
        plugin_dir=str(plugin_dir),
    )

    archs: list[tuple[str, str, str]] = [
        ("x64", "x64", "ON"),
        ("x32", "Win32", "OFF"),
    ]
    built = False

    for arch_label, platform, build_x64_flag in archs:
        build_dir = plugin_dir / f"build_{arch_label}"
        build_dir.mkdir(parents=True, exist_ok=True)

        try:
            _subprocess_run(
                [
                    str(cmake_path),
                    str(plugin_dir),
                    "-G",
                    generator,
                    "-A",
                    platform,
                    f"-DBUILD_X64={build_x64_flag}",
                    f"-DX64DBG_PATH={x64dbg_path}",
                ],
                capture_output=False,
                stdout=PIPE,
                stderr=PIPE,
                cwd=str(build_dir),
                timeout=120,
                check=True,
            )
            _subprocess_run(
                [str(cmake_path), "--build", ".", "--config", "Release"],
                capture_output=False,
                stdout=PIPE,
                stderr=PIPE,
                cwd=str(build_dir),
                timeout=300,
                check=True,
            )
            _logger.info(
                "plugin_build_succeeded",
                arch=arch_label,
            )
            built = True
        except (CalledProcessError, OSError) as exc:
            _logger.warning(
                "plugin_build_failed",
                arch=arch_label,
                error=str(exc),
            )

    return built


def _find_plugin_source(plugin_dir: Path, filename: str) -> Path | None:
    """Locate a pre-built plugin binary in known build output locations.

    Args:
        plugin_dir: Root of the x64dbg_plugin source tree.
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


def deploy_x64dbg_plugin(x64dbg_path: Path, tools_directory: Path) -> bool:
    """Deploy the Intellicrack bridge plugin into x64dbg's plugins directories.

    Copies pre-built ``.dp64`` / ``.dp32`` binaries from the plugin source tree
    into the corresponding ``release/{arch}/plugins/`` folders inside the x64dbg
    installation.  The copy is skipped when the target is already up-to-date
    (same or newer mtime).

    Args:
        x64dbg_path: Path to the x64dbg installation root.
        tools_directory: Path to the tools directory containing ``x64dbg_plugin/``.

    Returns:
        bool: True if at least one plugin was deployed or is already up-to-date.
    """
    plugin_dir = tools_directory / "x64dbg_plugin"
    if not plugin_dir.is_dir():
        _logger.debug(
            "plugin_source_dir_missing",
            path=str(plugin_dir),
        )
        return False

    any_source_found = any(_find_plugin_source(plugin_dir, fn) is not None for _, fn, _ in _PLUGIN_ARCHS)
    if not any_source_found:
        _logger.info(
            "plugin_binaries_missing_attempting_build",
            plugin_dir=str(plugin_dir),
        )
        build_x64dbg_plugin(plugin_dir, x64dbg_path)

    deployed = False
    for arch, filename, _cpu in _PLUGIN_ARCHS:
        source = _find_plugin_source(plugin_dir, filename)
        if source is None:
            _logger.debug(
                "plugin_binary_not_found",
                plugin_filename=filename,
            )
            continue

        target_dir = x64dbg_path / "release" / arch / "plugins"
        target = target_dir / filename

        if target.is_file() and target.stat().st_mtime >= source.stat().st_mtime:
            _logger.debug(
                "plugin_already_up_to_date",
                target=str(target),
            )
            deployed = True
            continue

        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            _logger.info(
                "plugin_deployed",
                source=str(source),
                target=str(target),
            )
            deployed = True
        except OSError as exc:
            _logger.warning(
                "plugin_deploy_failed",
                target=str(target),
                error=str(exc),
            )

    return deployed
