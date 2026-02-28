"""Tool installer and detector for Intellicrack.

This module handles automatic detection, downloading, and installation
of reverse engineering tools required by the platform.
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

from intellicrack.core._subprocess import TimeoutExpired

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager
from ..core.types import ToolError, ToolName


_logger = get_logger("bridges.installer")

_ERR_UNSUPPORTED_ARCHIVE = "unsupported archive format"
_ERR_EXTRACTION_FAILED = "extraction failed"
_ERR_ENSURE_FAILED = "failed to ensure tool"
_ERR_EXTRACT_FAILED_FMT = "failed to extract archive"
_MIN_URL_PARTS = 2
_PROGRESS_CHUNK = 8192
_ONE_MB = 1024 * 1024


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
            Version string in major.minor.patch format.
        """
        return f"{self.major}.{self.minor}.{self.patch}"

    def __ge__(self, other: ToolVersion) -> bool:
        """Compare versions.

        Args:
            other: Version to compare against.

        Returns:
            True if this version is greater or equal.
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
            Path(os.path.expanduser("~/ghidra")),
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
    ToolName.RADARE2: ToolInfo(
        name=ToolName.RADARE2,
        display_name="radare2",
        common_paths=[
            Path("C:/Program Files/radare2"),
            Path("C:/Tools/radare2"),
            Path("C:/radare2"),
            Path("D:/Tools/radare2"),
        ],
        executables=["radare2.exe", "r2.exe"],
        download_url="https://github.com/radareorg/radare2/releases/latest",
        version_command=["radare2.exe", "-v"],
        min_version="5.9.0",
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
    ToolName.BINARY: ToolInfo(
        name=ToolName.BINARY,
        display_name="Binary Operations",
        common_paths=[],
        executables=[],
        download_url="",
        version_command=[],
        min_version="",
    ),
}


class ToolInstaller:
    """Handles automatic tool detection and installation.

    Attributes:
        tools_directory: Base directory for tool installations.
        _http_client: HTTP client for downloads.
    """

    def __init__(self, tools_directory: Path) -> None:
        """Initialize the tool installer.

        Args:
            tools_directory: Directory where tools should be installed.
        """
        self.tools_directory = tools_directory
        self._http_client: httpx.AsyncClient | None = None

        self.tools_directory.mkdir(parents=True, exist_ok=True)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            Async HTTP client instance.
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
            Path to tool installation or None if not found.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            _logger.warning("unknown_tool", extra={"tool": str(tool)})
            return None

        if tool == ToolName.FRIDA:
            return await self._find_frida()

        if tool in {ToolName.PROCESS, ToolName.BINARY}:
            return Path("builtin")

        for common_path in tool_info.common_paths:
            if common_path.exists():
                for exe in tool_info.executables:
                    exe_path = common_path / exe
                    if exe_path.exists():
                        _logger.info("tool_found", extra={"tool": tool_info.display_name, "path": str(exe_path)})
                        return common_path

        for exe in tool_info.executables:
            found = shutil.which(exe)
            if found is not None:
                found_path = Path(found).parent
                _logger.info("tool_found_in_path", extra={"tool": tool_info.display_name, "path": str(found_path)})
                return found_path

        tool_dir: Path = self.tools_directory / str(tool.value)
        if tool_dir.exists():
            for exe in tool_info.executables:
                exe_path = tool_dir / exe
                if exe_path.exists():
                    _logger.info("tool_found_in_tools_dir", extra={"tool": tool_info.display_name, "path": str(tool_dir)})
                    return tool_dir

                subdir: Path
                for subdir in tool_dir.iterdir():
                    if subdir.is_dir():
                        exe_path = subdir / exe
                        if exe_path.exists():
                            _logger.info("tool_found", extra={"tool": tool_info.display_name, "path": str(subdir)})
                            return subdir

        _logger.debug("tool_not_found", extra={"tool": tool_info.display_name})
        return None

    @staticmethod
    async def _find_frida() -> Path | None:
        """Check if Frida Python package is installed.

        Returns:
            Path indicating Frida is installed, or None.
        """
        try:
            process_manager = ProcessManager.get_instance()
            result = await process_manager.run_tracked_async(
                ["python", "-c", "import frida; print(frida.__version__)"],
                name="frida-version-check",
                timeout=10,
            )
            if result.returncode == 0:
                _logger.info("frida_installed", extra={"version": result.stdout.strip()})
                return Path("frida-python")
        except (TimeoutExpired, FileNotFoundError) as e:
            _logger.debug("frida_check_failed", extra={"error": str(e)})
        return None

    async def get_version(self, tool: ToolName, path: Path) -> ToolVersion | None:
        """Get the version of an installed tool.

        Args:
            tool: The tool to check.
            path: Path to the tool installation.

        Returns:
            Parsed version or None if couldn't determine.
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
                    timeout=10,
                )
            else:
                if path != Path("builtin"):
                    exe = path / cmd[0]
                    if exe.exists():
                        cmd[0] = str(exe)

                result = await process_manager.run_tracked_async(
                    cmd,
                    name=f"{tool.value}-version",
                    timeout=30,
                    cwd=str(path) if path.is_dir() else None,
                )

            if result.returncode == 0:
                version_str = result.stdout.strip()
                return self._parse_version(version_str)

        except (TimeoutExpired, OSError) as e:
            _logger.debug("version_check_failed", extra={"tool": str(tool), "error": str(e)})

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
            Parsed ToolVersion or None if the file cannot be read.
        """
        props_path = path / "Ghidra" / "application.properties"
        if not props_path.is_file():
            _logger.debug(
                "ghidra_properties_not_found",
                extra={"path": str(props_path)},
            )
            return None

        try:
            text = props_path.read_text(encoding="utf-8")
        except OSError as e:
            _logger.debug(
                "ghidra_properties_read_failed",
                extra={"path": str(props_path), "error": str(e)},
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
                    extra={"version": version_str, "path": str(props_path)},
                )
                return version

        _logger.debug(
            "ghidra_version_key_missing",
            extra={"path": str(props_path)},
        )
        return None

    @staticmethod
    def _parse_version(version_str: str) -> ToolVersion:
        """Parse a version string.

        Args:
            version_str: Raw version string.

        Returns:
            Parsed ToolVersion.
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
            True if installation is valid and meets minimum version.
        """
        if tool in {ToolName.PROCESS, ToolName.BINARY}:
            return True

        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return False

        if tool == ToolName.FRIDA:
            return path == Path("frida-python")

        for exe in tool_info.executables:
            exe_path = path / exe
            if exe_path.exists():
                version = await self.get_version(tool, path)
                if version is not None and tool_info.min_version:
                    min_ver = self._parse_version(tool_info.min_version)
                    if version >= min_ver:
                        return True
                    _logger.warning(
                        "version_below_minimum",
                        extra={"tool": tool_info.display_name, "version": str(version), "min_version": tool_info.min_version},
                    )
                    return False
                return True

        return False

    async def install_tool(self, tool: ToolName) -> InstallResult:
        """Download and install a tool.

        Args:
            tool: The tool to install.

        Returns:
            InstallResult with installation status.
        """
        tool_info = TOOL_REGISTRY.get(tool)
        if tool_info is None:
            return InstallResult(success=False, error=f"Unknown tool: {tool}")

        if tool == ToolName.FRIDA:
            return await self._install_frida()

        if tool in {ToolName.PROCESS, ToolName.BINARY}:
            return InstallResult(success=True, path=Path("builtin"))

        if not tool_info.download_url:
            return InstallResult(
                success=False,
                error=f"No download URL configured for {tool_info.display_name}",
            )

        try:
            _logger.info("tool_installing", extra={"tool": tool_info.display_name})

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

            download_path.unlink(missing_ok=True)

            version = await self.get_version(tool, install_path)
            _logger.info("tool_installed", extra={"tool": tool_info.display_name, "version": str(version), "path": str(install_path)})

            return InstallResult(
                success=True,
                path=install_path,
                version=version,
            )

        except Exception as e:
            _logger.exception("tool_install_failed", extra={"tool": tool_info.display_name})
            return InstallResult(success=False, error=str(e))

    async def _install_frida(self) -> InstallResult:
        """Install Frida Python package.

        Returns:
            InstallResult with installation status.
        """
        try:
            _logger.info("frida_pip_installing")
            process_manager = ProcessManager.get_instance()

            result = await process_manager.run_tracked_async(
                ["pip", "install", "--upgrade", "frida", "frida-tools"],
                name="pip-install-frida",
                timeout=300,
            )

            if result.returncode == 0:
                version_result = await process_manager.run_tracked_async(
                    ["python", "-c", "import frida; print(frida.__version__)"],
                    name="frida-version-verify",
                    timeout=10,
                )
                version = self._parse_version(version_result.stdout.strip())
                _logger.info("frida_installed", extra={"version": str(version)})
                return InstallResult(
                    success=True,
                    path=Path("frida-python"),
                    version=version,
                )

            return InstallResult(
                success=False,
                error=f"pip install failed: {result.stderr}",
            )

        except Exception as e:
            return InstallResult(success=False, error=str(e))

    async def _get_latest_release_url(self, tool: ToolName) -> str | None:
        """Get the latest release download URL from GitHub.

        Args:
            tool: Tool to get release for.

        Returns:
            Download URL or None if not found.
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
                elif tool == ToolName.RADARE2 and "w64" in name and name.endswith(".zip"):
                    return download_url

        except Exception:
            _logger.exception("release_info_fetch_failed")

        return None

    async def _download_file(self, url: str) -> Path | None:
        """Download a file to temporary location.

        Args:
            url: URL to download.

        Returns:
            Path to downloaded file or None on failure.
        """
        try:
            client = await self._get_client()

            filename = url.rsplit("/", maxsplit=1)[-1]
            temp_path = Path(tempfile.gettempdir()) / filename

            _logger.info("download_starting", extra={"file_name": filename})

            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", 0))
                downloaded = 0

                with open(temp_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            percent = (downloaded / total) * 100
                            if downloaded % _ONE_MB < _PROGRESS_CHUNK:
                                _logger.debug("download_progress", extra={"percent": round(percent, 1)})

            _logger.info("download_completed", extra={"file_name": filename, "bytes": downloaded})

        except Exception:
            _logger.exception("download_failed")
            return None
        else:
            return temp_path

    async def _extract_archive(self, archive_path: Path, tool: ToolName) -> Path:
        """Extract an archive to the tools directory.

        Args:
            archive_path: Path to the archive.
            tool: Tool being extracted.

        Returns:
            Path to extracted tool.

        Raises:
            ToolError: If extraction fails.
        """
        if archive_path.suffix != ".zip":
            raise ToolError(_ERR_UNSUPPORTED_ARCHIVE)

        tool_dir = self.tools_directory / tool.value
        tool_dir.mkdir(parents=True, exist_ok=True)

        _logger.info("extraction_starting", extra={"path": str(tool_dir)})

        try:
            await asyncio.to_thread(
                self._extract_zip,
                archive_path,
                tool_dir,
            )
            subdirs = [d for d in tool_dir.iterdir() if d.is_dir()]
        except Exception as e:
            _logger.exception("extraction_failed")
            raise ToolError(_ERR_EXTRACT_FAILED_FMT) from e
        else:
            return subdirs[0] if len(subdirs) == 1 else tool_dir

    @staticmethod
    def _extract_zip(archive_path: Path, dest_dir: Path) -> None:
        """Extract a zip archive.

        Args:
            archive_path: Path to zip file.
            dest_dir: Destination directory.
        """
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)

    async def ensure_tool(self, tool: ToolName) -> Path:
        """Ensure a tool is available, installing if necessary.

        Args:
            tool: The tool to ensure.

        Returns:
            Path to tool installation.

        Raises:
            ToolError: If tool cannot be found or installed.
        """
        path = await self.find_tool(tool)

        if path is not None:
            if await self.verify_tool(tool, path):
                return path
            _logger.warning("tool_verification_failed", extra={"tool": str(tool)})

        result = await self.install_tool(tool)
        if result.success and result.path is not None:
            return result.path

        raise ToolError(_ERR_ENSURE_FAILED)

    async def get_all_tool_status(self) -> dict[ToolName, tuple[bool, Path | None]]:
        """Get status of all tools.

        Returns:
            Dict mapping tool name to (available, path) tuple.
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
