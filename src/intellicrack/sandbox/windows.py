"""Windows Sandbox implementation for isolated binary analysis.

This module provides integration with Windows Sandbox for safe
execution and behavioral monitoring of potentially malicious binaries.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET  # noqa: S405
from datetime import datetime
from pathlib import Path

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager, ProcessType
from .base import (
    ExecutionReport,
    ExecutionResult,
    FileChange,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)


_logger = get_logger("sandbox.windows")

_WHERE_TIMEOUT = 10
_FEATURE_CHECK_TIMEOUT = 30
_STARTUP_WAIT_SECONDS = 15
_PROCESS_WAIT_TIMEOUT = 10
_TASKKILL_TIMEOUT = 30
_MONITOR_START_TIMEOUT = 10
_MONITOR_WAIT_SECONDS = 2
_POLL_INTERVAL_SECONDS = 1
_LOG_MIN_PARTS = 3
_NETWORK_LOG_MIN_PARTS = 4
_LOG_TIMESTAMP_INDEX = 0
_LOG_OPERATION_INDEX = 1
_LOG_PATH_INDEX = 2
_LOG_LOCAL_ADDR_INDEX = 2
_LOG_REMOTE_ADDR_INDEX = 3
_PROCESS_LOG_PID_INDEX = 2
_PROCESS_LOG_NAME_INDEX = 3
_PROCESS_LOG_PATH_INDEX = 4
_PROCESS_LOG_CMDLINE_INDEX = 5
_ADDRESS_INDEX = 0
_PORT_INDEX = 1
_ADDR_PORT_SPLIT_COUNT = 1
_RETURNCODE_SUCCESS = 0
_RETURNCODE_FAILURE = -1
_MS_PER_SECOND = 1000

_ERR_SANDBOX_NOT_RUNNING = "Sandbox is not running"
_ERR_SHARED_FOLDER_NOT_INIT = "Shared folder not initialized"
_ERR_SANDBOX_PATHS_NOT_INIT = "Sandbox paths not initialized"
_ERR_SANDBOX_TERMINATED = "Windows Sandbox terminated unexpectedly"
_ERR_START_FAILED = "Failed to start Windows Sandbox"
_ERR_STOP_FAILED = "Failed to stop Windows Sandbox"
_ERR_BINARY_NOT_FOUND = "Binary not found"
_ERR_SOURCE_NOT_FOUND = "Source file not found"
_ERR_SOURCE_IN_SANDBOX_NOT_FOUND = "Source file not found in sandbox"
_ERR_COPY_TO_SANDBOX_FAILED = "Failed to copy file to sandbox"
_ERR_COPY_FROM_SANDBOX_FAILED = "Failed to copy file from sandbox"
_ERR_CMD_TIMEOUT = "Command timed out"


class WindowsSandbox(SandboxBase):
    """Windows Sandbox implementation for isolated binary testing.

    Uses the Windows Sandbox feature (available in Windows 10 Pro/Enterprise)
    to provide an isolated execution environment for binary analysis.

    Attributes:
        _process: Windows Sandbox process.
        _wsb_path: Path to the .wsb configuration file.
        _shared_folder: Path to the shared folder.
        _monitor_folder: Path to monitoring scripts folder.
    """

    SANDBOX_EXE = "WindowsSandbox.exe"
    SHARED_FOLDER_NAME = "IntellicrackShared"
    SANDBOX_SHARED_PATH = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared"

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize Windows Sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self._process: subprocess.Popen[bytes] | None = None
        self._wsb_path: Path | None = None
        self._shared_folder: Path | None = None
        self._monitor_folder: Path | None = None
        self._temp_dir: Path | None = None

    async def is_available(self) -> bool:
        """Check if Windows Sandbox is available.

        Returns:
            True if Windows Sandbox can be used.
        """
        process_manager = ProcessManager.get_instance()

        try:
            result = await process_manager.run_tracked_async(
                ["where", self.SANDBOX_EXE],
                name="where-sandbox-exe",
                timeout=_WHERE_TIMEOUT,
            )
            if result.returncode != _RETURNCODE_SUCCESS:
                _logger.debug("windows_sandbox_exe_not_found")
                return False

            features_result = await process_manager.run_tracked_async(
                [
                    "powershell",
                    "-Command",
                    "(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State",
                ],
                name="powershell-sandbox-feature-check",
                timeout=_FEATURE_CHECK_TIMEOUT,
            )

            if "Enabled" in features_result.stdout:
                _logger.info("windows_sandbox_available")
                is_available = True
            else:
                _logger.warning("windows_sandbox_feature_not_enabled")
                is_available = False

        except Exception as e:
            _logger.debug("windows_sandbox_availability_check_failed", extra={"error": str(e)})
            return False
        else:
            return is_available

    async def start(self) -> None:
        """Start the Windows Sandbox environment.

        Creates the shared folder structure, generates the .wsb configuration,
        and launches Windows Sandbox.

        Raises:
            SandboxError: If sandbox cannot be started.
        """
        if self._state.status == "running":
            _logger.warning("sandbox_already_running")
            return

        self._state.status = "starting"
        self._state.last_error = None

        try:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_sandbox_"))
            self._shared_folder = self._temp_dir / self.SHARED_FOLDER_NAME
            self._shared_folder.mkdir(parents=True, exist_ok=True)

            self._monitor_folder = self._shared_folder / "monitor"
            self._monitor_folder.mkdir(exist_ok=True)

            input_folder = self._shared_folder / "input"
            input_folder.mkdir(exist_ok=True)

            output_folder = self._shared_folder / "output"
            output_folder.mkdir(exist_ok=True)

            logs_folder = self._shared_folder / "logs"
            logs_folder.mkdir(exist_ok=True)

            await self._create_monitor_scripts()

            self._wsb_path = self._temp_dir / "intellicrack.wsb"
            await self._generate_wsb_config()

            _logger.info("windows_sandbox_starting", extra={"config_path": str(self._wsb_path)})

            self._process = await asyncio.to_thread(
                subprocess.Popen,
                [self.SANDBOX_EXE, str(self._wsb_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )

            process_manager = ProcessManager.get_instance()
            process_manager.register(
                self._process,
                name="windows-sandbox",
                process_type=ProcessType.SANDBOX,
                metadata={"wsb_config": str(self._wsb_path)},
                cleanup_callback=self.stop,
            )

            await asyncio.sleep(_STARTUP_WAIT_SECONDS)

            if self._process.poll() is not None:
                raise SandboxError(_ERR_SANDBOX_TERMINATED)  # noqa: TRY301

            self._state.status = "running"
            self._state.started_at = datetime.now()
            self._state.pid = self._process.pid

            _logger.info("windows_sandbox_started", extra={"pid": self._process.pid})

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            await self._cleanup()
            raise SandboxError(_ERR_START_FAILED) from e

    async def stop(self) -> None:
        """Stop the Windows Sandbox environment.

        Terminates the sandbox process and cleans up resources.

        Raises:
            SandboxError: If sandbox cannot be stopped cleanly.
        """
        if self._state.status == "stopped":
            _logger.debug("sandbox_already_stopped")
            return

        self._state.status = "stopping"

        try:
            if self._process is not None:
                process_manager = ProcessManager.get_instance()
                process_manager.unregister(self._process.pid)

                await process_manager.run_tracked_async(
                    ["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
                    name="taskkill-sandbox",
                    timeout=_TASKKILL_TIMEOUT,
                )

                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(self._process.wait),
                        timeout=_PROCESS_WAIT_TIMEOUT,
                    )
                except TimeoutError:
                    self._process.kill()

                self._process = None

            await self._cleanup()

            self._state.status = "stopped"
            self._state.pid = None
            _logger.info("windows_sandbox_stopped")

        except Exception as e:
            self._state.status = "error"
            self._state.last_error = str(e)
            raise SandboxError(_ERR_STOP_FAILED) from e

    async def _cleanup(self) -> None:
        """Clean up temporary files and folders."""
        if self._temp_dir is not None and self._temp_dir.exists():
            try:
                await asyncio.to_thread(
                    shutil.rmtree,
                    self._temp_dir,
                    ignore_errors=True,
                )
            except Exception as e:
                _logger.warning("temp_dir_cleanup_failed", extra={"error": str(e)})

        self._temp_dir = None
        self._shared_folder = None
        self._monitor_folder = None
        self._wsb_path = None

    async def _generate_wsb_config(self) -> None:
        """Generate the .wsb configuration file.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._wsb_path is None or self._shared_folder is None:
            raise SandboxError(_ERR_SANDBOX_PATHS_NOT_INIT)

        config = ET.Element("Configuration")

        mapped_folders = ET.SubElement(config, "MappedFolders")
        folder = ET.SubElement(mapped_folders, "MappedFolder")
        ET.SubElement(folder, "HostFolder").text = str(self._shared_folder)
        ET.SubElement(folder, "SandboxFolder").text = self.SANDBOX_SHARED_PATH
        ET.SubElement(folder, "ReadOnly").text = "false"

        for host_path, sandbox_path, read_only in self._config.shared_folders:
            folder = ET.SubElement(mapped_folders, "MappedFolder")
            ET.SubElement(folder, "HostFolder").text = str(host_path)
            ET.SubElement(folder, "SandboxFolder").text = sandbox_path
            ET.SubElement(folder, "ReadOnly").text = "true" if read_only else "false"

        networking = "Enable" if self._config.network_enabled else "Disable"
        ET.SubElement(config, "Networking").text = networking

        if self._config.memory_limit_mb > 0:
            ET.SubElement(config, "MemoryInMB").text = str(self._config.memory_limit_mb)

        vgpu = "Enable" if self._config.video_enabled else "Disable"
        ET.SubElement(config, "vGPU").text = vgpu

        audio = "Enable" if self._config.audio_enabled else "Disable"
        ET.SubElement(config, "AudioInput").text = audio

        clipboard = "Enable" if self._config.clipboard_enabled else "Disable"
        ET.SubElement(config, "ClipboardRedirection").text = clipboard

        printer = "Enable" if self._config.printer_enabled else "Disable"
        ET.SubElement(config, "PrinterRedirection").text = printer

        if self._config.startup_commands:
            logon_command = ET.SubElement(config, "LogonCommand")
            command_text = " && ".join(self._config.startup_commands)
            ET.SubElement(logon_command, "Command").text = f"cmd.exe /c {command_text}"

        tree = ET.ElementTree(config)
        ET.indent(tree, space="  ")

        with open(self._wsb_path, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)

        _logger.debug("wsb_config_generated", extra={"path": str(self._wsb_path)})

    async def _create_monitor_scripts(self) -> None:
        """Create behavioral monitoring scripts for the sandbox."""
        if self._monitor_folder is None:
            return

        file_monitor_ps1 = self._monitor_folder / "file_monitor.ps1"
        file_monitor_script = """
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\file_changes.log"
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\\"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp|$changeType|$path" | Out-File -Append $logPath
}

Register-ObjectEvent $watcher "Created" -Action $action
Register-ObjectEvent $watcher "Changed" -Action $action
Register-ObjectEvent $watcher "Deleted" -Action $action
Register-ObjectEvent $watcher "Renamed" -Action $action

while ($true) { Start-Sleep -Seconds 1 }
"""
        file_monitor_ps1.write_text(file_monitor_script, encoding="utf-8")

        registry_monitor_ps1 = self._monitor_folder / "registry_monitor.ps1"
        registry_monitor_script = """
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\registry_changes.log"

$baselineKeys = @(
    "HKLM:\\SOFTWARE",
    "HKCU:\\SOFTWARE",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services"
)

$baseline = @{}
foreach ($key in $baselineKeys) {
    try {
        $items = Get-ChildItem -Path $key -Recurse -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $baseline[$item.PSPath] = $item.GetHashCode()
        }
    } catch {}
}

while ($true) {
    Start-Sleep -Seconds 5
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    foreach ($key in $baselineKeys) {
        try {
            $items = Get-ChildItem -Path $key -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if (-not $baseline.ContainsKey($item.PSPath)) {
                    "$timestamp|Created|$($item.PSPath)" | Out-File -Append $logPath
                    $baseline[$item.PSPath] = $item.GetHashCode()
                }
            }
        } catch {}
    }
}
"""
        registry_monitor_ps1.write_text(registry_monitor_script, encoding="utf-8")

        network_monitor_ps1 = self._monitor_folder / "network_monitor.ps1"
        network_monitor_script = """
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\network_activity.log"

while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $connections = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
        "$timestamp|$($conn.State)|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$processName" | Out-File -Append $logPath
    }

    Start-Sleep -Seconds 2
}
"""
        network_monitor_ps1.write_text(network_monitor_script, encoding="utf-8")

        process_monitor_ps1 = self._monitor_folder / "process_monitor.ps1"
        process_monitor_script = """
$logPath = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared\\logs\\process_activity.log"
$knownProcesses = @{}

while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $currentProcesses = Get-Process | Select-Object Id, Name, Path, StartTime

    foreach ($proc in $currentProcesses) {
        if (-not $knownProcesses.ContainsKey($proc.Id)) {
            $knownProcesses[$proc.Id] = $proc.Name
            $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            "$timestamp|Created|$($proc.Id)|$($proc.Name)|$($proc.Path)|$cmdLine" | Out-File -Append $logPath
        }
    }

    $currentIds = $currentProcesses | ForEach-Object { $_.Id }
    $terminatedIds = $knownProcesses.Keys | Where-Object { $_ -notin $currentIds }

    foreach ($id in $terminatedIds) {
        "$timestamp|Terminated|$id|$($knownProcesses[$id])" | Out-File -Append $logPath
        $knownProcesses.Remove($id)
    }

    Start-Sleep -Seconds 1
}
"""
        process_monitor_ps1.write_text(process_monitor_script, encoding="utf-8")

        start_monitors_cmd = self._monitor_folder / "start_monitors.cmd"
        start_monitors_script = """@echo off
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0file_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0registry_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0network_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0process_monitor.ps1"
"""
        start_monitors_cmd.write_text(start_monitors_script, encoding="utf-8")

        _logger.debug("monitoring_scripts_created", extra={"path": str(self._monitor_folder)})

    async def execute(
        self,
        command: str,
        timeout: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            timeout: Optional timeout override.
            working_directory: Optional working directory.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = timeout or self._config.timeout_seconds

        script_name = f"exec_{int(time.time() * _MS_PER_SECOND)}.cmd"
        result_name = f"result_{int(time.time() * _MS_PER_SECOND)}.txt"

        script_path = self._shared_folder / "input" / script_name
        result_path = self._shared_folder / "output" / result_name

        sandbox_script_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{script_name}"
        sandbox_result_path = f"{self.SANDBOX_SHARED_PATH}\\output\\{result_name}"

        cd_cmd = f'cd /d "{working_directory}"' if working_directory else ""
        script_content = f'''@echo off
{cd_cmd}
{command}
echo %ERRORLEVEL% > "{sandbox_result_path}"
'''
        script_path.write_text(script_content, encoding="utf-8")

        trigger_path = self._shared_folder / "input" / "trigger.cmd"
        trigger_content = f'''@echo off
call "{sandbox_script_path}"
'''
        trigger_path.write_text(trigger_content, encoding="utf-8")

        start_time = time.time()

        while time.time() - start_time < effective_timeout:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

            if result_path.exists():
                try:
                    result_text = result_path.read_text(encoding="utf-8").strip()
                    exit_code = int(result_text) if result_text.isdigit() else _RETURNCODE_FAILURE
                except Exception as e:
                    _logger.warning("result_read_failed", extra={"error": str(e)})
                else:
                    return (exit_code, "", "")

        raise SandboxError(_ERR_CMD_TIMEOUT)

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        timeout: int | None = None,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        if self._state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if not binary_path.exists():
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = timeout or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input\\{binary_path.name}")

        if monitor:
            logs_folder = self._shared_folder / "logs"
            for log_file in logs_folder.glob("*.log"):
                log_file.unlink()

            await self.execute(
                f'"{self.SANDBOX_SHARED_PATH}\\monitor\\start_monitors.cmd"',
                timeout=_MONITOR_START_TIMEOUT,
            )
            await asyncio.sleep(_MONITOR_WAIT_SECONDS)

        args_str = " ".join(f'"{a}"' for a in (args or []))
        binary_sandbox_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{binary_path.name}"
        command = f'"{binary_sandbox_path}" {args_str}'

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self.execute(
                command,
                timeout=effective_timeout,
            )
            result = "success"
        except SandboxError as e:
            if "timed out" in str(e):
                result = "timeout"
                exit_code = _RETURNCODE_FAILURE
                stdout = ""
                stderr = str(e)
            else:
                result = "error"
                exit_code = _RETURNCODE_FAILURE
                stdout = ""
                stderr = str(e)

        duration = time.time() - start_time

        file_changes: list[FileChange] = []
        registry_changes: list[RegistryChange] = []
        network_activity: list[NetworkActivity] = []
        process_activity: list[ProcessActivity] = []

        if monitor:
            await asyncio.sleep(_MONITOR_WAIT_SECONDS)
            file_changes = await self._parse_file_log()
            registry_changes = await self._parse_registry_log()
            network_activity = await self._parse_network_log()
            process_activity = await self._parse_process_log()

        return ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            file_changes=file_changes,
            registry_changes=registry_changes,
            network_activity=network_activity,
            process_activity=process_activity,
        )

    async def _parse_file_log(self) -> list[FileChange]:
        """Parse file monitoring log.

        Returns:
            List of file changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "file_changes.log"
        if not log_path.exists():
            return []

        changes: list[FileChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _LOG_MIN_PARTS:
                    changes.append(
                        FileChange(
                            path=parts[_LOG_PATH_INDEX],
                            operation=validate_file_operation(parts[_LOG_OPERATION_INDEX]),
                            old_path=None,
                            timestamp=parts[_LOG_TIMESTAMP_INDEX],
                            size=None,
                        )
                    )
        except Exception as e:
            _logger.warning("file_log_parse_failed", extra={"error": str(e)})

        return changes

    async def _parse_registry_log(self) -> list[RegistryChange]:
        """Parse registry monitoring log.

        Returns:
            List of registry changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "registry_changes.log"
        if not log_path.exists():
            return []

        changes: list[RegistryChange] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _LOG_MIN_PARTS:
                    changes.append(
                        RegistryChange(
                            key=parts[_LOG_PATH_INDEX],
                            value_name=None,
                            operation=validate_registry_operation(parts[_LOG_OPERATION_INDEX]),
                            value_type=None,
                            value_data=None,
                            timestamp=parts[_LOG_TIMESTAMP_INDEX],
                        )
                    )
        except Exception as e:
            _logger.warning("registry_log_parse_failed", extra={"error": str(e)})

        return changes

    async def _parse_network_log(self) -> list[NetworkActivity]:
        """Parse network monitoring log.

        Returns:
            List of network activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "network_activity.log"
        if not log_path.exists():
            return []

        activities: list[NetworkActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _NETWORK_LOG_MIN_PARTS:
                    local_parts = parts[_LOG_LOCAL_ADDR_INDEX].rsplit(":", _ADDR_PORT_SPLIT_COUNT)
                    remote_parts = parts[_LOG_REMOTE_ADDR_INDEX].rsplit(":", _ADDR_PORT_SPLIT_COUNT)

                    activities.append(
                        NetworkActivity(
                            protocol="tcp",
                            direction="outbound",
                            local_address=local_parts[_ADDRESS_INDEX] if local_parts else "",
                            local_port=int(local_parts[_PORT_INDEX]) if len(local_parts) > _PORT_INDEX else 0,
                            remote_address=remote_parts[_ADDRESS_INDEX] if remote_parts else "",
                            remote_port=int(remote_parts[_PORT_INDEX]) if len(remote_parts) > _PORT_INDEX else 0,
                            timestamp=parts[_LOG_TIMESTAMP_INDEX],
                            bytes_sent=0,
                            bytes_received=0,
                        )
                    )
        except Exception as e:
            _logger.warning("network_log_parse_failed", extra={"error": str(e)})

        return activities

    async def _parse_process_log(self) -> list[ProcessActivity]:
        """Parse process monitoring log.

        Returns:
            List of process activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "process_activity.log"
        if not log_path.exists():
            return []

        activities: list[ProcessActivity] = []
        try:
            for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("|")
                if len(parts) >= _NETWORK_LOG_MIN_PARTS:
                    activities.append(
                        ProcessActivity(
                            pid=int(parts[_PROCESS_LOG_PID_INDEX]) if parts[_PROCESS_LOG_PID_INDEX].isdigit() else 0,
                            name=parts[_PROCESS_LOG_NAME_INDEX],
                            path=parts[_PROCESS_LOG_PATH_INDEX] if len(parts) > _PROCESS_LOG_PATH_INDEX else None,
                            command_line=parts[_PROCESS_LOG_CMDLINE_INDEX] if len(parts) > _PROCESS_LOG_CMDLINE_INDEX else None,
                            parent_pid=None,
                            operation=validate_process_operation(parts[_LOG_OPERATION_INDEX]),
                            exit_code=None,
                            timestamp=parts[_LOG_TIMESTAMP_INDEX],
                        )
                    )
        except Exception as e:
            _logger.warning("process_log_parse_failed", extra={"error": str(e)})

        return activities

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path relative to sandbox shared folder.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        if not source.exists():
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest_path = self._shared_folder / dest
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", extra={"source": str(source), "dest": dest})
        except Exception as e:
            raise SandboxError(_ERR_COPY_TO_SANDBOX_FAILED) from e

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox.

        Args:
            source: Source path relative to sandbox shared folder.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        source_path = self._shared_folder / source

        if not source_path.exists():
            raise SandboxError(_ERR_SOURCE_IN_SANDBOX_NOT_FOUND)

        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", extra={"source": source, "dest": str(dest)})
        except Exception as e:
            raise SandboxError(_ERR_COPY_FROM_SANDBOX_FAILED) from e
