# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Windows Sandbox implementation for isolated binary analysis.

This module provides integration with Windows Sandbox for safe execution and behavioral monitoring of potentially malicious binaries.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from intellicrack.core._subprocess import CREATE_NEW_CONSOLE, PIPE, Popen
from intellicrack.core._xml_gen import Element, ElementTree, SubElement, indent
from intellicrack.core.logging import get_logger, log_sandbox_operation
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.sandbox.base import (
    ExecutionReport,
    ExecutionResult,
    FileChange,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxTimeoutError,
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
    r"""
    Windows Sandbox implementation for isolated binary testing.

    Uses the Windows Sandbox feature (available in Windows 10 Pro/Enterprise)
    to provide an isolated execution environment for binary analysis.

    Args:
        config: Optional sandbox configuration.

    Attributes:
        SANDBOX_EXE: Windows Sandbox executable filename.
        SHARED_FOLDER_NAME: Host-side shared folder name for sandbox mapping.
        SANDBOX_SHARED_PATH: Guest-side path where the shared folder is mounted.
    """

    SANDBOX_EXE = "WindowsSandbox.exe"
    SHARED_FOLDER_NAME = "IntellicrackShared"
    SANDBOX_SHARED_PATH = "C:\\Users\\WDAGUtilityAccount\\Desktop\\Shared"

    def __init__(self, config: SandboxConfig | None = None) -> None:
        super().__init__(config)
        self.process: Popen[bytes] | None = None
        self._wsb_path: Path | None = None
        self._shared_folder: Path | None = None
        self._monitor_folder: Path | None = None
        self._temp_dir: Path | None = None

    async def is_available(self) -> bool:
        """
        Check if Windows Sandbox is available.

        Returns:
            bool: True if Windows Sandbox can be used.
        """
        process_manager = ProcessManager.get_instance()

        try:
            result = await process_manager.run_tracked_async(
                ["where", self.SANDBOX_EXE],
                name="where-sandbox-exe",
                process_timeout=_WHERE_TIMEOUT,
            )
            if result.returncode != _RETURNCODE_SUCCESS:
                _logger.debug("windows_sandbox_exe_not_found", exe=self.SANDBOX_EXE)
                return False

            ps_exe = "pwsh" if shutil.which("pwsh") else "powershell"
            features_result = await process_manager.run_tracked_async(
                [
                    ps_exe,
                    "-Command",
                    "(Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State",
                ],
                name="pwsh-sandbox-feature-check",
                process_timeout=_FEATURE_CHECK_TIMEOUT,
            )

            if "Enabled" in features_result.stdout:
                _logger.info("windows_sandbox_available", feature_state="Enabled")
                is_available = True
            else:
                _logger.warning("windows_sandbox_feature_not_enabled", feature="Containers-DisposableClientVM")
                is_available = False

        except (OSError, RuntimeError) as e:
            _logger.warning("windows_sandbox_availability_check_failed", error=str(e))
            return False
        else:
            return is_available

    def _check_sandbox_alive(self) -> None:
        """
        Verify the sandbox process is still running.

        Raises:
            SandboxError: If the sandbox process has terminated.
        """
        if self.process is not None and self.process.poll() is not None:
            raise SandboxError(_ERR_SANDBOX_TERMINATED)

    async def start(self) -> None:
        """
        Start the Windows Sandbox environment.

        Creates the shared folder structure, generates the .wsb configuration,
        and launches Windows Sandbox.

        Raises:
            SandboxError: If sandbox cannot be started.
        """
        if self.state.status == "running":
            _logger.warning("sandbox_already_running", sandbox_type="windows")
            return

        log_sandbox_operation("start", "windows")
        self.state.status = "starting"
        self.state.last_error = None

        try:
            self._temp_dir = Path(await asyncio.to_thread(tempfile.mkdtemp, prefix="intellicrack_sandbox_"))
            self._shared_folder = self._temp_dir / self.SHARED_FOLDER_NAME
            await asyncio.to_thread(self._shared_folder.mkdir, parents=True, exist_ok=True)

            self._monitor_folder = self._shared_folder / "monitor"
            await asyncio.to_thread(self._monitor_folder.mkdir, exist_ok=True)

            input_folder = self._shared_folder / "input"
            await asyncio.to_thread(input_folder.mkdir, exist_ok=True)

            output_folder = self._shared_folder / "output"
            await asyncio.to_thread(output_folder.mkdir, exist_ok=True)

            logs_folder = self._shared_folder / "logs"
            await asyncio.to_thread(logs_folder.mkdir, exist_ok=True)

            await self._create_monitor_scripts()

            self._wsb_path = self._temp_dir / "intellicrack.wsb"
            await self._generate_wsb_config()

            _logger.info("windows_sandbox_starting", config_path=str(self._wsb_path))

            self.process = await asyncio.to_thread(
                Popen,
                [self.SANDBOX_EXE, str(self._wsb_path)],
                stdout=PIPE,
                stderr=PIPE,
                creationflags=CREATE_NEW_CONSOLE,
            )

            process_manager = ProcessManager.get_instance()
            process_manager.register(
                self.process,
                name="windows-sandbox",
                process_type=ProcessType.SANDBOX,
                metadata={"wsb_config": str(self._wsb_path)},
                cleanup_callback=self.stop,
            )

            await asyncio.sleep(_STARTUP_WAIT_SECONDS)

            self._check_sandbox_alive()

            self.state.status = "running"
            self.state.started_at = datetime.now(UTC)
            self.state.pid = self.process.pid

            _logger.info("windows_sandbox_started", pid=self.process.pid)

        except (OSError, RuntimeError, SandboxError) as e:
            _logger.warning("windows_sandbox_start_failed", error=str(e))
            self.state.status = "error"
            self.state.last_error = str(e)
            await self._cleanup()
            raise SandboxError(_ERR_START_FAILED) from e

    async def stop(self) -> None:
        """
        Stop the Windows Sandbox environment.

        Terminates the sandbox process and cleans up resources.

        Raises:
            SandboxError: If sandbox cannot be stopped cleanly.
        """
        if self.state.status == "stopped":
            _logger.debug("sandbox_already_stopped", sandbox_type="windows")
            return

        self.state.status = "stopping"

        try:
            if self.process is not None:
                pid = self.process.pid
                process_manager = ProcessManager.get_instance()

                try:
                    await process_manager.run_tracked_async(
                        ["taskkill", "/F", "/PID", str(pid)],
                        name="taskkill-sandbox-pid",
                        process_timeout=_TASKKILL_TIMEOUT,
                    )
                except (OSError, RuntimeError):
                    _logger.warning(
                        "pid_taskkill_failed_trying_image_name",
                        pid=pid,
                    )
                    await process_manager.run_tracked_async(
                        ["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
                        name="taskkill-sandbox-fallback",
                        process_timeout=_TASKKILL_TIMEOUT,
                    )

                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(self.process.wait),
                        timeout=_PROCESS_WAIT_TIMEOUT,
                    )
                except TimeoutError:
                    _logger.warning("sandbox_process_terminate_timeout", pid=pid)
                    self.process.kill()
                    await asyncio.to_thread(self.process.wait)

                process_manager.unregister(pid)
                self.process = None

            await self._cleanup()

            self.state.status = "stopped"
            self.state.pid = None
            _logger.info("windows_sandbox_stopped", sandbox_type="windows")

        except (OSError, RuntimeError, SandboxError) as e:
            _logger.warning("windows_sandbox_stop_failed", error=str(e))
            self.state.status = "error"
            self.state.last_error = str(e)
            raise SandboxError(_ERR_STOP_FAILED) from e

    async def _cleanup(self) -> None:
        """Clean up temporary files and folders."""
        if self._temp_dir is not None and await asyncio.to_thread(self._temp_dir.exists):
            try:
                await asyncio.to_thread(
                    shutil.rmtree,
                    self._temp_dir,
                    ignore_errors=True,
                )
            except OSError as e:
                _logger.warning("temp_dir_cleanup_failed", error=str(e))

        self._temp_dir = None
        self._shared_folder = None
        self._monitor_folder = None
        self._wsb_path = None

    async def _generate_wsb_config(self) -> None:
        """
        Generate the .wsb configuration file.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._wsb_path is None or self._shared_folder is None:
            raise SandboxError(_ERR_SANDBOX_PATHS_NOT_INIT)

        config = Element("Configuration")

        mapped_folders = SubElement(config, "MappedFolders")
        folder = SubElement(mapped_folders, "MappedFolder")
        SubElement(folder, "HostFolder").text = str(self._shared_folder)
        SubElement(folder, "SandboxFolder").text = self.SANDBOX_SHARED_PATH
        SubElement(folder, "ReadOnly").text = "false"

        for host_path, sandbox_path, read_only in self._config.shared_folders:
            folder = SubElement(mapped_folders, "MappedFolder")
            SubElement(folder, "HostFolder").text = str(host_path)
            SubElement(folder, "SandboxFolder").text = sandbox_path
            SubElement(folder, "ReadOnly").text = "true" if read_only else "false"

        networking = "Enable" if self._config.network_enabled else "Disable"
        SubElement(config, "Networking").text = networking

        if self._config.memory_limit_mb > 0:
            SubElement(config, "MemoryInMB").text = str(self._config.memory_limit_mb)

        vgpu = "Enable" if self._config.video_enabled else "Disable"
        SubElement(config, "vGPU").text = vgpu

        audio = "Enable" if self._config.audio_enabled else "Disable"
        SubElement(config, "AudioInput").text = audio

        clipboard = "Enable" if self._config.clipboard_enabled else "Disable"
        SubElement(config, "ClipboardRedirection").text = clipboard

        printer = "Enable" if self._config.printer_enabled else "Disable"
        SubElement(config, "PrinterRedirection").text = printer

        if self._config.startup_commands:
            logon_command = SubElement(config, "LogonCommand")
            command_text = " && ".join(self._config.startup_commands)
            SubElement(logon_command, "Command").text = f"cmd.exe /c {command_text}"

        tree = ElementTree(config)
        indent(tree, space="  ")

        wsb_path = self._wsb_path

        def _write_config() -> None:
            with wsb_path.open("wb") as f:
                tree.write(f, encoding="utf-8", xml_declaration=True)

        await asyncio.to_thread(_write_config)

        _logger.debug("wsb_config_generated", path=str(self._wsb_path))

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
        await asyncio.to_thread(file_monitor_ps1.write_text, file_monitor_script, encoding="utf-8")

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
        await asyncio.to_thread(registry_monitor_ps1.write_text, registry_monitor_script, encoding="utf-8")

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
        await asyncio.to_thread(network_monitor_ps1.write_text, network_monitor_script, encoding="utf-8")

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
        await asyncio.to_thread(process_monitor_ps1.write_text, process_monitor_script, encoding="utf-8")

        start_monitors_cmd = self._monitor_folder / "start_monitors.cmd"
        start_monitors_script = """@echo off
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0file_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0registry_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0network_monitor.ps1"
start /min powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0process_monitor.ps1"
"""
        await asyncio.to_thread(start_monitors_cmd.write_text, start_monitors_script, encoding="utf-8")

        _logger.debug("monitoring_scripts_created", path=str(self._monitor_folder))

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """
        Execute a command in the sandbox.

        Args:
            command: Command to execute.
            time_limit: Optional timeout override in seconds.
            working_directory: Optional working directory.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
            SandboxTimeoutError: If command times out.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = time_limit or self._config.timeout_seconds

        script_name = f"exec_{int(time.time() * _MS_PER_SECOND)}.cmd"
        result_name = f"result_{int(time.time() * _MS_PER_SECOND)}.txt"

        script_path = self._shared_folder / "input" / script_name
        result_path = self._shared_folder / "output" / result_name

        sandbox_script_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{script_name}"
        sandbox_result_path = f"{self.SANDBOX_SHARED_PATH}\\output\\{result_name}"

        cd_cmd = f'cd /d "{working_directory}"' if working_directory else ""
        script_content = f"""@echo off
{cd_cmd}
{command}
echo %ERRORLEVEL% > "{sandbox_result_path}"
"""
        await asyncio.to_thread(script_path.write_text, script_content, encoding="utf-8")

        trigger_path = self._shared_folder / "input" / "trigger.cmd"
        trigger_content = f"""@echo off
call "{sandbox_script_path}"
"""
        await asyncio.to_thread(trigger_path.write_text, trigger_content, encoding="utf-8")

        start_time = time.time()

        while time.time() - start_time < effective_timeout:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

            if await asyncio.to_thread(result_path.exists):
                try:
                    result_text_raw = await asyncio.to_thread(result_path.read_text, encoding="utf-8")
                    result_text = result_text_raw.strip()
                    exit_code = int(result_text) if result_text.isdigit() else _RETURNCODE_FAILURE
                except (OSError, ValueError) as e:
                    _logger.debug("result_read_failed", error=str(e))
                else:
                    return (exit_code, "", "")

        raise SandboxTimeoutError(_ERR_CMD_TIMEOUT)

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """
        Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            time_limit: Optional timeout override in seconds.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if not await asyncio.to_thread(binary_path.exists):
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = time_limit or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input\\{binary_path.name}")

        if monitor:
            logs_folder = self._shared_folder / "logs"
            log_files = await asyncio.to_thread(lambda: list(logs_folder.glob("*.log")))
            for log_file in log_files:
                await asyncio.to_thread(log_file.unlink)

            await self.run_command(
                f'"{self.SANDBOX_SHARED_PATH}\\monitor\\start_monitors.cmd"',
                time_limit=_MONITOR_START_TIMEOUT,
            )
            await asyncio.sleep(_MONITOR_WAIT_SECONDS)

        binary_sandbox_path = f"{self.SANDBOX_SHARED_PATH}\\input\\{binary_path.name}"
        command = f'"{binary_sandbox_path}" {" ".join(f"{chr(34)}{a}{chr(34)}" for a in (args or []))}'

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self.run_command(
                command,
                time_limit=effective_timeout,
            )
            result = "success"
        except SandboxTimeoutError as e:
            _logger.warning("sandbox_execution_timeout", binary=binary_path.name, timeout=effective_timeout)
            exit_code = _RETURNCODE_FAILURE
            result = "timeout"
            stderr = str(e)
            stdout = ""
        except SandboxError as e:
            _logger.warning("sandbox_execution_error", binary=binary_path.name, error=str(e))
            exit_code = _RETURNCODE_FAILURE
            result = "error"
            stderr = str(e)
            stdout = ""
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
        """
        Parse file monitoring log.

        Returns:
            list[FileChange]: List of file changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "file_changes.log"
        if not await asyncio.to_thread(log_path.exists):
            return []

        changes: list[FileChange] = []
        try:
            raw_text = await asyncio.to_thread(log_path.read_text, encoding="utf-8", errors="ignore")
            for line in raw_text.splitlines():
                parts = line.split("|")
                if len(parts) >= _LOG_MIN_PARTS:
                    changes.append(
                        FileChange(
                            path=parts[_LOG_PATH_INDEX],
                            operation=validate_file_operation(parts[_LOG_OPERATION_INDEX]),
                            old_path=None,
                            timestamp=parts[_LOG_TIMESTAMP_INDEX],
                            size=None,
                        ),
                    )
        except (OSError, ValueError) as e:
            _logger.warning("file_log_parse_failed", error=str(e))

        return changes

    async def _parse_registry_log(self) -> list[RegistryChange]:
        """
        Parse registry monitoring log.

        Returns:
            list[RegistryChange]: List of registry changes detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "registry_changes.log"
        if not await asyncio.to_thread(log_path.exists):
            return []

        changes: list[RegistryChange] = []
        try:
            raw_text = await asyncio.to_thread(log_path.read_text, encoding="utf-8", errors="ignore")
            for line in raw_text.splitlines():
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
                        ),
                    )
        except (OSError, ValueError) as e:
            _logger.warning("registry_log_parse_failed", error=str(e))

        return changes

    async def _parse_network_log(self) -> list[NetworkActivity]:
        """
        Parse network monitoring log.

        Returns:
            list[NetworkActivity]: List of network activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "network_activity.log"
        if not await asyncio.to_thread(log_path.exists):
            return []

        activities: list[NetworkActivity] = []
        try:
            raw_text = await asyncio.to_thread(log_path.read_text, encoding="utf-8", errors="ignore")
            for line in raw_text.splitlines():
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
                        ),
                    )
        except (OSError, ValueError) as e:
            _logger.warning("network_log_parse_failed", error=str(e))

        return activities

    async def _parse_process_log(self) -> list[ProcessActivity]:
        """
        Parse process monitoring log.

        Returns:
            list[ProcessActivity]: List of process activity detected during execution.
        """
        if self._shared_folder is None:
            return []

        log_path = self._shared_folder / "logs" / "process_activity.log"
        if not await asyncio.to_thread(log_path.exists):
            return []

        activities: list[ProcessActivity] = []
        try:
            raw_text = await asyncio.to_thread(log_path.read_text, encoding="utf-8", errors="ignore")
            for line in raw_text.splitlines():
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
                        ),
                    )
        except (OSError, ValueError) as e:
            _logger.warning("process_log_parse_failed", error=str(e))

        return activities

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """
        Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path relative to sandbox shared folder.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        if not await asyncio.to_thread(source.exists):
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest_path = self._shared_folder / dest
        await asyncio.to_thread(dest_path.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", source=str(source), dest=dest)
        except OSError as e:
            _logger.warning("copy_to_sandbox_failed", source=str(source), dest=dest, error=str(e))
            raise SandboxError(_ERR_COPY_TO_SANDBOX_FAILED) from e

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """
        Copy a file from the sandbox.

        Args:
            source: Source path relative to sandbox shared folder.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        source_path = self._shared_folder / source

        if not await asyncio.to_thread(source_path.exists):
            raise SandboxError(_ERR_SOURCE_IN_SANDBOX_NOT_FOUND)

        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", source=source, dest=str(dest))
        except OSError as e:
            _logger.warning("copy_from_sandbox_failed", source=source, dest=str(dest), error=str(e))
            raise SandboxError(_ERR_COPY_FROM_SANDBOX_FAILED) from e
