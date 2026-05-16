# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Windows Sandbox implementation for isolated binary analysis.

This module provides integration with Windows Sandbox for safe execution and behavioral monitoring of potentially malicious binaries.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import secrets
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, cast

from intellicrack.core._subprocess import CREATE_NEW_CONSOLE, PIPE, Popen
from intellicrack.core._xml_gen import Element, ElementTree, SubElement, indent
from intellicrack.core.logging import get_logger, log_sandbox_operation
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.sandbox._log_helpers import format_yara_match as _format_yara_match
from intellicrack.sandbox._log_parsers import (
    parse_api_trace_log,
    parse_clipboard_log,
    parse_dll_log,
    parse_file_log,
    parse_injection_log,
    parse_kernel_object_log,
    parse_network_log,
    parse_process_log,
    parse_registry_log,
    parse_resource_log,
    parse_service_log,
)
from intellicrack.sandbox.base import (
    ExecutionReport,
    ExecutionResult,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxTimeoutError,
)


if TYPE_CHECKING:
    from collections.abc import Callable


_logger = get_logger(__name__)

_WHERE_TIMEOUT = 10
_FEATURE_CHECK_TIMEOUT = 30
_DISPATCHER_STARTUP_TIMEOUT = 120
_DISPATCHER_POLL_INTERVAL = 0.5
_WORKER_PID_POLL_INTERVAL = 1.0
_WORKER_PID_POLL_TIMEOUT = 90
_PROCESS_WAIT_TIMEOUT = 10
_GRACEFUL_CLOSE_TIMEOUT = 30
_TASKKILL_TIMEOUT = 30
_MONITOR_START_TIMEOUT = 30
_MONITOR_WAIT_SECONDS = 3
_RESULT_POLL_INTERVAL = 0.25
_MINIDUMP_WITH_FULL_MEMORY = 0x00000002
_ERROR_ACCESS_DENIED = 5
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_WM_CLOSE = 0x0010

_RETURNCODE_SUCCESS = 0
_RETURNCODE_FAILURE = -1
_RETURNCODE_UNKNOWN = -2
_MS_PER_SECOND = 1000

_XCOPY_NO_FILES = 2
_XCOPY_INIT_ERROR = 4
_XCOPY_ACCESS_DENIED = 5

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
_ERR_PCAP_START_FAILED = "Packet capture start failed"
_ERR_PCAP_STOP_FAILED = "Packet capture stop failed"
_ERR_PCAP_NOT_ACTIVE = "No active packet capture with this ID"
_ERR_SCREENSHOT_FAILED = "Screenshot capture failed"
_ERR_MEMORY_DUMP_FAILED = "Memory dump failed"
_ERR_MEMORY_DUMP_NOT_WINDOWS = "Memory dump is only supported on Windows"
_ERR_MEMORY_DUMP_TARGET_PID_REQUIRED = (
    "target_pid is required for Windows Sandbox memory_dump: MiniDumpWriteDump must target a specific guest process"
)
_ERR_MEMORY_DUMP_TARGET_PID_INVALID = "target_pid must be a positive integer guest PID"
_ERR_EXTRACT_FILES_FAILED = "Dropped file extraction failed"
_ERR_YARA_NOT_AVAILABLE = "yara-python not installed"
_ERR_DISPATCHER_NOT_READY = "Sandbox dispatcher did not signal ready"
_ERR_SCRIPTS_NOT_FOUND = "Sandbox monitor scripts directory not found"
_ERR_WMI_HIJACK_COMPILE_FAILED = "Failed to compile anti-evasion MOF via mofcomp"
_ERR_WMI_HIJACK_VERIFY_FAILED = "WMI hijack verification did not return spoofed values"
_ERR_WMI_HIJACK_NO_SHARED = "Cannot stage anti-evasion MOF: shared folder not initialized"

_SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


@dataclass(frozen=True)
class _AntiEvasionProfile:
    """Spoofed hardware identity values for a single anti-evasion profile.

    Attributes:
        name: Profile identifier.
        manufacturer: Win32_ComputerSystem.Manufacturer value (also used as
            Win32_ComputerSystemProduct.Vendor via the :attr:`vendor` property).
        model: Win32_ComputerSystem.Model value.
        product_name: Win32_ComputerSystemProduct.Name value.
        identifying_number: Win32_ComputerSystemProduct.IdentifyingNumber value (chassis serial).
        bios_vendor: Spoofed BIOS vendor reported by Win32_BIOS.
        bios_version: Spoofed BIOS version string.
        domain: Win32_ComputerSystem.Domain (typically WORKGROUP for sandboxes).
        number_of_processors: Win32_ComputerSystem.NumberOfProcessors.
        number_of_logical_processors: Win32_ComputerSystem.NumberOfLogicalProcessors.
        total_physical_memory: Win32_ComputerSystem.TotalPhysicalMemory in bytes.
    """

    name: str
    manufacturer: str
    model: str
    product_name: str
    identifying_number: str
    bios_vendor: str
    bios_version: str
    domain: str = "WORKGROUP"
    number_of_processors: int = 1
    number_of_logical_processors: int = 4
    total_physical_memory: int = 17_179_869_184

    @property
    def vendor(self) -> str:
        """Return the Win32_ComputerSystemProduct.Vendor spoofed value.

        Returns:
            str: For the built-in profiles this mirrors :attr:`manufacturer`.
        """
        return self.manufacturer


def resolve_anti_evasion_profile(profile: str) -> _AntiEvasionProfile:
    """Return spoofed hardware identity values for ``profile``.

    Args:
        profile: Profile name (``default``, ``workstation``, or ``laptop``).
            Unknown values fall back to ``default``.

    Returns:
        _AntiEvasionProfile: Populated profile values used to drive WMI hijacking.
    """
    bios_major = secrets.randbelow(30) + 1
    bios_minor = secrets.randbelow(10)
    bios_version = f"A{bios_major}.{bios_minor}"
    bios_vendor = "American Megatrends Inc."

    if profile == "workstation":
        return _AntiEvasionProfile(
            name="workstation",
            manufacturer="Dell Inc.",
            model="OptiPlex 7090",
            product_name="OptiPlex 7090",
            identifying_number=f"SVC{secrets.token_hex(5).upper()}",
            bios_vendor=bios_vendor,
            bios_version=bios_version,
        )
    if profile == "laptop":
        return _AntiEvasionProfile(
            name="laptop",
            manufacturer="Lenovo",
            model="ThinkPad T14 Gen 3",
            product_name="ThinkPad T14 Gen 3",
            identifying_number=f"PF{secrets.token_hex(5).upper()}",
            bios_vendor=bios_vendor,
            bios_version=bios_version,
        )
    return _AntiEvasionProfile(
        name="default",
        manufacturer="HP",
        model="HP EliteDesk 800 G6",
        product_name="HP EliteDesk 800 G6",
        identifying_number=f"MXL{secrets.token_hex(5).upper()}",
        bios_vendor=bios_vendor,
        bios_version=bios_version,
    )


def build_anti_evasion_mof(profile: _AntiEvasionProfile, machine_name: str) -> str:
    """Build a MOF document that hijacks WMI hardware identity classes.

    The MOF redefines ``Win32_ComputerSystem`` and
    ``Win32_ComputerSystemProduct`` as static classes (``[Static]`` qualifier)
    overriding the dynamic CIMV2 provider classes so the spoofed instance values
    are returned to queries such as ``Get-CimInstance Win32_ComputerSystem``.

    Args:
        profile: Anti-evasion profile providing spoofed identity values.
        machine_name: ``ComputerSystem.Name`` value (typically the spoofed hostname).

    Returns:
        str: MOF source text suitable for ``mofcomp.exe``.
    """
    cs_props = (
        f'    [Key] string Name = "{machine_name}";\n'
        f'    string Manufacturer = "{profile.manufacturer}";\n'
        f'    string Model = "{profile.model}";\n'
        f'    string Domain = "{profile.domain}";\n'
        '    string SystemType = "x64-based PC";\n'
        "    string DNSHostName;\n"
        f"    uint32 NumberOfProcessors = {profile.number_of_processors};\n"
        f"    uint32 NumberOfLogicalProcessors = {profile.number_of_logical_processors};\n"
        f"    uint64 TotalPhysicalMemory = {profile.total_physical_memory};\n"
        "    boolean PartOfDomain = FALSE;\n"
    )
    csp_props = (
        f'    [Key] string IdentifyingNumber = "{profile.identifying_number}";\n'
        f'    [Key] string Name = "{profile.product_name}";\n'
        '    [Key] string Version = "1.0";\n'
        f'    string Vendor = "{profile.vendor}";\n'
        f'    string UUID = "{secrets.token_hex(4)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(6)}";\n'
    )
    bios_props = (
        f'    [Key] string Name = "{profile.bios_version}";\n'
        f'    [Key] string SoftwareElementID = "{profile.bios_version}";\n'
        "    [Key] uint16 SoftwareElementState = 3;\n"
        '    [Key] string TargetOperatingSystem = "0";\n'
        f'    [Key] string Version = "{profile.bios_version}";\n'
        f'    string Manufacturer = "{profile.bios_vendor}";\n'
        f'    string SMBIOSBIOSVersion = "{profile.bios_version}";\n'
        "    boolean PrimaryBIOS = TRUE;\n"
    )

    return (
        "#pragma autorecover\n"
        '#pragma namespace("\\\\\\\\.\\\\root\\\\cimv2")\n'
        "\n"
        '#pragma deleteclass("Win32_ComputerSystem", NOFAIL)\n'
        "[Static, dynamic: ToInstance ToSubClass DisableOverride]\n"
        "class Win32_ComputerSystem {\n"
        f"{cs_props}"
        "};\n"
        "instance of Win32_ComputerSystem {\n"
        f'    Name = "{machine_name}";\n'
        f'    Manufacturer = "{profile.manufacturer}";\n'
        f'    Model = "{profile.model}";\n'
        f'    Domain = "{profile.domain}";\n'
        '    SystemType = "x64-based PC";\n'
        f"    NumberOfProcessors = {profile.number_of_processors};\n"
        f"    NumberOfLogicalProcessors = {profile.number_of_logical_processors};\n"
        f"    TotalPhysicalMemory = {profile.total_physical_memory};\n"
        "    PartOfDomain = FALSE;\n"
        "};\n"
        "\n"
        '#pragma deleteclass("Win32_ComputerSystemProduct", NOFAIL)\n'
        "[Static, dynamic: ToInstance ToSubClass DisableOverride]\n"
        "class Win32_ComputerSystemProduct {\n"
        f"{csp_props}"
        "};\n"
        "instance of Win32_ComputerSystemProduct {\n"
        f'    IdentifyingNumber = "{profile.identifying_number}";\n'
        f'    Name = "{profile.product_name}";\n'
        '    Version = "1.0";\n'
        f'    Vendor = "{profile.vendor}";\n'
        "};\n"
        "\n"
        '#pragma deleteclass("Win32_BIOS", NOFAIL)\n'
        "[Static, dynamic: ToInstance ToSubClass DisableOverride]\n"
        "class Win32_BIOS {\n"
        f"{bios_props}"
        "};\n"
        "instance of Win32_BIOS {\n"
        f'    Name = "{profile.bios_version}";\n'
        f'    SoftwareElementID = "{profile.bios_version}";\n'
        "    SoftwareElementState = 3;\n"
        "    TargetOperatingSystem = 0;\n"
        f'    Version = "{profile.bios_version}";\n'
        f'    Manufacturer = "{profile.bios_vendor}";\n'
        f'    SMBIOSBIOSVersion = "{profile.bios_version}";\n'
        "    PrimaryBIOS = TRUE;\n"
        "};\n"
    )


def _assert_wmi_hijack_matches(
    observed: dict[str, str],
    evasion_profile: _AntiEvasionProfile,
) -> None:
    """Raise :class:`SandboxError` if any observed value disagrees with the profile.

    Args:
        observed: Dictionary returned by :meth:`WindowsSandbox._query_wmi_identity`.
        evasion_profile: Expected anti-evasion profile values.

    Raises:
        SandboxError: If one or more identity fields do not match the profile.
    """
    expected: dict[str, str] = {
        "Manufacturer": evasion_profile.manufacturer,
        "Model": evasion_profile.model,
        "ProductName": evasion_profile.product_name,
        "BIOSVendor": evasion_profile.bios_vendor,
        "BIOSVersion": evasion_profile.bios_version,
    }
    mismatches: list[str] = [
        f"{key.lower()}={observed.get(key, '')!r}!={expected_value!r}"
        for key, expected_value in expected.items()
        if observed.get(key, "") != expected_value
    ]
    if mismatches:
        _logger.warning("wmi_hijack_verification_value_mismatch", mismatches=mismatches)
        mismatch_summary = "; ".join(mismatches)
        err_msg = f"{_ERR_WMI_HIJACK_VERIFY_FAILED}: {mismatch_summary}"
        raise SandboxError(err_msg)


class WindowsSandbox(SandboxBase):
    r"""Windows Sandbox implementation for isolated binary testing.

    Uses the Windows Sandbox feature (available in Windows 10 Pro/Enterprise)
    to provide an isolated execution environment for binary analysis. The
    sandbox is launched through ``WindowsSandboxClient.exe`` and monitored
    via an in-guest PowerShell dispatcher that relays command requests on a
    shared folder and captures a full suite of behavioural telemetry via
    bundled monitor scripts.

    Attributes:
        SANDBOX_EXE: Windows Sandbox launcher executable filename.
        SANDBOX_WORKER_EXE: Hyper-V worker process backing the sandbox VM.
        SHARED_FOLDER_NAME: Host-side shared folder name for sandbox mapping.
        SANDBOX_SHARED_PATH: Guest-side path where the shared folder is mounted.
        DISPATCHER_READY_MARKER: Marker filename used to signal dispatcher readiness.
    """

    SANDBOX_EXE = "WindowsSandboxClient.exe"
    SANDBOX_WORKER_EXE = "vmwp.exe"
    SHARED_FOLDER_NAME = "IntellicrackShared"
    SANDBOX_SHARED_PATH = r"C:\Users\WDAGUtilityAccount\Desktop\Shared"
    DISPATCHER_READY_MARKER = "dispatcher_ready.flag"

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the WindowsSandbox with the given configuration.

        Args:
            config: Sandbox configuration for execution settings. If None, uses defaults.
        """
        super().__init__(config)
        self.process: Popen[bytes] | None = None
        self._wsb_path: Path | None = None
        self._shared_folder: Path | None = None
        self._monitor_folder: Path | None = None
        self._temp_dir: Path | None = None
        self._worker_pid: int | None = None
        self._active_captures: dict[str, str] = {}
        _logger.info(
            "windows_sandbox_initialized",
            timeout_seconds=self._config.timeout_seconds,
        )

    async def is_available(self) -> bool:
        """Check if Windows Sandbox is available.

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
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
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
                _logger.warning(
                    "windows_sandbox_feature_not_enabled",
                    feature="Containers-DisposableClientVM",
                )
                is_available = False

        except (OSError, RuntimeError) as e:
            _logger.warning("windows_sandbox_availability_check_failed", error=str(e))
            return False
        else:
            return is_available

    def _check_sandbox_alive(self) -> None:
        """Verify the sandbox process is still running.

        Raises:
            SandboxError: If the sandbox process has terminated.
        """
        if self.process is not None and self.process.poll() is not None:
            _logger.error("windows_sandbox_process_terminated", returncode=self.process.returncode)
            raise SandboxError(_ERR_SANDBOX_TERMINATED)

    async def start(self) -> None:
        """Start the Windows Sandbox environment.

        Creates the shared folder structure, generates the .wsb configuration,
        launches Windows Sandbox, and waits for the in-guest dispatcher to signal
        that it is ready to receive commands.

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
            self._temp_dir = Path(
                await asyncio.to_thread(tempfile.mkdtemp, prefix="intellicrack_sandbox_"),
            )
            self._shared_folder = self._temp_dir / self.SHARED_FOLDER_NAME
            await asyncio.to_thread(self._shared_folder.mkdir, parents=True, exist_ok=True)

            self._monitor_folder = self._shared_folder / "monitor"
            await asyncio.to_thread(self._monitor_folder.mkdir, exist_ok=True)

            for sub in ("input", "output", "logs", "flags"):
                await asyncio.to_thread(
                    (self._shared_folder / sub).mkdir,
                    exist_ok=True,
                )

            trigger_dir = self._shared_folder / "input" / "trigger"
            await asyncio.to_thread(trigger_dir.mkdir, exist_ok=True)

            await self._create_monitor_scripts()
            await self._create_dispatcher_scripts()

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
                name="windows-sandbox-client",
                process_type=ProcessType.SANDBOX,
                metadata={"wsb_config": str(self._wsb_path)},
                cleanup_callback=self.stop,
            )

            await self._wait_for_dispatcher_ready()
            self._check_sandbox_alive()

            worker_pid = await self._resolve_worker_pid()
            if worker_pid is not None:
                self._worker_pid = worker_pid
                process_manager.register_external_pid(
                    worker_pid,
                    name="windows-sandbox-worker",
                    process_type=ProcessType.SANDBOX,
                    metadata={"client_pid": self.process.pid},
                )
                _logger.info("windows_sandbox_worker_registered", worker_pid=worker_pid)
            else:
                _logger.warning("windows_sandbox_worker_pid_not_found")

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
        """Stop the Windows Sandbox environment.

        Attempts a graceful WM_CLOSE on the sandbox client first, falling back
        to ``taskkill /F`` on the vmwp worker and the client if graceful close
        does not complete within the allotted window.

        Raises:
            SandboxError: If sandbox cannot be stopped cleanly.
        """
        if self.state.status == "stopped":
            _logger.debug("sandbox_already_stopped", sandbox_type="windows")
            return

        self.state.status = "stopping"
        process_manager = ProcessManager.get_instance()

        try:
            if self.process is not None:
                pid = self.process.pid
                graceful_ok = await self._try_graceful_close(pid)

                if not graceful_ok:
                    await self._force_kill_sandbox(pid)

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

            if self._worker_pid is not None:
                worker_pid = self._worker_pid
                try:
                    process_manager.terminate_external_pid(worker_pid, force=True)
                except (OSError, RuntimeError) as worker_err:
                    _logger.warning(
                        "worker_pid_terminate_failed",
                        worker_pid=worker_pid,
                        error=str(worker_err),
                    )
                self._worker_pid = None

            await self._cleanup()

            self.state.status = "stopped"
            self.state.pid = None
            _logger.info("windows_sandbox_stopped", sandbox_type="windows")

        except (OSError, RuntimeError, SandboxError) as e:
            _logger.warning("windows_sandbox_stop_failed", error=str(e))
            self.state.status = "error"
            self.state.last_error = str(e)
            raise SandboxError(_ERR_STOP_FAILED) from e

    async def _try_graceful_close(self, pid: int) -> bool:
        """Send ``WM_CLOSE`` to the sandbox client and wait for it to exit.

        Args:
            pid: Windows Sandbox client PID.

        Returns:
            bool: True if the client closed gracefully within the timeout, False otherwise.
        """
        if sys.platform != "win32":
            return False

        def _post_wm_close() -> bool:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            enum_windows_proc = ctypes.WINFUNCTYPE(
                ctypes.c_bool,
                ctypes.c_void_p,
                ctypes.c_void_p,
            )

            user32.EnumWindows.argtypes = [enum_windows_proc, ctypes.c_void_p]
            user32.EnumWindows.restype = ctypes.c_bool
            user32.GetWindowThreadProcessId.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            user32.GetWindowThreadProcessId.restype = ctypes.c_ulong
            user32.PostMessageW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            user32.PostMessageW.restype = ctypes.c_bool
            kernel32.GetLastError.restype = ctypes.c_ulong

            target_pid = ctypes.c_ulong(pid)
            posted = {"count": 0}

            def _cb(hwnd: int, _: int) -> bool:
                owner = ctypes.c_ulong(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
                if owner.value == target_pid.value and user32.PostMessageW(hwnd, _WM_CLOSE, None, None):
                    posted["count"] += 1
                return True

            user32.EnumWindows(enum_windows_proc(_cb), None)
            return posted["count"] > 0

        try:
            posted = await asyncio.to_thread(_post_wm_close)
        except (OSError, RuntimeError) as exc:
            _logger.warning("wm_close_post_failed", pid=pid, error=str(exc))
            return False

        if not posted:
            _logger.info("wm_close_no_top_level_window", pid=pid)
            return False

        if self.process is None:
            return True

        try:
            await asyncio.wait_for(
                asyncio.to_thread(self.process.wait),
                timeout=_GRACEFUL_CLOSE_TIMEOUT,
            )
        except TimeoutError:
            _logger.warning("graceful_close_timeout", pid=pid)
            return False
        else:
            _logger.info("graceful_close_ok", pid=pid)
            return True

    async def _force_kill_sandbox(self, client_pid: int) -> None:
        """Force-kill the sandbox client by PID.

        Args:
            client_pid: Windows Sandbox client PID.
        """
        process_manager = ProcessManager.get_instance()
        try:
            await process_manager.run_tracked_async(
                ["taskkill", "/F", "/PID", str(client_pid)],
                name="taskkill-sandbox-client",
                process_timeout=_TASKKILL_TIMEOUT,
            )
        except (OSError, RuntimeError) as err:
            _logger.warning(
                "client_taskkill_failed_trying_image_name",
                pid=client_pid,
                error=str(err),
            )
            try:
                await process_manager.run_tracked_async(
                    ["taskkill", "/F", "/IM", self.SANDBOX_EXE],
                    name="taskkill-sandbox-fallback",
                    process_timeout=_TASKKILL_TIMEOUT,
                )
            except (OSError, RuntimeError) as fallback_err:
                _logger.warning(
                    "client_taskkill_fallback_failed",
                    error=str(fallback_err),
                )

    @staticmethod
    async def _resolve_worker_pid() -> int | None:
        """Locate the ``vmwp.exe`` worker backing this sandbox.

        Polls Win32 process info for the vmwp worker whose command line
        references a fresh disposable VM spawned during this start. The
        worker is matched by command-line GUID when available, falling back
        to the most recently created vmwp started within the last two minutes
        when no command-line match is possible.

        Returns:
            int | None: PID of the matched worker, or None if it could not be resolved.
        """
        if sys.platform != "win32":
            return None

        process_manager = ProcessManager.get_instance()
        ps_exe = "pwsh" if shutil.which("pwsh") else "powershell"
        ps_script = (
            "$ErrorActionPreference='Stop';"
            "$since=(Get-Date).AddMinutes(-2);"
            "$rows=Get-CimInstance Win32_Process -Filter \"Name='vmwp.exe'\" |"
            " Where-Object { $_.CreationDate -and $_.CreationDate -ge $since } |"
            " Sort-Object CreationDate -Descending |"
            " Select-Object ProcessId,CreationDate,CommandLine;"
            "if ($rows) {"
            " $best=$null;"
            " foreach ($r in @($rows)) {"
            "  if ($r.CommandLine -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {"
            "   $best=$r; break"
            "  }"
            " };"
            " if (-not $best) { $best=$rows | Select-Object -First 1 };"
            " if ($best) {"
            "  [pscustomobject]@{pid=[int]$best.ProcessId;"
            "   started=$best.CreationDate.ToString('o');"
            "   cmdline=[string]$best.CommandLine} | ConvertTo-Json -Compress"
            " }"
            "}"
        )

        deadline = time.monotonic() + _WORKER_PID_POLL_TIMEOUT
        while time.monotonic() < deadline:
            try:
                result = await process_manager.run_tracked_async(
                    [ps_exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    name="pwsh-find-vmwp",
                    process_timeout=_FEATURE_CHECK_TIMEOUT,
                )
            except (OSError, RuntimeError) as err:
                _logger.warning("vmwp_lookup_error", error=str(err))
                await asyncio.sleep(_WORKER_PID_POLL_INTERVAL)
                continue

            raw = (result.stdout or "").strip()
            if raw:
                try:
                    data: object = json.loads(raw)
                except (ValueError, TypeError) as parse_err:
                    _logger.warning(
                        "vmwp_json_parse_failed",
                        error=str(parse_err),
                        output_size=len(raw),
                        output_prefix=raw[:120],
                    )
                else:
                    if isinstance(data, dict):
                        pid_val: object = cast("dict[str, object]", data).get("pid")
                        if isinstance(pid_val, int) and pid_val > 0:
                            return pid_val

            await asyncio.sleep(_WORKER_PID_POLL_INTERVAL)

        return None

    async def _cleanup(self) -> None:
        """Clean up temporary files and folders."""
        if self._temp_dir is not None and await asyncio.to_thread(self._temp_dir.exists):
            temp_dir = self._temp_dir

            def _rmtree_onerror(func: object, path: object, exc_info: object) -> None:
                _logger.warning(
                    "temp_dir_cleanup_entry_failed",
                    func=getattr(func, "__name__", str(func)),
                    path=str(path),
                    error=str(exc_info),
                )

            try:
                await asyncio.to_thread(shutil.rmtree, temp_dir, onerror=_rmtree_onerror)
            except OSError as e:
                _logger.warning("temp_dir_cleanup_failed", error=str(e))

        self._temp_dir = None
        self._shared_folder = None
        self._monitor_folder = None
        self._wsb_path = None

    async def _wait_for_dispatcher_ready(self) -> None:
        """Block until the in-guest dispatcher has signalled readiness.

        Raises:
            SandboxError: If readiness was not signalled within the timeout,
                or the sandbox process terminated during startup.
        """
        if self._shared_folder is None:
            _logger.error("dispatcher_wait_shared_folder_not_initialized")
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        marker = self._shared_folder / "flags" / self.DISPATCHER_READY_MARKER
        deadline = time.monotonic() + _DISPATCHER_STARTUP_TIMEOUT

        while time.monotonic() < deadline:
            self._check_sandbox_alive()
            if await asyncio.to_thread(marker.exists):
                _logger.info("dispatcher_ready_signalled")
                return
            await asyncio.sleep(_DISPATCHER_POLL_INTERVAL)

        _logger.error("dispatcher_ready_timeout", time_limit=_DISPATCHER_STARTUP_TIMEOUT)
        raise SandboxError(_ERR_DISPATCHER_NOT_READY)

    async def _generate_wsb_config(self) -> None:
        """Generate the .wsb configuration file.

        Always emits a ``LogonCommand`` that launches the in-guest dispatcher,
        kicks off the monitor fleet, then runs any user-supplied startup
        commands. The dispatcher is the durable channel used by subsequent
        ``run_command`` calls.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._wsb_path is None or self._shared_folder is None:
            _logger.error(
                "wsb_config_generation_paths_not_initialized",
                wsb_path_set=self._wsb_path is not None,
                shared_folder_set=self._shared_folder is not None,
            )
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

        SubElement(config, "vGPU").text = "Enable" if self._config.video_enabled else "Disable"
        SubElement(config, "AudioInput").text = "Enable" if self._config.audio_enabled else "Disable"
        SubElement(config, "ClipboardRedirection").text = "Enable" if self._config.clipboard_enabled else "Disable"
        SubElement(config, "PrinterRedirection").text = "Enable" if self._config.printer_enabled else "Disable"

        logon_command = SubElement(config, "LogonCommand")
        SubElement(logon_command, "Command").text = self._build_logon_command()

        tree = ElementTree(config)
        indent(tree, space="  ")

        wsb_path = self._wsb_path

        def _write_config() -> None:
            with wsb_path.open("wb") as fh:
                tree.write(fh, encoding="utf-8", xml_declaration=True)

        await asyncio.to_thread(_write_config)
        _logger.debug("wsb_config_generated", path=str(self._wsb_path))

    def _build_logon_command(self) -> str:
        """Compose the single LogonCommand string.

        Returns:
            str: Command line that launches the bootstrap script inside the guest.
        """
        bootstrap = rf"{self.SANDBOX_SHARED_PATH}\monitor\sandbox_bootstrap.cmd"
        return f'cmd.exe /c "{bootstrap}"'

    async def _create_dispatcher_scripts(self) -> None:
        r"""Write the in-guest dispatcher, bootstrap, and environment helpers.

        The dispatcher tails ``input\trigger\*.cmd`` and runs each request,
        capturing stdout, stderr, and exit code to per-request files in the
        ``output`` directory. The bootstrap script primes the environment,
        launches the dispatcher and the monitor fleet, applies user startup
        commands, and finally signals readiness via the ``flags`` marker file.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._monitor_folder is None or self._shared_folder is None:
            _logger.error(
                "dispatcher_scripts_paths_not_initialized",
                monitor_folder_set=self._monitor_folder is not None,
                shared_folder_set=self._shared_folder is not None,
            )
            raise SandboxError(_ERR_SANDBOX_PATHS_NOT_INIT)

        dispatcher_ps1 = self._monitor_folder / "sandbox_dispatcher.ps1"
        dispatcher_source = self._dispatcher_ps1_source()
        await asyncio.to_thread(
            dispatcher_ps1.write_text,
            dispatcher_source,
            encoding="utf-8",
        )

        bootstrap_cmd = self._monitor_folder / "sandbox_bootstrap.cmd"
        bootstrap_source = self._bootstrap_cmd_source()
        await asyncio.to_thread(
            bootstrap_cmd.write_text,
            bootstrap_source,
            encoding="utf-8",
        )

        _logger.debug(
            "dispatcher_scripts_created",
            monitor_folder=str(self._monitor_folder),
        )

    def _dispatcher_ps1_source(self) -> str:
        """Return the PowerShell source for the in-guest dispatcher.

        Returns:
            str: PowerShell script source text.
        """
        trigger_dir = rf"{self.SANDBOX_SHARED_PATH}\input\trigger"
        output_dir = rf"{self.SANDBOX_SHARED_PATH}\output"
        flags_dir = rf"{self.SANDBOX_SHARED_PATH}\flags"
        ready_flag = rf"{flags_dir}\{self.DISPATCHER_READY_MARKER}"
        return (
            "param()\n"
            "$ErrorActionPreference = 'Stop'\n"
            f"$triggerDir = '{trigger_dir}'\n"
            f"$outputDir = '{output_dir}'\n"
            f"$flagsDir = '{flags_dir}'\n"
            f"$readyFlag = '{ready_flag}'\n"
            "foreach ($d in @($triggerDir, $outputDir, $flagsDir)) {\n"
            "    if (-not (Test-Path -LiteralPath $d)) {\n"
            "        New-Item -ItemType Directory -Path $d -Force | Out-Null\n"
            "    }\n"
            "}\n"
            "Set-Content -LiteralPath $readyFlag -Value ((Get-Date).ToString('o')) -Encoding utf8\n"
            "$processed = @{}\n"
            "while ($true) {\n"
            "    try {\n"
            "        $pending = Get-ChildItem -LiteralPath $triggerDir -Filter '*.cmd' -ErrorAction SilentlyContinue |\n"
            "            Sort-Object LastWriteTime\n"
            "        foreach ($item in $pending) {\n"
            "            if ($processed.ContainsKey($item.FullName)) { continue }\n"
            "            $processed[$item.FullName] = $true\n"
            "            $base = [System.IO.Path]::GetFileNameWithoutExtension($item.Name)\n"
            "            $out = Join-Path $outputDir ($base + '.out.txt')\n"
            "            $err = Join-Path $outputDir ($base + '.err.txt')\n"
            "            $res = Join-Path $outputDir ($base + '.result.txt')\n"
            "            Set-Content -LiteralPath $out -Value '' -Encoding utf8\n"
            "            Set-Content -LiteralPath $err -Value '' -Encoding utf8\n"
            "            $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', ('\"' + $item.FullName + '\"')) "
            "-NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err\n"
            "            $code = 0\n"
            "            if ($null -ne $proc) { $code = [int]$proc.ExitCode }\n"
            "            Set-Content -LiteralPath $res -Value ([string]$code) -Encoding utf8\n"
            "            try { Remove-Item -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue } catch { $_ | Out-Null }\n"
            "        }\n"
            "    } catch {\n"
            "        $errMsg = $_.Exception.Message\n"
            "        $ts = (Get-Date).ToString('o')\n"
            "        \"$ts|dispatcher_error|$errMsg\" | Out-File -Append -FilePath (Join-Path $outputDir 'dispatcher_errors.log') -Encoding utf8\n"
            "        Start-Sleep -Milliseconds 500\n"
            "    }\n"
            "    Start-Sleep -Milliseconds 250\n"
            "}\n"
        )

    def _bootstrap_cmd_source(self) -> str:
        """Return the cmd.exe source for the guest bootstrap script.

        Returns:
            str: Batch script source text.
        """
        logs_dir = rf"{self.SANDBOX_SHARED_PATH}\logs"
        monitor_dir = rf"{self.SANDBOX_SHARED_PATH}\monitor"
        dispatcher_ps1 = rf"{monitor_dir}\sandbox_dispatcher.ps1"
        start_monitors = rf"{monitor_dir}\start_monitors.cmd"

        env_lines: list[str] = []
        for var_name, var_value in self._config.environment_variables.items():
            safe_value = var_value.replace('"', '""')
            env_lines.extend(
                (
                    f'setx {var_name} "{safe_value}" >nul 2>&1',
                    f'set "{var_name}={var_value}"',
                ),
            )

        user_startup: list[str] = [f"cmd.exe /c {cmd}" for cmd in self._config.startup_commands]

        lines = [
            "@echo off",
            "setlocal ENABLEEXTENSIONS",
            f'if not exist "{logs_dir}" mkdir "{logs_dir}"',
            *env_lines,
            (
                'start "" /B powershell.exe -NoLogo -NoProfile -NonInteractive '
                "-ExecutionPolicy Bypass -WindowStyle Hidden "
                f'-File "{dispatcher_ps1}"'
            ),
            f'call "{start_monitors}" "{logs_dir}"',
            *user_startup,
            "endlocal",
            "exit /b 0",
            "",
        ]
        return "\r\n".join(lines)

    async def _create_monitor_scripts(self) -> None:
        """Stage the monitor fleet into the shared folder.

        Copies every PowerShell monitor bundled in ``sandbox/scripts`` plus
        the ``start_monitors.cmd`` launcher into the guest-accessible monitor
        directory, then emits the inline process / file / registry / network
        monitors used for base telemetry.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._monitor_folder is None:
            _logger.error("monitor_scripts_monitor_folder_not_initialized")
            raise SandboxError(_ERR_SANDBOX_PATHS_NOT_INIT)

        monitor_folder = self._monitor_folder

        def _copy_scripts() -> list[str]:
            scripts_dir = _SCRIPTS_DIR
            if not scripts_dir.is_dir():
                _logger.error("monitor_scripts_dir_not_found", scripts_dir=str(scripts_dir))
                raise SandboxError(_ERR_SCRIPTS_NOT_FOUND)
            copied: list[str] = []
            for src in scripts_dir.iterdir():
                if src.is_file() and src.suffix.lower() in {".ps1", ".cmd"}:
                    shutil.copy2(src, monitor_folder / src.name)
                    copied.append(src.name)
            return copied

        copied_names = await asyncio.to_thread(_copy_scripts)

        await self._emit_inline_monitors()

        _logger.debug(
            "monitoring_scripts_created",
            path=str(self._monitor_folder),
            copied=copied_names,
        )

    async def _emit_inline_monitors(self) -> None:
        """Write the file, registry, network, and process baseline monitors.

        These cover the core FileChange / RegistryChange / NetworkActivity / ProcessActivity telemetry that the :class:`ExecutionReport`
        always expects; they complement the external PowerShell monitors.
        """
        if self._monitor_folder is None:
            return

        monitors: list[tuple[str, str]] = [
            ("file_monitor.ps1", self._file_monitor_source()),
            ("registry_monitor.ps1", self._registry_monitor_source()),
            ("network_monitor.ps1", self._network_monitor_source()),
            ("process_monitor.ps1", self._process_monitor_source()),
        ]
        monitor_folder = self._monitor_folder

        for name, source in monitors:
            target = monitor_folder / name
            await asyncio.to_thread(target.write_text, source, encoding="utf-8")

    @staticmethod
    def _file_monitor_source() -> str:
        """Return PowerShell source for the baseline file-system monitor.

        Returns:
            str: PowerShell script source text.
        """
        return (
            "param([string]$LogDir = '.')\n"
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            "if (-not (Test-Path -LiteralPath $LogDir)) {\n"
            "    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null\n"
            "}\n"
            "$logPath = Join-Path -Path $LogDir -ChildPath 'file_monitor.log'\n"
            "$roots = @('C:\\Users\\WDAGUtilityAccount', 'C:\\ProgramData', 'C:\\Windows\\Temp', 'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64', 'C:\\Users\\Public')\n"
            "$watchers = @()\n"
            "$action = {\n"
            "    $lp = $Event.MessageData\n"
            "    $ts = (Get-Date).ToString('o')\n"
            "    $op = $Event.SourceEventArgs.ChangeType\n"
            "    $p = ($Event.SourceEventArgs.FullPath -replace '\\|','_')\n"
            "    $size = ''\n"
            "    try { $size = (Get-Item -LiteralPath $Event.SourceEventArgs.FullPath -ErrorAction Stop).Length } catch {}\n"
            "    $old = ''\n"
            "    if ($Event.SourceEventArgs.GetType().Name -eq 'RenamedEventArgs') {\n"
            "        $old = ($Event.SourceEventArgs.OldFullPath -replace '\\|','_')\n"
            "    }\n"
            '    "$ts|$op|$p|$old|$size" | Out-File -Append -FilePath $lp -Encoding utf8\n'
            "}\n"
            "foreach ($root in $roots) {\n"
            "    if (-not (Test-Path -LiteralPath $root)) { continue }\n"
            "    $w = New-Object System.IO.FileSystemWatcher\n"
            "    $w.Path = $root\n"
            "    $w.IncludeSubdirectories = $true\n"
            "    $w.EnableRaisingEvents = $true\n"
            "    $w.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, LastWrite, Size'\n"
            "    $watchers += $w\n"
            "    Register-ObjectEvent $w 'Created' -Action $action -MessageData $logPath | Out-Null\n"
            "    Register-ObjectEvent $w 'Changed' -Action $action -MessageData $logPath | Out-Null\n"
            "    Register-ObjectEvent $w 'Deleted' -Action $action -MessageData $logPath | Out-Null\n"
            "    Register-ObjectEvent $w 'Renamed' -Action $action -MessageData $logPath | Out-Null\n"
            "}\n"
            "while ($true) { Start-Sleep -Seconds 1 }\n"
        )

    @staticmethod
    def _registry_monitor_source() -> str:
        """Return PowerShell source for the baseline registry monitor.

        Returns:
            str: PowerShell script source text.
        """
        return (
            "param([string]$LogDir = '.')\n"
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            "if (-not (Test-Path -LiteralPath $LogDir)) {\n"
            "    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null\n"
            "}\n"
            "$logPath = Join-Path -Path $LogDir -ChildPath 'registry_monitor.log'\n"
            "$watchedRoots = @(\n"
            "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',\n"
            "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',\n"
            "    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',\n"
            "    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',\n"
            "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services'\n"
            ")\n"
            "$baseline = @{}\n"
            "function Get-RegValueType {\n"
            "    param([string]$RegPath, [string]$ValueName)\n"
            "    try {\n"
            "        $item = Get-Item -LiteralPath $RegPath -ErrorAction Stop\n"
            "        $kind = $item.GetValueKind($ValueName)\n"
            "        return [string]$kind\n"
            "    } catch { return 'Unknown' }\n"
            "}\n"
            "function Snapshot-Values {\n"
            "    param([string]$Root)\n"
            "    $snap = @{}\n"
            "    try {\n"
            "        $items = Get-ChildItem -LiteralPath $Root -Recurse -ErrorAction SilentlyContinue\n"
            "        foreach ($it in $items) {\n"
            "            $props = $null\n"
            "            try { $props = Get-ItemProperty -LiteralPath $it.PSPath -ErrorAction Stop } catch { continue }\n"
            "            foreach ($p in $props.PSObject.Properties) {\n"
            "                if ($p.Name -match '^PS') { continue }\n"
            "                $vtype = Get-RegValueType -RegPath $it.PSPath -ValueName $p.Name\n"
            "                $key = $it.PSPath + '::' + $p.Name + '::' + $vtype\n"
            "                $snap[$key] = [string]$p.Value\n"
            "            }\n"
            "        }\n"
            "    } catch {}\n"
            "    return $snap\n"
            "}\n"
            "foreach ($root in $watchedRoots) {\n"
            "    $snap = Snapshot-Values -Root $root\n"
            "    foreach ($k in $snap.Keys) { $baseline[$k] = $snap[$k] }\n"
            "}\n"
            "while ($true) {\n"
            "    Start-Sleep -Seconds 3\n"
            "    $ts = (Get-Date).ToString('o')\n"
            "    foreach ($root in $watchedRoots) {\n"
            "        $current = Snapshot-Values -Root $root\n"
            "        foreach ($k in $current.Keys) {\n"
            "            $full = $k -split '::', 3\n"
            "            $path = $full[0]\n"
            "            $name = if ($full.Count -gt 1) { $full[1] } else { '' }\n"
            "            $rtype = if ($full.Count -gt 2) { $full[2] } else { 'Unknown' }\n"
            "            $val = ($current[$k] -replace '\\|','_')\n"
            "            if (-not $baseline.ContainsKey($k)) {\n"
            '                "$ts|created|$path|$name|$rtype|$val" | Out-File -Append -FilePath $logPath -Encoding utf8\n'
            "                $baseline[$k] = $current[$k]\n"
            "            } elseif ($baseline[$k] -ne $current[$k]) {\n"
            '                "$ts|modified|$path|$name|$rtype|$val" | Out-File -Append -FilePath $logPath -Encoding utf8\n'
            "                $baseline[$k] = $current[$k]\n"
            "            }\n"
            "        }\n"
            "        foreach ($k in @($baseline.Keys)) {\n"
            "            if ($k -like ($root + '*') -and -not $current.ContainsKey($k)) {\n"
            "                $full = $k -split '::', 3\n"
            "                $path = $full[0]\n"
            "                $name = if ($full.Count -gt 1) { $full[1] } else { '' }\n"
            "                $rtype = if ($full.Count -gt 2) { $full[2] } else { 'Unknown' }\n"
            '                "$ts|deleted|$path|$name|$rtype|" | Out-File -Append -FilePath $logPath -Encoding utf8\n'
            "                $baseline.Remove($k)\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )

    @staticmethod
    def _network_monitor_source() -> str:
        """Return PowerShell source for the baseline network monitor.

        Returns:
            str: PowerShell script source text.
        """
        return (
            "param([string]$LogDir = '.')\n"
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            "if (-not (Test-Path -LiteralPath $LogDir)) {\n"
            "    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null\n"
            "}\n"
            "$logPath = Join-Path -Path $LogDir -ChildPath 'network_monitor.log'\n"
            "$seen = @{}\n"
            "while ($true) {\n"
            "    $ts = (Get-Date).ToString('o')\n"
            "    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue\n"
            "    foreach ($c in $tcp) {\n"
            "        $ownerPid = [int]$c.OwningProcess\n"
            "        $name = 'unknown'\n"
            "        try { $name = (Get-Process -Id $ownerPid -ErrorAction Stop).Name } catch {}\n"
            "        $sent = 0\n"
            "        $recv = 0\n"
            '        $local = "$($c.LocalAddress):$($c.LocalPort)"\n'
            '        $remote = "$($c.RemoteAddress):$($c.RemotePort)"\n'
            "        $state = [string]$c.State\n"
            '        $op = if ($state -eq "Listen") { "listen" } else { "connection" }\n'
            '        $key = "tcp|$local|$remote|$state|$ownerPid"\n'
            "        if ($seen.ContainsKey($key)) { continue }\n"
            "        $seen[$key] = $true\n"
            '        "$ts|$op|$local|$remote|$state|tcp|$sent|$recv|$ownerPid|$name" |\n'
            "            Out-File -Append -FilePath $logPath -Encoding utf8\n"
            "    }\n"
            "    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue\n"
            "    foreach ($u in $udp) {\n"
            "        $ownerPid = [int]$u.OwningProcess\n"
            "        $name = 'unknown'\n"
            "        try { $name = (Get-Process -Id $ownerPid -ErrorAction Stop).Name } catch {}\n"
            '        $local = "$($u.LocalAddress):$($u.LocalPort)"\n'
            "        $remote = '0.0.0.0:0'\n"
            "        $state = 'Bound'\n"
            '        $key = "udp|$local|$ownerPid"\n'
            "        if ($seen.ContainsKey($key)) { continue }\n"
            "        $seen[$key] = $true\n"
            '        "$ts|bind|$local|$remote|$state|udp|0|0|$ownerPid|$name" |\n'
            "            Out-File -Append -FilePath $logPath -Encoding utf8\n"
            "    }\n"
            "    if ($seen.Count -gt 8192) { $seen.Clear() }\n"
            "    Start-Sleep -Seconds 2\n"
            "}\n"
        )

    @staticmethod
    def _process_monitor_source() -> str:
        """Return PowerShell source for the baseline process monitor.

        Returns:
            str: PowerShell script source text.
        """
        return (
            "param([string]$LogDir = '.')\n"
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            "if (-not (Test-Path -LiteralPath $LogDir)) {\n"
            "    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null\n"
            "}\n"
            "$logPath = Join-Path -Path $LogDir -ChildPath 'process_monitor.log'\n"
            "$known = @{}\n"
            "while ($true) {\n"
            "    $ts = (Get-Date).ToString('o')\n"
            "    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue\n"
            "    $currentIds = @{}\n"
            "    foreach ($p in $procs) {\n"
            "        $procId = [int]$p.ProcessId\n"
            "        $currentIds[$procId] = $true\n"
            "        if ($known.ContainsKey($procId)) { continue }\n"
            "        $name = ($p.Name -replace '\\|','_')\n"
            "        $path = ($p.ExecutablePath -replace '\\|','_')\n"
            "        $cmd = ($p.CommandLine -replace '\\|','_')\n"
            "        $ppid = [int]$p.ParentProcessId\n"
            '        "$ts|created|$procId|$name|$path|$cmd|$ppid|" | Out-File -Append -FilePath $logPath -Encoding utf8\n'
            "        $known[$procId] = @{ name = $name; ppid = $ppid }\n"
            "    }\n"
            "    foreach ($procId in @($known.Keys)) {\n"
            "        if (-not $currentIds.ContainsKey($procId)) {\n"
            "            $entry = $known[$procId]\n"
            '            "$ts|terminated|$procId|$($entry.name)|||$($entry.ppid)|" | Out-File -Append -FilePath $logPath -Encoding utf8\n'
            "            $known.Remove($procId)\n"
            "        }\n"
            "    }\n"
            "    Start-Sleep -Seconds 1\n"
            "}\n"
        )

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Writes an exec file into the dispatcher trigger directory and waits
        for the result/out/err triple to appear in the output directory.

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
            _logger.error("run_command_sandbox_not_running", state=self.state.status, command_prefix=command[:120])
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if self._shared_folder is None:
            _logger.error("run_command_shared_folder_not_initialized", command_prefix=command[:120])
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = time_limit or self._config.timeout_seconds
        ticket = f"exec_{int(time.time() * _MS_PER_SECOND)}_{secrets.token_hex(4)}"
        paths = _DispatcherPaths.for_ticket(self._shared_folder, ticket)

        await asyncio.to_thread(paths.trigger.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(paths.result.parent.mkdir, parents=True, exist_ok=True)

        cd_line = f'cd /d "{working_directory}"\r\n' if working_directory else ""
        exec_content = (
            f"@echo off\r\nsetlocal ENABLEEXTENSIONS\r\n{cd_line}{command}\r\nset __RC=%ERRORLEVEL%\r\nendlocal & exit /b %__RC%\r\n"
        )
        await asyncio.to_thread(paths.trigger.write_text, exec_content, encoding="utf-8")

        try:
            deadline = time.monotonic() + effective_timeout
            while time.monotonic() < deadline:
                self._check_sandbox_alive()
                await asyncio.sleep(_RESULT_POLL_INTERVAL)
                if not await asyncio.to_thread(paths.result.exists):
                    continue
                completed = await _read_dispatcher_result(paths)
                if completed is not None:
                    return completed

            raise SandboxTimeoutError(_ERR_CMD_TIMEOUT)
        finally:
            for ticket_path in (paths.trigger, paths.out, paths.err, paths.result):
                try:
                    if await asyncio.to_thread(ticket_path.exists):
                        await asyncio.to_thread(ticket_path.unlink, missing_ok=True)
                except OSError as del_err:
                    _logger.debug(
                        "ticket_file_cleanup_failed",
                        path=str(ticket_path),
                        error=str(del_err),
                    )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            time_limit: Optional timeout override in seconds.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: ExecutionReport with results and activity from every parser.

        Raises:
            SandboxError: If execution fails.
        """
        if self.state.status != "running":
            _logger.error("run_binary_sandbox_not_running", state=self.state.status, binary_path=str(binary_path))
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)

        if not await asyncio.to_thread(binary_path.exists):
            _logger.error("run_binary_target_not_found", binary_path=str(binary_path))
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            _logger.error("run_binary_shared_folder_not_initialized", binary_path=str(binary_path))
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        effective_timeout = time_limit or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input\\{binary_path.name}")

        if monitor:
            await self._reset_monitor_logs()

        binary_sandbox_path = rf"{self.SANDBOX_SHARED_PATH}\input\{binary_path.name}"
        quoted_args = " ".join(f'"{a}"' for a in (args or []))
        command = f'"{binary_sandbox_path}" {quoted_args}'.rstrip()

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self.run_command(
                command,
                time_limit=effective_timeout,
            )
            result = "success" if exit_code == _RETURNCODE_SUCCESS else "error"
        except SandboxTimeoutError as e:
            _logger.warning(
                "sandbox_execution_timeout",
                binary=binary_path.name,
                timeout=effective_timeout,
            )
            exit_code = _RETURNCODE_FAILURE
            result = "timeout"
            stderr = str(e)
            stdout = ""
        except SandboxError as e:
            _logger.warning(
                "sandbox_execution_error",
                binary=binary_path.name,
                error=str(e),
            )
            exit_code = _RETURNCODE_FAILURE
            result = "error"
            stderr = str(e)
            stdout = ""

        duration = time.time() - start_time

        report = ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

        if monitor:
            await self._wait_for_monitor_quiescence()
            await self._attach_all_logs(report)

        return report

    async def _reset_monitor_logs(self) -> None:
        """Clear monitor log files from a previous execution."""
        if self._shared_folder is None:
            return
        logs_folder = self._shared_folder / "logs"
        if not await asyncio.to_thread(logs_folder.exists):
            return
        log_files = await asyncio.to_thread(lambda: list(logs_folder.glob("*.log")))
        for log_file in log_files:
            try:
                await asyncio.to_thread(log_file.unlink)
            except OSError as err:
                _logger.warning(
                    "log_cleanup_failed",
                    log=str(log_file),
                    error=str(err),
                )

    async def _wait_for_monitor_quiescence(self) -> None:
        """Wait until monitor logs stop growing or the maximum wait elapses.

        Polls the host-side logs folder at ``_RESULT_POLL_INTERVAL`` intervals. Returns as soon as the aggregate log size has been stable
        for one full poll cycle, or after ``_MONITOR_WAIT_SECONDS`` seconds have elapsed.
        """
        if self._shared_folder is None:
            return

        logs_folder = self._shared_folder / "logs"
        deadline = time.monotonic() + _MONITOR_WAIT_SECONDS
        prev_size = -1

        while time.monotonic() < deadline:
            await asyncio.sleep(_RESULT_POLL_INTERVAL)
            try:
                total = await asyncio.to_thread(
                    lambda: sum(f.stat().st_size for f in logs_folder.glob("*.log") if f.is_file()),
                )
            except OSError:
                break
            if total == prev_size:
                return
            prev_size = total

    async def _attach_all_logs(self, report: ExecutionReport) -> None:
        """Populate every activity field on the report from guest log files.

        Args:
            report: Report to populate with parsed monitor output.
        """
        shared = self._shared_folder
        report.file_changes = await parse_file_log(shared)
        report.registry_changes = await parse_registry_log(shared)
        report.network_activity = await parse_network_log(shared)
        report.process_activity = await parse_process_log(shared)
        report.service_changes = await parse_service_log(shared)
        report.kernel_objects = await parse_kernel_object_log(shared)
        report.dll_loads = await parse_dll_log(shared)
        report.injection_events = await parse_injection_log(shared)
        report.resource_samples = await parse_resource_log(shared)
        report.clipboard_events = await parse_clipboard_log(shared)
        report.api_calls = await parse_api_trace_log(shared)

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

        if not await asyncio.to_thread(source.exists):
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        dest_path = self._shared_folder / dest
        await asyncio.to_thread(dest_path.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", source=str(source), dest=dest)
        except OSError as e:
            _logger.warning(
                "copy_to_sandbox_failed",
                source=str(source),
                dest=dest,
                error=str(e),
            )
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
        if not await asyncio.to_thread(source_path.exists):
            raise SandboxError(_ERR_SOURCE_IN_SANDBOX_NOT_FOUND)

        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)
        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", source=source, dest=str(dest))
        except OSError as e:
            _logger.warning(
                "copy_from_sandbox_failed",
                source=source,
                dest=str(dest),
                error=str(e),
            )
            raise SandboxError(_ERR_COPY_FROM_SANDBOX_FAILED) from e

    async def start_pcap_capture(self) -> str:
        """Start packet capture on the sandbox network.

        Returns:
            str: Capture identifier for stopping later.

        Raises:
            SandboxError: If capture cannot be started.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        capture_id = f"pcap_{secrets.token_hex(8)}"
        pcap_filename = f"{capture_id}.etl"
        sandbox_pcap_path = rf"{self.SANDBOX_SHARED_PATH}\output\{pcap_filename}"

        exit_code, _, stderr = await self.run_command(
            f'pktmon start --capture --file-name "{sandbox_pcap_path}" --log-mode real-time',
        )
        if exit_code != _RETURNCODE_SUCCESS:
            _logger.warning("pcap_start_failed", capture_id=capture_id, stderr=stderr)
            raise SandboxError(_ERR_PCAP_START_FAILED)

        self._active_captures[capture_id] = pcap_filename
        _logger.info("pcap_capture_started", capture_id=capture_id)
        return capture_id

    async def stop_pcap_capture(
        self,
        capture_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """Stop packet capture and retrieve the PCAP file.

        Args:
            capture_id: Capture identifier from start_pcap_capture.
            output_path: Optional path to save the PCAP file.

        Returns:
            Path: Path to the saved PCAP file.

        Raises:
            SandboxError: If capture cannot be stopped.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)
        if capture_id not in self._active_captures:
            raise SandboxError(_ERR_PCAP_NOT_ACTIVE)

        exit_code, _, stderr = await self.run_command("pktmon stop")
        if exit_code != _RETURNCODE_SUCCESS:
            _logger.warning("pcap_stop_failed", capture_id=capture_id, stderr=stderr)
            raise SandboxError(_ERR_PCAP_STOP_FAILED)

        etl_filename = self._active_captures.pop(capture_id)
        etl_path = self._shared_folder / "output" / etl_filename
        pcap_filename = etl_filename.replace(".etl", ".pcap")
        sandbox_etl_path = rf"{self.SANDBOX_SHARED_PATH}\output\{etl_filename}"
        sandbox_pcap_path = rf"{self.SANDBOX_SHARED_PATH}\output\{pcap_filename}"

        conv_exit, _, conv_err = await self.run_command(
            f'pktmon etl2pcap "{sandbox_etl_path}" --out "{sandbox_pcap_path}"',
        )
        if conv_exit == _RETURNCODE_SUCCESS:
            result_path = self._shared_folder / "output" / pcap_filename
            _logger.info("pcap_etl2pcap_converted", capture_id=capture_id, path=str(result_path))
        else:
            _logger.warning(
                "pcap_etl2pcap_failed_returning_etl",
                capture_id=capture_id,
                stderr=conv_err,
            )
            result_path = etl_path

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, result_path, output_path)
            _logger.info("pcap_saved", capture_id=capture_id, path=str(output_path))
            return output_path

        _logger.info("pcap_capture_stopped", capture_id=capture_id, path=str(result_path))
        return result_path

    async def capture_screenshot(self, output_path: Path | None = None) -> Path:
        """Capture a screenshot of the sandbox display.

        Args:
            output_path: Optional path to save the screenshot.

        Returns:
            Path: Path to the saved screenshot file.

        Raises:
            SandboxError: If screenshot cannot be captured.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        screenshot_id = secrets.token_hex(8)
        screenshot_filename = f"screenshot_{screenshot_id}.png"
        sandbox_screenshot_path = rf"{self.SANDBOX_SHARED_PATH}\output\{screenshot_filename}"

        ps_script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "[System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object {"
            "  $bounds = $_.Bounds;"
            "  $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height);"
            "  $graphics = [System.Drawing.Graphics]::FromImage($bmp);"
            "  $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size);"
            f'  $bmp.Save("{sandbox_screenshot_path}", [System.Drawing.Imaging.ImageFormat]::Png);'
            "  $graphics.Dispose();"
            "  $bmp.Dispose()"
            "}"
        )

        exit_code, _, stderr = await self.run_command(
            f'powershell -Command "{ps_script}"',
        )
        if exit_code != _RETURNCODE_SUCCESS:
            _logger.warning("screenshot_failed", stderr=stderr)
            raise SandboxError(_ERR_SCREENSHOT_FAILED)

        screenshot_path = self._shared_folder / "output" / screenshot_filename

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, screenshot_path, output_path)
            _logger.info("screenshot_saved", path=str(output_path))
            return output_path

        _logger.info("screenshot_captured", path=str(screenshot_path))
        return screenshot_path

    async def apply_anti_evasion(self, profile: str = "default") -> dict[str, Any]:
        r"""Apply anti-evasion techniques to make the sandbox less detectable.

        Drops the previous volatile ``HKLM:\HARDWARE\DESCRIPTION\*`` registry
        writes (audit7 F-0013): those keys live in a volatile hive that the
        kernel rebuilds at boot, so the writes never reach evasive samples that
        actually query ``Get-CimInstance Win32_ComputerSystem`` / ``Win32_BIOS``.
        Instead a MOF file is generated from the active anti-evasion profile,
        compiled into the CIMV2 namespace with ``mofcomp.exe``, and verified
        with ``Get-CimInstance`` to confirm the spoofed values are now returned.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            dict[str, Any]: Dictionary describing applied techniques.

        Raises:
            SandboxError: If anti-evasion cannot be applied.
        """
        if self.state.status != "running":
            _logger.error("anti_evasion_skipped_sandbox_not_running", state=self.state.status, profile=profile)
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            _logger.error("anti_evasion_skipped_shared_folder_not_init")
            raise SandboxError(_ERR_WMI_HIJACK_NO_SHARED)

        applied: dict[str, Any] = {"profile": profile, "techniques": []}
        techniques: list[str] = []

        evasion_profile = resolve_anti_evasion_profile(profile)
        machine_name = f"DESKTOP-{secrets.token_hex(3).upper()}"

        wmi_result = await self._apply_wmi_hijack(evasion_profile, machine_name)
        if wmi_result["status"] == "verified":
            techniques.extend([
                "wmi_hijack_win32_computersystem",
                "wmi_hijack_win32_computersystemproduct",
                "wmi_hijack_win32_bios",
            ])
        applied["wmi_hijack"] = wmi_result

        hostname_cmd = f"powershell -Command \"Rename-Computer -NewName '{machine_name}' -Force -ErrorAction SilentlyContinue\""
        exit_code, _, _ = await self.run_command(hostname_cmd)
        if exit_code == _RETURNCODE_SUCCESS:
            techniques.append("hostname_change")

        username_dirs_cmd = (
            "powershell -Command \"New-Item -Path 'C:\\Users\\John' -ItemType Directory -Force -ErrorAction SilentlyContinue\""
        )
        exit_code, _, _ = await self.run_command(username_dirs_cmd)
        if exit_code == _RETURNCODE_SUCCESS:
            techniques.append("decoy_user_profile")

        recent_docs_cmd = (
            'powershell -Command "'
            "1..10 | ForEach-Object {"
            "  $name = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_});"
            '  New-Item -Path \\"C:\\Users\\WDAGUtilityAccount\\Documents\\$name.docx\\" -ItemType File -Force -ErrorAction SilentlyContinue'
            '}"'
        )
        exit_code, _, _ = await self.run_command(recent_docs_cmd)
        if exit_code == _RETURNCODE_SUCCESS:
            techniques.append("decoy_documents")

        applied["techniques"] = techniques
        applied["count"] = len(techniques)
        applied["spoofed_manufacturer"] = evasion_profile.manufacturer
        applied["spoofed_model"] = evasion_profile.model
        applied["spoofed_product_name"] = evasion_profile.product_name
        applied["spoofed_bios_vendor"] = evasion_profile.bios_vendor
        applied["spoofed_bios_version"] = evasion_profile.bios_version
        applied["spoofed_hostname"] = machine_name
        _logger.info(
            "anti_evasion_applied",
            profile=profile,
            technique_count=len(techniques),
            wmi_hijack_status=wmi_result["status"],
        )
        return applied

    async def _apply_wmi_hijack(
        self,
        evasion_profile: _AntiEvasionProfile,
        machine_name: str,
    ) -> dict[str, Any]:
        """Compile a MOF that hijacks Win32_ComputerSystem*/Win32_BIOS and verify it.

        Stages the MOF file into the shared folder so it is reachable from the
        guest, invokes ``mofcomp.exe`` inside the sandbox to register the
        static class definitions and spoofed instances, then runs
        ``Get-CimInstance`` to confirm the spoofed manufacturer/model values
        come back. Raises :class:`SandboxError` if either step fails.

        Args:
            evasion_profile: Resolved anti-evasion profile to materialise.
            machine_name: ``Win32_ComputerSystem.Name`` value to inject.

        Returns:
            dict[str, Any]: Result mapping with keys ``status`` (``verified``),
            ``mof_path`` (host-side path), ``observed_manufacturer``,
            ``observed_model``, ``observed_product_name``, and
            ``observed_bios_vendor``.

        Raises:
            SandboxError: If MOF compilation fails or the verification query
                does not return the spoofed values.
        """
        if self._shared_folder is None:
            raise SandboxError(_ERR_WMI_HIJACK_NO_SHARED)

        mof_filename = f"intellicrack_antievasion_{secrets.token_hex(6)}.mof"
        mof_host_path = self._shared_folder / "input" / mof_filename
        await asyncio.to_thread(mof_host_path.parent.mkdir, parents=True, exist_ok=True)

        mof_text = build_anti_evasion_mof(evasion_profile, machine_name)
        await asyncio.to_thread(mof_host_path.write_text, mof_text, encoding="utf-8")

        mof_guest_path = rf"{self.SANDBOX_SHARED_PATH}\input\{mof_filename}"
        mofcomp_cmd = f'mofcomp.exe -N:root\\cimv2 "{mof_guest_path}"'
        compile_exit, compile_out, compile_err = await self.run_command(mofcomp_cmd)
        if compile_exit != _RETURNCODE_SUCCESS:
            _logger.warning(
                "wmi_hijack_mofcomp_failed",
                exit_code=compile_exit,
                stdout=compile_out[:500],
                stderr=compile_err[:500],
                mof_path=str(mof_host_path),
            )
            raise SandboxError(_ERR_WMI_HIJACK_COMPILE_FAILED)

        observed = await self._query_wmi_identity()
        _assert_wmi_hijack_matches(observed, evasion_profile)

        return {
            "status": "verified",
            "mof_path": str(mof_host_path),
            "observed_manufacturer": observed["Manufacturer"],
            "observed_model": observed["Model"],
            "observed_product_name": observed["ProductName"],
            "observed_bios_vendor": observed["BIOSVendor"],
            "observed_bios_version": observed["BIOSVersion"],
        }

    async def _query_wmi_identity(self) -> dict[str, str]:
        """Query the spoofed identity values via ``Get-CimInstance``.

        Returns:
            dict[str, str]: Mapping with keys ``Manufacturer``, ``Model``,
            ``ProductName``, ``ProductVendor``, ``BIOSVendor``, ``BIOSVersion``.

        Raises:
            SandboxError: If the dispatched query fails or the JSON payload is malformed.
        """
        verify_script = (
            "$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop;"
            " $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop;"
            " $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop;"
            " $payload = [pscustomobject]@{"
            " Manufacturer=$cs.Manufacturer; Model=$cs.Model;"
            " ProductName=$csp.Name; ProductVendor=$csp.Vendor;"
            " BIOSVendor=$bios.Manufacturer; BIOSVersion=$bios.SMBIOSBIOSVersion"
            " };"
            " $payload | ConvertTo-Json -Compress"
        )
        verify_cmd = f'powershell -NoProfile -NonInteractive -Command "{verify_script}"'
        verify_exit, verify_out, verify_err = await self.run_command(verify_cmd)
        if verify_exit != _RETURNCODE_SUCCESS:
            _logger.warning(
                "wmi_hijack_verification_query_failed",
                exit_code=verify_exit,
                stderr=verify_err[:500],
            )
            raise SandboxError(_ERR_WMI_HIJACK_VERIFY_FAILED)

        try:
            parsed_obj: object = json.loads(verify_out.strip())
        except (ValueError, json.JSONDecodeError) as parse_err:
            _logger.warning(
                "wmi_hijack_verification_parse_failed",
                error=str(parse_err),
                stdout=verify_out[:500],
            )
            raise SandboxError(_ERR_WMI_HIJACK_VERIFY_FAILED) from parse_err
        if not isinstance(parsed_obj, dict):
            _logger.warning("wmi_hijack_verification_unexpected_payload", payload=str(parsed_obj)[:500])
            raise SandboxError(_ERR_WMI_HIJACK_VERIFY_FAILED)

        observed = cast("dict[str, Any]", parsed_obj)
        return {
            "Manufacturer": str(observed.get("Manufacturer", "")),
            "Model": str(observed.get("Model", "")),
            "ProductName": str(observed.get("ProductName", "")),
            "ProductVendor": str(observed.get("ProductVendor", "")),
            "BIOSVendor": str(observed.get("BIOSVendor", "")),
            "BIOSVersion": str(observed.get("BIOSVersion", "")),
        }

    async def dump_memory(
        self,
        output_path: Path | None = None,
        target_pid: int | None = None,
    ) -> Path:
        """Dump a guest process by running ``MiniDumpWriteDump`` inside the guest.

        The Windows Sandbox worker process (``vmwp.exe``) is a Protected Process
        Light (PPL). ``OpenProcess(PROCESS_VM_READ)`` from the host always returns
        ``ERROR_ACCESS_DENIED`` — even from SYSTEM — so host-side minidump
        approaches (``dbghelp``, ``procdump``) cannot succeed against it.

        This implementation requests the dump from inside the guest by running
        a PowerShell ``MiniDumpWriteDump`` script via the dispatcher. The
        dispatcher's PowerShell host opens the **target** process via
        ``OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)``
        and passes that handle (not ``GetCurrentProcess()``) to
        ``MiniDumpWriteDump`` so the resulting dump describes the sample under
        analysis instead of the PowerShell host itself (audit7 F-0021). The
        process handle is always closed in the PowerShell ``finally`` block.
        The dump file is then copied back to the host via the shared folder.

        Args:
            output_path: Optional path to save the memory dump.
            target_pid: Guest-side PID of the process to dump. Required for
                Windows Sandbox because ``MiniDumpWriteDump`` must target a
                specific process; passing ``None`` would (incorrectly) dump
                the PowerShell host.

        Returns:
            Path: Path to the saved memory dump file.

        Raises:
            SandboxError: If memory dump fails or ``target_pid`` is missing/invalid.
        """
        if self.state.status != "running":
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)
        if target_pid is None:
            _logger.error("memory_dump_missing_target_pid")
            raise SandboxError(_ERR_MEMORY_DUMP_TARGET_PID_REQUIRED)
        if target_pid <= 0:
            _logger.error("memory_dump_invalid_target_pid", target_pid=target_pid)
            raise SandboxError(_ERR_MEMORY_DUMP_TARGET_PID_INVALID)

        dump_filename = f"memdump_pid{target_pid}_{secrets.token_hex(8)}.dmp"
        sandbox_dump_path = rf"{self.SANDBOX_SHARED_PATH}\output\{dump_filename}"

        ps_script = (
            f"$targetPid = {target_pid};"
            ' Add-Type -TypeDefinition @"\n'
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class MiniDumper {\n"
            '    [DllImport("dbghelp.dll", SetLastError=true)] public static extern bool MiniDumpWriteDump(\n'
            "        IntPtr hProcess, uint ProcessId, IntPtr hFile, uint DumpType,\n"
            "        IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);\n"
            '    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(\n'
            "        uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);\n"
            '    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);\n'
            '}"@ -ErrorAction Stop;\n'
            f"$access = {_PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ};\n"
            "$handle = [MiniDumper]::OpenProcess($access, $false, $targetPid);\n"
            "if ($handle -eq [IntPtr]::Zero) {\n"
            "    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error();\n"
            "    throw ('OpenProcess failed for target_pid=' + $targetPid + ' err=' + $err)\n"
            "}\n"
            f"$fs = [System.IO.File]::Create('{sandbox_dump_path}');\n"
            "try {\n"
            "    $ok = [MiniDumper]::MiniDumpWriteDump(\n"
            "        $handle, $targetPid,\n"
            "        $fs.SafeFileHandle.DangerousGetHandle(),\n"
            "        2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);\n"
            "    if (-not $ok) {\n"
            "        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error();\n"
            "        throw ('MiniDumpWriteDump returned false err=' + $err)\n"
            "    }\n"
            "} finally {\n"
            "    $fs.Close();\n"
            "    [void][MiniDumper]::CloseHandle($handle)\n"
            "}"
        )
        exit_code, _, stderr = await self.run_command(f'powershell -Command "{ps_script}"')
        if exit_code != _RETURNCODE_SUCCESS:
            _logger.warning("guest_memory_dump_failed", stderr=stderr)
            raise SandboxError(_ERR_MEMORY_DUMP_FAILED)

        dump_dir = self._shared_folder / "output"
        dump_path = dump_dir / dump_filename

        if not await asyncio.to_thread(dump_path.exists):
            raise SandboxError(_ERR_MEMORY_DUMP_FAILED)

        _logger.info("memory_dump_created", path=str(dump_path))

        try:
            yara_matches = await self.yara_scan(scan_target="memory")
            _logger.info(
                "memory_dump_yara_scanned",
                path=str(dump_path),
                match_count=len(yara_matches),
            )
        except SandboxError as yara_err:
            _logger.warning("memory_dump_yara_skipped", error=str(yara_err))

        if output_path is not None:
            await asyncio.to_thread(
                output_path.parent.mkdir,
                parents=True,
                exist_ok=True,
            )
            await asyncio.to_thread(shutil.copy2, dump_path, output_path)
            _logger.info("memory_dump_saved", path=str(output_path))
            return output_path

        return dump_path

    @staticmethod
    async def _minidump_via_procdump(pid: int, dump_path: Path) -> bool:
        """Dump a host process via ``dbghelp`` first, then ``procdump64.exe``.

        Attempts ``MiniDumpWriteDump`` via ``dbghelp.dll`` first. Falls back
        to ``procdump64.exe`` / ``procdump.exe`` if that fails.

        Args:
            pid: Process to dump.
            dump_path: Destination dump path.

        Returns:
            bool: True if the dump file was produced, False otherwise.
        """
        dbghelp_ok, dbghelp_err = await asyncio.to_thread(_minidump_via_dbghelp, pid, dump_path)
        if dbghelp_ok and await asyncio.to_thread(dump_path.exists):
            return True
        _logger.debug("minidump_via_dbghelp_failed_trying_procdump", pid=pid, error=dbghelp_err)

        procdump = shutil.which("procdump64.exe") or shutil.which("procdump.exe")
        if procdump is None:
            _logger.debug("procdump_not_found", pid=pid)
            return False

        process_manager = ProcessManager.get_instance()
        try:
            result = await process_manager.run_tracked_async(
                [procdump, "-accepteula", "-ma", str(pid), str(dump_path)],
                name="procdump-fallback",
                process_timeout=_FEATURE_CHECK_TIMEOUT,
            )
        except (OSError, RuntimeError) as err:
            _logger.warning("procdump_invocation_failed", pid=pid, error=str(err))
            return False
        else:
            ok = result.returncode == _RETURNCODE_SUCCESS and await asyncio.to_thread(dump_path.exists)
            if not ok:
                _logger.warning(
                    "procdump_failed",
                    pid=pid,
                    returncode=result.returncode,
                    stderr=(result.stderr or "")[:500],
                )
            return ok

    async def extract_dropped_files(self, output_path: Path | None = None) -> Path:
        """Extract files created by the binary during execution.

        Args:
            output_path: Optional path to save the ZIP archive.

        Returns:
            Path: Path to ZIP archive of extracted files.

        Raises:
            SandboxError: If extraction fails.
        """
        if self.state.status != "running":
            _logger.error("dropped_files_extraction_skipped_not_running", state=self.state.status)
            raise SandboxError(_ERR_SANDBOX_NOT_RUNNING)
        if self._shared_folder is None:
            _logger.error("dropped_files_extraction_shared_folder_not_initialized")
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        extract_id = secrets.token_hex(8)
        staging_dir = self._shared_folder / "output" / f"dropped_{extract_id}"
        await asyncio.to_thread(staging_dir.mkdir, parents=True, exist_ok=True)

        guest_dirs = [
            r"C:\Users\WDAGUtilityAccount\Downloads",
            r"C:\Users\WDAGUtilityAccount\AppData\Local\Temp",
            r"C:\Windows\Temp",
            r"C:\Users\Public\Downloads",
        ]
        sandbox_staging = rf"{self.SANDBOX_SHARED_PATH}\output\dropped_{extract_id}"

        for guest_dir in guest_dirs:
            dir_name = Path(guest_dir).name
            copy_cmd = f'xcopy /S /E /Y /I /Q "{guest_dir}" "{sandbox_staging}\\{dir_name}"'
            xcopy_exit, _, xcopy_err = await self.run_command(copy_cmd)
            if xcopy_exit == _XCOPY_INIT_ERROR:
                _logger.warning(
                    "xcopy_initialisation_error",
                    guest_dir=guest_dir,
                    exit_code=xcopy_exit,
                    stderr=xcopy_err,
                )
                raise SandboxError(_ERR_EXTRACT_FILES_FAILED)
            if xcopy_exit == _XCOPY_ACCESS_DENIED:
                _logger.warning(
                    "xcopy_access_denied",
                    guest_dir=guest_dir,
                    exit_code=xcopy_exit,
                    stderr=xcopy_err,
                )
            elif xcopy_exit == _XCOPY_NO_FILES:
                _logger.debug("xcopy_no_files_found", guest_dir=guest_dir)
            elif xcopy_exit not in {0, 1}:
                _logger.warning(
                    "xcopy_unexpected_exit_code",
                    guest_dir=guest_dir,
                    exit_code=xcopy_exit,
                    stderr=xcopy_err,
                )

        zip_filename = f"dropped_files_{extract_id}.zip"
        zip_path = self._shared_folder / "output" / zip_filename

        def _create_zip() -> None:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                if staging_dir.exists():
                    for file_path in staging_dir.rglob("*"):
                        if file_path.is_file():
                            arcname = file_path.relative_to(staging_dir)
                            zf.write(file_path, arcname)

        await asyncio.to_thread(_create_zip)

        try:
            await asyncio.to_thread(shutil.rmtree, staging_dir, ignore_errors=True)
        except OSError as e:
            _logger.warning("staging_dir_cleanup_failed", error=str(e), staging_dir=str(staging_dir))

        _logger.info("dropped_files_extracted", zip_path=str(zip_path))

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, zip_path, output_path)
            return output_path

        return zip_path

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, Any]]:
        """Run YARA rules against sandbox artifacts.

        Args:
            rules_path: Path to YARA rules file. Uses built-in rules if None.
            scan_target: What to scan - 'files' for dropped files, 'memory' for memory dump.

        Returns:
            list[dict[str, Any]]: List of YARA match dictionaries.

        Raises:
            SandboxError: If scan fails.
        """
        try:
            import yara  # noqa: PLC0415
        except ImportError as exc:
            raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc

        if self._shared_folder is None:
            raise SandboxError(_ERR_SHARED_FOLDER_NOT_INIT)

        yara_compile = cast("Callable[..., Any]", yara.compile)
        if rules_path is not None:
            compiled_rules = await asyncio.to_thread(yara_compile, filepath=rules_path)
        else:
            compiled_rules = await asyncio.to_thread(
                yara_compile,
                source=_DEFAULT_YARA_RULES,
            )

        matches: list[dict[str, Any]] = []
        output_dir = self._shared_folder / "output"

        if scan_target == "memory":
            dump_files = await asyncio.to_thread(
                lambda: list(output_dir.glob("memdump_*.dmp")),
            )
            for dump_file in dump_files:
                file_matches: list[Any] = await asyncio.to_thread(
                    compiled_rules.match,
                    filepath=str(dump_file),
                )
                matches.extend(_format_yara_match(ym, str(dump_file), "memory") for ym in file_matches)
        else:
            scan_files: list[Path] = []
            zip_files = await asyncio.to_thread(
                lambda: list(output_dir.glob("dropped_files_*.zip")),
            )
            if zip_files:
                extract_dir = output_dir / f"yara_scan_{secrets.token_hex(4)}"
                await asyncio.to_thread(extract_dir.mkdir, parents=True, exist_ok=True)

                def _extract_zips() -> list[Path]:
                    extracted: list[Path] = []
                    for zf_path in zip_files:
                        with zipfile.ZipFile(zf_path, "r") as zf:
                            zf.extractall(extract_dir)
                    extracted.extend(fp for fp in extract_dir.rglob("*") if fp.is_file())
                    return extracted

                scan_files = await asyncio.to_thread(_extract_zips)
            else:
                scan_files = await asyncio.to_thread(
                    lambda: [f for f in output_dir.rglob("*") if f.is_file() and f.suffix.lower() not in {".txt", ".log"}],
                )

            for scan_file in scan_files:
                try:
                    file_matches = await asyncio.to_thread(
                        compiled_rules.match,
                        filepath=str(scan_file),
                    )
                    matches.extend(_format_yara_match(ym, str(scan_file), "files") for ym in file_matches)
                except (OSError, RuntimeError) as e:
                    _logger.warning(
                        "yara_file_scan_error",
                        file=str(scan_file),
                        error=str(e),
                    )

        _logger.info(
            "yara_scan_complete",
            match_count=len(matches),
            scan_target=scan_target,
        )
        return matches


_DEFAULT_YARA_RULES = """
rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "CreateRemoteThread"
        $s4 = "VirtualAllocEx"
        $s5 = "WriteProcessMemory"
        $s6 = "NtUnmapViewOfSection"
        $s7 = "WScript.Shell"
        $s8 = "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
    condition:
        any of them
}

rule PackedBinary {
    strings:
        $upx = "UPX!"
        $aspack = ".aspack"
        $themida = ".themida"
    condition:
        any of them
}
"""


class _DispatcherPaths:
    """Paths for a single dispatcher ticket (trigger, stdout, stderr, result)."""

    __slots__ = ("err", "out", "result", "trigger")

    def __init__(self, trigger: Path, out: Path, err: Path, result: Path) -> None:
        """Initialize dispatcher paths.

        Args:
            trigger: Trigger cmd file under ``input/trigger``.
            out: Stdout capture file under ``output``.
            err: Stderr capture file under ``output``.
            result: Exit-code file under ``output``.
        """
        self.trigger = trigger
        self.out = out
        self.err = err
        self.result = result
        _logger.debug("dispatcher_paths_initialized", trigger_path=str(trigger))

    @classmethod
    def for_ticket(cls, shared_folder: Path, ticket: str) -> _DispatcherPaths:
        """Build the path set used by a single dispatcher exec ticket.

        Args:
            shared_folder: Host-side root of the shared folder.
            ticket: Unique ticket identifier for this command.

        Returns:
            _DispatcherPaths: Populated instance for the ticket.
        """
        trigger_dir = shared_folder / "input" / "trigger"
        output_dir = shared_folder / "output"
        return cls(
            trigger=trigger_dir / f"{ticket}.cmd",
            out=output_dir / f"{ticket}.out.txt",
            err=output_dir / f"{ticket}.err.txt",
            result=output_dir / f"{ticket}.result.txt",
        )


async def _read_dispatcher_result(paths: _DispatcherPaths) -> tuple[int, str, str] | None:
    """Read the exit code, stdout, and stderr for a dispatcher ticket.

    Args:
        paths: Dispatcher paths for the ticket.

    Returns:
        tuple[int, str, str] | None: ``(exit_code, stdout, stderr)`` on success,
        or None if the result file could not be read (caller should keep polling).
    """
    try:
        code_raw = await asyncio.to_thread(
            paths.result.read_text,
            encoding="utf-8",
            errors="ignore",
        )
    except OSError as err:
        _logger.debug("result_read_failed", error=str(err), result_path=str(paths.result), exc_info=True)
        return None

    code_str = code_raw.strip()
    exit_code = int(code_str) if code_str.lstrip("-").isdigit() else _RETURNCODE_UNKNOWN

    stdout = ""
    stderr = ""
    if await asyncio.to_thread(paths.out.exists):
        stdout = await asyncio.to_thread(
            paths.out.read_text,
            encoding="utf-8",
            errors="ignore",
        )
    if await asyncio.to_thread(paths.err.exists):
        stderr = await asyncio.to_thread(
            paths.err.read_text,
            encoding="utf-8",
            errors="ignore",
        )
    return (exit_code, stdout, stderr)


def _minidump_via_dbghelp(pid: int, dump_path: Path) -> tuple[bool, str]:
    """Produce a full-memory minidump using ``dbghelp.MiniDumpWriteDump``.

    Args:
        pid: Target process PID (typically the sandbox's vmwp.exe worker).
        dump_path: Destination file path for the dump.

    Returns:
        tuple[bool, str]: Success flag and diagnostic error string (empty on success).
    """
    if sys.platform != "win32":
        return (False, _ERR_MEMORY_DUMP_NOT_WINDOWS)

    try:
        dbghelp = ctypes.WinDLL("dbghelp.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError as err:
        _logger.warning("dbghelp_library_load_failed", pid=pid, error=str(err))
        return (False, f"library_load_failed:{err}")

    kernel32.OpenProcess.argtypes = [
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.GetLastError.restype = ctypes.c_uint

    dbghelp.MiniDumpWriteDump.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dbghelp.MiniDumpWriteDump.restype = ctypes.c_int

    access = _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ
    handle = kernel32.OpenProcess(access, 0, pid)
    if not handle:
        err_code = kernel32.GetLastError()
        return (False, f"open_process_failed:{err_code}")

    try:
        dump_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fh = dump_path.open("wb")
        except OSError as err:
            _logger.warning("dbghelp_dump_open_failed", pid=pid, dump_path=str(dump_path), error=str(err))
            return (False, f"dump_open_failed:{err}")
        try:
            file_handle = _win_handle_from_file(fh)
            if file_handle is None:
                return (False, "dump_handle_failed")
            ok = dbghelp.MiniDumpWriteDump(
                handle,
                pid,
                file_handle,
                _MINIDUMP_WITH_FULL_MEMORY,
                None,
                None,
                None,
            )
        finally:
            fh.close()
        if not ok:
            err_code = kernel32.GetLastError()
            if err_code == _ERROR_ACCESS_DENIED:
                return (False, f"access_denied:{err_code}")
            return (False, f"minidump_failed:{err_code}")
    finally:
        kernel32.CloseHandle(handle)

    return (True, "")


def _win_handle_from_file(file_obj: IO[bytes]) -> int | None:
    """Return the raw Win32 HANDLE for an opened file, or None on failure.

    Args:
        file_obj: Python file object.

    Returns:
        int | None: Win32 HANDLE, or None if it could not be obtained.
    """
    if sys.platform != "win32":
        return None
    msvcrt_mod = sys.modules.get("msvcrt")
    if msvcrt_mod is None:
        try:
            import msvcrt  # noqa: PLC0415

            msvcrt_mod = msvcrt
        except ImportError:
            _logger.warning("msvcrt_import_failed_returning_none")
            return None
    get_osfhandle: Callable[[int], int] = msvcrt_mod.get_osfhandle
    try:
        return get_osfhandle(file_obj.fileno())
    except (OSError, ValueError, AttributeError):
        return None
