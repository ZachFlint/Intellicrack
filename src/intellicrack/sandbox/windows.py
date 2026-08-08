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
import re
import secrets
import shutil
import sys
import tempfile
import time
import zipfile


if sys.platform == "win32":
    import msvcrt as _msvcrt
else:
    _msvcrt = None
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, NoReturn, cast

from intellicrack.core._optional_imports import require_yara
from intellicrack.core.logging import get_logger, log_sandbox_operation
from intellicrack.core.process_manager import ProcessManager, ProcessType, pid_is_running
from intellicrack.core.subprocess_compat import CREATE_NEW_CONSOLE, PIPE, CompletedProcess, Popen
from intellicrack.sandbox.base import (
    ExecutionReport,
    ExecutionResult,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxTimeoutError,
)
from intellicrack.sandbox.log_helpers import (
    ERR_YARA_NO_ARTIFACTS,
    ERR_YARA_NO_MEMORY_DUMP,
    ERR_YARA_UNKNOWN_TARGET,
    YARA_SCAN_TARGETS,
    YARA_TARGET_MEMORY,
    format_yara_match as _format_yara_match,
    scannable_output_files,
)
from intellicrack.sandbox.log_parsers import (
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
from intellicrack.sandbox.wsb import WsbMappedFolder, build_wsb_configuration, render_wsb_configuration


if TYPE_CHECKING:
    from collections.abc import Callable


_logger = get_logger(__name__)

_WHERE_TIMEOUT = 10
_FEATURE_CHECK_TIMEOUT = 30
_SANDBOX_FEATURE_NAME = "Containers-DisposableClientVM"
_SANDBOX_INSTALL_STATE_ENABLED = "1"
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

_ERR_LAUNCH_CLIENT_EXITED = (
    "The Windows Sandbox launcher exited during startup before the in-guest dispatcher "
    "became ready. Confirm the Windows Sandbox feature is healthy and that no other "
    "sandbox instance is running."
)
_ERR_LAUNCH_DIALOG = "Windows Sandbox reported a launch failure"
_ERR_LAUNCH_RPC_ENDPOINT = (
    "Windows Sandbox could not initialize its connection to the sandbox "
    "(0x800706d9, EPT_S_NOT_REGISTERED). The usual cause is that a sandbox session is "
    "already running: Windows Sandbox permits only one at a time, so destroy the "
    "existing session and confirm no WindowsSandboxRemoteSession.exe, "
    "WindowsSandboxServer.exe or vmmemWindowsSandbox process remains. This error is "
    "also raised when the sandbox is started through WindowsSandboxClient.exe on "
    "Windows builds where that binary is only the connection client and cannot create "
    "a session on its own; WindowsSandbox.exe is the launcher that creates one. Only "
    "if neither applies is this host Hyper-V / Host Compute Service state."
)
_ERR_LAUNCH_SESSION_NOT_STARTED = (
    "The Windows Sandbox launcher exited successfully but no sandbox session process appeared. The sandbox did not start."
)

_SANDBOX_SESSION_EXE = "WindowsSandboxRemoteSession.exe"
_SANDBOX_DIALOG_CLASS = "#32770"
_SANDBOX_RPC_ENDPOINT_ERROR = "0x800706d9"
_SANDBOX_RPC_ENDPOINT_EXIT_CODE = -2147023143
_SESSION_PID_POLL_INTERVAL = 0.5
_SESSION_PID_POLL_TIMEOUT = 60.0
_SANDBOX_ERROR_CODE_RE = re.compile(r"0x[0-9A-Fa-f]{8}")
_SANDBOX_FAILURE_MARKERS = (
    "could not be initialized",
    "endpoint mapper",
    "no more endpoints",
    "failed to start",
    "cannot start",
)
_GET_CLASS_NAME_BUFFER = 256

_SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


def find_sandbox_session_pid(wsb_name: str) -> int | None:
    """Locate a Windows Sandbox session process started from a given config.

    The launcher passes the ``.wsb`` path through to the session host, so a
    session can be matched exactly by its command line. Shared by the sandbox
    backend and by the Sandbox Settings "Test Sandbox" path so both judge
    "did a sandbox actually start" the same way.

    Args:
        wsb_name: Filename of the ``.wsb`` configuration used to launch.

    Returns:
        int | None: PID of the matching session process, or None when no
        session references that configuration.
    """
    if sys.platform != "win32":
        return None

    escaped = wsb_name.replace("'", "''")
    ps_script = (
        "$ErrorActionPreference='Stop';"
        f"$rows=Get-CimInstance Win32_Process -Filter \"Name='{_SANDBOX_SESSION_EXE}'\" |"
        f" Where-Object {{ $_.CommandLine -and $_.CommandLine.Contains('{escaped}') }} |"
        " Select-Object -First 1 ProcessId;"
        "if ($rows) { [pscustomobject]@{pid=[int]$rows.ProcessId} | ConvertTo-Json -Compress }"
    )
    try:
        result: CompletedProcess[str] = ProcessManager.get_instance().run_tracked(
            ["pwsh" if shutil.which("pwsh") else "powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            name="pwsh-find-sandbox-session",
            timeout=_FEATURE_CHECK_TIMEOUT,
        )
    except (OSError, RuntimeError) as err:
        _logger.warning("sandbox_session_lookup_error", error=str(err))
        return None

    raw = (result.stdout or "").strip()
    if not raw:
        return None
    try:
        data: object = json.loads(raw)
    except (ValueError, TypeError) as parse_err:
        _logger.warning("sandbox_session_json_parse_failed", error=str(parse_err), output_prefix=raw[:120])
        return None
    if isinstance(data, dict):
        pid_val: object = cast("dict[str, object]", data).get("pid")
        if isinstance(pid_val, int) and pid_val > 0:
            return pid_val
    return None


def _is_sandbox_failure_text(text: str) -> bool:
    """Classify combined dialog text as a Windows Sandbox launch failure.

    Args:
        text: Combined window title and static-text content of a dialog.

    Returns:
        bool: True when the text contains a Windows error code (``0x........``)
        or a known failure phrase; False otherwise. Requiring one of these
        markers prevents the transient ``Starting Windows Sandbox`` progress
        dialog from being treated as a failure.
    """
    if not text:
        return False
    if _SANDBOX_ERROR_CODE_RE.search(text):
        return True
    lowered = text.lower()
    return any(marker in lowered for marker in _SANDBOX_FAILURE_MARKERS)


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
        """Spoofed value reported for Win32_ComputerSystemProduct.Vendor.

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
    if mismatches := [
        f"{key.lower()}={observed.get(key, '')!r}!={expected_value!r}"
        for key, expected_value in expected.items()
        if observed.get(key, "") != expected_value
    ]:
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
        SANDBOX_FALLBACK_EXE: Legacy launcher used when :attr:`SANDBOX_EXE` is
            absent from ``PATH``.
        SANDBOX_SESSION_EXE: Session host process spawned by the launcher. It
            receives the ``.wsb`` path on its own command line, which is how a
            session is correlated back to the instance that created it.
        SANDBOX_WORKER_EXE: Hyper-V worker process backing the sandbox VM.
        SHARED_FOLDER_NAME: Host-side shared folder name for sandbox mapping.
        SANDBOX_SHARED_PATH: Guest-side path where the shared folder is mounted.
        DISPATCHER_READY_MARKER: Marker filename used to signal dispatcher readiness.
    """

    SANDBOX_EXE = "WindowsSandbox.exe"
    SANDBOX_FALLBACK_EXE = "WindowsSandboxClient.exe"
    SANDBOX_SESSION_EXE = "WindowsSandboxRemoteSession.exe"
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
        self._session_pid: int | None = None
        self._launcher_exe: str | None = None
        self._active_captures: dict[str, str] = {}
        _logger.info(
            "windows_sandbox_initialized",
            timeout_seconds=self._config.timeout_seconds,
        )

    @staticmethod
    async def _exe_on_path(exe: str) -> bool:
        """Report whether an executable resolves on ``PATH``.

        Args:
            exe: Executable filename to look up.

        Returns:
            bool: True when ``where`` resolves the executable.
        """
        process_manager = ProcessManager.get_instance()
        result = await process_manager.run_tracked_async(
            ["where", exe],
            name="where-sandbox-exe",
            process_timeout=_WHERE_TIMEOUT,
        )
        return result.returncode == _RETURNCODE_SUCCESS

    async def _resolve_launcher_exe(self) -> str | None:
        """Resolve which Windows Sandbox launcher binary to use.

        Prefers :attr:`SANDBOX_EXE` (``WindowsSandbox.exe``), which creates a
        sandbox session. Falls back to :attr:`SANDBOX_FALLBACK_EXE`
        (``WindowsSandboxClient.exe``) only when the preferred launcher is
        absent, because on current Windows builds that binary is purely the
        connection client: started on its own it cannot create a session and
        fails with ``0x800706d9`` (verified on Windows 11 build 26220, where the
        client exits ``-2147023143`` from a clean process state while
        ``WindowsSandbox.exe`` starts a working VM).

        Returns:
            str | None: Launcher filename, or None when neither is on ``PATH``.
        """
        if self._launcher_exe is not None:
            return self._launcher_exe
        for candidate in (self.SANDBOX_EXE, self.SANDBOX_FALLBACK_EXE):
            if await self._exe_on_path(candidate):
                self._launcher_exe = candidate
                _logger.debug("windows_sandbox_launcher_resolved", exe=candidate)
                return candidate
        return None

    async def _probe_sandbox_availability(self) -> bool:
        """Probe the host for Windows Sandbox availability.

        Resolves the sandbox launcher on ``PATH``, then queries
        ``Win32_OptionalFeature`` via CIM to verify the
        ``Containers-DisposableClientVM`` install state. The CIM query is used
        instead of ``Get-WindowsOptionalFeature -Online`` because the latter
        requires administrator elevation, which would cause the probe to fail
        for ordinary unelevated Intellicrack sessions.

        Returns:
            bool: True when both the executable lookup and the feature
            probe succeed.
        """
        process_manager = ProcessManager.get_instance()
        if await self._resolve_launcher_exe() is None:
            _logger.debug("windows_sandbox_exe_not_found", exe=self.SANDBOX_EXE)
            return False

        ps_exe = "pwsh" if shutil.which("pwsh") else "powershell"
        ps_command = f"(Get-CimInstance -ClassName Win32_OptionalFeature -Filter \"Name='{_SANDBOX_FEATURE_NAME}'\").InstallState"
        features_result = await process_manager.run_tracked_async(
            [
                ps_exe,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_command,
            ],
            name="pwsh-sandbox-feature-check",
            process_timeout=_FEATURE_CHECK_TIMEOUT,
        )

        install_state = (features_result.stdout or "").strip()
        if install_state == _SANDBOX_INSTALL_STATE_ENABLED:
            _logger.info(
                "windows_sandbox_available",
                feature=_SANDBOX_FEATURE_NAME,
                install_state=install_state,
            )
            return True
        _logger.warning(
            "windows_sandbox_feature_not_enabled",
            feature=_SANDBOX_FEATURE_NAME,
            install_state=install_state or "unknown",
            returncode=features_result.returncode,
        )
        return False

    async def is_available(self) -> bool:
        """Check if Windows Sandbox is available.

        Returns:
            bool: True if Windows Sandbox can be used.
        """
        try:
            return await self._probe_sandbox_availability()
        except (OSError, RuntimeError) as e:
            _logger.warning("windows_sandbox_availability_check_failed", error=str(e))
            return False

    def _check_sandbox_alive(self) -> None:
        """Verify the sandbox session is still running.

        Liveness is judged on the session host process, not on the launcher:
        the launcher exits immediately by design once it has handed off, so
        polling it would report every healthy sandbox as terminated. The
        launcher is only consulted while no session has been bound yet.

        Raises:
            SandboxError: If the sandbox session has terminated.
        """
        if self._session_pid is not None:
            if not pid_is_running(self._session_pid):
                _logger.error("windows_sandbox_session_terminated", session_pid=self._session_pid)
                raise SandboxError(_ERR_SANDBOX_TERMINATED)
            return
        if self.process is not None and self.process.poll() not in {None, _RETURNCODE_SUCCESS}:
            _logger.error("windows_sandbox_process_terminated", returncode=self.process.returncode)
            raise SandboxError(_ERR_SANDBOX_TERMINATED)

    @staticmethod
    def detect_failure_dialog(client_pid: int) -> str | None:
        """Detect a native Windows Sandbox failure dialog.

        Public entry point over the same detection the backend uses during
        startup, so other callers (notably the Sandbox Settings "Test Sandbox"
        path) judge a failed launch identically instead of reimplementing it.

        Args:
            client_pid: PID whose dialogs should be considered, in addition to
                any top-level window titled "Windows Sandbox".

        Returns:
            str | None: Combined dialog text when a failure dialog is present,
            otherwise None.
        """
        return WindowsSandbox._detect_client_failure_dialog(client_pid)

    @staticmethod
    def _detect_client_failure_dialog(client_pid: int) -> str | None:
        """Detect a native Windows Sandbox failure dialog for the client process.

        The Windows Sandbox client raises its own modal dialog (window class
        ``#32770``, title ``Windows Sandbox``) when the guest VM cannot be
        connected -- for example the ``0x800706d9`` (``EPT_S_NOT_REGISTERED``)
        endpoint-mapper error. Because that dialog blocks while the client
        process stays alive, the readiness poll would otherwise wait the full
        dispatcher timeout. This enumerates top-level dialogs owned by
        ``client_pid`` (or titled ``Windows Sandbox``), reads their static-text
        children, and returns the combined text only when it looks like a real
        failure, so the transient startup progress dialog is ignored.

        Args:
            client_pid: PID of the ``WindowsSandboxClient.exe`` process.

        Returns:
            str | None: Combined dialog text when a failure dialog is present,
            otherwise None (including on every non-Windows platform).
        """
        if sys.platform != "win32":
            return None

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        enum_windows_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        user32.EnumWindows.argtypes = [enum_windows_proc, ctypes.c_void_p]
        user32.EnumWindows.restype = ctypes.c_bool
        user32.EnumChildWindows.argtypes = [ctypes.c_void_p, enum_windows_proc, ctypes.c_void_p]
        user32.EnumChildWindows.restype = ctypes.c_bool
        user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        user32.GetWindowThreadProcessId.restype = ctypes.c_ulong
        user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        user32.GetClassNameW.restype = ctypes.c_int
        user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        user32.GetWindowTextW.restype = ctypes.c_int
        user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
        user32.GetWindowTextLengthW.restype = ctypes.c_int

        def _window_text(hwnd: int) -> str:
            """Read the caption text of a top-level or child window.

            Args:
                hwnd: Native window handle.

            Returns:
                str: Window text, or an empty string when the window has none.
            """
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return ""
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            return buffer.value

        def _class_name(hwnd: int) -> str:
            """Read the Win32 class name of a window.

            Args:
                hwnd: Native window handle.

            Returns:
                str: Class name reported by ``GetClassNameW``.
            """
            buffer = ctypes.create_unicode_buffer(_GET_CLASS_NAME_BUFFER)
            user32.GetClassNameW(hwnd, buffer, _GET_CLASS_NAME_BUFFER)
            return buffer.value

        collected: list[str] = []

        def _child_cb(hwnd: int, _lparam: int) -> bool:
            """Collect non-empty child window captions during enumeration.

            Args:
                hwnd: Child window handle supplied by ``EnumChildWindows``.
                _lparam: Unused ``lParam`` from the enumeration callback.

            Returns:
                bool: Always ``True`` so enumeration continues.
            """
            text = _window_text(hwnd)
            if text:
                collected.append(text)
            return True

        child_proc = enum_windows_proc(_child_cb)
        matched: dict[str, str] = {}

        def _top_cb(hwnd: int, _lparam: int) -> bool:
            """Match Windows Sandbox client failure dialogs and harvest text.

            Args:
                hwnd: Top-level window handle supplied by ``EnumWindows``.
                _lparam: Unused ``lParam`` from the enumeration callback.

            Returns:
                bool: Always ``True`` so enumeration continues after a match.
            """
            if "text" in matched:
                return True
            title = _window_text(hwnd)
            owner_pid = ctypes.c_ulong(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
            owned_by_client = owner_pid.value == client_pid
            sandbox_titled = "windows sandbox" in title.lower()
            if not (owned_by_client or sandbox_titled):
                return True
            if _class_name(hwnd) != _SANDBOX_DIALOG_CLASS:
                return True
            collected.clear()
            collected.append(title)
            user32.EnumChildWindows(hwnd, child_proc, None)
            combined = "\n".join(part for part in collected if part).strip()
            if _is_sandbox_failure_text(combined):
                matched["text"] = combined
            return True

        try:
            user32.EnumWindows(enum_windows_proc(_top_cb), None)
        except OSError as err:
            _logger.debug("sandbox_failure_dialog_enum_failed", client_pid=client_pid, error=str(err))
            return None
        return matched.get("text")

    @staticmethod
    def _raise_launch_dialog_failure(detail: str) -> NoReturn:
        """Raise an actionable :class:`SandboxError` for a detected failure dialog.

        Args:
            detail: Combined dialog text captured from the failure dialog.

        Raises:
            SandboxError: Always. Uses the RPC-endpoint guidance when the
                ``0x800706d9`` code is present, otherwise a generic message that
                embeds the captured dialog text.
        """
        code_match = _SANDBOX_ERROR_CODE_RE.search(detail)
        error_code = code_match.group(0) if code_match else None
        _logger.error(
            "windows_sandbox_launch_failure_dialog",
            error_code=error_code,
            dialog_text=detail[:500],
        )
        if error_code is not None and error_code.lower() == _SANDBOX_RPC_ENDPOINT_ERROR:
            raise SandboxError(_ERR_LAUNCH_RPC_ENDPOINT)
        normalized = " ".join(detail.split())
        suffix = f": {normalized}" if normalized else ""
        msg = f"{_ERR_LAUNCH_DIALOG}{suffix}"
        raise SandboxError(msg)

    async def _check_startup_health(self) -> None:
        """Detect a failed launch or native failure dialog during startup.

        ``WindowsSandbox.exe`` is a fire-and-forget launcher: it spawns the
        session host and exits ``0`` immediately, so a zero exit is a normal
        successful launch and must not be treated as a crash. Only a non-zero
        launcher exit is fatal, and an exit code of ``0x800706d9`` is mapped to
        the same actionable message the failure dialog produces -- from a clean
        process state the launcher reports that condition as an exit code
        rather than a dialog, so without this mapping it surfaced only as a bare
        ``-2147023143``.

        Raises:
            SandboxError: If the launcher exited non-zero, or a Windows Sandbox
                failure dialog (such as the ``0x800706d9`` endpoint-mapper
                error) was detected.
        """
        if self.process is None:
            return
        if self.process.poll() is not None:
            returncode = self.process.returncode
            if returncode == _SANDBOX_RPC_ENDPOINT_EXIT_CODE:
                _logger.error(
                    "windows_sandbox_launch_rpc_endpoint_exit",
                    returncode=returncode,
                    launcher=self._launcher_exe,
                )
                raise SandboxError(_ERR_LAUNCH_RPC_ENDPOINT)
            if returncode != _RETURNCODE_SUCCESS:
                _logger.error("windows_sandbox_client_exited_during_startup", returncode=returncode)
                msg = f"{_ERR_LAUNCH_CLIENT_EXITED} (launcher exit code {returncode})"
                raise SandboxError(msg)
        dialog_pid = self._session_pid if self._session_pid is not None else self.process.pid
        detail = await asyncio.to_thread(self._detect_client_failure_dialog, dialog_pid)
        if detail is not None:
            self._raise_launch_dialog_failure(detail)

    async def _prepare_shared_folders(self) -> None:
        """Create the temp dir, shared folder, monitor folder, and ticket subdirectories."""
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

    async def _find_session_pid(self) -> int | None:
        """Locate the sandbox session process created for this instance.

        The launcher passes the ``.wsb`` path straight through to
        :attr:`SANDBOX_SESSION_EXE`, so the session is matched exactly by its
        command line rather than by a most-recently-started heuristic. That
        matters when several sandboxes are launched in sequence, where a
        newest-wins match can attach to the wrong session.

        Returns:
            int | None: PID of the session process, or None when no session
            process references this instance's configuration file.
        """
        if self._wsb_path is None:
            return None
        return await asyncio.to_thread(find_sandbox_session_pid, self._wsb_path.name)

    async def _await_session_pid(self) -> int | None:
        """Poll for this instance's sandbox session process.

        Returns:
            int | None: PID of the session process, or None if none appeared
            within :data:`_SESSION_PID_POLL_TIMEOUT`.
        """
        deadline = time.monotonic() + _SESSION_PID_POLL_TIMEOUT
        while time.monotonic() < deadline:
            if (pid := await self._find_session_pid()) is not None:
                return pid
            await asyncio.sleep(_SESSION_PID_POLL_INTERVAL)
        return None

    async def _launch_sandbox_process(self) -> None:
        """Launch Windows Sandbox and bind this instance to the resulting session.

        Generates monitor and dispatcher scripts, produces the ``.wsb``
        configuration, spawns the resolved sandbox launcher, registers the
        process with the global :class:`ProcessManager`, and resolves the
        session host process the launcher created.

        Raises:
            SandboxError: If the temporary sandbox directory was not
                initialised before this call, if no sandbox launcher is
                available, or if the launcher produced no session.
        """
        await self._create_monitor_scripts()
        await self._create_dispatcher_scripts()

        if self._temp_dir is None:
            raise SandboxError(_ERR_START_FAILED)
        self._wsb_path = self._temp_dir / "intellicrack.wsb"
        await self._generate_wsb_config()

        launcher = await self._resolve_launcher_exe()
        if launcher is None:
            raise SandboxError(_ERR_START_FAILED)

        _logger.info("windows_sandbox_starting", config_path=str(self._wsb_path), launcher=launcher)

        self.process = await asyncio.to_thread(
            Popen,
            [launcher, str(self._wsb_path)],
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

        await self._check_startup_health()
        await self._bind_sandbox_session()

    async def _bind_sandbox_session(self) -> None:
        """Resolve and register the sandbox session host for this instance.

        The launcher exits as soon as it has handed off, so the session host
        process is what actually owns the running VM and its window. Resolving
        it here gives teardown and health checks a real target instead of an
        already-dead launcher PID.

        Raises:
            SandboxError: If no session process appeared, after re-checking for
                a failure dialog so the specific cause is reported when one is
                available.
        """
        self._session_pid = await self._await_session_pid()
        if self._session_pid is None:
            await self._check_startup_health()
            _logger.error("windows_sandbox_session_not_started", launcher=self._launcher_exe)
            raise SandboxError(_ERR_LAUNCH_SESSION_NOT_STARTED)

        _logger.info("windows_sandbox_session_bound", session_pid=self._session_pid)
        ProcessManager.get_instance().register_external_pid(
            self._session_pid,
            name="windows-sandbox-session",
            process_type=ProcessType.SANDBOX,
        )

    async def _attach_sandbox_worker(self) -> None:
        """Wait for dispatcher readiness, resolve worker PID, and finalize state.

        Raises:
            SandboxError: If the sandbox process has died before becoming ready.
        """
        await self._wait_for_dispatcher_ready()
        self._check_sandbox_alive()

        if self.process is None:
            raise SandboxError(_ERR_SANDBOX_TERMINATED)

        process_manager = ProcessManager.get_instance()
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
        self.state.pid = self._session_pid if self._session_pid is not None else self.process.pid

        _logger.info("windows_sandbox_started", pid=self.state.pid, session_pid=self._session_pid)

    async def _start_impl(self) -> None:
        """Execute the full Windows Sandbox start sequence."""
        await self._prepare_shared_folders()
        await self._launch_sandbox_process()
        await self._attach_sandbox_worker()

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
            await self._start_impl()
        except SandboxError as e:
            await self._handle_start_failure(e)
            raise
        except (OSError, RuntimeError) as e:
            await self._handle_start_failure(e)
            raise SandboxError(_ERR_START_FAILED) from e

    async def _handle_start_failure(self, error: Exception) -> None:
        """Record error state and tear down the partially-started sandbox.

        Args:
            error: The exception that aborted the start sequence.
        """
        _logger.warning("windows_sandbox_start_failed", error=str(error))
        self.state.status = "error"
        self.state.last_error = str(error)
        await self._abort_client()
        await self._cleanup()

    async def _abort_client(self) -> None:
        """Force-terminate a sandbox client (and its modal failure dialog) after a failed start.

        Unlike :meth:`stop`, this skips the graceful ``WM_CLOSE`` path because a failed launch typically leaves the client blocked on a
        modal error dialog that never honours a close request; the client is force-killed and unregistered so the next launch attempt is not
        blocked by a stale instance.
        """
        process_manager = ProcessManager.get_instance()
        await self._terminate_sandbox_session(process_manager)

        if self.process is None:
            return

        pid = self.process.pid
        if self.process.poll() is None:
            await self._force_kill_sandbox(pid)

        try:
            await asyncio.wait_for(
                asyncio.to_thread(self.process.wait),
                timeout=_PROCESS_WAIT_TIMEOUT,
            )
        except TimeoutError:
            _logger.warning("sandbox_client_abort_wait_timeout", pid=pid)
            self.process.kill()
            await asyncio.to_thread(self.process.wait)

        process_manager.unregister(pid)
        self.process = None

    async def _terminate_sandbox_client(self, process_manager: ProcessManager) -> None:
        """Terminate the sandbox client process gracefully or forcefully.

        Args:
            process_manager: Active :class:`ProcessManager` used to
                unregister the client PID after termination.
        """
        if self.process is None:
            return

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

    async def _terminate_sandbox_session(self, process_manager: ProcessManager) -> None:
        """Close the sandbox session host, unwinding the VM with it.

        The session is closed gracefully first. That matters: force-killing the
        session processes leaves the backing ``vmmemWindowsSandbox`` VM
        resident, because only an orderly shutdown makes the Host Compute
        Service terminate the compute system. A leaked VM then blocks the next
        create through the single-instance limit. Force-kill is the fallback,
        not the default.

        Args:
            process_manager: Active :class:`ProcessManager` used to terminate
                and unregister the session PID.
        """
        if self._session_pid is None:
            return

        session_pid = self._session_pid
        graceful_ok = await self._try_graceful_close(session_pid)
        if not graceful_ok or pid_is_running(session_pid):
            _logger.warning("windows_sandbox_session_force_kill", session_pid=session_pid, graceful=graceful_ok)
            try:
                process_manager.terminate_external_pid(session_pid, force=True)
            except (OSError, RuntimeError) as session_err:
                _logger.warning("sandbox_session_terminate_failed", session_pid=session_pid, error=str(session_err))

        process_manager.unregister(session_pid)
        self._session_pid = None

    def _terminate_sandbox_worker(self, process_manager: ProcessManager) -> None:
        """Terminate the vmwp.exe worker registered for this sandbox.

        Args:
            process_manager: Active :class:`ProcessManager` used to issue
                the forced external-PID termination.
        """
        if self._worker_pid is None:
            return

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

    async def _stop_impl(self) -> None:
        """Execute the full Windows Sandbox stop sequence."""
        process_manager = ProcessManager.get_instance()
        await self._terminate_sandbox_session(process_manager)
        await self._terminate_sandbox_client(process_manager)
        self._terminate_sandbox_worker(process_manager)
        await self._cleanup()

        self.state.status = "stopped"
        self.state.pid = None
        _logger.info("windows_sandbox_stopped", sandbox_type="windows")

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

        try:
            await self._stop_impl()
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
            """Post ``WM_CLOSE`` to every top-level window owned by ``pid``.

            Returns:
                bool: ``True`` when at least one ``WM_CLOSE`` was posted.
            """
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

            def _cb(hwnd: int, _lparam: int) -> bool:
                """Post ``WM_CLOSE`` when the window belongs to the target PID.

                Args:
                    hwnd: Top-level window handle from ``EnumWindows``.
                    _lparam: Unused ``lParam`` from the enumeration callback.

                Returns:
                    bool: Always ``True`` so remaining windows are visited.
                """
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

            if raw := (result.stdout or "").strip():
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
                """Log a single ``shutil.rmtree`` entry failure without aborting.

                Args:
                    func: OS function that failed (for example ``os.unlink``).
                    path: Filesystem path that could not be removed.
                    exc_info: Exception triple or error object from ``rmtree``.
                """
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
            await self._check_startup_health()
            if await asyncio.to_thread(marker.exists):
                _logger.info("dispatcher_ready_signalled")
                return
            await asyncio.sleep(_DISPATCHER_POLL_INTERVAL)

        _logger.error("dispatcher_ready_timeout", time_limit=_DISPATCHER_STARTUP_TIMEOUT)
        raise SandboxError(_ERR_DISPATCHER_NOT_READY)

    async def _generate_wsb_config(self) -> None:
        """Generate the .wsb configuration file.

        The document itself is built by
        :func:`~intellicrack.sandbox.wsb.build_wsb_configuration`, which is
        shared with the configuration dialog's sandbox test so the two cannot
        drift apart.

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

        mapped_folders = [
            WsbMappedFolder(
                host_folder=self._shared_folder,
                sandbox_folder=self.SANDBOX_SHARED_PATH,
                read_only=False,
            ),
        ]
        mapped_folders.extend(
            WsbMappedFolder(host_folder=host_path, sandbox_folder=sandbox_path, read_only=read_only)
            for host_path, sandbox_path, read_only in self._config.shared_folders
        )

        configuration = build_wsb_configuration(
            logon_command=self._build_logon_command(),
            mapped_folders=mapped_folders,
            networking_enabled=self._config.network_enabled,
            memory_limit_mb=self._config.memory_limit_mb,
            video_enabled=self._config.video_enabled,
            audio_enabled=self._config.audio_enabled,
            clipboard_enabled=self._config.clipboard_enabled,
            printer_enabled=self._config.printer_enabled,
        )

        await asyncio.to_thread(self._wsb_path.write_bytes, render_wsb_configuration(configuration))
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

    @staticmethod
    def bundled_scripts_dir() -> Path:
        """Return the on-disk directory holding the bundled monitor scripts.

        Returns:
            Path: Absolute path to the ``sandbox/scripts`` directory whose
            contents :meth:`_create_monitor_scripts` stages into the guest.
            The path is resolved from this module's location, so it is safe
            to compute synchronously even from async callers.
        """
        return _SCRIPTS_DIR

    async def _create_monitor_scripts(self) -> None:
        """Stage the monitor fleet into the shared folder.

        Copies every PowerShell monitor bundled in ``sandbox/scripts`` plus
        the ``start_monitors.cmd`` launcher into the guest-accessible monitor
        directory, then emits the inline process / file / network monitors
        used for base telemetry. Registry telemetry comes from the bundled
        ``registry_monitor.ps1`` copied above, so nothing is emitted inline
        for it.

        Raises:
            SandboxError: If sandbox paths are not initialized.
        """
        if self._monitor_folder is None:
            _logger.error("monitor_scripts_monitor_folder_not_initialized")
            raise SandboxError(_ERR_SANDBOX_PATHS_NOT_INIT)

        monitor_folder = self._monitor_folder

        def _copy_scripts() -> list[str]:
            """Copy PowerShell and CMD monitor scripts into the shared folder.

            Returns:
                list[str]: Names of files copied into ``monitor_folder``.

            Raises:
                SandboxError: If the host scripts directory is missing.
            """
            scripts_dir = WindowsSandbox.bundled_scripts_dir()
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
        """Write the file, network, and process baseline monitors.

        These cover the core FileChange / NetworkActivity / ProcessActivity telemetry that the :class:`ExecutionReport`
        always expects; they complement the external PowerShell monitors.
        RegistryChange telemetry deliberately has no inline monitor: the
        bundled ``sandbox/scripts/registry_monitor.ps1`` staged by
        :meth:`_create_monitor_scripts` is its single source of truth, and an
        inline copy here would overwrite the staged file.
        """
        if self._monitor_folder is None:
            return

        monitors: list[tuple[str, str]] = [
            ("file_monitor.ps1", self._file_monitor_source()),
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

    async def _poll_dispatcher_result(
        self,
        paths: _DispatcherPaths,
        effective_timeout: float,
    ) -> tuple[int, str, str] | None:
        """Poll dispatcher output paths until a result appears or timeout elapses.

        Args:
            paths: Ticket-specific dispatcher paths to poll.
            effective_timeout: Total wall-clock budget in seconds.

        Returns:
            tuple[int, str, str] | None: The decoded ``(exit_code, stdout, stderr)``
            triple emitted by the dispatcher, or ``None`` if the deadline was
            reached without a result.
        """
        deadline = time.monotonic() + effective_timeout
        while time.monotonic() < deadline:
            self._check_sandbox_alive()
            await asyncio.sleep(_RESULT_POLL_INTERVAL)
            if not await asyncio.to_thread(paths.result.exists):
                continue
            completed = await _read_dispatcher_result(paths)
            if completed is not None:
                return completed
        return None

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
        _logger.info(
            "windows_sandbox_run_command_started",
            command=command[:200],
            time_limit=time_limit,
            working_directory=working_directory,
        )
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
            completed = await self._poll_dispatcher_result(paths, effective_timeout)
            if completed is None:
                raise SandboxTimeoutError(_ERR_CMD_TIMEOUT)
            return completed
        finally:
            for ticket_path in (paths.trigger, paths.out, paths.err, paths.result):
                try:
                    if await asyncio.to_thread(ticket_path.exists):
                        await asyncio.to_thread(ticket_path.unlink, missing_ok=True)
                except OSError as del_err:
                    _logger.warning(
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
        _logger.info("windows_sandbox_run_binary_started", binary=str(binary_path), arg_count=len(args) if args else 0, monitor=monitor)
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
            _logger.exception(
                "sandbox_execution_timeout",
                binary=binary_path.name,
                timeout=effective_timeout,
            )
            exit_code = _RETURNCODE_FAILURE
            result = "timeout"
            stderr = str(e)
            stdout = ""
        except SandboxError as e:
            _logger.exception(
                "sandbox_execution_error",
                binary=binary_path.name,
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
                _logger.warning("monitor_quiescence_stat_failed")
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
        _logger.info("windows_sandbox_copy_to_sandbox_started", source=str(source), dest=dest)
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
        _logger.info("windows_sandbox_copy_from_sandbox_started", source=source, dest=str(dest))
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
        _logger.info("windows_sandbox_capture_screenshot_started", output_path=str(output_path) if output_path else None)
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
        _logger.info("windows_sandbox_apply_anti_evasion_started", profile=profile)
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
            _logger.warning("wmi_hijack_verification_unexpected_payload", payload_preview=str(parsed_obj)[:500])
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
        _logger.info("windows_sandbox_dump_memory_started", output_path=str(output_path) if output_path else None, target_pid=target_pid)
        if sys.platform != "win32":
            raise SandboxError(_ERR_MEMORY_DUMP_NOT_WINDOWS)
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
            "}\n"
            '"@ -ErrorAction Stop;\n'
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
        _logger.info("windows_sandbox_extract_dropped_files_started", output_path=str(output_path) if output_path else None)
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
            """Archive every file under the staging directory into ``zip_path``."""
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

        An empty result means the rules matched nothing in artifacts that were
        really scanned. Having nothing to scan is a different outcome and is
        raised rather than returned, so a scan that never reached the guest
        cannot be mistaken for a clean one.

        Args:
            rules_path: Path to YARA rules file. Uses built-in rules if None.
            scan_target: What to scan - 'files' for dropped files, 'memory' for memory dump.

        Returns:
            list[dict[str, Any]]: List of YARA match dictionaries.

        Raises:
            SandboxError: If the scan target is unknown, the sandbox has no
                shared folder, or there is nothing of the requested kind to
                scan.
        """
        _logger.info("windows_sandbox_yara_scan_started", rules_path=rules_path, scan_target=scan_target)
        if scan_target not in YARA_SCAN_TARGETS:
            _logger.warning("yara_scan_unknown_target", scan_target=scan_target)
            raise SandboxError(
                ERR_YARA_UNKNOWN_TARGET.format(target=scan_target, expected=", ".join(YARA_SCAN_TARGETS)),
            )
        yara = require_yara()

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

        if scan_target == YARA_TARGET_MEMORY:
            dump_files = await asyncio.to_thread(
                lambda: list(output_dir.glob("memdump_*.dmp")),
            )
            if not dump_files:
                _logger.warning("yara_scan_no_memory_dump", output_dir=str(output_dir))
                raise SandboxError(ERR_YARA_NO_MEMORY_DUMP.format(path=output_dir))
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
                    """Unpack dropped-file archives and list every extracted path.

                    Returns:
                        list[Path]: Files under ``extract_dir`` after extraction.
                    """
                    extracted: list[Path] = []
                    for zf_path in zip_files:
                        with zipfile.ZipFile(zf_path, "r") as zf:
                            zf.extractall(extract_dir)
                    extracted.extend(fp for fp in extract_dir.rglob("*") if fp.is_file())
                    return extracted

                scan_files = await asyncio.to_thread(_extract_zips)
            else:
                scan_files = await asyncio.to_thread(scannable_output_files, output_dir)

            if not scan_files:
                _logger.warning("yara_scan_no_artifacts", output_dir=str(output_dir))
                raise SandboxError(ERR_YARA_NO_ARTIFACTS.format(path=output_dir))

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
        return _write_minidump_to_path(dbghelp, kernel32, handle, pid, dump_path)
    finally:
        kernel32.CloseHandle(handle)


def _write_minidump_to_path(
    dbghelp: ctypes.WinDLL,
    kernel32: ctypes.WinDLL,
    process_handle: int,
    pid: int,
    dump_path: Path,
) -> tuple[bool, str]:
    """Write the minidump for ``process_handle`` to ``dump_path``.

    Args:
        dbghelp: Loaded ``dbghelp.dll`` interface.
        kernel32: Loaded ``kernel32.dll`` interface.
        process_handle: Opened Win32 process handle for ``pid``.
        pid: Target process PID (used only for diagnostic context).
        dump_path: Destination file path for the dump.

    Returns:
        tuple[bool, str]: Success flag and diagnostic error string (empty on success).
    """
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
            process_handle,
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
    return (True, "")


def _win_handle_from_file(file_obj: IO[bytes]) -> int | None:
    """Return the raw Win32 HANDLE for an opened file, or None on failure.

    Args:
        file_obj: Python file object.

    Returns:
        int | None: Win32 HANDLE, or None if it could not be obtained.
    """
    if sys.platform != "win32" or _msvcrt is None:
        return None
    get_osfhandle: Callable[[int], int] = _msvcrt.get_osfhandle
    try:
        return get_osfhandle(file_obj.fileno())
    except (OSError, ValueError, AttributeError):
        _logger.warning("win_handle_from_file_failed", exc_info=True)
        return None
