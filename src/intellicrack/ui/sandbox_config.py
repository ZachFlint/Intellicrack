# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox configuration dialog for Intellicrack.

This module provides the UI for configuring Windows Sandbox settings, including isolation options, resource limits, and execution policies.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import inspect
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, cast, override

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.config import get_config_dir, get_config_file, get_project_root
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import CREATE_NO_WINDOW, PIPE, CompletedProcess, Popen, SubprocessError, TimeoutExpired
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS
from intellicrack.sandbox.settings import (
    QEMU_ACCELERATION_KEY,
    QEMU_AGENT_TIMEOUT_KEY,
    QEMU_CPU_CORES_KEY,
    QEMU_DEFAULT_AGENT_TIMEOUT,
    QEMU_DEFAULT_CPU_CORES,
    QEMU_DEFAULT_GUEST_OS,
    QEMU_DEFAULT_MEMORY_MB,
    QEMU_GUEST_OS_KEY,
    QEMU_IMAGE_PATH_KEY,
    QEMU_MAX_AGENT_TIMEOUT,
    QEMU_MAX_CPU_CORES,
    QEMU_MAX_MEMORY_MB,
    QEMU_MEMORY_MB_KEY,
    QEMU_MIN_AGENT_TIMEOUT,
    QEMU_MIN_CPU_CORES,
    QEMU_MIN_MEMORY_MB,
    build_qemu_config,
)
from intellicrack.sandbox.windows import WindowsSandbox, find_sandbox_session_pid

from .dialogs_helpers import show_info, show_warning
from .panels.async_bridge import (
    WORKER_DEFAULT_EXCEPTIONS,
    GenericCallableWorker,
    run_bridge_coroutine,
    run_bridge_coroutine_async,
)
from .resources import IconManager
from .win32_embed import find_window_by_pid


if TYPE_CHECKING:
    from collections.abc import Mapping

    from PyQt6.QtGui import QCloseEvent

    from intellicrack.sandbox.manager import SandboxManager


_logger = get_logger(__name__)

_DIALOG_WIDTH: Final[int] = 550
_DIALOG_HEIGHT: Final[int] = 500
_OUTPUT_MAX_HEIGHT: Final[int] = 150
_IS_WIN32: bool = os.name == "nt"
_TEST_VERIFY_TIMEOUT: Final[float] = 90.0
_TEST_VERIFY_POLL_INTERVAL: Final[float] = 1.0
_DEFAULT_CONFIG_ATTR: Final[str] = "_default_config"
_SANDBOX_FEATURE_NAME: Final[str] = "Containers-DisposableClientVM"
_SANDBOX_INSTALL_STATE_ENABLED: Final[str] = "1"
_SANDBOX_AVAILABILITY_TIMEOUT_SECONDS: Final[int] = 10
_AVAILABILITY_RESULT_LEN: Final[int] = 2
_WM_CLOSE: Final[int] = 0x0010
_GRACEFUL_CLOSE_TIMEOUT_S: Final[float] = 5.0


def _windows_sandbox_binary_path() -> Path:
    r"""Return the expected path to the Windows Sandbox client binary.

    Returns:
        Path: Absolute path to ``WindowsSandbox.exe`` under ``%SystemRoot%\System32``.
    """
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    return Path(system_root) / "System32" / "WindowsSandbox.exe"


def _post_wm_close(pid: int) -> bool:
    """Post ``WM_CLOSE`` to the top-level window owned by ``pid``, if any.

    Mirrors clicking the sandbox window's own close button so Windows
    Sandbox can run its documented teardown of the Host Compute Service
    session it owns. A bare ``TerminateProcess`` kill of the client does
    not reliably release that session, which can leave a subsequent
    Windows Sandbox ``Create`` blocked by the orphaned instance. Reuses
    :func:`~intellicrack.ui.win32_embed.find_window_by_pid` (returns
    ``None`` on non-Windows platforms or when no window is found) instead
    of duplicating window enumeration.

    Args:
        pid: Process ID whose top-level window should receive ``WM_CLOSE``.

    Returns:
        bool: True when a window belonging to ``pid`` was found and
        ``WM_CLOSE`` was successfully posted to it.
    """
    hwnd = find_window_by_pid(pid)
    if hwnd is None:
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.PostMessageW.argtypes = [
        ctypes.wintypes.HWND,
        ctypes.wintypes.UINT,
        ctypes.wintypes.WPARAM,
        ctypes.wintypes.LPARAM,
    ]
    user32.PostMessageW.restype = ctypes.wintypes.BOOL
    return bool(user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0))


class _AvailabilityCache:
    """Process-wide cache for the Windows Sandbox availability probe result.

    The probe may spawn a bounded PowerShell subprocess, so its ``(available, reason)`` result is memoised here to avoid repeating the work
    on every caller (for example each time the Sandbox tab is constructed).
    """

    value: ClassVar[tuple[bool, str] | None] = None
    lock: ClassVar[threading.Lock] = threading.Lock()


def _query_sandbox_optional_feature() -> tuple[str, int]:
    """Query the CIM optional-feature install state for Windows Sandbox.

    Uses a ``Win32_OptionalFeature`` CIM query which - unlike
    ``Get-WindowsOptionalFeature -Online`` - reports ``InstallState`` without
    requiring administrator elevation. Propagates ``TimeoutExpired`` when the
    PowerShell probe exceeds its timeout, ``FileNotFoundError`` when the
    PowerShell executable cannot be located, and ``OSError`` when the operating
    system rejects the process launch; callers wrap the call in an exception
    handler.

    Returns:
        tuple[str, int]: ``(install_state, returncode)`` where ``install_state``
        is the trimmed ``InstallState`` value reported by CIM and ``returncode``
        is the PowerShell process exit code.
    """
    ps_command = f"(Get-CimInstance -ClassName Win32_OptionalFeature -Filter \"Name='{_SANDBOX_FEATURE_NAME}'\").InstallState"
    process_manager = ProcessManager.get_instance()
    result = process_manager.run_tracked(
        [
            "powershell",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ps_command,
        ],
        name="powershell-sandbox-check",
        check=False,
        timeout=_SANDBOX_AVAILABILITY_TIMEOUT_SECONDS,
        creationflags=CREATE_NO_WINDOW,
    )
    return (result.stdout or "").strip(), result.returncode


def _probe_windows_sandbox() -> tuple[bool, str]:
    r"""Probe Windows for the Containers-DisposableClientVM optional feature.

    Runs two unelevated detection paths in sequence so the result is accurate
    when Intellicrack is launched from a standard (non-admin) session:

    1. Presence of ``WindowsSandbox.exe`` under ``%SystemRoot%\System32``. DISM
       only installs this binary when the optional feature is enabled, so a hit
       is definitive and avoids spawning a subprocess entirely.
    2. A CIM ``Win32_OptionalFeature`` query for the install state.

    Returns:
        tuple[bool, str]: ``(available, reason)`` where ``available`` is ``True``
        with an empty ``reason`` when Windows Sandbox can be launched, or
        ``False`` with a human-readable explanation otherwise.
    """
    if not _IS_WIN32:
        _logger.info(
            "sandbox_config_validated",
            valid=False,
            reason="non_windows_platform",
            platform=sys.platform,
        )
        return False, "Windows Sandbox is only available on Windows"

    sandbox_binary = _windows_sandbox_binary_path()
    if sandbox_binary.is_file():
        _logger.info(
            "sandbox_config_validated",
            valid=True,
            sandbox_available=True,
            detection="windows_sandbox_binary",
            binary_path=str(sandbox_binary),
        )
        return True, ""

    try:
        install_state, returncode = _query_sandbox_optional_feature()
    except TimeoutExpired:
        _logger.exception("sandbox_config_error", operation="availability_check", failure_reason="timeout")
        return False, "Timeout checking Windows Sandbox status"
    except FileNotFoundError:
        _logger.exception("sandbox_config_error", operation="availability_check", failure_reason="powershell_not_found")
        return False, "PowerShell not found"
    except OSError as exc:
        _logger.exception("sandbox_config_error", operation="availability_check", failure_reason="os_error")
        return False, f"Could not determine Windows Sandbox status: {exc}"

    if install_state == _SANDBOX_INSTALL_STATE_ENABLED:
        _logger.info(
            "sandbox_config_validated",
            valid=True,
            sandbox_available=True,
            detection="cim_optional_feature",
            install_state=install_state,
        )
        return True, ""

    _logger.info(
        "sandbox_config_validated",
        valid=False,
        reason="feature_not_enabled",
        detection="cim_optional_feature",
        install_state=install_state or "unknown",
        returncode=returncode,
    )
    return False, "Windows Sandbox feature is not enabled"


def check_windows_sandbox_availability(*, use_cache: bool = True) -> tuple[bool, str]:
    """Return the Windows Sandbox availability probe result, optionally cached.

    Args:
        use_cache: When ``True`` (default) return a previously computed result
            if one exists and store freshly computed results for reuse. When
            ``False`` always run the probe and refresh the cache.

    Returns:
        tuple[bool, str]: ``(available, reason)`` as documented on
        :func:`_probe_windows_sandbox`.
    """
    if use_cache:
        with _AvailabilityCache.lock:
            cached = _AvailabilityCache.value
        if cached is not None:
            return cached
    result = _probe_windows_sandbox()
    with _AvailabilityCache.lock:
        _AvailabilityCache.value = result
    return result


def is_windows_sandbox_available(*, use_cache: bool = True) -> bool:
    """Return whether Windows Sandbox is available without constructing any UI.

    This standalone entry point lets callers determine sandbox availability
    without instantiating - and leaking - a :class:`SandboxConfigDialog` purely
    to read its instance ``is_sandbox_available()``.

    Args:
        use_cache: Whether to reuse a cached probe result. See
            :func:`check_windows_sandbox_availability`.

    Returns:
        bool: ``True`` when Windows Sandbox can be launched on this host.
    """
    available, _reason = check_windows_sandbox_availability(use_cache=use_cache)
    return available


class SandboxTestWorker(QThread):
    """Worker thread for testing Windows Sandbox.

    Launches Windows Sandbox with a test configuration and monitors
    its execution without blocking the UI.

    Attributes:
        finished: Signal emitted when test completes with (success, message).
        output: Signal emitted with sandbox output messages.
    """

    finished: ClassVar[pyqtSignal] = pyqtSignal(bool, str)
    output: ClassVar[pyqtSignal] = pyqtSignal(str)

    def __init__(
        self,
        *,
        network_enabled: bool = False,
        memory_limit_mb: int = 2048,
        shared_folder: str | None = None,
        read_only: bool = False,
        parent: QObject | None = None,
    ) -> None:
        """Initialize the SandboxTestWorker with sandbox configuration.

        Args:
            network_enabled: Whether networking is enabled in the sandbox.
            memory_limit_mb: Memory limit in MB for the sandbox.
            shared_folder: Path to the host-side shared folder.
            read_only: Whether the shared folder is read-only.
            parent: Parent QObject that owns this worker thread.
        """
        super().__init__(parent)
        self._network_enabled = network_enabled
        self._memory_limit_mb = memory_limit_mb
        self._shared_folder = shared_folder
        self._read_only = read_only
        self._wsb_file: Path | None = None
        self._process: Popen[bytes] | None = None

    def _launch_sandbox_test(self) -> bool:
        """Generate the WSB config, launch Windows Sandbox, and wait for it.

        Returns:
            bool: ``True`` when the helper handled finish signalling itself
            (the caller should return without emitting a success), ``False``
            when the run completed normally and the caller should emit success.
        """
        self.output.emit("Creating sandbox configuration...")
        wsb_content = self._generate_wsb_config()

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".wsb",
            delete=False,
            encoding="utf-8",
        ) as wsb_file:
            wsb_file.write(wsb_content)
            self._wsb_file = Path(wsb_file.name)

        self._log_wsb_written(wsb_content)
        self.output.emit(f"Configuration file: {self._wsb_file}")
        self.output.emit("Launching Windows Sandbox...")

        self._process = Popen(
            ["WindowsSandbox.exe", str(self._wsb_file)],
            stdout=PIPE,
            stderr=PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        self._register_test_process()

        self.output.emit("Windows Sandbox launched")
        self.output.emit("Verifying the sandbox session actually started...")

        return self._verify_sandbox_session()

    def _verify_sandbox_session(self) -> bool:
        """Confirm a real sandbox session started, or report why it did not.

        Liveness of the launched process is not evidence of success. The
        launcher is fire-and-forget and exits ``0`` as soon as it has handed
        off, and a launch that fails with ``0x800706d9`` leaves a process alive
        on a modal dialog -- so both "exited 0" and "still running after N
        seconds" occur on hosts where creating a sandbox is impossible. Success
        is therefore defined as an actual session host process existing for this
        configuration, with no failure dialog on screen.

        Returns:
            bool: ``True`` when this method emitted ``finished`` itself (the
            caller must not emit success); ``False`` when a real session was
            confirmed and the caller should emit success.
        """
        failed = False
        if self._wsb_file is None:
            self.finished.emit(failed, "Sandbox test could not write its configuration file")
            return True

        wsb_name = self._wsb_file.name
        deadline = time.monotonic() + _TEST_VERIFY_TIMEOUT
        while time.monotonic() < deadline:
            probe_pid = self._process.pid if self._process is not None else 0
            if detail := WindowsSandbox.detect_failure_dialog(probe_pid):
                normalized = " ".join(detail.split())
                _logger.warning("sandbox_test_failure_dialog", dialog_text=normalized[:500])
                self.finished.emit(failed, f"Windows Sandbox failed to start: {normalized}")
                return True

            if find_sandbox_session_pid(wsb_name) is not None:
                self.output.emit("Sandbox session is running")
                return False

            if self._process is not None and self._process.poll() is not None and self._handle_sandbox_exit_status():
                return True

            time.sleep(_TEST_VERIFY_POLL_INTERVAL)

        _logger.warning("sandbox_test_no_session", wsb=wsb_name)
        self.finished.emit(
            failed,
            f"Windows Sandbox did not start: no sandbox session appeared within {_TEST_VERIFY_TIMEOUT:.0f} seconds.",
        )
        return True

    def run(self) -> None:
        """Execute the sandbox test."""
        if not _IS_WIN32:
            success = False
            self.finished.emit(success, "Windows Sandbox is only available on Windows")
            return

        try:
            if self._launch_sandbox_test():
                return
            success = True
            self.finished.emit(success, "Windows Sandbox test completed successfully")

        except SubprocessError as e:
            _logger.exception(
                "sandbox_test_error",
                failure_reason="subprocess_error",
            )
            success = False
            self.finished.emit(success, f"Sandbox process error: {e}")
        except FileNotFoundError:
            _logger.exception(
                "sandbox_test_error",
                failure_reason="windows_sandbox_not_found",
            )
            success = False
            self.finished.emit(
                success,
                "WindowsSandbox.exe not found. Windows Sandbox may not be installed.",
            )
        except PermissionError:
            _logger.exception(
                "sandbox_test_error",
                failure_reason="permission_denied",
            )
            success = False
            self.finished.emit(
                success,
                "Permission denied. Administrator rights may be required.",
            )
        except OSError as e:
            _logger.exception(
                "sandbox_test_error",
                failure_reason="os_error",
            )
            success = False
            self.finished.emit(success, f"Failed to launch sandbox: {e}")
        finally:
            self._terminate_sandbox_process()
            if self._wsb_file and self._wsb_file.exists():
                try:
                    _logger.info("wsb_file_unlinking", path=str(self._wsb_file))
                    self._wsb_file.unlink()
                except OSError:
                    _logger.exception("wsb_file_unlink_error")

    def _log_wsb_written(self, wsb_content: str) -> None:
        """Log structured event for the freshly written ``.wsb`` file.

        Args:
            wsb_content: Generated XML configuration payload written to disk.
        """
        if self._wsb_file is None:
            return
        _logger.info(
            "sandbox_wsb_written",
            path=str(self._wsb_file),
            size=len(wsb_content),
        )

    def _register_test_process(self) -> None:
        """Register the launched sandbox process with the global ``ProcessManager``.

        Logs structured ``windows_sandbox_launched`` and ``sandbox_test_process_registered`` events so the audit trail captures both the
        process creation and the manager registration.
        """
        if self._process is None or self._wsb_file is None:
            return
        _logger.info("windows_sandbox_launched", pid=self._process.pid)
        process_manager = ProcessManager.get_instance()
        process_manager.register(
            self._process,
            name="sandbox-test",
            process_type=ProcessType.SANDBOX,
            metadata={"wsb_config": str(self._wsb_file)},
        )
        _logger.info(
            "sandbox_test_process_registered",
            pid=self._process.pid,
            wsb_config=str(self._wsb_file),
        )

    def _handle_sandbox_exit_status(self) -> bool:
        """Handle the sandbox process exit after a successful wait.

        Emits the ``finished`` signal with the captured stderr when the sandbox
        exited with a non-zero return code and logs the event for the
        structured audit trail.

        Returns:
            bool: ``True`` if the caller should return early (non-zero exit was
            reported); ``False`` if execution should continue.
        """
        if self._process is None or self._process.returncode == 0:
            return False
        stderr_output = self._process.stderr.read().decode("utf-8", errors="replace") if self._process.stderr else ""
        _logger.warning(
            "sandbox_test_nonzero_exit",
            returncode=self._process.returncode,
            stderr=stderr_output,
        )
        success = False
        self.finished.emit(success, f"Sandbox exited with error: {stderr_output}")
        return True

    def _generate_wsb_config(self) -> str:
        """Generate Windows Sandbox .wsb configuration XML.

        Returns:
            str: XML configuration string.
        """
        config_lines = ["<Configuration>", "  <VGpu>Enable</VGpu>"]

        if self._network_enabled:
            config_lines.append("  <Networking>Enable</Networking>")
        else:
            config_lines.append("  <Networking>Disable</Networking>")

        if self._memory_limit_mb > 0:
            config_lines.append(f"  <MemoryInMB>{self._memory_limit_mb}</MemoryInMB>")

        if self._shared_folder:
            shared_path = Path(self._shared_folder)
            if shared_path.exists():
                config_lines.extend((
                    "  <MappedFolders>",
                    "    <MappedFolder>",
                    f"      <HostFolder>{shared_path}</HostFolder>",
                    "      <SandboxFolder>C:\\Shared</SandboxFolder>",
                    f"      <ReadOnly>{'true' if self._read_only else 'false'}</ReadOnly>",
                    "    </MappedFolder>",
                    "  </MappedFolders>",
                ))
        config_lines.extend((
            "  <LogonCommand>",
            '    <Command>cmd.exe /c "echo Intellicrack Sandbox Test &amp;&amp; timeout /t 5"</Command>',
            "  </LogonCommand>",
            "</Configuration>",
        ))
        return "\n".join(config_lines)

    def _terminate_sandbox_process(self) -> None:
        """Stop the launched sandbox client, preferring a graceful window close.

        Posts ``WM_CLOSE`` to the sandbox client's top-level window first so
        Windows Sandbox can run its own teardown of the Host Compute Service
        session it owns instead of only ever being force-killed, which can
        leave that session orphaned and block a subsequent sandbox
        ``Create`` (S16-D11). Falls back to a forced process-tree
        termination when no window is found or the graceful close does not
        complete within :data:`_GRACEFUL_CLOSE_TIMEOUT_S`. Unconditionally
        unregisters the process from ``ProcessManager`` afterwards so no
        leaked tracking entry survives regardless of which path terminated
        it. No-op when no process was launched or it has already exited.
        """
        if self._process is None or self._process.poll() is not None:
            return
        pid = self._process.pid
        closed = False
        if _post_wm_close(pid):
            try:
                self._process.wait(timeout=_GRACEFUL_CLOSE_TIMEOUT_S)
                closed = True
                _logger.info("sandbox_test_graceful_close_ok", pid=pid)
            except TimeoutExpired:
                _logger.warning("sandbox_test_graceful_close_timeout", pid=pid)
        if not closed:
            try:
                ProcessManager.terminate_tree(pid, graceful_timeout=5.0, force_timeout=3.0)
                _logger.info("sandbox_test_process_terminated", pid=pid)
            except (OSError, TimeoutExpired):
                _logger.exception("sandbox_test_termination_error", pid=pid)
        ProcessManager.get_instance().unregister(pid)

    def stop(self) -> None:
        """Stop the sandbox test and terminate the process."""
        if self._process:
            pid = self._process.pid
            _logger.info("sandbox_test_stop_requested", pid=pid)
            self._terminate_sandbox_process()
            _logger.info("sandbox_test_stop_completed", pid=pid)


class SandboxConfigDialog(QDialog):
    """Dialog for configuring Windows Sandbox.

    Allows users to configure sandbox isolation settings, resource
    limits, network access, and shared folders.

    Attributes:
        settings_updated: Signal emitted when settings change.
        CONFIG_DIR: Path to the application configuration directory.
        CONFIG_FILE: Path to the sandbox JSON configuration file.
    """

    settings_updated: ClassVar[pyqtSignal] = pyqtSignal()

    CONFIG_DIR: ClassVar[Path] = get_config_dir()
    CONFIG_FILE: ClassVar[Path] = get_config_file("sandbox.json")

    def __init__(
        self,
        sandbox_manager: SandboxManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the SandboxConfigDialog with an optional sandbox manager.

        Args:
            sandbox_manager: Sandbox manager for creating and controlling sandbox instances.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = sandbox_manager
        self._is_available = False
        self._test_worker: SandboxTestWorker | None = None
        self._progress_dialog: QProgressDialog | None = None
        self._availability_worker: GenericCallableWorker | None = None

        self._setup_ui()
        self._start_availability_check()
        self._load_settings()

        self.setWindowTitle("Sandbox Settings")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)

        self._status_frame = QFrame()
        self._status_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        status_layout = QHBoxLayout(self._status_frame)

        self._status_icon = QLabel()
        status_layout.addWidget(self._status_icon)

        self._status_label = QLabel("Checking Windows Sandbox availability...")
        self._status_label.setWordWrap(True)
        self._status_label.setToolTip("Checking Windows Sandbox availability...")
        status_layout.addWidget(self._status_label, 1)

        layout.addWidget(self._status_frame)

        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable sandbox for binary execution")
        self._enabled_checkbox.setChecked(True)
        general_layout.addRow(self._enabled_checkbox)

        self._auto_cleanup_checkbox = QCheckBox("Auto-cleanup after execution")
        self._auto_cleanup_checkbox.setChecked(True)
        general_layout.addRow(self._auto_cleanup_checkbox)

        general_group.setLayout(general_layout)
        layout.addWidget(general_group)

        resources_group = QGroupBox("Resource Limits")
        resources_layout = QFormLayout()

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(30, 3600)
        self._timeout_spin.setValue(300)
        self._timeout_spin.setSuffix(" seconds")
        resources_layout.addRow("Execution Timeout:", self._timeout_spin)

        self._memory_spin = QSpinBox()
        self._memory_spin.setRange(512, 16384)
        self._memory_spin.setValue(2048)
        self._memory_spin.setSuffix(" MB")
        self._memory_spin.setSingleStep(256)
        resources_layout.addRow("Memory Limit:", self._memory_spin)

        resources_group.setLayout(resources_layout)
        layout.addWidget(resources_group)

        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()

        self._network_enabled_checkbox = QCheckBox("Enable networking in sandbox")
        self._network_enabled_checkbox.setChecked(False)
        self._network_enabled_checkbox.setToolTip("WARNING: Enabling networking allows sandbox to access external resources")
        network_layout.addRow(self._network_enabled_checkbox)

        self._block_telemetry_checkbox = QCheckBox("Block telemetry endpoints")
        self._block_telemetry_checkbox.setChecked(True)
        network_layout.addRow(self._block_telemetry_checkbox)

        network_group.setLayout(network_layout)
        layout.addWidget(network_group)

        folders_group = QGroupBox("Shared Folders")
        folders_layout = QVBoxLayout()

        folder_row = QHBoxLayout()
        self._shared_folder_input = QLineEdit()
        self._shared_folder_input.setReadOnly(True)
        folder_row.addWidget(self._shared_folder_input)

        self._browse_folder_btn = QPushButton("Browse...")
        self._browse_folder_btn.clicked.connect(self._browse_shared_folder)
        folder_row.addWidget(self._browse_folder_btn)

        folders_layout.addLayout(folder_row)

        self._read_only_checkbox = QCheckBox("Mount shared folder as read-only")
        self._read_only_checkbox.setChecked(False)
        folders_layout.addWidget(self._read_only_checkbox)

        folders_group.setLayout(folders_layout)
        layout.addWidget(folders_group)

        layout.addWidget(self._build_qemu_group())

        button_layout = QHBoxLayout()

        self._test_btn = QPushButton("Test Sandbox")
        self._test_btn.clicked.connect(self._test_sandbox)
        button_layout.addWidget(self._test_btn)

        button_layout.addStretch()

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply,
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        if apply_button := button_box.button(QDialogButtonBox.StandardButton.Apply):
            apply_button.clicked.connect(self._on_apply)

        button_layout.addWidget(button_box)

        layout.addLayout(button_layout)

    def _build_qemu_group(self) -> QGroupBox:
        """Build the QEMU backend settings group.

        These controls are intentionally kept outside
        :meth:`_set_controls_enabled`, which gates the Windows Sandbox
        controls on the Windows Sandbox availability probe. The QEMU backend
        is independent of that feature, so a host without Windows Sandbox must
        still be able to configure and use QEMU.

        Returns:
            QGroupBox: Group box holding the QEMU disk image, guest OS, CPU,
            memory, acceleration, and guest-agent timeout controls.
        """
        qemu_group = QGroupBox("QEMU Backend")
        qemu_layout = QFormLayout()

        image_row = QHBoxLayout()
        self._qemu_image_input = QLineEdit()
        self._qemu_image_input.setPlaceholderText("Path to a qcow2 disk image")
        self._qemu_image_input.setToolTip("QEMU cannot start without a bootable qcow2 disk image.")
        image_row.addWidget(self._qemu_image_input)

        self._qemu_browse_btn = QPushButton("Browse...")
        self._qemu_browse_btn.clicked.connect(self._browse_qemu_image)
        image_row.addWidget(self._qemu_browse_btn)

        qemu_layout.addRow("Disk Image:", image_row)

        self._qemu_guest_os_combo = QComboBox()
        for guest_os in GuestOS:
            self._qemu_guest_os_combo.addItem(guest_os.value.capitalize(), guest_os.value)
        qemu_layout.addRow("Guest OS:", self._qemu_guest_os_combo)

        self._qemu_cpu_spin = QSpinBox()
        self._qemu_cpu_spin.setRange(QEMU_MIN_CPU_CORES, QEMU_MAX_CPU_CORES)
        self._qemu_cpu_spin.setValue(QEMU_DEFAULT_CPU_CORES)
        qemu_layout.addRow("CPU Cores:", self._qemu_cpu_spin)

        self._qemu_memory_spin = QSpinBox()
        self._qemu_memory_spin.setRange(QEMU_MIN_MEMORY_MB, QEMU_MAX_MEMORY_MB)
        self._qemu_memory_spin.setValue(QEMU_DEFAULT_MEMORY_MB)
        self._qemu_memory_spin.setSuffix(" MB")
        self._qemu_memory_spin.setSingleStep(256)
        qemu_layout.addRow("Guest Memory:", self._qemu_memory_spin)

        self._qemu_accel_checkbox = QCheckBox("Use hardware acceleration when available")
        self._qemu_accel_checkbox.setChecked(True)
        qemu_layout.addRow(self._qemu_accel_checkbox)

        self._qemu_agent_timeout_spin = QSpinBox()
        self._qemu_agent_timeout_spin.setRange(int(QEMU_MIN_AGENT_TIMEOUT), int(QEMU_MAX_AGENT_TIMEOUT))
        self._qemu_agent_timeout_spin.setValue(int(QEMU_DEFAULT_AGENT_TIMEOUT))
        self._qemu_agent_timeout_spin.setSuffix(" seconds")
        qemu_layout.addRow("Guest Agent Timeout:", self._qemu_agent_timeout_spin)

        qemu_group.setLayout(qemu_layout)
        return qemu_group

    def _browse_qemu_image(self) -> None:
        """Open a file browser for the QEMU disk image."""
        _logger.debug("qemu_image_browse_opened")
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select QEMU Disk Image",
            self._qemu_image_input.text(),
            "QEMU disk images (*.qcow2 *.qcow *.img *.raw);;All files (*)",
        )
        if path:
            _logger.debug("qemu_image_browse_selected", path=path)
            self._qemu_image_input.setText(path)

    def _apply_qemu_settings(self, settings: Mapping[str, object]) -> None:
        """Apply persisted QEMU settings to the QEMU widgets.

        Args:
            settings: Parsed sandbox settings document.
        """
        qemu_config = build_qemu_config(settings)

        self._qemu_image_input.setText(str(qemu_config.image_path) if qemu_config.image_path else "")
        guest_index = self._qemu_guest_os_combo.findData(qemu_config.guest_os.value)
        if guest_index >= 0:
            self._qemu_guest_os_combo.setCurrentIndex(guest_index)
        self._qemu_cpu_spin.setValue(qemu_config.cpu_cores)
        self._qemu_memory_spin.setValue(qemu_config.memory_mb)
        self._qemu_accel_checkbox.setChecked(qemu_config.enable_acceleration)
        self._qemu_agent_timeout_spin.setValue(int(qemu_config.agent_connect_timeout))

    def _selected_qemu_guest_os(self) -> str:
        """Return the guest OS identifier selected in the QEMU group.

        Returns:
            str: Guest OS value such as ``"linux"`` or ``"windows"``.
        """
        data = self._qemu_guest_os_combo.currentData()
        if isinstance(data, str):
            return data
        return QEMU_DEFAULT_GUEST_OS.value

    def _start_availability_check(self) -> None:
        """Probe Windows Sandbox availability off the GUI thread and update status.

        Dispatches the (potentially subprocess-spawning) probe to a background :class:`GenericCallableWorker` so the dialog constructor
        never blocks the Qt main thread. The status widgets are refreshed on the GUI thread via :meth:`_on_availability_checked` once the
        worker completes, so the dialog still shows an accurate result when it is actually opened.
        """
        _logger.debug("sandbox_availability_check_started")
        worker = GenericCallableWorker(
            check_windows_sandbox_availability,
            exceptions=WORKER_DEFAULT_EXCEPTIONS,
            parent=self,
        )
        self._availability_worker = worker
        _ = worker.call_finished.connect(self._on_availability_checked)
        _ = worker.call_error.connect(self._on_availability_error)
        worker.start()

    @staticmethod
    def _coerce_availability_result(result: object) -> tuple[bool, str]:
        """Normalise a probe worker payload into an ``(available, reason)`` pair.

        Args:
            result: Value emitted by the availability worker; expected to be a
                two-element ``(available, reason)`` tuple.

        Returns:
            tuple[bool, str]: Coerced availability flag and reason string, with a
            safe fallback when the payload does not match the expected shape.
        """
        if isinstance(result, tuple):
            typed = cast("tuple[object, ...]", result)
            if len(typed) == _AVAILABILITY_RESULT_LEN:
                return bool(typed[0]), str(typed[1])
        return False, "Could not determine Windows Sandbox status"

    def _on_availability_checked(self, result: object) -> None:
        """Apply an availability probe result to the dialog status widgets.

        Args:
            result: ``(available, reason)`` tuple emitted by the probe worker.
        """
        self._availability_worker = None
        available, reason = self._coerce_availability_result(result)
        if available:
            self._set_available()
        else:
            self._set_unavailable(reason)

    def _on_availability_error(self, exc: object) -> None:
        """Handle an unexpected failure of the availability probe worker.

        Args:
            exc: Exception object emitted by the worker.
        """
        self._availability_worker = None
        _logger.warning("sandbox_availability_check_error", error=str(exc))
        self._set_unavailable("Could not determine Windows Sandbox status")

    def _set_available(self) -> None:
        """Update UI for sandbox available state."""
        self._is_available = True
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
        self._status_label.setText("Windows Sandbox is available")
        self._status_label.setToolTip("Windows Sandbox is available")
        self._status_label.setProperty("status", "success")
        style = self._status_label.style()
        if style is not None:
            style.unpolish(self._status_label)
            style.polish(self._status_label)
        self._status_frame.setProperty("toolResult", "success")
        frame_style = self._status_frame.style()
        if frame_style is not None:
            frame_style.unpolish(self._status_frame)
            frame_style.polish(self._status_frame)
        self._set_controls_enabled(enabled=True)

    def _set_unavailable(self, reason: str) -> None:
        """Update UI for sandbox unavailable state.

        Args:
            reason: Reason sandbox is unavailable.
        """
        self._is_available = False
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
        unavailable_text = f"Windows Sandbox unavailable: {reason}"
        self._status_label.setText(unavailable_text)
        self._status_label.setToolTip(unavailable_text)
        self._status_label.setProperty("status", "error")
        style = self._status_label.style()
        if style is not None:
            style.unpolish(self._status_label)
            style.polish(self._status_label)
        self._status_frame.setProperty("toolResult", "error")
        frame_style = self._status_frame.style()
        if frame_style is not None:
            frame_style.unpolish(self._status_frame)
            frame_style.polish(self._status_frame)
        self._set_controls_enabled(enabled=False)

    def _set_controls_enabled(self, *, enabled: bool) -> None:
        """Enable or disable all configuration controls.

        Args:
            enabled: Whether controls should be enabled.
        """
        self._enabled_checkbox.setEnabled(enabled)
        self._auto_cleanup_checkbox.setEnabled(enabled)
        self._timeout_spin.setEnabled(enabled)
        self._memory_spin.setEnabled(enabled)
        self._network_enabled_checkbox.setEnabled(enabled)
        self._block_telemetry_checkbox.setEnabled(enabled)
        self._browse_folder_btn.setEnabled(enabled)
        self._read_only_checkbox.setEnabled(enabled)
        self._test_btn.setEnabled(enabled)

    def _apply_settings_from_config(self, default_shared: Path) -> None:
        """Load sandbox settings JSON from ``CONFIG_FILE`` and apply them to widgets.

        Args:
            default_shared: Default shared-folder path used when the saved
                config omits the ``shared_folder`` key.
        """
        with self.CONFIG_FILE.open(encoding="utf-8") as f:
            settings = json.load(f)

        self._enabled_checkbox.setChecked(settings.get("enabled", True))
        self._auto_cleanup_checkbox.setChecked(settings.get("auto_cleanup", True))
        self._timeout_spin.setValue(settings.get("timeout_seconds", 300))
        self._memory_spin.setValue(settings.get("memory_limit_mb", 2048))
        self._network_enabled_checkbox.setChecked(settings.get("network_enabled", False))
        self._block_telemetry_checkbox.setChecked(settings.get("block_telemetry", True))
        self._shared_folder_input.setText(settings.get("shared_folder", str(default_shared)))
        self._read_only_checkbox.setChecked(settings.get("shared_folder_read_only", False))
        self._apply_qemu_settings(settings)

        _logger.info(
            "sandbox_config_loaded",
            config_file=str(self.CONFIG_FILE),
            settings_count=len(settings),
        )

    def _load_settings(self) -> None:
        """Load settings from config file."""
        default_shared = get_project_root() / "sandbox_shared"

        _logger.debug(
            "sandbox_config_load_started",
            config_file=str(self.CONFIG_FILE),
        )
        if self.CONFIG_FILE.exists():
            try:
                self._apply_settings_from_config(default_shared)
            except (json.JSONDecodeError, OSError):
                _logger.exception(
                    "sandbox_config_error",
                    operation="load",
                    config_file=str(self.CONFIG_FILE),
                )
                self._shared_folder_input.setText(str(default_shared))
        else:
            _logger.info(
                "sandbox_config_load_defaulted",
                config_file=str(self.CONFIG_FILE),
                reason="file_missing",
            )
            self._shared_folder_input.setText(str(default_shared))

    def _browse_shared_folder(self) -> None:
        """Open folder browser for shared folder."""
        _logger.debug("sandbox_shared_folder_browse_opened")
        if path := QFileDialog.getExistingDirectory(
            self,
            "Select Shared Folder",
            self._shared_folder_input.text(),
        ):
            _logger.debug("sandbox_shared_folder_browse_selected", path=path)
            self._shared_folder_input.setText(path)

    def _test_sandbox(self) -> None:
        """Test sandbox by launching a simple instance."""
        if not self._is_available:
            show_warning(
                self,
                "Sandbox Unavailable",
                "Windows Sandbox is not available on this system.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Test Sandbox",
            "This will launch Windows Sandbox to verify it's working.\n\nThe sandbox will open briefly for testing.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        self._test_btn.setEnabled(False)
        self._test_btn.setText("Testing...")

        self._progress_dialog = QProgressDialog(
            "Testing Windows Sandbox...",
            "Cancel",
            0,
            0,
            self,
        )
        self._progress_dialog.setWindowTitle("Sandbox Test")
        self._progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress_dialog.setMinimumDuration(0)
        self._progress_dialog.canceled.connect(self._cancel_test)

        self._test_worker = SandboxTestWorker(
            network_enabled=self._network_enabled_checkbox.isChecked(),
            memory_limit_mb=self._memory_spin.value(),
            shared_folder=self._shared_folder_input.text(),
            read_only=self._read_only_checkbox.isChecked(),
            parent=self,
        )

        def _test_finished_slot(s: int, m: str) -> None:
            """Coerce sandbox test worker ints into the finished-handler bool/message pair.

            Args:
                s: Worker success flag; nonzero means the sandbox test succeeded.
                m: Status or error text emitted by the sandbox test worker.
            """
            self._on_test_finished(success=bool(s), message=m)

        self._test_worker.finished.connect(_test_finished_slot)
        self._test_worker.output.connect(self._on_test_output)
        _logger.info(
            "sandbox_test_started",
            network_enabled=self._network_enabled_checkbox.isChecked(),
            memory_limit_mb=self._memory_spin.value(),
            shared_folder=self._shared_folder_input.text(),
        )
        self._test_worker.start()

    def _cancel_test(self) -> None:
        """Cancel the sandbox test."""
        if self._test_worker and self._test_worker.isRunning():
            _logger.info("sandbox_test_cancelled")
            self._test_worker.stop()
            self._test_worker.wait(5000)
            self._test_btn.setEnabled(True)
            self._test_btn.setText("Test Sandbox")

    def _on_test_output(self, message: str) -> None:
        """Handle test output messages.

        Args:
            message: Output message from the test worker.
        """
        if self._progress_dialog:
            self._progress_dialog.setLabelText(message)

    def _on_test_finished(self, *, success: bool, message: str) -> None:
        """Handle test completion.

        Args:
            success: Whether the test succeeded.
            message: Result message.
        """
        self._test_btn.setEnabled(True)
        self._test_btn.setText("Test Sandbox")

        if self._progress_dialog:
            self._progress_dialog.close()
            self._progress_dialog = None

        if success:
            show_info(
                self,
                "Test Complete",
                f"Sandbox test passed!\n\n{message}",
            )
        else:
            show_warning(
                self,
                "Test Failed",
                f"Sandbox test failed:\n\n{message}",
            )

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        _logger.info("sandbox_config_dialog_accepted")
        self._save_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        _logger.info("sandbox_config_dialog_apply")
        self._save_settings()

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Cancel any in-flight sandbox test before the dialog closes.

        Args:
            a0: The close event.
        """
        self._cancel_test()
        super().closeEvent(a0)

    @override
    def reject(self) -> None:
        """Cancel any in-flight sandbox test before rejecting the dialog."""
        self._cancel_test()
        super().reject()

    def _save_settings(self) -> None:
        """Save current settings to config file and apply to the sandbox manager."""
        _logger.debug(
            "sandbox_config_dir_ensuring",
            config_dir=str(self.CONFIG_DIR),
        )
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        settings = self.get_settings()

        try:
            with self.CONFIG_FILE.open("w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)

            self._ensure_shared_folder(Path(str(settings["shared_folder"])))

            _logger.info(
                "sandbox_config_saved",
                config_file=str(self.CONFIG_FILE),
                settings_count=len(settings),
            )

        except OSError as e:
            _logger.exception(
                "sandbox_config_error",
                operation="save",
                config_file=str(self.CONFIG_FILE),
            )
            show_warning(
                self,
                "Save Error",
                f"Failed to save sandbox settings:\n{e}",
            )
            return

        new_config = self._build_sandbox_config()
        self._apply_config_to_manager(new_config)
        self.settings_updated.emit()

    @staticmethod
    def _ensure_shared_folder(shared_folder: Path) -> None:
        """Create the shared folder if it does not already exist.

        Logs a ``sandbox_shared_folder_creating`` debug event before attempting
        to create the directory. Failures are logged at debug level because
        the sandbox can still launch without a host-side mapped folder.

        Args:
            shared_folder: Filesystem path requested as the sandbox shared
                folder.
        """
        if shared_folder.exists():
            return
        _logger.debug("sandbox_shared_folder_creating", path=str(shared_folder))
        try:
            shared_folder.mkdir(parents=True, exist_ok=True)
        except OSError:
            _logger.debug("shared_folder_create_failed", exc_info=True)

    def _build_sandbox_config(self) -> SandboxConfig:
        """Construct a SandboxConfig dataclass from the dialog's widget state.

        Returns:
            SandboxConfig: Backend-ready configuration object.
        """
        shared_folder_str = self._shared_folder_input.text()
        read_only = self._read_only_checkbox.isChecked()
        shared_folders: list[tuple[Path, str, bool]] = []
        if shared_folder_str:
            shared_folders.append((Path(shared_folder_str), "C:\\Shared", read_only))

        return SandboxConfig(
            timeout_seconds=self._timeout_spin.value(),
            memory_limit_mb=self._memory_spin.value(),
            network_enabled=self._network_enabled_checkbox.isChecked(),
            shared_folders=shared_folders,
        )

    def _apply_config_to_manager(self, new_config: SandboxConfig) -> None:
        """Apply the new configuration to the sandbox manager.

        Invokes ``update_default_config`` or ``load_from_file`` via introspection when
        the back-end exposes them. When neither is available, executes the documented
        fallback: tear down running sandboxes whose live configuration no longer matches
        the newly supplied one and mutate the manager's internal default configuration
        so subsequent sandbox creations use the new settings.

        Args:
            new_config: The SandboxConfig built from the dialog state.
        """
        manager = self._manager
        _logger.info(
            "sandbox_config_apply_started",
            manager_attached=manager is not None,
            timeout_seconds=new_config.timeout_seconds,
            memory_limit_mb=new_config.memory_limit_mb,
            network_enabled=new_config.network_enabled,
        )
        if manager is None:
            _logger.debug(
                "sandbox_manager_not_attached",
                timeout_seconds=new_config.timeout_seconds,
                memory_limit_mb=new_config.memory_limit_mb,
                network_enabled=new_config.network_enabled,
            )
            return

        if self._invoke_backend_method(manager, "update_default_config", new_config):
            return

        if self._invoke_backend_method(manager, "load_from_file", self.CONFIG_FILE):
            return

        self._fallback_rebuild_manager(manager, new_config)

    @staticmethod
    def _invoke_backend_method(manager: SandboxManager, method_name: str, argument: object) -> bool:
        """Invoke a sandbox-manager backend method if it exists on the manager.

        Uses :func:`inspect.signature` to decide whether the method expects the
        supplied argument or takes no parameters, and routes coroutine return
        values through :func:`run_bridge_coroutine`.

        Args:
            manager: The active sandbox manager.
            method_name: The attribute name to resolve on the manager.
            argument: Positional argument passed when the method's signature
                advertises one or more parameters.

        Returns:
            bool: ``True`` if the method was resolved and invoked successfully,
                ``False`` otherwise.
        """
        raw_method: object = getattr(manager, method_name, None)
        if not callable(raw_method):
            return False

        try:
            signature = inspect.signature(raw_method)
        except (TypeError, ValueError):
            _logger.debug("backend_method_signature_unavailable", method=method_name, exc_info=True)
            signature = None

        try:
            result: object = raw_method() if signature is not None and len(signature.parameters) == 0 else raw_method(argument)
            if inspect.iscoroutine(result):
                run_bridge_coroutine(result)
        except (RuntimeError, TypeError, ValueError, OSError) as exc:
            _logger.warning("backend_method_invocation_failed", method=method_name, error=str(exc))
            return False

        _logger.info("sandbox_manager_config_updated_via_backend", method=method_name)
        return True

    @staticmethod
    def _fallback_rebuild_manager(manager: SandboxManager, new_config: SandboxConfig) -> None:
        """Tear down mismatched sandboxes and swap the manager's default config.

        Iterates every managed sandbox instance, compares the live sandbox's
        ``config`` against ``new_config``, and destroys instances whose
        configuration no longer matches. Afterwards, overwrites the manager's
        private ``_default_config`` so subsequent ``create()`` calls pick up the
        new settings.

        Args:
            manager: The active sandbox manager.
            new_config: The SandboxConfig to apply as the new default.
        """
        destroyed_ids: list[str] = []
        skipped_ids: list[str] = []

        for instance in list(manager.instances):
            if instance.sandbox.config == new_config:
                skipped_ids.append(instance.id)
                continue

            try:
                run_bridge_coroutine(manager.destroy(instance.id))
                destroyed_ids.append(instance.id)
            except (RuntimeError, OSError) as exc:
                _logger.warning(
                    "sandbox_rebuild_destroy_failed",
                    instance_id=instance.id,
                    error=str(exc),
                )

        setattr(manager, _DEFAULT_CONFIG_ATTR, new_config)

        _logger.info(
            "sandbox_manager_rebuilt_fallback",
            destroyed_count=len(destroyed_ids),
            kept_count=len(skipped_ids),
            timeout_seconds=new_config.timeout_seconds,
            memory_limit_mb=new_config.memory_limit_mb,
            network_enabled=new_config.network_enabled,
        )

    def get_settings(self) -> dict[str, object]:
        """Get current settings as a dictionary.

        Returns:
            dict[str, object]: Dictionary of current settings.
        """
        return {
            "enabled": self._enabled_checkbox.isChecked(),
            "auto_cleanup": self._auto_cleanup_checkbox.isChecked(),
            "timeout_seconds": self._timeout_spin.value(),
            "memory_limit_mb": self._memory_spin.value(),
            "network_enabled": self._network_enabled_checkbox.isChecked(),
            "block_telemetry": self._block_telemetry_checkbox.isChecked(),
            "shared_folder": self._shared_folder_input.text(),
            "shared_folder_read_only": self._read_only_checkbox.isChecked(),
            QEMU_IMAGE_PATH_KEY: self._qemu_image_input.text(),
            QEMU_GUEST_OS_KEY: self._selected_qemu_guest_os(),
            QEMU_CPU_CORES_KEY: self._qemu_cpu_spin.value(),
            QEMU_MEMORY_MB_KEY: self._qemu_memory_spin.value(),
            QEMU_ACCELERATION_KEY: self._qemu_accel_checkbox.isChecked(),
            QEMU_AGENT_TIMEOUT_KEY: float(self._qemu_agent_timeout_spin.value()),
        }

    def is_sandbox_available(self) -> bool:
        """Check if sandbox is available.

        Returns:
            bool: True if sandbox is available.
        """
        return self._is_available


class SandboxMonitorWidget(QFrame):
    """Widget for monitoring active sandbox sessions.

    Displays information about running sandbox instances and
    allows control over them.

    Attributes:
        sandbox_stopped: Signal emitted when sandbox is stopped.
    """

    sandbox_stopped: ClassVar[pyqtSignal] = pyqtSignal()

    def __init__(
        self,
        sandbox_manager: SandboxManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the SandboxMonitorWidget with an optional sandbox manager.

        Args:
            sandbox_manager: Sandbox manager instance for monitoring.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = sandbox_manager
        self._sandbox_pid: int | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()

        title = QLabel("<b>Sandbox Monitor</b>")
        header_layout.addWidget(title)

        header_layout.addStretch()

        icon_manager = IconManager.get_instance()
        self.status_indicator = QLabel()
        self.status_indicator.setPixmap(icon_manager.get_pixmap("status_idle", 16))
        self.status_indicator.setFixedSize(20, 20)
        header_layout.addWidget(self.status_indicator)

        self._status_text = QLabel("No active sandbox")
        self._status_text.setObjectName("status_text")
        header_layout.addWidget(self._status_text)

        layout.addLayout(header_layout)

        self._output_text = QTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(_OUTPUT_MAX_HEIGHT)
        self._output_text.setObjectName("sandbox_output")
        layout.addWidget(self._output_text)

        control_layout = QHBoxLayout()

        self._stop_btn = QPushButton("Stop Sandbox")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_sandbox)
        control_layout.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear Output")
        self._clear_btn.clicked.connect(self._output_text.clear)
        control_layout.addWidget(self._clear_btn)

        control_layout.addStretch()

        layout.addLayout(control_layout)

    def set_running(self, *, is_running: bool, binary_name: str = "", pid: int | None = None) -> None:
        """Update the running state display.

        Args:
            is_running: Whether sandbox is currently running.
            binary_name: Name of binary being executed.
            pid: Process ID of the sandbox.
        """
        _logger.info(
            "sandbox_monitor_running_state",
            is_running=is_running,
            binary=binary_name,
            pid=pid,
        )
        self._sandbox_pid = pid if is_running else None
        icon_manager = IconManager.get_instance()

        if is_running:
            self.status_indicator.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_text.setText(f"Running: {binary_name}")
            self._stop_btn.setEnabled(True)
        else:
            self.status_indicator.setPixmap(icon_manager.get_pixmap("status_idle", 16))
            self._status_text.setText("No active sandbox")
            self._stop_btn.setEnabled(False)

    def append_output(self, text: str) -> None:
        """Append text to the output display.

        Args:
            text: Text to append.
        """
        self._output_text.append(text)

    def _stop_sandbox(self) -> None:
        """Stop the running sandbox without blocking the GUI thread.

        Disables the stop button immediately to prevent a second dispatch while the (async or worker-thread) teardown is in flight. The
        running indicator is cleared and :attr:`sandbox_stopped` is emitted only once the dispatched teardown actually completes, via
        :meth:`_finish_stop_sandbox`.
        """
        self._stop_btn.setEnabled(False)
        if self._manager is not None:
            self._stop_via_manager()
        elif self._sandbox_pid is not None:
            self._stop_via_pid(self._sandbox_pid)
        else:
            self._terminate_sandbox_by_name()

    def _finish_stop_sandbox(self) -> None:
        """Clear the running indicator and notify listeners that the sandbox stopped."""
        self.set_running(is_running=False)
        self.sandbox_stopped.emit()

    def _stop_via_manager(self) -> None:
        """Stop the sandbox by delegating to the attached ``SandboxManager``.

        Dispatches :meth:`SandboxManager.destroy_all` to the persistent
        background bridge event loop via :func:`run_bridge_coroutine_async`
        so the GUI thread never blocks on VM/container teardown latency.
        Completion is handled on the GUI thread by
        :meth:`_on_manager_stop_succeeded` / :meth:`_on_manager_stop_failed`.
        """
        if self._manager is None:
            self._finish_stop_sandbox()
            return
        _logger.info("sandbox_stop_started", method="manager")
        run_bridge_coroutine_async(
            self._manager.destroy_all(),
            self._on_manager_stop_succeeded,
            self._on_manager_stop_failed,
            self,
        )

    def _on_manager_stop_succeeded(self, _result: object) -> None:
        """Handle successful completion of a manager-based sandbox stop.

        Args:
            _result: Unused return value from ``SandboxManager.destroy_all``.
        """
        _logger.info("sandbox_stop_completed", method="manager")
        self.append_output("[Sandbox stopped via manager]")
        self._finish_stop_sandbox()

    def _on_manager_stop_failed(self, exc: object) -> None:
        """Handle a failure raised while stopping the sandbox via the manager.

        Args:
            exc: Exception raised by ``SandboxManager.destroy_all``.
        """
        _logger.warning("sandbox_stop_error", method="manager", error=str(exc))
        self.append_output(f"[Error stopping sandbox: {exc}]")
        self._finish_stop_sandbox()

    def _stop_via_pid(self, pid: int) -> None:
        """Stop the sandbox by terminating the registered process by PID.

        On Windows this dispatches ``taskkill /F /PID`` to a background
        worker thread via :class:`GenericCallableWorker` so the bounded
        (10 second) ``taskkill`` subprocess never blocks the GUI thread. On
        other platforms it sends ``SIGKILL`` via :func:`os.kill`, which is a
        non-blocking signal delivery and does not need dispatch.

        Args:
            pid: Process identifier of the running sandbox process.
        """
        _logger.info("sandbox_stop_started", method="pid_kill", pid=pid)
        if not _IS_WIN32:
            try:
                os.kill(pid, 9)
            except OSError as e:
                _logger.exception("sandbox_stop_error", method="pid_kill", pid=pid)
                self.append_output(f"[Error terminating sandbox: {e}]")
                self._finish_stop_sandbox()
                return
            _logger.info("sandbox_stop_completed", method="pid_kill", pid=pid)
            self.append_output(f"[Sandbox process {pid} killed]")
            self._finish_stop_sandbox()
            return

        process_manager = ProcessManager.get_instance()
        worker = GenericCallableWorker(
            process_manager.run_tracked,
            ["taskkill", "/F", "/PID", str(pid)],
            name="taskkill-sandbox-pid",
            check=False,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
            exceptions=(*WORKER_DEFAULT_EXCEPTIONS, TimeoutExpired),
            parent=self,
        )

        def _pid_kill_finished_slot(_result: object) -> None:
            """Continue stop-sandbox cleanup after PID ``taskkill`` completes.

            Args:
                _result: Unused success payload from the PID kill worker.
            """
            self._on_pid_kill_succeeded(pid)

        def _pid_kill_error_slot(exc: object) -> None:
            """Report stop-sandbox failure when PID ``taskkill`` cannot terminate.

            Args:
                exc: Error from the worker that ran ``taskkill`` against ``pid``.
            """
            self._on_pid_kill_failed(pid, exc)

        _ = worker.call_finished.connect(_pid_kill_finished_slot)
        _ = worker.call_error.connect(_pid_kill_error_slot)
        worker.start()

    def _on_pid_kill_succeeded(self, pid: int) -> None:
        """Handle successful completion of a PID-based ``taskkill``.

        Args:
            pid: Process identifier that was terminated.
        """
        _logger.info("sandbox_stop_completed", method="pid_kill", pid=pid)
        self.append_output(f"[Sandbox process {pid} terminated]")
        self._finish_stop_sandbox()

    def _on_pid_kill_failed(self, pid: int, exc: object) -> None:
        """Handle a failure raised while terminating the sandbox by PID.

        Args:
            pid: Process identifier that was targeted for termination.
            exc: Exception raised by the ``taskkill`` worker.
        """
        _logger.warning("sandbox_stop_error", method="pid_kill", pid=pid, error=str(exc))
        self.append_output(f"[Error terminating sandbox: {exc}]")
        self._finish_stop_sandbox()

    def _terminate_sandbox_by_name(self) -> None:
        """Terminate Windows Sandbox by process name without blocking the GUI thread.

        Dispatches ``taskkill /F /IM WindowsSandbox.exe`` to a background worker thread via :class:`GenericCallableWorker` so the bounded
        (10 second) subprocess call never blocks the GUI thread.
        """
        if not _IS_WIN32:
            self.append_output("[Cannot terminate sandbox on non-Windows platform]")
            self._finish_stop_sandbox()
            return

        _logger.info("sandbox_terminate_by_name_started")
        process_manager = ProcessManager.get_instance()
        worker = GenericCallableWorker(
            process_manager.run_tracked,
            ["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
            name="taskkill-sandbox-name",
            check=False,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
            exceptions=(*WORKER_DEFAULT_EXCEPTIONS, TimeoutExpired),
            parent=self,
        )
        _ = worker.call_finished.connect(self._on_name_kill_succeeded)
        _ = worker.call_error.connect(self._on_name_kill_failed)
        worker.start()

    def _on_name_kill_succeeded(self, result: object) -> None:
        """Handle successful completion of the name-based ``taskkill``.

        Args:
            result: ``CompletedProcess`` emitted by the ``taskkill`` worker.
        """
        returncode = result.returncode if isinstance(result, CompletedProcess) else 1
        self._report_taskkill_result(returncode)
        self._finish_stop_sandbox()

    def _on_name_kill_failed(self, exc: object) -> None:
        """Handle a failure raised while terminating the sandbox by name.

        Args:
            exc: Exception raised by the ``taskkill`` worker.
        """
        _logger.warning("sandbox_stop_error", method="name_kill", error=str(exc))
        self.append_output(f"[Error: {exc}]")
        self._finish_stop_sandbox()

    def _report_taskkill_result(self, returncode: int) -> None:
        """Surface the outcome of the name-based taskkill in the output panel.

        Args:
            returncode: Exit code captured from the ``taskkill`` invocation.
        """
        if returncode == 0:
            _logger.info("sandbox_terminate_by_name_completed", outcome="terminated")
            self.append_output("[Windows Sandbox terminated]")
            return
        _logger.info(
            "sandbox_terminate_by_name_completed",
            outcome="no_process_found",
            returncode=returncode,
        )
        self.append_output("[No Windows Sandbox process found]")
