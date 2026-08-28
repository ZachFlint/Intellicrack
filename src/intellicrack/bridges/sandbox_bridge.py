# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox bridge for isolated binary execution environments.

This module provides a tool bridge that wraps the SandboxManager to expose sandbox operations to the AI orchestrator.
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import yaml

from intellicrack.bridges.base import BridgeCapabilities, BridgeState, ToolBridgeBase
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.sandbox import (
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxInstance,
    SandboxManager,
    SandboxType,
)


if TYPE_CHECKING:
    import types
    from collections.abc import Callable
    from types import TracebackType

    from intellicrack.sandbox import ExecutionReport, QEMUConfig


_logger = get_logger(__name__)


@functools.lru_cache(maxsize=1)
def _get_analysis_module() -> types.ModuleType:
    """Return the cached sandbox analysis module, importing it on first call.

    Returns:
        types.ModuleType: The ``intellicrack.sandbox.analysis`` module.
    """
    return importlib.import_module("intellicrack.sandbox.analysis")


_ERR_CREATE_FAILED = "Failed to create sandbox"
_ERR_DESTROY_FAILED = "Failed to destroy sandbox"
_ERR_RESTART_FAILED = "Failed to restart sandbox"
_ERR_BINARY_NOT_FOUND = "Binary not found"
_ERR_EXECUTION_FAILED = "Binary execution failed"
_ERR_INSTANCE_NOT_FOUND = "Sandbox instance not found"
_ERR_CMD_EXEC_FAILED = "Command execution failed"
_ERR_SRC_NOT_FOUND = "Source file not found"
_ERR_COPY_TO_FAILED = "Copy to sandbox failed"
_ERR_COPY_FROM_FAILED = "Copy from sandbox failed"
_ERR_QEMU_ONLY = "Snapshots only supported for QEMU sandboxes"
_ERR_QEMU_REQUIRED = "Operation requires QEMU sandbox"
_ERR_SNAPSHOT_CREATE_FAILED = "Snapshot creation failed"
_ERR_SNAPSHOT_RESTORE_FAILED = "Snapshot restore failed"
_ERR_SNAPSHOT_LIST_FAILED = "Snapshot listing failed"
_ERR_SNAPSHOT_DELETE_FAILED = "Snapshot deletion failed"
_ERR_CONT_FAILED = "Failed to resume VM execution"
_ERR_MESSAGES_FAILED = "Failed to retrieve pending messages"
_ERR_PCAP_START_FAILED = "Failed to start PCAP capture"
_ERR_PCAP_STOP_FAILED = "Failed to stop PCAP capture"
_ERR_SCREENSHOT_FAILED = "Failed to capture screenshot"
_ERR_ANTI_EVASION_FAILED = "Failed to apply anti-evasion"
_ERR_MEMORY_DUMP_FAILED = "Failed to dump guest memory"
_ERR_LIST_PROCESSES_FAILED = "Failed to list guest processes"
_ERR_WINDOWS_REQUIRED = "Operation requires Windows Sandbox"
_ERR_EXTRACT_FILES_FAILED = "Failed to extract dropped files"
_ERR_YARA_SCAN_FAILED = "Failed to run YARA scan"
_ERR_YARA_INVALID_MODE = "Invalid scan_target; must be 'files' or 'memory'"
_ERR_NO_REPORT = "No execution report available for this instance"
_ERR_IOC_EXTRACT_FAILED = "Failed to extract IOCs"
_ERR_TIMELINE_FAILED = "Failed to generate timeline"
_ERR_BEHAVIOR_FAILED = "Failed to detect behaviors"
_ERR_C2_DETECT_FAILED = "Failed to detect C2 patterns"
_ERR_DIFF_FAILED = "Failed to diff reports"
_ERR_INVALID_SANDBOX_TYPE = "Invalid sandbox_type"
_ERR_MANAGER_DESTROYED = "manager was shut down; call create() to recreate"
_ERR_RULES_NOT_FOUND = "Custom rules file not found"
_ERR_RULES_INVALID = "Custom rules file is not valid YAML or has wrong shape"
_ERR_VNC_PORT_UNAVAILABLE = "VNC port is not allocated on this QEMU sandbox"
_ERR_STOP_PCAP_FAILED = "Failed to stop active PCAP capture during cleanup"

_VALID_SANDBOX_TYPES: frozenset[str] = frozenset({"windows", "qemu"})
_VALID_YARA_MODES: frozenset[str] = frozenset({"files", "memory"})


def json_safe(value: object) -> object:
    """Recursively convert a value to a JSON-serialisable form.

    Converts ``datetime`` instances to UTC ISO-8601 strings, ``Path``
    instances to POSIX strings, and recurses into ``dict``/``list``.
    All other types are returned unchanged.

    Args:
        value: The value to convert.

    Returns:
        object: A JSON-serialisable representation of ``value``.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        d = cast("dict[object, object]", value)
        return {k: json_safe(v) for k, v in d.items()}
    if isinstance(value, list):
        lst = cast("list[object]", value)
        return [json_safe(item) for item in lst]
    return value


def dataclass_to_dict(obj: object) -> dict[str, Any]:
    """Convert a dataclass instance to a JSON-serialisable dictionary.

    Uses ``dataclasses.asdict`` for the conversion and then applies
    :func:`json_safe` to convert ``datetime`` and ``Path`` values to
    strings.  A ``json.dumps`` round-trip is verified before returning.

    Args:
        obj: A dataclass instance to convert.

    Returns:
        dict[str, Any]: JSON-safe dictionary representation of ``obj``.

    Raises:
        ToolError: If the object is not a dataclass or the result is not
            JSON-serialisable.
    """
    if not dataclasses.is_dataclass(obj) or isinstance(obj, type):
        msg = f"Expected a dataclass instance, got {type(obj).__name__}"
        raise ToolError(msg)

    dc_instance = cast("Any", obj)
    raw: dict[str, Any] = dataclasses.asdict(dc_instance)
    safe = json_safe(raw)
    try:
        json.dumps(safe)
    except (TypeError, ValueError) as exc:
        msg = f"Dataclass result is not JSON-serialisable: {exc}"
        raise ToolError(msg) from exc
    return cast("dict[str, Any]", safe)


class _StateTracker:
    """Async context manager that maintains ``BridgeState.last_error`` lifecycle.

    Wrapping a bridge operation in :class:`_StateTracker` ensures that ``last_error`` is cleared on success and set to the failing
    exception's text on failure, while preserving the rest of ``BridgeState`` (``connected``, ``tool_running``, ``binary_loaded``,
    ``process_attached``, ``target_path``, ``target_pid``). This eliminates stale ``last_error`` readings after a successful operation
    following a prior failure.

    The tracker re-raises the original exception unchanged so callers can convert ``SandboxError`` to ``ToolError`` (or any other
    transformation) in the normal ``except``/``raise from`` flow. See :meth:`__init__` for constructor arguments.
    """

    __slots__ = ("apply_outcome", "operation")

    def __init__(
        self,
        apply_outcome: Callable[[str | None], None],
        operation: str,
    ) -> None:
        """Initialize the tracker.

        Args:
            apply_outcome: Callable invoked with ``None`` on success or
                the exception text on failure to update bridge state.
            operation: Short operation label (e.g. ``"copy_to"``) recorded
                in the failure log line emitted by :meth:`__aexit__`.
        """
        self.apply_outcome: Callable[[str | None], None] = apply_outcome
        self.operation: str = operation

    async def __aenter__(self) -> None:
        """Enter the context.

        Returns:
            None: The tracker does not expose any value to the ``async
            with`` block; only the exit-side state update matters.
        """
        _logger.debug("state_tracker_entered", operation=self.operation)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Update ``BridgeState.last_error`` based on operation outcome.

        Args:
            exc_type: Exception type raised inside the context, or ``None``
                if the block exited normally.
            exc: Exception instance raised inside the context, or ``None``
                if the block exited normally.
            traceback: Traceback associated with ``exc``. Unused but
                required by the async context-manager protocol.

        Returns:
            None: Never suppresses the exception; ``None`` propagates the
            original raise.
        """
        del exc_type, traceback
        if exc is None:
            self.apply_outcome(None)
        else:
            _logger.debug("state_tracker_failure", operation=self.operation, error=str(exc))
            self.apply_outcome(str(exc))


class SandboxBridge(ToolBridgeBase):
    """Bridge for sandbox operations.

    Provides an AI-accessible interface to the ``SandboxManager`` for creating isolated execution environments and running binaries.
    Instances own a lazy slot for the shared ``SandboxManager`` singleton and record the advertised ``BridgeCapabilities`` describing the
    dynamic-analysis features this bridge can provide.
    """

    def __init__(self) -> None:
        """Initialize the SandboxBridge instance."""
        super().__init__()
        self._manager: SandboxManager | None = None
        self._manager_destroyed: bool = False
        self._vnc_passwords: dict[str, str] = {}
        self._active_pcap_captures: dict[str, str] = {}
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_patching=False,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe", "elf"],
        )
        _logger.info("sandbox_bridge_constructed", bridge="sandbox")

    def _set_state_outcome(self, error: str | None) -> None:
        """Update ``BridgeState.last_error`` while preserving other fields.

        Used by :class:`_StateTracker` to keep ``last_error`` symmetric:
        cleared on success, populated on failure. Other state fields
        (``connected``, ``tool_running``, ``binary_loaded``,
        ``process_attached``, ``target_path``, ``target_pid``) are
        copied through unchanged so callers that already wrote them
        (``create``, ``run_binary``) do not see those values reset.

        The new state is assigned via the ``state`` property setter so
        the base ``ToolBridgeBase`` ``bridge_state_changed`` log record
        is emitted consistently with every other state transition.

        Args:
            error: Exception text to record, or ``None`` to clear the
                ``last_error`` field after a successful operation.
        """
        current = self._state
        if current.last_error == error:
            return
        _logger.debug("sandbox_bridge_state_outcome_changed", error=error)
        self.state = dataclasses.replace(current, last_error=error)

    def _track_state(self, operation: str) -> _StateTracker:
        """Return an async context manager that maintains state lifecycle.

        The returned context manager clears ``BridgeState.last_error`` on
        successful completion of the wrapped block and records the
        exception text on failure. Other state fields are preserved.

        Args:
            operation: Short operation label (e.g. ``"copy_to"``) used by
                the tracker for structured logging context.

        Returns:
            _StateTracker: Async context manager to use in
            ``async with self._track_state("op"):`` blocks.
        """
        return _StateTracker(self._set_state_outcome, operation)

    @property
    def manager(self) -> SandboxManager | None:
        """The underlying ``SandboxManager`` instance, if initialized.

        Returns:
            SandboxManager | None: Active manager, or ``None`` if the bridge
            has not yet allocated one (or has been shut down).
        """
        return self._manager

    @property
    def manager_destroyed(self) -> bool:
        """Whether the manager has been shut down.

        Returns:
            bool: ``True`` if :meth:`shutdown` has been called and the manager
            has not been recreated, ``False`` otherwise.
        """
        return self._manager_destroyed

    def attach_manager(self, manager: SandboxManager) -> None:
        """Install an externally constructed ``SandboxManager``.

        Used by callers that need to wrap an existing
        ``SandboxBase``/``SandboxManager`` instance behind the bridge
        without spinning up a fresh manager via :meth:`ensure_manager`.
        Re-arming a previously shut-down bridge is also supported and
        clears the destroyed flag so subsequent operations succeed.

        Args:
            manager: Pre-existing manager to install on this bridge.
        """
        self._manager = manager
        self._manager_destroyed = False
        _logger.info(
            "sandbox_manager_attached",
            instance_count=len(manager.instances),
        )

    def register_existing_sandbox(
        self,
        sandbox: object,
        sandbox_type: SandboxType,
    ) -> str:
        """Register an already-constructed sandbox with the bridge manager.

        Wraps the supplied sandbox in a ``SandboxInstance`` (using the
        manager's normal instance bookkeeping) and adds it to the
        manager owned by this bridge. If no manager has been
        constructed yet, a fresh one is created. Returns the new
        instance ID so callers can drive subsequent bridge operations.

        Args:
            sandbox: Pre-constructed ``SandboxBase`` (or compatible
                duck-typed object) to register.
            sandbox_type: Type tag (``"windows"`` or ``"qemu"``) used
                by bridge dispatch logic to gate type-specific
                operations such as snapshots and screenshots.

        Returns:
            str: ID of the registered ``SandboxInstance``.
        """
        manager = self.ensure_manager()
        sb = cast("SandboxBase", sandbox)
        instance = SandboxInstance(sandbox=sb, sandbox_type=sandbox_type)
        instances_map = cast("dict[str, SandboxInstance]", vars(manager)["_instances"])
        instances_map[instance.id] = instance
        _logger.info(
            "sandbox_existing_registered",
            instance_id=instance.id,
            sandbox_type=sandbox_type,
        )
        return instance.id

    @property
    def name(self) -> ToolName:
        """The tool's name.

        Returns:
            ToolName: ToolName.SANDBOX.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """Tool definition for LLM function calling.

        Returns:
            ToolDefinition: ToolDefinition with all sandbox functions.
        """
        return ToolDefinition(
            tool_name=ToolName.SANDBOX,
            description=(
                "Sandbox environment for isolated binary execution with behavior "
                "monitoring. Use for safely testing patched binaries, observing "
                "runtime behavior, and validating license bypass attempts."
            ),
            functions=[
                ToolFunction(
                    name="sandbox.create",
                    description=(
                        "Create a new sandbox instance for isolated binary execution. "
                        "Use Windows Sandbox for quick testing or QEMU for persistent "
                        "VM-based analysis with snapshot support."
                    ),
                    parameters=[
                        ToolParameter(
                            name="sandbox_type",
                            type="string",
                            description="Type of sandbox: 'windows' or 'qemu'",
                            required=False,
                            enum=["windows", "qemu"],
                            default="windows",
                        ),
                        ToolParameter(
                            name="timeout_seconds",
                            type="integer",
                            description="Execution timeout in seconds (default: 300)",
                            required=False,
                            default=300,
                        ),
                        ToolParameter(
                            name="network_enabled",
                            type="boolean",
                            description="Whether to enable network access",
                            required=False,
                            default=False,
                        ),
                        ToolParameter(
                            name="memory_limit_mb",
                            type="integer",
                            description="Memory limit in megabytes (default: 2048)",
                            required=False,
                            default=2048,
                        ),
                    ],
                    returns="Dictionary with instance_id and status",
                ),
                ToolFunction(
                    name="sandbox.destroy",
                    description="Destroy a sandbox instance and free resources.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance to destroy",
                            required=True,
                        ),
                    ],
                    returns="Success confirmation",
                ),
                ToolFunction(
                    name="sandbox.restart",
                    description=(
                        "Tear down a sandbox instance and create a fresh replacement of the "
                        "same type in one operation. Use this to return a sandbox to a clean "
                        "state between runs; the original instance is destroyed in every "
                        "outcome, and no replacement is registered if the recreate fails."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance to restart",
                            required=True,
                        ),
                        ToolParameter(
                            name="timeout_seconds",
                            type="integer",
                            description="Execution timeout in seconds for the replacement instance",
                            required=False,
                        ),
                        ToolParameter(
                            name="network_enabled",
                            type="boolean",
                            description="Whether the replacement instance may access the network",
                            required=False,
                        ),
                        ToolParameter(
                            name="memory_limit_mb",
                            type="integer",
                            description="Memory limit in megabytes for the replacement instance",
                            required=False,
                        ),
                    ],
                    returns="New instance_id, the previous_instance_id, type, status, and creation timestamp",
                ),
                ToolFunction(
                    name="sandbox.run_binary",
                    description=(
                        "Execute a binary in a sandbox with full behavior monitoring. "
                        "Returns detailed execution report including exit code, output, "
                        "file changes, registry modifications, network activity, and "
                        "process spawns. Use this to test if licensing patches work."
                    ),
                    parameters=[
                        ToolParameter(
                            name="binary_path",
                            type="string",
                            description="Path to the binary to execute",
                            required=True,
                        ),
                        ToolParameter(
                            name="args",
                            type="array",
                            description="Command line arguments for the binary (default: [])",
                            required=False,
                            default=[],
                        ),
                        ToolParameter(
                            name="sandbox_type",
                            type="string",
                            description="Type of sandbox: 'windows' or 'qemu'",
                            required=False,
                            enum=["windows", "qemu"],
                            default="windows",
                        ),
                        ToolParameter(
                            name="time_limit",
                            type="integer",
                            description="Execution timeout in seconds (default: sandbox config value)",
                            required=False,
                            default=300,
                        ),
                        ToolParameter(
                            name="monitor",
                            type="boolean",
                            description="Whether to monitor behavior (default: true)",
                            required=False,
                            default=True,
                        ),
                    ],
                    returns="ExecutionReport with results and monitored activity",
                ),
                ToolFunction(
                    name="sandbox.execute",
                    description="Execute an arbitrary command in an existing sandbox.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="command",
                            type="string",
                            description="Command to execute",
                            required=True,
                        ),
                        ToolParameter(
                            name="time_limit",
                            type="integer",
                            description="Command timeout in seconds (default: sandbox config value)",
                            required=False,
                            default=60,
                        ),
                        ToolParameter(
                            name="working_directory",
                            type="string",
                            description="Working directory for the command",
                            required=False,
                        ),
                    ],
                    returns="Tuple of (exit_code, stdout, stderr)",
                ),
                ToolFunction(
                    name="sandbox.copy_to",
                    description="Copy a file into a sandbox instance.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="source",
                            type="string",
                            description="Local source file path",
                            required=True,
                        ),
                        ToolParameter(
                            name="dest",
                            type="string",
                            description="Destination path inside sandbox",
                            required=True,
                        ),
                    ],
                    returns="Success confirmation",
                ),
                ToolFunction(
                    name="sandbox.copy_from",
                    description="Copy a file from a sandbox instance to local filesystem.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="source",
                            type="string",
                            description="Source path inside sandbox",
                            required=True,
                        ),
                        ToolParameter(
                            name="dest",
                            type="string",
                            description="Local destination file path",
                            required=True,
                        ),
                    ],
                    returns="Success confirmation",
                ),
                ToolFunction(
                    name="sandbox.status",
                    description="Get status of the sandbox manager and all instances.",
                    parameters=[],
                    returns="Status dictionary with available types and instance info",
                ),
                ToolFunction(
                    name="sandbox.list",
                    description="List all active sandbox instances.",
                    parameters=[],
                    returns="List of instance information dictionaries",
                ),
                ToolFunction(
                    name="sandbox.snapshot_create",
                    description=("Create a snapshot of a QEMU sandbox state. Use before applying risky patches to enable rollback."),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="name",
                            type="string",
                            description="Name for the snapshot",
                            required=True,
                        ),
                    ],
                    returns="Snapshot ID",
                ),
                ToolFunction(
                    name="sandbox.snapshot_restore",
                    description="Restore a QEMU sandbox to a previous snapshot state.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="snapshot_id",
                            type="string",
                            description="ID of the snapshot to restore",
                            required=True,
                        ),
                    ],
                    returns="Success confirmation",
                ),
                ToolFunction(
                    name="sandbox.snapshot_list",
                    description="List all available snapshots for a QEMU sandbox.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Dictionary with instance_id, snapshots (list of names), and count",
                ),
                ToolFunction(
                    name="sandbox.snapshot_delete",
                    description="Delete a snapshot from a QEMU sandbox.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="name",
                            type="string",
                            description="Name of the snapshot to delete",
                            required=True,
                        ),
                    ],
                    returns="Success confirmation",
                ),
                ToolFunction(
                    name="sandbox.stop",
                    description="Pause execution of a running QEMU sandbox VM.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Command response from QEMU monitor",
                ),
                ToolFunction(
                    name="sandbox.cont",
                    description=("Resume execution of a paused QEMU sandbox VM. Use after breakpoints or manual pauses."),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Command response from QEMU monitor",
                ),
                ToolFunction(
                    name="sandbox.get_pending_messages",
                    description=("Retrieve pending messages from the QEMU guest agent. Returns queued agent communication messages."),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="List of pending guest agent messages",
                ),
                ToolFunction(
                    name="sandbox.pcap_start",
                    description="Start network packet capture on a QEMU sandbox instance.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Dictionary with capture_id",
                ),
                ToolFunction(
                    name="sandbox.pcap_stop",
                    description="Stop packet capture and retrieve the PCAP file.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="capture_id",
                            type="string",
                            description="Capture ID from pcap_start",
                            required=True,
                        ),
                        ToolParameter(
                            name="output_path",
                            type="string",
                            description="Optional local path to save the PCAP file (default: auto-generated temp path)",
                            required=False,
                            default="",
                        ),
                    ],
                    returns="Dictionary with pcap file path",
                ),
                ToolFunction(
                    name="sandbox.stop_pcap",
                    description=(
                        "Stop any active PCAP capture for a sandbox instance without requiring the original "
                        "capture_id. Cleanup-friendly variant of pcap_stop; a no-op if no capture is active."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance whose PCAP capture should be stopped",
                            required=True,
                        ),
                    ],
                    returns="Dictionary with instance_id, stopped flag, and capture_id/pcap_path if a capture was active",
                ),
                ToolFunction(
                    name="sandbox.screenshot",
                    description="Capture a screenshot of the QEMU sandbox display.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="output_path",
                            type="string",
                            description="Optional local path to save the screenshot (default: auto-generated temp path)",
                            required=False,
                            default="",
                        ),
                    ],
                    returns="Dictionary with screenshot file path",
                ),
                ToolFunction(
                    name="sandbox.anti_evasion",
                    description="Apply anti-evasion hardening to make the QEMU sandbox less detectable by malware.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="profile",
                            type="string",
                            description="Anti-evasion profile name",
                            required=False,
                            default="default",
                        ),
                    ],
                    returns="Dictionary describing applied anti-evasion techniques",
                ),
                ToolFunction(
                    name="sandbox.memory_dump",
                    description=(
                        "Dump guest memory to a file for offline analysis. "
                        "QEMU dumps the entire VM; Windows Sandbox dumps the specific guest process "
                        "identified by target_pid via MiniDumpWriteDump."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="output_path",
                            type="string",
                            description="Optional local path to save the memory dump (default: auto-generated temp path)",
                            required=False,
                            default="",
                        ),
                        ToolParameter(
                            name="target_pid",
                            type="integer",
                            description=(
                                "Guest-side PID of the process to dump. Required for Windows Sandbox "
                                "(MiniDumpWriteDump targets a specific process). Ignored for QEMU."
                            ),
                            required=False,
                            default=0,
                        ),
                    ],
                    returns="Dictionary with memory dump file path",
                ),
                ToolFunction(
                    name="sandbox.list_guest_processes",
                    description=(
                        "List processes currently running inside a Windows Sandbox guest, "
                        "for choosing a target_pid before calling sandbox.memory_dump."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the Windows Sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Dictionary with a list of guest process records (pid, name, path)",
                ),
                ToolFunction(
                    name="sandbox.extract_dropped_files",
                    description="Extract files created by the binary during execution into a ZIP archive (QEMU sandboxes only).",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="output_path",
                            type="string",
                            description="Optional local path to save the ZIP archive (default: auto-generated temp path)",
                            required=False,
                            default="",
                        ),
                    ],
                    returns="Dictionary with ZIP archive path",
                ),
                ToolFunction(
                    name="sandbox.yara_scan",
                    description="Run YARA rules against sandbox artifacts (dropped files or memory dump).",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="rules_path",
                            type="string",
                            description="Path to YARA rules file. Uses built-in rules if omitted.",
                            required=False,
                        ),
                        ToolParameter(
                            name="scan_target",
                            type="string",
                            description="What to scan: 'files' for dropped files, 'memory' for memory dump",
                            required=False,
                            enum=["files", "memory"],
                            default="files",
                        ),
                    ],
                    returns="List of YARA match dictionaries",
                ),
                ToolFunction(
                    name="sandbox.extract_iocs",
                    description="Extract structured Indicators of Compromise from the last execution report.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="List of IOC entries with type, value, source, context",
                ),
                ToolFunction(
                    name="sandbox.timeline",
                    description="Generate a unified event timeline from the last execution report.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="categories",
                            type="array",
                            description="Optional list of categories to include (e.g., 'file', 'registry', 'network'). Default: all categories.",
                            required=False,
                            default=[],
                        ),
                    ],
                    returns="List of timeline events sorted by timestamp",
                ),
                ToolFunction(
                    name="sandbox.detect_behaviors",
                    description=(
                        "Match behavioral signatures against the last execution report using MITRE ATT&CK patterns. "
                        "Accepts an optional path to a custom YAML rules file."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="custom_rules_path",
                            type="string",
                            description="Optional path to custom behavioral rules YAML file",
                            required=False,
                        ),
                    ],
                    returns="List of behavioral signature matches with severity and MITRE ATT&CK IDs",
                ),
                ToolFunction(
                    name="sandbox.detect_c2",
                    description="Detect Command and Control communication patterns in the last execution report.",
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="List of C2 pattern detections with confidence scores",
                ),
                ToolFunction(
                    name="sandbox.diff",
                    description="Compare two sandbox execution reports to identify behavioral differences.",
                    parameters=[
                        ToolParameter(
                            name="instance_id_a",
                            type="string",
                            description="ID of the first sandbox instance",
                            required=True,
                        ),
                        ToolParameter(
                            name="instance_id_b",
                            type="string",
                            description="ID of the second sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="Dictionary with per-field comparison of unique and common items",
                ),
                ToolFunction(
                    name="sandbox.get_vnc_port",
                    description=(
                        "Return the VNC TCP port the QEMU sandbox is exposing its framebuffer on. "
                        "Raises an error when the sandbox is not QEMU or VNC is not configured. "
                        "Use this to attach a VNC viewer for interactive display inspection."
                    ),
                    parameters=[
                        ToolParameter(
                            name="instance_id",
                            type="string",
                            description="ID of the QEMU sandbox instance",
                            required=True,
                        ),
                    ],
                    returns="VNC port number (integer)",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the sandbox bridge.

        Args:
            tool_path: Not used for sandbox (ignored).
        """
        del tool_path
        if self._manager is None:
            self._manager = SandboxManager()
            self._manager_destroyed = False

        self.state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

        _logger.info("sandbox_bridge_initialized", bridge="sandbox")

    async def shutdown(self) -> None:
        """Shutdown the sandbox bridge and cleanup resources."""
        if self._manager is not None:
            await self._manager.destroy_all()
            self._manager = None
            self._manager_destroyed = True

        await super().shutdown()
        _logger.info("sandbox_bridge_shutdown", bridge="sandbox")

    async def is_available(self) -> bool:
        """Check if sandbox functionality is available.

        Returns:
            bool: True if at least one sandbox type is available.
        """
        _logger.info("is_available_started")
        if self._manager is None:
            self._manager = SandboxManager()
            self._manager_destroyed = False

        available_types = await self._manager.get_available_types()
        return len(available_types) > 0

    def ensure_manager(self) -> SandboxManager:
        """Ensure manager is initialized and has not been shut down.

        Returns:
            SandboxManager: The SandboxManager instance.

        Raises:
            ToolError: If the manager was previously shut down via ``shutdown()``.
        """
        _logger.info("ensure_manager_started")
        if self._manager is None:
            if self._manager_destroyed:
                raise ToolError(_ERR_MANAGER_DESTROYED)
            self._manager = SandboxManager()
        return self._manager

    async def create(
        self,
        sandbox_type: str = "windows",
        timeout_seconds: int = 300,
        *,
        network_enabled: bool = False,
        block_telemetry: bool = True,
        memory_limit_mb: int = 2048,
        qemu_config: QEMUConfig | None = None,
    ) -> dict[str, Any]:
        """Create a new sandbox instance.

        Rejects unknown ``sandbox_type`` values explicitly instead of
        silently coercing them to ``"qemu"``. The previous behaviour
        hid typos (``"Qemu"``, ``"window"``, ``"vm"``) and caused the
        orchestrator to spin up the wrong sandbox flavour; validating
        up-front surfaces the mistake to the caller immediately.

        ``qemu_config`` carries the QEMU-specific settings the generic
        :class:`SandboxConfig` cannot express - most importantly the qcow2
        disk image. Without it a ``"qemu"`` sandbox has no bootable disk and
        can never start, so callers creating a QEMU sandbox must supply one.

        Args:
            sandbox_type: Type of sandbox (``"windows"`` or ``"qemu"``).
            timeout_seconds: Execution timeout in seconds.
            network_enabled: Whether to enable network access.
            block_telemetry: Whether the guest's own operating-system telemetry
                is silenced inside the guest at start. Defaults to on, matching
                the dialog, so a caller that says nothing gets a capture in
                which outbound traffic belongs to the sample.
            memory_limit_mb: Memory limit in megabytes.
            qemu_config: QEMU backend configuration forwarded to the manager.
                Ignored for the ``"windows"`` sandbox type.

        Returns:
            dict[str, Any]: Dictionary with instance_id and status.

        Raises:
            ToolError: If ``sandbox_type`` is not one of the supported
                values or if creation fails inside the manager.
        """
        if sandbox_type not in _VALID_SANDBOX_TYPES:
            msg = f"{_ERR_INVALID_SANDBOX_TYPE}: {sandbox_type!r}"
            raise ToolError(msg)

        manager = self.ensure_manager()

        config = SandboxConfig(
            timeout_seconds=timeout_seconds,
            network_enabled=network_enabled,
            block_telemetry=block_telemetry,
            memory_limit_mb=memory_limit_mb,
        )

        try:
            sb_type: SandboxType = cast("SandboxType", sandbox_type)
            instance = await manager.create(
                sandbox_type=sb_type,
                config=config,
                qemu_config=qemu_config,
                auto_start=True,
            )

            _logger.info("sandbox_created", instance_id=instance.id, type=sb_type)

            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=None,
            )

            return {
                "instance_id": instance.id,
                "type": instance.sandbox_type,
                "status": instance.state.status,
                "created_at": instance.created_at.astimezone(UTC).isoformat(),
            }

        except SandboxError as e:
            _logger.warning("sandbox_create_failed", error=str(e))
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=str(e),
            )
            msg = f"{_ERR_CREATE_FAILED}: {e}"
            raise ToolError(msg) from e

    async def destroy(self, instance_id: str) -> dict[str, Any]:
        """Destroy a sandbox instance.

        Args:
            instance_id: ID of the instance to destroy.

        Returns:
            dict[str, Any]: Success confirmation.

        Raises:
            ToolError: If destruction fails.
        """
        manager = self.ensure_manager()

        try:
            await manager.destroy(instance_id)
            _logger.info("sandbox_destroyed", instance_id=instance_id)
        except SandboxError as e:
            _logger.warning("sandbox_destroy_failed", instance_id=instance_id, error=str(e))
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=self.state.binary_loaded,
                process_attached=self.state.process_attached,
                target_path=self.state.target_path,
                target_pid=self.state.target_pid,
                last_error=str(e),
            )
            msg = f"{_ERR_DESTROY_FAILED}: {e}"
            raise ToolError(msg) from e
        else:
            self._vnc_passwords.pop(instance_id, None)
            self._active_pcap_captures.pop(instance_id, None)
            return {"success": True, "instance_id": instance_id}

    async def restart(
        self,
        instance_id: str,
        timeout_seconds: int = 300,
        *,
        network_enabled: bool = False,
        block_telemetry: bool = True,
        memory_limit_mb: int = 2048,
        qemu_config: QEMUConfig | None = None,
    ) -> dict[str, Any]:
        """Restart a sandbox instance as a single managed operation.

        Delegates to :meth:`SandboxManager.restart`, so the teardown and the
        recreate share the manager's failure semantics instead of being chained
        by the caller: the original instance is gone in every outcome, and no
        replacement is registered when the recreate fails.

        ``qemu_config`` carries the QEMU-specific settings the generic
        :class:`SandboxConfig` cannot express - most importantly the qcow2 disk
        image. A QEMU instance restarted without it has no bootable disk and can
        never start again, so callers restarting a QEMU sandbox must supply one.

        Args:
            instance_id: ID of the instance to restart.
            timeout_seconds: Execution timeout in seconds for the replacement.
            network_enabled: Whether the replacement may access the network.
            block_telemetry: Whether the replacement silences the guest's own
                operating-system telemetry inside the guest at start.
            memory_limit_mb: Memory limit in megabytes for the replacement.
            qemu_config: QEMU backend configuration forwarded to the manager.
                Ignored for the ``"windows"`` sandbox type.

        Returns:
            dict[str, Any]: Dictionary with the new ``instance_id``, the
            ``previous_instance_id`` that was torn down, and the replacement's
            type, status, and creation timestamp.

        Raises:
            ToolError: If the instance is unknown or the replacement could not
                be created.
        """
        manager = self.ensure_manager()

        config = SandboxConfig(
            timeout_seconds=timeout_seconds,
            network_enabled=network_enabled,
            block_telemetry=block_telemetry,
            memory_limit_mb=memory_limit_mb,
        )

        self._vnc_passwords.pop(instance_id, None)
        self._active_pcap_captures.pop(instance_id, None)

        try:
            instance = await manager.restart(instance_id, config=config, qemu_config=qemu_config)
        except SandboxError as e:
            _logger.warning("sandbox_restart_failed", instance_id=instance_id, error=str(e))
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=str(e),
            )
            msg = f"{_ERR_RESTART_FAILED}: {e}"
            raise ToolError(msg) from e

        _logger.info("sandbox_restarted", previous_instance_id=instance_id, instance_id=instance.id)
        self.state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )
        return {
            "instance_id": instance.id,
            "previous_instance_id": instance_id,
            "type": instance.sandbox_type,
            "status": instance.state.status,
            "created_at": instance.created_at.astimezone(UTC).isoformat(),
        }

    async def run_binary(
        self,
        binary_path: str,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        time_limit: int | None = None,
        companions: list[str] | None = None,
        *,
        monitor: bool = True,
        qemu_config: QEMUConfig | None = None,
        reuse_instance: bool = False,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a binary in a sandbox with monitoring.

        Validates ``sandbox_type`` up-front and refuses to launch the
        target under a coerced fallback when the caller supplies an
        unknown flavour. The previous silent coercion mapped any
        non-``"windows"`` string to ``"qemu"``, which made
        ``sandbox_type="Qemu"`` (capitalised) or future sandbox flavours
        silently behave as QEMU.

        Both ``qemu_config`` and ``reuse_instance`` are forwarded to the
        manager, which has always accepted them. Without the first, a QEMU
        run reaches the backend with no disk image and cannot start at all;
        without the second, a caller that already has a running sandbox gets
        a second virtual machine booted beside it rather than its binary run
        in the one it is looking at.

        ``instance_id`` is stronger than ``reuse_instance`` and is what a
        caller needs to compare two runs. ``reuse_instance`` cannot express
        *which* sandbox to use - it takes whichever idle one of that type
        comes first - so with two sandboxes running, two successive calls both
        land on the same instance and :meth:`diff` has only one report to work
        from.

        Args:
            binary_path: Path to the binary to execute.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox to use (``"windows"`` or
                ``"qemu"``).
            time_limit: Optional timeout override in seconds.
            companions: Paths to files or directories the target needs beside
                it, each placed in the sandbox under its own name. A target
                staged without one of these still launches and still exits
                ``0`` while doing nothing.
            monitor: Whether to monitor behavior.
            qemu_config: QEMU-specific configuration, required for the
                ``"qemu"`` type to reach a bootable disk image.
            reuse_instance: Whether to run in an existing idle sandbox of the
                same type instead of creating one.
            instance_id: Identifier of the existing sandbox to run in. Takes
                precedence over ``reuse_instance``.

        Returns:
            dict[str, Any]: ExecutionReport as dictionary.

        Raises:
            ToolError: If ``sandbox_type`` is not one of the supported
                values, the binary does not exist, or execution fails.
        """
        if sandbox_type not in _VALID_SANDBOX_TYPES:
            msg = f"{_ERR_INVALID_SANDBOX_TYPE}: {sandbox_type!r}"
            raise ToolError(msg)

        manager = self.ensure_manager()

        path = Path(binary_path)
        if not await asyncio.to_thread(path.exists):
            msg = f"{_ERR_BINARY_NOT_FOUND}: {binary_path}"
            raise ToolError(msg)

        companion_paths = [Path(companion) for companion in companions] if companions else None

        try:
            sb_type: SandboxType = cast("SandboxType", sandbox_type)
            instance, report = await manager.run_binary(
                binary_path=path,
                args=args,
                sandbox_type=sb_type,
                time_limit=time_limit,
                qemu_config=qemu_config,
                instance_id=instance_id,
                companions=companion_paths,
                monitor=monitor,
                reuse_instance=reuse_instance,
            )

            _logger.info("binary_execution_completed", instance_id=instance.id, result=report.result, exit_code=report.exit_code)

            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=True,
                process_attached=False,
                target_path=path,
                target_pid=None,
                last_error=None,
            )
        except (SandboxError, OSError, RuntimeError) as e:
            _logger.warning("binary_execution_failed", error=str(e))
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=False,
                process_attached=False,
                target_path=None,
                target_pid=None,
                last_error=str(e),
            )
            msg = f"{_ERR_EXECUTION_FAILED}: {e}"
            raise ToolError(msg) from e
        else:
            return self._report_to_dict(report, instance.id)

    async def execute(
        self,
        instance_id: str,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> dict[str, Any]:
        """Execute a command in an existing sandbox.

        Args:
            instance_id: ID of the sandbox instance.
            command: Command to execute.
            time_limit: Optional command timeout in seconds.
            working_directory: Optional working directory.

        Returns:
            dict[str, Any]: Dictionary with exit_code, stdout, stderr.

        Raises:
            ToolError: If execution fails.
        """
        manager = self.ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
            raise ToolError(msg)

        try:
            exit_code, stdout, stderr = await instance.sandbox.run_command(
                command=command,
                time_limit=time_limit,
                working_directory=working_directory,
            )

            instance.touch()
            _logger.info("command_executed", instance_id=instance_id, exit_code=exit_code)

            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=self.state.binary_loaded,
                process_attached=self.state.process_attached,
                target_path=self.state.target_path,
                target_pid=self.state.target_pid,
                last_error=None,
            )
        except SandboxError as e:
            _logger.warning("command_execution_failed", instance_id=instance_id, error=str(e))
            self.state = BridgeState(
                connected=True,
                tool_running=True,
                binary_loaded=self.state.binary_loaded,
                process_attached=self.state.process_attached,
                target_path=self.state.target_path,
                target_pid=self.state.target_pid,
                last_error=str(e),
            )
            msg = f"{_ERR_CMD_EXEC_FAILED}: {e}"
            raise ToolError(msg) from e
        else:
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            }

    async def copy_to(
        self,
        instance_id: str,
        source: str,
        dest: str,
    ) -> dict[str, Any]:
        """Copy a file into a sandbox.

        Args:
            instance_id: ID of the sandbox instance.
            source: Local source file path.
            dest: Destination path inside sandbox.

        Returns:
            dict[str, Any]: Success confirmation.

        Raises:
            ToolError: If copy fails.
        """
        _logger.info("copy_to_started")

        async with self._track_state("copy_to"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            source_path = Path(source)
            if not await asyncio.to_thread(source_path.exists):
                msg = f"{_ERR_SRC_NOT_FOUND}: {source}"
                raise ToolError(msg)

            try:
                await instance.sandbox.copy_to_sandbox(source_path, dest)
                instance.touch()
                _logger.info("file_copied_to_sandbox", source=source, instance_id=instance_id, dest=dest)
            except SandboxError as e:
                _logger.warning("copy_to_sandbox_failed", error=str(e))
                msg = f"{_ERR_COPY_TO_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "success": True,
                    "source": source,
                    "dest": dest,
                    "instance_id": instance_id,
                }

    async def copy_from(
        self,
        instance_id: str,
        source: str,
        dest: str,
    ) -> dict[str, Any]:
        """Copy a file from a sandbox.

        Args:
            instance_id: ID of the sandbox instance.
            source: Source path inside sandbox.
            dest: Local destination file path.

        Returns:
            dict[str, Any]: Success confirmation.

        Raises:
            ToolError: If copy fails.
        """
        _logger.info("copy_from_started")

        async with self._track_state("copy_from"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            dest_path = Path(dest)

            try:
                await instance.sandbox.copy_from_sandbox(source, dest_path)
                instance.touch()
                _logger.info("file_copied_from_sandbox", instance_id=instance_id, source=source, dest=dest)
            except SandboxError as e:
                _logger.warning("copy_from_sandbox_failed", error=str(e))
                msg = f"{_ERR_COPY_FROM_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "success": True,
                    "source": source,
                    "dest": dest,
                    "instance_id": instance_id,
                }

    async def status(self) -> dict[str, Any]:
        """Get sandbox manager status.

        Returns:
            dict[str, Any]: Status dictionary with available types and instance info.
        """
        _logger.info("status_started")
        manager = self.ensure_manager()
        return dict(await manager.get_status())

    async def list(self) -> list[dict[str, Any]]:
        """List all active sandbox instances.

        Returns:
            list[dict[str, Any]]: List of instance information dictionaries.
        """
        _logger.info("list_started")
        manager = self.ensure_manager()

        return [
            {
                "id": inst.id,
                "type": inst.sandbox_type,
                "status": inst.state.status,
                "created_at": inst.created_at.astimezone(UTC).isoformat(),
                "last_used": inst.last_used.astimezone(UTC).isoformat(),
                "binary": str(inst.binary_path) if inst.binary_path else None,
            }
            for inst in manager.instances
        ]

    async def snapshot_create(
        self,
        instance_id: str,
        name: str,
    ) -> dict[str, Any]:
        """Create a snapshot of a QEMU sandbox.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            name: Name for the snapshot.

        Returns:
            dict[str, Any]: Dictionary with snapshot_id.

        Raises:
            ToolError: If snapshot fails or not supported.
        """
        _logger.info("snapshot_create_started")

        async with self._track_state("snapshot_create"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                raise ToolError(_ERR_QEMU_ONLY)

            try:
                snapshot_id = await instance.sandbox.take_snapshot(name)
                instance.touch()
                _logger.info("snapshot_created", snapshot_name=name, instance_id=instance_id, snapshot_id=snapshot_id)
            except SandboxError as e:
                _logger.warning("snapshot_creation_failed", error=str(e))
                msg = f"{_ERR_SNAPSHOT_CREATE_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "snapshot_id": snapshot_id,
                    "name": name,
                    "instance_id": instance_id,
                }

    async def snapshot_restore(
        self,
        instance_id: str,
        snapshot_id: str,
    ) -> dict[str, Any]:
        """Restore a QEMU sandbox to a snapshot.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            snapshot_id: ID of the snapshot to restore.

        Returns:
            dict[str, Any]: Success confirmation.

        Raises:
            ToolError: If restore fails or not supported.
        """
        _logger.info("snapshot_restore_started")

        async with self._track_state("snapshot_restore"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                raise ToolError(_ERR_QEMU_ONLY)

            try:
                await instance.sandbox.restore_snapshot(snapshot_id)
                instance.touch()
                _logger.info("snapshot_restored", instance_id=instance_id, snapshot_id=snapshot_id)
            except SandboxError as e:
                _logger.warning("snapshot_restore_failed", error=str(e))
                msg = f"{_ERR_SNAPSHOT_RESTORE_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "success": True,
                    "instance_id": instance_id,
                    "snapshot_id": snapshot_id,
                }

    async def snapshot_list(
        self,
        instance_id: str,
    ) -> dict[str, Any]:
        """List available snapshots for a QEMU sandbox.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with list of snapshot names.

        Raises:
            ToolError: If listing fails or not supported.
        """
        _logger.info("snapshot_list_started")

        async with self._track_state("snapshot_list"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                raise ToolError(_ERR_QEMU_ONLY)

            try:
                snapshots = await instance.sandbox.list_snapshots()
                _logger.info(
                    "snapshots_listed",
                    instance_id=instance_id,
                    count=len(snapshots),
                )
            except SandboxError as e:
                _logger.warning("snapshot_list_failed", error=str(e))
                msg = f"{_ERR_SNAPSHOT_LIST_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "snapshots": snapshots,
                    "count": len(snapshots),
                }

    async def snapshot_delete(
        self,
        instance_id: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a snapshot from a QEMU sandbox.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            name: Name of the snapshot to delete.

        Returns:
            dict[str, Any]: Success confirmation.

        Raises:
            ToolError: If deletion fails or not supported.
        """
        _logger.info("snapshot_delete_started")

        async with self._track_state("snapshot_delete"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                raise ToolError(_ERR_QEMU_ONLY)

            try:
                await instance.sandbox.delete_snapshot(name)
                instance.touch()
                _logger.info(
                    "snapshot_deleted",
                    instance_id=instance_id,
                    snapshot_name=name,
                )
            except SandboxError as e:
                _logger.warning("snapshot_delete_failed", error=str(e))
                msg = f"{_ERR_SNAPSHOT_DELETE_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "success": True,
                    "instance_id": instance_id,
                    "name": name,
                }

    async def stop(
        self,
        instance_id: str,
    ) -> dict[str, Any]:
        """Pause execution of a running QEMU sandbox VM.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            dict[str, Any]: Command response dictionary.

        Raises:
            ToolError: If pause fails, QMP is not connected, or the
                instance is not a QEMU sandbox.
        """
        manager = self.ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
            raise ToolError(msg)

        if instance.sandbox_type != "qemu":
            raise ToolError(_ERR_QEMU_ONLY)

        qmp = getattr(instance.sandbox, "qmp", None)
        if qmp is None:
            msg = "Failed to pause VM: QMP client not connected"
            raise ToolError(msg)

        try:
            response = await qmp.stop()
        except Exception as e:
            _logger.warning("vm_pause_failed", error=str(e))
            msg = f"Failed to pause VM: {e}"
            raise ToolError(msg) from e

        if not response.success:
            err_detail = response.error or "QMP stop command failed"
            _logger.warning("vm_pause_qmp_error", error=err_detail, instance_id=instance_id)
            msg = f"Failed to pause VM: {err_detail}"
            raise ToolError(msg)

        instance.touch()
        _logger.info("vm_paused", instance_id=instance_id)

        return {
            "success": response.success,
            "status": "paused",
            "instance_id": instance_id,
        }

    async def cont(
        self,
        instance_id: str,
    ) -> dict[str, Any]:
        """Resume execution of a paused QEMU sandbox VM.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            dict[str, Any]: Command response dictionary.

        Raises:
            ToolError: If resume fails, QMP is not connected, or the
                instance is not a QEMU sandbox.
        """
        manager = self.ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
            raise ToolError(msg)

        if instance.sandbox_type != "qemu":
            raise ToolError(_ERR_QEMU_ONLY)

        qmp = getattr(instance.sandbox, "qmp", None)
        if qmp is None:
            msg = f"{_ERR_CONT_FAILED}: QMP client not connected"
            raise ToolError(msg)

        try:
            response = await qmp.cont()
        except Exception as e:
            _logger.warning("vm_resume_failed", error=str(e))
            msg = f"{_ERR_CONT_FAILED}: {e}"
            raise ToolError(msg) from e

        if not response.success:
            err_detail = response.error or "QMP cont command failed"
            _logger.warning("vm_resume_qmp_error", error=err_detail, instance_id=instance_id)
            msg = f"{_ERR_CONT_FAILED}: {err_detail}"
            raise ToolError(msg)

        instance.touch()
        _logger.info("vm_resumed", instance_id=instance_id)

        return {
            "success": response.success,
            "instance_id": instance_id,
            "data": response.data,
        }

    async def get_pending_messages(
        self,
        instance_id: str,
    ) -> dict[str, Any]:
        """Get pending messages from the QEMU guest agent.

        Raises ``ToolError`` when the guest agent is not connected
        instead of returning an empty list, so callers can distinguish
        "no messages waiting" (empty ``messages`` list, success) from
        "agent channel is dead" (error). Previously both paths returned
        ``{"messages": [], "count": 0}``, which masked agent-channel
        faults behind a benign-looking empty response and left GUI /
        orchestrator consumers with no way to surface the root cause.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with list of pending messages.

        Raises:
            ToolError: If the instance is unknown, is not a QEMU
                sandbox, has no connected guest agent, or the retrieval
                call itself fails.
        """
        manager = self.ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
            raise ToolError(msg)

        if instance.sandbox_type != "qemu":
            raise ToolError(_ERR_QEMU_ONLY)

        agent = getattr(instance.sandbox, "agent", None)
        if agent is None:
            msg = f"{_ERR_MESSAGES_FAILED}: guest agent channel not connected"
            raise ToolError(msg)

        try:
            messages = await agent.get_pending_messages()
            _logger.info(
                "pending_messages_retrieved",
                instance_id=instance_id,
                count=len(messages),
            )
            serialised = [{"type": getattr(msg, "message_type", "unknown"), "data": getattr(msg, "data", {})} for msg in messages]
        except (SandboxError, AttributeError) as e:
            _logger.warning("pending_messages_failed", error=str(e))
            msg_err = f"{_ERR_MESSAGES_FAILED}: {e}"
            raise ToolError(msg_err) from e

        return {
            "instance_id": instance_id,
            "messages": serialised,
            "count": len(serialised),
        }

    async def pcap_start(self, instance_id: str) -> dict[str, Any]:
        """Start packet capture on a QEMU sandbox instance.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with capture_id.

        Raises:
            ToolError: If capture cannot be started or sandbox is not QEMU.
        """
        _logger.info("pcap_start_started")

        async with self._track_state("pcap_start"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                msg = f"{_ERR_PCAP_START_FAILED}: {_ERR_QEMU_REQUIRED}"
                raise ToolError(msg)

            try:
                capture_id = await instance.sandbox.start_pcap_capture()
                instance.touch()
                _logger.info("pcap_capture_started", instance_id=instance_id, capture_id=capture_id)
            except SandboxError as e:
                _logger.warning("pcap_start_failed", error=str(e))
                msg = f"{_ERR_PCAP_START_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                self._active_pcap_captures[instance_id] = capture_id
                return {
                    "instance_id": instance_id,
                    "capture_id": capture_id,
                }

    async def pcap_stop(
        self,
        instance_id: str,
        capture_id: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Stop packet capture and retrieve the PCAP file.

        Args:
            instance_id: ID of the sandbox instance.
            capture_id: Capture ID from pcap_start.
            output_path: Optional local path to save the PCAP file.

        Returns:
            dict[str, Any]: Dictionary with pcap file path.

        Raises:
            ToolError: If capture cannot be stopped.
        """
        _logger.info("pcap_stop_started")

        async with self._track_state("pcap_stop"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            out = Path(output_path) if output_path else None

            try:
                pcap_path = await instance.sandbox.stop_pcap_capture(capture_id, out)
                instance.touch()
                _logger.info("pcap_capture_stopped", instance_id=instance_id, path=str(pcap_path))
            except SandboxError as e:
                _logger.warning("pcap_stop_failed", error=str(e))
                msg = f"{_ERR_PCAP_STOP_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                tracked = self._active_pcap_captures.get(instance_id)
                if tracked == capture_id:
                    del self._active_pcap_captures[instance_id]
                return {
                    "instance_id": instance_id,
                    "capture_id": capture_id,
                    "pcap_path": str(pcap_path),
                }

    async def stop_pcap(self, instance_id: str) -> dict[str, Any]:
        """Stop any active PCAP capture for the given sandbox instance.

        Cleanup-friendly variant of :meth:`pcap_stop` used by UI teardown
        paths that do not retain the original ``capture_id`` value. If no
        capture is active for the instance, the call is a no-op and
        returns ``stopped=False``.

        Args:
            instance_id: ID of the sandbox instance whose PCAP capture
                should be stopped.

        Returns:
            dict[str, Any]: Dictionary describing the outcome. Contains
            ``instance_id`` (str) and ``stopped`` (bool); when a capture
            was active, also ``capture_id`` (str) and ``pcap_path`` (str)
            of the saved file.

        Raises:
            ToolError: If a capture was active and stopping it failed.
        """
        capture_id = self._active_pcap_captures.get(instance_id)
        if capture_id is None:
            _logger.debug("stop_pcap_no_active_capture", instance_id=instance_id)
            return {"instance_id": instance_id, "stopped": False}

        try:
            result = await self.pcap_stop(instance_id, capture_id)
        except ToolError as e:
            _logger.warning(
                "stop_pcap_failed",
                instance_id=instance_id,
                capture_id=capture_id,
                error=str(e),
            )
            self._active_pcap_captures.pop(instance_id, None)
            msg = f"{_ERR_STOP_PCAP_FAILED}: {e}"
            raise ToolError(msg) from e

        return {
            "instance_id": instance_id,
            "stopped": True,
            "capture_id": str(result.get("capture_id", capture_id)),
            "pcap_path": str(result.get("pcap_path", "")),
        }

    def set_vnc_password(self, instance_id: str, password: str) -> None:
        """Register the VNC password configured for a sandbox instance.

        QEMU VNC passwords are negotiated at launch (via the QMP
        ``change vnc password`` command) and are not persisted by the
        underlying QEMU process in a way the bridge can recover later.
        Callers that configure VNC authentication on a QEMU sandbox
        MUST register the password through this method so that UI
        consumers can retrieve it via :meth:`get_vnc_password` when
        auto-connecting an embedded viewer.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            password: Plaintext VNC password to associate with the
                instance. Pass an empty string to indicate the VNC
                display is configured without authentication.
        """
        self._vnc_passwords[instance_id] = password
        _logger.debug(
            "vnc_password_registered",
            instance_id=instance_id,
            has_password=bool(password),
        )

    def get_vnc_password(self, instance_id: str) -> str | None:
        """Return the VNC password registered for a sandbox instance.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            str | None: The plaintext VNC password previously registered
            via :meth:`set_vnc_password`, or ``None`` if no password has
            been registered for this instance.
        """
        return self._vnc_passwords.get(instance_id)

    async def screenshot(
        self,
        instance_id: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Capture a screenshot of the QEMU sandbox display.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            output_path: Optional local path to save the screenshot.

        Returns:
            dict[str, Any]: Dictionary with screenshot file path.

        Raises:
            ToolError: If screenshot cannot be captured or sandbox is not QEMU.
        """
        _logger.info("screenshot_started")

        async with self._track_state("screenshot"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                msg = f"{_ERR_SCREENSHOT_FAILED}: {_ERR_QEMU_REQUIRED}"
                raise ToolError(msg)

            out = Path(output_path) if output_path else None

            try:
                screenshot_path = await instance.sandbox.capture_screenshot(out)
                instance.touch()
                _logger.info("screenshot_captured", instance_id=instance_id, path=str(screenshot_path))
            except SandboxError as e:
                _logger.warning("screenshot_failed", error=str(e))
                msg = f"{_ERR_SCREENSHOT_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "screenshot_path": str(screenshot_path),
                }

    async def anti_evasion(
        self,
        instance_id: str,
        profile: str = "default",
    ) -> dict[str, Any]:
        """Apply anti-evasion hardening to a QEMU sandbox instance.

        Args:
            instance_id: ID of the QEMU sandbox instance.
            profile: Anti-evasion profile name.

        Returns:
            dict[str, Any]: Dictionary describing applied techniques.

        Raises:
            ToolError: If anti-evasion cannot be applied or sandbox is not QEMU.
        """
        _logger.info("anti_evasion_started")

        async with self._track_state("anti_evasion"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                msg = f"{_ERR_ANTI_EVASION_FAILED}: {_ERR_QEMU_REQUIRED}"
                raise ToolError(msg)

            try:
                result = await instance.sandbox.apply_anti_evasion(profile)
                instance.touch()
                _logger.info("anti_evasion_applied", instance_id=instance_id, profile=profile)
            except SandboxError as e:
                _logger.warning("anti_evasion_failed", error=str(e))
                msg = f"{_ERR_ANTI_EVASION_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "profile": profile,
                    "techniques": result,
                }

    async def memory_dump(
        self,
        instance_id: str,
        output_path: str | None = None,
        target_pid: int | None = None,
    ) -> dict[str, Any]:
        """Dump guest memory from a sandbox instance.

        QEMU sandboxes dump the whole VM via the ``dump-guest-memory`` QMP
        command and ignore ``target_pid``. Windows Sandbox runs
        ``MiniDumpWriteDump`` inside the guest against the process identified
        by ``target_pid``; ``target_pid`` is required for Windows Sandbox
        because passing ``GetCurrentProcess()`` would (incorrectly) dump the
        PowerShell host instead of the analysis target (audit7 F-0021).

        Args:
            instance_id: ID of the sandbox instance.
            output_path: Optional local path to save the memory dump.
            target_pid: Guest-side PID of the process to dump. Required for
                Windows Sandbox instances; ignored for QEMU.

        Returns:
            dict[str, Any]: Dictionary with memory dump file path.

        Raises:
            ToolError: If memory dump fails or required arguments are missing.
        """
        _logger.info("memory_dump_started")

        async with self._track_state("memory_dump"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type not in {"qemu", "windows"}:
                msg = f"{_ERR_MEMORY_DUMP_FAILED}: unsupported sandbox type {instance.sandbox_type!r}"
                raise ToolError(msg)

            if instance.sandbox_type == "windows" and (target_pid is None or target_pid <= 0):
                msg = (
                    f"{_ERR_MEMORY_DUMP_FAILED}: target_pid is required for Windows Sandbox memory_dump "
                    "(MiniDumpWriteDump must target a specific guest process)"
                )
                raise ToolError(msg)

            out = Path(output_path) if output_path else None

            try:
                dump_path = await instance.sandbox.dump_memory(out, target_pid=target_pid)
                instance.touch()
                _logger.info(
                    "memory_dumped",
                    instance_id=instance_id,
                    path=str(dump_path),
                    target_pid=target_pid,
                )
            except SandboxError as e:
                _logger.warning("memory_dump_failed", error=str(e))
                msg = f"{_ERR_MEMORY_DUMP_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "dump_path": str(dump_path),
                    "target_pid": target_pid,
                }

    async def list_guest_processes(self, instance_id: str) -> dict[str, Any]:
        """List processes currently running inside a Windows Sandbox guest.

        Lets a caller discover a valid ``target_pid`` before calling
        :meth:`memory_dump` against a Windows Sandbox instance, which
        rejects a missing or non-positive ``target_pid`` outright.

        Args:
            instance_id: ID of the Windows Sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with ``instance_id`` and a
            ``processes`` list of ``{"pid", "name", "path"}`` records.

        Raises:
            ToolError: If the instance is not found, is not a Windows
                Sandbox, or the guest process listing fails.
        """
        _logger.info("list_guest_processes_started")

        async with self._track_state("list_guest_processes"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "windows":
                msg = f"{_ERR_LIST_PROCESSES_FAILED}: {_ERR_WINDOWS_REQUIRED}"
                raise ToolError(msg)

            try:
                processes = await instance.sandbox.list_processes()
                instance.touch()
                _logger.info("guest_processes_listed", instance_id=instance_id, count=len(processes))
            except SandboxError as e:
                _logger.warning("list_guest_processes_failed", error=str(e))
                msg = f"{_ERR_LIST_PROCESSES_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "processes": [{"pid": proc.pid, "name": proc.name, "path": proc.path} for proc in processes],
                }

    async def extract_dropped_files(
        self,
        instance_id: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Extract files created during sandbox execution (QEMU only).

        Args:
            instance_id: ID of the QEMU sandbox instance.
            output_path: Optional local path to save the ZIP archive.

        Returns:
            dict[str, Any]: Dictionary with ZIP archive path.

        Raises:
            ToolError: If extraction fails or sandbox is not QEMU.
        """
        _logger.info("extract_dropped_files_started")

        async with self._track_state("extract_dropped_files"):
            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.sandbox_type != "qemu":
                msg = f"{_ERR_EXTRACT_FILES_FAILED}: {_ERR_QEMU_REQUIRED}"
                raise ToolError(msg)

            out = Path(output_path) if output_path else None

            try:
                zip_path = await instance.sandbox.extract_dropped_files(out)
                instance.touch()
                _logger.info("dropped_files_extracted", instance_id=instance_id, path=str(zip_path))
            except SandboxError as e:
                _logger.warning("extract_dropped_files_failed", error=str(e))
                msg = f"{_ERR_EXTRACT_FILES_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "zip_path": str(zip_path),
                }

    async def yara_scan(
        self,
        instance_id: str,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> dict[str, Any]:
        """Run YARA rules against sandbox artifacts.

        Args:
            instance_id: ID of the sandbox instance.
            rules_path: Path to YARA rules file.
            scan_target: What to scan ('files' or 'memory').

        Returns:
            dict[str, Any]: Dictionary with YARA match results.

        Raises:
            ToolError: If scan_target is invalid or scan fails.
        """
        _logger.info("yara_scan_started")

        async with self._track_state("yara_scan"):
            if scan_target not in _VALID_YARA_MODES:
                msg = f"{_ERR_YARA_INVALID_MODE}: {scan_target!r}"
                raise ToolError(msg)

            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            try:
                matches = await instance.sandbox.yara_scan(rules_path, scan_target)
                instance.touch()
                _logger.info("yara_scan_completed", instance_id=instance_id, match_count=len(matches))
            except SandboxError as e:
                _logger.warning("yara_scan_failed", error=str(e))
                msg = f"{_ERR_YARA_SCAN_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "matches": matches,
                    "match_count": len(matches),
                }

    async def extract_iocs(self, instance_id: str) -> dict[str, Any]:
        """Extract IOCs from the last execution report.

        Args:
            instance_id: ID of the sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with list of IOC entries.

        Raises:
            ToolError: If extraction fails or no report available.
        """
        _logger.info("extract_iocs_started")

        async with self._track_state("extract_iocs"):
            analysis = _get_analysis_module()
            extract_fn = analysis.extract_iocs

            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.last_report is None:
                raise ToolError(_ERR_NO_REPORT)

            try:
                raw_iocs: list[dict[str, Any]] = extract_fn(instance.last_report)
                _logger.info("iocs_extracted", instance_id=instance_id, count=len(raw_iocs))
            except (ValueError, KeyError, TypeError) as e:
                _logger.warning("ioc_extraction_failed", error=str(e))
                msg = f"{_ERR_IOC_EXTRACT_FAILED}: {e}"
                raise ToolError(msg) from e
            except Exception as e:
                _logger.warning("ioc_extraction_unexpected_error", error=str(e))
                msg = f"{_ERR_IOC_EXTRACT_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "iocs": [dict(ioc) for ioc in raw_iocs],
                    "count": len(raw_iocs),
                }

    async def timeline(
        self,
        instance_id: str,
        categories: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate an event timeline from the last execution report.

        Args:
            instance_id: ID of the sandbox instance.
            categories: Optional list of categories to include.

        Returns:
            dict[str, Any]: Dictionary with list of timeline events.

        Raises:
            ToolError: If timeline generation fails or no report available.
        """
        _logger.info("timeline_started")

        async with self._track_state("timeline"):
            analysis = _get_analysis_module()
            timeline_fn = analysis.generate_timeline

            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.last_report is None:
                raise ToolError(_ERR_NO_REPORT)

            try:
                raw_events: list[dict[str, Any]] = timeline_fn(instance.last_report, categories)
                _logger.info("timeline_generated", instance_id=instance_id, event_count=len(raw_events))
            except (ValueError, KeyError, TypeError) as e:
                _logger.warning("timeline_generation_failed", error=str(e))
                msg = f"{_ERR_TIMELINE_FAILED}: {e}"
                raise ToolError(msg) from e
            except Exception as e:
                _logger.warning("timeline_unexpected_error", error=str(e))
                msg = f"{_ERR_TIMELINE_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "events": [dict(ev) for ev in raw_events],
                    "count": len(raw_events),
                }

    async def detect_behaviors(
        self,
        instance_id: str,
        custom_rules_path: str | None = None,
    ) -> dict[str, Any]:
        """Match behavioral signatures against the last execution report.

        If ``custom_rules_path`` is provided it must point to an existing
        YAML file whose top-level value is a list of rule dictionaries.
        A missing file or invalid YAML raises ``ToolError`` immediately;
        the underlying ``match_behaviors`` call is not made.

        Args:
            instance_id: ID of the sandbox instance.
            custom_rules_path: Optional path to custom YAML rules file.

        Returns:
            dict[str, Any]: Dictionary with list of behavior matches.

        Raises:
            ToolError: If the rules path is given but not found, the file
                is not valid YAML, the YAML top-level is not a list,
                detection fails, or no report is available.
        """
        _logger.info("detect_behaviors_started")

        async with self._track_state("detect_behaviors"):
            analysis = _get_analysis_module()
            behaviors_fn = analysis.match_behaviors

            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.last_report is None:
                raise ToolError(_ERR_NO_REPORT)

            custom_rules: list[dict[str, Any]] | None = None
            if custom_rules_path is not None:
                rules_file = Path(custom_rules_path)
                if not await asyncio.to_thread(rules_file.exists):
                    msg = f"{_ERR_RULES_NOT_FOUND}: {custom_rules_path}"
                    raise ToolError(msg)

                raw_text = await asyncio.to_thread(rules_file.read_text, encoding="utf-8")
                try:
                    loaded: Any = yaml.safe_load(raw_text)
                except yaml.YAMLError as e:
                    msg = f"{_ERR_RULES_INVALID}: {e}"
                    raise ToolError(msg) from e

                if not isinstance(loaded, list):
                    msg = f"{_ERR_RULES_INVALID}: expected a list, got {type(loaded).__name__}"
                    raise ToolError(msg)

                custom_rules = cast("list[dict[str, Any]]", loaded)

            try:
                raw_matches: list[dict[str, Any]] = behaviors_fn(instance.last_report, custom_rules)
                _logger.info("behaviors_detected", instance_id=instance_id, match_count=len(raw_matches))
            except (ValueError, KeyError, TypeError) as e:
                _logger.warning("behavior_detection_failed", error=str(e))
                msg = f"{_ERR_BEHAVIOR_FAILED}: {e}"
                raise ToolError(msg) from e
            except Exception as e:
                _logger.warning("behavior_detection_unexpected_error", error=str(e))
                msg = f"{_ERR_BEHAVIOR_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "matches": [dict(m) for m in raw_matches],
                    "count": len(raw_matches),
                }

    async def detect_c2(self, instance_id: str) -> dict[str, Any]:
        """Detect C2 communication patterns in the last execution report.

        Args:
            instance_id: ID of the sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with list of C2 pattern detections.

        Raises:
            ToolError: If detection fails or no report available.
        """
        _logger.info("detect_c2_started")

        async with self._track_state("detect_c2"):
            analysis = _get_analysis_module()
            c2_fn = analysis.detect_c2_patterns

            manager = self.ensure_manager()

            instance = await manager.get(instance_id)
            if instance is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
                raise ToolError(msg)

            if instance.last_report is None:
                raise ToolError(_ERR_NO_REPORT)

            try:
                patterns: list[dict[str, Any]] = c2_fn(instance.last_report.network_activity)
                _logger.info("c2_patterns_detected", instance_id=instance_id, pattern_count=len(patterns))
            except (ValueError, KeyError, TypeError) as e:
                _logger.warning("c2_detection_failed", error=str(e))
                msg = f"{_ERR_C2_DETECT_FAILED}: {e}"
                raise ToolError(msg) from e
            except Exception as e:
                _logger.warning("c2_detection_unexpected_error", error=str(e))
                msg = f"{_ERR_C2_DETECT_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id": instance_id,
                    "patterns": patterns,
                    "count": len(patterns),
                }

    async def diff(
        self,
        instance_id_a: str,
        instance_id_b: str,
    ) -> dict[str, Any]:
        """Compare two sandbox execution reports.

        Args:
            instance_id_a: ID of the first sandbox instance.
            instance_id_b: ID of the second sandbox instance.

        Returns:
            dict[str, Any]: Dictionary with per-field comparison results.

        Raises:
            ToolError: If comparison fails or reports unavailable.
        """
        _logger.info("diff_started")

        async with self._track_state("diff"):
            analysis = _get_analysis_module()
            diff_fn = analysis.diff_reports

            manager = self.ensure_manager()

            instance_a = await manager.get(instance_id_a)
            if instance_a is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id_a}"
                raise ToolError(msg)

            instance_b = await manager.get(instance_id_b)
            if instance_b is None:
                msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id_b}"
                raise ToolError(msg)

            if instance_a.last_report is None:
                msg = f"{_ERR_NO_REPORT} (instance {instance_id_a})"
                raise ToolError(msg)

            if instance_b.last_report is None:
                msg = f"{_ERR_NO_REPORT} (instance {instance_id_b})"
                raise ToolError(msg)

            try:
                result: dict[str, Any] = diff_fn(instance_a.last_report, instance_b.last_report)
                _logger.info("reports_diffed", instance_a=instance_id_a, instance_b=instance_id_b)
            except (ValueError, KeyError, TypeError) as e:
                _logger.warning("diff_failed", error=str(e))
                msg = f"{_ERR_DIFF_FAILED}: {e}"
                raise ToolError(msg) from e
            except Exception as e:
                _logger.warning("diff_unexpected_error", error=str(e))
                msg = f"{_ERR_DIFF_FAILED}: {e}"
                raise ToolError(msg) from e
            else:
                return {
                    "instance_id_a": instance_id_a,
                    "instance_id_b": instance_id_b,
                    "diff": result,
                }

    async def get_vnc_port(self, instance_id: str) -> int:
        """Get the VNC port for a QEMU sandbox instance.

        Only QEMU sandboxes expose a VNC port. Calling this on a
        non-QEMU instance raises ``ToolError``.  A QEMU instance whose
        VNC port has not been allocated yet also raises ``ToolError``
        rather than returning ``None``, since callers that query this
        method are specifically trying to connect a viewer and a
        ``None`` return is not actionable.

        Args:
            instance_id: ID of the QEMU sandbox instance.

        Returns:
            int: The VNC port number.

        Raises:
            ToolError: If the instance is not registered, is not a QEMU
                sandbox, or has no VNC port allocated.
        """
        manager = self.ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            msg = f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"
            raise ToolError(msg)

        if instance.sandbox_type != "qemu":
            msg = f"{_ERR_VNC_PORT_UNAVAILABLE}: requires QEMU sandbox"
            raise ToolError(msg)

        port: int | None = getattr(instance.sandbox, "vnc_port", None)
        if port is None:
            msg = f"{_ERR_VNC_PORT_UNAVAILABLE}: VNC display not configured on this QEMU instance"
            raise ToolError(msg)

        _logger.debug("vnc_port_queried", instance_id=instance_id, vnc_port=port)
        return port

    @staticmethod
    def _report_to_dict(
        report: ExecutionReport,
        instance_id: str,
    ) -> dict[str, Any]:
        """Convert ExecutionReport to dictionary.

        Args:
            report: The execution report.
            instance_id: Associated sandbox instance ID.

        Returns:
            dict[str, Any]: Dictionary representation.
        """
        d = dataclass_to_dict(report)
        d["instance_id"] = instance_id
        return d
