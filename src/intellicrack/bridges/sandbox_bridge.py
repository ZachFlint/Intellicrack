"""Sandbox bridge for isolated binary execution environments.

This module provides a tool bridge that wraps the SandboxManager
to expose sandbox operations to the AI orchestrator.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.logging import get_logger
from ..core.types import (
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from ..sandbox import (
    SandboxConfig,
    SandboxError,
    SandboxManager,
    SandboxType,
)
from .base import BridgeCapabilities, BridgeState, ToolBridgeBase


if TYPE_CHECKING:
    from ..sandbox import ExecutionReport


_logger = get_logger("bridges.sandbox")


class SandboxBridge(ToolBridgeBase):
    """Bridge for sandbox operations.

    Provides AI-accessible interface to the SandboxManager for
    creating isolated execution environments and running binaries.

    Attributes:
        _manager: The underlying SandboxManager instance.
    """

    def __init__(self) -> None:
        """Initialize the sandbox bridge."""
        super().__init__()
        self._manager: SandboxManager | None = None
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_patching=False,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe", "elf"],
        )

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.SANDBOX.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all sandbox functions.
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
                            description="Command line arguments for the binary",
                            required=False,
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
                            name="timeout",
                            type="integer",
                            description="Execution timeout in seconds",
                            required=False,
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
                            name="timeout",
                            type="integer",
                            description="Command timeout in seconds",
                            required=False,
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

        self._state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

        _logger.info("sandbox_bridge_initialized")

    async def shutdown(self) -> None:
        """Shutdown the sandbox bridge and cleanup resources."""
        if self._manager is not None:
            await self._manager.destroy_all()
            self._manager = None

        self._state = BridgeState()
        _logger.info("sandbox_bridge_shutdown")

    async def is_available(self) -> bool:
        """Check if sandbox functionality is available.

        Returns:
            True if at least one sandbox type is available.
        """
        if self._manager is None:
            self._manager = SandboxManager()

        available_types = await self._manager.get_available_types()
        return len(available_types) > 0

    def _ensure_manager(self) -> SandboxManager:
        """Ensure manager is initialized.

        Returns:
            The SandboxManager instance.
        """
        if self._manager is None:
            self._manager = SandboxManager()
        return self._manager

    async def create(
        self,
        sandbox_type: str = "windows",
        timeout_seconds: int = 300,
        network_enabled: bool = False,
        memory_limit_mb: int = 2048,
    ) -> dict[str, Any]:
        """Create a new sandbox instance.

        Args:
            sandbox_type: Type of sandbox ('windows' or 'qemu').
            timeout_seconds: Execution timeout in seconds.
            network_enabled: Whether to enable network access.
            memory_limit_mb: Memory limit in megabytes.

        Returns:
            Dictionary with instance_id and status.

        Raises:
            ToolError: If creation fails.
        """
        manager = self._ensure_manager()

        config = SandboxConfig(
            timeout_seconds=timeout_seconds,
            network_enabled=network_enabled,
            memory_limit_mb=memory_limit_mb,
        )

        try:
            sb_type: SandboxType = "windows" if sandbox_type == "windows" else "qemu"
            instance = await manager.create(
                sandbox_type=sb_type,
                config=config,
                auto_start=True,
            )

            _logger.info("sandbox_created", extra={"instance_id": instance.id, "type": sb_type})

            return {
                "instance_id": instance.id,
                "type": instance.sandbox_type,
                "status": instance.state.status,
                "created_at": instance.created_at.isoformat(),
            }

        except SandboxError as e:
            _logger.error("sandbox_create_failed", extra={"error": str(e)})
            raise ToolError(f"Failed to create sandbox: {e}") from e

    async def destroy(self, instance_id: str) -> dict[str, Any]:
        """Destroy a sandbox instance.

        Args:
            instance_id: ID of the instance to destroy.

        Returns:
            Success confirmation.

        Raises:
            ToolError: If destruction fails.
        """
        manager = self._ensure_manager()

        try:
            await manager.destroy(instance_id)
            _logger.info("sandbox_destroyed", extra={"instance_id": instance_id})
            return {"success": True, "instance_id": instance_id}

        except SandboxError as e:
            _logger.error("sandbox_destroy_failed", extra={"instance_id": instance_id, "error": str(e)})
            raise ToolError(f"Failed to destroy sandbox: {e}") from e

    async def run_binary(
        self,
        binary_path: str,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        timeout: int | None = None,
        monitor: bool = True,
    ) -> dict[str, Any]:
        """Execute a binary in a sandbox with monitoring.

        Args:
            binary_path: Path to the binary to execute.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox to use.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport as dictionary.

        Raises:
            ToolError: If execution fails.
        """
        manager = self._ensure_manager()

        path = Path(binary_path)
        if not path.exists():
            raise ToolError(f"Binary not found: {binary_path}")

        try:
            sb_type: SandboxType = "windows" if sandbox_type == "windows" else "qemu"
            instance, report = await manager.run_binary(
                binary_path=path,
                args=args,
                sandbox_type=sb_type,
                timeout=timeout,
                monitor=monitor,
            )

            _logger.info(
                "binary_execution_completed", extra={"instance_id": instance.id, "result": report.result, "exit_code": report.exit_code}
            )

            return self._report_to_dict(report, instance.id)

        except Exception as e:
            _logger.error("binary_execution_failed", extra={"error": str(e)})
            raise ToolError(f"Binary execution failed: {e}") from e

    async def execute(
        self,
        instance_id: str,
        command: str,
        timeout: int | None = None,
        working_directory: str | None = None,
    ) -> dict[str, Any]:
        """Execute a command in an existing sandbox.

        Args:
            instance_id: ID of the sandbox instance.
            command: Command to execute.
            timeout: Optional timeout.
            working_directory: Optional working directory.

        Returns:
            Dictionary with exit_code, stdout, stderr.

        Raises:
            ToolError: If execution fails.
        """
        manager = self._ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            raise ToolError(f"Sandbox instance not found: {instance_id}")

        try:
            exit_code, stdout, stderr = await instance.sandbox.execute(
                command=command,
                timeout=timeout,
                working_directory=working_directory,
            )

            instance.touch()
            _logger.info("command_executed", extra={"instance_id": instance_id, "exit_code": exit_code})

            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            }

        except SandboxError as e:
            _logger.error("command_execution_failed", extra={"instance_id": instance_id, "error": str(e)})
            raise ToolError(f"Command execution failed: {e}") from e

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
            Success confirmation.

        Raises:
            ToolError: If copy fails.
        """
        manager = self._ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            raise ToolError(f"Sandbox instance not found: {instance_id}")

        source_path = Path(source)
        if not source_path.exists():
            raise ToolError(f"Source file not found: {source}")

        try:
            await instance.sandbox.copy_to_sandbox(source_path, dest)
            instance.touch()
            _logger.info("file_copied_to_sandbox", extra={"source": source, "instance_id": instance_id, "dest": dest})

            return {
                "success": True,
                "source": source,
                "dest": dest,
                "instance_id": instance_id,
            }

        except SandboxError as e:
            _logger.error("copy_to_sandbox_failed", extra={"error": str(e)})
            raise ToolError(f"Copy to sandbox failed: {e}") from e

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
            Success confirmation.

        Raises:
            ToolError: If copy fails.
        """
        manager = self._ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            raise ToolError(f"Sandbox instance not found: {instance_id}")

        dest_path = Path(dest)

        try:
            await instance.sandbox.copy_from_sandbox(source, dest_path)
            instance.touch()
            _logger.info("file_copied_from_sandbox", extra={"instance_id": instance_id, "source": source, "dest": dest})

            return {
                "success": True,
                "source": source,
                "dest": dest,
                "instance_id": instance_id,
            }

        except SandboxError as e:
            _logger.error("copy_from_sandbox_failed", extra={"error": str(e)})
            raise ToolError(f"Copy from sandbox failed: {e}") from e

    async def status(self) -> dict[str, Any]:
        """Get sandbox manager status.

        Returns:
            Status dictionary with available types and instance info.
        """
        manager = self._ensure_manager()
        return dict(await manager.get_status())

    async def list(self) -> list[dict[str, Any]]:
        """List all active sandbox instances.

        Returns:
            List of instance information dictionaries.
        """
        manager = self._ensure_manager()

        return [
            {
                "id": inst.id,
                "type": inst.sandbox_type,
                "status": inst.state.status,
                "created_at": inst.created_at.isoformat(),
                "last_used": inst.last_used.isoformat(),
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
            Dictionary with snapshot_id.

        Raises:
            ToolError: If snapshot fails or not supported.
        """
        manager = self._ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            raise ToolError(f"Sandbox instance not found: {instance_id}")

        if instance.sandbox_type != "qemu":
            raise ToolError("Snapshots only supported for QEMU sandboxes")

        try:
            snapshot_id = await instance.sandbox.take_snapshot(name)
            instance.touch()
            _logger.info("snapshot_created", extra={"name": name, "instance_id": instance_id, "snapshot_id": snapshot_id})

            return {
                "snapshot_id": snapshot_id,
                "name": name,
                "instance_id": instance_id,
            }

        except SandboxError as e:
            _logger.error("snapshot_creation_failed", extra={"error": str(e)})
            raise ToolError(f"Snapshot creation failed: {e}") from e

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
            Success confirmation.

        Raises:
            ToolError: If restore fails or not supported.
        """
        manager = self._ensure_manager()

        instance = await manager.get(instance_id)
        if instance is None:
            raise ToolError(f"Sandbox instance not found: {instance_id}")

        if instance.sandbox_type != "qemu":
            raise ToolError("Snapshots only supported for QEMU sandboxes")

        try:
            await instance.sandbox.restore_snapshot(snapshot_id)
            instance.touch()
            _logger.info("snapshot_restored", extra={"instance_id": instance_id, "snapshot_id": snapshot_id})

            return {
                "success": True,
                "instance_id": instance_id,
                "snapshot_id": snapshot_id,
            }

        except SandboxError as e:
            _logger.error("snapshot_restore_failed", extra={"error": str(e)})
            raise ToolError(f"Snapshot restore failed: {e}") from e

    def _report_to_dict(
        self,
        report: ExecutionReport,
        instance_id: str,
    ) -> dict[str, Any]:
        """Convert ExecutionReport to dictionary.

        Args:
            report: The execution report.
            instance_id: Associated sandbox instance ID.

        Returns:
            Dictionary representation.
        """
        return {
            "instance_id": instance_id,
            "result": report.result,
            "exit_code": report.exit_code,
            "stdout": report.stdout,
            "stderr": report.stderr,
            "duration_seconds": report.duration_seconds,
            "file_changes": list(report.file_changes),
            "registry_changes": list(report.registry_changes),
            "network_activity": list(report.network_activity),
            "process_activity": list(report.process_activity),
        }
