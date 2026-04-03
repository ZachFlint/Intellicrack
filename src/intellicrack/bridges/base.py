# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Base protocol for tool bridges.

This module defines the abstract interface that all tool bridge implementations must follow, enabling consistent interaction across Ghidra,
x64dbg, Frida, Cutter/Rizin, and other reverse engineering tools.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from intellicrack.core.types import (
        BinaryInfo,
        BreakpointInfo,
        CrossReference,
        ExportInfo,
        FunctionInfo,
        HookInfo,
        ImportInfo,
        MemoryRegion,
        ModuleInfo,
        PatchInfo,
        RegisterState,
        StringInfo,
        ThreadInfo,
        ToolDefinition,
        ToolName,
    )

__all__ = [
    "BinaryOperationsBridge",
    "BridgeCapabilities",
    "BridgeState",
    "DebuggerBridge",
    "DisassemblyLine",
    "DynamicAnalysisBridge",
    "InstrumentationBridge",
    "MemorySearchResult",
    "StackFrame",
    "StaticAnalysisBridge",
    "ToolBridgeBase",
    "WatchpointInfo",
]

_ERR_MUST_OVERRIDE = "must override method"


@dataclass
class DisassemblyLine:
    """Single line of disassembly output.

    Attributes:
        address: Virtual address of the instruction.
        bytes_str: Raw bytes of the instruction as a hex string.
        mnemonic: Assembly mnemonic (e.g. MOV, JMP).
        operands: Instruction operands as a string.
        comment: Optional comment at this line.
    """

    address: int
    bytes_str: str
    mnemonic: str
    operands: str
    comment: str | None = None


@dataclass
class MemorySearchResult:
    """Result from a memory pattern search.

    Attributes:
        address: Virtual address of the match.
        matched_bytes: Matched bytes as a hex string.
        context_before: Bytes preceding the match as a hex string.
        context_after: Bytes following the match as a hex string.
    """

    address: int
    matched_bytes: str
    context_before: str
    context_after: str


@dataclass
class StackFrame:
    """Single stack frame in a call stack.

    Attributes:
        index: Frame index (0 = top/current).
        address: Instruction pointer for this frame.
        return_address: Return address for this frame.
        frame_pointer: Base/frame pointer (RBP/EBP).
        stack_pointer: Stack pointer (RSP/ESP).
        function_name: Function name if resolved, None otherwise.
        module_name: Module name if resolved, None otherwise.
    """

    index: int
    address: int
    return_address: int
    frame_pointer: int
    stack_pointer: int
    function_name: str | None
    module_name: str | None


@dataclass
class WatchpointInfo:
    """Memory watchpoint information.

    Attributes:
        id: Watchpoint identifier.
        address: Memory address being watched.
        size: Size of the watched region in bytes.
        watch_type: Access type to watch (read, write, or exec).
        enabled: Whether the watchpoint is active.
        hit_count: Number of times the watchpoint has triggered.
    """

    id: int
    address: int
    size: int
    watch_type: str
    enabled: bool
    hit_count: int


@dataclass
class BridgeCapabilities:
    """Describes the capabilities of a tool bridge.

    Attributes:
        supports_static_analysis: Whether the tool supports static analysis.
        supports_dynamic_analysis: Whether the tool supports dynamic analysis.
        supports_decompilation: Whether the tool can decompile to pseudocode.
        supports_debugging: Whether the tool can debug processes.
        supports_patching: Whether the tool can patch binaries.
        supports_scripting: Whether the tool supports custom scripts.
        supports_memory_access: Whether the tool can read/write process memory.
        supported_architectures: List of supported CPU architectures.
        supported_formats: List of supported binary formats.
    """

    supports_static_analysis: bool = False
    supports_dynamic_analysis: bool = False
    supports_decompilation: bool = False
    supports_debugging: bool = False
    supports_patching: bool = False
    supports_scripting: bool = False
    supports_memory_access: bool = False
    supported_architectures: list[str] = field(default_factory=list[str])
    supported_formats: list[str] = field(default_factory=list[str])

    def has_capability(self, capability: str) -> bool:
        """Check if a specific capability is supported.

        Args:
            capability: Name of the capability to check.

        Returns:
            bool: True if the capability is supported.
        """
        return getattr(self, f"supports_{capability}", False)

    def supports_arch(self, arch: str) -> bool:
        """Check if an architecture is supported.

        Args:
            arch: Architecture identifier to check.

        Returns:
            bool: True if the architecture is in the supported set.
        """
        return arch in self.supported_architectures

    def supports_format(self, fmt: str) -> bool:
        """Check if a binary format is supported.

        Args:
            fmt: Binary format identifier to check.

        Returns:
            bool: True if the format is in the supported set.
        """
        return fmt in self.supported_formats


@dataclass
class BridgeState:
    """Current state of a tool bridge.

    Attributes:
        connected: Whether connected to the tool.
        tool_running: Whether the tool process is running.
        binary_loaded: Whether a binary is loaded.
        process_attached: Whether attached to a process.
        target_path: Path to the loaded binary.
        target_pid: PID of attached process.
        last_error: Last error message if any.
    """

    connected: bool = False
    tool_running: bool = False
    binary_loaded: bool = False
    process_attached: bool = False
    target_path: Path | None = None
    target_pid: int | None = None
    last_error: str | None = None

    def is_ready(self) -> bool:
        """Check if bridge is connected and tool is running.

        Returns:
            bool: True if both connected and tool_running are True.
        """
        return self.connected and self.tool_running

    def clear_error(self) -> None:
        """Clear the last error."""
        self.last_error = None


class ToolBridgeBase(abc.ABC):
    """Base class for tool bridges.

    All bridge implementations must inherit from this class and override the methods defined here. This ensures a consistent interface for
    the orchestrator to interact with any reverse engineering tool.
    """

    def __init__(self) -> None:
        self._state: BridgeState = BridgeState()
        self._capabilities: BridgeCapabilities = BridgeCapabilities()
        self._logger = get_logger(f"bridges.{self.__class__.__name__.lower()}").bind(bridge=self.__class__.__name__.lower())

    @property
    @abc.abstractmethod
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName: The tool's name enum value.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @property
    def state(self) -> BridgeState:
        """Get current bridge state.

        Returns:
            BridgeState: Current BridgeState instance.
        """
        return self._state

    @state.setter
    def state(self, value: BridgeState) -> None:
        """Set bridge state.

        Args:
            value: New BridgeState instance to assign.
        """
        self._state = value

    @property
    def capabilities(self) -> BridgeCapabilities:
        """Get bridge capabilities.

        Returns:
            BridgeCapabilities: BridgeCapabilities describing what this tool can do.
        """
        return self._capabilities

    @property
    @abc.abstractmethod
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition: Tool definition with available functions.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the tool bridge.

        Args:
            tool_path: Optional path to tool installation.
                      If None, will auto-detect or download.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    async def shutdown(self) -> None:
        """Shutdown the tool and cleanup resources."""
        self._logger.info("bridge_shutdown", bridge_class=self.__class__.__name__)
        self._state = BridgeState()

    @abc.abstractmethod
    async def is_available(self) -> bool:
        """Check if the tool is installed and available.

        Returns:
            bool: True if the tool is ready.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class StaticAnalysisBridge(ToolBridgeBase):
    """Base class for static analysis tools (Ghidra, Cutter/Rizin).

    Provides interface for binary loading, disassembly, decompilation, and cross-reference analysis without executing the target.
    """

    def __init__(self) -> None:
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho"],
        )

    @abc.abstractmethod
    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary for analysis.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo: Information about the loaded binary.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def analyze(self) -> None:
        """Run full analysis on loaded binary.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex pattern to filter function names.

        Returns:
            list[FunctionInfo]: List of analyzed function information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at specific address.

        Args:
            address: Function address.

        Returns:
            FunctionInfo | None: Function info or None if not found.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            str: Decompiled C pseudocode.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def disassemble(
        self,
        address: int,
        count: int = 20,
    ) -> list[DisassemblyLine]:
        """Disassemble instructions at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            list[DisassemblyLine]: List of disassembly lines.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            list[CrossReference]: List of cross-references to the address.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            list[CrossReference]: List of cross-references from the address.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Returns:
            list[StringInfo]: List of matching strings.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Returns:
            list[int]: List of match addresses.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_imports(self) -> list[ImportInfo]:
        """Get all imported functions.

        Returns:
            list[ImportInfo]: List of import information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_exports(self) -> list[ExportInfo]:
        """Get all exported functions.

        Returns:
            list[ExportInfo]: List of export information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Returns:
            bool: True if rename succeeded.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        Args:
            address: Address for comment.
            comment: Comment text.
            comment_type: Type of comment (EOL, PRE, POST, PLATE).

        Returns:
            bool: True if comment was added.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class DynamicAnalysisBridge(ToolBridgeBase):
    """Base class for dynamic analysis tools (x64dbg, Frida).

    Provides interface for process attachment, memory manipulation, breakpoints, and runtime instrumentation.
    """

    def __init__(self) -> None:
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_dynamic_analysis=True,
            supports_debugging=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe"],
        )

    @abc.abstractmethod
    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def spawn(
        self,
        path: Path,
        args: Sequence[str] | None = None,
    ) -> int:
        """Spawn a new process.

        Args:
            path: Path to executable.
            args: Command line arguments.

        Returns:
            int: PID of spawned process.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def detach(self) -> None:
        """Detach from current process.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Returns:
            bytes: Memory contents.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def write_memory(self, address: int, data: bytes) -> int:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Returns:
            int: Number of bytes written.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Returns:
            list[MemoryRegion]: List of memory regions.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Returns:
            list[MemorySearchResult]: List of matches with context.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class DebuggerBridge(DynamicAnalysisBridge):
    """Base class for full debuggers (x64dbg).

    Extends DynamicAnalysisBridge with breakpoints, stepping, and register manipulation.
    """

    def __init__(self) -> None:
        super().__init__()
        self._capabilities.supports_debugging = True

    @abc.abstractmethod
    async def run(self) -> None:
        """Continue execution.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def pause(self) -> None:
        """Pause execution.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop debugging (terminate process).

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def step_into(self) -> int:
        """Single step into.

        Returns:
            int: New instruction pointer.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def step_over(self) -> int:
        """Single step over.

        Returns:
            int: New instruction pointer.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def step_out(self) -> int:
        """Step out of current function.

        Returns:
            int: New instruction pointer.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def set_breakpoint(
        self,
        address: int,
        bp_type: Literal["software", "hardware", "memory"] = "software",
        condition: str | None = None,
    ) -> int:
        """Set a breakpoint.

        Args:
            address: Address for breakpoint.
            bp_type: Type (software, hardware, memory).
            condition: Optional condition expression.

        Returns:
            int: Breakpoint ID.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Returns:
            bool: True if removed successfully.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Returns:
            list[BreakpointInfo]: List of breakpoint information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Returns:
            RegisterState: Current register state.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name (rax, rbx, etc.).
            value: New value.

        Returns:
            bool: True if set successfully.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Returns:
            list[StackFrame]: List of stack frames.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def disassemble_at(
        self,
        address: int,
        count: int = 10,
    ) -> list[DisassemblyLine]:
        """Disassemble at runtime address.

        Args:
            address: Start address.
            count: Number of instructions.

        Returns:
            list[DisassemblyLine]: List of disassembly lines.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            bytes: Assembled bytes.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class InstrumentationBridge(DynamicAnalysisBridge):
    """Base class for instrumentation tools (Frida).

    Extends DynamicAnalysisBridge with function hooking and script execution capabilities.
    """

    def __init__(self) -> None:
        super().__init__()
        self._capabilities.supports_scripting = True

    @abc.abstractmethod
    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Returns:
            list[ModuleInfo]: List of loaded module information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            list[ExportInfo]: List of export information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Attach a hook to a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: Script code to run on function entry.
            on_leave: Script code to run on function exit.

        Returns:
            HookInfo: Information about the installed hook.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Returns:
            bool: True if hook was removed successfully.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Returns:
            list[HookInfo]: List of active hook information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def execute_script(self, script: str) -> str:
        """Execute custom script code.

        Args:
            script: Script code to execute.

        Returns:
            str: Script execution result.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Intercept a function and replace its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Returns:
            HookInfo: Information about the installed interception hook.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def call_function(
        self,
        address: int,
        args: Sequence[int] | None = None,
    ) -> int:
        """Call a function in the target process.

        Args:
            address: Function address.
            args: Function arguments.

        Returns:
            int: Function return value.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_imports(self, module_name: str) -> list[ImportInfo]:
        """List imports of a module.

        Args:
            module_name: Name of the module.

        Returns:
            list[ImportInfo]: List of import information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_threads(self) -> list[ThreadInfo]:
        """List all threads in the attached process.

        Returns:
            list[ThreadInfo]: List of thread information.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class BinaryOperationsBridge(ToolBridgeBase):
    """Base class for direct binary file operations.

    Provides interface for reading, modifying, and patching binary files without running a full analysis tool.
    """

    def __init__(self) -> None:
        super().__init__()
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_patching=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    @abc.abstractmethod
    async def load_file(self, path: Path) -> BinaryInfo:
        """Load a binary file.

        Args:
            path: Path to the binary.

        Returns:
            BinaryInfo: Information about the loaded binary.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from file.

        Args:
            offset: File offset.
            size: Number of bytes.

        Returns:
            bytes: Bytes read from the file.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to file.

        Args:
            offset: File offset.
            data: Bytes to write.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def apply_patch(self, patch: PatchInfo) -> bool:
        """Apply a patch to the binary.

        Args:
            patch: Patch information.

        Returns:
            bool: True if the patch was applied successfully.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Returns:
            bool: True if the patch was reverted successfully.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def save(self, path: Path | None = None) -> Path:
        """Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Returns:
            Path: Path where the file was saved.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def search_pattern(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """Search for byte pattern in file.

        Args:
            pattern: Byte pattern to find.
            start_offset: Starting offset for search.
            max_results: Maximum results to return.

        Returns:
            list[int]: List of file offsets where the pattern was found.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def calculate_checksum(
        self,
        algorithm: str = "sha256",
    ) -> str:
        """Calculate file checksum.

        Args:
            algorithm: Hash algorithm (md5, sha256).

        Returns:
            str: Hex digest of the file hash.

        Raises:
            RuntimeError: If the subclass does not override this method.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)
