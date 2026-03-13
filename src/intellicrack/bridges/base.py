# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Base protocol for tool bridges.

This module defines the abstract interface that all tool bridge implementations
must follow, enabling consistent interaction across Ghidra, x64dbg, Frida,
Cutter/Rizin, and other reverse engineering tools.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from ..core.logging import get_logger


if TYPE_CHECKING:
    import logging
    from collections.abc import Sequence
    from pathlib import Path

    from ..core.types import (
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
        bytes_str: Hex representation of instruction bytes.
        mnemonic: Instruction mnemonic (e.g., 'mov', 'jmp').
        operands: Instruction operands (e.g., 'rax, rbx').
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
        matched_bytes: The actual bytes that matched (hex string).
        context_before: Bytes preceding the match (hex string).
        context_after: Bytes following the match (hex string).
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
        address: Instruction pointer in this frame.
        return_address: Return address for this frame.
        frame_pointer: Base/Frame pointer (RBP/EBP).
        stack_pointer: Stack pointer (RSP/ESP).
        function_name: Name of the function if known.
        module_name: Name of the module if known.
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
        size: Size of the watched region.
        watch_type: Type of access to watch (read/write/exec).
        enabled: Whether the watchpoint is active.
        hit_count: Number of times hit.
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
            True if the capability is supported.
        """
        return getattr(self, f"supports_{capability}", False)

    def supports_arch(self, arch: str) -> bool:
        """Check if an architecture is supported.

        Args:
            arch: Architecture identifier to check.

        Returns:
            True if the architecture is in the supported set.
        """
        return arch in self.supported_architectures

    def supports_format(self, fmt: str) -> bool:
        """Check if a binary format is supported.

        Args:
            fmt: Binary format identifier to check.

        Returns:
            True if the format is in the supported set.
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
            True if both connected and tool_running are True.
        """
        return self.connected and self.tool_running

    def clear_error(self) -> None:
        """Clear the last error."""
        self.last_error = None


class ToolBridgeBase(abc.ABC):
    """Base class for tool bridges.

    All bridge implementations must inherit from this class and override
    the methods defined here. This ensures a consistent interface for
    the orchestrator to interact with any reverse engineering tool.

    Attributes:
        _state: Current state of the bridge.
        _capabilities: Capabilities of the tool.
        _logger: Logger instance for this bridge.
    """

    def __init__(self) -> None:
        """Initialize the base bridge."""
        self._state: BridgeState = BridgeState()
        self._capabilities: BridgeCapabilities = BridgeCapabilities()
        self._logger: logging.Logger = get_logger(f"bridges.{self.__class__.__name__.lower()}")

    @property
    @abc.abstractmethod
    def name(self) -> ToolName:
        """Get the tool's name.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the ToolName enum value.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @property
    def state(self) -> BridgeState:
        """Get current bridge state.

        Returns:
            Current BridgeState instance.
        """
        return self._state

    @property
    def capabilities(self) -> BridgeCapabilities:
        """Get bridge capabilities.

        Returns:
            BridgeCapabilities describing what this tool can do.
        """
        return self._capabilities

    @property
    @abc.abstractmethod
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return a ToolDefinition
            with all available functions for this bridge.
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
        self._logger.info("bridge_shutdown", extra={"bridge_class": self.__class__.__name__})
        self._state = BridgeState()

    @abc.abstractmethod
    async def is_available(self) -> bool:
        """Check if the tool is installed and available.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if tool is ready.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class StaticAnalysisBridge(ToolBridgeBase):
    """Base class for static analysis tools (Ghidra, Cutter/Rizin).

    Provides interface for binary loading, disassembly, decompilation,
    and cross-reference analysis without executing the target.
    """

    def __init__(self) -> None:
        """Initialize static analysis bridge."""
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return BinaryInfo with file details.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of function information.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at specific address.

        Args:
            address: Function address.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return function info or None.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return decompiled C pseudocode.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of disassembly lines.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of cross-references.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of cross-references.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return matching strings.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of match addresses.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_imports(self) -> list[ImportInfo]:
        """Get all imported functions.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of import information.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_exports(self) -> list[ExportInfo]:
        """Get all exported functions.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of export information.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if rename succeeded.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if comment was added.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class DynamicAnalysisBridge(ToolBridgeBase):
    """Base class for dynamic analysis tools (x64dbg, Frida).

    Provides interface for process attachment, memory manipulation,
    breakpoints, and runtime instrumentation.
    """

    def __init__(self) -> None:
        """Initialize dynamic analysis bridge."""
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return PID of spawned process.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return memory contents.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def write_memory(self, address: int, data: bytes) -> int:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the number of bytes written.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of memory regions.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of matches with context.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class DebuggerBridge(DynamicAnalysisBridge):
    """Base class for full debuggers (x64dbg).

    Extends DynamicAnalysisBridge with breakpoints, stepping,
    and register manipulation.
    """

    def __init__(self) -> None:
        """Initialize debugger bridge."""
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return new instruction pointer.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def step_over(self) -> int:
        """Single step over.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return new instruction pointer.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def step_out(self) -> int:
        """Step out of current function.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return new instruction pointer.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the breakpoint ID.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if removed successfully.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of breakpoint information.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return RegisterState with all registers.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name (rax, rbx, etc.).
            value: New value.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if set successfully.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of stack frames.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of disassembly lines.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return assembled bytes.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class InstrumentationBridge(DynamicAnalysisBridge):
    """Base class for instrumentation tools (Frida).

    Extends DynamicAnalysisBridge with function hooking
    and script execution capabilities.
    """

    def __init__(self) -> None:
        """Initialize instrumentation bridge."""
        super().__init__()
        self._capabilities.supports_scripting = True

    @abc.abstractmethod
    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of ModuleInfo for each
            loaded module in the attached process.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of ExportInfo for all
            exported symbols from the specified module.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def hook_function(
        self,
        target: str,
        on_enter: str | None = None,
        on_leave: str | None = None,
    ) -> HookInfo:
        """Hook a function by name or address.

        Args:
            target: Function name (module!func) or hex address.
            on_enter: Script code to run on function entry.
            on_leave: Script code to run on function exit.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return HookInfo describing the
            installed hook on the target function.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if hook was removed
            successfully, False otherwise.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of HookInfo for all
            currently installed hooks in the process.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def execute_script(self, script: str) -> str:
        """Execute custom script code.

        Args:
            script: Script code to execute.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the script execution result
            as a string.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Hook a function and modify its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return HookInfo describing the
            installed return value interception hook.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the integer return value
            from calling the function at the specified address.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_imports(self, module_name: str) -> list[ImportInfo]:
        """List imports of a module.

        Args:
            module_name: Name of the module.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of ImportInfo for all
            imported symbols from the specified module.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def enumerate_threads(self) -> list[ThreadInfo]:
        """List all threads in the attached process.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of ThreadInfo for each
            thread in the attached process.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)


class BinaryOperationsBridge(ToolBridgeBase):
    """Base class for direct binary file operations.

    Provides interface for reading, modifying, and patching
    binary files without running a full analysis tool.
    """

    def __init__(self) -> None:
        """Initialize binary operations bridge."""
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return BinaryInfo with file details
            including format, architecture, sections, and entry point.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from file.

        Args:
            offset: File offset.
            size: Number of bytes.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return bytes read from the file
            at the specified offset.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if the patch was
            applied successfully, False otherwise.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return True if the patch was
            reverted successfully, False otherwise.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)

    @abc.abstractmethod
    async def save(self, path: Path | None = None) -> Path:
        """Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the Path where the file
            was saved.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return list of file offsets where
            the byte pattern was found.
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

        Raises:
            RuntimeError: If the subclass does not override this method.

        Note:
            Subclasses must override to return the hex digest of the
            file hash using the specified algorithm.
        """
        raise RuntimeError(_ERR_MUST_OVERRIDE)
