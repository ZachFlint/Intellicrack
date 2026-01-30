"""Base protocol for tool bridges.

This module defines the abstract interface that all tool bridge implementations
must follow, enabling consistent interaction across Ghidra, x64dbg, Frida,
radare2, and other reverse engineering tools.
"""
# ruff: noqa: PLR6301

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict

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
    ToolDefinition,
    ToolError,
    ToolName,
)


_ERR_MUST_OVERRIDE = "must override method"


class DisassemblyLine(TypedDict):
    """Single line of disassembly output."""

    address: int
    bytes: str
    mnemonic: str
    operands: str
    comment: str | None


class MemorySearchResult(TypedDict):
    """Result from a memory pattern search."""

    address: int
    matched_bytes: str
    context_before: str
    context_after: str


class StackFrame(TypedDict):
    """Single stack frame in a call stack."""

    index: int
    address: int
    return_address: int
    frame_pointer: int
    stack_pointer: int
    function_name: str | None
    module_name: str | None


class WatchpointInfo(TypedDict):
    """Memory watchpoint information."""

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
    supported_architectures: list[str] = field(default_factory=list)
    supported_formats: list[str] = field(default_factory=list)


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


class ToolBridgeBase:
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
        self._logger: logging.Logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Note:
            Subclasses must override to return the ToolName enum value.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

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
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Note:
            Subclasses must override to return a ToolDefinition
            with all available functions for this bridge.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the tool bridge.

        Args:
            tool_path: Optional path to tool installation.
                      If None, will auto-detect or download.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del tool_path
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def shutdown(self) -> None:
        """Shutdown the tool and cleanup resources."""
        self._logger.info("bridge_shutdown", extra={"bridge_class": self.__class__.__name__})
        self._state = BridgeState()

    async def is_available(self) -> bool:
        """Check if the tool is installed and available.

        Note:
            Subclasses must override to return True if tool is ready.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)


class StaticAnalysisBridge(ToolBridgeBase):
    """Base class for static analysis tools (Ghidra, radare2).

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

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary for analysis.

        Args:
            path: Path to the binary file.

        Note:
            Subclasses must override to return BinaryInfo with file details.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del path
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def analyze(self) -> None:
        """Run full analysis on loaded binary.

        Raises:
            ToolError: If analysis fails.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex pattern to filter function names.

        Note:
            Subclasses must override to return list of function information.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del filter_pattern
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at specific address.

        Args:
            address: Function address.

        Note:
            Subclasses must override to return function info or None.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Note:
            Subclasses must override to return decompiled C pseudocode.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def disassemble(
        self,
        address: int,
        count: int = 20,
    ) -> list[DisassemblyLine]:
        """Disassemble instructions at address.

        Args:
            address: Start address.
            count: Number of instructions.

        Note:
            Subclasses must override to return list of disassembly lines.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, count
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Note:
            Subclasses must override to return list of cross-references.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Note:
            Subclasses must override to return list of cross-references.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Note:
            Subclasses must override to return matching strings.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del pattern
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Note:
            Subclasses must override to return list of match addresses.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del pattern
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_imports(self) -> list[ImportInfo]:
        """Get all imported functions.

        Note:
            Subclasses must override to return list of import information.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_exports(self) -> list[ExportInfo]:
        """Get all exported functions.

        Note:
            Subclasses must override to return list of export information.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Note:
            Subclasses must override to return True if rename succeeded.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, new_name
        raise ToolError(_ERR_MUST_OVERRIDE)

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

        Note:
            Subclasses must override to return True if comment was added.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, comment, comment_type
        raise ToolError(_ERR_MUST_OVERRIDE)


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

    async def attach(self, pid: int) -> None:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del pid
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def spawn(
        self,
        path: Path,
        args: list[str] | None = None,
    ) -> int:
        """Spawn a new process.

        Args:
            path: Path to executable.
            args: Command line arguments.

        Note:
            Subclasses must override to return PID of spawned process.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del path, args
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def detach(self) -> None:
        """Detach from current process.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def read_memory(self, address: int, size: int) -> bytes:
        """Read process memory.

        Args:
            address: Memory address.
            size: Number of bytes to read.

        Note:
            Subclasses must override to return memory contents.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, size
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def write_memory(self, address: int, data: bytes) -> int:
        """Write to process memory.

        Args:
            address: Memory address.
            data: Bytes to write.

        Note:
            Subclasses must override to return the number of bytes written.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, data
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_memory_regions(self) -> list[MemoryRegion]:
        """Get process memory map.

        Note:
            Subclasses must override to return list of memory regions.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def scan_memory(self, pattern: bytes) -> list[MemorySearchResult]:
        """Scan process memory for a pattern.

        Args:
            pattern: Byte pattern to search for.

        Note:
            Subclasses must override to return list of matches with context.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del pattern
        raise ToolError(_ERR_MUST_OVERRIDE)


class DebuggerBridge(DynamicAnalysisBridge):
    """Base class for full debuggers (x64dbg).

    Extends DynamicAnalysisBridge with breakpoints, stepping,
    and register manipulation.
    """

    def __init__(self) -> None:
        """Initialize debugger bridge."""
        super().__init__()
        self._capabilities.supports_debugging = True

    async def run(self) -> None:
        """Continue execution.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def pause(self) -> None:
        """Pause execution.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def stop(self) -> None:
        """Stop debugging (terminate process).

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def step_into(self) -> int:
        """Single step into.

        Note:
            Subclasses must override to return new instruction pointer.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def step_over(self) -> int:
        """Single step over.

        Note:
            Subclasses must override to return new instruction pointer.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def step_out(self) -> int:
        """Step out of current function.

        Note:
            Subclasses must override to return new instruction pointer.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

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

        Note:
            Subclasses must override to return the breakpoint ID.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, bp_type, condition
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint.

        Args:
            address: Breakpoint address.

        Note:
            Subclasses must override to return True if removed successfully.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_breakpoints(self) -> list[BreakpointInfo]:
        """Get all breakpoints.

        Note:
            Subclasses must override to return list of breakpoint information.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_registers(self) -> RegisterState:
        """Get all register values.

        Note:
            Subclasses must override to return RegisterState with all registers.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def set_register(self, register: str, value: int) -> bool:
        """Set a register value.

        Args:
            register: Register name (rax, rbx, etc.).
            value: New value.

        Note:
            Subclasses must override to return True if set successfully.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del register, value
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_stack_trace(self) -> list[StackFrame]:
        """Get current stack trace.

        Note:
            Subclasses must override to return list of stack frames.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def disassemble_at(
        self,
        address: int,
        count: int = 10,
    ) -> list[DisassemblyLine]:
        """Disassemble at runtime address.

        Args:
            address: Start address.
            count: Number of instructions.

        Note:
            Subclasses must override to return list of disassembly lines.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, count
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Note:
            Subclasses must override to return assembled bytes.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, instruction
        raise ToolError(_ERR_MUST_OVERRIDE)


class InstrumentationBridge(DynamicAnalysisBridge):
    """Base class for instrumentation tools (Frida).

    Extends DynamicAnalysisBridge with function hooking
    and script execution capabilities.
    """

    def __init__(self) -> None:
        """Initialize instrumentation bridge."""
        super().__init__()
        self._capabilities.supports_scripting = True

    async def enumerate_modules(self) -> list[ModuleInfo]:
        """List all loaded modules in the process.

        Note:
            Subclasses must override to return list of ModuleInfo for each
            loaded module in the attached process.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def enumerate_exports(self, module_name: str) -> list[ExportInfo]:
        """List exports of a module.

        Args:
            module_name: Name of the module.

        Note:
            Subclasses must override to return list of ExportInfo for all
            exported symbols from the specified module.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del module_name
        raise ToolError(_ERR_MUST_OVERRIDE)

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

        Note:
            Subclasses must override to return HookInfo describing the
            installed hook on the target function.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del target, on_enter, on_leave
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def remove_hook(self, hook_id: str) -> bool:
        """Remove a previously installed hook.

        Args:
            hook_id: ID of the hook to remove.

        Note:
            Subclasses must override to return True if hook was removed
            successfully, False otherwise.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del hook_id
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def get_hooks(self) -> list[HookInfo]:
        """Get all active hooks.

        Note:
            Subclasses must override to return list of HookInfo for all
            currently installed hooks in the process.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def execute_script(self, script: str) -> str:
        """Execute custom script code.

        Args:
            script: Script code to execute.

        Note:
            Subclasses must override to return the script execution result
            as a string.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del script
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def intercept_return(self, target: str, return_value: int) -> HookInfo:
        """Hook a function and modify its return value.

        Args:
            target: Function to hook.
            return_value: Value to return instead.

        Note:
            Subclasses must override to return HookInfo describing the
            installed return value interception hook.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del target, return_value
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def call_function(
        self,
        address: int,
        args: list[int] | None = None,
    ) -> int:
        """Call a function in the target process.

        Args:
            address: Function address.
            args: Function arguments.

        Note:
            Subclasses must override to return the integer return value
            from calling the function at the specified address.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del address, args
        raise ToolError(_ERR_MUST_OVERRIDE)


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

    async def load_file(self, path: Path) -> BinaryInfo:
        """Load a binary file.

        Args:
            path: Path to the binary.

        Note:
            Subclasses must override to return BinaryInfo with file details
            including format, architecture, sections, and entry point.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del path
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes from file.

        Args:
            offset: File offset.
            size: Number of bytes.

        Note:
            Subclasses must override to return bytes read from the file
            at the specified offset.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del offset, size
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def write_bytes(self, offset: int, data: bytes) -> None:
        """Write bytes to file.

        Args:
            offset: File offset.
            data: Bytes to write.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del offset, data
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def apply_patch(self, patch: PatchInfo) -> bool:
        """Apply a patch to the binary.

        Args:
            patch: Patch information.

        Note:
            Subclasses must override to return True if the patch was
            applied successfully, False otherwise.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del patch
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a previously applied patch.

        Args:
            patch: Patch to revert.

        Note:
            Subclasses must override to return True if the patch was
            reverted successfully, False otherwise.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del patch
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def save(self, path: Path | None = None) -> Path:
        """Save the binary to file.

        Args:
            path: Optional new path. Uses original if None.

        Note:
            Subclasses must override to return the Path where the file
            was saved.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del path
        raise ToolError(_ERR_MUST_OVERRIDE)

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

        Note:
            Subclasses must override to return list of file offsets where
            the byte pattern was found.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del pattern, start_offset, max_results
        raise ToolError(_ERR_MUST_OVERRIDE)

    async def calculate_checksum(
        self,
        algorithm: str = "sha256",
    ) -> str:
        """Calculate file checksum.

        Args:
            algorithm: Hash algorithm (md5, sha1, sha256).

        Note:
            Subclasses must override to return the hex digest of the
            file hash using the specified algorithm.

        Raises:
            ToolError: Must be overridden by subclass.
        """
        del algorithm
        raise ToolError(_ERR_MUST_OVERRIDE)
