# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Core type definitions for Intellicrack.

This module contains all the fundamental dataclasses, enums, and type definitions used throughout the Intellicrack application.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable


if TYPE_CHECKING:
    from pathlib import Path


@runtime_checkable
class HexDocumentLike(Protocol):
    """Protocol for objects providing hex document read access."""

    def read(self, offset: int, length: int) -> list[int]:
        """Read bytes from the document.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to read.

        Returns:
            list[int]: List of byte values.
        """
        _ = (self, offset, length)
        return []

    def length(self) -> int:
        """Get the total length of the document in bytes.

        Returns:
            int: Document length.
        """
        _ = self
        return 0


@runtime_checkable
class HexDocumentFull(HexDocumentLike, Protocol):
    """Protocol for full HexDocument with template and write support."""

    def write(self, offset: int, data: bytes) -> None:
        """Write bytes to the document.

        Args:
            offset: Byte offset to write at.
            data: Bytes to write.
        """
        _ = (self, offset, data)

    def list_templates(self) -> list[tuple[str, str]]:
        """List available templates.

        Returns:
            list[tuple[str, str]]: List of (name, description) tuples.
        """
        _ = self
        return []

    def list_templates_detailed(self) -> list[object]:
        """List templates with full detail objects.

        Returns:
            list[object]: List of template detail objects.
        """
        _ = self
        return []

    def register_json_template(self, name: str, json_str: str) -> None:
        """Register a JSON-defined template.

        Args:
            name: Template name.
            json_str: JSON string defining the template.
        """
        _ = (self, name, json_str)

    def remove_template(self, name: str) -> None:
        """Remove a registered template.

        Args:
            name: Template name to remove.
        """
        _ = (self, name)

    def export_template_json(self, name: str) -> str:
        """Export a template as a JSON string.

        Args:
            name: Template name to export.

        Returns:
            str: JSON representation of the template.
        """
        _ = (self, name)
        return ""

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Inspect data at the given offset.

        Args:
            offset: Byte offset to inspect.

        Returns:
            dict[str, object]: Inspection results.
        """
        _ = (self, offset)
        return {}


@runtime_checkable
class CompiledYaraRules(Protocol):
    """Protocol for compiled YARA rules objects."""

    def match(
        self,
        data: bytes | None = None,
        filepath: str | None = None,
        timeout: int = 60,
    ) -> list[object]:
        """Match rules against data or a file.

        Args:
            data: Binary data to scan.
            filepath: File path to scan.
            timeout: Scan timeout in seconds.

        Returns:
            list[object]: List of match result objects.
        """
        _ = (self, data, filepath, timeout)
        return []


__all__: list[str] = [
    "ApiResolverMatch",
    "AttachError",
    "AuthenticationError",
    "BinaryInfo",
    "BlockInfo",
    "BreakpointInfo",
    "BridgeAnalysisSummary",
    "CacheConfig",
    "ChildProcessInfo",
    "ClassInfo",
    "CommentInfo",
    "CompiledYaraRules",
    "ConfigurationError",
    "ConfirmationLevel",
    "CrashInfo",
    "CrossReference",
    "DataTypeInfo",
    "ExportInfo",
    "FlagInfo",
    "FridaDeviceInfo",
    "FunctionInfo",
    "GadgetInfo",
    "HeaderInfo",
    "HexDocumentFull",
    "HexDocumentLike",
    "HookInfo",
    "ImportInfo",
    "InitializationError",
    "IntellicrackError",
    "LibraryInfo",
    "MemoryRegion",
    "Message",
    "ModelInfo",
    "ModelNotFoundError",
    "ModuleInfo",
    "ParameterInfo",
    "PatchInfo",
    "ProcessInfo",
    "ProviderCredentials",
    "ProviderError",
    "ProviderName",
    "RateLimitError",
    "RegisterState",
    "RelocationInfo",
    "ResourceInfo",
    "SandboxError",
    "SectionInfo",
    "SegmentInfo",
    "Session",
    "StalkerEvent",
    "StalkerTrace",
    "StringInfo",
    "SymbolInfo",
    "ThinkingConfig",
    "ThreadInfo",
    "ToolCall",
    "ToolChoice",
    "ToolChoiceMode",
    "ToolDefinition",
    "ToolError",
    "ToolFunction",
    "ToolName",
    "ToolNotFoundError",
    "ToolParameter",
    "ToolResult",
    "ToolState",
    "VariableInfo",
    "VtableInfo",
]


class ToolName(enum.Enum):
    """Enumeration of all supported reverse engineering tools."""

    GHIDRA = "ghidra"
    X64DBG = "x64dbg"
    FRIDA = "frida"
    CUTTER = "cutter"
    PROCESS = "process"
    SANDBOX = "sandbox"
    HEX_EDITOR = "hex_editor"


class ProviderName(enum.Enum):
    """Enumeration of all supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"
    HUGGINGFACE = "huggingface"
    GROK = "grok"
    LOCAL_TRANSFORMERS = "local_transformers"


class ConfirmationLevel(enum.Enum):
    """User confirmation requirement levels for destructive operations."""

    NONE = "none"
    DESTRUCTIVE = "destructive"
    ALL = "all"


class ToolChoiceMode(enum.Enum):
    """How the LLM should decide whether to call a tool.

    Attributes:
        AUTO: Let the model decide whether to call tools.
        NONE: Prevent the model from calling any tools.
        REQUIRED: Force the model to call at least one tool.
        SPECIFIC: Force the model to call a specific named tool.
    """

    AUTO = "auto"
    NONE = "none"
    REQUIRED = "required"
    SPECIFIC = "specific"


@dataclass
class ToolChoice:
    """Specifies how the LLM should select tools.

    Attributes:
        mode: The tool selection mode.
        function_name: Required when mode is SPECIFIC, ignored otherwise.
    """

    mode: ToolChoiceMode
    function_name: str | None = None


@dataclass
class ThinkingConfig:
    """Configuration for extended thinking (chain-of-thought).

    Attributes:
        enabled: Whether extended thinking is active.
        budget_tokens: Maximum tokens the model may use for thinking.
    """

    enabled: bool = False
    budget_tokens: int = 10000


@dataclass
class CacheConfig:
    """Configuration for prompt caching.

    Attributes:
        enabled: Whether prompt caching is active.
        ttl_seconds: Time-to-live for cached content in seconds.
    """

    enabled: bool = False
    ttl_seconds: int = 3600


@dataclass
class ToolCall:
    """Represents a tool/function call request from the LLM.

    Attributes:
        id: Unique identifier for this tool call.
        tool_name: Name of the tool being called.
        function_name: Specific function within the tool.
        arguments: Dictionary of function arguments.
    """

    id: str
    tool_name: str
    function_name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Result of executing a tool call.

    Attributes:
        call_id: ID of the corresponding ToolCall.
        success: Whether the operation succeeded.
        result: The result data if successful.
        error: Error message if failed.
        duration_ms: Execution time in milliseconds.
    """

    call_id: str
    success: bool
    result: object
    error: str | None
    duration_ms: float


@dataclass
class Message:
    """A single message in the conversation.

    Attributes:
        role: The message sender role.
        content: Text content of the message.
        tool_calls: Tool calls made by this message (if assistant).
        tool_results: Results of tool calls (if tool response).
        thinking_content: Extended thinking text from the model, if any.
        timestamp: When the message was created.
    """

    role: Literal["user", "assistant", "system", "tool"]
    content: str
    tool_calls: list[ToolCall] | None = None
    tool_results: list[ToolResult] | None = None
    thinking_content: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))


@dataclass
class SectionInfo:
    """PE/ELF section information.

    Attributes:
        name: Section name (e.g., ".text", ".data").
        virtual_address: Address when loaded in memory.
        virtual_size: Size in memory.
        raw_size: Size on disk.
        characteristics: Section flags/permissions.
        entropy: Shannon entropy (0-8, higher = more random/encrypted).
    """

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float

    @property
    def is_executable(self) -> bool:
        """Check if section is executable.

        Returns:
            bool: True if the section has the executable characteristic flag set.
        """
        return bool(self.characteristics & 0x20000000)

    @property
    def is_readable(self) -> bool:
        """Check if section is readable.

        Returns:
            bool: True if the section has the readable characteristic flag set.
        """
        return bool(self.characteristics & 0x40000000)

    @property
    def is_writable(self) -> bool:
        """Check if section is writable.

        Returns:
            bool: True if the section has the writable characteristic flag set.
        """
        return bool(self.characteristics & 0x80000000)


@dataclass
class ImportInfo:
    """Import table entry.

    Attributes:
        dll: Name of the imported DLL/library.
        function: Name of the imported function.
        ordinal: Import ordinal if by ordinal.
        address: Address of the import thunk.
    """

    dll: str
    function: str
    ordinal: int | None
    address: int


@dataclass
class ExportInfo:
    """Export table entry.

    Attributes:
        name: Name of the exported symbol.
        ordinal: Export ordinal number.
        address: Virtual address of the export.
    """

    name: str
    ordinal: int
    address: int


@dataclass
class BinaryInfo:
    """Information about a loaded binary file.

    Attributes:
        path: Filesystem path to the binary.
        name: Filename without path.
        size: File size in bytes.
        md5: MD5 hash of the file.
        sha256: SHA-256 hash of the file.
        file_type: Detected file type (PE, ELF, Mach-O, etc.).
        architecture: Target architecture (x86, x64, ARM, etc.).
        is_64bit: Whether it's a 64-bit binary.
        entry_point: Entry point address.
        sections: List of sections in the binary.
        imports: List of imported functions.
        exports: List of exported functions.
    """

    path: Path
    name: str
    size: int
    md5: str
    sha256: str
    file_type: str
    architecture: str
    is_64bit: bool
    entry_point: int
    sections: list[SectionInfo]
    imports: list[ImportInfo]
    exports: list[ExportInfo]


@dataclass
class ParameterInfo:
    """Function parameter information.

    Attributes:
        name: Parameter name.
        type: Parameter type.
        size: Size in bytes.
        location: Where stored (register, stack, etc.).
    """

    name: str
    type: str
    size: int
    location: str


@dataclass
class VariableInfo:
    """Local variable information.

    Attributes:
        name: Variable name.
        type: Variable type.
        offset: Stack offset or register.
        size: Size in bytes.
    """

    name: str
    type: str
    offset: int
    size: int


@dataclass
class DataTypeInfo:
    """Ghidra data type details for a program address.

    Attributes:
        address: Address where the data type is defined.
        name: Display name of the data type.
        category: Data type category path.
        size: Size in bytes of the data type.
        is_pointer: Whether the data type is a pointer.
        is_array: Whether the data type is an array.
        array_length: Array length if this is an array.
        base_type: Base element type if pointer or array.
    """

    address: int
    name: str
    category: str
    size: int
    is_pointer: bool
    is_array: bool
    array_length: int | None
    base_type: str | None

    @property
    def display_type(self) -> str:
        """Get the display string for the data type.

        Returns:
            str: Formatted type string including pointer or array notation.
        """
        if self.is_pointer and self.base_type:
            return f"{self.base_type} *"
        if self.is_array and self.base_type and self.array_length is not None:
            return f"{self.base_type}[{self.array_length}]"
        return self.name


@dataclass
class FunctionInfo:
    """Analyzed function information.

    Attributes:
        name: Function name (may be auto-generated).
        address: Function start address.
        size: Function size in bytes.
        calling_convention: Calling convention (cdecl, stdcall, etc.).
        return_type: Return type.
        parameters: List of parameters.
        local_variables: List of local variables.
        decompiled_code: Decompiled C pseudocode if available.
        disassembly: Disassembly listing if available.
    """

    name: str
    address: int
    size: int
    calling_convention: str
    return_type: str
    parameters: list[ParameterInfo]
    local_variables: list[VariableInfo]
    decompiled_code: str | None = None
    disassembly: str | None = None

    @property
    def has_code(self) -> bool:
        """Check if code is available.

        Returns:
            bool: True if decompiled code or disassembly is present.
        """
        return bool(self.decompiled_code or self.disassembly)

    @property
    def summary(self) -> str:
        """Get function summary.

        Returns:
            str: Summary string with name, address, convention, and variable count.
        """
        vars_count = len(self.local_variables)
        return f"{self.name}@{hex(self.address)} ({self.calling_convention}, {vars_count} vars)"


@dataclass
class CrossReference:
    """Cross-reference information.

    Attributes:
        from_address: Source address of the reference.
        to_address: Target address being referenced.
        ref_type: Type of reference.
        from_function: Source function name if known.
        to_function: Target function name if known.
    """

    from_address: int
    to_address: int
    ref_type: Literal["call", "jump", "data", "read", "write"]
    from_function: str | None
    to_function: str | None

    def __str__(self) -> str:
        """Get string representation of the cross reference.

        Returns:
            str: Formatted cross-reference showing type, source, and destination.
        """
        src = self.from_function or hex(self.from_address)
        dst = self.to_function or hex(self.to_address)
        return f"[{self.ref_type}] {src} -> {dst}"


@dataclass
class StringInfo:
    """String found in binary.

    Attributes:
        address: Address where string is located.
        value: The string content.
        encoding: String encoding.
        section: Section containing the string.
    """

    address: int
    value: str
    encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be"]
    section: str


@dataclass
class BridgeAnalysisSummary:
    """Aggregated analysis results from connected bridges.

    Attributes:
        binary_name: Name of the analyzed binary.
        strings: Strings extracted from the binary.
        imports: Import table entries.
        exports: Export table entries.
        sections: Binary sections.
        functions: Analyzed functions from static analysis bridges.
        format_info: Detected file format description.
        architecture: Target architecture.
        source_bridges: Names of bridges that contributed data.
        analysis_notes: Notes and observations from the aggregation.
    """

    binary_name: str
    strings: list[StringInfo]
    imports: list[ImportInfo]
    exports: list[ExportInfo]
    sections: list[SectionInfo]
    functions: list[FunctionInfo]
    format_info: str
    architecture: str
    source_bridges: list[str]
    analysis_notes: list[str]


@dataclass
class BreakpointInfo:
    """Debugger breakpoint.

    Attributes:
        id: Breakpoint ID.
        address: Address of the breakpoint.
        bp_type: Type of breakpoint.
        enabled: Whether breakpoint is active.
        hit_count: Number of times breakpoint was hit.
        condition: Conditional expression if any.
    """

    id: int
    address: int
    bp_type: Literal["software", "hardware", "memory"]
    enabled: bool
    hit_count: int
    condition: str | None = None

    def __str__(self) -> str:
        """Get string representation of the breakpoint.

        Returns:
            str: Formatted breakpoint info with ID, address, type, and hit count.
        """
        status = "enabled" if self.enabled else "disabled"
        return f"BP#{self.id} @ {hex(self.address)} ({self.bp_type}): {status}, hit {self.hit_count} times"


@dataclass
class RegisterState:
    """CPU register state (x64).

    Attributes:
        rax: General purpose register RAX.
        rbx: General purpose register RBX.
        rcx: General purpose register RCX.
        rdx: General purpose register RDX.
        rsi: General purpose register RSI.
        rdi: General purpose register RDI.
        rbp: Base pointer register.
        rsp: Stack pointer register.
        rip: Instruction pointer register.
        r8: General purpose register R8.
        r9: General purpose register R9.
        r10: General purpose register R10.
        r11: General purpose register R11.
        r12: General purpose register R12.
        r13: General purpose register R13.
        r14: General purpose register R14.
        r15: General purpose register R15.
        rflags: Flags register.
        cs: Code segment register.
        ds: Data segment register.
        es: Extra segment register.
        fs: FS segment register.
        gs: GS segment register.
        ss: Stack segment register.
    """

    rax: int
    rbx: int
    rcx: int
    rdx: int
    rsi: int
    rdi: int
    rbp: int
    rsp: int
    rip: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    rflags: int
    cs: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int

    def __getitem__(self, key: str) -> int:
        """Access register by name.

        Args:
            key: Register name.

        Returns:
            int: Register value.

        Raises:
            KeyError: If register name is invalid.
        """
        if hasattr(self, key):
            val = getattr(self, key)
            if isinstance(val, int):
                return val
        raise KeyError(key)

    def get_gpr_dict(self) -> dict[str, int]:
        """Get general purpose registers.

        Returns:
            dict[str, int]: Dictionary of GPR names and values.
        """
        return {
            "rax": self.rax,
            "rbx": self.rbx,
            "rcx": self.rcx,
            "rdx": self.rdx,
            "rsi": self.rsi,
            "rdi": self.rdi,
            "rbp": self.rbp,
            "rsp": self.rsp,
            "r8": self.r8,
            "r9": self.r9,
            "r10": self.r10,
            "r11": self.r11,
            "r12": self.r12,
            "r13": self.r13,
            "r14": self.r14,
            "r15": self.r15,
        }

    def get_segment_registers(self) -> dict[str, int]:
        """Get segment registers.

        Returns:
            dict[str, int]: Dictionary of segment register names and values.
        """
        return {
            "cs": self.cs,
            "ds": self.ds,
            "es": self.es,
            "fs": self.fs,
            "gs": self.gs,
            "ss": self.ss,
        }


@dataclass
class MemoryRegion:
    """Process memory region.

    Attributes:
        base_address: Start address of the region.
        size: Size of the region in bytes.
        protection: Memory protection flags.
        state: Memory state (committed, reserved, free).
        type: Memory type (private, mapped, image).
        module_name: Module name if this is an image.
    """

    base_address: int
    size: int
    protection: str
    state: str
    type: str
    module_name: str | None


@dataclass
class ThreadInfo:
    """Thread information.

    Attributes:
        tid: Thread ID.
        start_address: Thread start address.
        state: Thread state.
        priority: Thread priority.
    """

    tid: int
    start_address: int
    state: str
    priority: int

    def __str__(self) -> str:
        """Get string representation of the thread.

        Returns:
            str: Formatted thread info with TID, state, priority, and address.
        """
        return f"Thread {self.tid} ({self.state}, prio={self.priority}) @ {hex(self.start_address)}"


@dataclass
class ModuleInfo:
    """Loaded module information.

    Attributes:
        name: Module filename.
        path: Full path to module.
        base_address: Base address in process.
        size: Module size in memory.
        entry_point: Module entry point.
    """

    name: str
    path: Path
    base_address: int
    size: int
    entry_point: int


@dataclass
class ProcessInfo:
    """Running process information.

    Attributes:
        pid: Process ID.
        name: Process name.
        path: Path to executable.
        command_line: Command line arguments.
        parent_pid: Parent process ID.
        threads: List of threads.
        modules: List of loaded modules.
    """

    pid: int
    name: str
    path: Path | None
    command_line: str | None
    parent_pid: int
    threads: list[ThreadInfo]
    modules: list[ModuleInfo]


@dataclass
class HookInfo:
    """Frida hook information.

    Attributes:
        id: Unique hook identifier.
        target: Target function or address.
        address: Resolved address if known.
        script_id: ID of the script containing the hook.
        active: Whether the hook is currently active.
    """

    id: str
    target: str
    address: int | None
    script_id: str
    active: bool


@dataclass
class PatchInfo:
    """Binary patch information.

    Attributes:
        address: Address where patch is applied.
        original_bytes: Original bytes before patching.
        new_bytes: New bytes after patching.
        description: Description of what the patch does.
        applied: Whether the patch has been applied.
    """

    address: int
    original_bytes: bytes
    new_bytes: bytes
    description: str
    applied: bool


@dataclass
class SymbolInfo:
    """Debug symbol information resolved from an address.

    Attributes:
        name: Symbol name.
        address: Symbol address.
        module_name: Module containing the symbol.
        file_name: Source file name if available.
        line_number: Source line number if available.
    """

    name: str
    address: int
    module_name: str | None
    file_name: str | None
    line_number: int | None


@dataclass
class LibraryInfo:
    """Linked library information from binary analysis.

    Attributes:
        name: Library file name or path.
    """

    name: str


@dataclass
class HeaderInfo:
    """Binary header field information.

    Attributes:
        name: Header field name.
        value: Header field value as string.
        address: Address of the header field if available.
    """

    name: str
    value: str
    address: int


@dataclass
class RelocationInfo:
    """Relocation table entry.

    Attributes:
        name: Symbol name for the relocation.
        address: Physical address of the relocation.
        type: Relocation type string.
        vaddr: Virtual address of the relocation.
    """

    name: str
    address: int
    type: str
    vaddr: int


@dataclass
class ResourceInfo:
    """Embedded resource information from a binary.

    Attributes:
        name: Resource name or identifier.
        address: Physical address of the resource.
        size: Size of the resource in bytes.
        type: Resource type string.
        language: Resource language identifier.
    """

    name: str
    address: int
    size: int
    type: str
    language: str


@dataclass
class GadgetInfo:
    """ROP gadget information from binary analysis.

    Attributes:
        address: Address of the gadget.
        instructions: Disassembled instruction sequence.
        size: Size of the gadget in bytes.
    """

    address: int
    instructions: str
    size: int


@dataclass
class ClassInfo:
    """Class information from binary analysis.

    Attributes:
        name: Class name.
        address: Address of the class metadata.
        methods: List of method dictionaries with name and address.
        fields: List of field dictionaries with name and offset.
    """

    name: str
    address: int
    methods: list[dict[str, Any]]
    fields: list[dict[str, Any]]


@dataclass
class VtableInfo:
    """Virtual function table information.

    Attributes:
        address: Address of the vtable.
        methods: List of method dictionaries with name and address.
        name: Class or vtable name.
    """

    address: int
    methods: list[dict[str, Any]]
    name: str


@dataclass
class CommentInfo:
    """Comment annotation at a binary address.

    Attributes:
        address: Address of the comment.
        text: Comment text content.
        comment_type: Type of comment (inline, function, etc.).
    """

    address: int
    text: str
    comment_type: str


@dataclass
class FlagInfo:
    """Named flag/label at a binary address.

    Attributes:
        name: Flag name.
        address: Address of the flag.
        size: Size covered by the flag.
    """

    name: str
    address: int
    size: int


@dataclass
class BlockInfo:
    """Basic block information from control flow analysis.

    Attributes:
        address: Start address of the basic block.
        size: Size of the block in bytes.
        jump: Address of the true/unconditional jump target.
        fail: Address of the false/fallthrough target.
        instructions: List of instruction dictionaries in the block.
    """

    address: int
    size: int
    jump: int | None
    fail: int | None
    instructions: list[dict[str, Any]]


@dataclass
class SegmentInfo:
    """Binary segment information (ELF segments, PE sections extended).

    Attributes:
        name: Segment name.
        address: Start address of the segment.
        size: Size of the segment in bytes.
        permissions: Permission string (e.g. 'r-x').
        type: Segment type identifier.
    """

    name: str
    address: int
    size: int
    permissions: str
    type: str


@dataclass
class CrashInfo:
    """Process crash report from Frida.

    Attributes:
        pid: Process ID that crashed.
        process_name: Name of the crashed process.
        summary: Short crash summary.
        report: Full crash report text.
        parameters: Additional crash parameters.
        timestamp: Time when the crash occurred.
    """

    pid: int
    process_name: str
    summary: str
    report: str
    parameters: dict[str, object]
    timestamp: float


@dataclass
class ChildProcessInfo:
    """Information about a child process intercepted by Frida child gating.

    Attributes:
        pid: Child process ID.
        parent_pid: Parent process ID.
        origin: How the child was created (fork, exec, spawn).
        identifier: Application identifier if available.
        path: Executable path if available.
        argv: Command line arguments.
    """

    pid: int
    parent_pid: int
    origin: str
    identifier: str | None
    path: str | None
    argv: list[str]


@dataclass
class StalkerEvent:
    """Single Stalker code tracing event.

    Attributes:
        event_type: Type of event (call, ret, exec, block, compile).
        from_address: Source address.
        to_address: Destination address if applicable.
        depth: Call depth at the time of the event.
    """

    event_type: str
    from_address: int
    to_address: int | None
    depth: int


@dataclass
class StalkerTrace:
    """Complete Stalker trace result for a thread.

    Attributes:
        thread_id: Thread that was traced.
        events: Collected trace events.
        event_count: Total number of events collected.
        duration_ms: Trace duration in milliseconds.
    """

    thread_id: int
    events: list[StalkerEvent]
    event_count: int
    duration_ms: float


@dataclass
class FridaDeviceInfo:
    """Frida device information.

    Attributes:
        id: Device identifier.
        name: Human-readable device name.
        device_type: Device type (local, usb, remote).
    """

    id: str
    name: str
    device_type: str


@dataclass
class FridaProcessEntry:
    """Frida process information.

    Attributes:
        pid: Process identifier.
        name: Process name.
    """

    pid: int
    name: str


@dataclass
class ApiResolverMatch:
    """Result from Frida ApiResolver query.

    Attributes:
        name: Fully qualified API name.
        address: Resolved address of the API.
    """

    name: str
    address: int


@dataclass
class InstructionInfo:
    """Disassembled instruction information from Frida.

    Attributes:
        address: Instruction address.
        next_address: Address of the next instruction.
        size: Size of the instruction in bytes.
        mnemonic: Instruction mnemonic.
        op_str: Operand string.
        string: Full instruction string representation.
    """

    address: int
    next_address: int
    size: int
    mnemonic: str
    op_str: str
    string: str


@dataclass
class SystemCallResult:
    """Result from a SystemFunction call capturing errno/lastError.

    Attributes:
        value: Return value of the function.
        errno: POSIX errno value after the call.
        last_error: Windows GetLastError value after the call.
    """

    value: int
    errno: int
    last_error: int


@dataclass
class FridaApplicationInfo:
    """Frida application information from device enumeration.

    Attributes:
        identifier: Application bundle identifier.
        name: Human-readable application name.
        pid: Process ID (0 if not running).
    """

    identifier: str
    name: str
    pid: int


@dataclass
class ToolState:
    """State of a tool bridge.

    Attributes:
        tool: Which tool this state is for.
        connected: Whether connected to the tool.
        process_attached: Whether attached to a process.
        target_path: Path to the loaded target.
        last_error: Last error message if any.
    """

    tool: ToolName
    connected: bool
    process_attached: bool
    target_path: Path | None
    last_error: str | None


@dataclass
class Session:
    """Complete session state.

    Attributes:
        id: Unique session identifier.
        created_at: When session was created.
        updated_at: When session was last updated.
        binaries: List of loaded binaries.
        active_binary_index: Index of currently active binary.
        provider: Active LLM provider.
        model: Active model ID.
        messages: Conversation history.
        tool_states: State of each tool bridge.
        patches: List of patches applied or pending.
    """

    id: str
    created_at: datetime
    updated_at: datetime
    binaries: list[BinaryInfo]
    active_binary_index: int
    provider: ProviderName
    model: str
    messages: list[Message]
    tool_states: dict[ToolName, ToolState]
    patches: list[PatchInfo]


@dataclass
class ModelInfo:
    """LLM model information.

    Attributes:
        id: Model identifier string.
        name: Human-readable model name.
        provider: Which provider offers this model.
        context_window: Maximum context length in tokens.
        supports_tools: Whether model supports function calling.
        supports_vision: Whether model supports image input.
        supports_streaming: Whether model supports streaming.
        input_cost_per_1m_tokens: Cost per 1M input tokens.
        output_cost_per_1m_tokens: Cost per 1M output tokens.
    """

    id: str
    name: str
    provider: ProviderName
    context_window: int
    supports_tools: bool
    supports_vision: bool
    supports_streaming: bool
    input_cost_per_1m_tokens: float | None
    output_cost_per_1m_tokens: float | None


@dataclass
class ProviderCredentials:
    """Credentials for an LLM provider.

    Attributes:
        api_key: API key for authentication.
        api_base: Custom API base URL if any.
        organization_id: Organization ID for providers that support it.
        project_id: Project ID for providers that support it.
        timeout: Optional HTTP request timeout override in seconds.
    """

    api_key: str | None = None
    api_base: str | None = None
    organization_id: str | None = None
    project_id: str | None = None
    timeout: float | None = None


@dataclass
class ToolParameter:
    """Tool function parameter definition for LLM schema.

    Attributes:
        name: Parameter name.
        type: JSON Schema type (string, integer, etc.).
        description: Description of the parameter.
        required: Whether the parameter is required.
        enum: List of allowed values if enumerated.
        default: Default value if optional.
    """

    name: str
    type: str
    description: str
    required: bool = True
    enum: list[str] | None = None
    default: str | int | float | bool | None = None


@dataclass
class ToolFunction:
    """Tool function definition for LLM.

    Attributes:
        name: Full function name (e.g., "ghidra.decompile").
        description: What the function does.
        parameters: List of parameters.
        returns: Description of return value.
    """

    name: str
    description: str
    parameters: list[ToolParameter]
    returns: str

    @property
    def signature(self) -> str:
        """Get function signature string.

        Returns:
            str: Formatted signature with name, parameters, and return type.
        """
        params = ", ".join(f"{p.name}: {p.type}" for p in self.parameters)
        return f"{self.name}({params}) -> {self.returns}"


@dataclass
class ToolDefinition:
    """Complete tool definition for LLM function calling.

    Attributes:
        tool_name: Which tool this definition is for.
        description: Overall tool description.
        functions: List of available functions.
    """

    tool_name: ToolName
    description: str
    functions: list[ToolFunction]


class IntellicrackError(Exception):
    """Base exception for all Intellicrack errors.

    Args:
        message: Human-readable error description.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        message: Human-readable error description.
        error_code: Optional numeric error code for programmatic handling.
        details: Optional dictionary with additional context.
    """

    message: str
    error_code: int | None
    details: dict[str, Any]

    def __init__(
        self,
        message: str,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class ProviderError(IntellicrackError):
    """Error related to LLM providers.

    Args:
        message: Human-readable error description.
        provider_name: Name of the provider.
        status_code: HTTP status code if applicable.
        response_body: Raw response body for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        provider_name: Name of the provider that raised the error.
        status_code: HTTP status code if applicable.
        response_body: Raw response body for debugging.
    """

    provider_name: str | None
    status_code: int | None
    response_body: str | None

    def __init__(
        self,
        message: str,
        provider_name: str | None = None,
        status_code: int | None = None,
        response_body: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code, details)
        self.provider_name = provider_name
        self.status_code = status_code
        self.response_body = response_body


class AuthenticationError(ProviderError):
    """Authentication failed with provider."""


class RateLimitError(ProviderError):
    """Rate limit exceeded.

    Args:
        message: Human-readable error description.
        retry_after: Seconds until retry is allowed.
        limit_type: Type of rate limit hit.
        provider_name: Name of the provider.
        status_code: HTTP status code if applicable.
        response_body: Raw response body for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        retry_after: Seconds until retry is allowed.
        limit_type: Type of rate limit hit.
    """

    retry_after: float | None
    limit_type: str | None

    def __init__(
        self,
        message: str,
        retry_after: float | None = None,
        limit_type: str | None = None,
        provider_name: str | None = None,
        status_code: int | None = None,
        response_body: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, provider_name, status_code, response_body, error_code, details)
        self.retry_after = retry_after
        self.limit_type = limit_type


class ModelNotFoundError(ProviderError):
    """Requested model not found.

    Args:
        message: Human-readable error description.
        model_name: Name of the model that was not found.
        available_models: List of available model names.
        provider_name: Name of the provider.
        status_code: HTTP status code if applicable.
        response_body: Raw response body for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        model_name: Name of the model that was not found.
        available_models: List of available model names.
    """

    model_name: str | None
    available_models: list[str]

    def __init__(
        self,
        message: str,
        model_name: str | None = None,
        available_models: list[str] | None = None,
        provider_name: str | None = None,
        status_code: int | None = None,
        response_body: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, provider_name, status_code, response_body, error_code, details)
        self.model_name = model_name
        self.available_models = available_models or []


class ToolError(IntellicrackError):
    """Error related to tool bridges.

    Args:
        message: Human-readable error description.
        tool_name: Name of the tool.
        exit_code: Process exit code if applicable.
        stderr: Standard error output for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        tool_name: Name of the tool that raised the error.
        exit_code: Process exit code if applicable.
        stderr: Standard error output for debugging.
    """

    tool_name: str | None
    exit_code: int | None
    stderr: str | None

    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code, details)
        self.tool_name = tool_name
        self.exit_code = exit_code
        self.stderr = stderr


class ToolNotFoundError(ToolError):
    """Tool could not be found or installed.

    Args:
        message: Human-readable error description.
        tool_name: Name of the tool.
        search_paths: Paths that were searched.
        install_hint: Hint for how to install the tool.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        search_paths: Paths that were searched.
        install_hint: Hint for how to install the tool.
    """

    search_paths: list[str]
    install_hint: str | None

    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        search_paths: list[str] | None = None,
        install_hint: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, tool_name, None, None, error_code, details)
        self.search_paths = search_paths or []
        self.install_hint = install_hint


class InitializationError(ToolError):
    """Tool failed to initialize.

    Args:
        message: Human-readable error description.
        tool_name: Name of the tool.
        config_path: Path to configuration that failed.
        missing_dependency: Name of missing dependency.
        exit_code: Process exit code if applicable.
        stderr: Standard error output for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        config_path: Path to configuration that failed.
        missing_dependency: Name of missing dependency.
    """

    config_path: str | None
    missing_dependency: str | None

    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        config_path: str | None = None,
        missing_dependency: str | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, tool_name, exit_code, stderr, error_code, details)
        self.config_path = config_path
        self.missing_dependency = missing_dependency


class AttachError(ToolError):
    """Failed to attach to process.

    Args:
        message: Human-readable error description.
        tool_name: Name of the tool.
        pid: Process ID that could not be attached.
        process_name: Name of the process that could not be attached.
        reason: Specific reason for attachment failure.
        exit_code: Process exit code if applicable.
        stderr: Standard error output for debugging.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        pid: Process ID that could not be attached.
        process_name: Name of the process that could not be attached.
        reason: Specific reason for attachment failure.
    """

    pid: int | None
    process_name: str | None
    reason: str | None

    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        reason: str | None = None,
        exit_code: int | None = None,
        stderr: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, tool_name, exit_code, stderr, error_code, details)
        self.pid = pid
        self.process_name = process_name
        self.reason = reason


class SandboxError(IntellicrackError):
    """Error related to sandbox operations.

    Args:
        message: Human-readable error description.
        sandbox_type: Type of sandbox.
        vm_state: Current VM state when error occurred.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        sandbox_type: Type of sandbox.
        vm_state: Current VM state when error occurred.
    """

    sandbox_type: str | None
    vm_state: str | None

    def __init__(
        self,
        message: str,
        sandbox_type: str | None = None,
        vm_state: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code, details)
        self.sandbox_type = sandbox_type
        self.vm_state = vm_state


class SandboxTimeoutError(SandboxError):
    """Timeout during sandbox command execution.

    Args:
        message: Human-readable error description.
        timeout_seconds: Timeout duration that was exceeded.
        sandbox_type: Type of sandbox.
        vm_state: Current VM state when error occurred.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        timeout_seconds: Timeout duration that was exceeded.
    """

    timeout_seconds: float | None

    def __init__(
        self,
        message: str,
        timeout_seconds: float | None = None,
        sandbox_type: str | None = None,
        vm_state: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, sandbox_type, vm_state, error_code, details)
        self.timeout_seconds = timeout_seconds


class ConfigurationError(IntellicrackError):
    """Configuration error.

    Args:
        message: Human-readable error description.
        config_key: Configuration key that caused the error.
        expected_type: Expected type or format.
        actual_value: Actual value that was provided.
        error_code: Optional numeric error code.
        details: Optional dictionary with additional context.

    Attributes:
        config_key: Configuration key that caused the error.
        expected_type: Expected type or format.
        actual_value: Actual value that was provided.
    """

    config_key: str | None
    expected_type: str | None
    actual_value: str | None

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        expected_type: str | None = None,
        actual_value: str | None = None,
        error_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, error_code, details)
        self.config_key = config_key
        self.expected_type = expected_type
        self.actual_value = actual_value
