"""radare2 bridge for static and dynamic analysis.

This module provides integration with radare2 for disassembly,
analysis, and debugging capabilities using r2pipe.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, Any, Literal, cast, override

import r2pipe

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager, ProcessType
from ..core.types import (
    BinaryInfo,
    CrossReference,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    ParameterInfo,
    SectionInfo,
    StringInfo,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    VariableInfo,
)
from .base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    StaticAnalysisBridge,
)


if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["Radare2Bridge"]

XRefType = Literal["call", "jump", "data", "read", "write"]
StringEncoding = Literal["ascii", "utf-8", "utf-16le", "utf-16be"]

_logger = get_logger("bridges.radare2")

_ERR_FILE_NOT_FOUND = "file not found"
_ERR_LOAD_FAILED = "failed to load binary"
_ERR_NO_BINARY = "no binary loaded"
_ERR_NOT_ANALYZED = "binary not analyzed"
_ERR_CMD_FAILED = "command execution failed"
_ERR_TOOL_NOT_AVAILABLE = "radare2 not available"
_ERR_DECOMPILE_NA = "decompilation not available"
_ERR_ASSEMBLE_FAILED = "failed to assemble instruction"
_ERR_CMD_TIMEOUT = "radare2 command timed out"
_BITS_64 = 64
_R2_COMMAND_TIMEOUT: float = 60.0


def _get_str(data: dict[str, Any], key: str, default: str = "") -> str:
    """Get a string value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not a string.

    Returns:
        String value or default.
    """
    val = data.get(key, default)
    return val if isinstance(val, str) else default


def _get_int(data: dict[str, Any], key: str, default: int = 0) -> int:
    """Get an integer value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not an int.

    Returns:
        Integer value or default.
    """
    val = data.get(key, default)
    return val if isinstance(val, int) else default


def _get_float(data: dict[str, Any], key: str, default: float = 0.0) -> float:
    """Get a float value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.
        default: Default value if key not found or not a float.

    Returns:
        Float value or default.
    """
    val = data.get(key, default)
    return float(val) if isinstance(val, (int, float)) else default


def _get_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    """Get a nested dictionary from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        Dictionary value or empty dict.
    """
    val = data.get(key)
    return cast("dict[str, Any]", val) if isinstance(val, dict) else {}


def _get_optional_str(data: dict[str, Any], key: str) -> str | None:
    """Get an optional string value from a dictionary.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        String value or None.
    """
    val = data.get(key)
    return val if isinstance(val, str) else None


def _get_optional_int(data: dict[str, Any], key: str) -> int | None:
    """Get an optional integer value from a dictionary.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        Integer value or None.
    """
    val = data.get(key)
    return val if isinstance(val, int) else None


def _get_list(data: dict[str, Any], key: str) -> list[Any]:
    """Get a list value from a dictionary with type safety.

    Args:
        data: Dictionary to get value from.
        key: Key to look up.

    Returns:
        List value or empty list.
    """
    val = data.get(key)
    return val if isinstance(val, list) else []


class Radare2Bridge(StaticAnalysisBridge):
    """Bridge for radare2 reverse engineering framework.

    Provides static analysis, disassembly, and debugging capabilities
    using the r2pipe interface.

    Attributes:
        _r2: The r2pipe instance.
        _binary_path: Path to the loaded binary.
        _analyzed: Whether analysis has been run.
    """

    def __init__(self) -> None:
        """Initialize the radare2 bridge."""
        super().__init__()
        self._r2: r2pipe.open_sync | None = None
        self._binary_path: Path | None = None
        self._analyzed: bool = False
        self._r2_pid: int | None = None
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_dynamic_analysis=True,
            supports_decompilation=True,
            supports_debugging=True,
            supports_patching=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc"],
            supported_formats=["pe", "elf", "macho", "raw"],
        )

    async def _r2_cmd(self, command: str) -> str:
        """Execute an r2 command and return a guaranteed string result.

        Args:
            command: The r2 command to execute.

        Returns:
            Command output as string, empty string if None.

        Raises:
            ToolError: If r2 is not connected or command times out.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._r2.cmd, command),
                timeout=_R2_COMMAND_TIMEOUT,
            )
        except TimeoutError:
            _logger.warning(
                "r2_command_timeout",
                extra={"command": command, "timeout": _R2_COMMAND_TIMEOUT},
            )
            msg = f"{_ERR_CMD_TIMEOUT} after {_R2_COMMAND_TIMEOUT}s: {command}"
            raise ToolError(msg) from None
        return "" if result is None else result

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.RADARE2
        """
        return ToolName.RADARE2

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.RADARE2,
            description="radare2 reverse engineering - disassembly, analysis, patching",
            functions=[
                ToolFunction(
                    name="r2.load_binary",
                    description="Load a binary file into radare2",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file",
                            required=True,
                        ),
                    ],
                    returns="BinaryInfo object with file details",
                ),
                ToolFunction(
                    name="r2.analyze",
                    description="Run full analysis on the loaded binary",
                    parameters=[
                        ToolParameter(
                            name="level",
                            type="string",
                            description="Analysis level: quick, normal, deep",
                            required=False,
                            default="normal",
                            enum=["quick", "normal", "deep"],
                        ),
                    ],
                    returns="Analysis completion status",
                ),
                ToolFunction(
                    name="r2.get_functions",
                    description="Get list of all functions",
                    parameters=[
                        ToolParameter(
                            name="filter_pattern",
                            type="string",
                            description="Optional regex to filter function names",
                            required=False,
                        ),
                    ],
                    returns="List of FunctionInfo objects",
                ),
                ToolFunction(
                    name="r2.decompile",
                    description="Decompile a function to pseudocode",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address to decompile",
                            required=True,
                        ),
                    ],
                    returns="Decompiled C-like pseudocode",
                ),
                ToolFunction(
                    name="r2.disassemble",
                    description="Disassemble instructions at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions",
                            required=False,
                            default=20,
                        ),
                    ],
                    returns="Disassembly listing",
                ),
                ToolFunction(
                    name="r2.get_xrefs_to",
                    description="Get cross-references to an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="List of cross-references",
                ),
                ToolFunction(
                    name="r2.get_xrefs_from",
                    description="Get cross-references from an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Source address",
                            required=True,
                        ),
                    ],
                    returns="List of cross-references",
                ),
                ToolFunction(
                    name="r2.search_strings",
                    description="Search for strings in the binary",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="String or regex pattern",
                            required=True,
                        ),
                    ],
                    returns="List of matching strings",
                ),
                ToolFunction(
                    name="r2.search_bytes",
                    description="Search for byte pattern",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern (e.g., '48 8B ?? ??')",
                            required=True,
                        ),
                    ],
                    returns="List of addresses",
                ),
                ToolFunction(
                    name="r2.get_imports",
                    description="Get imported functions",
                    parameters=[],
                    returns="List of imports",
                ),
                ToolFunction(
                    name="r2.get_exports",
                    description="Get exported functions",
                    parameters=[],
                    returns="List of exports",
                ),
                ToolFunction(
                    name="r2.get_sections",
                    description="Get binary sections",
                    parameters=[],
                    returns="List of sections",
                ),
                ToolFunction(
                    name="r2.rename_function",
                    description="Rename a function",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                        ToolParameter(
                            name="new_name",
                            type="string",
                            description="New function name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.add_comment",
                    description="Add a comment at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address for comment",
                            required=True,
                        ),
                        ToolParameter(
                            name="comment",
                            type="string",
                            description="Comment text",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.write_bytes",
                    description="Write bytes at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to write at",
                            required=True,
                        ),
                        ToolParameter(
                            name="hex_data",
                            type="string",
                            description="Hex bytes to write",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="r2.assemble",
                    description="Assemble instruction at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                        ToolParameter(
                            name="instruction",
                            type="string",
                            description="Assembly instruction",
                            required=True,
                        ),
                    ],
                    returns="Assembled bytes",
                ),
                ToolFunction(
                    name="r2.execute",
                    description="Execute raw radare2 command",
                    parameters=[
                        ToolParameter(
                            name="command",
                            type="string",
                            description="radare2 command to execute",
                            required=True,
                        ),
                    ],
                    returns="Command output",
                ),
                ToolFunction(
                    name="r2.get_function",
                    description="Get function at a specific address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Function address",
                            required=True,
                        ),
                    ],
                    returns="FunctionInfo or None if not found",
                ),
                ToolFunction(
                    name="r2.search_bytes_wildcard",
                    description="Search for byte pattern with wildcards",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex pattern like '48 8B ?? ??'",
                            required=True,
                        ),
                    ],
                    returns="List of addresses where pattern found",
                ),
                ToolFunction(
                    name="r2.assemble_at",
                    description="Assemble instruction at address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                        ToolParameter(
                            name="instruction",
                            type="string",
                            description="Assembly instruction to assemble",
                            required=True,
                        ),
                    ],
                    returns="Assembled bytes",
                ),
                ToolFunction(
                    name="r2.seek",
                    description="Seek to a specific address in the binary",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="Output of seek command",
                ),
                ToolFunction(
                    name="r2.get_function_address",
                    description="Get address of a function by name",
                    parameters=[
                        ToolParameter(
                            name="name",
                            type="string",
                            description="Function name to look up",
                            required=True,
                        ),
                    ],
                    returns="Address of function or None if not found",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Initialize the radare2 bridge.

        Args:
            tool_path: Optional path to radare2 installation.
        """
        del tool_path
        self._state = BridgeState(
            connected=True,
            tool_running=True,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )
        _logger.info("radare2_bridge_initialized")

    async def shutdown(self) -> None:
        """Shutdown radare2 and cleanup resources."""
        if self._r2 is not None:
            try:
                await asyncio.to_thread(self._r2.quit)
            except Exception as e:
                _logger.warning("radare2_close_failed", extra={"error": str(e)})
            self._r2 = None

        if self._r2_pid is not None:
            process_manager = ProcessManager.get_instance()
            process_manager.unregister_external_pid(self._r2_pid)
            self._r2_pid = None

        self._binary_path = None
        self._analyzed = False
        await super().shutdown()
        _logger.info("radare2_bridge_shutdown")

    @override
    async def is_available(self) -> bool:
        """Check if radare2 is available.

        Returns:
            True if radare2 can be used.
        """
        r2: r2pipe.open_sync | None = None
        try:
            r2 = await asyncio.to_thread(r2pipe.open, "-")
            version: str | None = await asyncio.to_thread(r2.cmd, "?V")
        except Exception as e:
            _logger.debug("radare2_availability_check_failed", extra={"error": str(e)})
            return False
        else:
            return bool(version)
        finally:
            if r2 is not None:
                try:
                    await asyncio.to_thread(r2.quit)
                except Exception as e:
                    _logger.debug("radare2_cleanup_failed", extra={"error": str(e)})

    async def _close_existing_r2(self) -> None:
        """Close existing radare2 session and unregister process."""
        if self._r2 is not None:
            await asyncio.to_thread(self._r2.quit)
            if self._r2_pid is not None:
                process_manager = ProcessManager.get_instance()
                process_manager.unregister_external_pid(self._r2_pid)
                self._r2_pid = None

    def _register_r2_process(self, path: Path) -> None:
        """Register radare2 process with process manager.

        Args:
            path: Path to the binary being analyzed.
        """
        if not hasattr(self._r2, "_child"):
            return

        child: object = getattr(self._r2, "_child", None)
        if child is None or not hasattr(child, "pid"):
            return

        pid_val: object = getattr(child, "pid", None)
        if not isinstance(pid_val, int):
            return

        self._r2_pid = pid_val
        process_manager = ProcessManager.get_instance()
        process_manager.register_external_pid(
            self._r2_pid,
            name=f"radare2-{path.name}",
            process_type=ProcessType.EXTERNAL_TOOL,
            metadata={"binary": str(path)},
        )
        _logger.debug("radare2_process_registered", extra={"pid": self._r2_pid})

    async def _extract_hashes(self) -> tuple[str, str]:
        """Extract MD5 and SHA256 hashes from loaded binary.

        Returns:
            Tuple of (md5, sha256) hash strings.
        """
        hashes = await self._cmd_json("itj")
        md5 = ""
        sha256 = ""
        for h in hashes:
            hash_type = _get_str(h, "type")
            if hash_type == "md5":
                md5 = _get_str(h, "hash")
            elif hash_type == "sha256":
                sha256 = _get_str(h, "hash")
        return md5, sha256

    async def _extract_binary_metadata(self) -> tuple[str, str, int, int]:
        """Extract binary metadata from radare2.

        Returns:
            Tuple of (file_type, arch, bits, entry_point).
        """
        info_list = await self._cmd_json("ij")
        info = info_list[0] if info_list else {}

        bin_info = _get_dict(info, "bin")
        file_type = _get_str(bin_info, "class", "unknown")
        arch = _get_str(bin_info, "arch", "unknown")
        bits = _get_int(bin_info, "bits", 32)
        baddr = _get_int(bin_info, "baddr", 0)
        entry_offset = _get_int(bin_info, "entry", 0)
        entry = baddr + entry_offset

        return file_type, arch, bits, entry

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file into radare2.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            raise ToolError(_ERR_FILE_NOT_FOUND)

        try:
            await self._close_existing_r2()

            self._r2 = await asyncio.to_thread(r2pipe.open, str(path), ["-2"])
            self._binary_path = path.resolve()
            self._analyzed = False

            self._register_r2_process(path)

            file_type, arch, bits, entry = await self._extract_binary_metadata()
            await self._r2_cmd("e io.cache=true")
            md5, sha256 = await self._extract_hashes()

            sections = await self._get_sections_internal()
            imports = await self._get_imports_internal()
            exports = await self._get_exports_internal()

            self._state.connected = True
            self._state.tool_running = True
            self._state.binary_loaded = True
            self._state.target_path = self._binary_path

            _logger.info("binary_loaded", extra={"path": path.name, "file_type": file_type, "arch": arch, "bits": bits})

            return BinaryInfo(
                path=self._binary_path,
                name=path.name,
                size=path.stat().st_size,
                md5=md5,
                sha256=sha256,
                file_type=file_type.lower(),
                architecture=arch,
                is_64bit=bits == _BITS_64,
                entry_point=entry,
                sections=sections,
                imports=imports,
                exports=exports,
            )

        except Exception as e:
            _logger.exception("binary_load_failed")
            raise ToolError(_ERR_LOAD_FAILED) from e

    async def analyze(self, level: str = "normal") -> None:
        """Run analysis on the loaded binary.

        Args:
            level: Analysis level (quick, normal, deep).

        Raises:
            ToolError: If analysis fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)

        cmd_map = {
            "quick": "aa",
            "normal": "aaa",
            "deep": "aaaa",
        }
        cmd = cmd_map.get(level, "aaa")

        _logger.info("analysis_starting", extra={"level": level})
        await self._r2_cmd(cmd)
        self._analyzed = True
        _logger.info("analysis_complete")

    async def get_functions(
        self,
        filter_pattern: str | None = None,
    ) -> list[FunctionInfo]:
        """Get all analyzed functions.

        Args:
            filter_pattern: Optional regex to filter names.

        Returns:
            List of function information.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        funcs = await self._cmd_json("aflj")

        result: list[FunctionInfo] = []
        pattern = re.compile(filter_pattern) if filter_pattern else None

        for f in funcs:
            name = _get_str(f, "name")
            if pattern and not pattern.search(name):
                continue

            result.append(
                FunctionInfo(
                    name=name,
                    address=_get_int(f, "offset"),
                    size=_get_int(f, "size"),
                    calling_convention=_get_str(f, "cc", "unknown"),
                    return_type="unknown",
                    parameters=[],
                    local_variables=[],
                    decompiled_code=None,
                    disassembly=None,
                )
            )

        return result

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            Function info or None if not found.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"s {address}")
        func_info = await self._cmd_json("afij")

        if not func_info:
            return None

        f = func_info[0]

        vars_data_list = await self._cmd_json("afvj")
        vars_data = vars_data_list[0] if vars_data_list else {}
        params: list[ParameterInfo] = []
        locals_list: list[VariableInfo] = []

        sp_vars = _get_list(vars_data, "sp")
        bp_vars = _get_list(vars_data, "bp")
        reg_vars = _get_list(vars_data, "reg")
        all_vars: list[dict[str, Any]] = [var_item for var_item in sp_vars + bp_vars + reg_vars if isinstance(var_item, dict)]

        for var in all_vars:
            var_name = _get_str(var, "name")
            var_type = _get_str(var, "type", "unknown")
            ref_data = _get_dict(var, "ref")
            var_offset = _get_int(ref_data, "offset")

            if _get_str(var, "kind") == "arg":
                params.append(
                    ParameterInfo(
                        name=var_name,
                        type=var_type,
                        size=0,
                        location="stack",
                    )
                )
            else:
                locals_list.append(
                    VariableInfo(
                        name=var_name,
                        type=var_type,
                        offset=var_offset,
                        size=0,
                    )
                )

        return FunctionInfo(
            name=_get_str(f, "name"),
            address=_get_int(f, "offset"),
            size=_get_int(f, "size"),
            calling_convention=_get_str(f, "cc", "unknown"),
            return_type=_get_str(f, "type", "unknown"),
            parameters=params,
            local_variables=locals_list,
            decompiled_code=None,
            disassembly=None,
        )

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            Decompiled C-like pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"s {address}")
        result = await self._r2_cmd("pdc")

        if not result or "Cannot" in result:
            result = await self._r2_cmd("pdg")

        if not result or "Cannot" in result:
            raise ToolError(_ERR_DECOMPILE_NA)

        return result

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
            List of disassembly lines.

        Raises:
            ToolError: If disassembly fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"s {address}")
        insns = await self._cmd_json(f"pdj {count}")

        result: list[DisassemblyLine] = []
        for insn in insns:
            hex_bytes = _get_str(insn, "bytes")
            opcode = _get_str(insn, "opcode")
            opcode_parts = opcode.split() if opcode else []
            mnemonic = opcode_parts[0] if opcode_parts else ""
            operands = " ".join(opcode_parts[1:]) if len(opcode_parts) > 1 else ""
            result.append(
                DisassemblyLine(
                    address=_get_int(insn, "offset"),
                    bytes_str=hex_bytes,
                    mnemonic=mnemonic,
                    operands=operands,
                    comment=_get_optional_str(insn, "comment"),
                )
            )

        return result

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        xrefs = await self._cmd_json(f"axtj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = _get_str(x, "type")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in {"JMP", "CJMP"}:
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=_get_int(x, "from"),
                    to_address=address,
                    ref_type=xref_type,
                    from_function=_get_optional_str(x, "fcn_name"),
                    to_function=None,
                )
            )

        return result

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        xrefs = await self._cmd_json(f"axfj @ {address}")

        result: list[CrossReference] = []
        for x in xrefs:
            ref_type = _get_str(x, "type")
            xref_type: XRefType
            if ref_type == "CALL":
                xref_type = "call"
            elif ref_type in {"JMP", "CJMP"}:
                xref_type = "jump"
            else:
                xref_type = "data"

            result.append(
                CrossReference(
                    from_address=address,
                    to_address=_get_int(x, "ref"),
                    ref_type=xref_type,
                    from_function=None,
                    to_function=_get_optional_str(x, "fcn_name"),
                )
            )

        return result

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern to match.

        Returns:
            List of matching strings.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        strings = await self._cmd_json("izj")

        regex = re.compile(pattern, re.IGNORECASE)
        result: list[StringInfo] = []

        for s in strings:
            string_val = _get_str(s, "string")
            if regex.search(string_val):
                raw_encoding = _get_str(s, "type", "ascii")
                encoding: StringEncoding
                if raw_encoding == "utf-16be":
                    encoding = "utf-16be"
                elif raw_encoding == "utf-8":
                    encoding = "utf-8"
                elif raw_encoding in {"wide", "utf-16le"}:
                    encoding = "utf-16le"
                else:
                    encoding = "ascii"

                result.append(
                    StringInfo(
                        address=_get_int(s, "vaddr"),
                        value=string_val,
                        encoding=encoding,
                        section=_get_str(s, "section"),
                    )
                )

        return result

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Byte sequence to find.

        Returns:
            List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        hex_pattern = pattern.hex()
        results = await self._cmd_json(f"/xj {hex_pattern}")

        return [_get_int(r, "offset") for r in results]

    async def search_bytes_wildcard(self, hex_pattern: str) -> list[int]:
        """Search for byte pattern with wildcards.

        Args:
            hex_pattern: Hex pattern like '48 8B ?? ??'.

        Returns:
            List of addresses.

        Raises:
            ToolError: If search fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        clean_pattern = hex_pattern.replace(" ", "").replace("??", "..")
        results = await self._cmd_json(f"/xj {clean_pattern}")

        return [_get_int(r, "offset") for r in results]

    async def _get_sections_internal(self) -> list[SectionInfo]:
        """Get section information.

        Returns:
            List of section info.
        """
        if self._r2 is None:
            _logger.error("radare2_unavailable", extra={"operation": "_get_sections_internal"})
            return []

        sections = await self._cmd_json("iSj")

        return [
            SectionInfo(
                name=_get_str(s, "name"),
                virtual_address=_get_int(s, "vaddr"),
                virtual_size=_get_int(s, "vsize"),
                raw_size=_get_int(s, "size"),
                characteristics=_get_int(s, "perm"),
                entropy=_get_float(s, "entropy"),
            )
            for s in sections
        ]

    async def _get_imports_internal(self) -> list[ImportInfo]:
        """Get import information.

        Returns:
            List of import info.
        """
        if self._r2 is None:
            _logger.error("radare2_unavailable", extra={"operation": "_get_imports_internal"})
            return []

        imports = await self._cmd_json("iij")

        return [
            ImportInfo(
                dll=_get_str(i, "lib"),
                function=_get_str(i, "name"),
                ordinal=_get_optional_int(i, "ordinal"),
                address=_get_int(i, "plt"),
            )
            for i in imports
        ]

    async def _get_exports_internal(self) -> list[ExportInfo]:
        """Get export information.

        Returns:
            List of export info.
        """
        if self._r2 is None:
            _logger.error("radare2_unavailable", extra={"operation": "_get_exports_internal"})
            return []

        exports = await self._cmd_json("iEj")

        result: list[ExportInfo] = [
            ExportInfo(
                name=_get_str(e, "name"),
                ordinal=idx,
                address=_get_int(e, "vaddr"),
            )
            for idx, e in enumerate(exports)
        ]
        return result

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            List of import information.
        """
        return await self._get_imports_internal() if self._analyzed else []

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            List of export information.
        """
        return await self._get_exports_internal() if self._analyzed else []

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New function name.

        Returns:
            True if rename succeeded.

        Raises:
            ToolError: If operation fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        await self._r2_cmd(f"afn {new_name} @ {address}")
        _logger.info("function_renamed", extra={"address": hex(address), "new_name": new_name})
        return True

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
            comment_type: Type of comment.

        Returns:
            True if comment was added.

        Raises:
            ToolError: If operation fails.
        """
        del comment_type
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        escaped = comment.replace('"', '\\"')
        await self._r2_cmd(f'CC "{escaped}" @ {address}')
        _logger.info("comment_added", extra={"address": hex(address)})
        return True

    async def write_bytes(self, address: int, data: bytes) -> None:
        """Write bytes at an address.

        Args:
            address: Address to write at.
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)

        hex_data = data.hex()
        await self._r2_cmd(f"wx {hex_data} @ {address}")
        _logger.debug("bytes_written", extra={"length": len(data), "address": hex(address)})

    async def assemble_at(self, address: int, instruction: str) -> bytes:
        """Assemble instruction at address.

        Args:
            address: Target address.
            instruction: Assembly instruction.

        Returns:
            Assembled bytes.

        Raises:
            ToolError: If assembly fails.
        """
        del address
        if self._r2 is None:
            raise ToolError(_ERR_NO_BINARY)
        if not self._analyzed:
            raise ToolError(_ERR_NOT_ANALYZED)

        result = await self._r2_cmd(
            f'rasm2 -a x86 -b 64 "{instruction}"',
        )

        if not result or "Cannot" in result:
            raise ToolError(_ERR_ASSEMBLE_FAILED)

        return bytes.fromhex(result.strip())

    async def execute_command(self, command: str) -> str:
        """Execute raw radare2 command.

        Args:
            command: radare2 command to execute.

        Returns:
            Command output.
        """
        return await self._r2_cmd(command)

    async def _cmd_json(self, command: str) -> list[dict[str, Any]]:
        """Execute command and parse JSON output.

        Args:
            command: Command to execute.

        Returns:
            Parsed JSON as list of dicts.
        """
        if self._r2 is None:
            _logger.error("radare2_unavailable", extra={"operation": "_cmd_json"})
            return []

        result = await self._r2_cmd(command)

        if not result or not result.strip():
            return []

        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            _logger.exception("json_parse_failed", extra={"command": command})
            return []
        else:
            if isinstance(parsed, list):
                return cast("list[dict[str, Any]]", parsed)
            return [cast("dict[str, Any]", parsed)] if isinstance(parsed, dict) else []

    async def seek(self, address: int) -> str:
        """Seek to a specific address.

        Args:
            address: Target address.

        Returns:
            Output of seek command.
        """
        return await self.execute_command(f"s {address}")

    async def get_function_address(self, name: str) -> int | None:
        """Get address of a function by name.

        Args:
            name: Function name.

        Returns:
            Address of function or None if not found.
        """
        funcs = await self.get_functions(filter_pattern=name)
        return next((f.address for f in funcs if f.name == name), None)
