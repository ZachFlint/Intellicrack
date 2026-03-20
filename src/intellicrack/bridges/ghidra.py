# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ghidra bridge for static analysis and decompilation.

This module provides integration with Ghidra for advanced static analysis,
decompilation, and reverse engineering capabilities using ghidra_bridge.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.util
import json
import re
import socket
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from intellicrack.core._subprocess import PIPE, Popen

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager, ProcessType
from ..core.types import (
    BinaryInfo,
    CrossReference,
    DataTypeInfo,
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


_logger = get_logger("bridges.ghidra")

_RemoteExecFunc = Callable[[str], object]

_MIN_HEADER_SIZE = 4
_PE_POINTER_OFFSET = 0x3C
_PE_POINTER_END = 0x40
_PE_HEADER_MIN = 6
_PE_MAGIC = b"PE\x00\x00"
_MZ_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}
_ELF_CLASS_64 = 2
_MIN_ELF_HEADER = 64
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C


class GhidraBridge(StaticAnalysisBridge):
    """Bridge for Ghidra reverse engineering suite.

    Provides advanced static analysis and decompilation capabilities
    using the ghidra_bridge Python interface.

    Attributes:
        _ghidra_path: Path to Ghidra installation.
        _bridge: The ghidra_bridge connection.
        _process: Ghidra headless process.
        _binary_path: Path to loaded binary.
    """

    DEFAULT_PORT = 4768

    def __init__(self) -> None:
        """Initialize the Ghidra bridge."""
        super().__init__()
        self._ghidra_path: Path | None = None
        self._bridge: object | None = None
        self._process: Popen[bytes] | None = None
        self._binary_path: Path | None = None
        self._project_path: Path | None = None
        self._port: int = self.DEFAULT_PORT
        self._bridge_script_path: Path | None = None
        self._capabilities = BridgeCapabilities(
            supports_static_analysis=True,
            supports_decompilation=True,
            supports_scripting=True,
            supported_architectures=["x86", "x86_64", "arm", "arm64", "mips", "ppc", "sparc"],
            supported_formats=["pe", "elf", "macho", "raw", "coff"],
        )

    @property
    def ghidra_path(self) -> Path | None:
        """Get the Ghidra installation path.

        Returns:
            Path to Ghidra installation, or None if not set.
        """
        return self._ghidra_path

    @ghidra_path.setter
    def ghidra_path(self, value: Path | None) -> None:
        """Set the Ghidra installation path.

        Args:
            value: Path to Ghidra installation directory, or None.
        """
        self._ghidra_path = value

    @property
    def name(self) -> ToolName:
        """Get the tool's name.

        Returns:
            ToolName.GHIDRA
        """
        return ToolName.GHIDRA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get tool definition for LLM function calling.

        Returns:
            ToolDefinition with all available functions.
        """
        return ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Ghidra static analysis - decompilation, disassembly, cross-references",
            functions=[
                ToolFunction(
                    name="ghidra.load_binary",
                    description="Load a binary file into Ghidra for analysis",
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
                    name="ghidra.analyze",
                    description="Run full Ghidra analysis on loaded binary",
                    parameters=[],
                    returns="Analysis completion status",
                ),
                ToolFunction(
                    name="ghidra.get_functions",
                    description="Get list of all functions in the binary",
                    parameters=[
                        ToolParameter(
                            name="filter_pattern",
                            type="string",
                            description="Optional regex pattern to filter function names",
                            required=False,
                        ),
                    ],
                    returns="List of FunctionInfo objects",
                ),
                ToolFunction(
                    name="ghidra.decompile",
                    description="Decompile a function to C pseudocode",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address of the function to decompile",
                            required=True,
                        ),
                    ],
                    returns="Decompiled C code as string",
                ),
                ToolFunction(
                    name="ghidra.disassemble",
                    description="Get disassembly at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Start address for disassembly",
                            required=True,
                        ),
                        ToolParameter(
                            name="count",
                            type="integer",
                            description="Number of instructions to disassemble",
                            required=False,
                            default=20,
                        ),
                    ],
                    returns="Disassembly text",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_to",
                    description="Get all cross-references pointing to an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Target address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.get_xrefs_from",
                    description="Get all cross-references from an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Source address",
                            required=True,
                        ),
                    ],
                    returns="List of CrossReference objects",
                ),
                ToolFunction(
                    name="ghidra.search_strings",
                    description="Search for strings in the binary",
                    parameters=[
                        ToolParameter(
                            name="pattern",
                            type="string",
                            description="Regex pattern to match",
                            required=True,
                        ),
                    ],
                    returns="List of StringInfo objects",
                ),
                ToolFunction(
                    name="ghidra.search_bytes",
                    description="Search for a byte pattern in the binary",
                    parameters=[
                        ToolParameter(
                            name="hex_pattern",
                            type="string",
                            description="Hex string pattern (e.g., '48 8B 05 ?? ?? ?? ??')",
                            required=True,
                        ),
                    ],
                    returns="List of addresses where pattern found",
                ),
                ToolFunction(
                    name="ghidra.rename_function",
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
                    name="ghidra.add_comment",
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
                        ToolParameter(
                            name="comment_type",
                            type="string",
                            description="Type: EOL, PRE, POST, PLATE",
                            required=False,
                            default="EOL",
                            enum=["EOL", "PRE", "POST", "PLATE"],
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.get_imports",
                    description="Get all imported functions",
                    parameters=[],
                    returns="List of ImportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_exports",
                    description="Get all exported functions",
                    parameters=[],
                    returns="List of ExportInfo objects",
                ),
                ToolFunction(
                    name="ghidra.get_data_type",
                    description="Get data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to check",
                            required=True,
                        ),
                    ],
                    returns="Data type information",
                ),
                ToolFunction(
                    name="ghidra.set_data_type",
                    description="Set data type at an address",
                    parameters=[
                        ToolParameter(
                            name="address",
                            type="integer",
                            description="Address to set type",
                            required=True,
                        ),
                        ToolParameter(
                            name="data_type",
                            type="string",
                            description="Data type name",
                            required=True,
                        ),
                    ],
                    returns="Success status",
                ),
                ToolFunction(
                    name="ghidra.start_headless",
                    description="Start Ghidra in headless mode with bridge",
                    parameters=[
                        ToolParameter(
                            name="project_dir",
                            type="string",
                            description="Directory for Ghidra project",
                            required=True,
                        ),
                        ToolParameter(
                            name="project_name",
                            type="string",
                            description="Name of the project",
                            required=False,
                            default="intellicrack",
                        ),
                    ],
                    returns="None",
                ),
                ToolFunction(
                    name="ghidra.get_function",
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
                    name="ghidra.execute_script",
                    description="Execute arbitrary Jython script in Ghidra's JVM context. Gives access to all Ghidra APIs.",
                    parameters=[
                        ToolParameter(
                            name="code",
                            type="string",
                            description="Jython code to execute in Ghidra",
                            required=True,
                        ),
                    ],
                    returns="Script execution result",
                ),
                ToolFunction(
                    name="ghidra.set_label",
                    description="Create or modify a label at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for the label", required=True),
                        ToolParameter(name="name", type="string", description="Label name", required=True),
                    ],
                    returns="Label creation result",
                ),
                ToolFunction(
                    name="ghidra.get_labels",
                    description="Get labels near an address within a radius",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Center address", required=True),
                        ToolParameter(name="radius", type="integer", description="Search radius in bytes", required=False, default=256),
                    ],
                    returns="List of labels with addresses",
                ),
                ToolFunction(
                    name="ghidra.create_bookmark",
                    description="Create an analysis bookmark at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to bookmark", required=True),
                        ToolParameter(name="category", type="string", description="Bookmark category", required=True),
                        ToolParameter(name="comment", type="string", description="Bookmark comment", required=True),
                    ],
                    returns="Bookmark creation result",
                ),
                ToolFunction(
                    name="ghidra.get_bookmarks",
                    description="List bookmarks, optionally filtered by category",
                    parameters=[
                        ToolParameter(name="category", type="string", description="Filter by category", required=False),
                    ],
                    returns="List of bookmarks",
                ),
                ToolFunction(
                    name="ghidra.create_function",
                    description="Define a new function at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Entry point address", required=True),
                        ToolParameter(name="name", type="string", description="Function name (auto-generated if omitted)", required=False),
                    ],
                    returns="Created function info",
                ),
                ToolFunction(
                    name="ghidra.delete_function",
                    description="Remove function definition at an address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function entry point", required=True),
                    ],
                    returns="Deletion result",
                ),
                ToolFunction(
                    name="ghidra.edit_function_signature",
                    description="Modify function return type, calling convention, or name",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Function entry point", required=True),
                        ToolParameter(name="return_type", type="string", description="New return type", required=False),
                        ToolParameter(name="calling_convention", type="string", description="New calling convention", required=False),
                        ToolParameter(name="name", type="string", description="New function name", required=False),
                    ],
                    returns="Updated function info",
                ),
                ToolFunction(
                    name="ghidra.set_function_variable_type",
                    description="Change the data type of a local variable in a function",
                    parameters=[
                        ToolParameter(name="func_address", type="integer", description="Function entry address", required=True),
                        ToolParameter(name="var_name", type="string", description="Variable name", required=True),
                        ToolParameter(name="new_type", type="string", description="New data type", required=True),
                    ],
                    returns="Variable retype result",
                ),
                ToolFunction(
                    name="ghidra.define_structure",
                    description="Define a new struct data type with named fields",
                    parameters=[
                        ToolParameter(name="name", type="string", description="Structure name", required=True),
                        ToolParameter(
                            name="fields", type="array", description="List of {name, type, size} field definitions", required=True
                        ),
                    ],
                    returns="Structure definition result",
                ),
                ToolFunction(
                    name="ghidra.get_structures",
                    description="List defined structures, optionally filtered by name",
                    parameters=[
                        ToolParameter(name="filter_name", type="string", description="Substring filter for struct names", required=False),
                    ],
                    returns="List of structure definitions",
                ),
                ToolFunction(
                    name="ghidra.apply_structure_at",
                    description="Apply a defined structure type at a memory address",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to apply struct", required=True),
                        ToolParameter(name="struct_name", type="string", description="Name of the structure type", required=True),
                    ],
                    returns="Application result",
                ),
                ToolFunction(
                    name="ghidra.get_memory_map",
                    description="Get all memory blocks with addresses, sizes, and permissions",
                    parameters=[],
                    returns="List of memory block info",
                ),
                ToolFunction(
                    name="ghidra.get_call_graph",
                    description="Get function call graph from an address to a specified depth",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Root function address", required=True),
                        ToolParameter(
                            name="depth", type="integer", description="Maximum call depth to traverse", required=False, default=2
                        ),
                    ],
                    returns="Call graph tree structure",
                ),
                ToolFunction(
                    name="ghidra.get_segments",
                    description="Get program segments with detailed permissions and attributes",
                    parameters=[],
                    returns="List of segment info",
                ),
                ToolFunction(
                    name="ghidra.get_program_info",
                    description="Get program metadata: language, compiler, endianness, address size, image base",
                    parameters=[],
                    returns="Program information dict",
                ),
                ToolFunction(
                    name="ghidra.write_bytes",
                    description="Patch bytes at an address in the program",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address to write at", required=True),
                        ToolParameter(
                            name="data", type="string", description="Hex string of bytes (e.g. '90 90 90' or '909090')", required=True
                        ),
                    ],
                    returns="Write result with bytes written",
                ),
                ToolFunction(
                    name="ghidra.undo",
                    description="Undo the last change in Ghidra",
                    parameters=[],
                    returns="Undo result",
                ),
                ToolFunction(
                    name="ghidra.redo",
                    description="Redo the last undone change in Ghidra",
                    parameters=[],
                    returns="Redo result",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None, port: int | None = None) -> None:
        """Initialize the Ghidra bridge.

        Args:
            tool_path: Path to Ghidra installation.
            port: Bridge server port. Uses DEFAULT_PORT (4768) if not specified.

        Raises:
            ToolError: If ghidra_bridge package is not installed.
            ToolError: If connection to Ghidra fails.
        """
        self._ghidra_path = tool_path
        if port is not None:
            self._port = port
        self._state = BridgeState(
            connected=False,
            tool_running=False,
            binary_loaded=False,
            process_attached=False,
            target_path=None,
            target_pid=None,
            last_error=None,
        )

        try:
            ghidra_bridge_mod = importlib.import_module("ghidra_bridge")
            bridge_cls = cast("Callable[..., object]", ghidra_bridge_mod.GhidraBridge)

            self._bridge = await asyncio.to_thread(
                bridge_cls,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self._state.connected = True
            self._state.tool_running = True
            _logger.info("ghidra_bridge_connected", port=self._port)

        except ImportError as imp_err:
            _logger.warning("ghidra_bridge_not_installed", bridge="ghidra")
            self._bridge = None
            self._state.connected = False
            self._state.tool_running = False
            error_message = "ghidra_bridge package not installed"
            raise ToolError(error_message) from imp_err

        except Exception as exc:
            _logger.exception("ghidra_connect_failed", error=str(exc))
            self._bridge = None
            self._state.connected = False
            self._state.tool_running = False
            self._state.last_error = str(exc)
            error_message = f"Failed to connect to Ghidra: {exc}"
            raise ToolError(error_message) from exc

    async def shutdown(self) -> None:
        """Shutdown Ghidra and cleanup resources."""
        if self._process is not None:
            pid = self._process.pid
            process_manager = ProcessManager.get_instance()

            self._process.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._process.wait),
                    timeout=10,
                )
            except TimeoutError:
                _logger.warning("ghidra_process_terminate_timeout", pid=pid)
                self._process.kill()
                await asyncio.to_thread(self._process.wait)

            process_manager.unregister(pid)
            self._process = None

        if self._bridge_script_path is not None:
            try:
                if self._bridge_script_path.exists():
                    self._bridge_script_path.unlink(missing_ok=True)
                parent = self._bridge_script_path.parent
                if parent.exists() and not any(parent.iterdir()):
                    parent.rmdir()
            except OSError as e:
                _logger.debug(
                    "bridge_script_cleanup_failed",
                    error=str(e),
                )
            self._bridge_script_path = None

        self._bridge = None
        self._binary_path = None
        await super().shutdown()
        _logger.info("ghidra_bridge_shutdown", bridge="ghidra")

    async def is_available(self) -> bool:
        """Check if Ghidra is available.

        Returns:
            True if Ghidra can be used.
        """
        if self._ghidra_path is None:
            return False
        return importlib.util.find_spec("ghidra_bridge") is not None

    async def start_headless(
        self,
        project_dir: Path,
        project_name: str = "intellicrack",
    ) -> None:
        """Start Ghidra in headless mode with bridge.

        Args:
            project_dir: Directory for Ghidra project.
            project_name: Name of the project.

        Raises:
            ToolError: If Ghidra cannot be started.
        """
        if self._ghidra_path is None:
            error_message = "Ghidra path not set"
            raise ToolError(error_message)

        ghidra_run = self._ghidra_path / "support" / "analyzeHeadless.bat"
        if not ghidra_run.exists():
            ghidra_run = self._ghidra_path / "support" / "analyzeHeadless"

        if not ghidra_run.exists():
            error_message = f"Ghidra headless script not found: {ghidra_run}"
            raise ToolError(error_message)

        project_dir.mkdir(parents=True, exist_ok=True)
        self._project_path = project_dir / project_name

        bridge_script = self._create_bridge_script()

        cmd = [
            str(ghidra_run),
            str(project_dir),
            project_name,
            "-scriptPath",
            str(bridge_script.parent),
            "-postScript",
            bridge_script.name,
        ]

        _logger.info("ghidra_headless_starting", command=" ".join(cmd))

        def _start_process() -> Popen[bytes]:
            return Popen(
                cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

        self._process = await asyncio.to_thread(_start_process)

        process_manager = ProcessManager.get_instance()
        process_manager.register(
            self._process,
            name="ghidra-headless",
            process_type=ProcessType.EXTERNAL_TOOL,
            metadata={"project": project_name, "project_dir": str(project_dir)},
            cleanup_callback=self.shutdown,
        )

        await self._wait_for_bridge_port()

        try:
            ghidra_bridge_mod = importlib.import_module("ghidra_bridge")
            bridge_cls = cast("Callable[..., object]", ghidra_bridge_mod.GhidraBridge)

            self._bridge = await asyncio.to_thread(
                bridge_cls,
                namespace=None,
                connect_to_host="127.0.0.1",
                connect_to_port=self._port,
            )
            self._state.connected = True
            self._state.tool_running = True
            _logger.info("ghidra_headless_connected", port=self._port)
        except Exception as e:
            _logger.warning("ghidra_connect_failed", port=self._port, error=str(e))
            error_message = f"Failed to connect to Ghidra: {e}"
            self._state.last_error = error_message
            raise ToolError(error_message) from e

    async def _wait_for_bridge_port(
        self,
        timeout_seconds: int = 60,
        poll_interval: float = 2.0,
    ) -> None:
        """Poll until the Ghidra bridge port is accepting connections.

        Args:
            timeout_seconds: Maximum seconds to wait before raising.
            poll_interval: Seconds between connection attempts.

        Raises:
            ToolError: If the process exits or the timeout is exceeded.
        """
        elapsed = 0.0
        attempt = 0

        while elapsed < timeout_seconds:
            attempt += 1

            if self._process is not None and self._process.poll() is not None:
                rc = self._process.returncode
                msg = f"Ghidra process exited prematurely with code {rc}"
                raise ToolError(msg)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                result = await asyncio.to_thread(sock.connect_ex, ("127.0.0.1", self._port))
                if result == 0:
                    _logger.info(
                        "ghidra_bridge_port_ready",
                        port=self._port,
                        attempts=attempt,
                    )
                    return
            finally:
                sock.close()

            _logger.debug(
                "ghidra_bridge_port_polling",
                port=self._port,
                attempt=attempt,
                elapsed=elapsed,
            )
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        msg = f"Ghidra bridge port {self._port} not ready after {timeout_seconds}s ({attempt} attempts)"
        raise ToolError(msg)

    def _create_bridge_script(self) -> Path:
        """Create the Ghidra bridge startup script.

        Returns:
            Path to the created script.
        """
        script_content = f"""
# @category: IntelliCrack
# Start ghidra_bridge server

import ghidra_bridge_server
ghidra_bridge_server.GhidraBridgeServer(
    server_host="127.0.0.1",
    server_port={self._port},
).start()
"""
        script_dir = Path(tempfile.gettempdir()) / "intellicrack_ghidra"
        script_dir.mkdir(exist_ok=True)

        script_path = script_dir / "start_bridge.py"
        script_path.write_text(script_content)
        self._bridge_script_path = script_path

        return script_path

    async def load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file into Ghidra.

        Args:
            path: Path to the binary file.

        Returns:
            BinaryInfo with file details.

        Raises:
            ToolError: If load fails.
        """
        if not path.exists():
            error_message = f"File not found: {path}"
            raise ToolError(error_message)

        self._binary_path = path.resolve()

        if self._bridge is not None:
            try:
                await self._execute_remote(f'importFile(java.io.File("{path.as_posix()}"))')
            except Exception:
                _logger.exception("ghidra_remote_import_failed", binary_path=str(path))

        data = path.read_bytes()
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        file_type = self._detect_format(data)
        arch, is_64 = self._detect_architecture(data)

        self._state.connected = True
        self._state.tool_running = True
        self._state.binary_loaded = True
        self._state.target_path = self._binary_path

        _logger.info("binary_loaded", path=path.name)

        entry_point = 0
        sections: list[SectionInfo] = []
        imports: list[ImportInfo] = []
        exports: list[ExportInfo] = []

        if self._bridge is not None:
            try:
                entry_point, sections, imports, exports = await self._extract_binary_metadata()
            except Exception:
                _logger.exception("ghidra_metadata_extraction_failed", binary_path=str(path))

        return BinaryInfo(
            path=self._binary_path,
            name=path.name,
            size=len(data),
            md5=md5,
            sha256=sha256,
            file_type=file_type,
            architecture=arch,
            is_64bit=is_64,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
        )

    async def _extract_binary_metadata(
        self,
    ) -> tuple[int, list[SectionInfo], list[ImportInfo], list[ExportInfo]]:
        """Extract entry point, sections, imports, and exports from Ghidra.

        Returns:
            Tuple of (entry_point, sections, imports, exports).
        """
        if self._bridge is None:
            return 0, [], [], []

        _logger.debug("ghidra_metadata_extraction_started")
        result = await self._execute_remote(
            """
import math

metadata = {
    'entry_point': 0,
    'sections': [],
    'imports': [],
    'exports': [],
}

try:
    entry = currentProgram.getEntryPoint()
    if entry is not None:
        metadata['entry_point'] = entry.getOffset()

    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()

    for block in blocks:
        start = block.getStart()
        size = block.getSize()
        flags = 0
        if block.isRead():
            flags |= 0x1
        if block.isWrite():
            flags |= 0x2
        if block.isExecute():
            flags |= 0x4

        entropy = 0.0
        if block.isInitialized() and size > 0:
            counts = [0] * 256
            chunk_size = 0x10000
            offset = 0

            while offset < size:
                to_read = min(chunk_size, size - offset)
                data = memory.getBytes(start.add(offset), to_read)
                for b in data:
                    counts[b & 0xFF] += 1
                offset += to_read

            total = float(size)
            ent = 0.0
            for c in counts:
                if c:
                    p = c / total
                    ent -= p * math.log(p, 2)
            entropy = ent

        metadata['sections'].append({
            'name': block.getName(),
            'virtual_address': start.getOffset(),
            'virtual_size': size,
            'raw_size': size,
            'characteristics': flags,
            'entropy': float(entropy),
        })

    st = currentProgram.getSymbolTable()

    for sym in st.getExternalSymbols():
        parent = sym.getParentSymbol()
        dll_name = str(parent.getName()) if parent else ''
        metadata['imports'].append({
            'dll': dll_name,
            'function': sym.getName(),
            'address': sym.getAddress().getOffset(),
        })

    ordinal = 0
    for sym in st.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            metadata['exports'].append({
                'name': sym.getName(),
                'address': sym.getAddress().getOffset(),
                'ordinal': ordinal,
            })
            ordinal += 1
except Exception as e:
    metadata['extraction_errors'] = metadata.get('extraction_errors', [])
    metadata['extraction_errors'].append(str(e))

metadata
            """
        )

        if not isinstance(result, dict):
            return 0, [], [], []

        result_dict = cast("dict[str, Any]", result)
        entry_point = int(result_dict.get("entry_point", 0))

        sections_data = cast("list[dict[str, Any]]", result_dict.get("sections", []))
        sections = [
            SectionInfo(
                name=str(s.get("name", "")),
                virtual_address=int(s.get("virtual_address", 0)),
                virtual_size=int(s.get("virtual_size", 0)),
                raw_size=int(s.get("raw_size", 0)),
                characteristics=int(s.get("characteristics", 0)),
                entropy=float(s.get("entropy", 0.0)),
            )
            for s in sections_data
        ]

        imports_data = cast("list[dict[str, Any]]", result_dict.get("imports", []))
        imports = [
            ImportInfo(
                dll=str(i.get("dll", "")),
                function=str(i.get("function", "")),
                ordinal=None,
                address=int(i.get("address", 0)),
            )
            for i in imports_data
        ]

        exports_data = cast("list[dict[str, Any]]", result_dict.get("exports", []))
        exports = [
            ExportInfo(
                name=str(exp.get("name", "")),
                ordinal=int(exp.get("ordinal", 0)),
                address=int(exp.get("address", 0)),
            )
            for exp in exports_data
        ]

        _logger.debug(
            "ghidra_metadata_extraction_completed",
            section_count=len(sections),
            import_count=len(imports),
            export_count=len(exports),
        )
        return entry_point, sections, imports, exports

    @staticmethod
    def _detect_format(data: bytes) -> str:
        """Detect binary format.

        Args:
            data: Binary data.

        Returns:
            Format string.
        """
        if len(data) < _MIN_HEADER_SIZE:
            return "raw"

        if data[:2] == _MZ_MAGIC:
            return "pe"
        if data[:4] == _ELF_MAGIC:
            return "elf"
        return "macho" if data[:4] in _MACHO_MAGICS else "raw"

    @staticmethod
    def _detect_architecture(data: bytes) -> tuple[str, bool]:
        """Detect CPU architecture.

        Args:
            data: Binary data.

        Returns:
            Tuple of (architecture, is_64bit).
        """
        if len(data) < _MIN_ELF_HEADER:
            return "unknown", False

        if data[:2] == _MZ_MAGIC and len(data) > _PE_POINTER_END:
            pe_offset = int.from_bytes(
                data[_PE_POINTER_OFFSET:_PE_POINTER_END],
                "little",
            )
            if len(data) > pe_offset + _PE_HEADER_MIN:
                machine = int.from_bytes(
                    data[pe_offset + 4 : pe_offset + 6],
                    "little",
                )
                if machine == _MACHINE_AMD64:
                    return "x86_64", True
                if machine == _MACHINE_I386:
                    return "x86", False

        if data[:4] == _ELF_MAGIC:
            return ("x86_64", True) if data[4] == _ELF_CLASS_64 else ("x86", False)
        return "unknown", False

    async def analyze(self) -> None:
        """Run full Ghidra analysis.

        Raises:
            ToolError: If Ghidra is not connected.
            ToolError: If analysis fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            await self._execute_remote("analyzeAll(currentProgram)")
            _logger.info("ghidra_analysis_complete", bridge="ghidra")
        except Exception as e:
            _logger.warning("ghidra_analysis_failed", error=str(e))
            error_message = f"Analysis failed: {e}"
            raise ToolError(error_message) from e

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
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                functions = []
                fm = currentProgram.getFunctionManager()
                for func in fm.getFunctions(True):
                    functions.append({
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'calling_convention': func.getCallingConventionName(),
                        'return_type': str(func.getReturnType()),
                    })
                functions
            """)

            pattern = re.compile(filter_pattern) if filter_pattern else None
            functions: list[FunctionInfo] = []

            result_list = cast("list[dict[str, Any]]", result) if result else []
            for f in result_list:
                name = str(f.get("name", ""))
                if pattern and not pattern.search(name):
                    continue

                functions.append(
                    FunctionInfo(
                        name=name,
                        address=int(f.get("address", 0)),
                        size=int(f.get("size", 0)),
                        calling_convention=str(f.get("calling_convention", "unknown")),
                        return_type=str(f.get("return_type", "unknown")),
                        parameters=[],
                        local_variables=[],
                        decompiled_code=None,
                        disassembly=None,
                    )
                )

        except Exception:
            _logger.exception("get_functions_failed", filter_pattern=filter_pattern)
            return []

        return functions

    async def get_function(self, address: int) -> FunctionInfo | None:
        """Get function at a specific address.

        Args:
            address: Function address.

        Returns:
            Function info or None if not found.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    params = []
                    for param in func.getParameters():
                        params.append({{
                            'name': param.getName(),
                            'type': str(param.getDataType()),
                        }})
                    vars = []
                    for var in func.getLocalVariables():
                        vars.append({{
                            'name': var.getName(),
                            'type': str(var.getDataType()),
                            'offset': var.getStackOffset(),
                        }})
                    {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'size': func.getBody().getNumAddresses(),
                        'calling_convention': func.getCallingConventionName(),
                        'return_type': str(func.getReturnType()),
                        'signature': func.getSignature().getPrototypeString(),
                        'parameters': params,
                        'variables': vars,
                    }}
                else:
                    None
            """)

            if result is None:
                return None

            result_dict = cast("dict[str, Any]", result)

            params = [
                ParameterInfo(
                    name=str(p.get("name", "")),
                    type=str(p.get("type", "unknown")),
                    size=0,
                    location="unknown",
                )
                for p in cast("list[dict[str, Any]]", result_dict.get("parameters", []))
            ]

            variables = [
                VariableInfo(
                    name=str(v.get("name", "")),
                    type=str(v.get("type", "unknown")),
                    offset=int(v.get("offset", 0)),
                    size=0,
                )
                for v in cast("list[dict[str, Any]]", result_dict.get("variables", []))
            ]

            return FunctionInfo(
                name=str(result_dict.get("name", "")),
                address=int(result_dict.get("address", 0)),
                size=int(result_dict.get("size", 0)),
                calling_convention=str(result_dict.get("calling_convention", "unknown")),
                return_type=str(result_dict.get("return_type", "unknown")),
                parameters=params,
                local_variables=variables,
                decompiled_code=None,
                disassembly=None,
            )

        except Exception:
            _logger.exception("get_function_failed", address=hex(address))
            return None

    async def decompile(self, address: int) -> str:
        """Decompile function at address.

        Args:
            address: Function address.

        Returns:
            Decompiled C pseudocode.

        Raises:
            ToolError: If decompilation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.decompiler import DecompInterface

                ifc = DecompInterface()
                ifc.openProgram(currentProgram)

                addr = toAddr({address})
                func = getFunctionContaining(addr)

                if func is not None:
                    results = ifc.decompileFunction(func, 30, monitor)
                    if results.decompileCompleted():
                        results.getDecompiledFunction().getC()
                    else:
                        "Decompilation failed"
                else:
                    "Function not found"
            """)

            return str(result) if result else "Decompilation failed"

        except Exception as e:
            _logger.warning("ghidra_decompilation_failed", error=str(e))
            error_message = f"Decompilation failed: {e}"
            raise ToolError(error_message) from e

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
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                instructions = []
                addr = toAddr({address})
                listing = currentProgram.getListing()

                for i in range({count}):
                    instr = listing.getInstructionAt(addr)
                    if instr is None:
                        break
                    instructions.append({{
                        'address': addr.getOffset(),
                        'bytes': ' '.join('%02X' % b for b in instr.getBytes()),
                        'mnemonic': instr.getMnemonicString(),
                        'operands': instr.getDefaultOperandRepresentation(0),
                    }})
                    addr = instr.getNext().getAddress() if instr.getNext() else None
                    if addr is None:
                        break

                instructions
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                DisassemblyLine(
                    address=int(i.get("address", 0)),
                    bytes_str=str(i.get("bytes", "")),
                    mnemonic=str(i.get("mnemonic", "")),
                    operands=str(i.get("operands", "")),
                    comment=None,
                )
                for i in result_list
            ]

        except Exception:
            _logger.exception("disassembly_failed", address=hex(address), count=count)
            return []

    async def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references to an address.

        Args:
            address: Target address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesTo(addr):
                    xrefs.append({{
                        'from': ref.getFromAddress().getOffset(),
                        'to': addr.getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                CrossReference(
                    from_address=int(x.get("from", 0)),
                    to_address=int(x.get("to", 0)),
                    ref_type="call" if str(x.get("type", "")).startswith("CALL") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result_list
            ]

        except Exception:
            _logger.exception("get_xrefs_to_failed", address=hex(address))
            return []

    async def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references from an address.

        Args:
            address: Source address.

        Returns:
            List of cross-references.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                xrefs = []
                addr = toAddr({address})

                for ref in getReferencesFrom(addr):
                    xrefs.append({{
                        'from': addr.getOffset(),
                        'to': ref.getToAddress().getOffset(),
                        'type': str(ref.getReferenceType()),
                    }})

                xrefs
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                CrossReference(
                    from_address=int(x.get("from", 0)),
                    to_address=int(x.get("to", 0)),
                    ref_type="call" if str(x.get("type", "")).startswith("CALL") else "data",
                    from_function=None,
                    to_function=None,
                )
                for x in result_list
            ]

        except Exception:
            _logger.exception("get_xrefs_from_failed", address=hex(address))
            return []

    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Search for strings matching pattern.

        Args:
            pattern: Regex pattern.

        Returns:
            List of matching strings.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                import re
                strings = []
                pattern = re.compile({json.dumps(pattern)}, re.IGNORECASE)

                for string in currentProgram.getListing().getDefinedData(True):
                    if string.hasStringValue():
                        value = string.getValue()
                        if value and pattern.search(str(value)):
                            strings.append({{
                                'address': string.getAddress().getOffset(),
                                'value': str(value),
                            }})

                strings
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                StringInfo(
                    address=int(s.get("address", 0)),
                    value=str(s.get("value", "")),
                    encoding="ascii",
                    section="",
                )
                for s in result_list
            ]

        except Exception:
            _logger.exception("string_search_failed", pattern=pattern)
            return []

    async def search_bytes(self, pattern: bytes) -> list[int]:
        """Search for byte pattern.

        Args:
            pattern: Bytes to find.

        Returns:
            List of addresses.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.plugin.core.searchmem import MemSearcherAlgorithm

                addresses = []
                memory = currentProgram.getMemory()

                start = memory.getMinAddress()
                end = memory.getMaxAddress()

                searcher = memory.findBytes(start, end, [{", ".join(str(b) for b in pattern)}], None, True, monitor)

                while searcher is not None:
                    addresses.append(searcher.getOffset())
                    searcher = memory.findBytes(searcher.add(1), end, [{", ".join(str(b) for b in pattern)}], None, True, monitor)

                addresses
            """)

            if isinstance(result, list):
                return [int(addr) for addr in cast("list[int | float | str]", result)]
        except Exception:
            _logger.exception("byte_search_failed", pattern_length=len(pattern))
        return []

    async def rename_function(self, address: int, new_name: str) -> bool:
        """Rename a function.

        Args:
            address: Function address.
            new_name: New name.

        Returns:
            True if renamed.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is not None:
                    func.setName({json.dumps(new_name)}, SourceType.USER_DEFINED)
            """)

        except Exception as e:
            _logger.warning("ghidra_rename_failed", address=hex(address), error=str(e))
            error_message = f"Rename failed: {e}"
            raise ToolError(error_message) from e

        _logger.info("function_renamed", address=hex(address), new_name=new_name)
        return True

    async def add_comment(
        self,
        address: int,
        comment: str,
        comment_type: str = "EOL",
    ) -> bool:
        """Add a comment at an address.

        Args:
            address: Address.
            comment: Comment text.
            comment_type: Type of comment.

        Returns:
            True if added.

        Raises:
            ToolError: If operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        comment_map = {
            "EOL": "CodeUnit.EOL_COMMENT",
            "PRE": "CodeUnit.PRE_COMMENT",
            "POST": "CodeUnit.POST_COMMENT",
            "PLATE": "CodeUnit.PLATE_COMMENT",
        }
        ghidra_type = comment_map.get(comment_type, "CodeUnit.EOL_COMMENT")

        try:
            await self._execute_remote(f"""
                from ghidra.program.model.listing import CodeUnit

                addr = toAddr({address})
                cu = currentProgram.getListing().getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment({ghidra_type}, {json.dumps(comment)})
            """)

        except Exception as e:
            _logger.warning("ghidra_add_comment_failed", address=hex(address), error=str(e))
            error_message = f"Add comment failed: {e}"
            raise ToolError(error_message) from e

        _logger.info("comment_added", address=hex(address))
        return True

    async def get_imports(self) -> list[ImportInfo]:
        """Get imported functions.

        Returns:
            List of imports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                imports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getExternalSymbols():
                    imports.append({
                        'dll': str(sym.getParentSymbol().getName()) if sym.getParentSymbol() else '',
                        'function': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                    })

                imports
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                ImportInfo(
                    dll=str(i.get("dll", "")),
                    function=str(i.get("function", "")),
                    ordinal=None,
                    address=int(i.get("address", 0)),
                )
                for i in result_list
            ]

        except Exception:
            _logger.exception("get_imports_failed", binary_path=str(self._binary_path))
            return []

    async def get_exports(self) -> list[ExportInfo]:
        """Get exported functions.

        Returns:
            List of exports.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                exports = []
                st = currentProgram.getSymbolTable()

                for sym in st.getAllSymbols(True):
                    if sym.isExternalEntryPoint():
                        exports.append({
                            'name': sym.getName(),
                            'address': sym.getAddress().getOffset(),
                        })

                exports
            """)

            result_list = cast("list[dict[str, Any]]", result) if result else []
            return [
                ExportInfo(
                    name=str(e.get("name", "")),
                    ordinal=idx,
                    address=int(e.get("address", 0)),
                )
                for idx, e in enumerate(result_list)
            ]

        except Exception:
            _logger.exception("get_exports_failed", binary_path=str(self._binary_path))
            return []

    async def get_data_type(self, address: int) -> DataTypeInfo | None:
        """Get data type at address via Ghidra DataTypeManager.

        Args:
            address: Address to check.

        Returns:
            DataTypeInfo if data is defined, otherwise None.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.data import Pointer, Array

                addr = toAddr({address})
                data = currentProgram.getListing().getDataAt(addr)
                if data is None:
                    None
                else:
                    dt = data.getDataType()
                    is_pointer = isinstance(dt, Pointer)
                    is_array = isinstance(dt, Array)
                    base_type = None
                    array_length = None
                    if is_pointer:
                        base_type = str(dt.getDataType())
                    if is_array:
                        base_type = str(dt.getDataType())
                        array_length = int(dt.getNumElements())
                    {{
                        'address': data.getAddress().getOffset(),
                        'name': dt.getName(),
                        'category': dt.getCategoryPath().getPath(),
                        'size': int(dt.getLength()) if dt.getLength() >= 0 else 0,
                        'is_pointer': bool(is_pointer),
                        'is_array': bool(is_array),
                        'array_length': array_length,
                        'base_type': base_type,
                    }}
            """)

            if result is None or not isinstance(result, dict):
                return None

            result_dict = cast("dict[str, Any]", result)
            return DataTypeInfo(
                address=int(result_dict.get("address", address)),
                name=str(result_dict.get("name", "")),
                category=str(result_dict.get("category", "")),
                size=int(result_dict.get("size", 0)),
                is_pointer=bool(result_dict.get("is_pointer", False)),
                is_array=bool(result_dict.get("is_array", False)),
                array_length=(int(result_dict["array_length"]) if result_dict.get("array_length") is not None else None),
                base_type=(str(result_dict["base_type"]) if result_dict.get("base_type") is not None else None),
            )

        except Exception:
            _logger.exception("get_data_type_failed", address=hex(address))
            return None

    async def set_data_type(self, address: int, data_type: str) -> bool:
        """Set data type at an address.

        Args:
            address: Address to set type.
            data_type: Data type name.

        Returns:
            True if the data type was applied.

        Raises:
            ToolError: If setting the data type fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        data_type_literal = json.dumps(data_type)

        try:
            result = await self._execute_remote(f"""
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({address})
                listing = currentProgram.getListing()
                dtm = currentProgram.getDataTypeManager()
                parser = DataTypeParser(dtm)
                parsed = parser.parse({data_type_literal})

                if parsed is None:
                    False
                else:
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr, False)
                    listing.createData(addr, parsed)
                    True
            """)
            return bool(result)

        except Exception as e:
            _logger.warning("ghidra_set_data_type_failed", address=hex(address), error=str(e))
            error_message = f"Failed to set data type: {e}"
            raise ToolError(error_message) from e

    async def execute_script(self, code: str) -> str:
        """Execute arbitrary Jython script in Ghidra's JVM context.

        Args:
            code: Jython code to execute.

        Returns:
            String representation of the script result.
        """
        _logger.debug("script_executing", code_length=len(code))
        result = await self._execute_remote(code)
        return str(result) if result is not None else ""

    async def set_label(self, address: int, name: str) -> dict[str, Any]:
        """Create or modify a label at an address.

        Args:
            address: Address for the label.
            name: Label name.

        Returns:
            Dict with address, name, and success status.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("label_setting", address=hex(address), label_name=name)
        await self._execute_remote(f"""
            from ghidra.program.model.symbol import SourceType
            addr = toAddr({address})
            st = currentProgram.getSymbolTable()
            st.createLabel(addr, {json.dumps(name)}, SourceType.USER_DEFINED)
        """)
        return {"address": hex(address), "name": name, "success": True}

    async def get_labels(self, address: int, radius: int = 0x100) -> list[dict[str, Any]]:
        """Get labels near an address within a radius.

        Args:
            address: Center address.
            radius: Search radius in bytes.

        Returns:
            List of label dicts with name, address, and type fields.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                labels = []
                start = toAddr({address} - {radius})
                end = toAddr({address} + {radius})
                it = currentProgram.getSymbolTable().getSymbolIterator(start, True)
                while it.hasNext():
                    sym = it.next()
                    if sym.getAddress().compareTo(end) > 0:
                        break
                    labels.append({{
                        'name': sym.getName(),
                        'address': sym.getAddress().getOffset(),
                        'type': str(sym.getSymbolType()),
                    }})
                labels
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_labels_failed", address=hex(address))
            return []

    async def create_bookmark(self, address: int, category: str, comment: str) -> dict[str, Any]:
        """Create an analysis bookmark at an address.

        Args:
            address: Address to bookmark.
            category: Bookmark category.
            comment: Bookmark comment text.

        Returns:
            Dict with address, category, comment, and success status.

        Raises:
            ToolError: If Ghidra is not connected or operation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bookmark_creating", address=hex(address), category=category)
        await self._execute_remote(f"""
            bm = currentProgram.getBookmarkManager()
            bm.setBookmark(toAddr({address}), "Note", {json.dumps(category)}, {json.dumps(comment)})
        """)
        return {"address": hex(address), "category": category, "comment": comment, "success": True}

    async def get_bookmarks(self, category: str | None = None) -> list[dict[str, Any]]:
        """List bookmarks, optionally filtered by category.

        Args:
            category: Optional category filter.

        Returns:
            List of bookmark dicts with address, category, and comment.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        cat_filter = json.dumps(category) if category else "None"
        try:
            result = await self._execute_remote(f"""
                bookmarks = []
                bm = currentProgram.getBookmarkManager()
                cat_filter = {cat_filter}
                it = bm.getBookmarksIterator()
                while it.hasNext():
                    bk = it.next()
                    if cat_filter is None or bk.getCategory() == cat_filter:
                        bookmarks.append({{
                            'address': bk.getAddress().getOffset(),
                            'category': bk.getCategory(),
                            'comment': bk.getComment(),
                            'type': bk.getTypeString(),
                        }})
                bookmarks
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_bookmarks_failed")
            return []

    async def create_function(self, address: int, name: str | None = None) -> dict[str, Any]:
        """Define a new function at an address.

        Args:
            address: Entry point address.
            name: Optional function name.

        Returns:
            Dict with function info including address and name.

        Raises:
            ToolError: If Ghidra is not connected or function creation fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_creating", address=hex(address), func_name=name)
        name_arg = json.dumps(name) if name else "None"
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                func = createFunction(addr, {name_arg})
                if func is not None:
                    {{'name': func.getName(), 'address': func.getEntryPoint().getOffset(), 'size': func.getBody().getNumAddresses()}}
                else:
                    None
            """)
        except Exception as e:
            error_message = f"Create function failed: {e}"
            raise ToolError(error_message) from e

        if result is None:
            error_message = f"Failed to create function at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def delete_function(self, address: int) -> dict[str, Any]:
        """Remove function definition at an address.

        Args:
            address: Function entry point address.

        Returns:
            Dict with address and success status.

        Raises:
            ToolError: If Ghidra is not connected or deletion fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_deleting", address=hex(address))
        try:
            await self._execute_remote(f"""
                addr = toAddr({address})
                fm = currentProgram.getFunctionManager()
                func = fm.getFunctionAt(addr)
                if func is not None:
                    fm.removeFunction(func.getEntryPoint())
            """)
            return {"address": hex(address), "success": True}
        except Exception as e:
            error_message = f"Delete function failed: {e}"
            raise ToolError(error_message) from e

    async def edit_function_signature(
        self,
        address: int,
        return_type: str | None = None,
        calling_convention: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Modify function return type, calling convention, or name.

        Args:
            address: Function entry point.
            return_type: New return type string.
            calling_convention: New calling convention.
            name: New function name.

        Returns:
            Dict with updated function information.

        Raises:
            ToolError: If Ghidra is not connected or modification fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("function_signature_editing", address=hex(address), new_name=name, return_type=return_type)
        rt_literal = json.dumps(return_type) if return_type else "None"
        cc_literal = json.dumps(calling_convention) if calling_convention else "None"
        name_literal = json.dumps(name) if name else "None"

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({address})
                func = getFunctionContaining(addr)
                if func is None:
                    None
                else:
                    rt = {rt_literal}
                    cc = {cc_literal}
                    nm = {name_literal}

                    if rt is not None:
                        dtm = currentProgram.getDataTypeManager()
                        parser = DataTypeParser(dtm)
                        parsed = parser.parse(rt)
                        if parsed is not None:
                            func.setReturnType(parsed, SourceType.USER_DEFINED)

                    if cc is not None:
                        func.setCallingConvention(cc)

                    if nm is not None:
                        func.setName(nm, SourceType.USER_DEFINED)

                    {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'return_type': str(func.getReturnType()),
                        'calling_convention': func.getCallingConventionName(),
                    }}
            """)
        except Exception as e:
            error_message = f"Edit function signature failed: {e}"
            raise ToolError(error_message) from e

        if result is None:
            error_message = f"No function at {hex(address)}"
            raise ToolError(error_message)
        return cast("dict[str, Any]", result)

    async def set_function_variable_type(self, func_address: int, var_name: str, new_type: str) -> dict[str, Any]:
        """Change the data type of a local variable in a function.

        Args:
            func_address: Function entry address.
            var_name: Name of the variable to retype.
            new_type: New data type name.

        Returns:
            Dict with variable name, new type, and success status.

        Raises:
            ToolError: If Ghidra is not connected or retype fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("variable_type_setting", func_address=hex(func_address), var_name=var_name, new_type=new_type)
        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import SourceType
                from ghidra.app.util.parser import DataTypeParser

                addr = toAddr({func_address})
                func = getFunctionContaining(addr)
                found = False
                if func is not None:
                    dtm = currentProgram.getDataTypeManager()
                    parser = DataTypeParser(dtm)
                    parsed = parser.parse({json.dumps(new_type)})
                    if parsed is not None:
                        for var in func.getAllVariables():
                            if var.getName() == {json.dumps(var_name)}:
                                var.setDataType(parsed, SourceType.USER_DEFINED)
                                found = True
                                break
                found
            """)
        except Exception as e:
            error_message = f"Set variable type failed: {e}"
            raise ToolError(error_message) from e

        if not result:
            error_message = f"Variable {var_name!r} not found in function at {hex(func_address)}"
            raise ToolError(error_message)
        return {"var_name": var_name, "new_type": new_type, "success": True}

    async def define_structure(self, name: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
        """Define a new struct data type with named fields.

        Args:
            name: Structure name.
            fields: List of field definitions, each with 'name', 'type', and 'size' keys.

        Returns:
            Dict with structure name, size, and field count.

        Raises:
            ToolError: If Ghidra is not connected or definition fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.info("structure_defining", struct_name=name, field_count=len(fields))
        fields_json = json.dumps(fields)
        try:
            result = await self._execute_remote(f"""
                import json as _json
                from ghidra.program.model.data import StructureDataType, CategoryPath

                fields_data = _json.loads({json.dumps(fields_json)})
                struct = StructureDataType(CategoryPath.ROOT, {json.dumps(name)}, 0)

                type_map = {{
                    'byte': currentProgram.getDataTypeManager().getDataType('/byte'),
                    'word': currentProgram.getDataTypeManager().getDataType('/word'),
                    'dword': currentProgram.getDataTypeManager().getDataType('/dword'),
                    'qword': currentProgram.getDataTypeManager().getDataType('/qword'),
                    'float': currentProgram.getDataTypeManager().getDataType('/float'),
                    'double': currentProgram.getDataTypeManager().getDataType('/double'),
                    'char': currentProgram.getDataTypeManager().getDataType('/char'),
                    'pointer': currentProgram.getDataTypeManager().getDataType('/pointer'),
                }}

                for f in fields_data:
                    ft = type_map.get(f.get('type', 'byte'))
                    if ft is None:
                        from ghidra.app.util.parser import DataTypeParser
                        parser = DataTypeParser(currentProgram.getDataTypeManager())
                        ft = parser.parse(f.get('type', 'byte'))
                    if ft is not None:
                        struct.add(ft, f.get('size', ft.getLength()), f.get('name', ''), '')

                dtm = currentProgram.getDataTypeManager()
                added = dtm.addDataType(struct, None)
                {{'name': added.getName(), 'size': added.getLength(), 'field_count': added.getNumComponents()}}
            """)
            return cast("dict[str, Any]", result) if result else {"name": name, "success": False}
        except Exception as e:
            error_message = f"Define structure failed: {e}"
            raise ToolError(error_message) from e

    async def get_structures(self, filter_name: str | None = None) -> list[dict[str, Any]]:
        """List defined structures, optionally filtered by name.

        Args:
            filter_name: Optional substring filter for structure names.

        Returns:
            List of structure dicts with name, size, and field_count.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        name_filter = json.dumps(filter_name) if filter_name else "None"
        try:
            result = await self._execute_remote(f"""
                structs = []
                name_filter = {name_filter}
                it = currentProgram.getDataTypeManager().getAllStructures()
                while it.hasNext():
                    s = it.next()
                    if name_filter is None or name_filter.lower() in s.getName().lower():
                        structs.append({{
                            'name': s.getName(),
                            'size': s.getLength(),
                            'field_count': s.getNumComponents(),
                            'path': str(s.getCategoryPath()),
                        }})
                structs
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_structures_failed")
            return []

    async def apply_structure_at(self, address: int, struct_name: str) -> dict[str, Any]:
        """Apply a defined structure type at a memory address.

        Args:
            address: Address to apply the structure at.
            struct_name: Name of the structure type.

        Returns:
            Dict with address, struct_name, and success status.

        Raises:
            ToolError: If Ghidra is not connected or application fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("structure_applying", address=hex(address), struct_name=struct_name)
        try:
            result = await self._execute_remote(f"""
                addr = toAddr({address})
                dtm = currentProgram.getDataTypeManager()
                struct_type = None
                it = dtm.getAllStructures()
                while it.hasNext():
                    s = it.next()
                    if s.getName() == {json.dumps(struct_name)}:
                        struct_type = s
                        break
                if struct_type is not None:
                    listing = currentProgram.getListing()
                    existing = listing.getDataAt(addr)
                    if existing is not None:
                        listing.clearCodeUnits(addr, addr.add(struct_type.getLength() - 1), False)
                    listing.createData(addr, struct_type)
                    True
                else:
                    False
            """)
        except Exception as e:
            error_message = f"Apply structure failed: {e}"
            raise ToolError(error_message) from e

        if not result:
            error_message = f"Structure {struct_name!r} not found"
            raise ToolError(error_message)
        return {"address": hex(address), "struct_name": struct_name, "success": True}

    async def get_memory_map(self) -> list[dict[str, Any]]:
        """Get all memory blocks with addresses, sizes, and permissions.

        Returns:
            List of memory block dicts.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                blocks = []
                for block in getMemory().getBlocks():
                    blocks.append({
                        'name': block.getName(),
                        'start': block.getStart().getOffset(),
                        'end': block.getEnd().getOffset(),
                        'size': block.getSize(),
                        'read': block.isRead(),
                        'write': block.isWrite(),
                        'execute': block.isExecute(),
                        'initialized': block.isInitialized(),
                        'volatile': block.isVolatile(),
                    })
                blocks
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_memory_map_failed")
            return []

    async def get_call_graph(self, address: int, depth: int = 2) -> dict[str, Any]:
        """Get function call graph from an address to a specified depth.

        Args:
            address: Root function address.
            depth: Maximum call depth to traverse.

        Returns:
            Dict with call graph tree structure containing callers and callees.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote(f"""
                from ghidra.program.model.symbol import RefType

                def build_graph(func_addr, max_depth, current_depth, visited):
                    if current_depth >= max_depth or func_addr in visited:
                        return None
                    visited.add(func_addr)
                    func = getFunctionAt(func_addr)
                    if func is None:
                        return None

                    callees = []
                    for ref in getReferencesFrom(func.getEntryPoint()):
                        if ref.getReferenceType().isCall():
                            target = ref.getToAddress()
                            target_func = getFunctionAt(target)
                            if target_func is not None:
                                child = build_graph(target_func.getEntryPoint(), max_depth, current_depth + 1, visited)
                                callees.append({{
                                    'name': target_func.getName(),
                                    'address': target_func.getEntryPoint().getOffset(),
                                    'callees': child.get('callees', []) if child else [],
                                }})

                    body = func.getBody()
                    addr_iter = body.getAddresses(True)
                    while addr_iter.hasNext():
                        a = addr_iter.next()
                        for ref in getReferencesFrom(a):
                            if ref.getReferenceType().isCall():
                                target = ref.getToAddress()
                                target_func = getFunctionAt(target)
                                if target_func is not None and target_func.getEntryPoint().getOffset() not in [c.get('address') for c in callees]:
                                    child = build_graph(target_func.getEntryPoint(), max_depth, current_depth + 1, visited)
                                    callees.append({{
                                        'name': target_func.getName(),
                                        'address': target_func.getEntryPoint().getOffset(),
                                        'callees': child.get('callees', []) if child else [],
                                    }})

                    return {{
                        'name': func.getName(),
                        'address': func.getEntryPoint().getOffset(),
                        'callees': callees,
                    }}

                root_addr = toAddr({address})
                root_func = getFunctionContaining(root_addr)
                if root_func is not None:
                    build_graph(root_func.getEntryPoint(), {depth}, 0, set())
                else:
                    None
            """)
            if result is None:
                return {"address": hex(address), "callees": [], "callers": []}
            return cast("dict[str, Any]", result)
        except Exception:
            _logger.exception("get_call_graph_failed", address=hex(address))
            return {"address": hex(address), "callees": [], "callers": []}

    async def get_segments(self) -> list[dict[str, Any]]:
        """Get program segments with detailed permissions and attributes.

        Returns:
            List of segment dicts with name, addresses, permissions, and source info.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                segments = []
                for block in getMemory().getBlocks():
                    segments.append({
                        'name': block.getName(),
                        'start': block.getStart().getOffset(),
                        'end': block.getEnd().getOffset(),
                        'size': block.getSize(),
                        'read': block.isRead(),
                        'write': block.isWrite(),
                        'execute': block.isExecute(),
                        'initialized': block.isInitialized(),
                        'volatile': block.isVolatile(),
                        'type': str(block.getType()),
                        'source_name': block.getSourceName(),
                        'comment': block.getComment() if block.getComment() else '',
                    })
                segments
            """)
            return cast("list[dict[str, Any]]", result) if result else []
        except Exception:
            _logger.exception("get_segments_failed")
            return []

    async def get_program_info(self) -> dict[str, Any]:
        """Get program metadata including language, compiler, and layout info.

        Returns:
            Dict with language, compiler, endianness, pointer_size, image_base,
            and executable_format.

        Raises:
            ToolError: If Ghidra is not connected.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        try:
            result = await self._execute_remote("""
                lang = currentProgram.getLanguage()
                cs = currentProgram.getCompilerSpec()
                {
                    'name': currentProgram.getName(),
                    'language': str(lang.getLanguageID()),
                    'language_description': str(lang.getLanguageDescription()),
                    'compiler': str(cs.getCompilerSpecID()),
                    'endianness': str(lang.isBigEndian() and 'big' or 'little'),
                    'pointer_size': lang.getDefaultSpace().getPointerSize(),
                    'address_size': lang.getDefaultSpace().getSize(),
                    'image_base': currentProgram.getImageBase().getOffset(),
                    'executable_format': currentProgram.getExecutableFormat(),
                    'executable_path': currentProgram.getExecutablePath(),
                    'num_functions': currentProgram.getFunctionManager().getFunctionCount(),
                    'num_symbols': currentProgram.getSymbolTable().getNumSymbols(),
                }
            """)
            return cast("dict[str, Any]", result) if result else {}
        except Exception:
            _logger.exception("get_program_info_failed")
            return {}

    async def write_bytes(self, address: int, data: str) -> dict[str, Any]:
        """Patch bytes at an address in the program.

        Args:
            address: Address to write at.
            data: Hex string of bytes (e.g. '90 90 90' or '909090').

        Returns:
            Dict with address and bytes_written count.

        Raises:
            ToolError: If Ghidra is not connected or write fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("bytes_writing", address=hex(address), data_length=len(data.replace(" ", "")) // 2)
        clean_hex = data.replace(" ", "")
        byte_values = [int(clean_hex[i : i + 2], 16) for i in range(0, len(clean_hex), 2)]
        byte_list_str = ", ".join(str(b) for b in byte_values)

        try:
            await self._execute_remote(f"""
                from jarray import array
                addr = toAddr({address})
                data = array([{byte_list_str}], 'b')
                currentProgram.getMemory().setBytes(addr, data)
            """)
            return {"address": hex(address), "bytes_written": len(byte_values), "success": True}
        except Exception as e:
            error_message = f"Write bytes failed: {e}"
            raise ToolError(error_message) from e

    async def undo(self) -> dict[str, Any]:
        """Undo the last change in Ghidra.

        Returns:
            Dict with success status.

        Raises:
            ToolError: If Ghidra is not connected or undo fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("undo_requested")
        try:
            result = await self._execute_remote("""
                currentProgram.undo()
                True
            """)
            _logger.debug("undo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            error_message = f"Undo failed: {e}"
            raise ToolError(error_message) from e

    async def redo(self) -> dict[str, Any]:
        """Redo the last undone change in Ghidra.

        Returns:
            Dict with success status.

        Raises:
            ToolError: If Ghidra is not connected or redo fails.
        """
        if self._bridge is None:
            error_message = "Ghidra not connected"
            raise ToolError(error_message)

        _logger.debug("redo_requested")
        try:
            result = await self._execute_remote("""
                currentProgram.redo()
                True
            """)
            _logger.debug("redo_performed", success=bool(result))
            return {"success": bool(result)}
        except Exception as e:
            error_message = f"Redo failed: {e}"
            raise ToolError(error_message) from e

    async def _execute_remote(self, code: str) -> object:
        """Execute code on the Ghidra bridge.

        Args:
            code: Python code to execute.

        Returns:
            Result of execution.

        Raises:
            ToolError: If execution fails.
        """
        if self._bridge is None:
            error_message = "Ghidra bridge not connected"
            raise ToolError(error_message)

        remote_exec_attr = getattr(self._bridge, "remote_exec", None)
        if remote_exec_attr is None:
            error_message = "Ghidra bridge missing remote_exec"
            raise ToolError(error_message)
        remote_exec = cast("_RemoteExecFunc", remote_exec_attr)

        try:
            return await asyncio.to_thread(
                remote_exec,
                code,
            )
        except Exception as e:
            _logger.warning("ghidra_remote_exec_failed", error=str(e))
            error_message = f"Remote execution failed: {e}"
            raise ToolError(error_message) from e
