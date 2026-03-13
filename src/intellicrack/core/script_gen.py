# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Script infrastructure for Intellicrack.

This module provides data structures and utilities for AI-generated scripts.
The actual script content is written dynamically by the AI based on analysis
results - there are NO pre-built templates or generated scripts here.

The AI creates scripts from scratch using:
- Analysis results from analysis_aggregator
- Binary metadata from the disassembly tools
- Runtime information from Frida/debugger sessions

This module only provides:
- Data classes for script metadata and storage
- Validation utilities for script syntax
- Execution context information
- Script management (save, load, execute)
"""

from __future__ import annotations

import ast
import importlib
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Literal

from .logging import get_logger
from .process_manager import ProcessManager


_logger = get_logger("core.script_gen")

ScriptType = Literal["frida", "ghidra", "cutter", "python", "x64dbg"]

_ApiRefGetter = Callable[[], dict[str, str]]


def _empty_str_list() -> list[str]:
    """Typed factory for empty string lists (dataclass default).

    Returns:
        An empty string list.
    """
    return []


def _empty_int_list() -> list[int]:
    """Typed factory for empty int lists (dataclass default).

    Returns:
        An empty integer list.
    """
    return []


def _empty_dict_list() -> list[dict[str, Any]]:
    """Typed factory for empty dict lists (dataclass default).

    Returns:
        An empty list of string-Any dictionaries.
    """
    return []


def _empty_str_any_dict() -> dict[str, Any]:
    """Typed factory for empty string-Any dicts (dataclass default).

    Returns:
        An empty string-keyed dictionary.
    """
    return {}


class ScriptLanguage(Enum):
    """Script language enumeration."""

    JAVASCRIPT = "javascript"
    JAVA = "java"
    PYTHON = "python"
    R2_COMMANDS = "r2_commands"
    X64DBG_SCRIPT = "x64dbg_script"


class BypassStrategy(Enum):
    """Bypass strategy types for license protections.

    These are hints for the AI when writing scripts, not template selectors.
    """

    RETURN_TRUE = "return_true"
    RETURN_FALSE = "return_false"
    RETURN_ZERO = "return_zero"
    RETURN_ONE = "return_one"
    NOP_FUNCTION = "nop_function"
    SKIP_CHECK = "skip_check"
    PATCH_JUMP = "patch_jump"
    HOOK_REPLACE = "hook_replace"
    MEMORY_PATCH = "memory_patch"
    INLINE_PATCH = "inline_patch"
    VIRTUALIZATION_DEFEAT = "virtualization_defeat"

    @property
    def description(self) -> str:
        """Get human-readable description of the strategy.

        Returns:
            Description text for this bypass strategy.
        """
        descriptions = {
            BypassStrategy.RETURN_TRUE: "Force function to return true (1)",
            BypassStrategy.RETURN_FALSE: "Force function to return false (0)",
            BypassStrategy.RETURN_ZERO: "Force function to return 0",
            BypassStrategy.RETURN_ONE: "Force function to return 1",
            BypassStrategy.NOP_FUNCTION: "Replace function body with NOPs",
            BypassStrategy.SKIP_CHECK: "Skip validation check",
            BypassStrategy.PATCH_JUMP: "Patch conditional jump",
            BypassStrategy.HOOK_REPLACE: "Hook and replace function",
            BypassStrategy.MEMORY_PATCH: "Patch memory directly",
            BypassStrategy.INLINE_PATCH: "Inline assembly patch",
            BypassStrategy.VIRTUALIZATION_DEFEAT: "Defeat virtualization/obfuscation",
        }
        return descriptions.get(self, "Unknown strategy")


@dataclass
class ScriptContext:
    """Context information for AI script generation.

    Provides the AI with all necessary information to write an effective script.

    Attributes:
        binary_name: Name of the target binary.
        binary_path: Full path to the binary.
        architecture: Target architecture (x86, x64, arm, arm64).
        platform: Target platform (windows, linux, macos).
        module_base: Base address of the main module (if known).
        target_functions: Functions identified for bypass/hooking.
        identified_protections: Protection mechanisms detected.
        crypto_apis: Crypto API calls found in the binary.
        string_references: Relevant string references found.
        magic_constants: Magic constants used in validation.
        additional_context: Any additional context from analysis.
    """

    binary_name: str
    binary_path: Path | None = None
    architecture: str = "x64"
    platform: str = "windows"
    module_base: int | None = None
    target_functions: list[dict[str, Any]] = field(default_factory=_empty_dict_list)
    identified_protections: list[str] = field(default_factory=_empty_str_list)
    crypto_apis: list[str] = field(default_factory=_empty_str_list)
    string_references: list[str] = field(default_factory=_empty_str_list)
    magic_constants: list[int] = field(default_factory=_empty_int_list)
    additional_context: dict[str, Any] = field(default_factory=_empty_str_any_dict)

    _LANGUAGE_API_MAP: ClassVar[dict[ScriptLanguage, str]] = {
        ScriptLanguage.JAVASCRIPT: "frida",
        ScriptLanguage.JAVA: "ghidra",
        ScriptLanguage.R2_COMMANDS: "cutter",
        ScriptLanguage.X64DBG_SCRIPT: "x64dbg",
    }

    def to_prompt_context(self, language: ScriptLanguage | None = None) -> str:
        """Convert context to a string suitable for AI prompts.

        Args:
            language: Target script language (optional) to include API reference.

        Returns:
            Formatted context string.
        """
        lines = [
            f"Binary: {self.binary_name}",
            f"Architecture: {self.architecture}",
            f"Platform: {self.platform}",
        ]

        if self.binary_path:
            lines.append(f"Path: {self.binary_path}")

        if self.module_base is not None:
            lines.append(f"Module Base: 0x{self.module_base:X}")

        if self.target_functions:
            self._format_target_functions(lines)

        if self.identified_protections:
            lines.append(f"\nProtections: {', '.join(self.identified_protections)}")

        if self.crypto_apis:
            lines.append(f"\nCrypto APIs: {', '.join(self.crypto_apis)}")

        if self.string_references:
            lines.append("\nRelevant Strings:")
            lines.extend(f"  - {s!r}" for s in self.string_references[:20])

        if self.magic_constants:
            lines.append("\nMagic Constants:")
            lines.extend(f"  - 0x{c:X} ({c})" for c in self.magic_constants)

        if self.additional_context:
            lines.append("\nAdditional Analysis Context:")
            lines.extend(f"  - {k}: {v!r}" for k, v in self.additional_context.items())

        if language:
            self._format_api_reference(language, lines)

        return "\n".join(lines)

    def _format_target_functions(self, lines: list[str]) -> None:
        """Format target function entries and append them to lines.

        Args:
            lines: List of output lines to append to.
        """
        lines.append("\nTarget Functions:")
        for func in self.target_functions:
            name = func.get("name", "unknown")
            addr = func.get("address", 0)
            strategy_raw = func.get("strategy", "unknown")

            strategy_desc = str(strategy_raw)
            try:
                if isinstance(strategy_raw, str):
                    strategy_enum = BypassStrategy(strategy_raw)
                    strategy_desc = f"{strategy_enum.value} ({strategy_enum.description})"
                elif isinstance(strategy_raw, BypassStrategy):
                    strategy_desc = f"{strategy_raw.value} ({strategy_raw.description})"
            except ValueError:
                _logger.debug("unknown_bypass_strategy", extra={"strategy": str(strategy_raw)})

            lines.append(f"  - {name} @ 0x{addr:X} (strategy: {strategy_desc})")

    def _format_api_reference(self, language: ScriptLanguage, lines: list[str]) -> None:
        """Look up and format the API reference section for a language.

        Args:
            language: The script language to get API reference for.
            lines: List of output lines to append to.
        """
        api_ref_key = self._LANGUAGE_API_MAP.get(language)
        if api_ref_key is None:
            return

        api_getters: dict[str, _ApiRefGetter] = {
            "frida": get_frida_api_reference,
            "ghidra": get_ghidra_api_reference,
            "cutter": get_cutter_reference,
            "x64dbg": get_x64dbg_reference,
        }
        getter = api_getters.get(api_ref_key)
        if getter is None:
            return

        if api_ref := getter():
            lines.append(f"\n{language.value.upper()} API Reference:")
            lines.extend(f"  {category}: {usage}" for category, usage in api_ref.items())


@dataclass
class Script:
    """A script ready for execution.

    Attributes:
        name: Script name.
        script_type: Type of script (frida, ghidra, cutter, python, x64dbg).
        language: Script language.
        content: Script content (written by AI).
        description: Description of what the script does.
        created_at: Generation timestamp.
        context: Context used to generate the script.
        target_functions: Target functions the script operates on.
        verified: Whether the script has been syntax-verified.
        execution_results: Results from script execution (if run).
    """

    name: str
    script_type: ScriptType
    language: ScriptLanguage
    content: str
    description: str
    created_at: datetime = field(default_factory=datetime.now)
    context: ScriptContext | None = None
    target_functions: list[str] = field(default_factory=_empty_str_list)
    verified: bool = False
    execution_results: dict[str, Any] = field(default_factory=_empty_str_any_dict)

    def add_execution_result(self, tool_name: str, result: Any) -> None:
        """Add or update an execution result record.

        Args:
            tool_name: Name of the tool that executed the script.
            result: The result object or data.
        """
        self.execution_results[tool_name] = result
        self.execution_results["last_run"] = datetime.now().isoformat()

    def save(self, path: Path) -> None:
        """Save script to file.

        Args:
            path: File path to save to.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("directory_ensured", extra={"directory": str(path.parent)})
        path.write_text(self.content, encoding="utf-8")
        _logger.info("script_saved", extra={"path": str(path), "size": len(self.content)})

    def get_extension(self) -> str:
        """Get the appropriate file extension for this script type.

        Returns:
            File extension including the dot.
        """
        extensions = {
            ScriptLanguage.JAVASCRIPT: ".js",
            ScriptLanguage.JAVA: ".java",
            ScriptLanguage.PYTHON: ".py",
            ScriptLanguage.R2_COMMANDS: ".r2",
            ScriptLanguage.X64DBG_SCRIPT: ".txt",
        }
        return extensions.get(self.language, ".txt")


class ScriptValidator:
    """Validates script syntax before execution."""

    @staticmethod
    def validate_python(content: str) -> tuple[bool, str | None]:
        """Validate Python script syntax.

        Args:
            content: Python script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            ast.parse(content)
        except SyntaxError as e:
            _logger.debug("python_syntax_error", extra={"line": e.lineno, "detail": e.msg})
            return False, f"Syntax error at line {e.lineno}: {e.msg}"
        else:
            return True, None

    @staticmethod
    def validate_javascript(content: str) -> tuple[bool, str | None]:
        """Validate JavaScript syntax using node if available.

        Args:
            content: JavaScript script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        _logger.debug("validate_javascript_start", extra={"content_length": len(content)})
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".js",
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(content)
                temp_path = f.name
            _logger.debug("temp_file_created", extra={"path": temp_path, "suffix": ".js"})

            process_manager = ProcessManager.get_instance()
            cmd = ["node", "--check", temp_path]
            _logger.debug("subprocess_execute", extra={"command": cmd})
            result = process_manager.run_tracked(
                cmd,
                name="node-syntax-check",
                timeout=10,
            )
            _logger.debug("subprocess_completed", extra={"command": cmd, "exit_code": result.returncode})

            Path(temp_path).unlink(missing_ok=True)
            _logger.debug("temp_file_cleaned", extra={"path": temp_path})

            if result.returncode == 0:
                return True, None
            return False, result.stderr.strip()

        except FileNotFoundError:
            _logger.debug("node_not_found", extra={"reason": "node binary not available, skipping validation"})
            return True, None
        except Exception as exc:
            subprocess_mod = importlib.import_module("subprocess")
            if isinstance(exc, subprocess_mod.TimeoutExpired):
                _logger.warning("validation_timeout", extra={"language": "javascript", "timeout_seconds": 10})
                return False, "Validation timed out"
            _logger.debug("validation_exception", extra={"language": "javascript", "error": str(exc)})
            return True, None

    @staticmethod
    def validate_java(content: str) -> tuple[bool, str | None]:
        """Basic validation for Java/Ghidra scripts.

        Args:
            content: Java script content.

        Returns:
            Tuple of (is_valid, error_message).
        """
        _logger.debug("validate_java_start", extra={"content_length": len(content)})
        required_elements = ["import", "public", "void run("]
        for element in required_elements:
            if element not in content:
                _logger.debug("validate_java_missing_element", extra={"element": element})
                return False, f"Missing required element: {element}"

        brace_count = content.count("{") - content.count("}")
        if brace_count != 0:
            _logger.debug("validate_java_unbalanced_braces", extra={"brace_count": brace_count})
            return False, f"Unbalanced braces: {brace_count:+d}"

        return True, None

    def validate(self, script: Script) -> tuple[bool, str | None]:
        """Validate a script based on its language.

        Args:
            script: Script to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        validators = {
            ScriptLanguage.PYTHON: self.validate_python,
            ScriptLanguage.JAVASCRIPT: self.validate_javascript,
            ScriptLanguage.JAVA: self.validate_java,
        }

        if validator := validators.get(script.language):
            _logger.debug("script_validation_start", extra={"script": script.name, "language": script.language.value})
            is_valid, error = validator(script.content)
            script.verified = is_valid
            _logger.debug("script_validation_result", extra={"script": script.name, "valid": is_valid, "error": error})
            return is_valid, error

        _logger.debug("script_validation_skipped", extra={"script": script.name, "language": script.language.value})
        script.verified = True
        return True, None


class ScriptManager:
    """Manages script storage and retrieval.

    Attributes:
        scripts_dir: Directory for storing scripts.
        scripts: In-memory script cache.
    """

    def __init__(self, scripts_dir: Path) -> None:
        """Initialize the script manager.

        Args:
            scripts_dir: Directory for storing scripts.
        """
        self.scripts_dir = scripts_dir
        self.scripts: dict[str, Script] = {}
        self._validator = ScriptValidator()

    def add_script(self, script: Script, validate: bool = True) -> bool:
        """Add a script to the manager.

        Args:
            script: Script to add.
            validate: Whether to validate syntax before adding.

        Returns:
            True if script was added successfully.
        """
        if validate:
            is_valid, error = self._validator.validate(script)
            if not is_valid:
                _logger.error("script_validation_failed", extra={"error": error})
                return False

        self.scripts[script.name] = script
        _logger.info("script_added", extra={"script_name": script.name})
        return True

    def get_script(self, name: str) -> Script | None:
        """Get a script by name.

        Args:
            name: Script name.

        Returns:
            Script or None if not found.
        """
        return self.scripts.get(name)

    def delete_script(self, name: str) -> bool:
        """Delete a script by name.

        Args:
            name: Script name to delete.

        Returns:
            True if script was deleted, False if not found.
        """
        if name not in self.scripts:
            return False
        del self.scripts[name]
        _logger.info("script_deleted", extra={"script_name": name})
        return True

    def list_scripts(self, script_type: ScriptType | None = None) -> list[str]:
        """List available scripts.

        Args:
            script_type: Optional filter by script type.

        Returns:
            List of script names.
        """
        if script_type is None:
            return list(self.scripts.keys())
        return [name for name, script in self.scripts.items() if script.script_type == script_type]

    def save_script(self, name: str, subdir: str | None = None) -> Path | None:
        """Save a script to disk.

        Args:
            name: Script name.
            subdir: Optional subdirectory within scripts_dir.

        Returns:
            Path where script was saved, or None if not found.
        """
        script = self.scripts.get(name)
        if script is None:
            return None

        target_dir = self.scripts_dir
        if subdir:
            target_dir /= subdir
        target_dir.mkdir(parents=True, exist_ok=True)
        _logger.debug("directory_ensured", extra={"directory": str(target_dir)})

        filename = f"{name}{script.get_extension()}"
        path = target_dir / filename
        _logger.debug("script_save_start", extra={"script": name, "path": str(path)})
        script.save(path)
        return path

    def load_script(self, path: Path) -> Script | None:
        """Load a script from disk.

        Args:
            path: Path to script file.

        Returns:
            Loaded script or None if failed.
        """
        if not path.exists():
            _logger.debug("script_load_not_found", extra={"path": str(path)})
            return None

        content = path.read_text(encoding="utf-8")
        _logger.debug("script_file_read", extra={"path": str(path), "size": len(content)})

        ext = path.suffix.lower()
        language_map = {
            ".js": ScriptLanguage.JAVASCRIPT,
            ".py": ScriptLanguage.PYTHON,
            ".java": ScriptLanguage.JAVA,
            ".r2": ScriptLanguage.R2_COMMANDS,
            ".txt": ScriptLanguage.X64DBG_SCRIPT,
        }
        language = language_map.get(ext, ScriptLanguage.PYTHON)

        script_type: ScriptType
        if language == ScriptLanguage.JAVASCRIPT:
            script_type = "frida"
        elif language == ScriptLanguage.JAVA:
            script_type = "ghidra"
        elif language == ScriptLanguage.R2_COMMANDS:
            script_type = "cutter"
        elif language == ScriptLanguage.X64DBG_SCRIPT:
            script_type = "x64dbg"
        else:
            script_type = "python"

        script = Script(
            name=path.stem,
            script_type=script_type,
            language=language,
            content=content,
            description=f"Loaded from {path}",
        )

        self.scripts[script.name] = script
        _logger.debug("script_loaded", extra={"script": script.name, "language": language.value, "path": str(path)})
        return script

    def ensure_script_saved(self, name: str) -> bool:
        """Ensure a script is saved to disk.

        Args:
            name: Script name.

        Returns:
            True if saved successfully.
        """
        return self.save_script(name) is not None if name in self.scripts else False

    def reload_script(self, name: str) -> bool:
        """Reload a script from disk (if it exists).

        Args:
            name: Script name.

        Returns:
            True if reloaded successfully.
        """
        # First try to find where it might be saved
        # This is a bit tricky since save_script logic handles paths
        # We assume standard location in scripts_dir
        _logger.debug("script_reload_start", extra={"script": name})
        script = self.scripts.get(name)
        if not script:
            _logger.debug("script_reload_not_in_cache", extra={"script": name})
            return False

        ext = script.get_extension()
        filename = f"{name}{ext}"
        path = self.scripts_dir / filename

        if not path.exists():
            _logger.debug("script_reload_file_missing", extra={"script": name, "path": str(path)})
            return False

        if reloaded := self.load_script(path):
            self.scripts[name] = reloaded
            _logger.debug("script_reloaded", extra={"script": name, "path": str(path)})
            return True
        return False

    def record_execution(self, script_name: str, tool_name: str, result: Any) -> bool:
        """Record an execution result for a script.

        Forwards to the script's ``add_execution_result`` method to
        persist tool execution metadata.

        Args:
            script_name: Name of the script that was executed.
            tool_name: Name of the tool that executed the script.
            result: The result object or data from execution.

        Returns:
            True if the result was recorded, False if script not found.
        """
        script = self.scripts.get(script_name)
        if script is None:
            _logger.debug(
                "record_execution_script_not_found",
                extra={"script": script_name},
            )
            return False
        script.add_execution_result(tool_name, result)
        _logger.debug(
            "execution_result_recorded",
            extra={"script": script_name, "tool_name": tool_name},
        )
        return True


def get_frida_api_reference() -> dict[str, str]:
    """Get Frida API reference for AI context.

    Returns:
        Dictionary mapping API categories to usage examples.
    """
    return {
        "process": ("Process.findModuleByName(name), Process.enumerateModules(), Process.enumerateRanges(protection)"),
        "module": ("Module.findExportByName(module, name), module.base, module.size, module.enumerateExports(), module.enumerateImports()"),
        "memory": (
            "Memory.readByteArray(addr, length), Memory.writeByteArray(addr, bytes), "
            "Memory.protect(addr, size, protection), Memory.scanSync(addr, size, pattern)"
        ),
        "interceptor": (
            "Interceptor.attach(target, {onEnter, onLeave}), Interceptor.replace(target, replacement), Interceptor.revert(target)"
        ),
        "native_function": ("new NativeFunction(addr, retType, argTypes), new NativeCallback(func, retType, argTypes)"),
        "stalker": ("Stalker.follow(threadId, {events, onReceive, transform}), Stalker.unfollow(threadId)"),
    }


def get_ghidra_api_reference() -> dict[str, str]:
    """Get Ghidra API reference for AI context.

    Returns:
        Dictionary mapping API categories to usage examples.
    """
    return {
        "program": ("currentProgram.getListing(), currentProgram.getSymbolTable(), currentProgram.getMemory()"),
        "functions": ("getFunctionAt(addr), getFunctionContaining(addr), currentProgram.getListing().getFunctions(true)"),
        "symbols": ("symbolTable.getSymbols(name), symbol.getReferences(null), symbol.getAddress()"),
        "decompiler": ("DecompInterface(), decompInterface.decompileFunction(func, timeout, monitor)"),
        "patching": ("currentProgram.getMemory().setBytes(addr, bytes), clearListing(addr), createInstruction(addr)"),
    }


def get_cutter_reference() -> dict[str, str]:
    """Get Cutter/Rizin command reference for AI context.

    Returns:
        Dictionary mapping command categories to examples.
    """
    return {
        "analysis": "aaa (analyze all), af (analyze function), afl (list functions)",
        "seeking": "s addr (seek), s main (seek to main)",
        "printing": "pd N (disassemble N), px N (hexdump N), ps (print string)",
        "writing": "wx bytes (write hex), wa asm (write assembly), wao nop (nop instruction)",
        "flags": "f name @ addr (set flag), f- name (remove flag)",
        "visual": "V (visual mode), VV (visual graph)",
    }


def get_x64dbg_reference() -> dict[str, str]:
    """Get x64dbg command reference for AI context.

    Returns:
        Dictionary mapping command categories to examples.
    """
    return {
        "breakpoints": ("bp addr (set bp), bc addr (clear bp), bph addr (hardware bp)"),
        "stepping": "sti (step into), sto (step over), run (continue)",
        "memory": ("dump addr (view memory), fill addr,size,byte (fill memory)"),
        "patching": 'assemble addr, "instruction" (assemble), patch addr, bytes (patch)',
        "scripting": 'scriptload path, scriptcmd "command"',
    }


class ScriptGenerator:
    """Generates AI prompts for dynamic script generation in Intellicrack."""

    def __init__(self) -> None:
        """Initialize the script generator."""

    @staticmethod
    def prepare_ai_prompt(context: ScriptContext, language: ScriptLanguage) -> str:
        """Prepare a detailed prompt for AI script generation.

        Args:
            context: Analysis context.
            language: Target script language.

        Returns:
            Full prompt string including context and API references.
        """
        context_str = context.to_prompt_context(language)

        prompt = f"""
You are an expert reverse engineering script generator.
Target: {context.binary_name} ({context.architecture}/{context.platform})
Language: {language.value}

ANALYSIS CONTEXT:
{context_str}

TASK:
Write a standalone, error-free {language.value} script to bypass the protections described above.
The script must be production-ready and handle errors gracefully.
Implement full logic based on the provided addresses and strategies.
"""
        return prompt.strip()
