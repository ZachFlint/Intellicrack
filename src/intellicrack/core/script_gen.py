# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Script infrastructure for Intellicrack.

This module provides the stable Python API used by the application GUI layer
(see ``main.py`` wiring) and by the tool/AI bridges to orchestrate AI-generated
scripts. The actual script content is written dynamically by the AI based on
analysis results - there are NO pre-built templates or generated scripts here.

Integration pattern:
    A single :class:`ScriptGenerator` instance is owned by the top-level
    application shell and passed (or re-referenced by composition) into GUI
    panels and bridge orchestrators that need to build AI prompts from
    :class:`ScriptContext` state. :class:`ScriptManager` owns the on-disk
    storage and in-memory cache of :class:`Script` objects, and
    :class:`ScriptValidator` is used to validate script contents before
    handing them to an external execution bridge.

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
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Final, Literal

from .logging import get_logger
from .process_manager import ProcessManager
from .subprocess_compat import CompletedProcess, TimeoutExpired


_logger = get_logger(__name__)

ScriptType = Literal["frida", "ghidra", "cutter", "python", "x64dbg"]

_ApiRefGetter = Callable[[], dict[str, str]]

_JAVA_CLASS_DECLARATION_RE: Final[re.Pattern[str]] = re.compile(r"\bclass\s+[A-Za-z_][A-Za-z0-9_]*")
_JAVA_IMPORT_KEYWORD_RE: Final[re.Pattern[str]] = re.compile(r"\bimport\b")
_JAVA_PUBLIC_KEYWORD_RE: Final[re.Pattern[str]] = re.compile(r"\bpublic\b")
_JAVA_RUN_ENTRYPOINT_RE: Final[re.Pattern[str]] = re.compile(r"\bvoid\s+run\s*\(")

_DEFAULT_SCRIPTS_DIRNAME: Final[str] = "scripts"

_EXEC_TIMEOUT_DEFAULT: Final[float] = 30.0


def _empty_str_list() -> list[str]:
    """Typed factory for empty string lists (dataclass default).

    Returns:
        list[str]: An empty string list.
    """
    return []


def _empty_int_list() -> list[int]:
    """Typed factory for empty int lists (dataclass default).

    Returns:
        list[int]: An empty integer list.
    """
    return []


def _empty_dict_list() -> list[dict[str, Any]]:
    """Typed factory for empty dict lists (dataclass default).

    Returns:
        list[dict[str, Any]]: An empty list of string-Any dictionaries.
    """
    return []


def _empty_str_any_dict() -> dict[str, Any]:
    """Typed factory for empty string-Any dicts (dataclass default).

    Returns:
        dict[str, Any]: An empty string-keyed dictionary.
    """
    return {}


def _utc_now() -> datetime:
    """Return the current UTC timestamp as a tz-aware datetime.

    Returns:
        datetime: The current time in UTC, with ``tzinfo`` populated.
    """
    return datetime.now(tz=UTC)


def strip_java_strings_and_comments(content: str) -> str:
    """Strip Java string literals, char literals, and comments from source.

    Replaces every string literal, character literal, line comment, and
    block comment with whitespace of the same length. Preserves newline
    characters so line numbers remain stable for downstream analysis.

    Args:
        content: Java source text to scrub.

    Returns:
        str: Sanitised source where only true Java tokens are visible to
        keyword/brace counting routines.
    """
    out: list[str] = []
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            j = content.find("\n", i + 2)
            if j == -1:
                out.append(" " * (n - i))
                i = n
            else:
                out.append(" " * (j - i))
                i = j
            continue

        if ch == "/" and nxt == "*":
            j = content.find("*/", i + 2)
            if j == -1:
                segment = content[i:]
                i = n
            else:
                end = j + 2
                segment = content[i:end]
                i = end
            out.append("".join(c if c == "\n" else " " for c in segment))
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                cj = content[j]
                if cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cj == '"':
                    j += 1
                    break
                if cj == "\n":
                    break
                j += 1
            segment = content[i:j]
            out.append("".join(c if c == "\n" else " " for c in segment))
            i = j
            continue

        if ch == "'":
            j = i + 1
            while j < n:
                cj = content[j]
                if cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cj == "'":
                    j += 1
                    break
                if cj == "\n":
                    break
                j += 1
            segment = content[i:j]
            out.append("".join(c if c == "\n" else " " for c in segment))
            i = j
            continue

        out.append(ch)
        i += 1

    return "".join(out)


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

    Attributes:
        RETURN_TRUE: Force target function to return true (1).
        RETURN_FALSE: Force target function to return false (0).
        RETURN_ZERO: Force target function to return integer zero.
        RETURN_ONE: Force target function to return integer one.
        NOP_FUNCTION: Replace target function body with a no-op.
        SKIP_CHECK: Skip over a conditional check entirely.
        PATCH_JUMP: Patch a conditional jump to always or never branch.
        HOOK_REPLACE: Replace entire function with a custom implementation.
        MEMORY_PATCH: Patch bytes in process memory at runtime.
        INLINE_PATCH: Patch instruction bytes directly in the binary on disk.
        VIRTUALIZATION_DEFEAT: Bypass code-virtualization protections (VMProtect, Themida, etc.).
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
            str: Description text for this bypass strategy.
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
        binary_name: Name of the binary being analyzed.
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
        LANGUAGE_API_MAP: Class-level mapping from
            :class:`ScriptLanguage` to the API-reference key
            (``"frida"``, ``"ghidra"``, ``"cutter"``, ``"x64dbg"``)
            used to look up the per-language reference dict.
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

    LANGUAGE_API_MAP: ClassVar[dict[ScriptLanguage, str]] = {
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
            str: Formatted context string.
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
                _logger.exception("unknown_bypass_strategy", strategy=str(strategy_raw))

            lines.append(f"  - {name} @ 0x{addr:X} (strategy: {strategy_desc})")

    def _format_api_reference(self, language: ScriptLanguage, lines: list[str]) -> None:
        """Look up and format the API reference section for a language.

        Args:
            language: The script language to get API reference for.
            lines: List of output lines to append to.
        """
        api_ref_key = self.LANGUAGE_API_MAP.get(language)
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
        name: Script name identifier.
        script_type: Type of the script.
        language: Programming language of the script.
        content: Script source code content.
        description: Human-readable description of the script.
        created_at: Generation timestamp (tz-aware UTC).
        context: Context used to generate the script.
        target_functions: Target functions the script operates on.
        verified: Whether the script has been syntax-verified.
        execution_results: Results from script execution (if run).
        saved_path: On-disk path of the most recent successful save.
    """

    name: str
    script_type: ScriptType
    language: ScriptLanguage
    content: str
    description: str
    created_at: datetime = field(default_factory=_utc_now)
    context: ScriptContext | None = None
    target_functions: list[str] = field(default_factory=_empty_str_list)
    verified: bool = False
    execution_results: dict[str, Any] = field(default_factory=_empty_str_any_dict)
    saved_path: Path | None = None

    def add_execution_result(self, tool_name: str, result: object) -> None:
        """Add or update an execution result record.

        Args:
            tool_name: Name of the tool that executed the script.
            result: The result object or data.
        """
        self.execution_results[tool_name] = result
        self.execution_results["last_run"] = _utc_now().isoformat()

    def save(self, path: Path) -> None:
        """Save script to file.

        Writes the script's ``content`` to ``path`` after ensuring the parent
        directory exists. The success log record is emitted only after the
        write returns successfully; if the write raises an :class:`OSError`,
        the failure is logged with the exception detail and re-raised so
        callers can react.

        Args:
            path: File path to save to.

        Raises:
            OSError: If the parent directory cannot be created or the
                write_text call fails for any I/O reason.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("directory_ensured", directory=str(path.parent))
        try:
            path.write_text(self.content, encoding="utf-8")
        except OSError as exc:
            _logger.warning(
                "script_file_write_failed",
                path=str(path),
                size=len(self.content),
                error=str(exc),
            )
            raise
        _logger.info("script_file_written", path=str(path), size=len(self.content))
        _logger.info("script_saved", path=str(path), size=len(self.content))
        self.saved_path = path

    def get_extension(self) -> str:
        """Get the appropriate file extension for this script type.

        Returns:
            str: File extension including the dot.
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
            tuple[bool, str | None]: Tuple of (is_valid, error_message).
        """
        try:
            ast.parse(content)
        except SyntaxError as e:
            _logger.debug("python_syntax_error", line=e.lineno, detail=e.msg)
            return False, f"Syntax error at line {e.lineno}: {e.msg}"
        else:
            return True, None

    @staticmethod
    def _run_node_check(temp_path: str) -> tuple[bool, str | None]:
        """Invoke ``node --check`` against ``temp_path`` and translate the result.

        Args:
            temp_path: Path to a temporary ``.js`` file holding the script
                being validated.

        Returns:
            tuple[bool, str | None]: ``(True, None)`` when node reports a
            clean parse (exit code 0); ``(False, <reason>)`` for every other
            outcome (missing runtime, timeout, syntax error).
        """
        process_manager = ProcessManager.get_instance()
        cmd = ["node", "--check", temp_path]
        _logger.debug("subprocess_execute", command=cmd)
        try:
            result = process_manager.run_tracked(
                cmd,
                name="node-syntax-check",
                timeout=10,
            )
        except FileNotFoundError:
            _logger.warning("node_runtime_missing", language="javascript")
            return False, "node not installed"
        except TimeoutExpired:
            _logger.warning("validation_timeout", language="javascript", timeout_seconds=10)
            return False, "Validation timed out"
        _logger.debug("subprocess_completed", command=cmd, exit_code=result.returncode)

        if result.returncode == 0:
            return True, None
        stderr_text = (result.stderr or "").strip() or f"node exited with code {result.returncode}"
        return False, stderr_text

    @staticmethod
    def validate_javascript(content: str) -> tuple[bool, str | None]:
        """Validate JavaScript syntax using the ``node`` runtime.

        Writes the script to a temporary file and invokes ``node --check`` to
        perform real syntax validation. A ``(True, None)`` return is only
        produced when node actually reports a clean parse (exit code ``0``).

        Args:
            content: JavaScript script content.

        Returns:
            tuple[bool, str | None]: ``(True, None)`` when node confirms the
            script parses cleanly. ``(False, <reason>)`` in every other case,
            including node being unavailable, tempfile write failures,
            subprocess timeouts, and actual syntax errors. The second element
            is always populated when the first is ``False``.
        """
        _logger.debug("validate_javascript_start", content_length=len(content))
        temp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".js",
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(content)
                temp_path = f.name
            _logger.debug("temp_file_created", path=temp_path, suffix=".js")
        except OSError as exc:
            _logger.warning("tempfile_write_failed", language="javascript", error=str(exc))
            return False, f"tempfile write failed: {exc}"

        try:
            return ScriptValidator._run_node_check(temp_path)
        finally:
            _logger.info("temp_file_unlink_attempt", path=temp_path)
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError as exc:
                _logger.warning("temp_file_unlink_failed", path=temp_path, error=str(exc))
            else:
                _logger.debug("temp_file_cleaned", path=temp_path)

    @staticmethod
    def validate_java(content: str) -> tuple[bool, str | None]:
        r"""Validate Java/Ghidra script structure.

        Performs a structural check on a Ghidra Java script. String literals,
        character literals, line comments, and block comments are stripped
        from the source before any keyword or brace check runs, so tokens
        appearing inside strings or comments cannot satisfy the structural
        requirements and braces inside string literals do not contribute to
        the brace-balance count.

        Args:
            content: Java script content.

        Returns:
            tuple[bool, str | None]: ``(True, None)`` when the sanitised
            script contains an ``import`` statement, a ``public`` modifier,
            an explicit class declaration, and a ``void run(`` entry point
            with balanced braces. ``(False, <reason>)`` otherwise.
        """
        _logger.debug("validate_java_start", content_length=len(content))

        scrubbed = strip_java_strings_and_comments(content)

        if _JAVA_IMPORT_KEYWORD_RE.search(scrubbed) is None:
            _logger.debug("validate_java_missing_element", element="import")
            return False, "Missing required element: import"

        if _JAVA_PUBLIC_KEYWORD_RE.search(scrubbed) is None:
            _logger.debug("validate_java_missing_element", element="public")
            return False, "Missing required element: public"

        if _JAVA_CLASS_DECLARATION_RE.search(scrubbed) is None:
            _logger.debug("validate_java_missing_element", element="class")
            return False, "Missing required element: class declaration"

        if _JAVA_RUN_ENTRYPOINT_RE.search(scrubbed) is None:
            _logger.debug("validate_java_missing_element", element="void run(")
            return False, "Missing required element: void run("

        brace_count = scrubbed.count("{") - scrubbed.count("}")
        if brace_count != 0:
            _logger.debug("validate_java_unbalanced_braces", brace_count=brace_count)
            return False, f"Unbalanced braces: {brace_count:+d}"

        return True, None

    def validate(self, script: Script) -> tuple[bool, str | None]:
        """Validate a script based on its language.

        Languages without a real validator (currently ``R2_COMMANDS`` and
        ``X64DBG_SCRIPT``) return ``(False, <reason>)`` and leave
        :attr:`Script.verified` unchanged. The previous behaviour of
        silently returning success is removed because callers used the
        ``verified`` flag to gate execution and would otherwise treat
        unvalidated scripts as trusted.

        Args:
            script: Script to validate.

        Returns:
            tuple[bool, str | None]: ``(True, None)`` when the language has
            a validator and the script passes. ``(False, <reason>)`` when
            the script fails validation or no validator exists for the
            language.
        """
        validators = {
            ScriptLanguage.PYTHON: self.validate_python,
            ScriptLanguage.JAVASCRIPT: self.validate_javascript,
            ScriptLanguage.JAVA: self.validate_java,
        }

        validator = validators.get(script.language)
        if validator is None:
            _logger.debug(
                "script_validation_unsupported",
                script=script.name,
                language=script.language.value,
            )
            return False, f"no validator for language {script.language.value}"

        _logger.debug("script_validation_start", script=script.name, language=script.language.value)
        is_valid, error = validator(script.content)
        script.verified = is_valid
        _logger.debug("script_validation_result", script=script.name, valid=is_valid, error=error)
        return is_valid, error


class ScriptManager:
    """Manages script storage, retrieval, and execution.

    Attributes:
        scripts_dir: Directory for storing scripts.
        scripts: Mapping of script names to Script objects.
    """

    scripts_dir: Path
    scripts: dict[str, Script]

    def __init__(self, scripts_dir: Path | None = None) -> None:
        """Initialize the ScriptManager with a storage directory.

        Args:
            scripts_dir: Directory for storing scripts. When omitted, a
                ``scripts`` directory beneath the current working directory
                is used. The directory is not created on the filesystem
                until a script is actually written.
        """
        self.scripts_dir = scripts_dir if scripts_dir is not None else Path.cwd() / _DEFAULT_SCRIPTS_DIRNAME
        self.scripts = {}
        self._validator = ScriptValidator()
        _logger.debug("script_manager_initialized", scripts_dir=str(self.scripts_dir))

    def add_script(self, script: Script, *, validate: bool = True) -> bool:
        """Add a script to the manager.

        Args:
            script: Script to add.
            validate: Whether to validate syntax before adding.

        Returns:
            bool: True if script was added successfully.
        """
        if validate:
            is_valid, error = self._validator.validate(script)
            if not is_valid:
                _logger.error("script_validation_failed", error=error)
                return False

        self.scripts[script.name] = script
        _logger.info("script_added", script_name=script.name)
        return True

    def get_script(self, name: str) -> Script | None:
        """Get a script by name.

        Args:
            name: Script name.

        Returns:
            Script | None: Script or None if not found.
        """
        return self.scripts.get(name)

    def delete_script(self, name: str) -> bool:
        """Delete a script by name.

        Args:
            name: Script name to delete.

        Returns:
            bool: True if script was deleted, False if not found.
        """
        if name not in self.scripts:
            return False
        del self.scripts[name]
        _logger.info("script_deleted", script_name=name)
        return True

    def list_scripts(self, script_type: ScriptType | None = None) -> list[str]:
        """List available scripts.

        Args:
            script_type: Optional filter by script type.

        Returns:
            list[str]: List of script names.
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
            Path | None: Path where script was saved, or None if not found.
        """
        script = self.scripts.get(name)
        if script is None:
            return None

        target_dir = self.scripts_dir
        if subdir:
            target_dir /= subdir
        target_dir.mkdir(parents=True, exist_ok=True)
        _logger.debug("directory_ensured", directory=str(target_dir))

        filename = f"{name}{script.get_extension()}"
        path = target_dir / filename
        _logger.debug("script_save_start", script=name, path=str(path))
        script.save(path)
        return path

    def load_script(self, path: Path) -> Script | None:
        """Load a script from disk.

        Args:
            path: Path to script file.

        Returns:
            Script | None: Loaded script or None if failed.
        """
        if not path.exists():
            _logger.debug("script_load_not_found", path=str(path))
            return None

        content = path.read_text(encoding="utf-8")
        _logger.debug("script_file_read", path=str(path), size=len(content))

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
            saved_path=path,
        )

        self.scripts[script.name] = script
        _logger.debug("script_loaded", script=script.name, language=language.value, path=str(path))
        return script

    def ensure_script_saved(self, name: str) -> bool:
        """Ensure a script is saved to disk.

        Args:
            name: Script name.

        Returns:
            bool: True if saved successfully.
        """
        return self.save_script(name) is not None if name in self.scripts else False

    def reload_script(self, name: str) -> bool:
        """Reload a script from disk.

        When :meth:`save_script` was previously called for ``name``, the
        recorded :attr:`Script.saved_path` is used directly so reloads
        survive subdirectory writes. When no save path is recorded the
        manager falls back to the canonical ``scripts_dir / <name><ext>``
        location.

        Args:
            name: Script name.

        Returns:
            bool: True if reloaded successfully.
        """
        _logger.debug("script_reload_start", script=name)
        script = self.scripts.get(name)
        if script is None:
            _logger.debug("script_reload_not_in_cache", script=name)
            return False

        path = script.saved_path
        if path is None:
            ext = script.get_extension()
            path = self.scripts_dir / f"{name}{ext}"

        if not path.exists():
            _logger.debug("script_reload_file_missing", script=name, path=str(path))
            return False

        if reloaded := self.load_script(path):
            self.scripts[name] = reloaded
            _logger.debug("script_reloaded", script=name, path=str(path))
            return True
        return False

    def record_execution(self, script_name: str, tool_name: str, result: object) -> bool:
        """Record an execution result for a script.

        Forwards to the script's ``add_execution_result`` method to
        persist tool execution metadata.

        Args:
            script_name: Name of the script that was executed.
            tool_name: Name of the tool that executed the script.
            result: The result object or data from execution.

        Returns:
            bool: True if the result was recorded, False if script not found.
        """
        script = self.scripts.get(script_name)
        if script is None:
            _logger.debug(
                "record_execution_script_not_found",
                script=script_name,
            )
            return False
        script.add_execution_result(tool_name, result)
        _logger.debug(
            "execution_result_recorded",
            script=script_name,
            tool_name=tool_name,
        )
        return True

    def execute(
        self,
        name: str,
        *,
        args: list[str] | None = None,
        timeout: float | None = _EXEC_TIMEOUT_DEFAULT,
        cwd: Path | None = None,
    ) -> CompletedProcess[str]:
        """Execute a script via the language-appropriate runner.

        Dispatches the script's content to the right interpreter based on
        :attr:`Script.language`. Every supported language has a real
        runner wired up so the integration is end-to-end:

        * ``PYTHON`` is run with the active interpreter (``sys.executable``).
        * ``JAVASCRIPT`` is run with ``node``.
        * ``R2_COMMANDS`` are piped to ``r2`` via ``-q -i``.
        * ``JAVA`` (Ghidra script) is launched with Ghidra's
          ``analyzeHeadless`` driver and ``-postScript``.
        * ``X64DBG_SCRIPT`` is run with the platform-appropriate x64dbg
          binary using its ``-script`` switch.

        Scripts that have not yet been saved are written to a fresh
        temporary file before invocation so the runner sees a real path.
        The execution is tracked through :class:`ProcessManager`, the exit
        code and captured stdout/stderr are recorded on the script via
        :meth:`record_execution`, and the underlying
        :class:`subprocess.CompletedProcess` is returned to the caller so
        no diagnostic information is lost.

        Args:
            name: Name of the script to execute.
            args: Optional argument list to forward to the runner after
                the script path.
            timeout: Maximum seconds to wait for the runner to exit. Pass
                ``None`` to disable the timeout.
            cwd: Optional working directory to use for the runner.

        Returns:
            CompletedProcess[str]: The completed subprocess with text
            stdout/stderr and exit code.

        Raises:
            KeyError: If no script with ``name`` is registered.
            FileNotFoundError: If the runner binary required by the
                script's language cannot be located on ``PATH``.
            TimeoutExpired: If the runner does not exit within ``timeout``
                seconds.
        """
        script = self.scripts.get(name)
        if script is None:
            _logger.warning("script_execute_not_found", script=name)
            raise KeyError(name)

        cmd = self.build_execute_command(script, args)

        runner_binary = cmd[0]
        if runner_binary != sys.executable and shutil.which(runner_binary) is None:
            _logger.warning("script_execute_runner_missing", script=name, runner=runner_binary)
            raise FileNotFoundError(runner_binary)

        process_manager = ProcessManager.get_instance()
        _logger.debug("script_execute_start", script=name, command=cmd, timeout=timeout)
        try:
            result = process_manager.run_tracked(
                cmd,
                name=f"script-execute-{name}",
                timeout=timeout,
                cwd=str(cwd) if cwd is not None else None,
            )
        except TimeoutExpired:
            _logger.warning("script_execute_timeout", script=name, timeout=timeout)
            raise
        _logger.info(
            "script_execute_completed",
            script=name,
            returncode=result.returncode,
            stdout_len=len(result.stdout or ""),
            stderr_len=len(result.stderr or ""),
        )

        self.record_execution(
            name,
            "script_manager.execute",
            {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": cmd,
            },
        )
        return result

    def build_execute_command(self, script: Script, args: list[str] | None) -> list[str]:
        """Build the runner command line for a script.

        Materialises ``script`` to disk via :attr:`Script.saved_path` if
        already persisted, otherwise writes the content to a temporary
        file with the right extension. Returns the runner argv for the
        script's language.

        Args:
            script: Script to execute.
            args: Optional argument list to append after the script path.

        Returns:
            list[str]: Runner command line ready to pass to
            :meth:`ProcessManager.run_tracked`.
        """
        path = self._materialise_script_path(script)
        path_str = str(path)
        extra = list(args) if args else []

        if script.language == ScriptLanguage.PYTHON:
            return [sys.executable, path_str, *extra]
        if script.language == ScriptLanguage.JAVASCRIPT:
            return ["node", path_str, *extra]
        if script.language == ScriptLanguage.R2_COMMANDS:
            return ["r2", "-q", "-i", path_str, *extra]
        if script.language == ScriptLanguage.JAVA:
            return self._build_ghidra_command(path, extra)
        return self._build_x64dbg_command(path, extra)

    @staticmethod
    def _build_ghidra_command(script_path: Path, extra: list[str]) -> list[str]:
        """Construct a Ghidra ``analyzeHeadless`` invocation for a Java script.

        Args:
            script_path: On-disk path to the Ghidra Java script.
            extra: Additional arguments to forward after the script
                directory and script name.

        Returns:
            list[str]: ``analyzeHeadless`` argv that runs the script in a
            transient project rooted at the script's parent directory.
        """
        project_dir = str(script_path.parent)
        project_name = f"intellicrack_exec_{script_path.stem}"
        return [
            "analyzeHeadless",
            project_dir,
            project_name,
            "-scriptPath",
            project_dir,
            "-postScript",
            script_path.name,
            "-deleteProject",
            "-noanalysis",
            *extra,
        ]

    @staticmethod
    def _build_x64dbg_command(script_path: Path, extra: list[str]) -> list[str]:
        """Construct an x64dbg invocation for a debugger script.

        Args:
            script_path: On-disk path to the x64dbg script file.
            extra: Additional arguments to forward to the x64dbg binary
                after the ``-script`` switch and script path.

        Returns:
            list[str]: x64dbg argv. The 64-bit binary (``x64dbg``) is
            preferred; on platforms without it the 32-bit binary
            (``x32dbg``) is used as a fall back. ``ProcessManager`` is
            responsible for surfacing missing binaries via
            :class:`FileNotFoundError`.
        """
        runner = "x64dbg" if shutil.which("x64dbg") is not None else "x32dbg"
        return [runner, "-script", str(script_path), *extra]

    @staticmethod
    def _materialise_script_path(script: Script) -> Path:
        """Return an on-disk path for ``script``, writing if necessary.

        When the script already has a recorded :attr:`Script.saved_path`
        that exists, that path is returned unchanged. Otherwise the
        content is written to a fresh temporary file with the script's
        canonical extension and that path is returned.

        Args:
            script: Script whose content needs to be on disk.

        Returns:
            Path: Filesystem path containing the script's current content.
        """
        if script.saved_path is not None and script.saved_path.exists():
            return script.saved_path

        suffix = script.get_extension()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8",
        ) as fh:
            fh.write(script.content)
            tmp_path = Path(fh.name)
        _logger.debug("script_execute_temp_materialised", script=script.name, path=str(tmp_path))
        return tmp_path


def get_frida_api_reference() -> dict[str, str]:
    """Get Frida API reference for AI context.

    Returns:
        dict[str, str]: Dictionary mapping API categories to usage examples.
    """
    return {
        "process": ("Process.findModuleByName(name), Process.enumerateModules(), Process.enumerateRanges(protection)"),
        "module": ("Module.findExportByName(module, name), module.base, module.size, module.enumerateExports(), module.enumerateImports()"),
        "memory": "Memory.readByteArray(addr, length), Memory.writeByteArray(addr, bytes), Memory.protect(addr, size, protection), Memory.scanSync(addr, size, pattern)",
        "interceptor": "Interceptor.attach(target, {onEnter, onLeave}), Interceptor.replace(target, replacement), Interceptor.revert(target)",
        "native_function": ("new NativeFunction(addr, retType, argTypes), new NativeCallback(func, retType, argTypes)"),
        "stalker": ("Stalker.follow(threadId, {events, onReceive, transform}), Stalker.unfollow(threadId)"),
    }


def get_ghidra_api_reference() -> dict[str, str]:
    """Get Ghidra API reference for AI context.

    Returns:
        dict[str, str]: Dictionary mapping API categories to usage examples.
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
        dict[str, str]: Dictionary mapping command categories to examples.
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
        dict[str, str]: Dictionary mapping command categories to examples.
    """
    return {
        "breakpoints": ("bp addr (set bp), bc addr (clear bp), bph addr (hardware bp)"),
        "stepping": "sti (step into), sto (step over), run (continue)",
        "memory": ("dump addr (view memory), fill addr,size,byte (fill memory)"),
        "patching": 'assemble addr, "instruction" (assemble), patch addr, bytes (patch)',
        "scripting": 'scriptload path, scriptcmd "command"',
    }


_DEFAULT_API_REFERENCE_GETTERS: Final[dict[str, _ApiRefGetter]] = {
    "frida": get_frida_api_reference,
    "ghidra": get_ghidra_api_reference,
    "cutter": get_cutter_reference,
    "x64dbg": get_x64dbg_reference,
}


def _build_ai_prompt(
    context: ScriptContext,
    language: ScriptLanguage,
    api_reference: dict[str, str],
) -> str:
    """Compose the full AI prompt from a context and an API reference dict.

    Args:
        context: Analysis context describing the target binary and any
            artifacts upstream tools have surfaced.
        language: Target script language; used for the prompt label.
        api_reference: Pre-resolved language-specific API reference
            dictionary. Pass ``{}`` to skip the reference block.

    Returns:
        str: Fully formatted prompt text, stripped of leading and
        trailing whitespace.
    """
    context_str = context.to_prompt_context(language)
    if api_reference and "API Reference:" not in context_str:
        ref_lines = [f"\n{language.value.upper()} API Reference:"]
        ref_lines.extend(f"  {category}: {usage}" for category, usage in api_reference.items())
        context_str = f"{context_str}\n" + "\n".join(ref_lines)

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


def _resolve_api_reference(language: ScriptLanguage) -> dict[str, str]:
    """Return the API reference dict for a language without any caching.

    Args:
        language: Script language whose reference to fetch.

    Returns:
        dict[str, str]: Reference categories mapped to usage examples,
        or an empty dict when no reference is registered for the
        language.
    """
    api_ref_key = ScriptContext.LANGUAGE_API_MAP.get(language)
    if api_ref_key is None:
        return {}
    getter = _DEFAULT_API_REFERENCE_GETTERS.get(api_ref_key)
    return getter() if getter is not None else {}


class _PrepareAIPromptDescriptor:
    """Descriptor that lets ``prepare_ai_prompt`` work as both bound and unbound.

    Bound to an instance, it forwards the call to the per-instance implementation so the cached API reference is reused. Accessed through
    the class (``ScriptGenerator.prepare_ai_prompt(...)``), it resolves the API reference fresh for the call so legacy callers that treat
    the method as a free function still get a complete prompt without leaving a cache entry behind.
    """

    def __set_name__(self, owner: type, name: str) -> None:
        """Capture the attribute name the descriptor is bound to.

        Args:
            owner: The class the descriptor is being attached to.
            name: The attribute name used to reach the descriptor.
        """
        self._attr_name = name

    def __get__(
        self,
        instance: ScriptGenerator | None,
        owner: type[ScriptGenerator],
    ) -> Callable[[ScriptContext, ScriptLanguage], str]:
        """Return either the bound or unbound prompt builder.

        Args:
            instance: The ``ScriptGenerator`` instance the attribute is
                accessed through, or ``None`` for class-level access.
            owner: The owning class.

        Returns:
            Callable[[ScriptContext, ScriptLanguage], str]: A callable
            that produces the full prompt string. When ``instance`` is
            not ``None`` the callable closes over the existing instance
            so the per-instance API-reference cache is honored;
            otherwise the callable resolves the reference fresh on
            each invocation.
        """
        if instance is None:

            def _unbound(context: ScriptContext, language: ScriptLanguage) -> str:
                """Build the prompt via a fresh API reference lookup.

                Args:
                    context: Analysis context to embed in the prompt.
                    language: Target script language.

                Returns:
                    str: Fully formatted prompt text.
                """
                return _build_ai_prompt(context, language, _resolve_api_reference(language))

            return _unbound

        bound_instance = instance

        def _bound(context: ScriptContext, language: ScriptLanguage) -> str:
            """Build the prompt against ``instance``'s cache.

            Args:
                context: Analysis context to embed in the prompt.
                language: Target script language.

            Returns:
                str: Fully formatted prompt text.
            """
            return _build_ai_prompt(context, language, bound_instance.api_reference(language))

        return _bound


class ScriptGenerator:
    """Stateful entry point for building AI prompts that generate scripts.

    ``ScriptGenerator`` is the API surface consumed by the Intellicrack
    application shell (``main.py``) and by tool/AI bridges that need to
    turn a :class:`ScriptContext` into a prompt string ready for a
    language model.

    The instance owns three pieces of state that are referenced by the
    public ``generate_*`` helpers:

    * ``validator`` - a :class:`ScriptValidator` instance used to
      pre-flight script content before it is shipped to an external
      execution bridge.
    * ``output_dir`` - the directory under which generated scripts and
      drafts are persisted. Defaults to ``Path.cwd() / "generated_scripts"``
      and is created lazily by :meth:`prepare_output_path`.
    * An API-reference cache populated lazily by :meth:`api_reference`
      so the language-specific reference dicts are computed at most once
      per (language, generator) pair.

    All constructor parameters are optional so existing call sites
    (``main.py``, ``ui/app.py``, ``ui/tools.py``,
    ``ui/panels/script_manager.py``, ``core/orchestrator.py``) keep
    compiling with ``ScriptGenerator()``.
    """

    DEFAULT_OUTPUT_DIRNAME: ClassVar[str] = "generated_scripts"

    def __init__(
        self,
        validator: ScriptValidator | None = None,
        output_dir: Path | None = None,
    ) -> None:
        """Initialize the ScriptGenerator with stateful dependencies.

        Args:
            validator: Optional :class:`ScriptValidator` instance to reuse
                for pre-flight validation. A fresh instance is created
                when not supplied.
            output_dir: Optional directory under which generated scripts
                and drafts will be persisted. Defaults to
                ``Path.cwd() / "generated_scripts"``. The directory is
                materialised on the filesystem only when
                :meth:`prepare_output_path` is invoked.
        """
        self.validator: ScriptValidator = validator if validator is not None else ScriptValidator()
        self.output_dir: Path = output_dir if output_dir is not None else Path.cwd() / self.DEFAULT_OUTPUT_DIRNAME
        self._api_reference_cache: dict[ScriptLanguage, dict[str, str]] = {}
        _logger.debug(
            "script_generator_initialized",
            output_dir=str(self.output_dir),
            validator_id=id(self.validator),
        )

    def api_reference(self, language: ScriptLanguage) -> dict[str, str]:
        """Return the cached API reference for ``language``.

        Looks up the language-specific reference dict, populating the
        per-instance cache on first request. Languages without a known
        reference (currently ``PYTHON``) return an empty dict.

        Args:
            language: Script language whose reference to fetch.

        Returns:
            dict[str, str]: Reference categories mapped to usage examples,
            or an empty dict when no reference is registered for the
            language.
        """
        if (cached := self._api_reference_cache.get(language)) is not None:
            return cached

        ref = _resolve_api_reference(language)
        self._api_reference_cache[language] = ref
        return ref

    def prepare_output_path(self, name: str, language: ScriptLanguage) -> Path:
        """Resolve and ensure the output path for a generated script.

        Materialises :attr:`output_dir` on the filesystem (creating any
        missing parents) and returns the canonical path that
        ``name``/``language`` should be written to. The file itself is
        not created here; only the directory is ensured.

        Args:
            name: Script base name without extension.
            language: Target script language; controls the file extension.

        Returns:
            Path: Absolute path the caller can pass to
            :meth:`Script.save` or :meth:`ScriptManager.save_script`.
        """
        _logger.debug("script_prepare_output_path", script_name=name, language=language.value, output_dir=str(self.output_dir))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        extensions = {
            ScriptLanguage.JAVASCRIPT: ".js",
            ScriptLanguage.JAVA: ".java",
            ScriptLanguage.PYTHON: ".py",
            ScriptLanguage.R2_COMMANDS: ".r2",
            ScriptLanguage.X64DBG_SCRIPT: ".txt",
        }
        result_path = self.output_dir / f"{name}{extensions.get(language, '.txt')}"
        _logger.debug("script_output_path_resolved", path=str(result_path))
        return result_path

    prepare_ai_prompt: ClassVar[_PrepareAIPromptDescriptor] = _PrepareAIPromptDescriptor()
    """Build the AI prompt, dispatching as bound or unbound automatically.

    Calling ``generator.prepare_ai_prompt(context, language)`` consults the instance's API-reference cache. Calling
    ``ScriptGenerator.prepare_ai_prompt(context, language)`` keeps legacy free-function-style call sites working by resolving the API
    reference fresh on each invocation. The signature in both cases is ``(context: ScriptContext, language: ScriptLanguage) -> str``.
    """

    def generate_frida(self, context: ScriptContext) -> str:
        """Build an AI prompt targeted at Frida (JavaScript) script generation.

        Args:
            context: Analysis context to embed in the prompt.

        Returns:
            str: Prompt text with the Frida/JavaScript API reference included.
        """
        return self.prepare_ai_prompt(context, ScriptLanguage.JAVASCRIPT)

    def generate_ghidra(self, context: ScriptContext) -> str:
        """Build an AI prompt targeted at Ghidra (Java) script generation.

        Args:
            context: Analysis context to embed in the prompt.

        Returns:
            str: Prompt text with the Ghidra Java API reference included.
        """
        return self.prepare_ai_prompt(context, ScriptLanguage.JAVA)

    def generate_python(self, context: ScriptContext) -> str:
        """Build an AI prompt targeted at generic Python script generation.

        Args:
            context: Analysis context to embed in the prompt.

        Returns:
            str: Prompt text for a Python script (no vendor API reference).
        """
        return self.prepare_ai_prompt(context, ScriptLanguage.PYTHON)

    def generate_cutter(self, context: ScriptContext) -> str:
        """Build an AI prompt targeted at Cutter/Rizin command script generation.

        Args:
            context: Analysis context to embed in the prompt.

        Returns:
            str: Prompt text with the Cutter/Rizin command reference included.
        """
        return self.prepare_ai_prompt(context, ScriptLanguage.R2_COMMANDS)

    def generate_x64dbg(self, context: ScriptContext) -> str:
        """Build an AI prompt targeted at x64dbg script generation.

        Args:
            context: Analysis context to embed in the prompt.

        Returns:
            str: Prompt text with the x64dbg command reference included.
        """
        return self.prepare_ai_prompt(context, ScriptLanguage.X64DBG_SCRIPT)
