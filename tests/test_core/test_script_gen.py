# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.script_gen module - script infrastructure."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest

from intellicrack.core.script_gen import (
    BypassStrategy,
    Script,
    ScriptContext,
    ScriptGenerator,
    ScriptLanguage,
    ScriptManager,
    ScriptValidator,
    get_cutter_reference,
    get_frida_api_reference,
    get_ghidra_api_reference,
    get_x64dbg_reference,
)


_MODULE_BASE: Final[int] = 0x00400000
_FUNC_ADDR: Final[int] = 0x00401000
_MAGIC_CONST: Final[int] = 0xDEADBEEF
_LANGUAGE_COUNT: Final[int] = 5
_FRIDA_API_KEYS: Final[int] = 6
_GHIDRA_API_KEYS: Final[int] = 5
_CUTTER_REF_KEYS: Final[int] = 6
_X64DBG_REF_KEYS: Final[int] = 5


# --- ScriptLanguage enum ---


def test_script_language_values() -> None:
    """Verify ScriptLanguage enum has all expected values."""
    assert len(ScriptLanguage) == _LANGUAGE_COUNT
    assert ScriptLanguage.JAVASCRIPT.value == "javascript"
    assert ScriptLanguage.JAVA.value == "java"
    assert ScriptLanguage.PYTHON.value == "python"
    assert ScriptLanguage.R2_COMMANDS.value == "r2_commands"
    assert ScriptLanguage.X64DBG_SCRIPT.value == "x64dbg_script"


# --- BypassStrategy enum ---


def test_bypass_strategy_members_complete() -> None:
    """Verify BypassStrategy exposes exactly the independently enumerated members.

    The expected member-name-to-value mapping is enumerated here independently
    of the production enum, so this gate fails if the production enum drops,
    renames, or relabels any strategy -- not merely if a cardinality counter
    drifts. Analogous to ``test_script_get_extension_coverage_completeness``.
    """
    expected: dict[str, str] = {
        "RETURN_TRUE": "return_true",
        "RETURN_FALSE": "return_false",
        "RETURN_ZERO": "return_zero",
        "RETURN_ONE": "return_one",
        "NOP_FUNCTION": "nop_function",
        "SKIP_CHECK": "skip_check",
        "PATCH_JUMP": "patch_jump",
        "HOOK_REPLACE": "hook_replace",
        "MEMORY_PATCH": "memory_patch",
        "INLINE_PATCH": "inline_patch",
        "VIRTUALIZATION_DEFEAT": "virtualization_defeat",
    }
    actual: dict[str, str] = {member.name: member.value for member in BypassStrategy}
    assert actual == expected, f"BypassStrategy members diverged from expected set: {actual}"


@pytest.mark.parametrize(
    ("strategy", "expected_value"),
    [
        (BypassStrategy.RETURN_TRUE, "return_true"),
        (BypassStrategy.RETURN_FALSE, "return_false"),
        (BypassStrategy.RETURN_ZERO, "return_zero"),
        (BypassStrategy.RETURN_ONE, "return_one"),
        (BypassStrategy.NOP_FUNCTION, "nop_function"),
        (BypassStrategy.SKIP_CHECK, "skip_check"),
        (BypassStrategy.PATCH_JUMP, "patch_jump"),
        (BypassStrategy.HOOK_REPLACE, "hook_replace"),
        (BypassStrategy.MEMORY_PATCH, "memory_patch"),
        (BypassStrategy.INLINE_PATCH, "inline_patch"),
        (BypassStrategy.VIRTUALIZATION_DEFEAT, "virtualization_defeat"),
    ],
)
def test_bypass_strategy_values(strategy: BypassStrategy, expected_value: str) -> None:
    """Verify BypassStrategy values match expected strings.

    Args:
        strategy: The strategy enum member.
        expected_value: Expected string value.
    """
    assert strategy.value == expected_value


def test_bypass_strategy_description_return_true() -> None:
    """Verify RETURN_TRUE description text."""
    assert "return true" in BypassStrategy.RETURN_TRUE.description.lower()


def test_bypass_strategy_description_nop() -> None:
    """Verify NOP_FUNCTION description text."""
    assert "nop" in BypassStrategy.NOP_FUNCTION.description.lower()


_EXPECTED_DESCRIPTIONS: Final[dict[BypassStrategy, str]] = {
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


def test_bypass_strategy_description_all_nonempty() -> None:
    """Verify every BypassStrategy description matches the independently enumerated oracle.

    The expected descriptions are derived from tool knowledge of each strategy's
    purpose, not from reading the production enum; any strategy whose description
    drifts, is blanked, or is relabelled to a different meaning will fail this gate.
    """
    actual: dict[BypassStrategy, str] = {strategy: strategy.description for strategy in BypassStrategy}
    assert actual == _EXPECTED_DESCRIPTIONS, "BypassStrategy descriptions diverged from oracle:\n" + "\n".join(
        f"  {s.name}: got {actual[s]!r}, want {_EXPECTED_DESCRIPTIONS[s]!r}"
        for s in BypassStrategy
        if actual[s] != _EXPECTED_DESCRIPTIONS[s]
    )


# --- ScriptContext ---


def test_script_context_defaults() -> None:
    """Verify ScriptContext default field values."""
    ctx = ScriptContext(binary_name="test.exe")
    assert ctx.binary_name == "test.exe"
    assert ctx.architecture == "x64"
    assert ctx.platform == "windows"
    assert ctx.binary_path is None
    assert ctx.module_base is None
    assert ctx.target_functions == []
    assert ctx.identified_protections == []
    assert ctx.crypto_apis == []
    assert ctx.string_references == []
    assert ctx.magic_constants == []
    assert ctx.additional_context == {}


def test_script_context_to_prompt_minimal() -> None:
    """Verify to_prompt_context with minimal context."""
    ctx = ScriptContext(binary_name="app.exe")
    result = ctx.to_prompt_context()
    assert "app.exe" in result
    assert "x64" in result
    assert "windows" in result


def test_script_context_to_prompt_with_path() -> None:
    """Verify to_prompt_context emits the exact Path: line for the provided binary_path.

    The oracle is the str() rendering of the Path object as formatted by
    to_prompt_context, not just a header keyword. Any implementation that emits a
    wrong path value, omits the value, or changes the label fails this gate.
    """
    binary_path = Path("C:/test/app.exe")
    ctx = ScriptContext(
        binary_name="app.exe",
        binary_path=binary_path,
    )
    result = ctx.to_prompt_context()
    expected_line = f"Path: {binary_path}"
    assert expected_line in result, f"Expected line {expected_line!r} not found in to_prompt_context output:\n{result}"


def test_script_context_to_prompt_with_module_base() -> None:
    """Verify to_prompt_context includes module base address."""
    ctx = ScriptContext(
        binary_name="app.exe",
        module_base=_MODULE_BASE,
    )
    result = ctx.to_prompt_context()
    assert "Module Base:" in result
    assert "400000" in result


def test_script_context_to_prompt_with_target_functions() -> None:
    """Verify to_prompt_context includes target functions."""
    ctx = ScriptContext(
        binary_name="app.exe",
        target_functions=[
            {"name": "checkLicense", "address": _FUNC_ADDR, "strategy": "return_true"},
        ],
    )
    result = ctx.to_prompt_context()
    assert "Target Functions:" in result
    assert "checkLicense" in result


def test_script_context_to_prompt_with_protections() -> None:
    """Verify to_prompt_context includes protection list."""
    ctx = ScriptContext(
        binary_name="app.exe",
        identified_protections=["VMProtect", "Themida"],
    )
    result = ctx.to_prompt_context()
    assert "Protections:" in result
    assert "VMProtect" in result


def test_script_context_to_prompt_with_crypto_apis() -> None:
    """Verify to_prompt_context includes crypto APIs."""
    ctx = ScriptContext(
        binary_name="app.exe",
        crypto_apis=["CryptDecrypt", "BCryptHash"],
    )
    result = ctx.to_prompt_context()
    assert "Crypto APIs:" in result
    assert "CryptDecrypt" in result


def test_script_context_to_prompt_with_strings() -> None:
    """Verify to_prompt_context includes string references."""
    ctx = ScriptContext(
        binary_name="app.exe",
        string_references=["License expired", "Invalid key"],
    )
    result = ctx.to_prompt_context()
    assert "Relevant Strings:" in result
    assert "License expired" in result


def test_script_context_to_prompt_with_magic_constants() -> None:
    """Verify to_prompt_context includes magic constants."""
    ctx = ScriptContext(
        binary_name="app.exe",
        magic_constants=[_MAGIC_CONST],
    )
    result = ctx.to_prompt_context()
    assert "Magic Constants:" in result
    assert "DEADBEEF" in result


def test_script_context_to_prompt_with_additional_context() -> None:
    """Verify to_prompt_context formats each additional_context entry as '  - key: value'.

    The oracle is the exact formatted line ``  - compiler: 'MSVC'`` produced by
    the f-string ``f"  - {k}: {v!r}"`` in to_prompt_context. Asserting only the
    key name would pass a broken implementation that emits the key but not the
    value; asserting the exact formatted entry fails if the key, value, quoting,
    or indentation changes.
    """
    ctx = ScriptContext(
        binary_name="app.exe",
        additional_context={"compiler": "MSVC"},
    )
    result = ctx.to_prompt_context()
    assert "Additional Analysis Context:" in result
    expected_entry = "  - compiler: 'MSVC'"
    assert expected_entry in result, f"Expected entry {expected_entry!r} not found in to_prompt_context output:\n{result}"


def test_script_context_to_prompt_with_language() -> None:
    """Verify to_prompt_context embeds the exact Frida API reference entries for JAVASCRIPT.

    The independent oracle is get_frida_api_reference() called directly. Each
    category-to-usage pair emitted by to_prompt_context must exactly match the
    frida reference dict; an implementation that emits a wrong key name, truncates
    a value, or skips an entry fails this gate.
    """
    ctx = ScriptContext(binary_name="app.exe")
    result = ctx.to_prompt_context(language=ScriptLanguage.JAVASCRIPT)
    assert "JAVASCRIPT API Reference:" in result
    oracle = get_frida_api_reference()
    for category, usage in oracle.items():
        expected_entry = f"  {category}: {usage}"
        assert expected_entry in result, f"API reference entry {expected_entry!r} not found in to_prompt_context output:\n{result}"


def test_script_context_to_prompt_python_no_api_ref() -> None:
    """Verify to_prompt_context omits API ref for Python (no mapping)."""
    ctx = ScriptContext(binary_name="app.exe")
    result = ctx.to_prompt_context(language=ScriptLanguage.PYTHON)
    assert "API Reference:" not in result


def test_script_context_target_function_bypass_strategy_enum() -> None:
    """Verify to_prompt_context handles BypassStrategy enum in functions."""
    ctx = ScriptContext(
        binary_name="app.exe",
        target_functions=[
            {"name": "validate", "address": _FUNC_ADDR, "strategy": BypassStrategy.PATCH_JUMP},
        ],
    )
    result = ctx.to_prompt_context()
    assert "patch_jump" in result


def test_script_context_target_function_unknown_strategy() -> None:
    """Verify to_prompt_context handles unknown strategy strings."""
    ctx = ScriptContext(
        binary_name="app.exe",
        target_functions=[
            {"name": "func", "address": _FUNC_ADDR, "strategy": "custom_strat"},
        ],
    )
    result = ctx.to_prompt_context()
    assert "custom_strat" in result


# --- Script ---


def _make_script(**overrides: str | int | ScriptLanguage) -> Script:
    """Create a Script with sensible defaults.

    Args:
        **overrides: Field overrides for the Script.

    Returns:
        Script: Script instance.
    """
    defaults: dict[str, Any] = {
        "name": "test_script",
        "script_type": "python",
        "language": ScriptLanguage.PYTHON,
        "content": "print('hello')",
        "description": "Test script",
    } | overrides
    return Script(**defaults)


def test_script_construction() -> None:
    """Verify Script dataclass construction."""
    script = _make_script()
    assert script.name == "test_script"
    assert script.script_type == "python"
    assert script.language == ScriptLanguage.PYTHON
    assert script.verified is False
    assert script.execution_results == {}


def test_script_add_execution_result() -> None:
    """Verify add_execution_result stores tool result."""
    script = _make_script()
    script.add_execution_result("frida", {"status": "ok"})
    assert "frida" in script.execution_results
    assert script.execution_results["frida"] == {"status": "ok"}
    assert "last_run" in script.execution_results


def test_script_add_execution_result_overwrites() -> None:
    """Verify add_execution_result overwrites previous result."""
    script = _make_script()
    script.add_execution_result("frida", "first")
    script.add_execution_result("frida", "second")
    assert script.execution_results["frida"] == "second"


def test_script_save(tmp_path: Path) -> None:
    """Verify save writes content to file.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script = _make_script(content="# test content")
    out_path = tmp_path / "scripts" / "test.py"
    script.save(out_path)
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == "# test content"


def test_script_save_creates_parent_dirs(tmp_path: Path) -> None:
    """Verify save creates parent directories.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script = _make_script()
    deep_path = tmp_path / "a" / "b" / "c" / "script.py"
    script.save(deep_path)
    assert deep_path.exists()


_LANGUAGE_EXTENSIONS: Final[list[tuple[ScriptLanguage, str]]] = [
    (ScriptLanguage.JAVASCRIPT, ".js"),
    (ScriptLanguage.JAVA, ".java"),
    (ScriptLanguage.PYTHON, ".py"),
    (ScriptLanguage.R2_COMMANDS, ".r2"),
    (ScriptLanguage.X64DBG_SCRIPT, ".txt"),
]

_LANGUAGE_SCRIPT_TYPES: Final[dict[ScriptLanguage, str]] = {
    ScriptLanguage.JAVASCRIPT: "frida",
    ScriptLanguage.JAVA: "ghidra",
    ScriptLanguage.PYTHON: "python",
    ScriptLanguage.R2_COMMANDS: "cutter",
    ScriptLanguage.X64DBG_SCRIPT: "x64dbg",
}


def test_script_get_extension_coverage_completeness() -> None:
    """Verify _LANGUAGE_EXTENSIONS covers every ScriptLanguage enum member.

    If a new ScriptLanguage variant is added without a corresponding entry in
    _LANGUAGE_EXTENSIONS, this test fails immediately, preventing silent gaps
    in the parametrized test_script_get_extension suite from hiding a missing
    extension mapping.
    """
    covered_languages = {lang for lang, _ in _LANGUAGE_EXTENSIONS}
    all_languages = set(ScriptLanguage)
    missing = all_languages - covered_languages
    assert missing == set(), f"ScriptLanguage members missing from _LANGUAGE_EXTENSIONS: {missing}"


@pytest.mark.parametrize(("language", "expected_ext"), _LANGUAGE_EXTENSIONS)
def test_script_get_extension(language: ScriptLanguage, expected_ext: str) -> None:
    """Verify get_extension returns the conventional extension for each language.

    The expected extension is the well-known file-type convention for each
    tool's scripts (Frida ``.js``, Ghidra ``.java``, Python ``.py``, Rizin/r2
    ``.r2``, x64dbg ``.txt``) -- an oracle independent of the production map.
    The extension is the actual suffix used by each tool's native format, not
    a value derived from the implementation under test.

    Args:
        language: Script language.
        expected_ext: Conventional file extension for that language.
    """
    script = _make_script(language=language)
    ext = script.get_extension()
    assert ext == expected_ext, f"get_extension() returned {ext!r} for {language.name} but expected {expected_ext!r}"
    assert ext.startswith("."), f"Extension {ext!r} must start with a dot"
    assert ext == ext.lower(), f"Extension {ext!r} must be lowercase"


@pytest.mark.parametrize(("language", "expected_ext"), _LANGUAGE_EXTENSIONS)
def test_script_get_extension_roundtrip_through_load_script(
    language: ScriptLanguage,
    expected_ext: str,
    tmp_path: Path,
) -> None:
    """Verify the extension returned by get_extension() is consistent with load_script().

    This roundtrip test exercises both maps in the production code: the
    get_extension() map (Script._extensions) and the load_script() extension-to-
    language map. If either map regresses -- e.g. get_extension() returns ``.py``
    for JAVASCRIPT, or load_script() maps ``.js`` to PYTHON -- the recovered
    language will not match the original and this test fails.

    Args:
        language: Script language to roundtrip.
        expected_ext: Conventional file extension for that language.
        tmp_path: Pytest temporary directory.
    """
    script = _make_script(name="roundtrip", language=language, content=f"// body for {language.value}")
    ext = script.get_extension()
    assert ext == expected_ext

    disk_path = tmp_path / f"roundtrip{ext}"
    disk_path.write_text(script.content, encoding="utf-8")

    mgr = ScriptManager(tmp_path)
    loaded = mgr.load_script(disk_path)

    assert loaded is not None, f"load_script returned None for {disk_path}"
    assert loaded.language == language, (
        f"load_script recovered language {loaded.language!r} but expected {language!r} after roundtrip via extension {ext!r}"
    )
    assert loaded.script_type == _LANGUAGE_SCRIPT_TYPES[language], (
        f"load_script recovered script_type {loaded.script_type!r} but expected {_LANGUAGE_SCRIPT_TYPES[language]!r} for {language.name}"
    )
    assert loaded.content == script.content, f"Content mismatch after roundtrip: {loaded.content!r} != {script.content!r}"


@pytest.mark.parametrize(("language", "expected_ext"), _LANGUAGE_EXTENSIONS)
def test_script_manager_save_uses_language_extension_on_disk(
    language: ScriptLanguage,
    expected_ext: str,
    tmp_path: Path,
) -> None:
    """Verify ScriptManager.save_script writes a file named by the language enum.

    This exercises the real persistence path: ``save_script`` derives the
    on-disk filename from ``Script.get_extension()``. A regression in the
    enum-to-extension mapping (or in the path-building logic that consumes
    it) would produce a file with the wrong suffix and fail this test.

    Args:
        language: Script language driving the on-disk extension.
        expected_ext: Conventional file extension for that language.
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    body = f"// {language.value} payload"
    mgr.add_script(_make_script(name="persisted", language=language, content=body), validate=False)

    saved = mgr.save_script("persisted")

    assert saved is not None
    assert saved.exists()
    assert saved.suffix == expected_ext
    assert saved.name == f"persisted{expected_ext}"
    assert saved.parent == tmp_path
    assert saved.read_text(encoding="utf-8") == body


def test_script_context_to_prompt_full_structure_exact_layout() -> None:
    """Verify to_prompt_context emits the exact expected multi-section layout.

    A fully populated context is rendered to its prompt form and compared
    against a hand-written expected string. This pins the section order,
    headers, address formatting, strategy-description expansion, and the
    Frida API-reference footer -- any silent reordering, dropped section, or
    formatting drift in the rich output is caught.
    """
    ctx = ScriptContext(
        binary_name="app.exe",
        architecture="x64",
        platform="windows",
        binary_path=Path("C:/bin/app.exe"),
        module_base=_MODULE_BASE,
        target_functions=[{"name": "checkLicense", "address": _FUNC_ADDR, "strategy": "return_true"}],
        identified_protections=["VMProtect", "Themida"],
        crypto_apis=["CryptDecrypt"],
        string_references=["License expired"],
        magic_constants=[_MAGIC_CONST],
        additional_context={"compiler": "MSVC"},
    )

    result = ctx.to_prompt_context(language=ScriptLanguage.JAVASCRIPT)

    strategy_desc = f"return_true ({BypassStrategy.RETURN_TRUE.description})"
    frida_ref = get_frida_api_reference()
    expected_lines = [
        "Binary: app.exe",
        "Architecture: x64",
        "Platform: windows",
        "Path: C:\\bin\\app.exe",
        "Module Base: 0x400000",
        "",
        "Target Functions:",
        f"  - checkLicense @ 0x401000 (strategy: {strategy_desc})",
        "",
        "Protections: VMProtect, Themida",
        "",
        "Crypto APIs: CryptDecrypt",
        "",
        "Relevant Strings:",
        "  - 'License expired'",
        "",
        "Magic Constants:",
        "  - 0xDEADBEEF (3735928559)",
        "",
        "Additional Analysis Context:",
        "  - compiler: 'MSVC'",
        "",
        "JAVASCRIPT API Reference:",
        *[f"  {category}: {usage}" for category, usage in frida_ref.items()],
    ]
    assert result == "\n".join(expected_lines)


# --- ScriptValidator ---


def test_validator_python_valid() -> None:
    """Verify validate_python accepts valid Python."""
    is_valid, error = ScriptValidator.validate_python("x = 1\nprint(x)")
    assert is_valid is True
    assert error is None


def test_validator_python_syntax_error() -> None:
    """Verify validate_python rejects syntax errors."""
    is_valid, error = ScriptValidator.validate_python("def foo(")
    assert is_valid is False
    assert error is not None
    assert "Syntax error" in error


def test_validator_python_empty() -> None:
    """Verify validate_python accepts empty string."""
    is_valid, error = ScriptValidator.validate_python("")
    assert is_valid is True
    assert error is None


def test_validator_java_valid() -> None:
    """Verify validate_java accepts valid Ghidra script structure."""
    content = """
import ghidra.app.script.GhidraScript;
public class MyScript extends GhidraScript {
    public void run() {
        println("Hello");
    }
}
"""
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is True
    assert error is None


def test_validator_java_missing_import() -> None:
    """Verify validate_java rejects missing import."""
    content = """
public class MyScript {
    public void run() {}
}
"""
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "import" in error


def test_validator_java_missing_public() -> None:
    """Verify validate_java rejects missing public keyword."""
    content = """
import ghidra.app.script.GhidraScript;
class MyScript {
    void run() {}
}
"""
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "public" in error


def test_validator_java_missing_run() -> None:
    """Verify validate_java rejects missing void run()."""
    content = """
import ghidra.app.script.GhidraScript;
public class MyScript {
    public void execute() {}
}
"""
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "void run(" in error


def test_validator_java_unbalanced_braces() -> None:
    """Verify validate_java rejects unbalanced braces."""
    content = """
import ghidra.app.script.GhidraScript;
public class MyScript {
    public void run() {
        println("Hello");
}
"""
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "Unbalanced" in error


def test_validator_validate_method_python() -> None:
    """Verify validate() dispatches to Python validator."""
    validator = ScriptValidator()
    script = _make_script(content="x = 1")
    is_valid, error = validator.validate(script)
    assert is_valid is True
    assert error is None
    assert script.verified is True


def test_validator_validate_method_unsupported_language() -> None:
    """Verify validate() rejects unsupported languages instead of faking success."""
    validator = ScriptValidator()
    script = _make_script(language=ScriptLanguage.R2_COMMANDS, content="aaa")
    is_valid, error = validator.validate(script)
    assert is_valid is False
    assert error is not None
    assert "r2_commands" in error
    assert script.verified is False


def test_validator_validate_method_invalid_python() -> None:
    """Verify validate() sets verified=False for invalid Python."""
    validator = ScriptValidator()
    script = _make_script(content="def (bad")
    is_valid, error = validator.validate(script)
    assert is_valid is False
    assert error is not None
    assert script.verified is False


# --- ScriptManager ---


def test_manager_add_and_get(tmp_path: Path) -> None:
    """Verify add_script stores and get_script retrieves.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = _make_script()
    assert mgr.add_script(script, validate=False) is True
    assert mgr.get_script("test_script") is script


def test_manager_add_with_validation(tmp_path: Path) -> None:
    """Verify add_script validates and rejects invalid scripts.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    bad_script = _make_script(content="def (bad")
    assert mgr.add_script(bad_script, validate=True) is False
    assert mgr.get_script("test_script") is None


def test_manager_get_nonexistent(tmp_path: Path) -> None:
    """Verify get_script returns None for unknown name.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.get_script("no_such") is None


def test_manager_delete_script(tmp_path: Path) -> None:
    """Verify delete_script removes from cache.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(), validate=False)
    assert mgr.delete_script("test_script") is True
    assert mgr.get_script("test_script") is None


def test_manager_delete_nonexistent(tmp_path: Path) -> None:
    """Verify delete_script returns False for unknown name.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.delete_script("no_such") is False


def test_manager_list_scripts_all(tmp_path: Path) -> None:
    """Verify list_scripts returns all script names.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(name="a"), validate=False)
    mgr.add_script(_make_script(name="b"), validate=False)
    names = mgr.list_scripts()
    assert "a" in names
    assert "b" in names


def test_manager_list_scripts_filtered(tmp_path: Path) -> None:
    """Verify list_scripts filters by script_type.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(name="py1", script_type="python"), validate=False)
    mgr.add_script(
        _make_script(
            name="js1",
            script_type="frida",
            language=ScriptLanguage.JAVASCRIPT,
        ),
        validate=False,
    )
    py_scripts = mgr.list_scripts(script_type="python")
    assert "py1" in py_scripts
    assert "js1" not in py_scripts


def test_manager_save_script(tmp_path: Path) -> None:
    """Verify save_script writes to disk.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(content="# saved"), validate=False)
    result = mgr.save_script("test_script")
    assert result is not None
    assert result.exists()
    assert result.read_text(encoding="utf-8") == "# saved"


def test_manager_save_script_with_subdir(tmp_path: Path) -> None:
    """Verify save_script creates subdirectory.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(), validate=False)
    result = mgr.save_script("test_script", subdir="frida")
    assert result is not None
    assert "frida" in str(result.parent)


def test_manager_save_nonexistent(tmp_path: Path) -> None:
    """Verify save_script returns None for unknown name.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.save_script("no_such") is None


def test_manager_load_script_python(tmp_path: Path) -> None:
    """Verify load_script loads .py file as Python.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script_file = tmp_path / "loaded.py"
    script_file.write_text("x = 1", encoding="utf-8")
    mgr = ScriptManager(tmp_path)
    script = mgr.load_script(script_file)
    assert script is not None
    assert script.name == "loaded"
    assert script.language == ScriptLanguage.PYTHON
    assert script.script_type == "python"
    assert script.content == "x = 1"


def test_manager_load_script_javascript(tmp_path: Path) -> None:
    """Verify load_script loads .js file as JavaScript/Frida.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script_file = tmp_path / "hook.js"
    script_file.write_text("Interceptor.attach(...);", encoding="utf-8")
    mgr = ScriptManager(tmp_path)
    script = mgr.load_script(script_file)
    assert script is not None
    assert script.language == ScriptLanguage.JAVASCRIPT
    assert script.script_type == "frida"


def test_manager_load_script_java(tmp_path: Path) -> None:
    """Verify load_script loads .java file as Java/Ghidra.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script_file = tmp_path / "analyze.java"
    script_file.write_text("class A {}", encoding="utf-8")
    mgr = ScriptManager(tmp_path)
    script = mgr.load_script(script_file)
    assert script is not None
    assert script.language == ScriptLanguage.JAVA
    assert script.script_type == "ghidra"


def test_manager_load_script_r2(tmp_path: Path) -> None:
    """Verify load_script loads .r2 file as r2_commands/cutter.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script_file = tmp_path / "commands.r2"
    script_file.write_text("aaa\nafl", encoding="utf-8")
    mgr = ScriptManager(tmp_path)
    script = mgr.load_script(script_file)
    assert script is not None
    assert script.language == ScriptLanguage.R2_COMMANDS
    assert script.script_type == "cutter"


def test_manager_load_script_x64dbg(tmp_path: Path) -> None:
    """Verify load_script loads .txt file as x64dbg_script.

    Args:
        tmp_path: Pytest temporary directory.
    """
    script_file = tmp_path / "debug.txt"
    script_file.write_text("bp 0x401000", encoding="utf-8")
    mgr = ScriptManager(tmp_path)
    script = mgr.load_script(script_file)
    assert script is not None
    assert script.language == ScriptLanguage.X64DBG_SCRIPT
    assert script.script_type == "x64dbg"


def test_manager_load_script_not_found(tmp_path: Path) -> None:
    """Verify load_script returns None for missing file.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.load_script(tmp_path / "missing.py") is None


def test_manager_ensure_script_saved(tmp_path: Path) -> None:
    """Verify ensure_script_saved returns True when script exists.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(), validate=False)
    assert mgr.ensure_script_saved("test_script") is True


def test_manager_ensure_script_saved_not_found(tmp_path: Path) -> None:
    """Verify ensure_script_saved returns False for unknown name.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.ensure_script_saved("no_such") is False


def test_manager_reload_script(tmp_path: Path) -> None:
    """Verify reload_script refreshes from disk.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(content="original"), validate=False)
    mgr.save_script("test_script")

    saved_path = tmp_path / "test_script.py"
    saved_path.write_text("modified", encoding="utf-8")

    assert mgr.reload_script("test_script") is True
    reloaded = mgr.get_script("test_script")
    assert reloaded is not None
    assert reloaded.content == "modified"


def test_manager_reload_script_not_in_cache(tmp_path: Path) -> None:
    """Verify reload_script returns False if not in cache.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.reload_script("no_such") is False


def test_manager_reload_script_file_missing(tmp_path: Path) -> None:
    """Verify reload_script returns False if file doesn't exist.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(), validate=False)
    assert mgr.reload_script("test_script") is False


def test_manager_record_execution(tmp_path: Path) -> None:
    """Verify record_execution stores result in script.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    mgr.add_script(_make_script(), validate=False)
    assert mgr.record_execution("test_script", "frida", {"ok": True}) is True
    script = mgr.get_script("test_script")
    assert script is not None
    assert "frida" in script.execution_results


def test_manager_record_execution_not_found(tmp_path: Path) -> None:
    """Verify record_execution returns False for unknown script.

    Args:
        tmp_path: Pytest temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    assert mgr.record_execution("no_such", "frida", {}) is False


# --- API reference getters ---


def test_frida_api_reference_keys() -> None:
    """Verify Frida API reference maps categories to the real Frida JS API surface.

    Each asserted substring is an independent oracle: it is the actual Frida
    JavaScript API symbol documented by the Frida project for that category
    (``Interceptor.attach``, ``Memory.readByteArray``, ``Process.enumerateModules``,
    ``Stalker.follow``). A regression that drops a category, blanks a value, or
    pastes the wrong tool's syntax into a category fails this gate.
    """
    ref = get_frida_api_reference()
    assert len(ref) == _FRIDA_API_KEYS
    assert "Process.enumerateModules" in ref["process"]
    assert "Interceptor.attach" in ref["interceptor"]
    assert "Memory.readByteArray" in ref["memory"]
    assert "Stalker.follow" in ref["stalker"]


def test_ghidra_api_reference_keys() -> None:
    """Verify Ghidra API reference maps categories to the real Ghidra script API.

    Each asserted substring is an independent oracle drawn from Ghidra's
    GhidraScript / FlatProgramAPI: ``currentProgram`` for the program category,
    ``DecompInterface`` for the decompiler, and ``setBytes`` for patching. A
    regression that empties a value or swaps in unrelated text fails this gate.
    """
    ref = get_ghidra_api_reference()
    assert len(ref) == _GHIDRA_API_KEYS
    assert "currentProgram" in ref["program"]
    assert "DecompInterface" in ref["decompiler"]
    assert "setBytes" in ref["patching"]


def test_cutter_reference_keys() -> None:
    """Verify Cutter/Rizin reference maps categories to the real r2/rizin commands.

    Each asserted substring is an independent oracle: the actual radare2/rizin
    command for that category (``aaa`` analyze-all under analysis, ``wx`` write-hex
    under writing). A regression that blanks a value or substitutes a different
    tool's command fails this gate.
    """
    ref = get_cutter_reference()
    assert len(ref) == _CUTTER_REF_KEYS
    assert "aaa" in ref["analysis"]
    assert "wx" in ref["writing"]


def test_x64dbg_reference_keys() -> None:
    """Verify x64dbg reference maps categories to the real x64dbg script commands.

    Each asserted substring is an independent oracle: the actual x64dbg command
    for that category (``bp`` set-breakpoint under breakpoints, ``patch`` under
    patching). A regression that blanks a value or substitutes an unrelated
    command fails this gate.
    """
    ref = get_x64dbg_reference()
    assert len(ref) == _X64DBG_REF_KEYS
    assert "bp " in ref["breakpoints"]
    assert "patch " in ref["patching"]


# --- ScriptGenerator ---


def test_script_generator_prepare_ai_prompt() -> None:
    """Verify prepare_ai_prompt produces structured prompt."""
    ctx = ScriptContext(
        binary_name="target.exe",
        architecture="x64",
        platform="windows",
    )
    prompt = ScriptGenerator.prepare_ai_prompt(ctx, ScriptLanguage.JAVASCRIPT)
    assert "target.exe" in prompt
    assert "x64" in prompt
    assert "javascript" in prompt
    assert "ANALYSIS CONTEXT:" in prompt
    assert "TASK:" in prompt


def test_script_generator_prompt_includes_protections() -> None:
    """Verify prepare_ai_prompt includes protection info."""
    ctx = ScriptContext(
        binary_name="app.exe",
        identified_protections=["VMProtect"],
    )
    prompt = ScriptGenerator.prepare_ai_prompt(ctx, ScriptLanguage.PYTHON)
    assert "VMProtect" in prompt
