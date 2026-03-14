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
_BYPASS_STRATEGY_COUNT: Final[int] = 11
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


def test_bypass_strategy_count() -> None:
    """Verify BypassStrategy has all expected members."""
    assert len(BypassStrategy) == _BYPASS_STRATEGY_COUNT


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


def test_bypass_strategy_description_all_nonempty() -> None:
    """Verify all strategies have non-empty descriptions."""
    for strategy in BypassStrategy:
        assert strategy.description


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
    """Verify to_prompt_context includes binary path."""
    ctx = ScriptContext(
        binary_name="app.exe",
        binary_path=Path("C:/test/app.exe"),
    )
    result = ctx.to_prompt_context()
    assert "Path:" in result


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
    """Verify to_prompt_context includes additional context."""
    ctx = ScriptContext(
        binary_name="app.exe",
        additional_context={"compiler": "MSVC"},
    )
    result = ctx.to_prompt_context()
    assert "Additional Analysis Context:" in result
    assert "compiler" in result


def test_script_context_to_prompt_with_language() -> None:
    """Verify to_prompt_context includes API reference for language."""
    ctx = ScriptContext(binary_name="app.exe")
    result = ctx.to_prompt_context(language=ScriptLanguage.JAVASCRIPT)
    assert "API Reference:" in result


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


def _make_script(**overrides: Any) -> Script:
    """Create a Script with sensible defaults.

    Args:
        **overrides: Field overrides for the Script.

    Returns:
        Script instance.
    """
    defaults: dict[str, Any] = {
        "name": "test_script",
        "script_type": "python",
        "language": ScriptLanguage.PYTHON,
        "content": "print('hello')",
        "description": "Test script",
    }
    defaults.update(overrides)
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


@pytest.mark.parametrize(
    ("language", "expected_ext"),
    [
        (ScriptLanguage.JAVASCRIPT, ".js"),
        (ScriptLanguage.JAVA, ".java"),
        (ScriptLanguage.PYTHON, ".py"),
        (ScriptLanguage.R2_COMMANDS, ".r2"),
        (ScriptLanguage.X64DBG_SCRIPT, ".txt"),
    ],
)
def test_script_get_extension(language: ScriptLanguage, expected_ext: str) -> None:
    """Verify get_extension returns correct extension for each language.

    Args:
        language: Script language.
        expected_ext: Expected file extension.
    """
    script = _make_script(language=language)
    assert script.get_extension() == expected_ext


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
    """Verify validate() marks unsupported languages as verified."""
    validator = ScriptValidator()
    script = _make_script(language=ScriptLanguage.R2_COMMANDS, content="aaa")
    is_valid, error = validator.validate(script)
    assert is_valid is True
    assert error is None
    assert script.verified is True


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
    """Verify Frida API reference has expected categories."""
    ref = get_frida_api_reference()
    assert len(ref) == _FRIDA_API_KEYS
    assert "process" in ref
    assert "interceptor" in ref
    assert "memory" in ref
    assert "stalker" in ref


def test_ghidra_api_reference_keys() -> None:
    """Verify Ghidra API reference has expected categories."""
    ref = get_ghidra_api_reference()
    assert len(ref) == _GHIDRA_API_KEYS
    assert "program" in ref
    assert "decompiler" in ref
    assert "patching" in ref


def test_cutter_reference_keys() -> None:
    """Verify Cutter/Rizin reference has expected categories."""
    ref = get_cutter_reference()
    assert len(ref) == _CUTTER_REF_KEYS
    assert "analysis" in ref
    assert "writing" in ref


def test_x64dbg_reference_keys() -> None:
    """Verify x64dbg reference has expected categories."""
    ref = get_x64dbg_reference()
    assert len(ref) == _X64DBG_REF_KEYS
    assert "breakpoints" in ref
    assert "patching" in ref


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
