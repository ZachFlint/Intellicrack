# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :mod:`intellicrack.core.script_gen`.

Addresses the audit findings for ``script_gen.py``:

* The synthetic ``_make_script`` factory finding is answered by a real
  create -> save -> reload -> execute lifecycle test driven through
  :class:`ScriptManager` and the active Python interpreter.
* JavaScript validation is exercised with the real ``node`` runtime for both
  a clean parse and an actual syntax error (not just the "node missing"
  fallback).
* ``strip_java_strings_and_comments`` is validated across escape sequences,
  nested quotes, and brace-bearing string literals.
* Prompt-building helpers are validated for content correctness against the
  real API-reference getters, not merely structural presence.
* The R2/x64dbg validators (no real validator available) are confirmed to
  refuse rather than silently trust.
"""

from __future__ import annotations

import shutil
from pathlib import Path

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
    strip_java_strings_and_comments,
)


_NODE_AVAILABLE = shutil.which("node") is not None


class TestScriptLifecycle:
    """A script must survive create -> save -> reload -> execute intact."""

    @pytest.mark.spawns_process
    def test_python_script_create_save_reload_execute(self, tmp_path: Path) -> None:
        """A Python script persists, reloads byte-identical, and runs cleanly.

        Args:
            tmp_path: Per-test temporary directory.
        """
        manager = ScriptManager(tmp_path)
        content = "import sys\nsys.stdout.write('intellicrack-07b-roundtrip')\nsys.exit(0)\n"
        script = Script(
            name="roundtrip",
            script_type="python",
            language=ScriptLanguage.PYTHON,
            content=content,
            description="lifecycle probe",
        )
        assert manager.add_script(script) is True

        saved_path = manager.save_script("roundtrip")
        assert saved_path is not None
        assert saved_path.exists()

        # Mutate the in-memory copy, then reload from disk to prove persistence.
        manager.scripts["roundtrip"].content = "print('stale')"
        assert manager.reload_script("roundtrip") is True
        assert manager.scripts["roundtrip"].content == content

        result = manager.execute("roundtrip", timeout=30)
        assert result.returncode == 0
        assert "intellicrack-07b-roundtrip" in (result.stdout or "")

        recorded = manager.scripts["roundtrip"].execution_results
        assert recorded["script_manager.execute"]["returncode"] == 0


class TestJavaScriptValidation:
    """JavaScript validation must use the real ``node`` runtime when present."""

    @pytest.mark.spawns_process
    def test_valid_frida_script_passes_node_check(self) -> None:
        """A syntactically valid Frida script parses cleanly under node."""
        if not _NODE_AVAILABLE:
            pytest.skip("node runtime is not installed")
        content = (
            "const target = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');\n"
            "Interceptor.attach(target, {\n"
            "  onLeave: function (retval) { retval.replace(0); }\n"
            "});\n"
        )
        is_valid, error = ScriptValidator.validate_javascript(content)
        assert is_valid is True
        assert error is None

    @pytest.mark.spawns_process
    def test_syntax_error_rejected_by_node_check(self) -> None:
        """A genuine syntax error is reported as invalid with a node message."""
        if not _NODE_AVAILABLE:
            pytest.skip("node runtime is not installed")
        content = "function broken( {\n  return 1;\n"
        is_valid, error = ScriptValidator.validate_javascript(content)
        assert is_valid is False
        assert error
        assert "node not installed" not in error


class TestStripJavaStringsAndComments:
    """Java scrubbing must neutralise strings/comments but keep code tokens."""

    def test_keywords_inside_strings_are_removed(self) -> None:
        """``class``/``import`` inside a string literal cannot leak through."""
        source = 'String s = "public class import void run(";'
        scrubbed = strip_java_strings_and_comments(source)
        assert "public" not in scrubbed
        assert "import" not in scrubbed
        assert "String s =" in scrubbed

    def test_braces_inside_strings_do_not_count(self) -> None:
        """Braces inside string literals are erased before balance checks."""
        source = 'String s = "{{{";'
        scrubbed = strip_java_strings_and_comments(source)
        assert scrubbed.count("{") == 0
        assert scrubbed.count("}") == 0

    def test_escaped_quote_does_not_terminate_string(self) -> None:
        """An escaped quote keeps the literal open until the real terminator."""
        source = r'String s = "a\"b}"; int x;'
        scrubbed = strip_java_strings_and_comments(source)
        assert "}" not in scrubbed
        assert "int x;" in scrubbed

    def test_line_and_block_comments_stripped_preserving_newlines(self) -> None:
        """Line and block comments are blanked but newlines are preserved."""
        source = "// class A {\n/* import x */\nint y;\n"
        scrubbed = strip_java_strings_and_comments(source)
        assert "class" not in scrubbed
        assert "import" not in scrubbed
        assert scrubbed.count("\n") == source.count("\n")
        assert "int y;" in scrubbed

    def test_char_literal_brace_is_stripped(self) -> None:
        """A brace inside a char literal does not affect the brace balance."""
        source = "char c = '}'; int z;"
        scrubbed = strip_java_strings_and_comments(source)
        assert "}" not in scrubbed
        assert "int z;" in scrubbed

    def test_real_ghidra_script_validates(self) -> None:
        """A realistic Ghidra Java script passes the structural validator."""
        content = (
            "import ghidra.app.script.GhidraScript;\n"
            "public class PatchScript extends GhidraScript {\n"
            '    // strings with braces like "{" must not break balance\n'
            "    public void run() throws Exception {\n"
            '        println("done {");\n'
            "    }\n"
            "}\n"
        )
        is_valid, error = ScriptValidator.validate_java(content)
        assert is_valid is True
        assert error is None


class TestPromptContentAccuracy:
    """Prompts must embed real, accurate context and API-reference content."""

    def test_to_prompt_context_includes_real_metadata(self) -> None:
        """Context formatting reflects the supplied binary metadata exactly."""
        context = ScriptContext(
            binary_name="target.exe",
            binary_path=Path("C:/Windows/System32/kernel32.dll"),
            architecture="x64",
            platform="windows",
            module_base=0x140000000,
            target_functions=[{"name": "check_license", "address": 0x1400015A0, "strategy": "return_true"}],
            identified_protections=["VMProtect"],
            crypto_apis=["CryptHashData"],
            magic_constants=[0xDEADBEEF],
        )
        rendered = context.to_prompt_context(ScriptLanguage.JAVASCRIPT)
        assert "Binary: target.exe" in rendered
        assert "Architecture: x64" in rendered
        assert "Module Base: 0x140000000" in rendered
        assert "check_license @ 0x1400015A0" in rendered
        # Strategy is expanded to its human description, not the raw value.
        assert BypassStrategy.RETURN_TRUE.description in rendered
        assert "VMProtect" in rendered
        assert "CryptHashData" in rendered
        assert "0xDEADBEEF" in rendered
        # JavaScript maps to the Frida reference, which must be embedded.
        assert "Interceptor.attach" in rendered

    def test_prepare_ai_prompt_unbound_embeds_frida_reference(self) -> None:
        """Unbound prompt building embeds the real Frida API reference."""
        context = ScriptContext(binary_name="x.exe", architecture="x64", platform="windows")
        prompt = ScriptGenerator.prepare_ai_prompt(context, ScriptLanguage.JAVASCRIPT)
        assert "Language: javascript" in prompt
        for usage in get_frida_api_reference().values():
            fragment = usage.split("(")[0].split(",")[0].strip()
            assert fragment in prompt

    def test_generate_ghidra_embeds_ghidra_reference(self) -> None:
        """The Ghidra generator embeds the real Ghidra API reference."""
        generator = ScriptGenerator()
        context = ScriptContext(binary_name="x.bin", architecture="x64", platform="linux")
        prompt = generator.generate_ghidra(context)
        assert "currentProgram" in prompt
        assert get_ghidra_api_reference()["decompiler"].split("(")[0] in prompt

    def test_generate_cutter_and_x64dbg_embed_their_references(self) -> None:
        """Cutter and x64dbg generators embed their respective references."""
        generator = ScriptGenerator()
        context = ScriptContext(binary_name="x.bin", architecture="x64", platform="windows")
        cutter_prompt = generator.generate_cutter(context)
        x64_prompt = generator.generate_x64dbg(context)
        assert get_cutter_reference()["analysis"] in cutter_prompt
        assert get_x64dbg_reference()["breakpoints"].split("(")[0] in x64_prompt

    def test_api_reference_cache_returns_same_dict(self) -> None:
        """The per-instance API reference cache reuses one dict per language."""
        generator = ScriptGenerator()
        first = generator.api_reference(ScriptLanguage.JAVASCRIPT)
        second = generator.api_reference(ScriptLanguage.JAVASCRIPT)
        assert first is second
        assert first == get_frida_api_reference()


class TestUnsupportedValidators:
    """Languages without a real validator must refuse, not silently trust."""

    @pytest.mark.parametrize(
        "language",
        [ScriptLanguage.R2_COMMANDS, ScriptLanguage.X64DBG_SCRIPT],
    )
    def test_no_validator_returns_false_and_leaves_unverified(
        self,
        language: ScriptLanguage,
    ) -> None:
        """R2 and x64dbg scripts cannot be verified and stay ``verified=False``.

        Args:
            language: The validator-less script language under test.
        """
        script_type = "cutter" if language == ScriptLanguage.R2_COMMANDS else "x64dbg"
        script = Script(
            name="probe",
            script_type=script_type,
            language=language,
            content="aaa\npd 10\n",
            description="d",
        )
        is_valid, error = ScriptValidator().validate(script)
        assert is_valid is False
        assert error is not None
        assert "no validator" in error
        assert script.verified is False
