# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U8 tests for ``core.script_gen`` remediation.

Validates the nine fixes applied to
``src/intellicrack/core/script_gen.py``:

* F-0001 - ``ScriptGenerator`` is now stateful (validator instance,
  output directory, lazy API-reference cache) while keeping the no-arg
  constructor that existing callers rely on.
* F-0003 - ``ScriptValidator.validate`` no longer reports success for
  languages without a real validator; ``R2_COMMANDS`` and
  ``X64DBG_SCRIPT`` return ``(False, "no validator for ...")`` and
  leave ``Script.verified`` as ``False``.
* F-0004 - ``validate_java`` strips string literals, character
  literals, line comments, and block comments before keyword and
  brace-balance checks so ``import``/``public``/``void run(`` cannot
  be satisfied by tokens inside strings or comments and brace counts
  ignore braces inside string literals.
* F-0006 - ``ScriptManager.reload_script`` honors the path recorded
  by ``save_script`` (including subdirectory writes).
* F-0007 - ``Script.save`` emits the success log only AFTER the file
  is written, and emits a distinct failure log when the write raises.
* F-0010 - ``validate_javascript`` only logs ``temp_file_cleaned``
  when the unlink call returns successfully.
* F-0012 - ``ScriptManager.execute`` is implemented and runs scripts
  through the language-appropriate runner (Python/Node/r2/Ghidra/x64dbg).
* F-0013 - ``Script.created_at`` is a tz-aware UTC datetime so it can
  be subtracted from other tz-aware timestamps without ``TypeError``.
* F-0014 - The apologetic comments in ``reload_script`` are gone.
"""

from __future__ import annotations

import inspect
import shutil
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
import structlog
from structlog.testing import capture_logs


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from structlog.types import EventDict, Processor, WrappedLogger

from intellicrack.core.script_gen import (
    Script,
    ScriptContext,
    ScriptGenerator,
    ScriptLanguage,
    ScriptManager,
    ScriptValidator,
    strip_java_strings_and_comments,
)


_PYTHON_CONTENT: Final[str] = "print('hello from intellicrack audit3 unit8')\n"


def _event_names(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return the ordered list of structlog event names from a record list.

    Args:
        records: Sequence of structlog event mappings captured via
            :func:`structlog.testing.capture_logs`.

    Returns:
        list[str]: ``event`` field of each record in capture order.
    """
    return [str(rec.get("event", "")) for rec in records]


# --- F-0001: ScriptGenerator stateful ---


def test_script_generator_default_construction_holds_validator() -> None:
    """ScriptGenerator() exposes a real ScriptValidator instance."""
    gen = ScriptGenerator()
    assert isinstance(gen.validator, ScriptValidator)


def test_script_generator_default_output_dir_is_path() -> None:
    """ScriptGenerator() exposes a Path output_dir even with no args."""
    gen = ScriptGenerator()
    assert isinstance(gen.output_dir, Path)
    assert gen.output_dir.name == ScriptGenerator.DEFAULT_OUTPUT_DIRNAME


def test_script_generator_explicit_validator_is_held(tmp_path: Path) -> None:
    """ScriptGenerator(validator=...) holds the supplied instance.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    explicit = ScriptValidator()
    gen = ScriptGenerator(validator=explicit, output_dir=tmp_path)
    assert gen.validator is explicit
    assert gen.output_dir == tmp_path


def test_script_generator_constructor_signature_optional() -> None:
    """All ScriptGenerator constructor parameters are optional."""
    sig = inspect.signature(ScriptGenerator.__init__)
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        assert param.default is not inspect.Parameter.empty, name


def test_script_generator_api_reference_cached() -> None:
    """Repeated api_reference calls return the same dict object."""
    gen = ScriptGenerator()
    first = gen.api_reference(ScriptLanguage.JAVASCRIPT)
    second = gen.api_reference(ScriptLanguage.JAVASCRIPT)
    assert first is second
    assert "interceptor" in first


def test_script_generator_api_reference_python_empty() -> None:
    """Languages without a registered reference return an empty dict."""
    gen = ScriptGenerator()
    assert gen.api_reference(ScriptLanguage.PYTHON) == {}


def test_script_generator_prepare_output_path_creates_dir(tmp_path: Path) -> None:
    """prepare_output_path creates output_dir on the filesystem.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    out = tmp_path / "drafts"
    gen = ScriptGenerator(output_dir=out)
    path = gen.prepare_output_path("hook", ScriptLanguage.JAVASCRIPT)
    assert out.exists()
    assert path == out / "hook.js"


def test_script_generator_prepare_ai_prompt_includes_reference() -> None:
    """prepare_ai_prompt embeds the cached API reference."""
    gen = ScriptGenerator()
    ctx = ScriptContext(binary_name="target.exe")
    prompt = gen.prepare_ai_prompt(ctx, ScriptLanguage.JAVASCRIPT)
    assert "JAVASCRIPT API Reference:" in prompt
    assert "Interceptor" in prompt


def test_script_generator_generate_helpers_dispatch_correctly() -> None:
    """generate_* helpers route through prepare_ai_prompt with the right language."""
    gen = ScriptGenerator()
    ctx = ScriptContext(binary_name="target.exe")
    assert "javascript" in gen.generate_frida(ctx)
    assert "java" in gen.generate_ghidra(ctx)
    assert "python" in gen.generate_python(ctx)
    assert "r2_commands" in gen.generate_cutter(ctx)
    assert "x64dbg_script" in gen.generate_x64dbg(ctx)


# --- F-0003: ScriptValidator returns False for unknown languages ---


@pytest.mark.parametrize(
    "language",
    [ScriptLanguage.R2_COMMANDS, ScriptLanguage.X64DBG_SCRIPT],
)
def test_validator_returns_false_for_unsupported(language: ScriptLanguage) -> None:
    """Unsupported languages return (False, error) and leave verified=False.

    Args:
        language: Script language with no registered validator.
    """
    validator = ScriptValidator()
    script = Script(
        name="x",
        script_type="cutter",
        language=language,
        content="aaa",
        description="d",
    )
    is_valid, error = validator.validate(script)
    assert is_valid is False
    assert error is not None
    assert language.value in error
    assert script.verified is False


# --- F-0004: validate_java token-aware checks ---


def test_strip_java_strings_and_comments_removes_string_braces() -> None:
    """strip_java_strings_and_comments masks string-literal braces."""
    src = 'String s = "{}";'
    scrubbed = strip_java_strings_and_comments(src)
    assert "{" not in scrubbed
    assert "}" not in scrubbed


def test_strip_java_strings_and_comments_preserves_line_count() -> None:
    """Stripping preserves the line count of the original source."""
    src = "line1 // comment\nline2\n/* block\nspan */line3\n"
    scrubbed = strip_java_strings_and_comments(src)
    assert scrubbed.count("\n") == src.count("\n")


def test_validator_java_balanced_braces_in_string() -> None:
    """A } inside a string literal does not break brace balance."""
    content = (
        "import ghidra.app.script.GhidraScript;\n"
        "public class S extends GhidraScript {\n"
        '    public void run() { String s = "}"; println(s); }\n'
        "}\n"
    )
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is True, error


def test_validator_java_keyword_in_comment_is_ignored() -> None:
    """Import keyword inside a // comment does not satisfy the requirement."""
    content = "// import this\npublic class S {\n    public void run() {}\n}\n"
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "import" in error


def test_validator_java_keyword_in_block_comment_is_ignored() -> None:
    """Import keyword inside a block comment does not satisfy the requirement."""
    content = "/* import this thing */\npublic class S {\n    public void run() {}\n}\n"
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "import" in error


def test_validator_java_public_in_string_is_ignored() -> None:
    """Public keyword inside a string literal does not satisfy the requirement."""
    content = 'import ghidra.app.script.GhidraScript;\nclass S { String banner = "public class fake"; void run() {} }\n'
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "public" in error


def test_validator_java_void_run_in_comment_is_ignored() -> None:
    """Void run( inside a comment does not satisfy the requirement."""
    content = (
        "import ghidra.app.script.GhidraScript;\npublic class S {\n    // void run(... here is just docs\n    public void execute() {}\n}\n"
    )
    is_valid, error = ScriptValidator.validate_java(content)
    assert is_valid is False
    assert error is not None
    assert "void run(" in error


# --- F-0006: reload_script honors subdir saves ---


def test_reload_script_round_trips_subdir_save(tmp_path: Path) -> None:
    """reload_script reloads a script saved into a subdirectory.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="hook",
        script_type="frida",
        language=ScriptLanguage.JAVASCRIPT,
        content="console.log('v1');",
        description="d",
    )
    mgr.add_script(script, validate=False)
    saved = mgr.save_script("hook", subdir="frida")
    assert saved is not None
    assert saved.parent.name == "frida"

    saved.write_text("console.log('v2');", encoding="utf-8")
    assert mgr.reload_script("hook") is True
    reloaded = mgr.get_script("hook")
    assert reloaded is not None
    assert reloaded.content == "console.log('v2');"


def test_reload_script_falls_back_to_canonical_path(tmp_path: Path) -> None:
    """When no save was recorded, reload uses scripts_dir / <name><ext>.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="canon",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="d",
    )
    mgr.add_script(script, validate=False)
    (tmp_path / "canon.py").write_text("x = 2", encoding="utf-8")
    assert mgr.reload_script("canon") is True
    reloaded = mgr.get_script("canon")
    assert reloaded is not None
    assert reloaded.content == "x = 2"


# --- F-0007: Script.save logging order ---


def test_script_save_emits_success_log_only_after_write(tmp_path: Path) -> None:
    """script_file_written log appears only after a successful write.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    script = Script(
        name="ok",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="d",
    )
    with capture_logs() as records:
        script.save(tmp_path / "ok.py")
    events = _event_names(records)
    assert "script_file_written" in events
    assert "script_file_write_failed" not in events
    assert script.saved_path == tmp_path / "ok.py"


def test_script_save_failure_logs_failure_not_success(tmp_path: Path) -> None:
    """When a real write_text fails, success log is NOT emitted; failure log is.

    Drives a genuine :class:`OSError` from the filesystem rather than mocking
    the write that ``save`` performs: the save target is an existing directory,
    so ``Path.write_text`` raises a real :class:`PermissionError` (an
    ``OSError`` subclass) on Windows. The production ``except OSError`` branch
    must run, emitting ``script_file_write_failed`` (and never the success
    ``script_file_written``) and leaving ``saved_path`` untouched.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    script = Script(
        name="bad",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="d",
    )
    target = tmp_path / "occupied"
    target.mkdir()

    with capture_logs() as records, pytest.raises(OSError, match="occupied") as exc_info:
        script.save(target)

    assert exc_info.type is PermissionError
    events = _event_names(records)
    assert "script_file_written" not in events
    assert "script_saved" not in events
    assert "script_file_write_failed" in events
    assert script.saved_path is None


# --- F-0010: validate_javascript temp file logs in correct order ---


def _require_node() -> None:
    """Skip the calling test when the real ``node`` runtime is unavailable.

    ``validate_javascript`` shells out to ``node --check`` to perform genuine
    syntax validation. The cleanup-ordering and verdict assertions below need
    the real runtime so the verdict oracle is node's own parser, not a stub.
    Calls :func:`pytest.skip` when ``node`` is not on ``PATH``.
    """
    if shutil.which("node") is None:
        pytest.skip("node (Node.js) runtime is required to validate JavaScript syntax for real")


def _recording_processor(events: list[str]) -> Processor:
    """Build a structlog processor that appends each event name to ``events``.

    Args:
        events: Mutable list that receives the ordered ``event`` field of each
            emitted log record.

    Returns:
        Processor: A processor suitable as the terminal entry in a temporary
        ``structlog`` configuration.
    """

    def _proc(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> str:
        name = str(event_dict.get("event", ""))
        events.append(name)
        return name

    return _proc


def _install_recording_processors(processors: list[Processor]) -> tuple[list[str], Callable[[], None]]:
    """Install ``processors`` plus a terminal recorder; return events and restore.

    Unlike :func:`structlog.testing.capture_logs`, this lets a leading
    processor observe the real ``event_dict`` (including the live temp-file
    path emitted by production) and apply a deterministic, synchronous
    filesystem side effect before the production ``finally`` block runs. The
    caller must invoke the returned restore callable (in a ``finally``) to
    reinstate the prior ``structlog`` configuration.

    Args:
        processors: Processor chain to install. A terminal recording processor
            returning ``str`` is appended automatically.

    Returns:
        tuple[list[str], Callable[[], None]]: The list that accumulates the
        ordered event names and a callable that restores the prior config.
    """
    events: list[str] = []
    old_config = structlog.get_config()
    structlog.configure(processors=[*processors, _recording_processor(events)])

    def _restore() -> None:
        structlog.configure(**old_config)

    return events, _restore


def test_validate_javascript_emits_cleanup_after_unlink_attempt_on_real_run() -> None:
    """A real node validation cleans its temp file and logs cleanup in order.

    Drives the genuine ``node --check`` path on valid JavaScript and asserts
    the exact verdict ``(True, None)`` produced by node's own parser (the
    independent oracle), then asserts unconditionally that the temp file was
    unlinked and that ``temp_file_cleaned`` followed ``temp_file_unlink_attempt``.
    Cleanup is independent of node's verdict, so there is no conditional and no
    post-hoc skip masking a silent cleanup regression.
    """
    _require_node()
    with capture_logs() as records:
        is_valid, error = ScriptValidator.validate_javascript("var x = 1; function f() { return 42; }\n")

    assert (is_valid, error) == (True, None)

    events = _event_names(records)
    assert "temp_file_unlink_attempt" in events, events
    assert "temp_file_cleaned" in events, events
    assert "temp_file_unlink_failed" not in events, events
    assert events.index("temp_file_cleaned") > events.index("temp_file_unlink_attempt")


def test_validate_javascript_reports_node_syntax_error_and_still_cleans_up() -> None:
    """Invalid JavaScript yields node's real error and still cleans its temp file.

    The verdict's truth value and error text come from the real ``node``
    parser, not from re-implementing JS parsing in the test. Cleanup must still
    occur on the failure path.
    """
    _require_node()
    with capture_logs() as records:
        is_valid, error = ScriptValidator.validate_javascript("function (){")

    assert is_valid is False
    assert error is not None
    assert error != "node not installed"
    assert "SyntaxError" in error

    events = _event_names(records)
    assert "temp_file_unlink_attempt" in events
    assert "temp_file_cleaned" in events
    assert "temp_file_unlink_failed" not in events


def test_validate_javascript_unlink_failure_suppresses_cleaned_log() -> None:
    """A real read-only temp file makes unlink fail; cleanup log is suppressed.

    Instead of mocking ``Path.unlink`` (the operation under test), this drives
    the real production cleanup against a real read-only file. A leading
    structlog processor observes the genuine ``temp_file_created`` event,
    extracts the live temp path production chose, and marks that real file
    read-only via :meth:`pathlib.Path.chmod`. On Windows, unlinking a read-only
    file raises :class:`PermissionError`, so production's real
    ``except OSError`` branch runs: ``temp_file_unlink_failed`` is emitted and
    ``temp_file_cleaned`` is not. The side effect runs synchronously inside the
    ``temp_file_created`` log call, deterministically before the ``finally``
    unlink, with no sleeps or shared mutable global state. The exact temp path
    is restored to writable and removed afterwards so nothing leaks.
    """
    _require_node()
    captured_path: dict[str, str] = {}

    def _mark_temp_readonly(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
        if event_dict.get("event") == "temp_file_created":
            path = event_dict.get("path")
            if isinstance(path, str):
                Path(path).chmod(stat.S_IREAD)
                captured_path["created"] = path
        elif event_dict.get("event") == "temp_file_unlink_failed":
            failed = event_dict.get("path")
            if isinstance(failed, str):
                captured_path["failed"] = failed
        return event_dict

    events, restore = _install_recording_processors([_mark_temp_readonly])
    try:
        verdict = ScriptValidator.validate_javascript("var x = 1;")
    finally:
        restore()
        leaked = captured_path.get("created")
        if leaked is not None and Path(leaked).exists():
            Path(leaked).chmod(stat.S_IWRITE)
            Path(leaked).unlink()

    created = captured_path.get("created")
    assert created, "production never created a temp file to fail unlink on"
    assert verdict == (True, None), verdict
    assert "temp_file_unlink_attempt" in events, events
    assert "temp_file_unlink_failed" in events, events
    assert "temp_file_cleaned" not in events, events
    assert captured_path.get("failed") == created, captured_path


# --- F-0012: ScriptManager.execute runs Python scripts ---


def test_script_manager_execute_python_returns_exit_code(tmp_path: Path) -> None:
    """execute() runs a Python script and returns its exit code.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="hello",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content=_PYTHON_CONTENT,
        description="d",
    )
    mgr.add_script(script, validate=False)
    result = mgr.execute("hello", timeout=30)
    assert result.returncode == 0
    assert "intellicrack audit3 unit8" in (result.stdout or "")


def test_script_manager_execute_python_failure_propagates_exit_code(tmp_path: Path) -> None:
    """A failing Python script returns its non-zero exit code.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="bad",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="import sys; sys.exit(7)",
        description="d",
    )
    mgr.add_script(script, validate=False)
    result = mgr.execute("bad", timeout=30)
    assert result.returncode == 7


def test_script_manager_execute_records_result(tmp_path: Path) -> None:
    """execute() records the outcome in the script's execution_results.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="record",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="print('done')",
        description="d",
    )
    mgr.add_script(script, validate=False)
    mgr.execute("record", timeout=30)
    stored = mgr.get_script("record")
    assert stored is not None
    assert "script_manager.execute" in stored.execution_results
    payload = stored.execution_results["script_manager.execute"]
    assert isinstance(payload, dict)
    assert payload["returncode"] == 0


def test_script_manager_execute_unknown_raises_keyerror(tmp_path: Path) -> None:
    """execute() raises KeyError for unknown script names.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    with pytest.raises(KeyError):
        mgr.execute("missing")


def test_script_manager_execute_command_for_javascript(tmp_path: Path) -> None:
    """The internal command builder selects ``node`` for JavaScript scripts.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="hook",
        script_type="frida",
        language=ScriptLanguage.JAVASCRIPT,
        content="console.log('hi');",
        description="d",
        saved_path=tmp_path / "hook.js",
    )
    (tmp_path / "hook.js").write_text(script.content, encoding="utf-8")
    cmd = mgr.build_execute_command(script, None)
    assert cmd[0] == "node"
    assert cmd[1] == str(tmp_path / "hook.js")


def test_script_manager_execute_command_for_java(tmp_path: Path) -> None:
    """The internal command builder selects ``analyzeHeadless`` for Java.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="ghi",
        script_type="ghidra",
        language=ScriptLanguage.JAVA,
        content="// java",
        description="d",
        saved_path=tmp_path / "ghi.java",
    )
    (tmp_path / "ghi.java").write_text(script.content, encoding="utf-8")
    cmd = mgr.build_execute_command(script, None)
    assert cmd[0] == "analyzeHeadless"
    assert "-postScript" in cmd
    assert "ghi.java" in cmd


def test_script_manager_execute_command_for_x64dbg(tmp_path: Path) -> None:
    """The internal command builder selects an x64dbg runner for debugger scripts.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="dbg",
        script_type="x64dbg",
        language=ScriptLanguage.X64DBG_SCRIPT,
        content="bp 0x401000",
        description="d",
        saved_path=tmp_path / "dbg.txt",
    )
    (tmp_path / "dbg.txt").write_text(script.content, encoding="utf-8")
    cmd = mgr.build_execute_command(script, None)
    assert cmd[0] in {"x64dbg", "x32dbg"}
    assert "-script" in cmd
    assert str(tmp_path / "dbg.txt") in cmd


def test_script_manager_execute_command_for_python_uses_active_interpreter(
    tmp_path: Path,
) -> None:
    """The Python runner uses ``sys.executable`` so virtualenv stays consistent.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    mgr = ScriptManager(tmp_path)
    script = Script(
        name="py",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="d",
        saved_path=tmp_path / "py.py",
    )
    (tmp_path / "py.py").write_text(script.content, encoding="utf-8")
    cmd = mgr.build_execute_command(script, None)
    assert cmd[0] == sys.executable


# --- F-0013: Script.created_at is tz-aware UTC ---


def test_script_created_at_is_tz_aware() -> None:
    """Script.created_at is tz-aware UTC and subtracts cleanly."""
    script = Script(
        name="x",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="d",
    )
    assert script.created_at.tzinfo is not None
    delta = datetime.now(tz=UTC) - script.created_at
    assert delta.total_seconds() >= 0


# --- ScriptManager() default scripts_dir ---


def test_script_manager_no_args_default_scripts_dir() -> None:
    """ScriptManager() default scripts_dir is a Path under cwd."""
    mgr = ScriptManager()
    assert isinstance(mgr.scripts_dir, Path)
    assert mgr.scripts_dir.name == "scripts"
