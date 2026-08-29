# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Falsifiable gates for the Inno Setup hardening pass on ``intellicrack.iss``.

The installer audit produced a set of changes that are invisible to the existing
stage/``.iss`` agreement gates because none of them touches a ``[Files]`` entry:
a compiler-version floor, opt-in code signing, two message boxes that must not
stall or destroy anything under ``/SILENT``, a Windows build-number guard that
matches its own comment, a single-instance Setup mutex, a DISM progress callback,
and the removal of a guard the ``[Setup]`` architecture directive already
enforces.

Each gate below reads the real ``packaging/intellicrack.iss`` (and, where the
change is a documented contract, ``packaging/README.md``) and asserts the exact
shape of the construct rather than the presence of a substring, so a regression
to the pre-hardening form is what turns it red:

* a plain ``MsgBox`` in place of ``SuppressibleMsgBox`` fails, because the call
  is located by its kind and its argument list is split and inspected;
* an ``IDNO`` default flipped to ``IDYES`` fails, because the suppressed default
  is compared exactly - that one bit is the difference between an unattended
  uninstall leaving the tool cache alone and destroying it unasked;
* signing directives hoisted out of their ``#ifdef`` fail, because the
  preprocessor blocks are parsed and the directives are required to live inside
  one.

Pascal argument splitting is quote- and paren-aware so a comma inside a message
string cannot be mistaken for an argument separator.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from tests.packaging.test_stage_matches_iss import parse_setup_directives


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_ISS_PATH: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"
_README_PATH: Final[Path] = _REPO_ROOT / "packaging" / "README.md"

# ``#if VER < EncodeVer(6, 6, 0)`` -- the ISPP compiler-version floor.
_VER_GUARD_RE: Final[re.Pattern[str]] = re.compile(r"(?im)^\s*#if\s+VER\s*<\s*EncodeVer\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")

# ``#ifdef Name`` / ``#endif`` -- the preprocessor blocks signing lives in.
_IFDEF_RE: Final[re.Pattern[str]] = re.compile(r"(?im)^\s*#(ifdef|ifndef|if)\b(.*)$")
_ENDIF_RE: Final[re.Pattern[str]] = re.compile(r"(?im)^\s*#endif\b")

# A ``MsgBox(`` or ``SuppressibleMsgBox(`` call site in the [Code] section.
_MSGBOX_CALL_RE: Final[re.Pattern[str]] = re.compile(r"\b(SuppressibleMsgBox|MsgBox)\s*\(")

# The lowest Inno Setup release this script may be compiled with. 6.6.0 is where
# the dynamic wizard appearance and WizardImageFileDynamicDark arrived; the .iss
# uses both, so anything older fails with an unknown-directive error instead.
_MINIMUM_COMPILER: Final[tuple[int, int, int]] = (6, 6, 0)

# Directives that must never be emitted unconditionally: SignedUninstaller
# without a SignTool makes ISCC stop and prompt interactively at compile time,
# which would break every unsigned local build.
_SIGNING_DIRECTIVES: Final[tuple[str, ...]] = ("SignTool", "SignedUninstaller")
_SIGNING_SYMBOL: Final[str] = "SignToolName"

# Windows 10 RTM. The [Setup] MinVersion and the [Code] build guard must agree
# on this, or the two refusals contradict each other.
_MIN_WINDOWS_MAJOR: Final[str] = "10.0"
_MIN_WINDOWS_BUILD: Final[int] = 10240

_DISM_CALLBACK: Final[str] = "DismLogOutput"

# The exact TOnLog signature ExecAndLogOutput calls back with. A mismatch here is
# a compile error in Setup, not a runtime one, so it is worth pinning verbatim.
_DISM_CALLBACK_SIGNATURE: Final[str] = "procedure DismLogOutput(const S: String; const Error, FirstLine: Boolean);"


def read_iss() -> str:
    """Read the real Inno Setup script.

    Returns:
        str: The full text of ``packaging/intellicrack.iss``.
    """
    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    return _ISS_PATH.read_text(encoding="utf-8-sig")


def read_readme() -> str:
    """Read the packaging README.

    Returns:
        str: The full text of ``packaging/README.md``.
    """
    assert _README_PATH.is_file(), f"packaging README missing: {_README_PATH}"
    return _README_PATH.read_text(encoding="utf-8-sig")


def pascal_code(iss_text: str) -> str:
    """Extract the ``[Code]`` section of an Inno Setup script.

    Args:
        iss_text: The full text of an ``.iss`` script.

    Returns:
        str: Everything after the ``[Code]`` header up to the next section
            header, or to the end of the script when none follows.

    Raises:
        AssertionError: If the script declares no ``[Code]`` section.
    """
    lines = iss_text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line.strip().lower() == "[code]":
            start = index + 1
            break
    if start is None:
        msg = "the .iss declares no [Code] section"
        raise AssertionError(msg)
    end = len(lines)
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = index
            break
    return "\n".join(lines[start:end])


def split_call_arguments(text: str, open_paren: int) -> list[str]:
    """Split the argument list of a Pascal call into top-level arguments.

    Nesting and Pascal string literals (single-quoted, ``''`` for an embedded
    quote) are both tracked, so a comma inside a message string or inside a
    nested call is never mistaken for an argument separator.

    Args:
        text: The source containing the call.
        open_paren: Index of the call's opening parenthesis.

    Returns:
        list[str]: The stripped top-level arguments, in order.

    Raises:
        AssertionError: If the call's parentheses are unbalanced.
    """
    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    index = open_paren
    while index < len(text):
        char = text[index]
        if in_string:
            current.append(char)
            if char == "'":
                in_string = False
            index += 1
            continue
        if char == "'":
            in_string = True
            current.append(char)
        elif char == "(":
            depth += 1
            if depth > 1:
                current.append(char)
        elif char == ")":
            depth -= 1
            if depth == 0:
                arguments.append("".join(current).strip())
                return [argument for argument in arguments if argument]
            current.append(char)
        elif char == "," and depth == 1:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    msg = f"unbalanced parentheses in the call starting at offset {open_paren}"
    raise AssertionError(msg)


def message_box_calls(code: str) -> list[tuple[str, list[str]]]:
    """Collect every message-box call in a ``[Code]`` section.

    Args:
        code: The Pascal source of the ``[Code]`` section.

    Returns:
        list[tuple[str, list[str]]]: ``(function_name, arguments)`` for each
            ``MsgBox`` or ``SuppressibleMsgBox`` call, in document order.
    """
    return [(match.group(1), split_call_arguments(code, match.end() - 1)) for match in _MSGBOX_CALL_RE.finditer(code)]


def find_message_box(code: str, needle: str) -> tuple[str, list[str]]:
    """Locate the single message box whose text contains a phrase.

    Args:
        code: The Pascal source of the ``[Code]`` section.
        needle: A phrase that appears in the target dialog's message text.

    Returns:
        tuple[str, list[str]]: The ``(function_name, arguments)`` of the match.

    Raises:
        AssertionError: If the phrase matches no call, or more than one.
    """
    matches = [call for call in message_box_calls(code) if needle in call[1][0]]
    if len(matches) != 1:
        msg = f"expected exactly one message box mentioning {needle!r}, found {len(matches)}"
        raise AssertionError(msg)
    return matches[0]


def conditional_blocks(iss_text: str) -> dict[str, list[str]]:
    """Map each ``#ifdef``-style preprocessor block to the lines it guards.

    Args:
        iss_text: The full text of an ``.iss`` script.

    Returns:
        dict[str, list[str]]: Condition text (for example ``"SignToolName"``)
            mapped to the stripped, non-empty lines inside that block. Nested
            blocks are attributed to their innermost condition.
    """
    blocks: dict[str, list[str]] = {}
    stack: list[str] = []
    for line in iss_text.splitlines():
        opened = _IFDEF_RE.match(line)
        if opened is not None:
            condition = opened.group(2).strip()
            stack.append(condition)
            blocks.setdefault(condition, [])
            continue
        if _ENDIF_RE.match(line) is not None:
            if stack:
                stack.pop()
            continue
        stripped = line.strip()
        if stack and stripped:
            blocks[stack[-1]].append(stripped)
    return blocks


def directive_lines_outside_conditionals(iss_text: str, directive: str) -> list[str]:
    """Return occurrences of a ``[Setup]`` directive not wrapped in a conditional.

    Args:
        iss_text: The full text of an ``.iss`` script.
        directive: The directive name, matched case-insensitively at line start.

    Returns:
        list[str]: The stripped lines declaring that directive at conditional
            depth zero.
    """
    pattern = re.compile(rf"(?i)^{re.escape(directive)}\s*=")
    found: list[str] = []
    depth = 0
    for line in iss_text.splitlines():
        if _IFDEF_RE.match(line) is not None:
            depth += 1
            continue
        if _ENDIF_RE.match(line) is not None:
            depth = max(depth - 1, 0)
            continue
        stripped = line.strip()
        if depth == 0 and pattern.match(stripped):
            found.append(stripped)
    return found


# --- Parser falsifiability proofs --------------------------------------------


def test_call_argument_splitter_respects_strings_and_nesting() -> None:
    """Commas inside Pascal strings and nested calls are not argument separators.

    Without this the tool-cache assertion below could read ``'... folder ('`` as
    a whole argument and compare the wrong token against ``IDNO``.
    """
    source = "SuppressibleMsgBox('a, b' + #13#10 + IntToStr(Foo(1, 2)), mbConfirmation, MB_YESNO, IDNO);"
    arguments = split_call_arguments(source, source.index("("))
    assert arguments == ["'a, b' + #13#10 + IntToStr(Foo(1, 2))", "mbConfirmation", "MB_YESNO", "IDNO"]


def test_conditional_block_parser_attributes_lines_to_their_condition() -> None:
    """Lines are attributed to the enclosing ``#ifdef``, and unguarded lines to none."""
    text = "AppName=X\n#ifdef SignToolName\nSignTool={#SignToolName}\nSignedUninstaller=yes\n#endif\nCompression=lzma2\n"
    blocks = conditional_blocks(text)
    assert blocks == {"SignToolName": ["SignTool={#SignToolName}", "SignedUninstaller=yes"]}
    assert directive_lines_outside_conditionals(text, "AppName") == ["AppName=X"]
    assert directive_lines_outside_conditionals(text, "SignTool") == []


def test_pascal_code_section_extraction_stops_at_the_next_section() -> None:
    """``pascal_code`` returns the ``[Code]`` body only, not a following section."""
    text = "[Files]\nSource: x\n\n[Code]\nprocedure Foo();\nbegin\nend;\n"
    assert "procedure Foo();" in pascal_code(text)
    assert "Source: x" not in pascal_code(text)


# --- Item 8: the ISPP compiler-version floor ---------------------------------


def test_iss_refuses_to_compile_on_an_older_inno_setup() -> None:
    """Real gate: the script carries an ISPP floor of 6.6.0 or newer with an ``#error``.

    Falsifiable by deleting the guard, by lowering ``EncodeVer`` below 6.6.0, or
    by replacing the ``#error`` with a warning: the ``.iss`` uses directives that
    do not exist before 6.6.0, so without a hard stop the failure a packager sees
    is an unknown-directive error with no explanation.
    """
    iss_text = read_iss()
    match = _VER_GUARD_RE.search(iss_text)
    assert match is not None, "the .iss declares no `#if VER < EncodeVer(...)` compiler-version guard"

    declared = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    assert declared >= _MINIMUM_COMPILER, f"the compiler floor is {declared}, below the required {_MINIMUM_COMPILER}"

    tail = iss_text[match.end() :]
    endif = _ENDIF_RE.search(tail)
    assert endif is not None, "the compiler-version guard is never closed with #endif"
    assert re.search(r"(?im)^\s*#error\b", tail[: endif.start()]) is not None, (
        "the compiler-version guard does not raise #error, so an old compiler would carry on and fail obscurely"
    )


def test_compiler_floor_matches_the_feature_that_requires_it() -> None:
    """The declared floor is justified by a directive that only exists at that version.

    Couples the number to the reason: ``WizardImageFileDynamicDark`` is a 6.6.0
    directive. Dropping the floor while keeping the directive, or vice versa,
    breaks the pairing this asserts.
    """
    iss_text = read_iss()
    directives = parse_setup_directives(iss_text)
    assert "wizardimagefiledynamicdark" in directives, (
        "the 6.6.0 floor is declared but the 6.6.0-only directive that justifies it is gone; lower the floor or restore the directive"
    )
    match = _VER_GUARD_RE.search(iss_text)
    assert match is not None
    assert (int(match.group(1)), int(match.group(2))) >= (6, 6)


def test_readme_documents_the_compiler_floor() -> None:
    """The build-machine prerequisites name the same floor the script enforces.

    A packager reads the README before they ever run ``iscc``; a floor only the
    compiler knows about is a floor discovered the hard way.
    """
    readme = read_readme()
    assert "Inno Setup 6.6.0 or newer" in readme, "packaging/README.md does not state the Inno Setup 6.6.0 prerequisite"
    assert "6.6.0" in readme.split("## Build-machine prerequisites", 1)[-1], "the 6.6.0 floor is not in the prerequisites section"


# --- Item 1: opt-in code signing ---------------------------------------------


def test_signing_directives_live_inside_the_signtoolname_ifdef() -> None:
    """Real gate: ``SignTool`` and ``SignedUninstaller`` are emitted only when opted in.

    Both must sit inside ``#ifdef SignToolName``. Hoisting ``SignedUninstaller``
    out is the specific regression this catches: with no ``SignTool`` bound, ISCC
    stops and prompts interactively for a signature, so every unsigned local
    build would hang at compile time.
    """
    iss_text = read_iss()
    guarded = conditional_blocks(iss_text).get(_SIGNING_SYMBOL)
    assert guarded is not None, f"the .iss declares no `#ifdef {_SIGNING_SYMBOL}` block"

    for directive in _SIGNING_DIRECTIVES:
        assert any(line.lower().startswith(f"{directive.lower()}=") for line in guarded), (
            f"{directive} is not declared inside the #ifdef {_SIGNING_SYMBOL} block"
        )
        stray = directive_lines_outside_conditionals(iss_text, directive)
        assert stray == [], f"{directive} is declared unconditionally ({stray}); an unsigned build would no longer compile unattended"


def test_signtool_references_the_compile_time_symbol() -> None:
    """``SignTool`` names the symbol the packager defines, not a hardcoded tool name.

    A literal here would bind the script to one machine's Sign Tool registration.
    """
    directives = parse_setup_directives(read_iss())
    assert directives.get("signtool") == f"{{#{_SIGNING_SYMBOL}}}", (
        f"SignTool is {directives.get('signtool')!r}; it must resolve the {_SIGNING_SYMBOL} preprocessor symbol"
    )
    assert directives.get("signeduninstaller") == "yes", "SignedUninstaller must be yes so a signed build signs the uninstaller too"


def test_readme_documents_both_halves_of_the_signing_opt_in() -> None:
    """The README documents the ``/D`` symbol and the ``/S`` tool binding together.

    Defining one without the other is a compile error, so documenting only half
    is documenting a broken command.
    """
    readme = read_readme()
    assert f"/D{_SIGNING_SYMBOL}=" in readme, "the README does not show the /D<symbol> half of the signing invocation"
    assert re.search(r"/S\w+=", readme) is not None, "the README does not show the /S<name>=<command> half of the signing invocation"


# --- Items 3 and 4: nothing stalls or destroys under /SILENT -----------------


def test_uninstall_tool_cache_prompt_defaults_to_keeping_the_cache() -> None:
    """Real gate: the tool-cache prompt is suppressible and its silent default is NO.

    Two independent regressions are caught. Reverting to a plain ``MsgBox`` fails
    the kind assertion (a plain ``MsgBox`` is not suppressed by
    ``/SUPPRESSMSGBOXES``, so an unattended uninstall blocks on a modal forever).
    Changing the suppressed default to ``IDYES`` fails the default assertion --
    that single token decides whether an unattended uninstall silently deletes
    the user's tool cache.
    """
    code = pascal_code(read_iss())
    kind, arguments = find_message_box(code, "tool cache")

    assert kind == "SuppressibleMsgBox", f"the uninstall tool-cache prompt is a {kind}; a plain MsgBox stalls an unattended uninstall"
    assert arguments[-3:] == ["mbConfirmation", "MB_YESNO", "IDNO"], (
        f"the tool-cache prompt ends in {arguments[-3:]}; the suppressed default must be IDNO so a silent uninstall keeps the cache"
    )
    assert re.search(r"=\s*IDYES\s+then\s+DelTree\(ToolsDir", code) is not None, (
        "the tool cache is deleted on a branch other than an explicit IDYES answer"
    )


def test_tool_cache_deletion_is_the_only_deltree_in_the_uninstaller() -> None:
    """No second, unguarded ``DelTree`` can remove the cache behind the prompt's back.

    The prompt only protects the cache if it is the sole route to deleting it.
    """
    code = pascal_code(read_iss())
    deletions = re.findall(r"DelTree\(([^,]+)", code)
    assert deletions == ["ToolsDir"], f"unexpected DelTree targets in [Code]: {deletions}"


def test_unsupported_windows_refusal_is_suppressible() -> None:
    """Real gate: the fatal Windows-version dialog can be suppressed and defaults to OK.

    ``InitializeSetup`` returns ``False`` either way, so the message is advisory
    -- but as a plain ``MsgBox`` it is one of the boxes ``/SUPPRESSMSGBOXES``
    cannot dismiss, and an unattended run would hang on it instead of exiting.
    """
    code = pascal_code(read_iss())
    kind, arguments = find_message_box(code, "requires Windows 10")

    assert kind == "SuppressibleMsgBox", f"the unsupported-Windows refusal is a {kind}; it must be suppressible for an unattended run"
    assert arguments[-3:] == ["mbCriticalError", "MB_OK", "IDOK"], (
        f"the unsupported-Windows refusal ends in {arguments[-3:]}; it must be a suppressible mbCriticalError defaulting to IDOK"
    )


def test_readme_records_the_unattended_safety_contract() -> None:
    """The README states the non-destructive suppressed default explicitly.

    The default is invisible in the UI (it only shows under ``/SILENT``), so the
    documented promise is the only place a maintainer would see it stated.
    """
    readme = read_readme()
    assert "SuppressibleMsgBox" in readme, "the README does not document the suppressible message boxes"
    assert "defaults to **no**" in readme.lower() or "defaults to no" in readme.lower(), (
        "the README does not record that the tool-cache prompt defaults to keeping the cache when suppressed"
    )


def test_wizardsilent_is_never_reached_from_the_uninstall_path() -> None:
    """Real gate: the Setup-only ``WizardSilent`` sits inside the ``Add`` branch.

    ``SetDefenderExclusion`` is shared: Setup calls it with ``'Add'`` and the
    uninstaller with ``'Remove'``. ``WizardSilent`` is a Setup-only function, so
    the ``Remove`` path must not be able to reach it. Flattening the branch back
    into a single ``(Verb = 'Add') and (not WizardSilent())`` puts the call on the
    uninstaller's path and leaves it to short-circuit evaluation to save it.
    """
    code = pascal_code(read_iss())
    # Pascal brace comments are stripped first: the rationale comment above the
    # branch names WizardSilent, and a comment is not a call site.
    procedure = re.sub(r"\{[^}]*\}", "", code[code.index("procedure SetDefenderExclusion") : code.index("procedure DismLogOutput")])
    assert "WizardSilent" in procedure, "the Defender advisory no longer checks for a silent install"

    for match in re.finditer(r"\bWizardSilent\b", procedure):
        preceding = procedure[: match.start()]
        opening = preceding.rfind("if Verb = 'Add' then")
        assert opening >= 0, "a WizardSilent call in SetDefenderExclusion is not inside an `if Verb = 'Add'` branch"
        assert "end;" not in preceding[opening:], "the `if Verb = 'Add'` branch closes before the WizardSilent call it should contain"


# --- Items 4, 16, 18, 19: the platform guards agree with each other ----------


def test_windows_floor_is_declared_in_setup_and_enforced_in_code() -> None:
    """Real gate: ``MinVersion`` and the ``[Code]`` build guard describe one floor.

    The comment always claimed build 10240 while the code only tested
    ``Major < 10``, so a Windows 10 build below RTM passed. The build test must
    exist, and the ``[Setup]`` refusal must agree with it.
    """
    iss_text = read_iss()
    directives = parse_setup_directives(iss_text)
    assert directives.get("minversion") == _MIN_WINDOWS_MAJOR, (
        f"MinVersion is {directives.get('minversion')!r}; the supported floor is Windows {_MIN_WINDOWS_MAJOR}"
    )

    code = pascal_code(iss_text)
    constant = re.search(r"(?m)^\s*MinWindowsBuild\s*=\s*(\d+)\s*;", code)
    assert constant is not None, "[Code] declares no MinWindowsBuild constant"
    assert int(constant.group(1)) == _MIN_WINDOWS_BUILD, (
        f"MinWindowsBuild is {constant.group(1)}, not the Windows 10 RTM build {_MIN_WINDOWS_BUILD}"
    )
    assert re.search(r"Version\.Build\s*<\s*MinWindowsBuild", code) is not None, (
        "the [Code] guard never compares Version.Build against MinWindowsBuild, so a pre-RTM build 10 passes"
    )


def test_architecture_refusal_is_declared_once_in_setup_not_twice_in_code() -> None:
    """Real gate: the 64-bit refusal lives in ``[Setup]``, and ``[Code]`` does not repeat it.

    ``ArchitecturesAllowed=x64os`` rejects a 32-bit host before ``InitializeSetup``
    ever runs, so the old ``Is64BitInstallMode`` branch was unreachable. Removing
    the ``[Setup]`` directive without restoring a code guard turns this red, so
    the platform can never end up with no arch refusal at all.
    """
    iss_text = read_iss()
    directives = parse_setup_directives(iss_text)
    code = pascal_code(iss_text)

    has_code_guard = "Is64BitInstallMode" in code
    assert directives.get("architecturesallowed") == "x64os" or has_code_guard, (
        "neither ArchitecturesAllowed=x64os nor a [Code] architecture guard is present; a 32-bit host would not be refused"
    )
    assert not has_code_guard, "[Code] repeats the architecture refusal ArchitecturesAllowed=x64os already enforces; it is unreachable"


# --- Item 15: SetupMutex ------------------------------------------------------


def test_setup_declares_both_an_app_mutex_and_a_setup_mutex() -> None:
    r"""Real gate: a second Setup process cannot race the first on the same ``{app}``.

    ``AppMutex`` only detects a running *application*; it does nothing about two
    Setup processes both running ``[InstallDelete]`` over the same tree. The
    mutex must also carry a ``Global\`` form so the check spans sessions.
    """
    directives = parse_setup_directives(read_iss())
    app_mutex = directives.get("appmutex")
    setup_mutex = directives.get("setupmutex")

    assert app_mutex, "AppMutex is not declared; a running application would not be detected"
    assert setup_mutex, "SetupMutex is not declared; two Setup processes could race on the same install tree"
    assert setup_mutex != app_mutex, "SetupMutex reuses the AppMutex name, so Setup would refuse to run while the app is open"
    names = [name.strip() for name in setup_mutex.split(",")]
    assert any(name.startswith("Global\\") for name in names), f"SetupMutex {names} declares no Global\\ form, so it does not span sessions"


# --- Items 17 and 20: the DISM progress callback ------------------------------


def test_dism_output_is_routed_through_the_logging_callback() -> None:
    """Real gate: DISM output drives the gauge instead of being discarded to ``nil``.

    Reverting the last ``ExecAndLogOutput`` argument to ``nil`` -- the state that
    left the bar at 0% for the whole enable -- turns this red.
    """
    code = pascal_code(read_iss())
    match = re.search(r"\bExecAndLogOutput\s*\(", code)
    assert match is not None, "[Code] no longer calls ExecAndLogOutput for the DISM run"

    arguments = split_call_arguments(code, match.end() - 1)
    assert arguments[-1] == f"@{_DISM_CALLBACK}", f"ExecAndLogOutput's OnLog argument is {arguments[-1]!r}, not @{_DISM_CALLBACK}"


def test_dism_callback_signature_and_declaration_order_are_compilable() -> None:
    """The callback matches ``TOnLog`` exactly and is declared before its user.

    PascalScript resolves ``@DismLogOutput`` at the point of use, so a callback
    declared after ``EnableHyperVPlatform`` is a compile error -- one that only
    ``iscc`` would report, and this suite never runs ``iscc``.
    """
    code = pascal_code(read_iss())
    assert _DISM_CALLBACK_SIGNATURE in code, f"the DISM callback does not carry the TOnLog signature: {_DISM_CALLBACK_SIGNATURE}"

    callback_at = code.index(_DISM_CALLBACK_SIGNATURE)
    user_at = code.index("procedure EnableHyperVPlatform")
    assert callback_at < user_at, "DismLogOutput is declared after the procedure that references it, which will not compile"


def test_dism_callback_still_logs_every_line_unconditionally() -> None:
    """Supplying a callback must not lose the logging that ``nil`` performed.

    Inno logs child output itself only while ``OnLog`` is ``nil``. Once a handler
    is supplied, dropping the bare ``Log(S)`` silently removes the DISM
    transcript from the Setup log -- exactly the diagnostic a failed enable needs.
    """
    code = pascal_code(read_iss())
    start = code.index(_DISM_CALLBACK_SIGNATURE)
    body = code[start : code.index("procedure EnableHyperVPlatform")]
    assert re.search(r"(?m)^\s*Log\(S\);\s*$", body) is not None, (
        "DismLogOutput no longer writes every line to the log with an unguarded Log(S)"
    )


def test_dism_gauge_never_claims_completion_it_cannot_know() -> None:
    """The gauge ceiling stays below the maximum because DISM's line count is unknown.

    A ceiling equal to the maximum would park the bar at 100% partway through the
    enable and then sit there, which is worse than the 0% it replaced.
    """
    code = pascal_code(read_iss())
    constants = {
        name: int(value)
        for name, value in re.findall(r"(?m)^\s*(DismProgressStep|DismProgressCeiling|DismProgressMax)\s*=\s*(\d+)\s*;", code)
    }
    assert set(constants) == {"DismProgressStep", "DismProgressCeiling", "DismProgressMax"}, f"missing DISM gauge constants: {constants}"
    assert constants["DismProgressStep"] > 0, "the DISM gauge would never advance"
    assert constants["DismProgressCeiling"] < constants["DismProgressMax"], (
        "the DISM gauge ceiling reaches its maximum, so the bar claims completion before DISM finishes"
    )


def test_dism_progress_page_is_released_on_every_path() -> None:
    """The file-scope page variable is cleared in the ``finally``, so the callback nil-guards.

    The callback runs only while the page is alive; leaving a dangling reference
    after ``Hide`` is what a file-scope handle invites.
    """
    code = pascal_code(read_iss())
    assert re.search(r"finally\s+DismProgressPage\.Hide\(\);\s+DismProgressPage\s*:=\s*nil;", code) is not None, (
        "DismProgressPage is not cleared in the finally block after Hide()"
    )
    assert "if DismProgressPage <> nil then" in code, "the DISM callback does not nil-guard the page it writes to"


def test_no_source_claims_execandlogoutput_is_what_keeps_the_wizard_responsive() -> None:
    """The corrected rationale replaced the false one in both the script and the README.

    ``ExecAndLogOutput`` was documented as the reason the wizard stays responsive;
    plain ``Exec`` pumps the message queue just as well, so the claim was wrong
    and would have justified reverting the callback. Restoring the old wording
    turns this red.
    """
    iss_text = read_iss()
    readme = read_readme()
    for name, text in (("packaging/intellicrack.iss", iss_text), ("packaging/README.md", readme)):
        assert "Not Responding" not in text, f"{name} still claims ExecAndLogOutput prevents a 'Not Responding' wizard"
        assert "stays responsive" not in text, f"{name} still credits ExecAndLogOutput with keeping the wizard responsive"
    assert "line by line" in iss_text, "the .iss no longer records the real reason ExecAndLogOutput is used"
    assert "line by line" in readme, "the README no longer records the real reason ExecAndLogOutput is used"


# --- The DISM invocation cannot escape as an unhandled exception -------------


def enable_hyperv_procedure(code: str) -> str:
    """Extract the body of ``procedure EnableHyperVPlatform`` from ``[Code]``.

    Args:
        code: The Pascal source of the ``[Code]`` section.

    Returns:
        str: The procedure text from its header up to the next top-level
            ``procedure``/``function`` declaration, or end of section.

    Raises:
        AssertionError: If the procedure is not declared.
    """
    start = code.find("procedure EnableHyperVPlatform")
    if start < 0:
        msg = "[Code] declares no procedure EnableHyperVPlatform"
        raise AssertionError(msg)
    nxt = re.search(r"(?m)^\s*(procedure|function)\s+\w+", code[start + 1 :])
    end = start + 1 + nxt.start() if nxt is not None else len(code)
    return code[start:end]


def test_dism_invocation_is_wrapped_in_a_try_except_that_logs_the_failure() -> None:
    """Real gate: an exception from the DISM call is caught, logged, and made graceful.

    ``ExecAndLogOutput`` raises -- not returns ``False`` -- when the child cannot
    be created at all (for example a redirected or missing ``dism.exe``), and the
    supplied ``@DismLogOutput`` handler can raise too. The call must therefore sit
    inside a ``try``/``except`` whose handler logs ``GetExceptionMessage`` so the
    procedure falls through to its ``if not Launched`` recovery instead of letting
    the exception unwind through Setup.

    Falsifiable three ways: dropping the nested handler so the innermost ``try``
    guarding the call becomes a bare ``try``/``finally`` makes ``except`` no longer
    the first handler after the call; removing the ``GetExceptionMessage`` log
    empties the handler; and deleting the ``if not Launched`` branch removes the
    recovery the handler exists to reach.
    """
    # Strip Pascal brace comments first: the rationale comment above the call
    # names ExecAndLogOutput, and a comment is not a call site.
    procedure = re.sub(r"\{[^}]*\}", "", enable_hyperv_procedure(pascal_code(read_iss())))
    call_at = procedure.find("ExecAndLogOutput")
    assert call_at >= 0, "EnableHyperVPlatform no longer calls ExecAndLogOutput"

    before = procedure[:call_at]
    guarding_try = before.rfind("try")
    assert guarding_try >= 0, "the ExecAndLogOutput call is not inside any try block"
    assert re.search(r"\b(except|finally)\b", before[guarding_try:]) is None, (
        "a handler opens between the innermost try and the ExecAndLogOutput call; the call is not in the protected block"
    )

    after = procedure[call_at:]
    except_at = re.search(r"\bexcept\b", after)
    finally_at = re.search(r"\bfinally\b", after)
    assert except_at is not None, "no except handler follows the ExecAndLogOutput call"
    assert finally_at is None or except_at.start() < finally_at.start(), (
        "the innermost try guarding the DISM call is a try/finally, not a try/except; a raised exception is not caught"
    )

    handler_end = finally_at.start() if finally_at is not None else len(after)
    handler = after[except_at.start() : handler_end]
    assert "GetExceptionMessage" in handler, "the DISM except handler does not log GetExceptionMessage"
    assert re.search(r"\bLog\s*\(", handler) is not None, "the DISM except handler does not write the failure to the Setup log"

    assert re.search(r"if\s+not\s+Launched\s+then", procedure) is not None, (
        "EnableHyperVPlatform has no `if not Launched` recovery branch for the caught failure"
    )


def test_try_except_detection_distinguishes_except_from_finally() -> None:
    """Proof: the guard fires on a bare try/finally around the same call.

    A try/finally hides the page but re-raises; only a try/except makes the call
    non-fatal. The detection above must tell them apart, or its green would be
    meaningless.
    """
    guarded = "try\n try\n  x := ExecAndLogOutput(a);\n except\n  Log(GetExceptionMessage);\n end;\n finally\n end;"
    unguarded = "try\n x := ExecAndLogOutput(a);\nfinally\n Hide();\nend;"

    call = guarded.find("ExecAndLogOutput")
    after = guarded[call:]
    except_at = re.search(r"\bexcept\b", after)
    finally_at = re.search(r"\bfinally\b", after)
    assert except_at is not None
    assert finally_at is None or except_at.start() < finally_at.start()

    call = unguarded.find("ExecAndLogOutput")
    after = unguarded[call:]
    except_at = re.search(r"\bexcept\b", after)
    finally_at = re.search(r"\bfinally\b", after)
    assert except_at is None or (finally_at is not None and finally_at.start() < except_at.start())


# --- Item 5: the provenance stamp is installed, not merely staged ------------


def test_build_info_stamp_is_packaged_into_the_app_directory() -> None:
    """Real gate: ``build-info.json`` is an installed file, not a stage-only artifact.

    The stamp is what lets a support request name the exact commit an installed
    tree came from. Staging it without a ``[Files]`` entry -- its original state
    -- leaves every installation anonymous.
    """
    iss_text = read_iss()
    entries = [line for line in iss_text.splitlines() if "build-info.json" in line and line.strip().lower().startswith("source:")]
    assert len(entries) == 1, f"expected exactly one [Files] entry for build-info.json, found {len(entries)}"
    entry = entries[0]
    assert 'DestDir: "{app}\\app"' in entry, f"build-info.json is not installed beside the application source: {entry}"
    assert "Components: core" in entry, f"build-info.json is not part of the mandatory core component: {entry}"
