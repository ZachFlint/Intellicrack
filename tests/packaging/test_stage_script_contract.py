# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Falsifiable gates for the ``packaging/stage.ps1`` hardening pass.

Running the stager is a multi-hour, 205 MB-download, ~100 GB build, so none of
these gates run it. They pin the parts of it that can be checked without one, and
they avoid grep-style assertions wherever a real check is available:

* The **core-runtime gate** ``stage.ps1`` emits is real Python, embedded in a
  here-string. It is extracted and executed here, and its two load-bearing
  behaviours are exercised against real files on disk: a ``try``/``except``-guarded
  import must not be demanded of the core runtime (this is what keeps ``torch``
  out), an unguarded one must be, and a missing module must be reported as a
  failure rather than swallowed. This is the production code, lifted, not a
  restatement of it.
* The **wizard-freshness preflight** parses ``generate_banners.ps1`` at build
  time. The regexes it uses are extracted from ``stage.ps1`` itself and run
  against the real generator here, so this reddens exactly when that parse would
  start failing -- rather than hand-restating patterns that could drift.
* The **checksum manifest** must be written outside the staged tree, or the
  installer would package it as application content. That is not asserted from a
  string: both ``$ManifestPath`` and ``$Stage`` are resolved through the script's
  own ``Join-Path`` assignment chain and compared.
* The **parameter surface**, the ``ShouldProcess`` wrapping and the PyInstaller
  ``--clean`` flag are structural properties of the script text, checked by
  parsing the ``param()`` block and matching braces rather than by substring.

Here-strings are stripped before any brace matching, because the embedded Python
contains braces of its own.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from tests.packaging.test_stage_iss_coverage import resolve_path_variables


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_PACKAGING: Final[Path] = _REPO_ROOT / "packaging"
_STAGE_PS1: Final[Path] = _PACKAGING / "stage.ps1"
_WIZARD_DIR: Final[Path] = _PACKAGING / "wizard"
_GENERATOR_PS1: Final[Path] = _WIZARD_DIR / "generate_banners.ps1"
_ISS_PATH: Final[Path] = _PACKAGING / "intellicrack.iss"
_SRC_INTELLICRACK: Final[Path] = _REPO_ROOT / "src" / "intellicrack"

# A PowerShell here-string: a line ending in ``@'`` opens it, a line whose first
# non-space characters are ``'@`` closes it.
_HERE_OPEN_RE: Final[re.Pattern[str]] = re.compile(r"@'\s*$")
_HERE_CLOSE_RE: Final[re.Pattern[str]] = re.compile(r"^\s*'@")

# ``$Name = @'`` -- the assignment a here-string is bound to.
_HERE_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(r"^\s*\$(\w+)\s*=\s*@'\s*$")

# The regexes the wizard preflight applies to the generator's source.
_NOTMATCH_RE: Final[re.Pattern[str]] = re.compile(r'\$GeneratorText\s+-notmatch\s+"([^"]+)"')
_MATCHES_RE: Final[re.Pattern[str]] = re.compile(r'\[regex\]::Matches\(\$GeneratorText,\s*"([^"]+)"\)')

# The one interpolation inside those patterns, and what it stands for.
_SELECTED_KEY_INTERPOLATION: Final[str] = "$([regex]::Escape($WizardSelectedKey))"

_SHOULD_PROCESS: Final[str] = "$PSCmdlet.ShouldProcess("

# Every parameter the stager must expose, with the default that reproduces the
# behaviour it had before the parameters existed.
_EXPECTED_PARAMETERS: Final[dict[str, str]] = {
    "SkipJdkDownload": "switch",
    "SkipGuestImage": "switch",
    "SkipSigning": "switch",
    "HexcoreProfile": "string",
    "JdkDownloadRetries": "int",
}

# The name the core-runtime gate is bound to inside stage.ps1.
_CORE_GATE_VARIABLE: Final[str] = "CoreGateSource"

_MINIMUM_WIZARD_IMAGES: Final[int] = 3
_EXPECTED_NOTMATCH_PATTERNS: Final[int] = 4


def read_stage_script() -> str:
    """Read the staging script.

    Returns:
        str: The full text of ``packaging/stage.ps1``.
    """
    assert _STAGE_PS1.is_file(), f"staging script missing: {_STAGE_PS1}"
    return _STAGE_PS1.read_text(encoding="utf-8")


def strip_here_strings(script_text: str) -> str:
    """Blank out here-string bodies while preserving line numbering.

    The embedded core-runtime gate is Python and carries braces of its own, which
    would derail any brace matching over the PowerShell around it.

    Args:
        script_text: The full text of a PowerShell script.

    Returns:
        str: The script with every here-string body replaced by empty lines.
    """
    lines = script_text.splitlines()
    output: list[str] = []
    inside = False
    for line in lines:
        if inside:
            output.append("")
            if _HERE_CLOSE_RE.match(line):
                inside = False
            continue
        output.append(line)
        if _HERE_OPEN_RE.search(line):
            inside = True
    return "\n".join(output)


def extract_here_string(script_text: str, variable: str) -> str:
    """Return the body of the here-string assigned to one variable.

    Args:
        script_text: The full text of a PowerShell script.
        variable: The variable name, without its ``$``.

    Returns:
        str: The here-string body, without its opening or closing delimiters.

    Raises:
        AssertionError: If no here-string is assigned to that variable.
    """
    lines = script_text.splitlines()
    for index, line in enumerate(lines):
        match = _HERE_ASSIGN_RE.match(line)
        if match is None or match.group(1) != variable:
            continue
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if _HERE_CLOSE_RE.match(candidate):
                return "\n".join(body) + "\n"
            body.append(candidate)
        break
    msg = f"packaging/stage.ps1 assigns no here-string to ${variable}"
    raise AssertionError(msg)


def _matching_brace_span(text: str, start: int) -> tuple[int, int]:
    """Return the span of the brace-delimited block that opens after ``start``.

    Args:
        text: The source to scan.
        start: Index to begin looking for the opening brace from.

    Returns:
        tuple[int, int]: ``(open_index, close_index)`` of the block, or
            ``(-1, -1)`` when no balanced block follows.
    """
    opening = text.find("{", start)
    if opening < 0:
        return (-1, -1)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return (opening, index)
    return (-1, -1)


def guarded_statements(script_text: str, guard: str) -> list[str]:
    """Return the bodies of every block opened by a guard expression.

    Args:
        script_text: A PowerShell script with here-strings already stripped.
        guard: The literal guard text, for example ``"$PSCmdlet.ShouldProcess("``.

    Returns:
        list[str]: The source inside each block guarded by that expression.
    """
    bodies: list[str] = []
    position = 0
    while True:
        found = script_text.find(guard, position)
        if found < 0:
            return bodies
        opening, closing = _matching_brace_span(script_text, found)
        if opening < 0:
            return bodies
        bodies.append(script_text[opening : closing + 1])
        position = closing


def parameter_declarations(script_text: str) -> dict[str, str]:
    """Parse the script's ``param()`` block into per-parameter declarations.

    Args:
        script_text: The full text of a PowerShell script.

    Returns:
        dict[str, str]: Parameter name (without ``$``) mapped to the whole
            declaration, attributes included.

    Raises:
        AssertionError: If the script declares no ``param()`` block.
    """
    match = re.search(r"(?m)^param\(", script_text)
    if match is None:
        msg = "packaging/stage.ps1 declares no param() block"
        raise AssertionError(msg)
    depth = 0
    end = -1
    for index in range(match.end() - 1, len(script_text)):
        if script_text[index] == "(":
            depth += 1
        elif script_text[index] == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end < 0:
        msg = "packaging/stage.ps1 has an unterminated param() block"
        raise AssertionError(msg)

    declarations: dict[str, str] = {}
    for chunk in _split_top_level(script_text[match.end() : end]):
        name = re.search(r"\$(\w+)", chunk)
        if name is not None:
            declarations[name.group(1)] = chunk
    return declarations


def _split_top_level(body: str) -> list[str]:
    """Split a parameter list on commas that separate parameters.

    A validation attribute such as ``[ValidateSet('release', 'debug')]`` carries
    commas of its own; splitting naively would tear a declaration in half and
    make an assertion about it silently look at the wrong text.

    Args:
        body: The contents of a ``param(...)`` block, without the parentheses.

    Returns:
        list[str]: The individual parameter declarations, attributes included.
    """
    chunks: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    for char in body:
        if in_string:
            current.append(char)
            if char == "'":
                in_string = False
            continue
        if char == "'":
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            chunks.append("".join(current))
            current = []
            continue
        current.append(char)
    chunks.append("".join(current))
    return [chunk for chunk in chunks if chunk.strip()]


def powershell_pattern_to_python(pattern: str, selected_key: str | None = None) -> str:
    """Convert a PowerShell double-quoted regex literal into a Python pattern.

    Only two PowerShell-isms occur in the preflight's patterns: the backtick
    escape before ``$``, and the one interpolation that carries the selected
    background key.

    Args:
        pattern: The regex exactly as it appears inside the script's quotes.
        selected_key: The background key to substitute for the interpolation,
            when the pattern contains it.

    Returns:
        str: An equivalent Python regular expression.
    """
    converted = pattern.replace("`$", "$")
    if _SELECTED_KEY_INTERPOLATION in converted and selected_key is not None:
        converted = converted.replace(_SELECTED_KEY_INTERPOLATION, re.escape(selected_key))
    return converted


@pytest.fixture(scope="module")
def core_runtime_gate(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    """Materialise and import the core-runtime gate embedded in the stager.

    ``stage.ps1`` writes this here-string to ``build/_core_runtime_gate.py`` and
    runs it with the staged interpreter. Reproducing that -- writing the extracted
    source to a file and importing it -- is what makes the tests below exercise
    the shipped implementation rather than a restatement of it.

    Args:
        tmp_path_factory: Pytest factory for a module-scoped temporary directory.

    Returns:
        ModuleType: The imported gate module.
    """
    source = extract_here_string(read_stage_script(), _CORE_GATE_VARIABLE)
    path = tmp_path_factory.mktemp("core_runtime_gate") / "_core_runtime_gate.py"
    path.write_text(source, encoding="utf-8")

    spec = importlib.util.spec_from_file_location("intellicrack_core_runtime_gate", path)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load the extracted core-runtime gate from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- Item 14: the parameter surface and -WhatIf ------------------------------


def test_stage_script_declares_the_documented_parameter_surface() -> None:
    """Real gate: every skip switch, the profile and the retry count are declared.

    Falsifiable by removing a parameter or renaming one: a caller's
    ``-SkipJdkDownload`` would then bind to nothing and be silently ignored,
    because a plain script accepts unbound arguments without complaint.
    """
    declarations = parameter_declarations(read_stage_script())
    missing = sorted(name for name in _EXPECTED_PARAMETERS if name not in declarations)
    assert missing == [], f"packaging/stage.ps1 no longer declares: {missing}"

    for name, kind in _EXPECTED_PARAMETERS.items():
        assert f"[{kind}]" in declarations[name].lower(), f"${name} is not declared as [{kind}]: {declarations[name].strip()!r}"


def test_stage_script_defaults_reproduce_the_previous_behaviour() -> None:
    r"""Real gate: running the stager with no arguments builds what it always built.

    A switch defaults to false, so the skips are inert. The two valued parameters
    must carry the literals the script used before they were parameterised -- a
    release hexcore build and four download attempts. Changing either default
    silently changes what an unqualified ``pwsh packaging\stage.ps1`` produces.
    """
    declarations = parameter_declarations(read_stage_script())

    profile = declarations["HexcoreProfile"]
    assert re.search(r"\$HexcoreProfile\s*=\s*'release'", profile) is not None, (
        f"the default hexcore profile is no longer 'release': {profile.strip()!r}"
    )
    assert "ValidateSet('release', 'debug')" in profile.replace('"', "'"), "the hexcore profile accepts values other than release/debug"

    retries = declarations["JdkDownloadRetries"]
    assert re.search(r"\$JdkDownloadRetries\s*=\s*4\b", retries) is not None, (
        f"the default JDK download attempt count is no longer 4: {retries.strip()!r}"
    )
    assert re.search(r"ValidateRange\(\s*1\s*,\s*10\s*\)", retries) is not None, "the JDK retry count is unbounded"


def test_release_profile_still_builds_hexcore_with_release() -> None:
    """The default profile appends ``--release`` exactly as the unparameterised call did.

    The stager previously ran ``maturin build --release`` unconditionally; the
    parameterised form must still do so for the default, or a release stage would
    silently ship a debug hexcore.
    """
    script = strip_here_strings(read_stage_script())
    match = re.search(r"if \(\$HexcoreProfile -eq 'release'\)", script)
    assert match is not None, "the hexcore profile no longer selects the release build"
    opening, closing = _matching_brace_span(script, match.end())
    assert opening > 0, "the hexcore profile branch is not a balanced block"
    assert "'--release'" in script[opening:closing], "the release profile branch no longer adds --release to the maturin arguments"
    assert "maturin @MaturinArgs" in script, "maturin is no longer invoked with the assembled argument array"


def test_destructive_and_generating_steps_are_wrapped_in_shouldprocess() -> None:
    """Real gate: ``-WhatIf`` previews the stage wipe and every generated file.

    ``SupportsShouldProcess`` on its own changes nothing: each destructive or
    file-writing statement has to ask. Unwrapping any of them makes ``-WhatIf``
    quietly perform that step for real, which is the worst possible outcome for a
    preview flag.
    """
    script = strip_here_strings(read_stage_script())
    assert "[CmdletBinding(SupportsShouldProcess)]" in script, "the script no longer opts into ShouldProcess, so -WhatIf is not even accepted"

    guarded = "\n".join(guarded_statements(script, _SHOULD_PROCESS))
    assert "Remove-Item -LiteralPath $Stage -Recurse -Force" in guarded, "the stage wipe is no longer behind ShouldProcess"

    writes = script.count("[System.IO.File]::WriteAllText(")
    assert writes > 0, "the script writes no files through WriteAllText; the gate below would be vacuous"
    assert guarded.count("[System.IO.File]::WriteAllText(") == writes, (
        f"only {guarded.count('[System.IO.File]::WriteAllText(')} of {writes} WriteAllText calls are behind ShouldProcess"
    )


# --- Item 12: PyInstaller --clean --------------------------------------------


def test_launchers_are_built_from_a_clean_pyinstaller_cache() -> None:
    """Real gate: a stale PyInstaller cache cannot mask a launcher or spec change.

    Without ``--clean`` a changed spec (the version resource, for one) can be
    served from a cached analysis, so the shipped exe silently predates the fix.
    """
    script = strip_here_strings(read_stage_script())
    invocations = re.findall(r"&\s*pixi\s+run\s+pyinstaller\s+([^\r\n]*)", script)
    assert invocations, "the stager no longer invokes pyinstaller"
    for invocation in invocations:
        assert "--clean" in invocation, f"pyinstaller is invoked without --clean: {invocation.strip()!r}"


# --- Item 11: the SHA-256 manifest --------------------------------------------


def test_checksum_manifest_is_written_outside_the_staged_tree() -> None:
    """Real gate: the manifest is a sibling of ``build/stage``, never a member of it.

    Both paths are resolved through the script's own assignment chain rather than
    matched as strings, so moving the manifest inside the stage reddens this even
    if the file name is unchanged. A manifest inside the tree would have to list
    itself, and the installer packages that tree verbatim, so it would ship as if
    it were application content.
    """
    variables = resolve_path_variables(read_stage_script())
    manifest = variables.get("ManifestPath")
    stage = variables.get("Stage")
    assert stage, "packaging/stage.ps1 declares no resolvable $Stage"
    assert manifest, "packaging/stage.ps1 declares no resolvable $ManifestPath; the checksum manifest is gone"
    assert not manifest.startswith(f"{stage}/"), f"the checksum manifest {manifest!r} is written inside the staged tree {stage!r}"
    assert manifest.endswith(".txt"), f"the checksum manifest has an unexpected name: {manifest!r}"


def test_checksum_manifest_is_reproducible_and_bom_free() -> None:
    """The manifest is ordinally sorted, LF-terminated and written without a BOM.

    A culture-aware sort makes a Turkish or French build host produce a different
    manifest for identical inputs, and a BOM breaks ``sha256sum -c`` on the first
    line. Both are silent: the file still looks correct.
    """
    script = strip_here_strings(read_stage_script())
    manifest_block = script[script.index("$ManifestPath =") :]
    assert re.search(r"\[Array\]::Sort\(\$\w+,\s*\[System\.StringComparer\]::Ordinal\)", manifest_block) is not None, (
        "the manifest is no longer sorted with an ordinal comparer, so its contents depend on the build host's locale"
    )
    assert "Sort-Object" not in manifest_block, (
        "the manifest uses PowerShell's culture-aware Sort-Object; a Turkish or French host would emit a different file for identical inputs"
    )
    assert "New-Object System.Text.UTF8Encoding($false)" in manifest_block, "the manifest is no longer written without a BOM"
    assert re.search(r"\$ManifestLines -join \"`n\"", manifest_block) is not None, "the manifest no longer joins its lines with LF"
    assert "Refusing to write an empty checksum manifest" in manifest_block, (
        "the manifest no longer refuses an empty stage, so a failed build could produce a manifest of nothing"
    )


# --- Item 13: the wizard-image freshness preflight ----------------------------


def test_wizard_preflight_still_parses_the_real_generator() -> None:
    """Real gate: the preflight's parse of ``generate_banners.ps1`` still succeeds.

    The patterns are extracted from ``stage.ps1`` and run against the real
    generator, so this is the same question the stager asks at build time. It
    reddens when the generator is refactored in a way that would make the stager
    throw -- which is otherwise only discovered by starting a multi-hour build.
    """
    script = read_stage_script()
    generator = _GENERATOR_PS1.read_text(encoding="utf-8")

    patterns = _NOTMATCH_RE.findall(script)
    assert len(patterns) == _EXPECTED_NOTMATCH_PATTERNS, (
        f"the wizard preflight applies {len(patterns)} parse patterns, expected {_EXPECTED_NOTMATCH_PATTERNS}"
    )

    selected_key: str | None = None
    resolved: list[str] = []
    for pattern in patterns:
        converted = powershell_pattern_to_python(pattern, selected_key)
        match = re.search(converted, generator)
        assert match is not None, f"the preflight pattern {converted!r} no longer matches packaging/wizard/generate_banners.ps1"
        captured = match.group(1)
        resolved.append(captured)
        if "SelectedKey" in pattern:
            selected_key = captured

    assert selected_key, "the preflight never recovers the selected background key"
    icon, background_dir, _key, background_file = resolved
    assert (_WIZARD_DIR / icon).resolve().is_file(), f"the generator's icon source does not exist: {icon}"
    assert (_WIZARD_DIR / background_dir / background_file).is_file(), (
        f"the selected background does not exist: {background_dir}/{background_file}"
    )


def test_wizard_preflight_covers_every_image_the_installer_ships() -> None:
    """Real gate: every wizard image the ``.iss`` uses is one the preflight checks.

    The freshness gate is only worth having if it covers the images that actually
    ship. An image added to the ``.iss`` but not produced by the generator would
    be stale forever with nothing to notice.
    """
    script = read_stage_script()
    generator = _GENERATOR_PS1.read_text(encoding="utf-8")

    pattern = _MATCHES_RE.search(script)
    assert pattern is not None, "the wizard preflight no longer enumerates the generated images"
    generated = {match.group(1) for match in re.finditer(powershell_pattern_to_python(pattern.group(1)), generator)}
    assert len(generated) >= _MINIMUM_WIZARD_IMAGES, f"the preflight found only {sorted(generated)} generated wizard images"

    iss_text = _ISS_PATH.read_text(encoding="utf-8-sig")
    shipped = {name.rsplit("\\", 1)[-1] for name in re.findall(r"(?im)^Wizard\w*ImageFile\w*=(\S+)", iss_text)}
    assert shipped, "the .iss declares no wizard images"
    uncovered = sorted(shipped - generated)
    assert uncovered == [], f"these wizard images ship in the installer but are not produced (and so not freshness-checked): {uncovered}"

    for name in generated:
        assert (_WIZARD_DIR / name).is_file(), f"the generator writes {name} but no committed copy exists beside it"


def test_wizard_preflight_fails_the_build_rather_than_warning() -> None:
    """A stale banner must stop the build, not print a warning nobody reads.

    The installer embeds the committed images verbatim, so a warning would ship
    last release's branding.
    """
    script = strip_here_strings(read_stage_script())
    comparison = re.search(r"if \(\$WizardNewestSourceStamp -gt \$WizardNewestImageStamp\)", script)
    assert comparison is not None, "the wizard preflight no longer compares the newest source against the newest generated image"

    opening, closing = _matching_brace_span(script, comparison.end())
    assert opening > 0, "the wizard freshness comparison is not a balanced block"
    body = script[opening : closing + 1]
    assert "throw " in body, "a stale wizard image no longer fails the build"
    assert "Write-Warning" not in body, "a stale wizard image is only warned about, so the build would ship last release's branding"
    assert "generate_banners.ps1" in body, "the staleness failure does not tell the packager how to regenerate the images"


# --- Item 9: the core-runtime gate --------------------------------------------


def test_core_runtime_gate_demands_only_unconditional_imports(core_runtime_gate: ModuleType, tmp_path: Path) -> None:
    """Real gate: the embedded gate ignores guarded imports and catches plain ones.

    This is the property the whole split depends on. ``torch`` and
    ``transformers`` are imported behind ``try``/``except ImportError`` and move
    to ``ml_overlay``; ``structlog`` is imported unconditionally and must stay in
    the core runtime. If the gate stopped distinguishing them it would either
    demand the relocated ML stack of a core-only install (failing every build) or
    stop noticing a genuinely missing core dependency.

    Args:
        core_runtime_gate: The gate module extracted from ``stage.ps1``.
        tmp_path: Pytest temporary directory holding a fake staged app source.
    """
    app_src = tmp_path / "src"
    package = app_src / "intellicrack"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        "import json\n"
        "import structlog\n"
        "from httpx import AsyncClient\n"
        "from intellicrack import core\n"
        "\n"
        "try:\n"
        "    import torch\n"
        "except ImportError:\n"
        "    torch = None\n"
        "\n"
        "if True:\n"
        "    import transformers\n"
        "\n"
        "def loader():\n"
        "    import tensorflow\n",
        encoding="utf-8",
    )

    surface: list[str] = core_runtime_gate.third_party_surface(app_src)
    assert "structlog" in surface, "an unconditional third-party import is not demanded of the core runtime"
    assert "httpx" in surface, "an unconditional from-import is not demanded of the core runtime"
    assert "torch" not in surface, "a try/except-guarded import is demanded of the core runtime; every core-only build would fail"
    assert "transformers" not in surface, "an if-guarded import is demanded of the core runtime"
    assert "tensorflow" not in surface, "a function-local import is demanded of the core runtime"
    assert "json" not in surface, "a standard-library module is demanded of the runtime as if it were a dependency"
    assert "intellicrack" not in surface, "the application package is treated as a third-party dependency"


def test_core_runtime_gate_reports_an_unimportable_module(core_runtime_gate: ModuleType) -> None:
    """Real gate: a relocated dependency is reported, not swallowed.

    ``import_all`` is what turns a missing package into a build failure. If it
    ever stopped collecting failures the gate would pass on a runtime that cannot
    start, which is precisely the situation it exists to prevent.

    Args:
        core_runtime_gate: The gate module extracted from ``stage.ps1``.
    """
    assert core_runtime_gate.import_all(["json", "ast"]) == [], "an importable stdlib module was reported as a failure"

    failures: list[str] = core_runtime_gate.import_all(["intellicrack_no_such_module_exists"])
    assert len(failures) == 1, f"a missing module produced {len(failures)} failures, expected 1"
    assert "intellicrack_no_such_module_exists" in failures[0]


def test_core_runtime_gate_refuses_to_pass_vacuously(core_runtime_gate: ModuleType, tmp_path: Path) -> None:
    """Real gate: an empty import surface fails instead of reporting success.

    A staged tree the gate cannot read - a moved ``app/src``, a renamed package -
    would otherwise produce an empty surface, import nothing, and declare the
    runtime sound.

    Args:
        core_runtime_gate: The gate module extracted from ``stage.ps1``.
        tmp_path: Pytest temporary directory holding an empty fake app source.
    """
    app_src = tmp_path / "src"
    (app_src / "intellicrack").mkdir(parents=True)

    assert core_runtime_gate.main([str(app_src)]) == 1, "the core-runtime gate passed with nothing to check"


def test_core_runtime_gate_checks_the_real_startup_chain(core_runtime_gate: ModuleType) -> None:
    """The gate's startup modules are the ones the launcher actually loads.

    The launcher spawns ``pythonw.exe -m intellicrack``, so ``__main__`` and the
    module it hands off to are what a core-only install must be able to import.
    Naming a module that does not exist would make the gate fail every build;
    naming one that is never loaded would make it check nothing that matters.

    Args:
        core_runtime_gate: The gate module extracted from ``stage.ps1``.
    """
    startup: tuple[str, ...] = core_runtime_gate.STARTUP_MODULES
    assert isinstance(startup, tuple), "the core-runtime gate declares no STARTUP_MODULES tuple"
    assert startup, "the core-runtime gate checks no startup module"
    assert all(isinstance(module, str) for module in startup), f"STARTUP_MODULES holds a non-string entry: {startup}"

    for module in startup:
        relative = Path(*module.split(".")[1:]).with_suffix(".py")
        assert (_SRC_INTELLICRACK / relative).is_file(), f"the gate imports {module}, but src/intellicrack/{relative.as_posix()} does not exist"


def test_embedded_core_runtime_gate_is_valid_python() -> None:
    """The here-string the stager writes out is parseable Python.

    It is written to disk and run by the staged interpreter, so a syntax error in
    it surfaces only mid-build, after the runtime and the ML split are done.
    """
    source = extract_here_string(read_stage_script(), _CORE_GATE_VARIABLE)
    ast.parse(source, filename="_core_runtime_gate.py")
    assert "def main(" in source, "the emitted gate script has no entry point"
    assert source.startswith("# SPDX-License-Identifier"), "the emitted gate script carries no licence header"


def test_here_string_extraction_is_falsifiable() -> None:
    """The extraction helper finds a real here-string and refuses an absent one.

    Guards every gate above that depends on it: a helper that quietly returned an
    empty string would make them all pass.
    """
    script = "$Other = 'x'\n$Body = @'\nline one\nline two\n'@\n$After = 1\n"
    assert extract_here_string(script, "Body") == "line one\nline two\n"
    assert strip_here_strings(script).splitlines() == ["$Other = 'x'", "$Body = @'", "", "", "", "$After = 1"]

    with pytest.raises(AssertionError, match="no here-string"):
        extract_here_string(script, "Missing")


def test_conda_owned_entries_are_vetoed_before_the_move() -> None:
    """Real gate: the split cannot relocate a package conda installed.

    ``ml_split.py`` reasons over pip metadata alone and returns conda-owned base
    packages (setuptools, jinja2, markupsafe, pygments) as ML-only. Moving those
    carves pieces out of the interpreter's own environment. The veto reads
    ``conda-meta`` for the answer, and a post-move assertion catches one that
    slipped through anyway; dropping either turns this red.
    """
    script = strip_here_strings(read_stage_script())
    assert "function Get-CondaOwnedEntry" in script, "the conda ownership lookup is gone"
    assert re.search(r"\$MlEntries\s*=\s*@\(\$MlEntries\s*\|\s*Where-Object\s*\{\s*-not \$CondaOwners\.ContainsKey\(\$_\)", script) is not None, (
        "conda-owned entries are no longer removed from the ML move list"
    )
    assert re.search(r"foreach \(\$ownedEntry in \$CondaOwners\.Keys\)", script) is not None, (
        "the post-move assertion that no conda-owned entry reached ml_overlay is gone"
    )
    assert "conda-meta" in script, "the veto no longer reads the runtime's own conda-meta records"
