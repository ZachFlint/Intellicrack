# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable verification that ``build/stage`` matches the Inno Setup script.

The Windows installer is assembled in two coupled steps: ``packaging/stage.ps1``
materialises the full payload under the repo-relative ``build/stage`` directory,
and ``packaging/intellicrack.iss`` maps that staged tree into the installed
``{app}`` directory via ``[Files]`` entries rooted at the ``#define StageRoot``
prefix. If either half drifts -- a tool the ``.iss`` copies but the stager never
produced, or a renamed binary the launcher expects -- the installer ships a
broken product.

This module closes that gap with two independent gates over the real on-disk
stage:

* Every ``[Files]`` ``Source:`` token in ``packaging/intellicrack.iss`` is parsed
  (``{#StageRoot}`` substitution, trailing wildcards, quoting and flags handled)
  and asserted to resolve to an existing path under ``build/stage`` -- a
  wildcard ``.../foo/*`` requires ``build/stage/.../foo`` to exist and be
  non-empty.
* An explicit required-binary checklist (the launcher exe, the rebuilt hexcore
  ``.pyd``, the bundled JDK, x64dbg/rizin/radare2/QEMU executables, the vendor
  pattern corpus) is asserted present independently of what the ``.iss`` happens
  to list, so a missing critical binary fails even if the ``.iss`` forgot it.

The real ``build/stage`` tree is ~100+ GB and only exists on a build host, so the
two production gates skip with a clear reason when it is absent (for example
inside the test sandbox, which never stages the installer). Their detection
logic is proven falsifiable by companion tests that build a tiny complete fake
stage in ``tmp_path``, confirm the checkers report it clean, then remove or
duplicate a required entry and confirm the same checkers report the regression.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_BUILD_STAGE: Final[Path] = _REPO_ROOT / "build" / "stage"
_ISS_PATH: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"

# ``Source: "..."`` (quoted) or ``Source: token`` (unquoted), case-insensitive,
# anchored at the start of a line so commented (``; Source:``) lines are skipped.
_SOURCE_RE: Final[re.Pattern[str]] = re.compile(r'(?im)^[ \t]*Source:[ \t]*(?:"([^"]+)"|([^\s;]+))')

# ``#define Name "value"`` (value optional) at the start of a line.
_DEFINE_RE: Final[re.Pattern[str]] = re.compile(r'(?im)^[ \t]*#define[ \t]+(\w+)(?:[ \t]+"([^"]*)")?')

# A ``{#Name}`` preprocessor variable reference embedded in a directive value.
_MACRO_RE: Final[re.Pattern[str]] = re.compile(r"\{#(\w+)\}")

# Upper bound on macro-expansion passes; guards against a self-referential define.
_MAX_MACRO_PASSES: Final[int] = 16

# Files that must exist verbatim under build/stage (forward-slash relative
# paths). Directory and glob requirements are checked separately below.
_REQUIRED_FILES: Final[tuple[str, ...]] = (
    "Intellicrack.exe",
    "runtime/Lib/site-packages/intellicrack_hexcore/intellicrack_hexcore.cp313-win_amd64.pyd",
    "app/src/intellicrack/__init__.py",
    "app/src/intellicrack/assets/icon.ico",
    "app/tools/ghidra/support/analyzeHeadless.bat",
    "app/tools/x64dbg/release/x64/x64dbg.exe",
    "app/tools/x64dbg/release/x32/x32dbg.exe",
    "app/tools/x64dbg/release/x64/plugins/intellicrack_bridge_x64.dp64",
    "app/tools/x64dbg/release/x32/plugins/intellicrack_bridge_x32.dp32",
    "app/tools/cutter/rizin.exe",
    "app/tools/radare2/bin/radare2.exe",
    "app/tools/qemu/qemu-system-x86_64.exe",
    "app/tools/qemu/qemu-img.exe",
)

# The bundled JDK is a single ``jdk-21.<build>`` directory carrying java.exe.
_GHIDRA_DIR_REL: Final[str] = "app/tools/ghidra"
_JDK_GLOB: Final[str] = "jdk-21.*"
_JDK_JAVA_REL: Final[str] = "bin/java.exe"

# The community HexPat/YARA corpus directory that must exist and be non-empty.
_PATTERNS_DIR_REL: Final[str] = "app/vendor/community-patterns/patterns"


def _rel_to_path(root: Path, rel: str) -> Path:
    """Join a forward-slash relative path onto a root path.

    Args:
        root: The base directory the relative path is resolved against.
        rel: A forward-slash separated relative path (possibly empty).

    Returns:
        Path: ``root`` when ``rel`` is empty, otherwise ``root`` joined with each
            segment of ``rel``.
    """
    if not rel:
        return root
    return root.joinpath(*rel.split("/"))


def parse_defines(iss_text: str) -> dict[str, str]:
    """Collect every ``#define Name "value"`` from Inno Setup script text.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        dict[str, str]: Mapping of define name to its quoted value; a valueless
            ``#define Name`` maps to the empty string.
    """
    return {match.group(1): (match.group(2) or "") for match in _DEFINE_RE.finditer(iss_text)}


def _expand_macros(value: str, defines: dict[str, str]) -> str:
    """Iteratively substitute ``{#Name}`` references using the define table.

    Unknown references are left untouched (they surface later as a Source that
    fails to resolve). Substitution repeats so nested defines expand fully.

    Args:
        value: A directive value that may contain ``{#Name}`` references.
        defines: The define table from :func:`parse_defines`.

    Returns:
        str: ``value`` with every resolvable ``{#Name}`` reference expanded.
    """
    current = value
    for _ in range(_MAX_MACRO_PASSES):
        expanded = _MACRO_RE.sub(lambda ref: defines.get(ref.group(1), ref.group(0)), current)
        if expanded == current:
            break
        current = expanded
    return current


def parse_stage_root_define(iss_text: str) -> str:
    """Extract the ``#define StageRoot`` value from Inno Setup script text.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        str: The raw StageRoot value exactly as quoted in the script, which the
            contract fixes to the repo-relative ``build/stage`` prefix.

    Raises:
        AssertionError: If the script declares no ``#define StageRoot``.
    """
    defines = parse_defines(iss_text)
    if "StageRoot" not in defines:
        msg = 'the .iss defines no `#define StageRoot "..."`'
        raise AssertionError(msg)
    return defines["StageRoot"]


def iss_section_lines(iss_text: str, section: str) -> list[str]:
    """Return the meaningful lines inside one ``[Section]`` of an ``.iss`` script.

    Blank lines and comment (``;``) lines are dropped, and only the body of the
    requested section is returned (parsing stops at the next ``[...]`` header), so
    a directive of the same shape in another section cannot leak in.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.
        section: The bare section name to extract, without brackets (for example
            ``"Run"``); matched case-insensitively.

    Returns:
        list[str]: The stripped, non-empty, non-comment lines of that section, in
            document order; empty when the section is absent.
    """
    target = f"[{section.strip().lower()}]"
    in_section = False
    lines: list[str] = []
    for line in iss_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped.lower() == target
            continue
        if not in_section or not stripped or stripped.startswith(";"):
            continue
        lines.append(stripped)
    return lines


def parse_setup_directives(iss_text: str) -> dict[str, str]:
    """Parse the ``Name=value`` directives from the ``[Setup]`` section.

    Only the ``[Setup]`` section is read: an identically named directive under a
    later section (for example a ``[Files]`` line) must not shadow the real
    value. Keys are lower-cased for case-insensitive lookup; values are returned
    verbatim (macro references are left unexpanded).

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        dict[str, str]: The lower-cased directive names mapped to their values.
    """
    directives: dict[str, str] = {}
    in_setup = False
    for line in iss_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_setup = stripped.lower() == "[setup]"
            continue
        if not in_setup or not stripped or stripped.startswith(";"):
            continue
        key, sep, value = stripped.partition("=")
        if sep and key.strip():
            directives[key.strip().lower()] = value.strip()
    return directives


def iss_source_relpaths(iss_text: str) -> list[tuple[str, bool]]:
    """Parse every ``[Files]`` ``Source:`` token into stage-relative paths.

    Each ``Source`` value is macro-expanded against the script's ``#define``
    table (so nested references such as an embedded ``{#AppExeName}`` resolve
    fully) and must be rooted at the StageRoot prefix per the stage-path
    contract. That prefix is stripped so the returned paths are relative to
    ``build/stage`` regardless of where the stage tree actually lives,
    backslashes are normalised to forward slashes, and a trailing ``*`` wildcard
    is recorded as a directory (non-empty) requirement.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        list[tuple[str, bool]]: One ``(relative_path, is_wildcard)`` pair per
            ``Source`` entry, in document order. ``is_wildcard`` is ``True`` when
            the source ended in ``*`` (a whole-directory copy).

    Raises:
        AssertionError: If a ``Source`` value does not resolve under StageRoot.
    """
    defines = parse_defines(iss_text)
    stage_root = parse_stage_root_define(iss_text).replace("\\", "/").rstrip("/")
    sources: list[tuple[str, bool]] = []
    for match in _SOURCE_RE.finditer(iss_text):
        raw = match.group(1) if match.group(1) is not None else match.group(2)
        resolved = _expand_macros(raw, defines).replace("\\", "/")
        prefix = f"{stage_root}/"
        if not resolved.startswith(prefix):
            msg = f"[Files] Source does not resolve under StageRoot ({stage_root!r}): {raw!r} -> {resolved!r}"
            raise AssertionError(msg)
        rest = resolved[len(prefix) :].lstrip("/")
        is_wildcard = rest.endswith("*")
        if is_wildcard:
            rest = rest.rstrip("*").rstrip("/")
        sources.append((rest, is_wildcard))
    return sources


def missing_iss_sources(stage_root: Path, sources: list[tuple[str, bool]]) -> list[str]:
    """Return the parsed ``Source`` entries that are absent under ``stage_root``.

    Args:
        stage_root: The staged tree that mirrors the installed ``{app}`` layout.
        sources: ``(relative_path, is_wildcard)`` pairs from
            :func:`iss_source_relpaths`.

    Returns:
        list[str]: Human-readable descriptions of every source that does not
            resolve to an existing path (a wildcard entry that resolves to a
            missing or empty directory is included), empty when all resolve.
    """
    missing: list[str] = []
    for rel, is_wildcard in sources:
        target = _rel_to_path(stage_root, rel)
        if is_wildcard:
            if not (target.is_dir() and any(target.iterdir())):
                missing.append(f"{rel or '.'}/* (expected a non-empty directory)")
        elif not target.exists():
            missing.append(rel or ".")
    return missing


def missing_required_binaries(stage_root: Path) -> list[str]:
    """Return the required-binary checklist entries absent under ``stage_root``.

    Independently of the ``.iss``, this asserts the contract's critical payload:
    the launcher exe, the rebuilt hexcore ``.pyd``, the source and icon, the
    Ghidra headless launcher and its single bundled ``jdk-21.*`` JDK,
    x64dbg/rizin/radare2/QEMU executables, and the non-empty community pattern
    corpus.

    Args:
        stage_root: The staged tree that mirrors the installed ``{app}`` layout.

    Returns:
        list[str]: Human-readable descriptions of every required entry that is
            missing, empty when the stage satisfies the full checklist.
    """
    missing: list[str] = [rel for rel in _REQUIRED_FILES if not _rel_to_path(stage_root, rel).is_file()]

    ghidra_dir = _rel_to_path(stage_root, _GHIDRA_DIR_REL)
    jdk_dirs = sorted(candidate for candidate in ghidra_dir.glob(_JDK_GLOB) if candidate.is_dir())
    if len(jdk_dirs) != 1:
        missing.append(f"{_GHIDRA_DIR_REL}/{_JDK_GLOB} (expected exactly one directory, found {len(jdk_dirs)})")
    elif not _rel_to_path(jdk_dirs[0], _JDK_JAVA_REL).is_file():
        missing.append(f"{_GHIDRA_DIR_REL}/{jdk_dirs[0].name}/{_JDK_JAVA_REL}")

    patterns_dir = _rel_to_path(stage_root, _PATTERNS_DIR_REL)
    if not (patterns_dir.is_dir() and any(patterns_dir.iterdir())):
        missing.append(f"{_PATTERNS_DIR_REL}/ (expected a non-empty directory)")

    return missing


def test_every_iss_source_exists_in_stage() -> None:
    """Real gate: every ``[Files]`` Source in the ``.iss`` exists in ``build/stage``.

    Skips when the staging tree has not been built (for example inside the test
    sandbox, which never assembles the ~100+ GB installer payload). When the
    tree is present this is a hard gate on installer/stager agreement.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    iss_text = _ISS_PATH.read_text(encoding="utf-8-sig")

    stage_root_value = parse_stage_root_define(iss_text)
    resolved_root = (_ISS_PATH.parent / stage_root_value.replace("\\", "/")).resolve()
    assert resolved_root == _BUILD_STAGE.resolve(), (
        f"#define StageRoot resolves to {resolved_root}, not the expected {_BUILD_STAGE.resolve()}"
    )

    sources = iss_source_relpaths(iss_text)
    assert sources, "the .iss declared no [Files] Source entries to verify"

    missing = missing_iss_sources(_BUILD_STAGE, sources)
    assert not missing, "staged tree is missing .iss Source paths:\n  " + "\n  ".join(missing)


def test_required_binaries_present_in_stage() -> None:
    """Real gate: the required-binary checklist is present in ``build/stage``.

    Skips when the staging tree is absent; otherwise fails loudly listing every
    missing critical binary, directory, or JDK.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    missing = missing_required_binaries(_BUILD_STAGE)
    assert not missing, "staged tree is missing required binaries:\n  " + "\n  ".join(missing)


# --- Falsifiability proofs (run everywhere, including the sandbox) -----------

_FAKE_ISS: Final[str] = (
    '#define MyAppName "Intellicrack"\n'
    '#define AppExeName "Intellicrack.exe"\n'
    '#define StageRoot "..\\build\\stage"\n'
    "\n"
    "[Setup]\n"
    "AppName={#MyAppName}\n"
    "\n"
    "[Files]\n"
    '; Source: "{#StageRoot}\\this-is-a-comment.exe"; DestDir: "{app}"\n'
    'Source: "{#StageRoot}\\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion\n'
    'Source: "{#StageRoot}\\runtime\\*"; DestDir: "{app}\\runtime"; Flags: recursesubdirs createallsubdirs\n'
    'Source: "{#StageRoot}\\app\\src\\*"; DestDir: "{app}\\app\\src"; Flags: recursesubdirs\n'
)


def _write_stub_file(path: Path) -> None:
    """Create a small placeholder file, making parent directories as needed.

    Args:
        path: The file to create; its parents are created if absent.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"stub")


def _build_complete_fake_stage(root: Path) -> None:
    """Materialise a minimal stage that satisfies the full required checklist.

    Every checklist entry is created as an empty-ish placeholder: the plain
    files, exactly one ``jdk-21.*`` directory carrying ``bin/java.exe``, and a
    non-empty community-patterns directory.

    Args:
        root: The directory to populate as a fake ``build/stage`` tree.
    """
    for rel in _REQUIRED_FILES:
        _write_stub_file(_rel_to_path(root, rel))
    _write_stub_file(_rel_to_path(root, f"{_GHIDRA_DIR_REL}/jdk-21.0.5+11/{_JDK_JAVA_REL}"))
    _write_stub_file(_rel_to_path(root, f"{_PATTERNS_DIR_REL}/pe.hexpat"))


def test_iss_source_parsing_extracts_stage_relative_paths() -> None:
    """The ``.iss`` parser expands macros to stage-relative paths and flags wildcards.

    Proves the parser drops commented ``Source`` lines, expands nested defines
    (the ``{#AppExeName}`` reference resolves to ``Intellicrack.exe``), strips the
    StageRoot prefix, and flags trailing-``*`` copies as directory requirements --
    the transform the real gate depends on.
    """
    parsed = iss_source_relpaths(_FAKE_ISS)
    assert set(parsed) == {
        ("Intellicrack.exe", False),
        ("runtime", True),
        ("app/src", True),
    }
    assert parse_stage_root_define(_FAKE_ISS) == "..\\build\\stage"


def test_iss_source_checker_is_falsifiable(tmp_path: Path) -> None:
    """The ``.iss`` source checker passes on a complete stage and fails on a gap.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    sources = iss_source_relpaths(_FAKE_ISS)
    stage = tmp_path / "stage"
    _write_stub_file(stage / "Intellicrack.exe")
    _write_stub_file(stage / "runtime" / "python.exe")
    _write_stub_file(stage / "app" / "src" / "intellicrack" / "__init__.py")

    assert missing_iss_sources(stage, sources) == []

    (stage / "Intellicrack.exe").unlink()
    missing = missing_iss_sources(stage, sources)
    assert missing != []
    assert any("Intellicrack.exe" in entry for entry in missing)


def test_iss_wildcard_requires_a_nonempty_directory(tmp_path: Path) -> None:
    """A wildcard ``Source`` fails when its staged directory is empty.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    sources = iss_source_relpaths(_FAKE_ISS)
    stage = tmp_path / "stage"
    _write_stub_file(stage / "Intellicrack.exe")
    (stage / "runtime").mkdir(parents=True)
    _write_stub_file(stage / "app" / "src" / "intellicrack" / "__init__.py")

    missing = missing_iss_sources(stage, sources)
    assert any(entry.startswith("runtime/*") for entry in missing)


def test_required_binary_checker_is_falsifiable(tmp_path: Path) -> None:
    """The required-binary checker passes on a complete stage and fails on removal.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    _build_complete_fake_stage(stage)

    assert missing_required_binaries(stage) == []

    removed = _rel_to_path(stage, "app/tools/x64dbg/release/x64/x64dbg.exe")
    removed.unlink()
    missing = missing_required_binaries(stage)
    assert missing != []
    assert any("x64dbg.exe" in entry for entry in missing)


def test_required_binary_checker_flags_empty_pattern_corpus(tmp_path: Path) -> None:
    """Emptying the community-patterns directory is detected as a regression.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    _build_complete_fake_stage(stage)
    assert missing_required_binaries(stage) == []

    _rel_to_path(stage, f"{_PATTERNS_DIR_REL}/pe.hexpat").unlink()
    missing = missing_required_binaries(stage)
    assert any(entry.startswith(_PATTERNS_DIR_REL) for entry in missing)


def test_jdk_glob_requires_exactly_one_directory(tmp_path: Path) -> None:
    """The checklist rejects a stage with more than one ``jdk-21.*`` directory.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    _build_complete_fake_stage(stage)
    assert missing_required_binaries(stage) == []

    _write_stub_file(_rel_to_path(stage, f"{_GHIDRA_DIR_REL}/jdk-21.0.6+7/{_JDK_JAVA_REL}"))
    missing = missing_required_binaries(stage)
    assert any("jdk-21" in entry for entry in missing)


# --- [Setup] configuration invariants (read the real .iss directly) ----------

# The wizard image directives whose PNG targets must physically exist next to
# the .iss, keyed by the [Setup] directive that names them.
_WIZARD_IMAGE_DIRECTIVES: Final[tuple[str, ...]] = (
    "wizardimagefile",
    "wizardimagefiledynamicdark",
    "wizardsmallimagefile",
)


def _read_real_iss() -> str:
    """Read the production ``.iss`` script, failing loudly if it is absent.

    Returns:
        str: The full UTF-8 text of ``packaging/intellicrack.iss`` (a leading
            BOM, if present, is stripped).
    """
    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    return _ISS_PATH.read_text(encoding="utf-8-sig")


def test_installer_theme_arch_and_license_directives_are_set() -> None:
    """Real gate: the ``.iss`` pins the theme, native-x64, license and close config.

    These are the user-selected installer invariants that carry no staged
    artifact to catch them: the dynamic dark/light wizard style, native-x64-only
    architecture gating, the GPL license page, and Restart-Manager auto-close.
    Reverting any of them in the real script turns this red.
    """
    directives = parse_setup_directives(_read_real_iss())

    wizard_style = directives.get("wizardstyle", "").lower()
    assert "modern" in wizard_style, f"WizardStyle must be modern, got {directives.get('wizardstyle')!r}"
    assert "dynamic" in wizard_style, (
        f"WizardStyle must include 'dynamic' for system dark/light theming, got {directives.get('wizardstyle')!r}"
    )

    assert directives.get("architecturesallowed") == "x64os", (
        f"ArchitecturesAllowed must be native-x64-only (x64os), got {directives.get('architecturesallowed')!r}"
    )
    assert directives.get("architecturesinstallin64bitmode") == "x64os", (
        f"ArchitecturesInstallIn64BitMode must be x64os, got {directives.get('architecturesinstallin64bitmode')!r}"
    )

    assert directives.get("licensefile", ""), "LicenseFile must be set for the GPL-3.0 license page"
    assert directives.get("closeapplications", "").lower() == "yes", (
        f"CloseApplications must be yes for Restart-Manager auto-close, got {directives.get('closeapplications')!r}"
    )


def test_installer_declares_no_persistent_environment_change() -> None:
    """Real gate: the installer performs no persistent environment modification.

    The hard isolation requirement is that nothing installed under the install
    dir leaks onto the machine/user environment. The ``.iss`` must therefore
    neither set ``ChangesEnvironment=yes`` nor write to a machine or per-user
    ``Environment`` registry key.
    """
    iss_text = _read_real_iss()
    directives = parse_setup_directives(iss_text)

    assert directives.get("changesenvironment", "no").lower() != "yes", (
        "ChangesEnvironment must not be yes: the installer makes no persistent PATH/env changes"
    )
    assert "\\Environment" not in iss_text, "the .iss must not write a ...\\Environment registry key (no persistent PATH/JAVA_HOME)"


def test_installer_wizard_images_exist_next_to_iss() -> None:
    """Real gate: every wizard image the ``.iss`` names is present on disk.

    The three wizard PNG directives reference files by a packaging-relative
    path; each must resolve to a real file so the compile does not fail and the
    installer ships its banners.
    """
    directives = parse_setup_directives(_read_real_iss())
    base = _ISS_PATH.parent
    for directive in _WIZARD_IMAGE_DIRECTIVES:
        rel = directives.get(directive, "")
        assert rel, f"{directive} must be set"
        image = _rel_to_path(base, rel.replace("\\", "/"))
        assert image.is_file(), f"{directive} references a missing image: {image}"


def test_setup_directive_parser_is_section_scoped() -> None:
    """A directive outside ``[Setup]`` must not shadow the real ``[Setup]`` value.

    Proves :func:`parse_setup_directives` reads only the ``[Setup]`` section: a
    later ``[Files]`` line reusing a directive name is ignored, and a commented
    line inside ``[Setup]`` is skipped. Falsifiable -- a section-blind parser
    would capture the ``[Files]`` override.
    """
    sample = (
        "[Setup]\n"
        "WizardStyle=modern dynamic\n"
        "ArchitecturesAllowed=x64os\n"
        "; CloseApplications=no\n"
        "CloseApplications=yes\n"
        "\n"
        "[Files]\n"
        "WizardStyle=classic\n"
        'Source: "x"; DestDir: "{app}"\n'
    )
    directives = parse_setup_directives(sample)
    assert directives["wizardstyle"] == "modern dynamic"
    assert directives["architecturesallowed"] == "x64os"
    assert directives["closeapplications"] == "yes"


# --- Upgrade/uninstall lifecycle invariants (new installer features) ----------

# The AppMutex the .iss declares must equal the name the running application
# creates in intellicrack.core.single_instance; asserted verbatim here and
# cross-checked against the source constant in tests/core/test_single_instance.py.
_EXPECTED_APP_MUTEX: Final[str] = "Global\\IntellicrackSingleInstance"


def test_installer_declares_appmutex_and_setup_logging() -> None:
    """Real gate: the ``.iss`` sets the AppMutex and enables setup logging.

    ``AppMutex`` is what lets Setup detect a running Intellicrack (the app holds
    the identically named mutex) so it can close it via the Restart Manager
    before an in-place upgrade or uninstall instead of failing on in-use files;
    it must equal the name the application creates. ``SetupLogging=yes`` makes
    Setup write a diagnostic log. Reverting either turns this red.
    """
    directives = parse_setup_directives(_read_real_iss())

    assert directives.get("appmutex") == _EXPECTED_APP_MUTEX, (
        f"AppMutex must equal {_EXPECTED_APP_MUTEX!r} (the name the app creates), got {directives.get('appmutex')!r}"
    )
    assert directives.get("setuplogging", "").lower() == "yes", (
        f"SetupLogging must be yes for an installer diagnostic log, got {directives.get('setuplogging')!r}"
    )


def test_run_section_offers_launch_and_defers_dism_to_code() -> None:
    """Real gate: ``[Run]`` launches the app on finish and runs no inline DISM.

    The finished page must offer to launch Intellicrack (a ``postinstall``
    ``[Run]`` entry for the launcher exe). The Hypervisor-Platform enable moved
    out of ``[Run]`` into ``[Code]`` so its DISM 3010 reboot signal can drive
    ``NeedRestart``; a leftover ``dism`` line in ``[Run]`` would bypass that, so
    its absence here is part of the gate.
    """
    run_lines = iss_section_lines(_read_real_iss(), "Run")
    assert run_lines, "the [Run] section is empty"

    launch = [line for line in run_lines if "{#AppExeName}" in line or "Intellicrack.exe" in line]
    assert launch, "[Run] has no entry that launches the Intellicrack launcher on finish"
    assert any("postinstall" in line.lower() for line in launch), "the launch-on-finish [Run] entry must carry the postinstall flag"

    assert not any("dism" in line.lower() for line in run_lines), (
        "DISM must not run from [Run]; it moved to [Code] ssPostInstall for 3010 reboot detection"
    )


def test_uninstall_delete_purges_config_and_install_dir() -> None:
    """Real gate: ``[UninstallDelete]`` removes runtime config and the install dir.

    Uninstall must clear the runtime-generated ``.intellicrack`` config tree
    under ``{app}`` and finally sweep the whole ``{app}`` directory so no
    orphaned runtime leftovers (logs, ``__pycache__``) remain. Both entries are
    required.
    """
    ud_lines = iss_section_lines(_read_real_iss(), "UninstallDelete")
    assert ud_lines, "the [UninstallDelete] section is empty"

    assert any(".intellicrack" in line for line in ud_lines), "[UninstallDelete] must remove the {app}\\.intellicrack runtime config tree"
    assert any(re.search(r'Name:\s*"\{app\}"', line) for line in ud_lines), (
        "[UninstallDelete] must sweep the whole {app} directory as its final entry"
    )


def test_tasks_declare_hyperv_and_defender_optins() -> None:
    """Real gate: the two opt-in system tasks exist with the right defaults.

    ``enablehyperv`` gates the DISM Hypervisor-Platform enable (only meaningful
    with the QEMU component) and ``defenderexclusion`` gates the Defender folder
    exclusion. The Defender task must default unchecked - it is a security-
    relevant change the user opts into deliberately.
    """
    task_lines = iss_section_lines(_read_real_iss(), "Tasks")
    assert task_lines, "the [Tasks] section is empty"

    hyperv = [line for line in task_lines if 'Name: "enablehyperv"' in line]
    defender = [line for line in task_lines if 'Name: "defenderexclusion"' in line]

    assert hyperv, "[Tasks] must declare the enablehyperv opt-in"
    assert any("components: qemu" in line.lower() for line in hyperv), "the enablehyperv task must be gated on the qemu component"
    assert defender, "[Tasks] must declare the defenderexclusion opt-in"
    assert any("unchecked" in line.lower() for line in defender), "the defenderexclusion task must default unchecked"


def test_code_wires_reboot_detection_and_uninstall_cleanup() -> None:
    """Real gate: ``[Code]`` implements the 3010 reboot and uninstall handlers.

    The post-install step must detect DISM's 3010 (reboot-required) exit and
    surface it through ``NeedRestart``, and the uninstall step must run the
    Defender-exclusion removal and tool-cache purge. This asserts the wiring is
    present in the real script, not just the directives that trigger it.
    """
    code_lines = iss_section_lines(_read_real_iss(), "Code")
    body = "\n".join(code_lines)

    assert "3010" in body, "the reboot-required DISM exit code (3010) is not referenced in [Code]"
    assert "function NeedRestart" in body, "[Code] must implement NeedRestart to request the reboot"
    assert "HyperVRestartNeeded" in body, "NeedRestart must be driven by the DISM 3010 result flag"
    assert "procedure CurStepChanged" in body, "[Code] must implement CurStepChanged for the post-install actions"
    assert "procedure CurUninstallStepChanged" in body, "[Code] must implement CurUninstallStepChanged for cleanup"
    assert body.count("SetDefenderExclusion") >= 2, "SetDefenderExclusion must be invoked for both add (install) and remove (uninstall)"


# --- Section-parser falsifiability proofs (run everywhere) -------------------

_FAKE_SECTIONS_ISS: Final[str] = (
    "[Setup]\n"
    "AppName=Intellicrack\n"
    "\n"
    "[Run]\n"
    '; Filename: "{sys}\\dism.exe"; Parameters: "/online"\n'
    'Filename: "{app}\\Intellicrack.exe"; Flags: nowait postinstall skipifsilent\n'
    "\n"
    "[Tasks]\n"
    'Name: "enablehyperv"; Description: "x"; Components: qemu\n'
    'Name: "defenderexclusion"; Description: "y"; Flags: unchecked\n'
)


def test_iss_section_lines_is_scoped_and_skips_comments() -> None:
    """The section extractor returns only a section's real lines.

    Proves ``iss_section_lines`` stops at the next header (the ``[Run]`` body
    never leaks a ``[Tasks]`` line), drops comment lines (the commented DISM line
    is excluded), and matches case-insensitively. A section-blind or
    comment-blind parser would fail these assertions.
    """
    run = iss_section_lines(_FAKE_SECTIONS_ISS, "Run")
    assert run == ['Filename: "{app}\\Intellicrack.exe"; Flags: nowait postinstall skipifsilent']
    assert not any("dism" in line.lower() for line in run), "commented DISM line must be skipped"

    tasks = iss_section_lines(_FAKE_SECTIONS_ISS, "TASKS")
    assert len(tasks) == 2
    assert any('Name: "enablehyperv"' in line for line in tasks)

    assert iss_section_lines(_FAKE_SECTIONS_ISS, "UninstallDelete") == []
