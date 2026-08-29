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
import shutil
import subprocess
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
    "Hexbench.exe",
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


def unpackaged_staged_files(stage_root: Path, sources: list[tuple[str, bool]]) -> list[str]:
    r"""Return staged files that no ``[Files]`` ``Source`` entry would package.

    This is the reverse of :func:`missing_iss_sources`: rather than asking whether
    every ``.iss`` source exists in the stage, it asks whether every file the
    stager produced is actually copied by the installer. A staged file matched by
    no literal source and under no wildcard directory is dropped silently at
    compile time -- wasted payload at best, a forgotten ``[Files]`` directory (so
    a whole tool ships broken) at worst.

    Args:
        stage_root: The staged tree that mirrors the installed ``{app}`` layout.
        sources: ``(relative_path, is_wildcard)`` pairs from
            :func:`iss_source_relpaths`. A non-wildcard entry covers exactly its
            path; a wildcard entry covers every file beneath its directory (an
            empty directory, from a bare ``StageRoot\\*``, covers the whole tree).

    Returns:
        list[str]: Forward-slash stage-relative paths of every file covered by no
            source, sorted, empty when the installer packages the entire stage.
    """
    literals = {rel for rel, is_wildcard in sources if not is_wildcard}
    wildcard_dirs = [rel for rel, is_wildcard in sources if is_wildcard]
    orphans: list[str] = []
    for path in stage_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(stage_root).as_posix()
        if rel in literals:
            continue
        if any(not directory or rel == directory or rel.startswith(f"{directory}/") for directory in wildcard_dirs):
            continue
        orphans.append(rel)
    return sorted(orphans)


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


def test_every_staged_file_is_packaged_by_the_iss() -> None:
    """Real gate: every file in ``build/stage`` is packaged by some ``.iss`` Source.

    The complement of :func:`test_every_iss_source_exists_in_stage`: it catches a
    file the stager produced that the ``.iss`` never copies. Skips when the
    staging tree is absent; otherwise fails loudly listing every orphaned staged
    file so a forgotten ``[Files]`` entry cannot ship a silently truncated payload.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    iss_text = _ISS_PATH.read_text(encoding="utf-8-sig")

    sources = iss_source_relpaths(iss_text)
    assert sources, "the .iss declared no [Files] Source entries to verify"

    orphans = unpackaged_staged_files(_BUILD_STAGE, sources)
    assert not orphans, "staged files packaged by no .iss [Files] Source:\n  " + "\n  ".join(orphans)


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


def test_staged_file_coverage_checker_is_falsifiable(tmp_path: Path) -> None:
    """The reverse-coverage checker passes on a packaged stage and flags an orphan.

    A stage whose every file falls under a literal or wildcard ``Source`` reports
    clean; planting a file no ``Source`` covers must be reported by name. Deleting
    the ``rel.startswith`` wildcard test in :func:`unpackaged_staged_files` (so it
    only honours literal sources) reddens the orphan assertion.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    sources = iss_source_relpaths(_FAKE_ISS)
    stage = tmp_path / "stage"
    _write_stub_file(stage / "Intellicrack.exe")
    _write_stub_file(stage / "runtime" / "python.exe")
    _write_stub_file(stage / "runtime" / "Lib" / "os.py")
    _write_stub_file(stage / "app" / "src" / "intellicrack" / "__init__.py")

    assert unpackaged_staged_files(stage, sources) == [], "coverage checker flagged a fully packaged stage"

    _write_stub_file(stage / "app" / "tools" / "stray.exe")
    assert unpackaged_staged_files(stage, sources) == ["app/tools/stray.exe"], (
        "the coverage checker failed to flag a staged file that no .iss Source packages"
    )


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


# --- [Setup] hardening + upgrade/UX invariants (read the real .iss) -----------


def test_setup_shows_welcome_and_disables_solid_compression() -> None:
    """Real gate: the welcome page is shown and solid compression is off.

    ``DisableWelcomePage=no`` makes the wizard banner visible up front instead of
    only on the finished page. ``SolidCompression=no`` keeps a Compact/custom
    install from decompressing the whole multi-GB archive just to skip the
    optional components the user did not select. Reverting either turns this red.
    """
    directives = parse_setup_directives(_read_real_iss())

    assert directives.get("disablewelcomepage", "").lower() == "no", (
        f"DisableWelcomePage must be no so the wizard banner is seen up front, got {directives.get('disablewelcomepage')!r}"
    )
    assert directives.get("solidcompression", "").lower() == "no", (
        f"SolidCompression must be no for a component-selectable install, got {directives.get('solidcompression')!r}"
    )


def test_setup_version_comes_from_generated_include() -> None:
    """Real gate: the ``.iss`` single-sources its version via the generated include.

    The two hand-typed ``#define AppVersion``/``#define AppVerNumeric`` lines were
    replaced by ``#include "version.generated.iss"`` (regenerated by stage.ps1 from
    ``_metadata.py``). Re-introducing a literal define here would let the installer
    version drift from the package, so their absence plus the include is the gate.
    """
    iss_text = _read_real_iss()

    assert '#include "version.generated.iss"' in iss_text, "the .iss must #include version.generated.iss instead of hand-typing the version"
    defines = parse_defines(iss_text)
    for name in ("AppVersion", "AppVerNumeric"):
        assert name not in defines, f"{name} must come from version.generated.iss, not a literal #define in intellicrack.iss"


def test_install_delete_clears_managed_trees_before_copy() -> None:
    """Real gate: ``[InstallDelete]`` purges the install-managed trees.

    An upgrade must clear the runtime, source, tool, vendor, hexbench, and guest
    trees before the new files are copied so no stale module shadows a new one on
    ``PYTHONPATH`` and a deselected component (notably the ML overlay merged into
    the runtime site-packages) is actually removed. Every managed subtree is
    required; nothing user-writable (now under ``%LOCALAPPDATA%``) may appear.
    """
    id_lines = iss_section_lines(_read_real_iss(), "InstallDelete")
    assert id_lines, "the [InstallDelete] section is empty"

    body = "\n".join(id_lines)
    for managed in (r"{app}\runtime", r"{app}\app\src", r"{app}\app\tools", r"{app}\app\vendor", r"{app}\hexbench"):
        assert managed in body, f"[InstallDelete] must clear {managed} before copying new files"

    assert "localappdata" not in body.lower(), "[InstallDelete] must never touch user-writable state (it lives under %LOCALAPPDATA%)"


def test_enablehyperv_task_defaults_unchecked() -> None:
    """Real gate: the machine-wide Hypervisor-Platform task starts unchecked.

    ``enablehyperv`` runs DISM to turn on a machine-wide hypervisor feature, so it
    must never be silently pre-selected; the user opts into it deliberately. This
    complements :func:`test_tasks_declare_hyperv_and_defender_optins`, which pins
    the same default for the Defender task.
    """
    task_lines = iss_section_lines(_read_real_iss(), "Tasks")
    hyperv = [line for line in task_lines if 'Name: "enablehyperv"' in line]
    assert hyperv, "[Tasks] must declare the enablehyperv opt-in"
    assert all("unchecked" in line.lower() for line in hyperv), (
        "the enablehyperv task must default unchecked: it makes a machine-wide hypervisor change"
    )


def test_defender_exclusion_runs_before_payload_extraction() -> None:
    """Real gate: the Defender exclusion is added at ``ssInstall``, not post-install.

    The bundled activation/injection utilities can trip antivirus heuristics, so
    the folder must be excluded *before* ``[Files]`` extracts them. The add path
    (``SetDefenderExclusion('Add')``) must sit in the ``ssInstall`` branch of
    ``CurStepChanged``; leaving it at ``ssPostInstall`` (the original bug) lets the
    payload land unprotected and turns this red.
    """
    code_lines = iss_section_lines(_read_real_iss(), "Code")
    body = "\n".join(code_lines)

    install_marker = "CurStep = ssInstall"
    postinstall_marker = "CurStep = ssPostInstall"
    add_call = "SetDefenderExclusion('Add')"

    assert install_marker in body, "CurStepChanged must branch on ssInstall"
    assert postinstall_marker in body, "CurStepChanged must branch on ssPostInstall"
    assert add_call in body, "the Defender exclusion add call must be present in [Code]"

    install_at = body.index(install_marker)
    postinstall_at = body.index(postinstall_marker)
    add_at = body.index(add_call)
    assert install_at < add_at < postinstall_at, (
        "SetDefenderExclusion('Add') must run inside the ssInstall branch (before payload extraction), not in the ssPostInstall branch"
    )


def test_defender_exclusion_escapes_the_install_path() -> None:
    r"""Real gate: the Defender exclusion escapes single quotes in the install path.

    The exclusion path is embedded inside a PowerShell single-quoted literal, so a
    custom install directory containing an apostrophe (for example
    ``C:\Users\O'Brien\App``) would break out of the literal unless the quote is
    doubled first. ``SetDefenderExclusion`` must run the expanded ``{app}`` through
    ``StringChangeEx`` before building the command; reverting to embedding
    ``ExpandConstant('{app}')`` raw in the ``-ExclusionPath`` argument drops that
    call and turns this red.
    """
    body = "\n".join(iss_section_lines(_read_real_iss(), "Code"))
    assert "StringChangeEx" in body, (
        "SetDefenderExclusion must escape single quotes in the install path with StringChangeEx "
        "before embedding it in the PowerShell -ExclusionPath literal"
    )


# --- [Icons] -> [Files] destination cross-check ------------------------------

# An icon target that Inno itself generates (not staged by a [Files] entry).
_GENERATED_ICON_TARGETS: Final[frozenset[str]] = frozenset({"{uninstallexe}"})

_FILES_SOURCE_RE: Final[re.Pattern[str]] = re.compile(r'(?i)Source:\s*"([^"]+)"')
_FILES_DESTDIR_RE: Final[re.Pattern[str]] = re.compile(r'(?i)DestDir:\s*"([^"]+)"')
_ICONS_FILENAME_RE: Final[re.Pattern[str]] = re.compile(r'(?i)Filename:\s*"([^"]+)"')


def _normalise_install_path(value: str) -> str:
    r"""Normalise an installed-path token for comparison.

    Backslashes are unified and any trailing separator dropped so ``{app}\x`` and
    ``{app}/x/`` compare equal.

    Args:
        value: An install-relative path that may mix separators.

    Returns:
        str: The path with forward slashes and no trailing separator.
    """
    return value.replace("\\", "/").rstrip("/")


def installed_file_destinations(iss_text: str) -> tuple[set[str], set[str]]:
    """Compute the exact and directory install destinations from ``[Files]``.

    Each ``[Files]`` entry is macro-expanded and split by whether its ``Source``
    ends in a ``*`` wildcard. A non-wildcard entry installs exactly one file at
    ``DestDir`` + the source's basename. A wildcard entry populates the whole
    ``DestDir`` subtree, so its directory is recorded for prefix matching.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        tuple[set[str], set[str]]: ``(exact_files, wildcard_dirs)`` -- the set of
            exact installed file paths and the set of directories a wildcard copy
            fills, both normalised with forward slashes and no trailing separator.
    """
    defines = parse_defines(iss_text)
    exact_files: set[str] = set()
    wildcard_dirs: set[str] = set()
    for line in iss_section_lines(iss_text, "Files"):
        source_match = _FILES_SOURCE_RE.search(line)
        dest_match = _FILES_DESTDIR_RE.search(line)
        if source_match is None or dest_match is None:
            continue
        source = _expand_macros(source_match.group(1), defines).replace("\\", "/")
        dest_dir = _normalise_install_path(_expand_macros(dest_match.group(1), defines))
        if source.endswith("*"):
            wildcard_dirs.add(dest_dir)
        else:
            basename = source.rstrip("/").rsplit("/", 1)[-1]
            exact_files.add(f"{dest_dir}/{basename}")
    return exact_files, wildcard_dirs


def unresolved_icon_targets(iss_text: str) -> list[str]:
    """Return ``[Icons]`` targets that no ``[Files]`` entry actually installs.

    Every ``[Icons]`` ``Filename`` under ``{app}`` must resolve to a file some
    ``[Files]`` entry stages -- either an exact non-wildcard destination or a file
    beneath a wildcard-populated directory. Inno-generated targets (the
    uninstaller) are exempt. This is the gate that catches a shortcut pointing at
    a path the stager never produces (the original dead Hexbench shortcut).

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        list[str]: The normalised icon targets that resolve to no installed file,
            empty when every shortcut points at a staged path.
    """
    defines = parse_defines(iss_text)
    exact_files, wildcard_dirs = installed_file_destinations(iss_text)
    unresolved: list[str] = []
    for line in iss_section_lines(iss_text, "Icons"):
        filename_match = _ICONS_FILENAME_RE.search(line)
        if filename_match is None:
            continue
        raw = _expand_macros(filename_match.group(1), defines)
        if raw in _GENERATED_ICON_TARGETS:
            continue
        target = _normalise_install_path(raw)
        if target in exact_files:
            continue
        if any(target == wd or target.startswith(f"{wd}/") for wd in wildcard_dirs):
            continue
        unresolved.append(target)
    return unresolved


def test_every_icon_points_at_a_staged_file() -> None:
    r"""Real gate: every ``[Icons]`` shortcut resolves to a ``[Files]`` destination.

    Falsifiable against the exact regression that shipped a dead Hexbench
    shortcut: had ``{app}\hexbench\hexbench.exe`` been named while the exe is
    staged as ``{app}\Hexbench.exe``, it would appear here as unresolved.
    """
    unresolved = unresolved_icon_targets(_read_real_iss())
    assert unresolved == [], "[Icons] shortcuts point at paths no [Files] entry installs:\n  " + "\n  ".join(unresolved)


def test_icon_files_cross_check_is_falsifiable() -> None:
    """The icon/files cross-check accepts staged targets and rejects a bad one.

    Proves :func:`unresolved_icon_targets` resolves an exact exe destination and a
    wildcard-tree target, exempts ``{uninstallexe}``, and flags a shortcut whose
    path no ``[Files]`` entry produces -- the dead-shortcut failure mode.
    """
    good = (
        '#define AppExeName "Intellicrack.exe"\n'
        '#define HexbenchExeName "Hexbench.exe"\n'
        '#define StageRoot "..\\build\\stage"\n'
        "[Files]\n"
        'Source: "{#StageRoot}\\{#AppExeName}"; DestDir: "{app}"\n'
        'Source: "{#StageRoot}\\{#HexbenchExeName}"; DestDir: "{app}"\n'
        'Source: "{#StageRoot}\\app\\tools\\ghidra\\*"; DestDir: "{app}\\app\\tools\\ghidra"\n'
        "[Icons]\n"
        'Name: "{group}\\Intellicrack"; Filename: "{app}\\{#AppExeName}"\n'
        'Name: "{group}\\Hexbench"; Filename: "{app}\\{#HexbenchExeName}"\n'
        'Name: "{group}\\Ghidra"; Filename: "{app}\\app\\tools\\ghidra\\ghidraRun.bat"\n'
        'Name: "{group}\\Uninstall"; Filename: "{uninstallexe}"\n'
    )
    assert unresolved_icon_targets(good) == []

    bad = (
        '#define HexbenchExeName "Hexbench.exe"\n'
        '#define StageRoot "..\\build\\stage"\n'
        "[Files]\n"
        'Source: "{#StageRoot}\\{#HexbenchExeName}"; DestDir: "{app}"\n'
        "[Icons]\n"
        'Name: "{group}\\Hexbench"; Filename: "{app}\\hexbench\\hexbench.exe"\n'
    )
    unresolved = unresolved_icon_targets(bad)
    assert unresolved == ["{app}/hexbench/hexbench.exe"]


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


# --- Staged-runtime build-path hygiene ---------------------------------------

# The build interpreter path substring that pip/distlib console-script shims and
# the editable dist-info embed. It is drive/checkout- and env-independent (the
# installer stages from the ``runtime`` env, dev builds from ``default``), so
# matching ``.pixi\envs\`` generically flags a leaked build path regardless of
# which pixi environment the runtime was staged from or where it was built.
_BUILD_PATH_MARKER: Final[str] = r".pixi\envs" + "\\"

_SCRIPTS_REL: Final[str] = "runtime/Scripts"
_SITE_PACKAGES_REL: Final[str] = "runtime/Lib/site-packages"


def scripts_shims_embedding_build_path(stage_root: Path) -> list[str]:
    r"""Return staged ``runtime\Scripts`` exes that embed the build interpreter path.

    These pip/distlib console-script launchers hardcode the absolute build
    interpreter (``...\.pixi\envs\runtime\python.exe`` for the staged runtime,
    ``...\.pixi\envs\default\python.exe`` for a dev build); on a target that
    path is absent and, if user-writable, a code-execution surface. ``stage.ps1``
    strips every such shim, so any survivor is a staging regression.

    Every file is checked, not just ``*.exe``: pip also installs entry points as
    plain scripts (``bottle.py``, ``dul-receive-pack``) whose shebang carries the
    same absolute path, and those leak the build tree just as an exe does.

    Args:
        stage_root: The staged tree that mirrors the installed ``{app}`` layout.

    Returns:
        list[str]: The names of ``Scripts`` files still embedding the build path,
            empty when the strip step did its job (or no ``Scripts`` dir exists).
    """
    scripts = _rel_to_path(stage_root, _SCRIPTS_REL)
    if not scripts.is_dir():
        return []
    marker = _BUILD_PATH_MARKER.encode("ascii")
    return [item.name for item in sorted(scripts.iterdir()) if item.is_file() and marker in item.read_bytes()]


def editable_dist_infos(stage_root: Path) -> list[str]:
    r"""Return staged editable-install ``intellicrack*.dist-info`` directories.

    The editable install's ``dist-info`` carries a ``direct_url.json`` that leaks
    ``file:///.../Intellicrack``; the app source ships under ``app\src`` on
    ``PYTHONPATH`` instead, so ``stage.ps1`` removes this dead, path-leaking
    metadata.

    Args:
        stage_root: The staged tree that mirrors the installed ``{app}`` layout.

    Returns:
        list[str]: The names of surviving ``intellicrack*.dist-info`` directories,
            empty when the strip step did its job (or no site-packages exists).
    """
    site_packages = _rel_to_path(stage_root, _SITE_PACKAGES_REL)
    if not site_packages.is_dir():
        return []
    return sorted(entry.name for entry in site_packages.glob("intellicrack*.dist-info") if entry.is_dir())


def test_staged_runtime_has_no_build_path_shims() -> None:
    r"""Real gate: no staged ``Scripts`` shim embeds the build interpreter path.

    Skips when the staging tree is absent (for example in the sandbox); on a
    build host it fails loudly if the shim-strip step regressed and left a
    console-script launcher hardcoding a ``.pixi\envs\`` build path.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    offenders = scripts_shims_embedding_build_path(_BUILD_STAGE)
    assert offenders == [], "staged runtime\\Scripts shims still embed the build interpreter path:\n  " + "\n  ".join(offenders)


def test_staged_runtime_has_no_editable_dist_info() -> None:
    """Real gate: no staged editable ``intellicrack*.dist-info`` leaks the source path.

    Skips when the staging tree is absent; otherwise fails if the dist-info strip
    regressed and left the path-leaking editable metadata in the runtime.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    offenders = editable_dist_infos(_BUILD_STAGE)
    assert offenders == [], "staged runtime leaks editable-install dist-info:\n  " + "\n  ".join(offenders)


def test_build_path_hygiene_checkers_are_falsifiable(tmp_path: Path) -> None:
    """The shim and dist-info checkers pass on a clean stage and flag a leak.

    Builds a tiny fake stage: a clean ``Scripts`` exe and a clean site-packages,
    confirms both checkers report nothing, then plants a shim embedding the
    runtime-env build path (the current staging source), a *non-exe* entry-point
    script carrying the same path in a shebang, and an ``intellicrack*.dist-info``
    and confirms all three are detected.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    scripts = _rel_to_path(stage, _SCRIPTS_REL)
    site_packages = _rel_to_path(stage, _SITE_PACKAGES_REL)
    scripts.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    (scripts / "clean.exe").write_bytes(b"MZ\x90\x00 no build path here")
    (scripts / "clean.py").write_bytes(b"#!python\nprint(1)\n")

    assert scripts_shims_embedding_build_path(stage) == []
    assert editable_dist_infos(stage) == []

    (scripts / "pip.exe").write_bytes(b"MZ shebang C:\\build\\.pixi\\envs\\runtime\\python.exe")
    (scripts / "bottle.py").write_bytes(b"#!C:\\build\\.pixi\\envs\\runtime\\python.exe\nprint(1)\n")
    (site_packages / "intellicrack-0.1.0a1.dist-info").mkdir()

    assert scripts_shims_embedding_build_path(stage) == ["bottle.py", "pip.exe"], (
        "the shim checker missed a planted build-path leak; it must flag every file "
        "under Scripts, not just *.exe"
    )
    assert editable_dist_infos(stage) == ["intellicrack-0.1.0a1.dist-info"], (
        "the dist-info checker missed a planted editable install"
    )


# --- Git tracking of the launcher build inputs (host-native) -----------------

# The launcher bootstrappers and their PyInstaller specs must be committed, or a
# clean clone cannot build the installer (the original blocker: a broad *.spec
# ignore swallowed two of the three specs).
_TRACKED_LAUNCHER_FILES: Final[tuple[str, ...]] = (
    "launcher.py",
    "launcher.spec",
    "hexbench_launcher.py",
    "hexbench_launcher.spec",
    # Both specs import this at build time to generate their Win32 version
    # resource, so an untracked copy breaks the launcher build on a clean clone
    # exactly as a swallowed spec did.
    "version_resource.py",
)


def test_launcher_specs_and_bootstrappers_are_tracked() -> None:
    """Real gate: no launcher build input is swallowed by a gitignore rule.

    Reads the git index at the repository root (outside the sandbox's mounted
    subtree), so it runs in the host-native pass. Falsifiable by re-adding a
    blanket ``*.spec`` ignore without the per-file negation: the swallowed specs
    drop out of ``git ls-files`` and ``git add`` becomes a silent no-op, so a
    clean clone cannot build them.

    A file that is present and merely uncommitted passes, because ``git add``
    will pick it up; a file git refuses to add does not. That distinction is the
    whole failure mode -- a rule that makes staging silently do nothing is
    invisible in every other check.
    """
    git = shutil.which("git")
    assert git is not None, "git executable not found on PATH"
    listed = subprocess.run(
        [git, "-C", str(_REPO_ROOT), "ls-files", "packaging/launcher"],
        capture_output=True,
        text=True,
        check=True,
    )
    tracked = {line.rsplit("/", 1)[-1] for line in listed.stdout.splitlines() if line.strip()}

    launcher_dir = _REPO_ROOT / "packaging" / "launcher"
    untracked = [name for name in _TRACKED_LAUNCHER_FILES if name not in tracked]
    absent = [name for name in untracked if not (launcher_dir / name).is_file()]
    assert absent == [], f"launcher build inputs are neither tracked nor present on disk: {absent}"

    if not untracked:
        return

    # `git check-ignore` exits 0 when it matched at least one path, 1 when it
    # matched none, and >1 on a real error -- so a nonzero exit is not a failure.
    ignored = subprocess.run(
        [git, "-C", str(_REPO_ROOT), "check-ignore", "--", *(f"packaging/launcher/{name}" for name in untracked)],
        capture_output=True,
        text=True,
        check=False,
    )
    swallowed = sorted(line.rsplit("/", 1)[-1] for line in ignored.stdout.splitlines() if line.strip())
    assert swallowed == [], f"a gitignore rule swallows these launcher build inputs, so `git add` silently drops them: {swallowed}"
