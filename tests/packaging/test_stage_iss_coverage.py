# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""The missing half of the stage/installer contract: stage -> ``.iss`` coverage.

``tests/packaging/test_stage_matches_iss.py`` gates one direction only. It walks
the ``[Files]`` ``Source:`` entries of ``packaging/intellicrack.iss`` and proves
each one resolves under ``build/stage``, so the installer can never reference a
payload the stager did not produce. Nothing gated the opposite direction, and the
stage-side checklist it does carry (``_REQUIRED_FILES``) asserts *presence in the
stage*, not *coverage by the installer*. A file the stager produces and the
installer forgets to package is therefore invisible: that is exactly how
``app\build-info.json`` came to be staged, asserted, and never installed.

This module closes that direction twice, from two independent sources of truth:

* **Statically, from the stager itself.** ``packaging/stage.ps1`` declares what it
  produces with ``Assert-Produced -Path <path>``. Those paths are resolved here
  by following the script's own ``$Name = Join-Path $Base 'literal'`` assignment
  chain, and every resolved path that lands under ``$Stage`` must be covered by
  an ``.iss`` ``Source``. This runs everywhere - it needs no built stage - and it
  is the gate that would have caught ``build-info.json``.
* **Dynamically, from a real ``build/stage`` tree.** Every staged file must be
  packaged by some ``Source``, modulo a deliberately empty, documented allowlist
  of build-only artifacts. The real tree exists only on a build host, so that gate
  skips when it is absent; its detection logic is proven falsifiable against a
  fake stage built in ``tmp_path``.

The ``.iss`` parsing helpers are imported from the existing module rather than
reimplemented, so both directions read the installer through one parser.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from tests.packaging.test_stage_matches_iss import iss_source_relpaths


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_BUILD_STAGE: Final[Path] = _REPO_ROOT / "build" / "stage"
_ISS_PATH: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"
_STAGE_PS1: Final[Path] = _REPO_ROOT / "packaging" / "stage.ps1"

# ``$Name = Join-Path $Base 'literal'`` -- the only assignment shape this
# resolver follows. An assignment whose second argument is a variable or an
# interpolated string is deliberately not resolvable, so the paths it would
# produce are simply absent from the product set rather than guessed at.
_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)^[ \t]*\$(?P<name>[A-Za-z_]\w*)[ \t]*=[ \t]*Join-Path[ \t]+\$(?P<base>[A-Za-z_]\w*)[ \t]+'(?P<literal>[^']*)'[ \t]*$",
)

# ``Assert-Produced -Path (Join-Path $Var 'literal')`` or ``-Path $Var``.
_ASSERT_PRODUCED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)^[ \t]*Assert-Produced[ \t]+-Path[ \t]+"
    r"(?:\(Join-Path[ \t]+\$(?P<base>[A-Za-z_]\w*)[ \t]+'(?P<literal>[^']*)'\)|\$(?P<bare>[A-Za-z_]\w*)(?=[ \t]|$))",
)

# The repository-relative prefix every staged artifact lives under. Derived from
# the script's own ``$Stage`` assignment rather than assumed; this is only the
# name of the variable to look for.
_STAGE_VARIABLE: Final[str] = "Stage"
_ROOT_VARIABLE: Final[str] = "RepoRoot"

# Resolution is a fixed-point over the assignment chain; four passes is far more
# than the two levels (``$Stage`` -> ``$RuntimeDir`` -> ``$RuntimeSitePackages``)
# the script actually nests, and bounds a self-referential assignment.
_MAX_RESOLUTION_PASSES: Final[int] = 8

# A staged path that the installer deliberately does not package. Empty today:
# the checksum manifest, the extracted JDK archive and the PyInstaller work trees
# are all written outside ``build/stage`` precisely so they need no entry here.
# Add a path only with the reason it must ship in the stage yet not in the
# installer -- an entry here silences a real coverage failure.
_STAGE_ONLY_ALLOWLIST: Final[frozenset[str]] = frozenset()

# Vacuity anchor: the staged interpreter is the one artifact ``stage.ps1`` can
# never stop asserting, so its absence from the resolved product set means the
# resolver broke, not that the stager changed.
_ANCHOR_PRODUCT: Final[str] = "runtime/python.exe"


def resolve_path_variables(script_text: str) -> dict[str, str]:
    """Resolve the ``Join-Path`` assignment chain of a staging script.

    Every ``$Name = Join-Path $Base 'literal'`` assignment is followed from the
    repository root outwards, so the returned table maps a variable name to the
    forward-slash repository-relative path it holds. Assignments whose base is
    never resolved, or whose second argument is not a single-quoted literal, are
    omitted rather than approximated.

    Args:
        script_text: The full text of ``packaging/stage.ps1``.

    Returns:
        dict[str, str]: Variable name mapped to its repository-relative path,
            using forward slashes and no leading separator.
    """
    resolved: dict[str, str] = {_ROOT_VARIABLE: ""}
    assignments = [(match.group("name"), match.group("base"), match.group("literal")) for match in _ASSIGN_RE.finditer(script_text)]
    for _ in range(_MAX_RESOLUTION_PASSES):
        changed = False
        for name, base, literal in assignments:
            if name in resolved or base not in resolved:
                continue
            tail = literal.replace("\\", "/").strip("/")
            prefix = resolved[base]
            resolved[name] = f"{prefix}/{tail}" if prefix else tail
            changed = True
        if not changed:
            break
    return resolved


def staged_products(script_text: str) -> list[str]:
    """Collect the stage-relative paths the staging script asserts it produced.

    Only ``Assert-Produced`` targets that resolve under the script's own
    ``$Stage`` variable are returned: artifacts the script produces elsewhere
    (the downloaded JDK archive, the checksum manifest, the PyInstaller output in
    ``dist``) are not installer payload and are excluded by construction.

    Args:
        script_text: The full text of ``packaging/stage.ps1``.

    Returns:
        list[str]: Sorted, de-duplicated stage-relative forward-slash paths.

    Raises:
        AssertionError: If the script declares no resolvable ``$Stage``.
    """
    variables = resolve_path_variables(script_text)
    if _STAGE_VARIABLE not in variables:
        msg = "packaging/stage.ps1 declares no resolvable $Stage assignment"
        raise AssertionError(msg)
    stage_prefix = f"{variables[_STAGE_VARIABLE]}/"

    products: set[str] = set()
    for match in _ASSERT_PRODUCED_RE.finditer(script_text):
        bare = match.group("bare")
        if bare is not None:
            full = variables.get(bare)
        else:
            base = variables.get(match.group("base"))
            if base is None:
                continue
            tail = match.group("literal").replace("\\", "/").strip("/")
            full = f"{base}/{tail}" if base else tail
        if full is None or not full.startswith(stage_prefix):
            continue
        products.add(full[len(stage_prefix) :])
    return sorted(products)


def _is_covered(relative: str, sources: list[tuple[str, bool]]) -> bool:
    """Report whether one stage-relative path is packaged by any ``Source``.

    Args:
        relative: A forward-slash path relative to the stage root.
        sources: ``(relative_path, is_wildcard)`` pairs from
            :func:`tests.packaging.test_stage_matches_iss.iss_source_relpaths`.

    Returns:
        bool: ``True`` when an exact ``Source`` names the path, or a wildcard
            ``Source`` names it or one of its ancestor directories.
    """
    for source, is_wildcard in sources:
        if is_wildcard:
            if not source or relative == source or relative.startswith(f"{source}/"):
                return True
        elif relative == source:
            return True
    return False


def unpackaged_products(products: list[str], sources: list[tuple[str, bool]]) -> list[str]:
    """Return the asserted stage products no ``[Files]`` entry packages.

    Args:
        products: Stage-relative paths from :func:`staged_products`.
        sources: ``(relative_path, is_wildcard)`` pairs parsed from the ``.iss``.

    Returns:
        list[str]: The products that no ``Source`` covers, in input order.
    """
    return [product for product in products if not _is_covered(product, sources)]


def unpackaged_stage_files(stage_root: Path, sources: list[tuple[str, bool]], allowlist: frozenset[str]) -> list[str]:
    """Return the real staged files that no ``[Files]`` entry packages.

    Args:
        stage_root: A staged tree that mirrors the installed ``{app}`` layout.
        sources: ``(relative_path, is_wildcard)`` pairs parsed from the ``.iss``.
        allowlist: Stage-relative paths that are deliberately not packaged.

    Returns:
        list[str]: Sorted stage-relative paths of every file the installer would
            leave behind, excluding allowlisted entries.
    """
    unpackaged: list[str] = []
    for path in stage_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(stage_root).as_posix()
        if relative in allowlist or _is_covered(relative, sources):
            continue
        unpackaged.append(relative)
    return sorted(unpackaged)


def _read_real_iss_sources() -> list[tuple[str, bool]]:
    """Parse the real installer script's ``[Files]`` sources.

    Returns:
        list[tuple[str, bool]]: ``(relative_path, is_wildcard)`` pairs.
    """
    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    return iss_source_relpaths(_ISS_PATH.read_text(encoding="utf-8-sig"))


# --- stage -> .iss, derived statically from the stager (runs everywhere) ------


def test_every_asserted_stage_product_is_packaged_by_the_iss() -> None:
    r"""Real gate: everything ``stage.ps1`` asserts into the stage reaches ``{app}``.

    This is the direction ``test_stage_matches_iss`` never had. It goes red the
    moment the stager gains an ``Assert-Produced`` under ``$Stage`` that no
    ``[Files]`` ``Source`` covers -- the ``app\build-info.json`` case -- and it
    needs no built stage, so it runs in the sandbox alongside everything else.
    """
    assert _STAGE_PS1.is_file(), f"staging script missing: {_STAGE_PS1}"
    products = staged_products(_STAGE_PS1.read_text(encoding="utf-8"))

    assert _ANCHOR_PRODUCT in products, (
        f"the stage.ps1 path resolver produced no {_ANCHOR_PRODUCT!r}; it can no longer follow the "
        f"script's Join-Path assignments, so this gate would pass vacuously (resolved: {products})"
    )

    unpackaged = unpackaged_products(products, _read_real_iss_sources())
    assert unpackaged == [], (
        "packaging/stage.ps1 asserts these files into build/stage but packaging/intellicrack.iss "
        "packages none of them, so they are staged and never installed:\n  " + "\n  ".join(unpackaged)
    )


def test_stage_product_resolver_follows_the_assignment_chain() -> None:
    """The resolver walks nested ``Join-Path`` assignments and stops at the stage.

    Proves the transform the static gate depends on: a two-level variable chain
    resolves, a literal ``$Stage`` join resolves, an artifact produced outside
    ``$Stage`` is excluded, and an unresolvable target is dropped rather than
    guessed.
    """
    script = (
        "$Stage = Join-Path $RepoRoot 'build\\stage'\n"
        "$BuildRoot = Join-Path $RepoRoot 'build'\n"
        "$RuntimeDir = Join-Path $Stage 'runtime'\n"
        "$SitePackages = Join-Path $RuntimeDir 'Lib\\site-packages'\n"
        "$Manifest = Join-Path $BuildRoot 'stage-SHA256SUMS.txt'\n"
        "Assert-Produced -Path (Join-Path $RuntimeDir 'python.exe') -What 'python'\n"
        "Assert-Produced -Path $SitePackages -What 'site-packages'\n"
        "Assert-Produced -Path $Manifest -What 'manifest'\n"
        "Assert-Produced -Path (Join-Path $Missing.FullName 'java.exe') -What 'jdk'\n"
        "    Assert-Produced -Path (Join-Path $Stage 'qemu-guest\\guest.qcow2') -What 'guest'\n"
    )

    assert staged_products(script) == [
        "qemu-guest/guest.qcow2",
        "runtime/Lib/site-packages",
        "runtime/python.exe",
    ]


def test_static_coverage_checker_is_falsifiable() -> None:
    """The static checker passes on a covering ``.iss`` and fails when one entry is dropped.

    Mirrors the real defect: a product the stager asserts, packaged by an exact
    (non-wildcard) ``Source``, becomes unpackaged the moment that line is removed.
    """
    script = (
        "$Stage = Join-Path $RepoRoot 'build\\stage'\n"
        "$AppDir = Join-Path $Stage 'app'\n"
        "Assert-Produced -Path (Join-Path $AppDir 'build-info.json') -What 'stamp'\n"
        "Assert-Produced -Path (Join-Path $AppDir 'src\\intellicrack\\__init__.py') -What 'source'\n"
    )
    products = staged_products(script)
    assert products == ["app/build-info.json", "app/src/intellicrack/__init__.py"]

    covering: list[tuple[str, bool]] = [("app/src", True), ("app/build-info.json", False)]
    assert unpackaged_products(products, covering) == []

    without_stamp = [entry for entry in covering if entry[0] != "app/build-info.json"]
    assert unpackaged_products(products, without_stamp) == ["app/build-info.json"]


def test_wildcard_source_does_not_cover_a_sibling_prefix() -> None:
    """A wildcard ``Source`` covers its own subtree only, never a name that shares its prefix.

    Without the separator in the prefix test, ``app/tools`` would appear to
    package ``app/tools-extra/x.exe`` and the gate would miss a real omission.
    """
    sources: list[tuple[str, bool]] = [("app/tools", True)]
    assert unpackaged_products(["app/tools/qemu/qemu-img.exe"], sources) == []
    assert unpackaged_products(["app/tools-extra/x.exe"], sources) == ["app/tools-extra/x.exe"]


# --- stage -> .iss, over a real staged tree ----------------------------------


def test_every_staged_file_is_packaged_by_the_iss() -> None:
    """Real gate: no file in ``build/stage`` is left behind by the installer.

    Skips when the staging tree has not been built (the sandbox never assembles
    the ~100+ GB payload). On a build host this catches a whole staged directory
    the ``.iss`` forgot, which the statically derived gate above cannot see
    because the stager asserts only representative files from each tree.
    """
    if not _BUILD_STAGE.is_dir():
        pytest.skip(f"staging tree not built: {_BUILD_STAGE} is absent (run packaging/stage.ps1 on a build host first)")

    unpackaged = unpackaged_stage_files(_BUILD_STAGE, _read_real_iss_sources(), _STAGE_ONLY_ALLOWLIST)
    assert unpackaged == [], (
        "these staged files are packaged by no [Files] entry in packaging/intellicrack.iss; "
        "either add a Source for them or record them in _STAGE_ONLY_ALLOWLIST with a reason:\n  " + "\n  ".join(unpackaged)
    )


def test_staged_tree_coverage_checker_is_falsifiable(tmp_path: Path) -> None:
    """The tree walker reports a clean stage clean and an unpackaged file dirty.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    (stage / "runtime").mkdir(parents=True)
    (stage / "runtime" / "python.exe").write_bytes(b"MZ")
    (stage / "app").mkdir()
    (stage / "app" / "build-info.json").write_text("{}", encoding="utf-8")

    sources: list[tuple[str, bool]] = [("runtime", True), ("app/build-info.json", False)]
    assert unpackaged_stage_files(stage, sources, frozenset()) == []

    (stage / "app" / "orphan.dll").write_bytes(b"MZ")
    assert unpackaged_stage_files(stage, sources, frozenset()) == ["app/orphan.dll"]


def test_stage_only_allowlist_suppresses_exactly_its_entry(tmp_path: Path) -> None:
    """An allowlisted path is excused and no other path inherits that excuse.

    Args:
        tmp_path: Pytest temporary directory used to build a fake stage.
    """
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "excused.txt").write_text("build-only", encoding="utf-8")
    (stage / "orphan.txt").write_text("payload", encoding="utf-8")

    sources: list[tuple[str, bool]] = []
    assert unpackaged_stage_files(stage, sources, frozenset({"excused.txt"})) == ["orphan.txt"]


def test_shipped_allowlist_excuses_nothing_that_the_iss_already_packages() -> None:
    """Every allowlist entry must name a path the installer genuinely skips.

    An entry that a ``Source`` already covers is dead weight that hides nothing
    but invites the next omission to be parked beside it. Emptying the allowlist
    (its state today) trivially satisfies this; adding a redundant entry fails.
    """
    sources = _read_real_iss_sources()
    redundant = sorted(entry for entry in _STAGE_ONLY_ALLOWLIST if _is_covered(entry, sources))
    assert redundant == [], f"these _STAGE_ONLY_ALLOWLIST entries are already packaged by the .iss and must be removed: {redundant}"
