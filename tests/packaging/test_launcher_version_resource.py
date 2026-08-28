# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Falsifiable gates for the Win32 version resource on the frozen launchers.

``Intellicrack.exe`` and ``Hexbench.exe`` shipped with entirely empty file
properties: PyInstaller stamps a ``VS_VERSIONINFO`` resource only when ``EXE()``
is given a ``version=`` argument, and ``icon=`` does not supply one. The fix adds
``packaging/launcher/version_resource.py``, which renders that resource for both
spec files out of ``src/intellicrack/_metadata.py``.

The interesting risk is not that the resource is missing - that is one keyword
argument - but that the version inside it becomes a *copy*. A literal written
into the resource generator would agree with the installer today and drift at the
next bump, silently shipping executables whose properties contradict the
installer's ``AppVersion``. So the central gate here does not compare the
generator against a constant: it drives the real generator against a synthetic
metadata module carrying a version that appears nowhere in the repository, and
requires that version to come out the other end. A hardcoded literal cannot pass
that.

The remaining gates pin the numeric transform to the one
``tests/packaging/test_version_consistency.py`` already gates the installer with
(the two must not drift apart), parse the rendered text the way PyInstaller's
loader does, and check both spec files actually pass the generated file to
``EXE()`` under the right executable name.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from tests.packaging.test_version_consistency import derive_numeric_version


if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import ModuleType


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_LAUNCHER_DIR: Final[Path] = _REPO_ROOT / "packaging" / "launcher"
_VERSION_RESOURCE_PATH: Final[Path] = _LAUNCHER_DIR / "version_resource.py"
_METADATA_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "_metadata.py"

# The two frozen launchers and the spec file that builds each one.
_SPECS: Final[tuple[tuple[str, str], ...]] = (
    ("Intellicrack", "launcher.spec"),
    ("Hexbench", "hexbench_launcher.spec"),
)

# Version strings used by test_version_consistency's own derivation proof. Both
# transforms must agree on every one of them, or the executable properties and
# the installer's VersionInfoVersion can disagree for some future version.
_SHARED_VERSION_CASES: Final[tuple[str, ...]] = ("0.1.0a1", "1.2.3", "2.0.0rc2", "1.4.0.dev5", "3.1")

# A version that exists nowhere in the repository, used to prove the generator
# reads metadata rather than carrying a literal.
_SENTINEL_VERSION: Final[str] = "47.11.3b9"
_SENTINEL_NUMERIC: Final[tuple[int, int, int, int]] = (47, 11, 3, 0)

_VERSION_PARTS: Final[int] = 4


def _load_version_resource() -> ModuleType:
    """Load ``version_resource`` directly from its source file.

    ``packaging/launcher`` is not an importable package, so the module is loaded
    from disk the same way ``test_launcher`` loads the bootstrapper it gates.

    Returns:
        ModuleType: The imported ``version_resource`` module.
    """
    spec = importlib.util.spec_from_file_location("intellicrack_version_resource", _VERSION_RESOURCE_PATH)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load the version-resource generator from {_VERSION_RESOURCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


version_resource = _load_version_resource()


def write_fake_metadata(repo_root: Path, version: str, author: str, copyright_notice: str, summary: str) -> Path:
    """Write a synthetic ``_metadata.py`` in the layout the generator expects.

    Args:
        repo_root: A directory to treat as a repository root.
        version: The ``__version__`` literal to declare.
        author: The ``__author__`` literal to declare.
        copyright_notice: The ``__copyright__`` literal to declare.
        summary: The ``__summary__`` literal to declare.

    Returns:
        Path: The written metadata module.
    """
    metadata = repo_root / "src" / "intellicrack" / "_metadata.py"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(
        f'__version__: str = "{version}"\n'
        f'__author__: str = "{author}"\n'
        f'__copyright__: str = "{copyright_notice}"\n'
        f'__summary__: str = "{summary}"\n',
        encoding="utf-8",
    )
    return metadata


def _integer_tuple(name: str, node: ast.expr) -> tuple[int, ...]:
    """Evaluate a version-tuple keyword into a tuple of integers.

    Args:
        name: The keyword's name, used in the failure message.
        node: The keyword's value node.

    Returns:
        tuple[int, ...]: The evaluated components.

    Raises:
        TypeError: If the value is not a tuple of integers.
    """
    value: object = ast.literal_eval(node)
    if not isinstance(value, tuple):
        msg = f"{name} is not a tuple"
        raise TypeError(msg)
    parts: tuple[object, ...] = tuple(cast("Iterable[object]", value))
    components: list[int] = []
    for part in parts:
        if not isinstance(part, int):
            msg = f"{name} carries a non-integer component {part!r}"
            raise TypeError(msg)
        components.append(part)
    return tuple(components)


def parse_rendered_resource(text: str) -> tuple[tuple[int, ...], tuple[int, ...], dict[str, str]]:
    """Parse a rendered ``VSVersionInfo`` block the way PyInstaller's loader does.

    PyInstaller reads the resource by evaluating it as Python, so parsing it with
    :mod:`ast` proves both that it is syntactically valid input for that loader
    and what fields it actually carries.

    Args:
        text: The rendered ``VSVersionInfo(...)`` source.

    Returns:
        tuple[tuple[int, ...], tuple[int, ...], dict[str, str]]: The ``filevers``
            tuple, the ``prodvers`` tuple, and the string table as a mapping.

    Raises:
        AssertionError: If the text is not a single ``VSVersionInfo`` expression,
            or its ``FixedFileInfo`` does not declare both version tuples.
        TypeError: If the ``ffi`` keyword is not a call, or a version tuple holds
            something other than integers.
    """
    tree = ast.parse(text)
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Expr):
        msg = "the rendered resource is not a single expression"
        raise AssertionError(msg)
    root = tree.body[0].value
    if not isinstance(root, ast.Call) or not isinstance(root.func, ast.Name) or root.func.id != "VSVersionInfo":
        msg = "the rendered resource is not a VSVersionInfo(...) call"
        raise AssertionError(msg)

    fixed = next((keyword.value for keyword in root.keywords if keyword.arg == "ffi"), None)
    if not isinstance(fixed, ast.Call):
        msg = "the rendered resource carries no FixedFileInfo"
        raise TypeError(msg)
    versions: dict[str, tuple[int, ...]] = {}
    for keyword in fixed.keywords:
        if keyword.arg in {"filevers", "prodvers"}:
            versions[keyword.arg] = _integer_tuple(keyword.arg, keyword.value)
    if set(versions) != {"filevers", "prodvers"}:
        msg = f"FixedFileInfo declares {sorted(versions)}, not both filevers and prodvers"
        raise AssertionError(msg)

    table: dict[str, str] = {}
    expected_arguments = 2
    for node in ast.walk(root):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "StringStruct":
            arguments: list[object] = [ast.literal_eval(argument) for argument in node.args]
            if len(arguments) != expected_arguments:
                msg = f"StringStruct takes a name and a value, got {arguments}"
                raise AssertionError(msg)
            table[str(arguments[0])] = str(arguments[1])
    return versions["filevers"], versions["prodvers"], table


def parse_spec_calls(spec_path: Path) -> tuple[dict[str, ast.expr], dict[str, ast.expr]]:
    """Extract the ``EXE`` and ``write_version_resource`` keywords from a spec file.

    Args:
        spec_path: A PyInstaller ``.spec`` file.

    Returns:
        tuple[dict[str, ast.expr], dict[str, ast.expr]]: The keyword arguments of
            the ``EXE(...)`` call and of the ``write_version_resource(...)`` call.

    Raises:
        AssertionError: If either call is absent from the spec.
    """
    tree = ast.parse(spec_path.read_text(encoding="utf-8"), filename=str(spec_path))
    exe: dict[str, ast.expr] = {}
    writer: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
        if node.func.id == "EXE":
            exe = keywords
        elif node.func.id == "write_version_resource":
            writer = keywords
    if not exe:
        msg = f"{spec_path.name} contains no EXE(...) call"
        raise AssertionError(msg)
    if not writer:
        msg = f"{spec_path.name} never calls write_version_resource(...)"
        raise AssertionError(msg)
    return exe, writer


def _literal(node: ast.expr) -> object:
    """Evaluate a literal spec keyword value.

    Args:
        node: The keyword's value node.

    Returns:
        object: The literal value, or ``None`` when the node is not a literal.
    """
    try:
        value: object = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    return value


# --- The numeric transform stays tied to the installer's ---------------------


def test_launcher_and_installer_numeric_transforms_agree() -> None:
    """Real gate: the executable's numeric version is the installer's, case for case.

    ``version_resource.derive_file_version`` and
    ``test_version_consistency.derive_numeric_version`` are two implementations of
    the same PEP 440 to Win32 mapping - one for the exe properties, one gating the
    installer's ``VersionInfoVersion``. De-syncing either regex (dropping ``rc``,
    or padding to three parts) makes them disagree here.
    """
    for case in _SHARED_VERSION_CASES:
        launcher_parts: tuple[int, int, int, int] = version_resource.derive_file_version(case)
        installer_parts = tuple(int(part) for part in derive_numeric_version(case).split("."))
        assert launcher_parts == installer_parts, f"{case!r}: launcher derives {launcher_parts}, installer derives {installer_parts}"


def test_numeric_transform_agrees_on_the_real_project_version() -> None:
    """The transform agrees on the version actually shipping, not only on samples."""
    metadata: dict[str, str] = version_resource.read_metadata(_REPO_ROOT)
    real_version = metadata["version"]
    launcher_parts: tuple[int, int, int, int] = version_resource.derive_file_version(real_version)
    assert ".".join(str(part) for part in launcher_parts) == derive_numeric_version(real_version)


def test_out_of_range_and_non_numeric_versions_fail_the_build() -> None:
    """A version the 16-bit packing cannot hold is rejected instead of truncated.

    Silent truncation would ship an executable claiming a version it does not
    have; failing the build is the only safe outcome.
    """
    with pytest.raises(ValueError, match="non-numeric"):
        version_resource.derive_file_version("1!0.1.0")
    with pytest.raises(ValueError, match="exceeds"):
        version_resource.derive_file_version("70000.0.0")


# --- The version is read, not written down -----------------------------------


def test_version_resource_is_single_sourced_from_the_metadata_module(tmp_path: Path) -> None:
    """Real gate: the resource carries whatever ``_metadata.py`` says, not a literal.

    Drives the production generator against a synthetic metadata module whose
    version, publisher, copyright and summary appear nowhere in this repository.
    Every one of them must reappear in the rendered resource. A generator that
    hardcoded the current version - the drift this whole mechanism exists to
    prevent - fails on the very first field.

    Args:
        tmp_path: Pytest temporary directory used as a synthetic repo root.
    """
    fake_root = tmp_path / "repo"
    write_fake_metadata(
        fake_root,
        version=_SENTINEL_VERSION,
        author="Sentinel Publisher",
        copyright_notice="Copyright (C) 2999 Sentinel Publisher",
        summary="Sentinel summary line.",
    )

    written: Path = version_resource.write_version_resource(
        destination=tmp_path / "work" / "Sentinel.version.txt",
        repo_root=fake_root,
        executable_name="Sentinel",
    )
    assert written.is_file(), "write_version_resource did not produce the resource file"

    filevers, prodvers, table = parse_rendered_resource(written.read_text(encoding="utf-8"))

    assert filevers == _SENTINEL_NUMERIC, f"filevers is {filevers}; the generator did not read the synthetic __version__"
    assert prodvers == filevers, "prodvers must match filevers"
    assert table["ProductVersion"] == _SENTINEL_VERSION, "ProductVersion must carry the full PEP 440 string, prerelease marker included"
    assert table["FileVersion"] == ".".join(str(part) for part in _SENTINEL_NUMERIC)
    assert table["CompanyName"] == "Sentinel Publisher"
    assert table["LegalCopyright"] == "Copyright (C) 2999 Sentinel Publisher"
    assert table["FileDescription"] == "Sentinel summary line.", "the default FileDescription must come from __summary__"
    assert table["InternalName"] == "Sentinel"
    assert table["OriginalFilename"] == "Sentinel.exe"


def test_explicit_description_overrides_the_project_summary(tmp_path: Path) -> None:
    """Hexbench's own description reaches ``FileDescription`` instead of the summary.

    Args:
        tmp_path: Pytest temporary directory used as a synthetic repo root.
    """
    fake_root = tmp_path / "repo"
    write_fake_metadata(fake_root, _SENTINEL_VERSION, "A", "C", "the project summary")

    written: Path = version_resource.write_version_resource(
        destination=tmp_path / "work" / "Other.version.txt",
        repo_root=fake_root,
        executable_name="Other",
        description="a different description",
    )
    _filevers, _prodvers, table = parse_rendered_resource(written.read_text(encoding="utf-8"))
    assert table["FileDescription"] == "a different description"


def test_incomplete_metadata_fails_the_build(tmp_path: Path) -> None:
    """A metadata module missing a required field stops the build loudly.

    Falling back to an empty ``CompanyName`` would ship an executable whose
    properties are as blank as the ones this change exists to fill in.

    Args:
        tmp_path: Pytest temporary directory used as a synthetic repo root.
    """
    fake_root = tmp_path / "repo"
    metadata = write_fake_metadata(fake_root, _SENTINEL_VERSION, "A", "C", "S")
    metadata.write_text(f'__version__: str = "{_SENTINEL_VERSION}"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="__author__"):
        version_resource.read_metadata(fake_root)

    with pytest.raises(ValueError, match="metadata module not found"):
        version_resource.read_metadata(tmp_path / "not-a-repo")


def test_the_real_metadata_module_still_parses_with_the_generator() -> None:
    """The generator's parser matches the real ``_metadata.py`` declaration style.

    It parses the module rather than importing it, so a restyled declaration
    (dropping the ``: str`` annotation, or switching to single quotes) would make
    it silently see no fields. This couples the parser to the real file.
    """
    assert _METADATA_PATH.is_file(), f"metadata module missing: {_METADATA_PATH}"
    metadata: dict[str, str] = version_resource.read_metadata(_REPO_ROOT)
    for field in ("version", "author", "copyright", "summary"):
        assert metadata.get(field), f"the generator read no non-empty __{field}__ from {_METADATA_PATH}"


def test_rendered_resource_declares_a_us_english_translation() -> None:
    """The string table key and the translation entry describe the same locale.

    Windows looks the string table up by the ``VarFileInfo`` translation pair; a
    table keyed for one locale and declared for another reads back as empty
    properties, which is indistinguishable from having no resource at all.
    """
    text: str = version_resource.render_version_resource(
        version="1.2.3",
        author="A",
        copyright_notice="C",
        description="D",
        executable_name="E",
    )
    assert "StringTable('040904B0'" in text, "the string table is not keyed for US English / Unicode"
    assert "VarStruct('Translation', [1033, 1200])" in text, "the translation entry does not match the 040904B0 table key"


# --- Both spec files actually consume the generated resource ------------------


@pytest.mark.parametrize(("executable", "spec_name"), _SPECS)
def test_spec_passes_the_generated_version_resource_to_exe(executable: str, spec_name: str) -> None:
    """Real gate: each spec builds a resource and hands it to ``EXE(version=...)``.

    Without the ``version=`` keyword PyInstaller stamps no ``VS_VERSIONINFO`` at
    all - the original defect - and no other part of the build would notice.

    Args:
        executable: The executable base name the spec produces.
        spec_name: The spec file name under ``packaging/launcher``.
    """
    spec_path = _LAUNCHER_DIR / spec_name
    assert spec_path.is_file(), f"spec file missing: {spec_path}"
    exe_keywords, writer_keywords = parse_spec_calls(spec_path)

    assert "version" in exe_keywords, f"{spec_name} calls EXE() without version=, so the executable gets no version resource"
    version_argument = ast.unparse(exe_keywords["version"])
    assert version_argument == "str(VERSION_FILE)", f"{spec_name} passes version={version_argument}, not the generated resource path"

    assert _literal(exe_keywords["name"]) == executable, f"{spec_name} does not build {executable}"
    assert _literal(writer_keywords["executable_name"]) == executable, (
        f"{spec_name} generates the resource for {_literal(writer_keywords['executable_name'])!r} "
        f"but names the executable {executable!r}; OriginalFilename would not match the shipped file"
    )


@pytest.mark.parametrize(("executable", "spec_name"), _SPECS)
def test_spec_writes_the_resource_into_the_untracked_build_directory(executable: str, spec_name: str) -> None:
    """The generated resource lands under PyInstaller's ``workpath``, never in the tree.

    A tracked copy would be one more place the version can go stale, which is
    exactly what ``test_version_consistency`` exists to prevent.

    Args:
        executable: The executable base name the spec produces.
        spec_name: The spec file name under ``packaging/launcher``.
    """
    _exe_keywords, writer_keywords = parse_spec_calls(_LAUNCHER_DIR / spec_name)
    destination = ast.unparse(writer_keywords["destination"])
    assert "workpath" in destination, f"{spec_name} writes {executable}'s version resource to {destination}, outside PyInstaller's workpath"

    tracked = sorted(path.name for path in _LAUNCHER_DIR.glob("*.version.txt"))
    assert tracked == [], f"generated version resources are sitting in the launcher directory: {tracked}"


def test_rendered_resource_round_trips_through_the_parser() -> None:
    """The parser used above is not vacuous: it rejects a resource it cannot read.

    Guards the gates that depend on :func:`parse_rendered_resource` -- a parser
    that silently returned empty tables would make them all pass regardless.
    """
    text: str = version_resource.render_version_resource(
        version="9.8.7",
        author="A",
        copyright_notice="C",
        description="D",
        executable_name="E",
    )
    filevers, _prodvers, table = parse_rendered_resource(text)
    assert filevers == (9, 8, 7, 0)
    assert len(filevers) == _VERSION_PARTS
    assert table["ProductName"] == "Intellicrack"

    with pytest.raises(AssertionError, match="not a VSVersionInfo"):
        parse_rendered_resource("SomethingElse(ffi=None)")
