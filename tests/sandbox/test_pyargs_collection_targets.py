# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for importable (``--pyargs``) collection targets.

Addressing tests by filesystem path makes pytest build the target's package
chain twice inside the Windows container, so every test is collected under a
duplicate node. Run counts double, and in a package whose fixtures live in a
sibling ``conftest.py`` one of the two copies cannot resolve them (the ghidra
completeness slice reported 69 ``fixture 'connected_bridge' not found`` errors
for exactly this reason). Addressing the same tests by import path collects
each exactly once.

The argument-shaping tests drive the real :func:`build_pytest_args` rather than
restating the expected strings, so a regression in the production builder is
what fails. The collection tests run a real nested collection with the argv
the builder produced and assert every collected nodeid is unique -- they fail
if the targets revert to filesystem paths.

Pytest expands ``@argfile`` arguments itself, so node ids listed in an argfile
bypass the argv rewriting unless the harness rewrites the file too. The
argfile gates pin that rewrite: the argfile is read exactly as pytest's own
parser reads it, rewritten in the context of the surrounding argv, and a real
collection driven through a rewritten argfile must see each node once.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from scripts.sandbox.argfiles import materialize_invocation, read_argfile
from scripts.sandbox.test_types import (
    TestRunSpec,
    TestType,
    build_pytest_args,
    build_pytest_invocation,
    rewritten_argfile_name,
    to_pyargs_argv,
    to_pyargs_target,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TESTS_ROOT = _REPO_ROOT / "tests"
_TIMESTAMP = "08-22-2026_12-00"

# A small, self-contained package used for the real nested collection.
_SAMPLE_PACKAGE = "tests/sandbox/analysis_regex"
_ARGFILE = "reports/tests/order.txt"


class _ExpandedArgs(argparse.Namespace):
    """Typed namespace receiving the arguments an argfile expands to."""

    def __init__(self) -> None:
        """Initialize with no expanded arguments."""
        super().__init__()
        self.values: list[str] = []


def _expand_like_pytest(argfile: str) -> list[str]:
    """Expand an argfile reference with the stdlib mechanism pytest's parser uses.

    Pytest's option parser is an :class:`argparse.ArgumentParser` created with
    ``fromfile_prefix_chars="@"``. A parser with the same setting and a single
    catch-all positional returns the expansion verbatim; its prefix character
    is one no argument uses, so ``-v`` style lines stay positional.

    Args:
        argfile: The argfile path, without the ``@`` prefix.

    Returns:
        list[str]: Every argument the reference expands to, in order.
    """
    parser = argparse.ArgumentParser(fromfile_prefix_chars="@", prefix_chars="\x1f", add_help=False)
    _ = parser.add_argument("values", nargs="*")
    return parser.parse_args([f"@{argfile}"], namespace=_ExpandedArgs()).values


def _collection_args(args: list[str]) -> list[str]:
    """Strip the report-writing arguments from a production argv.

    Args:
        args: The argv produced by the builder.

    Returns:
        list[str]: The argv without junit/html report arguments.
    """
    return [arg for arg in args if not arg.startswith(("--junitxml=", "--html=")) and arg != "--self-contained-html"]


def _collect_nodeids(args: list[str]) -> list[str]:
    """Run a real nested collection and return every nodeid it reports.

    Args:
        args: Pytest arguments selecting what to collect.

    Returns:
        list[str]: Collected nodeids in reported order, repeats included.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *args,
            "--collect-only",
            "-q",
            "--disable-warnings",
            "-p",
            "no:randomly",
            "-o",
            "addopts=",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    nodeids = [line.strip() for line in proc.stdout.splitlines() if "::" in line]
    assert nodeids, f"nested collection produced no nodeids; stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"
    return nodeids


def _duplicates(nodeids: list[str]) -> list[str]:
    """Return every nodeid that occurs more than once.

    Args:
        nodeids: Collected nodeids.

    Returns:
        list[str]: Sorted repeated nodeids.
    """
    return sorted({nodeid for nodeid in nodeids if nodeids.count(nodeid) > 1})


def _args_for(
    test_type: TestType,
    *,
    module: str | None = None,
    extra_args: tuple[str, ...] = (),
) -> list[str]:
    """Build the production pytest argv for a test type.

    Args:
        test_type: The execution mode to build arguments for.
        module: Optional module target for module modes.
        extra_args: Optional operator-supplied pass-through arguments.

    Returns:
        list[str]: The argument vector produced by the production builder.
    """
    spec = TestRunSpec(
        test_type=test_type,
        timestamp=_TIMESTAMP,
        module=module,
        extra_args=extra_args,
    )
    return build_pytest_args(spec)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("tests/", "tests"),
        ("tests", "tests"),
        ("tests/hexpat/e2e/", "tests.hexpat.e2e"),
        ("tests/core/test_x.py", "tests.core.test_x"),
        ("tests\\core\\test_x.py", "tests.core.test_x"),
        ("tests/core/test_x.py::TestC", "tests.core.test_x::TestC"),
        ("tests/core/test_x.py::TestC::test_m", "tests.core.test_x::TestC::test_m"),
        ("tests/a/test_x.py::TestC::test_m[kernel32.dll]", "tests.a.test_x::TestC::test_m[kernel32.dll]"),
    ],
)
def test_target_conversion_preserves_selection(target: str, expected: str) -> None:
    """Filesystem targets must convert to dotted targets, keeping any selector.

    The ``::`` node selector and its parametrization id must survive verbatim,
    otherwise targeting a single test or class through the harness breaks.

    Args:
        target: The filesystem-style target handed to the harness.
        expected: The importable target pytest should receive.
    """
    assert to_pyargs_target(target) == expected


@pytest.mark.parametrize(
    "test_type",
    [
        TestType.UNIT,
        TestType.ALL,
        TestType.COVERAGE,
        TestType.INTEGRATION,
        TestType.SMOKE,
        TestType.PARALLEL,
        TestType.FAILED,
        TestType.VERBOSE,
        TestType.BENCH,
        TestType.REGISTRY,
    ],
)
def test_whole_tree_modes_emit_importable_target(test_type: TestType) -> None:
    """Whole-tree modes must address ``tests`` by import path, not by path.

    A filesystem ``tests/`` target doubles the entire suite, which is where the
    inflated pass counts come from. If the builder stops converting, ``tests/``
    reappears and ``--pyargs`` is absent, failing both assertions.

    Args:
        test_type: The whole-tree execution mode under test.
    """
    args = _args_for(test_type)
    assert "--pyargs" in args, f"{test_type.value} must use importable targets: {args}"
    assert "tests" in args, f"{test_type.value} must target the tests package: {args}"
    assert "tests/" not in args, f"{test_type.value} still passes a filesystem target: {args}"


def test_e2e_mode_emits_importable_subpackage() -> None:
    """The e2e mode must address its subpackage by import path."""
    args = _args_for(TestType.E2E)
    assert "tests.hexpat.e2e" in args, f"e2e target not converted: {args}"
    assert "tests/hexpat/e2e/" not in args, f"e2e still passes a filesystem target: {args}"


@pytest.mark.parametrize(
    ("module", "expected"),
    [
        ("bridges", "tests.test_bridges"),
        ("tests/bridges/completeness/ghidra", "tests.bridges.completeness.ghidra"),
        ("tests/core/test_orchestrator_streaming_s16d04.py", "tests.core.test_orchestrator_streaming_s16d04"),
    ],
)
def test_module_mode_emits_importable_target(module: str, expected: str) -> None:
    """Module mode must convert every accepted module spelling.

    Module mode is how a single slice is targeted, so a keyword, a directory,
    and an explicit file must all resolve to importable targets.

    Args:
        module: The module argument accepted by the harness.
        expected: The importable target pytest should receive.
    """
    args = _args_for(TestType.MODULE, module=module)
    assert expected in args, f"module {module!r} produced {args}"


def test_operator_supplied_path_is_converted() -> None:
    """A path passed through ``--extra-args`` must also be converted.

    Custom mode is how targeted slices are run, and it carries its target in
    ``extra_args``; leaving those unconverted would keep doubling exactly the
    runs this fix exists for.
    """
    args = _args_for(TestType.CUSTOM, extra_args=(_SAMPLE_PACKAGE, "--collect-only"))
    assert "tests.sandbox.analysis_regex" in args, f"custom target not converted: {args}"
    assert _SAMPLE_PACKAGE not in args, f"custom target left as a path: {args}"


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--ignore", "tests/sandbox"),
        ("--deselect", "tests/core/test_x.py::TestC::test_m"),
        ("--confcutdir", "tests"),
        ("-k", "tests"),
    ],
)
def test_option_values_keep_filesystem_form(option: str, value: str) -> None:
    """A path that is an option's value must not be converted.

    ``--ignore`` and friends take a filesystem path; rewriting their value to a
    dotted name would silently stop the option from matching anything. A
    converter that rewrote every ``tests``-prefixed token would fail here.

    Args:
        option: The option consuming a separate value token.
        value: The value token that must survive unchanged.
    """
    converted = to_pyargs_argv([option, value])
    assert converted == [option, value], f"option value was rewritten: {converted}"


def test_flags_and_marker_expressions_are_untouched() -> None:
    """Flags and marker expressions must pass through unchanged.

    Marker expressions such as ``not slow and not integration`` and flags such
    as ``--cov=src/intellicrack`` must survive verbatim.
    """
    args = _args_for(TestType.UNIT)
    assert "not slow and not integration" in args, f"marker expression altered: {args}"
    coverage_args = _args_for(TestType.COVERAGE)
    assert "--cov=src/intellicrack" in coverage_args, f"coverage flag altered: {coverage_args}"


def test_pyargs_flag_is_not_duplicated() -> None:
    """An operator-supplied ``--pyargs`` must not be added a second time."""
    args = to_pyargs_argv(["--pyargs", "tests.core", "tests/ui"])
    assert args.count("--pyargs") == 1, f"--pyargs duplicated: {args}"


def test_every_test_package_is_importable() -> None:
    """Every directory holding test modules must carry an ``__init__.py``.

    ``--pyargs`` resolves a target by importing it, so a test directory without
    an ``__init__.py`` becomes unaddressable by the harness. This gate fails as
    soon as such a directory is added, which is the moment it can be fixed
    cheaply. Directories holding only data fixtures are exempt because they
    contain no modules and are never collection targets.
    """
    missing: list[str] = []
    for directory in sorted(_TESTS_ROOT.rglob("*")):
        if not directory.is_dir() or "__pycache__" in directory.parts:
            continue
        if not any(directory.glob("*.py")):
            continue
        if not (directory / "__init__.py").exists():
            missing.append(str(directory.relative_to(_REPO_ROOT)))
    assert not missing, f"test packages without __init__.py are unaddressable by --pyargs: {missing}"


def test_builder_argv_collects_each_test_exactly_once() -> None:
    """The builder's argv must collect every nodeid exactly once.

    This is the end-to-end proof of the fix. A real nested pytest collection is
    run with the argv the production builder produced for a small package; the
    collected nodeids must contain no duplicates. Reverting the builder to
    filesystem targets makes the same collection report each nodeid twice and
    fails this test.
    """
    nodeids = _collect_nodeids(_collection_args(_args_for(TestType.MODULE, module=_SAMPLE_PACKAGE)))
    duplicates = _duplicates(nodeids)
    assert not duplicates, f"{len(duplicates)} nodeid(s) collected more than once, e.g. {duplicates[:3]}"


def test_argfile_targets_are_rewritten_into_a_run_scoped_file() -> None:
    """Node ids listed in an argfile must be rewritten, not passed through.

    The argv must reference a run-scoped rewritten argfile instead of the
    operator's, the rewritten file must hold dotted targets, and ``--pyargs``
    must be switched on because pytest reads the file's targets as imports.
    An option value inside the file keeps its filesystem form.
    """
    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{_ARGFILE}", "-v"))
    contents = {_ARGFILE: (f"{_SAMPLE_PACKAGE}/test_domain_pattern.py::test_x", "--deselect", "tests/core/test_x.py::TestC::test_m")}

    invocation = build_pytest_invocation(spec, contents)

    reference = f"@{PurePosixPath('C:/app/reports/tests') / rewritten_argfile_name(spec, 0)}"
    assert reference in invocation.argv, f"argv does not reference the rewritten argfile: {invocation.argv}"
    assert f"@{_ARGFILE}" not in invocation.argv, f"argv still references the unrewritten argfile: {invocation.argv}"
    assert "--pyargs" in invocation.argv, f"argfile targets were rewritten without --pyargs: {invocation.argv}"
    assert [argfile.tokens for argfile in invocation.argfiles] == [
        ("tests.sandbox.analysis_regex.test_domain_pattern::test_x", "--deselect", "tests/core/test_x.py::TestC::test_m"),
    ]


def test_argfile_rewrite_honours_option_values_across_the_file_boundary() -> None:
    """An option and its value split by an argfile boundary must stay paired.

    Pytest splices an argfile's lines into the argv, so ``--ignore @dirs.txt``
    makes the file's first line the ``--ignore`` value, and a file ending in
    ``--ignore`` claims the argv token after the reference. Rewriting the file
    in isolation would convert both values and silently break the options.
    """
    leading = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=("--ignore", f"@{_ARGFILE}"))
    leading_invocation = build_pytest_invocation(leading, {_ARGFILE: ("tests/slow", "tests/core")})
    assert leading_invocation.argfiles[0].tokens == ("tests/slow", "tests.core")

    trailing = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{_ARGFILE}", "tests/slow"))
    trailing_invocation = build_pytest_invocation(trailing, {_ARGFILE: ("tests/core", "--ignore")})
    assert trailing_invocation.argfiles[0].tokens == ("tests.core", "--ignore")
    assert trailing_invocation.argv[-1] == "tests/slow", f"--ignore value was rewritten: {trailing_invocation.argv}"


def test_unread_argfile_is_refused() -> None:
    """An argfile whose contents were never read must not pass through.

    Passing the reference through unrewritten is exactly the path that
    collected every node twice and hung on an unguarded modal dialog.
    """
    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{_ARGFILE}",))
    with pytest.raises(ValueError, match="was not read"):
        _ = build_pytest_args(spec)


def test_rewritten_argfile_lives_beside_the_run_artifacts() -> None:
    """The default argfile location must be the mounted container reports dir.

    The container sees only the project (read-only) and ``reports/tests``
    (read-write); the rewritten argfile must be addressed where the host
    writes it and the container can read it, next to the junit report.
    """
    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{_ARGFILE}",))
    argv = build_pytest_invocation(spec, {_ARGFILE: (_SAMPLE_PACKAGE,)}).argv
    junit = next(arg for arg in argv if arg.startswith("--junitxml=")).removeprefix("--junitxml=")
    reference = next(arg for arg in argv if arg.startswith("@")).removeprefix("@")
    assert PurePosixPath(reference).parent == PurePosixPath(junit).parent
    assert PurePosixPath(reference).name == rewritten_argfile_name(spec, 0)


def test_read_argfile_matches_pytests_parser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The host reader must expand an argfile exactly as pytest's parser does.

    Covers CRLF line endings, a blank line (an empty argument to pytest), a
    dash-prefixed line, and a nested reference resolved against the working
    directory, which the reader must flatten in place.

    Args:
        tmp_path: Directory holding the argfiles and acting as the run root.
        monkeypatch: Fixture used to run the stdlib parser from that root.
    """
    _ = (tmp_path / "inner.txt").write_bytes(b"--deselect\r\ntests/core/test_x.py::TestC::test_m\r\n")
    _ = (tmp_path / "outer.txt").write_bytes(b"tests/sandbox/analysis_regex\r\n\r\n@inner.txt\r\n-v\r\n")
    monkeypatch.chdir(tmp_path)

    expanded = list(read_argfile("outer.txt", base=tmp_path))

    assert expanded == ["tests/sandbox/analysis_regex", "", "--deselect", "tests/core/test_x.py::TestC::test_m", "-v"]
    assert expanded == _expand_like_pytest("outer.txt")


def test_read_argfile_rejects_a_reference_cycle(tmp_path: Path) -> None:
    """A self-referencing argfile chain must fail with a clear error.

    Args:
        tmp_path: Directory holding the argfiles.
    """
    _ = (tmp_path / "a.txt").write_text("tests/core\n@b.txt\n", encoding="utf-8")
    _ = (tmp_path / "b.txt").write_text("@a.txt\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cycle"):
        _ = read_argfile("a.txt", base=tmp_path)


def test_written_argfile_round_trips_through_pytests_parser(tmp_path: Path) -> None:
    """The rewritten argfile on disk must expand back to the rewritten tokens.

    Args:
        tmp_path: Directory holding the source and rewritten argfiles.
    """
    source = tmp_path / "order.txt"
    _ = source.write_text(f"{_SAMPLE_PACKAGE}\n\n-v\ntests/core/test_x.py::TestC::test_m[a b]\n", encoding="utf-8")
    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{source}",))
    destination = tmp_path / "rewritten"

    invocation = materialize_invocation(spec, base=_REPO_ROOT, destination=destination, argfile_root=destination)

    written = destination / rewritten_argfile_name(spec, 0)
    assert invocation.argfiles[0].tokens == ("tests.sandbox.analysis_regex", "", "-v", "tests.core.test_x::TestC::test_m[a b]")
    assert _expand_like_pytest(str(written)) == list(invocation.argfiles[0].tokens)


def test_argfile_argv_collects_each_test_exactly_once(tmp_path: Path) -> None:
    """A collection driven through an argfile must see every node exactly once.

    This is the end-to-end proof of the argfile fix. The sample package's real
    node ids are written to an argfile in filesystem form, as an operator
    replaying a run order would, and a real nested collection is driven with
    the argv and rewritten argfile the production path produced. Reverting the
    rewrite leaves filesystem node ids in the file, which the container
    collects twice, failing both assertions.

    Args:
        tmp_path: Directory holding the source and rewritten argfiles.
    """
    reference = _collect_nodeids(to_pyargs_argv([_SAMPLE_PACKAGE]))
    assert not _duplicates(reference), f"reference collection is itself duplicated: {reference[:3]}"
    source = tmp_path / "order.txt"
    _ = source.write_text("".join(f"{nodeid}\n" for nodeid in reference), encoding="utf-8")
    spec = TestRunSpec(test_type=TestType.CUSTOM, timestamp=_TIMESTAMP, extra_args=(f"@{source}",))
    destination = tmp_path / "rewritten"

    invocation = materialize_invocation(spec, base=_REPO_ROOT, destination=destination, argfile_root=destination)
    collected = _collect_nodeids(_collection_args(list(invocation.argv)))

    duplicates = _duplicates(collected)
    assert not duplicates, f"{len(duplicates)} of {len(reference)} argfile nodeid(s) collected more than once, e.g. {duplicates[:3]}"
    assert sorted(collected) == sorted(reference)
