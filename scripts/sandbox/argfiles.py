# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Host-side reading and writing of pytest argfiles for sandbox runs.

Pytest expands ``@path`` arguments itself, so the node ids inside an argfile
never pass through the sandbox's ``--pyargs`` target rewriting and are
collected twice inside the Windows container. This module reads each
referenced argfile on the host exactly as pytest's parser would, hands the
contents to :func:`scripts.sandbox.test_types.build_pytest_invocation` for
rewriting, and writes the rewritten argfiles where the container can read them.

Nested references are flattened into the rewritten file, so the container
never needs access to any argfile the operator wrote.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .test_types import (
    PytestInvocation,
    TestRunSpec,
    argfile_source,
    argfile_sources,
    build_pytest_invocation,
)


if TYPE_CHECKING:
    from pathlib import PurePath


def _encoding() -> tuple[str, str]:
    """Return the codec pytest's argument parser uses for argfiles.

    Returns:
        tuple[str, str]: The filesystem encoding and its error handler.
    """
    return sys.getfilesystemencoding(), sys.getfilesystemencodeerrors()


def _expand(source: str, *, base: Path, chain: tuple[Path, ...]) -> list[str]:
    """Expand one argfile reference, recursing into nested references.

    Args:
        source: The referenced path as written after ``@``.
        base: Directory relative references resolve against.
        chain: Argfiles already being expanded above this one.

    Returns:
        list[str]: The fully expanded arguments.

    Raises:
        ValueError: If the reference re-enters an argfile already being
            expanded, which pytest's parser would recurse on forever.
    """
    candidate = Path(source)
    path = (candidate if candidate.is_absolute() else base / candidate).resolve()
    if path in chain:
        cycle = " -> ".join(str(item) for item in (*chain, path))
        message = f"argfile reference cycle: {cycle}"
        raise ValueError(message)
    encoding, errors = _encoding()
    tokens: list[str] = []
    for line in path.read_text(encoding=encoding, errors=errors).splitlines():
        nested = argfile_source(line)
        if nested is None:
            tokens.append(line)
        else:
            tokens.extend(_expand(nested, base=base, chain=(*chain, path)))
    return tokens


def read_argfile(source: str, *, base: Path) -> tuple[str, ...]:
    """Read an argfile exactly as pytest's argument parser would expand it.

    Every line is one argument, verbatim (blank lines included), and a line
    starting with ``@`` is itself an argfile reference that is expanded in
    place. Relative references resolve against ``base``, the directory pytest
    runs from.

    Args:
        source: The referenced path as written after ``@``.
        base: Directory relative references resolve against.

    Returns:
        tuple[str, ...]: The fully expanded arguments.
    """
    return tuple(_expand(source, base=base, chain=()))


def load_argfiles(spec: TestRunSpec, *, base: Path) -> dict[str, tuple[str, ...]]:
    """Read every argfile a run references.

    Args:
        spec: The run specification.
        base: Directory relative references resolve against.

    Returns:
        dict[str, tuple[str, ...]]: Expanded arguments keyed by the referenced
            path as written.
    """
    return {source: read_argfile(source, base=base) for source in dict.fromkeys(argfile_sources(spec))}


def write_argfiles(invocation: PytestInvocation, destination: Path) -> tuple[Path, ...]:
    """Write an invocation's rewritten argfiles, one argument per line.

    Args:
        invocation: The invocation whose argfiles are written.
        destination: Directory the argfiles are written into.

    Returns:
        tuple[Path, ...]: The written files, in reference order.
    """
    if not invocation.argfiles:
        return ()
    destination.mkdir(parents=True, exist_ok=True)
    encoding, errors = _encoding()
    written: list[Path] = []
    for argfile in invocation.argfiles:
        path = destination / argfile.name
        _ = path.write_text("".join(f"{token}\n" for token in argfile.tokens), encoding=encoding, errors=errors)
        written.append(path)
    return tuple(written)


def materialize_invocation(
    spec: TestRunSpec,
    *,
    base: Path,
    destination: Path,
    argfile_root: PurePath | None = None,
) -> PytestInvocation:
    """Read a run's argfiles, build its invocation, and write the rewritten argfiles.

    Args:
        spec: The run specification.
        base: Directory relative argfile references resolve against.
        destination: Host directory the rewritten argfiles are written into.
        argfile_root: The same directory as the pytest process will see it;
            defaults to the container's ``reports/tests`` directory.

    Returns:
        PytestInvocation: The invocation whose argfiles now exist on disk.
    """
    invocation = build_pytest_invocation(spec, load_argfiles(spec, base=base), argfile_root=argfile_root)
    _ = write_argfiles(invocation, destination)
    return invocation
