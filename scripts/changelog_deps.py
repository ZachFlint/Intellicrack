#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate the Markdown ``Dependency changes`` section of the project changelog.

Produces a Unity-style ``### Dependency changes`` block by diffing dependency
manifests between two git refs. Handles ``pyproject.toml`` (PEP 621
``[project].dependencies``, ``[project.optional-dependencies]``,
``[dependency-groups]``, and ``[tool.pixi]`` conda + PyPI dependency tables) and
all ``Cargo.toml`` manifests under the working tree (regular,
``[dev-dependencies]``, ``[build-dependencies]``, and target-conditional
sections).

The script is invoked by ``scripts/update-changelog.ps1`` after ``git-cliff``
regenerates ``CHANGELOG.md``. It substitutes ``<!-- DEPS:UNRELEASED -->``
markers with the rendered diff between the most recent tag and ``HEAD`` (or
between two arbitrary refs supplied via CLI).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast


_DEFAULT_PYPROJECT: Final[str] = "pyproject.toml"
_TAG_PATTERN: Final[str] = "v[0-9]*"


def _resolve_git() -> str:
    """Return the absolute path of the ``git`` executable.

    Returns:
        str: Fully-qualified path to ``git``.

    Raises:
        RuntimeError: When ``git`` is not present on ``PATH``.
    """
    resolved = shutil.which("git")
    if not resolved:
        msg = "git executable not found on PATH"
        raise RuntimeError(msg)
    return resolved


_GIT_EXE: Final[str] = _resolve_git()


@dataclass(frozen=True, slots=True)
class DepChange:
    """A single dependency-version change between two refs.

    Attributes:
        ecosystem: Short label identifying the ecosystem/section (e.g. ``"python"``,
            ``"python-optional"``, ``"pixi-conda"``, ``"pixi-pypi"``, ``"rust"``).
        name: Package or crate name.
        old_version: Version specifier at the older ref, or ``None`` if the
            dependency was added.
        new_version: Version specifier at the newer ref, or ``None`` if the
            dependency was removed.
    """

    ecosystem: str
    name: str
    old_version: str | None
    new_version: str | None


@dataclass(slots=True)
class _DiffBuckets:
    """Three-bucket grouping of :class:`DepChange` instances for rendering.

    Attributes:
        updated: Entries whose version specifier changed between the two refs.
        added: Entries newly introduced at the newer ref.
        removed: Entries dropped at the newer ref.
    """

    updated: list[DepChange] = field(default_factory=list)
    added: list[DepChange] = field(default_factory=list)
    removed: list[DepChange] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return ``True`` when no changes are present in any bucket.

        Returns:
            bool: ``True`` if all three buckets are empty, ``False`` otherwise.
        """
        return not (self.updated or self.added or self.removed)


def _run_git(args: list[str], cwd: Path, *, check: bool = True) -> str:
    """Run a ``git`` subcommand and return its stdout as text.

    Args:
        args: Subcommand and arguments (without the leading ``git``).
        cwd: Working directory in which to execute git.
        check: When ``True``, raise on non-zero exit; otherwise return ``""``.

    Returns:
        str: Captured ``stdout`` decoded as UTF-8 with stripped trailing newline.

    Raises:
        subprocess.CalledProcessError: When ``check`` is ``True`` and git exits
            non-zero.
    """
    completed = subprocess.run(
        [_GIT_EXE, *args],
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        if check:
            raise subprocess.CalledProcessError(
                completed.returncode,
                completed.args,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return ""
    return completed.stdout


def _repo_root(start: Path) -> Path:
    """Return the absolute path of the enclosing git working tree.

    Args:
        start: Any path inside (or equal to) a git working tree.

    Returns:
        Path: Absolute path to the repository root.

    Raises:
        RuntimeError: If ``start`` is not inside a git working tree.
    """
    output = _run_git(["rev-parse", "--show-toplevel"], cwd=start, check=False).strip()
    if not output:
        msg = f"Not inside a git working tree: {start}"
        raise RuntimeError(msg)
    return Path(output).resolve()


def _read_at_ref(ref: str, rel_path: str, repo_root: Path) -> str | None:
    """Read a tracked file's contents at a specific git ref.

    Args:
        ref: A git revision (commit hash, tag, branch, ``"HEAD"``).
        rel_path: Path to the file relative to ``repo_root`` using forward
            slashes.
        repo_root: Repository root path.

    Returns:
        str | None: File contents as text, or ``None`` if the path does not
        exist at ``ref``.
    """
    completed = subprocess.run(
        [_GIT_EXE, "show", f"{ref}:{rel_path}"],
        cwd=str(repo_root),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _list_tracked_files(ref: str, repo_root: Path, suffix: str) -> list[str]:
    """List tracked files matching a suffix at the given git ref.

    Args:
        ref: A git revision.
        repo_root: Repository root path.
        suffix: File-name suffix to match (e.g. ``"Cargo.toml"``).

    Returns:
        list[str]: Forward-slash relative paths of matching tracked files at
        ``ref``.
    """
    output = _run_git(["ls-tree", "-r", "--name-only", ref], cwd=repo_root, check=False)
    if not output:
        return []
    return [line for line in output.splitlines() if line.endswith(suffix)]


def _str_or_none(value: object) -> str | None:
    """Return ``value`` if it is a non-empty string, else ``None``.

    Args:
        value: The candidate value.

    Returns:
        str | None: The trimmed string, or ``None`` when not a non-empty string.
    """
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _normalize_version(spec: object) -> str:
    """Normalize a TOML dependency specifier to a comparable string.

    Args:
        spec: The raw value from a TOML table. Strings are returned trimmed.
            Mappings are reduced to their ``"version"`` key when present, else
            rendered as a sorted ``key=value`` summary.

    Returns:
        str: A short, stable string representation suitable for diffing and
        display.
    """
    if isinstance(spec, str):
        return spec.strip() or "*"
    if isinstance(spec, Mapping):
        spec_map = cast("Mapping[str, object]", spec)
        version_text = _str_or_none(spec_map.get("version"))
        if version_text is not None:
            return version_text
        path_text = _str_or_none(spec_map.get("path"))
        if path_text is not None:
            return f"path={path_text}"
        git_text = _str_or_none(spec_map.get("git"))
        if git_text is not None:
            rev_text = _str_or_none(spec_map.get("rev")) or _str_or_none(spec_map.get("tag")) or _str_or_none(spec_map.get("branch"))
            if rev_text is not None:
                return f"git={git_text}@{rev_text}"
            return f"git={git_text}"
        scalar_pairs = sorted((str(key), str(val)) for key, val in spec_map.items() if not isinstance(val, (Mapping, list)))
        rendered = ", ".join(f"{key}={val}" for key, val in scalar_pairs)
        return rendered or "*"
    return str(spec)


def _coerce_str_mapping(value: object) -> dict[str, object]:
    """Return ``value`` as a ``dict[str, object]`` if it is a mapping, else empty.

    Args:
        value: An arbitrary object pulled from parsed TOML data.

    Returns:
        dict[str, object]: A mapping with string keys preserved from ``value``,
        or an empty dict when ``value`` is not a mapping.
    """
    if not isinstance(value, Mapping):
        return {}
    value_map = cast("Mapping[object, object]", value)
    return {str(key): val for key, val in value_map.items()}


def _parse_pep621_list(deps: object) -> dict[str, str]:
    """Parse a PEP 508 dependency-string list into a name-to-spec mapping.

    Args:
        deps: A list of dependency strings (e.g. ``["psutil>=7,<8", "rich"]``).

    Returns:
        dict[str, str]: Mapping of canonical lowercase package name to its
        version spec (or ``"*"`` when no spec is given).
    """
    out: dict[str, str] = {}
    if not isinstance(deps, list):
        return out
    deps_list = cast("list[object]", deps)
    for item in deps_list:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text or text.startswith("#"):
            continue
        marker = text.split(";", 1)[0].strip()
        name = marker
        spec = "*"
        for op_idx, ch in enumerate(marker):
            if ch in "<>=!~ ":
                name = marker[:op_idx].strip()
                spec = marker[op_idx:].strip() or "*"
                break
        if "[" in name:
            name = name.split("[", 1)[0].strip()
        if name:
            out[name.lower()] = spec
    return out


def _normalize_table(table: dict[str, object]) -> dict[str, str]:
    """Render a TOML table of name-to-spec pairs as a name-to-version mapping.

    Args:
        table: Mapping of dependency name to raw TOML value.

    Returns:
        dict[str, str]: Mapping of lowercase dependency name to normalized
        version string.
    """
    return {key.lower(): _normalize_version(val) for key, val in table.items()}


def _parse_pyproject(content: str) -> dict[str, dict[str, str]]:
    """Parse a ``pyproject.toml`` document into per-section dependency maps.

    Recognised sections:

    * ``python`` - ``[project].dependencies``
    * ``python-optional:<extra>`` - ``[project.optional-dependencies].<extra>``
    * ``dependency-group:<name>`` - ``[dependency-groups].<name>``
    * ``pixi-conda`` - ``[tool.pixi].dependencies.*``
    * ``pixi-pypi`` - ``[tool.pixi].pypi-dependencies.*``
    * ``pixi-conda:<feature>`` - ``[tool.pixi.feature.<feature>].dependencies``
    * ``pixi-pypi:<feature>`` - ``[tool.pixi.feature.<feature>].pypi-dependencies``

    Args:
        content: The full text of ``pyproject.toml``.

    Returns:
        dict[str, dict[str, str]]: Mapping ``section -> {name: version}``.
        Missing sections yield empty sub-mappings rather than absent keys.
    """
    data = tomllib.loads(content)
    sections: dict[str, dict[str, str]] = {}

    project = _coerce_str_mapping(data.get("project"))
    sections["python"] = _parse_pep621_list(project.get("dependencies"))

    optional = _coerce_str_mapping(project.get("optional-dependencies"))
    for extra_name, extra_deps in optional.items():
        sections[f"python-optional:{extra_name}"] = _parse_pep621_list(extra_deps)

    groups = _coerce_str_mapping(data.get("dependency-groups"))
    for group_name, group_deps in groups.items():
        sections[f"dependency-group:{group_name}"] = _parse_pep621_list(group_deps)

    pixi = _coerce_str_mapping(_coerce_str_mapping(data.get("tool")).get("pixi"))
    sections["pixi-conda"] = _normalize_table(_coerce_str_mapping(pixi.get("dependencies")))
    sections["pixi-pypi"] = _normalize_table(_coerce_str_mapping(pixi.get("pypi-dependencies")))

    pixi_features = _coerce_str_mapping(pixi.get("feature"))
    for feat_name, feat_value in pixi_features.items():
        feat = _coerce_str_mapping(feat_value)
        feat_conda = _normalize_table(_coerce_str_mapping(feat.get("dependencies")))
        if feat_conda:
            sections[f"pixi-conda:{feat_name}"] = feat_conda
        feat_pypi = _normalize_table(_coerce_str_mapping(feat.get("pypi-dependencies")))
        if feat_pypi:
            sections[f"pixi-pypi:{feat_name}"] = feat_pypi

    return {section: deps for section, deps in sections.items() if deps}


def _parse_cargo(content: str) -> dict[str, dict[str, str]]:
    """Parse a ``Cargo.toml`` manifest into per-section crate maps.

    Recognised sections:

    * ``rust`` - top-level ``[dependencies]``
    * ``rust-dev`` - ``[dev-dependencies]``
    * ``rust-build`` - ``[build-dependencies]``
    * ``rust-target:<cfg>`` - ``[target.'<cfg>'.dependencies]``

    Args:
        content: The full text of a ``Cargo.toml`` file.

    Returns:
        dict[str, dict[str, str]]: Mapping ``section -> {name: version}``.
        Empty sections are omitted.
    """
    data = tomllib.loads(content)
    sections: dict[str, dict[str, str]] = {}

    direct = _normalize_table(_coerce_str_mapping(data.get("dependencies")))
    if direct:
        sections["rust"] = direct

    dev = _normalize_table(_coerce_str_mapping(data.get("dev-dependencies")))
    if dev:
        sections["rust-dev"] = dev

    build = _normalize_table(_coerce_str_mapping(data.get("build-dependencies")))
    if build:
        sections["rust-build"] = build

    target = _coerce_str_mapping(data.get("target"))
    for cfg_key, cfg_value in target.items():
        cfg = _coerce_str_mapping(cfg_value)
        cfg_deps = _normalize_table(_coerce_str_mapping(cfg.get("dependencies")))
        if cfg_deps:
            sections[f"rust-target:{cfg_key}"] = cfg_deps

    return sections


def _gather_pyproject_at_ref(ref: str, repo_root: Path) -> dict[str, dict[str, str]]:
    """Return parsed ``pyproject.toml`` dependency sections at ``ref``.

    Args:
        ref: A git revision.
        repo_root: Repository root path.

    Returns:
        dict[str, dict[str, str]]: Section-name to name-to-version mapping.
        Empty when the file is absent or unparseable.
    """
    content = _read_at_ref(ref, _DEFAULT_PYPROJECT, repo_root)
    if content is None:
        return {}
    try:
        return _parse_pyproject(content)
    except tomllib.TOMLDecodeError:
        return {}


def _gather_cargo_at_ref(
    ref: str,
    repo_root: Path,
) -> dict[str, dict[str, dict[str, str]]]:
    """Return parsed Cargo manifests at ``ref``, keyed by manifest path.

    Args:
        ref: A git revision.
        repo_root: Repository root path.

    Returns:
        dict[str, dict[str, dict[str, str]]]: Mapping
        ``manifest_path -> {section -> {name: version}}``.
    """
    out: dict[str, dict[str, dict[str, str]]] = {}
    for path in _list_tracked_files(ref, repo_root, "Cargo.toml"):
        if path.startswith(("vendor/", "target/", ".pixi/", "node_modules/")):
            continue
        content = _read_at_ref(ref, path, repo_root)
        if content is None:
            continue
        try:
            parsed = _parse_cargo(content)
        except tomllib.TOMLDecodeError:
            continue
        if parsed:
            out[path] = parsed
    return out


def _diff_section(
    old: dict[str, str],
    new: dict[str, str],
    ecosystem: str,
) -> list[DepChange]:
    """Compute :class:`DepChange` entries for a single ecosystem section.

    Args:
        old: Name-to-spec mapping at the older ref.
        new: Name-to-spec mapping at the newer ref.
        ecosystem: Short ecosystem label assigned to each emitted change.

    Returns:
        list[DepChange]: Combined list of updated, added, and removed entries
        (in that order).
    """
    updated_changes = [
        DepChange(ecosystem, name, old[name], new[name]) for name in sorted(old.keys() & new.keys()) if old[name] != new[name]
    ]
    added_changes = [DepChange(ecosystem, name, None, new[name]) for name in sorted(new.keys() - old.keys())]
    removed_changes = [DepChange(ecosystem, name, old[name], None) for name in sorted(old.keys() - new.keys())]
    return updated_changes + added_changes + removed_changes


def _bucket(changes: Iterable[DepChange]) -> _DiffBuckets:
    """Group a stream of :class:`DepChange` entries by mutation type.

    Args:
        changes: Iterable of dependency changes.

    Returns:
        _DiffBuckets: A populated :class:`_DiffBuckets` instance.
    """
    buckets = _DiffBuckets()
    for change in changes:
        if change.old_version is None and change.new_version is not None:
            buckets.added.append(change)
        elif change.new_version is None and change.old_version is not None:
            buckets.removed.append(change)
        elif change.old_version != change.new_version:
            buckets.updated.append(change)
    return buckets


def _format_change_line(change: DepChange) -> str:
    """Render a single :class:`DepChange` as a Markdown bullet.

    Args:
        change: The dependency change to render.

    Returns:
        str: Bullet text (no leading ``- ``) suitable for the ``Updated``,
        ``Added``, or ``Removed`` subsections.
    """
    if change.old_version is None and change.new_version is not None:
        return f"**{change.ecosystem}:** {change.name}: {change.new_version}"
    if change.new_version is None and change.old_version is not None:
        return f"**{change.ecosystem}:** {change.name} (was {change.old_version})"
    return f"**{change.ecosystem}:** {change.name}: {change.old_version} to {change.new_version}"


def _emit_subsection(
    title: str,
    changes: list[DepChange],
    lines: list[str],
) -> None:
    """Append a Markdown subsection to ``lines`` if ``changes`` is non-empty.

    Args:
        title: Subsection heading text (e.g. ``"Updated"``).
        changes: Entries to render underneath the heading.
        lines: Output buffer to which heading and bullets are appended.
    """
    if not changes:
        return
    lines.extend((f"#### {title}", ""))
    lines.extend(f"- {_format_change_line(change)}" for change in changes)
    lines.append("")


def _render_section(buckets: _DiffBuckets) -> str:
    """Render the full Markdown ``Dependency changes`` section.

    Args:
        buckets: Pre-grouped diff entries.

    Returns:
        str: Multi-line Markdown text terminated by a single trailing newline.
        An empty string is returned when ``buckets`` contains nothing.
    """
    if buckets.is_empty():
        return ""
    lines: list[str] = ["### Dependency changes", ""]
    _emit_subsection("Updated", buckets.updated, lines)
    _emit_subsection("Added", buckets.added, lines)
    _emit_subsection("Removed", buckets.removed, lines)
    return "\n".join(lines).rstrip() + "\n"


def _last_tag(repo_root: Path, pattern: str = _TAG_PATTERN) -> str | None:
    """Return the most recent annotated/lightweight tag matching ``pattern``.

    Args:
        repo_root: Repository root path.
        pattern: Glob expression passed to ``git tag --list``.

    Returns:
        str | None: The tag name (e.g. ``"v1.2.0"``) or ``None`` when no
        matching tag exists in the repository.
    """
    output = _run_git(
        ["tag", "--list", pattern, "--sort=-v:refname"],
        cwd=repo_root,
        check=False,
    )
    if not output.strip():
        return None
    first_line = output.splitlines()[0].strip()
    return first_line or None


def _ref_exists(ref: str, repo_root: Path) -> bool:
    """Return whether a given ref resolves in the repository.

    Args:
        ref: The git revision to verify.
        repo_root: Repository root path.

    Returns:
        bool: ``True`` when ``ref`` resolves, ``False`` otherwise.
    """
    output = _run_git(
        ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        cwd=repo_root,
        check=False,
    )
    return bool(output.strip())


def compute_diff(from_ref: str, to_ref: str, repo_root: Path) -> _DiffBuckets:
    """Compute the full set of dependency changes between two refs.

    Args:
        from_ref: The older revision (baseline).
        to_ref: The newer revision (target).
        repo_root: Repository root path.

    Returns:
        _DiffBuckets: A :class:`_DiffBuckets` containing every recognised
        dependency change across the Python and Rust ecosystems.
    """
    changes: list[DepChange] = []

    old_py = _gather_pyproject_at_ref(from_ref, repo_root)
    new_py = _gather_pyproject_at_ref(to_ref, repo_root)
    py_sections = sorted(set(old_py) | set(new_py))
    for section in py_sections:
        changes.extend(
            _diff_section(old_py.get(section, {}), new_py.get(section, {}), section),
        )

    old_rust = _gather_cargo_at_ref(from_ref, repo_root)
    new_rust = _gather_cargo_at_ref(to_ref, repo_root)
    cargo_paths = sorted(set(old_rust) | set(new_rust))
    for cargo_path in cargo_paths:
        old_manifest = old_rust.get(cargo_path, {})
        new_manifest = new_rust.get(cargo_path, {})
        sections = sorted(set(old_manifest) | set(new_manifest))
        crate_label = Path(cargo_path).parent.name or "workspace"
        for section in sections:
            ecosystem = f"{section} ({crate_label})"
            changes.extend(
                _diff_section(
                    old_manifest.get(section, {}),
                    new_manifest.get(section, {}),
                    ecosystem,
                ),
            )

    return _bucket(changes)


def render(from_ref: str, to_ref: str, repo_root: Path) -> str:
    """Render the dependency-changes section between two refs.

    Args:
        from_ref: The older revision (baseline).
        to_ref: The newer revision (target).
        repo_root: Repository root path.

    Returns:
        str: Markdown text (terminated by a newline) or an empty string when
        there are no changes.
    """
    buckets = compute_diff(from_ref, to_ref, repo_root)
    return _render_section(buckets)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser.

    Returns:
        argparse.ArgumentParser: Configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description=("Emit a Markdown 'Dependency changes' section by diffing manifests between two git refs."),
    )
    parser.add_argument(
        "--from",
        dest="from_ref",
        default=None,
        help="Older git revision (default: most recent v* tag, if any).",
    )
    parser.add_argument(
        "--to",
        dest="to_ref",
        default="HEAD",
        help="Newer git revision (default: HEAD).",
    )
    parser.add_argument(
        "--repo",
        dest="repo",
        default=".",
        help="Path inside the repository (default: current directory).",
    )
    parser.add_argument(
        "--allow-no-tag",
        action="store_true",
        help=("When --from is not supplied and no v* tag exists, fall back to the first commit instead of producing empty output."),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: Command-line arguments (excluding the program name). When
            ``None``, ``sys.argv[1:]`` is used.

    Returns:
        int: Process exit code (``0`` on success).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    repo_root = _repo_root(Path(cast("str", args.repo)).resolve())
    to_ref = cast("str", args.to_ref)
    from_ref_arg = cast("str | None", args.from_ref)
    allow_no_tag = bool(args.allow_no_tag)

    from_ref = from_ref_arg
    if from_ref is None:
        from_ref = _last_tag(repo_root)
        if from_ref is None:
            if not allow_no_tag:
                return 0
            first_commit = _run_git(
                ["rev-list", "--max-parents=0", to_ref],
                cwd=repo_root,
                check=False,
            ).strip()
            if not first_commit:
                return 0
            from_ref = first_commit.splitlines()[0]

    if not _ref_exists(from_ref, repo_root):
        return 0
    if not _ref_exists(to_ref, repo_root):
        return 0

    rendered = render(from_ref, to_ref, repo_root)
    if rendered:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
