# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable gates on the ``.pre-commit-config.yaml`` hook pins.

The pre-commit framework is only useful while the ruff it downloads can read the
project's own ruff configuration. That contract silently broke once already: the
config pinned ``astral-sh/ruff-pre-commit`` at ``v0.12.11`` while
``[tool.ruff] lint.ignore`` in ``pyproject.toml`` grew a selector that only ruff
0.16+ understands, so both the ``ruff-check`` and ``ruff-format`` hooks aborted
with ``Unknown rule selector`` on every run. Nothing caught it because commits go
through ``--no-verify``.

These gates hold the contract from both directions:

* the pinned rev must name the same ruff version as the pixi toolchain, so the
  hook and ``just lint`` can never disagree about which rules exist;
* that pinned ruff must actually load ``pyproject.toml`` -- the real failure mode,
  reproduced by running the binary rather than by re-deriving its parser;
* the ``mixed-line-ending`` hook must not rewrite the files ``.gitattributes``
  keeps at LF, or the fixer and git fight over every run.

``.pre-commit-config.yaml``, ``.gitattributes``, ``pyproject.toml`` and the pixi
environment are all outside the test container's mounts, so these run in the
host-native pass.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

import pytest
import yaml


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_PRECOMMIT_CONFIG: Final[Path] = _REPO_ROOT / ".pre-commit-config.yaml"
_GITATTRIBUTES: Final[Path] = _REPO_ROOT / ".gitattributes"
_PIXI_RUFF: Final[Path] = _REPO_ROOT / ".pixi" / "envs" / "default" / "Scripts" / "ruff.exe"
# Any tracked, ruff-clean source file works; ruff must load pyproject.toml to
# lint it, which is the behaviour under test.
_PROBE_SOURCE: Final[Path] = Path("scripts") / "clean_nul.py"

_RUFF_REPO: Final[str] = "https://github.com/astral-sh/ruff-pre-commit"
_PRECOMMIT_HOOKS_REPO: Final[str] = "https://github.com/pre-commit/pre-commit-hooks"

# ruff exits 2 when it cannot start work at all -- an unreadable or unparseable
# configuration file included. Exit 0/1 mean "ran, found nothing / found lint".
_RUFF_ERROR_EXIT: Final[int] = 2

_VERSION_LINE: Final[re.Pattern[str]] = re.compile(r"^ruff\s+(\S+)$")
# ``.gitattributes`` lines such as ``.envrc text eol=lf`` / ``*.sh   text eol=lf``.
_EOL_LF_RULE: Final[re.Pattern[str]] = re.compile(r"^(?P<pattern>\S+)\s+.*\beol=lf\b")

_SUBPROCESS_TIMEOUT: Final[int] = 300


def _as_mapping(value: object, what: str) -> Mapping[str, object]:
    """Narrow a decoded YAML *value* to a mapping.

    Args:
        value: Decoded YAML node.
        what: Human-readable name used in the failure message.

    Returns:
        Mapping[str, object]: The same node, typed as a mapping.
    """
    assert isinstance(value, Mapping), f"{what} must be a mapping, got {type(value).__name__}"
    return cast("Mapping[str, object]", value)


def _as_sequence(value: object, what: str) -> Sequence[object]:
    """Narrow a decoded YAML *value* to a list.

    Args:
        value: Decoded YAML node.
        what: Human-readable name used in the failure message.

    Returns:
        Sequence[object]: The same node, typed as a sequence.
    """
    assert isinstance(value, list), f"{what} must be a list, got {type(value).__name__}"
    return cast("Sequence[object]", value)


def _load_precommit_config() -> Mapping[str, object]:
    """Parse ``.pre-commit-config.yaml``.

    Returns:
        Mapping[str, object]: The decoded configuration document.
    """
    with _PRECOMMIT_CONFIG.open(encoding="utf-8") as handle:
        loaded: object = yaml.safe_load(handle)
    return _as_mapping(loaded, str(_PRECOMMIT_CONFIG))


def _repo_entry(url: str) -> Mapping[str, object]:
    """Return the single ``repos:`` entry declaring *url*.

    Args:
        url: Repository URL to look up.

    Returns:
        Mapping[str, object]: The matching repository entry.
    """
    repos = _as_sequence(_load_precommit_config()["repos"], "'repos'")
    entries = [_as_mapping(item, "'repos' entry") for item in repos]
    matches = [entry for entry in entries if entry.get("repo") == url]
    assert len(matches) == 1, f"expected exactly one {url} entry, found {len(matches)}"
    return matches[0]


def _pinned_ruff_version() -> str:
    """Return the ruff version named by the ``ruff-pre-commit`` ``rev`` pin.

    Returns:
        str: The version string, e.g. ``"0.16.4"`` for a ``v0.16.4`` rev.
    """
    rev = _repo_entry(_RUFF_REPO)["rev"]
    assert isinstance(rev, str), "ruff-pre-commit 'rev' must be a string"
    assert rev.startswith("v"), f"expected a vX.Y.Z ruff pin, got {rev!r}"
    return rev[1:]


def _executable_version(executable: Path) -> str:
    """Return the version reported by a ruff *executable*.

    Args:
        executable: Path to a ``ruff`` binary.

    Returns:
        str: The reported version, e.g. ``"0.16.4"``.
    """
    completed = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    match = _VERSION_LINE.match(completed.stdout.strip())
    assert match is not None, f"unexpected `ruff --version` output: {completed.stdout!r}"
    return match.group(1)


def _candidate_ruff_executables() -> list[Path]:
    """Return every ruff binary reachable from this checkout.

    The pinned hook's ruff lives in the pre-commit cache; the toolchain ruff
    lives in the pixi environment. The cache is searched first so the gate
    exercises the genuinely pinned build whenever the hook has been installed.

    Returns:
        list[Path]: Existing ruff executables, pre-commit cache entries first.
    """
    relative_names = ("Scripts/ruff.exe", "bin/ruff")
    cache_roots: list[Path] = []
    configured_home = os.environ.get("PRE_COMMIT_HOME")
    if configured_home:
        cache_roots.append(Path(configured_home))
    cache_roots.append(Path.home() / ".cache" / "pre-commit")

    candidates: list[Path] = []
    for root in cache_roots:
        if not root.is_dir():
            continue
        for repo_dir in sorted(root.glob("repo*")):
            for env_dir in sorted(repo_dir.glob("py_env-*")):
                candidates.extend(env_dir / name for name in relative_names)
    candidates.append(_PIXI_RUFF)
    return [path for path in candidates if path.is_file()]


def _ruff_of_version(version: str) -> Path:
    """Return a ruff executable reporting exactly *version*.

    Args:
        version: The required ruff version, e.g. ``"0.16.4"``.

    Returns:
        Path: The matching executable.
    """
    candidates = _candidate_ruff_executables()
    assert candidates, "no ruff executable found in the pre-commit cache or the pixi environment"
    seen: list[str] = []
    for candidate in candidates:
        found = _executable_version(candidate)
        seen.append(f"{found} ({candidate})")
        if found == version:
            return candidate
    pytest.fail(f"no ruff {version} available; found: {', '.join(seen)}")


def test_pinned_ruff_matches_the_pixi_toolchain_version() -> None:
    """The hook's ruff and the project's ruff must be the same version.

    A pin that drifts from the toolchain lets ``just lint`` accept a
    ``[tool.ruff]`` configuration the hook cannot even parse.
    """
    assert _PIXI_RUFF.is_file(), f"pixi ruff missing at {_PIXI_RUFF}"
    pinned = _pinned_ruff_version()
    toolchain = _executable_version(_PIXI_RUFF)
    assert pinned == toolchain, (
        f".pre-commit-config.yaml pins ruff {pinned} but the pixi toolchain is ruff {toolchain}; "
        f"selectors valid for one can be unknown to the other"
    )


def _assert_config_loads_cleanly(argv: list[str], what: str) -> None:
    """Run a pinned-ruff *argv* from the repo root and assert the config loaded.

    ``--quiet`` is deliberately not passed: ruff 0.16 demotes an unknown
    selector in ``ignore``/``per-file-ignores`` to a warning that ``--quiet``
    would swallow, while ruff 0.12 aborted outright. Reading the unfiltered
    output catches both shapes.

    Args:
        argv: Full ruff command line to execute.
        what: Human-readable name of the invocation, used in failure messages.
    """
    completed = subprocess.run(
        argv,
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    combined = completed.stdout + completed.stderr
    assert completed.returncode != _RUFF_ERROR_EXIT, f"{what} could not run:\n{combined}"
    assert "Failed to parse" not in combined, f"{what} rejected the project configuration:\n{combined}"
    assert "Unknown rule selector" not in combined, f"{what} does not know a configured selector:\n{combined}"


def test_the_pinned_ruff_can_parse_the_project_ruff_configuration() -> None:
    """The pinned ruff must load ``[tool.ruff]`` from ``pyproject.toml``.

    This runs the pinned binary against a real source file from the repository
    root, so it fails exactly the way the framework failed: a selector in
    ``lint.select`` / ``lint.ignore`` / ``lint.unfixable`` /
    ``lint.per-file-ignores`` that the pinned build does not know either aborts
    ruff with exit 2 or is reported as an unknown-selector warning.
    """
    assert (_REPO_ROOT / _PROBE_SOURCE).is_file(), f"probe file {_PROBE_SOURCE} is missing"
    ruff = _ruff_of_version(_pinned_ruff_version())
    _assert_config_loads_cleanly(
        [str(ruff), "check", "--no-cache", str(_PROBE_SOURCE)],
        "pinned ruff check",
    )


def test_the_pinned_ruff_formatter_can_parse_the_project_ruff_configuration() -> None:
    """The ``ruff-format`` hook loads the same config and must survive it too.

    ``ruff format`` reads ``[tool.ruff]`` in full, so a selector the pinned build
    does not know kills the formatter hook as well as the linter hook.
    """
    ruff = _ruff_of_version(_pinned_ruff_version())
    _assert_config_loads_cleanly(
        [str(ruff), "format", "--check", "--no-cache", str(_PROBE_SOURCE)],
        "pinned ruff format",
    )


def _lf_only_patterns() -> set[str]:
    """Return the ``.gitattributes`` path patterns pinned to LF endings.

    Returns:
        set[str]: Patterns such as ``".envrc"`` and ``"*.sh"``.
    """
    patterns: set[str] = set()
    for raw in _GITATTRIBUTES.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _EOL_LF_RULE.match(line)
        if match is not None:
            patterns.add(match.group("pattern"))
    return patterns


def test_mixed_line_ending_hook_skips_every_lf_only_path() -> None:
    """``mixed-line-ending --fix=crlf`` must not touch LF-pinned paths.

    ``.gitattributes`` keeps ``.envrc`` and ``*.sh`` at LF because a trailing CR
    breaks direnv and bash. Without a matching exclude the fixer rewrites them to
    CRLF on every run while git converts them straight back, so the hook can
    never reach a stable state.
    """
    hooks = _as_sequence(_repo_entry(_PRECOMMIT_HOOKS_REPO)["hooks"], "'hooks'")
    entries = [_as_mapping(item, "'hooks' entry") for item in hooks]
    hook = next(entry for entry in entries if entry.get("id") == "mixed-line-ending")
    args = hook.get("args")
    assert args == ["--fix=crlf"], f"unexpected mixed-line-ending args: {args!r}"

    exclude = hook.get("exclude")
    assert isinstance(exclude, str), "mixed-line-ending 'exclude' must be a string"
    assert exclude, "mixed-line-ending must declare an exclude pattern"
    excluded = re.compile(exclude)

    lf_patterns = _lf_only_patterns()
    assert lf_patterns, ".gitattributes declares no eol=lf rules; this gate has gone vacuous"

    for pattern in lf_patterns:
        sample = f"example{pattern[1:]}" if pattern.startswith("*") else pattern
        assert excluded.search(sample) is not None, (
            f"mixed-line-ending exclude {exclude!r} does not cover {sample!r}, which .gitattributes pins to eol=lf"
        )
