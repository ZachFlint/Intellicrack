# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates on ``scripts/git-push.ps1`` and ``scripts/git-rebase.ps1``.

``just git-commit`` pushes through ``git-push.ps1``. When ``origin`` has moved
ahead (dependabot auto-merges do this), the script rebases the commit it just
made onto the new remote tip and pushes again. It must do that for the
out-of-date rejection only: a conflict, a dirty working tree or any other push
failure must stop with the local commit exactly as it was.

``git-rebase.ps1`` used to exit on a failed rebase without aborting it when
nothing had been stashed, leaving the repository stuck mid-rebase.

Every gate builds a real bare ``origin``, a local clone and a second clone that
pushes competing work, then runs the real script with ``pwsh``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from collections.abc import Mapping

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_PUSH_SCRIPT: Final[Path] = _REPO_ROOT / "scripts" / "git-push.ps1"
_REBASE_SCRIPT: Final[Path] = _REPO_ROOT / "scripts" / "git-rebase.ps1"
_GIT: Final[str | None] = shutil.which("git")
_PWSH: Final[str | None] = shutil.which("pwsh")
_TIMEOUT_S: Final[int] = 180


@dataclass(frozen=True, slots=True)
class Topology:
    """A bare origin with two working clones sharing one isolated git config.

    Attributes:
        origin: Bare repository acting as ``origin``.
        local: Clone that runs the script under test.
        other: Clone that pushes competing commits to ``origin``.
        env: Environment isolating git from the host configuration.
    """

    origin: Path
    local: Path
    other: Path
    env: dict[str, str]


def _git(cwd: Path, env: Mapping[str, str], *args: str, check: bool = True) -> str:
    """Run git in *cwd* and return its standard output.

    Args:
        cwd: Working directory.
        env: Environment for the subprocess.
        *args: Arguments passed after ``git``.
        check: Raise when git exits non-zero.

    Returns:
        str: Standard output with surrounding whitespace removed.
    """
    assert _GIT is not None, "git is not on PATH"
    completed = subprocess.run(
        [_GIT, *args],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=check,
        timeout=_TIMEOUT_S,
    )
    return completed.stdout.strip()


def _run_ps1(script: Path, cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a repository PowerShell script the way ``just`` does.

    Args:
        script: Script to execute.
        cwd: Repository the script operates on.
        env: Environment for the subprocess.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    assert _PWSH is not None, "pwsh is not on PATH"
    return subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TIMEOUT_S,
    )


def _commit_file(repo: Path, env: Mapping[str, str], name: str, content: str, message: str) -> str:
    """Write *name*, commit it and return the new commit hash.

    Args:
        repo: Working clone.
        env: Environment for git.
        name: File to write.
        content: File content.
        message: Commit message.

    Returns:
        str: The new commit's full hash.
    """
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, env, "add", name)
    _git(repo, env, "commit", "--quiet", "--no-gpg-sign", "-m", message)
    return _git(repo, env, "rev-parse", "HEAD")


def _rebase_in_progress(repo: Path) -> bool:
    """Report whether *repo* is stopped in the middle of a rebase.

    Args:
        repo: Working clone.

    Returns:
        bool: ``True`` when a rebase state directory exists.
    """
    git_dir = repo / ".git"
    return (git_dir / "rebase-merge").exists() or (git_dir / "rebase-apply").exists()


@pytest.fixture
def topology(tmp_path: Path) -> Topology:
    """Create origin, a local clone and a competing clone, all on ``main``.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Topology: The three repositories and their environment.
    """
    config = tmp_path / "gitconfig"
    config.write_text("[init]\n\tdefaultBranch = main\n", encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(config),
        "GIT_AUTHOR_NAME": "Test Human",
        "GIT_AUTHOR_EMAIL": "human@example.org",
        "GIT_COMMITTER_NAME": "Test Human",
        "GIT_COMMITTER_EMAIL": "human@example.org",
        "GIT_TERMINAL_PROMPT": "0",
    })
    origin = tmp_path / "origin.git"
    _git(tmp_path, env, "init", "--quiet", "--bare", str(origin))
    seed = tmp_path / "seed"
    _git(tmp_path, env, "clone", "--quiet", str(origin), str(seed))
    _commit_file(seed, env, "shared.txt", "base\n", "initial")
    _git(seed, env, "push", "--quiet", "origin", "main")
    local = tmp_path / "local"
    other = tmp_path / "other"
    _git(tmp_path, env, "clone", "--quiet", str(origin), str(local))
    _git(tmp_path, env, "clone", "--quiet", str(origin), str(other))
    return Topology(origin=origin, local=local, other=other, env=env)


def test_push_rebases_and_retries_when_origin_moved(topology: Topology) -> None:
    """An out-of-date rejection is rebased and pushed; both commits reach origin."""
    remote_commit = _commit_file(topology.other, topology.env, "theirs.txt", "theirs\n", "remote work")
    _git(topology.other, topology.env, "push", "--quiet", "origin", "main")
    _commit_file(topology.local, topology.env, "mine.txt", "mine\n", "local work")

    result = _run_ps1(_PUSH_SCRIPT, topology.local, topology.env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "rebasing onto it (attempt 1 of 2)" in result.stdout
    origin_tip = _git(topology.origin, topology.env, "rev-parse", "main")
    assert origin_tip == _git(topology.local, topology.env, "rev-parse", "HEAD")
    assert _git(topology.origin, topology.env, "rev-parse", "main~1") == remote_commit
    assert _git(topology.origin, topology.env, "log", "-1", "--format=%s", "main") == "local work"


def test_push_conflict_aborts_and_leaves_the_commit_untouched(topology: Topology) -> None:
    """Both sides editing one file stops the retry with the commit exactly as it was."""
    remote_tip = _commit_file(topology.other, topology.env, "shared.txt", "theirs\n", "remote edit")
    _git(topology.other, topology.env, "push", "--quiet", "origin", "main")
    local_commit = _commit_file(topology.local, topology.env, "shared.txt", "mine\n", "local edit")

    result = _run_ps1(_PUSH_SCRIPT, topology.local, topology.env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "Rebase conflicts in: shared.txt" in result.stdout
    assert "Rebase aborted; your commit is unchanged" in result.stdout
    assert not _rebase_in_progress(topology.local)
    assert _git(topology.local, topology.env, "rev-parse", "HEAD") == local_commit
    assert (topology.local / "shared.txt").read_text(encoding="utf-8") == "mine\n"
    assert _git(topology.origin, topology.env, "rev-parse", "main") == remote_tip


def test_other_push_failures_are_not_retried(topology: Topology) -> None:
    """A server-side rejection fails at once, with no fetch or rebase attempted."""
    hook = topology.origin / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'policy says no' >&2\nexit 1\n", encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    local_commit = _commit_file(topology.local, topology.env, "mine.txt", "mine\n", "local work")
    origin_before = _git(topology.origin, topology.env, "rev-parse", "main")

    result = _run_ps1(_PUSH_SCRIPT, topology.local, topology.env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "[remote rejected]" in result.stdout
    assert "rebasing onto it" not in result.stdout
    assert "Push failed" in result.stdout
    assert _git(topology.local, topology.env, "rev-parse", "HEAD") == local_commit
    assert _git(topology.origin, topology.env, "rev-parse", "main") == origin_before


def test_dirty_working_tree_blocks_the_automatic_rebase(topology: Topology) -> None:
    """Uncommitted changes stop the retry instead of being stashed or lost."""
    _commit_file(topology.other, topology.env, "theirs.txt", "theirs\n", "remote work")
    _git(topology.other, topology.env, "push", "--quiet", "origin", "main")
    local_commit = _commit_file(topology.local, topology.env, "mine.txt", "mine\n", "local work")
    (topology.local / "mine.txt").write_text("edited after commit\n", encoding="utf-8")

    result = _run_ps1(_PUSH_SCRIPT, topology.local, topology.env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "Working tree has uncommitted changes; not rebasing automatically" in result.stdout
    assert _git(topology.local, topology.env, "rev-parse", "HEAD") == local_commit
    assert (topology.local / "mine.txt").read_text(encoding="utf-8") == "edited after commit\n"
    assert not _git(topology.local, topology.env, "stash", "list")


def test_git_rebase_recipe_aborts_a_conflicting_rebase_with_a_clean_tree(topology: Topology) -> None:
    """``just git-rebase`` no longer leaves the repository stuck mid-rebase."""
    _commit_file(topology.other, topology.env, "shared.txt", "theirs\n", "remote edit")
    _git(topology.other, topology.env, "push", "--quiet", "origin", "main")
    local_commit = _commit_file(topology.local, topology.env, "shared.txt", "mine\n", "local edit")

    result = _run_ps1(_REBASE_SCRIPT, topology.local, topology.env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "Rebase aborted; local commits unchanged" in result.stdout
    assert not _rebase_in_progress(topology.local)
    assert _git(topology.local, topology.env, "rev-parse", "HEAD") == local_commit
