# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates on ``scripts/check_claude_attribution.py`` and its wiring.

Claude attribution reached the history three ways: ``Co-Authored-By: Claude``
trailers, ``Claude-Session:`` links, and whole commits authored as
``Claude <noreply@anthropic.com>`` by cloud sessions. Every gate here builds
real git repositories and real commits, drives the script as git and CI do, and
reads the result back out of git.

The last gates pin the wiring: the pre-commit framework must install the
``commit-msg`` hook, CI must run the scan on pushes and pull requests, and the
repository's own history must stay clean.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

import pytest
import yaml


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SCRIPT: Final[Path] = _REPO_ROOT / "scripts" / "check_claude_attribution.py"
_PRECOMMIT_CONFIG: Final[Path] = _REPO_ROOT / ".pre-commit-config.yaml"
_WORKFLOW: Final[Path] = _REPO_ROOT / ".github" / "workflows" / "claude-attribution.yml"
_TIMEOUT_S: Final[int] = 120
_GIT: Final[str | None] = shutil.which("git")

_HUMAN_NAME: Final[str] = "Test Human"
_HUMAN_EMAIL: Final[str] = "human@example.org"
_CLAUDE_NAME: Final[str] = "Claude"
_CLAUDE_EMAIL: Final[str] = "noreply@anthropic.com"

_CLAUDE_TRAILER: Final[str] = "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
_SESSION_TRAILER: Final[str] = "Claude-Session: https://claude.ai/code/session_01Ua6MzmeNSKAJAoSzEo838e"
_BARE_SESSION_TRAILER: Final[str] = "Claude-Session: 01Ua6MzmeNSKAJAoSzEo838e"
_HUMAN_TRAILER: Final[str] = "Co-authored-by: Other Person <other@example.org>"
_SIGNOFF_TRAILER: Final[str] = "Signed-off-by: Test Human <human@example.org>"


def _git_env(home: Path, author_name: str = _HUMAN_NAME, author_email: str = _HUMAN_EMAIL) -> dict[str, str]:
    """Build an environment that isolates git from the host's configuration.

    Args:
        home: Directory holding the empty global configuration file.
        author_name: Author and committer name.
        author_email: Author and committer e-mail address.

    Returns:
        dict[str, str]: The environment for git subprocesses.
    """
    global_config = home / "gitconfig"
    global_config.touch()
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(global_config),
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
        "GIT_COMMITTER_NAME": author_name,
        "GIT_COMMITTER_EMAIL": author_email,
    })
    return env


def _git(repo: Path, env: Mapping[str, str], *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run git inside *repo*.

    Args:
        repo: Repository working directory.
        env: Environment for the subprocess.
        *args: Arguments passed after ``git``.
        check: Raise when git exits non-zero.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    assert _GIT is not None, "git is not on PATH"
    return subprocess.run(
        [_GIT, *args],
        cwd=repo,
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=check,
        timeout=_TIMEOUT_S,
    )


def _run_script(cwd: Path, env: Mapping[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    """Run the attribution script the way CI and the hook do.

    Args:
        cwd: Working directory (the repository under test).
        env: Environment for the subprocess.
        *args: Script arguments.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=_TIMEOUT_S,
    )


def _commit(repo: Path, env: Mapping[str, str], filename: str, message: str) -> str:
    """Create a commit touching *filename* and return its hash.

    Args:
        repo: Repository working directory.
        env: Environment carrying the author identity.
        filename: File to create in the commit.
        message: Full commit message.

    Returns:
        str: The new commit's full hash.
    """
    (repo / filename).write_text(f"{filename}\n", encoding="utf-8")
    _git(repo, env, "add", filename)
    _git(repo, env, "commit", "--quiet", "--no-gpg-sign", "-m", message)
    return _git(repo, env, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """Create an empty repository with an isolated git configuration.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        tuple[Path, dict[str, str]]: The repository path and its environment.
    """
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    env = _git_env(home)
    _git(work, env, "init", "--quiet", "--initial-branch=main")
    return work, env


def _install_commit_msg_hook(repo: Path, env: Mapping[str, str]) -> None:
    """Install the script as the repository's real ``commit-msg`` hook.

    Args:
        repo: Repository working directory.
        env: Environment for git.
    """
    hooks = repo / ".hooks"
    hooks.mkdir()
    python = Path(sys.executable).as_posix()
    script = _SCRIPT.as_posix()
    hook = hooks / "commit-msg"
    hook.write_text(f'#!/bin/sh\nexec "{python}" "{script}" commit-msg "$1"\n', encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    _git(repo, env, "config", "core.hooksPath", ".hooks")


def test_range_flags_claude_trailers_and_sessions_but_not_clean_commits(repo: tuple[Path, dict[str, str]]) -> None:
    """A trailer or session link fails the scan and names only its commit."""
    work, env = repo
    clean = _commit(work, env, "a.txt", f"feat: clean change\n\n{_HUMAN_TRAILER}\n{_SIGNOFF_TRAILER}")
    tainted = _commit(work, env, "b.txt", f"fix: tainted change\n\n{_CLAUDE_TRAILER}\n{_SESSION_TRAILER}")

    result = _run_script(work, env, "range", "HEAD")

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{tainted[:12]}  message line: {_CLAUDE_TRAILER}" in result.stdout
    assert f"{tainted[:12]}  message line: {_SESSION_TRAILER}" in result.stdout
    assert clean[:12] not in result.stdout
    assert "2 Claude attribution finding(s) in 1 commit(s)" in result.stdout


def test_range_flags_commits_authored_as_claude(tmp_path: Path, repo: tuple[Path, dict[str, str]]) -> None:
    """A commit made under Claude's identity fails even with a clean message."""
    work, env = repo
    _commit(work, env, "a.txt", "feat: human change")
    claude_env = _git_env(tmp_path / "home", _CLAUDE_NAME, _CLAUDE_EMAIL)
    claude_commit = _commit(work, claude_env, "b.txt", "fix: change made by a cloud session")

    result = _run_script(work, env, "range", "HEAD")

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{claude_commit[:12]}  author is {_CLAUDE_NAME} <{_CLAUDE_EMAIL}>" in result.stdout
    assert f"{claude_commit[:12]}  committer is {_CLAUDE_NAME} <{_CLAUDE_EMAIL}>" in result.stdout


def test_range_honours_not_so_ci_scans_only_new_commits(repo: tuple[Path, dict[str, str]]) -> None:
    """``--not base`` excludes history the branch did not add, as CI passes it."""
    work, env = repo
    _commit(work, env, "a.txt", f"old: already on main\n\n{_CLAUDE_TRAILER}")
    _git(work, env, "branch", "base")
    _commit(work, env, "b.txt", "feat: new clean work")

    new_only = _run_script(work, env, "range", "HEAD", "--not", "base")
    whole = _run_script(work, env, "range", "HEAD")

    assert new_only.returncode == 0, new_only.stdout + new_only.stderr
    assert whole.returncode == 1, whole.stdout + whole.stderr


def test_commit_msg_hook_strips_claude_lines_and_keeps_everything_else(repo: tuple[Path, dict[str, str]]) -> None:
    """A real ``git commit`` through the hook lands without Claude attribution.

    The human co-author and sign-off trailers, and a body line that merely
    mentions the Anthropic provider, must survive unchanged.
    """
    work, env = repo
    _install_commit_msg_hook(work, env)
    body = "Route the Anthropic provider through the capability layer."
    message = (
        f"fix(providers): route capabilities\n\n{body}\n\n"
        f"{_HUMAN_TRAILER}\n{_CLAUDE_TRAILER}\n{_SESSION_TRAILER}\n{_BARE_SESSION_TRAILER}\n{_SIGNOFF_TRAILER}\n"
        "\nGenerated with [Claude Code](https://claude.com/claude-code)\n"
    )
    _commit(work, env, "a.txt", message)

    recorded = _git(work, env, "log", "-1", "--format=%B").stdout

    assert "anthropic.com" not in recorded
    assert "Claude" not in recorded
    assert recorded.startswith("fix(providers): route capabilities\n\n")
    assert body in recorded
    assert _HUMAN_TRAILER in recorded
    assert _SIGNOFF_TRAILER in recorded
    assert _run_script(work, env, "range", "HEAD").returncode == 0


def test_commit_msg_hook_refuses_a_claude_identity(tmp_path: Path, repo: tuple[Path, dict[str, str]]) -> None:
    """The hook refuses a commit whose author is Claude, so none is created."""
    work, env = repo
    _install_commit_msg_hook(work, env)
    _commit(work, env, "a.txt", "feat: first")
    before = _git(work, env, "rev-parse", "HEAD").stdout.strip()

    claude_env = _git_env(tmp_path / "home", _CLAUDE_NAME, _CLAUDE_EMAIL)
    (work / "b.txt").write_text("b\n", encoding="utf-8")
    _git(work, claude_env, "add", "b.txt")
    refused = _git(work, claude_env, "commit", "--no-gpg-sign", "-m", "fix: from a session", check=False)

    assert refused.returncode != 0
    assert "commit refused: GIT_AUTHOR_IDENT" in refused.stderr
    assert _git(work, env, "rev-parse", "HEAD").stdout.strip() == before


def test_text_mode_flags_pull_request_footers_only(tmp_path: Path, repo: tuple[Path, dict[str, str]]) -> None:
    """A pull request body with a Claude Code footer fails; provider prose passes."""
    work, env = repo
    tainted = tmp_path / "tainted.md"
    tainted.write_text(
        "## Description\n\nFixes the Anthropic provider.\n\n"
        "Generated with [Claude Code](https://claude.com/claude-code)\n\n"
        "https://claude.ai/code/session_01Ua6MzmeNSKAJAoSzEo838e\n",
        encoding="utf-8",
    )
    clean = tmp_path / "clean.md"
    clean.write_text("## Description\n\nFixes the Anthropic provider and the claude.yml workflow.\n", encoding="utf-8")

    flagged = _run_script(work, env, "text", str(tainted))
    passed = _run_script(work, env, "text", str(clean))

    assert flagged.returncode == 1
    assert flagged.stdout.count("tainted.md: ") == 2
    assert passed.returncode == 0, passed.stdout


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


def test_precommit_installs_the_commit_msg_hook() -> None:
    """``pre-commit install`` must install the hook at the ``commit-msg`` stage."""
    config = _as_mapping(yaml.safe_load(_PRECOMMIT_CONFIG.read_text(encoding="utf-8")), "config")
    install_types = _as_sequence(config.get("default_install_hook_types"), "default_install_hook_types")
    assert "commit-msg" in install_types

    hooks = [
        _as_mapping(hook, "hook")
        for repo_entry in _as_sequence(config["repos"], "repos")
        for hook in _as_sequence(_as_mapping(repo_entry, "repo")["hooks"], "hooks")
    ]
    matching = [hook for hook in hooks if hook.get("id") == "no-claude-attribution"]
    assert len(matching) == 1
    hook = matching[0]
    assert hook.get("stages") == ["commit-msg"]
    entry = hook.get("entry")
    assert isinstance(entry, str)
    assert "scripts/check_claude_attribution.py commit-msg" in entry


def test_ci_scans_pushes_and_pull_requests() -> None:
    """The workflow must run on both events and invoke every scan mode."""
    loaded: object = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), "workflow must be a mapping"
    raw_keys = cast("dict[object, object]", loaded)
    workflow = _as_mapping({str(key): value for key, value in raw_keys.items()}, "workflow")
    triggers = _as_mapping(workflow.get("True", workflow.get("on")), "on")
    assert "push" in triggers
    assert "pull_request" in triggers

    jobs = _as_mapping(workflow["jobs"], "jobs")
    job = _as_mapping(jobs["no-claude-attribution"], "job")
    assert "continue-on-error" not in job
    runs = [str(_as_mapping(step, "step").get("run", "")) for step in _as_sequence(job["steps"], "steps")]
    script = "python scripts/check_claude_attribution.py"
    assert any(f"{script} range" in run and "pull_request.base.sha" in run for run in runs)
    assert any(f"{script} text" in run for run in runs)
    assert any(f'{script} range "$BEFORE..$AFTER"' in run for run in runs)


def test_repository_history_is_free_of_claude_attribution() -> None:
    """The project's own history, as checked out, carries no Claude attribution."""
    result = _run_script(_REPO_ROOT, os.environ, "range", "HEAD")
    assert result.returncode == 0, result.stdout + result.stderr
