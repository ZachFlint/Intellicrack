# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Keep Claude attribution out of the repository's commit history.

Two entry points share one definition of what counts as Claude attribution:

* ``commit-msg MESSAGE_FILE`` runs as a git ``commit-msg`` hook. It removes
  Claude co-author trailers, ``Claude-Session`` trailers and Claude Code
  footers from the message in place, and refuses the commit when the author or
  committer identity belongs to Claude.
* ``range REVISION...`` scans every commit selected by the given ``git log``
  revision arguments and fails if any of them carries a Claude identity or a
  Claude attribution line. CI runs it over each push and pull request.
* ``text FILE`` fails if a text file (for example a pull request body, whose
  footer can be copied into a squash-merge message) carries attribution lines.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final


_CLAUDE_EMAIL: Final[re.Pattern[str]] = re.compile(
    r"(@anthropic\.com|\+claude\[bot\]@users\.noreply\.github\.com)$",
    re.IGNORECASE,
)
_ATTRIBUTION_LINE: Final[re.Pattern[str]] = re.compile(
    r"^[ \t>*-]*("
    r"co-authored-by:.*(@anthropic\.com|\bclaude\b|claude\[bot\]).*"
    r"|claude-session:.*"
    r"|.*generated (with|by) \[?claude code\]?.*"
    r"|.*claude\.ai/code/session_\S*.*"
    r")$",
    re.IGNORECASE,
)
_EXCESS_BLANK_LINES: Final[re.Pattern[str]] = re.compile(r"\n{3,}")
_FIELD_SEPARATOR: Final[str] = "\x1f"
_RECORD_SEPARATOR: Final[str] = "\x1e"
_LOG_FIELDS: Final[tuple[str, ...]] = ("%H", "%an", "%ae", "%cn", "%ce", "%B")
_LOG_FORMAT: Final[str] = _FIELD_SEPARATOR.join(_LOG_FIELDS) + _RECORD_SEPARATOR
_GIT_TIMEOUT_S: Final[int] = 120
_GIT: Final[str] = shutil.which("git") or "git"


@dataclass(frozen=True, slots=True)
class Violation:
    """A single piece of Claude attribution found in a commit.

    Attributes:
        commit: Full hash of the offending commit.
        detail: Human-readable description of what was found.
    """

    commit: str
    detail: str


def is_claude_email(email: str) -> bool:
    """Report whether *email* is an identity Claude commits under.

    Args:
        email: Author or committer e-mail address.

    Returns:
        bool: ``True`` for Anthropic addresses and the Claude GitHub App bot.
    """
    return _CLAUDE_EMAIL.search(email.strip()) is not None


def attribution_lines(message: str) -> list[str]:
    """Return every Claude attribution line in a commit message.

    Args:
        message: Full commit message or other text.

    Returns:
        list[str]: The matching lines, stripped of surrounding whitespace.
    """
    return [line.strip() for line in message.splitlines() if _ATTRIBUTION_LINE.match(line)]


def strip_attribution(message: str) -> str:
    """Remove Claude attribution lines from a commit message.

    Blank-line runs left behind are collapsed, and a message that changed ends
    with exactly one newline. A message with no attribution is returned as is.

    Args:
        message: Full commit message.

    Returns:
        str: The message without attribution lines.
    """
    kept = [line for line in message.splitlines() if not _ATTRIBUTION_LINE.match(line)]
    if len(kept) == len(message.splitlines()):
        return message
    cleaned = _EXCESS_BLANK_LINES.sub("\n\n", "\n".join(kept)).strip("\n")
    return f"{cleaned}\n" if cleaned else ""


def _git(args: list[str], cwd: Path) -> str:
    """Run git and return its standard output.

    Args:
        args: Arguments passed after ``git``.
        cwd: Working directory for the command.

    Returns:
        str: Decoded standard output.

    Raises:
        RuntimeError: If git exits with a non-zero status.
    """
    completed = subprocess.run(
        [_GIT, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_GIT_TIMEOUT_S,
    )
    if completed.returncode != 0:
        msg = f"git {' '.join(args)} failed with exit code {completed.returncode}: {completed.stderr.strip()}"
        raise RuntimeError(msg)
    return completed.stdout


def _identity_email(ident: str) -> str:
    """Extract the e-mail address from a ``git var`` identity line.

    Args:
        ident: Output of ``git var GIT_AUTHOR_IDENT`` or ``GIT_COMMITTER_IDENT``.

    Returns:
        str: The address between the angle brackets, or an empty string.
    """
    match = re.search(r"<([^>]*)>", ident)
    return match.group(1) if match else ""


def scan_commits(revisions: list[str], cwd: Path) -> list[Violation]:
    """Find Claude attribution in every commit selected by *revisions*.

    Args:
        revisions: Revision arguments for ``git log`` (ranges, refs, ``--not``).
        cwd: Repository working directory.

    Returns:
        list[Violation]: Every identity or message violation, oldest commit last.
    """
    output = _git(["log", f"--format={_LOG_FORMAT}", *revisions, "--"], cwd)
    violations: list[Violation] = []
    for record in output.split(_RECORD_SEPARATOR):
        fields = record.lstrip("\n").split(_FIELD_SEPARATOR)
        if len(fields) != len(_LOG_FIELDS):
            continue
        commit, author_name, author_email, committer_name, committer_email, body = fields
        if is_claude_email(author_email):
            violations.append(Violation(commit, f"author is {author_name} <{author_email}>"))
        if is_claude_email(committer_email):
            violations.append(Violation(commit, f"committer is {committer_name} <{committer_email}>"))
        violations.extend(Violation(commit, f"message line: {line}") for line in attribution_lines(body))
    return violations


def _run_commit_msg(message_file: Path) -> int:
    """Clean a pending commit message and refuse a Claude identity.

    Args:
        message_file: Path git passes to the ``commit-msg`` hook.

    Returns:
        int: ``0`` to accept the commit, ``1`` to refuse it.
    """
    try:
        message_file = message_file.resolve()
    except RuntimeError as exc:
        sys.stderr.write(f"commit refused: cannot resolve commit message path {message_file}: {exc}\n")
        return 1
    cwd = Path.cwd()
    for variable in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
        ident = _git(["var", variable], cwd).strip()
        if is_claude_email(_identity_email(ident)):
            identity = ident.rsplit(">", 1)[0]
            sys.stderr.write(f"commit refused: {variable} is '{identity}>'. Set user.name and user.email to your own.\n")
            return 1
    original = message_file.read_text(encoding="utf-8")
    cleaned = strip_attribution(original)
    if cleaned != original:
        message_file.write_text(cleaned, encoding="utf-8", newline="")
        sys.stderr.write("removed Claude attribution lines from the commit message\n")
    return 0


def _run_range(revisions: list[str]) -> int:
    """Report Claude attribution across a revision range.

    Args:
        revisions: Revision arguments for ``git log``.

    Returns:
        int: ``0`` when clean, ``1`` when any violation was found.
    """
    violations = scan_commits(revisions, Path.cwd())
    for violation in violations:
        sys.stdout.write(f"{violation.commit[:12]}  {violation.detail}\n")
    if violations:
        commits = len({violation.commit for violation in violations})
        sys.stdout.write(f"\n{len(violations)} Claude attribution finding(s) in {commits} commit(s)\n")
        return 1
    return 0


def _run_text(text_file: Path) -> int:
    """Report Claude attribution lines in a text file.

    Args:
        text_file: File to scan.

    Returns:
        int: ``0`` when clean, ``1`` when attribution lines were found.
    """
    lines = attribution_lines(text_file.read_text(encoding="utf-8"))
    for line in lines:
        sys.stdout.write(f"{text_file.name}: {line}\n")
    return 1 if lines else 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the selected check.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when omitted.

    Returns:
        int: Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    commands = parser.add_subparsers(dest="command", required=True)
    commit_msg = commands.add_parser("commit-msg", help="clean a commit message file (git commit-msg hook)")
    commit_msg.add_argument("message_file", type=Path)
    revision_range = commands.add_parser("range", help="scan the commits selected by git log revision arguments")
    revision_range.add_argument("revisions", nargs=argparse.REMAINDER)
    text = commands.add_parser("text", help="scan a text file such as a pull request body")
    text.add_argument("text_file", type=Path)
    args = parser.parse_args(argv)

    command: str = args.command
    if command == "commit-msg":
        message_file: Path = args.message_file
        return _run_commit_msg(message_file)
    if command == "range":
        revisions: list[str] = args.revisions
        if not revisions:
            parser.error("range requires at least one revision argument")
        return _run_range(revisions)
    text_file: Path = args.text_file
    return _run_text(text_file)


if __name__ == "__main__":
    sys.exit(main())
