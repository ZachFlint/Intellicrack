"""Independently verify and bank accepted-but-unmerged remediation units (model-free).

For each pending-merge unit (writer-complete + worktree present) this re-runs the
full six-check verification inside its git worktree; only if every check is
genuinely green does it copy the finalized test files into the main tree and
remove the worktree+branch. Units that fail verification are left untouched for a
later model-driven re-run. Progress is appended to ``audit/_bank.log``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


REPO = "D:/Intellicrack"
WTBASE = "D:/ic-wt2"
PENDING = [
    "U10-a09",
    "U24-a09",
    "U29-a07",
    "U32-a17",
    "U35-a03",
    "U38-a01",
    "U39-a04",
    "U41-a08",
    "U42-a17",
    "U44-a05",
    "U45-a08",
    "U46-a08",
    "U51-a19",
    "U53-a03",
    "U56-a20",
    "U59-a06",
]


def run(cmd: str, cwd: str | None = None, timeout: int = 600) -> int:
    """Run a shell command and return its exit code (124 on timeout).

    Args:
        cmd: Command line to execute via the shell.
        cwd: Working directory for the command.
        timeout: Hard timeout in seconds.

    Returns:
        The process exit code, or 124 if it timed out.
    """
    try:
        return subprocess.run(cmd, check=False, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return 124


def main() -> None:
    """Verify and bank each pending unit, logging the outcome."""
    units = {u["id"]: u for u in json.loads(Path(f"{REPO}/audit/_units.json").read_text(encoding="utf-8"))}
    log = Path(f"{REPO}/audit/_bank.log").open("w", encoding="utf-8")
    banked = 0
    for uid in PENDING:
        wt = f"{WTBASE}/{uid}"
        if not Path(wt).is_dir():
            log.write(f"{uid} NO-WORKTREE skip\n")
            log.flush()
            continue
        rel = " ".join(units[uid]["files"])
        base = f"pixi run --manifest-path {REPO}/pyproject.toml"
        checks = [
            ("ruff", f"{base} ruff check {rel}", 180),
            ("rufffmt", f"{base} ruff format --check {rel}", 180),
            ("basedpyright", f"{base} basedpyright {rel}", 300),
            ("pydoclint", f"{base} pydoclint {rel}", 180),
            ("pydocstyle", f"{base} pydocstyle {rel}", 180),
            ("pytest", f"{base} pytest {rel} -p no:timeout -p no:cacheprovider -q", 600),
        ]
        failed = [name for name, cmd, to in checks if run(cmd, cwd=wt, timeout=to) != 0]
        if failed:
            log.write(f"{uid} VERIFY-FAIL {failed}\n")
            log.flush()
            continue
        for f in units[uid]["files"]:
            dst = Path(f"{REPO}/{f}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f"{wt}/{f}", dst)
        run(f'git -C "{REPO}" worktree remove --force "{wt}"')
        run(f'git -C "{REPO}" branch -D wf2/{uid}')
        banked += 1
        log.write(f"{uid} BANKED ({len(units[uid]['files'])} files)\n")
        log.flush()
    log.write(f"DONE banked={banked}/{len(PENDING)}\n")
    log.close()


if __name__ == "__main__":
    main()
