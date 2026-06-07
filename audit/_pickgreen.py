"""For files whose recovered version has lint/type errors, search dangling commits for a green version.

For each target file this enumerates every dangling-commit version that modifies it (status M vs
HEAD), newest first, checks it out, and runs ruff + basedpyright on that single file. The first
version that is clean on both is kept. Files with no clean version are reported for manual repair.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = "D:/Intellicrack"
MANIFEST = f"{REPO}/pyproject.toml"
TARGETS = [
    "tests/test_audit4/a4_windows_sandbox/test_ps_sources.py",
    "tests/test_audit4/b5_modules_tab/test_modules_tab.py",
    "tests/test_audit4/b2_process_tab/test_process_tab.py",
    "tests/test_hexcore_e2e/test_bridge_transforms_deep.py",
    "tests/test_hexcore_e2e/test_bridge_base_convert.py",
    "tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py",
]


def sh(args: list[str], timeout: int = 200) -> tuple[int, str]:
    """Run a command, returning its exit code and combined output.

    Args:
        args: Command and arguments.
        timeout: Hard timeout in seconds.

    Returns:
        Tuple of exit code (124 on timeout) and stdout text.
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, ""
    return result.returncode, result.stdout


def candidates(path: str) -> list[str]:
    """Return dangling-commit hashes that modify ``path`` (status M), newest first.

    Args:
        path: Repository-relative file path.

    Returns:
        Commit hashes sorted by descending commit time.
    """
    _, fsck = sh(["git", "fsck", "--dangling", "--no-progress"], timeout=120)
    commits = [line.split()[2] for line in fsck.splitlines() if "dangling commit" in line]
    dated: list[tuple[int, str]] = []
    for commit in commits:
        _, names = sh(["git", "diff", "--name-status", "HEAD", commit, "--", path])
        if any(line.split("\t")[0] == "M" for line in names.splitlines() if "\t" in line):
            _, when = sh(["git", "show", "-s", "--format=%ct", commit])
            dated.append((int(when.strip() or 0), commit))
    return [commit for _, commit in sorted(dated, reverse=True)]


def is_green(path: str) -> bool:
    """Return whether the working-tree ``path`` passes ruff and basedpyright.

    Args:
        path: Repository-relative file path.

    Returns:
        True if both checks exit zero.
    """
    base = ["pixi", "run", "--manifest-path", MANIFEST]
    return sh([*base, "ruff", "check", path])[0] == 0 and sh([*base, "basedpyright", path], timeout=300)[0] == 0


def main() -> None:
    """Pick and check out a green version for each target file."""
    log = Path(f"{REPO}/audit/_pickgreen.log").open("w", encoding="utf-8")
    for path in TARGETS:
        chosen = ""
        for commit in candidates(path):
            if sh(["git", "checkout", commit, "--", path])[0] != 0:
                continue
            if is_green(path):
                chosen = commit
                break
        log.write(f"{path} -> {'GREEN ' + chosen[:10] if chosen else 'NO-GREEN-VERSION'}\n")
        log.flush()
    log.write("DONE\n")
    log.close()


if __name__ == "__main__":
    main()
