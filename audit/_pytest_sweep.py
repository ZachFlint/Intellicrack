"""Run pytest per changed test file and log pass/fail, isolating failures.

Each changed test file under ``tests/`` is run on its own with a hard timeout so a
single hang or crash cannot mask the rest. Results are appended to
``audit/_pytest_sweep.log`` with a final summary of failing files.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

REPO = "D:/Intellicrack"
MANIFEST = f"{REPO}/pyproject.toml"


def changed_test_files() -> list[str]:
    """Return repo-relative paths of changed ``tests/**/*.py`` files.

    Returns:
        Sorted list of changed test file paths.
    """
    out = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=False).stdout
    files: list[str] = []
    for line in out.splitlines():
        path = line[3:].strip().strip('"')
        if path.startswith("tests/") and path.endswith(".py"):
            files.append(path)
    return sorted(files)


def main() -> None:
    """Run pytest on each changed test file and record outcomes."""
    files = changed_test_files()
    log = Path(f"{REPO}/audit/_pytest_sweep.log").open("w", encoding="utf-8")
    base = ["pixi", "run", "--manifest-path", MANIFEST, "pytest"]
    failed: list[str] = []
    passed = 0
    for index, path in enumerate(files, start=1):
        start = time.monotonic()
        try:
            result = subprocess.run(
                [*base, path, "-p", "no:timeout", "-p", "no:cacheprovider", "-q"],
                capture_output=True,
                text=True,
                timeout=600,
            )
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
        elapsed = time.monotonic() - start
        if code == 0:
            passed += 1
            status = "PASS"
        else:
            failed.append(path)
            status = f"FAIL(rc={code})"
        log.write(f"[{index}/{len(files)}] {status} {elapsed:5.1f}s {path}\n")
        log.flush()
    log.write(f"\nDONE passed={passed} failed={len(failed)} of {len(files)}\n")
    for path in failed:
        log.write(f"  FAILED {path}\n")
    log.close()


if __name__ == "__main__":
    main()
