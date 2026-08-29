# Copyright (c) 2026 Intellicrack contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Windows-safe Semgrep driver for Intellicrack.

Semgrep-core 1.159 on Windows crashes with an RPC JSON decode error
when asked to discover target files under a directory tree. The same
invocation succeeds when targets are provided as explicit file paths.

This driver enumerates Python source files below ``src/intellicrack``
(respecting the repository's exclude conventions), runs them through
``semgrep scan`` in batches to avoid exceeding the Windows command-line
length limit, and aggregates the human-readable ``--text`` output so
it can be consumed by ``scripts/lint_report.py`` via the same pipeline
as every other linter.

Invoked from ``just semgrep``; direct invocation is also supported::

    pixi run python scripts/run-semgrep.py [--config PATH]... [--batch N] [TARGET]...

If no TARGET is provided, scans ``src/intellicrack`` by default.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = REPO_ROOT / "src" / "intellicrack"
DEFAULT_CONFIGS = (".semgrep/logging/",)
DEFAULT_BATCH_SIZE = 40
EXCLUDE_DIR_NAMES = frozenset({
    "__pycache__",
    ".git",
    ".pixi",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".semgrep",
    ".serena",
    ".claude",
    "node_modules",
    "build",
    "dist",
    "tests",
    "vendor",
    "typings",
})
SOURCE_EXTENSIONS = (".py",)


def _iter_source_files(target: Path) -> Iterator[Path]:
    """Yield scannable Python source files beneath ``target``.

    Args:
        target: Root directory or single file to enumerate.

    Yields:
        Every ``*.py`` path under ``target`` that is not inside an
        excluded directory.

    """
    if target.is_file():
        if target.suffix in SOURCE_EXTENSIONS:
            yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES]
        for fname in filenames:
            if fname.endswith(SOURCE_EXTENSIONS):
                yield Path(dirpath) / fname


def _batched(items: Iterable[Path], size: int) -> Iterator[list[Path]]:
    """Split an iterable of paths into contiguous batches.

    Args:
        items: Paths to group.
        size: Maximum items per batch (must be >= 1).

    Yields:
        Successive batches of up to ``size`` paths.

    """
    batch: list[Path] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _run_batch(
    configs: tuple[str, ...],
    files: list[Path],
    timeout: int,
) -> tuple[int, str, str]:
    """Run semgrep on one batch of files.

    Args:
        configs: Tuple of ``--config=PATH`` values.
        files: Paths to scan in this invocation.
        timeout: Per-rule timeout passed to ``--timeout``.

    Returns:
        Tuple ``(exit_code, stdout, stderr)``.

    """
    _purge_settings_locks()
    cmd: list[str] = [
        "semgrep",
        "scan",
        "--text",
        "--no-rewrite-rule-ids",
        f"--timeout={timeout}",
        "--no-git-ignore",
    ]
    cmd.extend(f"--config={cfg}" for cfg in configs)
    cmd.extend(str(f) for f in files)
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("NO_COLOR", "1")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(REPO_ROOT),
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _purge_settings_locks() -> None:
    """Remove stale ``~/.semgrep/settings*.yml`` files.

    Semgrep on Windows writes a temporary settings file during each
    invocation and, under contention, leaves ``settings<random>.yml``
    behind. Accumulating temp files eventually trigger a permission
    error on future scans. Clearing them before every batch avoids
    the race.
    """
    settings_dir = Path.home() / ".semgrep"
    if not settings_dir.is_dir():
        return
    for path in settings_dir.iterdir():
        name = path.name
        if name.startswith("settings") and name.endswith(".yml") and name != "settings.yml":
            try:
                path.unlink()
            except OSError:
                continue


def _merge_outputs(batch_outputs: list[str]) -> str:
    """Concatenate semgrep text outputs with safe separators.

    Args:
        batch_outputs: Raw stdout strings from each batch.

    Returns:
        A single string safe for :func:`process_semgrep_text` to
        ingest. Scan Summary banners are preserved as-is because the
        processor already ignores them.

    """
    pieces: list[str] = []
    for chunk in batch_outputs:
        if not chunk:
            continue
        pieces.append(chunk.rstrip("\n"))
    return "\n".join(pieces) + "\n"


def main() -> int:
    """Drive the batched scan and emit aggregated text output to stdout.

    Returns:
        ``0`` on success (even when findings exist), ``1`` when every
        batch failed to run, or ``2`` when argument parsing fails.

    """
    parser = argparse.ArgumentParser(prog="run-semgrep", add_help=True)
    parser.add_argument(
        "--config",
        action="append",
        default=[],
        help="Semgrep config path (repeatable).",
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Files per semgrep invocation (default: 40).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-rule timeout in seconds (default: 30).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="File to write aggregated text output to (default: stdout).",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target files or directories (default: src/intellicrack).",
    )
    args = parser.parse_args()

    configs: tuple[str, ...] = tuple(args.config) if args.config else DEFAULT_CONFIGS
    target_paths: list[Path] = [Path(t).resolve() for t in args.targets] if args.targets else [DEFAULT_TARGET]

    files: list[Path] = []
    for target in target_paths:
        if not target.exists():
            print(f"[run-semgrep] skipping missing target: {target}", file=sys.stderr)
            continue
        files.extend(sorted(_iter_source_files(target)))
    files = sorted(set(files))

    if not files:
        print("[run-semgrep] no source files found to scan", file=sys.stderr)
        return 0

    batch_size = max(1, args.batch)
    outputs: list[str] = []
    batch_failures = 0
    total_batches = 0
    for batch in _batched(files, batch_size):
        total_batches += 1
        exit_code, stdout, stderr = _run_batch(configs, batch, args.timeout)
        if exit_code not in {0, 1}:
            batch_failures += 1
            print(
                f"[run-semgrep] batch {total_batches} failed (exit {exit_code}): {stderr[-400:]}",
                file=sys.stderr,
            )
            continue
        outputs.append(stdout)

    merged = _merge_outputs(outputs)
    if args.output is not None:
        args.output.write_text(merged, encoding="utf-8")
    else:
        sys.stdout.write(merged)
        sys.stdout.flush()

    if batch_failures == total_batches and total_batches > 0:
        print("[run-semgrep] every batch failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
