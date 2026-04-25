#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Native runner for pre-commit-hooks that outputs JSON findings.

Imports ``pre_commit_hooks`` modules directly and invokes their ``main(argv)``
entry points with discovered file lists. Captures stdout/stderr, parses
findings, and outputs JSON for ``scripts/lint_report.py``.

File discovery uses ``git ls-files`` when inside a git repository (matching
pre-commit's behavior exactly), with a ``Path.rglob`` fallback otherwise.

Usage::

    python scripts/precommit_hooks.py                              # all hooks
    python scripts/precommit_hooks.py trailing-whitespace           # one hook
    python scripts/precommit_hooks.py mixed-line-ending --fix=lf    # hook + flags
    python scripts/precommit_hooks.py --target-dir tests            # different dir
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from types import ModuleType

TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".py",
    ".pyi",
    ".md",
    ".txt",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".cfg",
    ".ini",
    ".rst",
    ".sh",
    ".bash",
    ".bat",
    ".cmd",
    ".ps1",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".rs",
    ".go",
    ".rb",
    ".sql",
    ".graphql",
    ".proto",
    ".tf",
    ".hcl",
    ".conf",
    ".rc",
    ".inc",
    ".lang",
    ".theme",
    ".1",
})
PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py", ".pyi"})
PYTHON_ONLY: frozenset[str] = frozenset({".py"})
YAML_EXTENSIONS: frozenset[str] = frozenset({".yaml", ".yml"})
JSON_EXTENSIONS: frozenset[str] = frozenset({".json"})
TOML_EXTENSIONS: frozenset[str] = frozenset({".toml"})
XML_EXTENSIONS: frozenset[str] = frozenset({".xml"})
ALL_EXTENSIONS: frozenset[str] = frozenset()

BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".obj",
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".lock",
    ".whl",
    ".egg",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pyd",
    ".node",
    ".map",
    ".sln",
    ".csproj",
    ".suo",
    ".cache",
    ".nupkg",
    ".snk",
    ".dat",
    ".graphml",
})

_BINARY_CHECK_SIZE = 8192

EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git",
    "__pycache__",
    ".pixi",
    "node_modules",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "venv",
})

WINDOWS_SKIP_HOOKS: frozenset[str] = frozenset({
    "check-executables-have-shebangs",
    "check-shebang-scripts-are-executable",
})

_WINDOWS_RESERVED: frozenset[str] = frozenset({
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})
_WINDOWS_ILLEGAL_CHARS: str = '<>:"|?*'
_MAX_WIN_PATH = 260

_FIXING_RE = re.compile(r"^Fixing\s+(.+)$", re.MULTILINE)
_FIXER_MSG_RE = re.compile(r"^(.+?):\s+(fixed\s+.+|removed\s+.+)$", re.MULTILINE)
_FILE_LINE_COL_RE = re.compile(r"^(.+?):(\d+):(\d+):\s*(.+)$", re.MULTILINE)
_FILE_MSG_RE = re.compile(r"^(.+?):\s+(.+)$", re.MULTILINE)
_PRIVATE_KEY_RE = re.compile(r"^Private key detected:\s*(.+)$", re.MULTILINE)
_BOM_RE = re.compile(r"^(.+?):\s+Has a byte-order marker$", re.MULTILINE)

_FALSE_POSITIVE_PREFIXES: tuple[str, ...] = (
    "Traceback",
    "File ",
    "None",
    "Error",
    "Warning",
    "IndentationError",
    "SyntaxError",
    "UnicodeDecodeError",
    "CalledProcessError",
)


def _is_plausible_path(candidate: str) -> bool:
    """Check if a string looks like a real file path rather than error output.

    Returns:
        bool: True if the candidate looks like a valid file path.
    """
    stripped = candidate.lstrip()
    if stripped != candidate:
        return False
    if stripped.startswith(_FALSE_POSITIVE_PREFIXES):
        return False
    if any(kw in stripped for kw in ("class ", "def ", "import ", "from ", "raise ")):
        return False
    return Path(stripped).is_file()


@dataclass(frozen=True)
class HookConfig:
    """Configuration for a single pre-commit hook."""

    hook_id: str
    module: str
    extensions: frozenset[str]
    default_args: tuple[str, ...]
    is_fixer: bool


@dataclass
class Finding:
    """A single finding from a hook run."""

    file: str
    line: int | None
    column: int | None
    hook_id: str
    message: str
    fixed: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output.

        Returns:
            dict[str, Any]: Dictionary representation of the finding.
        """
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "hook_id": self.hook_id,
            "message": self.message,
            "fixed": self.fixed,
        }


FIXER_ORDER: tuple[str, ...] = (
    "trailing-whitespace",
    "end-of-file-fixer",
    "mixed-line-ending",
    "fix-byte-order-marker",
)

HOOK_REGISTRY: dict[str, HookConfig] = {
    "trailing-whitespace": HookConfig(
        hook_id="trailing-whitespace",
        module="pre_commit_hooks.trailing_whitespace_fixer",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=True,
    ),
    "end-of-file-fixer": HookConfig(
        hook_id="end-of-file-fixer",
        module="pre_commit_hooks.end_of_file_fixer",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=True,
    ),
    "mixed-line-ending": HookConfig(
        hook_id="mixed-line-ending",
        module="pre_commit_hooks.mixed_line_ending",
        extensions=ALL_EXTENSIONS,
        default_args=("--fix=crlf",),
        is_fixer=True,
    ),
    "fix-byte-order-marker": HookConfig(
        hook_id="fix-byte-order-marker",
        module="pre_commit_hooks.fix_byte_order_marker",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=True,
    ),
    "check-yaml": HookConfig(
        hook_id="check-yaml",
        module="pre_commit_hooks.check_yaml",
        extensions=YAML_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-json": HookConfig(
        hook_id="check-json",
        module="pre_commit_hooks.check_json",
        extensions=JSON_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-toml": HookConfig(
        hook_id="check-toml",
        module="pre_commit_hooks.check_toml",
        extensions=TOML_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-xml": HookConfig(
        hook_id="check-xml",
        module="pre_commit_hooks.check_xml",
        extensions=XML_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-ast": HookConfig(
        hook_id="check-ast",
        module="pre_commit_hooks.check_ast",
        extensions=PYTHON_ONLY,
        default_args=(),
        is_fixer=False,
    ),
    "check-case-conflict": HookConfig(
        hook_id="check-case-conflict",
        module="pre_commit_hooks.check_case_conflict",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-illegal-windows-names": HookConfig(
        hook_id="check-illegal-windows-names",
        module="",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-symlinks": HookConfig(
        hook_id="check-symlinks",
        module="pre_commit_hooks.check_symlinks",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-executables-have-shebangs": HookConfig(
        hook_id="check-executables-have-shebangs",
        module="pre_commit_hooks.check_executables_have_shebangs",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-shebang-scripts-are-executable": HookConfig(
        hook_id="check-shebang-scripts-are-executable",
        module="pre_commit_hooks.check_shebang_scripts_are_executable",
        extensions=TEXT_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "destroyed-symlinks": HookConfig(
        hook_id="destroyed-symlinks",
        module="pre_commit_hooks.destroyed_symlinks",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "debug-statements": HookConfig(
        hook_id="debug-statements",
        module="pre_commit_hooks.debug_statement_hook",
        extensions=PYTHON_ONLY,
        default_args=(),
        is_fixer=False,
    ),
    "detect-private-key": HookConfig(
        hook_id="detect-private-key",
        module="pre_commit_hooks.detect_private_key",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "check-byte-order-marker": HookConfig(
        hook_id="check-byte-order-marker",
        module="pre_commit_hooks.check_byte_order_marker",
        extensions=ALL_EXTENSIONS,
        default_args=(),
        is_fixer=False,
    ),
    "name-tests-test": HookConfig(
        hook_id="name-tests-test",
        module="pre_commit_hooks.tests_should_end_in_test",
        extensions=PYTHON_EXTENSIONS,
        default_args=("--pytest-test-first",),
        is_fixer=False,
    ),
}


def _is_binary_content(filepath: str) -> bool:
    """Check if a file contains binary content by looking for null bytes.

    Returns:
        bool: True if the file contains null bytes or cannot be read.
    """
    try:
        with Path(filepath).open("rb") as fh:
            chunk = fh.read(_BINARY_CHECK_SIZE)
            return b"\x00" in chunk
    except OSError:
        return True


def _should_exclude_dir(name: str) -> bool:
    """Check if a directory component should be excluded from file discovery.

    Returns:
        bool: True if the directory should be excluded.
    """
    return name in EXCLUDE_DIRS or name.endswith(".egg-info")


def _is_windows() -> bool:
    """Check if running on Windows.

    Returns:
        bool: True if the platform is Windows.
    """
    return sys.platform == "win32"


def _git_ls_files(target_dir: Path) -> list[str] | None:
    """Get tracked files from git, or ``None`` if not in a git repo.

    Returns:
        list[str] | None: List of tracked file paths, or None if git is
            unavailable or the command fails.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--", str(target_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    raw = result.stdout
    if not raw.strip("\0").strip():
        return None

    return [f for f in raw.split("\0") if f]


def discover_files(target_dir: Path, extensions: frozenset[str]) -> list[str]:
    """Discover files under *target_dir*, optionally filtered by *extensions*.

    Uses ``git ls-files`` when available (matching pre-commit behavior), with a
    ``Path.rglob`` fallback. Binary extensions are always excluded. When
    *extensions* is empty every non-binary file is returned.

    Returns:
        list[str]: Sorted list of discovered file paths in POSIX format.
    """
    git_files = _git_ls_files(target_dir)

    if git_files is not None:
        files: list[str] = []
        for fp in git_files:
            path = Path(fp)
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in BINARY_EXTENSIONS:
                continue
            if extensions and suffix not in extensions:
                continue
            if not extensions and _is_binary_content(fp):
                continue
            files.append(path.as_posix())
        return sorted(files)

    files = []
    if not target_dir.is_dir():
        return files

    for item in target_dir.rglob("*"):
        if not item.is_file():
            continue
        if any(_should_exclude_dir(part) for part in item.parts):
            continue
        suffix = item.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            continue
        if extensions and suffix not in extensions:
            continue
        if not extensions and _is_binary_content(item.as_posix()):
            continue
        files.append(item.as_posix())

    return sorted(files)


def _import_hook(module_path: str) -> ModuleType:
    """Import a hook module by its dotted path.

    Returns:
        ModuleType: The imported module.
    """
    return importlib.import_module(module_path)


def _check_illegal_windows_names(files: list[str]) -> list[Finding]:
    """Custom implementation for check-illegal-windows-names.

    Checks for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9,
    LPT1-9), illegal characters (<>:"|?*), trailing dots/spaces, and paths
    exceeding 260 characters.

    Returns:
        list[Finding]: Findings for files with illegal Windows names.
    """
    findings: list[Finding] = []

    for filepath in files:
        path = Path(filepath)
        name = path.name
        stem_upper = path.stem.upper().split(".")[0]
        reasons: list[str] = []

        if stem_upper in _WINDOWS_RESERVED:
            reasons.append(f"reserved Windows device name '{stem_upper}'")

        for char in name:
            if char in _WINDOWS_ILLEGAL_CHARS:
                reasons.append(f"illegal character '{char}'")
                break

        if name.endswith((" ", ".")):
            reasons.append("trailing space or dot")

        if len(filepath) > _MAX_WIN_PATH:
            reasons.append(f"path exceeds {_MAX_WIN_PATH} characters")

        findings.extend(
            Finding(
                file=filepath,
                line=None,
                column=None,
                hook_id="check-illegal-windows-names",
                message=f"Illegal Windows filename: {reason}",
                fixed=False,
            )
            for reason in reasons
        )

    return findings


def _parse_fixer_output(
    hook_id: str,
    output: str,
) -> list[Finding]:
    """Extract findings from a fixer hook's captured output.

    Handles two output formats:
    - ``Fixing <filepath>`` (trailing-whitespace, end-of-file-fixer)
    - ``<filepath>: fixed <detail>`` / ``<filepath>: removed <detail>``
      (mixed-line-ending, fix-byte-order-marker)

    Returns:
        list[Finding]: Parsed findings from the fixer output.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for match in _FIXING_RE.finditer(output):
        fixed_path = match.group(1).strip()
        normalized = Path(fixed_path).as_posix()
        if normalized not in seen:
            seen.add(normalized)
            findings.append(
                Finding(
                    file=normalized,
                    line=None,
                    column=None,
                    hook_id=hook_id,
                    message="Fixed",
                    fixed=True,
                ),
            )

    for match in _FIXER_MSG_RE.finditer(output):
        fixed_path = match.group(1).strip()
        msg = match.group(2).strip()
        normalized = Path(fixed_path).as_posix()
        if normalized not in seen:
            seen.add(normalized)
            findings.append(
                Finding(
                    file=normalized,
                    line=None,
                    column=None,
                    hook_id=hook_id,
                    message=msg,
                    fixed=True,
                ),
            )

    return findings


def _parse_checker_output(
    hook_id: str,
    output: str,
) -> list[Finding]:
    """Extract findings from a checker hook's captured output.

    Handles several output formats: ``file:line:col: message``,
    ``file: message``, ``Private key detected: file``, and
    ``file: Has a byte-order marker``.

    Returns:
        list[Finding]: Parsed findings from the checker output.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    if hook_id == "detect-private-key":
        for match in _PRIVATE_KEY_RE.finditer(output):
            fp = match.group(1).strip()
            key = f"{fp}:private-key"
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        file=Path(fp).as_posix(),
                        line=None,
                        column=None,
                        hook_id=hook_id,
                        message="Private key material detected",
                        fixed=False,
                    ),
                )
        return findings

    if hook_id == "check-byte-order-marker":
        for match in _BOM_RE.finditer(output):
            fp = match.group(1).strip()
            key = f"{fp}:bom"
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        file=Path(fp).as_posix(),
                        line=None,
                        column=None,
                        hook_id=hook_id,
                        message="Has a byte-order marker",
                        fixed=False,
                    ),
                )
        return findings

    for match in _FILE_LINE_COL_RE.finditer(output):
        fp = match.group(1).strip()
        if not _is_plausible_path(fp):
            continue
        line_num = int(match.group(2))
        col = int(match.group(3))
        msg = match.group(4).strip()
        key = f"{fp}:{line_num}:{col}:{msg}"
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    file=Path(fp).as_posix(),
                    line=line_num,
                    column=col,
                    hook_id=hook_id,
                    message=msg,
                    fixed=False,
                ),
            )

    matched_lines = {m.start() for m in _FILE_LINE_COL_RE.finditer(output)}

    for match in _FILE_MSG_RE.finditer(output):
        if match.start() in matched_lines:
            continue
        fp = match.group(1).strip()
        msg = match.group(2).strip()
        if not msg or msg.startswith(("#", "OK", "Passed")):
            continue
        if not _is_plausible_path(fp):
            continue
        key = f"{fp}:{msg}"
        if key not in seen:
            seen.add(key)
            findings.append(
                Finding(
                    file=Path(fp).as_posix(),
                    line=None,
                    column=None,
                    hook_id=hook_id,
                    message=msg,
                    fixed=False,
                ),
            )

    return findings


def run_hook(
    config: HookConfig,
    files: list[str],
    extra_args: list[str] | None = None,
) -> list[Finding]:
    """Run a single hook against *files* and return any findings.

    For ``check-illegal-windows-names`` a custom implementation is used.
    All other hooks are invoked via their module's ``main(argv)`` entry point
    with stdout/stderr captured.

    Returns:
        list[Finding]: Findings produced by the hook execution.
    """
    if not files:
        return []

    if config.hook_id == "check-illegal-windows-names":
        return _check_illegal_windows_names(files)

    if not config.module:
        return []

    if _is_windows() and config.hook_id in WINDOWS_SKIP_HOOKS:
        return []

    try:
        module = _import_hook(config.module)
    except ImportError:
        sys.stderr.write(f"  [WARN] Could not import {config.module}\n")
        return []

    argv: list[str] = list(config.default_args)
    if extra_args:
        argv.extend(extra_args)
    argv.extend(files)

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    exit_code = 0

    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        try:
            result = module.main(argv)
            exit_code = result if isinstance(result, int) else 0
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1
        except (RuntimeError, ValueError, TypeError, OSError, KeyError, AttributeError, UnicodeError) as exc:
            stderr_buf.write(f"{type(exc).__name__}: {exc}\n")
            exit_code = 1

    combined = stdout_buf.getvalue() + stderr_buf.getvalue()

    if exit_code == 0 and not combined.strip():
        return []

    if config.is_fixer:
        return _parse_fixer_output(config.hook_id, combined)

    return _parse_checker_output(config.hook_id, combined)


def _get_hooks_to_run(hook_name: str | None) -> list[HookConfig]:
    """Return an ordered list of hooks to execute.

    When *hook_name* is ``None`` all hooks are returned with fixers first
    (in :data:`FIXER_ORDER`) followed by checkers sorted alphabetically.
    """
    if hook_name:
        config = HOOK_REGISTRY.get(hook_name)
        if not config:
            sys.stderr.write(f"Unknown hook: {hook_name}\n")
            sys.stderr.write(f"Available: {', '.join(sorted(HOOK_REGISTRY))}\n")
            sys.exit(1)
        return [config]

    fixers = [HOOK_REGISTRY[h] for h in FIXER_ORDER if h in HOOK_REGISTRY]
    checkers = [cfg for _, cfg in sorted(HOOK_REGISTRY.items()) if not cfg.is_fixer]
    return fixers + checkers


def parse_cli(argv: list[str]) -> tuple[str | None, str, list[str]]:
    """Parse CLI arguments into ``(hook_name, target_dir, extra_args)``.

    Returns:
        tuple[str | None, str, list[str]]: A tuple of the hook name (or None
            for all hooks), target directory, and extra arguments.
    """
    hook_name: str | None = None
    target_dir = "."
    extra_args: list[str] = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--target-dir" and i + 1 < len(argv):
            target_dir = argv[i + 1]
            i += 2
        elif arg.startswith("--target-dir="):
            target_dir = arg.split("=", 1)[1]
            i += 1
        elif hook_name is None and not arg.startswith("-") and arg in HOOK_REGISTRY:
            hook_name = arg
            i += 1
        else:
            extra_args.append(arg)
            i += 1

    return hook_name, target_dir, extra_args


def main() -> int:
    """Run pre-commit hooks and output JSON findings to stdout.

    Returns:
        int: Exit code, 0 on success or 1 on failure.
    """
    hook_name, target_dir, extra_args = parse_cli(sys.argv[1:])
    target_path = Path(target_dir)

    if not target_path.is_dir():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        return 1

    hooks = _get_hooks_to_run(hook_name)
    all_findings: list[Finding] = []
    hooks_run: list[str] = []

    for config in hooks:
        sys.stderr.write(f"  [{config.hook_id}] ")
        files = discover_files(target_path, config.extensions)

        if not files:
            sys.stderr.write("0 files matched\n")
            hooks_run.append(config.hook_id)
            continue

        if _is_windows() and config.hook_id in WINDOWS_SKIP_HOOKS:
            sys.stderr.write("skipped (Unix-only)\n")
            hooks_run.append(config.hook_id)
            continue

        sys.stderr.write(f"{len(files)} files ")

        hook_extra = extra_args if config.hook_id == hook_name else []
        findings = run_hook(config, files, hook_extra)
        all_findings.extend(findings)
        hooks_run.append(config.hook_id)

        count = len(findings)
        if count:
            sys.stderr.write(f"-> {count} finding{'s' if count != 1 else ''}\n")
        else:
            sys.stderr.write("-> passed\n")

    output: dict[str, Any] = {
        "tool": "precommit-hooks",
        "generated": datetime.now(tz=UTC).isoformat(),
        "hooks_run": hooks_run,
        "target_dir": str(target_path),
        "total_findings": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
    }

    json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")

    sys.stderr.write(f"\n  Total: {len(all_findings)} finding{'s' if len(all_findings) != 1 else ''} across {len(hooks_run)} hooks\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
