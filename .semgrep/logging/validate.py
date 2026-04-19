"""Validate Intellicrack logging Semgrep rules against paired test fixtures.

Run via: `pixi run python .semgrep/logging/validate.py` or `just semgrep-test-logging`.

This script exists because `semgrep --test` is unreliable on Windows (RPC
decoding race in semgrep 1.159 on uv-installed Python 3.13). It performs
the same contract: for each `NN-category.yml` there is a paired
`NN-category.py` fixture annotated with `# ruleid: <rule>` before lines
that must trigger the rule, and `# ok: <rule>` before lines that must
NOT trigger the rule. A finding outside either annotation is also a
failure (surprising match).

Exit code 0 if every annotation matches actual findings, 1 otherwise.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
RULE_COMMENT_RE = re.compile(r"^\s*#\s*(ruleid|ok|todoruleid|todook):\s*([A-Za-z0-9\-\._,\s]+?)\s*$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
RULE_HEADER_RE = re.compile(r"^\s*[^\w\s]+\s+(intellicrack-logging-[a-z0-9\-]+)\s*$")
FINDING_LINE_RE = re.compile(r"^\s+(\d+)\S*\s*[\u2506\u2502\|]\s")


@dataclass(frozen=True)
class Expectation:
    """Annotation recorded on a fixture line.

    Attributes:
        line: 1-based line number the annotation applies to (the next
            non-comment line after the comment).
        kind: One of ``ruleid`` (must match), ``ok`` (must NOT match),
            ``todoruleid`` (expected match, treated as ruleid),
            ``todook`` (expected non-match, treated as ok).
        rule_id: The rule-id referenced by the annotation.

    """

    line: int
    kind: str
    rule_id: str


def _parse_expectations(py_path: Path) -> list[Expectation]:
    """Parse ``# ruleid:`` / ``# ok:`` annotations from a fixture file.

    Args:
        py_path: Path to a Python test fixture file.

    Returns:
        Sorted list of :class:`Expectation` entries, one per annotation.

    """
    text = py_path.read_text(encoding="utf-8").splitlines()
    out: list[Expectation] = []
    for i, raw in enumerate(text, start=1):
        m = RULE_COMMENT_RE.match(raw)
        if not m:
            continue
        kind, ids = m.group(1), m.group(2)
        target = _next_code_line(text, i)
        for rid in (s.strip() for s in ids.split(",") if s.strip()):
            out.append(Expectation(line=target, kind=kind, rule_id=rid))
    return out


def _next_code_line(lines: list[str], comment_lineno: int) -> int:
    """Return the line number of the first non-comment, non-blank line.

    Args:
        lines: All lines from the fixture file (0-indexed list).
        comment_lineno: 1-based line number where the annotation comment
            was found.

    Returns:
        The 1-based line number of the next code line the annotation
        applies to, or the comment line itself if no code follows.

    """
    for j in range(comment_lineno, len(lines)):
        stripped = lines[j].strip()
        if not stripped or stripped.startswith("#"):
            continue
        return j + 1
    return comment_lineno


def _run_semgrep(yml_path: Path, py_path: Path) -> list[tuple[int, str]]:
    """Invoke semgrep scan on a rule/fixture pair and parse text output.

    Args:
        yml_path: Path to the rule YAML file.
        py_path: Path to the paired fixture file.

    Returns:
        List of ``(line_number, short_rule_id)`` tuples, one per
        finding. Empty list if the scan finds nothing.

    Raises:
        RuntimeError: If semgrep exits with an error status AND produces
            no parseable output. Normal ``exit=1`` (findings present)
            is not an error.

    """
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    _purge_settings_locks()
    cmd = [
        "semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        f"--config={yml_path}",
        "--no-git-ignore",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
        "--text",
        "--quiet",
        str(py_path),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"semgrep exited with {proc.returncode} for {yml_path.name}: "
            f"stderr={proc.stderr[-400:]}"
        )
    return _parse_text_output(proc.stdout)


def _parse_text_output(stdout: str) -> list[tuple[int, str]]:
    """Parse semgrep's human-readable text output into findings.

    Args:
        stdout: Raw stdout from ``semgrep scan --text``.

    Returns:
        List of ``(line_number, short_rule_id)`` tuples, one per finding.

    """
    results: list[tuple[int, str]] = []
    current_rule: str | None = None
    for raw_line in stdout.splitlines():
        line = ANSI_RE.sub("", raw_line)
        header = RULE_HEADER_RE.match(line)
        if header is not None:
            current_rule = header.group(1)
            continue
        if current_rule is None:
            continue
        finding = FINDING_LINE_RE.match(line)
        if finding is not None:
            results.append((int(finding.group(1)), current_rule))
    return results


def _purge_settings_locks() -> None:
    """Remove leftover semgrep temp settings files that block concurrent runs.

    Semgrep on Windows leaves behind `settings<random>.yml` files in
    ``~/.semgrep`` when the settings write races across worker
    processes. Subsequent runs then fail with a permission error. This
    function clears them before every scan.
    """
    settings_dir = Path.home() / ".semgrep"
    if not settings_dir.is_dir():
        return
    for p in settings_dir.iterdir():
        name = p.name
        if name.startswith("settings") and name.endswith(".yml") and name != "settings.yml":
            try:
                p.unlink()
            except OSError:
                pass


def _short_rule_id(full: str) -> str:
    """Strip the semgrep config namespace prefix from a finding rule id.

    Args:
        full: The dotted rule id reported by semgrep
            (e.g. ``"semgrep.logging.intellicrack-logging-a1-..."``).

    Returns:
        The final dotted component, which is the rule id declared in
        the YAML ``id:`` field.

    """
    return full.rsplit(".", 1)[-1]


def _validate_pair(yml_path: Path, py_path: Path) -> tuple[int, list[str]]:
    """Validate one rule file against its paired fixture.

    Args:
        yml_path: Path to the rule YAML.
        py_path: Path to the paired fixture file.

    Returns:
        Tuple ``(failures, log_lines)`` where ``failures`` is the number
        of mismatches and ``log_lines`` contains human-readable detail.

    """
    log: list[str] = []
    expectations = _parse_expectations(py_path)
    findings = _run_semgrep(yml_path, py_path)

    expected_matches: set[tuple[int, str]] = set()
    expected_non_matches: set[tuple[int, str]] = set()
    for exp in expectations:
        key = (exp.line, exp.rule_id)
        if exp.kind in ("ruleid", "todoruleid"):
            expected_matches.add(key)
        elif exp.kind in ("ok", "todook"):
            expected_non_matches.add(key)

    found: set[tuple[int, str]] = set()
    by_rule: dict[str, list[int]] = defaultdict(list)
    for line, rid in findings:
        found.add((line, rid))
        by_rule[rid].append(line)

    missing = sorted(expected_matches - found)
    unexpected = sorted(found & expected_non_matches)
    failures = 0
    for line, rid in missing:
        failures += 1
        log.append(
            f"  FAIL expected hit: {rid} at {py_path.name}:{line} "
            f"(actual hits for rule: {sorted(by_rule.get(rid, []))})"
        )
    for line, rid in unexpected:
        failures += 1
        log.append(f"  FAIL expected NO hit: {rid} at {py_path.name}:{line}")

    hit_count = len(expected_matches & found)
    total_expected = len(expected_matches)
    log.insert(
        0,
        f"{yml_path.name:<35} hits {hit_count:3d}/{total_expected:3d} "
        f"findings={len(findings)} ok-lines={len(expected_non_matches)} "
        f"{'PASS' if failures == 0 else 'FAIL'}",
    )
    return failures, log


def main() -> int:
    """Run validation across every rule/fixture pair in this directory.

    Returns:
        Exit code 0 if all pairs validate, 1 if any pair has failures
        or could not be scanned.

    """
    yml_files = sorted(HERE.glob("*.yml"))
    if not yml_files:
        print(f"No rule files found in {HERE}", file=sys.stderr)
        return 1

    total_failures = 0
    scan_errors = 0
    for yml in yml_files:
        py = yml.with_suffix(".py")
        if not py.is_file():
            print(f"SKIP (no fixture): {yml.name}")
            continue
        try:
            fails, lines = _validate_pair(yml, py)
        except RuntimeError as exc:
            scan_errors += 1
            print(f"{yml.name:<35} SCAN ERROR: {exc}")
            continue
        total_failures += fails
        for line in lines:
            print(line)

    print("-" * 70)
    if total_failures == 0 and scan_errors == 0:
        print("All rule/fixture pairs validated successfully.")
        return 0
    print(f"Validation failures: {total_failures}; scan errors: {scan_errors}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
