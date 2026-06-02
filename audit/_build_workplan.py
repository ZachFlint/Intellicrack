"""Parse the 20 test-quality audit reports into a balanced, severity-ordered work plan.

Reads ``audit/agent-01.md`` .. ``audit/agent-20.md``, extracts every finding (a
``### <path>:<linespec> - <name>`` block that contains a ``Severity:`` line),
groups findings by source test file, and packs whole files into balanced work
units ordered Critical -> High -> Medium -> Low. Shared ``conftest.py`` fixture
files are pulled into a single dedicated unit so parallel members never edit the
same fixture. Emits ``audit/_workplan.json`` consumed by the remediation workflow.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

AUDIT_DIR = Path(__file__.replace("\\", "/")).parent
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_WEIGHT = {"Critical": 8, "High": 4, "Medium": 2, "Low": 1}
FILE_BASE_COST = 2  # fixed per-file overhead so single-finding files are not free
TARGET_UNIT_WEIGHT = 18  # weight budget per work unit (tuned to keep units reviewable)

HEADING_RE = re.compile(r"^###\s+(tests/\S+?\.py)\b(.*)$")
REMAINDER_RE = re.compile(r"^\s*:?\s*([0-9]+(?:-[0-9]+)?)?\s*(?:-\s*(.+?)|\((.+?)\))?\s*$")


def _clean(text: str) -> str:
    """Strip markdown emphasis markers and surrounding whitespace from a field value.

    Args:
        text: Raw field text taken from a report line.

    Returns:
        The text with ``*`` emphasis characters removed and edges trimmed.
    """
    return text.replace("**", "").strip()


def _field(body: list[str], label: str) -> str:
    """Extract a single labelled field's value from a finding block body.

    Args:
        body: Lines of the finding block (excluding the heading).
        label: Field label to match, e.g. ``"Severity"`` or ``"Fix recommendation"``.

    Returns:
        The field value with emphasis stripped, or an empty string if absent.
    """
    pattern = re.compile(rf"^\s*-?\s*\*{{0,2}}{re.escape(label)}\*{{0,2}}\s*:\s*(.*)$")
    for line in body:
        match = pattern.match(line)
        if match:
            return _clean(match.group(1))
    return ""


def parse_report(path: Path) -> list[dict[str, str]]:
    """Parse one audit report into a list of finding records.

    Args:
        path: Path to an ``agent-NN.md`` report file.

    Returns:
        A list of finding dicts; entries without a severity (clean-test listings)
        are excluded.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    heading_idx: list[tuple[int, re.Match[str]]] = []
    for i, line in enumerate(lines):
        match = HEADING_RE.match(line)
        if match:
            heading_idx.append((i, match))

    findings: list[dict[str, str]] = []
    for pos, (start, match) in enumerate(heading_idx):
        end = heading_idx[pos + 1][0] if pos + 1 < len(heading_idx) else len(lines)
        body = lines[start + 1 : end]
        severity_raw = _field(body, "Severity")
        severity = severity_raw.split()[0].rstrip("(") if severity_raw else ""
        if severity not in SEVERITY_ORDER:
            continue  # clean-test entry / summary / "Unknown (insufficient data)" non-finding
        rem = REMAINDER_RE.match(match.group(2)) if match.group(2) else None
        line = (rem.group(1) if rem and rem.group(1) else "") or "file-level"
        test = ((rem.group(2) or rem.group(3)) if rem else "") or "(file-level)"
        findings.append(
            {
                "report": path.name,
                "file": match.group(1),
                "line": line,
                "test": test.strip(),
                "severity": severity,
                "violations": _field(body, "Violation(s)"),
                "why": _field(body, "Why it is not a real gate"),
                "fix": _field(body, "Fix recommendation"),
            }
        )
    return findings


def file_weight(findings: list[dict[str, str]]) -> int:
    """Compute the rewrite-difficulty weight for a single file's findings.

    Args:
        findings: All findings belonging to one test file.

    Returns:
        Severity-weighted difficulty plus a fixed per-file overhead.
    """
    return FILE_BASE_COST + sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)


def max_severity(findings: list[dict[str, str]]) -> str:
    """Return the highest (worst) severity among a file or unit's findings.

    Args:
        findings: Findings to scan.

    Returns:
        The worst severity label present.
    """
    return min((f["severity"] for f in findings), key=lambda s: SEVERITY_ORDER[s])


def build_units(by_file: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    """Pack whole files into balanced, severity-ordered work units.

    Shared ``conftest.py`` files form one dedicated leading unit. Remaining files
    are grouped by their source report and greedily binned to the target weight,
    never splitting a file across units. Units are ordered worst-severity first.

    Args:
        by_file: Mapping of file path to its findings.

    Returns:
        Ordered list of work-unit dicts.
    """
    conftest_files = sorted(p for p in by_file if p.endswith("conftest.py"))
    other_files = [p for p in by_file if not p.endswith("conftest.py")]

    units: list[dict[str, object]] = []

    if conftest_files:
        cf_findings = [f for p in conftest_files for f in by_file[p]]
        units.append(
            {
                "kind": "fixtures",
                "files": conftest_files,
                "reports": sorted({f["report"] for f in cf_findings}),
                "findingCount": len(cf_findings),
                "maxSeverity": max_severity(cf_findings),
                "weight": sum(file_weight(by_file[p]) for p in conftest_files),
            }
        )

    by_report: dict[str, list[str]] = {}
    for path in other_files:
        by_report.setdefault(by_file[path][0]["report"], []).append(path)

    raw_units: list[dict[str, object]] = []
    for report in sorted(by_report):
        files = sorted(
            by_report[report],
            key=lambda p: (SEVERITY_ORDER[max_severity(by_file[p])], -file_weight(by_file[p])),
        )
        current: list[str] = []
        current_weight = 0
        for path in files:
            weight = file_weight(by_file[path])
            if current and current_weight + weight > TARGET_UNIT_WEIGHT:
                raw_units.append(_finalize_unit(report, current, by_file))
                current, current_weight = [], 0
            current.append(path)
            current_weight += weight
        if current:
            raw_units.append(_finalize_unit(report, current, by_file))

    raw_units.sort(key=lambda u: (SEVERITY_ORDER[str(u["maxSeverity"])], -int(u["weight"])))
    units.extend(raw_units)

    for idx, unit in enumerate(units):
        unit["id"] = f"U{idx:02d}-{unit['kind']}"
    return units


def _finalize_unit(report: str, files: list[str], by_file: dict[str, list[dict[str, str]]]) -> dict[str, object]:
    """Assemble a work-unit dict from a packed list of files.

    Args:
        report: Source report name the files belong to.
        files: File paths assigned to this unit.
        by_file: Mapping of file path to its findings.

    Returns:
        A work-unit dict with aggregate metadata.
    """
    findings = [f for p in files for f in by_file[p]]
    return {
        "kind": report.replace("agent-", "a").replace(".md", ""),
        "files": sorted(files),
        "reports": [report],
        "findingCount": len(findings),
        "maxSeverity": max_severity(findings),
        "weight": sum(file_weight(by_file[p]) for p in files),
    }


def main() -> None:
    """Parse all reports, build the work plan, write JSON, and print a summary."""
    all_findings: list[dict[str, str]] = []
    for path in sorted(AUDIT_DIR.glob("agent-*.md")):
        all_findings.extend(parse_report(path))

    by_file: dict[str, list[dict[str, str]]] = {}
    for finding in all_findings:
        by_file.setdefault(finding["file"], []).append(finding)

    units = build_units(by_file)

    totals = {sev: sum(1 for f in all_findings if f["severity"] == sev) for sev in SEVERITY_ORDER}
    totals["total"] = len(all_findings)

    workplan = {
        "totals": totals,
        "fileCount": len(by_file),
        "unitCount": len(units),
        "findingsByFile": by_file,
        "units": units,
    }
    out = AUDIT_DIR / "_workplan.json"
    out.write_text(json.dumps(workplan, indent=2), encoding="utf-8")

    print(f"findings parsed : {totals['total']}")
    print(f"  Critical={totals['Critical']} High={totals['High']} Medium={totals['Medium']} Low={totals['Low']}")
    print(f"files with findings : {len(by_file)}")
    print(f"work units          : {len(units)}")
    print(f"conftest files      : {sum(1 for p in by_file if p.endswith('conftest.py'))}")
    print("unit severity histogram:")
    for sev in SEVERITY_ORDER:
        print(f"  units led by {sev:<8}: {sum(1 for u in units if u['maxSeverity'] == sev)}")
    print(f"written: {out}")


if __name__ == "__main__":
    main()
