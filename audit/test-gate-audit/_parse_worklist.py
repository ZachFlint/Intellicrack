"""Parse the 19 per-area audit reports into an authoritative per-file work-list."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

AUDIT_DIR = Path(__file__).parent
REPORTS = [
    "misc_credentials_root_scripts.md",
    "test_audit3.md",
    "test_audit4_group1.md",
    "test_audit4_group2.md",
    "test_audit4_group3.md",
    "test_audit5.md",
    "test_audit7_group1.md",
    "test_audit7_group2.md",
    "test_bridges_part1.md",
    "test_bridges_part2.md",
    "test_core_part1.md",
    "test_core_part2.md",
    "test_hexcore_e2e_part1.md",
    "test_hexcore_e2e_part2.md",
    "test_providers_part1.md",
    "test_providers_part2.md",
    "test_sandbox_and_hexpat.md",
    "test_ui_part1.md",
    "test_ui_part2.md",
]

# A file header is a level-3 heading that names a path ending in .py
FILE_RE = re.compile(r"^###\s+(\S*test\S*\.py|\S+\.py)\s*$")
# A finding header: #### `name` — SEVERITY — category
FINDING_RE = re.compile(r"^####\s+`?([^`—]+?)`?\s+[—-]+\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+[—-]+\s+(.+?)\s*$")
LOC_RE = re.compile(r"\*\*Location:\*\*\s*(.+?):(\d+)")


def parse_report(path: Path) -> dict[str, list[dict[str, object]]]:
    """Parse one report file into {file_path: [finding, ...]}."""
    by_file: dict[str, list[dict[str, object]]] = defaultdict(list)
    lines = path.read_text(encoding="utf-8").splitlines()
    in_flagged = False
    current_file: str | None = None
    current: dict[str, object] | None = None
    body: list[str] = []

    def flush() -> None:
        nonlocal current
        if current is not None and current_file is not None:
            current["body"] = "\n".join(body).strip()
            loc = LOC_RE.search(current["body"])  # type: ignore[arg-type]
            if loc:
                current["loc_file"] = loc.group(1).strip()
                current["line"] = int(loc.group(2))
            by_file[current_file].append(current)
        current = None

    for raw in lines:
        line = raw.rstrip()
        if line.startswith("## "):
            in_flagged = line.strip() == "## Flagged tests"
            flush()
            current_file = None
            continue
        if not in_flagged:
            continue
        fm = FILE_RE.match(line)
        if fm:
            flush()
            current_file = fm.group(1).strip()
            continue
        find = FINDING_RE.match(line)
        if find:
            flush()
            body = []
            current = {
                "test": find.group(1).strip(),
                "severity": find.group(2).strip(),
                "category": find.group(3).strip(),
                "report": path.name,
            }
            continue
        if current is not None:
            body.append(line)
    flush()
    return by_file


def resolve_path(repo_root: Path, candidate: str) -> str | None:
    """Resolve a (possibly partial) report path to a real on-disk test file."""
    candidate = candidate.replace("\\", "/").strip()
    if candidate.startswith("relative/path"):
        return None
    direct = repo_root / candidate
    if direct.is_file():
        return candidate
    # match by longest path suffix against all test_*.py files under tests/
    parts = candidate.split("/")
    for start in range(len(parts)):
        sub = "/".join(parts[start:])
        matches = [
            p.relative_to(repo_root).as_posix()
            for p in repo_root.glob(f"tests/**/{Path(sub).name}")
            if p.as_posix().endswith(sub)
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def main() -> None:
    """Aggregate all reports and emit the work-list JSON + a summary."""
    repo_root = AUDIT_DIR.parent.parent
    combined: dict[str, list[dict[str, object]]] = defaultdict(list)
    per_report_counts: dict[str, int] = {}
    unresolved: list[str] = []
    for name in REPORTS:
        rep = parse_report(AUDIT_DIR / name)
        n = 0
        for f, findings in rep.items():
            for fnd in findings:
                raw = str(fnd.get("loc_file") or f)
                resolved = resolve_path(repo_root, raw)
                if resolved is None:
                    unresolved.append(f"{name}: {raw} ({fnd.get('test')})")
                    resolved = raw.replace("\\", "/")
                combined[resolved].append(fnd)
                n += 1
        per_report_counts[name] = n

    total = sum(len(v) for v in combined.values())
    sev_counts: dict[str, int] = defaultdict(int)
    for findings in combined.values():
        for fnd in findings:
            sev_counts[str(fnd["severity"])] += 1

    worklist = {
        "total_findings": total,
        "total_files": len(combined),
        "severity_counts": dict(sev_counts),
        "per_report_counts": per_report_counts,
        "files": {
            f: sorted(findings, key=lambda x: x.get("line", 0))
            for f, findings in sorted(combined.items())
        },
    }
    out = AUDIT_DIR / "_worklist.json"
    out.write_text(json.dumps(worklist, indent=2), encoding="utf-8")

    if unresolved:
        print(f"UNRESOLVED ({len(unresolved)}):")
        for u in unresolved:
            print(f"  {u}")
    print(f"Total findings: {total}")
    print(f"Total files: {len(combined)}")
    print(f"Severity: {dict(sev_counts)}")
    print("Per report:")
    for name, cnt in per_report_counts.items():
        print(f"  {name}: {cnt}")
    print("\nFiles (findings count):")
    for f, findings in sorted(combined.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(findings):2d}  {f}")


if __name__ == "__main__":
    main()
