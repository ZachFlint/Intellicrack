"""Generate remediation bookkeeping from merged fix results + sandbox outcomes.

Writes, under ``audit/test-gate-audit/``:

* ``remediation/<key>.status.json`` - one record per remediated test file with
  the findings addressed, action taken, oracle used, falsifiability proof
  (mutation tried and the sandbox red/green result), and lint/type/doc results.
* ``PRODUCTION-DEFECTS.md`` - every production defect surfaced (now-red gates).
* ``REMEDIATION-RESULTS.md`` - totals by severity, hardened vs deleted counts,
  the red production-defect gates, and any remaining work.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_AUDIT = Path("D:/Intellicrack/audit/test-gate-audit")
_REM = _AUDIT / "remediation"


def _key(file: str) -> str:
    """Derive a stable status-file key from a test path.

    Args:
        file: Repo-relative test file path.

    Returns:
        str: Sanitized key (path separators to double underscore).
    """
    return file.replace("/", "__").removesuffix(".py")


def _load(path: Path, default: Any) -> Any:
    """Load JSON if present, else return default.

    Args:
        path: JSON file path.
        default: Value to return when the file is absent.

    Returns:
        Any: Parsed JSON or the default.
    """
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def main() -> None:
    """Generate all bookkeeping artifacts."""
    _REM.mkdir(parents=True, exist_ok=True)
    merged = _load(_AUDIT / "_merged_results.json", {"result": {"results": []}})
    results = merged["result"]["results"]
    green = _load(_AUDIT / "_green_outcomes.json", {})
    falsify = _load(_AUDIT / "_falsify_results.json", {})
    plan = _load(_AUDIT / "_plan.json", [])
    plan_by_file = {p["file"]: p for p in plan}

    def green_status(nodeid: str) -> str:
        """Look up a covering test's green-baseline status.

        Args:
            nodeid: pytest nodeid.

        Returns:
            str: ``pass`` / ``fail`` / ``skip`` / ``unknown``.
        """
        func = nodeid.split("::")[-1]
        for key, val in green.items():
            if key.split("::")[-1] == func:
                return str(val.get("status", "unknown"))
        return "unknown"

    totals = {
        "files": 0,
        "hardened": 0,
        "deleted": 0,
        "red_prod_defect": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "falsifiable_proven": 0,
        "falsifiable_total": 0,
    }
    prod_defects: list[dict[str, object]] = []

    for r in results:
        file = r["file"]
        fix = r["fix"]
        review = r.get("review") or {}
        totals["files"] += 1
        findings = fix.get("findings_addressed", [])
        plan_muts = {m["covering_test"]: m for m in plan_by_file.get(file, {}).get("mutations", [])}

        rec_findings: list[dict[str, object]] = []
        for fa in findings:
            action = fa.get("action", "")
            sev = (fa.get("severity") or "").upper()
            if sev in totals["by_severity"]:
                totals["by_severity"][sev] += 1
            if action == "hardened":
                totals["hardened"] += 1
            elif action == "deleted":
                totals["deleted"] += 1
            elif action == "red-prod-defect":
                totals["red_prod_defect"] += 1
            fal = fa.get("falsifiability") or {}
            covering = fal.get("covering_test", "")
            fres = falsify.get(covering, {}) if covering else {}
            rec_findings.append(
                {
                    "test": fa.get("test"),
                    "severity": fa.get("severity"),
                    "category": fa.get("category"),
                    "action": action,
                    "oracle": fa.get("oracle"),
                    "deletion_sibling": fa.get("deletion_sibling"),
                    "falsifiability": {
                        "src_file": fal.get("src_file"),
                        "mutation": f"{fal.get('mutation_search')} -> {fal.get('mutation_replace')}"
                        if fal.get("mutation_search")
                        else None,
                        "covering_test": covering or None,
                        "expected_baseline": fal.get("expected_baseline"),
                        "green_status": green_status(covering) if covering else None,
                        "mutation_result": fres.get("status") if fres else None,
                        "proven_falsifiable": fres.get("falsifiable") if fres else None,
                    }
                    if action != "deleted"
                    else None,
                }
            )
            if action != "deleted" and fal.get("expected_baseline") == "green":
                totals["falsifiable_total"] += 1
                if fres.get("falsifiable") == "yes":
                    totals["falsifiable_proven"] += 1

        for pd in fix.get("production_defects", []):
            prod_defects.append({**pd, "test_file": file})

        status = {
            "file": file,
            "review_overall": review.get("overall"),
            "lint": {
                "ruff": fix.get("ruff_clean"),
                "basedpyright": fix.get("basedpyright_clean", True),
                "pydoclint": fix.get("pydoclint_clean"),
                "pydocstyle": fix.get("pydocstyle_clean"),
            },
            "findings_addressed": rec_findings,
            "production_defects": [pd for pd in fix.get("production_defects", [])],
            "n_mutations": len(plan_muts),
        }
        (_REM / f"{_key(file)}.status.json").write_text(json.dumps(status, indent=1), encoding="utf-8")

    _write_prod_defects(prod_defects, falsify)
    _write_results(totals, prod_defects)
    print(f"status records: {totals['files']}")
    print(f"hardened={totals['hardened']} deleted={totals['deleted']} red_prod_defect={totals['red_prod_defect']}")
    print(f"falsifiable proven={totals['falsifiable_proven']}/{totals['falsifiable_total']}")
    print(f"production defects: {len(prod_defects)}")


def _write_prod_defects(defects: list[dict[str, object]], falsify: dict[str, object]) -> None:
    """Write PRODUCTION-DEFECTS.md.

    Args:
        defects: Production-defect records.
        falsify: Falsifiability results keyed by nodeid.
    """
    lines = ["# Production Defects Surfaced by Test-Gate Remediation", ""]
    lines.append(
        "Defects found while writing correct falsifiable gates. Per remediation rule 1, "
        "the production source was NOT modified; the correct gate was written and stays RED "
        "until the source is fixed."
    )
    lines.append("")
    if not defects:
        lines.append("_No production defects surfaced._")
    for i, d in enumerate(defects, 1):
        red = d.get("red_test", "")
        fres = falsify.get(str(red), {}) if red else {}
        lines += [
            f"## PD-{i:03d}: {d.get('symbol') or d.get('src_file')}",
            f"- **Source:** `{d.get('src_file')}`" + (f":{d.get('line')}" if d.get("line") else ""),
            f"- **Test file:** `{d.get('test_file')}`",
            f"- **Expected:** {d.get('expected')}",
            f"- **Actual:** {d.get('actual')}",
            f"- **Red gate:** `{red}`",
            f"- **Sandbox status:** {fres.get('status', 'pending') if fres else 'pending'} (expected red)",
            "",
        ]
    (_AUDIT / "PRODUCTION-DEFECTS.md").write_text("\n".join(lines), encoding="utf-8")


def _write_results(totals: dict[str, object], defects: list[dict[str, object]]) -> None:
    """Write REMEDIATION-RESULTS.md.

    Args:
        totals: Aggregate counters.
        defects: Production-defect records.
    """
    sev = totals["by_severity"]
    lines = [
        "# Test-Gate Remediation Results",
        "",
        f"- Test files remediated: **{totals['files']}**",
        f"- Findings hardened: **{totals['hardened']}**",
        f"- Findings deleted (redundant duplicates): **{totals['deleted']}**",
        f"- Red production-defect gates: **{totals['red_prod_defect']}**",
        "",
        "## By severity (findings addressed)",
        f"- CRITICAL: {sev['CRITICAL']}",
        f"- HIGH: {sev['HIGH']}",
        f"- MEDIUM: {sev['MEDIUM']}",
        f"- LOW: {sev['LOW']}",
        "",
        "## Falsifiability (sandbox-proven)",
        f"- Proven red under mutation: **{totals['falsifiable_proven']}/{totals['falsifiable_total']}**",
        "",
        "## Production defects",
        f"- {len(defects)} surfaced; see PRODUCTION-DEFECTS.md",
        "",
    ]
    (_AUDIT / "REMEDIATION-RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
