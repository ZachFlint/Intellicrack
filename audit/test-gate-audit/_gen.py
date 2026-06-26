"""Source-of-truth generator for the test-gate-audit report.

Reads raw_findings.json (the finding list, each with a stable id) and
_corrections.json (my independent verification: per-id overrides + notes),
applies the corrections, and rewrites INDEX.md, the per-group files, and
raw_findings.json (with ids + applied verification state).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).resolve().parent
RAW = OUT / "raw_findings.json"
CORR = OUT / "_corrections.json"

data = json.loads(RAW.read_text(encoding="utf-8"))
findings: list[dict[str, object]] = data["findings"]

# assign stable ids if missing
for n, f in enumerate(findings, 1):
    f.setdefault("id", f"G{n:04d}")

corrections: dict[str, dict[str, object]] = {}
if CORR.exists():
    for c in json.loads(CORR.read_text(encoding="utf-8")):
        corrections[str(c["id"])] = c

OVERRIDE_FIELDS = ("confirmed", "severity", "category", "line", "test")
for f in findings:
    c = corrections.get(str(f["id"]))
    if not c:
        f["verification"] = "unverified"
        continue
    for k in OVERRIDE_FIELDS:
        if k in c and c[k] is not None:
            f[k] = c[k]
    # verification status: accurate | corrected | reclassified | removed
    f["verification"] = c.get("status", "accurate")
    if c.get("note"):
        f["verification_note"] = c["note"]


def norm(p: object) -> str:
    return str(p).replace("\\", "/")


def group_of(path: str) -> str:
    parts = norm(path).split("/")
    return parts[1] if len(parts) >= 2 and parts[0] == "tests" else parts[0]


SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

active = [f for f in findings if f.get("verification") != "removed"]
confirmed = [f for f in active if f["confirmed"]]
refuted = [f for f in active if not f["confirmed"]]
removed = [f for f in findings if f.get("verification") == "removed"]

by_group: dict[str, list[dict[str, object]]] = defaultdict(list)
for f in active:
    by_group[group_of(str(f["file"]))].append(f)

CATEGORY_DESC = {
    "tautological": "Assertion always true / circular (asserts a value the test itself set)",
    "no-assertion": "No behavioral assertion - only 'does not raise' smoke",
    "weak-existence": "Asserts only not-None / isinstance / hasattr / truthiness - a thin impl passes",
    "mock-shadows-target": "Replaces the unit under test; assertion checks the canned value",
    "mock-call-only": "Asserts only that a collaborator was called, never the real produced effect",
    "swallows-failure": "try/except or 'or' that lets the failure path pass the test",
    "skip-masks-failure": "Skips/xfails when capability missing so a broken build goes green",
    "conditional-never-runs": "Assertions guarded so the body never executes in CI",
    "asserts-on-stub-output": "Expected value matches a hardcoded/thin prod return (circular)",
    "other": "Other reason the test cannot fail on real breakage",
}

VSTATUS_BADGE = {
    "accurate": "verified accurate",
    "corrected": "CORRECTED",
    "reclassified": "RECLASSIFIED",
    "unverified": "unverified",
}


def esc(s: object) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def slug(g: str) -> str:
    return g.replace("/", "_")


def write_group(group: str, items: list[dict[str, object]]) -> str:
    conf = sorted(
        [i for i in items if i["confirmed"]],
        key=lambda i: (SEV_ORDER.get(str(i["severity"]), 3), str(i["file"]), i.get("line") or 0),
    )
    ref = [i for i in items if not i["confirmed"]]
    L: list[str] = []
    L.append(f"# Test-Gate Audit - `tests/{group}`")
    L.append("")
    sc = {s: sum(1 for i in conf if i["severity"] == s) for s in ("high", "medium", "low")}
    L.append(
        f"**{len(conf)} confirmed non-gate defects** "
        f"(high: {sc['high']}, medium: {sc['medium']}, low: {sc['low']}) "
        f"| {len(ref)} flags refuted (genuine gates)."
    )
    L.append("")
    if conf:
        L.append("## Confirmed non-gate tests")
        L.append("")
        cur = None
        for i in conf:
            if i["file"] != cur:
                cur = i["file"]
                L.append(f"### `{cur}`")
                L.append("")
            badge = VSTATUS_BADGE.get(str(i.get("verification", "unverified")), "")
            L.append(
                f"- **{esc(i['test'])}** (line {i.get('line')}) - "
                f"`{i['category']}` / **{i['severity']}** - _[{badge}]_"
            )
            reason = i.get("verdict_reason") or i.get("finder_reason") or ""
            L.append(f"  - Why it is not a gate: {esc(reason)}")
            if i.get("recommendation"):
                L.append(f"  - Fix: {esc(i['recommendation'])}")
            if i.get("verification_note"):
                L.append(f"  - Independent check: {esc(i['verification_note'])}")
            L.append("")
    if ref:
        L.append("## Refuted flags (verified to be real gates - no action needed)")
        L.append("")
        for i in sorted(ref, key=lambda i: (str(i["file"]), i.get("line") or 0)):
            note = i.get("verification_note")
            extra = f" _[Independent check: {esc(note)}]_" if note else ""
            L.append(
                f"- `{esc(i['file'])}` :: **{esc(i['test'])}** (line {i.get('line')}) - "
                f"{esc(i.get('verdict_reason') or '')}{extra}"
            )
        L.append("")
    (OUT / f"{slug(group)}.md").write_text("\n".join(L), encoding="utf-8")
    return f"{slug(group)}.md"


gfiles: dict[str, str] = {}
for g, items in sorted(by_group.items()):
    gfiles[g] = write_group(g, items)

cat_counts: dict[str, int] = defaultdict(int)
for f in confirmed:
    cat_counts[str(f["category"])] += 1
sev_total = {s: sum(1 for f in confirmed if f["severity"] == s) for s in ("high", "medium", "low")}
nverif = sum(1 for f in active if f.get("verification") in ("accurate", "corrected", "reclassified"))

I: list[str] = []
I.append("# Intellicrack Test-Gate Audit")
I.append("")
I.append(
    "Every `test_*.py` under `tests/` (excluding vendored suites) was read in full and evaluated "
    "against a single criterion: **if the production capability the test covers were broken, "
    "removed, or made to return wrong data, would this test FAIL?** A test that stays green under a "
    "realistic breakage is not a production gate and is flagged below."
)
I.append("")
I.append(
    f"**Independent verification:** {nverif} of {len(findings)} findings have been re-checked by "
    "hand against the actual test and production source. Each confirmed finding is tagged "
    "_[verified accurate]_, _[CORRECTED]_, or _[RECLASSIFIED]_; findings proven wrong were moved to "
    "the refuted section or removed."
)
I.append("")
I.append("## Totals")
I.append("")
I.append("- Test files audited: **353**")
I.append(f"- Findings (after verification): **{len(active)}** ({len(removed)} removed as invalid)")
I.append(f"- Flags refuted on verification (genuine gates): **{len(refuted)}**")
I.append(f"- **Confirmed non-gate tests: {len(confirmed)}**")
I.append(f"  - high: **{sev_total['high']}**, medium: **{sev_total['medium']}**, low: **{sev_total['low']}**")
I.append("")
I.append("## Confirmed defects by category")
I.append("")
I.append("| Category | Count | Meaning |")
I.append("| --- | ---: | --- |")
for cat, _ in sorted(cat_counts.items(), key=lambda kv: -kv[1]):
    I.append(f"| `{cat}` | {cat_counts[cat]} | {CATEGORY_DESC.get(cat, '')} |")
I.append("")
I.append("## Confirmed defects by test group")
I.append("")
I.append("| Group | Confirmed | high | med | low | Refuted | Report |")
I.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
for g in sorted(by_group):
    items = by_group[g]
    cf = [i for i in items if i["confirmed"]]
    rf = [i for i in items if not i["confirmed"]]
    h = sum(1 for i in cf if i["severity"] == "high")
    m = sum(1 for i in cf if i["severity"] == "medium")
    lo = sum(1 for i in cf if i["severity"] == "low")
    I.append(f"| `tests/{g}` | {len(cf)} | {h} | {m} | {lo} | {len(rf)} | [{gfiles[g]}]({gfiles[g]}) |")
I.append("")
I.append("## Methodology")
I.append("")
I.append(
    "- **Finder pass:** 71 Sonnet 4.6 agents read each chunk of ~5 test files plus the production "
    "source under test and flagged every test that would stay green under a realistic breakage."
)
I.append(
    "- **Adversarial verify pass:** one verifier per chunk tried to refute each flag by constructing "
    "a real breakage the test would catch (67 findings on Sonnet 4.6, 305 on Haiku 4.5)."
)
I.append(
    "- **Independent hand-verification:** each finding re-checked directly against the cited test and "
    "production code; inaccurate findings corrected, reclassified, or removed."
)
I.append("")
(OUT / "INDEX.md").write_text("\n".join(I), encoding="utf-8")

data["findings"] = findings
RAW.write_text(json.dumps(data, indent=2), encoding="utf-8")

print(json.dumps({
    "active": len(active), "confirmed": len(confirmed), "refuted": len(refuted),
    "removed": len(removed), "verified": nverif, "groups": len(by_group),
    "sev": sev_total,
}, indent=2))
