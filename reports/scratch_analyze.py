"""One-off basedpyright findings analyzer (scratch tool, ok to delete)."""
from __future__ import annotations
import json
from collections import Counter

with open("D:/Intellicrack/reports/json/bp_fresh.json") as f:
    data = json.load(f)

diags = data.get("generalDiagnostics", [])
print(f"Total findings: {len(diags)}")

by_rule_file: Counter[tuple[str, str]] = Counter()
for d in diags:
    rel = d["file"].replace("d:\\Intellicrack\\", "").replace("\\", "/")
    by_rule_file[(rel, d.get("rule", "?"))] += 1

file_top: dict[str, list[tuple[str, int]]] = {}
for (f, r), c in by_rule_file.items():
    file_top.setdefault(f, []).append((r, c))

print()
print("Top 20 files with dominant rules:")
for f, rules in sorted(file_top.items(), key=lambda x: -sum(c for _, c in x[1]))[:20]:
    total = sum(c for _, c in rules)
    rules.sort(key=lambda x: -x[1])
    top3 = ", ".join(f"{r}:{c}" for r, c in rules[:3])
    print(f"  {total:4d}  {f}  [{top3}]")

print()
print("Sample findings (one per top file):")
samples: dict[str, dict[str, object]] = {}
wanted = [
    "test_commit_message.py", "cutter_panel.py", "test_cutter.py",
    "ghidra_panel.py", "test_local_xpu_e2e.py", "test_process_manager.py",
]
for d in diags:
    for w in wanted:
        if d["file"].endswith(w) and w not in samples:
            samples[w] = d

for name, d in samples.items():
    rng = d.get("range", {}).get("start", {})
    print(f"  {name} [{d.get('rule')} @ line {rng.get('line')}]: {str(d['message'])[:180]}")
