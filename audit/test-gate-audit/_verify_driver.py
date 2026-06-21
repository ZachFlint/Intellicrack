"""Serial sandbox verification driver for the test-gate remediation.

This tool consumes the Phase-1 fixer/reviewer workflow output and drives the
Docker sandbox (the only place Intellicrack tests may run) to:

* ``aggregate`` - merge one or more workflow ``.output`` JSON files into a flat
  remediation plan (``_plan.json``) under ``audit/test-gate-audit/``.
* ``green`` - run every changed test file through the sandbox in batched
  ``custom`` runs and confirm hardened/deleted files are GREEN while
  red-production-defect tests are RED (expected).
* ``falsify`` - prove each hardened test is falsifiable by applying its planned
  production mutation to the host source, running the covering test in the
  sandbox, confirming it turns RED, then reverting. Mutations are batched across
  distinct source files to bound the number of (serial) sandbox runs.

All sandbox invocations go through ``scripts.sandbox.docker_sandbox`` in
``custom`` mode with ``-p no:timeout`` (per the project's sandbox guidance:
``--timeout-method=thread`` crashes the interpreter). Per-test outcomes are read
from the JUnit XML the run always emits under ``reports/tests/``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path("D:/Intellicrack")
_AUDIT = _REPO / "audit" / "test-gate-audit"
_REPORTS = _REPO / "reports" / "tests"
_PLAN_PATH = _AUDIT / "_plan.json"


@dataclass
class Mutation:
    """A single planned production mutation that should turn one test RED.

    Attributes:
        test_file: Test file that owns the covering test.
        covering_test: pytest nodeid expected to fail under the mutation.
        src_file: Production file to mutate (repo-relative, forward slashes).
        search: Exact unique substring currently present in ``src_file``.
        replace: Replacement that breaks the gated behavior.
        baseline: ``"green"`` or ``"expected-red"``.
        action: Fixer action (``hardened`` / ``deleted`` / ``red-prod-defect``).
    """

    test_file: str
    covering_test: str
    src_file: str
    search: str
    replace: str
    baseline: str
    action: str


@dataclass
class FilePlan:
    """Aggregated remediation outcome for one test file.

    Attributes:
        file: Test file path (repo-relative).
        review_overall: Reviewer verdict (``pass`` / ``fail`` / ``None``).
        actions: Mapping of action name to count.
        mutations: Falsifiability mutations for this file.
        deleted_tests: Tests deleted as redundant duplicates.
        red_prod_defect_tests: Tests intentionally left RED (production defect).
    """

    file: str
    review_overall: str | None
    actions: dict[str, int] = field(default_factory=dict)
    mutations: list[Mutation] = field(default_factory=list)
    deleted_tests: list[str] = field(default_factory=list)
    red_prod_defect_tests: list[str] = field(default_factory=list)


def _load_workflow_results(output_files: list[Path]) -> list[dict[str, object]]:
    """Extract the per-file results array from workflow ``.output`` JSON files.

    Args:
        output_files: Paths to workflow task ``.output`` files.

    Returns:
        list[dict[str, object]]: Concatenated ``result.results`` entries.
    """
    merged: list[dict[str, object]] = []
    for path in output_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        result = data.get("result", data)
        if isinstance(result, dict):
            results = result.get("results", [])
            if isinstance(results, list):
                merged.extend(r for r in results if isinstance(r, dict))
    return merged


def _verify_search_unique(src_file: str, search: str) -> str:
    """Check that ``search`` occurs exactly once in the host source file.

    Args:
        src_file: Repo-relative production file path.
        search: Substring the mutation will replace.

    Returns:
        str: ``"ok"``, ``"missing"`` (zero occurrences), ``"nonunique"`` (more
            than one), or ``"nofile"`` (source file not found).
    """
    path = _REPO / src_file
    if not path.is_file():
        return "nofile"
    text = path.read_text(encoding="utf-8")
    count = text.count(search)
    if count == 0:
        return "missing"
    if count > 1:
        return "nonunique"
    return "ok"


def cmd_aggregate(args: argparse.Namespace) -> int:
    """Merge workflow outputs into a flat remediation plan.

    Args:
        args: Parsed CLI namespace with ``outputs`` (list of paths).

    Returns:
        int: Process exit code (0 on success).
    """
    outputs = [Path(p) for p in args.outputs]
    results = _load_workflow_results(outputs)
    plans: list[FilePlan] = []
    for entry in results:
        fix = entry.get("fix") or {}
        review = entry.get("review") or {}
        file = str(entry.get("file", fix.get("file", "")))
        fp = FilePlan(file=file, review_overall=str(review.get("overall")) if review else None)
        findings = fix.get("findings_addressed", []) if isinstance(fix, dict) else []
        for finding in findings:
            action = str(finding.get("action", ""))
            fp.actions[action] = fp.actions.get(action, 0) + 1
            test = str(finding.get("test", ""))
            if action == "deleted":
                fp.deleted_tests.append(test)
                continue
            fal = finding.get("falsifiability") or {}
            covering = str(fal.get("covering_test", "")) or test
            baseline = str(fal.get("expected_baseline", "green"))
            if action == "red-prod-defect":
                fp.red_prod_defect_tests.append(covering)
            if fal.get("src_file") and fal.get("mutation_search"):
                fp.mutations.append(
                    Mutation(
                        test_file=file,
                        covering_test=covering,
                        src_file=str(fal["src_file"]).replace("\\", "/"),
                        search=str(fal["mutation_search"]),
                        replace=str(fal["mutation_replace"]),
                        baseline=baseline,
                        action=action,
                    )
                )
        plans.append(fp)

    validated: list[dict[str, object]] = []
    for fp in plans:
        muts: list[dict[str, object]] = []
        for m in fp.mutations:
            status = _verify_search_unique(m.src_file, m.search)
            muts.append(
                {
                    "test_file": m.test_file,
                    "covering_test": m.covering_test,
                    "src_file": m.src_file,
                    "search": m.search,
                    "replace": m.replace,
                    "baseline": m.baseline,
                    "action": m.action,
                    "search_status": status,
                }
            )
        validated.append(
            {
                "file": fp.file,
                "review_overall": fp.review_overall,
                "actions": fp.actions,
                "mutations": muts,
                "deleted_tests": fp.deleted_tests,
                "red_prod_defect_tests": fp.red_prod_defect_tests,
            }
        )

    _PLAN_PATH.write_text(json.dumps(validated, indent=1), encoding="utf-8")

    n_files = len(validated)
    n_mut = sum(len(p["mutations"]) for p in validated)
    bad = [
        (p["file"], m["src_file"], m["search_status"])
        for p in validated
        for m in p["mutations"]
        if m["search_status"] != "ok"
    ]
    n_red = sum(len(p["red_prod_defect_tests"]) for p in validated)
    n_del = sum(len(p["deleted_tests"]) for p in validated)
    print(f"plan written: {_PLAN_PATH}")
    print(f"files={n_files} mutations={n_mut} red_prod_defect={n_red} deleted={n_del}")
    print(f"mutations with bad search ({len(bad)}):")
    for f, s, st in bad:
        print(f"  [{st}] {f} -> {s}")
    return 0


def _latest_junit() -> Path | None:
    """Return the most recent ``junit_custom_*.xml`` under reports/tests.

    Returns:
        Path | None: Newest matching JUnit file, or ``None`` if none exist.
    """
    candidates = sorted(
        _REPORTS.glob("junit_custom_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return candidates[0] if candidates else None


def _parse_junit(path: Path) -> dict[str, dict[str, str]]:
    """Parse a JUnit XML file into per-test outcomes.

    Args:
        path: JUnit XML file path.

    Returns:
        dict[str, dict[str, str]]: Mapping of ``file::Class::test`` nodeid-ish
            key to ``{"status": ..., "detail": ...}`` where status is one of
            ``pass`` / ``fail`` / ``error`` / ``skip``.
    """
    outcomes: dict[str, dict[str, str]] = {}
    tree = ET.parse(path)
    for case in tree.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        file_attr = case.get("file", "")
        status = "pass"
        detail = ""
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None:
            status, detail = "fail", (failure.get("message") or "")
        elif error is not None:
            status, detail = "error", (error.get("message") or "")
        elif skipped is not None:
            status, detail = "skip", (skipped.get("message") or "")
        key = f"{classname}::{name}" if classname else name
        outcomes[key] = {"status": status, "detail": detail[:300], "file": file_attr}
    return outcomes


def _match_nodeid(nodeid: str, outcomes: dict[str, dict[str, str]]) -> dict[str, str] | None:
    """Match a pytest nodeid to a parsed JUnit outcome.

    Args:
        nodeid: pytest nodeid (``tests/x/test_y.py::Class::test`` form).
        outcomes: Parsed JUnit outcomes keyed by ``Class::test`` / ``test``.

    Returns:
        dict[str, str] | None: The matching outcome, or ``None`` if not found.
    """
    parts = nodeid.split("::")
    func = parts[-1]
    cls = parts[-2] if len(parts) >= 3 else ""
    direct = f"{cls}::{func}" if cls else func
    if direct in outcomes:
        return outcomes[direct]
    for key, val in outcomes.items():
        if key.endswith(f"::{func}") or key == func:
            return val
    return None


def _run_sandbox(extra_args: str, timeout: int = 1800, memory: str = "10g") -> int:
    """Invoke the Docker sandbox in ``custom`` mode with the given pytest args.

    Args:
        extra_args: Pytest argument string (targets/nodeids plus flags).
        timeout: Container hard timeout in seconds.
        memory: Docker memory quota.

    Returns:
        int: The sandbox process exit code.
    """
    cmd = [
        "pixi",
        "run",
        "python",
        "-m",
        "scripts.sandbox.docker_sandbox",
        "custom",
        "--extra-args",
        f"{extra_args} -p no:timeout --continue-on-collection-errors",
        "--timeout",
        str(timeout),
        "--memory",
        memory,
    ]
    proc = subprocess.run(cmd, cwd=_REPO, check=False)  # noqa: S603
    return proc.returncode


def _load_plan() -> list[dict[str, object]]:
    """Load the aggregated remediation plan.

    Returns:
        list[dict[str, object]]: The plan entries.
    """
    return json.loads(_PLAN_PATH.read_text(encoding="utf-8"))


def cmd_green(args: argparse.Namespace) -> int:
    """Run hardened tests and report green/red per expectation.

    Targets the specific hardened-test nodeids from the plan (not whole files)
    to avoid unrelated slow/hanging tests. Runs in small batches with a bounded
    container timeout so a hang is localized.

    Args:
        args: Parsed CLI namespace with optional ``batch`` size and
            ``timeout`` (per-batch container hard timeout seconds).

    Returns:
        int: 0 if outcomes match expectations, 1 otherwise.
    """
    plan = _load_plan()
    red_expected: set[str] = set()
    for p in plan:
        for t in p.get("red_prod_defect_tests", []):
            red_expected.add(str(t))

    nodeids = sorted(
        {
            str(m.get("_resolved") or m.get("covering_test"))
            for p in plan
            for m in p.get("mutations", [])
            if "::" in str(m.get("_resolved") or m.get("covering_test", ""))
        }
        | red_expected
    )
    targets = nodeids
    batch = args.batch or 30
    timeout = args.timeout or 600
    all_outcomes: dict[str, dict[str, str]] = {}
    for i in range(0, len(targets), batch):
        chunk = targets[i : i + batch]
        print(f"[green] batch {i // batch + 1}/{(len(targets) + batch - 1) // batch}: {len(chunk)} nodeids", flush=True)
        _run_sandbox(" ".join(chunk), timeout=timeout)
        junit = _latest_junit()
        if junit is None:
            print("  ERROR: no junit produced")
            continue
        all_outcomes.update(_parse_junit(junit))

    (_AUDIT / "_green_outcomes.json").write_text(
        json.dumps(all_outcomes, indent=1), encoding="utf-8"
    )
    unexpected_fail = {
        k: v
        for k, v in all_outcomes.items()
        if v["status"] in {"fail", "error"} and not _is_expected_red(k, red_expected)
    }
    print(f"[green] total testcases={len(all_outcomes)} unexpected_failures={len(unexpected_fail)}")
    for k, v in unexpected_fail.items():
        print(f"  FAIL {k}: {v['detail'][:120]}")
    return 0 if not unexpected_fail else 1


def _is_expected_red(outcome_key: str, red_expected: set[str]) -> bool:
    """Return whether a failing testcase was expected to be red.

    Args:
        outcome_key: JUnit outcome key (``Class::test`` / ``test``).
        red_expected: Set of red-prod-defect covering-test nodeids.

    Returns:
        bool: ``True`` if the failing testcase matches a known red-prod-defect.
    """
    func = outcome_key.split("::")[-1]
    return any(nodeid.split("::")[-1] == func for nodeid in red_expected)


def cmd_falsify(args: argparse.Namespace) -> int:
    """Prove falsifiability by batched mutation, run, verify-red, revert.

    Args:
        args: Parsed CLI namespace with optional ``batch`` size.

    Returns:
        int: 0 if every covering test turned red, 1 if any did not.
    """
    plan = _load_plan()
    green_path = _AUDIT / "_green_outcomes.json"
    green: dict[str, dict[str, str]] = (
        json.loads(green_path.read_text(encoding="utf-8")) if green_path.is_file() else {}
    )
    green_pass = {k.split("::")[-1] for k, v in green.items() if v.get("status") == "pass"}

    mutations: list[dict[str, object]] = []
    results: dict[str, dict[str, str]] = {}
    for p in plan:
        for m in p.get("mutations", []):
            nodeid = str(m.get("_resolved") or m.get("covering_test"))
            func = nodeid.split("::")[-1]
            if m.get("baseline") != "green" or m.get("search_status") != "ok":
                continue
            if func not in green_pass:
                results[nodeid] = {
                    "status": "not-green",
                    "falsifiable": "skipped",
                    "detail": "covering test did not pass green baseline (skip-guard/defect/env)",
                }
                continue
            mutations.append(m)

    batches = _batch_mutations(mutations, args.batch or 20)
    for bi, batch in enumerate(batches):
        print(f"[falsify] batch {bi + 1}/{len(batches)}: {len(batch)} mutations")
        applied: list[tuple[Path, str]] = []
        try:
            for m in batch:
                path = _REPO / str(m["src_file"])
                original = path.read_text(encoding="utf-8")
                applied.append((path, original))
                path.write_text(
                    original.replace(str(m["search"]), str(m["replace"]), 1), encoding="utf-8"
                )
            nodeids = " ".join(str(m.get("_resolved") or m["covering_test"]) for m in batch)
            _run_sandbox(nodeids, timeout=args.timeout or 900)
            junit = _latest_junit()
            outcomes = _parse_junit(junit) if junit else {}
            for m in batch:
                nodeid = str(m.get("_resolved") or m["covering_test"])
                got = _match_nodeid(nodeid, outcomes)
                status = got["status"] if got else "absent"
                red = status in {"fail", "error"}
                results[nodeid] = {
                    "status": status,
                    "falsifiable": "yes" if red else "no",
                    "detail": got["detail"] if got else "not found in junit",
                }
        finally:
            for path, original in reversed(applied):
                path.write_text(original, encoding="utf-8")

    (_AUDIT / "_falsify_results.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    not_falsifiable = {k: v for k, v in results.items() if v["falsifiable"] != "yes"}
    print(f"[falsify] proven={len(results) - len(not_falsifiable)}/{len(results)}")
    for k, v in not_falsifiable.items():
        print(f"  NOT-RED {k}: status={v['status']} {v['detail'][:100]}")
    return 0 if not not_falsifiable else 1


def _batch_mutations(
    mutations: list[dict[str, object]], size: int
) -> list[list[dict[str, object]]]:
    """Group mutations into batches with distinct source files per batch.

    Args:
        mutations: Flat mutation list.
        size: Maximum mutations per batch.

    Returns:
        list[list[dict[str, object]]]: Batches, each holding at most one
            mutation per source file to keep red attribution clean.
    """
    batches: list[list[dict[str, object]]] = []
    pending = list(mutations)
    while pending:
        batch: list[dict[str, object]] = []
        used_src: set[str] = set()
        leftover: list[dict[str, object]] = []
        for m in pending:
            src = str(m["src_file"])
            if len(batch) < size and src not in used_src:
                batch.append(m)
                used_src.add(src)
            else:
                leftover.append(m)
        batches.append(batch)
        pending = leftover
    return batches


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        int: Process exit code.
    """
    parser = argparse.ArgumentParser(prog="verify-driver")
    sub = parser.add_subparsers(dest="cmd", required=True)
    agg = sub.add_parser("aggregate", help="Merge workflow outputs into _plan.json")
    agg.add_argument("outputs", nargs="+", help="Workflow .output JSON files")
    agg.set_defaults(func=cmd_aggregate)
    green = sub.add_parser("green", help="Run hardened test nodeids; verify green/expected-red")
    green.add_argument("--batch", type=int, default=30)
    green.add_argument("--timeout", type=int, default=600)
    green.set_defaults(func=cmd_green)
    fals = sub.add_parser("falsify", help="Batched mutation falsifiability proof")
    fals.add_argument("--batch", type=int, default=20)
    fals.add_argument("--timeout", type=int, default=900)
    fals.set_defaults(func=cmd_falsify)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
