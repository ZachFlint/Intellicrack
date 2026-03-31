# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Download GitHub Actions CI job logs and artifacts to reports/ci-jobs/."""

from __future__ import annotations

import contextlib
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO


WORKFLOWS: list[str] = [
    "ci.yml",
    "claude-code-review.yml",
    "claude.yml",
    "gemini-dispatch.yml",
    "gemini-invoke.yml",
    "gemini-review.yml",
    "gemini-scheduled-triage.yml",
    "gemini-triage.yml",
    "qodana_code_quality.yml",
]

MAX_WORKERS: int = 4
GH_TIMEOUT: int = 60

E: str = "\x1b"


def _print(msg: str, *, file: TextIO | None = None) -> None:
    """Print with immediate flush so output appears in real time through piped streams.

    Args:
        msg: The message to print.
        file: Output stream (defaults to sys.stdout via print's default).
    """
    if file is not None:
        print(msg, file=file, flush=True)
    else:
        print(msg, flush=True)


@dataclass
class JobResult:
    """Result of downloading a single job's log."""

    job_name: str
    job_id: int
    status: str
    conclusion: str | None
    log_downloaded: bool
    error: str | None = None


@dataclass
class WorkflowResult:
    """Result of processing a single workflow."""

    workflow_file: str
    run_id: int | None = None
    run_url: str | None = None
    run_status: str | None = None
    run_conclusion: str | None = None
    jobs: list[JobResult] = field(default_factory=list)
    artifacts_downloaded: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None


def run_gh(args: list[str], *, timeout: int = GH_TIMEOUT) -> str:
    """Execute a gh CLI command and return stdout.

    Args:
        args: Arguments to pass to the gh CLI.
        timeout: Maximum seconds to wait for the command.

    Returns:
        The stdout output from the gh command.

    Raises:
        subprocess.CalledProcessError: If the gh command exits with a non-zero code.
    """
    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, ["gh", *args], result.stdout, result.stderr)
    return result.stdout


def detect_repo() -> str:
    """Detect the owner/repo slug from the current git repository.

    Returns:
        The owner/repo string (e.g. "user/repo").
    """
    try:
        raw = run_gh(["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        _print(f"{E}[31mERROR:{E}[0m Failed to detect repository: {exc}", file=sys.stderr)
        sys.exit(1)
    else:
        repo = raw.strip()
        if "/" not in repo:
            _print(f"{E}[31mERROR:{E}[0m Unexpected repo format: {repo}", file=sys.stderr)
            sys.exit(1)
        return repo


def sanitize_dirname(name: str) -> str:
    """Convert a string to a filesystem-safe directory name.

    Args:
        name: The raw name to sanitize.

    Returns:
        A sanitized directory name with unsafe characters replaced by hyphens.
    """
    safe = re.sub(r"[^\w\-.]", "-", name.strip())
    safe = re.sub(r"-{2,}", "-", safe)
    return safe.strip("-").lower()


def get_last_completed_run(workflow_file: str) -> dict[str, object] | None:
    """Get the most recent completed run for a workflow.

    Args:
        workflow_file: The workflow filename (e.g. "ci.yml").

    Returns:
        A dict with run info (databaseId, url, status, conclusion) or None if no run found.
    """
    try:
        raw = run_gh([
            "run",
            "list",
            "--workflow",
            workflow_file,
            "--status",
            "completed",
            "--limit",
            "1",
            "--json",
            "databaseId,url,status,conclusion",
        ])
        runs: list[dict[str, object]] = json.loads(raw)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    else:
        if not runs:
            return None
        return runs[0]


def get_run_jobs(run_id: int) -> list[dict[str, object]]:
    """List all jobs in a workflow run.

    Args:
        run_id: The workflow run database ID.

    Returns:
        A list of job dicts with databaseId, name, status, conclusion fields.
    """
    try:
        raw = run_gh([
            "run",
            "view",
            str(run_id),
            "--json",
            "jobs",
            "-q",
            ".jobs",
        ])
        jobs: list[dict[str, object]] = json.loads(raw)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    else:
        return jobs


def download_job_log(repo: str, job_id: int, dest: Path) -> str | None:
    """Download a single job's log file.

    Args:
        repo: The owner/repo slug.
        job_id: The job database ID.
        dest: The directory to write job.log into.

    Returns:
        None on success, or an error message string on failure.
    """
    dest.mkdir(parents=True, exist_ok=True)
    log_path = dest / "job.log"
    try:
        raw = run_gh(
            [
                "api",
                f"repos/{repo}/actions/jobs/{job_id}/logs",
            ],
            timeout=120,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        if "410" in stderr or "Gone" in stderr:
            log_path.write_text("(log expired - GitHub returns 410 Gone)\n", encoding="utf-8")
            return "log expired (410 Gone)"
        if "404" in stderr or "Not Found" in stderr:
            log_path.write_text("(no log available - job may have been skipped)\n", encoding="utf-8")
            return "no log (404)"
        return f"HTTP error: {stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "timeout downloading log"
    else:
        log_path.write_text(raw, encoding="utf-8")
        return None


def download_run_artifacts(run_id: int, dest: Path) -> int:
    """Download all artifacts for a workflow run.

    Args:
        run_id: The workflow run database ID.
        dest: The directory to download artifacts into.

    Returns:
        The number of artifacts downloaded.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        run_gh(
            [
                "run",
                "download",
                str(run_id),
                "--dir",
                str(dest),
            ],
            timeout=300,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return 0
    else:
        return sum(1 for p in dest.iterdir() if p.is_dir())


def process_workflow(
    workflow_file: str,
    repo: str,
    base_dir: Path,
    workflow_idx: int,
    workflow_total: int,
) -> WorkflowResult:
    """Process a single workflow: download logs and artifacts.

    Args:
        workflow_file: The workflow filename (e.g. "ci.yml").
        repo: The owner/repo slug.
        base_dir: The base output directory (reports/ci-jobs/).
        workflow_idx: 1-based index of this workflow in the processing order.
        workflow_total: Total number of workflows being processed.

    Returns:
        A WorkflowResult with details about what was downloaded.
    """
    prefix = f"{E}[36m[{workflow_idx}/{workflow_total}]{E}[0m"
    stem = workflow_file.removesuffix(".yml").removesuffix(".yaml")
    workflow_dir = base_dir / sanitize_dirname(stem)
    result = WorkflowResult(workflow_file=workflow_file)

    _print(f"{prefix} {workflow_file}: finding last run...")
    run_info = get_last_completed_run(workflow_file)
    if run_info is None:
        result.skipped = True
        result.skip_reason = "no completed runs found"
        _print(f"{prefix} {workflow_file}: {E}[33mskipped{E}[0m (no completed runs)")
        return result

    run_id = int(str(run_info.get("databaseId", 0)))
    if run_id == 0:
        result.skipped = True
        result.skip_reason = "invalid run ID"
        _print(f"{prefix} {workflow_file}: {E}[33mskipped{E}[0m (invalid run ID)")
        return result

    result.run_id = run_id
    result.run_url = str(run_info.get("url", ""))
    result.run_status = str(run_info.get("status", ""))
    result.run_conclusion = str(run_info.get("conclusion", ""))

    _print(f"{prefix} {workflow_file}: fetching job list for run {run_id}...")
    jobs = get_run_jobs(run_id)
    if not jobs:
        result.skipped = True
        result.skip_reason = "no jobs found in run"
        _print(f"{prefix} {workflow_file}: {E}[33mskipped{E}[0m (no jobs in run)")
        return result

    _print(f"{prefix} {workflow_file}: downloading {len(jobs)} job logs...")
    completed_count = 0
    total_jobs = len(jobs)

    def _download_one_job(job: dict[str, object]) -> JobResult:
        job_name = str(job.get("name", "unknown"))
        jid = int(str(job.get("databaseId", 0)))
        job_status = str(job.get("status", ""))
        job_conclusion: str | None = None
        raw_conclusion = job.get("conclusion")
        if raw_conclusion is not None:
            job_conclusion = str(raw_conclusion)

        job_dir = workflow_dir / sanitize_dirname(job_name)
        error = download_job_log(repo, jid, job_dir)

        return JobResult(
            job_name=job_name,
            job_id=jid,
            status=job_status,
            conclusion=job_conclusion,
            log_downloaded=error is None,
            error=error,
        )

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_download_one_job, job): job for job in jobs}
        for future in as_completed(futures):
            job_result = future.result()
            result.jobs.append(job_result)
            completed_count += 1
            mark = f"{E}[32m+{E}[0m" if job_result.log_downloaded else f"{E}[31m!{E}[0m"
            _print(f"{prefix}   [{mark}] {job_result.job_name} ({completed_count}/{total_jobs})")

    result.jobs.sort(key=lambda j: j.job_name)

    _print(f"{prefix} {workflow_file}: checking artifacts...")
    artifacts_dir = workflow_dir / "_artifacts"
    result.artifacts_downloaded = download_run_artifacts(run_id, artifacts_dir)
    if result.artifacts_downloaded == 0 and artifacts_dir.exists():
        with contextlib.suppress(OSError):
            artifacts_dir.rmdir()

    n_logs = sum(1 for j in result.jobs if j.log_downloaded)
    _print(f"{prefix} {workflow_file}: {E}[32mdone{E}[0m ({n_logs} logs, {result.artifacts_downloaded} artifacts)")
    return result


def generate_summary_json(results: list[WorkflowResult], dest: Path) -> None:
    """Write a JSON summary of all workflow results.

    Args:
        results: The list of WorkflowResult objects.
        dest: The directory to write summary.json into.
    """
    data: dict[str, object] = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "workflows_total": len(results),
        "workflows_downloaded": sum(1 for r in results if not r.skipped),
        "workflows_skipped": sum(1 for r in results if r.skipped),
        "jobs_total": sum(len(r.jobs) for r in results),
        "logs_downloaded": sum(sum(1 for j in r.jobs if j.log_downloaded) for r in results),
        "logs_failed": sum(sum(1 for j in r.jobs if not j.log_downloaded) for r in results),
        "artifacts_total": sum(r.artifacts_downloaded for r in results),
        "workflows": [
            {
                "file": r.workflow_file,
                "run_id": r.run_id,
                "run_url": r.run_url,
                "conclusion": r.run_conclusion,
                "skipped": r.skipped,
                "skip_reason": r.skip_reason,
                "jobs": [
                    {
                        "name": j.job_name,
                        "id": j.job_id,
                        "conclusion": j.conclusion,
                        "log_downloaded": j.log_downloaded,
                        "error": j.error,
                    }
                    for j in r.jobs
                ],
                "artifacts_downloaded": r.artifacts_downloaded,
            }
            for r in results
        ],
    }
    path = dest / "summary.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def generate_summary_txt(results: list[WorkflowResult], dest: Path) -> None:
    """Write a plain-text summary of all workflow results.

    Args:
        results: The list of WorkflowResult objects.
        dest: The directory to write summary.txt into.
    """
    lines: list[str] = []
    lines.extend(("CI Reports Summary", "=" * 60, f"Generated: {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}", ""))

    total_jobs = sum(len(r.jobs) for r in results)
    total_logs = sum(sum(1 for j in r.jobs if j.log_downloaded) for r in results)
    total_artifacts = sum(r.artifacts_downloaded for r in results)
    total_skipped = sum(1 for r in results if r.skipped)

    lines.extend((f"Workflows: {len(results)} total, {len(results) - total_skipped} downloaded, {total_skipped} skipped", f"Jobs:      {total_jobs} total, {total_logs} logs downloaded", f"Artifacts: {total_artifacts} downloaded", ""))

    for r in results:
        if r.skipped:
            lines.append(f"  [SKIP] {r.workflow_file}: {r.skip_reason}")
            continue
        conclusion_str = r.run_conclusion or "unknown"
        lines.append(f"  [{conclusion_str.upper():^8s}] {r.workflow_file} (run {r.run_id})")
        for j in r.jobs:
            log_mark = "+" if j.log_downloaded else "!"
            j_conclusion = j.conclusion or "?"
            error_suffix = f" ({j.error})" if j.error else ""
            lines.append(f"    [{log_mark}] {j.job_name} [{j_conclusion}]{error_suffix}")
        if r.artifacts_downloaded > 0:
            lines.append(f"    artifacts: {r.artifacts_downloaded}")

    lines.append("")
    path = dest / "summary.txt"
    path.write_text("\n".join(lines), encoding="utf-8")


def print_console_summary(results: list[WorkflowResult]) -> None:
    """Print a colored summary to the console.

    Args:
        results: The list of WorkflowResult objects.
    """
    total_jobs = sum(len(r.jobs) for r in results)
    total_logs = sum(sum(1 for j in r.jobs if j.log_downloaded) for r in results)
    total_artifacts = sum(r.artifacts_downloaded for r in results)
    total_skipped = sum(1 for r in results if r.skipped)
    total_downloaded = len(results) - total_skipped

    _print(f"\n{E}[1;36m{'=' * 50}{E}[0m")
    _print(f"{E}[1;36m  CI Reports Download Summary{E}[0m")
    _print(f"{E}[1;36m{'=' * 50}{E}[0m\n")

    for r in results:
        if r.skipped:
            _print(f"  {E}[33m[SKIP]{E}[0m {r.workflow_file}: {r.skip_reason}")
            continue

        conclusion = r.run_conclusion or "unknown"
        if conclusion == "success":
            color = "32"
        elif conclusion == "failure":
            color = "31"
        else:
            color = "33"

        _print(f"  {E}[{color}m[{conclusion.upper():^8s}]{E}[0m {r.workflow_file}")
        for j in r.jobs:
            mark = f"{E}[32m+{E}[0m" if j.log_downloaded else f"{E}[31m!{E}[0m"
            j_conclusion = j.conclusion or "?"
            error_suffix = f" {E}[33m({j.error}){E}[0m" if j.error else ""
            _print(f"    [{mark}] {j.job_name} [{j_conclusion}]{error_suffix}")
        if r.artifacts_downloaded > 0:
            _print(f"    {E}[36martifacts: {r.artifacts_downloaded}{E}[0m")

    _print(f"\n  Workflows: {total_downloaded} downloaded, {total_skipped} skipped")
    _print(f"  Jobs:      {total_jobs} total, {total_logs} logs OK")
    _print(f"  Artifacts: {total_artifacts}\n")


def main() -> int:
    """Download CI job logs and artifacts from GitHub Actions.

    Returns:
        Exit code (0 for success, 1 for fatal errors).
    """
    _print(f"{E}[36m[CI]{E}[0m Checking gh authentication...")
    try:
        run_gh(["auth", "status"])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        _print(
            f"{E}[31mERROR:{E}[0m gh CLI not authenticated. Run 'gh auth login' first.",
            file=sys.stderr,
        )
        return 1

    _print(f"{E}[36m[CI]{E}[0m Detecting repository...")
    repo = detect_repo()
    _print(f"{E}[36m[CI]{E}[0m Repository: {repo}")

    base_dir = Path("reports/ci-jobs")
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    _print(f"{E}[36m[CI]{E}[0m Processing {len(WORKFLOWS)} workflows...\n")

    results: list[WorkflowResult] = []
    for idx, wf in enumerate(WORKFLOWS, start=1):
        wf_result = process_workflow(wf, repo, base_dir, idx, len(WORKFLOWS))
        results.append(wf_result)

    _print(f"\n{E}[36m[CI]{E}[0m Writing summaries...")
    generate_summary_json(results, base_dir)
    generate_summary_txt(results, base_dir)
    print_console_summary(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
