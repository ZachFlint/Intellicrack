# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Run all development tools with parallel linting and progress tracking."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import NamedTuple


_raw_stdout = sys.stdout
if isinstance(_raw_stdout, io.TextIOWrapper):
    _raw_stdout.reconfigure(line_buffering=True)

ESC = "\033"
CHECK = "\u2714"
CROSS = "\u2718"
H = "\u2500"
TL = "\u256D"
TR = "\u256E"
BL = "\u2570"
BR = "\u256F"
V = "\u2502"
CLEAR_EOL = f"{ESC}[K"

BAR_FILL = "\u2588"
BAR_HEAD = "\u2593"
BAR_EMPTY = "\u2591"
SPINNER = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"

BAR_DONE = f"{ESC}[1;92m"
BAR_PROGRESS = f"{ESC}[93m"
BAR_REMAIN = f"{ESC}[38;5;240m"
BAR_COMPLETE = f"{ESC}[1;92m"
WHITE_BRIGHT = f"{ESC}[97m"

GROUP_COLORS: dict[str, str] = {
    "py": f"{ESC}[36m",
    "rs": f"{ESC}[38;2;222;120;40m",
    "dash": f"{ESC}[95m",
}
GROUP_NAMES: dict[str, str] = {"py": "Python", "rs": "Rust", "dash": "Dashboard"}
GROUP_ALIASES: dict[str, str] = {
    "python": "py",
    "py": "py",
    "rust": "rs",
    "rs": "rs",
    "dashboard": "dash",
    "dash": "dash",
}
RESET = f"{ESC}[0m"
RED = f"{ESC}[31m"
GRAY = f"{ESC}[90m"
BRAND = f"{ESC}[38;2;228;0;43m"
BOLD_PURPLE = f"{ESC}[1;95m"
FINDINGS_RE = re.compile(r"(\d+)\s+findings")


class Tool(NamedTuple):
    """Single tool entry in the pipeline."""

    name: str
    recipe: str
    is_formatter: bool
    group: str


TOOLS: list[Tool] = [
    Tool("Ruff Fmt", "ruff-fmt", is_formatter=True, group="py"),
    Tool("Docformatter", "docformatter", is_formatter=True, group="py"),
    Tool("TOMLfmt", "tomlfmt", is_formatter=True, group="py"),
    Tool("JSONfmt", "jsonfmt", is_formatter=True, group="py"),
    Tool("YAMLfmt", "yamlfmt", is_formatter=True, group="py"),
    Tool("MDfmt", "mdfmt", is_formatter=True, group="py"),
    Tool("Ruff", "ruff", is_formatter=False, group="py"),
    Tool("Flake8", "flake8", is_formatter=False, group="py"),
    Tool("Wemake", "wemake", is_formatter=False, group="py"),
    Tool("BasedPyright", "basedpyright", is_formatter=False, group="py"),
    Tool("Mypy", "mypy", is_formatter=False, group="py"),
    Tool("Ty", "ty", is_formatter=False, group="py"),
    Tool("Pydocstyle", "pydocstyle", is_formatter=False, group="py"),
    Tool("Pydoclint", "pydoclint", is_formatter=False, group="py"),
    Tool("Interrogate", "interrogate", is_formatter=False, group="py"),
    Tool("McCabe", "mccabe", is_formatter=False, group="py"),
    Tool("Radon", "radon", is_formatter=False, group="py"),
    Tool("Xenon", "xenon", is_formatter=False, group="py"),
    Tool("Complexipy", "complexipy", is_formatter=False, group="py"),
    Tool("Skylos", "skylos", is_formatter=False, group="py"),
    Tool("Vulture", "vulture", is_formatter=False, group="py"),
    Tool("Dead", "dead", is_formatter=False, group="py"),
    Tool("Deadcode", "deadcode", is_formatter=False, group="py"),
    Tool("Uncalled", "uncalled", is_formatter=False, group="py"),
    Tool("Bandit", "bandit", is_formatter=False, group="py"),
    Tool("Semgrep", "semgrep", is_formatter=False, group="py"),
    Tool("Deptry", "deptry", is_formatter=False, group="py"),
    Tool("Vermin", "vermin", is_formatter=False, group="py"),
    Tool("JSONLint", "jsonlint", is_formatter=False, group="py"),
    Tool("Taplo", "taplo", is_formatter=False, group="py"),
    Tool("Markdown", "mdlint", is_formatter=False, group="py"),
    Tool("YAML", "yamllint", is_formatter=False, group="py"),
    Tool("ShellCheck", "shellcheck", is_formatter=False, group="py"),
    Tool("Blinter", "blinter", is_formatter=False, group="py"),
    Tool("PSScript", "psscriptanalyzer", is_formatter=False, group="py"),
    Tool("Codespell", "codespell", is_formatter=False, group="py"),
    Tool("PreCommitHooks", "precommit-hooks", is_formatter=False, group="py"),
    Tool("Clippy", "clippy", is_formatter=False, group="rs"),
    Tool("RustFmt", "rustfmt", is_formatter=True, group="rs"),
    Tool("CargoDeny", "cargo-deny", is_formatter=False, group="rs"),
    Tool("Nextest", "nextest", is_formatter=False, group="rs"),
    Tool("LlvmCov", "llvm-cov", is_formatter=False, group="rs"),
    Tool("Machete", "machete", is_formatter=False, group="rs"),
    Tool("RustAnalysis", "rust-code-analysis", is_formatter=False, group="rs"),
    Tool("Typos", "typos", is_formatter=False, group="rs"),
    Tool("Dashboard", "lint-dashboard", is_formatter=True, group="dash"),
]


class ToolResult(NamedTuple):
    """Result from running a single tool."""

    name: str
    recipe: str
    findings: int
    duration: float
    success: bool
    is_formatter: bool


def _classify_tools(
    tools: list[Tool],
) -> tuple[list[Tool], list[Tool], list[Tool]]:
    """Split tool list into formatters, linters, and dashboard phases.

    Args:
        tools: Full list of tools to classify.

    Returns:
        tuple[list[Tool], list[Tool], list[Tool]]: Formatters, linters,
            and dashboard tools.
    """
    formatters: list[Tool] = []
    linters: list[Tool] = []
    dashboard: list[Tool] = []
    for t in tools:
        if t.group == "dash":
            dashboard.append(t)
        elif t.is_formatter:
            formatters.append(t)
        else:
            linters.append(t)
    return formatters, linters, dashboard


_DEFAULT_DURATION = 15.0
_DURATION_CACHE_PATH = Path("reports/.tool_durations.json")
_TICK_INTERVAL = 0.2
_TERM_REFRESH_TICKS = 10


def _load_durations() -> dict[str, float]:
    """Load cached tool durations from JSON file.

    Returns:
        dict[str, float]: Mapping of recipe names to durations in seconds.
    """
    try:
        text = _DURATION_CACHE_PATH.read_text(encoding="utf-8")
        parsed: dict[str, float] = json.loads(text)
        return {k: float(v) for k, v in parsed.items()}
    except (
        OSError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        AttributeError,
    ):
        return {}


def _save_durations(durations: dict[str, float]) -> None:
    """Write updated tool durations to JSON cache file.

    Args:
        durations: Mapping of recipe names to durations in seconds.
    """
    try:
        _DURATION_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DURATION_CACHE_PATH.write_text(
            json.dumps(durations, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def _parse_findings(output: str) -> int:
    """Extract findings count from tool output.

    Args:
        output: Combined stdout and stderr from tool execution.

    Returns:
        int: Number of findings parsed from the output.
    """
    match = FINDINGS_RE.search(output)
    return int(match.group(1)) if match else 0


def _read_report_findings(recipe: str) -> int | None:
    """Try to read findings from JSON report file as fallback.

    Args:
        recipe: The just recipe name used to locate the report file.

    Returns:
        int | None: Number of findings from the report, or None if
            unavailable.
    """
    report_path = Path(f"reports/json/{recipe}_findings.json")
    if not report_path.exists():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8-sig"))
        total = data.get("total_findings")
        if isinstance(total, int):
            return total
    except (json.JSONDecodeError, OSError, KeyError, TypeError):
        pass
    return None


_CREATE_NEW_PROCESS_GROUP = 0x00000200
_TOOL_TIMEOUT = 600


def _run_just(recipe: str) -> subprocess.CompletedProcess[str]:
    """Run a just recipe in an isolated process group.

    Args:
        recipe: The just recipe name to execute.

    Returns:
        subprocess.CompletedProcess[str]: The completed process result.
    """
    creation_flags = _CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    return subprocess.run(
        ["just", recipe],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=_TOOL_TIMEOUT,
        creationflags=creation_flags,
        check=False,
    )


def run_tool(tool: Tool) -> ToolResult:
    """Run a single tool via just and capture results.

    Args:
        tool: The tool definition to execute.

    Returns:
        ToolResult: Result containing name, findings, duration, and status.
    """
    start = time.monotonic()
    try:
        result = _run_just(tool.recipe)
        duration = round(time.monotonic() - start, 1)
        output = (result.stdout or "") + (result.stderr or "")
        findings = 0
        if not tool.is_formatter:
            findings = _parse_findings(output)
            if findings == 0:
                report_findings = _read_report_findings(tool.recipe)
                if report_findings is not None and report_findings > 0:
                    findings = report_findings
        return ToolResult(
            tool.name, tool.recipe, findings, duration,
            success=True, is_formatter=tool.is_formatter,
        )
    except subprocess.TimeoutExpired:
        duration = round(time.monotonic() - start, 1)
        return ToolResult(
            tool.name, tool.recipe, 0, duration,
            success=False, is_formatter=tool.is_formatter,
        )
    except OSError:
        duration = round(time.monotonic() - start, 1)
        return ToolResult(
            tool.name, tool.recipe, 0, duration,
            success=False, is_formatter=tool.is_formatter,
        )


def _format_eta(seconds: float) -> str:
    """Format seconds into a human-readable ETA string.

    Args:
        seconds: Estimated remaining seconds.

    Returns:
        str: Formatted string like ``'~3m 12s'`` or empty if zero.
    """
    if seconds <= 0:
        return ""
    minutes = int(seconds) // 60
    secs = int(seconds) % 60
    if minutes > 0:
        return f"~{minutes}m {secs:02d}s"
    return f"~{secs}s"


class ProgressTracker:
    """Thread-safe live progress bar with background ticker and ETA countdown.

    Args:
        total: Total number of tools to run across all phases.
        durations: Cached durations keyed by recipe name.
        max_workers: Max parallel workers for ETA calculation.
    """

    def __init__(
        self,
        total: int,
        durations: dict[str, float],
        max_workers: int,
    ) -> None:
        self._lock = threading.Lock()
        self._completed = 0
        self._total = total
        self._phase = ""
        self._active_workers = 0
        self._durations = dict(durations)
        self._all_remaining: set[str] = set()
        self._linter_recipes: set[str] = set()
        self._is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        self._max_workers = max_workers
        self._parallel = False
        self._ci_counter = 0
        self._tick_count = 0
        self._eta_base_time = 0.0
        self._eta_base_secs = 0.0
        self._term_width = shutil.get_terminal_size((80, 24)).columns
        self._term_width_tick = 0
        self._stop_event = threading.Event()
        self._ticker = threading.Thread(
            target=self._tick_loop, daemon=True,
        )

    def set_all_recipes(
        self,
        formatter_recipes: list[str],
        linter_recipes: list[str],
        dashboard_recipes: list[str],
    ) -> None:
        """Register all phase recipes for global ETA calculation.

        Args:
            formatter_recipes: Recipes in the formatting phase.
            linter_recipes: Recipes in the parallel linting phase.
            dashboard_recipes: Recipes in the dashboard phase.
        """
        with self._lock:
            self._all_remaining = (
                set(formatter_recipes)
                | set(linter_recipes)
                | set(dashboard_recipes)
            )
            self._linter_recipes = set(linter_recipes)

    def start(self) -> None:
        """Start the live background ticker thread."""
        with self._lock:
            self._recalculate_eta()
        self._ticker.start()

    def stop(self) -> None:
        """Stop the background ticker and clear the progress line."""
        self._stop_event.set()
        self._ticker.join(timeout=1.0)
        if self._is_tty:
            sys.stdout.write(f"\r{CLEAR_EOL}")
            sys.stdout.flush()

    def set_phase(self, name: str) -> None:
        """Update current phase label.

        Args:
            name: Phase display name.
        """
        with self._lock:
            self._phase = name
            self._parallel = name == "Linting"

    def record_start(self) -> None:
        """Increment active worker count for parallel tracking."""
        with self._lock:
            self._active_workers += 1

    def record_completion(self, tool: Tool, result: ToolResult) -> None:
        """Record tool completion and print result with progress.

        Args:
            tool: The tool definition that completed.
            result: The execution result for the tool.
        """
        gc = GROUP_COLORS.get(tool.group, "")
        with self._lock:
            self._completed += 1
            self._active_workers = max(0, self._active_workers - 1)
            self._all_remaining.discard(result.recipe)
            self._linter_recipes.discard(result.recipe)
            self._durations[result.recipe] = result.duration

            if self._is_tty:
                sys.stdout.write(f"\r{CLEAR_EOL}")
                sys.stdout.flush()

            if result.success:
                if result.is_formatter:
                    print(
                        f"  {gc}{CHECK} {result.name}:"
                        f" Done in {result.duration}s{RESET}",
                    )
                else:
                    print(
                        f"  {gc}{CHECK} {result.name}:"
                        f" Completed in {result.duration}s"
                        f" with {result.findings} findings{RESET}",
                    )
            else:
                print(
                    f"  {RED}{CROSS} {result.name}:"
                    f" Failed after {result.duration}s{RESET}",
                )

            self._recalculate_eta()

            if not self._is_tty:
                self._ci_counter += 1
                if self._ci_counter % 5 == 0 or self._completed == self._total:
                    eta_str = _format_eta(self._eta_base_secs)
                    print(
                        f"  {GRAY}[{self._completed}/{self._total}]"
                        f" {self._phase} {eta_str}{RESET}",
                    )

    def _tick_loop(self) -> None:
        while not self._stop_event.wait(_TICK_INTERVAL):
            with self._lock:
                if self._is_tty and self._completed < self._total:
                    self._tick_count += 1
                    self._render_bar()

    def _render_bar(self) -> None:
        self._term_width_tick += 1
        if self._term_width_tick >= _TERM_REFRESH_TICKS:
            self._term_width_tick = 0
            self._term_width = shutil.get_terminal_size((80, 24)).columns
        fraction = self._completed / self._total if self._total > 0 else 0.0

        elapsed_since_calc = time.monotonic() - self._eta_base_time
        live_eta = max(0.0, self._eta_base_secs - elapsed_since_calc)
        eta_str = _format_eta(live_eta)

        spinner_char = SPINNER[self._tick_count % len(SPINNER)]

        counter = f"{self._completed}/{self._total}"
        right_text = f" {counter} {self._phase} {spinner_char} {eta_str}"
        bar_width = max(10, min(35, self._term_width - len(right_text) - 4))

        filled_count = int(fraction * bar_width)
        if filled_count >= bar_width:
            bar = f"{BAR_COMPLETE}{BAR_FILL * bar_width}{RESET}"
        else:
            filled_part = BAR_FILL * filled_count
            empty_part = BAR_EMPTY * (bar_width - filled_count - 1)
            bar = (
                f"{BAR_DONE}{filled_part}{BAR_PROGRESS}{BAR_HEAD}"
                f"{BAR_REMAIN}{empty_part}{RESET}"
            )

        line = f"  {bar}{WHITE_BRIGHT}{right_text}{RESET}"
        sys.stdout.write(f"\r{line}{CLEAR_EOL}")
        sys.stdout.flush()

    def _recalculate_eta(self) -> None:
        self._eta_base_time = time.monotonic()
        self._eta_base_secs = self._estimate_remaining()

    def _estimate_remaining(self) -> float:
        sequential = sum(
            self._durations.get(r, _DEFAULT_DURATION)
            for r in self._all_remaining
            if r not in self._linter_recipes
        )
        parallel = sum(
            self._durations.get(r, _DEFAULT_DURATION)
            for r in self._linter_recipes
        )
        if self._max_workers > 1:
            parallel /= self._max_workers
        return sequential + parallel


def _parse_args() -> tuple[list[str], list[str], int]:
    """Parse CLI arguments for skip list, group filter, and worker count.

    Returns:
        tuple[list[str], list[str], int]: The skip list, group filter,
            and max workers count.
    """
    args = sys.argv[1:]
    skip_list: list[str] = []
    group_filter: list[str] = []
    max_workers = 4
    i = 0
    while i < len(args):
        if args[i] == "--skip" and i + 1 < len(args):
            skip_list = args[i + 1].split(",")
            i += 2
        elif args[i] == "--workers" and i + 1 < len(args):
            with contextlib.suppress(ValueError):
                max_workers = min(max(int(args[i + 1]), 1), 16)
            i += 2
        elif not args[i].startswith("--") and args[i].lower() in GROUP_ALIASES:
            group_filter.append(GROUP_ALIASES[args[i].lower()])
            i += 1
        else:
            i += 1
    return skip_list, group_filter, max_workers


def _print_banner() -> None:
    """Print the branded pipeline banner."""
    line = H * 31
    print(f"\n{BRAND}{TL}{line}{TR}{RESET}")
    print(
        f"{BRAND}{V}{RESET}     {BOLD_PURPLE}Running All Dev Tools{RESET}"
        f"     {BRAND}{V}{RESET}",
    )
    print(f"{BRAND}{BL}{line}{BR}{RESET}\n")


def _filter_tools(
    tools: list[Tool],
    group_filter: list[str],
    skip_list: list[str],
) -> list[Tool]:
    """Apply group and skip filters to the tool list.

    Args:
        tools: Full list of tools to filter.
        group_filter: Group codes to include (empty means all).
        skip_list: Recipe names to exclude.

    Returns:
        list[Tool]: Filtered list of tools to run.
    """
    if group_filter:
        tools = [t for t in tools if t.group in group_filter]
        filter_names = ", ".join(GROUP_NAMES.get(g, g) for g in group_filter)
        print(f"  {GRAY}Filtering: {filter_names} only{RESET}\n")

    if skip_list:
        valid_names = [t.recipe for t in tools]
        invalid = [s for s in skip_list if s not in valid_names]
        if invalid:
            print(f"  {RED}Unknown tool(s): {', '.join(invalid)}{RESET}")
            print(f"  {GRAY}Valid names: {', '.join(valid_names)}{RESET}\n")
            sys.exit(1)
        tools = [t for t in tools if t.recipe not in skip_list]
        print(f"  {GRAY}Skipping: {', '.join(skip_list)}{RESET}\n")

    return tools


def _run_phase_sequential(
    tools: list[Tool],
    tracker: ProgressTracker,
    results: dict[str, ToolResult],
    phase_name: str,
) -> None:
    """Run a list of tools sequentially through a single phase.

    Args:
        tools: Tools to run in order.
        tracker: Progress tracker for output management.
        results: Mutable results dict to update with completions.
        phase_name: Display name for this phase.
    """
    if not tools:
        return
    tracker.set_phase(phase_name)
    for tool in tools:
        result = run_tool(tool)
        results[tool.recipe] = result
        tracker.record_completion(tool, result)


def _run_phase_parallel(
    tools: list[Tool],
    tracker: ProgressTracker,
    results: dict[str, ToolResult],
    max_workers: int,
) -> None:
    """Run linters concurrently using a thread pool.

    Args:
        tools: Linter tools to run in parallel.
        tracker: Progress tracker for output management.
        results: Mutable results dict to update with completions.
        max_workers: Maximum number of concurrent workers.

    Raises:
        KeyboardInterrupt: Re-raised after cancelling pending futures.
    """
    if not tools:
        return
    if max_workers > 1 and len(tools) > 1:
        print(
            f"  {GRAY}Parallel linting: {len(tools)} tools,"
            f" {max_workers} workers{RESET}\n",
        )
    tracker.set_phase("Linting")
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        future_to_tool: dict[Future[ToolResult], Tool] = {}
        for tool in tools:
            tracker.record_start()
            future = pool.submit(run_tool, tool)
            future_to_tool[future] = tool

        for completed in as_completed(future_to_tool):
            tool = future_to_tool[completed]
            result = completed.result()
            results[tool.recipe] = result
            tracker.record_completion(tool, result)
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)


def _print_summary(results: dict[str, ToolResult], elapsed: float) -> None:
    """Print the final summary line with time, findings, and pass count.

    Args:
        results: All tool results keyed by recipe name.
        elapsed: Total elapsed wall-clock seconds.
    """
    total_time = round(elapsed, 1)
    total_findings = sum(r.findings for r in results.values())
    passed_count = sum(
        1 for r in results.values() if r.success and r.findings == 0
    )
    total_count = len(results)
    print(f"\n{GRAY}{'-' * 60}{RESET}")
    print(
        f"Time: {ESC}[36m{total_time}s{RESET}"
        f" | Findings: {ESC}[33m{total_findings}{RESET}"
        f" | Passed: {ESC}[32m{passed_count}/{total_count}{RESET}",
    )


def main() -> None:
    """Run all development tools with parallel linting and progress tracking."""
    skip_list, group_filter, max_workers = _parse_args()
    _print_banner()

    tools = _filter_tools(list(TOOLS), group_filter, skip_list)
    formatters, linters, dashboard = _classify_tools(tools)
    durations = _load_durations()
    total_tools = len(formatters) + len(linters) + len(dashboard)

    tracker = ProgressTracker(total_tools, durations, max_workers)
    tracker.set_all_recipes(
        [t.recipe for t in formatters],
        [t.recipe for t in linters],
        [t.recipe for t in dashboard],
    )
    results: dict[str, ToolResult] = {}
    global_start = time.monotonic()

    try:
        tracker.start()
        _run_phase_sequential(formatters, tracker, results, "Formatting")
        _run_phase_parallel(linters, tracker, results, max_workers)
        _run_phase_sequential(dashboard, tracker, results, "Dashboard")
        tracker.stop()
    except KeyboardInterrupt:
        tracker.stop()
        print(f"\n\n  {RED}Interrupted{RESET}")
        os._exit(130)

    _print_summary(results, time.monotonic() - global_start)
    durations.update({r.recipe: r.duration for r in results.values()})
    _save_durations(durations)


if __name__ == "__main__":
    main()
