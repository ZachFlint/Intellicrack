"""Testing tools for MCP dev-tools server."""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ..config import LONG_TIMEOUT, PIXI
from ..validation import validate_path


def register_testing_tools(
    mcp: FastMCP,
    run_command: Callable[..., dict[str, Any]],
    error_result: Callable[[str], dict[str, Any]],
) -> None:
    """Register testing tools with the MCP server."""

    @mcp.tool()
    def pytest_run(
        path: str = "tests",
        markers: str | None = None,
        keyword: str | None = None,
        verbose: int = 0,
        quiet: int = 0,
        maxfail: int | None = None,
        exitfirst: bool = False,
        parallel: int | None = None,
        tb: str = "short",
        capture: str | None = None,
        show_capture: str | None = None,
        runxfail: bool = False,
        last_failed: bool = False,
        failed_first: bool = False,
        new_first: bool = False,
        durations: int | None = None,
        durations_min: float | None = None,
        strict_markers: bool = False,
        strict_config: bool = False,
        continue_on_collection_errors: bool = False,
        ignore: str | None = None,
        ignore_glob: str | None = None,
        rootdir: str | None = None,
        confcutdir: str | None = None,
        cache_clear: bool = False,
        stepwise: bool = False,
        stepwise_skip: bool = False,
        color: str | None = None,
        code_highlight: str | None = None,
        no_header: bool = False,
        override_ini: str | None = None,
        assert_mode: str | None = None,
        setup_show: bool = False,
        fixtures: bool = False,
        basetemp: str | None = None,
        plugins: str | None = None,
        disable_plugins: str | None = None,
        pyargs: bool = False,
        doctest_modules: bool = False,
        collect_only: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """
        Run pytest tests on specified path.

        Args:
            path: Test file or directory.
            markers: Pytest markers to select (e.g., "not slow").
            keyword: Keyword expression to filter tests (-k).
            verbose: Verbosity level (0-3, use -v, -vv, -vvv).
            quiet: Quiet level (0-3, use -q, -qq, -qqq).
            maxfail: Stop after N failures.
            exitfirst: Exit on first failure (-x).
            parallel: Number of parallel workers (None=sequential, -1=auto).
            tb: Traceback style (auto, long, short, line, native, no).
            capture: Capture method (fd, sys, no, tee-sys).
            show_capture: When to show captured output (no, stdout, stderr, log, all).
            runxfail: Run tests marked xfail as if not marked.
            last_failed: Re-run only last failed tests (--lf).
            failed_first: Run last failed tests first (--ff).
            new_first: Run new tests first (--nf).
            durations: Show N slowest setup/test durations (0=all).
            durations_min: Minimum duration (s) to show in durations.
            strict_markers: Markers not registered raise error.
            strict_config: Any warnings during parsing config file raise error.
            continue_on_collection_errors: Force test execution on collection errors.
            ignore: Ignore path during collection (can be comma-separated).
            ignore_glob: Ignore paths matching glob pattern.
            rootdir: Force root directory.
            confcutdir: Only load conftest.py's from this directory and below.
            cache_clear: Clear pytest cache before running.
            stepwise: Exit on test failure and continue from last failing test.
            stepwise_skip: Ignore first failing test and continue.
            color: Color terminal output (yes, no, auto).
            code_highlight: Highlight code in tracebacks (yes, no).
            no_header: Disable header in output.
            override_ini: Override ini option (e.g., "minversion=2.0").
            assert_mode: Assert mode (rewrite, plain).
            setup_show: Show setup/teardown of fixtures.
            fixtures: Show available fixtures and exit.
            basetemp: Base temporary directory for test runs.
            plugins: Comma-separated early-load plugins.
            disable_plugins: Comma-separated plugins to disable.
            pyargs: Try to interpret arguments as Python packages.
            doctest_modules: Run doctests in all .py modules.
            collect_only: Only collect tests, don't run them (--co).
            timeout: Per-test timeout in seconds (requires pytest-timeout).

        Returns:
            Dict with test results and output.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "pytest", path, f"--tb={tb}"]

        if markers:
            args.extend(["-m", markers])
        if keyword:
            args.extend(["-k", keyword])
        if verbose > 0:
            args.append("-" + "v" * verbose)
        if quiet > 0:
            args.append("-" + "q" * quiet)
        if maxfail is not None:
            args.extend(["--maxfail", str(maxfail)])
        if exitfirst:
            args.append("-x")
        if parallel is not None:
            args.extend(["-n", "auto" if parallel == -1 else str(parallel)])
        if capture:
            args.extend(["--capture", capture])
        if show_capture:
            args.extend(["--show-capture", show_capture])
        if runxfail:
            args.append("--runxfail")
        if last_failed:
            args.append("--lf")
        if failed_first:
            args.append("--ff")
        if new_first:
            args.append("--nf")
        if durations is not None:
            args.extend(["--durations", str(durations)])
        if durations_min is not None:
            args.extend(["--durations-min", str(durations_min)])
        if strict_markers:
            args.append("--strict-markers")
        if strict_config:
            args.append("--strict-config")
        if continue_on_collection_errors:
            args.append("--continue-on-collection-errors")
        if ignore:
            for p in ignore.split(","):
                args.extend(["--ignore", p.strip()])
        if ignore_glob:
            args.extend(["--ignore-glob", ignore_glob])
        if rootdir:
            args.extend(["--rootdir", rootdir])
        if confcutdir:
            args.extend(["--confcutdir", confcutdir])
        if cache_clear:
            args.append("--cache-clear")
        if stepwise:
            args.append("--stepwise")
        if stepwise_skip:
            args.append("--stepwise-skip")
        if color:
            args.extend(["--color", color])
        if code_highlight:
            args.extend(["--code-highlight", code_highlight])
        if no_header:
            args.append("--no-header")
        if override_ini:
            args.extend(["-o", override_ini])
        if assert_mode:
            args.extend(["--assert", assert_mode])
        if setup_show:
            args.append("--setup-show")
        if fixtures:
            args.append("--fixtures")
        if basetemp:
            args.extend(["--basetemp", basetemp])
        if plugins:
            for p in plugins.split(","):
                args.extend(["-p", p.strip()])
        if disable_plugins:
            for p in disable_plugins.split(","):
                args.extend(["-p", f"no:{p.strip()}"])
        if pyargs:
            args.append("--pyargs")
        if doctest_modules:
            args.append("--doctest-modules")
        if collect_only:
            args.append("--collect-only")
        if timeout is not None:
            args.extend(["--timeout", str(timeout)])

        return run_command(args, timeout=LONG_TIMEOUT)

    @mcp.tool()
    def pytest_collect(
        path: str = "tests",
        markers: str | None = None,
        keyword: str | None = None,
        quiet: int = 1,
        verbose: int = 0,
        ignore: str | None = None,
        ignore_glob: str | None = None,
        rootdir: str | None = None,
        confcutdir: str | None = None,
        pyargs: bool = False,
        doctest_modules: bool = False,
        import_mode: str | None = None,
        keep_duplicates: bool = False,
    ) -> dict[str, Any]:
        """
        Collect pytest test items without running them.

        Args:
            path: Test file or directory.
            markers: Pytest markers to filter (e.g., "not slow").
            keyword: Keyword expression to filter tests (-k).
            quiet: Quiet level (0-3, use -q, -qq, -qqq).
            verbose: Verbosity level (0-3, use -v, -vv, -vvv).
            ignore: Ignore path during collection (can be comma-separated).
            ignore_glob: Ignore paths matching glob pattern.
            rootdir: Force root directory.
            confcutdir: Only load conftest.py's from this directory and below.
            pyargs: Try to interpret arguments as Python packages.
            doctest_modules: Collect doctests in all .py modules.
            import_mode: Import mode (prepend, append, importlib).
            keep_duplicates: Keep duplicate tests.

        Returns:
            Dict with collected test items.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "pytest", "--collect-only", path]

        if markers:
            args.extend(["-m", markers])
        if keyword:
            args.extend(["-k", keyword])
        if quiet > 0:
            args.append("-" + "q" * quiet)
        if verbose > 0:
            args.append("-" + "v" * verbose)
        if ignore:
            for p in ignore.split(","):
                args.extend(["--ignore", p.strip()])
        if ignore_glob:
            args.extend(["--ignore-glob", ignore_glob])
        if rootdir:
            args.extend(["--rootdir", rootdir])
        if confcutdir:
            args.extend(["--confcutdir", confcutdir])
        if pyargs:
            args.append("--pyargs")
        if doctest_modules:
            args.append("--doctest-modules")
        if import_mode:
            args.extend(["--import-mode", import_mode])
        if keep_duplicates:
            args.append("--keep-duplicates")

        return run_command(args, timeout=LONG_TIMEOUT)

    @mcp.tool()
    def coverage_run(
        path: str = "tests",
        source: str = "intellicrack",
        fail_under: int | None = None,
        report_format: str = "term",
        omit: str | None = None,
        include: str | None = None,
        branch: bool = False,
        append: bool = False,
        context: str | None = None,
        markers: str | None = None,
        keyword: str | None = None,
        verbose: int = 0,
        maxfail: int | None = None,
        parallel: int | None = None,
        tb: str = "short",
        cov_config: str | None = None,
        no_cov_on_fail: bool = False,
        cov_append: bool = False,
        show_missing: bool = False,
    ) -> dict[str, Any]:
        """
        Run tests with coverage measurement.

        Args:
            path: Test file or directory.
            source: Source directory to measure (comma-separated for multiple).
            fail_under: Fail if coverage is below this percentage.
            report_format: Report format (term, term-missing, html, xml, json, lcov, annotate).
            omit: Comma-separated patterns for files to omit from coverage.
            include: Comma-separated patterns for files to include in coverage.
            branch: Measure branch coverage.
            append: Append to existing coverage data.
            context: Context to record for coverage data.
            markers: Pytest markers to select (e.g., "not slow").
            keyword: Keyword expression to filter tests (-k).
            verbose: Verbosity level (0-3).
            maxfail: Stop after N failures.
            parallel: Number of parallel workers (None=sequential, -1=auto).
            tb: Traceback style (auto, long, short, line, native, no).
            cov_config: Path to coverage config file.
            no_cov_on_fail: Don't report coverage if test run fails.
            cov_append: Don't clear existing coverage data before run.
            show_missing: Show line numbers of missing coverage in report.

        Returns:
            Dict with test and coverage results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "pytest", path, f"--tb={tb}"]

        for src in source.split(","):
            args.append(f"--cov={src.strip()}")

        report = f"--cov-report={report_format}"
        if show_missing and report_format.startswith("term"):
            report = "--cov-report=term-missing"
        args.append(report)

        if fail_under is not None:
            args.append(f"--cov-fail-under={fail_under}")
        if omit:
            args.append(f"--cov-report=:omit={omit}")
        if include:
            args.append(f"--cov-report=:include={include}")
        if branch:
            args.append("--cov-branch")
        if append or cov_append:
            args.append("--cov-append")
        if context:
            args.append(f"--cov-context={context}")
        if cov_config:
            args.append(f"--cov-config={cov_config}")
        if no_cov_on_fail:
            args.append("--no-cov-on-fail")
        if markers:
            args.extend(["-m", markers])
        if keyword:
            args.extend(["-k", keyword])
        if verbose > 0:
            args.append("-" + "v" * verbose)
        if maxfail is not None:
            args.extend(["--maxfail", str(maxfail)])
        if parallel is not None:
            args.extend(["-n", "auto" if parallel == -1 else str(parallel)])

        return run_command(args, timeout=LONG_TIMEOUT)

    @mcp.tool()
    def coverage_report(
        report_format: str = "report",
        include: str | None = None,
        omit: str | None = None,
        fail_under: int | None = None,
        precision: int | None = None,
        show_missing: bool = False,
        skip_covered: bool = False,
        skip_empty: bool = False,
        sort: str | None = None,
        ignore_errors: bool = False,
        contexts: str | None = None,
        data_file: str | None = None,
        rcfile: str | None = None,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate coverage report from previous coverage run.

        Args:
            report_format: Report type (report, html, xml, json, lcov, annotate).
            include: Comma-separated file patterns to include.
            omit: Comma-separated file patterns to omit.
            fail_under: Exit with error if coverage is below this percentage.
            precision: Number of decimal places for percentages (0-6).
            show_missing: Show line numbers of missing coverage.
            skip_covered: Skip files with 100% coverage.
            skip_empty: Skip files with no executable lines.
            sort: Sort column (Name, Stmts, Miss, Branch, BrPart, Cover, Missing).
            ignore_errors: Ignore errors during report generation.
            contexts: Only show data from lines covered in given contexts.
            data_file: Path to coverage data file (.coverage).
            rcfile: Path to coverage configuration file.
            output_dir: Directory for html/xml/annotate output.

        Returns:
            Dict with coverage report output.
        """
        valid_formats = {"report", "html", "xml", "json", "lcov", "annotate"}
        if report_format not in valid_formats:
            return error_result(f"Invalid format: {report_format}. Valid: {valid_formats}")

        args = [PIXI, "run", "coverage", report_format]

        if include:
            args.extend(["--include", include])
        if omit:
            args.extend(["--omit", omit])
        if fail_under is not None:
            args.extend(["--fail-under", str(fail_under)])
        if precision is not None:
            args.extend(["--precision", str(precision)])
        if show_missing and report_format == "report":
            args.append("--show-missing")
        if skip_covered:
            args.append("--skip-covered")
        if skip_empty:
            args.append("--skip-empty")
        if sort:
            args.extend(["--sort", sort])
        if ignore_errors:
            args.append("--ignore-errors")
        if contexts:
            args.extend(["--contexts", contexts])
        if data_file:
            args.extend(["--data-file", data_file])
        if rcfile:
            args.extend(["--rcfile", rcfile])
        if output_dir and report_format in {"html", "xml", "annotate"}:
            if report_format == "html":
                args.extend(["-d", output_dir])
            elif report_format == "xml":
                args.extend(["-o", output_dir])
            elif report_format == "annotate":
                args.extend(["-d", output_dir])

        return run_command(args)
