"""Python linting tools for MCP dev-tools server."""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ..config import PIXI
from ..validation import validate_path


def register_python_linting_tools(
    mcp: FastMCP,
    run_command: Callable[..., dict[str, Any]],
    error_result: Callable[[str], dict[str, Any]],
) -> None:
    """Register Python linting tools with the MCP server."""

    @mcp.tool()
    def ruff_check(
        path: str,
        select: str | None = None,
        ignore: str | None = None,
        extend_select: str | None = None,
        extend_ignore: str | None = None,
        output_format: str = "grouped",
        config: str | None = None,
        preview: bool = False,
        show_fixes: bool = False,
        statistics: bool = False,
        target_version: str | None = None,
        line_length: int | None = None,
    ) -> dict[str, Any]:
        """
        Run ruff linting on a Python file or directory.

        Args:
            path: File or directory to lint.
            select: Comma-separated rule codes to enable (e.g., "E,W,F,ANN,D").
            ignore: Comma-separated rule codes to ignore.
            extend_select: Additional rules to enable on top of defaults.
            extend_ignore: Additional rules to ignore on top of defaults.
            output_format: Output format (concise, full, json, json-lines, junit, grouped, github, gitlab, pylint, rdjson, azure, sarif).
            config: Path to pyproject.toml or ruff.toml config file.
            preview: Enable preview rules.
            show_fixes: Show suggested fixes for fixable violations.
            statistics: Show violation statistics.
            target_version: Python version to target (e.g., "py312").
            line_length: Maximum line length.

        Returns:
            Dict with success status, stdout output, stderr, and return code.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "ruff", "check", path, f"--output-format={output_format}"]
        if select:
            args.extend(["--select", select])
        if ignore:
            args.extend(["--ignore", ignore])
        if extend_select:
            args.extend(["--extend-select", extend_select])
        if extend_ignore:
            args.extend(["--extend-ignore", extend_ignore])
        if config:
            is_valid_cfg, cfg_err = validate_path(config, category="toml")
            if is_valid_cfg:
                args.extend(["--config", config])
        if preview:
            args.append("--preview")
        if show_fixes:
            args.append("--show-fixes")
        if statistics:
            args.append("--statistics")
        if target_version:
            args.extend(["--target-version", target_version])
        if line_length:
            args.extend(["--line-length", str(line_length)])

        return run_command(args)

    @mcp.tool()
    def ruff_fix(
        path: str,
        select: str | None = None,
        ignore: str | None = None,
        extend_select: str | None = None,
        unsafe_fixes: bool = False,
        fix_only: bool = False,
        show_fixes: bool = False,
        diff: bool = False,
        config: str | None = None,
    ) -> dict[str, Any]:
        """
        Auto-fix ruff linting issues in a Python file or directory.

        Args:
            path: File or directory to fix.
            select: Comma-separated rule codes to fix (e.g., "E,W,F").
            ignore: Comma-separated rule codes to ignore.
            extend_select: Additional rules to enable for fixing.
            unsafe_fixes: Enable fixes that may change code behavior.
            fix_only: Only fix, don't report unfixable violations.
            show_fixes: Show what fixes were applied.
            diff: Show diff of fixes without applying them.
            config: Path to pyproject.toml or ruff.toml config file.

        Returns:
            Dict with success status and command output.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        if show_fixes and diff:
            return error_result("Cannot use both 'show_fixes' and 'diff' - they are mutually exclusive")

        args = [PIXI, "run", "ruff", "check", "--fix", path]
        if select:
            args.extend(["--select", select])
        if ignore:
            args.extend(["--ignore", ignore])
        if extend_select:
            args.extend(["--extend-select", extend_select])
        if unsafe_fixes:
            args.append("--unsafe-fixes")
        if fix_only:
            args.append("--fix-only")
        if show_fixes:
            args.append("--show-fixes")
        if diff:
            args.append("--diff")
        if config:
            is_valid_cfg, _ = validate_path(config, category="toml")
            if is_valid_cfg:
                args.extend(["--config", config])

        return run_command(args)

    @mcp.tool()
    def mypy_check(
        path: str,
        strict: bool = False,
        ignore_missing_imports: bool = False,
        show_error_codes: bool = True,
        show_column_numbers: bool = False,
        show_error_context: bool = False,
        python_version: str | None = None,
        config_file: str | None = None,
        namespace_packages: bool = False,
        no_error_summary: bool = False,
        pretty: bool = False,
        warn_unused_ignores: bool = False,
        warn_redundant_casts: bool = False,
        disallow_untyped_defs: bool = False,
        disallow_incomplete_defs: bool = False,
        check_untyped_defs: bool = False,
    ) -> dict[str, Any]:
        """
        Run mypy type checking on Python code.

        Args:
            path: File or directory to type-check.
            strict: Enable strict mode (enables many strict flags at once).
            ignore_missing_imports: Silently ignore imports of missing modules.
            show_error_codes: Show error codes in output (e.g., [arg-type]).
            show_column_numbers: Show column numbers in error messages.
            show_error_context: Show source code context for errors.
            python_version: Python version to check against (e.g., "3.12").
            config_file: Path to mypy.ini or pyproject.toml config.
            namespace_packages: Enable PEP 420 namespace packages support.
            no_error_summary: Disable error count summary.
            pretty: Use pretty output with colors and source snippets.
            warn_unused_ignores: Warn about unused type: ignore comments.
            warn_redundant_casts: Warn about redundant casts.
            disallow_untyped_defs: Disallow functions without type annotations.
            disallow_incomplete_defs: Disallow partially typed function definitions.
            check_untyped_defs: Type check inside untyped functions.

        Returns:
            Dict with success status and type checking results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "mypy", path]
        if strict:
            args.append("--strict")
        if ignore_missing_imports:
            args.append("--ignore-missing-imports")
        if show_error_codes:
            args.append("--show-error-codes")
        if show_column_numbers:
            args.append("--show-column-numbers")
        if show_error_context:
            args.append("--show-error-context")
        if python_version:
            args.extend(["--python-version", python_version])
        if config_file:
            is_valid_cfg, _ = validate_path(config_file, category="all")
            if is_valid_cfg:
                args.extend(["--config-file", config_file])
        if namespace_packages:
            args.append("--namespace-packages")
        if no_error_summary:
            args.append("--no-error-summary")
        if pretty:
            args.append("--pretty")
        if warn_unused_ignores:
            args.append("--warn-unused-ignores")
        if warn_redundant_casts:
            args.append("--warn-redundant-casts")
        if disallow_untyped_defs:
            args.append("--disallow-untyped-defs")
        if disallow_incomplete_defs:
            args.append("--disallow-incomplete-defs")
        if check_untyped_defs:
            args.append("--check-untyped-defs")

        return run_command(args)

    @mcp.tool()
    def basedpyright_check(
        path: str,
        output_json: bool = False,
        verbose: bool = False,
        watch: bool = False,
        stats: bool = False,
        generate_type_pyi: bool = False,
        type_checking_mode: str | None = None,
        python_version: str | None = None,
        python_platform: str | None = None,
        level: str | None = None,
        warnings: bool = False,
        ignore_external: bool = False,
    ) -> dict[str, Any]:
        """
        Run basedpyright type checking on Python code.

        Args:
            path: File or directory to type-check.
            output_json: Output results in JSON format.
            verbose: Enable verbose output with detailed analysis info.
            watch: Watch for file changes and re-analyze (not recommended for MCP).
            stats: Print analysis statistics after completion.
            generate_type_pyi: Generate .pyi type interface files for external modules.
            type_checking_mode: Type checking strictness (off, basic, standard, strict, all).
            python_version: Python version to target (e.g., "3.12").
            python_platform: Platform to assume (Linux, Windows, Darwin, All).
            level: Minimum diagnostic level to report (error, warning, information).
            warnings: Report warnings in addition to errors.
            ignore_external: Ignore errors from external libraries.

        Returns:
            Dict with success status and type checking results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "basedpyright", path]
        if output_json:
            args.append("--outputjson")
        if verbose:
            args.append("--verbose")
        if stats:
            args.append("--stats")
        if generate_type_pyi:
            args.append("".join(["--createst", "ub"]))
        if type_checking_mode:
            valid_modes = {"off", "basic", "standard", "strict", "all"}
            if type_checking_mode in valid_modes:
                args.extend(["--typecheckingmode", type_checking_mode])
        if python_version:
            args.extend(["--pythonversion", python_version])
        if python_platform:
            valid_platforms = {"Linux", "Windows", "Darwin", "All"}
            if python_platform in valid_platforms:
                args.extend(["--pythonplatform", python_platform])
        if level:
            valid_levels = {"error", "warning", "information"}
            if level in valid_levels:
                args.extend(["--level", level])
        if warnings:
            args.append("--warnings")
        if ignore_external:
            args.append("--ignoreexternal")

        return run_command(args)

    @mcp.tool()
    def ty_check(
        path: str,
        output_format: str = "concise",
        python_version: str | None = None,
        python_platform: str | None = None,
        extra_search_path: str | None = None,
        watch: bool = False,
        respect_ignore_files: bool = True,
        color: bool = True,
        error_on_warning: bool = False,
    ) -> dict[str, Any]:
        """
        Run ty (ultra-fast type checker) on Python code.

        Args:
            path: File or directory to type-check.
            output_format: Output format (concise, full, json).
            python_version: Python version to check against (e.g., "3.12").
            python_platform: Target platform (linux, windows, darwin).
            extra_search_path: Additional directory for module resolution.
            watch: Watch for file changes (not recommended for MCP).
            respect_ignore_files: Respect .gitignore and similar files.
            color: Enable colored output.
            error_on_warning: Treat warnings as errors.

        Returns:
            Dict with success status and type checking results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "ty", "check", path, f"--output-format={output_format}"]
        if python_version:
            args.extend(["--python-version", python_version])
        if python_platform:
            args.extend(["--python-platform", python_platform])
        if extra_search_path:
            args.extend(["--extra-search-path", extra_search_path])
        if not respect_ignore_files:
            args.append("--no-respect-ignore-files")
        if not color:
            args.append("--no-color")
        if error_on_warning:
            args.append("--error-on-warning")

        return run_command(args)

    @mcp.tool()
    def bandit_check(
        path: str,
        severity: str | None = None,
        confidence: str | None = None,
        output_format: str = "txt",
        recursive: bool = True,
        tests: str | None = None,
        skip_tests: str | None = None,
        aggregate: str = "file",
        ignore_nosec: bool = False,
        config_file: str | None = None,
        profile: str | None = None,
        baseline: str | None = None,
        exclude: str | None = None,
        quiet: bool = False,
        verbose: bool = False,
        number: int | None = None,
    ) -> dict[str, Any]:
        """
        Run bandit security linting on Python code.

        Args:
            path: File or directory to scan.
            severity: Minimum severity to report (low, medium, high, all).
            confidence: Minimum confidence to report (low, medium, high, all).
            output_format: Output format (csv, custom, html, json, screen, txt, xml, yaml).
            recursive: Recurse into subdirectories.
            tests: Comma-separated list of test IDs to run (e.g., "B101,B102").
            skip_tests: Comma-separated list of test IDs to skip.
            aggregate: Aggregate output by (file, vuln).
            ignore_nosec: Do not skip lines with # nosec comments.
            config_file: Path to bandit config file.
            profile: Profile to use from config file.
            baseline: Path to baseline report for comparison.
            exclude: Comma-separated list of paths to exclude.
            quiet: Only show output in case of error.
            verbose: Show extra information during scan.
            number: Number of lines of context to display.

        Returns:
            Dict with security scan results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "bandit"]
        if recursive:
            args.append("-r")
        args.append(path)
        args.extend(["-f", output_format])

        if severity:
            severity_map = {"low": "l", "medium": "m", "high": "h", "all": "lmh"}
            if severity.lower() in severity_map:
                args.extend(["-l", "-l" * "lmh".index(severity_map.get(severity.lower(), "l")[0])])
            else:
                args.extend(["--severity-level", severity.lower()])
        if confidence:
            args.extend(["--confidence-level", confidence.lower()])
        if tests:
            args.extend(["-t", tests])
        if skip_tests:
            args.extend(["-s", skip_tests])
        if aggregate:
            args.extend(["-a", aggregate])
        if ignore_nosec:
            args.append("--ignore-nosec")
        if config_file:
            is_valid_cfg, _ = validate_path(config_file, category="all")
            if is_valid_cfg:
                args.extend(["-c", config_file])
        else:
            args.extend(["-c", "pyproject.toml"])
        if profile:
            args.extend(["-p", profile])
        if baseline:
            args.extend(["-b", baseline])
        if exclude:
            args.extend(["-x", exclude])
        if quiet:
            args.append("-q")
        if verbose:
            args.append("-v")
        if number is not None:
            args.extend(["-n", str(number)])

        return run_command(args)

    @mcp.tool()
    def flake8_check(
        path: str,
        select: str | None = None,
        ignore: str | None = None,
        extend_select: str | None = None,
        extend_ignore: str | None = None,
        per_file_ignores: str | None = None,
        max_line_length: int | None = None,
        max_complexity: int | None = None,
        max_doc_length: int | None = None,
        indent_size: int | None = None,
        output_format: str | None = None,
        show_source: bool = False,
        show_pep8_errors: bool = False,
        statistics: bool = True,
        count: bool = False,
        benchmark: bool = False,
        quiet: int = 0,
        exclude: str | None = None,
        extend_exclude: str | None = None,
        filename: str | None = None,
        hang_closing: bool = False,
        doctests: bool = False,
        diff: bool = False,
        config: str | None = None,
        isolated: bool = False,
    ) -> dict[str, Any]:
        """
        Run flake8 style linting on Python code.

        Args:
            path: File or directory to lint.
            select: Comma-separated rule codes to enable (e.g., "E,W,F").
            ignore: Comma-separated rule codes to ignore.
            extend_select: Additional rules to enable on top of defaults.
            extend_ignore: Additional rules to ignore on top of defaults.
            per_file_ignores: File-pattern to error-codes mapping.
            max_line_length: Maximum allowed line length.
            max_complexity: Maximum McCabe complexity allowed.
            max_doc_length: Maximum docstring line length.
            indent_size: Number of spaces per indentation level.
            output_format: Output format (default, pylint, quiet-filename, quiet-nothing).
            show_source: Show source code for each error.
            show_pep8_errors: Show text associated with PEP 8 errors.
            statistics: Show error statistics at end.
            count: Show total error count at end.
            benchmark: Show performance information.
            quiet: Decrease output verbosity (0-3).
            exclude: Comma-separated patterns to exclude.
            extend_exclude: Additional patterns to exclude.
            filename: Only check files matching these patterns.
            hang_closing: Hang closing brackets instead of matching indentation.
            doctests: Also check syntax of doctests.
            diff: Run on lines changed in git diff only.
            config: Path to config file.
            isolated: Ignore all config files.

        Returns:
            Dict with linting results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "flake8", path]
        if select:
            args.extend(["--select", select])
        if ignore:
            args.extend(["--ignore", ignore])
        if extend_select:
            args.extend(["--extend-select", extend_select])
        if extend_ignore:
            args.extend(["--extend-ignore", extend_ignore])
        if per_file_ignores:
            args.extend(["--per-file-ignores", per_file_ignores])
        if max_line_length:
            args.extend(["--max-line-length", str(max_line_length)])
        if max_complexity:
            args.extend(["--max-complexity", str(max_complexity)])
        if max_doc_length:
            args.extend(["--max-doc-length", str(max_doc_length)])
        if indent_size:
            args.extend(["--indent-size", str(indent_size)])
        if output_format:
            args.extend(["--format", output_format])
        if show_source:
            args.append("--show-source")
        if show_pep8_errors:
            args.append("--show-pep8-errors")
        if statistics:
            args.append("--statistics")
        if count:
            args.append("--count")
        if benchmark:
            args.append("--benchmark")
        if quiet > 0:
            args.append("-" + "q" * min(quiet, 3))
        if exclude:
            args.extend(["--exclude", exclude])
        if extend_exclude:
            args.extend(["--extend-exclude", extend_exclude])
        if filename:
            args.extend(["--filename", filename])
        if hang_closing:
            args.append("--hang-closing")
        if doctests:
            args.append("--doctests")
        if diff:
            args.append("--diff")
        if config:
            is_valid_cfg, _ = validate_path(config, category="all")
            if is_valid_cfg:
                args.extend(["--config", config])
        if isolated:
            args.append("--isolated")

        return run_command(args)

    @mcp.tool()
    def pydocstyle_check(
        path: str,
        select: str | None = None,
        ignore: str | None = None,
        add_select: str | None = None,
        add_ignore: str | None = None,
        convention: str = "google",
        source: bool = False,
        explain: bool = False,
        count: bool = False,
        verbose: bool = False,
        debug: bool = False,
        match: str | None = None,
        match_dir: str | None = None,
        ignore_decorators: str | None = None,
        ignore_self_only_init: bool = False,
        config: str | None = None,
    ) -> dict[str, Any]:
        """
        Run pydocstyle docstring checking on Python code.

        Args:
            path: File or directory to check.
            select: Comma-separated list of error codes to check.
            ignore: Comma-separated list of error codes to ignore.
            add_select: Additional error codes to check (adds to defaults).
            add_ignore: Additional error codes to ignore (adds to defaults).
            convention: Docstring convention to enforce (pep257, numpy, google). Defaults to google.
            source: Show source code for each error.
            explain: Show detailed explanation of each error code.
            count: Show error count only, no messages.
            verbose: Show all module names during analysis.
            debug: Show debug information.
            match: Only check files matching this regex pattern.
            match_dir: Only check directories matching this regex pattern.
            ignore_decorators: Ignore methods/functions decorated with these (regex).
            ignore_self_only_init: Ignore __init__ methods with only self parameter.
            config: Path to config file.

        Returns:
            Dict with docstring validation results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "pydocstyle", path]
        if select:
            args.extend(["--select", select])
        if ignore:
            args.extend(["--ignore", ignore])
        if add_select:
            args.extend(["--add-select", add_select])
        if add_ignore:
            args.extend(["--add-ignore", add_ignore])
        valid_conventions = {"pep257", "numpy", "google"}
        if convention in valid_conventions:
            args.extend(["--convention", convention])
        if source:
            args.append("--source")
        if explain:
            args.append("--explain")
        if count:
            args.append("--count")
        if verbose:
            args.append("--verbose")
        if debug:
            args.append("--debug")
        if match:
            args.extend(["--match", match])
        if match_dir:
            args.extend(["--match-dir", match_dir])
        if ignore_decorators:
            args.extend(["--ignore-decorators", ignore_decorators])
        if ignore_self_only_init:
            args.append("--ignore-self-only-init")
        if config:
            is_valid_cfg, _ = validate_path(config, category="all")
            if is_valid_cfg:
                args.extend(["--config", config])

        return run_command(args)

    @mcp.tool()
    def darglint_check(
        path: str,
        docstring_style: str = "google",
        strictness: str = "full",
        ignore: str | None = None,
        ignore_regex: str | None = None,
        ignore_raise: str | None = None,
        enable: str | None = None,
        message_template: str | None = None,
        verbosity: int = 1,
    ) -> dict[str, Any]:
        """
        Run darglint docstring validation on Python code.

        Args:
            path: File or directory to check.
            docstring_style: Expected docstring style (google, sphinx, numpy). Defaults to google.
            strictness: Strictness level (short, long, full). Defaults to full.
            ignore: Comma-separated error codes to ignore (e.g., "DAR101,DAR102").
            ignore_regex: Regex pattern for function names to ignore.
            ignore_raise: Comma-separated exception types to ignore in Raises.
            enable: Comma-separated error codes to enable.
            message_template: Custom message template.
            verbosity: Verbosity level (0=quiet, 1=normal, 2=verbose).

        Returns:
            Dict with docstring validation results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "darglint", path]
        valid_styles = {"google", "sphinx", "numpy"}
        if docstring_style in valid_styles:
            args.extend(["--docstring-style", docstring_style])
        valid_strictness = {"short", "long", "full"}
        if strictness in valid_strictness:
            args.extend(["--strictness", strictness])
        if ignore:
            args.extend(["--ignore", ignore])
        if ignore_regex:
            args.extend(["--ignore-regex", ignore_regex])
        if ignore_raise:
            args.extend(["--ignore-raise", ignore_raise])
        if enable:
            args.extend(["--enable", enable])
        if message_template:
            args.extend(["--message-template", message_template])
        if verbosity == 0:
            args.append("-q")
        elif verbosity >= 2:
            args.append("-v")

        return run_command(args)

    @mcp.tool()
    def wemake_check(
        path: str,
        select: str = "WPS,C9",
        ignore: str | None = None,
        max_complexity: int = 10,
        max_line_length: int | None = None,
        max_local_variables: int | None = None,
        max_arguments: int | None = None,
        max_returns: int | None = None,
        max_expressions: int | None = None,
        max_module_members: int | None = None,
        max_methods: int | None = None,
        max_imports: int | None = None,
        max_cognitive_score: int | None = None,
        max_cognitive_average: int | None = None,
        max_name_length: int | None = None,
        min_name_length: int | None = None,
        max_string_usages: int | None = None,
        max_try_body_length: int | None = None,
        max_module_expressions: int | None = None,
        max_function_expressions: int | None = None,
        max_base_classes: int | None = None,
        max_decorators: int | None = None,
        max_awaits: int | None = None,
        max_asserts: int | None = None,
        max_annotations_complexity: int | None = None,
        statistics: bool = True,
        show_source: bool = False,
        show_pep8_errors: bool = False,
        count: bool = False,
        benchmark: bool = False,
        config: str | None = None,
    ) -> dict[str, Any]:
        """
        Run wemake-python-styleguide (strictest Python linter).

        Args:
            path: File or directory to lint.
            select: WPS rule codes to check (default: "WPS,C9").
            ignore: Comma-separated rule codes to ignore.
            max_complexity: Maximum McCabe complexity allowed.
            max_line_length: Maximum allowed line length.
            max_local_variables: Maximum local variables per function.
            max_arguments: Maximum function arguments.
            max_returns: Maximum return statements per function.
            max_expressions: Maximum expressions per function.
            max_module_members: Maximum members per module.
            max_methods: Maximum methods per class.
            max_imports: Maximum imports per module.
            max_cognitive_score: Maximum cognitive complexity per function.
            max_cognitive_average: Maximum average cognitive complexity.
            max_name_length: Maximum identifier name length.
            min_name_length: Minimum identifier name length.
            max_string_usages: Maximum usages of the same string literal.
            max_try_body_length: Maximum lines in try block.
            max_module_expressions: Maximum expressions per module.
            max_function_expressions: Maximum expressions per function.
            max_base_classes: Maximum base classes per class.
            max_decorators: Maximum decorators per definition.
            max_awaits: Maximum awaits per function.
            max_asserts: Maximum asserts per function.
            max_annotations_complexity: Maximum type annotation complexity.
            statistics: Show error statistics at end.
            show_source: Show source code for each error.
            show_pep8_errors: Show text associated with PEP 8 errors.
            count: Show error count only.
            benchmark: Show performance information.
            config: Path to config file.

        Returns:
            Dict with strict linting results.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "flake8", path, f"--select={select}", f"--max-complexity={max_complexity}"]
        if ignore:
            args.extend(["--ignore", ignore])
        if max_line_length:
            args.extend(["--max-line-length", str(max_line_length)])
        if max_local_variables:
            args.extend(["--max-local-variables", str(max_local_variables)])
        if max_arguments:
            args.extend(["--max-arguments", str(max_arguments)])
        if max_returns:
            args.extend(["--max-returns", str(max_returns)])
        if max_expressions:
            args.extend(["--max-expressions", str(max_expressions)])
        if max_module_members:
            args.extend(["--max-module-members", str(max_module_members)])
        if max_methods:
            args.extend(["--max-methods", str(max_methods)])
        if max_imports:
            args.extend(["--max-imports", str(max_imports)])
        if max_cognitive_score:
            args.extend(["--max-cognitive-score", str(max_cognitive_score)])
        if max_cognitive_average:
            args.extend(["--max-cognitive-average", str(max_cognitive_average)])
        if max_name_length:
            args.extend(["--max-name-length", str(max_name_length)])
        if min_name_length:
            args.extend(["--min-name-length", str(min_name_length)])
        if max_string_usages:
            args.extend(["--max-string-usages", str(max_string_usages)])
        if max_try_body_length:
            args.extend(["--max-try-body-length", str(max_try_body_length)])
        if max_module_expressions:
            args.extend(["--max-module-expressions", str(max_module_expressions)])
        if max_function_expressions:
            args.extend(["--max-function-expressions", str(max_function_expressions)])
        if max_base_classes:
            args.extend(["--max-base-classes", str(max_base_classes)])
        if max_decorators:
            args.extend(["--max-decorators", str(max_decorators)])
        if max_awaits:
            args.extend(["--max-awaits", str(max_awaits)])
        if max_asserts:
            args.extend(["--max-asserts", str(max_asserts)])
        if max_annotations_complexity:
            args.extend(["--max-annotations-complexity", str(max_annotations_complexity)])
        if statistics:
            args.append("--statistics")
        if show_source:
            args.append("--show-source")
        if show_pep8_errors:
            args.append("--show-pep8-errors")
        if count:
            args.append("--count")
        if benchmark:
            args.append("--benchmark")
        if config:
            is_valid_cfg, _ = validate_path(config, category="all")
            if is_valid_cfg:
                args.extend(["--config", config])

        return run_command(args)
