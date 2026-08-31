"""Version control (Git) tools for MCP dev-tools server."""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ..config import GIT
from ..validation import validate_path


def register_vcs_tools(
    mcp: FastMCP,
    run_command: Callable[..., dict[str, Any]],
    error_result: Callable[[str], dict[str, Any]],
) -> None:
    """Register Git VCS tools with the MCP server."""

    @mcp.tool()
    def git_status(
        short: bool = True,
        branch: bool = True,
        show_stash: bool = False,
        verbose: bool = False,
        untracked_files: str | None = None,
        ignored: bool = False,
        ignore_submodules: str | None = None,
        porcelain: int | None = None,
        ahead_behind: bool = True,
        renames: bool = True,
        find_renames: int | None = None,
        column: bool = False,
        no_column: bool = False,
    ) -> dict[str, Any]:
        """
        Show git working tree status.

        Args:
            short: Use short format output (-s).
            branch: Show branch info in short format (-b).
            show_stash: Show stash info (--show-stash).
            verbose: Verbose output with diff of staged changes (-v).
            untracked_files: Untracked files mode (no, normal, all).
            ignored: Show ignored files.
            ignore_submodules: Ignore submodules (none, untracked, dirty, all).
            porcelain: Machine-readable format version (1 or 2).
            ahead_behind: Show ahead/behind counts.
            renames: Detect renames in short format.
            find_renames: Similarity threshold for rename detection (0-100).
            column: Show untracked files in columns.
            no_column: Never show in columns.

        Returns:
            Dict with status output.
        """
        args = [GIT, "status"]
        if short:
            args.append("--short")
        if branch:
            args.append("--branch")
        if show_stash:
            args.append("--show-stash")
        if verbose:
            args.append("-v")
        if untracked_files:
            args.extend(["--untracked-files", untracked_files])
        if ignored:
            args.append("--ignored")
        if ignore_submodules:
            args.extend(["--ignore-submodules", ignore_submodules])
        if porcelain is not None:
            args.append(f"--porcelain={porcelain}" if porcelain > 1 else "--porcelain")
        if not ahead_behind:
            args.append("--no-ahead-behind")
        if not renames:
            args.append("--no-renames")
        if find_renames is not None:
            args.extend(["--find-renames", str(find_renames)])
        if column:
            args.append("--column")
        if no_column:
            args.append("--no-column")

        return run_command(args)

    @mcp.tool()
    def git_diff(
        path: str | None = None,
        staged: bool = False,
        commit: str | None = None,
        commit_range: str | None = None,
        stat: bool = False,
        numstat: bool = False,
        shortstat: bool = False,
        name_only: bool = False,
        name_status: bool = False,
        check: bool = False,
        word_diff: str | None = None,
        color_words: bool = False,
        unified: int | None = None,
        ignore_space_at_eol: bool = False,
        ignore_space_change: bool = False,
        ignore_all_space: bool = False,
        ignore_blank_lines: bool = False,
        diff_filter: str | None = None,
        relative: str | None = None,
        text: bool = False,
        binary: bool = False,
        abbrev: int | None = None,
        full_index: bool = False,
        compact_summary: bool = False,
        src_prefix: str | None = None,
        dst_prefix: str | None = None,
        no_prefix: bool = False,
        histogram: bool = False,
        patience: bool = False,
        minimal: bool = False,
    ) -> dict[str, Any]:
        """
        Show git diff for changes.

        Args:
            path: Specific path to diff (optional).
            staged: Show staged changes instead of unstaged (--cached).
            commit: Show diff against specific commit.
            commit_range: Show diff between commits (e.g., "HEAD~3..HEAD").
            stat: Show diffstat summary.
            numstat: Show numeric diffstat (files, insertions, deletions).
            shortstat: Show only summary line (files changed, insertions, deletions).
            name_only: Show only names of changed files.
            name_status: Show names and status of changed files (A/D/M).
            check: Warn if changes introduce conflict markers or whitespace errors.
            word_diff: Word diff mode (color, plain, porcelain, none).
            color_words: Word diff with color (shortcut for --word-diff=color).
            unified: Number of context lines (default 3).
            ignore_space_at_eol: Ignore whitespace changes at end of line.
            ignore_space_change: Ignore changes in amount of whitespace (-b).
            ignore_all_space: Ignore all whitespace (-w).
            ignore_blank_lines: Ignore blank line changes.
            diff_filter: Filter files by status (A=Added, D=Deleted, M=Modified, etc.).
            relative: Show paths relative to given directory.
            text: Treat all files as text (-a).
            binary: Output binary diffs that can be applied.
            abbrev: Abbreviate object names to N characters.
            full_index: Show full object names in index line.
            compact_summary: Condensed summary of extended header info.
            src_prefix: Prefix for source file names (default "a/").
            dst_prefix: Prefix for destination file names (default "b/").
            no_prefix: Don't show source/destination prefixes.
            histogram: Use histogram diff algorithm.
            patience: Use patience diff algorithm.
            minimal: Produce minimal diff.

        Returns:
            Dict with diff output.
        """
        args = [GIT, "diff"]
        if staged:
            args.append("--cached")
        if commit:
            args.append(commit)
        if commit_range:
            args.append(commit_range)
        if stat:
            args.append("--stat")
        if numstat:
            args.append("--numstat")
        if shortstat:
            args.append("--shortstat")
        if name_only:
            args.append("--name-only")
        if name_status:
            args.append("--name-status")
        if check:
            args.append("--check")
        if word_diff:
            args.extend(["--word-diff", word_diff])
        if color_words:
            args.append("--color-words")
        if unified is not None:
            args.extend(["-U", str(unified)])
        if ignore_space_at_eol:
            args.append("--ignore-space-at-eol")
        if ignore_space_change:
            args.append("-b")
        if ignore_all_space:
            args.append("-w")
        if ignore_blank_lines:
            args.append("--ignore-blank-lines")
        if diff_filter:
            args.extend(["--diff-filter", diff_filter])
        if relative:
            args.extend(["--relative", relative])
        if text:
            args.append("-a")
        if binary:
            args.append("--binary")
        if abbrev is not None:
            args.extend(["--abbrev", str(abbrev)])
        if full_index:
            args.append("--full-index")
        if compact_summary:
            args.append("--compact-summary")
        if src_prefix:
            args.extend(["--src-prefix", src_prefix])
        if dst_prefix:
            args.extend(["--dst-prefix", dst_prefix])
        if no_prefix:
            args.append("--no-prefix")
        if histogram:
            args.append("--histogram")
        if patience:
            args.append("--patience")
        if minimal:
            args.append("--minimal")

        if path:
            is_valid, err = validate_path(path, must_exist=False)
            if not is_valid:
                return error_result(err or "Invalid path")
            args.extend(["--", path])

        return run_command(args)

    @mcp.tool()
    def git_log(
        count: int = 10,
        oneline: bool = True,
        format_string: str | None = None,
        graph: bool = False,
        abbrev_commit: bool = False,
        decorate: str | None = None,
        all_refs: bool = False,
        branches: str | None = None,
        tags: str | None = None,
        remotes: str | None = None,
        follow: bool = False,
        since: str | None = None,
        until: str | None = None,
        author: str | None = None,
        committer: str | None = None,
        grep: str | None = None,
        invert_grep: bool = False,
        all_match: bool = False,
        regexp_ignore_case: bool = False,
        merges: bool | None = None,
        first_parent: bool = False,
        ancestry_path: bool = False,
        simplify_by_decoration: bool = False,
        stat: bool = False,
        name_only: bool = False,
        name_status: bool = False,
        diff_filter: str | None = None,
        reverse: bool = False,
        date: str | None = None,
        relative_date: bool = False,
        path: str | None = None,
    ) -> dict[str, Any]:
        """
        Show git commit history.

        Args:
            count: Number of commits to show (max 100).
            oneline: Use compact one-line format.
            format_string: Pretty format string (e.g., "%h %s", "short", "medium", "full").
            graph: Show ASCII graph of branch structure.
            abbrev_commit: Show abbreviated commit hashes.
            decorate: Show ref names (short, full, auto, no).
            all_refs: Show all refs (branches, tags, remotes).
            branches: Show commits reachable from branches matching pattern.
            tags: Show commits reachable from tags matching pattern.
            remotes: Show commits reachable from remotes matching pattern.
            follow: Follow file renames (only works with single file path).
            since: Show commits after date (e.g., "2 weeks ago", "2024-01-01").
            until: Show commits before date.
            author: Filter by author (regex pattern).
            committer: Filter by committer (regex pattern).
            grep: Filter by commit message (regex pattern).
            invert_grep: Invert grep match.
            all_match: Match all grep patterns (AND instead of OR).
            regexp_ignore_case: Case-insensitive grep.
            merges: True=only merges, False=no merges, None=all.
            first_parent: Follow only first parent of merges.
            ancestry_path: Show only commits on ancestry path.
            simplify_by_decoration: Show only commits with refs.
            stat: Show diffstat for each commit.
            name_only: Show names of changed files.
            name_status: Show names and status of changed files.
            diff_filter: Filter by file change type (A/D/M/etc).
            reverse: Show commits in reverse order.
            date: Date format (relative, local, short, iso, rfc, format:...).
            relative_date: Show relative dates.
            path: Show commits affecting this path.

        Returns:
            Dict with log output.
        """
        count = min(max(count, 1), 100)
        args = [GIT, "log", f"-{count}"]

        if oneline and not format_string:
            args.append("--oneline")
        if format_string:
            args.extend(["--format", format_string])
        if graph:
            args.append("--graph")
        if abbrev_commit:
            args.append("--abbrev-commit")
        if decorate:
            args.extend(["--decorate", decorate])
        if all_refs:
            args.append("--all")
        if branches:
            args.extend(["--branches", branches])
        if tags:
            args.extend(["--tags", tags])
        if remotes:
            args.extend(["--remotes", remotes])
        if follow:
            args.append("--follow")
        if since:
            args.extend(["--since", since])
        if until:
            args.extend(["--until", until])
        if author:
            args.extend(["--author", author])
        if committer:
            args.extend(["--committer", committer])
        if grep:
            args.extend(["--grep", grep])
        if invert_grep:
            args.append("--invert-grep")
        if all_match:
            args.append("--all-match")
        if regexp_ignore_case:
            args.append("--regexp-ignore-case")
        if merges is True:
            args.append("--merges")
        elif merges is False:
            args.append("--no-merges")
        if first_parent:
            args.append("--first-parent")
        if ancestry_path:
            args.append("--ancestry-path")
        if simplify_by_decoration:
            args.append("--simplify-by-decoration")
        if stat:
            args.append("--stat")
        if name_only:
            args.append("--name-only")
        if name_status:
            args.append("--name-status")
        if diff_filter:
            args.extend(["--diff-filter", diff_filter])
        if reverse:
            args.append("--reverse")
        if date:
            args.extend(["--date", date])
        if relative_date:
            args.append("--relative-date")
        if path:
            is_valid, err = validate_path(path, must_exist=False)
            if not is_valid:
                return error_result(err or "Invalid path")
            args.extend(["--", path])

        return run_command(args)
