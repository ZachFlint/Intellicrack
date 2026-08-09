# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for S17-D79: the injection monitor's diagnostic can be located.

When ``injection_monitor.ps1`` sets up its ETW trace session and one of the
statements calls a method on a null receiver, PowerShell raises "You cannot
call a method on a null-valued expression." The monitor used to record that
message alone (``Write-InjectionDiagnostic -Detail $_.Exception.Message``),
which names neither the failing statement nor its line, so a live Windows run
that died there left a diagnostic that could not be located.

Two things fix it, and both are exercised here against a real PowerShell:

* ``Write-InjectionDiagnostic`` now takes the error record and folds its
  ``InvocationInfo`` - the offending source line and its number - into the
  detail, and the ``trace_session_failed`` catch passes ``-ErrorRecord $_``.
  The first two tests lift that function and that very catch statement out of
  the script and drive them with a genuine null-receiver error, so the bytes
  under test are the guest's own and the diagnostic really does name the
  statement. The control proves the locator is added only when an error record
  is supplied, so the located assertion is not trivially true of every line.
* ``Assert-TraceObject`` guards the two property reads (``$session.Source`` and
  ``$source.Kernel``) that could return null and propagate silently. The last
  two tests lift that helper and prove a null value is reported through the
  diagnostic and stops the setup, while a present value passes through
  untouched.

Nothing here restates the script's logic: every function and statement under
test is extracted from ``injection_monitor.ps1`` and run verbatim, so renaming
or reverting either change reddens these tests rather than passing silently.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import run


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "injection_monitor.ps1"

_DIAG_WRITER: Final[str] = "Write-InjectionDiagnostic"
_TRACE_GUARD: Final[str] = "Assert-TraceObject"
_TRACE_FAILED_PREFIX: Final[str] = "Write-InjectionDiagnostic -Timestamp $ts -Category 'trace_session_failed'"

_SENTINEL_METHOD: Final[str] = "InvokeSentinelMethodForD79"
_SOURCE_NULL_CATEGORY: Final[str] = "trace_source_null"
_TIMESTAMP: Final[str] = "2026-08-09T12:00:00.0000000+00:00"
_PLAIN_CATEGORY: Final[str] = "plain_detail"
_PLAIN_DETAIL: Final[str] = "a detail with no error record"
_PRESENT_VALUE: Final[str] = "live- etw-source"
_POWERSHELL_TIMEOUT_SEC: Final[float] = 60.0

# The located suffix the fix appends: "... [at <script>:<line>: <statement>]".
# The statement is the sentinel null call, so this matches only when the real
# InvocationInfo of the failing statement reached the diagnostic.
_LOCATED_SUFFIX: Final[re.Pattern[str]] = re.compile(r"\[at [^\]]+:\d+: [^\]]*" + _SENTINEL_METHOD + r"\(\)\]")


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the lifted injection_monitor.ps1 diagnostic writer needs a Windows PowerShell",
)


def _resolve_powershell() -> str:
    """Locate a PowerShell interpreter able to run the lifted script.

    Returns:
        str: Absolute path to ``pwsh`` or to Windows PowerShell.
    """
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell interpreter is available to run the lifted diagnostic writer")
    return shell


def _script_lines() -> list[str]:
    """Read ``injection_monitor.ps1`` as newline-normalised lines.

    Returns:
        list[str]: The script's lines, without their line terminators.
    """
    return _SCRIPT_PATH.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")


def _extract_function(lines: list[str], name: str) -> str:
    """Lift one whole PowerShell function definition out of the script.

    Args:
        lines: The script's lines.
        name: Name of the function to lift.

    Returns:
        str: The function's source text, from its ``function`` line through
        its closing brace.
    """
    opening = f"function {name} {{"
    start = next((index for index, line in enumerate(lines) if line.strip() == opening), -1)
    assert start >= 0, f"{_SCRIPT_PATH.name} no longer defines {name}"
    end = next((index for index in range(start + 1, len(lines)) if lines[index] == "}"), -1)
    assert end > start, f"{name} has no closing brace in {_SCRIPT_PATH.name}"
    return "\n".join(lines[start : end + 1])


def _extract_statement(lines: list[str], prefix: str) -> str:
    """Lift the single statement whose first line begins with ``prefix``.

    A PowerShell statement continues onto the next line when the current one
    ends in a backtick, so any continuation lines are gathered with it.

    Args:
        lines: The script's lines.
        prefix: Text the wanted statement's first line starts with.

    Returns:
        str: The statement as one dedented source block.
    """
    for index, line in enumerate(lines):
        if not line.strip().startswith(prefix):
            continue
        block = [line.strip()]
        cursor = index
        while lines[cursor].rstrip().endswith("`") and cursor + 1 < len(lines):
            cursor += 1
            block.append(lines[cursor].strip())
        return "\n".join(block)
    pytest.fail(f"{_SCRIPT_PATH.name} no longer has a statement starting with {prefix!r}")


def _run_driver(tmp_path: Path, body: list[str]) -> tuple[int, list[str]]:
    """Run a PowerShell driver and return its exit code and the diagnostics.

    Args:
        tmp_path: Directory the driver and its diagnostic log live in.
        body: PowerShell statements to run after the diagnostic path is set
            and the lifted definitions are in scope.

    Returns:
        tuple[int, list[str]]: The interpreter's return code and the non-empty
        lines the lifted writer appended to the diagnostic log.
    """
    diag_path = tmp_path / "injection_monitor.diag.log"
    quoted_diag = str(diag_path).replace("'", "''")
    preamble = [
        "$ErrorActionPreference = 'Stop'",
        f"$script:diagPathRef = '{quoted_diag}'",
    ]
    driver_path = tmp_path / "d79_driver.ps1"
    driver_path.write_text("\n".join([*preamble, *body]), encoding="utf-8")

    completed = run(
        [
            _resolve_powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(driver_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=_POWERSHELL_TIMEOUT_SEC,
    )
    raw = diag_path.read_text(encoding="utf-8-sig").splitlines() if diag_path.exists() else []
    diagnostics = [line for line in raw if line.strip()]
    return completed.returncode, diagnostics


class TestTheTraceFailureDiagnosticNamesItsStatement:
    """The ``trace_session_failed`` diagnostic must name the failing statement."""

    def test_diagnostic_carries_the_failing_line_and_statement(self, tmp_path: Path) -> None:
        """A null-receiver failure is recorded with its line and source text.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        lines = _script_lines()
        writer = _extract_function(lines, _DIAG_WRITER)
        trace_failed = _extract_statement(lines, _TRACE_FAILED_PREFIX)

        code, diagnostics = _run_driver(
            tmp_path,
            [
                writer,
                "try {",
                f"    $null.{_SENTINEL_METHOD}()",
                "} catch {",
                f"    $ts = '{_TIMESTAMP}'",
                f"    {trace_failed}",
                "}",
            ],
        )

        assert code == 0, "the lifted diagnostic writer failed to run"
        assert len(diagnostics) == 1, f"unexpected diagnostics: {diagnostics}"
        _timestamp, category, detail = diagnostics[0].split("|", 2)
        assert category == "trace_session_failed", f"unexpected category: {category}"
        assert _LOCATED_SUFFIX.search(detail), f"the diagnostic did not name the failing statement: {detail!r}"

    def test_a_diagnostic_without_an_error_record_is_not_located(self, tmp_path: Path) -> None:
        """The control: no error record means no location suffix is added.

        Without this, a writer that appended a location to every detail would
        pass the test above for the wrong reason. It proves the suffix comes
        from the error record, so the located assertion is discriminating.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        lines = _script_lines()
        writer = _extract_function(lines, _DIAG_WRITER)

        code, diagnostics = _run_driver(
            tmp_path,
            [
                writer,
                f"{_DIAG_WRITER} -Timestamp '{_TIMESTAMP}' -Category '{_PLAIN_CATEGORY}' -Detail '{_PLAIN_DETAIL}'",
            ],
        )

        assert code == 0, "the lifted diagnostic writer failed to run"
        assert diagnostics == [f"{_TIMESTAMP}|{_PLAIN_CATEGORY}|{_PLAIN_DETAIL}"], f"unexpected diagnostics: {diagnostics}"
        assert "[at " not in diagnostics[0], "a plain detail was decorated with a location it never had"


class TestANullTraceObjectIsNamedAtItsOrigin:
    """A null ``Source`` or ``Kernel`` must be reported where it is read."""

    def test_a_null_value_is_reported_and_stops_setup(self, tmp_path: Path) -> None:
        """A null passed to the guard writes a diagnostic and aborts.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        lines = _script_lines()
        writer = _extract_function(lines, _DIAG_WRITER)
        guard = _extract_function(lines, _TRACE_GUARD)
        marker = tmp_path / "reached_after_guard.txt"
        quoted_marker = str(marker).replace("'", "''")

        code, diagnostics = _run_driver(
            tmp_path,
            [
                writer,
                guard,
                f"$source = {_TRACE_GUARD} -Value $null -Category '{_SOURCE_NULL_CATEGORY}' -Detail 'source was null'",
                f"'reached' | Out-File -LiteralPath '{quoted_marker}' -Encoding utf8",
            ],
        )

        assert code != 0, "a null value passed the guard without aborting"
        assert not marker.exists(), "setup continued past a null Source"
        categories = [line.split("|", 2)[1] for line in diagnostics]
        assert _SOURCE_NULL_CATEGORY in categories, f"the null Source was not reported: {diagnostics}"

    def test_a_present_value_passes_through_untouched(self, tmp_path: Path) -> None:
        """The control: a real value is returned and raises no diagnostic.

        Without this, a guard that always threw would pass the test above and
        would also break every healthy run. It proves the guard fires only on
        null and returns the value it was given.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        lines = _script_lines()
        writer = _extract_function(lines, _DIAG_WRITER)
        guard = _extract_function(lines, _TRACE_GUARD)

        code, diagnostics = _run_driver(
            tmp_path,
            [
                writer,
                guard,
                f"$result = {_TRACE_GUARD} -Value '{_PRESENT_VALUE}' -Category '{_SOURCE_NULL_CATEGORY}' -Detail 'unused'",
                f"if ($result -ne '{_PRESENT_VALUE}') {{ throw \"guard mangled a present value: $result\" }}",
            ],
        )

        assert code == 0, "the guard fired on a present value or mangled it"
        assert diagnostics == [], f"a present value raised a diagnostic: {diagnostics}"
