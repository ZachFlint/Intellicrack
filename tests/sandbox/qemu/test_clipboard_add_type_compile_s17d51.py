# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D51: the clipboard collector's embedded C# must compile.

Measured live: the first log line ``clipboard_monitor.ps1`` writes on every
run is ``init.add_type_failed``, carrying the real CodeDom compiler diagnostic
``'ClipboardChangedEventArgs.OwnerPid.get' must declare a body because it is
not marked abstract or extern. Automatically implemented properties must
define both get and set accessors.`` The script then falls back to clipboard
polling, which produced zero entries for the whole run.

The offending source is ``public uint OwnerPid { get; }`` - a get-only
auto-property - inside the C# ``Add-Type`` embeds through
``$clipSource``. Get-only auto-properties are a C# 6 feature; a stock Windows
guest has only Windows PowerShell 5.1, whose ``Add-Type`` compiles through the
in-box CodeDom provider, which is a C# 5 compiler. That compiler also rejects
the null-conditional operator (``ClipboardChanged?.Invoke(...)``) used
elsewhere in the same embedded source, so a fix that touches only the reported
property leaves the class uncompilable for the second reason.

This gate reproduces the guest's own compiler rather than a description of it:
it extracts the real ``$clipSource`` here-string and the real ``Add-Type``
invocation out of the production script - both taken verbatim, never retyped -
and feeds them to a real ``powershell.exe`` (Windows PowerShell 5.1, not
``pwsh``, which hosts a different, Roslyn-based provider and would not
reproduce the guest's C# 5 restriction at all). A script whose embedded C# is
not C# 5-clean fails this compile exactly as it fails on the guest.
"""

from __future__ import annotations

import re
import shutil
import sys
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import run
from intellicrack.sandbox.qemu import QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Add-Type against System.Windows.Forms requires a Windows host",
)

_SCRIPT_NAME: Final[str] = "clipboard_monitor.ps1"
_HERESTRING_RE: Final[re.Pattern[str]] = re.compile(r"\$clipSource = @'\r?\n(.*?\r?\n)'@", re.DOTALL)
_ADD_TYPE_LINE_RE: Final[re.Pattern[str]] = re.compile(r"^[ \t]*Add-Type[^\r\n]*\$clipSource[^\r\n]*$", re.MULTILINE)
_COMPILE_TIMEOUT_S: Final[float] = 45.0
_OK_SENTINEL: Final[str] = "INTELLICRACK_ADD_TYPE_OK"


def _bundled_script_path() -> Path:
    """Return the on-disk path of the real bundled clipboard monitor script.

    Returns:
        Path: Absolute path resolved the same way production locates it, via
        :meth:`QEMUSandbox.bundled_scripts_dir`, so this gate cannot drift
        from the file production actually stages into a guest.
    """
    return QEMUSandbox.bundled_scripts_dir() / _SCRIPT_NAME


def _extract_clip_source(script_text: str) -> str:
    """Extract the ``$clipSource`` here-string body from the script text.

    Args:
        script_text: Full text of ``clipboard_monitor.ps1``.

    Returns:
        str: The C# source exactly as it appears between the here-string
        delimiters, unmodified.
    """
    match = _HERESTRING_RE.search(script_text)
    assert match is not None, "could not find the $clipSource here-string in clipboard_monitor.ps1; the script's structure changed"
    return match.group(1)


def _extract_add_type_line(script_text: str) -> str:
    """Extract the real ``Add-Type`` invocation line for ``$clipSource``.

    Args:
        script_text: Full text of ``clipboard_monitor.ps1``.

    Returns:
        str: The invocation line, whitespace-trimmed, exactly as production
        wrote it - including whatever ``-ReferencedAssemblies`` and
        ``-Language`` flags it currently passes.
    """
    match = _ADD_TYPE_LINE_RE.search(script_text)
    assert match is not None, "could not find the Add-Type invocation for $clipSource in clipboard_monitor.ps1"
    return match.group(0).strip()


def _resolve_windows_powershell() -> str:
    """Locate Windows PowerShell 5.1, the guest's own ``Add-Type`` host.

    Calls ``pytest.skip`` if it is not on ``PATH``. ``pwsh`` (PowerShell 7)
    is deliberately not accepted as a substitute: it hosts a different,
    Roslyn-based CodeDom provider that does not reproduce the C# 5
    restriction a stock Windows guest's ``powershell.exe`` enforces.

    Returns:
        str: Absolute path to ``powershell.exe``.
    """
    exe = shutil.which("powershell")
    if exe is None:
        pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to reproduce the guest's CodeDom C# 5 compiler")
    return exe


def _build_compile_driver(clip_source: str, add_type_line: str) -> str:
    """Assemble a standalone script that compiles the real embedded C#.

    The here-string body and the ``Add-Type`` invocation are both taken
    verbatim from production; only the surrounding try/catch and the success
    sentinel are test scaffolding.

    Args:
        clip_source: C# source extracted from ``clipboard_monitor.ps1``.
        add_type_line: ``Add-Type`` invocation extracted from the same file.

    Returns:
        str: PowerShell source for the compile-only driver script.
    """
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$clipSource = @'\n"
        f"{clip_source}'@\n"
        "try {\n"
        f"    {add_type_line}\n"
        f"    Write-Output '{_OK_SENTINEL}'\n"
        "} catch {\n"
        "    Write-Output ('ADD_TYPE_FAILED: ' + $_.Exception.Message)\n"
        "    exit 1\n"
        "}\n"
    )


def test_the_embedded_clipboard_c_sharp_compiles_under_the_guests_powershell(tmp_path: Path) -> None:
    """The real ``$clipSource`` must compile through Windows PowerShell 5.1.

    A stock Windows guest never runs anything but this compiler against this
    exact source, so a pass here is what "the collector no longer logs
    ``add_type_failed``" means in practice.

    Args:
        tmp_path: pytest-provided temporary directory fixture.
    """
    powershell = _resolve_windows_powershell()
    script_text = _bundled_script_path().read_text(encoding="utf-8")
    clip_source = _extract_clip_source(script_text)
    add_type_line = _extract_add_type_line(script_text)

    driver_path = tmp_path / "compile_driver.ps1"
    driver_path.write_text(_build_compile_driver(clip_source, add_type_line), encoding="utf-8")

    completed = run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_COMPILE_TIMEOUT_S,
    )

    combined = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 0, (
        f"the embedded clipboard C# failed to compile under Windows PowerShell 5.1's CodeDom C# 5 provider: {combined}"
    )
    assert _OK_SENTINEL in completed.stdout, f"the compile driver did not report success: {combined}"


def test_the_add_type_invocation_still_targets_clip_source(tmp_path: Path) -> None:
    """The extraction regexes must still match production, or the gate is void.

    A gate built from extraction that silently stopped matching would pass
    every future revision without ever compiling anything, which is
    indistinguishable from a gate that was deleted. This asserts the two
    extractions actually found real, non-empty content tied to
    ``$clipSource``.

    Args:
        tmp_path: pytest-provided temporary directory fixture, unused but
            required to keep this test's signature uniform with its sibling.
    """
    del tmp_path
    script_text = _bundled_script_path().read_text(encoding="utf-8")

    clip_source = _extract_clip_source(script_text)
    assert "class ClipboardChangedEventArgs" in clip_source, "the extracted here-string is not the clipboard C# source"

    add_type_line = _extract_add_type_line(script_text)
    assert add_type_line.startswith("Add-Type"), f"the extracted line is not an Add-Type invocation: {add_type_line!r}"
    assert "$clipSource" in add_type_line, f"the extracted Add-Type line does not target $clipSource: {add_type_line!r}"
