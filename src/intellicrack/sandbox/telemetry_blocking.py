# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""In-guest blocking of a Windows guest's own operating-system telemetry.

Sandbox Settings offers "Block telemetry endpoints", and what an analyst wants
from it is a capture in which every outbound flow belongs to the sample. A
stock Windows guest talks to its vendor constantly, and that traffic is
indistinguishable from a sample's beaconing in a PCAP unless it is stopped at
the source.

Two mechanisms are applied inside the guest, because neither is sufficient
alone:

* a **hosts-file sinkhole** for the published telemetry FQDNs. Name resolution
  is where a hostname is still a hostname; by the time a packet exists it
  carries an address that rotates across an enormous CDN, so a host-side or
  firewall filter cannot express "this endpoint" at all.
* **outbound firewall rules** for the telemetry *programs*. The sinkhole is
  bypassed by anything that resolves without the hosts file - a client with a
  pinned address, or DNS-over-HTTPS - and blocking the executables covers that
  path regardless of how they resolve.

Deliberately absent: stopping or disabling the DiagTrack service. It is the
obvious third mechanism and it is the one a sample can see. A guest whose
telemetry service is missing does not look like the machine the sample expects
to be running on, and this package spends real effort elsewhere on making the
guest look stock.
"""

from __future__ import annotations

import base64
import ipaddress
from typing import Final


__all__ = [
    "HOSTS_BLOCK_MARKER",
    "SINKHOLE_ADDRESS",
    "TELEMETRY_HOSTS",
    "TELEMETRY_PROGRAMS",
    "build_windows_blocking_command",
    "build_windows_blocking_script",
    "parse_blocking_result",
]


# Published Microsoft telemetry, error-reporting and settings endpoints. The
# ``v10.events.data.microsoft.com`` entry is not decorative: a Windows guest
# booted by this package was measured resolving it and completing a TCP
# connection to it on 443 within a minute of reaching the desktop.
TELEMETRY_HOSTS: Final[tuple[str, ...]] = (
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "vortex-sandbox.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com",
    "watson.ppe.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com",
    "df.telemetry.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "sqm.df.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "settings-sandbox.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "v10.vortex-win.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "eu-v10.events.data.microsoft.com",
    "us-v10.events.data.microsoft.com",
    "umwatson.events.data.microsoft.com",
    "watson.microsoft.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
)

# Telemetry and error-reporting clients, blocked outbound by program path.
# Scoped to these executables rather than to ``svchost.exe``: a blanket block
# on the service host would take the guest's networking with it, and a sandbox
# whose guest cannot reach anything measures nothing.
TELEMETRY_PROGRAMS: Final[tuple[str, ...]] = (
    r"%SystemRoot%\System32\CompatTelRunner.exe",
    r"%SystemRoot%\System32\DeviceCensus.exe",
    r"%SystemRoot%\System32\dmclient.exe",
    r"%SystemRoot%\System32\wermgr.exe",
    r"%SystemRoot%\System32\WerFault.exe",
    r"%SystemRoot%\System32\wsqmcons.exe",
)

# The unspecified address rather than loopback: a loopback sinkhole makes the
# client open a connection to a local port something else may be listening on,
# and that connection then appears in the capture as traffic the sample did not
# make. The unspecified address fails immediately instead.
SINKHOLE_ADDRESS: Final[str] = str(ipaddress.IPv4Address(0))

# Fences the block this package owns inside a file the guest also maintains, so
# re-applying it replaces exactly what was written last time and nothing else.
HOSTS_BLOCK_MARKER: Final[str] = "Intellicrack telemetry sinkhole"

_FIREWALL_RULE_PREFIX: Final[str] = "Intellicrack telemetry block"

# The summary the script prints is pipe-delimited rather than JSON, matching the
# shape every other guest-to-host record in this package uses. ``ConvertTo-Json``
# is not dependable at this boundary: its behaviour differs between the Windows
# PowerShell a stock guest ships and PowerShell 7, and a guest that fails to
# serialise its summary is indistinguishable from one that never ran the script.
_RESULT_MARKER: Final[str] = "INTELLICRACK_TELEMETRY_BLOCK"
_RESULT_FIELDS: Final[tuple[str, ...]] = (
    "hosts_entries",
    "firewall_rules",
    "firewall_backend",
    "hosts_path",
    "problems",
)
_RESULT_COUNT_FIELDS: Final[frozenset[str]] = frozenset({"hosts_entries", "firewall_rules"})
_PROBLEM_SEPARATOR: Final[str] = " ;; "


def _powershell_single_quoted(value: str) -> str:
    """Quote a value as a PowerShell literal string.

    Args:
        value: Text to embed in the generated script.

    Returns:
        str: The value wrapped in single quotes, with any single quote doubled.
    """
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _powershell_string_array(values: tuple[str, ...]) -> str:
    """Render values as a PowerShell array literal.

    Args:
        values: Strings to render.

    Returns:
        str: A PowerShell ``@(...)`` array of quoted literals.
    """
    return "@(" + ", ".join(_powershell_single_quoted(value) for value in values) + ")"


def build_windows_blocking_script() -> str:
    """Build the PowerShell that blocks telemetry inside a Windows guest.

    The script is idempotent: the hosts block it owns is delimited by
    :data:`HOSTS_BLOCK_MARKER` and rewritten wholesale, and each firewall rule
    is removed before being recreated. Applying it to a guest that already has
    it leaves the guest in the same state.

    Firewall rules go through the ``NetSecurity`` module when it is present and
    fall back to ``netsh advfirewall`` when it is not, because Windows editions
    that ship without the module still have the firewall.

    Returns:
        str: A complete PowerShell script. Its last line is a single
        pipe-delimited record prefixed with a marker, reporting how many hosts
        entries and firewall rules were written, which firewall backend was
        used, and any error encountered.
    """
    hosts = _powershell_string_array(TELEMETRY_HOSTS)
    programs = _powershell_string_array(TELEMETRY_PROGRAMS)
    marker = _powershell_single_quoted(HOSTS_BLOCK_MARKER)
    rule_prefix = _powershell_single_quoted(_FIREWALL_RULE_PREFIX)
    sinkhole = _powershell_single_quoted(SINKHOLE_ADDRESS)
    result_marker = _powershell_single_quoted(_RESULT_MARKER)
    separator = _powershell_single_quoted(_PROBLEM_SEPARATOR)

    return f"""$ErrorActionPreference = 'Stop'
$hosts = {hosts}
$programs = {programs}
$marker = {marker}
$rulePrefix = {rule_prefix}
$sinkhole = {sinkhole}
$resultMarker = {result_marker}
$hostsWritten = 0
$rulesWritten = 0
$problems = @()

$hostsPath = Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'
try {{
    $begin = "# BEGIN $marker"
    $end = "# END $marker"
    $existing = @()
    if (Test-Path -LiteralPath $hostsPath) {{
        $existing = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
    }}
    $kept = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in $existing) {{
        if ($line -eq $begin) {{ $inBlock = $true; continue }}
        if ($line -eq $end) {{ $inBlock = $false; continue }}
        if (-not $inBlock) {{ $kept.Add($line) }}
    }}
    $kept.Add($begin)
    $added = 0
    foreach ($name in $hosts) {{
        $kept.Add("$sinkhole $name")
        $added = $added + 1
    }}
    $kept.Add($end)
    Set-Content -LiteralPath $hostsPath -Value $kept.ToArray() -Encoding ASCII -Force
    # Counted only once the file is on disk. Counting while building the list
    # would have reported a full sinkhole for a write that threw.
    $hostsWritten = $added
}} catch {{
    $problems += "hosts: $($_.Exception.Message)"
}}

$useModule = $null -ne (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue)
foreach ($program in $programs) {{
    $expanded = [System.Environment]::ExpandEnvironmentVariables($program)
    $leaf = Split-Path -Path $expanded -Leaf
    $ruleName = "$rulePrefix - $leaf"
    try {{
        if ($useModule) {{
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $expanded `
                -Action Block -Profile Any -Enabled True | Out-Null
        }} else {{
            & netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
            & netsh advfirewall firewall add rule name="$ruleName" dir=out action=block `
                program="$expanded" enable=yes | Out-Null
            if ($LASTEXITCODE -ne 0) {{ throw "netsh exited $LASTEXITCODE" }}
        }}
        $rulesWritten = $rulesWritten + 1
    }} catch {{
        $problems += "$leaf`: $($_.Exception.Message)"
    }}
}}

$backend = 'netsh'
if ($useModule) {{ $backend = 'netsecurity' }}
$problemText = ($problems -join {separator})
$fields = @($hostsWritten, $rulesWritten, $backend, $hostsPath, $problemText)
$clean = foreach ($field in $fields) {{ ([string]$field).Replace('|', '/').Replace("`r", ' ').Replace("`n", ' ') }}
Write-Output ($resultMarker + '|' + ($clean -join '|'))
"""


def build_windows_blocking_command() -> list[str]:
    """Build the guest argv that runs the blocking script.

    ``powershell.exe`` is invoked with ``-EncodedCommand`` because the guest
    channels this package uses dispatch through ``cmd.exe``, which mangles a
    multi-line script into an empty run that still reports success.

    Returns:
        list[str]: Arguments for ``powershell.exe``, excluding the executable.
    """
    encoded = base64.b64encode(build_windows_blocking_script().encode("utf-16-le")).decode("ascii")
    return ["-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]


def parse_blocking_result(output: str) -> dict[str, object] | None:
    """Extract the summary the blocking script printed.

    The counts come back as integers and ``problems`` as a list, so a caller
    can tell "wrote nothing" from "wrote thirty-one" without reparsing text.
    A record whose counts are not numeric is rejected outright rather than
    reported as zero: a guest that garbled its summary has not been shown to
    have blocked anything.

    Args:
        output: Captured standard output of the script.

    Returns:
        dict[str, object] | None: The parsed summary, keyed by
        :data:`_RESULT_FIELDS`, or ``None`` when the script produced no
        readable marker line.
    """
    prefix = f"{_RESULT_MARKER}|"
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        fields = stripped[len(prefix) :].split("|")
        if len(fields) != len(_RESULT_FIELDS):
            return None
        summary: dict[str, object] = {}
        for name, value in zip(_RESULT_FIELDS, fields, strict=True):
            if name in _RESULT_COUNT_FIELDS:
                if not value.isdigit():
                    return None
                summary[name] = int(value)
            elif name == "problems":
                summary[name] = [item.strip() for item in value.split(_PROBLEM_SEPARATOR.strip()) if item.strip()]
            else:
                summary[name] = value
        return summary
    return None
