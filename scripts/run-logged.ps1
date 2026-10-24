#Requires -Version 7
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Recipe,
    [string]$RecipeArgs = '',
    [Parameter(Mandatory)][scriptblock]$Body
)

# PowerShell 7.4+ turns a healthy non-zero native exit into a terminating error.
# The recipe bodies below check $LASTEXITCODE at each call site, so keep the old
# behaviour and let them drive their own exit handling.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot 'logs'
$LogPath = Join-Path $LogDir 'justfile.log'
$MaxLines = 30000
# Matches the CSI escape sequences the Write-* helpers and coloured tools emit.
# The console keeps its colour (the sequence stays in the string handed to
# Write-Host); only the file copy is stripped so the log reads cleanly.
$AnsiPattern = "`e\[[0-9;?]*[ -/]*[@-~]"

# A nested invocation means an outer run-logged is already capturing this whole
# process tree (an orchestrator such as `build` or `clean` that calls wrapped
# sub-recipes). Run the body inline and let the outer capture record it, so one
# logical run produces exactly one block instead of one per sub-recipe.
if ($env:INTELLICRACK_JUST_LOGGING -eq '1') {
    $DebugPreference = 'Continue'
    $InformationPreference = 'Continue'
    & $Body
    exit $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    $null = New-Item -ItemType Directory -Path $LogDir -Force
}

# Force maximum verbosity across the child process tree. Tools that honour an
# environment switch pick these up without every call site being edited; tools a
# recipe invokes directly get their own debug flag at that call site. Appending
# to PYTEST_ADDOPTS preserves any value the caller already set.
$env:INTELLICRACK_JUST_LOGGING = '1'
$env:RUST_BACKTRACE = '1'
# Quiet by default so pixi/rattler/reqwest plumbing does not flood the log on
# every `pixi run`; raise only the project's own crate to debug. Cargo/maturin
# build verbosity comes from CARGO_TERM_VERBOSE and the recipes' own -v/-vv, not
# from RUST_LOG, so this keeps the useful detail without the noise.
$env:RUST_LOG = 'warn,intellicrack_hexcore=debug'
$env:CARGO_TERM_VERBOSE = 'true'
$env:PIP_VERBOSE = '2'
$env:CMAKE_VERBOSE_MAKEFILE = 'ON'
$env:VERBOSE = '1'
$env:BUILDKIT_PROGRESS = 'plain'
$pytestAddopts = '-vv -o log_cli=true -o log_cli_level=DEBUG'
if ($env:PYTEST_ADDOPTS) { $env:PYTEST_ADDOPTS = "$($env:PYTEST_ADDOPTS) $pytestAddopts" } else { $env:PYTEST_ADDOPTS = $pytestAddopts }

# The body is written to a temp script and run in-process with the call operator.
# A script file's `exit` only sets $LASTEXITCODE and returns to this wrapper (a
# script block's would terminate it), so the run is still recorded with its code
# without the multi-second cost of cold-starting a child pwsh. The preamble turns
# on the debug/information streams so a body's own Write-Debug/Write-Information
# reach the log, silences progress bars that only make sense on an interactive
# console, and keeps a healthy non-zero native exit from becoming a terminating
# error inside the body. VerbosePreference is left alone: raising it surfaces
# PowerShell's own module auto-load chatter, which is noise, not an operation;
# tool verbosity comes from the forced flags above instead.
$bodyScript = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.ps1')
$runTemp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.log')
$preamble = @'
$DebugPreference = 'Continue'
$InformationPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$PSNativeCommandUseErrorActionPreference = $false

'@
Set-Content -LiteralPath $bodyScript -Value ($preamble + $Body.ToString()) -Encoding utf8

$started = Get-Date
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$code = 0

# Capture to a private temp file first (streamed, so a long or very verbose tool
# cannot exhaust memory) while echoing every line live to the console. Push the
# repo root so a body that changes directory cannot redirect the prepend below,
# and catch a terminating error so a crashing body is still recorded.
$writer = [System.IO.StreamWriter]::new($runTemp, $false, [System.Text.UTF8Encoding]::new($false))
$writer.AutoFlush = $true
Push-Location -LiteralPath $RepoRoot
try {
    & $bodyScript *>&1 | ForEach-Object {
        $raw = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() } else { [string]$_ }
        Write-Host $raw
        $stamp = (Get-Date).ToString('HH:mm:ss.fff')
        $writer.WriteLine("$stamp  $($raw -replace $AnsiPattern, '')")
    }
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
} catch {
    $msg = $_.Exception.Message
    Write-Host $msg
    $writer.WriteLine("$((Get-Date).ToString('HH:mm:ss.fff'))  [run-logged] body raised a terminating error: $msg")
    $code = 1
} finally {
    $writer.Dispose()
    Pop-Location
}
$stopwatch.Stop()
$seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

$argSuffix = if ([string]::IsNullOrWhiteSpace($RecipeArgs)) { '' } else { " $($RecipeArgs.Trim())" }
$header = "===== $($started.ToString('yyyy-MM-dd HH:mm:ss')) | just $Recipe$argSuffix ====="
$footer = "----- just $Recipe : exit $code in ${seconds}s -----"
$runLines = @($header) + @(Get-Content -LiteralPath $runTemp) + @($footer, '')

# Prepend this run above the older entries and keep only the newest $MaxLines,
# under a (session-scoped) mutex so concurrent recipe runs cannot interleave
# their rewrites of the shared log. An abandoned mutex (a run killed mid-write)
# still transfers ownership, so that case proceeds rather than deadlocking.
$mutex = [System.Threading.Mutex]::new($false, 'IntellicrackJustfileLog')
try {
    try { [void]$mutex.WaitOne() } catch [System.Threading.AbandonedMutexException] { Write-Debug "Recovered abandoned log mutex from a run killed mid-write: $_" }
    $keep = $MaxLines - $runLines.Count
    if ($keep -lt 0) { $keep = 0 }
    $old = if ($keep -gt 0 -and (Test-Path -LiteralPath $LogPath)) { @(Get-Content -LiteralPath $LogPath -TotalCount $keep) } else { @() }
    $final = @($runLines) + $old
    if ($final.Count -gt $MaxLines) { $final = $final[0..($MaxLines - 1)] }
    Set-Content -LiteralPath $LogPath -Value $final -Encoding utf8
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

Remove-Item -LiteralPath $bodyScript, $runTemp -Force -ErrorAction SilentlyContinue
exit $code
