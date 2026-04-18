param(
    [string]$LogDir = '.',
    [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'api_trace.log'

function Write-TraceLine {
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )
    Add-Content -LiteralPath $logPath -Value $Line -Encoding utf8
}

function Format-TraceField {
    param(
        [Parameter(Mandatory = $false)][object]$Value
    )
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '\|', '_' -replace '[\r\n]+', ' '
}

function Find-TraceEventAssembly {
    $candidates = [System.Collections.Generic.List[string]]::new()

    $nugetRoot = Join-Path -Path $env:USERPROFILE -ChildPath '.nuget\packages\microsoft.diagnostics.tracing.traceevent'
    if (Test-Path -LiteralPath $nugetRoot) {
        $versions = Get-ChildItem -LiteralPath $nugetRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending
        foreach ($ver in $versions) {
            $libRoot = Join-Path -Path $ver.FullName -ChildPath 'lib'
            if (-not (Test-Path -LiteralPath $libRoot)) { continue }
            $dlls = Get-ChildItem -LiteralPath $libRoot -Recurse -Filter 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' -ErrorAction SilentlyContinue
            foreach ($dll in $dlls) { $candidates.Add($dll.FullName) }
        }
    }

    $programFiles = 'C:\Program Files\TraceEvent'
    if (Test-Path -LiteralPath $programFiles) {
        $dlls = Get-ChildItem -LiteralPath $programFiles -Recurse -Filter 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' -ErrorAction SilentlyContinue
        foreach ($dll in $dlls) { $candidates.Add($dll.FullName) }
    }

    $scriptDir = Split-Path -Parent $PSCommandPath
    if ($scriptDir -and (Test-Path -LiteralPath $scriptDir)) {
        $localDll = Join-Path -Path $scriptDir -ChildPath 'Microsoft.Diagnostics.Tracing.TraceEvent.dll'
        if (Test-Path -LiteralPath $localDll) { $candidates.Add($localDll) }
    }

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}

$sessionName = 'IntApiTrace'
$realtimeSessionName = 'IntApiTraceRT'
$etlPath = Join-Path -Path $LogDir -ChildPath "$sessionName.etl"
$auditApiProvider = '{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}'

$traceEventDll = Find-TraceEventAssembly
if (-not $traceEventDll) {
    $ts = Get-Date -Format 'o'
    Write-TraceLine -Line "$ts|tracer|0|ERROR|unavailable|TraceEvent.dll not found|-1"
    exit 0
}

try {
    Add-Type -LiteralPath $traceEventDll -ErrorAction Stop
} catch {
    $ts = Get-Date -Format 'o'
    $detail = Format-TraceField -Value $_.Exception.Message
    Write-TraceLine -Line "$ts|tracer|0|ERROR|unavailable|TraceEvent load failed: $detail|-1"
    exit 0
}

& logman.exe stop $sessionName 2>&1 | Out-Null
& logman.exe delete $sessionName 2>&1 | Out-Null
& logman.exe stop $realtimeSessionName -ets 2>&1 | Out-Null

$createArgs = @(
    'create', 'trace', $sessionName,
    '-p', $auditApiProvider, '0xFFFFFFFF', '5',
    '-o', $etlPath
)
$createOutput = & logman.exe @createArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    $ts = Get-Date -Format 'o'
    $detail = Format-TraceField -Value ($createOutput -join ' ')
    Write-TraceLine -Line "$ts|tracer|0|ERROR|logman|logman create failed: $detail|$LASTEXITCODE"
    exit 0
}

$startOutput = & logman.exe start $sessionName 2>&1
if ($LASTEXITCODE -ne 0) {
    $ts = Get-Date -Format 'o'
    $detail = Format-TraceField -Value ($startOutput -join ' ')
    Write-TraceLine -Line "$ts|tracer|0|ERROR|logman|logman start failed: $detail|$LASTEXITCODE"
    & logman.exe delete $sessionName 2>&1 | Out-Null
    exit 0
}

$session = $null
try {
    $sessionType = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]
    $session = $sessionType::new($realtimeSessionName, $null)
    $session.StopOnDispose = $true

    $providerGuid = [Guid]$auditApiProvider
    $session.EnableProvider($providerGuid, [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Verbose, [uint64]::MaxValue) | Out-Null

    $source = $session.Source
    $dynParser = [Microsoft.Diagnostics.Tracing.Parsers.DynamicTraceEventParser]::new($source)

    $script:TargetPid = $TargetPid

    $handler = {
        param($evt)
        try {
            if ($script:TargetPid -ne 0 -and [int]$evt.ProcessID -ne [int]$script:TargetPid) { return }

            $ts = Get-Date -Format 'o'
            $procId = [int]$evt.ProcessID
            $procName = 'unknown'
            try {
                $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if ($p) { $procName = $p.Name }
            } catch {
                $procName = 'unknown'
            }

            $apiName = Format-TraceField -Value $evt.OpcodeName
            if (-not $apiName) { $apiName = Format-TraceField -Value $evt.EventName }
            if (-not $apiName) { $apiName = "EventId_$($evt.ID)" }

            $module = Format-TraceField -Value $evt.ProviderName

            $argParts = [System.Collections.Generic.List[string]]::new()
            try {
                $payloadNames = $evt.PayloadNames
                if ($payloadNames) {
                    foreach ($name in $payloadNames) {
                        $val = $evt.PayloadByName($name)
                        $argParts.Add("$name=$(Format-TraceField -Value $val)")
                    }
                }
            } catch {
                $argParts.Add("payload_error=$(Format-TraceField -Value $_.Exception.Message)")
            }
            $arguments = Format-TraceField -Value ($argParts -join ';')

            $returnValue = ''
            try {
                $rv = $evt.PayloadByName('ReturnValue')
                if ($null -ne $rv) { $returnValue = Format-TraceField -Value $rv }
            } catch {
                $returnValue = ''
            }

            Write-TraceLine -Line "$ts|$procName|$procId|$apiName|$module|$arguments|$returnValue"
        } catch {
            $ts = Get-Date -Format 'o'
            $detail = Format-TraceField -Value $_.Exception.Message
            Write-TraceLine -Line "$ts|tracer|0|ERROR|handler|$detail|-1"
        }
    }

    $boundHandler = $handler.GetNewClosure()

    $dynParser.add_All($boundHandler)
    $source.UnhandledEvents.add_All($boundHandler)

    $ts = Get-Date -Format 'o'
    Write-TraceLine -Line "$ts|tracer|0|START|$sessionName|provider=$auditApiProvider;etl=$etlPath;pid_filter=$TargetPid|0"

    $source.Process() | Out-Null
} catch {
    $ts = Get-Date -Format 'o'
    $detail = Format-TraceField -Value $_.Exception.Message
    Write-TraceLine -Line "$ts|tracer|0|ERROR|session|$detail|-1"
} finally {
    if ($null -ne $session) {
        try {
            $session.Dispose()
        } catch {
            $ts = Get-Date -Format 'o'
            $detail = Format-TraceField -Value $_.Exception.Message
            Write-TraceLine -Line "$ts|tracer|0|ERROR|dispose|$detail|-1"
        }
    }
    & logman.exe stop $sessionName 2>&1 | Out-Null
    & logman.exe delete $sessionName 2>&1 | Out-Null
    & logman.exe stop $realtimeSessionName -ets 2>&1 | Out-Null
    $ts = Get-Date -Format 'o'
    Write-TraceLine -Line "$ts|tracer|0|STOP|$sessionName||0"
}
