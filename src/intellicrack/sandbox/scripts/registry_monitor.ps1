[CmdletBinding()]
param(
    [Parameter()][string]$LogDir = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\Shared\logs')
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$logPath = Join-Path -Path $LogDir -ChildPath 'registry_monitor.log'

$watchedRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SYSTEM\CurrentControlSet\Services'
)

function Get-RegValueType {
    param([string]$RegPath, [string]$ValueName)
    try {
        $item = Get-Item -LiteralPath $RegPath -ErrorAction Stop
        $kind = $item.GetValueKind($ValueName)
        return [string]$kind
    } catch {
        return 'Unknown'
    }
}

function ConvertTo-HivePath {
    param([string]$ProviderPath)
    $path = $ProviderPath -replace '^.*?Registry::', ''
    $path = $path -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $path = $path -replace '^HKEY_CURRENT_USER', 'HKCU'
    $path = $path -replace '^HKEY_CLASSES_ROOT', 'HKCR'
    $path = $path -replace '^HKEY_USERS', 'HKU'
    return ($path -replace '^HKEY_CURRENT_CONFIG', 'HKCC')
}

function ConvertTo-LogField {
    param([string]$Text)
    return (($Text -replace '\|', '_') -replace '[\r\n]+', ' ')
}

function Get-ValueSnapshot {
    param([string]$Root)
    $snap = @{}
    try {
        $items = Get-ChildItem -LiteralPath $Root -Recurse -ErrorAction SilentlyContinue
        foreach ($it in $items) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $it.PSPath -ErrorAction Stop } catch { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match '^PS') { continue }
                $vtype = Get-RegValueType -RegPath $it.PSPath -ValueName $p.Name
                $key = $Root + '|' + $it.PSPath + '|' + $p.Name
                $snap[$key] = [pscustomobject]@{
                    Root  = $Root
                    Path  = ConvertTo-HivePath -ProviderPath $it.PSPath
                    Name  = $p.Name
                    Type  = $vtype
                    Value = [string]$p.Value
                }
            }
        }
    } catch {}
    return $snap
}

$baseline = @{}
foreach ($root in $watchedRoots) {
    $snap = Get-ValueSnapshot -Root $root
    foreach ($k in $snap.Keys) { $baseline[$k] = $snap[$k] }
}

while ($true) {
    Start-Sleep -Seconds 3
    $ts = (Get-Date).ToString('o')
    foreach ($root in $watchedRoots) {
        $current = Get-ValueSnapshot -Root $root
        foreach ($k in $current.Keys) {
            $entry = $current[$k]
            $path = ConvertTo-LogField -Text $entry.Path
            $name = ConvertTo-LogField -Text $entry.Name
            $vtype = ConvertTo-LogField -Text $entry.Type
            $val = ConvertTo-LogField -Text $entry.Value
            if (-not $baseline.ContainsKey($k)) {
                "$ts|created|$path|$name|$vtype|$val" | Out-File -Append -FilePath $logPath -Encoding utf8
                $baseline[$k] = $entry
            } elseif ($baseline[$k].Value -ne $entry.Value) {
                "$ts|modified|$path|$name|$vtype|$val" | Out-File -Append -FilePath $logPath -Encoding utf8
                $baseline[$k] = $entry
            }
        }
        foreach ($k in @($baseline.Keys)) {
            $entry = $baseline[$k]
            if ($entry.Root -eq $root -and -not $current.ContainsKey($k)) {
                $path = ConvertTo-LogField -Text $entry.Path
                $name = ConvertTo-LogField -Text $entry.Name
                $vtype = ConvertTo-LogField -Text $entry.Type
                "$ts|deleted|$path|$name|$vtype|" | Out-File -Append -FilePath $logPath -Encoding utf8
                $baseline.Remove($k)
            }
        }
    }
}
