$env:PYTHONUTF8 = '1'
$tmpFile = [System.IO.Path]::GetTempFileName()
$stderrFile = [System.IO.Path]::GetTempFileName()

Write-Host "Starting semgrep with --pro..."
$proc = Start-Process -FilePath 'semgrep' -ArgumentList @('scan','--pro','--config=auto','--json','src/') -NoNewWindow -PassThru -RedirectStandardOutput $tmpFile -RedirectStandardError $stderrFile
Write-Host "PID: $($proc.Id)"

if (!$proc.WaitForExit(300000)) {
    $proc.Kill()
    Write-Host "Killed hung process after 5 min timeout"
} else {
    Write-Host "Exited normally with code: $($proc.ExitCode)"
}

$size = (Get-Item $tmpFile).Length
Write-Host "Output file size: $size bytes"

if ($size -gt 10) {
    Write-Host "--- First 3 lines ---"
    Get-Content $tmpFile -TotalCount 3
    Write-Host "--- Last 3 lines ---"
    Get-Content $tmpFile -Tail 3
}

$stderrSize = (Get-Item $stderrFile).Length
Write-Host "Stderr file size: $stderrSize bytes"
if ($stderrSize -gt 0) {
    Write-Host "--- Stderr last 5 lines ---"
    Get-Content $stderrFile -Tail 5
}

Remove-Item $tmpFile,$stderrFile -Force -ErrorAction SilentlyContinue
