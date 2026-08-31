param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Commit"

$prepPyCode = @'
import sys
import traceback
from pathlib import Path

_REPO = Path.cwd()
sys.path.insert(0, str(_REPO / "scripts"))
sys.path.insert(0, str(_REPO / "scripts" / "knowledge-graph"))


def _emit(tag: str, name: str, detail: str = "") -> None:
    print(f"__STEP_{tag}__:{name}:{detail}", flush=True)


def _step(name: str, fn) -> None:
    _emit("START", name)
    try:
        fn()
    except SystemExit as exc:
        code = exc.code
        if code in (None, 0):
            _emit("OK", name)
            return
        _emit("FAIL", name, f"exit code {code}")
        return
    except BaseException as exc:
        _emit("FAIL", name, f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
        return
    _emit("OK", name)


def _run_nul() -> None:
    import clean_nul
    clean_nul.clean_nul_files()


def _run_tree() -> None:
    import generate_tree
    root = str(_REPO)
    generate_tree.generate_hta(root, str(_REPO / "IntellicrackStructure.hta"))
    generate_tree.generate_txt_tree(root, str(_REPO / "IntellicrackStructure.txt"))


def _run_kmap() -> None:
    import visualize_architecture
    saved_argv = sys.argv[:]
    sys.argv = ["visualize_architecture.py", "--layout", "hierarchical"]
    try:
        visualize_architecture.main()
    finally:
        sys.argv = saved_argv


def _run_reqs() -> None:
    import generate_requirements
    rc = generate_requirements.generate_requirements()
    if rc != 0:
        raise SystemExit(rc)


_step("nul", _run_nul)
_step("tree", _run_tree)
_step("kmap", _run_kmap)
_step("reqs", _run_reqs)
'@

$stepLabels = @{
    nul  = @{ start = 'Running NUL cleanup...';            ok = 'NUL cleanup complete' }
    tree = @{ start = 'Generating structure files...';     ok = 'Structure generated' }
    kmap = @{ start = 'Generating knowledge map...';       ok = 'Knowledge map generated' }
    reqs = @{ start = 'Generating requirements.txt...';    ok = 'Requirements generated' }
}

$pixiParts = @($Pixi -split '\s+' | Where-Object { $_ })
if ($pixiParts.Count -eq 0) {
    Write-Fail "Pixi command is empty"
    exit 1
}
$pixiExe = $pixiParts[0]
$pixiSub = @()
if ($pixiParts.Count -gt 1) { $pixiSub = @($pixiParts[1..($pixiParts.Count - 1)]) }

try {
    $prepPyCode | & $pixiExe @pixiSub python - 2>&1 | ForEach-Object {
        $line = "$_"
        if ($line -match '^__STEP_START__:([^:]+):') {
            $name = $matches[1]
            $msg = if ($stepLabels.ContainsKey($name)) { $stepLabels[$name].start } else { "Running $name..." }
            Write-Step 'GIT' $msg '32'
        } elseif ($line -match '^__STEP_OK__:([^:]+):') {
            $name = $matches[1]
            $msg = if ($stepLabels.ContainsKey($name)) { $stepLabels[$name].ok } else { $name }
            Write-Success $msg
        } elseif ($line -match '^__STEP_FAIL__:([^:]+):(.*)$') {
            $name = $matches[1]
            $detail = $matches[2]
            $label = if ($stepLabels.ContainsKey($name)) { $stepLabels[$name].ok } else { $name }
            Write-Fail "$label failed: $detail"
        }
    }
} catch {
    Write-Fail "Prep bundle exception: $($_.Exception.Message)"
}

Write-Step 'GIT' "Staging changes..." '32'
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
try {
    git add -A 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git add failed" }
    Write-Success "Changes staged"
} catch {
    Write-Fail "Staging failed: $_"
    exit 1
}

$commitMsg = "WIP: $timestamp"
Write-Step 'GIT' "Generating commit message..." '32'
try {
    $stat = (git diff --cached --stat 2>&1) | Out-String
    $diffBody = (git diff --cached -- 'src/' 'tests/' 'scripts/' 'pyproject.toml' 'justfile' 2>&1) | Out-String
    $diffInput = "FILES CHANGED:`n$stat`nDIFF:`n$diffBody"
    $raw = Invoke-Expression "`$diffInput | $Pixi python scripts/generate_commit_message.py"
    $geminiExit = $LASTEXITCODE
    $genMsg = if ($raw) { ($raw | Out-String).Trim() } else { '' }
    if ($geminiExit -eq 0 -and $genMsg.Length -gt 5) {
        $commitMsg = $genMsg
        Write-Success "Message: $($commitMsg.Split("`n")[0])"
    } else {
        Write-Fail "Gemini failed (exit=$geminiExit, output=$($genMsg.Length) chars)"
        Write-Step 'GIT' "Using fallback: $commitMsg" '32'
    }
} catch {
    Write-Fail "Gemini exception: $($_.Exception.Message)"
    Write-Step 'GIT' "Using fallback: $commitMsg" '32'
}

Write-Step 'GIT' "Regenerating CHANGELOG.md (including pending commit)..." '32'
try {
    & "$PSScriptRoot/update-changelog.ps1" -Pixi "$Pixi" -Message "$commitMsg"
    if ($LASTEXITCODE -ne 0) { throw "update-changelog.ps1 failed (exit=$LASTEXITCODE)" }
    git add CHANGELOG.md 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git add CHANGELOG.md failed" }
    Write-Success "CHANGELOG.md staged"
} catch {
    Write-Fail "Changelog step failed: $_"
    Write-Step 'GIT' "Proceeding with commit without changelog update" '33'
}

Write-Step 'GIT' "Committing and pushing..." '32'
try {
    git commit --no-verify -m $commitMsg 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git commit failed" }
    Write-Success "Committed"
} catch {
    Write-Fail "Commit failed: $_"
    exit 1
}

try {
    $pushArgs = "git push --no-verify origin HEAD $Flags"
    Invoke-Expression $pushArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
    Write-Success "Pushed to origin"
} catch {
    Write-Fail "Push failed: $_"
    exit 1
}

Write-Footer "Commit Complete" $startTime
