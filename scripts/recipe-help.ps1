param(
    [Parameter(Mandatory)][string]$Recipe
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$justfile = Join-Path (Split-Path -Parent $PSScriptRoot) 'justfile'

$dump = & just --justfile $justfile --dump --dump-format json 2>$null
if ($LASTEXITCODE -ne 0 -or -not $dump) {
    Write-Fail "Could not read recipe metadata (just --dump failed)"
    exit 1
}

$model = $dump | Out-String | ConvertFrom-Json

$target = $Recipe
$aliasOf = $null
if (($model.recipes.PSObject.Properties.Name) -notcontains $Recipe) {
    $alias = $model.aliases.PSObject.Properties | Where-Object { $_.Name -eq $Recipe } | Select-Object -First 1
    if ($alias) {
        $target = $alias.Value.target
        $aliasOf = $Recipe
    } else {
        Write-Fail "No recipe named '$Recipe'"
        exit 1
    }
}

$recipeObj = $model.recipes.$target

$groups = @()
$docAttr = $null
foreach ($attr in $recipeObj.attributes) {
    if ($null -ne $attr.group) { $groups += $attr.group }
    if ($null -ne $attr.doc) { $docAttr = $attr.doc }
}

$aliases = @()
foreach ($prop in $model.aliases.PSObject.Properties) {
    if ($prop.Value.target -eq $target) { $aliases += $prop.Name }
}

$usage = @()
$argRows = @()
foreach ($param in $recipeObj.parameters) {
    if ($param.name -eq 'help') { continue }
    if ($param.long) {
        $flag = "--$($param.long)"
        if ($param.short) { $flag = "$flag, -$($param.short)" }
        $usage += "[--$($param.long)]"
        $argRows += [pscustomobject]@{ Name = $flag; Desc = "flag (default: $($param.default))" }
    } elseif ($param.kind -eq 'star') {
        $suffix = if ($param.default) { " (default: '$($param.default)')" } else { '' }
        $usage += "[$($param.name)...]"
        $argRows += [pscustomobject]@{ Name = "$($param.name)..."; Desc = "optional, passed through to the underlying tool$suffix" }
    } elseif ($param.kind -eq 'plus') {
        $usage += "<$($param.name)...>"
        $argRows += [pscustomobject]@{ Name = "$($param.name)..."; Desc = 'one or more values, passed through to the underlying tool' }
    } elseif ($null -ne $param.default) {
        $usage += "[$($param.name)]"
        $argRows += [pscustomobject]@{ Name = $param.name; Desc = "optional (default: '$($param.default)')" }
    } else {
        $usage += "<$($param.name)>"
        $argRows += [pscustomobject]@{ Name = $param.name; Desc = 'required' }
    }
}
$usage += '[--help]'
$argRows += [pscustomobject]@{ Name = '--help, -h'; Desc = 'show this help and exit' }

# just --dump keeps only the comment paragraph adjacent to the recipe, so the
# author's fuller notes (flag tables, TYPE lists, examples set off by a blank
# line) are lost from it. Read them straight from the justfile instead: walk up
# from the recipe past its attributes, then collect the contiguous comment
# lines, bridging a blank line only when more comment lines continue above it so
# the whole documentation block is kept but the previous recipe is not.
$notes = @()
$body = ''
$lines = @(Get-Content -LiteralPath $justfile)
$defPattern = "^$([regex]::Escape($target))(?:\s|:)"
$defIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $defPattern) { $defIdx = $i; break }
}
if ($defIdx -ge 0) {
    $k = $defIdx + 1
    while ($k -lt $lines.Count -and $lines[$k] -match '^\s+\S') { $body += ' ' + $lines[$k]; $k++ }

    $collected = [System.Collections.Generic.List[string]]::new()
    $i = $defIdx - 1
    while ($i -ge 0 -and $lines[$i] -match '^\s*\[') { $i-- }
    while ($i -ge 0) {
        if ($lines[$i] -match '^\s*#') {
            $collected.Insert(0, ($lines[$i] -replace '^\s*#\s?', ''))
            $i--
        } elseif ($lines[$i].Trim() -eq '') {
            $j = $i
            while ($j -ge 0 -and $lines[$j].Trim() -eq '') { $j-- }
            if ($j -ge 0 -and $lines[$j] -match '^\s*#') {
                $collected.Insert(0, '')
                $i = $j
            } else {
                break
            }
        } else {
            break
        }
    }
    $notes = @($collected)
    while ($notes.Count -gt 0 -and $notes[0].Trim() -eq '') { $notes = $notes[1..($notes.Count - 1)] }
    while ($notes.Count -gt 0 -and $notes[-1].Trim() -eq '') { $notes = $notes[0..($notes.Count - 2)] }
}

# A passthrough recipe forwards its flags to the underlying tool, so the real,
# complete option list lives there. When such a recipe runs one of the project's
# own Python entry points (always argparse, whose --help prints and exits), run
# that --help and show it. The probe is gated to recipes that actually take
# variadic arguments and are not lint wrappers, so a fixed-script recipe like
# fix-pyqt6-stubs or a tool buried in a run-lint-tool.ps1 -Command string is
# never executed by a mere --help; a bare .ps1 is never probed either.
$hasVariadic = @($recipeObj.parameters | Where-Object { $_.kind -in @('star', 'plus') }).Count -gt 0
$toolProbe = $null
$toolHelp = $null
if ($hasVariadic -and $body -notmatch 'run-lint-tool') {
    if ($body -match 'python\s+-m\s+([A-Za-z0-9_.]+)') {
        $module = $Matches[1]
        $toolProbe = "pixi run python -m $module --help"
        $toolHelp = & pixi run python -m $module --help 2>&1 | Out-String
    } elseif ($body -match 'python\s+([^\s"'']+\.py)') {
        $scriptPath = $Matches[1]
        $toolProbe = "pixi run python $scriptPath --help"
        $toolHelp = & pixi run python $scriptPath --help 2>&1 | Out-String
    }
}

Write-Banner "just $target"
if ($docAttr) {
    Write-Host $docAttr
    Write-Host ''
}
Write-Host "$script:e[1mUsage:$script:e[0m just $target $($usage -join ' ')"

$meta = @()
if ($groups.Count -gt 0) { $meta += "group: $($groups -join ', ')" }
if ($aliases.Count -gt 0) { $meta += "aliases: $($aliases -join ', ')" }
if ($meta.Count -gt 0) { Write-Host "$script:e[90m$($meta -join '    ')$script:e[0m" }
if ($aliasOf) { Write-Host "$script:e[90m('$aliasOf' is an alias for '$target')$script:e[0m" }

if ($notes.Count -gt 0) {
    Write-Host ''
    Write-Host "$script:e[1mNotes:$script:e[0m"
    foreach ($line in $notes) { Write-Host "  $line" }
}

Write-Host ''
Write-Host "$script:e[1mArguments:$script:e[0m"
$width = ($argRows | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
foreach ($row in $argRows) {
    Write-Host ("  {0}  {1}" -f $row.Name.PadRight($width), $row.Desc)
}

if ($toolHelp -and $toolHelp.Trim()) {
    Write-Host ''
    Write-Host "$script:e[1mTool options$script:e[0m $script:e[90m($toolProbe)$script:e[0m"
    foreach ($line in ($toolHelp -split "`r?`n")) { Write-Host "  $line" }
}
