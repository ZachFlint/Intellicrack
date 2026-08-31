param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Generating Knowledge Map"

$scriptPath = "scripts\knowledge-graph\visualize_architecture.py"

Write-Step 'MAP' "Running map generator..."
try {
    $output = Invoke-Expression "$Pixi python $scriptPath --layout hierarchical 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "Map generation failed" }
    Write-Success "Map generated"
} catch {
    Write-Fail "Generation failed: $_"
    exit 1
}

Write-Step 'MAP' "Validating outputs..."
$htmlPath = "IntellicrackKnowledgeGraph.html"
$kgDir = "scripts\knowledge-graph"
$graphmlPath = "$kgDir\IntellicrackKnowledgeGraph.graphml"
$dotPath = "$kgDir\IntellicrackKnowledgeGraph.dot"

if (-not (Test-Path $htmlPath)) { Write-Fail "HTML not found: $htmlPath"; exit 1 }
Write-Success "HTML: $htmlPath"

if (Test-Path $graphmlPath) { Write-Success "GraphML: $graphmlPath" }
if (Test-Path $dotPath) { Write-Success "DOT: $dotPath" }

$e = [char]27
$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n${e}[1;36m=== Knowledge Map Complete ===${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m`n"
