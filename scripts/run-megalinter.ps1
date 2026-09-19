#Requires -Version 7
[CmdletBinding()]
param(
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
# docker/npx/DockerCli.exe exit codes are checked explicitly below (MegaLinter
# itself is expected to exit non-zero whenever it finds real findings) -- the
# PowerShell 7.4+ default would turn that into a terminating error before the
# check runs.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
. "$PSScriptRoot/common.ps1"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$DockerCli = 'C:\Program Files\Docker\Docker\DockerCli.exe'
# mega-linter-runner leaves the container unnamed unless --container-name or
# --timeout is passed, which leaves nothing to target if --rm ever fails to
# fire (the process is killed, the daemon restarts mid-run). Naming it makes
# the post-run sweep below deterministic, and gives a name to watch the run
# with: docker ps --filter name=intellicrack-megalinter
$DefaultContainerName = 'intellicrack-megalinter'
$RunnerPackage = 'mega-linter-runner@10'
# mega-linter-runner's own fallbacks when neither the CLI nor .mega-linter.yml
# supplies a value (lib/config.js DEFAULT_RELEASE, lib/options.js platform).
$StableRelease = 'v10'
$DefaultPlatform = 'linux/amd64'

function Split-CommandArgument {
    <#
    .SYNOPSIS
        Split a recipe-supplied argument string into an argument array.
    .DESCRIPTION
        just hands flags through as a single string; an empty or whitespace-only
        value must become an empty array rather than one empty argument, which
        npx would reject.
    .PARAMETER Value
        The raw flag string handed over by the just recipe.
    .OUTPUTS
        System.String[]. The parsed arguments, empty when nothing was passed.
    #>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split '\s+' | Where-Object { $_ })
}

function Get-OptionSpelling {
    <#
    .SYNOPSIS
        Expand option names into the dashed spellings optionator accepts.
    .PARAMETER Names
        Option names without leading dashes; single characters become short flags.
    .OUTPUTS
        System.String[]. The dashed spellings to match against.
    #>
    param([Parameter(Mandatory)][string[]]$Names)
    return @($Names | ForEach-Object { if ($_.Length -eq 1) { "-$_" } else { "--$_" } })
}

function Get-FlagValue {
    <#
    .SYNOPSIS
        Read the value of a mega-linter-runner option out of an argument array.
    .DESCRIPTION
        Handles both the `--option value` and `--option=value` forms, and any of
        the option's accepted spellings (long name plus short alias).
    .PARAMETER Arguments
        The arguments destined for mega-linter-runner.
    .PARAMETER Names
        Accepted spellings of the option, each without its leading dashes.
    .OUTPUTS
        System.String. The option's value, or $null when it is absent.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory)][string[]]$Names
    )
    $spellings = Get-OptionSpelling -Names $Names
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $token = $Arguments[$i]
        foreach ($flag in $spellings) {
            if ($token -eq $flag) {
                if ($i + 1 -lt $Arguments.Count) { return $Arguments[$i + 1] }
                return $null
            }
            if ($token.StartsWith("$flag=")) { return $token.Substring($flag.Length + 1) }
        }
    }
    return $null
}

function Test-FlagPresent {
    <#
    .SYNOPSIS
        Report whether a boolean mega-linter-runner option was passed.
    .PARAMETER Arguments
        The arguments destined for mega-linter-runner.
    .PARAMETER Names
        Accepted spellings of the option, each without its leading dashes.
    .OUTPUTS
        System.Boolean. True when one of the spellings is present.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory)][string[]]$Names
    )
    $spellings = Get-OptionSpelling -Names $Names
    foreach ($token in $Arguments) {
        foreach ($flag in $spellings) {
            if ($token -eq $flag -or $token.StartsWith("$flag=")) { return $true }
        }
    }
    return $false
}

function Get-LocalConfigValue {
    <#
    .SYNOPSIS
        Read a top-level scalar out of .mega-linter.yml.
    .DESCRIPTION
        mega-linter-runner resolves the image from MEGALINTER_FLAVOR and
        MEGALINTER_VERSION in this file (lib/runner.js readLocalConfig), so the
        install and uninstall steps below have to read the same two keys to
        target the same image. Only unquoted top-level scalars are needed here.
    .PARAMETER Key
        The configuration key to look up.
    .OUTPUTS
        System.String. The value, or $null when the key or the file is absent.
    #>
    param([Parameter(Mandatory)][string]$Key)
    $configPath = Join-Path $RepoRoot '.mega-linter.yml'
    if (-not (Test-Path -LiteralPath $configPath)) { return $null }
    $pattern = "^\s*$([regex]::Escape($Key))\s*:\s*(\S+)\s*$"
    foreach ($line in Get-Content -LiteralPath $configPath) {
        if ($line -match $pattern) { return $Matches[1].Trim('"', "'") }
    }
    return $null
}

function Resolve-MegaLinterImage {
    <#
    .SYNOPSIS
        Resolve the docker image mega-linter-runner will run.
    .DESCRIPTION
        Mirrors resolveDockerImage() in mega-linter-runner v10's lib/runner.js:
        CLI flags win over .mega-linter.yml, which wins over the package
        defaults. The v4/v5 retro-compatibility image names are not reproduced
        because this script pins the runner to v10.
    .PARAMETER Arguments
        The arguments destined for mega-linter-runner.
    .OUTPUTS
        System.String. A fully qualified image reference.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments)

    $explicitImage = Get-FlagValue -Arguments $Arguments -Names @('image', 'd')
    if ($explicitImage) { return $explicitImage }

    $release = Get-FlagValue -Arguments $Arguments -Names @('release', 'r')
    if (-not $release) { $release = Get-LocalConfigValue -Key 'MEGALINTER_VERSION' }
    if (-not $release) { $release = 'latest' }
    if ($release -eq 'stable') { $release = $StableRelease }

    $linter = Get-FlagValue -Arguments $Arguments -Names @('linter', 'l')
    if ($linter) {
        return "ghcr.io/oxsecurity/megalinter-only-$($linter.ToLowerInvariant()):${release}"
    }

    $flavor = Get-FlagValue -Arguments $Arguments -Names @('flavor', 'f')
    if (-not $flavor) { $flavor = Get-LocalConfigValue -Key 'MEGALINTER_FLAVOR' }
    if (-not $flavor) { $flavor = 'all' }
    if ($flavor -eq 'all') { return "ghcr.io/oxsecurity/megalinter:${release}" }
    return "ghcr.io/oxsecurity/megalinter-${flavor}:${release}"
}

function Test-ProcessRunning {
    <#
    .SYNOPSIS
        Check whether any process matching one of the given name patterns is running.
    .PARAMETER NamePatterns
        Process name patterns to test, as accepted by Get-Process -Name.
    .OUTPUTS
        System.Boolean. True when at least one pattern matches a live process.
    #>
    param([Parameter(Mandatory)][string[]]$NamePatterns)
    foreach ($pattern in $NamePatterns) {
        if (Get-Process -Name $pattern -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

function Test-DockerImagePresent {
    <#
    .SYNOPSIS
        Report whether an image is present in the local docker image store.
    .PARAMETER Image
        The image reference to look up.
    .OUTPUTS
        System.Boolean. True when docker can inspect the image locally.
    #>
    param([Parameter(Mandatory)][string]$Image)
    & docker image inspect $Image --format '{{.Id}}' *> $null
    return $LASTEXITCODE -eq 0
}

function Test-DockerContainerPresent {
    <#
    .SYNOPSIS
        Report whether a container of the given name exists, running or stopped.
    .PARAMETER Name
        The exact container name to look up.
    .OUTPUTS
        System.Boolean. True when docker lists a container with that name.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $ids = & docker ps --all --quiet --filter "name=^/$Name$" 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    return -not [string]::IsNullOrWhiteSpace(($ids -join ''))
}

function Remove-MegaLinterContainer {
    <#
    .SYNOPSIS
        Force-remove the MegaLinter container and confirm it is gone.
    .DESCRIPTION
        --remove-container already asks docker for --rm, which covers the normal
        exit path. This is the backstop for the paths --rm does not cover: the
        runner process being killed, or the run never reaching docker run at all.
    .PARAMETER Name
        The container name passed to mega-linter-runner.
    .OUTPUTS
        System.Boolean. True when no container of that name remains.
    #>
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-DockerContainerPresent -Name $Name)) { return $true }
    Write-Progress "Removing leftover container $Name"
    & docker rm --force $Name *> $null
    return -not (Test-DockerContainerPresent -Name $Name)
}

function Remove-MegaLinterImage {
    <#
    .SYNOPSIS
        Uninstall a MegaLinter image and confirm it is gone.
    .PARAMETER Image
        The image reference to remove.
    .OUTPUTS
        System.Boolean. True when the image is no longer present locally.
    #>
    param([Parameter(Mandatory)][string]$Image)
    if (-not (Test-DockerImagePresent -Image $Image)) { return $true }
    & docker rmi --force $Image *> $null
    return -not (Test-DockerImagePresent -Image $Image)
}

function Get-DockerEngine {
    <#
    .SYNOPSIS
        Return the running Docker Desktop engine's OSType ('linux' or 'windows'),
        or $null if the Docker daemon is unreachable.
    .OUTPUTS
        System.String. The engine OSType, or $null when docker info fails.
    #>
    $result = & docker info --format '{{.OSType}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $result) { return $null }
    return $result.Trim()
}

function Wait-DockerEngine {
    <#
    .SYNOPSIS
        Poll until Docker Desktop reports the requested engine, or time out.
    .PARAMETER Target
        The engine OSType to wait for.
    .PARAMETER TimeoutSeconds
        How long to keep polling before giving up.
    .OUTPUTS
        System.Boolean. True when the engine reported the target in time.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('linux', 'windows')][string]$Target,
        [int]$TimeoutSeconds = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if ((Get-DockerEngine) -eq $Target) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

Write-Banner 'MegaLinter'
$started = Get-Date

# Wrapped in @() because a function returning an empty array yields $null to
# its caller, which the argument-inspecting helpers below would reject.
$userArgs = @(Split-CommandArgument -Value $Flags)
# Not a mega-linter-runner option: this script's own escape hatch. The image is
# a ~4 GB download, so re-installing it on every run costs real time -- pass
# `just megalint --keep-image` while iterating to leave it installed.
$keepImage = Test-FlagPresent -Arguments $userArgs -Names @('keep-image')
if ($keepImage) {
    $userArgs = @($userArgs | Where-Object { $_ -ne '--keep-image' })
}

if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    Write-Fail 'npx is not on PATH; install Node.js'
    exit 1
}

Write-Step 'MEGALINT' 'Checking Docker Desktop is running...'
$originalEngine = Get-DockerEngine
if (-not $originalEngine) {
    Write-Fail 'Docker Desktop is not running (docker info failed). Start Docker Desktop and retry.'
    exit 1
}
Write-Success "Docker Desktop is running (engine: $originalEngine)"

# Interleaving a WHPX-backed VM (QEMU, Windows Sandbox) with a Docker Desktop
# engine switch has previously crashed this host outright -- both compete for
# the same Host Compute Service layer. Refuse to switch engines while one is up.
Write-Step 'MEGALINT' 'Checking for running QEMU / Windows Sandbox VMs...'
if (Test-ProcessRunning -NamePatterns @('qemu-system-*', 'WindowsSandbox*')) {
    Write-Fail 'A QEMU or Windows Sandbox VM is currently running. Switching the Docker engine while one is active has previously crashed this machine -- close it first, then retry.'
    exit 1
}
Write-Success 'No QEMU / Windows Sandbox VM detected'

if ($originalEngine -ne 'linux') {
    Write-Step 'MEGALINT' 'Switching Docker Desktop to Linux containers (MegaLinter images are Linux-only)...'
    & $DockerCli -SwitchLinuxEngine
    if (-not (Wait-DockerEngine -Target 'linux')) {
        Write-Fail 'Docker Desktop did not report the Linux engine within 120s; check its state manually'
        exit 1
    }
    Write-Success 'Docker Desktop is now running Linux containers'
} else {
    Write-Progress 'Docker Desktop is already running Linux containers'
}

$image = Resolve-MegaLinterImage -Arguments $userArgs
$platform = Get-FlagValue -Arguments $userArgs -Names @('platform', 'z')
if (-not $platform) { $platform = $DefaultPlatform }
$skipPull = Test-FlagPresent -Arguments $userArgs -Names @('nodockerpull', 'n')
$containerName = Get-FlagValue -Arguments $userArgs -Names @('container-name', 'containername')
if (-not $containerName) {
    $containerName = $DefaultContainerName
    $userArgs += @('--container-name', $DefaultContainerName)
}

$exitCode = 1
try {
    # Naming the container means docker run fails outright with "name already in
    # use" if one survived a previous run, so clear it before installing rather
    # than only in the finally block.
    if (-not (Remove-MegaLinterContainer -Name $containerName)) {
        Write-Fail "A container named $containerName already exists and could not be removed; remove it with 'docker rm --force $containerName' and retry"
        exit 1
    }

    # Install. mega-linter-runner pulls the image itself, but doing it here
    # instead makes the install an explicit, verified step of this script (and
    # keeps it symmetrical with the uninstall in the finally block) -- the
    # runner is then told to skip its own pull.
    if ($skipPull) {
        Write-Skip "--nodockerpull was passed, so $image is not installed by this run"
        if (-not (Test-DockerImagePresent -Image $image)) {
            Write-Fail "$image is not present locally and --nodockerpull forbids installing it; drop the flag and retry"
            exit 1
        }
    } else {
        # A copy left behind by an interrupted run would turn the pull below
        # into a digest check rather than a real install, so clear it first.
        if (Test-DockerImagePresent -Image $image) {
            Write-Progress "Uninstalling a copy of $image left behind by a previous run"
            if (-not (Remove-MegaLinterImage -Image $image)) {
                Write-Fail "Could not remove the existing $image; remove it manually with 'docker rmi --force $image' and retry"
                exit 1
            }
        }
        Write-Step 'MEGALINT' "Installing $image for $platform (a few GB; this is downloaded fresh every run)..."
        & docker pull --platform $platform $image
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "docker pull $image failed (exit $LASTEXITCODE)"
            exit 1
        }
        if (-not (Test-DockerImagePresent -Image $image)) {
            Write-Fail "docker pull reported success but $image is not in the local image store"
            exit 1
        }
        Write-Success "$image is installed"
    }

    Write-Step 'MEGALINT' "Running MegaLinter on src/ via mega-linter-runner (npx), container $containerName..."
    $runnerArgv = @('--yes', $RunnerPackage, '--no-prompt', '--remove-container')
    if (-not $skipPull) { $runnerArgv += '--nodockerpull' }
    # mega-linter-runner forwards every KEY=VALUE in a repo-root .env file into
    # the container. Running `just megalint` from inside the pixi shell puts a
    # Windows CONDA_PREFIX/VIRTUAL_ENV there, and pyo3's build script reads both
    # when deciding which interpreter to query, so RUST_CLIPPY died with
    # "failed to run the Python interpreter at D:\Intellicrack\.pixi\envs\default/bin/python".
    # PYO3_PYTHON takes precedence over both, and a bare command name resolves
    # through the container's PATH rather than pinning an image-specific path.
    if ($Flags -notmatch 'PYO3_PYTHON') {
        $runnerArgv += @('--env', 'PYO3_PYTHON=python3')
    }
    $runnerArgv += @('--path', '.') + $userArgs
    & npx @runnerArgv
    $exitCode = $LASTEXITCODE
} finally {
    Write-Step 'MEGALINT' 'Uninstalling the MegaLinter container and image...'
    if (Remove-MegaLinterContainer -Name $containerName) {
        Write-Success "No container named $containerName remains"
    } else {
        Write-Fail "Container $containerName could not be removed; check 'docker ps --all --filter name=$containerName'"
    }
    if ($keepImage) {
        Write-Skip "--keep-image was passed, so $image stays installed"
    } elseif (-not (Test-DockerImagePresent -Image $image)) {
        Write-Success "$image is not installed"
    } elseif (Remove-MegaLinterImage -Image $image) {
        Write-Success "$image has been uninstalled"
    } else {
        Write-Fail "$image is still installed; remove it with 'docker rmi --force $image'"
    }

    if ($originalEngine -eq 'windows') {
        Write-Step 'MEGALINT' 'Restoring Docker Desktop to Windows containers...'
        & $DockerCli -SwitchWindowsEngine
        if (Wait-DockerEngine -Target 'windows') {
            Write-Success 'Docker Desktop is back on Windows containers'
        } else {
            Write-Fail 'Docker Desktop did not report back to the Windows engine within 120s; check it manually'
        }
    }
}

Write-Footer 'MegaLinter' $started
if ($exitCode -eq 0) {
    Write-Success 'MegaLinter found no issues'
} else {
    Write-Progress "MegaLinter reported findings (exit $exitCode) -- see reports/megalinter/megalinter.log"
}
exit $exitCode
