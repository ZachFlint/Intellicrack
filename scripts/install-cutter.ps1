$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Install-GitHubRelease `
    -Tag 'CUTTER' `
    -Repo 'rizinorg/cutter' `
    -AssetPattern 'Windows.*x64.*\.zip$|win64.*\.zip$|Windows.*\.zip$' `
    -DestName 'cutter' `
    -VerifyFile 'Cutter.exe' `
    -AlternateVerifyFiles @('cutter.exe') `
    -SearchPath 'tools\cutter'
