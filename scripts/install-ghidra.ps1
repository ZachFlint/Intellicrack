$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Install-GitHubRelease `
    -Tag 'GHIDRA' `
    -Repo 'NationalSecurityAgency/ghidra' `
    -AssetPattern '\.zip$' `
    -AssetExclude 'DEV' `
    -DestName 'ghidra' `
    -VerifyFile 'ghidraRun.bat'
