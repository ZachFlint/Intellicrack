$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Install-GitHubRelease `
    -Tag 'X64DBG' `
    -Repo 'x64dbg/x64dbg' `
    -AssetPattern 'snapshot.*\.zip$' `
    -AssetExclude 'pdb' `
    -DestName 'x64dbg' `
    -VerifyFile 'x64dbg.exe' `
    -AlternateVerifyFiles @('x96dbg.exe', 'x32dbg.exe') `
    -SearchPath 'tools\x64dbg' `
    -DirectExtract
