$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Install-GitHubRelease `
    -Tag 'RADARE2' `
    -Repo 'radareorg/radare2' `
    -AssetPattern 'w64\.zip$|windows.*\.zip$' `
    -DestName 'radare2' `
    -VerifyFile 'radare2.exe' `
    -AlternateVerifyFiles @('r2.exe')
