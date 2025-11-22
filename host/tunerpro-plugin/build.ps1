[CmdletBinding()]
param(
    [string]$Config = "Release",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$Solution = Join-Path $PSScriptRoot "PicoROMTunerPro.sln"
if (-not (Test-Path $Solution)) {
    throw "Solution not found at $Solution"
}

$msbuild = Get-Command msbuild -ErrorAction Stop

if ($Clean) {
    & $msbuild.Path $Solution /t:Clean /p:Configuration=$Config /p:Platform=x64
}

& $msbuild.Path $Solution /p:Configuration=$Config /p:Platform=x64
