[CmdletBinding()]
param(
    [string]$Config = "Release",
    [string]$Generator = "",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$SourceDir = $PSScriptRoot
$BuildDir = Join-Path $SourceDir "build"

if ($Clean -and (Test-Path $BuildDir)) {
    Remove-Item -Path $BuildDir -Recurse -Force
}

if (-not (Test-Path $BuildDir)) {
    New-Item -Path $BuildDir -ItemType Directory | Out-Null
}

$cmakeArgs = @('-S', $SourceDir, '-B', $BuildDir)

if ($Generator) {
    $cmakeArgs += @('-G', $Generator)
    if ($Generator -like 'Visual Studio*') {
        $cmakeArgs += @('-A', 'x64')
    }
} else {
    $cmakeArgs += @('-A', 'x64')
}

cmake @cmakeArgs
cmake --build $BuildDir --config $Config
