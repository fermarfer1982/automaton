[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtimeRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace '.runtime'))
$installRoot = [System.IO.Path]::GetFullPath((Join-Path $runtimeRoot 'node-v22.22.0-win-x64'))
$node = Join-Path $installRoot 'node.exe'
$corepack = Join-Path $installRoot 'corepack.cmd'
$expectedNodeSha256 = 'bae898add4643fcf890a83ad8ae56e20dce7e781cab161a53991ceba70c99ffb'

if (-not $installRoot.StartsWith(
    $runtimeRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw 'Portable Node path escaped the reviewed runtime directory.'
}
foreach ($requiredFile in @($node, $corepack)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Reviewed portable Node runtime is absent: $requiredFile"
    }
    $item = Get-Item -LiteralPath $requiredFile -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Portable Node runtime must not contain reparse-point executables: $requiredFile"
    }
}

$actualNodeSha256 = (Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualNodeSha256 -ne $expectedNodeSha256) {
    throw "Portable node.exe integrity check failed: $actualNodeSha256"
}
$version = (& $node --version).Trim()
if ($LASTEXITCODE -ne 0) { throw "Portable node.exe version check failed with exit code $LASTEXITCODE." }
$architecture = (& $node -p 'process.arch').Trim()
if ($LASTEXITCODE -ne 0) { throw "Portable node.exe architecture check failed with exit code $LASTEXITCODE." }
if ($version -ne 'v22.22.0' -or $architecture -ne 'x64') {
    throw "Reviewed Node v22.22.0 x64 is required; found $version $architecture."
}

[pscustomobject]@{
    Root = $installRoot
    Node = $node
    Corepack = $corepack
    Version = $version
    Architecture = $architecture
}
