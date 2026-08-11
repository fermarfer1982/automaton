[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $ReadinessOutput = 'C:\ProgramData\AutomatonMT5Lab\control\readiness.json'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
$nodeVersionText = (& node -p "process.versions.node").Trim()
$nodeVersion = [version]$nodeVersionText
$nodeSupported = (
    ($nodeVersion.Major -eq 20 -and $nodeVersion -ge [version]'20.18.0') -or
    $nodeVersion.Major -eq 22
)
if (-not $nodeSupported) {
    throw "Reviewed Node 20.18+ or Node 22 is required; found $nodeVersionText."
}
$pnpmVersion = (& corepack pnpm@10.28.1 --version).Trim()
if ($pnpmVersion -ne '10.28.1') { throw "Reviewed pnpm 10.28.1 is required; found $pnpmVersion." }
Push-Location $workspace
try {
    & $python -m pytest -q
    corepack pnpm@10.28.1 typecheck
    corepack pnpm@10.28.1 build
    corepack pnpm@10.28.1 test
    & $python -m trading_lab.readiness --config $Config --output $ReadinessOutput
} finally { Pop-Location }
