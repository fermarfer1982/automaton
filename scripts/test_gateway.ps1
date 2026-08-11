[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $ReadinessOutput = 'C:\ProgramData\AutomatonMT5Lab\control\readiness.json'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
$nodeRuntime = & (Join-Path $PSScriptRoot 'Resolve-TradingLabNode.ps1')
$pnpmVersion = (& $nodeRuntime.Corepack pnpm@10.28.1 --version).Trim()
if ($LASTEXITCODE -ne 0) { throw "pnpm runtime check failed with exit code $LASTEXITCODE." }
if ($pnpmVersion -ne '10.28.1') { throw "Reviewed pnpm 10.28.1 is required; found $pnpmVersion." }
Push-Location $workspace
$previousPath = $env:Path
try {
    $env:Path = $nodeRuntime.Root + [System.IO.Path]::PathSeparator + $previousPath
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "pytest failed with exit code $LASTEXITCODE." }
    & $nodeRuntime.Corepack pnpm@10.28.1 typecheck
    if ($LASTEXITCODE -ne 0) { throw "Typecheck failed with exit code $LASTEXITCODE." }
    & $nodeRuntime.Corepack pnpm@10.28.1 build
    if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
    & $nodeRuntime.Corepack pnpm@10.28.1 test
    if ($LASTEXITCODE -ne 0) { throw "Vitest failed with exit code $LASTEXITCODE." }
    & $python -m trading_lab.readiness --config $Config --output $ReadinessOutput
    if ($LASTEXITCODE -ne 0) { throw "Readiness failed with exit code $LASTEXITCODE." }
} finally {
    $env:Path = $previousPath
    Pop-Location
}
