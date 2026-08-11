[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $ReadinessOutput = 'C:\ProgramData\AutomatonMT5Lab\control\readiness.json'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
$pnpmVersion = (& pnpm --version).Trim()
if ($pnpmVersion -ne '10.28.1') { throw "Reviewed pnpm 10.28.1 is required; found $pnpmVersion." }
Push-Location $workspace
try {
    & $python -m pytest -q
    pnpm typecheck
    pnpm build
    pnpm test
    & $python -m trading_lab.readiness --config $Config --output $ReadinessOutput
} finally { Pop-Location }
