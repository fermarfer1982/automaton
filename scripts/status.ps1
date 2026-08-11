[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $Output = 'C:\ProgramData\AutomatonMT5Lab\control\readiness.json'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
& $python -m trading_lab.readiness --config $Config --output $Output
if ($LASTEXITCODE -ne 0) { throw "Readiness failed with exit code $LASTEXITCODE." }
