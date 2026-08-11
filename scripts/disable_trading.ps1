[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [switch] $Apply
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
$arguments = @('-m', 'trading_lab.operator', '--config', $Config, 'disable')
if ($Apply) { $arguments += '--apply' }
& $python @arguments
