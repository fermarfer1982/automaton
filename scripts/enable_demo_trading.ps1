[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $Readiness = 'C:\ProgramData\AutomatonMT5Lab\control\readiness.json',
    [switch] $Apply,
    [switch] $ClearKillSwitch
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
$arguments = @('-m', 'trading_lab.operator', '--config', $Config, 'enable-demo', '--readiness', $Readiness)
if ($Apply) { $arguments += '--apply' }
if ($ClearKillSwitch) { $arguments += '--clear-kill-switch' }
& $python @arguments
