[CmdletBinding()]
param([string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml')
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
& $python -m trading_lab.operator --config $Config emergency-stop
