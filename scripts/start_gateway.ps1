[CmdletBinding()]
param(
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [string] $PidFile = 'C:\ProgramData\AutomatonMT5Lab\data\gateway.pid'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$python = Join-Path $workspace '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Reviewed .venv is absent.' }
& $python -m trading_lab.operator --config $Config verify-gateway
if (Test-Path -LiteralPath $PidFile) { throw 'Gateway PID file already exists; run status/stop first.' }
$process = Start-Process -FilePath $python -WorkingDirectory $workspace -WindowStyle Hidden -PassThru `
    -ArgumentList @('-m', 'trading_lab.service', '--config', $Config)
[System.IO.File]::WriteAllText($PidFile, $process.Id.ToString(), [System.Text.Encoding]::ASCII)
Write-Host "Gateway started as the current dedicated identity (PID $($process.Id))."
