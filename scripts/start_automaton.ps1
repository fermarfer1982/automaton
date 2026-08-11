[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AutomatonStateDir,
    [string] $ApiKeyFile = 'C:\ProgramData\AutomatonMT5Lab\ipc\automaton.key',
    [string] $PidFile
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $PidFile) { $PidFile = Join-Path $AutomatonStateDir 'automaton.pid' }
if (-not $env:AUTOMATON_LAB_PROVIDER -or -not $env:AUTOMATON_LAB_MODEL) {
    throw 'Set an explicit provider and model in this dedicated user environment.'
}
if (-not (Test-Path -LiteralPath (Join-Path $workspace 'dist\index.js'))) {
    throw 'Human-reviewed Automaton build is absent.'
}
if (Test-Path -LiteralPath $PidFile) { throw 'Automaton PID file already exists; run status/stop first.' }
$env:AUTOMATON_RUNTIME_PROFILE = 'trading_lab'
$env:AUTOMATON_STATE_DIR = [System.IO.Path]::GetFullPath($AutomatonStateDir)
$env:AUTOMATON_MT5_API_KEY_FILE = [System.IO.Path]::GetFullPath($ApiKeyFile)
$process = Start-Process -FilePath 'node.exe' -WorkingDirectory $workspace -WindowStyle Hidden -PassThru `
    -ArgumentList @('dist/index.js', '--run')
[System.IO.File]::WriteAllText($PidFile, $process.Id.ToString(), [System.Text.Encoding]::ASCII)
Write-Host "Automaton started in trading_lab profile (PID $($process.Id))."
