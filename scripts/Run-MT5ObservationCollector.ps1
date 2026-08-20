param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$RunId,

    [ValidateRange(1024, 65535)]
    [int]$Port = 8766,

    [ValidateRange(1, 60)]
    [int]$CollectorIntervalSeconds = 10
)

$ErrorActionPreference = 'Stop'

$Workspace = 'C:\automaton'
$Python = 'C:\automaton\.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Python not found: $Python"
}

Set-Location -LiteralPath $Workspace

$env:TRADING_MODE = 'OBSERVE_ONLY'
$env:MT5_ACCESS_ENABLED = 'false'
$env:MT5_READ_ONLY_DATA_ACCESS = 'true'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'
$env:PYTHONPATH = $Workspace

& $Python `
    -B `
    -m trading_lab.observation_service `
    --run-id $RunId `
    --port $Port `
    --collect-market-experiences `
    --collector-interval-seconds $CollectorIntervalSeconds

exit $LASTEXITCODE
