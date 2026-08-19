[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AutomatonStateDir,
    [string] $PidFile
)

$ErrorActionPreference = 'Stop'

$workspace = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..')
)

$nodeRuntime = & (
    Join-Path $PSScriptRoot 'Resolve-TradingLabNode.ps1'
)

$observationApiKeyFile = (
    'C:\ProgramData\AutomatonMT5Lab\ipc\observation.key'
)

$researchApiKeyFile = (
    'C:\ProgramData\AutomatonMT5Lab\ipc\research.key'
)

if (-not $PidFile) {
    $PidFile = Join-Path $AutomatonStateDir 'automaton.pid'
}

if (
    -not $env:AUTOMATON_LAB_PROVIDER -or
    -not $env:AUTOMATON_LAB_MODEL
) {
    throw (
        'Set an explicit provider and model ' +
        'in this dedicated user environment.'
    )
}

if (
    Test-Path `
        -LiteralPath (
            Join-Path $workspace 'dist\index.js'
        )
) {
    # Reviewed build exists.
}
else {
    throw 'Human-reviewed Automaton build is absent.'
}

if (Test-Path -LiteralPath $PidFile) {
    throw (
        'Automaton PID file already exists; ' +
        'run status/stop first.'
    )
}

if (
    Test-Path `
        Env:AUTOMATON_MT5_API_KEY_FILE
) {
    throw (
        'Gateway API key environment variable must be absent ' +
        'from the AutomatonAgent runtime.'
    )
}

$env:AUTOMATON_RUNTIME_PROFILE = 'trading_lab'

$env:AUTOMATON_STATE_DIR = (
    [System.IO.Path]::GetFullPath(
        $AutomatonStateDir
    )
)

$env:AUTOMATON_MT5_OBSERVATION_API_KEY_FILE = (
    $observationApiKeyFile
)

$env:AUTOMATON_MT5_RESEARCH_API_KEY_FILE = (
    $researchApiKeyFile
)

$process = Start-Process `
    -FilePath $nodeRuntime.Node `
    -WorkingDirectory $workspace `
    -WindowStyle Hidden `
    -PassThru `
    -ArgumentList @(
        'dist/index.js',
        '--run'
    )

[System.IO.File]::WriteAllText(
    $PidFile,
    $process.Id.ToString(),
    [System.Text.Encoding]::ASCII
)

Write-Host (
    "Automaton started in trading_lab profile " +
    "(PID $($process.Id))."
)
