[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $GatewayIdentity,
    [Parameter(Mandatory = $true)] [string] $AutomatonIdentity,
    [Parameter(Mandatory = $true)] [string] $AutomatonStateDir,
    [string] $Config = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml',
    [switch] $Apply,
    [switch] $InstallDependencies
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$plan = [pscustomobject]@{
    apply = [bool]$Apply
    install_dependencies = [bool]$InstallDependencies
    config = [System.IO.Path]::GetFullPath($Config)
    workspace = $workspace
    creates_users = $false
    captures_passwords = $false
}
$plan | ConvertTo-Json
& (Join-Path $PSScriptRoot 'Initialize-TradingLabAcl.ps1') `
    -GatewayIdentity $GatewayIdentity `
    -AutomatonIdentity $AutomatonIdentity `
    -AutomatonStateDir $AutomatonStateDir `
    -WorkspaceRoot $workspace `
    -Apply:$Apply
if (-not $Apply) { exit 0 }
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw 'Copy and human-review trading.yaml in the protected control directory first.'
}
if ($InstallDependencies) {
    $pnpmVersion = (& pnpm --version).Trim()
    if ($pnpmVersion -ne '10.28.1') {
        throw "Reviewed pnpm 10.28.1 is required; found $pnpmVersion."
    }
    $venv = Join-Path $workspace '.venv'
    if (-not (Test-Path -LiteralPath $venv)) { python -m venv $venv }
    & (Join-Path $venv 'Scripts\python.exe') -m pip install `
        --require-hashes -r (Join-Path $workspace 'requirements-gateway-win-py314.lock')
    Push-Location $workspace
    try { pnpm install --frozen-lockfile } finally { Pop-Location }
}
Write-Host 'Setup applied. DEMO_EXECUTION remains disabled.'
