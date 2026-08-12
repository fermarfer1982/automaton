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
if ($Apply -and -not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw 'Copy and human-review trading.yaml in the protected control directory before ACL application.'
}
& (Join-Path $PSScriptRoot 'Initialize-TradingLabAcl.ps1') `
    -GatewayIdentity $GatewayIdentity `
    -AutomatonIdentity $AutomatonIdentity `
    -AutomatonStateDir $AutomatonStateDir `
    -WorkspaceRoot $workspace `
    -Apply:$Apply
if (-not $Apply) { exit 0 }
if ($InstallDependencies) {
    $nodeRuntime = & (Join-Path $PSScriptRoot 'Resolve-TradingLabNode.ps1')
    $machinePython = 'C:\Program Files\AutomatonPython\3.14.5\python.exe'
    if (-not (Test-Path -LiteralPath $machinePython -PathType Leaf)) {
        throw 'Managed machine-wide Python is absent; run Install-TradingLabPythonRuntime.ps1 through its separate human gate.'
    }
    $pythonRuntime = (& $machinePython -I -c "import platform,sys; print(f'{platform.python_version()}|{platform.architecture()[0]}|{sys.base_prefix}')").Trim()
    if ($LASTEXITCODE -ne 0) { throw "Python runtime check failed with exit code $LASTEXITCODE." }
    if ($pythonRuntime -ne '3.14.5|64bit|C:\Program Files\AutomatonPython\3.14.5') {
        throw "Reviewed machine-wide CPython 3.14.5 x64 is required; found $pythonRuntime."
    }
    $pnpmVersion = (& $nodeRuntime.Corepack pnpm@10.28.1 --version).Trim()
    if ($LASTEXITCODE -ne 0) { throw "pnpm runtime check failed with exit code $LASTEXITCODE." }
    if ($pnpmVersion -ne '10.28.1') {
        throw "Reviewed pnpm 10.28.1 is required; found $pnpmVersion."
    }
    $venv = Join-Path $workspace '.venv'
    if (-not (Test-Path -LiteralPath $venv)) {
        & $machinePython -I -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed with exit code $LASTEXITCODE." }
    }
    $venvBase = (& (Join-Path $venv 'Scripts\python.exe') -I -c 'import sys;print(sys.base_prefix)').Trim()
    if ($LASTEXITCODE -ne 0 -or $venvBase -ne 'C:\Program Files\AutomatonPython\3.14.5') {
        throw 'Existing .venv does not reference the managed machine-wide Python; use the dedicated rebuild gate.'
    }
    & (Join-Path $venv 'Scripts\python.exe') -m pip install `
        --require-hashes -r (Join-Path $workspace 'requirements-gateway-win-py314.lock')
    if ($LASTEXITCODE -ne 0) { throw "Hash-locked Python install failed with exit code $LASTEXITCODE." }
    Push-Location $workspace
    $previousPath = $env:Path
    try {
        $env:Path = $nodeRuntime.Root + [System.IO.Path]::PathSeparator + $previousPath
        & $nodeRuntime.Corepack pnpm@10.28.1 install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "Frozen pnpm install failed with exit code $LASTEXITCODE." }
    } finally {
        $env:Path = $previousPath
        Pop-Location
    }
}
Write-Host 'Setup applied. DEMO_EXECUTION remains disabled.'
