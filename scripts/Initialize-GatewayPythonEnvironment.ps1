Set-StrictMode -Version 2.0

function Initialize-GatewayPythonEnvironment {
    $expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne $expectedGatewaySid) {
        throw 'Gateway Python environment requires the exact AutomatonGateway SID.'
    }
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Gateway Python environment refuses an administrative token.'
    }

    $operationalRoot = [System.IO.Path]::GetFullPath(
        'C:\ProgramData\AutomatonMT5Lab\operational'
    ).TrimEnd('\')
    $runtimeTempBase = Join-Path $operationalRoot 'runtime-tmp'
    $runtimeTempPath = Join-Path $runtimeTempBase 'gateway-service'
    $canonicalTemp = [System.IO.Path]::GetFullPath($runtimeTempPath).TrimEnd('\')
    if (-not $canonicalTemp.StartsWith(
        $operationalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Gateway runtime TEMP escapes the operational domain.'
    }
    foreach ($path in @($operationalRoot, $runtimeTempBase, $runtimeTempPath)) {
        if ([System.IO.File]::Exists($path)) {
            throw "Gateway runtime TEMP component is a file: $path"
        }
        if (-not [System.IO.Directory]::Exists($path)) {
            [void][System.IO.Directory]::CreateDirectory($path)
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Gateway runtime TEMP component is invalid or a reparse point: $path"
        }
    }
    foreach ($item in Get-ChildItem -LiteralPath $runtimeTempPath -Force -Recurse -ErrorAction Stop) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Gateway runtime TEMP contains a reparse point: $($item.FullName)"
        }
    }

    $env:TEMP = $canonicalTemp
    $env:TMP = $canonicalTemp
    $env:PYTHONDONTWRITEBYTECODE = '1'
    if (([System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')) -ne $canonicalTemp) {
        throw 'Gateway process did not adopt its private operational TEMP.'
    }
    $canary = Join-Path $canonicalTemp '.gateway-runtime-temp.canary'
    $stream = [System.IO.File]::Open(
        $canary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try { $stream.WriteByte(1); $stream.Flush() } finally { $stream.Dispose() }
    [System.IO.File]::Delete($canary)
    if ([System.IO.File]::Exists($canary)) {
        throw 'Gateway operational TEMP canary cleanup failed.'
    }
}
