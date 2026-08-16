[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [ValidateRange(1024, 65535)]
    [int] $ListenPort = 18765
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$effectiveSid = $effectiveIdentity.User.Value
if ($effectiveSid -ne $expectedGatewaySid) {
    throw "Wrong Gateway token SID. Expected $expectedGatewaySid; received $effectiveSid."
}
$principal = [System.Security.Principal.WindowsPrincipal]::new($effectiveIdentity)
if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Gateway health-only harness refuses an administrative token.'
}

$normalizedRunId = $RunId.ToLowerInvariant()
$workspace = 'C:\automaton'
$finalRoot = 'C:\automaton\.venv'
$pythonExecutable = 'C:\automaton\.venv\Scripts\python.exe'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$apiKeyPath = 'C:\ProgramData\AutomatonMT5Lab\ipc\automaton.key'
$operationalRoot = 'C:\ProgramData\AutomatonMT5Lab\operational'
$runtimeTemp = Join-Path $operationalRoot 'runtime-tmp'
$reportRoot = Join-Path $operationalRoot 'gateway-startup-results'
$reportPath = Join-Path $reportRoot "gateway-health-only-$normalizedRunId.json"
$listenAddress = '127.0.0.1'

function Get-CanonicalPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-ExactPath([string] $Path, [string] $Expected) {
    try {
        return (Get-CanonicalPath $Path).Equals(
            (Get-CanonicalPath $Expected),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    } catch { return $false }
}

function Assert-NoReparsePoint([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw "Expected directory: $Path" }
    if (-not $Directory -and $item.PSIsContainer) { throw "Expected file: $Path" }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Reparse point rejected: $Path"
    }
}

function Assert-PathConfined([string] $Path, [string] $Root) {
    $candidate = Get-CanonicalPath $Path
    $canonicalRoot = Get-CanonicalPath $Root
    if (-not (
        $candidate.Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($canonicalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
    )) {
        throw "Path escapes authorized root: $candidate"
    }
}

function Get-TextSha256([string] $Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($hash.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $hash.Dispose() }
}

function Get-FinalRuntimeFingerprint {
    if (-not (Test-ExactPath $finalRoot 'C:\automaton\.venv')) {
        throw 'FINAL_PATH_EXACT=FAIL'
    }
    Assert-NoReparsePoint $finalRoot $true
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue((Get-CanonicalPath $finalRoot))
    $contentRecords = [System.Collections.Generic.List[string]]::new()
    $aclRecords = [System.Collections.Generic.List[string]]::new()
    $itemCount = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        Assert-PathConfined $current $finalRoot
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        Assert-NoReparsePoint $item.FullName $item.PSIsContainer
        $canonicalItem = Get-CanonicalPath $item.FullName
        $relative = if ($canonicalItem.Equals(
            (Get-CanonicalPath $finalRoot),
            [System.StringComparison]::OrdinalIgnoreCase
        )) { '.' } else { $canonicalItem.Substring((Get-CanonicalPath $finalRoot).Length + 1) }
        $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor
            [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group
        $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $sddl = $security.GetSecurityDescriptorSddlForm($sections)
        $aclRecords.Add("$relative|$sddl")
        $itemCount++
        if ($item.PSIsContainer) {
            foreach ($child in [System.IO.Directory]::EnumerateFileSystemEntries($item.FullName)) {
                Assert-PathConfined $child $finalRoot
                $pending.Enqueue($child)
            }
        } else {
            $fileHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $contentRecords.Add("$relative|$($item.Length)|$fileHash")
        }
    }
    $contentRecords.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $aclRecords.Sort([System.StringComparer]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        item_count = $itemCount
        content_sha256 = Get-TextSha256 ($contentRecords -join "`n")
        acl_sha256 = Get-TextSha256 ($aclRecords -join "`n")
    }
}

function Assert-LoopbackPortAvailable([int] $Port) {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        $Port
    )
    try {
        $listener.Start()
    } catch {
        throw "Requested loopback port is unavailable: $Port"
    } finally {
        try { $listener.Stop() } catch {}
    }
}

function Write-ExclusiveJson([string] $Path, [object] $Value) {
    $json = $Value | ConvertTo-Json -Depth 10
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false)
        )
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

if (-not (Test-ExactPath $pythonExecutable 'C:\automaton\.venv\Scripts\python.exe')) {
    throw 'FINAL_PYTHON_EXACT=FAIL'
}
foreach ($requiredDirectory in @($workspace, $finalRoot, $operationalRoot, $runtimeTemp)) {
    Assert-NoReparsePoint $requiredDirectory $true
}
foreach ($requiredFile in @($pythonExecutable, $configPath, $apiKeyPath)) {
    Assert-NoReparsePoint $requiredFile $false
}
if (-not [System.IO.Directory]::Exists($reportRoot)) {
    [void][System.IO.Directory]::CreateDirectory($reportRoot)
}
Assert-NoReparsePoint $reportRoot $true
if ([System.IO.File]::Exists($reportPath) -or [System.IO.Directory]::Exists($reportPath)) {
    throw 'Gateway health-only report RunId collision. Use a new UUID.'
}

$configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
    throw 'TRADING_MODE_OBSERVE_ONLY=FAIL'
}
if ($configText -match '(?m)^\s*mt5_access_enabled\s*:\s*true\s*$') {
    throw 'MT5_ACCESS_ENABLED_FALSE=FAIL'
}
if ($configText -match '(?im)^\s*(password|passwd|credential|credentials|token|secret|private_key)\s*:') {
    throw 'Forbidden secret field exists in the protected trading config.'
}

$apiKey = [System.IO.File]::ReadAllText($apiKeyPath, [System.Text.Encoding]::ASCII)
if ($apiKey -ne $apiKey.Trim() -or $apiKey -notmatch '^[A-Za-z0-9_-]{43,128}$') {
    throw 'Protected Gateway API key format is invalid.'
}

Assert-LoopbackPortAvailable $ListenPort
$beforeFingerprint = Get-FinalRuntimeFingerprint
[void][System.Reflection.Assembly]::Load('System.Net.Http')

$process = $null
$gatewayProcessStarted = $false
$healthHttpStatus = 0
$healthPayloadValid = $false
$mt5PackageVersion = $null
$mt5Imported = $true
$mt5Accessed = $true
$orderCheckCalled = $true
$orderSendCalled = $true
$processStoppedCleanly = $false
$orphanProcesses = 1
$failureCode = $null

try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonExecutable
    $startInfo.Arguments = "-B -m trading_lab.service --config `"$configPath`" --port $ListenPort --controlled-stdin-shutdown"
    $startInfo.WorkingDirectory = $workspace
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['TRADING_MODE'] = 'OBSERVE_ONLY'
    $startInfo.EnvironmentVariables['MT5_ACCESS_ENABLED'] = 'false'
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $startInfo.EnvironmentVariables['TEMP'] = $runtimeTemp
    $startInfo.EnvironmentVariables['TMP'] = $runtimeTemp
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Gateway process did not start.' }
    $gatewayProcessStarted = $true

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $healthPayload = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) { break }
        $client = [System.Net.Http.HttpClient]::new()
        $request = $null
        try {
            $client.Timeout = [TimeSpan]::FromSeconds(3)
            $request = [System.Net.Http.HttpRequestMessage]::new(
                [System.Net.Http.HttpMethod]::Get,
                "http://$listenAddress`:$ListenPort/health"
            )
            try {
                [void]$request.Headers.TryAddWithoutValidation('X-AUTOMATON-KEY', $apiKey)
                $response = $client.SendAsync($request).GetAwaiter().GetResult()
                try {
                    $healthHttpStatus = [int]$response.StatusCode
                    if ($healthHttpStatus -eq 200) {
                        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                        $healthPayload = $body | ConvertFrom-Json
                        break
                    }
                } finally { $response.Dispose() }
            } finally { if ($null -ne $request) { $request.Dispose() } }
        } catch {
            Start-Sleep -Milliseconds 200
        } finally { $client.Dispose() }
    }

    if ($null -eq $healthPayload) { throw 'Gateway health endpoint did not become ready.' }
    $mt5PackageVersion = [string]$healthPayload.mt5_package_metadata_version
    $mt5Imported = [bool]$healthPayload.mt5_imported
    $mt5Accessed = [bool]$healthPayload.mt5_accessed
    $orderCheckCalled = [bool]$healthPayload.order_check_called
    $orderSendCalled = [bool]$healthPayload.order_send_called
    $healthPayloadValid =
        $healthPayload.gateway_status -eq 'UP' -and
        $healthPayload.trading_mode -eq 'OBSERVE_ONLY' -and
        -not [bool]$healthPayload.mt5_access_enabled -and
        $healthPayload.mt5_status -eq 'DISABLED_NOT_ACCESSED' -and
        $mt5PackageVersion -eq '5.0.6090' -and
        -not $mt5Imported -and -not $mt5Accessed -and
        -not $orderCheckCalled -and -not $orderSendCalled -and
        -not [bool]$healthPayload.automaton_started
    if (-not $healthPayloadValid) { throw 'Gateway health payload violated the disabled-MT5 contract.' }
} catch {
    $failureCode = 'GATEWAY_HEALTH_ONLY_VALIDATION_FAILED'
} finally {
    if ($null -ne $process -and $gatewayProcessStarted -and -not $process.HasExited) {
        try {
            $process.StandardInput.Write('Q')
            $process.StandardInput.Flush()
            $process.StandardInput.Close()
            $processStoppedCleanly = $process.WaitForExit(15000) -and $process.ExitCode -eq 0
        } catch { $processStoppedCleanly = $false }
        if (-not $process.HasExited) {
            try {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            } catch {}
        }
    } elseif ($null -ne $process -and $process.HasExited) {
        $processStoppedCleanly = $process.ExitCode -eq 0
    }
    if ($null -ne $process -and $gatewayProcessStarted) {
        $knownPid = $process.Id
        $orphanProcesses = if (Get-Process -Id $knownPid -ErrorAction SilentlyContinue) { 1 } else { 0 }
        $process.Dispose()
    }
}

$afterFingerprint = Get-FinalRuntimeFingerprint
$filesystemRuntimeModified = $beforeFingerprint.content_sha256 -ne $afterFingerprint.content_sha256
$aclModified = $beforeFingerprint.acl_sha256 -ne $afterFingerprint.acl_sha256
$passed =
    $gatewayProcessStarted -and $healthHttpStatus -eq 200 -and $healthPayloadValid -and
    -not $mt5Imported -and -not $mt5Accessed -and
    -not $orderCheckCalled -and -not $orderSendCalled -and
    $processStoppedCleanly -and $orphanProcesses -eq 0 -and
    -not $filesystemRuntimeModified -and -not $aclModified
if (-not $passed -and [string]::IsNullOrWhiteSpace($failureCode)) {
    $failureCode = 'GATEWAY_HEALTH_ONLY_BOUNDARY_FAILED'
}

$report = [ordered]@{
    schema_version = 1
    mode = 'GATEWAY_HEALTH_ONLY'
    run_id = $normalizedRunId
    effective_sid = $effectiveSid
    status = if ($passed) { 'PASS' } else { 'FAIL' }
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    failure_code = if ($passed) { $null } else { $failureCode }
    python_executable = $pythonExecutable
    listen_address = $listenAddress
    listen_port = $ListenPort
    trading_mode = 'OBSERVE_ONLY'
    mt5_access_enabled = $false
    gateway_process_started = $gatewayProcessStarted
    health_http_status = $healthHttpStatus
    health_payload_valid = $healthPayloadValid
    mt5_package_metadata_version = $mt5PackageVersion
    mt5_imported = $mt5Imported
    mt5_accessed = $mt5Accessed
    order_check_called = $orderCheckCalled
    order_send_called = $orderSendCalled
    automaton_started = $false
    process_stopped_cleanly = $processStoppedCleanly
    orphan_processes = $orphanProcesses
    filesystem_runtime_modified = $filesystemRuntimeModified
    acl_modified = $aclModified
    final_runtime_item_count = $afterFingerprint.item_count
}
Write-ExclusiveJson $reportPath $report

Write-Output "MODE=GATEWAY_HEALTH_ONLY"
Write-Output "STATUS=$($report.status)"
Write-Output "LISTEN_ADDRESS=$listenAddress"
Write-Output "TRADING_MODE=OBSERVE_ONLY"
Write-Output "MT5_ACCESS_ENABLED=false"
Write-Output "MT5_IMPORTED=$($mt5Imported.ToString().ToLowerInvariant())"
Write-Output "MT5_ACCESSED=$($mt5Accessed.ToString().ToLowerInvariant())"
Write-Output "ORDER_CHECK=$($orderCheckCalled.ToString().ToLowerInvariant())"
Write-Output "ORDER_SEND=$($orderSendCalled.ToString().ToLowerInvariant())"
Write-Output "PROCESS_STOPPED_CLEANLY=$($processStoppedCleanly.ToString().ToLowerInvariant())"
Write-Output "ORPHAN_PROCESSES=$orphanProcesses"
Write-Output "REPORT=$reportPath"
if (-not $passed) { exit 1 }
