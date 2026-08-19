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

$normalizedRunId = $RunId.ToLowerInvariant()
$expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$workspace = 'C:\automaton'
$finalRoot = 'C:\automaton\.venv'
$pythonExecutable = 'C:\automaton\.venv\Scripts\python.exe'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$apiKeyPath = 'C:\ProgramData\AutomatonMT5Lab\ipc\automaton.key'
$researchKeyPath = 'C:\ProgramData\AutomatonMT5Lab\ipc\research.key'
$operationalRoot = 'C:\ProgramData\AutomatonMT5Lab\operational'
$runtimeTemp = Join-Path $operationalRoot 'runtime-tmp'
$reportRoot = Join-Path $operationalRoot 'gateway-startup-results'
$reportPath = Join-Path $reportRoot "gateway-health-only-$normalizedRunId.json"
$listenAddress = '127.0.0.1'

# Initialize the durable failure envelope before any identity, filesystem,
# socket, configuration, Python, or process operation.
$report = [ordered]@{
    schema_version = 2
    mode = 'GATEWAY_HEALTH_ONLY'
    run_id = $normalizedRunId
    effective_sid = $null
    status = 'FAIL_INITIALIZING'
    completed_at_utc = $null
    failure_code = $null
    failure_stage = 'INITIALIZING'
    runtime_error = $null
    python_executable = $pythonExecutable
    listen_address = $listenAddress
    listen_port = $ListenPort
    trading_mode = 'OBSERVE_ONLY'
    mt5_access_enabled = $false
    automaton_key_validated = $false
    research_key_validated = $false
    gateway_process_started = $false
    gateway_process_exit_observed = $false
    gateway_process_exit_code = $null
    gateway_exit_before_health = $false
    gateway_stdout_captured = $false
    gateway_stderr_captured = $false
    gateway_stdout_sanitized = $null
    gateway_stderr_sanitized = $null
    gateway_stream_capture_error = $null
    health_http_status = 0
    health_payload_valid = $false
    mt5_package_metadata_version = $null
    mt5_imported = $false
    mt5_accessed = $false
    order_check_called = $false
    order_send_called = $false
    automaton_started = $false
    cleanup_attempted = $false
    shutdown_requested = $false
    forced_termination_used = $false
    cleanup_error = $null
    process_stopped_cleanly = $false
    orphan_processes = 0
    runtime_fingerprint_verified = $false
    filesystem_runtime_modified = $false
    acl_modified = $false
    final_runtime_item_count = 0
}

$effectiveSid = $null
$apiKey = $null
$researchKey = $null
$sensitiveValues = @()
$process = $null
$stdoutReadTask = $null
$stderrReadTask = $null
$gatewayProcessStarted = $false
$gatewayProcessExitObserved = $false
$gatewayProcessExitCode = $null
$gatewayExitBeforeHealth = $false
$gatewayStdoutCaptured = $false
$gatewayStderrCaptured = $false
$gatewayStdoutSanitized = $null
$gatewayStderrSanitized = $null
$gatewayStreamCaptureError = $null
$healthHttpStatus = 0
$healthPayloadValid = $false
$mt5PackageVersion = $null
$mt5Imported = $false
$mt5Accessed = $false
$orderCheckCalled = $false
$orderSendCalled = $false
$cleanupAttempted = $false
$shutdownRequested = $false
$forcedTerminationUsed = $false
$cleanupError = $null
$processStoppedCleanly = $false
$orphanProcesses = 0
$beforeFingerprint = $null
$afterFingerprint = $null
$runtimeFingerprintVerified = $false
$filesystemRuntimeModified = $false
$aclModified = $false
$runtimeSucceeded = $false
$runtimeError = $null
$failureCode = $null
$failureStage = 'INITIALIZING'
$stage = 'INITIALIZING'
$reportWritten = $false
$reportWriteError = $null

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

function Get-SanitizedRuntimeError([object] $ErrorRecord, [string[]] $SensitiveValues) {
    $message = $null
    try { $message = [string]$ErrorRecord.Exception.Message } catch {}
    if ([string]::IsNullOrWhiteSpace($message)) { $message = 'Unspecified harness failure.' }
    foreach ($sensitiveValue in @($SensitiveValues)) {
        if (-not [string]::IsNullOrEmpty($sensitiveValue)) {
            $message = $message.Replace($sensitiveValue, '[REDACTED]')
        }
    }
    $message = $message -replace '(?i)\b(password|passwd|api[_-]?key|ipc[_-]?key|credential|credentials|login|server|account)\b\s*[:=]\s*[^\s;,]+', '${1}=[REDACTED]'
    $message = ($message -replace '[\r\n\t]+', ' ').Trim()
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    return $message
}

function Get-SanitizedBoundedProcessText(
    [AllowNull()][string] $Text,
    [AllowNull()][string[]] $SensitiveValues,
    [int] $MaximumUtf8Bytes = 8192
) {
    if ($MaximumUtf8Bytes -lt 64) { throw 'Process stream byte limit is too small.' }
    if ($null -eq $Text) { return '' }
    $sanitized = $Text
    foreach ($sensitiveValue in @($SensitiveValues)) {
        if (-not [string]::IsNullOrEmpty($sensitiveValue)) {
            $sanitized = $sanitized.Replace($sensitiveValue, '[REDACTED]')
        }
    }
    $secretAssignmentPattern = @'
(?im)["']?(X-AUTOMATON-KEY|X-AUTOMATON-RESEARCH-KEY|api[\s_-]?key|ipc[\s_-]?key|mt5[\s_-]?password|password|passwd|credential|credentials|client[\s_-]?secret|private[\s_-]?key|secret|access[\s_-]?token|refresh[\s_-]?token|token|mt5[\s_-]?login|login|authorized[\s_-]?account|account|server)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}\r\n]+)
'@.Trim()
    $sanitized = [regex]::Replace(
        $sanitized,
        $secretAssignmentPattern,
        '$1=[REDACTED]'
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    if ($encoding.GetByteCount($sanitized) -le $MaximumUtf8Bytes) {
        return $sanitized
    }
    $marker = '...[TRUNCATED]'
    $payloadLimit = $MaximumUtf8Bytes - $encoding.GetByteCount($marker)
    $low = 0
    $high = [Math]::Min($sanitized.Length, $payloadLimit)
    while ($low -lt $high) {
        $middle = [int][Math]::Ceiling(($low + $high) / 2.0)
        if ($encoding.GetByteCount($sanitized.Substring(0, $middle)) -le $payloadLimit) {
            $low = $middle
        } else {
            $high = $middle - 1
        }
    }
    if ($low -gt 0 -and [char]::IsHighSurrogate($sanitized[$low - 1])) {
        $low--
    }
    return $sanitized.Substring(0, $low) + $marker
}

function Receive-GatewayStreamCapture(
    [AllowNull()][object] $ReadTask,
    [AllowNull()][string[]] $SensitiveValues,
    [int] $TimeoutMilliseconds = 5000
) {
    if ($null -eq $ReadTask) {
        return [pscustomobject]@{
            captured = $false
            sanitized = $null
            error = 'Asynchronous stream reader was not initialized.'
        }
    }
    try {
        if (-not $ReadTask.Wait($TimeoutMilliseconds)) {
            return [pscustomobject]@{
                captured = $false
                sanitized = $null
                error = 'Asynchronous stream capture timed out.'
            }
        }
        return [pscustomobject]@{
            captured = $true
            sanitized = Get-SanitizedBoundedProcessText `
                ([string]$ReadTask.Result) $SensitiveValues 8192
            error = $null
        }
    } catch {
        return [pscustomobject]@{
            captured = $false
            sanitized = $null
            error = Get-SanitizedRuntimeError $_ $SensitiveValues
        }
    }
}

function Resolve-GatewayEarlyExit(
    [bool] $HasExited,
    [bool] $HealthObserved,
    [int] $ExitCode
) {
    $earlyExit = $HasExited -and -not $HealthObserved
    return [pscustomobject]@{
        early_exit = $earlyExit
        status = if ($earlyExit) { 'FAIL' } else { $null }
        failure_stage = if ($earlyExit) { 'GATEWAY_PROCESS_EARLY_EXIT' } else { $null }
        failure_code = if ($earlyExit) {
            'GATEWAY_HEALTH_ONLY_PROCESS_EARLY_EXIT'
        } else { $null }
        exit_observed = $HasExited
        exit_code = if ($HasExited) { $ExitCode } else { $null }
    }
}

# BEGIN_RUNTIME_GUARD: every potentially failing runtime operation is enclosed.
try {
    $stage = 'IDENTITY'
    $effectiveIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $effectiveSid = $effectiveIdentity.User.Value
    $report.effective_sid = $effectiveSid
    if ($effectiveSid -ne $expectedGatewaySid) {
        throw "Wrong Gateway token SID. Expected $expectedGatewaySid; received $effectiveSid."
    }
    $principal = [System.Security.Principal.WindowsPrincipal]::new($effectiveIdentity)
    if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Gateway health-only harness refuses an administrative token.'
    }

    $stage = 'PATH_PREFLIGHT'
    if (-not (Test-ExactPath $pythonExecutable 'C:\automaton\.venv\Scripts\python.exe')) {
        throw 'FINAL_PYTHON_EXACT=FAIL'
    }
    foreach ($requiredDirectory in @($workspace, $finalRoot, $operationalRoot, $runtimeTemp)) {
        Assert-NoReparsePoint $requiredDirectory $true
    }
    foreach ($requiredFile in @($pythonExecutable, $configPath, $apiKeyPath, $researchKeyPath)) {
        Assert-NoReparsePoint $requiredFile $false
    }
    if (-not [System.IO.Directory]::Exists($reportRoot)) {
        [void][System.IO.Directory]::CreateDirectory($reportRoot)
    }
    Assert-NoReparsePoint $reportRoot $true
    if ([System.IO.File]::Exists($reportPath) -or [System.IO.Directory]::Exists($reportPath)) {
        throw 'Gateway health-only report RunId collision. Use a new UUID.'
    }

    $stage = 'CONFIG_PREFLIGHT'
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

    $stage = 'IPC_KEY_PREFLIGHT'
    $apiKey = [System.IO.File]::ReadAllText($apiKeyPath, [System.Text.Encoding]::ASCII)
    $sensitiveValues = @($apiKey)
    if ($apiKey -ne $apiKey.Trim() -or $apiKey -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'Protected Gateway API key format is invalid.'
    }
    $report.automaton_key_validated = $true
    $researchKey = [System.IO.File]::ReadAllText($researchKeyPath, [System.Text.Encoding]::ASCII)
    $sensitiveValues = @($apiKey, $researchKey)
    if ($researchKey -ne $researchKey.Trim() -or $researchKey -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'Protected Gateway research key format is invalid.'
    }
    $report.research_key_validated = $true

    $stage = 'PORT_PREFLIGHT'
    Assert-LoopbackPortAvailable $ListenPort

    $stage = 'RUNTIME_FINGERPRINT_BEFORE'
    $beforeFingerprint = Get-FinalRuntimeFingerprint

    $stage = 'STARTUP'
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
    $stdoutReadTask = $process.StandardOutput.ReadToEndAsync()
    $stderrReadTask = $process.StandardError.ReadToEndAsync()

    $stage = 'HEALTH_GET'
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $healthPayload = $null
    $lastHealthError = $null
    $healthUri = "http://127.0.0.1`:$ListenPort/health"
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            $earlyExit = Resolve-GatewayEarlyExit $true $false $process.ExitCode
            $gatewayExitBeforeHealth = $earlyExit.early_exit
            $gatewayProcessExitObserved = $earlyExit.exit_observed
            $gatewayProcessExitCode = $earlyExit.exit_code
            $stage = $earlyExit.failure_stage
            $failureCode = $earlyExit.failure_code
            throw "Gateway process exited before health with exit code $gatewayProcessExitCode."
        }
        try {
            $response = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $healthUri `
                -Headers @{ 'X-AUTOMATON-KEY' = $apiKey } `
                -TimeoutSec 3 `
                -ErrorAction Stop
            $healthHttpStatus = [int]$response.StatusCode
            if ($healthHttpStatus -eq 200) {
                $healthPayload = $response.Content | ConvertFrom-Json
                break
            }
        } catch {
            $lastHealthError = Get-SanitizedRuntimeError $_ $sensitiveValues
            if ($process.HasExited) {
                $earlyExit = Resolve-GatewayEarlyExit $true $false $process.ExitCode
                $gatewayExitBeforeHealth = $earlyExit.early_exit
                $gatewayProcessExitObserved = $earlyExit.exit_observed
                $gatewayProcessExitCode = $earlyExit.exit_code
                $stage = $earlyExit.failure_stage
                $failureCode = $earlyExit.failure_code
                throw "Gateway process exited before health with exit code $gatewayProcessExitCode."
            }
            Start-Sleep -Milliseconds 200
        }
    }

    if ($null -eq $healthPayload) {
        $detail = if ([string]::IsNullOrWhiteSpace($lastHealthError)) {
            'no HTTP response was received'
        } else { $lastHealthError }
        throw "Gateway health endpoint did not become ready: $detail"
    }
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
    if (-not $healthPayloadValid) {
        throw 'Gateway health payload violated the disabled-MT5 contract.'
    }
    $runtimeSucceeded = $true
} catch {
    $failureStage = $stage
    if ([string]::IsNullOrWhiteSpace($failureCode)) {
        $failureCode = "GATEWAY_HEALTH_ONLY_$($stage)_FAILED"
    }
    $runtimeError = Get-SanitizedRuntimeError $_ $sensitiveValues
} finally {
    # BEGIN_DURABLE_REPORT_FINALLY: only the exact process object created above
    # can be signalled or terminated here.
    if ($null -ne $process -and $gatewayProcessStarted) {
        $cleanupAttempted = $true
        try {
            $knownPid = $process.Id
            if (-not $process.HasExited) {
                $shutdownRequested = $true
                try {
                    $process.StandardInput.Write('Q')
                    $process.StandardInput.Flush()
                    $process.StandardInput.Close()
                    $processStoppedCleanly =
                        $process.WaitForExit(15000) -and $process.ExitCode -eq 0
                    if (-not $processStoppedCleanly) {
                        throw 'Controlled Gateway shutdown did not complete successfully.'
                    }
                } catch {
                    $cleanupError = Get-SanitizedRuntimeError $_ $sensitiveValues
                    $processStoppedCleanly = $false
                }
            } else {
                $processStoppedCleanly = $process.ExitCode -eq 0
                if (-not $processStoppedCleanly) {
                    $cleanupError = 'Gateway process exited unsuccessfully before controlled shutdown.'
                }
            }
            if (-not $process.HasExited) {
                $forcedTerminationUsed = $true
                try {
                    $process.Kill()
                    [void]$process.WaitForExit(5000)
                } catch {
                    $forcedError = Get-SanitizedRuntimeError $_ $sensitiveValues
                    $cleanupError = if ([string]::IsNullOrWhiteSpace($cleanupError)) {
                        $forcedError
                    } else { "$cleanupError; $forcedError" }
                }
            }
            if ($process.HasExited) {
                $gatewayProcessExitObserved = $true
                $gatewayProcessExitCode = $process.ExitCode
            }
            $stdoutCapture = Receive-GatewayStreamCapture $stdoutReadTask $sensitiveValues 5000
            $stderrCapture = Receive-GatewayStreamCapture $stderrReadTask $sensitiveValues 5000
            $gatewayStdoutCaptured = [bool]$stdoutCapture.captured
            $gatewayStderrCaptured = [bool]$stderrCapture.captured
            $gatewayStdoutSanitized = $stdoutCapture.sanitized
            $gatewayStderrSanitized = $stderrCapture.sanitized
            $streamErrors = @(
                @($stdoutCapture.error, $stderrCapture.error) |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            )
            if ($streamErrors.Count -gt 0) {
                $gatewayStreamCaptureError = $streamErrors -join '; '
            }
            $orphanProcesses = if (
                Get-Process -Id $knownPid -ErrorAction SilentlyContinue
            ) { 1 } else { 0 }
        } catch {
            $cleanupError = Get-SanitizedRuntimeError $_ $sensitiveValues
            $processStoppedCleanly = $false
            $orphanProcesses = 1
        } finally {
            try { $process.Dispose() } catch {
                $disposeError = Get-SanitizedRuntimeError $_ $sensitiveValues
                $cleanupError = if ([string]::IsNullOrWhiteSpace($cleanupError)) {
                    $disposeError
                } else { "$cleanupError; $disposeError" }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($cleanupError)) {
        if ([string]::IsNullOrWhiteSpace($runtimeError)) {
            $failureStage = 'SHUTDOWN'
            $failureCode = 'GATEWAY_HEALTH_ONLY_SHUTDOWN_FAILED'
            $runtimeError = $cleanupError
        }
    }

    if (
        $gatewayProcessStarted -and
        (-not $gatewayStdoutCaptured -or -not $gatewayStderrCaptured) -and
        [string]::IsNullOrWhiteSpace($runtimeError)
    ) {
        $failureStage = 'STREAM_CAPTURE'
        $failureCode = 'GATEWAY_HEALTH_ONLY_STREAM_CAPTURE_FAILED'
        $runtimeError = if ([string]::IsNullOrWhiteSpace($gatewayStreamCaptureError)) {
            'Gateway stdout/stderr capture did not complete.'
        } else { $gatewayStreamCaptureError }
    }

    if ($null -ne $beforeFingerprint) {
        try {
            $afterFingerprint = Get-FinalRuntimeFingerprint
            $runtimeFingerprintVerified = $true
            $filesystemRuntimeModified =
                $beforeFingerprint.content_sha256 -ne $afterFingerprint.content_sha256
            $aclModified = $beforeFingerprint.acl_sha256 -ne $afterFingerprint.acl_sha256
        } catch {
            $runtimeFingerprintVerified = $false
            if ([string]::IsNullOrWhiteSpace($runtimeError)) {
                $failureStage = 'RUNTIME_FINGERPRINT_AFTER'
                $failureCode = 'GATEWAY_HEALTH_ONLY_RUNTIME_FINGERPRINT_AFTER_FAILED'
                $runtimeError = Get-SanitizedRuntimeError $_ $sensitiveValues
            }
        }
    }

    $passed =
        $runtimeSucceeded -and $gatewayProcessStarted -and
        $gatewayProcessExitObserved -and
        $gatewayStdoutCaptured -and $gatewayStderrCaptured -and
        $healthHttpStatus -eq 200 -and $healthPayloadValid -and
        -not $mt5Imported -and -not $mt5Accessed -and
        -not $orderCheckCalled -and -not $orderSendCalled -and
        $processStoppedCleanly -and $orphanProcesses -eq 0 -and
        [string]::IsNullOrWhiteSpace($cleanupError) -and
        $runtimeFingerprintVerified -and
        -not $filesystemRuntimeModified -and -not $aclModified
    if (-not $passed -and [string]::IsNullOrWhiteSpace($failureCode)) {
        $failureStage = 'BOUNDARY_VALIDATION'
        $failureCode = 'GATEWAY_HEALTH_ONLY_BOUNDARY_FAILED'
        $runtimeError = 'One or more health-only boundary checks did not pass.'
    }

    $report.effective_sid = $effectiveSid
    $report.status = if ($passed) { 'PASS' } else { 'FAIL' }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $report.failure_code = if ($passed) { $null } else { $failureCode }
    $report.failure_stage = if ($passed) { $null } else { $failureStage }
    $report.runtime_error = if ($passed) { $null } else { $runtimeError }
    $report.gateway_process_started = $gatewayProcessStarted
    $report.gateway_process_exit_observed = $gatewayProcessExitObserved
    $report.gateway_process_exit_code = $gatewayProcessExitCode
    $report.gateway_exit_before_health = $gatewayExitBeforeHealth
    $report.gateway_stdout_captured = $gatewayStdoutCaptured
    $report.gateway_stderr_captured = $gatewayStderrCaptured
    $report.gateway_stdout_sanitized = $gatewayStdoutSanitized
    $report.gateway_stderr_sanitized = $gatewayStderrSanitized
    $report.gateway_stream_capture_error = $gatewayStreamCaptureError
    $report.health_http_status = $healthHttpStatus
    $report.health_payload_valid = $healthPayloadValid
    $report.mt5_package_metadata_version = $mt5PackageVersion
    $report.mt5_imported = $mt5Imported
    $report.mt5_accessed = $mt5Accessed
    $report.order_check_called = $orderCheckCalled
    $report.order_send_called = $orderSendCalled
    $report.cleanup_attempted = $cleanupAttempted
    $report.shutdown_requested = $shutdownRequested
    $report.forced_termination_used = $forcedTerminationUsed
    $report.cleanup_error = $cleanupError
    $report.process_stopped_cleanly = $processStoppedCleanly
    $report.orphan_processes = $orphanProcesses
    $report.runtime_fingerprint_verified = $runtimeFingerprintVerified
    $report.filesystem_runtime_modified = $filesystemRuntimeModified
    $report.acl_modified = $aclModified
    $report.final_runtime_item_count = if ($null -eq $afterFingerprint) {
        0
    } else { $afterFingerprint.item_count }

    try {
        Write-ExclusiveJson $reportPath $report
        $reportWritten = $true
    } catch {
        $reportWriteError = Get-SanitizedRuntimeError $_ $sensitiveValues
        $report.status = 'FAIL'
        $passed = $false
    }
}

if (-not [string]::IsNullOrWhiteSpace($reportWriteError)) {
    Write-Error "REPORT_WRITE_FAILED: $reportWriteError" -ErrorAction Continue
    if (-not [string]::IsNullOrWhiteSpace($runtimeError)) {
        Write-Error "ORIGINAL_RUNTIME_ERROR: $runtimeError" -ErrorAction Continue
    }
}

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
if (-not $passed -or -not $reportWritten) { exit 1 }
