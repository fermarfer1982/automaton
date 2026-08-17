#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$python = 'C:\automaton\.venv\Scripts\python.exe'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$policyPath = 'C:\automaton\config\windows-acl-policy.json'
$reportRoot = 'C:\ProgramData\AutomatonMT5Lab\maintenance\mt5-read-only-preconditions'
$normalizedRunId = ([guid]::ParseExact($RunId, 'D')).ToString('D').ToLowerInvariant()
$reportPath = Join-Path $reportRoot "protected-identity-$normalizedRunId.json"
$tempPath = Join-Path (Split-Path -Parent $configPath) ".trading.identity-$normalizedRunId.tmp"
$backupPath = Join-Path (Split-Path -Parent $configPath) ".trading.identity-$normalizedRunId.backup"
$failedPath = Join-Path (Split-Path -Parent $configPath) ".trading.identity-$normalizedRunId.failed"
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$gatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$agentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$fullControl = 2032127L
$readRights = 1179785L

$report = [ordered]@{
    schema_version = 1
    mode = 'MT5_READ_ONLY_PROTECTED_IDENTITY'
    run_id = $normalizedRunId
    apply_requested = [bool]$Apply
    status = 'FAIL_INITIALIZING'
    config_path = $configPath
    report_path = $reportPath
    maintenance_identity = $null
    maintenance_sid = $null
    initial_state = $null
    mt5_access_enabled_initially_present = $null
    target = [ordered]@{
        authorized_account = 107554164
        authorized_server = 'MetaQuotes-Demo'
        allowed_symbol = 'XAUUSD'
        mt5_terminal_path = 'C:\Program Files\MetaTrader 5\terminal64.exe'
        trading_mode = 'OBSERVE_ONLY'
        mt5_access_enabled = $false
    }
    hash_before = $null
    hash_candidate = $null
    hash_after = $null
    acl_before_sddl = $null
    acl_after_sddl = $null
    candidate_validated = $false
    real_loader_validated = $false
    controlled_replace_performed = $false
    set_acl_call_count = 0
    rollback_attempted = $false
    rollback_succeeded = $false
    temporary_artifacts_removed = $false
    config_modified = $false
    mt5_imported = $false
    mt5_accessed = $false
    gateway_started = $false
    automaton_started = $false
    trading_mode = 'OBSERVE_ONLY'
    error = $null
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    completed_at_utc = $null
}

function Get-CanonicalPath([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { throw "Path must be absolute: $Path" }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Resolve-OwnerSid([string] $Owner) {
    try {
        return ([System.Security.Principal.NTAccount]::new($Owner)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch { return $Owner }
}

function Get-ConfigAclSnapshot {
    $item = Get-Item -LiteralPath $configPath -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $configPath -ErrorAction Stop
    return [pscustomobject]@{
        reparse = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        is_directory = [bool]$item.PSIsContainer
        owner_sid = Resolve-OwnerSid $acl.Owner
        protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.Sddl
        rules = @($acl.Access | ForEach-Object {
            $sid = try {
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { 'UNRESOLVED:' + $_.IdentityReference.Value }
            [pscustomobject]@{
                sid = $sid
                type = $_.AccessControlType.ToString()
                rights = [int64]$_.FileSystemRights
                inherited = [bool]$_.IsInherited
                inheritance_flags = $_.InheritanceFlags.ToString()
                propagation_flags = $_.PropagationFlags.ToString()
            }
        })
    }
}

function Assert-ExactConfigAcl($Snapshot) {
    if ($Snapshot.reparse -or $Snapshot.is_directory -or -not $Snapshot.protected -or
        $Snapshot.owner_sid -ne $administratorsSid -or @($Snapshot.rules).Count -ne 3) {
        throw 'Protected config owner, type, inheritance, or ACE count is not canonical.'
    }
    foreach ($expected in @(
        [pscustomobject]@{ sid = $systemSid; rights = $fullControl },
        [pscustomobject]@{ sid = $administratorsSid; rights = $fullControl },
        [pscustomobject]@{ sid = $gatewaySid; rights = $readRights }
    )) {
        $matches = @($Snapshot.rules | Where-Object {
            $_.sid -eq $expected.sid -and $_.type -eq 'Allow' -and
            [int64]$_.rights -eq [int64]$expected.rights -and -not $_.inherited -and
            $_.inheritance_flags -eq 'None' -and $_.propagation_flags -eq 'None'
        })
        if ($matches.Count -ne 1) { throw 'Protected config ACL is not the exact reviewed policy.' }
    }
    if (@($Snapshot.rules | Where-Object { $_.sid -eq $agentSid -or $_.type -ne 'Allow' }).Count -ne 0) {
        throw 'Protected config contains Agent access or a non-Allow ACE.'
    }
}

function Invoke-ProtectedHelper([string] $Arguments) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $python
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = $workspace
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $startInfo.EnvironmentVariables['TRADING_MODE'] = 'OBSERVE_ONLY'
    $startInfo.EnvironmentVariables['MT5_ACCESS_ENABLED'] = 'false'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Protected config helper did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw 'Protected config helper timed out.'
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
            throw 'Protected config helper output capture did not complete.'
        }
        if ($process.ExitCode -ne 0) {
            throw "Protected config helper failed closed with exit code $($process.ExitCode)."
        }
        return ([string]$stdout.Result).Trim() | ConvertFrom-Json -ErrorAction Stop
    } finally { $process.Dispose() }
}

function Write-DurableReport {
    if (-not (Test-Path -LiteralPath $reportRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $reportRoot -ErrorAction Stop | Out-Null
    }
    $item = Get-Item -LiteralPath $reportRoot -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'Maintenance report root cannot be a reparse point.'
    }
    $stream = [System.IO.File]::Open(
        $reportPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write(($report | ConvertTo-Json -Depth 10)) } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

$originalAcl = $null
$replacePerformed = $false
try {
    if ((Get-CanonicalPath $configPath) -ne 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml') {
        throw 'Protected config target is not exact.'
    }
    foreach ($path in @($workspace, $python, $configPath, $policyPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Required path is a reparse point: $path"
        }
    }
    foreach ($transient in @($tempPath, $backupPath, $failedPath)) {
        if ([System.IO.File]::Exists($transient) -or [System.IO.Directory]::Exists($transient)) {
            throw "RunId-specific transaction artifact already exists: $transient"
        }
    }
    $policy = [System.IO.File]::ReadAllText($policyPath, [System.Text.Encoding]::UTF8) |
        ConvertFrom-Json -ErrorAction Stop
    $maintenanceIdentity = [string]$policy.maintenance_identity
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.Name.Equals($maintenanceIdentity, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Current token is not the canonical maintenance identity.'
    }
    $maintenanceUser = Get-LocalUser -SID $current.User -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -SID ([System.Security.Principal.SecurityIdentifier]::new($administratorsSid)) |
        ForEach-Object { $_.SID.Value })
    if (-not $maintenanceUser.Enabled -or $maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or
        $adminMembers -notcontains $current.User.Value) {
        throw 'Maintenance identity must be an enabled local direct Administrator.'
    }
    $report.maintenance_identity = $maintenanceIdentity
    $report.maintenance_sid = $current.User.Value

    $beforeAcl = Get-ConfigAclSnapshot
    Assert-ExactConfigAcl $beforeAcl
    $originalAcl = Get-Acl -LiteralPath $configPath -ErrorAction Stop
    $report.acl_before_sddl = $beforeAcl.sddl
    $inspection = Invoke-ProtectedHelper "-B -m trading_lab.protected_identity_config inspect --config `"$configPath`""
    $report.initial_state = [string]$inspection.state
    $report.mt5_access_enabled_initially_present = [bool]$inspection.mt5_access_enabled_present
    $report.hash_before = [string]$inspection.source_sha256
    $report.hash_candidate = [string]$inspection.candidate_sha256
    if (-not [bool]$inspection.candidate_schema_validated) {
        throw 'Protected identity candidate did not pass schema prevalidation.'
    }

    if (-not $Apply) {
        $report.candidate_validated = [bool]$inspection.candidate_schema_validated
        $report.real_loader_validated = ($report.initial_state -eq 'EXACT_TARGET')
        $report.hash_after = $report.hash_before
    } elseif ($report.initial_state -eq 'KNOWN_PLACEHOLDER') {
        $rendered = Invoke-ProtectedHelper "-B -m trading_lab.protected_identity_config render --config `"$configPath`" --output `"$tempPath`""
        if ([string]$rendered.source_sha256 -ne $report.hash_before -or
            [string]$rendered.candidate_sha256 -ne $report.hash_candidate) {
            throw 'Protected config changed between inspect and render.'
        }
        $validated = Invoke-ProtectedHelper "-B -m trading_lab.protected_identity_config validate --baseline `"$configPath`" --candidate `"$tempPath`""
        $report.candidate_validated = ([string]$validated.status -eq 'PASS')
        $preReplaceAcl = Get-ConfigAclSnapshot
        Assert-ExactConfigAcl $preReplaceAcl
        $preReplaceHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($preReplaceAcl.sddl -ne $beforeAcl.sddl -or $preReplaceHash -ne $report.hash_before) {
            throw 'Protected config content or ACL changed before controlled replace.'
        }
        [System.IO.File]::Replace($tempPath, $configPath, $backupPath, $true)
        $replacePerformed = $true
        $report.controlled_replace_performed = $true
        $report.config_modified = $true
        Set-Acl -LiteralPath $configPath -AclObject $originalAcl
        $report.set_acl_call_count = 1
        $afterAcl = Get-ConfigAclSnapshot
        Assert-ExactConfigAcl $afterAcl
        if ($afterAcl.sddl -ne $beforeAcl.sddl) { throw 'Protected config ACL was not preserved exactly.' }
        $reloaded = Invoke-ProtectedHelper "-B -m trading_lab.protected_identity_config validate --baseline `"$backupPath`" --candidate `"$configPath`""
        $report.real_loader_validated = ([string]$reloaded.loader -eq 'load_mt5_security_config')
        $report.hash_after = [string]$reloaded.candidate_sha256
    } else {
        $validated = Invoke-ProtectedHelper "-B -m trading_lab.protected_identity_config validate --baseline `"$configPath`" --candidate `"$configPath`""
        $report.candidate_validated = ([string]$validated.status -eq 'PASS')
        $report.real_loader_validated = ([string]$validated.loader -eq 'load_mt5_security_config')
        $report.hash_after = [string]$validated.candidate_sha256
    }
    $finalAcl = Get-ConfigAclSnapshot
    Assert-ExactConfigAcl $finalAcl
    $report.acl_after_sddl = $finalAcl.sddl
    if ($Apply -and ($report.hash_after -ne $report.hash_candidate -or -not $report.real_loader_validated)) {
        throw 'Protected config final hash or real-loader validation failed.'
    }
    if ($Apply -and $replacePerformed) {
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction Stop
    }
    $report.temporary_artifacts_removed = -not (
        [System.IO.File]::Exists($tempPath) -or [System.IO.File]::Exists($backupPath) -or
        [System.IO.File]::Exists($failedPath)
    )
    if (-not $report.temporary_artifacts_removed) { throw 'Transaction artifacts were not removed.' }
    $report.status = if ($Apply) { 'PASS' } else { 'DRY_RUN_PASS' }
} catch {
    $report.error = $_.Exception.Message
    if ($Apply -and $replacePerformed -and [System.IO.File]::Exists($backupPath)) {
        $report.rollback_attempted = $true
        try {
            [System.IO.File]::Replace($backupPath, $configPath, $failedPath, $true)
            if ($null -ne $originalAcl) {
                Set-Acl -LiteralPath $configPath -AclObject $originalAcl
                $report.set_acl_call_count++
            }
            $restoredAcl = Get-ConfigAclSnapshot
            Assert-ExactConfigAcl $restoredAcl
            $restoredHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $report.rollback_succeeded = ($restoredHash -eq $report.hash_before -and
                $restoredAcl.sddl -eq $report.acl_before_sddl)
        } catch { $report.rollback_succeeded = $false }
    }
    foreach ($transient in @($tempPath, $backupPath, $failedPath)) {
        if ([System.IO.File]::Exists($transient)) {
            try { Remove-Item -LiteralPath $transient -Force -ErrorAction Stop } catch { }
        }
    }
    $report.status = 'FAIL_CLOSED'
} finally {
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    try { Write-DurableReport } catch {
        [Console]::Error.WriteLine("Unable to persist protected config report: $($_.Exception.Message)")
        throw
    }
}

$report | ConvertTo-Json -Depth 10
if ($report.status -notin @('PASS', 'DRY_RUN_PASS')) { exit 1 }
