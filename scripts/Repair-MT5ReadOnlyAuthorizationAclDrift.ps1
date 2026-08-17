#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string] $RunId,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$controlPath = 'C:\ProgramData\AutomatonMT5Lab\control'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$demoAuthorizationPath = 'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization'
$reportRoot = 'C:\ProgramData\AutomatonMT5Lab\maintenance\mt5-read-only-preconditions'
$policyPath = 'C:\automaton\config\windows-acl-policy.json'
$bootstrapPath = 'C:\automaton\scripts\TradingLabAclBootstrap.ps1'
$helperPath = 'C:\automaton\scripts\MT5ReadOnlyAclRepairHelpers.ps1'
$verifierPath = 'C:\automaton\trading_lab\acl_repair_verifier.py'
$pythonPath = 'C:\automaton\.venv\Scripts\python.exe'
$expectedConfigSha256 = 'beabc9b2553a674739b62195a4181eeca0ed59019e11b78055808ec4cd31686e'
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$usersSid = 'S-1-5-32-545'
$gatewayName = 'AutomatonGateway'
$automatonName = 'AutomatonAgent'
$expectedGatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$expectedAutomatonSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$normalizedRunId = ([guid]::ParseExact($RunId, 'D')).ToString('D')
if ($RunId -cne $normalizedRunId) { throw 'RunId must use lowercase canonical UUID form.' }
$reportPath = Join-Path $reportRoot "acl-repair-$normalizedRunId.json"

$report = [ordered]@{
    schema_version = 1
    mode = 'MT5_READ_ONLY_AUTHORIZATION_ACL_DRIFT_REPAIR'
    run_id = $normalizedRunId
    report_path = $reportPath
    status = 'FAIL_INITIALIZING'
    dry_run = -not [bool]$Apply
    apply = [bool]$Apply
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    finished_at_utc = $null
    current_sid = $null
    maintenance_sid = $null
    gateway_sid = $null
    automaton_sid = $null
    drift_detected = $false
    control_repair_required = $false
    demo_auth_repair_required = $false
    auth_file_convergence_required = $false
    control = [ordered]@{
        before_sddl = $null; expected_sddl = $null; after_sddl = $null
        modified = $false; verified = $false; before_owner_sid = $null
        after_owner_sid = $null; before_inheritance_protected = $null
        expected_inheritance_protected = $true; after_inheritance_protected = $null
        drift_state = $null; mutation_attempted = $false
    }
    demo_authorization = [ordered]@{
        before_sddl = $null; expected_sddl = $null; after_sddl = $null
        modified = $false; verified = $false; before_owner_sid = $null
        after_owner_sid = $null; before_inheritance_protected = $null
        expected_inheritance_protected = $true; after_inheritance_protected = $null
        drift_state = $null; mutation_attempted = $false
    }
    authorization_artifacts = @()
    trading_yaml_sha256_before = $null
    trading_yaml_sha256_after = $null
    set_acl_call_count = 0
    filesystem_mutation = $false
    report_only_mutation = $true
    rollback_attempted = $false
    rollback_verified = $false
    rollback_error = $null
    primary_failure_stage = $null
    residual_state_captured = $false
    canonical_verifier_passed = $false
    candidate_verifier_passed = $false
    full_verifier_passed = $false
    verifier_without_automaton_state_passed = $false
    verifier_with_automaton_state_passed = $false
    mt5_imported = $false
    mt5_accessed = $false
    gateway_started = $false
    automaton_started = $false
    trading_mode = 'OBSERVE_ONLY'
    error = $null
    failure_stage = $null
    last_completed_stage = 'INITIALIZED'
    exclusive_lock_acquired = $false
    report_reserved_before_mutation = $false
}

function Get-CanonicalPath([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { throw "Path is not absolute: $Path" }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-ExactPath(
    [string] $Path,
    [string] $Expected,
    [ValidateSet('File', 'Directory')] [string] $Kind
) {
    if ((Get-CanonicalPath $Path) -cne (Get-CanonicalPath $Expected)) {
        throw "Protected path is not exact: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($Kind -eq 'Directory' -and -not $item.PSIsContainer) -or
        ($Kind -eq 'File' -and $item.PSIsContainer) -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Protected path type or reparse state is unsafe: $Path"
    }
}

function Get-DirectLocalGroupSids(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
    $memberships = [System.Collections.Generic.List[string]]::new()
    foreach ($group in Get-LocalGroup -ErrorAction Stop) {
        $memberSids = try {
            @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop |
                ForEach-Object { $_.SID.Value })
        } catch { throw "Unable to inspect direct membership of local group $($group.Name)." }
        if ($memberSids -contains $UserSid.Value) { $memberships.Add($group.SID.Value) }
    }
    return @($memberships | Sort-Object -Unique)
}

function Assert-ServiceIdentity(
    [string] $Name,
    [string] $ExpectedSid
) {
    $user = Get-LocalUser -Name $Name -ErrorAction Stop
    if ($user.SID.Value -ne $ExpectedSid -or -not $user.Enabled -or
        $user.PrincipalSource.ToString() -ne 'Local') {
        throw "Service identity is not the exact enabled local account: $Name"
    }
    $groups = @(Get-DirectLocalGroupSids $user.SID)
    if ($groups.Count -ne 1 -or $groups[0] -ne $usersSid) {
        throw "Service identity direct group membership is not exactly BUILTIN\Users: $Name"
    }
    return $user.SID.Value
}

function Assert-RepositoryClean {
    $git = Get-Command git.exe -ErrorAction Stop
    $output = @(& $git.Source -C $workspace status --porcelain=v1 --untracked-files=all 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Git worktree state.' }
    if ($output.Count -ne 0) { throw 'ACL repair requires a clean Git worktree.' }
}

function Assert-ProtectedSourceFiles {
    foreach ($path in @(
        $policyPath, $bootstrapPath, $helperPath, $verifierPath,
        'C:\automaton\scripts\Repair-MT5ReadOnlyAuthorizationAclDrift.ps1',
        'C:\automaton\trading_lab\windows_acl.py',
        'C:\automaton\trading_lab\config.py'
    )) {
        Assert-ExactPath $path $path 'File'
        $relative = $path.Substring($workspace.Length + 1).Replace('\', '/')
        $git = Get-Command git.exe -ErrorAction Stop
        [void](& $git.Source -C $workspace ls-files --error-unmatch -- $relative 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "Protected source is not tracked by Git: $path" }
    }
}

function Assert-FreshSecurityPreconditions {
    Assert-RepositoryClean
    Assert-ProtectedSourceFiles
    $freshPolicy = Read-TradingLabWindowsAclPolicy $policyPath
    $freshCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($freshCurrent.User.Value -ne $maintenanceSid -or
        -not $freshCurrent.Name.Equals(
            [string]$freshPolicy.maintenance_identity,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Maintenance identity changed before ACL mutation.'
    }
    $freshMaintenance = Get-LocalUser -SID $freshCurrent.User -ErrorAction Stop
    $freshAdminMembers = @(Get-LocalGroupMember -SID (
        [System.Security.Principal.SecurityIdentifier]::new($administratorsSid)
    ) -ErrorAction Stop | ForEach-Object { $_.SID.Value })
    if (-not $freshMaintenance.Enabled -or
        $freshMaintenance.PrincipalSource.ToString() -ne 'Local' -or
        $freshAdminMembers -notcontains $maintenanceSid) {
        throw 'Maintenance identity lost its exact authorization before ACL mutation.'
    }
    if ((Assert-ServiceIdentity $gatewayName $expectedGatewaySid) -ne $gatewaySid -or
        (Assert-ServiceIdentity $automatonName $expectedAutomatonSid) -ne $automatonSid) {
        throw 'Service identity changed before ACL mutation.'
    }
    Assert-ExactPath $controlPath $controlPath 'Directory'
    Assert-ExactPath $demoAuthorizationPath $demoAuthorizationPath 'Directory'
    Assert-ExactPath $configPath $configPath 'File'
    if ((Get-Sha256 $configPath) -ne $expectedConfigSha256) {
        throw 'trading.yaml changed before ACL mutation.'
    }
    Assert-ExactConfigAcl (Get-MT5AclFilesystemSnapshot $configPath) $gatewaySid
}

function Get-Sha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).
        Hash.ToLowerInvariant()
}

function Assert-ExactConfigAcl($Snapshot, [string] $GatewaySid) {
    $expected = @(
        New-MT5AclRuleRecord $systemSid 2032127L $false 'None' 'None'
        New-MT5AclRuleRecord $administratorsSid 2032127L $false 'None' 'None'
        New-MT5AclRuleRecord $GatewaySid 1179785L $false 'None' 'None'
    )
    if ($Snapshot.is_directory -or $Snapshot.reparse -or -not $Snapshot.protected -or
        $Snapshot.owner_sid -ne $administratorsSid -or
        -not (Test-MT5AclExactRuleSet $Snapshot $expected)) {
        throw 'trading.yaml ACL is not the exact protected control-file model.'
    }
}

function Get-AuthorizationArtifactEvidence(
    [System.IO.FileSystemInfo] $Item,
    [string] $GatewaySid,
    [string] $MaintenanceSid
) {
    if ($Item.PSIsContainer -or
        ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Authorization child is a directory or reparse point: $($Item.FullName)"
    }
    $match = [regex]::Match(
        $Item.Name,
        '^mt5-read-only-authorization-(?<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.json$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success) { throw "Unexpected authorization child filename: $($Item.Name)" }
    $artifactId = $match.Groups['id'].Value
    $parsedId = try { ([guid]::ParseExact($artifactId, 'D')).ToString('D') } catch { $null }
    if ($null -eq $parsedId -or $parsedId -cne $artifactId) {
        throw "Authorization filename does not contain a canonical UUID: $($Item.Name)"
    }
    if ($Item.Length -le 0 -or $Item.Length -gt 65536) {
        throw "Authorization artifact size is outside the reviewed range: $($Item.Name)"
    }
    $content = [System.IO.File]::ReadAllText($Item.FullName, [System.Text.Encoding]::UTF8) |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$content.run_id -cne $artifactId -or
        [string]$content.purpose -ne 'MT5_READ_ONLY_PREFLIGHT' -or
        [string]$content.trading_mode -ne 'OBSERVE_ONLY' -or
        [string]$content.gateway_sid -ne $GatewaySid -or
        [string]$content.issuer_sid -ne $MaintenanceSid) {
        throw "Authorization artifact content does not match its protected identity binding: $($Item.Name)"
    }
    $snapshot = Get-MT5AclFilesystemSnapshot $Item.FullName
    $state = Get-MT5AclRepairState $snapshot 'AUTHORIZATION_FILE' `
        $GatewaySid $MaintenanceSid
    return [pscustomobject]@{
        path = $snapshot.path
        file_name = $Item.Name
        length_before = [int64]$Item.Length
        last_write_time_utc_before = $Item.LastWriteTimeUtc.ToString('o')
        sha256_before = Get-Sha256 $Item.FullName
        sha256_after = $null
        before_sddl = $snapshot.sddl
        expected_sddl = Get-MT5AclCanonicalArtifactSddl $GatewaySid
        after_sddl = $null
        drift_state = $state
        convergence_required = $state -ne 'CANONICAL'
        modified_content = $false
        acl_verified = $state -eq 'CANONICAL'
        snapshot = $snapshot
    }
}

function Get-RepairState([string] $GatewaySid, [string] $MaintenanceSid) {
    $control = Get-MT5AclFilesystemSnapshot $controlPath
    $demo = Get-MT5AclFilesystemSnapshot $demoAuthorizationPath
    $controlState = Get-MT5AclRepairState $control 'CONTROL' $GatewaySid $MaintenanceSid
    $demoState = Get-MT5AclRepairState $demo 'DEMO_AUTHORIZATION' $GatewaySid $MaintenanceSid
    $artifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($child in @(Get-ChildItem -LiteralPath $demoAuthorizationPath -Force -ErrorAction Stop)) {
        $artifacts.Add((Get-AuthorizationArtifactEvidence $child $GatewaySid $MaintenanceSid))
    }
    return [pscustomobject]@{
        control = $control
        control_state = $controlState
        demo = $demo
        demo_state = $demoState
        artifacts = @($artifacts)
        config_sha256 = Get-Sha256 $configPath
    }
}

function Assert-RepairStateUnchanged($Expected, $Actual) {
    if (-not (Test-MT5AclSnapshotEqual $Expected.control $Actual.control) -or
        -not (Test-MT5AclSnapshotEqual $Expected.demo $Actual.demo) -or
        $Expected.config_sha256 -ne $Actual.config_sha256 -or
        @($Expected.artifacts).Count -ne @($Actual.artifacts).Count) {
        throw 'Protected ACL repair state changed during prevalidation.'
    }
    for ($index = 0; $index -lt @($Expected.artifacts).Count; $index++) {
        $before = $Expected.artifacts[$index]
        $after = $Actual.artifacts[$index]
        if ($before.path -cne $after.path -or $before.sha256_before -ne $after.sha256_before -or
            $before.before_sddl -ne $after.before_sddl -or
            $before.length_before -ne $after.length_before) {
            throw 'Authorization artifact changed during prevalidation.'
        }
    }
}

function ConvertTo-SafeDiagnostic([string] $Text) {
    if ($null -eq $Text) { return '' }
    $safe = [regex]::Replace(
        $Text,
        '(?im)(password|passwd|secret|token|api[ _-]*key|ipc[ _-]*key)\s*[:=]\s*[^\s,;\}\]]+',
        '$1=[REDACTED]'
    )
    if ($safe.Length -gt 8192) { return $safe.Substring(0, 8178) + '...[TRUNCATED]' }
    return $safe
}

function Invoke-FullCanonicalVerifier {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonPath
    $startInfo.Arguments = '-B -m trading_lab.acl_repair_verifier'
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
        if (-not $process.Start()) { throw 'Canonical verifier process did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw 'Canonical verifier exceeded its bounded timeout.'
        }
        if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
            throw 'Canonical verifier output capture did not complete.'
        }
        $stdout = [string]$stdoutTask.Result
        $stderr = ConvertTo-SafeDiagnostic ([string]$stderrTask.Result)
        $payload = try { $stdout | ConvertFrom-Json -ErrorAction Stop } catch {
            throw "Canonical verifier returned invalid JSON. stderr=$stderr"
        }
        if ($process.ExitCode -ne 0 -or [string]$payload.status -ne 'PASS') {
            throw "Canonical verifier failed closed with exit code $($process.ExitCode). stderr=$stderr"
        }
        return $payload
    } finally { $process.Dispose() }
}

function Set-ReportFromState($State, [bool] $AfterMutation) {
    $report.control.after_sddl = $State.control.sddl
    $report.control.after_owner_sid = $State.control.owner_sid
    $report.control.after_inheritance_protected = $State.control.protected
    $report.demo_authorization.after_sddl = $State.demo.sddl
    $report.demo_authorization.after_owner_sid = $State.demo.owner_sid
    $report.demo_authorization.after_inheritance_protected = $State.demo.protected
    $report.trading_yaml_sha256_after = $State.config_sha256
    $artifactReports = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in @($State.artifacts)) {
        $initial = @($initialState.artifacts | Where-Object { $_.path -ceq $artifact.path })
        if ($initial.Count -ne 1) { throw 'Authorization artifact set changed during repair.' }
        $artifactReports.Add([ordered]@{
            path = $artifact.path
            sha256_before = $initial[0].sha256_before
            sha256_after = $artifact.sha256_before
            length_before = $initial[0].length_before
            length_after = $artifact.length_before
            last_write_time_utc_before = $initial[0].last_write_time_utc_before
            last_write_time_utc_after = $artifact.last_write_time_utc_before
            before_sddl = $initial[0].before_sddl
            expected_sddl = $initial[0].expected_sddl
            after_sddl = $artifact.before_sddl
            owner_sid_before = $initial[0].snapshot.owner_sid
            owner_sid_after = $artifact.snapshot.owner_sid
            inheritance_protected_before = $initial[0].snapshot.protected
            inheritance_protected_after = $artifact.snapshot.protected
            drift_state = $initial[0].drift_state
            convergence_required = [bool]$initial[0].convergence_required
            modified_content = $initial[0].sha256_before -ne $artifact.sha256_before -or
                $initial[0].length_before -ne $artifact.length_before
            content_metadata_changed =
                $initial[0].last_write_time_utc_before -ne $artifact.last_write_time_utc_before
            acl_verified = $artifact.drift_state -eq 'CANONICAL'
        })
    }
    $report.authorization_artifacts = @($artifactReports)
    if ($AfterMutation) {
        Assert-MT5AclCanonicalSnapshot $State.control 'CONTROL' $gatewaySid $maintenanceSid
        Assert-MT5AclCanonicalSnapshot $State.demo 'DEMO_AUTHORIZATION' $gatewaySid $maintenanceSid
        foreach ($artifact in @($State.artifacts)) {
            Assert-MT5AclCanonicalSnapshot $artifact.snapshot 'AUTHORIZATION_FILE' `
                $gatewaySid $maintenanceSid
        }
    }
}

function Invoke-RepairRollback {
    $errors = [System.Collections.Generic.List[string]]::new()
    $restored = $null
    foreach ($entry in @(
        [pscustomobject]@{ path = $controlPath; acl = $controlAclBefore },
        [pscustomobject]@{ path = $demoAuthorizationPath; acl = $demoAclBefore }
    )) {
        try {
            $report.set_acl_call_count++
            Set-Acl -LiteralPath $entry.path -AclObject $entry.acl -ErrorAction Stop
        } catch { $errors.Add("Rollback Set-Acl failed for $($entry.path): $($_.Exception.Message)") }
    }
    try {
        $restored = Get-RepairState $gatewaySid $maintenanceSid
        Assert-RepairStateUnchanged $initialState $restored
    } catch { $errors.Add("Rollback verification failed: $($_.Exception.Message)") }
    return [pscustomobject]@{
        verified = $errors.Count -eq 0
        error = if ($errors.Count -eq 0) { $null } else { ConvertTo-SafeDiagnostic ($errors -join '; ') }
        state = $restored
    }
}

function Write-DurableRepairReport {
    Assert-ExactPath $reportRoot $reportRoot 'Directory'
    $stream = $script:reportReservation
    if ($null -eq $stream) {
        if ([System.IO.File]::Exists($reportPath) -or [System.IO.Directory]::Exists($reportPath)) {
            throw 'RunId report path already exists.'
        }
        $stream = [System.IO.File]::Open(
            $reportPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read
        )
    }
    try {
        $writer = [System.IO.StreamWriter]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false)
        )
        try { $writer.Write(($report | ConvertTo-Json -Depth 16)) } finally { $writer.Dispose() }
    } finally {
        $stream.Dispose()
        $script:reportReservation = $null
    }
}

function Reserve-RepairReport {
    Assert-ExactPath $reportRoot $reportRoot 'Directory'
    if ([System.IO.File]::Exists($reportPath) -or [System.IO.Directory]::Exists($reportPath)) {
        throw 'RunId report path already exists.'
    }
    $script:reportReservation = [System.IO.File]::Open(
        $reportPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    $report.report_reserved_before_mutation = $true
}

$initialState = $null
$controlAclBefore = $null
$demoAclBefore = $null
$mutationStarted = $false
$primaryError = $null
$reportReservation = $null
$gateMutex = $null
$gateMutexHeld = $false
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'ACL repair is supported only on Windows.'
    }
    Assert-ExactPath $workspace 'C:\automaton' 'Directory'
    Assert-ExactPath $bootstrapPath $bootstrapPath 'File'
    Assert-ExactPath $helperPath $helperPath 'File'
    Assert-RepositoryClean
    . $bootstrapPath
    . $helperPath
    Assert-ExactPath $labRoot 'C:\ProgramData\AutomatonMT5Lab' 'Directory'
    Assert-ExactPath $controlPath 'C:\ProgramData\AutomatonMT5Lab\control' 'Directory'
    Assert-ExactPath $configPath 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml' 'File'
    Assert-ExactPath $demoAuthorizationPath `
        'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization' 'Directory'
    Assert-ExactPath $reportRoot $reportRoot 'Directory'
    Assert-ExactPath $pythonPath $pythonPath 'File'
    Assert-ProtectedSourceFiles

    $gateMutex = [System.Threading.Mutex]::new(
        $false,
        'Global\AutomatonMT5ReadOnlyAuthorizationAclRepair'
    )
    $gateMutexHeld = $gateMutex.WaitOne(0)
    if (-not $gateMutexHeld) { throw 'Another ACL repair gate instance is active.' }
    $report.exclusive_lock_acquired = $true

    $policy = Read-TradingLabWindowsAclPolicy $policyPath
    foreach ($forbiddenTarget in @(
        'control_directory', 'control_demo_authorization', 'control_config',
        'control_mt5_read_only_authorization_file'
    )) {
        if (@($policy.maintenance_targets.PSObject.Properties.Name) -contains $forbiddenTarget) {
            throw "Canonical maintenance policy unexpectedly includes $forbiddenTarget."
        }
    }
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.Name.Equals(
        [string]$policy.maintenance_identity,
        [System.StringComparison]::OrdinalIgnoreCase
    )) { throw 'Current identity is not the canonical maintenance identity.' }
    $maintenanceUser = Get-LocalUser -SID $current.User -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -SID (
        [System.Security.Principal.SecurityIdentifier]::new($administratorsSid)
    ) -ErrorAction Stop | ForEach-Object { $_.SID.Value })
    if (-not $maintenanceUser.Enabled -or
        $maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or
        $adminMembers -notcontains $current.User.Value) {
        throw 'Maintenance identity must be an enabled local direct Administrator.'
    }
    $maintenanceSid = $current.User.Value
    $gatewaySid = Assert-ServiceIdentity $gatewayName $expectedGatewaySid
    $automatonSid = Assert-ServiceIdentity $automatonName $expectedAutomatonSid
    if ($gatewaySid -eq $automatonSid -or $maintenanceSid -in @($gatewaySid, $automatonSid)) {
        throw 'ACL repair identities are not strictly separated.'
    }
    $report.current_sid = $current.User.Value
    $report.maintenance_sid = $maintenanceSid
    $report.gateway_sid = $gatewaySid
    $report.automaton_sid = $automatonSid

    $configHash = Get-Sha256 $configPath
    if ($configHash -ne $expectedConfigSha256) {
        throw 'trading.yaml hash does not match the exact repair authorization.'
    }
    Assert-ExactConfigAcl (Get-MT5AclFilesystemSnapshot $configPath) $gatewaySid
    $report.trading_yaml_sha256_before = $configHash

    $controlCandidate = New-MT5AclCanonicalDirectorySecurity 'CONTROL' $gatewaySid
    $demoCandidate = New-MT5AclCanonicalDirectorySecurity 'DEMO_AUTHORIZATION' $gatewaySid
    $controlExpected = Get-MT5AclDirectorySecuritySnapshot $controlCandidate $controlPath
    $demoExpected = Get-MT5AclDirectorySecuritySnapshot $demoCandidate $demoAuthorizationPath
    Assert-MT5AclCanonicalSnapshot $controlExpected 'CONTROL' $gatewaySid $maintenanceSid
    Assert-MT5AclCanonicalSnapshot $demoExpected 'DEMO_AUTHORIZATION' $gatewaySid $maintenanceSid

    $initialState = Get-RepairState $gatewaySid $maintenanceSid
    $controlAclBefore = Get-Acl -LiteralPath $controlPath -ErrorAction Stop
    $demoAclBefore = Get-Acl -LiteralPath $demoAuthorizationPath -ErrorAction Stop
    $report.control.before_sddl = $initialState.control.sddl
    $report.control.before_owner_sid = $initialState.control.owner_sid
    $report.control.before_inheritance_protected = $initialState.control.protected
    $report.control.expected_sddl = $controlExpected.sddl
    $report.control.drift_state = $initialState.control_state
    $report.demo_authorization.before_sddl = $initialState.demo.sddl
    $report.demo_authorization.before_owner_sid = $initialState.demo.owner_sid
    $report.demo_authorization.before_inheritance_protected = $initialState.demo.protected
    $report.demo_authorization.expected_sddl = $demoExpected.sddl
    $report.demo_authorization.drift_state = $initialState.demo_state
    $repairPlan = Get-MT5AclRepairPlan `
        $initialState.control_state `
        $initialState.demo_state `
        @($initialState.artifacts | ForEach-Object { $_.drift_state })
    $report.control_repair_required = $repairPlan.control_repair_required
    $report.demo_auth_repair_required = $repairPlan.demo_auth_repair_required
    $report.auth_file_convergence_required = $repairPlan.auth_file_convergence_required
    $report.drift_detected = $repairPlan.drift_detected
    Set-ReportFromState $initialState $false
    $report.control.verified = $initialState.control_state -eq 'CANONICAL'
    $report.demo_authorization.verified = $initialState.demo_state -eq 'CANONICAL'
    $report.candidate_verifier_passed = $true

    Reserve-RepairReport
    Assert-FreshSecurityPreconditions
    $freshState = Get-RepairState $gatewaySid $maintenanceSid
    Assert-RepairStateUnchanged $initialState $freshState
    $controlAclBefore = Get-Acl -LiteralPath $controlPath -ErrorAction Stop
    $demoAclBefore = Get-Acl -LiteralPath $demoAuthorizationPath -ErrorAction Stop
    if ($controlAclBefore.Sddl -ne $freshState.control.sddl -or
        $demoAclBefore.Sddl -ne $freshState.demo.sddl) {
        throw 'Fresh rollback descriptors do not match the revalidated snapshots.'
    }
    $report.last_completed_stage = 'PRE_MUTATION_REVALIDATION'
    if (-not $Apply) {
        if ($report.set_acl_call_count -ne 0 -or $report.filesystem_mutation) {
            throw 'Dry run reached an ACL mutation boundary.'
        }
        $report.status = 'DRY_RUN_PASS'
    } else {
        if ($repairPlan.control_set_acl_required) {
            $report.failure_stage = 'APPLY_CONTROL'
            $mutationStarted = $true
            $report.control.mutation_attempted = $true
            $report.filesystem_mutation = $true
            $report.set_acl_call_count++
            Set-Acl -LiteralPath $controlPath -AclObject $controlCandidate -ErrorAction Stop
            $report.control.modified = $true
            $report.filesystem_mutation = $true
            $report.last_completed_stage = 'APPLY_CONTROL'
        }
        if ($repairPlan.demo_set_acl_required) {
            $report.failure_stage = 'APPLY_DEMO_AUTHORIZATION'
            $mutationStarted = $true
            $report.demo_authorization.mutation_attempted = $true
            $report.filesystem_mutation = $true
            $report.set_acl_call_count++
            Set-Acl -LiteralPath $demoAuthorizationPath -AclObject $demoCandidate -ErrorAction Stop
            $report.demo_authorization.modified = $true
            $report.filesystem_mutation = $true
            $report.last_completed_stage = 'APPLY_DEMO_AUTHORIZATION'
        }
        $report.failure_stage = 'POST_APPLY_SPECIALIZED_VERIFICATION'
        $postState = Get-RepairState $gatewaySid $maintenanceSid
        Set-ReportFromState $postState $true
        $report.canonical_verifier_passed = $true
        $report.control.verified = $true
        $report.demo_authorization.verified = $true
        foreach ($artifact in $report.authorization_artifacts) {
            if ($artifact.modified_content -or $artifact.content_metadata_changed -or
                -not $artifact.acl_verified) {
                throw 'Authorization artifact content or ACL postcondition failed.'
            }
        }
        if ($postState.config_sha256 -ne $expectedConfigSha256 -or
            $postState.config_sha256 -ne $initialState.config_sha256) {
            throw 'trading.yaml changed during ACL repair.'
        }
        Assert-RepositoryClean
        $report.last_completed_stage = 'POST_APPLY_SPECIALIZED_VERIFICATION'
        $report.failure_stage = 'POST_APPLY_FULL_VERIFICATION'
        $verification = Invoke-FullCanonicalVerifier
        $report.verifier_without_automaton_state_passed =
            [bool]$verification.without_automaton_state.passed
        $report.verifier_with_automaton_state_passed =
            [bool]$verification.with_automaton_state.passed
        $report.mt5_imported = [bool]$verification.mt5_imported
        $report.mt5_accessed = [bool]$verification.mt5_accessed
        $report.full_verifier_passed =
            $report.verifier_without_automaton_state_passed -and
            $report.verifier_with_automaton_state_passed -and
            -not $report.mt5_imported -and -not $report.mt5_accessed
        if (-not $report.full_verifier_passed) {
            throw 'Canonical full verifier did not pass both required scopes.'
        }
        $report.last_completed_stage = 'POST_APPLY_FULL_VERIFICATION'
        $report.failure_stage = $null
        $report.status = 'PASS'
    }
} catch {
    $primaryError = ConvertTo-SafeDiagnostic $_.Exception.Message
    $report.error = $primaryError
    $report.primary_failure_stage = $report.failure_stage
    if ($Apply -and $mutationStarted -and $null -ne $initialState) {
        $report.rollback_attempted = $true
        $report.failure_stage = 'ROLLBACK'
        $rollback = Invoke-RepairRollback
        $report.rollback_verified = [bool]$rollback.verified
        $report.rollback_error = $rollback.error
        if ($null -ne $rollback.state) {
            Set-ReportFromState $rollback.state $false
            $report.control.verified = $rollback.state.control_state -eq 'CANONICAL'
            $report.demo_authorization.verified = $rollback.state.demo_state -eq 'CANONICAL'
            $report.residual_state_captured = $true
        }
    }
    $report.status = 'FAIL_CLOSED'
} finally {
    $report.finished_at_utc = [DateTime]::UtcNow.ToString('o')
    try { Write-DurableRepairReport } catch {
        [Console]::Error.WriteLine("Unable to persist ACL repair report: $($_.Exception.Message)")
        if ($null -ne $primaryError) {
            [Console]::Error.WriteLine("Primary ACL repair error: $primaryError")
        }
        throw
    } finally {
        if ($gateMutexHeld -and $null -ne $gateMutex) {
            try { $gateMutex.ReleaseMutex() } catch { }
        }
        if ($null -ne $gateMutex) { $gateMutex.Dispose() }
    }
}

if ($report.status -eq 'DRY_RUN_PASS') {
    Write-Output 'ACL_REPAIR_DRY_RUN=PASS'
}
Write-Output "DRIFT_DETECTED=$($report.drift_detected.ToString().ToLowerInvariant())"
Write-Output "CONTROL_REPAIR_REQUIRED=$($report.control_repair_required.ToString().ToLowerInvariant())"
Write-Output "DEMO_AUTH_REPAIR_REQUIRED=$($report.demo_auth_repair_required.ToString().ToLowerInvariant())"
Write-Output "AUTH_FILE_CONVERGENCE_REQUIRED=$($report.auth_file_convergence_required.ToString().ToLowerInvariant())"
Write-Output "SET_ACL_CALL_COUNT=$($report.set_acl_call_count)"
Write-Output "FILESYSTEM_MUTATION=$($report.filesystem_mutation.ToString().ToLowerInvariant())"
$report | ConvertTo-Json -Depth 16
if ($report.status -notin @('PASS', 'DRY_RUN_PASS')) { exit 1 }
