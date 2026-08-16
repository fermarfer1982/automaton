#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ReportPath
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$agentState = 'C:\Users\AutomatonAgent\.automaton'
$agentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$gatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$usersSid = 'S-1-5-32-545'
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
. (Join-Path $PSScriptRoot 'TradingLabFileSystemRights.ps1')
$fullControl = 2032127L
$readRights = 131209L
$readExecuteRights = 131241L
$modifyRights = 197055L
$synchronizeRight = 1048576L
$appendDataRight = 4L
$writeOrSecurityRights = Get-TradingLabProhibitedMutationRightsMask
$appendForbiddenRights = $writeOrSecurityRights -band (-bnot $appendDataRight)
$report = [ordered]@{
    acl_prevalidation = 'FAIL'
    acl_apply = 'NOT_RUN'
    acl_applied = $false
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    service_identities_executed = $false
    mt5_accessed = $false
    order_check_executed = $false
    order_send_executed = $false
    demo_execution_enabled = $false
    trading_mode = 'OBSERVE_ONLY'
    account_configured = $false
    maintenance_identity = $null
    maintenance_sid = $null
    paths_created = @()
    prepared_state_verified = $false
    ipc_secret_created = $false
    ipc_secret_reused = $false
    ipc_secret_length = $null
    security_descriptors_applied = @()
    acl_snapshots = @()
    checks = [ordered]@{}
    tests = [ordered]@{}
    warnings = @()
    error = $null
}
. (Join-Path $PSScriptRoot 'TradingLabAclBootstrap.ps1')
$aclPolicyPath = Join-Path $workspace 'config\windows-acl-policy.json'
$aclPolicy = $null
$maintenanceSid = $null
$progressPath = $ReportPath + '.acl-progress.jsonl'

function Get-CanonicalPath([string] $Value) {
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        throw "Path must be absolute: $Value"
    }
    return [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Write-GateReport {
    $reportDirectory = Split-Path -Parent $ReportPath
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $reportDirectory | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $ReportPath,
        ($report | ConvertTo-Json -Depth 12),
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Resolve-OwnerSid([string] $Owner) {
    try {
        return ([System.Security.Principal.NTAccount]::new($Owner)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        return $Owner
    }
}

function Get-DirectLocalGroups(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($group in Get-LocalGroup) {
        $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
        if ($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $UserSid.Value }) {
            $groups.Add([pscustomobject]@{ name = $group.Name; sid = $group.SID.Value })
        }
    }
    return @($groups)
}

function Assert-ExactUser([string] $Name, [string] $ExpectedSid) {
    $user = Get-LocalUser -Name $Name -ErrorAction Stop
    $groups = @(Get-DirectLocalGroups $user.SID)
    if (
        $user.SID.Value -ne $ExpectedSid -or
        -not $user.Enabled -or
        $user.PrincipalSource.ToString() -ne 'Local' -or
        $groups.Count -ne 1 -or
        $groups[0].sid -ne $usersSid
    ) {
        throw "$Name failed exact SID/enabled/local/Users-only prevalidation."
    }
    return [pscustomobject]@{
        name = $Name
        sid = $user.SID.Value
        enabled = [bool]$user.Enabled
        principal_source = $user.PrincipalSource.ToString()
        administrator = $false
        direct_local_groups = $groups
    }
}

function Get-AclSnapshot([string] $Path, [string] $Domain) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = @($acl.Access | ForEach-Object {
        try {
            $sid = $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        } catch {
            $sid = 'UNRESOLVED:' + $_.IdentityReference.Value
        }
        [pscustomobject]@{
            sid = $sid
            type = $_.AccessControlType.ToString()
            rights = [int64]$_.FileSystemRights
            rights_text = $_.FileSystemRights.ToString()
            inherited = [bool]$_.IsInherited
            inheritance_flags = $_.InheritanceFlags.ToString()
            propagation_flags = $_.PropagationFlags.ToString()
        }
    })
    return [pscustomobject]@{
        domain = $Domain
        path = $Path
        owner_sid = Resolve-OwnerSid $acl.Owner
        owner = $acl.Owner
        inheritance_protected = [bool]$acl.AreAccessRulesProtected
        rules = $rules
    }
}

function Get-AllowRights($Snapshot, [string] $Sid) {
    $rights = 0L
    foreach ($rule in $Snapshot.rules) {
        if ($rule.sid -eq $Sid -and $rule.type -eq 'Allow') {
            $rights = $rights -bor [int64]$rule.rights
        }
    }
    return $rights
}

function Assert-RecoveryAndOwner($Snapshot) {
    if ($Snapshot.owner_sid -ne $administratorsSid -or -not $Snapshot.inheritance_protected) {
        throw "Unsafe owner or inheritance on $($Snapshot.path)."
    }
    if ((Get-AllowRights $Snapshot $systemSid) -band $fullControl -ne $fullControl) {
        throw "SYSTEM lacks FullControl on $($Snapshot.path)."
    }
    if ((Get-AllowRights $Snapshot $administratorsSid) -band $fullControl -ne $fullControl) {
        throw "Administrators lack FullControl on $($Snapshot.path)."
    }
    if (@($Snapshot.rules | Where-Object { $_.type -eq 'Deny' }).Count -ne 0) {
        throw "Deny ACE found on $($Snapshot.path)."
    }
}

function Assert-NoUnexpectedAllow($Snapshot, [string[]] $AllowedSids) {
    $unexpected = @($Snapshot.rules | Where-Object {
        $_.type -eq 'Allow' -and $_.sid -notin $AllowedSids
    })
    if ($unexpected.Count -ne 0) {
        throw "Unexpected Allow ACE on $($Snapshot.path): $($unexpected.sid -join ', ')"
    }
}

function Assert-ExactMaintenanceAllow($Snapshot) {
    $rules = @($Snapshot.rules | Where-Object {
        $_.sid -eq $maintenanceSid -and $_.type -eq 'Allow'
    })
    if ($rules.Count -ne 1 -or
        [int64]$rules[0].rights -ne $fullControl -or
        [bool]$rules[0].inherited -or
        $rules[0].inheritance_flags -ne 'ContainerInherit, ObjectInherit' -or
        $rules[0].propagation_flags -ne 'None') {
        throw "Maintenance ACE does not match the exact per-target policy on $($Snapshot.path)."
    }
}

function Invoke-Test([string] $Name, [scriptblock] $Command, [string] $LogPath) {
    try {
        & $Command *> $LogPath
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
        $report.tests[$Name] = [ordered]@{ passed = ($exitCode -eq 0); exit_code = $exitCode; log = $LogPath }
        if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode" }
    } catch {
        if (-not $report.tests.Contains($Name)) {
            $report.tests[$Name] = [ordered]@{ passed = $false; exit_code = -1; log = $LogPath }
        }
        throw
    }
}

try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
    if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ACL gate requires an elevated Administrator token.'
    }
    $aclPolicy = Read-TradingLabWindowsAclPolicy $aclPolicyPath
    $maintenanceSid = (Resolve-TradingLabAclIdentitySid $aclPolicy.maintenance_identity).Value
    if ($maintenanceSid -in @($systemSid, $administratorsSid, $gatewaySid, $agentSid)) {
        throw 'Maintenance identity conflicts with a protected principal.'
    }
    $maintenanceUser = Get-LocalUser -SID $([System.Security.Principal.SecurityIdentifier]::new($maintenanceSid)) -ErrorAction Stop
    $administratorMembers = @(Get-LocalGroupMember -SID $([System.Security.Principal.SecurityIdentifier]::new($administratorsSid)) |
        ForEach-Object { $_.SID.Value })
    if (-not $maintenanceUser.Enabled -or $maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or
        $administratorMembers -notcontains $maintenanceSid) {
        throw 'Maintenance identity must be an enabled local direct Administrator.'
    }
    $report.maintenance_identity = $aclPolicy.maintenance_identity
    $report.maintenance_sid = $maintenanceSid
    if ((Get-CanonicalPath $workspace) -ne 'C:\automaton') {
        throw 'Unexpected workspace path.'
    }
    if ((git -C $workspace status --porcelain=v1 | Out-String).Trim()) {
        throw 'Worktree must be clean before ACL application.'
    }

    $report.automaton_agent = Assert-ExactUser 'AutomatonAgent' $agentSid
    $report.automaton_gateway = Assert-ExactUser 'AutomatonGateway' $gatewaySid
    $runningLab = @(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match 'trading_lab\.service|dist[\\/]index\.js.*--run'
    })
    if ($runningLab.Count -ne 0) {
        throw 'A Gateway or Automaton laboratory process is already running.'
    }

    $template = Join-Path $workspace 'config\trading.bootstrap-observe-only.yaml'
    $configPath = Join-Path $labRoot 'control\trading.yaml'
    # This validates an existing config/key before creating any new path.
    if (Test-Path -LiteralPath $configPath) {
        [void](Assert-ExactBootstrapConfig $configPath $template)
    }
    $existingSecretPath = Join-Path $labRoot 'ipc\automaton.key'
    if (Test-Path -LiteralPath $existingSecretPath) {
        [void](Assert-ValidIpcSecret $existingSecretPath)
    }
    $report.acl_prevalidation = 'PASS'
    Write-GateReport

    $prepared = Initialize-TradingLabBootstrapState $labRoot $agentState $template
    $report.paths_created = @($prepared.created_paths)
    $report.prepared_state_verified = $true
    $report.ipc_secret_created = [bool]$prepared.ipc_secret_created
    $report.ipc_secret_reused = [bool]$prepared.ipc_secret_reused
    $report.ipc_secret_length = [int]$prepared.ipc_secret_length
    Write-GateReport

    $aclScript = Join-Path $workspace 'scripts\Initialize-TradingLabAcl.ps1'
    if (Test-Path -LiteralPath $progressPath) {
        Remove-Item -LiteralPath $progressPath -Force
    }
    $report.acl_apply = 'IN_PROGRESS'
    Write-GateReport
    & $aclScript `
        -GatewayIdentity $gatewaySid `
        -AutomatonIdentity $agentSid `
        -AutomatonStateDir $agentState `
        -WorkspaceRoot $workspace `
        -LabRoot $labRoot `
        -ProgressPath $progressPath `
        -Apply | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Initialize-TradingLabAcl.ps1 failed with exit code $LASTEXITCODE."
    }
    $report.acl_apply = 'PASS'
    $report.acl_applied = $true
    $report.security_descriptors_applied = @(Read-AclProgressFile $progressPath)
    Write-GateReport

    $targets = [ordered]@{
        workspace = $workspace
        programdata = $labRoot
        control = (Join-Path $labRoot 'control')
        config = $configPath
        demo_authorization = (Join-Path $labRoot 'control\demo-authorization')
        ipc = (Join-Path $labRoot 'ipc')
        ipc_key = (Join-Path $labRoot 'ipc\automaton.key')
        operational = (Join-Path $labRoot 'operational')
        research = (Join-Path $labRoot 'research')
        audit_sqlite = (Join-Path $labRoot 'audit\sqlite')
        audit_journal_directory = (Join-Path $labRoot 'audit\journal')
        audit_journal = (Join-Path $labRoot 'audit\journal\audit.jsonl')
        gateway_logs = (Join-Path $labRoot 'logs\gateway')
        logs = (Join-Path $labRoot 'logs')
        security_logs_directory = (Join-Path $labRoot 'logs\security')
        security_log = (Join-Path $labRoot 'logs\security\security.log')
        agent_state = $agentState
    }
    $snapshots = [ordered]@{}
    foreach ($entry in $targets.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value)) {
            throw "Required post-apply ACL target is absent: $($entry.Value)"
        }
        $snapshot = Get-AclSnapshot $entry.Value $entry.Key
        Assert-RecoveryAndOwner $snapshot
        $snapshots[$entry.Key] = $snapshot
    }

    Assert-NoUnexpectedAllow $snapshots.workspace @($systemSid, $administratorsSid, $gatewaySid, $agentSid)
    Assert-NoUnexpectedAllow $snapshots.programdata @($systemSid, $administratorsSid, $maintenanceSid, $gatewaySid, $agentSid)
    foreach ($name in @('control', 'config', 'demo_authorization', 'research', 'audit_sqlite', 'audit_journal_directory', 'audit_journal', 'security_log')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $gatewaySid)
    }
    foreach ($name in @('operational', 'logs', 'gateway_logs', 'security_logs_directory')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $maintenanceSid, $gatewaySid)
        Assert-ExactMaintenanceAllow $snapshots[$name]
    }
    foreach ($name in @('ipc', 'ipc_key')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $gatewaySid, $agentSid)
    }
    Assert-NoUnexpectedAllow $snapshots.agent_state @($systemSid, $administratorsSid, $maintenanceSid, $agentSid)
    Assert-ExactMaintenanceAllow $snapshots.programdata
    Assert-ExactMaintenanceAllow $snapshots.agent_state

    $workspaceAgent = Get-AllowRights $snapshots.workspace $agentSid
    $workspaceGateway = Get-AllowRights $snapshots.workspace $gatewaySid
    if (
        ($workspaceAgent -band $readExecuteRights) -ne $readExecuteRights -or
        ($workspaceGateway -band $readExecuteRights) -ne $readExecuteRights -or
        ($workspaceAgent -band $writeOrSecurityRights) -ne 0 -or
        ($workspaceGateway -band $writeOrSecurityRights) -ne 0
    ) { throw 'Workspace runtime rights do not match read-only design.' }

    $configGateway = Get-AllowRights $snapshots.config $gatewaySid
    if (
        (Get-AllowRights $snapshots.config $agentSid) -ne 0 -or
        ($configGateway -band $readRights) -ne $readRights -or
        ($configGateway -band $writeOrSecurityRights) -ne 0
    ) { throw 'Protected config rights mismatch.' }

    foreach ($principalSid in @($agentSid, $gatewaySid)) {
        $keyRights = Get-AllowRights $snapshots.ipc_key $principalSid
        if (($keyRights -band $readRights) -ne $readRights -or ($keyRights -band $writeOrSecurityRights) -ne 0) {
            throw 'IPC key rights mismatch.'
        }
    }
    foreach ($name in @('operational', 'research', 'audit_sqlite', 'gateway_logs')) {
        if (
            ((Get-AllowRights $snapshots[$name] $gatewaySid) -band $modifyRights) -ne $modifyRights -or
            (Get-AllowRights $snapshots[$name] $agentSid) -ne 0
        ) { throw "Gateway mutable-domain rights mismatch: $name" }
    }
    foreach ($name in @('audit_journal', 'security_log')) {
        $rights = Get-AllowRights $snapshots[$name] $gatewaySid
        if (
            ($rights -band $readRights) -ne $readRights -or
            ($rights -band $appendDataRight) -ne $appendDataRight -or
            ($rights -band $synchronizeRight) -ne $synchronizeRight -or
            ($rights -band $appendForbiddenRights) -ne 0 -or
            (Get-AllowRights $snapshots[$name] $agentSid) -ne 0
        ) { throw "Append-only file ACL mismatch: $name" }
    }
    if (
        ((Get-AllowRights $snapshots.agent_state $agentSid) -band $modifyRights) -ne $modifyRights -or
        (Get-AllowRights $snapshots.agent_state $gatewaySid) -ne 0
    ) { throw 'Agent state rights mismatch.' }

    $authenticatedUsersModify = $false
    foreach ($rule in $snapshots.workspace.rules) {
        if ($rule.sid -eq 'S-1-5-11' -and $rule.type -eq 'Allow' -and
            (Test-TradingLabFileSystemRightsMutation ([int64]$rule.rights))) {
            $authenticatedUsersModify = $true
        }
    }
    if ($authenticatedUsersModify) { throw 'Authenticated Users still has Modify on workspace.' }
    if (Test-Path -LiteralPath (Join-Path $labRoot 'control\STOP_TRADING')) {
        throw 'Presence-based STOP_TRADING was unexpectedly asserted by bootstrap.'
    }
    if (Test-Path -LiteralPath (Join-Path $labRoot 'control\demo-authorization\authorization.json')) {
        throw 'DEMO authorization was unexpectedly created by bootstrap.'
    }

    $report.acl_snapshots = @($snapshots.Values)
    $report.checks = [ordered]@{
        workspace_authenticated_users_modify = $authenticatedUsersModify
        agent_workspace_write = $false
        gateway_workspace_write = $false
        config_agent_access = 'NONE'
        config_gateway_read = $true
        config_gateway_write = $false
        ipc_agent_read = $true
        ipc_agent_write = $false
        ipc_gateway_read = $true
        ipc_gateway_write = $false
        kill_switch_exists = $false
        kill_switch_agent_write = $false
        kill_switch_gateway_write = $false
        demo_authorization_file_exists = $false
        demo_authorization_agent_write = $false
        demo_authorization_gateway_write = $false
        operational_gateway_modify = $true
        research_gateway_modify = $true
        audit_sqlite_gateway_modify = $true
        audit_sqlite_immutable = $false
        audit_journal_acl = 'Read,AppendData,Synchronize; no WriteData/Delete/DeleteChild/Modify/ChangePermissions/TakeOwnership'
        security_log_acl = 'Read,AppendData,Synchronize; no WriteData/Delete/DeleteChild/Modify/ChangePermissions/TakeOwnership'
        agent_state_agent_modify = $true
        agent_state_gateway_access = 'NONE'
        system_full_control = $true
        administrators_full_control = $true
        deny_aces_used = $false
    }

    $logRoot = Split-Path -Parent $ReportPath
    $python = Join-Path $workspace '.venv\Scripts\python.exe'
    Invoke-Test 'python' { & $python -m pytest -q } (Join-Path $logRoot 'acl-gate-python.log')
    Invoke-Test 'powershell_users' { & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $workspace 'tests\Test-NewTradingLabUsers.ps1') } (Join-Path $logRoot 'acl-gate-powershell-users.log')
    Invoke-Test 'powershell_acl' { & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $workspace 'tests\Test-TradingLabAcl.ps1') } (Join-Path $logRoot 'acl-gate-powershell-acl.log')
    $nodeRuntime = & (Join-Path $workspace 'scripts\Resolve-TradingLabNode.ps1')
    $previousPath = $env:Path
    try {
        $env:Path = $nodeRuntime.Root + [System.IO.Path]::PathSeparator + $previousPath
        Invoke-Test 'node_vitest' { & $nodeRuntime.Corepack pnpm@10.28.1 test } (Join-Path $logRoot 'acl-gate-node.log')
        Invoke-Test 'typecheck' { & $nodeRuntime.Corepack pnpm@10.28.1 typecheck } (Join-Path $logRoot 'acl-gate-typecheck.log')
        Invoke-Test 'build' { & $nodeRuntime.Corepack pnpm@10.28.1 build } (Join-Path $logRoot 'acl-gate-build.log')
    } finally {
        $env:Path = $previousPath
    }
    Invoke-Test 'git_diff_check' { & git -C $workspace diff --check } (Join-Path $logRoot 'acl-gate-git-diff-check.log')
    $report.git = [ordered]@{
        branch = (& git -C $workspace branch --show-current).Trim()
        head = (& git -C $workspace log -1 --format='%H %s').Trim()
        worktree = (& git -C $workspace status --porcelain=v1 | Out-String).Trim()
        push_performed = $false
    }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
} catch {
    $report.security_descriptors_applied = @(Read-AclProgressFile $progressPath)
    $report.acl_apply = Resolve-AclApplyFailureStatus `
        $report.acl_apply `
        @($report.security_descriptors_applied).Count
    $report.acl_applied = $report.acl_apply -eq 'PASS'
    $report.error = $_.Exception.Message
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
} finally {
    Write-GateReport
}

if ($null -ne $report.error) { exit 1 }
