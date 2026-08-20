#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ReportPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedTradingConfigSha256
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$expectedConfigSha256 = $ExpectedTradingConfigSha256.ToLowerInvariant()

$workspace = 'C:\automaton'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$agentState = 'C:\Users\AutomatonAgent\.automaton'
$agentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$gatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$usersSid = 'S-1-5-32-545'
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$credentialFiles = [ordered]@{
    automaton = (Join-Path $labRoot 'ipc\automaton.key')
    observation = (Join-Path $labRoot 'ipc\observation.key')
    research = (Join-Path $labRoot 'ipc\research.key')
}
$configPath = Join-Path $labRoot 'control\trading.yaml'
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
    expected_trading_config_sha256 = $expectedConfigSha256
    trading_config_sha256_before = $null
    trading_config_sha256_after = $null
    trading_config_validation_mode = 'PINNED_EXISTING_SHA256'
    semantic_config_validation_status = 'NOT_RUN'
    semantic_config_validation_state = $null
    semantic_config_helper_exit_code = $null
    maintenance_identity = $null
    maintenance_sid = $null
    paths_created = @()
    prepared_state_verified = $false
    automaton_key_created = $false
    automaton_key_reused = $false
    automaton_key_length = $null
    observation_key_created = $false
    observation_key_reused = $false
    observation_key_length = $null
    research_key_created = $false
    research_key_reused = $false
    research_key_length = $null
    credential_state_snapshots = @()
    credential_state_rollback_attempted = $false
    credential_state_rollback_succeeded = $null
    credential_state_rollback_errors = @()
    security_descriptors_applied = @()
    acl_snapshots = @()
    checks = [ordered]@{}
    tests = [ordered]@{}
    warnings = @()
    error = $null
}
. (Join-Path $PSScriptRoot 'TradingLabAclBootstrap.ps1')
. (Join-Path $PSScriptRoot 'ProtectedIdentityGateHelpers.ps1')
$aclPolicyPath = Join-Path $workspace 'config\windows-acl-policy.json'
$aclPolicy = $null
$maintenanceSid = $null
$progressPath = $ReportPath + '.acl-progress.jsonl'
$credentialRollbackSnapshots = [ordered]@{}
$credentialSnapshotsReady = $false
$bootstrapMutationStarted = $false

function Get-CanonicalPath([string] $Value) {
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        throw "Path must be absolute: $Value"
    }
    return [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Get-SafeTradingConfigSha256([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Canonical trading configuration must be an existing absolute file.'
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        (Get-CanonicalPath $item.FullName) -ne (Get-CanonicalPath $Path)) {
        throw 'Canonical trading configuration must be an exact regular non-reparse file.'
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ExpectedTradingConfigSha256([string] $Path, [string] $ExpectedSha256) {
    $actualSha256 = Get-SafeTradingConfigSha256 $Path
    if ($actualSha256 -cne $ExpectedSha256) {
        throw 'Canonical trading configuration SHA256 differs from the operator-reviewed value.'
    }
    return $actualSha256
}

function Invoke-ReviewedTradingConfigInspection([string] $ConfigPath) {
    $python = Join-Path $workspace '.venv\Scripts\python.exe'
    if ((Get-CanonicalPath $python) -ne 'C:\automaton\.venv\Scripts\python.exe' -or
        -not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'Reviewed repository Python runtime is unavailable.'
    }
    $pythonItem = Get-Item -LiteralPath $python -Force -ErrorAction Stop
    if ($pythonItem.PSIsContainer -or
        ($pythonItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Reviewed repository Python runtime path is unsafe.'
    }
    $helperResult = Invoke-ProtectedIdentityHelperProcess `
        -Operation 'inspect' `
        -Stage 'INSPECT' `
        -Executable $python `
        -Arguments "-B -m trading_lab.protected_identity_config inspect --config `"$ConfigPath`"" `
        -WorkingDirectory $workspace `
        -SensitiveValues @('10012236003')
    $report.semantic_config_helper_exit_code = [int]$helperResult.exit_code
    if (-not $helperResult.succeeded) {
        throw 'Protected configuration inspection failed closed.'
    }
    try {
        return ([string]$helperResult.raw_stdout).Trim() | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'Protected configuration inspection returned invalid JSON.'
    }
}

function Assert-ReviewedTradingConfigInspection($Inspection, [string] $ExpectedSha256) {
    if ([string]$Inspection.status -ne 'PASS' -or
        [string]$Inspection.state -ne 'EXACT_TARGET' -or
        -not [bool]$Inspection.candidate_schema_validated -or
        [string]$Inspection.source_sha256 -cne $ExpectedSha256 -or
        [string]$Inspection.candidate_sha256 -cne $ExpectedSha256 -or
        [string]$Inspection.target.trading_mode -ne 'OBSERVE_ONLY' -or
        [bool]$Inspection.target.mt5_access_enabled -ne $false -or
        [int64]$Inspection.target.authorized_account -ne 10012236003L -or
        [string]$Inspection.target.authorized_server -cne 'MetaQuotes-Demo' -or
        [string]$Inspection.target.allowed_symbol -cne 'XAUUSD' -or
        [string]$Inspection.target.mt5_terminal_path -cne 'C:\Program Files\MetaTrader 5\terminal64.exe') {
        throw 'Protected configuration inspection does not match the exact reviewed target.'
    }
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

function Get-CredentialRollbackSnapshot([string] $Name, [string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            name = $Name
            path = $Path
            existed_before = $false
            sha256_before = $null
            acl_sddl_before = $null
            acl_object = $null
        }
    }
    [void](Assert-ValidIpcSecret $Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{
        name = $Name
        path = $Path
        existed_before = $true
        sha256_before = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        acl_sddl_before = $acl.Sddl
        acl_object = $acl
    }
}

function Invoke-CredentialStateRollback {
    $report.credential_state_rollback_attempted = $true
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($snapshot in $credentialRollbackSnapshots.Values) {
        try {
            if ($snapshot.existed_before) {
                [void](Assert-ValidIpcSecret $snapshot.path)
                $currentHash = (Get-FileHash -LiteralPath $snapshot.path -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($currentHash -ne $snapshot.sha256_before) {
                    throw 'Pre-existing credential content changed; refusing content rollback.'
                }
                $currentAcl = Get-Acl -LiteralPath $snapshot.path -ErrorAction Stop
                if ($currentAcl.Sddl -ne $snapshot.acl_sddl_before) {
                    Set-Acl -LiteralPath $snapshot.path -AclObject $snapshot.acl_object -ErrorAction Stop
                }
                $verifiedAcl = Get-Acl -LiteralPath $snapshot.path -ErrorAction Stop
                $verifiedHash = (Get-FileHash -LiteralPath $snapshot.path -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($verifiedAcl.Sddl -ne $snapshot.acl_sddl_before -or
                    $verifiedHash -ne $snapshot.sha256_before) {
                    throw 'Pre-existing credential rollback verification failed.'
                }
                continue
            }

            if (-not (Test-Path -LiteralPath $snapshot.path)) { continue }
            if (@($report.paths_created) -notcontains $snapshot.path) {
                throw 'Credential was not proven to have been created by this gate; refusing deletion.'
            }
            [void](Assert-ValidIpcSecret $snapshot.path)
            [System.IO.File]::Delete($snapshot.path)
            if (Test-Path -LiteralPath $snapshot.path) {
                throw 'Created credential remained after rollback.'
            }
        } catch {
            $errors.Add("$($snapshot.name): $($_.Exception.Message)")
        }
    }
    $report.credential_state_rollback_errors = @($errors)
    $report.credential_state_rollback_succeeded = $errors.Count -eq 0
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

function Test-ExactAclRule(
    $Rule,
    [string] $Sid,
    [int64] $Rights,
    [bool] $Inherited,
    [string] $InheritanceFlags,
    [string] $PropagationFlags
) {
    $synchronize = [int64][System.Security.AccessControl.FileSystemRights]::Synchronize
    $actualRights = [int64]$Rule.rights
    $expectedRights = [int64]$Rights
    if ($Rule.type -eq 'Allow') {
        $actualRights = $actualRights -bor $synchronize
        $expectedRights = $expectedRights -bor $synchronize
    }
    return $Rule.sid -eq $Sid -and $Rule.type -eq 'Allow' -and
        $actualRights -eq $expectedRights -and [bool]$Rule.inherited -eq $Inherited -and
        $Rule.inheritance_flags -eq $InheritanceFlags -and
        $Rule.propagation_flags -eq $PropagationFlags
}

function Assert-ExactControlDirectoryAcl($Snapshot) {
    Assert-RecoveryAndOwner $Snapshot
    if (@($Snapshot.rules).Count -ne 3) {
        throw 'Control directory must contain exactly three canonical ACEs.'
    }
    $expected = @(
        [pscustomobject]@{ Sid = $systemSid; Rights = $fullControl; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = $fullControl; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' },
        [pscustomobject]@{ Sid = $gatewaySid; Rights = $readExecuteRights; Inheritance = 'None'; Propagation = 'None' }
    )
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Snapshot.rules) { $remaining.Add($rule) }
    foreach ($item in $expected) {
        $match = @($remaining | Where-Object {
            Test-ExactAclRule $_ $item.Sid ([int64]$item.Rights) $false $item.Inheritance $item.Propagation
        } | Select-Object -First 1)
        if ($match.Count -ne 1) { throw 'Control directory ACL is not canonical.' }
        [void]$remaining.Remove($match[0])
    }
}

function Assert-ExactAuthorizationDirectoryAcl($Snapshot) {
    Assert-RecoveryAndOwner $Snapshot
    if (@($Snapshot.rules).Count -ne 4) {
        throw 'Authorization directory must contain exactly four canonical ACEs.'
    }
    $expected = @(
        [pscustomobject]@{ Sid = $systemSid; Rights = $fullControl; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = $fullControl; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' },
        [pscustomobject]@{ Sid = $gatewaySid; Rights = $readExecuteRights; Inheritance = 'None'; Propagation = 'None' },
        [pscustomobject]@{ Sid = $gatewaySid; Rights = $readRights; Inheritance = 'ObjectInherit'; Propagation = 'InheritOnly' }
    )
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Snapshot.rules) { $remaining.Add($rule) }
    foreach ($item in $expected) {
        $match = @($remaining | Where-Object {
            Test-ExactAclRule $_ $item.Sid ([int64]$item.Rights) $false $item.Inheritance $item.Propagation
        } | Select-Object -First 1)
        if ($match.Count -ne 1) { throw 'Authorization directory ACL is not canonical.' }
        [void]$remaining.Remove($match[0])
    }
    if ((Get-AllowRights $Snapshot $agentSid) -ne 0 -or
        ((Get-AllowRights $Snapshot $gatewaySid) -band $writeOrSecurityRights) -ne 0) {
        throw 'Authorization directory grants forbidden Agent or Gateway mutation rights.'
    }
}

function Assert-ExactAuthorizationArtifactAcl($Snapshot) {
    if ($Snapshot.owner_sid -ne $administratorsSid -or $Snapshot.inheritance_protected) {
        throw "Authorization artifact owner/inheritance mismatch: $($Snapshot.path)"
    }
    if (@($Snapshot.rules).Count -ne 3) {
        throw "Authorization artifact ACE count mismatch: $($Snapshot.path)"
    }
    foreach ($item in @(
        [pscustomobject]@{ Sid = $systemSid; Rights = $fullControl },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = $fullControl },
        [pscustomobject]@{ Sid = $gatewaySid; Rights = $readRights }
    )) {
        $match = @($Snapshot.rules | Where-Object {
            Test-ExactAclRule $_ $item.Sid ([int64]$item.Rights) $true 'None' 'None'
        })
        if ($match.Count -ne 1) { throw "Authorization artifact inherited ACL mismatch: $($Snapshot.path)" }
    }
    if ((Get-AllowRights $Snapshot $agentSid) -ne 0 -or
        ((Get-AllowRights $Snapshot $gatewaySid) -band $writeOrSecurityRights) -ne 0) {
        throw "Authorization artifact grants forbidden Agent or Gateway mutation rights: $($Snapshot.path)"
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
    # Pin both bytes and reviewed semantics before credential snapshots or any
    # filesystem/ACL mutation.  The helper does not import or access MT5.
    $report.trading_config_sha256_before = Assert-ExpectedTradingConfigSha256 `
        $configPath $expectedConfigSha256
    $configInspection = Invoke-ReviewedTradingConfigInspection $configPath
    Assert-ReviewedTradingConfigInspection $configInspection $expectedConfigSha256
    $report.semantic_config_validation_status = [string]$configInspection.status
    $report.semantic_config_validation_state = [string]$configInspection.state
    $report.account_configured = $true

    # Validate every existing credential only after the pinned operational
    # configuration has passed both byte and semantic validation.
    foreach ($credentialEntry in $credentialFiles.GetEnumerator()) {
        $snapshot = Get-CredentialRollbackSnapshot $credentialEntry.Key $credentialEntry.Value
        $credentialRollbackSnapshots[$credentialEntry.Key] = $snapshot
    }
    $credentialSnapshotsReady = $true
    $report.credential_state_snapshots = @($credentialRollbackSnapshots.Values | ForEach-Object {
        [ordered]@{
            name = $_.name
            path = $_.path
            existed_before = $_.existed_before
            acl_sddl_before = $_.acl_sddl_before
        }
    })
    $report.acl_prevalidation = 'PASS'
    Write-GateReport

    $bootstrapMutationStarted = $true
    $prepared = Initialize-TradingLabBootstrapState `
        $labRoot `
        $agentState `
        $template `
        -ExpectedExistingConfigSha256 $expectedConfigSha256
    $report.paths_created = @($prepared.created_paths)
    $report.prepared_state_verified = $true
    if ($prepared.config_validation_mode -ne 'PINNED_EXISTING_SHA256' -or
        [string]$prepared.config_sha256 -cne $expectedConfigSha256 -or
        $prepared.config_created -or -not $prepared.config_reused) {
        throw 'Bootstrap did not preserve the pinned existing configuration contract.'
    }
    [void](Assert-ExpectedTradingConfigSha256 $configPath $expectedConfigSha256)
    $report.automaton_key_created = [bool]$prepared.automaton_key_created
    $report.automaton_key_reused = [bool]$prepared.automaton_key_reused
    $report.automaton_key_length = [int]$prepared.automaton_key_length
    $report.observation_key_created = [bool]$prepared.observation_key_created
    $report.observation_key_reused = [bool]$prepared.observation_key_reused
    $report.observation_key_length = [int]$prepared.observation_key_length
    $report.research_key_created = [bool]$prepared.research_key_created
    $report.research_key_reused = [bool]$prepared.research_key_reused
    $report.research_key_length = [int]$prepared.research_key_length
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
        -ExpectedExistingConfigSha256 $expectedConfigSha256 `
        -Apply | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Initialize-TradingLabAcl.ps1 failed with exit code $LASTEXITCODE."
    }
    $report.acl_apply = 'PASS'
    $report.acl_applied = $true
    $report.security_descriptors_applied = @(Read-AclProgressFile $progressPath)
    [void](Assert-ExpectedTradingConfigSha256 $configPath $expectedConfigSha256)
    Write-GateReport

    $targets = [ordered]@{
        workspace = $workspace
        programdata = $labRoot
        control = (Join-Path $labRoot 'control')
        config = $configPath
        demo_authorization = (Join-Path $labRoot 'control\demo-authorization')
        ipc = (Join-Path $labRoot 'ipc')
        automaton_key = $credentialFiles.automaton
        observation_key = $credentialFiles.observation
        research_key = $credentialFiles.research
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

    Assert-ExactControlDirectoryAcl $snapshots.control
    Assert-ExactAuthorizationDirectoryAcl $snapshots.demo_authorization
    $authorizationArtifacts = @()
    foreach ($artifact in @(Get-ChildItem -LiteralPath $targets.demo_authorization -Force)) {
        if ($artifact.PSIsContainer -or
            $artifact.Name -cnotmatch '^mt5-read-only-authorization-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$' -or
            ($artifact.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected authorization artifact: $($artifact.FullName)"
        }
        $artifactSnapshot = Get-AclSnapshot $artifact.FullName "authorization_artifact_$($artifact.Name)"
        Assert-ExactAuthorizationArtifactAcl $artifactSnapshot
        $authorizationArtifacts += $artifactSnapshot
    }

    Assert-NoUnexpectedAllow $snapshots.workspace @($systemSid, $administratorsSid, $gatewaySid, $agentSid)
    Assert-NoUnexpectedAllow $snapshots.programdata @($systemSid, $administratorsSid, $maintenanceSid, $gatewaySid, $agentSid)
    foreach ($name in @('control', 'config', 'research', 'audit_sqlite', 'audit_journal_directory', 'audit_journal', 'security_log')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $gatewaySid)
    }
    foreach ($name in @('operational', 'logs', 'gateway_logs', 'security_logs_directory')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $maintenanceSid, $gatewaySid)
        Assert-ExactMaintenanceAllow $snapshots[$name]
    }
    foreach ($name in @('ipc', 'observation_key', 'research_key')) {
        Assert-NoUnexpectedAllow $snapshots[$name] @($systemSid, $administratorsSid, $gatewaySid, $agentSid)
    }
    Assert-NoUnexpectedAllow $snapshots.automaton_key @($systemSid, $administratorsSid, $gatewaySid)
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

    $automatonGatewayRights = Get-AllowRights $snapshots.automaton_key $gatewaySid
    if (($automatonGatewayRights -band $readRights) -ne $readRights -or
        ($automatonGatewayRights -band $writeOrSecurityRights) -ne 0 -or
        (Get-AllowRights $snapshots.automaton_key $agentSid) -ne 0) {
        throw 'Automaton IPC key rights mismatch.'
    }
    foreach ($keyName in @('observation_key', 'research_key')) {
        foreach ($principalSid in @($agentSid, $gatewaySid)) {
            $keyRights = Get-AllowRights $snapshots[$keyName] $principalSid
            if (($keyRights -band $readRights) -ne $readRights -or
                ($keyRights -band $writeOrSecurityRights) -ne 0) {
                throw "Shared IPC key rights mismatch: $keyName"
            }
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
    $report.acl_snapshots = @($snapshots.Values) + @($authorizationArtifacts)
    $report.checks = [ordered]@{
        workspace_authenticated_users_modify = $authenticatedUsersModify
        agent_workspace_write = $false
        gateway_workspace_write = $false
        config_agent_access = 'NONE'
        config_gateway_read = $true
        config_gateway_write = $false
        automaton_key_agent_read = $false
        automaton_key_gateway_read = $true
        observation_key_agent_read = $true
        observation_key_gateway_read = $true
        research_key_agent_read = $true
        research_key_gateway_read = $true
        ipc_agent_write = $false
        ipc_gateway_write = $false
        kill_switch_exists = $false
        kill_switch_agent_write = $false
        kill_switch_gateway_write = $false
        demo_authorization_artifact_pattern = 'mt5-read-only-authorization-<UUID>.json'
        demo_authorization_artifact_count = @($authorizationArtifacts).Count
        demo_authorization_artifacts_verified = $true
        demo_authorization_legacy_authorization_json_absent = $true
        demo_authorization_agent_access = 'NONE'
        demo_authorization_gateway_read = $true
        demo_authorization_gateway_mutation = $false
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
    $report.trading_config_sha256_after = Assert-ExpectedTradingConfigSha256 `
        $configPath $expectedConfigSha256
    if ($report.trading_config_sha256_before -cne $expectedConfigSha256 -or
        $report.trading_config_sha256_after -cne $expectedConfigSha256) {
        throw 'Canonical trading configuration did not remain byte-identical throughout the ACL gate.'
    }
    $report.git = [ordered]@{
        branch = (& git -C $workspace branch --show-current).Trim()
        head = (& git -C $workspace log -1 --format='%H %s').Trim()
        worktree = (& git -C $workspace status --porcelain=v1 | Out-String).Trim()
        push_performed = $false
    }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
} catch {
    $primaryError = $_.Exception.Message
    if ($null -ne $configPath) {
        try {
            $report.trading_config_sha256_after = Get-SafeTradingConfigSha256 $configPath
        } catch { }
    }
    if ($credentialSnapshotsReady -and $bootstrapMutationStarted) {
        Invoke-CredentialStateRollback
    }
    $report.security_descriptors_applied = @(Read-AclProgressFile $progressPath)
    $report.acl_apply = Resolve-AclApplyFailureStatus `
        $report.acl_apply `
        @($report.security_descriptors_applied).Count
    $report.acl_applied = $report.acl_apply -eq 'PASS'
    if ($report.credential_state_rollback_succeeded -eq $false) {
        $report.error = "$primaryError Credential state rollback failed: $($report.credential_state_rollback_errors -join '; ')"
    } else {
        $report.error = $primaryError
    }
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
} finally {
    Write-GateReport
}

if ($null -ne $report.error) { exit 1 }
