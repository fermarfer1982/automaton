#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'PrepareWheelhouse', 'UninstallTraditional', 'InstallMachineRuntime', 'ResumeMachineRuntime', 'BuildVenv', 'PromoteVenv')]
    [string] $Phase = 'Inventory',
    [string] $InstallerPath = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe',
    [string] $RegisteredBundlePath,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $GatewayPythonBaseRunId,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $AgentPythonBaseRunId,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$venvPath = Join-Path $workspace '.venv'
$stagingVenvPath = Join-Path $workspace '.venv.new'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$maintenanceRoot = Join-Path $labRoot 'maintenance'
$logsRoot = Join-Path $maintenanceRoot 'logs'
$wheelhousePath = Join-Path $maintenanceRoot 'wheelhouse\cp314-win_amd64'
$pythonBase = 'C:\Program Files\AutomatonPython\3.14.5'
$basePython = Join-Path $pythonBase 'python.exe'
$lockPath = Join-Path $workspace 'requirements-gateway-win-py314.lock'
$expectedPythonVersion = '3.14.5'
$expectedInstallerName = 'python-3.14.5-amd64.exe'
$expectedInstallerLength = 30361968L
$expectedInstallerSha256 = 'f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d'
$expectedRegisteredBundleSha256 = '693522e3a8a747926a2f1f5a013b07315ac9472657d691b8f152fb6438b81723'
$expectedLockSha256 = '68d14ddc9d943079e8f791bb8f276ae630f46c8ee8997b2bf2afeabed1e30d99'
$expectedWheelRequirementCount = 27
$expectedTraditionalBundleId = '{2FC382FA-68A9-44F7-8851-98D7664255E6}'
$expectedManagerRegistryId = 'pymanager-pythoncore-3.14-64'
$expectedTraditionalMsiComponents = @(
    [pscustomobject]@{ product_code = '{1B0251E9-CD20-49FC-AD22-70FCDBC2BAD7}'; display_name = 'Python 3.14.5 Executables (64-bit)' },
    [pscustomobject]@{ product_code = '{4B0FBDDD-D38E-48FF-A686-1A27792E66F9}'; display_name = 'Python 3.14.5 Tcl/Tk Support (64-bit)' },
    [pscustomobject]@{ product_code = '{59989632-5855-479A-A589-433911625C16}'; display_name = 'Python 3.14.5 Development Libraries (64-bit)' },
    [pscustomobject]@{ product_code = '{7040E6D8-53FD-4FE0-A539-92C0B33E9A10}'; display_name = 'Python 3.14.5 pip Bootstrap (64-bit)' },
    [pscustomobject]@{ product_code = '{A0B65FCB-97C6-47FD-984A-9EF9ECC1CE3B}'; display_name = 'Python 3.14.5 Standard Library (64-bit)' },
    [pscustomobject]@{ product_code = '{E402961E-7539-41B4-ADA9-62143E6D32D7}'; display_name = 'Python 3.14.5 Core Interpreter (64-bit)' },
    [pscustomobject]@{ product_code = '{EDE01DCA-6375-4140-A590-B2FA5948D01D}'; display_name = 'Python 3.14.5 Documentation (64-bit)' },
    [pscustomobject]@{ product_code = '{F479F658-E4C4-4A61-8DB6-3E66633FBFFF}'; display_name = 'Python 3.14.5 Test Suite (64-bit)' },
    [pscustomobject]@{ product_code = '{F689BE51-4D7A-47E9-A4DF-1C42528856E7}'; display_name = 'Python 3.14.5 Add to Path (64-bit)' }
)
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$usersSid = 'S-1-5-32-545'
$authenticatedUsersSid = 'S-1-5-11'
$everyoneSid = 'S-1-1-0'
$agentSid = 'S-1-5-21-568964486-193631783-1609210587-1006'
$gatewaySid = 'S-1-5-21-568964486-193631783-1609210587-1007'
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$gatewayReadExecute = $readExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
$runId = [guid]::NewGuid().ToString('D').ToLowerInvariant()
$reportDirectory = Join-Path $maintenanceRoot 'python-runtime-results'
$reportPath = Join-Path $reportDirectory "python-runtime-$runId.json"
$report = [ordered]@{
    schema_version = 3
    run_id = $runId
    phase = $Phase
    apply_requested = [bool]$Apply
    status = 'PREVALIDATING'
    trading_mode = 'OBSERVE_ONLY'
    python_version = $expectedPythonVersion
    python_base = $pythonBase
    active_venv = $venvPath
    staging_venv = $stagingVenvPath
    wheelhouse = $wheelhousePath
    lock_file = $lockPath
    installer = $InstallerPath
    installer_executed = $false
    installer_reexecuted = $false
    uninstaller_executed = $false
    venv_rebuilt = $false
    venv_promoted = $false
    staging_venv_created = $false
    staging_build_failed = $false
    staging_left_for_inspection = $false
    active_venv_modified = $false
    active_venv_deleted = $false
    active_venv_renamed = $false
    active_venv_executed = $false
    current_run_applied_phase = 'NONE'
    required_previous_phase = $null
    previous_phase_verified = $false
    previous_phase_report = $null
    previous_phase_report_sha256 = $null
    gateway_python_base_run_id = $GatewayPythonBaseRunId
    gateway_python_base_report = $null
    gateway_python_base_report_sha256 = $null
    agent_python_base_run_id = $AgentPythonBaseRunId
    agent_python_base_report = $null
    agent_python_base_report_sha256 = $null
    old_venv_backup = $null
    mt5_accessed = $false
    mt5_package_installed = $false
    mt5_imported = $false
    order_check_called = $false
    order_send_called = $false
    automaton_started = $false
    gateway_started = $false
    acl_existing_domains_modified = $false
    acl_modified = $false
    machine_runtime_acl_modified = $false
    acl_apply_requested = $false
    acl_applied = $false
    acl_reapplied = $false
    must_not_call_set_acl = $false
    set_acl_call_count = 0
    acl_plan = $null
    acl_recursive_audit = $null
    must_not_execute_installer = $false
    recovery_state = $null
    installer_result_log = $null
    installer_result_log_sha256 = $null
    gates = [ordered]@{}
    inventory_before = $null
    inventory_after = $null
    python_manager_preserve_path = $null
    traditional_bundle_target = $null
    traditional_bundle_uninstaller = $null
    traditional_msi_components = @()
    wheelhouse_validation = $null
    runtime_verification = $null
    build_venv_plan = $null
    post_build_validation_plan = $null
    post_build_validation = $null
    uninstall_plan = $null
    installer_plan = $null
    error = $null
}

. (Join-Path $PSScriptRoot 'TradingLabPythonInventory.ps1')
. (Join-Path $PSScriptRoot 'TradingLabBuildVenvGate.ps1')
. (Join-Path $PSScriptRoot 'TradingLabPythonAclPlan.ps1')
. (Join-Path $PSScriptRoot 'TradingLabFileSystemRights.ps1')

function Get-CanonicalPath([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) { throw "Path must be absolute: $Path" }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-PathWithin([string] $Path, [string] $Root) {
    $candidate = Get-CanonicalPath $Path
    $canonicalRoot = Get-CanonicalPath $Root
    return $candidate.Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($canonicalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-OutsideUserProfiles([string] $Path, [string] $Label) {
    if (Test-PathWithin $Path (Join-Path $env:SystemDrive 'Users')) {
        throw "$Label must not be located under a Windows user profile."
    }
}

function Assert-NoReparseComponents([string] $Path) {
    $current = Get-CanonicalPath $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point rejected in trusted path: $current"
            }
        }
        $parent = Split-Path $current -Parent
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function Resolve-IdentitySid([object] $Identity) {
    try {
        $reference = if ($Identity -is [System.Security.Principal.IdentityReference]) {
            $Identity
        } else {
            [System.Security.Principal.NTAccount]::new([string]$Identity)
        }
        return $reference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return 'UNRESOLVED:' + [string]$Identity }
}

function Get-DirectLocalGroupSids([System.Security.Principal.SecurityIdentifier] $UserSid) {
    $groups = [System.Collections.Generic.List[string]]::new()
    foreach ($group in Get-LocalGroup) {
        $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
        if ($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $UserSid.Value }) {
            $groups.Add($group.SID.Value)
        }
    }
    return @($groups)
}

function Assert-ExactServiceIdentity([string] $Name, [string] $ExpectedSid) {
    $user = Get-LocalUser -Name $Name -ErrorAction Stop
    $groups = @(Get-DirectLocalGroupSids $user.SID)
    if (
        $user.SID.Value -ne $ExpectedSid -or -not $user.Enabled -or
        $user.PrincipalSource.ToString() -ne 'Local' -or
        $groups.Count -ne 1 -or $groups[0] -ne $usersSid
    ) { throw "$Name failed exact SID/enabled/local/Users-only prevalidation." }
}

function Assert-NoUntrustedModify([string] $Path, [string[]] $ProtectedSids) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = Resolve-IdentitySid $rule.IdentityReference
        if ($sid -in $ProtectedSids -and (Test-TradingLabFileSystemRightsMutation ([int64]$rule.FileSystemRights))) {
            throw "Untrusted principal has Modify-equivalent rights on ${Path}: $sid"
        }
    }
}

function Assert-TreeNotModifiableByServices([string] $Root) {
    $protected = @($gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid)
    Assert-NoReparseComponents $Root
    foreach ($item in @((Get-Item -LiteralPath $Root -Force)) + @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop
    )) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Runtime tree contains a reparse point: $($item.FullName)"
        }
        Assert-NoUntrustedModify $item.FullName $protected
    }
}

function Resolve-ExactIdentityName([string] $Sid) {
    try {
        $securityIdentifier = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        $account = $securityIdentifier.Translate([System.Security.Principal.NTAccount])
        $roundTrip = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($roundTrip -ne $Sid) { throw 'SID round-trip mismatch.' }
        return $account.Value
    } catch { throw "ACL_IDENTITY_UNRESOLVED=FAIL: $Sid" }
}

function Assert-ExactRuntimeTarget([string] $Root) {
    $canonical = Get-CanonicalPath $Root
    if (-not $canonical.Equals((Get-CanonicalPath $pythonBase), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ACL_TARGET_ONLY=FAIL: $canonical"
    }
    if (-not (Test-Path -LiteralPath $canonical -PathType Container)) {
        throw 'ACL_TARGET_ONLY=FAIL: exact runtime target is absent.'
    }
    Assert-NoReparseComponents $canonical
    return $canonical
}

function Get-ExactRuntimeTreeSnapshot([string] $Root) {
    $canonicalRoot = Assert-ExactRuntimeTarget $Root
    $snapshot = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($canonicalRoot)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "REPARSE_POINT_FAIL_CLOSED: $($item.FullName)"
        }
        $canonicalItem = Get-CanonicalPath $item.FullName
        if (-not (Test-PathWithin $canonicalItem $canonicalRoot)) {
            throw "ACL_TARGET_CONFINEMENT=FAIL: $canonicalItem"
        }
        $snapshot.Add([pscustomobject]@{ path = $canonicalItem; is_directory = [bool]$item.PSIsContainer })
        if (-not $item.PSIsContainer) { continue }
        foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($canonicalItem)) {
            $child = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
            if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "REPARSE_POINT_FAIL_CLOSED: $($child.FullName)"
            }
            $canonicalChild = Get-CanonicalPath $child.FullName
            if (-not (Test-PathWithin $canonicalChild $canonicalRoot)) {
                throw "ACL_TARGET_CONFINEMENT=FAIL: $canonicalChild"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($canonicalChild) }
            else { $snapshot.Add([pscustomobject]@{ path = $canonicalChild; is_directory = $false }) }
        }
    }
    return @($snapshot)
}

function New-MachineRuntimeAclPlan([string] $Target) {
    $canonicalTarget = Assert-ExactRuntimeTarget $Target
    $tree = @(Get-ExactRuntimeTreeSnapshot $canonicalTarget)
    $systemName = Resolve-ExactIdentityName $systemSid
    $administratorsName = Resolve-ExactIdentityName $administratorsSid
    $gatewayName = Resolve-ExactIdentityName $gatewaySid
    [pscustomobject][ordered]@{
        target = $canonicalTarget
        owner = $administratorsName
        owner_sid = $administratorsSid
        protect_inheritance = $true
        remove_inherited_aces = $true
        target_tree_reparse_points = 0
        validated_tree_item_count = $tree.Count
        entries = @(
            [pscustomobject][ordered]@{ identity = $systemName; sid = $systemSid; rights = 'FullControl'; rights_value = [int64]$fullControl; type = 'Allow' },
            [pscustomobject][ordered]@{ identity = $administratorsName; sid = $administratorsSid; rights = 'FullControl'; rights_value = [int64]$fullControl; type = 'Allow' },
            [pscustomobject][ordered]@{ identity = $gatewayName; sid = $gatewaySid; rights = 'ReadAndExecute,Synchronize'; rights_value = [int64]$gatewayReadExecute; type = 'Allow' }
        )
        automaton_agent_effective_access = 'NONE'
        authenticated_users_modify = $false
        users_modify = $false
        deny_aces_planned = 0
        other_domains_modified = $false
    }
}

function Assert-MachineRuntimeAclPlan([object] $Plan) {
    $state = Test-TradingLabRuntimeAclPlan $Plan $pythonBase `
        $systemSid $administratorsSid $gatewaySid $agentSid `
        $authenticatedUsersSid $usersSid ([int64]$fullControl) ([int64]$gatewayReadExecute)
    if (-not $state.valid) { throw "ACL_PLAN=FAIL: $($state.failures -join ';')" }
}

function Set-MachineRuntimeAclPlanGates([object] $Plan) {
    Assert-MachineRuntimeAclPlan $Plan
    $report.acl_plan = $Plan
    $report.gates.ACL_TARGET_ONLY = 'PASS'
    $report.gates.ACL_OWNER_ADMINISTRATORS_PLANNED = 'PASS'
    $report.gates.ACL_INHERITANCE_PROTECTED_PLANNED = 'PASS'
    $report.gates.SYSTEM_FULLCONTROL_PLANNED = 'PASS'
    $report.gates.ADMINISTRATORS_FULLCONTROL_PLANNED = 'PASS'
    $report.gates.GATEWAY_READ_EXECUTE_PLANNED = 'PASS'
    $report.gates.GATEWAY_WRITE_ABSENT_PLANNED = 'PASS'
    $report.gates.GATEWAY_MODIFY_ABSENT_PLANNED = 'PASS'
    $report.gates.GATEWAY_DELETE_ABSENT_PLANNED = 'PASS'
    $report.gates.GATEWAY_CHANGE_PERMISSIONS_ABSENT_PLANNED = 'PASS'
    $report.gates.GATEWAY_TAKE_OWNERSHIP_ABSENT_PLANNED = 'PASS'
    $report.gates.AGENT_ACCESS_ABSENT_PLANNED = 'PASS'
    $report.gates.AUTHENTICATED_USERS_MODIFY_ABSENT_PLANNED = 'PASS'
    $report.gates.USERS_MODIFY_ABSENT_PLANNED = 'PASS'
    $report.gates.DENY_ACES_PLANNED = 0
    $report.gates.ACL_OTHER_DOMAINS_MODIFIED = 'false'
}

function New-ExactRuntimeSecurity([bool] $Directory, [object] $Plan) {
    Assert-MachineRuntimeAclPlan $Plan
    return New-TradingLabRuntimeSecurityDescriptor $Directory $Plan
}

function Assert-InMemoryRuntimeSecurity([object] $Security, [object] $Plan) {
    $entries = @($Security.GetAccessRules(
        $true, $false, [System.Security.Principal.SecurityIdentifier]
    ) | ForEach-Object {
        [pscustomobject]@{
            identity = $_.IdentityReference.Value
            sid = $_.IdentityReference.Value
            rights_value = [int64]$_.FileSystemRights
            type = $_.AccessControlType.ToString()
        }
    })
    $materialized = [pscustomobject]@{
        target = $Plan.target
        owner = $Plan.owner
        owner_sid = $Security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        protect_inheritance = [bool]$Security.AreAccessRulesProtected
        remove_inherited_aces = $true
        target_tree_reparse_points = 0
        entries = $entries
        automaton_agent_effective_access = 'NONE'
        authenticated_users_modify = $false
        users_modify = $false
        deny_aces_planned = @($entries | Where-Object { $_.type -eq 'Deny' }).Count
        other_domains_modified = $false
    }
    Assert-MachineRuntimeAclPlan $materialized
}

function Protect-ExactRuntimeTree([string] $Root, [object] $Plan) {
    $canonicalRoot = Assert-ExactRuntimeTarget $Root
    Assert-MachineRuntimeAclPlan $Plan
    if (-not (Get-CanonicalPath ([string]$Plan.target)).Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'ACL_TARGET_ONLY=FAIL: plan and apply target differ.'
    }

    # Materialize and validate both descriptors, and snapshot the complete tree,
    # before the first filesystem ACL mutation.
    $directorySecurity = New-ExactRuntimeSecurity $true $Plan
    $fileSecurity = New-ExactRuntimeSecurity $false $Plan
    Assert-InMemoryRuntimeSecurity $directorySecurity $Plan
    Assert-InMemoryRuntimeSecurity $fileSecurity $Plan
    $snapshot = @(Get-ExactRuntimeTreeSnapshot $canonicalRoot)

    foreach ($entry in @($snapshot | Where-Object { $_.path -ne $canonicalRoot })) {
        $item = Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint -or
            -not (Test-PathWithin $item.FullName $canonicalRoot)) {
            throw "ACL_APPLY_TARGET_CHANGED=FAIL: $($item.FullName)"
        }
        $report.set_acl_call_count++
        Set-Acl -LiteralPath $item.FullName -AclObject $(if ($entry.is_directory) { $directorySecurity } else { $fileSecurity })
    }
    $report.set_acl_call_count++
    Set-Acl -LiteralPath $canonicalRoot -AclObject $directorySecurity
}

function New-AdministrativeMaintenanceSecurity([bool] $Directory) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else { [System.Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new($administratorsSid))
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($systemSid, $administratorsSid)) {
        [void]$security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid), $fullControl,
            $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $security
}

function Protect-AdministrativeMaintenanceTree([string] $Root) {
    Assert-NoReparseComponents $Root
    $items = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Maintenance tree contains a reparse point: $($item.FullName)"
        }
        Set-Acl -LiteralPath $item.FullName -AclObject (New-AdministrativeMaintenanceSecurity $item.PSIsContainer)
    }
    Set-Acl -LiteralPath $Root -AclObject (New-AdministrativeMaintenanceSecurity $true)
}

function Get-MachineRuntimeAclAudit([string] $Root) {
    $auditItems = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @(Get-ExactRuntimeTreeSnapshot $Root)) {
        $acl = Get-Acl -LiteralPath $item.path -ErrorAction Stop
        $rules = @($acl.Access | ForEach-Object {
            [pscustomobject]@{
                sid = Resolve-IdentitySid $_.IdentityReference
                rights = [int64]$_.FileSystemRights
                type = $_.AccessControlType.ToString()
                inherited = [bool]$_.IsInherited
            }
        })
        $auditItems.Add([pscustomobject]@{
            path = $item.path
            is_directory = $item.is_directory
            is_reparse_point = $false
            owner_sid = Resolve-IdentitySid $acl.Owner
            inheritance_protected = [bool]$acl.AreAccessRulesProtected
            rules = $rules
        })
    }
    return Test-TradingLabRuntimeAclAudit @($auditItems) $pythonBase `
        $systemSid $administratorsSid $gatewaySid $agentSid `
        ([int64]$fullControl) ([int64]$gatewayReadExecute)
}

function Assert-ExactBaseAcl([string] $Root) {
    $audit = Get-MachineRuntimeAclAudit $Root
    if (-not $audit.valid) {
        throw "PYTHON_RUNTIME_ACL=FAIL: $(@($audit.findings | Select-Object -First 5) -join ';')"
    }
    return $audit
}

function Assert-Installer([string] $Path) {
    $canonical = Get-CanonicalPath $Path
    Assert-OutsideUserProfiles $canonical 'Python installer'
    Assert-NoReparseComponents $canonical
    if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) {
        throw "Verified full Python installer is absent: $canonical"
    }
    $item = Get-Item -LiteralPath $canonical -Force
    $hash = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash.ToLowerInvariant()
    $signature = Get-AuthenticodeSignature -LiteralPath $canonical
    $artifact = Resolve-TradingLabInstallerArtifactState `
        $item.Name $item.Length $hash ([string]$signature.Status) `
        $(if ($null -eq $signature.SignerCertificate) { '' } else { $signature.SignerCertificate.Subject }) `
        $expectedInstallerName $expectedInstallerLength $expectedInstallerSha256
    if (-not $artifact.size_valid) { throw 'PYTHON_INSTALLER_SIZE=FAIL: name/length differs from the reviewed full offline artifact.' }
    if (-not $artifact.hash_valid) { throw "PYTHON_INSTALLER_SHA256=FAIL: $hash" }
    if (-not $artifact.authenticode_valid) { throw 'PYTHON_INSTALLER_AUTHENTICODE=FAIL: signature is not valid for Python Software Foundation.' }
    Assert-NoUntrustedModify $canonical @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    return $canonical
}

function Assert-DependencyLock {
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Hash-locked Gateway requirements are absent.'
    }
    $hash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $expectedLockSha256) { throw "Gateway dependency lock SHA-256 mismatch: $hash" }
    $text = [System.IO.File]::ReadAllText($lockPath, [System.Text.Encoding]::UTF8)
    foreach ($required in @(
        '--only-binary=:all:', '--require-hashes',
        'MetaTrader5==5.0.6090 --hash=sha256:', 'numpy==2.5.2 --hash=sha256:',
        'fastapi==0.141.1 --hash=sha256:', 'uvicorn==0.52.1 --hash=sha256:',
        'pydantic==2.13.4 --hash=sha256:', 'pytest==9.1.1 --hash=sha256:'
    )) {
        if (-not $text.Contains($required)) { throw "Gateway dependency lock lacks invariant: $required" }
    }
}

function Assert-ManagerRuntime([object] $Inventory) {
    if (
        $Inventory.state.python_manager_runtime -ne 'FUNCTIONAL' -or
        $Inventory.python_manager.probe.metadata.version -ne $expectedPythonVersion -or
        $Inventory.python_manager.probe.metadata.architecture -ne '64bit'
    ) { throw 'PYTHON_MANAGER_RUNTIME=FAIL: exact CPython 3.14.5 x64 maintenance runtime is not functional.' }
    return $Inventory.python_manager.executable
}

function Assert-NoTraditionalRuntime([object] $Inventory) {
    if ($Inventory.state.same_version_traditional_install_present -notin @('ABSENT', 'PASS')) {
        throw 'SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=FAIL: supported uninstall must complete before machine installation.'
    }
}

function Assert-NoPartialTarget([object] $Inventory) {
    if ($Inventory.state.partial_target_runtime -ne 'ABSENT') {
        throw 'PARTIAL_TARGET_RUNTIME=FAIL: supported uninstall must remove the partial target before installation.'
    }
}

function Assert-NoMixedPythonCore([object] $Inventory) {
    if ($Inventory.state.mixed_pythoncore_registration -ne 'ABSENT') {
        throw 'MIXED_PYTHONCORE_REGISTRATION=FAIL: stop for supported registration recovery.'
    }
}

function Get-LockedWheelManifest {
    $manifest = [System.Collections.Generic.List[object]]::new()
    foreach ($line in Get-Content -LiteralPath $lockPath) {
        if ($line -notmatch '^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-fA-F]{64})\s*$') { continue }
        $manifest.Add([pscustomobject]@{
            name = ConvertTo-TradingLabNormalizedDistributionName $Matches[1]
            version = $Matches[2].ToLowerInvariant()
            sha256 = $Matches[3].ToLowerInvariant()
        })
    }
    if ($manifest.Count -eq 0) { throw 'DECLARATIVE_HASH_LOCK=FAIL: no locked wheel requirements parsed.' }
    return @($manifest)
}

function Assert-Wheelhouse([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "WHEELHOUSE_PRESENT=FAIL: $Path"
    }
    Assert-NoReparseComponents $Path
    $artifacts = @()
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "WHEELHOUSE_REPARSE_POINT=FAIL: $($item.FullName)"
        }
        $artifacts += [pscustomobject]@{
            name = $item.Name
            is_directory = [bool]$item.PSIsContainer
            sha256 = if ($item.PSIsContainer) { $null } else {
                (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    }
    if ($artifacts.Count -eq 0) { throw 'WHEELHOUSE_PRESENT=FAIL: no artifacts were staged.' }
    $state = Resolve-TradingLabWheelhouseManifestState (Get-LockedWheelManifest) $artifacts
    if ($state.expected_requirements -ne $expectedWheelRequirementCount) {
        throw "WHEELHOUSE_COMPLETE=FAIL: expected locked cardinality $expectedWheelRequirementCount; actual=$($state.expected_requirements)"
    }
    if ($state.source_distributions.Count -ne 0) {
        throw "WHEELHOUSE_SOURCE_DISTRIBUTION=FAIL: $($state.source_distributions -join ',')"
    }
    if ($state.corrupt_artifacts.Count -ne 0) {
        throw "WHEELHOUSE_HASH_LOCKED=FAIL: $($state.corrupt_artifacts -join ',')"
    }
    if ($state.unexpected_artifacts.Count -ne 0) {
        throw "WHEELHOUSE_UNEXPECTED_ARTIFACT=FAIL: $($state.unexpected_artifacts -join ',')"
    }
    if (-not $state.complete) {
        throw "WHEELHOUSE_COMPLETE=FAIL: missing=$($state.missing_requirements -join ','); duplicates=$($state.duplicate_requirements -join ',')"
    }
    if (-not $state.metatrader5_present) { throw 'META_TRADER5_WHEEL_PRESENT=FAIL' }
    if (-not $state.numpy_present) { throw 'NUMPY_WHEEL_PRESENT=FAIL' }
    return $state
}

function Get-RegisteredTraditionalBundle([object] $Inventory) {
    $bundles = @($Inventory.uninstall_entries | Where-Object { $_.kind -eq 'TRADITIONAL_BUNDLE' })
    if ($bundles.Count -ne 1 -or $bundles[0].scope -ne 'HKCU') {
        throw 'TRADITIONAL_USER_RUNTIME=FAIL: exactly one HKCU traditional bundle is required for supported recovery.'
    }
    if (
        $bundles[0].registry_id.ToUpperInvariant() -ne $expectedTraditionalBundleId -or
        $bundles[0].display_name -ne 'Python 3.14.5 (64-bit)' -or
        $bundles[0].display_version -ne '3.14.5150.0'
    ) { throw 'TRADITIONAL_BUNDLE_TARGET=FAIL: registered bundle identity is unexpected.' }
    return $bundles[0]
}

function Resolve-RegisteredBundleExecutable([object] $Bundle) {
    $registeredPath = $null
    if ($Bundle.uninstall_string -match '^\s*"([^"]+\.exe)"') {
        $registeredPath = $Matches[1]
    } elseif ($Bundle.uninstall_string -match '^\s*([^\s]+\.exe)') {
        $registeredPath = $Matches[1]
    }
    if (-not $registeredPath) { throw 'REGISTERED_UNINSTALLER_PATH=FAIL: executable cannot be parsed.' }
    if ($RegisteredBundlePath) {
        if ((Get-CanonicalPath $RegisteredBundlePath) -ne (Get-CanonicalPath $registeredPath)) {
            throw 'REGISTERED_UNINSTALLER_PATH=FAIL: supplied path differs from registered bundle.'
        }
        $registeredPath = $RegisteredBundlePath
    }
    Assert-NoReparseComponents $registeredPath
    if (-not (Test-Path -LiteralPath $registeredPath -PathType Leaf)) {
        throw 'REGISTERED_UNINSTALLER_PATH=FAIL: registered bundle is absent.'
    }
    $hash = (Get-FileHash -LiteralPath $registeredPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $expectedRegisteredBundleSha256) { throw "REGISTERED_UNINSTALLER_HASH=FAIL: $hash" }
    $signature = Get-AuthenticodeSignature -LiteralPath $registeredPath
    if (
        $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Python Software Foundation(,|$)'
    ) { throw 'REGISTERED_UNINSTALLER_SIGNATURE=FAIL' }
    return Get-CanonicalPath $registeredPath
}

function Get-VerifiedPrepareWheelhouseEvidence {
    Assert-NoReparseComponents $reportDirectory
    Assert-NoUntrustedModify $reportDirectory @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $evidence = Find-TradingLabPrepareWheelhouseReport `
        $reportDirectory $wheelhousePath $lockPath $expectedPythonVersion
    $reportItem = Get-Item -LiteralPath $evidence.path -Force -ErrorAction Stop
    if ($reportItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: report is a reparse point.'
    }
    Assert-NoUntrustedModify $reportItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $expectedName = "python-runtime-$($evidence.record.run_id).json"
    if ($reportItem.Name -ne $expectedName) {
        throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: report filename/run_id mismatch.'
    }
    $latestWheelWrite = (Get-ChildItem -LiteralPath $wheelhousePath -File |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
    if ($null -eq $latestWheelWrite -or $reportItem.LastWriteTimeUtc -lt $latestWheelWrite) {
        throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: report predates current wheelhouse artifacts.'
    }
    return [pscustomobject]@{
        path = $reportItem.FullName
        sha256 = (Get-FileHash -LiteralPath $reportItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        record = $evidence.record
    }
}

function Get-VerifiedUninstallTraditionalEvidence {
    Assert-NoReparseComponents $reportDirectory
    Assert-NoUntrustedModify $reportDirectory @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $evidence = Find-TradingLabUninstallTraditionalReport `
        $reportDirectory $wheelhousePath $lockPath $expectedPythonVersion $pythonBase $venvPath
    $reportItem = Get-Item -LiteralPath $evidence.path -Force -ErrorAction Stop
    if ($reportItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: report is a reparse point.'
    }
    Assert-NoUntrustedModify $reportItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    if ($reportItem.Name -ne "python-runtime-$($evidence.record.run_id).json") {
        throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: report filename/run_id mismatch.'
    }

    $preparePath = Get-CanonicalPath $evidence.record.previous_phase_report
    if (-not (Test-PathWithin $preparePath $reportDirectory)) {
        throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: nested PrepareWheelhouse report is outside the protected report directory.'
    }
    Assert-NoReparseComponents $preparePath
    $prepareItem = Get-Item -LiteralPath $preparePath -Force -ErrorAction Stop
    Assert-NoUntrustedModify $prepareItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $prepareHash = (Get-FileHash -LiteralPath $prepareItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($prepareHash -ne $evidence.record.previous_phase_report_sha256) {
        throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: nested PrepareWheelhouse report hash mismatch.'
    }
    $prepareRecord = [System.IO.File]::ReadAllText($prepareItem.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    if (-not (Test-TradingLabPrepareWheelhouseReportRecord `
        $prepareRecord $wheelhousePath $lockPath $expectedPythonVersion
    )) { throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: nested PrepareWheelhouse evidence is no longer valid.' }

    return [pscustomobject]@{
        path = $reportItem.FullName
        sha256 = (Get-FileHash -LiteralPath $reportItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        record = $evidence.record
    }
}

function Get-VerifiedInstalledRuntimePendingEvidence {
    Assert-NoReparseComponents $reportDirectory
    Assert-NoUntrustedModify $reportDirectory @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $evidence = Find-TradingLabInstalledRuntimePendingReport `
        $reportDirectory $expectedPythonVersion $pythonBase $InstallerPath
    $reportItem = Get-Item -LiteralPath $evidence.path -Force -ErrorAction Stop
    if ($reportItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: report is a reparse point.'
    }
    Assert-NoUntrustedModify $reportItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    if ($reportItem.Name -ne "python-runtime-$($evidence.record.run_id).json") {
        throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: report filename/run_id mismatch.'
    }

    $uninstallPath = Get-CanonicalPath $evidence.record.previous_phase_report
    if (-not (Test-PathWithin $uninstallPath $reportDirectory)) {
        throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: UninstallTraditional report is outside the protected report directory.'
    }
    Assert-NoReparseComponents $uninstallPath
    $uninstallItem = Get-Item -LiteralPath $uninstallPath -Force -ErrorAction Stop
    Assert-NoUntrustedModify $uninstallItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $uninstallHash = (Get-FileHash -LiteralPath $uninstallItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($uninstallHash -ne $evidence.record.previous_phase_report_sha256) {
        throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: UninstallTraditional report hash mismatch.'
    }
    $uninstallRecord = [System.IO.File]::ReadAllText($uninstallItem.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    if (-not (Test-TradingLabUninstallTraditionalReportRecord `
        $uninstallRecord $wheelhousePath $lockPath $expectedPythonVersion $pythonBase $venvPath
    )) { throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: linked UninstallTraditional evidence is invalid.' }

    $logPath = Join-Path $logsRoot "python-$($evidence.record.run_id)-machine-install.log"
    if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
        throw 'INSTALLER_RESULT_EVIDENCE=FAIL: durable installer log is absent.'
    }
    Assert-NoReparseComponents $logPath
    Assert-NoUntrustedModify $logPath @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $logText = [System.IO.File]::ReadAllText($logPath, [System.Text.Encoding]::UTF8)
    foreach ($required in @(
        'Apply complete, result: 0x0', 'Exit code: 0x0',
        'Variable: InstallAllUsers = 1', "Variable: TargetDir = $pythonBase",
        'Variable: Include_core = 1', 'Variable: Include_exe = 1',
        'Variable: Include_lib = 1', 'Variable: Include_pip = 1',
        'Variable: Include_dev = 0', 'Variable: Include_test = 0',
        'Variable: Include_doc = 0', 'Variable: Include_tcltk = 0'
    )) {
        if (-not $logText.Contains($required)) {
            throw "INSTALLER_RESULT_EVIDENCE=FAIL: log lacks reviewed result: $required"
        }
    }
    return [pscustomobject]@{
        path = $reportItem.FullName
        sha256 = (Get-FileHash -LiteralPath $reportItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        log_path = $logPath
        log_sha256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant()
        record = $evidence.record
    }
}

function Get-VerifiedResumeMachineRuntimeEvidence {
    Assert-NoReparseComponents $reportDirectory
    Assert-NoUntrustedModify $reportDirectory @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $evidence = Find-TradingLabResumeMachineRuntimeReport `
        $reportDirectory $expectedPythonVersion $pythonBase
    $item = Get-Item -LiteralPath $evidence.path -Force -ErrorAction Stop
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: report is a reparse point.'
    }
    Assert-NoUntrustedModify $item.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    if ($item.Name -ne "python-runtime-$($evidence.record.run_id).json") {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: filename/run_id mismatch.'
    }

    $installPath = Get-CanonicalPath $evidence.record.previous_phase_report
    if (-not (Test-PathWithin $installPath $reportDirectory)) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: linked install report is outside the protected directory.'
    }
    Assert-NoReparseComponents $installPath
    $installItem = Get-Item -LiteralPath $installPath -Force -ErrorAction Stop
    Assert-NoUntrustedModify $installItem.FullName @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $installHash = (Get-FileHash -LiteralPath $installItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installHash -ne $evidence.record.previous_phase_report_sha256) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: linked install report hash mismatch.'
    }
    $installRecord = [System.IO.File]::ReadAllText(
        $installItem.FullName, [System.Text.Encoding]::UTF8
    ) | ConvertFrom-Json
    if (-not (Test-TradingLabInstalledRuntimePendingReportRecord `
        $installRecord $expectedPythonVersion $pythonBase $InstallerPath
    )) { throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: linked install evidence is invalid.' }

    $installerLog = Get-CanonicalPath $evidence.record.installer_result_log
    if (-not (Test-PathWithin $installerLog $logsRoot)) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: installer result log is outside the protected log directory.'
    }
    Assert-NoReparseComponents $installerLog
    Assert-NoUntrustedModify $installerLog @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    $installerLogHash = (Get-FileHash -LiteralPath $installerLog -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installerLogHash -ne $evidence.record.installer_result_log_sha256) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: installer result log hash mismatch.'
    }
    return [pscustomobject]@{
        path = $item.FullName
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        record = $evidence.record
    }
}

function Get-VerifiedPythonBaseRuntimeEvidence(
    [string] $Role,
    [string] $EvidenceRunId,
    [string] $ExpectedSid
) {
    $normalized = ([guid]::ParseExact($EvidenceRunId, 'D')).ToString('D').ToLowerInvariant()
    $root = if ($Role -eq 'AutomatonGateway') {
        'C:\ProgramData\AutomatonMT5Lab\operational\acl-runtime-results'
    } else { 'C:\Users\AutomatonAgent\.automaton\acl-runtime-results' }
    $stem = if ($Role -eq 'AutomatonGateway') { 'gateway' } else { 'agent' }
    $path = Join-Path $root "$stem-python-base-$normalized.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$($stem.ToUpperInvariant())_PYTHON_BASE_RUNTIME_EVIDENCE=FAIL: exact report is absent."
    }
    Assert-NoReparseComponents $path
    if (-not (Test-PathWithin $path $root)) {
        throw "$($stem.ToUpperInvariant())_PYTHON_BASE_RUNTIME_EVIDENCE=FAIL: report path escaped its canonical root."
    }
    try { $record = Read-TradingLabPythonBaseRuntimeEvidenceFile $path $Role $normalized $ExpectedSid }
    catch { throw "$($stem.ToUpperInvariant())_$($_.Exception.Message)" }
    return [pscustomobject]@{
        path = Get-CanonicalPath $path
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        record = $record
    }
}

function New-BuildVenvPlan {
    $stagingPython = Join-Path $stagingVenvPath 'Scripts\python.exe'
    $environment = [ordered]@{
        PIP_CONFIG_FILE = 'NUL'
        PIP_NO_INDEX = '1'
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        PIP_NO_CACHE_DIR = '1'
        PYTHONNOUSERSITE = '1'
        PYTHONDONTWRITEBYTECODE = '1'
        TEMP = (Join-Path $maintenanceRoot "runtime-tmp\build-venv-$runId")
        TMP = (Join-Path $maintenanceRoot "runtime-tmp\build-venv-$runId")
    }
    return [ordered]@{
        operation = 'BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED'
        base_python = $basePython
        staging_venv = $stagingVenvPath
        active_venv_action = 'UNTOUCHED'
        lock_file = $lockPath
        wheelhouse = $wheelhousePath
        network = 'DISABLED_NO_INDEX'
        temp_path = (Join-Path $maintenanceRoot "runtime-tmp\build-venv-$runId")
        steps = @(
            [ordered]@{
                name = 'CREATE_STAGING_VENV'
                executable = $basePython
                arguments = @('-I', '-m', 'venv', $stagingVenvPath)
                use_shell = $false
                environment = $environment
            },
            [ordered]@{
                name = 'INSTALL_HASH_LOCKED_WHEELS'
                executable = $stagingPython
                arguments = @(
                    '-I', '-m', 'pip', 'install', '--disable-pip-version-check',
                    '--no-input', '--no-index', '--find-links', $wheelhousePath,
                    '--require-hashes', '--only-binary=:all:', '-r', $lockPath
                )
                use_shell = $false
                environment = $environment
            }
        )
    }
}

function Assert-BuildVenvPlan([object] $Plan) {
    $state = Resolve-TradingLabBuildVenvPlanState `
        $Plan $basePython $stagingVenvPath $lockPath $wheelhousePath $venvPath
    if (-not $state.valid) { throw "BUILD_VENV_PLAN=FAIL: $($state.failures -join ',')" }
    $report.gates.BUILD_VENV_PLAN = 'PASS'
    $report.gates.BASE_PYTHON_EXACT = 'PASS'
    $report.gates.PIP_OFFLINE_NO_INDEX = 'PASS'
    $report.gates.PIP_REQUIRE_HASHES = 'PASS'
    $report.gates.PIP_ONLY_BINARY = 'PASS'
    $report.gates.PIP_NO_USER = 'PASS'
    $report.gates.PIP_NO_URL = 'PASS'
    $report.gates.ACTIVE_VENV_ISOLATED = 'PASS'
}

function New-PostBuildValidationPlan {
    return [ordered]@{
        operation = 'VALIDATE_STAGING_WITHOUT_IMPORTING_METATRADER5'
        executable = (Join-Path $stagingVenvPath 'Scripts\python.exe')
        arguments = @('-I', '-')
        use_shell = $false
        source_transport = 'STDIN'
        imports = @('importlib.metadata', 'json', 'platform', 'site', 'sys', 'venv')
        forbidden_imports = @('MetaTrader5')
        expected_python_version = $expectedPythonVersion
        expected_architecture = '64bit'
        expected_prefix = $stagingVenvPath
        expected_base_prefix = $pythonBase
        expected_executable = (Join-Path $stagingVenvPath 'Scripts\python.exe')
        expected_lock_requirements = $expectedWheelRequirementCount
        bootstrap_distribution_allowlist = @('pip')
        validate_pyvenv_cfg = $true
        validate_no_user_profile_paths = $true
        validate_service_mutation_denied = $true
        call_set_acl = $false
    }
}

function Set-WheelhousePassGates([object] $State) {
    $report.wheelhouse_validation = $State
    $report.gates.WHEELHOUSE_PRESENT = 'PASS'
    $report.gates.WHEELHOUSE_HASH_LOCKED = 'PASS'
    $report.gates.WHEELHOUSE_COMPLETE = 'PASS'
    $report.gates.META_TRADER5_WHEEL_PRESENT = 'PASS'
    $report.gates.NUMPY_WHEEL_PRESENT = 'PASS'
}

function Assert-InstallMachinePreconditions([object] $Inventory) {
    $state = Resolve-TradingLabInstallPreconditionState $Inventory.state
    if (-not $state.valid) {
        throw "INSTALL_MACHINE_PRECONDITIONS=FAIL: $($state.failures -join ';')"
    }
    if ($Inventory.state.completed_target_runtime -ne 'ABSENT') {
        throw 'TARGET_PATH_EMPTY_OR_ABSENT=FAIL: a complete target already exists in the pre-install path.'
    }
    if (Test-Path -LiteralPath $pythonBase) {
        Assert-NoReparseComponents $pythonBase
        if (@(Get-ChildItem -LiteralPath $pythonBase -Force -ErrorAction Stop).Count -ne 0) {
            throw 'TARGET_PATH_EMPTY_OR_ABSENT=FAIL: target contains files.'
        }
    }
    $report.gates.TRADITIONAL_USER_RUNTIME_ABSENT = 'PASS'
    $report.gates.TRADITIONAL_MACHINE_RUNTIME_ABSENT = 'PASS'
    $report.gates.TRADITIONAL_MSI_COMPONENTS_ZERO = 'PASS'
    $report.gates.PARTIAL_TARGET_RUNTIME_ABSENT = 'PASS'
    $report.gates.MIXED_PYTHONCORE_REGISTRATION_ABSENT = 'PASS'
    $report.gates.SAME_VERSION_TRADITIONAL_INSTALL_PRESENT = 'PASS'
    $report.gates.TARGET_PATH_EMPTY_OR_ABSENT = 'PASS'
}

function Test-InstalledMachineRuntimePending([object] $Inventory) {
    return (
        $Inventory.target_layout.complete_layout -and
        $Inventory.target_probe.functional -and
        $Inventory.state.traditional_user_runtime -eq 'ABSENT' -and
        $Inventory.state.traditional_machine_runtime -eq 'PRESENT' -and
        $Inventory.state.machine_runtime_target_present -and
        $Inventory.state.machine_runtime_msi_components -eq 4 -and
        $Inventory.state.expected_machine_msi_components -eq 4 -and
        $Inventory.state.unexpected_machine_msi_components -eq 0 -and
        $Inventory.state.machine_runtime_msi_valid -and
        $Inventory.state.partial_target_runtime -eq 'ABSENT' -and
        $Inventory.state.mixed_pythoncore_registration -eq 'ABSENT' -and
        $Inventory.state.same_version_traditional_install_present -eq 'EXPECTED_INSTALLED_TARGET_RUNTIME'
    )
}

function New-MachineRuntimeInstallerPlan([string] $Executable) {
    $arguments = @(
        '/quiet', 'InstallAllUsers=1', ('TargetDir=' + $pythonBase),
        'AssociateFiles=0', 'PrependPath=0', 'AppendPath=0', 'Shortcuts=0',
        'Include_doc=0', 'Include_debug=0', 'Include_dev=0', 'Include_exe=1',
        'Include_launcher=0', 'InstallLauncherAllUsers=0', 'Include_lib=1',
        'Include_pip=1', 'Include_symbols=0', 'Include_tcltk=0',
        'Include_test=0', 'Include_tools=0', 'CompileAll=0'
    )
    return [ordered]@{
        operation = 'INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL'
        executable = $Executable
        arguments = $arguments
        target_dir = $pythonBase
        log_path_template = (Join-Path $logsRoot 'python-<RUN_ID>-machine-install.log')
        components = [ordered]@{
            core_interpreter = 'ENABLED'
            executables = 'ENABLED'
            standard_library = 'ENABLED'
            venv = 'STDLIB_ENABLED'
            pip_bootstrap = 'ENABLED'
            development_libraries = 'DISABLED'
            test_suite = 'DISABLED'
            documentation = 'DISABLED'
            tcl_tk = 'DISABLED'
            launcher = 'DISABLED'
            file_associations = 'DISABLED'
            path_prepend_append = 'DISABLED'
        }
    }
}

function Assert-MachineInstallerPlan([object] $Plan) {
    if ($Plan.operation -ne 'INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL') { throw 'INSTALLER_PLAN=FAIL: operation.' }
    if (-not (Test-TradingLabExactMachineTarget $Plan.target_dir $pythonBase (Join-Path $env:SystemDrive 'Users'))) {
        throw 'TARGET_MACHINE_WIDE=FAIL'
    }
    $arguments = @($Plan.arguments)
    foreach ($required in @(
        'InstallAllUsers=1', 'PrependPath=0', 'AppendPath=0', 'Include_launcher=0',
        'InstallLauncherAllUsers=0', 'AssociateFiles=0', 'Include_exe=1',
        'Include_lib=1', 'Include_pip=1', 'Include_dev=0', 'Include_test=0',
        'Include_doc=0', 'Include_tcltk=0'
    )) {
        if ($required -notin $arguments) { throw "INSTALLER_PLAN=FAIL: missing $required" }
    }
    $report.gates.INSTALL_ALL_USERS = 'PASS'
    $report.gates.TARGET_MACHINE_WIDE = 'PASS'
    $report.gates.TARGET_OUTSIDE_USER_PROFILE = 'PASS'
    $report.gates.PREPEND_PATH_DISABLED = 'PASS'
    $report.gates.LAUNCHER_DISABLED = 'PASS'
    $report.gates.FILE_ASSOCIATIONS_DISABLED = 'PASS'
    $report.gates.CORE_INTERPRETER_ENABLED = 'PASS'
    $report.gates.STANDARD_LIBRARY_ENABLED = 'PASS'
    $report.gates.VENV_STDLIB_ENABLED = 'PASS'
    $report.gates.PIP_BOOTSTRAP_ENABLED = 'PASS'
    $report.gates.DEVELOPMENT_LIBRARIES_DISABLED = 'PASS'
    $report.gates.TEST_SUITE_DISABLED = 'PASS'
    $report.gates.DOCUMENTATION_DISABLED = 'PASS'
    $report.gates.TCL_TK_DISABLED = 'PASS'
}

function Assert-ExpectedTraditionalMsiComponents(
    [object] $Inventory,
    [string] $ExpectedOwnerSid
) {
    $actual = @($Inventory.msi_products)
    $state = Resolve-TradingLabMsiComponentSetState $expectedTraditionalMsiComponents $actual
    if (-not $state.valid) {
        throw "TRADITIONAL_MSI_COMPONENTS=FAIL: expected=9 actual=$($state.actual_count) missing=$($state.missing_product_codes -join ',') unexpected=$($state.unexpected_product_codes -join ',') duplicate=$($state.duplicate_product_codes -join ',') name_mismatch=$($state.display_name_mismatches -join ',')"
    }
    $uninstallComponentIds = @($Inventory.uninstall_entries | Where-Object {
        $_.kind -eq 'TRADITIONAL_MSI_COMPONENT'
    } | ForEach-Object { $_.registry_id.ToUpperInvariant() } | Sort-Object)
    $expectedIds = @($expectedTraditionalMsiComponents | ForEach-Object {
        $_.product_code.ToUpperInvariant()
    } | Sort-Object)
    if (@(Compare-Object $expectedIds $uninstallComponentIds).Count -ne 0) {
        throw 'TRADITIONAL_MSI_COMPONENTS=FAIL: Uninstall entries and Installer UserData disagree.'
    }
    $windowsInstallerRoot = Get-CanonicalPath (Join-Path $env:WINDIR 'Installer')
    foreach ($component in $actual) {
        if ($component.user_data_sid -ne $ExpectedOwnerSid) {
            throw "TRADITIONAL_MSI_COMPONENTS=FAIL: unexpected owner SID for $($component.product_code)."
        }
        if (
            -not $component.local_package -or
            -not (Test-PathWithin $component.local_package $windowsInstallerRoot) -or
            -not (Test-Path -LiteralPath $component.local_package -PathType Leaf)
        ) { throw "TRADITIONAL_MSI_COMPONENTS=FAIL: registered MSI cache is absent or outside Windows Installer for $($component.product_code)." }
        Assert-NoReparseComponents $component.local_package
    }
    return @($actual | Sort-Object product_code)
}

function New-TraditionalUninstallPlan(
    [object] $Bundle,
    [string] $Executable,
    [object[]] $Components
) {
    return [ordered]@{
        operation = 'SUPPORTED_REGISTERED_BUNDLE_UNINSTALL'
        executable = $Executable
        arguments = @('/uninstall', '/quiet')
        log_argument_added_at_execution = '/log <RUN_SCOPED_DURABLE_LOG>'
        bundle_display_name = $Bundle.display_name
        bundle_registry_id = $Bundle.registry_id.ToUpperInvariant()
        destructive_registry_ids = @($Bundle.registry_id.ToUpperInvariant()) + @(
            $Components | ForEach-Object { $_.product_code.ToUpperInvariant() }
        )
        expected_msi_components = @($Components | ForEach-Object {
            [ordered]@{ display_name = $_.display_name; product_code = $_.product_code.ToUpperInvariant() }
        })
        direct_registry_deletes = @()
        direct_filesystem_deletes = @()
        package_cache_deletes = @()
        windows_installer_cache_deletes = @()
        manager_uninstall_actions = @()
        active_venv_action = 'UNTOUCHED_BY_SCRIPT'
        partial_target_action = 'UNTOUCHED_BY_SCRIPT'
    }
}

function Assert-PythonManagerPreserved(
    [object] $Inventory,
    [object] $Plan
) {
    $managerEntries = @($Inventory.uninstall_entries | Where-Object {
        $_.kind -eq 'PYTHON_MANAGER_RUNTIME'
    })
    $expectedManagerPath = Get-CanonicalPath (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.14-64')
    if (
        $managerEntries.Count -ne 1 -or
        $managerEntries[0].registry_id -ne $expectedManagerRegistryId -or
        (Get-CanonicalPath $managerEntries[0].install_location) -ne $expectedManagerPath -or
        (Get-CanonicalPath $Inventory.python_manager.probe.metadata.base_prefix) -ne $expectedManagerPath -or
        (Get-CanonicalPath $Inventory.python_manager.executable) -ne (Join-Path $expectedManagerPath 'python.exe')
    ) { throw 'PYTHON_MANAGER_PRESERVE=FAIL: Manager registration/path/runtime is not exact.' }
    if (-not (Test-TradingLabManagerExcludedFromUninstallPlan $Plan $expectedManagerRegistryId $expectedManagerPath)) {
        throw 'PYTHON_MANAGER_PRESERVE=CRITICAL_FAIL: Manager appears in the destructive plan.'
    }
    return [pscustomobject]@{ registry_id = $expectedManagerRegistryId; path = $expectedManagerPath }
}

function Assert-UninstallPlanHasNoDirectCleanup([object] $Plan) {
    if (@($Plan.direct_registry_deletes).Count -ne 0) { throw 'NO_MANUAL_REGISTRY_CLEANUP=FAIL' }
    if (@($Plan.package_cache_deletes).Count -ne 0) { throw 'NO_PACKAGE_CACHE_DELETE=FAIL' }
    if (@($Plan.windows_installer_cache_deletes).Count -ne 0) { throw 'NO_WINDOWS_INSTALLER_CACHE_DELETE=FAIL' }
    if (@($Plan.direct_filesystem_deletes).Count -ne 0) { throw 'DIRECT_FILESYSTEM_DELETE=FAIL' }
    if ($Plan.active_venv_action -ne 'UNTOUCHED_BY_SCRIPT') { throw 'ACTIVE_VENV_UNTOUCHED=FAIL' }
    if ($Plan.partial_target_action -ne 'UNTOUCHED_BY_SCRIPT') { throw 'PARTIAL_TARGET_NOT_DELETED_YET=FAIL' }
}

function Assert-LabStoppedAndObserveOnly {
    $runningLab = @(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match 'trading_lab\.service|dist[\\/]index\.js.*--run'
    })
    if ($runningLab.Count -ne 0) { throw 'LAB_PROCESSES_STOPPED=FAIL' }
    $configText = [System.IO.File]::ReadAllText(
        (Join-Path $labRoot 'control\trading.yaml'), [System.Text.Encoding]::UTF8
    )
    if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
        throw 'TRADING_MODE_OBSERVE_ONLY=FAIL'
    }
}

function Invoke-CheckedPythonJson([string] $Python, [string] $Source) {
    $result = Invoke-TradingLabPythonStdinJson $Python $Source
    if (-not $result.functional) {
        $diagnostic = if ([string]::IsNullOrWhiteSpace([string]$result.stderr)) {
            $result.error
        } else { "$($result.error):$($result.stderr)" }
        throw "Python metadata command failed for ${Python}: $diagnostic"
    }
    return $result.metadata
}

function Get-PythonMetadata([string] $Python) {
    return Invoke-CheckedPythonJson $Python @'
import json
import os
import pip
import platform
import sys
import venv
print(json.dumps({
    "architecture": platform.architecture()[0],
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "pip_import": True,
    "prefix": sys.prefix,
    "stdlib_import": True,
    "stdlib_path": os.__file__,
    "sys_import": True,
    "sys_path": sys.path,
    "venv_import": True,
    "version": platform.python_version(),
}, sort_keys=True, separators=(",", ":")))
'@
}

function Assert-BasePython([string] $Python) {
    $layout = Get-TradingLabPythonLayout $pythonBase
    if (-not $layout.complete_layout) {
        throw 'PYTHON_BASE_LAYOUT=FAIL: python.exe, python314.dll, Lib or stdlib is absent.'
    }
    Assert-NoReparseComponents $Python
    $metadata = Get-PythonMetadata $Python
    if (
        $metadata.version -ne $expectedPythonVersion -or $metadata.architecture -ne '64bit' -or
        (Get-CanonicalPath $metadata.executable) -ne (Get-CanonicalPath $Python) -or
        (Get-CanonicalPath $metadata.base_prefix) -ne (Get-CanonicalPath $pythonBase) -or
        (Get-CanonicalPath $metadata.prefix) -ne (Get-CanonicalPath $pythonBase)
    ) { throw 'Machine-wide Python metadata does not match the exact CPython 3.14.5 x64 target.' }
    Assert-OutsideUserProfiles $metadata.base_prefix 'Machine-wide Python base'
    if (-not (Test-PathWithin $metadata.stdlib_path $pythonBase)) {
        throw 'PYTHON_STDLIB_FUNCTIONAL=FAIL: stdlib resolved outside the managed runtime.'
    }
    foreach ($entry in @($metadata.sys_path | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
        Assert-OutsideUserProfiles ([string]$entry) 'Machine-wide Python sys.path entry'
    }
    return $metadata
}

function Set-MachineRuntimePassGates([object] $Metadata) {
    $layout = Get-TradingLabPythonLayout $pythonBase
    if (-not $layout.complete_layout -or -not $Metadata.sys_import -or
        -not $Metadata.venv_import -or -not $Metadata.stdlib_import -or -not $Metadata.pip_import
    ) { throw 'PYTHON_RUNTIME_POST_INSTALL=FAIL: runtime imports/layout are incomplete.' }
    $report.gates.PYTHON_EXE_EXISTS = 'PASS'
    $report.gates.PYTHON314_DLL_EXISTS = 'PASS'
    $report.gates.PYTHON_LIB_EXISTS = 'PASS'
    $report.gates.PYTHON_STDLIB = 'PASS'
    $report.gates.PYTHON_VENV_IMPORT = 'PASS'
    $report.gates.PYTHON_PIP_AVAILABLE = 'PASS'
    $report.gates.PYTHON_VERSION_EXACT = 'PASS'
    $report.gates.PYTHON_ARCH_X64 = 'PASS'
    $report.gates.PYTHON_BASE_PREFIX_TARGET = 'PASS'
    $report.gates.PYTHON_EXECUTABLE_TARGET = 'PASS'
    $report.gates.PYTHON_RUNTIME_USER_PROFILE_DEPENDENCIES = 'NONE_PASS'
    $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
    $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
}

function ConvertTo-NormalizedRequirement([string] $Value) {
    $parts = $Value.Trim() -split '==', 2
    if ($parts.Count -ne 2) { throw "Non-pinned requirement found: $Value" }
    $name = [regex]::Replace($parts[0].ToLowerInvariant(), '[-_.]+', '-')
    return "$name==$($parts[1].ToLowerInvariant())"
}

function Get-LockedRequirements {
    return @(Get-Content -LiteralPath $lockPath | Where-Object {
        $_ -match '^[A-Za-z0-9_.-]+=='
    } | ForEach-Object {
        ConvertTo-NormalizedRequirement (($_ -split '\s+--hash=')[0])
    } | Sort-Object -Unique)
}

function Assert-VenvPackages([string] $Python) {
    & $Python -I -m pip check | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'pip check failed in staged venv.' }
    $actual = @(& $Python -I -m pip freeze --disable-pip-version-check)
    if ($LASTEXITCODE -ne 0) { throw 'pip freeze failed in staged venv.' }
    $actual = @($actual | ForEach-Object { ConvertTo-NormalizedRequirement $_ } | Sort-Object -Unique)
    if (@(Compare-Object (Get-LockedRequirements) $actual).Count -ne 0) {
        throw 'Staged venv package inventory differs from the reviewed hash lock.'
    }
    $distribution = Invoke-CheckedPythonJson $Python @'
import importlib.metadata
import json
print(json.dumps({
    "MetaTrader5": importlib.metadata.version("MetaTrader5"),
    "numpy": importlib.metadata.version("numpy"),
}, sort_keys=True, separators=(",", ":")))
'@
    if ($distribution.MetaTrader5 -ne '5.0.6090' -or $distribution.numpy -ne '2.5.2') {
        throw 'MetaTrader5/numpy distribution metadata differs from the reviewed lock.'
    }
}

function Assert-Venv([string] $Root) {
    $python = Join-Path $Root 'Scripts\python.exe'
    $metadata = Get-PythonMetadata $python
    if (
        $metadata.version -ne $expectedPythonVersion -or $metadata.architecture -ne '64bit' -or
        (Get-CanonicalPath $metadata.executable) -ne (Get-CanonicalPath $python) -or
        (Get-CanonicalPath $metadata.prefix) -ne (Get-CanonicalPath $Root) -or
        (Get-CanonicalPath $metadata.base_prefix) -ne (Get-CanonicalPath $pythonBase)
    ) { throw 'Venv does not redirect to the exact machine-wide Python base.' }
    Assert-OutsideUserProfiles $metadata.base_prefix 'Venv Python base'
    $cfg = [System.IO.File]::ReadAllText((Join-Path $Root 'pyvenv.cfg'), [System.Text.Encoding]::UTF8)
    if ($cfg -match '(?i)[a-z]:\\users\\' -or $cfg -notmatch [regex]::Escape($pythonBase)) {
        throw 'pyvenv.cfg references a user profile or omits the managed machine-wide base.'
    }
    Assert-VenvPackages $python
    Assert-TreeNotModifiableByServices $Root
    return $metadata
}

function Initialize-PhaseStorage {
    if (-not (Test-Path -LiteralPath $maintenanceRoot -PathType Container)) {
        throw 'MAINTENANCE_ROOT_PRESENT=FAIL: prepare the protected maintenance domain first.'
    }
    Assert-NoReparseComponents $maintenanceRoot
    Assert-NoUntrustedModify $maintenanceRoot @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    foreach ($directory in @($logsRoot, $reportDirectory)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            [void][System.IO.Directory]::CreateDirectory($directory)
        }
        Assert-NoReparseComponents $directory
    }
}

function New-PhaseLogPath([string] $Name, [string] $Extension = 'log') {
    return Join-Path $logsRoot ("python-$runId-$Name.$Extension")
}

function ConvertTo-ProcessArgument([string] $Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-LoggedProcess([string] $Executable, [string[]] $Arguments, [string] $LogStem) {
    $stdoutPath = New-PhaseLogPath "$LogStem-stdout"
    $stderrPath = New-PhaseLogPath "$LogStem-stderr"
    $argumentLine = (($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $process = Start-Process -FilePath $Executable -ArgumentList $argumentLine `
        -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if ($process.ExitCode -ne 0) {
        throw "PROCESS_EXIT_NONZERO: executable=$Executable; exit=$($process.ExitCode); stdout=$stdoutPath; stderr=$stderrPath"
    }
}

function Set-BuildVenvProcessEnvironment(
    [System.Diagnostics.ProcessStartInfo] $StartInfo,
    [string] $TempPath
) {
    foreach ($key in @($StartInfo.EnvironmentVariables.Keys)) {
        if ([string]$key -match '^(?i:PIP_|PYTHONPATH$|PYTHONHOME$|PYTHONUSERBASE$|VIRTUAL_ENV$)') {
            $StartInfo.EnvironmentVariables.Remove([string]$key)
        }
    }
    $StartInfo.EnvironmentVariables['PIP_CONFIG_FILE'] = 'NUL'
    $StartInfo.EnvironmentVariables['PIP_NO_INDEX'] = '1'
    $StartInfo.EnvironmentVariables['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    $StartInfo.EnvironmentVariables['PIP_NO_CACHE_DIR'] = '1'
    $StartInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $StartInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $StartInfo.EnvironmentVariables['TEMP'] = $TempPath
    $StartInfo.EnvironmentVariables['TMP'] = $TempPath
}

function Initialize-BuildVenvPrivateTemp([string] $Path) {
    if (-not (Test-PathWithin $Path $maintenanceRoot)) {
        throw 'BUILD_VENV_TEMP_CONFINEMENT=FAIL'
    }
    if (Test-Path -LiteralPath $Path) { throw 'BUILD_VENV_TEMP_COLLISION=FAIL' }
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
    Assert-NoReparseComponents $parent
    [void][System.IO.Directory]::CreateDirectory($Path)
    Assert-NoReparseComponents $Path
    return Get-CanonicalPath $Path
}

function Clear-BuildVenvPrivateTemp([string] $Path) {
    if (-not (Test-PathWithin $Path $maintenanceRoot)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    try {
        Assert-NoReparseComponents $Path
        foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $false }
        }
        [System.IO.Directory]::Delete($Path, $true)
        return -not (Test-Path -LiteralPath $Path)
    } catch { return $false }
}

function New-BuildVenvProcessStartInfo(
    [string] $Executable,
    [string[]] $Arguments,
    [string] $TempPath
) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $startInfo.WorkingDirectory = $TempPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Set-BuildVenvProcessEnvironment $startInfo $TempPath
    return $startInfo
}

function Invoke-BuildVenvProcess(
    [string] $Executable,
    [string[]] $Arguments,
    [string] $LogStem,
    [string] $TempPath,
    [string] $StandardInput = ''
) {
    $stdoutPath = New-PhaseLogPath "$LogStem-stdout"
    $stderrPath = New-PhaseLogPath "$LogStem-stderr"
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = New-BuildVenvProcessStartInfo $Executable $Arguments $TempPath
    try {
        if (-not $process.Start()) { throw "BUILD_VENV_PROCESS_START_FALSE:$LogStem" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not [string]::IsNullOrEmpty($StandardInput)) { $process.StandardInput.Write($StandardInput) }
        $process.StandardInput.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($stdoutPath, $stdout, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($stderrPath, $stderr, [System.Text.UTF8Encoding]::new($false))
        if ($process.ExitCode -ne 0) {
            throw "PROCESS_EXIT_NONZERO: executable=$Executable; exit=$($process.ExitCode); stdout=$stdoutPath; stderr=$stderrPath"
        }
        return [pscustomobject]@{ stdout = $stdout; stderr = $stderr; exit_code = $process.ExitCode }
    } finally { $process.Dispose() }
}

function Invoke-BuildVenvStdinJson(
    [string] $Python,
    [string] $Source,
    [string] $TempPath
) {
    $result = Invoke-BuildVenvProcess $Python @('-I', '-') 'venv-validate' $TempPath $Source
    if (-not [string]::IsNullOrWhiteSpace($result.stderr)) {
        throw 'STAGING_VALIDATION_STDERR=FAIL: see durable validation log.'
    }
    try { return $result.stdout.Trim() | ConvertFrom-Json }
    catch { throw 'STAGING_VALIDATION_JSON=FAIL: Python metadata was not valid JSON.' }
}

function Assert-StagingVenv([string] $Root, [string] $TempPath) {
    if (-not (Test-TradingLabInventoryExactPath $Root $stagingVenvPath)) {
        throw 'STAGING_TARGET_EXACT=FAIL'
    }
    Assert-NoReparseComponents $Root
    $python = Join-Path $Root 'Scripts\python.exe'
    $metadata = Invoke-BuildVenvStdinJson $python @'
import importlib.metadata
import json
import platform
import site
import sys
import venv
distributions = []
for distribution in importlib.metadata.distributions():
    name = distribution.metadata.get("Name")
    if name:
        distributions.append({"name": name, "version": distribution.version})
print(json.dumps({
    "architecture": platform.architecture()[0],
    "base_prefix": sys.base_prefix,
    "distributions": sorted(distributions, key=lambda item: item["name"].lower()),
    "executable": sys.executable,
    "prefix": sys.prefix,
    "sys_path": sys.path,
    "user_site_enabled": bool(site.ENABLE_USER_SITE),
    "venv_import": True,
    "version": platform.python_version(),
}, sort_keys=True, separators=(",", ":")))
'@ $TempPath
    if ($metadata.version -ne $expectedPythonVersion) { throw 'STAGING_PYTHON_VERSION=FAIL' }
    if ($metadata.architecture -ne '64bit') { throw 'STAGING_PYTHON_ARCH=FAIL' }
    if (-not (Test-TradingLabInventoryExactPath $metadata.prefix $Root)) { throw 'STAGING_PREFIX=FAIL' }
    if (-not (Test-TradingLabInventoryExactPath $metadata.base_prefix $pythonBase)) { throw 'STAGING_BASE_PREFIX=FAIL' }
    if (-not (Test-TradingLabInventoryExactPath $metadata.executable $python)) { throw 'STAGING_EXECUTABLE=FAIL' }
    if (-not [bool]$metadata.venv_import) { throw 'STAGING_VENV_IMPORT=FAIL' }
    if ([bool]$metadata.user_site_enabled) { throw 'STAGING_USER_SITE_ACTIVE=FAIL' }
    foreach ($path in @($metadata.sys_path)) {
        if ([string]$path -match '(?i)^C:\\Users\\') { throw 'STAGING_NO_USER_PROFILE_DEPENDENCY=FAIL' }
    }
    $cfgPath = Join-Path $Root 'pyvenv.cfg'
    $cfg = [System.IO.File]::ReadAllText($cfgPath, [System.Text.Encoding]::UTF8)
    if ($cfg -match '(?i)[a-z]:\\users\\' -or
        $cfg -notmatch ('(?im)^\s*home\s*=\s*' + [regex]::Escape($pythonBase) + '\s*$')) {
        throw 'STAGING_PYVENV_CFG=FAIL'
    }
    $distributionState = Resolve-TradingLabStagingDistributionState `
        (Get-LockedWheelManifest) @($metadata.distributions) @('pip')
    if (-not $distributionState.valid) {
        throw "STAGING_DISTRIBUTIONS=FAIL: missing=$(@($distributionState.missing_requirements).Count); mismatch=$(@($distributionState.version_mismatches).Count); unexpected=$(@($distributionState.unexpected_distributions).Count); duplicate=$(@($distributionState.duplicate_distributions).Count)"
    }
    if (-not $distributionState.metatrader5_metadata) { throw 'STAGING_METATRADER5_METADATA=FAIL' }
    Assert-TreeNotModifiableByServices $Root
    $report.post_build_validation = [ordered]@{
        metadata = $metadata
        distributions = $distributionState
        pyvenv_cfg = 'PASS_MACHINE_BASE_NO_USER_PROFILE'
        service_mutation_rights = 'DENY_PASS'
    }
    $report.gates.STAGING_PYTHON_VERSION = 'PASS'
    $report.gates.STAGING_PYTHON_ARCH = 'PASS'
    $report.gates.STAGING_PREFIX = 'PASS'
    $report.gates.STAGING_BASE_PREFIX = 'PASS'
    $report.gates.STAGING_EXECUTABLE = 'PASS'
    $report.gates.STAGING_NO_USER_PROFILE_DEPENDENCY = 'PASS'
    $report.gates.STAGING_LOCK_REQUIREMENTS = $distributionState.expected_requirements
    $report.gates.STAGING_MISSING_REQUIREMENTS = @($distributionState.missing_requirements).Count
    $report.gates.STAGING_VERSION_MISMATCHES = @($distributionState.version_mismatches).Count
    $report.gates.STAGING_UNEXPECTED_DISTRIBUTIONS = @($distributionState.unexpected_distributions).Count
    $report.gates.STAGING_METATRADER5_METADATA = 'PASS'
    $report.gates.STAGING_SERVICE_MUTATION_DENY = 'PASS'
    return $metadata
}

function Start-LoggedInstaller([string] $Executable, [string[]] $Arguments, [string] $LogPath) {
    $allArguments = @($Arguments) + @('/log', $LogPath)
    $argumentLine = (($allArguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $process = Start-Process -FilePath $Executable -ArgumentList $argumentLine -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        $classification = Resolve-TradingLabInstallerExit $process.ExitCode
        throw "$classification`: exit=$($process.ExitCode); log=$LogPath"
    }
}

function Assert-MachineInstallationInventory([object] $Inventory) {
    if (-not (Test-InstalledMachineRuntimePending $Inventory)) {
        throw 'MACHINE_TRADITIONAL_REGISTRATION=FAIL: expected exact machine payload, PythonCore and four SYSTEM MSI components.'
    }
    foreach ($component in @($Inventory.msi_products)) {
        if (
            $component.user_data_sid -ne $systemSid -or
            $component.display_version -ne '3.14.5150.0' -or
            -not $component.local_package -or
            -not (Test-PathWithin $component.local_package (Join-Path $env:WINDIR 'Installer')) -or
            -not (Test-Path -LiteralPath $component.local_package -PathType Leaf)
        ) { throw "MACHINE_MSI_COMPONENT=FAIL: $($component.product_code)" }
    }
    $report.gates.EXPECTED_MACHINE_MSI_COMPONENTS = 4
    $report.gates.UNEXPECTED_MACHINE_MSI_COMPONENTS = 0
}

function Get-MachineRuntimeAclState {
    $audit = Get-MachineRuntimeAclAudit $pythonBase
    return [pscustomobject]@{
        state = if ($audit.valid) { 'EXACT' } else { 'INCOMPLETE' }
        audit = $audit
    }
}

function Get-ReadOnlyVerifiedMachineRuntimeInventory([object] $Inventory) {
    $aclAudit = $null
    try {
        if ($Inventory.target_layout.complete_layout) {
            $aclAudit = Get-MachineRuntimeAclAudit $pythonBase
        }
    } catch {
        $reparseFailure = $_.Exception.Message -match 'REPARSE_POINT'
        $aclAudit = [pscustomobject]@{
            valid = $false
            scanned_items = 0
            recursive_findings = 1
            findings = @('ACL_AUDIT_INFRASTRUCTURE_ERROR:' + $_.Exception.GetType().Name)
            unexpected_principals = 0
            reparse_points = if ($reparseFailure) { 1 } else { 0 }
            owner_administrators = $false
            inheritance_protected = $false
            system_full_control = $false
            administrators_full_control = $false
            gateway_read_execute = $false
            agent_allow_aces = 0
            deny_aces = 0
            gateway_mutation_intersection = $null
            error_type = $_.Exception.GetType().Name
            error_code = if ($reparseFailure) { 'REPARSE_POINT_FAIL_CLOSED' } else { 'ACL_AUDIT_INFRASTRUCTURE_ERROR' }
        }
    }
    return ConvertTo-TradingLabVerifiedPythonInventory `
        $Inventory $aclAudit $pythonBase $expectedPythonVersion (Join-Path $env:SystemDrive 'Users')
}

function Assert-FinalVerifiedMachineRuntimeInventory([object] $Inventory) {
    if (
        $Inventory.state.completed_target_runtime -ne 'PRESENT_VERIFIED' -or
        $Inventory.state.prevalidation -ne 'PASS' -or
        $null -eq $Inventory.runtime_verification -or
        -not $Inventory.runtime_verification.verified -or
        $Inventory.runtime_verification.evidence_source -ne 'LIVE_READ_ONLY'
    ) {
        $failures = if ($null -ne $Inventory.runtime_verification) {
            @($Inventory.runtime_verification.failures) -join ','
        } else { 'RUNTIME_VERIFICATION_ABSENT' }
        throw "FINAL_MACHINE_RUNTIME_VERIFICATION=FAIL: $failures"
    }
}

function Set-MachineRuntimeAclPassGates([object] $Audit) {
    if ($null -eq $Audit -or -not $Audit.valid) {
        throw 'PYTHON_RUNTIME_ACL=FAIL: recursive audit did not pass.'
    }
    $report.acl_recursive_audit = $Audit
    $report.gates.ACL_OWNER_ADMINISTRATORS = 'PASS'
    $report.gates.ACL_INHERITANCE_PROTECTED = 'PASS'
    $report.gates.SYSTEM_FULLCONTROL = 'PASS'
    $report.gates.ADMINISTRATORS_FULLCONTROL = 'PASS'
    $report.gates.PYTHON_GATEWAY_EXECUTE = 'PASS'
    $report.gates.PYTHON_GATEWAY_READ = 'PASS'
    $report.gates.PYTHON_GATEWAY_WRITE_DENY = 'PASS'
    $report.gates.PYTHON_GATEWAY_MODIFY_DENY = 'PASS'
    $report.gates.PYTHON_GATEWAY_DELETE_DENY = 'PASS'
    $report.gates.PYTHON_GATEWAY_CHANGE_PERMISSIONS_DENY = 'PASS'
    $report.gates.PYTHON_GATEWAY_TAKE_OWNERSHIP_DENY = 'PASS'
    $report.gates.PYTHON_AGENT_ACCESS_DENY = 'PASS'
    $report.gates.AUTHENTICATED_USERS_MODIFY = 'false'
    $report.gates.USERS_MODIFY = 'false'
    $report.gates.DENY_ACES_USED = 'false'
    $report.gates.ACL_UNEXPECTED_PRINCIPALS = $Audit.unexpected_principals
    $report.gates.ACL_RECURSIVE_FINDINGS = $Audit.recursive_findings
    $report.gates.ACL_REPARSE_POINTS = $Audit.reparse_points
    $report.gates.ACL_OTHER_DOMAINS_MODIFIED = 'false'
    $report.gates.PYTHON_RUNTIME_ACL = 'PASS'
}

function Complete-InstalledMachineRuntime([object] $Inventory) {
    if (-not (Test-InstalledMachineRuntimePending $Inventory)) {
        throw 'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING=FAIL: exact installed payload is absent.'
    }
    $report.recovery_state = 'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING'
    $report.must_not_execute_installer = $true
    $report.installer_reexecuted = $false
    $report.gates.TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING = 'PASS'
    $report.gates.MUST_NOT_EXECUTE_INSTALLER = 'true'
    $report.gates.INSTALLER_REEXECUTED = 'false'

    $evidence = Get-VerifiedInstalledRuntimePendingEvidence
    $report.required_previous_phase = 'InstallMachineRuntime'
    $report.previous_phase_verified = $true
    $report.previous_phase_report = $evidence.path
    $report.previous_phase_report_sha256 = $evidence.sha256
    $report.installer_result_log = $evidence.log_path
    $report.installer_result_log_sha256 = $evidence.log_sha256
    $report.gates.INSTALLED_RUNTIME_EVIDENCE = 'PASS'
    $report.gates.INSTALLER_RESULT_EVIDENCE = 'PASS'

    $metadata = Assert-BasePython $basePython
    Assert-MachineInstallationInventory $Inventory
    Set-MachineRuntimePassGates $metadata
    $report.inventory_after = $Inventory.state

    $aclPlan = New-MachineRuntimeAclPlan $pythonBase
    Set-MachineRuntimeAclPlanGates $aclPlan
    $report.acl_apply_requested = [bool]$Apply

    $aclState = Get-MachineRuntimeAclState
    $report.acl_recursive_audit = $aclState.audit
    if ($aclState.state -eq 'EXACT') {
        $report.recovery_state = 'TARGET_RUNTIME_ACL_ALREADY_APPLIED_VALIDATION_PENDING'
        $report.must_not_call_set_acl = $true
        $report.acl_reapplied = $false
        $report.gates.TARGET_RUNTIME_ACL_ALREADY_APPLIED_VALIDATION_PENDING = 'PASS'
        $report.gates.MUST_NOT_CALL_SET_ACL = 'true'
        $report.gates.ACL_REAPPLIED = 'false'
        Set-MachineRuntimeAclPassGates $aclState.audit
        $Inventory = ConvertTo-TradingLabVerifiedPythonInventory `
            $Inventory $aclState.audit $pythonBase $expectedPythonVersion (Join-Path $env:SystemDrive 'Users')
        Assert-FinalVerifiedMachineRuntimeInventory $Inventory
        $report.inventory_after = $Inventory.state
        if ($Apply) {
            Initialize-PhaseStorage
            $report.current_run_applied_phase = 'MachineRuntimeValidationRecovered'
        }
        return
    }

    $report.gates.PYTHON_RUNTIME_ACL = 'INCOMPLETE_REQUIRES_EXPLICIT_APPLY'
    if (-not $Apply) { return }
    Initialize-PhaseStorage
    $report.current_run_applied_phase = 'MachineRuntimeAclRecoveryRequested'
    Protect-ExactRuntimeTree $pythonBase $aclPlan
    $report.machine_runtime_acl_modified = $true
    $report.acl_modified = $true
    $report.acl_applied = $true
    $report.acl_reapplied = $true
    $postApplyAudit = Assert-ExactBaseAcl $pythonBase
    $report.current_run_applied_phase = 'MachineRuntimeAclRecovered'
    Set-MachineRuntimeAclPassGates $postApplyAudit
    $Inventory = ConvertTo-TradingLabVerifiedPythonInventory `
        $Inventory $postApplyAudit $pythonBase $expectedPythonVersion (Join-Path $env:SystemDrive 'Users')
    Assert-FinalVerifiedMachineRuntimeInventory $Inventory
    $report.inventory_after = $Inventory.state
}

function Write-Report {
    $json = $report | ConvertTo-Json -Depth 10
    $stream = [System.IO.File]::Open(
        $reportPath, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally { $stream.Dispose() }
}

function Write-Gates {
    foreach ($gate in $report.gates.GetEnumerator()) {
        Write-Output "$($gate.Key)=$($gate.Value)"
    }
}

function Write-MutationBoundarySummary {
    Write-Output "machine_runtime_acl_modified=$($report.machine_runtime_acl_modified.ToString().ToLowerInvariant())"
    Write-Output "acl_apply_requested=$($report.acl_apply_requested.ToString().ToLowerInvariant())"
    Write-Output "ACL_APPLIED=$($report.acl_applied.ToString().ToLowerInvariant())"
    Write-Output "MUST_NOT_CALL_SET_ACL=$($report.must_not_call_set_acl.ToString().ToLowerInvariant())"
    Write-Output "ACL_REAPPLIED=$($report.acl_reapplied.ToString().ToLowerInvariant())"
    Write-Output "SET_ACL_CALL_COUNT=$($report.set_acl_call_count)"
    Write-Output "installer_executed=$($report.installer_executed.ToString().ToLowerInvariant())"
    Write-Output "STAGING_VENV_CREATED=$($report.staging_venv_created.ToString().ToLowerInvariant())"
    Write-Output "STAGING_BUILD_FAILED=$($report.staging_build_failed.ToString().ToLowerInvariant())"
    Write-Output "STAGING_LEFT_FOR_INSPECTION=$($report.staging_left_for_inspection.ToString().ToLowerInvariant())"
    Write-Output "VENV_REBUILT=$($report.venv_rebuilt.ToString().ToLowerInvariant())"
    Write-Output "VENV_PROMOTED=$($report.venv_promoted.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_MODIFIED=$($report.active_venv_modified.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_DELETED=$($report.active_venv_deleted.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_RENAMED=$($report.active_venv_renamed.ToString().ToLowerInvariant())"
    Write-Output "ACTIVE_VENV_EXECUTED=$($report.active_venv_executed.ToString().ToLowerInvariant())"
    Write-Output "MT5_IMPORTED=$($report.mt5_imported.ToString().ToLowerInvariant())"
    Write-Output "MT5_ACCESSED=$($report.mt5_accessed.ToString().ToLowerInvariant())"
    Write-Output "ORDER_CHECK_CALLED=$($report.order_check_called.ToString().ToLowerInvariant())"
    Write-Output "ORDER_SEND_CALLED=$($report.order_send_called.ToString().ToLowerInvariant())"
    Write-Output "ORDER_CHECK=$($report.order_check_called.ToString().ToLowerInvariant())"
    Write-Output "ORDER_SEND=$($report.order_send_called.ToString().ToLowerInvariant())"
    Write-Output "ACL_MODIFIED=$($report.acl_modified.ToString().ToLowerInvariant())"
    Write-Output "GATEWAY_STARTED=$($report.gateway_started.ToString().ToLowerInvariant())"
    Write-Output "AUTOMATON_STARTED=$($report.automaton_started.ToString().ToLowerInvariant())"
}

function Write-BuildVenvPreflightSummary {
    if ($Phase -ne 'BuildVenv' -or $null -eq $report.build_venv_plan) { return }
    Write-Output "required_previous_phase=$($report.required_previous_phase)"
    Write-Output "previous_phase_verified=$($report.previous_phase_verified.ToString().ToLowerInvariant())"
    Write-Output "previous_phase_report=$($report.previous_phase_report)"
    Write-Output "previous_phase_report_sha256=$($report.previous_phase_report_sha256)"
    Write-Output "GATEWAY_PYTHON_BASE_REPORT=$($report.gateway_python_base_report)"
    Write-Output "GATEWAY_PYTHON_BASE_REPORT_SHA256=$($report.gateway_python_base_report_sha256)"
    Write-Output "AGENT_PYTHON_BASE_REPORT=$($report.agent_python_base_report)"
    Write-Output "AGENT_PYTHON_BASE_REPORT_SHA256=$($report.agent_python_base_report_sha256)"
    Write-Output "RUNTIME_EVIDENCE_MODE=$($report.runtime_verification.evidence_source)"
    Write-Output "COMPLETED_TARGET_RUNTIME=$($report.inventory_before.completed_target_runtime)"
    Write-Output "RUNTIME_VERIFICATION=$($report.runtime_verification.status)"
    Write-Output "PREVALIDATION=$($report.inventory_before.prevalidation)"
    Write-Output "WHEELHOUSE_EXPECTED_REQUIREMENTS=$($report.wheelhouse_validation.expected_requirements)"
    Write-Output "WHEELHOUSE_ARTIFACT_COUNT=$($report.wheelhouse_validation.artifact_count)"
    Write-Output "WHEELHOUSE_MISSING_REQUIREMENTS=$(@($report.wheelhouse_validation.missing_requirements).Count)"
    Write-Output "WHEELHOUSE_CORRUPT_ARTIFACTS=$(@($report.wheelhouse_validation.corrupt_artifacts).Count)"
    Write-Output "WHEELHOUSE_SOURCE_DISTRIBUTIONS=$(@($report.wheelhouse_validation.source_distributions).Count)"
    Write-Output "WHEELHOUSE_UNEXPECTED_ARTIFACTS=$(@($report.wheelhouse_validation.unexpected_artifacts).Count)"
    Write-Output "WHEELHOUSE_DUPLICATE_REQUIREMENTS=$(@($report.wheelhouse_validation.duplicate_requirements).Count)"
    Write-Output "build_venv_plan=$($report.build_venv_plan | ConvertTo-Json -Depth 8 -Compress)"
    Write-Output "post_build_validation_plan=$($report.post_build_validation_plan | ConvertTo-Json -Depth 8 -Compress)"
}

function Write-UninstallPreflightSummary {
    if ($Phase -ne 'UninstallTraditional' -or $null -eq $report.uninstall_plan) { return }
    Write-Output "required_previous_phase=$($report.required_previous_phase)"
    Write-Output "previous_phase_verified=$($report.previous_phase_verified.ToString().ToLowerInvariant())"
    Write-Output "previous_phase_report=$($report.previous_phase_report)"
    Write-Output "WHEELHOUSE_EXPECTED_REQUIREMENTS=$($report.wheelhouse_validation.expected_requirements)"
    Write-Output "WHEELHOUSE_ARTIFACT_COUNT=$($report.wheelhouse_validation.artifact_count)"
    Write-Output "WHEELHOUSE_MISSING_REQUIREMENTS=$(@($report.wheelhouse_validation.missing_requirements).Count)"
    Write-Output "WHEELHOUSE_SOURCE_DISTRIBUTIONS=$(@($report.wheelhouse_validation.source_distributions).Count)"
    Write-Output "WHEELHOUSE_UNEXPECTED_ARTIFACTS=$(@($report.wheelhouse_validation.unexpected_artifacts).Count)"
    Write-Output "WHEELHOUSE_CORRUPT_ARTIFACTS=$(@($report.wheelhouse_validation.corrupt_artifacts).Count)"
    Write-Output "PYTHON_MANAGER_PRESERVE_PATH=$($report.python_manager_preserve_path)"
    Write-Output "TRADITIONAL_BUNDLE_DISPLAY_NAME=$($report.traditional_bundle_target.display_name)"
    Write-Output "TRADITIONAL_BUNDLE_REGISTRY_ID=$($report.traditional_bundle_target.registry_id)"
    Write-Output "TRADITIONAL_BUNDLE_UNINSTALLER=$($report.traditional_bundle_uninstaller)"
    $index = 0
    foreach ($component in $report.traditional_msi_components) {
        $index++
        Write-Output ("TRADITIONAL_MSI_COMPONENT_{0:D2}={1}|{2}" -f `
            $index, $component.product_code, $component.display_name)
    }
}

function Write-InstallMachineRuntimePreflightSummary {
    if ($Phase -ne 'InstallMachineRuntime' -or $null -eq $report.installer_plan) { return }
    Write-Output "required_previous_phase=$($report.required_previous_phase)"
    Write-Output "previous_phase_verified=$($report.previous_phase_verified.ToString().ToLowerInvariant())"
    Write-Output "previous_phase_report=$($report.previous_phase_report)"
    Write-Output "previous_phase_report_sha256=$($report.previous_phase_report_sha256)"
    Write-Output "WHEELHOUSE_EXPECTED_REQUIREMENTS=$($report.wheelhouse_validation.expected_requirements)"
    Write-Output "WHEELHOUSE_ARTIFACT_COUNT=$($report.wheelhouse_validation.artifact_count)"
    Write-Output "WHEELHOUSE_MISSING_REQUIREMENTS=$(@($report.wheelhouse_validation.missing_requirements).Count)"
    Write-Output "WHEELHOUSE_SOURCE_DISTRIBUTIONS=$(@($report.wheelhouse_validation.source_distributions).Count)"
    Write-Output "WHEELHOUSE_UNEXPECTED_ARTIFACTS=$(@($report.wheelhouse_validation.unexpected_artifacts).Count)"
    Write-Output "WHEELHOUSE_CORRUPT_ARTIFACTS=$(@($report.wheelhouse_validation.corrupt_artifacts).Count)"
    Write-Output "installer_plan.operation=$($report.installer_plan.operation)"
    Write-Output "installer_plan.executable=$($report.installer_plan.executable)"
    Write-Output "installer_plan.arguments=$(@($report.installer_plan.arguments) | ConvertTo-Json -Compress)"
    Write-Output "installer_plan.target_dir=$($report.installer_plan.target_dir)"
    Write-Output "installer_plan.log_path_template=$($report.installer_plan.log_path_template)"
    foreach ($component in $report.installer_plan.components.GetEnumerator()) {
        Write-Output "installer_plan.components.$($component.Key)=$($component.Value)"
    }
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Python runtime recovery requires an elevated Administrator token.'
    }
    if ((Get-CanonicalPath $workspace) -ne 'C:\automaton') { throw 'Unexpected workspace path.' }
    if ((Get-CanonicalPath $pythonBase) -ne 'C:\Program Files\AutomatonPython\3.14.5') {
        throw 'Unexpected machine-wide Python target.'
    }
    Assert-OutsideUserProfiles $pythonBase 'Machine-wide Python target'
    Assert-OutsideUserProfiles $venvPath 'Active venv'
    Assert-OutsideUserProfiles $stagingVenvPath 'Staging venv'
    Assert-DependencyLock
    $report.gates.DECLARATIVE_HASH_LOCK = 'PASS'

    $inventory = Get-TradingLabPythonInventory
    if ($Phase -in @('Inventory', 'BuildVenv')) {
        $inventory = Get-ReadOnlyVerifiedMachineRuntimeInventory $inventory
    }
    $report.inventory_before = $inventory.state
    if ($Phase -eq 'Inventory') {
        if ($Apply) { throw 'INVENTORY_APPLY_FORBIDDEN: select one explicit recovery phase.' }
        $inventory | ConvertTo-Json -Depth 10
        Write-Output "PYTHON_MANAGER_RUNTIME=$($inventory.state.python_manager_runtime)"
        Write-Output "TRADITIONAL_USER_RUNTIME=$($inventory.state.traditional_user_runtime)"
        Write-Output "TRADITIONAL_MACHINE_RUNTIME=$($inventory.state.traditional_machine_runtime)"
        Write-Output "TRADITIONAL_BUNDLE_REGISTRATION_SCOPE=$($inventory.state.traditional_bundle_registration_scope)"
        Write-Output "TRADITIONAL_RUNTIME_PAYLOAD_SCOPE=$($inventory.state.traditional_runtime_payload_scope)"
        Write-Output "MACHINE_RUNTIME_TARGET_PRESENT=$($inventory.state.machine_runtime_target_present)"
        Write-Output "MACHINE_RUNTIME_MSI_COMPONENTS=$($inventory.state.machine_runtime_msi_components)"
        Write-Output "PARTIAL_TARGET_RUNTIME=$($inventory.state.partial_target_runtime)"
        Write-Output "BROKEN_ACTIVE_VENV=$($inventory.state.broken_active_venv)"
        Write-Output "MIXED_PYTHONCORE_REGISTRATION=$($inventory.state.mixed_pythoncore_registration)"
        Write-Output "TRADITIONAL_MSI_COMPONENTS=$($inventory.state.traditional_msi_components)"
        Write-Output "SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=$($inventory.state.same_version_traditional_install_present)"
        Write-Output "COMPLETED_TARGET_RUNTIME=$($inventory.state.completed_target_runtime)"
        Write-Output "RUNTIME_VERIFICATION=$($inventory.runtime_verification.status)"
        Write-Output "RUNTIME_VERIFICATION_FAILURES=$(@($inventory.runtime_verification.failures) -join ',')"
        Write-Output "PREVALIDATION=$($inventory.state.prevalidation)"
        if ($inventory.state.prevalidation -ne 'PASS') { exit 2 }
        exit 0
    }

    Assert-ExactServiceIdentity 'AutomatonAgent' $agentSid
    Assert-ExactServiceIdentity 'AutomatonGateway' $gatewaySid
    Assert-LabStoppedAndObserveOnly
    $report.gates.TRADING_MODE_OBSERVE_ONLY = 'PASS'
    $managerPython = Assert-ManagerRuntime $inventory
    $report.gates.PYTHON_MANAGER_RUNTIME = 'PASS'

    switch ($Phase) {
        'PrepareWheelhouse' {
            if (Test-Path -LiteralPath $wheelhousePath) {
                $wheelhouseState = Assert-Wheelhouse $wheelhousePath
                $report.wheelhouse_validation = $wheelhouseState
                $report.gates.WHEELHOUSE_PRESENT = 'PASS'
                $report.gates.WHEELHOUSE_HASH_LOCKED = 'PASS'
                $report.gates.WHEELHOUSE_COMPLETE = 'PASS'
                $report.gates.META_TRADER5_WHEEL_PRESENT = 'PASS'
                $report.gates.NUMPY_WHEEL_PRESENT = 'PASS'
            }
            if (-not $Apply) { break }
            Initialize-PhaseStorage
            if (-not (Test-Path -LiteralPath $wheelhousePath)) {
                $wheelhouseStaging = Join-Path $maintenanceRoot "wheelhouse.new-$runId"
                if (Test-Path -LiteralPath $wheelhouseStaging) { throw 'WHEELHOUSE_STAGING_COLLISION=FAIL' }
                [void][System.IO.Directory]::CreateDirectory($wheelhouseStaging)
                $report.current_run_applied_phase = 'PrepareWheelhouseRequested'
                Invoke-LoggedProcess $managerPython @(
                    '-I', '-m', 'pip', 'download', '--disable-pip-version-check', '--no-input',
                    '--dest', $wheelhouseStaging, '--only-binary=:all:', '--require-hashes', '-r', $lockPath
                ) 'wheelhouse-download'
                [void](Assert-Wheelhouse $wheelhouseStaging)
                $wheelhouseParent = Split-Path $wheelhousePath -Parent
                if (-not (Test-Path -LiteralPath $wheelhouseParent)) {
                    [void][System.IO.Directory]::CreateDirectory($wheelhouseParent)
                }
                Move-Item -LiteralPath $wheelhouseStaging -Destination $wheelhousePath
            }
            $wheelhouseState = Assert-Wheelhouse $wheelhousePath
            $report.wheelhouse_validation = $wheelhouseState
            $report.current_run_applied_phase = 'PrepareWheelhouse'
            $report.gates.WHEELHOUSE_PRESENT = 'PASS'
            $report.gates.WHEELHOUSE_HASH_LOCKED = 'PASS'
            $report.gates.WHEELHOUSE_COMPLETE = 'PASS'
            $report.gates.META_TRADER5_WHEEL_PRESENT = 'PASS'
            $report.gates.NUMPY_WHEEL_PRESENT = 'PASS'
        }
        'UninstallTraditional' {
            $report.required_previous_phase = 'PrepareWheelhouse'
            $wheelhouseState = Assert-Wheelhouse $wheelhousePath
            $report.wheelhouse_validation = $wheelhouseState
            $report.gates.WHEELHOUSE_PRESENT = 'PASS'
            $report.gates.WHEELHOUSE_HASH_LOCKED = 'PASS'
            $report.gates.WHEELHOUSE_COMPLETE = 'PASS'
            $report.gates.META_TRADER5_WHEEL_PRESENT = 'PASS'
            $report.gates.NUMPY_WHEEL_PRESENT = 'PASS'
            $previousEvidence = Get-VerifiedPrepareWheelhouseEvidence
            $report.previous_phase_verified = $true
            $report.previous_phase_report = $previousEvidence.path
            $report.previous_phase_report_sha256 = $previousEvidence.sha256
            $report.gates.PREVIOUS_PHASE_PREPARE_WHEELHOUSE = 'PASS'

            $bundle = Get-RegisteredTraditionalBundle $inventory
            $bundleExecutable = Resolve-RegisteredBundleExecutable $bundle
            $components = Assert-ExpectedTraditionalMsiComponents $inventory $identity.User.Value
            $plan = New-TraditionalUninstallPlan $bundle $bundleExecutable $components
            $managerEvidence = Assert-PythonManagerPreserved $inventory $plan
            Assert-UninstallPlanHasNoDirectCleanup $plan
            if ($inventory.state.partial_target_runtime -ne 'PRESENT') {
                throw 'PARTIAL_TARGET_NOT_DELETED_YET=FAIL: expected current recovery input is absent.'
            }
            if (
                -not $inventory.active_venv.redirector_exists -or
                -not $inventory.active_venv.pyvenv_cfg_exists
            ) { throw 'ACTIVE_VENV_UNTOUCHED=FAIL: active venv evidence is absent before uninstall.' }

            $report.python_manager_preserve_path = $managerEvidence.path
            $report.traditional_bundle_target = [ordered]@{
                display_name = $bundle.display_name
                registry_id = $bundle.registry_id.ToUpperInvariant()
            }
            $report.traditional_bundle_uninstaller = $bundleExecutable
            $report.traditional_msi_components = @($plan.expected_msi_components)
            $report.uninstall_plan = $plan
            $report.gates.PYTHON_MANAGER_RUNTIME = 'PASS'
            $report.gates.PYTHON_MANAGER_PRESERVE = 'PASS'
            $report.gates.TRADITIONAL_BUNDLE_TARGET = 'PASS'
            $report.gates.TRADITIONAL_MSI_COMPONENTS_EXPECTED = 9
            $report.gates.NO_MANUAL_REGISTRY_CLEANUP = 'PASS'
            $report.gates.NO_PACKAGE_CACHE_DELETE = 'PASS'
            $report.gates.NO_WINDOWS_INSTALLER_CACHE_DELETE = 'PASS'
            $report.gates.ACTIVE_VENV_UNTOUCHED = 'PASS'
            $report.gates.PARTIAL_TARGET_NOT_DELETED_YET = 'PASS'
            $report.gates.SAME_VERSION_TRADITIONAL_INSTALL_PRESENT = 'FAIL_EXPECTED_RECOVERY_INPUT'
            $report.gates.REGISTERED_UNINSTALLER_VERIFIED = 'PASS'
            if (-not $Apply) { break }
            if (-not $report.previous_phase_verified -or $report.required_previous_phase -ne 'PrepareWheelhouse') {
                throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: destructive execution is not authorized by stale current-run state.'
            }
            Initialize-PhaseStorage
            $uninstallLog = New-PhaseLogPath 'traditional-uninstall'
            $report.uninstaller_executed = $true
            $report.current_run_applied_phase = 'UninstallTraditionalRequested'
            Start-LoggedInstaller $bundleExecutable @('/uninstall', '/quiet') $uninstallLog
            $report.current_run_applied_phase = 'UninstallTraditional'
            $after = Get-TradingLabPythonInventory
            $report.inventory_after = $after.state
            [void](Assert-ManagerRuntime $after)
            Assert-NoTraditionalRuntime $after
            $report.gates.SAME_VERSION_TRADITIONAL_INSTALL_PRESENT = 'PASS'
            $report.gates.PYTHON_MANAGER_PRESERVE = 'PASS'
            $report.gates.PARTIAL_TARGET_POST_STATE = $after.state.partial_target_runtime
            $report.gates.MIXED_PYTHONCORE_POST_STATE = $after.state.mixed_pythoncore_registration
        }
        'InstallMachineRuntime' {
            if (Test-InstalledMachineRuntimePending $inventory) {
                Complete-InstalledMachineRuntime $inventory
                break
            }
            $report.required_previous_phase = 'UninstallTraditional'
            $previousEvidence = Get-VerifiedUninstallTraditionalEvidence
            $report.previous_phase_verified = $true
            $report.previous_phase_report = $previousEvidence.path
            $report.previous_phase_report_sha256 = $previousEvidence.sha256
            $report.gates.PREVIOUS_PHASE_UNINSTALL_TRADITIONAL = 'PASS'

            $wheelhouseState = Assert-Wheelhouse $wheelhousePath
            Set-WheelhousePassGates $wheelhouseState
            $InstallerPath = Assert-Installer $InstallerPath
            $report.installer = $InstallerPath
            $report.gates.PYTHON_INSTALLER_SIZE = 'PASS'
            $report.gates.PYTHON_INSTALLER_SHA256 = 'PASS'
            $report.gates.PYTHON_INSTALLER_AUTHENTICODE = 'PASS'
            $report.gates.PYTHON_INSTALLER_VERIFIED = 'PASS'
            $plan = New-MachineRuntimeInstallerPlan $InstallerPath
            Assert-MachineInstallerPlan $plan
            $report.installer_plan = $plan

            Assert-InstallMachinePreconditions $inventory
            if (-not $Apply) { break }
            if (-not $report.previous_phase_verified -or $report.required_previous_phase -ne 'UninstallTraditional') {
                throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: installation is not authorized by durable evidence.'
            }
            Initialize-PhaseStorage
            $installLog = New-PhaseLogPath 'machine-install'
            $report.installer_executed = $true
            $report.installer_reexecuted = $false
            $report.current_run_applied_phase = 'InstallMachineRuntimeRequested'
            Start-LoggedInstaller $plan.executable $plan.arguments $installLog
            $report.current_run_applied_phase = 'InstallMachineRuntime'
            $metadata = Assert-BasePython $basePython
            $after = Get-TradingLabPythonInventory
            $report.inventory_after = $after.state
            Assert-MachineInstallationInventory $after
            $aclPlan = New-MachineRuntimeAclPlan $pythonBase
            Set-MachineRuntimeAclPlanGates $aclPlan
            $report.acl_apply_requested = $true
            Protect-ExactRuntimeTree $pythonBase $aclPlan
            $report.machine_runtime_acl_modified = $true
            $report.acl_modified = $true
            $report.acl_applied = $true
            $freshAclAudit = Assert-ExactBaseAcl $pythonBase
            Set-MachineRuntimePassGates $metadata
            Set-MachineRuntimeAclPassGates $freshAclAudit
            $after = ConvertTo-TradingLabVerifiedPythonInventory `
                $after $freshAclAudit $pythonBase $expectedPythonVersion (Join-Path $env:SystemDrive 'Users')
            Assert-FinalVerifiedMachineRuntimeInventory $after
            $report.inventory_after = $after.state
            $report.gates.INSTALLER_REEXECUTED = 'false'
        }
        'ResumeMachineRuntime' {
            Complete-InstalledMachineRuntime $inventory
        }
        'BuildVenv' {
            if ([string]::IsNullOrWhiteSpace($GatewayPythonBaseRunId) -or
                [string]::IsNullOrWhiteSpace($AgentPythonBaseRunId)) {
                throw 'PYTHON_BASE_RUNTIME_RUN_IDS_REQUIRED=FAIL: supply both explicit UUIDs.'
            }
            $report.must_not_execute_installer = $true
            $report.must_not_call_set_acl = $true
            $report.gates.MUST_NOT_EXECUTE_INSTALLER = 'true'
            $report.gates.INSTALLER_REEXECUTED = 'false'
            $report.gates.MUST_NOT_CALL_SET_ACL = 'true'
            $report.gates.SET_ACL_CALL_COUNT = 0

            $previousEvidence = Get-VerifiedResumeMachineRuntimeEvidence
            $report.required_previous_phase = 'ResumeMachineRuntime'
            $report.previous_phase_verified = $true
            $report.previous_phase_report = $previousEvidence.path
            $report.previous_phase_report_sha256 = $previousEvidence.sha256
            $report.gates.PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME = 'PASS'

            $gatewayEvidence = Get-VerifiedPythonBaseRuntimeEvidence `
                'AutomatonGateway' $GatewayPythonBaseRunId $gatewaySid
            $report.gateway_python_base_run_id = $gatewayEvidence.record.run_id
            $report.gateway_python_base_report = $gatewayEvidence.path
            $report.gateway_python_base_report_sha256 = $gatewayEvidence.sha256
            $report.gates.GATEWAY_PYTHON_BASE_RUNTIME_EVIDENCE = 'PASS'
            $agentEvidence = Get-VerifiedPythonBaseRuntimeEvidence `
                'AutomatonAgent' $AgentPythonBaseRunId $agentSid
            $report.agent_python_base_run_id = $agentEvidence.record.run_id
            $report.agent_python_base_report = $agentEvidence.path
            $report.agent_python_base_report_sha256 = $agentEvidence.sha256
            $report.gates.AGENT_PYTHON_BASE_RUNTIME_EVIDENCE = 'PASS'

            Assert-FinalVerifiedMachineRuntimeInventory $inventory
            Assert-MachineInstallationInventory $inventory
            $report.runtime_verification = $inventory.runtime_verification
            $report.gates.COMPLETED_TARGET_RUNTIME = 'PRESENT_VERIFIED'
            $report.gates.RUNTIME_VERIFICATION = 'VERIFIED'
            $report.gates.PREVALIDATION = 'PASS'
            $report.gates.RUNTIME_EVIDENCE_MODE = 'LIVE_READ_ONLY'
            $baseMetadata = Assert-BasePython $basePython
            Set-MachineRuntimePassGates $baseMetadata
            $baseAcl = Assert-ExactBaseAcl $pythonBase
            Set-MachineRuntimeAclPassGates $baseAcl

            $wheelhouseState = Assert-Wheelhouse $wheelhousePath
            Set-WheelhousePassGates $wheelhouseState
            if (Test-Path -LiteralPath $stagingVenvPath) {
                throw 'STAGING_VENV_ABSENT=FAIL: existing staging requires separate human inspection/removal authorization.'
            }
            $report.gates.STAGING_VENV_ABSENT = 'PASS'
            $report.build_venv_plan = New-BuildVenvPlan
            Assert-BuildVenvPlan $report.build_venv_plan
            $report.post_build_validation_plan = New-PostBuildValidationPlan
            if (-not $Apply) { break }
            if (-not $report.previous_phase_verified -or
                $report.required_previous_phase -ne 'ResumeMachineRuntime') {
                throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: BuildVenv Apply lacks durable authorization evidence.'
            }
            Initialize-PhaseStorage
            $tempPath = Initialize-BuildVenvPrivateTemp $report.build_venv_plan.temp_path
            try {
                $report.current_run_applied_phase = 'BuildVenvRequested'
                $createStep = $report.build_venv_plan.steps[0]
                [void](Invoke-BuildVenvProcess $createStep.executable `
                    @($createStep.arguments) 'venv-create' $tempPath)
                $report.staging_venv_created = Test-Path -LiteralPath $stagingVenvPath -PathType Container
                if (-not $report.staging_venv_created) { throw 'STAGING_VENV_CREATED=FAIL' }
                $installStep = $report.build_venv_plan.steps[1]
                [void](Invoke-BuildVenvProcess $installStep.executable `
                    @($installStep.arguments) 'venv-install' $tempPath)
                [void](Assert-StagingVenv $stagingVenvPath $tempPath)
                $report.current_run_applied_phase = 'BuildVenv'
                $report.venv_rebuilt = $true
                $report.mt5_package_installed = $true
                $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
                $report.gates.VENV_LOCK_MATCH = 'PASS'
                $report.gates.META_TRADER5_PACKAGE_PRESENT = 'PASS'
            } catch {
                $report.staging_build_failed = $true
                $report.staging_left_for_inspection = Test-Path -LiteralPath $stagingVenvPath
                $report.staging_venv_created = $report.staging_left_for_inspection
                throw
            } finally {
                if (-not (Clear-BuildVenvPrivateTemp $tempPath)) {
                    Write-Warning 'BuildVenv private TEMP cleanup failed; staging was not promoted or removed.'
                }
            }
        }
        'PromoteVenv' {
            Assert-MachineInstallationInventory $inventory
            [void](Assert-BasePython $basePython)
            if (-not (Test-Path -LiteralPath $stagingVenvPath) -and (Test-Path -LiteralPath $venvPath)) {
                [void](Assert-Venv $venvPath)
                $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
                $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
                $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
                $report.gates.VENV_LOCK_MATCH = 'PASS'
                $report.gates.META_TRADER5_PACKAGE_PRESENT = 'PASS'
                if ($Apply) { Initialize-PhaseStorage; $report.current_run_applied_phase = 'PromoteVenvAlreadyComplete' }
                break
            }
            [void](Assert-Venv $stagingVenvPath)
            if ((git -C $workspace status --porcelain=v1 --untracked-files=no | Out-String).Trim()) {
                throw 'WORKTREE_TRACKED_CHANGES=FAIL: commit reviewed source before promotion.'
            }
            if (-not $Apply) { break }
            Initialize-PhaseStorage
            $backupPath = Join-Path $maintenanceRoot "venv-admin-base-backup-$runId"
            if (Test-Path -LiteralPath $backupPath) { throw 'VENV_BACKUP_COLLISION=FAIL' }
            $oldMoved = $false
            if (Test-Path -LiteralPath $venvPath) {
                Move-Item -LiteralPath $venvPath -Destination $backupPath
                $oldMoved = $true
            }
            $report.current_run_applied_phase = 'ActiveVenvBackedUp'
            try {
                Move-Item -LiteralPath $stagingVenvPath -Destination $venvPath
                [void](Assert-Venv $venvPath)
                $report.current_run_applied_phase = 'PromoteVenv'
                $report.venv_promoted = $true
            } catch {
                if (Test-Path -LiteralPath $venvPath) {
                    $failedPath = Join-Path $maintenanceRoot "venv-failed-$runId"
                    Move-Item -LiteralPath $venvPath -Destination $failedPath
                    Protect-AdministrativeMaintenanceTree $failedPath
                }
                if ($oldMoved -and -not (Test-Path -LiteralPath $venvPath)) {
                    Move-Item -LiteralPath $backupPath -Destination $venvPath
                    $report.current_run_applied_phase = 'PromotionRolledBack'
                }
                throw
            }
            if ($oldMoved) {
                Protect-AdministrativeMaintenanceTree $backupPath
                $report.old_venv_backup = $backupPath
            }
            $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
            $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
            $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
            $report.gates.VENV_LOCK_MATCH = 'PASS'
            $report.gates.META_TRADER5_PACKAGE_PRESENT = 'PASS'
            $report.gates.GATEWAY_TEMP_OPERATIONAL_ONLY = 'PENDING_RUNTIME_IDENTITY_TEST'
        }
    }

    if (-not $Apply) {
        $report.status = 'DRY_RUN_PASS'
        $report | ConvertTo-Json -Depth 10
        Write-Gates
        Write-UninstallPreflightSummary
        Write-InstallMachineRuntimePreflightSummary
        Write-BuildVenvPreflightSummary
        Write-Output "PYTHON_RECOVERY_PHASE=$Phase"
        Write-Output "MUST_NOT_EXECUTE_INSTALLER=$($report.must_not_execute_installer.ToString().ToLowerInvariant())"
        Write-Output "INSTALLER_REEXECUTED=$($report.installer_reexecuted.ToString().ToLowerInvariant())"
        Write-MutationBoundarySummary
        Write-Output 'PYTHON_RUNTIME_APPLY=NOT_RUN'
        exit 0
    }
    $report.status = 'PASS'
    Write-Report
    Write-Gates
    Write-BuildVenvPreflightSummary
    Write-Output "PYTHON_RECOVERY_PHASE=$Phase"
    Write-Output "MUST_NOT_EXECUTE_INSTALLER=$($report.must_not_execute_installer.ToString().ToLowerInvariant())"
    Write-Output "INSTALLER_REEXECUTED=$($report.installer_reexecuted.ToString().ToLowerInvariant())"
    Write-MutationBoundarySummary
    Write-Output "PYTHON_RUNTIME_GATE_REPORT=$reportPath"
} catch {
    $report.status = 'FAIL'
    $report.error = $_.Exception.Message
    if ($Apply -and $Phase -ne 'Inventory') {
        try {
            Initialize-PhaseStorage
            Write-Report
        } catch {
            Write-Warning 'The durable recovery report could not be written; no retry or promotion was attempted.'
        }
    }
    throw
}
