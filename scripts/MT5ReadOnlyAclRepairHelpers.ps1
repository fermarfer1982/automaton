Set-StrictMode -Version 2.0

function New-MT5AclRuleRecord(
    [string] $Sid,
    [int64] $Rights,
    [bool] $Inherited,
    [string] $Inheritance,
    [string] $Propagation
) {
    return [pscustomobject]@{
        sid = $Sid
        type = 'Allow'
        rights = $Rights
        inherited = $Inherited
        inheritance_flags = $Inheritance
        propagation_flags = $Propagation
    }
}

function Get-MT5AclExpectedRules(
    [ValidateSet('CONTROL', 'DEMO_AUTHORIZATION', 'AUTHORIZATION_FILE')]
    [string] $Kind,
    [string] $GatewaySid,
    [string] $SystemSid = 'S-1-5-18',
    [string] $AdministratorsSid = 'S-1-5-32-544'
) {
    $fullControl = 2032127L
    $read = 1179785L
    $readExecute = 1179817L
    if ($Kind -eq 'AUTHORIZATION_FILE') {
        return @(
            New-MT5AclRuleRecord $SystemSid $fullControl $true 'None' 'None'
            New-MT5AclRuleRecord $AdministratorsSid $fullControl $true 'None' 'None'
            New-MT5AclRuleRecord $GatewaySid $read $true 'None' 'None'
        )
    }
    $rules = @(
        New-MT5AclRuleRecord $SystemSid $fullControl $false `
            'ContainerInherit, ObjectInherit' 'None'
        New-MT5AclRuleRecord $AdministratorsSid $fullControl $false `
            'ContainerInherit, ObjectInherit' 'None'
        New-MT5AclRuleRecord $GatewaySid $readExecute $false 'None' 'None'
    )
    if ($Kind -eq 'DEMO_AUTHORIZATION') {
        $rules += New-MT5AclRuleRecord $GatewaySid $read $false 'ObjectInherit' 'InheritOnly'
    }
    return $rules
}

function Test-MT5AclExactRule($Actual, $Expected) {
    return [string]$Actual.sid -eq [string]$Expected.sid -and
        [string]$Actual.type -eq [string]$Expected.type -and
        [int64]$Actual.rights -eq [int64]$Expected.rights -and
        [bool]$Actual.inherited -eq [bool]$Expected.inherited -and
        [string]$Actual.inheritance_flags -eq [string]$Expected.inheritance_flags -and
        [string]$Actual.propagation_flags -eq [string]$Expected.propagation_flags
}

function Test-MT5AclExactRuleSet($Snapshot, [object[]] $Expected) {
    $actual = @($Snapshot.rules)
    if ($actual.Count -ne $Expected.Count) { return $false }
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $actual) { $remaining.Add($rule) }
    foreach ($expectedRule in $Expected) {
        $match = @($remaining | Where-Object {
            Test-MT5AclExactRule $_ $expectedRule
        } | Select-Object -First 1)
        if ($match.Count -ne 1) { return $false }
        [void]$remaining.Remove($match[0])
    }
    return $remaining.Count -eq 0
}

function Get-MT5AclFilesystemSnapshot([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $ownerSid = try {
        ([System.Security.Principal.NTAccount]::new($acl.Owner)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch { [string]$acl.Owner }
    return [pscustomobject]@{
        path = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
        is_directory = [bool]$item.PSIsContainer
        reparse = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        owner_sid = $ownerSid
        protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All
        )
        rules = @($acl.Access | ForEach-Object {
            $sid = try {
                $_.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
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

function Get-MT5AclDirectorySecuritySnapshot(
    [System.Security.AccessControl.DirectorySecurity] $Security,
    [string] $Path
) {
    return [pscustomobject]@{
        path = $Path
        is_directory = $true
        reparse = $false
        owner_sid = $Security.GetOwner(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        protected = [bool]$Security.AreAccessRulesProtected
        sddl = $Security.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All
        )
        rules = @($Security.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        ) | ForEach-Object {
            [pscustomobject]@{
                sid = $_.IdentityReference.Value
                type = $_.AccessControlType.ToString()
                rights = [int64]$_.FileSystemRights
                inherited = [bool]$_.IsInherited
                inheritance_flags = $_.InheritanceFlags.ToString()
                propagation_flags = $_.PropagationFlags.ToString()
            }
        })
    }
}

function New-MT5AclCanonicalDirectorySecurity(
    [ValidateSet('CONTROL', 'DEMO_AUTHORIZATION')]
    [string] $Kind,
    [string] $GatewaySid,
    [string] $SystemSid = 'S-1-5-18',
    [string] $AdministratorsSid = 'S-1-5-32-544'
) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner(
        [System.Security.Principal.SecurityIdentifier]::new($AdministratorsSid)
    )
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($SystemSid, $AdministratorsSid)) {
        [void]$security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new($sid),
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    [void]$security.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($GatewaySid),
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    )
    if ($Kind -eq 'DEMO_AUTHORIZATION') {
        [void]$security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new($GatewaySid),
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    return $security
}

function Get-MT5AclCanonicalArtifactSddl(
    [string] $GatewaySid,
    [string] $SystemSid = 'S-1-5-18',
    [string] $AdministratorsSid = 'S-1-5-32-544'
) {
    $rawAcl = [System.Security.AccessControl.RawAcl]::new(2, 3)
    $rules = Get-MT5AclExpectedRules 'AUTHORIZATION_FILE' $GatewaySid `
        $SystemSid $AdministratorsSid
    for ($index = 0; $index -lt $rules.Count; $index++) {
        $rule = $rules[$index]
        $ace = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::Inherited,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            [int]$rule.rights,
            [System.Security.Principal.SecurityIdentifier]::new($rule.sid),
            $false,
            $null
        )
        $rawAcl.InsertAce($index, $ace)
    }
    $flags = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
        [System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited
    $administrators = [System.Security.Principal.SecurityIdentifier]::new(
        $AdministratorsSid
    )
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $flags,
        $administrators,
        $administrators,
        $null,
        $rawAcl
    )
    return $descriptor.GetSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All
    )
}

function Get-MT5AclRepairState(
    $Snapshot,
    [ValidateSet('CONTROL', 'DEMO_AUTHORIZATION', 'AUTHORIZATION_FILE')]
    [string] $Kind,
    [string] $GatewaySid,
    [string] $MaintenanceSid,
    [string] $AdministratorsSid = 'S-1-5-32-544'
) {
    $expectDirectory = $Kind -ne 'AUTHORIZATION_FILE'
    if ([bool]$Snapshot.is_directory -ne $expectDirectory -or [bool]$Snapshot.reparse) {
        throw "$Kind target type or reparse state is unsafe: $($Snapshot.path)"
    }
    if ([string]$Snapshot.owner_sid -ne $AdministratorsSid) {
        throw "$Kind owner is not BUILTIN\Administrators: $($Snapshot.path)"
    }
    if ($expectDirectory -and -not [bool]$Snapshot.protected) {
        throw "$Kind directory inheritance must be protected: $($Snapshot.path)"
    }
    if (-not $expectDirectory -and [bool]$Snapshot.protected) {
        throw "Authorization artifact must inherit from its canonical parent: $($Snapshot.path)"
    }
    $canonical = @(Get-MT5AclExpectedRules $Kind $GatewaySid)
    if (Test-MT5AclExactRuleSet $Snapshot $canonical) { return 'CANONICAL' }
    $maintenanceRule = if ($expectDirectory) {
        New-MT5AclRuleRecord $MaintenanceSid 2032127L $false `
            'ContainerInherit, ObjectInherit' 'None'
    } else {
        New-MT5AclRuleRecord $MaintenanceSid 2032127L $true 'None' 'None'
    }
    $knownDrift = @($canonical) + @($maintenanceRule)
    if (Test-MT5AclExactRuleSet $Snapshot $knownDrift) {
        return 'MAINTENANCE_FULL_CONTROL_DRIFT'
    }
    throw "$Kind ACL is outside the single repairable maintenance-drift model: $($Snapshot.path)"
}

function Assert-MT5AclCanonicalSnapshot(
    $Snapshot,
    [ValidateSet('CONTROL', 'DEMO_AUTHORIZATION', 'AUTHORIZATION_FILE')]
    [string] $Kind,
    [string] $GatewaySid,
    [string] $MaintenanceSid
) {
    $state = Get-MT5AclRepairState $Snapshot $Kind $GatewaySid $MaintenanceSid
    if ($state -ne 'CANONICAL') {
        throw "$Kind ACL has not converged to the exact canonical policy."
    }
}

function Get-MT5AclRepairPlan(
    [string] $ControlState,
    [string] $DemoAuthorizationState,
    [string[]] $AuthorizationArtifactStates
) {
    $allowed = @('CANONICAL', 'MAINTENANCE_FULL_CONTROL_DRIFT')
    if ($ControlState -notin $allowed -or $DemoAuthorizationState -notin $allowed -or
        @($AuthorizationArtifactStates | Where-Object { $_ -notin $allowed }).Count -ne 0) {
        throw 'ACL repair plan contains an unreviewed drift state.'
    }
    $controlRepair = $ControlState -ne 'CANONICAL'
    $demoRepair = $DemoAuthorizationState -ne 'CANONICAL'
    $artifactConvergence = @(
        $AuthorizationArtifactStates | Where-Object { $_ -ne 'CANONICAL' }
    ).Count -ne 0
    return [pscustomobject]@{
        drift_detected = $controlRepair -or $demoRepair -or $artifactConvergence
        control_repair_required = $controlRepair
        demo_auth_repair_required = $demoRepair
        auth_file_convergence_required = $artifactConvergence
        control_set_acl_required = $controlRepair
        demo_set_acl_required = $demoRepair -or $artifactConvergence
        forward_set_acl_call_count = [int]$controlRepair + [int]($demoRepair -or $artifactConvergence)
    }
}

function Test-MT5AclSnapshotEqual($First, $Second) {
    return [string]$First.owner_sid -eq [string]$Second.owner_sid -and
        [string]$First.sddl -eq [string]$Second.sddl -and
        [bool]$First.protected -eq [bool]$Second.protected
}
