Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'TradingLabFileSystemRights.ps1')

function Get-TradingLabAclPlanProperty([object] $InputObject, [string] $Name) {
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-TradingLabAclPlanHasProperty([object] $InputObject, [string] $Name) {
    return $null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name]
}

function Test-TradingLabRuntimeAclPlan(
    [object] $Plan,
    [string] $ExpectedTarget,
    [string] $SystemSid,
    [string] $AdministratorsSid,
    [string] $GatewaySid,
    [string] $AgentSid,
    [string] $AuthenticatedUsersSid,
    [string] $UsersSid,
    [int64] $FullControlValue,
    [int64] $GatewayReadExecuteValue
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Plan) {
        $failures.Add('ACL_PLAN_MISSING')
        return [pscustomobject]@{ valid = $false; failures = @($failures) }
    }

    foreach ($requiredProperty in @(
        'target', 'owner', 'owner_sid', 'protect_inheritance',
        'remove_inherited_aces', 'target_tree_reparse_points', 'entries',
        'automaton_agent_effective_access', 'authenticated_users_modify',
        'users_modify', 'deny_aces_planned', 'other_domains_modified'
    )) {
        if (-not (Test-TradingLabAclPlanHasProperty $Plan $requiredProperty)) {
            $failures.Add("ACL_PLAN_PROPERTY_MISSING:$requiredProperty")
        }
    }

    try {
        $target = [System.IO.Path]::GetFullPath([string](Get-TradingLabAclPlanProperty $Plan 'target')).TrimEnd('\')
        $expected = [System.IO.Path]::GetFullPath($ExpectedTarget).TrimEnd('\')
        if (-not $target.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            $failures.Add('ACL_TARGET_NOT_EXACT_RUNTIME')
        }
    } catch { $failures.Add('ACL_TARGET_INVALID') }

    if ((Get-TradingLabAclPlanProperty $Plan 'owner_sid') -ne $AdministratorsSid) {
        $failures.Add('ACL_OWNER_NOT_ADMINISTRATORS')
    }
    if (-not [bool](Get-TradingLabAclPlanProperty $Plan 'protect_inheritance')) {
        $failures.Add('ACL_INHERITANCE_NOT_PROTECTED')
    }
    if (-not [bool](Get-TradingLabAclPlanProperty $Plan 'remove_inherited_aces')) {
        $failures.Add('ACL_INHERITED_ACES_NOT_REMOVED')
    }
    if ([int](Get-TradingLabAclPlanProperty $Plan 'target_tree_reparse_points') -ne 0) {
        $failures.Add('ACL_TARGET_REPARSE_POINT')
    }
    if ([bool](Get-TradingLabAclPlanProperty $Plan 'other_domains_modified')) {
        $failures.Add('ACL_OTHER_DOMAIN_MUTATION')
    }
    if ([int](Get-TradingLabAclPlanProperty $Plan 'deny_aces_planned') -ne 0) {
        $failures.Add('ACL_DENY_ACE_PLANNED')
    }

    $entries = @((Get-TradingLabAclPlanProperty $Plan 'entries'))
    if ($entries.Count -ne 3) { $failures.Add('ACL_ENTRY_COUNT_NOT_EXACT') }
    $rightsBySid = @{}
    foreach ($entry in $entries) {
        foreach ($requiredEntryProperty in @('identity', 'sid', 'rights_value', 'type')) {
            if (-not (Test-TradingLabAclPlanHasProperty $entry $requiredEntryProperty)) {
                $failures.Add("ACL_ENTRY_PROPERTY_MISSING:$requiredEntryProperty")
            }
        }
        $sid = [string](Get-TradingLabAclPlanProperty $entry 'sid')
        $identity = [string](Get-TradingLabAclPlanProperty $entry 'identity')
        $type = [string](Get-TradingLabAclPlanProperty $entry 'type')
        if ([string]::IsNullOrWhiteSpace($sid) -or [string]::IsNullOrWhiteSpace($identity)) {
            $failures.Add('ACL_ENTRY_IDENTITY_UNRESOLVED')
            continue
        }
        if ($type -ne 'Allow') { $failures.Add("ACL_NON_ALLOW_ENTRY:$sid") }
        if ($rightsBySid.ContainsKey($sid)) {
            $failures.Add("ACL_DUPLICATE_SID:$sid")
            continue
        }
        try {
            $rightsBySid[$sid] = [int64](Get-TradingLabAclPlanProperty $entry 'rights_value')
        } catch { $failures.Add("ACL_RIGHTS_INVALID:$sid") }
    }

    $expectedSids = @($SystemSid, $AdministratorsSid, $GatewaySid)
    foreach ($sid in $rightsBySid.Keys) {
        if ($sid -notin $expectedSids) { $failures.Add("ACL_UNEXPECTED_ALLOW:$sid") }
    }
    foreach ($sid in $expectedSids) {
        if (-not $rightsBySid.ContainsKey($sid)) { $failures.Add("ACL_REQUIRED_ALLOW_MISSING:$sid") }
    }
    if ($rightsBySid.ContainsKey($SystemSid) -and $rightsBySid[$SystemSid] -ne $FullControlValue) {
        $failures.Add('ACL_SYSTEM_NOT_EXACT_FULLCONTROL')
    }
    if ($rightsBySid.ContainsKey($AdministratorsSid) -and $rightsBySid[$AdministratorsSid] -ne $FullControlValue) {
        $failures.Add('ACL_ADMINISTRATORS_NOT_EXACT_FULLCONTROL')
    }
    if ($rightsBySid.ContainsKey($GatewaySid) -and $rightsBySid[$GatewaySid] -ne $GatewayReadExecuteValue) {
        $failures.Add('ACL_GATEWAY_RIGHTS_NOT_EXACT_RX')
    }
    foreach ($forbiddenSid in @($AgentSid, $AuthenticatedUsersSid, $UsersSid)) {
        if ($rightsBySid.ContainsKey($forbiddenSid)) { $failures.Add("ACL_FORBIDDEN_ALLOW:$forbiddenSid") }
    }
    if ((Get-TradingLabAclPlanProperty $Plan 'automaton_agent_effective_access') -ne 'NONE') {
        $failures.Add('ACL_AGENT_EFFECTIVE_ACCESS_NOT_NONE')
    }
    if ([bool](Get-TradingLabAclPlanProperty $Plan 'authenticated_users_modify')) {
        $failures.Add('ACL_AUTHENTICATED_USERS_MODIFY')
    }
    if ([bool](Get-TradingLabAclPlanProperty $Plan 'users_modify')) {
        $failures.Add('ACL_USERS_MODIFY')
    }

    return [pscustomobject]@{ valid = $failures.Count -eq 0; failures = @($failures) }
}

function New-TradingLabRuntimeSecurityDescriptor([bool] $Directory, [object] $Plan) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else { [System.Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new(
        [string](Get-TradingLabAclPlanProperty $Plan 'owner_sid')
    ))
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($entry in @((Get-TradingLabAclPlanProperty $Plan 'entries'))) {
        [void]$security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new(
                [string](Get-TradingLabAclPlanProperty $entry 'sid')
            ),
            [System.Security.AccessControl.FileSystemRights][int64](
                Get-TradingLabAclPlanProperty $entry 'rights_value'
            ),
            $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $security
}

function Test-TradingLabRuntimeAclAudit(
    [object[]] $Items,
    [string] $ExpectedTarget,
    [string] $SystemSid,
    [string] $AdministratorsSid,
    [string] $GatewaySid,
    [string] $AgentSid,
    [int64] $FullControlValue,
    [int64] $GatewayReadExecuteValue
) {
    $findings = [System.Collections.Generic.List[string]]::new()
    $unexpectedPrincipals = 0
    $reparsePoints = 0
    $ownerMismatches = 0
    $inheritanceMismatches = 0
    $systemRightsMismatches = 0
    $administratorsRightsMismatches = 0
    $gatewayRightsMismatches = 0
    $gatewayMutationIntersection = 0L
    $agentAllowAces = 0
    $denyAces = 0
    $canonicalTarget = [System.IO.Path]::GetFullPath($ExpectedTarget).TrimEnd('\')
    if (@($Items).Count -eq 0) { $findings.Add('ACL_AUDIT_EMPTY') }

    foreach ($item in @($Items)) {
        $path = [string](Get-TradingLabAclPlanProperty $item 'path')
        try {
            $canonicalPath = [System.IO.Path]::GetFullPath($path).TrimEnd('\')
            if (-not ($canonicalPath.Equals($canonicalTarget, [System.StringComparison]::OrdinalIgnoreCase) -or
                $canonicalPath.StartsWith($canonicalTarget + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
                $findings.Add("ACL_AUDIT_PATH_OUTSIDE_TARGET:$path")
            }
        } catch { $findings.Add("ACL_AUDIT_PATH_INVALID:$path") }

        if ([bool](Get-TradingLabAclPlanProperty $item 'is_reparse_point')) {
            $reparsePoints++
            $findings.Add("ACL_AUDIT_REPARSE_POINT:$path")
        }
        if ((Get-TradingLabAclPlanProperty $item 'owner_sid') -ne $AdministratorsSid) {
            $ownerMismatches++
            $findings.Add("ACL_AUDIT_OWNER_NOT_ADMINISTRATORS:$path")
        }
        if (-not [bool](Get-TradingLabAclPlanProperty $item 'inheritance_protected')) {
            $inheritanceMismatches++
            $findings.Add("ACL_AUDIT_INHERITANCE_NOT_PROTECTED:$path")
        }

        $rightsBySid = @{}
        foreach ($rule in @((Get-TradingLabAclPlanProperty $item 'rules'))) {
            $sid = [string](Get-TradingLabAclPlanProperty $rule 'sid')
            $type = [string](Get-TradingLabAclPlanProperty $rule 'type')
            $rights = [int64](Get-TradingLabAclPlanProperty $rule 'rights')
            if ($type -eq 'Deny') {
                $denyAces++
                $findings.Add("ACL_AUDIT_DENY_ACE:$path`:$sid")
                continue
            }
            if ($type -ne 'Allow') {
                $findings.Add("ACL_AUDIT_UNKNOWN_ACE_TYPE:$path`:$sid")
                continue
            }
            if ($rightsBySid.ContainsKey($sid)) {
                $findings.Add("ACL_AUDIT_DUPLICATE_ALLOW:$path`:$sid")
                $rightsBySid[$sid] = $rightsBySid[$sid] -bor $rights
            } else { $rightsBySid[$sid] = $rights }
            if ($sid -notin @($SystemSid, $AdministratorsSid, $GatewaySid)) {
                $unexpectedPrincipals++
                $classification = Get-TradingLabFileSystemRightsClassification $rights
                $findings.Add("ACL_AUDIT_UNEXPECTED_PRINCIPAL:$path`:$sid`:mutation=$($classification.modify_equivalent)")
            }
        }

        if ($rightsBySid.ContainsKey($AgentSid)) {
            $agentAllowAces++
            $findings.Add("ACL_AUDIT_AGENT_ALLOW:$path")
        }
        if (-not $rightsBySid.ContainsKey($SystemSid) -or $rightsBySid[$SystemSid] -ne $FullControlValue) {
            $systemRightsMismatches++
            $findings.Add("ACL_AUDIT_SYSTEM_NOT_FULLCONTROL:$path")
        }
        if (-not $rightsBySid.ContainsKey($AdministratorsSid) -or $rightsBySid[$AdministratorsSid] -ne $FullControlValue) {
            $administratorsRightsMismatches++
            $findings.Add("ACL_AUDIT_ADMINISTRATORS_NOT_FULLCONTROL:$path")
        }
        if (-not $rightsBySid.ContainsKey($GatewaySid)) {
            $gatewayRightsMismatches++
            $findings.Add("ACL_AUDIT_GATEWAY_MISSING:$path")
        } else {
            $gatewayMutationIntersection = $gatewayMutationIntersection -bor `
                (Get-TradingLabMutationRightsIntersection $rightsBySid[$GatewaySid])
            if ($rightsBySid[$GatewaySid] -ne $GatewayReadExecuteValue -or
                (Test-TradingLabFileSystemRightsMutation $rightsBySid[$GatewaySid])) {
                $gatewayRightsMismatches++
                $findings.Add("ACL_AUDIT_GATEWAY_RIGHTS_UNSAFE:$path")
            }
        }
        if ($rightsBySid.Count -ne 3) {
            $findings.Add("ACL_AUDIT_ALLOW_PRINCIPAL_COUNT:$path`:$($rightsBySid.Count)")
        }
    }

    $gatewayClassification = Get-TradingLabFileSystemRightsClassification $GatewayReadExecuteValue
    return [pscustomobject]@{
        valid = $findings.Count -eq 0
        scanned_items = @($Items).Count
        recursive_findings = $findings.Count
        findings = @($findings)
        unexpected_principals = $unexpectedPrincipals
        reparse_points = $reparsePoints
        owner_administrators = $ownerMismatches -eq 0
        inheritance_protected = $inheritanceMismatches -eq 0
        system_full_control = $systemRightsMismatches -eq 0
        administrators_full_control = $administratorsRightsMismatches -eq 0
        gateway_read_execute = $gatewayRightsMismatches -eq 0
        agent_allow_aces = $agentAllowAces
        deny_aces = $denyAces
        gateway_rights = $GatewayReadExecuteValue
        gateway_rights_hex = '0x' + $GatewayReadExecuteValue.ToString('X')
        prohibited_mutation_mask = $gatewayClassification.prohibited_mutation_mask
        prohibited_mutation_mask_hex = $gatewayClassification.prohibited_mutation_mask_hex
        gateway_mutation_intersection = $gatewayMutationIntersection
    }
}
