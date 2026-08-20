$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Initialize-TradingLabAcl.ps1'
$tokens = $null
$errors = $null
$initializerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "ACL script has PowerShell AST errors: $($errors -join '; ')"
}

$source = [System.IO.File]::ReadAllText($scriptPath)
$initializerParameters = @($initializerAst.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
$expectedHashParameter = @($initializerAst.ParamBlock.Parameters | Where-Object {
    $_.Name.VariablePath.UserPath -eq 'ExpectedExistingConfigSha256'
})
if ($expectedHashParameter.Count -ne 1 -or
    $initializerParameters[-2] -ne 'ExpectedExistingConfigSha256') {
    throw 'ACL initializer must expose the optional pinned existing config SHA256 parameter.'
}
$expectedHashParameterSource = $expectedHashParameter[0].Extent.Text
if (-not $expectedHashParameterSource.Contains("[ValidatePattern('^[0-9A-Fa-f]{64}$')]") -or
    $expectedHashParameterSource.Contains('Mandatory')) {
    throw 'ACL initializer pinned SHA256 parameter must be optional and exactly 64 hexadecimal characters.'
}
foreach ($initializerPinBoundary in @(
    "`$PSBoundParameters.ContainsKey('ExpectedExistingConfigSha256')",
    'Initialize-TradingLabBootstrapState $root $state $bootstrapTemplate',
    '-ExpectedExistingConfigSha256 $ExpectedExistingConfigSha256',
    '-not [bool]$preparedState.config_valid',
    "[string]`$preparedState.config_validation_mode -cne 'PINNED_EXISTING_SHA256'",
    '[string]$preparedState.config_sha256 -cne $normalizedExpectedConfigSha256',
    '[bool]$preparedState.config_created',
    '-not [bool]$preparedState.config_reused',
    'Assert-PinnedExistingBootstrapConfig',
    "[string]`$configBeforeAclMutation.validation_mode -cne 'PINNED_EXISTING_SHA256'"
)) {
    if (-not $source.Contains($initializerPinBoundary)) {
        throw "ACL initializer lacks pinned config boundary: $initializerPinBoundary"
    }
}
$pinnedRevalidationIndex = $source.LastIndexOf('Assert-PinnedExistingBootstrapConfig')
$firstAclMutationIndex = $source.IndexOf(
    'Set-ExactAcl $root @($gatewaySid, $automatonSid) @($readExecute, $readExecute)'
)
if ($pinnedRevalidationIndex -lt 0 -or $firstAclMutationIndex -le $pinnedRevalidationIndex) {
    throw 'Pinned canonical config revalidation must immediately precede the first ACL mutation.'
}
$preAclBoundary = $source.Substring(
    $pinnedRevalidationIndex,
    $firstAclMutationIndex - $pinnedRevalidationIndex
)
if ($preAclBoundary.Contains('Set-Acl') -or $preAclBoundary.Contains('Set-ExactAcl') -or
    $preAclBoundary.Contains('Set-ExactTreeAcl') -or
    $preAclBoundary.Contains('Set-ExactControlAcl')) {
    throw 'An ACL mutation can occur between pinned config revalidation and the first exact ACL application.'
}
$setupPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\setup.ps1'
$setupSource = [System.IO.File]::ReadAllText($setupPath)
if (-not $setupSource.Contains("Join-Path `$PSScriptRoot 'Initialize-TradingLabAcl.ps1'") -or
    $setupSource.Contains('ExpectedExistingConfigSha256')) {
    throw 'setup.ps1 must retain the backward-compatible default initializer call without pinned mode.'
}

$initializerFunctionAsts = @($initializerAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
$demoAuthorizationFunction = @($initializerFunctionAsts | Where-Object {
    $_.Name -eq 'Set-ExactDemoAuthorizationAcl'
})
if ($demoAuthorizationFunction.Count -ne 1) {
    throw 'Set-ExactDemoAuthorizationAcl function boundary was not found.'
}
$demoAuthorizationSource = $demoAuthorizationFunction[0].Extent.Text
foreach ($forbiddenSerializedAclDecision in @(
    '$current.Sddl',
    'GetSecurityDescriptorSddlForm'
)) {
    if ($demoAuthorizationSource.Contains($forbiddenSerializedAclDecision)) {
        throw "Existing authorization artifacts still use serialized SDDL canonicality: $forbiddenSerializedAclDecision"
    }
}
$snapshotFunction = @($initializerFunctionAsts | Where-Object {
    $_.Name -eq 'Get-DemoAuthorizationAclSnapshot'
})
if ($snapshotFunction.Count -ne 1) {
    throw 'Authorization ACL semantic snapshot helper was not found.'
}
$snapshotFunctionSource = $snapshotFunction[0].Extent.Text
foreach ($requiredSnapshotBoundary in @(
    '$Security.GetOwner(',
    '$Security.GetAccessRules(',
    '[System.Security.Principal.SecurityIdentifier]',
    '$_.IdentityReference.Value',
    'rights = [int64]$_.FileSystemRights',
    'access_type = [int]$_.AccessControlType',
    'inherited = [bool]$_.IsInherited',
    'inheritance_flags = [int]$_.InheritanceFlags',
    'propagation_flags = [int]$_.PropagationFlags'
)) {
    if (-not $snapshotFunctionSource.Contains($requiredSnapshotBoundary)) {
        throw "Authorization ACL snapshot is not SID/numeric exact: $requiredSnapshotBoundary"
    }
}
foreach ($forbiddenSnapshotMetadata in @('.Sddl', 'GetGroup(', 'GetSecurityDescriptorSddlForm')) {
    if ($snapshotFunctionSource.Contains($forbiddenSnapshotMetadata)) {
        throw "Authorization ACL policy improperly depends on descriptor metadata: $forbiddenSnapshotMetadata"
    }
}
foreach ($requiredSemanticAclBoundary in @(
    '$validatedInventory = Get-DemoAuthorizationChildInventory',
    'if ($validatedInventory.children.Count -gt 0)',
    'Get-DemoAuthorizationAclSnapshot $current $demoAuthorization',
    'Assert-DemoAuthorizationParentAclSnapshot',
    'foreach ($authorizationChild in @($validatedInventory.children))',
    'Get-Item -LiteralPath $authorizationChild.FullName',
    '$childItem.PSIsContainer',
    'FileAttributes]::ReparsePoint',
    '^mt5-read-only-authorization-',
    'Get-Acl -LiteralPath $childItem.FullName',
    'Assert-DemoAuthorizationChildAclSnapshot',
    'Set-Acl -LiteralPath $demoAuthorization -AclObject $security',
    '$finalInventory = Get-DemoAuthorizationChildInventory',
    'Assert-DemoAuthorizationChildInventoryStable'
)) {
    if (-not $demoAuthorizationSource.Contains($requiredSemanticAclBoundary)) {
        throw "Authorization ACL semantic branch lacks boundary: $requiredSemanticAclBoundary"
    }
}
$freshInventoryIndex = $demoAuthorizationSource.IndexOf(
    '$validatedInventory = Get-DemoAuthorizationChildInventory'
)
$existingArtifactsBranch = $demoAuthorizationSource.IndexOf(
    'if ($validatedInventory.children.Count -gt 0)',
    [Math]::Max(0, $freshInventoryIndex)
)
$parentSemanticCheck = $demoAuthorizationSource.IndexOf(
    'Assert-DemoAuthorizationParentAclSnapshot',
    [Math]::Max(0, $existingArtifactsBranch)
)
$childSemanticCheck = $demoAuthorizationSource.IndexOf(
    'Assert-DemoAuthorizationChildAclSnapshot',
    [Math]::Max(0, $parentSemanticCheck)
)
$existingArtifactsElse = $demoAuthorizationSource.IndexOf(
    "`n    } else {",
    [Math]::Max(0, $childSemanticCheck)
)
$emptyDirectorySetAcl = $demoAuthorizationSource.IndexOf(
    'Set-Acl -LiteralPath $demoAuthorization -AclObject $security',
    [Math]::Max(0, $existingArtifactsElse)
)
$finalInventoryIndex = $demoAuthorizationSource.IndexOf(
    '$finalInventory = Get-DemoAuthorizationChildInventory',
    [Math]::Max(0, $emptyDirectorySetAcl)
)
$finalInventoryAssertion = $demoAuthorizationSource.IndexOf(
    'Assert-DemoAuthorizationChildInventoryStable',
    [Math]::Max(0, $finalInventoryIndex)
)
if ($freshInventoryIndex -lt 0 -or
    $existingArtifactsBranch -le $freshInventoryIndex -or
    $parentSemanticCheck -le $existingArtifactsBranch -or
    $childSemanticCheck -le $parentSemanticCheck -or
    $existingArtifactsElse -le $childSemanticCheck -or
    $emptyDirectorySetAcl -le $existingArtifactsElse -or
    $finalInventoryIndex -le $emptyDirectorySetAcl -or
    $finalInventoryAssertion -le $finalInventoryIndex) {
    throw 'Authorization ACL branch does not use fresh validation and final inventories around all ACL work.'
}
$existingArtifactsSource = $demoAuthorizationSource.Substring(
    $existingArtifactsBranch,
    $existingArtifactsElse - $existingArtifactsBranch
)
if ($existingArtifactsSource.Contains('Set-Acl')) {
    throw 'Existing canonical authorization artifacts can reach Set-Acl instead of returning unchanged.'
}

foreach ($semanticFunctionName in @(
    'New-DemoAuthorizationAclRule',
    'Test-DemoAuthorizationAclRuleExact',
    'Assert-DemoAuthorizationAclRuleSet',
    'Assert-DemoAuthorizationParentAclSnapshot',
    'Assert-DemoAuthorizationChildAclSnapshot',
    'ConvertTo-DemoAuthorizationChildInventory',
    'Assert-DemoAuthorizationChildInventoryStable'
)) {
    $semanticFunction = @($initializerFunctionAsts | Where-Object {
        $_.Name -eq $semanticFunctionName
    })
    if ($semanticFunction.Count -ne 1) {
        throw "Authorization semantic helper is missing: $semanticFunctionName"
    }
    . ([scriptblock]::Create($semanticFunction[0].Extent.Text))
}

function Copy-TestDemoAuthorizationRule($Rule) {
    return [pscustomobject]@{
        sid = [string]$Rule.sid
        rights = [int64]$Rule.rights
        access_type = [int]$Rule.access_type
        inherited = [bool]$Rule.inherited
        inheritance_flags = [int]$Rule.inheritance_flags
        propagation_flags = [int]$Rule.propagation_flags
    }
}

function New-TestDemoAuthorizationSnapshot(
    [object[]] $Rules,
    [bool] $Protected,
    [string] $OwnerSid = 'S-1-5-32-544',
    [string] $GroupSid = 'S-1-5-21-10-20-30-513',
    [string] $DescriptorControl = 'D:PAI'
) {
    return [pscustomobject]@{
        path = 'synthetic-authorization-target'
        owner_sid = $OwnerSid
        group_sid = $GroupSid
        descriptor_control = $DescriptorControl
        protected = $Protected
        rules = @($Rules | ForEach-Object { Copy-TestDemoAuthorizationRule $_ })
    }
}

function Assert-DemoAuthorizationTestThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    if (-not $threw) { throw $Message }
}

function New-TestDemoAuthorizationChild([string] $Name) {
    return [pscustomobject]@{
        Name = $Name
        FullName = 'C:\synthetic\demo-authorization\' + $Name
        PSIsContainer = $false
        Attributes = [System.IO.FileAttributes]::Normal
    }
}

function Assert-DemoAuthorizationInventoryDrift(
    [string[]] $ValidatedNames,
    [string[]] $FinalNames,
    [string] $Case
) {
    $message = $null
    try {
        Assert-DemoAuthorizationChildInventoryStable $ValidatedNames $FinalNames
    } catch {
        $message = $_.Exception.Message
    }
    if ($message -cne 'Authorization artifact inventory changed after validation.') {
        throw "$Case did not fail specifically because of authorization inventory drift."
    }
}

$semanticSystemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$semanticAdministratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$semanticGatewaySid = [System.Security.Principal.SecurityIdentifier]::new(
    'S-1-5-21-10-20-30-1007'
)
$semanticAgentSid = [System.Security.Principal.SecurityIdentifier]::new(
    'S-1-5-21-10-20-30-1006'
)
$semanticDirectoryInheritance = [System.Security.AccessControl.InheritanceFlags](
    [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
)
$canonicalParentRules = @(
    New-DemoAuthorizationAclRule $semanticSystemSid `
        ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        $false $semanticDirectoryInheritance `
        ([System.Security.AccessControl.PropagationFlags]::None)
    New-DemoAuthorizationAclRule $semanticAdministratorsSid `
        ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        $false $semanticDirectoryInheritance `
        ([System.Security.AccessControl.PropagationFlags]::None)
    New-DemoAuthorizationAclRule $semanticGatewaySid `
        ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        $false ([System.Security.AccessControl.InheritanceFlags]::None) `
        ([System.Security.AccessControl.PropagationFlags]::None)
    New-DemoAuthorizationAclRule $semanticGatewaySid `
        ([System.Security.AccessControl.FileSystemRights]::Read) `
        $false ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit) `
        ([System.Security.AccessControl.PropagationFlags]::InheritOnly)
)
$canonicalChildRules = @(
    New-DemoAuthorizationAclRule $semanticSystemSid `
        ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        $true ([System.Security.AccessControl.InheritanceFlags]::None) `
        ([System.Security.AccessControl.PropagationFlags]::None)
    New-DemoAuthorizationAclRule $semanticAdministratorsSid `
        ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        $true ([System.Security.AccessControl.InheritanceFlags]::None) `
        ([System.Security.AccessControl.PropagationFlags]::None)
    New-DemoAuthorizationAclRule $semanticGatewaySid `
        ([System.Security.AccessControl.FileSystemRights]::Read) `
        $true ([System.Security.AccessControl.InheritanceFlags]::None) `
        ([System.Security.AccessControl.PropagationFlags]::None)
)

$inventoryNameA = 'mt5-read-only-authorization-11111111-1111-4111-8111-111111111111.json'
$inventoryNameB = 'mt5-read-only-authorization-22222222-2222-4222-8222-222222222222.json'
$inventoryNameC = 'mt5-read-only-authorization-33333333-3333-4333-8333-333333333333.json'
$validatedInventory = ConvertTo-DemoAuthorizationChildInventory @(
    (New-TestDemoAuthorizationChild $inventoryNameB),
    (New-TestDemoAuthorizationChild $inventoryNameA)
)
$stableInventory = ConvertTo-DemoAuthorizationChildInventory @(
    (New-TestDemoAuthorizationChild $inventoryNameA),
    (New-TestDemoAuthorizationChild $inventoryNameB)
)
Assert-DemoAuthorizationChildInventoryStable `
    $validatedInventory.canonical_names $stableInventory.canonical_names
$addedInventory = ConvertTo-DemoAuthorizationChildInventory @(
    (New-TestDemoAuthorizationChild $inventoryNameA),
    (New-TestDemoAuthorizationChild $inventoryNameB),
    (New-TestDemoAuthorizationChild $inventoryNameC)
)
Assert-DemoAuthorizationInventoryDrift `
    $validatedInventory.canonical_names $addedInventory.canonical_names 'Added child'
$removedInventory = ConvertTo-DemoAuthorizationChildInventory @(
    (New-TestDemoAuthorizationChild $inventoryNameA)
)
Assert-DemoAuthorizationInventoryDrift `
    $validatedInventory.canonical_names $removedInventory.canonical_names 'Removed child'
Assert-DemoAuthorizationTestThrows {
    ConvertTo-DemoAuthorizationChildInventory @(
        (New-TestDemoAuthorizationChild $inventoryNameA),
        (New-TestDemoAuthorizationChild $inventoryNameA)
    ) | Out-Null
} 'Duplicate authorization inventory entries were accepted.'
Assert-DemoAuthorizationTestThrows {
    ConvertTo-DemoAuthorizationChildInventory @(
        (New-TestDemoAuthorizationChild 'unexpected.json')
    ) | Out-Null
} 'Malformed authorization inventory entries were accepted.'

$reorderedParentRules = @($canonicalParentRules | ForEach-Object {
    Copy-TestDemoAuthorizationRule $_
})
[array]::Reverse($reorderedParentRules)
$canonicalParent = New-TestDemoAuthorizationSnapshot `
    $reorderedParentRules $true $semanticAdministratorsSid.Value `
    'S-1-5-21-10-20-30-999' 'D:PAI'
Assert-DemoAuthorizationParentAclSnapshot `
    $canonicalParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
$canonicalParent.group_sid = 'S-1-5-21-10-20-30-998'
$canonicalParent.descriptor_control = 'D:P'
Assert-DemoAuthorizationParentAclSnapshot `
    $canonicalParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid

$extraParent = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$extraParent.rules += New-DemoAuthorizationAclRule $semanticAgentSid `
    ([System.Security.AccessControl.FileSystemRights]::Read) $false `
    ([System.Security.AccessControl.InheritanceFlags]::None) `
    ([System.Security.AccessControl.PropagationFlags]::None)
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $extraParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An additional parent ACE was accepted.'

$denyParent = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$denyParent.rules[0].access_type = [int][System.Security.AccessControl.AccessControlType]::Deny
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $denyParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'A Deny parent ACE was accepted.'

$agentParent = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$agentParent.rules[2].sid = $semanticAgentSid.Value
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $agentParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An Agent parent ACE was accepted.'

$wrongParentRights = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$wrongParentRights.rules[2].rights = [int64][System.Security.AccessControl.FileSystemRights]::Read
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $wrongParentRights $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'Wrong Gateway parent rights were accepted.'

$wrongParentInheritance = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$wrongParentInheritance.rules[0].inheritance_flags = `
    [int][System.Security.AccessControl.InheritanceFlags]::None
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $wrongParentInheritance $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'Wrong parent inheritance flags were accepted.'

$wrongParentPropagation = New-TestDemoAuthorizationSnapshot $canonicalParentRules $true
$wrongParentPropagation.rules[3].propagation_flags = `
    [int][System.Security.AccessControl.PropagationFlags]::None
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $wrongParentPropagation $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'Wrong parent propagation flags were accepted.'

$unprotectedParent = New-TestDemoAuthorizationSnapshot $canonicalParentRules $false
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $unprotectedParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An unprotected parent DACL was accepted.'

$wrongOwnerParent = New-TestDemoAuthorizationSnapshot `
    $canonicalParentRules $true $semanticSystemSid.Value
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationParentAclSnapshot `
        $wrongOwnerParent $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'A parent with the wrong owner was accepted.'

$canonicalChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
Assert-DemoAuthorizationChildAclSnapshot `
    $canonicalChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid

$wrongOwnerChild = New-TestDemoAuthorizationSnapshot `
    $canonicalChildRules $false $semanticSystemSid.Value
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $wrongOwnerChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An authorization child with the wrong owner was accepted.'

$protectedChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $true
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $protectedChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'A protected authorization child was accepted.'

$explicitChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$explicitChild.rules[0].inherited = $false
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $explicitChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An explicit authorization child ACE was accepted.'

$denyChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$denyChild.rules[0].access_type = [int][System.Security.AccessControl.AccessControlType]::Deny
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $denyChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'A Deny authorization child ACE was accepted.'

$extraChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$extraChild.rules += New-DemoAuthorizationAclRule $semanticAgentSid `
    ([System.Security.AccessControl.FileSystemRights]::Read) $true `
    ([System.Security.AccessControl.InheritanceFlags]::None) `
    ([System.Security.AccessControl.PropagationFlags]::None)
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $extraChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An additional authorization child ACE was accepted.'

$agentChild = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$agentChild.rules[2].sid = $semanticAgentSid.Value
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $agentChild $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'An Agent authorization child ACE was accepted.'

$wrongChildInheritance = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$wrongChildInheritance.rules[2].inheritance_flags = `
    [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $wrongChildInheritance $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'Wrong inherited child flags were accepted.'

$wrongChildPropagation = New-TestDemoAuthorizationSnapshot $canonicalChildRules $false
$wrongChildPropagation.rules[2].propagation_flags = `
    [int][System.Security.AccessControl.PropagationFlags]::InheritOnly
Assert-DemoAuthorizationTestThrows {
    Assert-DemoAuthorizationChildAclSnapshot `
        $wrongChildPropagation $semanticGatewaySid $semanticSystemSid $semanticAdministratorsSid
} 'Wrong inherited child propagation was accepted.'

$applyGatePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Apply-TradingLabAclGate.ps1'
$applyTokens = $null
$applyErrors = $null
$applyAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $applyGatePath, [ref]$applyTokens, [ref]$applyErrors
)
if ($applyErrors.Count -ne 0) {
    throw "ACL apply gate has PowerShell AST errors: $($applyErrors -join '; ')"
}
$applySource = [System.IO.File]::ReadAllText($applyGatePath)
$applyParameters = @($applyAst.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
if (($applyParameters -join ',') -ne 'ReportPath,ExpectedTradingConfigSha256') {
    throw 'ACL apply gate must require only ReportPath and the operator-supplied config SHA256.'
}
$authorizationAclPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Set-MT5ReadOnlyAuthorizationAcl.ps1'
$repairAclPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Repair-MT5ReadOnlyAuthorizationAclDrift.ps1'
$repairHelperPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\MT5ReadOnlyAclRepairHelpers.ps1'
$repairVerifierPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'trading_lab\acl_repair_verifier.py'
$protectedIdentityPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Set-MT5ReadOnlyProtectedIdentity.ps1'
$protectedHelperPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\ProtectedIdentityGateHelpers.ps1'
foreach ($maintenanceScript in @(
    $authorizationAclPath, $repairAclPath, $repairHelperPath,
    $protectedIdentityPath, $protectedHelperPath
)) {
    $maintenanceTokens = $null
    $maintenanceErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $maintenanceScript, [ref]$maintenanceTokens, [ref]$maintenanceErrors
    )
    if ($maintenanceErrors.Count -ne 0) {
        throw "MT5 precondition script has PowerShell AST errors: $($maintenanceErrors -join '; ')"
    }
}
$authorizationAclSource = [System.IO.File]::ReadAllText($authorizationAclPath)
$repairAclSource = [System.IO.File]::ReadAllText($repairAclPath)
$repairHelperSource = [System.IO.File]::ReadAllText($repairHelperPath)
$repairVerifierSource = [System.IO.File]::ReadAllText($repairVerifierPath)
$protectedIdentitySource = [System.IO.File]::ReadAllText($protectedIdentityPath)
$protectedHelperSource = [System.IO.File]::ReadAllText($protectedHelperPath)
$protectedIdentityTokens = $null
$protectedIdentityErrors = $null
$protectedIdentityAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $protectedIdentityPath, [ref]$protectedIdentityTokens, [ref]$protectedIdentityErrors
)
$protectedIdentityParameters = @($protectedIdentityAst.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
if ($protectedIdentityParameters.Count -ne 2 -or
    $protectedIdentityParameters[0] -ne 'RunId' -or
    $protectedIdentityParameters[1] -ne 'Apply') {
    throw 'Protected identity gate must expose exactly RunId and Apply; arbitrary account input is forbidden.'
}
. $protectedHelperPath
. $repairHelperPath
foreach ($forbidden in @('Start-Process -Credential', 'runas.exe', '.order_send(', '.order_check(', 'import MetaTrader5')) {
    if ($applySource.Contains($forbidden)) {
        throw "ACL apply gate contains forbidden runtime action: $forbidden"
    }
}
foreach ($requiredApply in @(
    '#Requires -RunAsAdministrator',
    'S-1-5-21-568964486-193631783-1609210587-1006',
    'S-1-5-21-568964486-193631783-1609210587-1007',
    'trading.bootstrap-observe-only.yaml',
    "[ValidatePattern('^[0-9A-Fa-f]{64}$')]",
    '[string] $ExpectedTradingConfigSha256',
    '-Apply | Out-Null',
    "service_identities_executed = `$false",
    "mt5_accessed = `$false"
)) {
    if (-not $applySource.Contains($requiredApply)) {
        throw "ACL apply gate lacks required boundary: $requiredApply"
    }
}
foreach ($configPinBoundary in @(
    "trading_config_validation_mode = 'PINNED_EXISTING_SHA256'",
    'expected_trading_config_sha256 = $expectedConfigSha256',
    'trading_config_sha256_before',
    'trading_config_sha256_after',
    "semantic_config_validation_status = 'NOT_RUN'",
    'Invoke-ProtectedIdentityHelperProcess',
    "-Operation 'inspect'",
    "-Stage 'INSPECT'",
    'trading_lab.protected_identity_config inspect',
    "[string]`$Inspection.status -ne 'PASS'",
    "[string]`$Inspection.state -ne 'EXACT_TARGET'",
    '[string]$Inspection.source_sha256 -cne $ExpectedSha256',
    '[string]$Inspection.candidate_sha256 -cne $ExpectedSha256',
    "[string]`$Inspection.target.trading_mode -ne 'OBSERVE_ONLY'",
    '[bool]$Inspection.target.mt5_access_enabled -ne $false',
    '[int64]$Inspection.target.authorized_account -ne 10012236003L',
    "[string]`$Inspection.target.authorized_server -cne 'MetaQuotes-Demo'",
    "[string]`$Inspection.target.allowed_symbol -cne 'XAUUSD'",
    "[string]`$Inspection.target.mt5_terminal_path -cne 'C:\Program Files\MetaTrader 5\terminal64.exe'",
    '-ExpectedExistingConfigSha256 $expectedConfigSha256'
)) {
    if (-not $applySource.Contains($configPinBoundary)) {
        throw "ACL apply gate lacks pinned operational config boundary: $configPinBoundary"
    }
}
$initializerInvocationIndex = $applySource.IndexOf('& $aclScript')
$initializerInvocationEnd = $applySource.IndexOf(
    'if ($LASTEXITCODE -ne 0)',
    [Math]::Max(0, $initializerInvocationIndex)
)
if ($initializerInvocationIndex -lt 0 -or $initializerInvocationEnd -le $initializerInvocationIndex) {
    throw 'ACL apply gate initializer invocation boundary was not found.'
}
$initializerInvocation = $applySource.Substring(
    $initializerInvocationIndex,
    $initializerInvocationEnd - $initializerInvocationIndex
)
if (-not $initializerInvocation.Contains(
    '-ExpectedExistingConfigSha256 $expectedConfigSha256'
)) {
    throw 'ACL apply gate does not forward the operator-reviewed SHA256 into the initializer.'
}
$combinedAclSurface = $source + $applySource
foreach ($forbiddenAclCapability in @(
    'MetaTrader5.initialize', 'import MetaTrader5', '.order_check(', '.order_send(',
    'symbol_select(', 'login('
)) {
    if ($combinedAclSurface.Contains($forbiddenAclCapability)) {
        throw "ACL pinned-config surface contains forbidden MT5/trading capability: $forbiddenAclCapability"
    }
}
$semanticInspectionIndex = $applySource.IndexOf(
    '$configInspection = Invoke-ReviewedTradingConfigInspection $configPath'
)
$semanticAssertionIndex = $applySource.IndexOf(
    'Assert-ReviewedTradingConfigInspection $configInspection $expectedConfigSha256'
)
$credentialSnapshotIndex = $applySource.IndexOf(
    '$snapshot = Get-CredentialRollbackSnapshot $credentialEntry.Key $credentialEntry.Value'
)
$bootstrapMutationIndex = $applySource.IndexOf('$bootstrapMutationStarted = $true')
if ($semanticInspectionIndex -lt 0 -or
    $semanticAssertionIndex -le $semanticInspectionIndex -or
    $credentialSnapshotIndex -le $semanticAssertionIndex -or
    $bootstrapMutationIndex -le $credentialSnapshotIndex) {
    throw 'EXACT_TARGET/hash validation must precede credential snapshots and bootstrap mutation.'
}
foreach ($forbiddenConfigMutation in @(
    'Assert-ExactBootstrapConfig $configPath',
    'trading_lab.protected_identity_config render',
    'trading_lab.protected_identity_config validate',
    '[System.IO.File]::Replace',
    '[System.IO.File]::WriteAllText($configPath',
    'Copy-Item -LiteralPath $template -Destination $configPath',
    'import MetaTrader5', 'MetaTrader5.initialize', '.order_check(', '.order_send('
)) {
    if ($applySource.Contains($forbiddenConfigMutation)) {
        throw "ACL apply gate contains forbidden config/MT5 operation: $forbiddenConfigMutation"
    }
}
if ($applySource.Contains('RandomNumberGenerator]::Fill')) {
    throw 'ACL apply boundary reintroduced a Windows PowerShell 5.1-incompatible RNG API.'
}
foreach ($transactional in @(
    "acl_apply = 'IN_PROGRESS'",
    'Resolve-AclApplyFailureStatus',
    'security_descriptors_applied',
    '-ProgressPath $progressPath',
    'Write-GateReport'
)) {
    if (-not $applySource.Contains($transactional)) {
        throw "ACL apply gate lacks transactional reporting: $transactional"
    }
}
foreach ($required in @(
    "Join-Path `$root 'operational'",
    "Join-Path `$root 'research'",
    "Join-Path `$audit 'sqlite'",
    "Join-Path `$audit 'journal'",
    "Join-Path `$logs 'gateway'",
    "Join-Path `$logs 'security'",
    "Join-Path `$control 'STOP_TRADING'",
    "Join-Path `$control 'demo-authorization'",
    "Read,AppendData,Synchronize",
    "Get-LocalUser -SID `$runtimeIdentity.Sid",
    "S-1-5-32-545",
    "Get-DirectLocalGroupSids",
    "SetAccessRuleProtection(`$true, `$false)",
    'New-ControlAclProposal',
    'Set-ExactControlAcl',
    "`$protectedSourceDirectories",
    "Protected source tree contains a reparse point",
    "sqlite_immutable = `$false",
    "deny_aces_used = `$false"
    'Read-TradingLabWindowsAclPolicy'
    'Maintenance identity must be an enabled local direct Administrator.'
    "'lab_root'"
    "'operational'"
    "'logs_root'"
    "'gateway_logs'"
    "'security_logs'"
    "'automaton_state'"
)) {
    if (-not $source.Contains($required)) {
        throw "ACL source is missing required invariant: $required"
    }
}
foreach ($requiredPolicyBoundary in @(
    'config\windows-acl-policy.json',
    'Resolve-TradingLabAclIdentitySid',
    '$maintenanceTargetKeys.Contains($MaintenancePolicyKey)',
    'New-AccessRule $maintenanceSid ([System.Security.AccessControl.FileSystemRights]::FullControl'
)) {
    if (-not $source.Contains($requiredPolicyBoundary)) {
        throw "ACL source does not consume the canonical maintenance policy: $requiredPolicyBoundary"
    }
}
foreach ($ipcCredentialBoundary in @(
    "`$automatonKeyFile = Join-Path `$ipc 'automaton.key'",
    "`$observationKeyFile = Join-Path `$ipc 'observation.key'",
    "`$researchKeyFile = Join-Path `$ipc 'research.key'",
    "New-AclProposal `$ipc 'shared_ipc_directory' @(`$gatewaySid, `$automatonSid)",
    "New-AclProposal `$automatonKeyFile 'gateway_automaton_ipc_key_file' @(`$gatewaySid)",
    "New-AclProposal `$observationKeyFile 'shared_observation_ipc_key_file' @(`$gatewaySid, `$automatonSid)",
    "New-AclProposal `$researchKeyFile 'shared_research_ipc_key_file' @(`$gatewaySid, `$automatonSid)",
    'Set-ExactAcl $ipc @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $false',
    'Set-ExactAcl $automatonKeyFile @($gatewaySid) @($read) $false $false',
    'Set-ExactAcl $observationKeyFile @($gatewaySid, $automatonSid) @($read, $read) $false $false',
    'Set-ExactAcl $researchKeyFile @($gatewaySid, $automatonSid) @($read, $read) $false $false'
)) {
    if (-not $source.Contains($ipcCredentialBoundary)) {
        throw "ACL source lacks split IPC credential boundary: $ipcCredentialBoundary"
    }
}
if ($source.Contains('$apiKeyFile') -or
    $source.Contains('[System.Security.AccessControl.AccessControlType]::Deny')) {
    throw 'ACL source contains an ambiguous IPC variable or explicit Deny ACE strategy.'
}
foreach ($applyCredentialBoundary in @(
    "automaton = (Join-Path `$labRoot 'ipc\automaton.key')",
    "observation = (Join-Path `$labRoot 'ipc\observation.key')",
    "research = (Join-Path `$labRoot 'ipc\research.key')",
    'automaton_key_created',
    'observation_key_created',
    'research_key_created',
    'Get-CredentialRollbackSnapshot',
    'Invoke-CredentialStateRollback',
    'Credential was not proven to have been created by this gate; refusing deletion.',
    'Pre-existing credential content changed; refusing content rollback.',
    'Assert-NoUnexpectedAllow $snapshots.automaton_key @($systemSid, $administratorsSid, $gatewaySid)',
    '(Get-AllowRights $snapshots.automaton_key $agentSid) -ne 0'
)) {
    if (-not $applySource.Contains($applyCredentialBoundary)) {
        throw "ACL apply gate lacks split credential/rollback boundary: $applyCredentialBoundary"
    }
}
if ($source.Contains('S-1-5-21-568964486-193631783-1609210587-1001')) {
    throw 'Maintenance SID must be resolved from the configured account name, not hardcoded.'
}
if ($source.Contains("gateway_writable_data") -or $source.Contains("Join-Path `$root 'data'")) {
    throw 'ACL source reintroduced a globally writable data domain.'
}
if ($source.Contains('WriteAllText($killSwitchFile') -or $source.Contains('WriteAllText($demoAuthorizationFile')) {
    throw 'ACL bootstrap must not assert the presence-based kill switch or DEMO authorization.'
}

foreach ($requiredAuthorizationPolicy in @(
    "[System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
    "[System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'",
    'mt5-read-only-authorization-<UUID>.json',
    'Set-ExactDemoAuthorizationAcl'
)) {
    if (-not $source.Contains($requiredAuthorizationPolicy)) {
        throw "Canonical ACL source lacks RunId authorization policy: $requiredAuthorizationPolicy"
    }
}
if ($source.Contains("New-AclProposal `$demoAuthorizationFile") -or
    $source.Contains("Join-Path `$demoAuthorization 'authorization.json'")) {
    throw 'Canonical ACL source still models legacy authorization.json as an artifact.'
}
foreach ($requiredTargeted in @(
    '#Requires -RunAsAdministrator',
    'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization',
    'KNOWN_LEGACY_DIRECTORY_ONLY',
    'CANONICAL_RUN_ID_ARTIFACTS',
    "[System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
    'Set-Acl -LiteralPath $target',
    'rollback_attempted',
    'gateway_mutation_rights',
    'agent_access',
    'FileMode]::CreateNew'
)) {
    if (-not $authorizationAclSource.Contains($requiredTargeted)) {
        throw "Targeted authorization ACL gate lacks boundary: $requiredTargeted"
    }
}
foreach ($forbiddenTargeted in @(
    'icacls', '/reset', 'MetaTrader5', 'initialize()', 'order_check', 'order_send',
    'Start-Process', 'trading_lab.service'
)) {
    if ($authorizationAclSource.Contains($forbiddenTargeted)) {
        throw "Targeted authorization ACL gate contains forbidden action: $forbiddenTargeted"
    }
}
$readOnlyRights = 1179785L
$forbiddenMutation = 2L -bor 4L -bor 16L -bor 64L -bor 256L -bor 65536L -bor 262144L -bor 524288L
if (($readOnlyRights -band $forbiddenMutation) -ne 0) {
    throw 'Gateway inherited Read+Synchronize unexpectedly permits create/write/append/delete/security mutation.'
}
foreach ($requiredConfigGate in @(
    '#Requires -RunAsAdministrator',
    "mode = 'MT5_READ_ONLY_PROTECTED_IDENTITY'",
    'trading_lab.protected_identity_config inspect',
    'trading_lab.protected_identity_config render',
    'trading_lab.protected_identity_config validate',
    '[System.IO.File]::Replace',
    'Set-Acl -LiteralPath $configPath -AclObject $originalAcl',
    '[System.IO.File]::Replace($backupPath, $configPath, $failedPath, $true)',
    'Assert-ExactConfigAcl $restoredAcl',
    'real_loader_validated',
    'rollback_attempted',
    'hash_before',
    'hash_after',
    "Invoke-ProtectedHelper 'inspect' 'INSPECT'",
    "Invoke-ProtectedHelper 'render' 'RENDER'",
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_PRE_REPLACE'",
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_POST_REPLACE'",
    '--mode pre-replace',
    '--mode post-replace',
    '[string]$validated.candidate_sha256 -eq $report.hash_candidate',
    'temporary_artifacts_cleanup_attempted',
    'temporary_artifacts_remaining',
    'transactionPathsWereInitiallyAbsent',
    'Pre-existing RunId artifacts were preserved; this run did not own them.',
    'Rollback backup is unavailable; automatic cleanup was withheld.',
    "trading_mode = 'OBSERVE_ONLY'",
    'authorized_account = 10012236003',
    'mt5_access_enabled = $false'
)) {
    if (-not $protectedIdentitySource.Contains($requiredConfigGate)) {
        throw "Protected identity gate lacks transaction boundary: $requiredConfigGate"
    }
}
foreach ($requiredHelperBoundary in @(
    "ValidateSet('inspect', 'render', 'validate')",
    "ValidateSet('INSPECT', 'RENDER', 'VALIDATE_PRE_REPLACE', 'VALIDATE_POST_REPLACE')",
    'ReadToEndAsync()',
    '...[TRUNCATED]',
    'Rejected non-transaction cleanup path',
    'Unexpected transaction directory was not removed'
)) {
    if (-not $protectedHelperSource.Contains($requiredHelperBoundary)) {
        throw "Protected identity helper lacks diagnostic or cleanup boundary: $requiredHelperBoundary"
    }
}
foreach ($forbiddenConfigGate in @(
    'MetaTrader5', 'initialize()', 'login(', 'order_check', 'order_send',
    'trading_lab.service', 'start_gateway', 'start_automaton', 'Invoke-Expression'
)) {
    if ($protectedIdentitySource.Contains($forbiddenConfigGate)) {
        throw "Protected identity gate contains forbidden action: $forbiddenConfigGate"
    }
}
$combinedProtectedSource = $protectedIdentitySource + $protectedHelperSource
foreach ($forbiddenConfigHelper in @(
    'MetaTrader5', 'initialize()', 'login(', 'order_check', 'order_send',
    'trading_lab.service', 'start_gateway', 'start_automaton', 'Invoke-Expression'
)) {
    if ($combinedProtectedSource.Contains($forbiddenConfigHelper)) {
        throw "Protected identity helper contains forbidden action: $forbiddenConfigHelper"
    }
}

$preValidationCall = $protectedIdentitySource.IndexOf(
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_PRE_REPLACE'"
)
$replaceCall = $protectedIdentitySource.IndexOf('[System.IO.File]::Replace($tempPath, $configPath')
$postValidationCall = $protectedIdentitySource.IndexOf(
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_POST_REPLACE'",
    [Math]::Max(0, $replaceCall)
)
$rollbackCall = $protectedIdentitySource.IndexOf(
    '[System.IO.File]::Replace($backupPath, $configPath, $failedPath',
    [Math]::Max(0, $postValidationCall)
)
if ($preValidationCall -lt 0 -or $replaceCall -le $preValidationCall -or
    $postValidationCall -le $replaceCall -or $rollbackCall -le $postValidationCall) {
    throw 'Protected identity transaction does not order pre-validation, replace, canonical validation, and rollback.'
}

$migrationStateCondition = "`$migrationRequired = @('KNOWN_PLACEHOLDER', 'KNOWN_PREVIOUS_TARGET') -contains `$report.initial_state"
$prepareCondition = 'if (-not $Apply -or $migrationRequired)'
$dryRunCondition = 'if (-not $Apply)'
$applyMigrationCondition = 'elseif ($migrationRequired)'
$migrationStateIndex = $protectedIdentitySource.IndexOf($migrationStateCondition)
$prepareIndex = $protectedIdentitySource.IndexOf($prepareCondition)
$dryRunIndex = $protectedIdentitySource.IndexOf($dryRunCondition, [Math]::Max(0, $prepareIndex))
$applyMigrationIndex = $protectedIdentitySource.IndexOf(
    $applyMigrationCondition,
    [Math]::Max(0, $dryRunIndex)
)
if ($migrationStateIndex -lt 0 -or $prepareIndex -le $migrationStateIndex -or
    $dryRunIndex -le $prepareIndex -or $applyMigrationIndex -le $dryRunIndex) {
    throw 'Protected identity gate lacks the reviewed dry-run/apply branch structure.'
}
$inspectCall = $protectedIdentitySource.IndexOf("Invoke-ProtectedHelper 'inspect' 'INSPECT'")
if ($inspectCall -lt 0 -or $inspectCall -ge $prepareIndex) {
    throw 'Dry-run does not inspect the canonical config before candidate preparation.'
}
$dryReviewedMigrationPath = $protectedIdentitySource.Substring(
    $inspectCall,
    $applyMigrationIndex - $inspectCall
)
$dryHelperCalls = [regex]::Matches($dryReviewedMigrationPath, 'Invoke-ProtectedHelper\s+''').Count
if ($dryHelperCalls -ne 3) {
    throw "Dry-run reviewed migration path must contain exactly three helper calls; found $dryHelperCalls."
}
$prepareBlock = $protectedIdentitySource.Substring($prepareIndex, $dryRunIndex - $prepareIndex)
$dryRunBlock = $protectedIdentitySource.Substring(
    $dryRunIndex,
    $applyMigrationIndex - $dryRunIndex
)
foreach ($requiredDryPreparation in @(
    "Invoke-ProtectedHelper 'render' 'RENDER'",
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_PRE_REPLACE'",
    '[string]$validated.candidate_sha256 -eq $report.hash_candidate',
    '$preReplaceAcl.sddl -ne $beforeAcl.sddl',
    '$preReplaceHash -ne $report.hash_before',
    'Rendered candidate is not the exact regular non-reparse transaction file.'
)) {
    if (-not $prepareBlock.Contains($requiredDryPreparation)) {
        throw "Dry-run candidate preparation lacks boundary: $requiredDryPreparation"
    }
}
foreach ($requiredDryReport in @(
    '$report.real_loader_validated = $false',
    '$report.hash_after = $report.hash_before'
)) {
    if (-not $dryRunBlock.Contains($requiredDryReport)) {
        throw "Dry-run report semantics lack boundary: $requiredDryReport"
    }
}
foreach ($dryDefault in @(
    'controlled_replace_performed = $false',
    'set_acl_call_count = 0',
    'config_modified = $false',
    'rollback_attempted = $false'
)) {
    if (-not $protectedIdentitySource.Contains($dryDefault)) {
        throw "Dry-run report lacks immutable default: $dryDefault"
    }
}
if (-not $prepareBlock.Contains('$report.candidate_validated = (')) {
    throw 'Dry-run does not persist successful builder candidate validation.'
}
foreach ($forbiddenDryMutation in @(
    '[System.IO.File]::Replace',
    'Set-Acl',
    'VALIDATE_POST_REPLACE',
    'rollback_attempted'
)) {
    if ($dryRunBlock.Contains($forbiddenDryMutation)) {
        throw "Dry-run branch contains forbidden mutation or post-validation: $forbiddenDryMutation"
    }
}
$applyMigrationEnd = $protectedIdentitySource.IndexOf(
    "`n    } else {",
    [Math]::Max(0, $applyMigrationIndex)
)
if ($applyMigrationEnd -le $applyMigrationIndex) {
    throw 'Apply reviewed migration branch boundary was not found.'
}
$commonCleanupIndex = $protectedIdentitySource.IndexOf(
    '$cleanup = Remove-ProtectedIdentityTransactionArtifacts',
    [Math]::Max(0, $applyMigrationEnd)
)
$dryPassIndex = $protectedIdentitySource.IndexOf(
    "`$report.status = if (`$Apply) { 'PASS' } else { 'DRY_RUN_PASS' }",
    [Math]::Max(0, $commonCleanupIndex)
)
if ($commonCleanupIndex -le $applyMigrationEnd -or $dryPassIndex -le $commonCleanupIndex) {
    throw 'Dry-run cleanup is not common, verified, and ordered before DRY_RUN_PASS.'
}
$commonFinalization = $protectedIdentitySource.Substring(
    $applyMigrationEnd,
    $dryPassIndex - $applyMigrationEnd
)
foreach ($requiredDryFinalization in @(
    '$report.acl_after_sddl = $finalAcl.sddl',
    'Set-CleanupReport $cleanup',
    'if (-not $report.temporary_artifacts_removed)',
    'temporary_artifacts_remaining'
)) {
    if (-not ($commonFinalization.Contains($requiredDryFinalization) -or
        $protectedIdentitySource.Contains($requiredDryFinalization))) {
        throw "Dry-run finalization lacks verified evidence: $requiredDryFinalization"
    }
}
$applyMigrationBlock = $protectedIdentitySource.Substring(
    $applyMigrationIndex,
    $applyMigrationEnd - $applyMigrationIndex
)
foreach ($requiredApplyMutation in @(
    '[System.IO.File]::Replace($tempPath, $configPath, $backupPath, $true)',
    'Set-Acl -LiteralPath $configPath -AclObject $originalAcl',
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_POST_REPLACE'"
)) {
    if (-not $applyMigrationBlock.Contains($requiredApplyMutation)) {
        throw "Apply path lost transaction stage: $requiredApplyMutation"
    }
}
if (-not $protectedIdentitySource.Contains(
    "if (-not `$migrationRequired -and `$report.initial_state -ne 'EXACT_TARGET')"
)) {
    throw 'Protected identity gate does not fail closed on an unreviewed helper state.'
}
$exactTargetApplyBlock = $protectedIdentitySource.Substring(
    $applyMigrationEnd,
    $commonCleanupIndex - $applyMigrationEnd
)
if (-not $exactTargetApplyBlock.Contains(
    "Invoke-ProtectedHelper 'validate' 'VALIDATE_POST_REPLACE'"
) -or $exactTargetApplyBlock.Contains('[System.IO.File]::Replace($tempPath, $configPath') -or
    $exactTargetApplyBlock.Contains('Set-Acl -LiteralPath $configPath')) {
    throw 'EXACT_TARGET Apply must validate only, without controlled replace or ACL mutation.'
}
if (-not $protectedIdentitySource.Contains('if ($Apply -and $replacePerformed)')) {
    throw 'Rollback is not structurally restricted to an Apply replacement.'
}
if (-not $protectedIdentitySource.Contains("`$report.status = 'FAIL_CLOSED'")) {
    throw 'Helper or cleanup failures are not guaranteed to fail closed.'
}
$catchIndex = $protectedIdentitySource.IndexOf('} catch {', $dryPassIndex)
$finallyIndex = $protectedIdentitySource.IndexOf('} finally {', [Math]::Max(0, $catchIndex))
if ($catchIndex -lt 0 -or $finallyIndex -le $catchIndex) {
    throw 'Protected identity failure handler was not found.'
}
$failureHandler = $protectedIdentitySource.Substring($catchIndex, $finallyIndex - $catchIndex)
foreach ($requiredFailureBoundary in @(
    'if ($Apply -and $replacePerformed)',
    'Remove-ProtectedIdentityTransactionArtifacts',
    '$report.error = $primaryError',
    '$report.status = ''FAIL_CLOSED'''
)) {
    if (-not $failureHandler.Contains($requiredFailureBoundary)) {
        throw "Dry-run render/validate failure handling lacks boundary: $requiredFailureBoundary"
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('.automaton-protected-helper-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($testRoot)
try {
    $childPath = Join-Path $testRoot 'diagnostic-child.ps1'
    [System.IO.File]::WriteAllText(
        $childPath,
        "[Console]::Out.WriteLine('token=stdout-secret')`r`n" +
        "[Console]::Error.WriteLine('Traceback: candidate validation failed password=stderr-secret')`r`n" +
        'exit 7',
        [System.Text.UTF8Encoding]::new($false)
    )
    foreach ($case in @(
        [pscustomobject]@{ operation = 'inspect'; stage = 'INSPECT' },
        [pscustomobject]@{ operation = 'render'; stage = 'RENDER' },
        [pscustomobject]@{ operation = 'validate'; stage = 'VALIDATE_PRE_REPLACE' },
        [pscustomobject]@{ operation = 'validate'; stage = 'VALIDATE_POST_REPLACE' }
    )) {
        $diagnostic = Invoke-ProtectedIdentityHelperProcess `
            -Operation $case.operation `
            -Stage $case.stage `
            -Executable 'powershell.exe' `
            -Arguments "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$childPath`"" `
            -WorkingDirectory $testRoot
        if ($diagnostic.succeeded -or $diagnostic.exit_code -ne 7 -or
            $diagnostic.operation -ne $case.operation -or $diagnostic.stage -ne $case.stage) {
            throw "Protected helper failure lost its operation/stage/exit code: $($case.operation)."
        }
        if (-not $diagnostic.stderr.Contains('Traceback: candidate validation failed') -or
            $diagnostic.stderr.Contains('stderr-secret') -or
            $diagnostic.stdout.Contains('stdout-secret')) {
            throw "Protected helper failure did not preserve sanitized diagnostics: $($case.operation)."
        }
    }
    $arbitraryOperationRejected = $false
    try {
        Invoke-ProtectedIdentityHelperProcess `
            -Operation 'arbitrary' `
            -Stage 'INSPECT' `
            -Executable 'powershell.exe' `
            -Arguments '-NoLogo -NoProfile' `
            -WorkingDirectory $testRoot | Out-Null
    } catch { $arbitraryOperationRejected = $true }
    if (-not $arbitraryOperationRejected) {
        throw 'Protected helper operation allowlist accepted an arbitrary operation.'
    }
    $bounded = ConvertTo-ProtectedHelperDiagnostic ('x' * 9000)
    if ($bounded.Length -ne 8192 -or -not $bounded.EndsWith('...[TRUNCATED]')) {
        throw 'Protected helper diagnostics are not bounded to 8 KiB.'
    }
    $exactRedaction = ConvertTo-ProtectedHelperDiagnostic 'known-sensitive-value' @('known-sensitive-value')
    if ($exactRedaction -ne '[REDACTED]') {
        throw 'Protected helper did not redact an explicitly known sensitive value.'
    }

    $cleanupRunId = [guid]::NewGuid()
    $cleanupPrefix = ".trading.identity-$($cleanupRunId.ToString('D').ToLowerInvariant())"
    $cleanupPaths = @(
        (Join-Path $testRoot "$cleanupPrefix.tmp"),
        (Join-Path $testRoot "$cleanupPrefix.backup"),
        (Join-Path $testRoot "$cleanupPrefix.failed")
    )
    [System.IO.File]::WriteAllText($cleanupPaths[0], 'canary')
    $cleanup = Remove-ProtectedIdentityTransactionArtifacts `
        $cleanupPaths -ExpectedParent $testRoot -RunId $cleanupRunId
    if (-not $cleanup.attempted -or -not $cleanup.removed -or
        @($cleanup.remaining).Count -ne 0 -or [System.IO.File]::Exists($cleanupPaths[0])) {
        throw 'Successful transaction cleanup was not reported from filesystem state.'
    }
    [void][System.IO.Directory]::CreateDirectory($cleanupPaths[2])
    $incomplete = Remove-ProtectedIdentityTransactionArtifacts `
        $cleanupPaths -ExpectedParent $testRoot -RunId $cleanupRunId
    if ($incomplete.removed -or @($incomplete.remaining).Count -ne 1 -or
        -not [System.IO.Directory]::Exists($cleanupPaths[2])) {
        throw 'Incomplete transaction cleanup did not fail closed with the remaining artifact.'
    }
    [System.IO.Directory]::Delete($cleanupPaths[2], $false)
} finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}
foreach ($legacyApplySemantic in @(
    'demo_authorization_file_exists = $false',
    'demo_authorization_gateway_write = $false'
)) {
    if ($applySource.Contains($legacyApplySemantic)) {
        throw "ACL apply gate retains legacy authorization semantics: $legacyApplySemantic"
    }
}
foreach ($newApplySemantic in @(
    'Assert-ExactControlDirectoryAcl',
    'Assert-ExactAuthorizationDirectoryAcl',
    'Assert-ExactAuthorizationArtifactAcl',
    'mt5-read-only-authorization-<UUID>.json',
    'demo_authorization_artifacts_verified = $true',
    'demo_authorization_gateway_mutation = $false'
)) {
    if (-not $applySource.Contains($newApplySemantic)) {
        throw "ACL apply gate lacks RunId artifact verification: $newApplySemantic"
    }
}

$testGatewaySid = 'S-1-5-21-10-20-30-1007'
$testAgentSid = 'S-1-5-21-10-20-30-1006'
$testMaintenanceSid = 'S-1-5-21-10-20-30-1001'
$testAdministratorsSid = 'S-1-5-32-544'

function New-RepairTestSnapshot(
    [string] $Path,
    [bool] $Directory,
    [bool] $Protected,
    [object[]] $Rules,
    [string] $Owner = 'S-1-5-32-544',
    [bool] $Reparse = $false
) {
    return [pscustomobject]@{
        path = $Path
        is_directory = $Directory
        reparse = $Reparse
        owner_sid = $Owner
        protected = $Protected
        sddl = 'synthetic-test-sddl'
        rules = @($Rules)
    }
}

function Assert-RepairTestThrows([scriptblock] $Action, [string] $Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    if (-not $threw) { throw $Message }
}

$canonicalControl = New-RepairTestSnapshot 'C:\control' $true $true `
    @(Get-MT5AclExpectedRules 'CONTROL' $testGatewaySid)
$canonicalDemo = New-RepairTestSnapshot 'C:\control\demo-authorization' $true $true `
    @(Get-MT5AclExpectedRules 'DEMO_AUTHORIZATION' $testGatewaySid)
$canonicalArtifact = New-RepairTestSnapshot `
    'C:\control\demo-authorization\mt5-read-only-authorization-00000000-0000-0000-0000-000000000001.json' `
    $false $false @(Get-MT5AclExpectedRules 'AUTHORIZATION_FILE' $testGatewaySid)

foreach ($case in @(
    [pscustomobject]@{ snapshot=$canonicalControl; kind='CONTROL' },
    [pscustomobject]@{ snapshot=$canonicalDemo; kind='DEMO_AUTHORIZATION' },
    [pscustomobject]@{ snapshot=$canonicalArtifact; kind='AUTHORIZATION_FILE' }
)) {
    $state = Get-MT5AclRepairState $case.snapshot $case.kind `
        $testGatewaySid $testMaintenanceSid
    if ($state -ne 'CANONICAL') { throw "Canonical repair test state failed: $($case.kind)" }
}
$canonicalPlan = Get-MT5AclRepairPlan 'CANONICAL' 'CANONICAL' @('CANONICAL')
if ($canonicalPlan.drift_detected -or $canonicalPlan.forward_set_acl_call_count -ne 0 -or
    $canonicalPlan.control_set_acl_required -or $canonicalPlan.demo_set_acl_required) {
    throw 'Canonical/idempotent repair plan would mutate an already canonical state.'
}

$controlMaintenance = New-RepairTestSnapshot 'C:\control' $true $true `
    (@(Get-MT5AclExpectedRules 'CONTROL' $testGatewaySid) + @(
        New-MT5AclRuleRecord $testMaintenanceSid 2032127L $false `
            'ContainerInherit, ObjectInherit' 'None'
    ))
if ((Get-MT5AclRepairState $controlMaintenance 'CONTROL' $testGatewaySid `
    $testMaintenanceSid) -ne 'MAINTENANCE_FULL_CONTROL_DRIFT') {
    throw 'Maintenance drift on control was not detected.'
}
$demoMaintenance = New-RepairTestSnapshot 'C:\control\demo-authorization' $true $true `
    (@(Get-MT5AclExpectedRules 'DEMO_AUTHORIZATION' $testGatewaySid) + @(
        New-MT5AclRuleRecord $testMaintenanceSid 2032127L $false `
            'ContainerInherit, ObjectInherit' 'None'
    ))
if ((Get-MT5AclRepairState $demoMaintenance 'DEMO_AUTHORIZATION' $testGatewaySid `
    $testMaintenanceSid) -ne 'MAINTENANCE_FULL_CONTROL_DRIFT') {
    throw 'Maintenance drift on demo-authorization was not detected.'
}
$artifactMaintenance = New-RepairTestSnapshot $canonicalArtifact.path $false $false `
    (@(Get-MT5AclExpectedRules 'AUTHORIZATION_FILE' $testGatewaySid) + @(
        New-MT5AclRuleRecord $testMaintenanceSid 2032127L $true 'None' 'None'
    ))
if ((Get-MT5AclRepairState $artifactMaintenance 'AUTHORIZATION_FILE' $testGatewaySid `
    $testMaintenanceSid) -ne 'MAINTENANCE_FULL_CONTROL_DRIFT') {
    throw 'Inherited maintenance drift on an authorization file was not detected.'
}
$driftPlan = Get-MT5AclRepairPlan `
    'MAINTENANCE_FULL_CONTROL_DRIFT' `
    'MAINTENANCE_FULL_CONTROL_DRIFT' `
    @('MAINTENANCE_FULL_CONTROL_DRIFT')
if (-not $driftPlan.drift_detected -or -not $driftPlan.control_set_acl_required -or
    -not $driftPlan.demo_set_acl_required -or $driftPlan.forward_set_acl_call_count -ne 2) {
    throw 'Maintenance drift did not produce the exact bounded two-directory repair plan.'
}

$agentControl = New-RepairTestSnapshot 'C:\control' $true $true `
    (@(Get-MT5AclExpectedRules 'CONTROL' $testGatewaySid) + @(
        New-MT5AclRuleRecord $testAgentSid 1179785L $false 'None' 'None'
    ))
Assert-RepairTestThrows {
    Get-MT5AclRepairState $agentControl 'CONTROL' $testGatewaySid $testMaintenanceSid
} 'Agent ACE was accepted as repairable drift.'
$denyRules = @(Get-MT5AclExpectedRules 'DEMO_AUTHORIZATION' $testGatewaySid)
$denyRules[0].type = 'Deny'
$denyDemo = New-RepairTestSnapshot 'C:\control\demo-authorization' $true $true $denyRules
Assert-RepairTestThrows {
    Get-MT5AclRepairState $denyDemo 'DEMO_AUTHORIZATION' $testGatewaySid $testMaintenanceSid
} 'Deny ACE was accepted as repairable drift.'
$explicitArtifactRules = @(Get-MT5AclExpectedRules 'AUTHORIZATION_FILE' $testGatewaySid)
$explicitArtifactRules[0].inherited = $false
$explicitArtifact = New-RepairTestSnapshot $canonicalArtifact.path $false $false $explicitArtifactRules
Assert-RepairTestThrows {
    Get-MT5AclRepairState $explicitArtifact 'AUTHORIZATION_FILE' `
        $testGatewaySid $testMaintenanceSid
} 'Explicit authorization-file ACE was accepted as repairable drift.'
$wrongOwner = New-RepairTestSnapshot 'C:\control' $true $true `
    @(Get-MT5AclExpectedRules 'CONTROL' $testGatewaySid) $testMaintenanceSid
Assert-RepairTestThrows {
    Get-MT5AclRepairState $wrongOwner 'CONTROL' $testGatewaySid $testMaintenanceSid
} 'Unexpected owner was accepted by the repair model.'
$reparseArtifact = New-RepairTestSnapshot $canonicalArtifact.path $false $false `
    @(Get-MT5AclExpectedRules 'AUTHORIZATION_FILE' $testGatewaySid) `
    $testAdministratorsSid $true
Assert-RepairTestThrows {
    Get-MT5AclRepairState $reparseArtifact 'AUTHORIZATION_FILE' `
        $testGatewaySid $testMaintenanceSid
} 'Reparse authorization file was accepted by the repair model.'

$candidateControl = Get-MT5AclDirectorySecuritySnapshot `
    (New-MT5AclCanonicalDirectorySecurity 'CONTROL' $testGatewaySid) 'C:\control'
$candidateDemo = Get-MT5AclDirectorySecuritySnapshot `
    (New-MT5AclCanonicalDirectorySecurity 'DEMO_AUTHORIZATION' $testGatewaySid) `
    'C:\control\demo-authorization'
Assert-MT5AclCanonicalSnapshot $candidateControl 'CONTROL' $testGatewaySid $testMaintenanceSid
Assert-MT5AclCanonicalSnapshot $candidateDemo 'DEMO_AUTHORIZATION' `
    $testGatewaySid $testMaintenanceSid
$artifactSddl = Get-MT5AclCanonicalArtifactSddl $testGatewaySid
if ($artifactSddl -notmatch 'D:AI' -or $artifactSddl -notmatch ';ID;') {
    throw 'Canonical authorization-file expected SDDL is not inherited.'
}

foreach ($requiredRepairBoundary in @(
    '#Requires -RunAsAdministrator',
    "mode = 'MT5_READ_ONLY_AUTHORIZATION_ACL_DRIFT_REPAIR'",
    'Read-TradingLabWindowsAclPolicy',
    'Assert-RepositoryClean',
    'Assert-FreshSecurityPreconditions',
    'Reserve-RepairReport',
    'Assert-ServiceIdentity',
    'Get-MT5AclRepairPlan',
    'Set-Acl -LiteralPath $controlPath -AclObject $controlCandidate',
    'Set-Acl -LiteralPath $demoAuthorizationPath -AclObject $demoCandidate',
    'Invoke-RepairRollback',
    'Assert-RepairStateUnchanged $initialState $restored',
    'Invoke-FullCanonicalVerifier',
    'without_automaton_state',
    'with_automaton_state',
    'modified_content',
    'trading.yaml changed during ACL repair',
    'expectedConfigSha256 = ''beabc9b2553a674739b62195a4181eeca0ed59019e11b78055808ec4cd31686e''',
    'FileMode]::CreateNew',
    'SET_ACL_CALL_COUNT=',
    'FILESYSTEM_MUTATION='
)) {
    if (-not $repairAclSource.Contains([string]$requiredRepairBoundary)) {
        throw "Transactional ACL repair gate lacks required boundary: $requiredRepairBoundary"
    }
}
foreach ($forbiddenRepairBoundary in @(
    'MetaTrader5.initialize', 'import MetaTrader5', '.order_check(', '.order_send(',
    'runas.exe', 'Start-Process', 'icacls', 'Invoke-Expression',
    'New-MT5ReadOnlyAuthorization.ps1', 'trading_lab.service'
)) {
    if (($repairAclSource + $repairHelperSource + $repairVerifierSource).Contains(
        $forbiddenRepairBoundary
    )) {
        throw "Transactional ACL repair gate contains forbidden boundary: $forbiddenRepairBoundary"
    }
}
foreach ($requiredChildBoundary in @(
    '^mt5-read-only-authorization-',
    'Authorization child is a directory or reparse point',
    'Unexpected authorization child filename',
    'FileAttributes]::ReparsePoint',
    'Authorization artifact changed during prevalidation'
)) {
    if (-not $repairAclSource.Contains($requiredChildBoundary)) {
        throw "Authorization child repair boundary is absent: $requiredChildBoundary"
    }
}
$mainRepairStart = $repairAclSource.IndexOf('Reserve-RepairReport', $repairAclSource.IndexOf('$initialState = Get-RepairState'))
$freshPreconditions = $repairAclSource.IndexOf('Assert-FreshSecurityPreconditions', $mainRepairStart)
$freshSnapshot = $repairAclSource.IndexOf('$freshState = Get-RepairState', $freshPreconditions)
$controlApply = $repairAclSource.IndexOf(
    'Set-Acl -LiteralPath $controlPath -AclObject $controlCandidate',
    $freshSnapshot
)
$demoApply = $repairAclSource.IndexOf(
    'Set-Acl -LiteralPath $demoAuthorizationPath -AclObject $demoCandidate',
    $controlApply
)
$specializedVerify = $repairAclSource.IndexOf(
    '$postState = Get-RepairState',
    $demoApply
)
$fullVerify = $repairAclSource.IndexOf('Invoke-FullCanonicalVerifier', $specializedVerify)
$failureCatch = $repairAclSource.IndexOf('} catch {', $fullVerify)
$rollbackCall = $repairAclSource.IndexOf('Invoke-RepairRollback', $failureCatch)
if ($mainRepairStart -lt 0 -or $freshPreconditions -le $mainRepairStart -or
    $freshSnapshot -le $freshPreconditions -or $controlApply -le $freshSnapshot -or
    $demoApply -le $controlApply -or $specializedVerify -le $demoApply -or
    $fullVerify -le $specializedVerify -or $failureCatch -le $fullVerify -or
    $rollbackCall -le $failureCatch) {
    throw 'Transactional repair ordering or rollback coverage is incomplete.'
}
$dryBranch = $repairAclSource.Substring(
    $repairAclSource.IndexOf('if (-not $Apply)', $freshSnapshot),
    $repairAclSource.IndexOf('} else {', $freshSnapshot) -
        $repairAclSource.IndexOf('if (-not $Apply)', $freshSnapshot)
)
foreach ($forbiddenDryRepair in @('Set-Acl', 'Invoke-FullCanonicalVerifier', 'Invoke-RepairRollback')) {
    if ($dryBranch.Contains($forbiddenDryRepair)) {
        throw "ACL repair dry-run branch contains mutation: $forbiddenDryRepair"
    }
}
foreach ($rollbackEvidence in @(
    '$report.rollback_attempted = $true',
    '$report.rollback_verified = [bool]$rollback.verified',
    '$report.error = $primaryError',
    "`$report.status = 'FAIL_CLOSED'"
)) {
    if (-not $repairAclSource.Contains($rollbackEvidence)) {
        throw "ACL repair failure/rollback evidence is missing: $rollbackEvidence"
    }
}
if ($repairVerifierSource -notmatch 'verify_windows_acl\(' -or
    $repairVerifierSource -notmatch 'include_automaton_state=False' -or
    $repairVerifierSource -notmatch 'include_automaton_state=True' -or
    $repairVerifierSource -match '(?m)^\s*(?:from|import)\s+MetaTrader5') {
    throw 'ACL repair verifier does not run both scopes or imports MetaTrader5.'
}

$aclDryRunIndex = $source.IndexOf('if (-not $Apply)')
if ($aclDryRunIndex -lt 0) { throw 'ACL script has no explicit dry-run exit.' }
foreach ($mutation in @('New-Item -ItemType Directory', 'WriteAllText', 'Set-Acl -LiteralPath')) {
    $mutationIndex = $source.IndexOf($mutation)
    if ($mutationIndex -ge 0 -and $mutationIndex -lt $aclDryRunIndex) {
        throw "ACL dry-run can reach mutation before its exit: $mutation"
    }
}

Write-Host 'ACL PowerShell AST and static least-privilege checks passed.'
