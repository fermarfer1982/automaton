#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Inventory', 'PrepareWheelhouse', 'UninstallTraditional', 'InstallMachineRuntime', 'BuildVenv', 'PromoteVenv')]
    [string] $Phase = 'Inventory',
    [string] $InstallerPath = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe',
    [string] $RegisteredBundlePath,
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
$modifyMask = [int64][System.Security.AccessControl.FileSystemRights]::Modify
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
    uninstaller_executed = $false
    venv_rebuilt = $false
    venv_promoted = $false
    current_run_applied_phase = 'NONE'
    required_previous_phase = $null
    previous_phase_verified = $false
    previous_phase_report = $null
    previous_phase_report_sha256 = $null
    old_venv_backup = $null
    mt5_accessed = $false
    automaton_started = $false
    gateway_started = $false
    acl_existing_domains_modified = $false
    gates = [ordered]@{}
    inventory_before = $null
    inventory_after = $null
    python_manager_preserve_path = $null
    traditional_bundle_target = $null
    traditional_bundle_uninstaller = $null
    traditional_msi_components = @()
    wheelhouse_validation = $null
    uninstall_plan = $null
    error = $null
}

. (Join-Path $PSScriptRoot 'TradingLabPythonInventory.ps1')

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
        if ($sid -in $ProtectedSids -and (([int64]$rule.FileSystemRights -band $modifyMask) -ne 0)) {
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

function New-ExactRuntimeSecurity([bool] $Directory, [bool] $IncludeGateway) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else { [System.Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new($administratorsSid))
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($entry in @(
        [pscustomobject]@{ Sid = $systemSid; Rights = $fullControl },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = $fullControl }
    )) {
        [void]$security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($entry.Sid), $entry.Rights,
            $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    if ($IncludeGateway) {
        [void]$security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($gatewaySid), $readExecute,
            $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $security
}

function Protect-ExactRuntimeTree([string] $Root, [bool] $IncludeGateway) {
    Assert-NoReparseComponents $Root
    $items = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Runtime tree contains a reparse point: $($item.FullName)"
        }
        Set-Acl -LiteralPath $item.FullName -AclObject (New-ExactRuntimeSecurity $item.PSIsContainer $IncludeGateway)
    }
    Set-Acl -LiteralPath $Root -AclObject (New-ExactRuntimeSecurity $true $IncludeGateway)
}

function Assert-ExactBaseAcl([string] $Root) {
    $allowedSids = @($systemSid, $administratorsSid, $gatewaySid)
    foreach ($item in @((Get-Item -LiteralPath $Root -Force)) + @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop
    )) {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if ((Resolve-IdentitySid $acl.Owner) -ne $administratorsSid -or -not $acl.AreAccessRulesProtected) {
            throw "Python runtime owner/inheritance is not exact: $($item.FullName)"
        }
        $rightsBySid = @{}
        foreach ($rule in $acl.Access) {
            $sid = Resolve-IdentitySid $rule.IdentityReference
            if ($rule.AccessControlType -ne 'Allow' -or $sid -notin $allowedSids) {
                throw "Unexpected Python runtime ACE on $($item.FullName): $sid"
            }
            if (-not $rightsBySid.ContainsKey($sid)) { $rightsBySid[$sid] = 0L }
            $rightsBySid[$sid] = $rightsBySid[$sid] -bor [int64]$rule.FileSystemRights
        }
        if (
            -not $rightsBySid.ContainsKey($systemSid) -or
            -not $rightsBySid.ContainsKey($administratorsSid) -or
            -not $rightsBySid.ContainsKey($gatewaySid) -or
            (($rightsBySid[$systemSid] -band [int64]$fullControl) -ne [int64]$fullControl) -or
            (($rightsBySid[$administratorsSid] -band [int64]$fullControl) -ne [int64]$fullControl) -or
            (($rightsBySid[$gatewaySid] -band [int64]$modifyMask) -ne 0) -or
            (($rightsBySid[$gatewaySid] -band [int64]$readExecute) -ne [int64]$readExecute)
        ) { throw "Python runtime ACL is incomplete or grants Gateway write rights: $($item.FullName)" }
    }
}

function Assert-Installer([string] $Path) {
    $canonical = Get-CanonicalPath $Path
    Assert-OutsideUserProfiles $canonical 'Python installer'
    Assert-NoReparseComponents $canonical
    if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) {
        throw "Verified full Python installer is absent: $canonical"
    }
    $item = Get-Item -LiteralPath $canonical -Force
    if ($item.Name -ne $expectedInstallerName -or $item.Length -ne $expectedInstallerLength) {
        throw 'Python installer name/length does not match the reviewed full offline artifact.'
    }
    $hash = (Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $expectedInstallerSha256) { throw "Python installer SHA-256 mismatch: $hash" }
    $signature = Get-AuthenticodeSignature -LiteralPath $canonical
    if (
        $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Python Software Foundation(,|$)'
    ) { throw 'Python installer Authenticode signature is not valid for Python Software Foundation.' }
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
    if ($Inventory.state.same_version_traditional_install_present -ne 'PASS') {
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
    $output = @(& $Python -I -c $Source)
    if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
        throw "Python metadata command failed for $Python."
    }
    return $output[0] | ConvertFrom-Json
}

function Get-PythonMetadata([string] $Python) {
    return Invoke-CheckedPythonJson $Python @'
import json
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
    return $metadata
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
    if (
        $Inventory.state.traditional_user_runtime -ne 'ABSENT' -or
        $Inventory.state.traditional_machine_runtime -ne 'PRESENT' -or
        $Inventory.state.partial_target_runtime -ne 'ABSENT' -or
        $Inventory.state.completed_target_runtime -ne 'PRESENT_UNVERIFIED' -or
        $Inventory.state.mixed_pythoncore_registration -ne 'ABSENT' -or
        -not $Inventory.target_probe.functional
    ) { throw 'MACHINE_TRADITIONAL_REGISTRATION=FAIL' }
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
    $report.inventory_before = $inventory.state
    if ($Phase -eq 'Inventory') {
        if ($Apply) { throw 'INVENTORY_APPLY_FORBIDDEN: select one explicit recovery phase.' }
        $inventory | ConvertTo-Json -Depth 10
        Write-Output "PYTHON_MANAGER_RUNTIME=$($inventory.state.python_manager_runtime)"
        Write-Output "TRADITIONAL_USER_RUNTIME=$($inventory.state.traditional_user_runtime)"
        Write-Output "TRADITIONAL_MACHINE_RUNTIME=$($inventory.state.traditional_machine_runtime)"
        Write-Output "PARTIAL_TARGET_RUNTIME=$($inventory.state.partial_target_runtime)"
        Write-Output "BROKEN_ACTIVE_VENV=$($inventory.state.broken_active_venv)"
        Write-Output "MIXED_PYTHONCORE_REGISTRATION=$($inventory.state.mixed_pythoncore_registration)"
        Write-Output "TRADITIONAL_MSI_COMPONENTS=$($inventory.state.traditional_msi_components)"
        Write-Output "SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=$($inventory.state.same_version_traditional_install_present)"
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
            $machineAlreadyValid =
                $inventory.state.traditional_user_runtime -eq 'ABSENT' -and
                $inventory.state.traditional_machine_runtime -eq 'PRESENT' -and
                $inventory.state.partial_target_runtime -eq 'ABSENT' -and
                $inventory.state.completed_target_runtime -eq 'PRESENT_UNVERIFIED' -and
                $inventory.state.mixed_pythoncore_registration -eq 'ABSENT'
            if ($machineAlreadyValid) {
                [void](Assert-BasePython $basePython)
                Assert-ExactBaseAcl $pythonBase
                Assert-TreeNotModifiableByServices $pythonBase
                $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
                $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
                $report.gates.PYTHON_GATEWAY_EXECUTE = 'PASS'
                $report.gates.PYTHON_GATEWAY_MODIFY_DENY = 'PASS'
                if ($Apply) { Initialize-PhaseStorage; $report.current_run_applied_phase = 'InstallMachineRuntimeAlreadyComplete' }
                break
            }
            Assert-NoTraditionalRuntime $inventory
            Assert-NoPartialTarget $inventory
            Assert-NoMixedPythonCore $inventory
            [void](Assert-Wheelhouse $wheelhousePath)
            $InstallerPath = Assert-Installer $InstallerPath
            $report.installer = $InstallerPath
            $report.gates.PYTHON_INSTALLER_VERIFIED = 'PASS'
            if (-not $Apply) { break }
            Initialize-PhaseStorage
            $installLog = New-PhaseLogPath 'machine-install'
            $report.installer_executed = $true
            $report.current_run_applied_phase = 'InstallMachineRuntimeRequested'
            Start-LoggedInstaller $InstallerPath @(
                '/quiet', 'InstallAllUsers=1', ('TargetDir=' + $pythonBase),
                'AssociateFiles=0', 'PrependPath=0', 'AppendPath=0', 'Shortcuts=0',
                'Include_doc=0', 'Include_debug=0', 'Include_dev=0', 'Include_exe=1',
                'Include_launcher=0', 'InstallLauncherAllUsers=0', 'Include_lib=1',
                'Include_pip=1', 'Include_symbols=0', 'Include_tcltk=0',
                'Include_test=0', 'Include_tools=0', 'CompileAll=0'
            ) $installLog
            $report.current_run_applied_phase = 'InstallMachineRuntime'
            [void](Assert-BasePython $basePython)
            $after = Get-TradingLabPythonInventory
            $report.inventory_after = $after.state
            Assert-MachineInstallationInventory $after
            Protect-ExactRuntimeTree $pythonBase $true
            Assert-ExactBaseAcl $pythonBase
            Assert-TreeNotModifiableByServices $pythonBase
            $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
            $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
            $report.gates.PYTHON_GATEWAY_EXECUTE = 'PASS'
            $report.gates.PYTHON_GATEWAY_MODIFY_DENY = 'PASS'
        }
        'BuildVenv' {
            Assert-MachineInstallationInventory $inventory
            [void](Assert-BasePython $basePython)
            [void](Assert-Wheelhouse $wheelhousePath)
            if (Test-Path -LiteralPath $stagingVenvPath) {
                [void](Assert-Venv $stagingVenvPath)
                $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
                $report.gates.VENV_LOCK_MATCH = 'PASS'
                $report.gates.META_TRADER5_PACKAGE_PRESENT = 'PASS'
                if ($Apply) { Initialize-PhaseStorage; $report.current_run_applied_phase = 'BuildVenvAlreadyComplete' }
                break
            }
            if (-not $Apply) { break }
            Initialize-PhaseStorage
            $report.current_run_applied_phase = 'BuildVenvRequested'
            Invoke-LoggedProcess $basePython @('-I', '-m', 'venv', $stagingVenvPath) 'venv-create'
            $stagingPython = Join-Path $stagingVenvPath 'Scripts\python.exe'
            Invoke-LoggedProcess $stagingPython @(
                '-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input',
                '--no-index', '--find-links', $wheelhousePath, '--only-binary=:all:',
                '--require-hashes', '-r', $lockPath
            ) 'venv-install'
            [void](Assert-Venv $stagingVenvPath)
            $report.current_run_applied_phase = 'BuildVenv'
            $report.venv_rebuilt = $true
            $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
            $report.gates.VENV_LOCK_MATCH = 'PASS'
            $report.gates.META_TRADER5_PACKAGE_PRESENT = 'PASS'
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
                    Protect-ExactRuntimeTree $failedPath $false
                }
                if ($oldMoved -and -not (Test-Path -LiteralPath $venvPath)) {
                    Move-Item -LiteralPath $backupPath -Destination $venvPath
                    $report.current_run_applied_phase = 'PromotionRolledBack'
                }
                throw
            }
            if ($oldMoved) {
                Protect-ExactRuntimeTree $backupPath $false
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
        Write-Output "PYTHON_RECOVERY_PHASE=$Phase"
        Write-Output 'PYTHON_RUNTIME_APPLY=NOT_RUN'
        exit 0
    }
    $report.status = 'PASS'
    Write-Report
    Write-Gates
    Write-Output "PYTHON_RECOVERY_PHASE=$Phase"
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
