Set-StrictMode -Version 2.0

$script:TradingLabPythonVersion = '3.14.5'
$script:TradingLabPythonDisplayVersion = '3.14.5150.0'
$script:TradingLabPythonTarget = 'C:\Program Files\AutomatonPython\3.14.5'
$script:TradingLabWorkspace = 'C:\automaton'
$script:TradingLabSystemSid = 'S-1-5-18'
$script:TradingLabExpectedMachineMsiComponents = @(
    [pscustomobject]@{ product_code = '{1B0251E9-CD20-49FC-AD22-70FCDBC2BAD7}'; display_name = 'Python 3.14.5 Executables (64-bit)' },
    [pscustomobject]@{ product_code = '{7040E6D8-53FD-4FE0-A539-92C0B33E9A10}'; display_name = 'Python 3.14.5 pip Bootstrap (64-bit)' },
    [pscustomobject]@{ product_code = '{A0B65FCB-97C6-47FD-984A-9EF9ECC1CE3B}'; display_name = 'Python 3.14.5 Standard Library (64-bit)' },
    [pscustomobject]@{ product_code = '{E402961E-7539-41B4-ADA9-62143E6D32D7}'; display_name = 'Python 3.14.5 Core Interpreter (64-bit)' }
)

function Get-TradingLabRegistryDefaultValue([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Item -LiteralPath $Path -ErrorAction Stop).GetValue('')
}

function Get-TradingLabProperty([object] $InputObject, [string] $Name) {
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Resolve-TradingLabInstallerExit([int] $ExitCode) {
    if ($ExitCode -eq 0) { return 'SUCCESS' }
    if ($ExitCode -eq 1603) { return 'INSTALLER_MAINTENANCE_COLLISION' }
    return 'INSTALLER_EXIT_NONZERO'
}

function ConvertTo-TradingLabNormalizedDistributionName([string] $Name) {
    return [regex]::Replace($Name.ToLowerInvariant(), '[-_.]+', '-')
}

function Resolve-TradingLabWheelhouseManifestState(
    [object[]] $LockedRequirements,
    [object[]] $Artifacts
) {
    $missing = [System.Collections.Generic.List[string]]::new()
    $unexpected = [System.Collections.Generic.List[string]]::new()
    $corrupt = [System.Collections.Generic.List[string]]::new()
    $sourceDistributions = [System.Collections.Generic.List[string]]::new()
    $duplicates = [System.Collections.Generic.List[string]]::new()
    $matchedArtifacts = [System.Collections.Generic.List[object]]::new()

    $expectedKeys = @{}
    foreach ($requirement in $LockedRequirements) {
        $key = "$(ConvertTo-TradingLabNormalizedDistributionName $requirement.name)==$($requirement.version.ToLowerInvariant())"
        if ($expectedKeys.ContainsKey($key)) { throw "Duplicate locked requirement: $key" }
        $expectedKeys[$key] = $requirement.sha256.ToLowerInvariant()
    }

    $actualByKey = @{}
    foreach ($artifact in $Artifacts) {
        $name = [string]$artifact.name
        $isDirectory = [bool](Get-TradingLabProperty $artifact 'is_directory')
        if ($isDirectory -or $name -notmatch '(?i)\.whl$') {
            $unexpected.Add($name)
            if ($name -match '(?i)(\.tar\.gz|\.zip|\.tar\.bz2)$') { $sourceDistributions.Add($name) }
            continue
        }
        $parts = [System.IO.Path]::GetFileNameWithoutExtension($name) -split '-'
        if ($parts.Count -lt 2) { $unexpected.Add($name); continue }
        $key = "$(ConvertTo-TradingLabNormalizedDistributionName $parts[0])==$($parts[1].ToLowerInvariant())"
        if (-not $expectedKeys.ContainsKey($key)) { $unexpected.Add($name); continue }
        if (-not $actualByKey.ContainsKey($key)) { $actualByKey[$key] = @() }
        $actualByKey[$key] = @($actualByKey[$key]) + @($artifact)
        if ([string]$artifact.sha256 -ne $expectedKeys[$key]) { $corrupt.Add($name) }
        $matchedArtifacts.Add([pscustomobject]@{ key = $key; name = $name; sha256 = $artifact.sha256 })
    }

    foreach ($key in $expectedKeys.Keys) {
        if (-not $actualByKey.ContainsKey($key)) {
            $missing.Add($key)
        } elseif (@($actualByKey[$key]).Count -ne 1) {
            $duplicates.Add($key)
        }
    }
    $mt5Key = 'metatrader5==5.0.6090'
    $numpyKey = 'numpy==2.5.2'
    return [pscustomobject]@{
        expected_requirements = $expectedKeys.Count
        artifact_count = $Artifacts.Count
        missing_requirements = @($missing)
        unexpected_artifacts = @($unexpected)
        corrupt_artifacts = @($corrupt)
        source_distributions = @($sourceDistributions)
        duplicate_requirements = @($duplicates)
        matched_artifacts = @($matchedArtifacts)
        hash_locked = $corrupt.Count -eq 0 -and $unexpected.Count -eq 0
        complete = $missing.Count -eq 0 -and $unexpected.Count -eq 0 -and
            $corrupt.Count -eq 0 -and $duplicates.Count -eq 0 -and
            $Artifacts.Count -eq $expectedKeys.Count
        metatrader5_present = $actualByKey.ContainsKey($mt5Key) -and @($actualByKey[$mt5Key]).Count -eq 1
        numpy_present = $actualByKey.ContainsKey($numpyKey) -and @($actualByKey[$numpyKey]).Count -eq 1
    }
}

function Test-TradingLabPrepareWheelhouseReportRecord(
    [object] $Record,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedLock,
    [string] $ExpectedVersion
) {
    if ($null -eq $Record) { return $false }
    $schema = Get-TradingLabProperty $Record 'schema_version'
    $appliedPhase = if ($schema -ge 3) {
        Get-TradingLabProperty $Record 'current_run_applied_phase'
    } else {
        Get-TradingLabProperty $Record 'last_applied_phase'
    }
    $gates = Get-TradingLabProperty $Record 'gates'
    return (
        $schema -in @(2, 3) -and
        (Get-TradingLabProperty $Record 'phase') -eq 'PrepareWheelhouse' -and
        [bool](Get-TradingLabProperty $Record 'apply_requested') -and
        (Get-TradingLabProperty $Record 'status') -eq 'PASS' -and
        (Get-TradingLabProperty $Record 'trading_mode') -eq 'OBSERVE_ONLY' -and
        (Get-TradingLabProperty $Record 'python_version') -eq $ExpectedVersion -and
        [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'wheelhouse')) -eq [System.IO.Path]::GetFullPath($ExpectedWheelhouse) -and
        [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'lock_file')) -eq [System.IO.Path]::GetFullPath($ExpectedLock) -and
        $appliedPhase -eq 'PrepareWheelhouse' -and
        (Get-TradingLabProperty $gates 'DECLARATIVE_HASH_LOCK') -eq 'PASS' -and
        (Get-TradingLabProperty $gates 'WHEELHOUSE_HASH_LOCKED') -eq 'PASS' -and
        (Get-TradingLabProperty $gates 'META_TRADER5_WHEEL_PRESENT') -eq 'PASS' -and
        (Get-TradingLabProperty $gates 'NUMPY_WHEEL_PRESENT') -eq 'PASS' -and
        -not [bool](Get-TradingLabProperty $Record 'installer_executed') -and
        -not [bool](Get-TradingLabProperty $Record 'uninstaller_executed') -and
        -not [bool](Get-TradingLabProperty $Record 'mt5_accessed') -and
        -not [bool](Get-TradingLabProperty $Record 'automaton_started') -and
        -not [bool](Get-TradingLabProperty $Record 'gateway_started') -and
        $null -eq (Get-TradingLabProperty $Record 'error')
    )
}

function Find-TradingLabPrepareWheelhouseReport(
    [string] $Directory,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedLock,
    [string] $ExpectedVersion
) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: report directory is absent.'
    }
    $candidates = @(Get-ChildItem -LiteralPath $Directory -File -Filter 'python-runtime-*.json' |
        Sort-Object LastWriteTimeUtc -Descending)
    foreach ($candidate in $candidates) {
        try {
            $record = [System.IO.File]::ReadAllText($candidate.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            if (Test-TradingLabPrepareWheelhouseReportRecord $record $ExpectedWheelhouse $ExpectedLock $ExpectedVersion) {
                return [pscustomobject]@{ path = $candidate.FullName; record = $record; last_write_time_utc = $candidate.LastWriteTimeUtc }
            }
        } catch { continue }
    }
    throw 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE=FAIL: no valid durable PASS report exists.'
}

function Test-TradingLabUninstallTraditionalReportRecord(
    [object] $Record,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedLock,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase,
    [string] $ExpectedActiveVenv
) {
    if ($null -eq $Record) { return $false }
    try {
        $gates = Get-TradingLabProperty $Record 'gates'
        $after = Get-TradingLabProperty $Record 'inventory_after'
        $wheelhouse = Get-TradingLabProperty $Record 'wheelhouse_validation'
        $previousHash = [string](Get-TradingLabProperty $Record 'previous_phase_report_sha256')
        return (
            (Get-TradingLabProperty $Record 'schema_version') -eq 3 -and
            (Get-TradingLabProperty $Record 'phase') -eq 'UninstallTraditional' -and
            [bool](Get-TradingLabProperty $Record 'apply_requested') -and
            (Get-TradingLabProperty $Record 'status') -eq 'PASS' -and
            (Get-TradingLabProperty $Record 'trading_mode') -eq 'OBSERVE_ONLY' -and
            (Get-TradingLabProperty $Record 'python_version') -eq $ExpectedVersion -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'python_base')) -eq [System.IO.Path]::GetFullPath($ExpectedPythonBase) -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'active_venv')) -eq [System.IO.Path]::GetFullPath($ExpectedActiveVenv) -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'wheelhouse')) -eq [System.IO.Path]::GetFullPath($ExpectedWheelhouse) -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'lock_file')) -eq [System.IO.Path]::GetFullPath($ExpectedLock) -and
            (Get-TradingLabProperty $Record 'current_run_applied_phase') -eq 'UninstallTraditional' -and
            (Get-TradingLabProperty $Record 'required_previous_phase') -eq 'PrepareWheelhouse' -and
            [bool](Get-TradingLabProperty $Record 'previous_phase_verified') -and
            -not [string]::IsNullOrWhiteSpace([string](Get-TradingLabProperty $Record 'previous_phase_report')) -and
            $previousHash -match '^[0-9a-f]{64}$' -and
            -not [bool](Get-TradingLabProperty $Record 'installer_executed') -and
            [bool](Get-TradingLabProperty $Record 'uninstaller_executed') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_rebuilt') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_promoted') -and
            -not [bool](Get-TradingLabProperty $Record 'mt5_accessed') -and
            -not [bool](Get-TradingLabProperty $Record 'automaton_started') -and
            -not [bool](Get-TradingLabProperty $Record 'gateway_started') -and
            -not [bool](Get-TradingLabProperty $Record 'acl_existing_domains_modified') -and
            (Get-TradingLabProperty $gates 'DECLARATIVE_HASH_LOCK') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_MANAGER_RUNTIME') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PREVIOUS_PHASE_PREPARE_WHEELHOUSE') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'WHEELHOUSE_PRESENT') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'WHEELHOUSE_HASH_LOCKED') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'WHEELHOUSE_COMPLETE') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'META_TRADER5_WHEEL_PRESENT') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'NUMPY_WHEEL_PRESENT') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_MANAGER_PRESERVE') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'SAME_VERSION_TRADITIONAL_INSTALL_PRESENT') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PARTIAL_TARGET_POST_STATE') -eq 'ABSENT' -and
            (Get-TradingLabProperty $gates 'MIXED_PYTHONCORE_POST_STATE') -eq 'ABSENT' -and
            (Get-TradingLabProperty $after 'python_manager_runtime') -eq 'FUNCTIONAL' -and
            (Get-TradingLabProperty $after 'traditional_user_runtime') -eq 'ABSENT' -and
            (Get-TradingLabProperty $after 'traditional_machine_runtime') -eq 'ABSENT' -and
            (Get-TradingLabProperty $after 'traditional_msi_components') -eq 0 -and
            (Get-TradingLabProperty $after 'partial_target_runtime') -eq 'ABSENT' -and
            (Get-TradingLabProperty $after 'mixed_pythoncore_registration') -eq 'ABSENT' -and
            (Get-TradingLabProperty $after 'same_version_traditional_install_present') -eq 'PASS' -and
            (Get-TradingLabProperty $wheelhouse 'expected_requirements') -eq 27 -and
            (Get-TradingLabProperty $wheelhouse 'artifact_count') -eq 27 -and
            @((Get-TradingLabProperty $wheelhouse 'missing_requirements')).Count -eq 0 -and
            @((Get-TradingLabProperty $wheelhouse 'source_distributions')).Count -eq 0 -and
            @((Get-TradingLabProperty $wheelhouse 'unexpected_artifacts')).Count -eq 0 -and
            @((Get-TradingLabProperty $wheelhouse 'corrupt_artifacts')).Count -eq 0 -and
            @((Get-TradingLabProperty $wheelhouse 'duplicate_requirements')).Count -eq 0 -and
            @((Get-TradingLabProperty $wheelhouse 'matched_artifacts')).Count -eq 27 -and
            [bool](Get-TradingLabProperty $wheelhouse 'hash_locked') -and
            [bool](Get-TradingLabProperty $wheelhouse 'complete') -and
            [bool](Get-TradingLabProperty $wheelhouse 'metatrader5_present') -and
            [bool](Get-TradingLabProperty $wheelhouse 'numpy_present') -and
            $null -eq (Get-TradingLabProperty $Record 'error')
        )
    } catch { return $false }
}

function Find-TradingLabUninstallTraditionalReport(
    [string] $Directory,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedLock,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase,
    [string] $ExpectedActiveVenv
) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: report directory is absent.'
    }
    $candidates = @(Get-ChildItem -LiteralPath $Directory -File -Filter 'python-runtime-*.json' |
        Sort-Object LastWriteTimeUtc -Descending)
    foreach ($candidate in $candidates) {
        try {
            $record = [System.IO.File]::ReadAllText($candidate.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            if (Test-TradingLabUninstallTraditionalReportRecord `
                $record $ExpectedWheelhouse $ExpectedLock $ExpectedVersion $ExpectedPythonBase $ExpectedActiveVenv
            ) {
                return [pscustomobject]@{
                    path = $candidate.FullName
                    record = $record
                    last_write_time_utc = $candidate.LastWriteTimeUtc
                }
            }
        } catch { continue }
    }
    throw 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=FAIL: no valid durable applied PASS report exists.'
}

function Test-TradingLabInstalledRuntimePendingReportRecord(
    [object] $Record,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase,
    [string] $ExpectedInstaller
) {
    if ($null -eq $Record) { return $false }
    try {
        $gates = Get-TradingLabProperty $Record 'gates'
        $plan = Get-TradingLabProperty $Record 'installer_plan'
        $previousHash = [string](Get-TradingLabProperty $Record 'previous_phase_report_sha256')
        return (
            (Get-TradingLabProperty $Record 'schema_version') -eq 3 -and
            (Get-TradingLabProperty $Record 'phase') -eq 'InstallMachineRuntime' -and
            [bool](Get-TradingLabProperty $Record 'apply_requested') -and
            (Get-TradingLabProperty $Record 'status') -eq 'FAIL' -and
            (Get-TradingLabProperty $Record 'trading_mode') -eq 'OBSERVE_ONLY' -and
            (Get-TradingLabProperty $Record 'python_version') -eq $ExpectedVersion -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'python_base')) -eq [System.IO.Path]::GetFullPath($ExpectedPythonBase) -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $Record 'installer')) -eq [System.IO.Path]::GetFullPath($ExpectedInstaller) -and
            (Get-TradingLabProperty $Record 'current_run_applied_phase') -eq 'InstallMachineRuntime' -and
            (Get-TradingLabProperty $Record 'required_previous_phase') -eq 'UninstallTraditional' -and
            [bool](Get-TradingLabProperty $Record 'previous_phase_verified') -and
            -not [string]::IsNullOrWhiteSpace([string](Get-TradingLabProperty $Record 'previous_phase_report')) -and
            $previousHash -match '^[0-9a-f]{64}$' -and
            [bool](Get-TradingLabProperty $Record 'installer_executed') -and
            -not [bool](Get-TradingLabProperty $Record 'uninstaller_executed') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_rebuilt') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_promoted') -and
            -not [bool](Get-TradingLabProperty $Record 'mt5_accessed') -and
            -not [bool](Get-TradingLabProperty $Record 'automaton_started') -and
            -not [bool](Get-TradingLabProperty $Record 'gateway_started') -and
            -not [bool](Get-TradingLabProperty $Record 'acl_existing_domains_modified') -and
            (Get-TradingLabProperty $gates 'TRADING_MODE_OBSERVE_ONLY') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PREVIOUS_PHASE_UNINSTALL_TRADITIONAL') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_INSTALLER_VERIFIED') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'INSTALL_ALL_USERS') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'TARGET_MACHINE_WIDE') -eq 'PASS' -and
            (Get-TradingLabProperty $plan 'operation') -eq 'INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL' -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $plan 'executable')) -eq [System.IO.Path]::GetFullPath($ExpectedInstaller) -and
            [System.IO.Path]::GetFullPath((Get-TradingLabProperty $plan 'target_dir')) -eq [System.IO.Path]::GetFullPath($ExpectedPythonBase) -and
            -not [string]::IsNullOrWhiteSpace([string](Get-TradingLabProperty $Record 'error'))
        )
    } catch { return $false }
}

function Find-TradingLabInstalledRuntimePendingReport(
    [string] $Directory,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase,
    [string] $ExpectedInstaller
) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: report directory is absent.'
    }
    foreach ($candidate in @(Get-ChildItem -LiteralPath $Directory -File -Filter 'python-runtime-*.json' |
        Sort-Object LastWriteTimeUtc -Descending)) {
        try {
            $record = [System.IO.File]::ReadAllText($candidate.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            if (Test-TradingLabInstalledRuntimePendingReportRecord `
                $record $ExpectedVersion $ExpectedPythonBase $ExpectedInstaller
            ) {
                return [pscustomobject]@{
                    path = $candidate.FullName
                    record = $record
                    last_write_time_utc = $candidate.LastWriteTimeUtc
                }
            }
        } catch { continue }
    }
    throw 'INSTALLED_RUNTIME_EVIDENCE=FAIL: no valid failed post-install report exists.'
}

function Resolve-TradingLabInstallPreconditionState([object] $State) {
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($check in @(
        [pscustomobject]@{ Name = 'PYTHON_MANAGER_RUNTIME'; Actual = Get-TradingLabProperty $State 'python_manager_runtime'; Expected = 'FUNCTIONAL' },
        [pscustomobject]@{ Name = 'TRADITIONAL_USER_RUNTIME_ABSENT'; Actual = Get-TradingLabProperty $State 'traditional_user_runtime'; Expected = 'ABSENT' },
        [pscustomobject]@{ Name = 'TRADITIONAL_MACHINE_RUNTIME_ABSENT'; Actual = Get-TradingLabProperty $State 'traditional_machine_runtime'; Expected = 'ABSENT' },
        [pscustomobject]@{ Name = 'TRADITIONAL_MSI_COMPONENTS_ZERO'; Actual = Get-TradingLabProperty $State 'traditional_msi_components'; Expected = 0 },
        [pscustomobject]@{ Name = 'PARTIAL_TARGET_RUNTIME_ABSENT'; Actual = Get-TradingLabProperty $State 'partial_target_runtime'; Expected = 'ABSENT' },
        [pscustomobject]@{ Name = 'MIXED_PYTHONCORE_REGISTRATION_ABSENT'; Actual = Get-TradingLabProperty $State 'mixed_pythoncore_registration'; Expected = 'ABSENT' },
        [pscustomobject]@{ Name = 'SAME_VERSION_TRADITIONAL_INSTALL_PRESENT'; Actual = Get-TradingLabProperty $State 'same_version_traditional_install_present'; Expected = 'ABSENT' }
    )) {
        if ($check.Actual -ne $check.Expected) { $failures.Add("$($check.Name):$($check.Actual)") }
    }
    return [pscustomobject]@{ valid = $failures.Count -eq 0; failures = @($failures) }
}

function Resolve-TradingLabInstallerArtifactState(
    [string] $Name,
    [long] $Length,
    [string] $Sha256,
    [string] $SignatureStatus,
    [string] $SignerSubject,
    [string] $ExpectedName,
    [long] $ExpectedLength,
    [string] $ExpectedSha256
) {
    $sizeValid = $Name -eq $ExpectedName -and $Length -eq $ExpectedLength
    $hashValid = $Sha256.ToLowerInvariant() -eq $ExpectedSha256.ToLowerInvariant()
    $signatureValid = $SignatureStatus -eq 'Valid' -and
        $SignerSubject -match '(^|,\s*)O=Python Software Foundation(,|$)'
    return [pscustomobject]@{
        size_valid = $sizeValid
        hash_valid = $hashValid
        authenticode_valid = $signatureValid
        verified = $sizeValid -and $hashValid -and $signatureValid
    }
}

function Test-TradingLabExactMachineTarget(
    [string] $Path,
    [string] $ExpectedTarget,
    [string] $UsersRoot
) {
    try {
        $candidate = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
        $expected = [System.IO.Path]::GetFullPath($ExpectedTarget).TrimEnd('\')
        $users = [System.IO.Path]::GetFullPath($UsersRoot).TrimEnd('\')
        return $candidate.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not ($candidate.Equals($users, [System.StringComparison]::OrdinalIgnoreCase) -or
                $candidate.StartsWith($users + '\', [System.StringComparison]::OrdinalIgnoreCase))
    } catch { return $false }
}

function Test-TradingLabManagerExcludedFromUninstallPlan(
    [object] $Plan,
    [string] $ManagerRegistryId,
    [string] $ManagerPath
) {
    $destructiveIds = @((Get-TradingLabProperty $Plan 'destructive_registry_ids'))
    $directDeletes = @((Get-TradingLabProperty $Plan 'direct_filesystem_deletes'))
    $arguments = @((Get-TradingLabProperty $Plan 'arguments'))
    $executable = [string](Get-TradingLabProperty $Plan 'executable')
    $allDestructiveText = @($destructiveIds + $directDeletes + $arguments + @($executable)) -join "`n"
    return (
        $ManagerRegistryId -notin $destructiveIds -and
        -not $executable.Equals((Join-Path $ManagerPath 'pymanager.exe'), [System.StringComparison]::OrdinalIgnoreCase) -and
        $allDestructiveText.IndexOf($ManagerRegistryId, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
        $allDestructiveText.IndexOf($ManagerPath, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
        $allDestructiveText.IndexOf('pymanager.exe uninstall', [System.StringComparison]::OrdinalIgnoreCase) -lt 0
    )
}

function Resolve-TradingLabMsiComponentSetState(
    [object[]] $Expected,
    [object[]] $Actual
) {
    $expectedByCode = @{}
    foreach ($item in $Expected) { $expectedByCode[$item.product_code.ToUpperInvariant()] = $item.display_name }
    $actualByCode = @{}
    $duplicates = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Actual) {
        $code = ([string]$item.product_code).ToUpperInvariant()
        if ($actualByCode.ContainsKey($code)) { $duplicates.Add($code) }
        $actualByCode[$code] = $item
    }
    $missing = @($expectedByCode.Keys | Where-Object { -not $actualByCode.ContainsKey($_) } | Sort-Object)
    $unexpected = @($actualByCode.Keys | Where-Object { -not $expectedByCode.ContainsKey($_) } | Sort-Object)
    $nameMismatch = @($expectedByCode.Keys | Where-Object {
        $actualByCode.ContainsKey($_) -and $actualByCode[$_].display_name -ne $expectedByCode[$_]
    } | Sort-Object)
    return [pscustomobject]@{
        expected_count = $expectedByCode.Count
        actual_count = $Actual.Count
        missing_product_codes = $missing
        unexpected_product_codes = $unexpected
        duplicate_product_codes = @($duplicates)
        display_name_mismatches = $nameMismatch
        valid = $Actual.Count -eq $expectedByCode.Count -and $missing.Count -eq 0 -and
            $unexpected.Count -eq 0 -and $duplicates.Count -eq 0 -and $nameMismatch.Count -eq 0
    }
}

function Resolve-TradingLabMachineMsiComponentState(
    [object[]] $MsiProducts,
    [object[]] $Expected = $script:TradingLabExpectedMachineMsiComponents,
    [string] $ExpectedOwnerSid = $script:TradingLabSystemSid
) {
    $ownedByMachine = @($MsiProducts | Where-Object {
        (Get-TradingLabProperty $_ 'user_data_sid') -eq $ExpectedOwnerSid
    })
    $setState = Resolve-TradingLabMsiComponentSetState $Expected $ownedByMachine
    $invalidOwners = @($MsiProducts | Where-Object {
        (Get-TradingLabProperty $_ 'user_data_sid') -ne $ExpectedOwnerSid
    } | ForEach-Object { Get-TradingLabProperty $_ 'product_code' })
    return [pscustomobject]@{
        expected_count = $Expected.Count
        expected_present = $setState.actual_count - $setState.unexpected_product_codes.Count
        actual_machine_count = $ownedByMachine.Count
        missing_product_codes = @($setState.missing_product_codes)
        unexpected_product_codes = @($setState.unexpected_product_codes)
        duplicate_product_codes = @($setState.duplicate_product_codes)
        display_name_mismatches = @($setState.display_name_mismatches)
        invalid_owner_product_codes = $invalidOwners
        valid = $setState.valid -and $invalidOwners.Count -eq 0
    }
}

function Get-TradingLabPythonCoreRegistrations {
    $registrations = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in @(
        [pscustomobject]@{ Scope = 'HKCU'; Path = 'HKCU:\Software\Python\PythonCore\3.14' },
        [pscustomobject]@{ Scope = 'HKLM'; Path = 'HKLM:\Software\Python\PythonCore\3.14' },
        [pscustomobject]@{ Scope = 'HKLM32'; Path = 'HKLM:\Software\WOW6432Node\Python\PythonCore\3.14' }
    )) {
        if (-not (Test-Path -LiteralPath $entry.Path)) { continue }
        $root = Get-ItemProperty -LiteralPath $entry.Path -ErrorAction Stop
        $installPathKey = Join-Path $entry.Path 'InstallPath'
        $install = if (Test-Path -LiteralPath $installPathKey) {
            Get-ItemProperty -LiteralPath $installPathKey -ErrorAction Stop
        } else { $null }
        $registrations.Add([pscustomobject]@{
            scope = $entry.Scope
            key = $entry.Path
            managed_by_python_manager = [bool]((Get-TradingLabProperty $root 'ManagedByPyManager') -eq 1)
            install_path = if ($null -ne $install) { Get-TradingLabRegistryDefaultValue $installPathKey } else { $null }
            executable_path = if ($null -ne $install) { Get-TradingLabProperty $install 'ExecutablePath' } else { $null }
        })
    }
    return @($registrations)
}

function Get-TradingLabPythonUninstallEntries {
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($root in @(
        [pscustomobject]@{ Scope = 'HKCU'; Pattern = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        [pscustomobject]@{ Scope = 'HKLM'; Pattern = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        [pscustomobject]@{ Scope = 'HKLM32'; Pattern = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    )) {
        foreach ($item in Get-ItemProperty $root.Pattern -ErrorAction SilentlyContinue) {
            $displayName = Get-TradingLabProperty $item 'DisplayName'
            $windowsInstaller = Get-TradingLabProperty $item 'WindowsInstaller'
            $isManager = $item.PSChildName -like 'pymanager-pythoncore-3.14*' -and
                $displayName -eq 'Python 3.14.5'
            $isTraditionalBundle = $displayName -eq 'Python 3.14.5 (64-bit)'
            $isTraditionalComponent = $displayName -match '^Python 3\.14\.5 .+ \(64-bit\)$' -and
                [bool]$windowsInstaller
            if (-not ($isManager -or $isTraditionalBundle -or $isTraditionalComponent)) { continue }
            $kind = if ($isManager) {
                'PYTHON_MANAGER_RUNTIME'
            } elseif ($isTraditionalBundle) {
                'TRADITIONAL_BUNDLE'
            } else {
                'TRADITIONAL_MSI_COMPONENT'
            }
            $entries.Add([pscustomobject]@{
                scope = $root.Scope
                registry_id = $item.PSChildName
                kind = $kind
                display_name = $displayName
                display_version = Get-TradingLabProperty $item 'DisplayVersion'
                install_location = Get-TradingLabProperty $item 'InstallLocation'
                uninstall_string = Get-TradingLabProperty $item 'UninstallString'
                modify_path = Get-TradingLabProperty $item 'ModifyPath'
                windows_installer = [bool]$windowsInstaller
            })
        }
    }
    return @($entries)
}

function Get-TradingLabPythonMsiProducts {
    $products = [System.Collections.Generic.List[object]]::new()
    $userDataRoot = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData'
    foreach ($sidKey in Get-ChildItem -LiteralPath $userDataRoot -ErrorAction SilentlyContinue) {
        $productsPath = Join-Path $sidKey.PSPath 'Products'
        foreach ($product in Get-ChildItem -LiteralPath $productsPath -ErrorAction SilentlyContinue) {
            $propertiesPath = Join-Path $product.PSPath 'InstallProperties'
            if (-not (Test-Path -LiteralPath $propertiesPath)) { continue }
            $properties = Get-ItemProperty -LiteralPath $propertiesPath -ErrorAction Stop
            $displayName = Get-TradingLabProperty $properties 'DisplayName'
            if ($displayName -notmatch '^Python 3\.14\.5 .+ \(64-bit\)$') { continue }
            $productCode = $null
            $uninstallString = Get-TradingLabProperty $properties 'UninstallString'
            if ($uninstallString -match '(?i)\{[0-9a-f-]{36}\}') {
                $productCode = $Matches[0].ToUpperInvariant()
            }
            $products.Add([pscustomobject]@{
                user_data_sid = $sidKey.PSChildName
                packed_product_code = $product.PSChildName
                product_code = $productCode
                display_name = $displayName
                display_version = Get-TradingLabProperty $properties 'DisplayVersion'
                install_location = Get-TradingLabProperty $properties 'InstallLocation'
                install_source = Get-TradingLabProperty $properties 'InstallSource'
                local_package = Get-TradingLabProperty $properties 'LocalPackage'
            })
        }
    }
    return @($products)
}

function Get-TradingLabPythonLayout([string] $Root) {
    $exists = Test-Path -LiteralPath $Root -PathType Container
    $python = Join-Path $Root 'python.exe'
    $dll = Join-Path $Root 'python314.dll'
    $library = Join-Path $Root 'Lib'
    $stdlib = Join-Path $library 'os.py'
    return [pscustomobject]@{
        root = $Root
        exists = $exists
        python_exists = Test-Path -LiteralPath $python -PathType Leaf
        dll_exists = Test-Path -LiteralPath $dll -PathType Leaf
        lib_exists = Test-Path -LiteralPath $library -PathType Container
        stdlib_exists = Test-Path -LiteralPath $stdlib -PathType Leaf
        complete_layout = $exists -and
            (Test-Path -LiteralPath $python -PathType Leaf) -and
            (Test-Path -LiteralPath $dll -PathType Leaf) -and
            (Test-Path -LiteralPath $library -PathType Container) -and
            (Test-Path -LiteralPath $stdlib -PathType Leaf)
    }
}

function Invoke-TradingLabPythonStdinJson([string] $Python, [string] $Source) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        return [pscustomobject]@{ attempted = $false; functional = $false; error = 'PYTHON_NOT_FOUND'; metadata = $null; stderr = $null }
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Python
    $startInfo.Arguments = '-I -'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            return [pscustomobject]@{ attempted = $true; functional = $false; error = 'PROCESS_START_FALSE'; metadata = $null; stderr = $null }
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($Source)
        $process.StandardInput.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            return [pscustomobject]@{
                attempted = $true
                functional = $false
                error = "PYTHON_EXIT_$($process.ExitCode)"
                metadata = $null
                stderr = $stderr.Trim()
            }
        }
        try {
            $metadata = $stdout.Trim() | ConvertFrom-Json
            return [pscustomobject]@{ attempted = $true; functional = $true; error = $null; metadata = $metadata; stderr = $stderr.Trim() }
        } catch {
            return [pscustomobject]@{ attempted = $true; functional = $false; error = 'INVALID_METADATA_JSON'; metadata = $null; stderr = $stderr.Trim() }
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-TradingLabPythonMetadata([string] $Python) {
    $source = @'
import json
import platform
import sys
import venv
print(json.dumps({
    "architecture": platform.architecture()[0],
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "prefix": sys.prefix,
    "venv_import": True,
    "version": platform.python_version(),
}, sort_keys=True, separators=(',', ':')))
'@
    return Invoke-TradingLabPythonStdinJson $Python $source
}

function Get-TradingLabVenvState([string] $Root) {
    $python = Join-Path $Root 'Scripts\python.exe'
    $cfgPath = Join-Path $Root 'pyvenv.cfg'
    $base = $null
    if (Test-Path -LiteralPath $cfgPath -PathType Leaf) {
        $cfg = [System.IO.File]::ReadAllText($cfgPath, [System.Text.Encoding]::UTF8)
        if ($cfg -match '(?im)^\s*home\s*=\s*(.+?)\s*$') { $base = $Matches[1].Trim() }
    }
    $basePython = if ($base) { Join-Path $base 'python.exe' } else { $null }
    $redirectorExists = Test-Path -LiteralPath $python -PathType Leaf
    $baseExists = $basePython -and (Test-Path -LiteralPath $basePython -PathType Leaf)
    return [pscustomobject]@{
        root = $Root
        redirector_exists = $redirectorExists
        pyvenv_cfg_exists = Test-Path -LiteralPath $cfgPath -PathType Leaf
        declared_base = $base
        declared_base_python_exists = [bool]$baseExists
        broken = $redirectorExists -and (-not $baseExists)
    }
}

function Resolve-TradingLabPythonInventoryState(
    [object[]] $UninstallEntries,
    [object[]] $MsiProducts,
    [object[]] $PythonCoreRegistrations,
    [object] $ManagerProbe,
    [object] $TargetLayout,
    [object] $VenvState
) {
    $managerEntries = @($UninstallEntries | Where-Object { $_.kind -eq 'PYTHON_MANAGER_RUNTIME' })
    $traditionalBundles = @($UninstallEntries | Where-Object { $_.kind -eq 'TRADITIONAL_BUNDLE' })
    $traditionalComponents = @($UninstallEntries | Where-Object { $_.kind -eq 'TRADITIONAL_MSI_COMPONENT' })
    $bundleScopes = @($traditionalBundles | ForEach-Object { $_.scope } | Sort-Object -Unique)
    $bundleRegistrationScope = if ($bundleScopes.Count -eq 0) {
        'NONE'
    } elseif ($bundleScopes.Count -eq 1) {
        $bundleScopes[0]
    } else { 'MULTIPLE' }
    $machineMsi = Resolve-TradingLabMachineMsiComponentState $MsiProducts
    $machineCore = @($PythonCoreRegistrations | Where-Object {
        (Get-TradingLabProperty $_ 'scope') -in @('HKLM', 'HKLM32') -and
        -not [bool](Get-TradingLabProperty $_ 'managed_by_python_manager') -and
        (Get-TradingLabProperty $_ 'executable_path') -and
        [System.IO.Path]::GetFullPath((Get-TradingLabProperty $_ 'executable_path')).Equals(
            [System.IO.Path]::GetFullPath((Join-Path $script:TradingLabPythonTarget 'python.exe')),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    })
    $mixedPythonCore = @($PythonCoreRegistrations | Where-Object {
        [bool](Get-TradingLabProperty $_ 'managed_by_python_manager') -and
        (Get-TradingLabProperty $_ 'executable_path') -and
        (Get-TradingLabProperty $_ 'executable_path') -like "$script:TradingLabPythonTarget*"
    }).Count -gt 0
    $expectedMachinePayload = $TargetLayout.complete_layout -and
        $machineCore.Count -eq 1 -and $machineMsi.valid
    $nonMachineMsi = @($MsiProducts | Where-Object {
        (Get-TradingLabProperty $_ 'user_data_sid') -ne $script:TradingLabSystemSid
    })
    $hasTraditionalEvidence = $traditionalBundles.Count -gt 0 -or
        $traditionalComponents.Count -gt 0 -or $MsiProducts.Count -gt 0 -or
        $machineCore.Count -gt 0 -or $TargetLayout.exists
    $classification = if ($expectedMachinePayload) {
        'EXPECTED_INSTALLED_TARGET_RUNTIME'
    } elseif ($hasTraditionalEvidence) {
        'CONFLICTING_PREEXISTING_RUNTIME'
    } else { 'ABSENT' }
    $payloadScope = if ($expectedMachinePayload) {
        'MACHINE'
    } elseif ($nonMachineMsi.Count -gt 0 -or ($bundleRegistrationScope -eq 'HKCU' -and -not $machineCore.Count)) {
        'USER_OR_LEGACY_CONTEXT'
    } elseif ($machineCore.Count -gt 0 -or $machineMsi.actual_machine_count -gt 0) {
        'MACHINE_INCOMPLETE'
    } else { 'NONE' }
    return [pscustomobject]@{
        python_manager_runtime = if ($managerEntries.Count -gt 0 -and $ManagerProbe.functional) { 'FUNCTIONAL' } elseif ($managerEntries.Count -gt 0) { 'REGISTERED_BUT_BROKEN' } else { 'ABSENT' }
        traditional_bundle_registration_scope = $bundleRegistrationScope
        traditional_runtime_payload_scope = $payloadScope
        traditional_user_runtime = if ($classification -eq 'CONFLICTING_PREEXISTING_RUNTIME' -and $payloadScope -eq 'USER_OR_LEGACY_CONTEXT') { 'PRESENT' } else { 'ABSENT' }
        traditional_machine_runtime = if ($payloadScope -in @('MACHINE', 'MACHINE_INCOMPLETE')) { 'PRESENT' } else { 'ABSENT' }
        traditional_msi_components = $MsiProducts.Count
        machine_runtime_target_present = [bool]$TargetLayout.complete_layout
        machine_runtime_msi_components = $machineMsi.actual_machine_count
        expected_machine_msi_components = $machineMsi.expected_count
        unexpected_machine_msi_components = $machineMsi.unexpected_product_codes.Count + $machineMsi.invalid_owner_product_codes.Count
        machine_runtime_msi_valid = $machineMsi.valid
        python_manager_runtime_path = if ($ManagerProbe.functional) { $ManagerProbe.metadata.base_prefix } else { $null }
        partial_target_runtime = if ($TargetLayout.exists -and -not $TargetLayout.complete_layout) { 'PRESENT' } else { 'ABSENT' }
        completed_target_runtime = if ($TargetLayout.complete_layout) { 'PRESENT_UNVERIFIED' } else { 'ABSENT' }
        broken_active_venv = if ($VenvState.broken) { 'PRESENT' } else { 'ABSENT' }
        mixed_pythoncore_registration = if ($mixedPythonCore) { 'PRESENT' } else { 'ABSENT' }
        same_version_traditional_install_present = $classification
        prevalidation = if (
            $classification -eq 'CONFLICTING_PREEXISTING_RUNTIME' -or
            ($TargetLayout.exists -and -not $TargetLayout.complete_layout) -or
            $mixedPythonCore
        ) { 'FAIL' } elseif ($classification -eq 'EXPECTED_INSTALLED_TARGET_RUNTIME') {
            'TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING'
        } else { 'PASS' }
    }
}

function Get-TradingLabPythonInventory {
    $uninstallEntries = @(Get-TradingLabPythonUninstallEntries)
    $msiProducts = @(Get-TradingLabPythonMsiProducts)
    $pythonCore = @(Get-TradingLabPythonCoreRegistrations)
    $managerEntry = $uninstallEntries | Where-Object { $_.kind -eq 'PYTHON_MANAGER_RUNTIME' } | Select-Object -First 1
    $managerPython = if ($managerEntry -and $managerEntry.install_location) {
        Join-Path $managerEntry.install_location 'python.exe'
    } else { $null }
    $managerProbe = if ($managerPython) {
        Invoke-TradingLabPythonMetadata $managerPython
    } else {
        [pscustomobject]@{ attempted = $false; functional = $false; error = 'MANAGER_RUNTIME_NOT_REGISTERED'; metadata = $null }
    }
    $targetLayout = Get-TradingLabPythonLayout $script:TradingLabPythonTarget
    $targetProbe = if ($targetLayout.complete_layout) {
        Invoke-TradingLabPythonMetadata (Join-Path $script:TradingLabPythonTarget 'python.exe')
    } else {
        [pscustomobject]@{ attempted = $false; functional = $false; error = 'TARGET_LAYOUT_INCOMPLETE'; metadata = $null }
    }
    $venvState = Get-TradingLabVenvState (Join-Path $script:TradingLabWorkspace '.venv')
    $state = Resolve-TradingLabPythonInventoryState `
        $uninstallEntries $msiProducts $pythonCore $managerProbe $targetLayout $venvState
    return [ordered]@{
        schema_version = 1
        collected_at_utc = [DateTime]::UtcNow.ToString('o')
        python_version = $script:TradingLabPythonVersion
        python_manager = [ordered]@{
            executable = $managerPython
            probe = $managerProbe
        }
        python_core = $pythonCore
        uninstall_entries = $uninstallEntries
        msi_products = $msiProducts
        target_layout = $targetLayout
        target_probe = $targetProbe
        active_venv = $venvState
        state = $state
        boundaries = [ordered]@{
            registry_modified = $false
            installer_executed = $false
            python_uninstalled = $false
            mt5_accessed = $false
            gateway_started = $false
            automaton_started = $false
        }
    }
}
