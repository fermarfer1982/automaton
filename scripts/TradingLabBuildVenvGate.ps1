Set-StrictMode -Version 2.0

function Test-TradingLabResumeMachineRuntimeReportRecord(
    [object] $Record,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase
) {
    if ($null -eq $Record) { return $false }
    try {
        $gates = Get-TradingLabProperty $Record 'gates'
        $previousHash = [string](Get-TradingLabProperty $Record 'previous_phase_report_sha256')
        return (
            (Get-TradingLabProperty $Record 'schema_version') -eq 3 -and
            (Get-TradingLabProperty $Record 'phase') -eq 'ResumeMachineRuntime' -and
            [bool](Get-TradingLabProperty $Record 'apply_requested') -and
            (Get-TradingLabProperty $Record 'status') -eq 'PASS' -and
            (Get-TradingLabProperty $Record 'trading_mode') -eq 'OBSERVE_ONLY' -and
            (Get-TradingLabProperty $Record 'python_version') -eq $ExpectedVersion -and
            (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $Record 'python_base') $ExpectedPythonBase) -and
            (Get-TradingLabProperty $Record 'current_run_applied_phase') -eq 'MachineRuntimeValidationRecovered' -and
            (Get-TradingLabProperty $Record 'required_previous_phase') -eq 'InstallMachineRuntime' -and
            [bool](Get-TradingLabProperty $Record 'previous_phase_verified') -and
            -not [string]::IsNullOrWhiteSpace([string](Get-TradingLabProperty $Record 'previous_phase_report')) -and
            $previousHash -match '^[0-9a-f]{64}$' -and
            (Get-TradingLabProperty $gates 'PYTHON_RUNTIME_ACL') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_VERSION_EXACT') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_ARCH_X64') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_BASE_PREFIX_TARGET') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'PYTHON_EXECUTABLE_TARGET') -eq 'PASS' -and
            (Get-TradingLabProperty $gates 'EXPECTED_MACHINE_MSI_COMPONENTS') -eq 4 -and
            (Get-TradingLabProperty $gates 'UNEXPECTED_MACHINE_MSI_COMPONENTS') -eq 0 -and
            -not [bool](Get-TradingLabProperty $Record 'installer_executed') -and
            -not [bool](Get-TradingLabProperty $Record 'installer_reexecuted') -and
            [bool](Get-TradingLabProperty $Record 'must_not_call_set_acl') -and
            (Get-TradingLabProperty $Record 'set_acl_call_count') -eq 0 -and
            -not [bool](Get-TradingLabProperty $Record 'machine_runtime_acl_modified') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_rebuilt') -and
            -not [bool](Get-TradingLabProperty $Record 'venv_promoted') -and
            -not [bool](Get-TradingLabProperty $Record 'mt5_accessed') -and
            -not [bool](Get-TradingLabProperty $Record 'gateway_started') -and
            -not [bool](Get-TradingLabProperty $Record 'automaton_started') -and
            $null -eq (Get-TradingLabProperty $Record 'error')
        )
    } catch { return $false }
}

function Find-TradingLabResumeMachineRuntimeReport(
    [string] $Directory,
    [string] $ExpectedVersion,
    [string] $ExpectedPythonBase
) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: report directory is absent.'
    }
    $valid = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in @(Get-ChildItem -LiteralPath $Directory -File -Filter 'python-runtime-*.json')) {
        try {
            $record = [System.IO.File]::ReadAllText(
                $candidate.FullName, [System.Text.Encoding]::UTF8
            ) | ConvertFrom-Json
        } catch {
            throw "PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: corrupt durable report: $($candidate.Name)"
        }
        if (Test-TradingLabResumeMachineRuntimeReportRecord $record $ExpectedVersion $ExpectedPythonBase) {
            $valid.Add([pscustomobject]@{ path = $candidate.FullName; record = $record })
        }
    }
    if ($valid.Count -eq 0) {
        throw 'PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: no valid durable applied PASS report exists.'
    }
    if ($valid.Count -ne 1) {
        throw "PREVIOUS_PHASE_RESUME_MACHINE_RUNTIME=FAIL: ambiguous PASS reports=$($valid.Count)."
    }
    return $valid[0]
}

function Get-TradingLabPythonBaseExpectedTests([string] $Role, [string] $ExpectedSid) {
    $tests = [ordered]@{ IDENTITY = @($ExpectedSid, $ExpectedSid) }
    if ($Role -eq 'AutomatonGateway') {
        $tests.MACHINE_PYTHON_READ = @('ALLOW', 'ALLOW')
        $tests.MACHINE_PYTHON_ENUMERATE = @('PASS', 'PASS')
        $tests.MACHINE_PYTHON_EXECUTE = @('PASS', 'PASS')
        foreach ($name in @(
            'MACHINE_PYTHON_CREATE_FILE_DENY', 'MACHINE_PYTHON_CREATE_DIRECTORY_DENY',
            'MACHINE_PYTHON_WRITE_DENY', 'MACHINE_PYTHON_APPEND_DENY',
            'MACHINE_PYTHON_TRUNCATE_DENY', 'MACHINE_PYTHON_RENAME_DENY',
            'MACHINE_PYTHON_DELETE_DENY', 'MACHINE_PYTHON_WRITE_ATTRIBUTES_DENY',
            'MACHINE_PYTHON_CHANGE_ACL_DENY', 'MACHINE_PYTHON_TAKE_OWNERSHIP_DENY'
        )) { $tests[$name] = @('DENY', 'DENY') }
        $tests.MACHINE_PYTHON_CREATE_DENY = @('PASS', 'PASS')
    } else {
        foreach ($name in @(
            'DIRECTORY_ENUMERATION_DENY', 'PYTHON_EXE_READ_DENY', 'PYTHON_DLL_READ_DENY',
            'STDLIB_READ_DENY', 'PYTHON_EXECUTE_DENY', 'CREATE_FILE_DENY',
            'CREATE_DIRECTORY_DENY', 'WRITE_DENY', 'DELETE_DENY',
            'CHANGE_ACL_DENY', 'TAKE_OWNERSHIP_DENY'
        )) { $tests[$name] = @('DENY', 'DENY') }
        $tests.CREATE_DENY = @('PASS', 'PASS')
    }
    return $tests
}

function Test-TradingLabPythonBaseRuntimeEvidenceRecord(
    [object] $Record,
    [string] $Role,
    [string] $ExpectedRunId,
    [string] $ExpectedSid
) {
    if ($null -eq $Record) { return $false }
    try {
        if (
            (Get-TradingLabProperty $Record 'schema_version') -ne 1 -or
            (Get-TradingLabProperty $Record 'mode') -ne 'PYTHON_BASE_ONLY' -or
            (Get-TradingLabProperty $Record 'role') -ne $Role -or
            (Get-TradingLabProperty $Record 'status') -ne 'PASS' -or
            (Get-TradingLabProperty $Record 'run_id') -ne $ExpectedRunId -or
            (Get-TradingLabProperty $Record 'effective_sid') -ne $ExpectedSid -or
            $null -ne (Get-TradingLabProperty $Record 'runtime_error')
        ) { return $false }
        $boundaries = Get-TradingLabProperty $Record 'boundaries'
        if ((Get-TradingLabProperty $boundaries 'trading_mode') -ne 'OBSERVE_ONLY') { return $false }
        foreach ($name in @(
            'build_venv', 'mt5_accessed', 'order_check_called', 'order_send_called',
            'gateway_started', 'automaton_started', 'venv_accessed', 'venv_new_accessed',
            'acl_modified', 'filesystem_runtime_modified'
        )) {
            if ((Get-TradingLabProperty $boundaries $name) -ne $false) { return $false }
        }
        $actualTests = Get-TradingLabProperty $Record 'tests'
        $expectedTests = Get-TradingLabPythonBaseExpectedTests $Role $ExpectedSid
        if (@($actualTests.PSObject.Properties).Count -ne $expectedTests.Count) { return $false }
        foreach ($entry in $expectedTests.GetEnumerator()) {
            $test = Get-TradingLabProperty $actualTests $entry.Key
            if (
                $null -eq $test -or -not [bool](Get-TradingLabProperty $test 'passed') -or
                (Get-TradingLabProperty $test 'expected') -ne $entry.Value[0] -or
                (Get-TradingLabProperty $test 'observed') -ne $entry.Value[1]
            ) { return $false }
        }
        return $true
    } catch { return $false }
}

function Read-TradingLabPythonBaseRuntimeEvidenceFile(
    [string] $Path,
    [string] $Role,
    [string] $ExpectedRunId,
    [string] $ExpectedSid
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL: exact report is absent.'
    }
    try {
        $record = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
    } catch {
        throw 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL: report JSON is invalid.'
    }
    if (-not (Test-TradingLabPythonBaseRuntimeEvidenceRecord `
        $record $Role $ExpectedRunId $ExpectedSid
    )) { throw 'PYTHON_BASE_RUNTIME_EVIDENCE=FAIL: report content is not exact PASS evidence.' }
    return $record
}

function Resolve-TradingLabBuildVenvPlanState(
    [object] $Plan,
    [string] $ExpectedBasePython,
    [string] $ExpectedStaging,
    [string] $ExpectedLock,
    [string] $ExpectedWheelhouse,
    [string] $ActiveVenv
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    try {
        $steps = @((Get-TradingLabProperty $Plan 'steps'))
        if ((Get-TradingLabProperty $Plan 'operation') -ne 'BUILD_STAGING_VENV_OFFLINE_HASH_LOCKED') { $failures.Add('OPERATION') }
        if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $Plan 'base_python') $ExpectedBasePython)) { $failures.Add('BASE_PYTHON') }
        if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $Plan 'staging_venv') $ExpectedStaging)) { $failures.Add('STAGING') }
        if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $Plan 'lock_file') $ExpectedLock)) { $failures.Add('LOCK') }
        if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $Plan 'wheelhouse') $ExpectedWheelhouse)) { $failures.Add('WHEELHOUSE') }
        if ($steps.Count -ne 2) { $failures.Add('STEP_COUNT') } else {
            $create = $steps[0]; $install = $steps[1]
            if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $create 'executable') $ExpectedBasePython)) { $failures.Add('CREATE_EXECUTABLE') }
            $actualCreateArguments = (@((Get-TradingLabProperty $create 'arguments')) -join "`n")
            $expectedCreateArguments = (@('-B','-I','-m','venv',$ExpectedStaging) -join "`n")
            if ($actualCreateArguments -ne $expectedCreateArguments) { $failures.Add('CREATE_ARGUMENTS') }
            $stagingPython = Join-Path $ExpectedStaging 'Scripts\python.exe'
            if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $install 'executable') $stagingPython)) { $failures.Add('PIP_EXECUTABLE') }
            $arguments = @((Get-TradingLabProperty $install 'arguments'))
            foreach ($required in @('-B','-I','-m','pip','install','--disable-pip-version-check','--no-input','--no-index','--find-links',$ExpectedWheelhouse,'--require-hashes','--only-binary=:all:','-r',$ExpectedLock)) {
                if ($required -notin $arguments) { $failures.Add("PIP_ARGUMENT:$required") }
            }
            if ($arguments -contains '--user') { $failures.Add('PIP_USER') }
            if (@($arguments | Where-Object { [string]$_ -match '(?i)https?://' }).Count -ne 0) { $failures.Add('NETWORK_URL') }
            foreach ($step in $steps) {
                if ([bool](Get-TradingLabProperty $step 'use_shell')) { $failures.Add('SHELL') }
                if (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $step 'executable') (Join-Path $ActiveVenv 'Scripts\python.exe')) { $failures.Add('ACTIVE_VENV_EXECUTABLE') }
                $environment = Get-TradingLabProperty $step 'environment'
                foreach ($pair in @{
                    PIP_CONFIG_FILE='NUL'; PIP_NO_INDEX='1'; PIP_DISABLE_PIP_VERSION_CHECK='1';
                    PIP_NO_CACHE_DIR='1';
                    PYTHONNOUSERSITE='1'; PYTHONDONTWRITEBYTECODE='1'
                }.GetEnumerator()) {
                    if ((Get-TradingLabProperty $environment $pair.Key) -ne $pair.Value) { $failures.Add("ENVIRONMENT:$($pair.Key)") }
                }
                $tempPath = Get-TradingLabProperty $Plan 'temp_path'
                if (-not (Test-TradingLabInventoryPathWithin $tempPath 'C:\ProgramData\AutomatonMT5Lab\maintenance')) { $failures.Add('TEMP_CONFINEMENT') }
                if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $environment 'TEMP') $tempPath)) { $failures.Add('TEMP') }
                if (-not (Test-TradingLabInventoryExactPath (Get-TradingLabProperty $environment 'TMP') $tempPath)) { $failures.Add('TMP') }
            }
        }
    } catch { $failures.Add('PLAN_PARSE') }
    return [pscustomobject]@{ valid = $failures.Count -eq 0; failures = @($failures) }
}

function Resolve-TradingLabStagingDistributionState(
    [object[]] $LockedRequirements,
    [object[]] $InstalledDistributions,
    [string[]] $BootstrapAllowlist
) {
    $expected = @{}
    foreach ($requirement in $LockedRequirements) {
        $key = ConvertTo-TradingLabNormalizedDistributionName ([string]$requirement.name)
        $expected[$key] = ([string]$requirement.version).ToLowerInvariant()
    }
    $actual = @{}
    $duplicates = [System.Collections.Generic.List[string]]::new()
    foreach ($distribution in $InstalledDistributions) {
        $key = ConvertTo-TradingLabNormalizedDistributionName ([string]$distribution.name)
        if ($actual.ContainsKey($key)) { $duplicates.Add($key) }
        $actual[$key] = ([string]$distribution.version).ToLowerInvariant()
    }
    $missing = [System.Collections.Generic.List[string]]::new()
    $mismatches = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $expected.Keys) {
        if (-not $actual.ContainsKey($key)) { $missing.Add($key) }
        elseif ($actual[$key] -ne $expected[$key]) { $mismatches.Add("$key==$($actual[$key])") }
    }
    $allowedExtra = @($BootstrapAllowlist | ForEach-Object { ConvertTo-TradingLabNormalizedDistributionName $_ })
    $unexpected = @($actual.Keys | Where-Object { -not $expected.ContainsKey($_) -and $_ -notin $allowedExtra } | Sort-Object)
    return [pscustomobject]@{
        expected_requirements = $expected.Count
        installed_distributions = $actual.Count
        missing_requirements = @($missing)
        version_mismatches = @($mismatches)
        duplicate_distributions = @($duplicates)
        unexpected_distributions = @($unexpected)
        metatrader5_metadata = $actual.ContainsKey('metatrader5') -and $actual.metatrader5 -eq '5.0.6090'
        valid = $missing.Count -eq 0 -and $mismatches.Count -eq 0 -and
            $duplicates.Count -eq 0 -and $unexpected.Count -eq 0 -and
            $expected.Count -eq 27
    }
}
