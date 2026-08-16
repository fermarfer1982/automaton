Set-StrictMode -Version 2.0

function Get-TradingLabPromoteProperty([object] $Record, [string] $Name) {
    if ($null -eq $Record) { return $null }
    if ($Record -is [System.Collections.IDictionary]) {
        if ($Record.Contains($Name)) { return $Record[$Name] }
        return $null
    }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-TradingLabPromoteExactPath([string] $Path, [string] $Expected) {
    try {
        return [System.IO.Path]::GetFullPath($Path).TrimEnd('\').Equals(
            [System.IO.Path]::GetFullPath($Expected).TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    } catch { return $false }
}

function Test-TradingLabBuildVenvEvidenceRecord(
    [object] $Record,
    [string] $ExpectedRunId,
    [string] $ExpectedPythonBase,
    [string] $ExpectedActive,
    [string] $ExpectedStaging,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedLock
) {
    try {
        $normalized = ([guid]::ParseExact($ExpectedRunId, 'D')).ToString('D').ToLowerInvariant()
        $boundariesPass = -not [bool](Get-TradingLabPromoteProperty $Record 'active_venv_modified') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'active_venv_deleted') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'active_venv_renamed') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'active_venv_executed') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'installer_executed') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'installer_reexecuted') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'mt5_imported') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'mt5_accessed') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'order_check_called') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'order_send_called') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'gateway_started') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'automaton_started') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'acl_modified') -and
            [int](Get-TradingLabPromoteProperty $Record 'set_acl_call_count') -eq 0
        return [int](Get-TradingLabPromoteProperty $Record 'schema_version') -ge 3 -and
            (Get-TradingLabPromoteProperty $Record 'run_id') -eq $normalized -and
            (Get-TradingLabPromoteProperty $Record 'phase') -eq 'BuildVenv' -and
            (Get-TradingLabPromoteProperty $Record 'status') -eq 'PASS' -and
            [bool](Get-TradingLabPromoteProperty $Record 'apply_requested') -and
            (Get-TradingLabPromoteProperty $Record 'current_run_applied_phase') -eq 'BuildVenv' -and
            (Get-TradingLabPromoteProperty $Record 'trading_mode') -eq 'OBSERVE_ONLY' -and
            [bool](Get-TradingLabPromoteProperty $Record 'staging_venv_created') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'staging_build_failed') -and
            [bool](Get-TradingLabPromoteProperty $Record 'venv_rebuilt') -and
            -not [bool](Get-TradingLabPromoteProperty $Record 'venv_promoted') -and
            [bool](Get-TradingLabPromoteProperty $Record 'mt5_package_installed') -and
            [bool](Get-TradingLabPromoteProperty $Record 'must_not_call_set_acl') -and
            [bool](Get-TradingLabPromoteProperty $Record 'must_not_execute_installer') -and
            (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Record 'python_base') $ExpectedPythonBase) -and
            (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Record 'active_venv') $ExpectedActive) -and
            (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Record 'staging_venv') $ExpectedStaging) -and
            (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Record 'wheelhouse') $ExpectedWheelhouse) -and
            (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Record 'lock_file') $ExpectedLock) -and
            $boundariesPass
    } catch { return $false }
}

function Get-TradingLabStagingCriticalTests([string] $Role) {
    $common = @(
        'IDENTITY', 'STAGING_PATH_EXACT', 'STAGING_ENUMERATE',
        'STAGING_PYTHON_PATH_EXACT', 'STAGING_BASE_REFERENCE_EXACT',
        'STAGING_PYTHON_READ', 'STAGING_SITE_PACKAGES_READ',
        'STAGING_CREATE_FILE_DENY', 'STAGING_CREATE_DIRECTORY_DENY',
        'STAGING_CREATE_DENY', 'STAGING_WRITE_DENY', 'STAGING_APPEND_DENY',
        'STAGING_TRUNCATE_DENY', 'STAGING_RENAME_DENY', 'STAGING_DELETE_DENY',
        'STAGING_WRITE_ATTRIBUTES_DENY', 'STAGING_CHANGE_ACL_DENY',
        'STAGING_TAKE_OWNERSHIP_DENY'
    )
    if ($Role -eq 'AutomatonGateway') {
        return @($common) + @(
            'STAGING_PYTHON_EXECUTE', 'STAGING_FASTAPI_IMPORT',
            'STAGING_PYDANTIC_IMPORT', 'STAGING_PYYAML_IMPORT',
            'STAGING_UVICORN_IMPORT', 'STAGING_METATRADER5_METADATA',
            'STAGING_METATRADER5_IMPORTED'
        )
    }
    return @($common) + @('STAGING_PYTHON_FUNCTIONAL_EXECUTION_DENY')
}

function Get-TradingLabStagingEvidenceTreeCount([object] $Record) {
    try {
        $tests = Get-TradingLabPromoteProperty $Record 'tests'
        $enumeration = Get-TradingLabPromoteProperty $tests 'STAGING_ENUMERATE'
        $evidence = [string](Get-TradingLabPromoteProperty $enumeration 'evidence')
        if ($evidence -notmatch '^ITEMS_ENUMERATED_([1-9][0-9]*)$') { return -1 }
        return [int]$Matches[1]
    } catch { return -1 }
}

function Test-TradingLabPythonStagingEvidenceRecord(
    [object] $Record,
    [string] $Role,
    [string] $ExpectedRunId,
    [string] $ExpectedSid
) {
    try {
        if ($Role -notin @('AutomatonGateway', 'AutomatonAgent')) { return $false }
        $normalized = ([guid]::ParseExact($ExpectedRunId, 'D')).ToString('D').ToLowerInvariant()
        if (
            [int](Get-TradingLabPromoteProperty $Record 'schema_version') -ne 1 -or
            (Get-TradingLabPromoteProperty $Record 'mode') -ne 'PYTHON_STAGING_ONLY' -or
            (Get-TradingLabPromoteProperty $Record 'role') -ne $Role -or
            (Get-TradingLabPromoteProperty $Record 'run_id') -ne $normalized -or
            (Get-TradingLabPromoteProperty $Record 'effective_sid') -ne $ExpectedSid -or
            (Get-TradingLabPromoteProperty $Record 'status') -ne 'PASS' -or
            $null -ne (Get-TradingLabPromoteProperty $Record 'runtime_error')
        ) { return $false }
        $tests = Get-TradingLabPromoteProperty $Record 'tests'
        if ((Get-TradingLabStagingEvidenceTreeCount $Record) -le 0) { return $false }
        foreach ($name in Get-TradingLabStagingCriticalTests $Role) {
            $test = Get-TradingLabPromoteProperty $tests $name
            if ($null -eq $test -or -not [bool](Get-TradingLabPromoteProperty $test 'passed')) {
                return $false
            }
            $expected = [string](Get-TradingLabPromoteProperty $test 'expected')
            $observed = [string](Get-TradingLabPromoteProperty $test 'observed')
            if ($name -eq 'IDENTITY') {
                if ($expected -ne $ExpectedSid -or $observed -ne $ExpectedSid) { return $false }
            } elseif ($name -in @('STAGING_PYTHON_READ', 'STAGING_SITE_PACKAGES_READ')) {
                if ($expected -ne 'ALLOW' -or $observed -ne 'ALLOW') { return $false }
            } elseif ($name -in @(
                'STAGING_CREATE_FILE_DENY', 'STAGING_CREATE_DIRECTORY_DENY',
                'STAGING_WRITE_DENY', 'STAGING_APPEND_DENY', 'STAGING_TRUNCATE_DENY',
                'STAGING_RENAME_DENY', 'STAGING_DELETE_DENY',
                'STAGING_WRITE_ATTRIBUTES_DENY', 'STAGING_CHANGE_ACL_DENY',
                'STAGING_TAKE_OWNERSHIP_DENY', 'STAGING_PYTHON_FUNCTIONAL_EXECUTION_DENY'
            )) {
                if ($expected -ne 'DENY' -or $observed -ne 'DENY') { return $false }
            } elseif ($name -eq 'STAGING_METATRADER5_IMPORTED') {
                if ($expected -ne 'false' -or $observed -ne 'false') { return $false }
            } elseif ($expected -ne 'PASS' -or $observed -ne 'PASS') {
                return $false
            }
        }
        $boundaries = Get-TradingLabPromoteProperty $Record 'boundaries'
        if ($null -eq $boundaries -or
            (Get-TradingLabPromoteProperty $boundaries 'trading_mode') -ne 'OBSERVE_ONLY') {
            return $false
        }
        foreach ($name in @(
            'build_venv', 'promote_venv', 'active_venv_accessed',
            'active_venv_modified', 'mt5_imported', 'mt5_accessed',
            'order_check_called', 'order_send_called', 'gateway_started',
            'automaton_started', 'acl_modified', 'filesystem_staging_modified'
        )) {
            if ([bool](Get-TradingLabPromoteProperty $boundaries $name)) { return $false }
        }
        if ($Role -eq 'AutomatonGateway') {
            $execution = Get-TradingLabPromoteProperty $Record 'execution'
            return [bool](Get-TradingLabPromoteProperty $execution 'process_started') -and
                [int](Get-TradingLabPromoteProperty $execution 'exit_code') -eq 0
        }
        $agentExecution = Get-TradingLabPromoteProperty $Record 'execution'
        return -not [bool](Get-TradingLabPromoteProperty $agentExecution 'success_marker_observed') -and
            (Get-TradingLabPromoteProperty $agentExecution 'exit_code') -ne 0
    } catch { return $false }
}

function Resolve-TradingLabPromoteArtifactState(
    [bool] $BackupTargetExists,
    [bool] $FailedTargetExists,
    [int] $ExistingBackupArtifacts,
    [int] $ExistingFailedArtifacts
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    if ($BackupTargetExists) { $failures.Add('BACKUP_PATH_EXISTS') }
    if ($FailedTargetExists) { $failures.Add('FAILED_PATH_EXISTS') }
    if ($ExistingBackupArtifacts -ne 0) { $failures.Add('PREEXISTING_BACKUP_ARTIFACTS') }
    if ($ExistingFailedArtifacts -ne 0) { $failures.Add('PREEXISTING_FAILED_ARTIFACTS') }
    return [pscustomobject]@{ valid = $failures.Count -eq 0; failures = @($failures) }
}

function Test-TradingLabProcessUsesVenv(
    [string] $ExecutablePath,
    [string] $CommandLine,
    [string] $VenvRoot
) {
    $root = [System.IO.Path]::GetFullPath($VenvRoot).TrimEnd('\')
    try {
        if (-not [string]::IsNullOrWhiteSpace($ExecutablePath)) {
            $executable = [System.IO.Path]::GetFullPath($ExecutablePath)
            if ($executable.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    } catch { return $true }
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    return $CommandLine.IndexOf($root + '\', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Resolve-TradingLabPromoteVenvPlanState(
    [object] $Plan,
    [string] $ExpectedBasePython,
    [string] $ExpectedActive,
    [string] $ExpectedStaging,
    [string] $ExpectedBackup,
    [string] $ExpectedFailed,
    [string] $ExpectedLock,
    [string] $ExpectedWheelhouse,
    [string] $ExpectedTemp
) {
    $failures = [System.Collections.Generic.List[string]]::new()
    try {
        if ((Get-TradingLabPromoteProperty $Plan 'promotion_strategy') -ne 'REBUILD_AT_FINAL_PATH_TRANSACTIONALLY') {
            $failures.Add('STRATEGY_NOT_TRANSACTIONAL_REBUILD')
        }
        foreach ($entry in @(
            @('active_venv', $ExpectedActive), @('staging_venv_read_only', $ExpectedStaging),
            @('backup_path', $ExpectedBackup), @('failed_path', $ExpectedFailed),
            @('base_python', $ExpectedBasePython), @('lock_file', $ExpectedLock),
            @('wheelhouse', $ExpectedWheelhouse), @('temp_path', $ExpectedTemp)
        )) {
            if (-not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $Plan $entry[0]) $entry[1])) {
                $failures.Add("PATH_MISMATCH_$($entry[0])")
            }
        }
        if ((Get-TradingLabPromoteProperty $Plan 'staging_action') -ne 'PRESERVE_READ_ONLY') {
            $failures.Add('STAGING_NOT_PRESERVED')
        }
        if ([System.IO.Path]::GetPathRoot($ExpectedActive) -ne [System.IO.Path]::GetPathRoot($ExpectedBackup)) {
            $failures.Add('BACKUP_NOT_SAME_VOLUME')
        }
        $steps = @(Get-TradingLabPromoteProperty $Plan 'steps')
        if ($steps.Count -ne 6) { $failures.Add('STEP_COUNT') }
        if ($steps.Count -eq 6) {
            $expectedPhases = @('BACKUP','CREATE_FINAL','INSTALL_FINAL','VALIDATE_FINAL','NON_RELOCATION','ACL')
            for ($index = 0; $index -lt $expectedPhases.Count; $index++) {
                if ((Get-TradingLabPromoteProperty $steps[$index] 'phase') -ne $expectedPhases[$index]) {
                    $failures.Add("PHASE_$index")
                }
            }
            $backup = $steps[0]
            if ((Get-TradingLabPromoteProperty $backup 'operation') -ne 'RENAME_DIRECTORY_SAME_VOLUME' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $backup 'source') $ExpectedActive) -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $backup 'destination') $ExpectedBackup) -or
                [bool](Get-TradingLabPromoteProperty $backup 'copy') -or
                [bool](Get-TradingLabPromoteProperty $backup 'delete') -or
                [bool](Get-TradingLabPromoteProperty $backup 'call_set_acl')) {
                $failures.Add('BACKUP_STEP')
            }
            $create = $steps[1]
            if (-not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $create 'executable') $ExpectedBasePython) -or
                (Get-TradingLabPromoteProperty $create 'use_shell') -ne $false -or
                (Get-TradingLabPromoteProperty $create 'operation') -ne 'CREATE_VENV_AT_FINAL_PATH' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $create 'target') $ExpectedActive) -or
                (@(Get-TradingLabPromoteProperty $create 'arguments') -join '|') -ne (@('-B','-I','-m','venv',$ExpectedActive) -join '|')) {
                $failures.Add('CREATE_FINAL_STEP')
            }
            $install = $steps[2]
            $expectedFinalPython = Join-Path $ExpectedActive 'Scripts\python.exe'
            $arguments = @(Get-TradingLabPromoteProperty $install 'arguments')
            $expectedArguments = @(
                '-B','-I','-m','pip','install','--disable-pip-version-check','--no-input',
                '--no-index','--find-links',$ExpectedWheelhouse,'--require-hashes',
                '--only-binary=:all:','-r',$ExpectedLock
            )
            if (-not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $install 'executable') $expectedFinalPython) -or
                (Get-TradingLabPromoteProperty $install 'use_shell') -ne $false -or
                (Get-TradingLabPromoteProperty $install 'operation') -ne 'INSTALL_HASH_LOCKED_WHEELS_OFFLINE' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $install 'target') $ExpectedActive) -or
                ($arguments -join '|') -ne ($expectedArguments -join '|')) {
                $failures.Add('INSTALL_FINAL_EXECUTABLE')
            }
            foreach ($required in @('--no-index','--require-hashes','--only-binary=:all:')) {
                if ($required -notin $arguments) { $failures.Add("PIP_MISSING_$required") }
            }
            if ('--user' -in $arguments -or ($arguments -join ' ') -match '(?i)https?://|pypi') {
                $failures.Add('PIP_EXTERNAL_OR_USER')
            }
            $environment = Get-TradingLabPromoteProperty $install 'environment'
            foreach ($pair in @(
                @('PIP_CONFIG_FILE','NUL'), @('PIP_NO_INDEX','1'),
                @('PIP_DISABLE_PIP_VERSION_CHECK','1'), @('PIP_NO_CACHE_DIR','1'),
                @('PYTHONNOUSERSITE','1'), @('PYTHONDONTWRITEBYTECODE','1'),
                @('TEMP',$ExpectedTemp), @('TMP',$ExpectedTemp)
            )) {
                if ((Get-TradingLabPromoteProperty $environment $pair[0]) -ne $pair[1]) {
                    $failures.Add("ENV_$($pair[0])")
                }
            }
            if (@($environment.PSObject.Properties).Count -ne 8) { $failures.Add('ENV_UNEXPECTED') }
            $createEnvironment = Get-TradingLabPromoteProperty $create 'environment'
            if (($createEnvironment | ConvertTo-Json -Compress) -ne ($environment | ConvertTo-Json -Compress)) {
                $failures.Add('CREATE_ENVIRONMENT')
            }
            $validate = $steps[3]
            if ((Get-TradingLabPromoteProperty $validate 'operation') -ne 'VALIDATE_READ_ONLY' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $validate 'executable') $expectedFinalPython) -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $validate 'target') $ExpectedActive) -or
                (@(Get-TradingLabPromoteProperty $validate 'arguments') -join '|') -ne '-B|-I|-' -or
                (Get-TradingLabPromoteProperty $validate 'source_transport') -ne 'STDIN' -or
                (Get-TradingLabPromoteProperty $validate 'metatrader5_validation') -ne 'IMPORTLIB_METADATA_ONLY' -or
                (Get-TradingLabPromoteProperty $validate 'use_shell') -ne $false -or
                (@(Get-TradingLabPromoteProperty $validate 'import_allowlist') -join '|') -ne 'fastapi|pydantic|yaml|uvicorn') {
                $failures.Add('VALIDATE_FINAL_STEP')
            }
            $nonRelocation = $steps[4]
            if ((Get-TradingLabPromoteProperty $nonRelocation 'operation') -ne 'SCAN_FINAL_ASCII_UTF16LE_READ_ONLY' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $nonRelocation 'target') $ExpectedActive) -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $nonRelocation 'forbidden_reference') $ExpectedStaging) -or
                [int](Get-TradingLabPromoteProperty $nonRelocation 'expected_references') -ne 0 -or
                [int](Get-TradingLabPromoteProperty $nonRelocation 'expected_read_errors') -ne 0) {
                $failures.Add('NON_RELOCATION_STEP')
            }
            $acl = $steps[5]
            if ((Get-TradingLabPromoteProperty $acl 'operation') -ne 'VALIDATE_READ_ONLY' -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $acl 'target') $ExpectedActive) -or
                -not (Test-TradingLabPromoteExactPath (Get-TradingLabPromoteProperty $acl 'inherit_from') (Split-Path $ExpectedActive -Parent)) -or
                [bool](Get-TradingLabPromoteProperty $acl 'call_set_acl')) {
                $failures.Add('ACL_STEP')
            }
        }
        $serialized = $Plan | ConvertTo-Json -Depth 12 -Compress
        if ($serialized -match '(?i)Set[-]Acl|Invoke[-]Expression|import\s+MetaTrader5|Start[-]Service|https?://|pypi') {
            $failures.Add('FORBIDDEN_PLAN_ACTION')
        }
        foreach ($step in $steps) {
            foreach ($name in @('source','destination','target')) {
                $value = Get-TradingLabPromoteProperty $step $name
                if ($null -ne $value -and
                    (Test-TradingLabPromoteExactPath ([string]$value) $ExpectedStaging) -and
                    (Get-TradingLabPromoteProperty $step 'operation') -notin @('VALIDATE_READ_ONLY')) {
                    $failures.Add('STAGING_MUTATION_OR_PROMOTION')
                }
            }
        }
    } catch { $failures.Add('PLAN_SCHEMA_ERROR') }
    return [pscustomobject]@{ valid = $failures.Count -eq 0; failures = @($failures) }
}

function Resolve-TradingLabRollbackExpectation(
    [bool] $BackupCompleted,
    [bool] $PartialFinalExists,
    [bool] $MovePartialSucceeded,
    [bool] $RestoreBackupSucceeded
) {
    if (-not $BackupCompleted) {
        return [pscustomobject]@{
            action = 'ACTIVE_UNTOUCHED'; critical = $false; active_restored = $true
            move_partial_to_failed = $false; delete_failed = $false; delete_staging = $false
        }
    }
    if ($PartialFinalExists -and -not $MovePartialSucceeded) {
        return [pscustomobject]@{
            action = 'FAIL_CLOSED_CRITICAL_RECOVERY_REQUIRED'; critical = $true; active_restored = $false
            move_partial_to_failed = $true; delete_failed = $false; delete_staging = $false
        }
    }
    if (-not $RestoreBackupSucceeded) {
        return [pscustomobject]@{
            action = 'FAIL_CLOSED_CRITICAL_RECOVERY_REQUIRED'; critical = $true; active_restored = $false
            move_partial_to_failed = $PartialFinalExists; delete_failed = $false; delete_staging = $false
        }
    }
    return [pscustomobject]@{
        action = 'PROMOTION_FAILED_ROLLED_BACK'; critical = $false; active_restored = $true
        move_partial_to_failed = $PartialFinalExists; delete_failed = $false; delete_staging = $false
    }
}
