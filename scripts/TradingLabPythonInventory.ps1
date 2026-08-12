Set-StrictMode -Version 2.0

$script:TradingLabPythonVersion = '3.14.5'
$script:TradingLabPythonDisplayVersion = '3.14.5150.0'
$script:TradingLabPythonTarget = 'C:\Program Files\AutomatonPython\3.14.5'
$script:TradingLabWorkspace = 'C:\automaton'

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

function Invoke-TradingLabPythonMetadata([string] $Python) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        return [pscustomobject]@{ attempted = $false; functional = $false; error = 'PYTHON_NOT_FOUND'; metadata = $null }
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Python
    $metadataSource = "import json,platform,sys,venv;print(json.dumps({'architecture':platform.architecture()[0],'base_prefix':sys.base_prefix,'executable':sys.executable,'prefix':sys.prefix,'venv_import':True,'version':platform.python_version()},sort_keys=True,separators=(',',':')))"
    $startInfo.Arguments = '-I -c "' + $metadataSource + '"'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            return [pscustomobject]@{ attempted = $true; functional = $false; error = 'PROCESS_START_FALSE'; metadata = $null }
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            return [pscustomobject]@{
                attempted = $true
                functional = $false
                error = "PYTHON_EXIT_$($process.ExitCode):$($stderr.Trim())"
                metadata = $null
            }
        }
        try {
            $metadata = $stdout.Trim() | ConvertFrom-Json
            return [pscustomobject]@{ attempted = $true; functional = $true; error = $null; metadata = $metadata }
        } catch {
            return [pscustomobject]@{ attempted = $true; functional = $false; error = 'INVALID_METADATA_JSON'; metadata = $null }
        }
    } finally {
        $process.Dispose()
    }
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
    $traditionalUser = @($traditionalBundles | Where-Object { $_.scope -eq 'HKCU' })
    $traditionalMachine = @($traditionalBundles | Where-Object { $_.scope -in @('HKLM','HKLM32') })
    $traditionalComponents = @($UninstallEntries | Where-Object { $_.kind -eq 'TRADITIONAL_MSI_COMPONENT' })
    $sameVersionTraditional = $traditionalBundles.Count -gt 0 -or
        $traditionalComponents.Count -gt 0 -or $MsiProducts.Count -gt 0
    $mixedPythonCore = @($PythonCoreRegistrations | Where-Object {
        $_.managed_by_python_manager -and $_.executable_path -and
        $_.executable_path -like "$script:TradingLabPythonTarget*"
    }).Count -gt 0
    return [pscustomobject]@{
        python_manager_runtime = if ($managerEntries.Count -gt 0 -and $ManagerProbe.functional) { 'FUNCTIONAL' } elseif ($managerEntries.Count -gt 0) { 'REGISTERED_BUT_BROKEN' } else { 'ABSENT' }
        traditional_user_runtime = if ($traditionalUser.Count -gt 0) { 'PRESENT' } else { 'ABSENT' }
        traditional_machine_runtime = if ($traditionalMachine.Count -gt 0) { 'PRESENT' } else { 'ABSENT' }
        traditional_msi_components = $MsiProducts.Count
        python_manager_runtime_path = if ($ManagerProbe.functional) { $ManagerProbe.metadata.base_prefix } else { $null }
        partial_target_runtime = if ($TargetLayout.exists -and -not $TargetLayout.complete_layout) { 'PRESENT' } else { 'ABSENT' }
        completed_target_runtime = if ($TargetLayout.complete_layout) { 'PRESENT_UNVERIFIED' } else { 'ABSENT' }
        broken_active_venv = if ($VenvState.broken) { 'PRESENT' } else { 'ABSENT' }
        mixed_pythoncore_registration = if ($mixedPythonCore) { 'PRESENT' } else { 'ABSENT' }
        same_version_traditional_install_present = if ($sameVersionTraditional) { 'FAIL' } else { 'PASS' }
        prevalidation = if ($sameVersionTraditional -or ($TargetLayout.exists -and -not $TargetLayout.complete_layout)) { 'FAIL' } else { 'PASS' }
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
