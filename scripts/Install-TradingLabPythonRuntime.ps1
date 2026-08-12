#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string] $InstallerPath = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe',
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspace = 'C:\automaton'
$venvPath = Join-Path $workspace '.venv'
$labRoot = 'C:\ProgramData\AutomatonMT5Lab'
$maintenanceRoot = Join-Path $labRoot 'maintenance'
$pythonBase = 'C:\Program Files\AutomatonPython\3.14.5'
$basePython = Join-Path $pythonBase 'python.exe'
$lockPath = Join-Path $workspace 'requirements-gateway-win-py314.lock'
$expectedPythonVersion = '3.14.5'
$expectedInstallerName = 'python-3.14.5-amd64.exe'
$expectedInstallerLength = 30361968L
$expectedInstallerSha256 = 'f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d'
$expectedLockSha256 = '68d14ddc9d943079e8f791bb8f276ae630f46c8ee8997b2bf2afeabed1e30d99'
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
    schema_version = 1
    run_id = $runId
    apply_requested = [bool]$Apply
    status = 'PREVALIDATING'
    trading_mode = 'OBSERVE_ONLY'
    python_version = $expectedPythonVersion
    python_base = $pythonBase
    venv = $venvPath
    lock_file = $lockPath
    installer = $InstallerPath
    installer_executed = $false
    venv_rebuilt = $false
    old_venv_backup = $null
    mt5_accessed = $false
    automaton_started = $false
    gateway_started = $false
    acl_existing_domains_modified = $false
    gates = [ordered]@{}
    error = $null
}

function Get-CanonicalPath([string] $Path) {
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "Path must be absolute: $Path"
    }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-PathWithin([string] $Path, [string] $Root) {
    $candidate = Get-CanonicalPath $Path
    $canonicalRoot = Get-CanonicalPath $Root
    return $candidate.Equals($canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($canonicalRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-OutsideUserProfiles([string] $Path, [string] $Label) {
    $profilesRoot = Join-Path $env:SystemDrive 'Users'
    if (Test-PathWithin $Path $profilesRoot) {
        throw "$Label must not be located under a Windows user profile."
    }
}

function Assert-NoReparseComponents([string] $Path) {
    $canonical = Get-CanonicalPath $Path
    $current = $canonical
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
    } catch {
        return 'UNRESOLVED:' + [string]$Identity
    }
}

function Get-DirectLocalGroupSids(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
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
        $user.SID.Value -ne $ExpectedSid -or
        -not $user.Enabled -or
        $user.PrincipalSource.ToString() -ne 'Local' -or
        $groups.Count -ne 1 -or
        $groups[0] -ne $usersSid
    ) {
        throw "$Name failed exact SID/enabled/local/Users-only prevalidation."
    }
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
    $protected = @(
        $gatewaySid, $agentSid, $usersSid, $authenticatedUsersSid, $everyoneSid
    )
    Assert-NoReparseComponents $Root
    Assert-NoUntrustedModify $Root $protected
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Runtime tree contains a reparse point: $($item.FullName)"
        }
        Assert-NoUntrustedModify $item.FullName $protected
    }
}

function New-ExactRuntimeSecurity([bool] $Directory, [bool] $IncludeGateway) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner([System.Security.Principal.SecurityIdentifier]::new($administratorsSid))
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($entry in @(
        [pscustomobject]@{ Sid = $systemSid; Rights = $fullControl },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = $fullControl }
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($entry.Sid),
            $entry.Rights,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    if ($IncludeGateway) {
        $gatewayRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($gatewaySid),
            $readExecute,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($gatewayRule)
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
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Runtime tree contains a reparse point: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $ownerSid = Resolve-IdentitySid $acl.Owner
        if ($ownerSid -ne $administratorsSid -or -not $acl.AreAccessRulesProtected) {
            throw "Python runtime owner/inheritance is not exact: $($item.FullName)"
        }
        $rightsBySid = @{}
        foreach ($rule in $acl.Access) {
            $sid = Resolve-IdentitySid $rule.IdentityReference
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or $sid -notin $allowedSids) {
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
        ) {
            throw "Python runtime ACL is incomplete or grants Gateway write rights: $($item.FullName)"
        }
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
    if ($hash -ne $expectedInstallerSha256) {
        throw "Python installer SHA-256 mismatch: $hash"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $canonical
    if (
        $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Python Software Foundation(,|$)'
    ) {
        throw 'Python installer Authenticode signature is not valid for Python Software Foundation.'
    }
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
    if ($hash -ne $expectedLockSha256) {
        throw "Gateway dependency lock SHA-256 mismatch: $hash"
    }
    $text = [System.IO.File]::ReadAllText($lockPath, [System.Text.Encoding]::UTF8)
    foreach ($required in @(
        '--only-binary=:all:', '--require-hashes',
        'MetaTrader5==5.0.6090 --hash=sha256:',
        'numpy==2.5.2 --hash=sha256:',
        'fastapi==0.141.1 --hash=sha256:',
        'uvicorn==0.52.1 --hash=sha256:',
        'pydantic==2.13.4 --hash=sha256:',
        'pytest==9.1.1 --hash=sha256:'
    )) {
        if (-not $text.Contains($required)) {
            throw "Gateway dependency lock lacks required invariant: $required"
        }
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
import platform
import sys
print(json.dumps({
    "architecture": platform.architecture()[0],
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "prefix": sys.prefix,
    "version": platform.python_version(),
}, sort_keys=True, separators=(",", ":")))
'@
}

function Assert-BasePython([string] $Python) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Machine-wide Python executable is absent: $Python"
    }
    Assert-NoReparseComponents $Python
    $metadata = Get-PythonMetadata $Python
    if (
        $metadata.version -ne $expectedPythonVersion -or
        $metadata.architecture -ne '64bit' -or
        (Get-CanonicalPath $metadata.executable) -ne (Get-CanonicalPath $Python) -or
        (Get-CanonicalPath $metadata.base_prefix) -ne (Get-CanonicalPath $pythonBase) -or
        (Get-CanonicalPath $metadata.prefix) -ne (Get-CanonicalPath $pythonBase)
    ) {
        throw 'Machine-wide Python metadata does not match CPython 3.14.5 x64 and the exact managed target.'
    }
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
    return @(
        Get-Content -LiteralPath $lockPath | Where-Object { $_ -match '^[A-Za-z0-9_.-]+==' } | ForEach-Object {
            ConvertTo-NormalizedRequirement (($_ -split '\s+--hash=')[0])
        } | Sort-Object -Unique
    )
}

function Assert-VenvPackages([string] $Python) {
    & $Python -I -m pip check | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'pip check failed in rebuilt venv.' }
    $actual = @(& $Python -I -m pip freeze --disable-pip-version-check)
    if ($LASTEXITCODE -ne 0) { throw 'pip freeze failed in rebuilt venv.' }
    $actual = @($actual | ForEach-Object { ConvertTo-NormalizedRequirement $_ } | Sort-Object -Unique)
    $expected = @(Get-LockedRequirements)
    $difference = @(Compare-Object $expected $actual)
    if ($difference.Count -ne 0) {
        throw 'Rebuilt venv package inventory differs from the reviewed hash lock.'
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
        $metadata.version -ne $expectedPythonVersion -or
        $metadata.architecture -ne '64bit' -or
        (Get-CanonicalPath $metadata.executable) -ne (Get-CanonicalPath $python) -or
        (Get-CanonicalPath $metadata.prefix) -ne (Get-CanonicalPath $Root) -or
        (Get-CanonicalPath $metadata.base_prefix) -ne (Get-CanonicalPath $pythonBase)
    ) {
        throw 'Venv does not redirect to the exact machine-wide Python base.'
    }
    Assert-OutsideUserProfiles $metadata.base_prefix 'Venv Python base'
    $cfg = [System.IO.File]::ReadAllText((Join-Path $Root 'pyvenv.cfg'), [System.Text.Encoding]::UTF8)
    $profilesRoot = [regex]::Escape((Get-CanonicalPath (Join-Path $env:SystemDrive 'Users')))
    if ($cfg -match "(?i)$profilesRoot\\" -or $cfg -notmatch [regex]::Escape($pythonBase)) {
        throw 'pyvenv.cfg references a user profile or omits the managed machine-wide base.'
    }
    Assert-VenvPackages $python
    Assert-TreeNotModifiableByServices $Root
    return $metadata
}

function Write-Report {
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) { return }
    $json = $report | ConvertTo-Json -Depth 8
    $stream = [System.IO.File]::Open(
        $reportPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Python runtime gate requires an elevated Administrator token.'
    }
    if ((Get-CanonicalPath $workspace) -ne 'C:\automaton') { throw 'Unexpected workspace path.' }
    if ((Get-CanonicalPath $pythonBase) -ne 'C:\Program Files\AutomatonPython\3.14.5') {
        throw 'Unexpected machine-wide Python target.'
    }
    Assert-OutsideUserProfiles $pythonBase 'Machine-wide Python target'
    Assert-OutsideUserProfiles $venvPath 'Venv path'
    Assert-OutsideUserProfiles $InstallerPath 'Python installer'
    Assert-ExactServiceIdentity 'AutomatonAgent' $agentSid
    Assert-ExactServiceIdentity 'AutomatonGateway' $gatewaySid
    Assert-DependencyLock
    $report.gates.DECLARATIVE_HASH_LOCK = 'PASS'
    $runningLab = @(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match 'trading_lab\.service|dist[\\/]index\.js.*--run'
    })
    if ($runningLab.Count -ne 0) {
        throw 'A Gateway or Automaton production process is running.'
    }
    $configPath = Join-Path $labRoot 'control\trading.yaml'
    $configText = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
    if ($configText -notmatch '(?m)^\s*trading_mode\s*:\s*OBSERVE_ONLY\s*$') {
        throw 'Protected trading config is not OBSERVE_ONLY.'
    }

    $baseExists = Test-Path -LiteralPath $basePython -PathType Leaf
    if ($baseExists) {
        [void](Assert-BasePython $basePython)
    } else {
        $InstallerPath = Assert-Installer $InstallerPath
        $report.installer = $InstallerPath
        $report.gates.PYTHON_INSTALLER_VERIFIED = 'PASS'
    }
    $report.status = if ($Apply) { 'PREVALIDATED' } else { 'DRY_RUN_PASS' }
    if (-not $Apply) {
        $report | ConvertTo-Json -Depth 8
        Write-Output 'PYTHON_RUNTIME_PREVALIDATION=PASS'
        Write-Output 'PYTHON_RUNTIME_APPLY=NOT_RUN'
        exit 0
    }

    if ((git -C $workspace status --porcelain=v1 | Out-String).Trim()) {
        throw 'Worktree must be clean before rebuilding the managed venv.'
    }
    if (-not (Test-Path -LiteralPath $maintenanceRoot -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($maintenanceRoot)
    }
    Protect-ExactRuntimeTree $maintenanceRoot $false
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($reportDirectory)
    }

    if (-not $baseExists) {
        $InstallerPath = Assert-Installer $InstallerPath
        $installerArguments = @(
            '/quiet',
            'InstallAllUsers=1',
            ('TargetDir="' + $pythonBase + '"'),
            'AssociateFiles=0', 'PrependPath=0', 'AppendPath=0', 'Shortcuts=0',
            'Include_doc=0', 'Include_debug=0', 'Include_dev=0', 'Include_exe=1',
            'Include_launcher=0', 'InstallLauncherAllUsers=0', 'Include_lib=1',
            'Include_pip=1', 'Include_symbols=0', 'Include_tcltk=0',
            'Include_test=0', 'Include_tools=0', 'CompileAll=0'
        )
        $install = Start-Process -FilePath $InstallerPath -ArgumentList $installerArguments `
            -Wait -PassThru -NoNewWindow
        $report.installer_executed = $true
        if ($install.ExitCode -ne 0) {
            throw "Verified Python installer failed with exit code $($install.ExitCode)."
        }
    }
    [void](Assert-BasePython $basePython)
    Protect-ExactRuntimeTree $pythonBase $true
    Assert-ExactBaseAcl $pythonBase
    Assert-TreeNotModifiableByServices $pythonBase
    $report.gates.PYTHON_BASE_MACHINE_WIDE = 'PASS'
    $report.gates.PYTHON_BASE_OUTSIDE_USER_PROFILE = 'PASS'
    $report.gates.PYTHON_GATEWAY_EXECUTE_ACL = 'PASS'
    $report.gates.PYTHON_GATEWAY_MODIFY_DENY_ACL = 'PASS'

    $venvCurrent = $false
    if (Test-Path -LiteralPath $venvPath -PathType Container) {
        try {
            [void](Assert-Venv $venvPath)
            $venvCurrent = $true
        } catch {
            $venvCurrent = $false
        }
    }
    if (-not $venvCurrent) {
        $stagingPath = Join-Path $workspace ".venv-machine-wide-staging-$runId"
        $backupPath = Join-Path $maintenanceRoot "venv-admin-base-backup-$runId"
        if ((Test-Path -LiteralPath $stagingPath) -or (Test-Path -LiteralPath $backupPath)) {
            throw 'Run-scoped venv staging/backup path already exists.'
        }
        try {
            & $basePython -I -m venv $stagingPath
            if ($LASTEXITCODE -ne 0) { throw 'Machine-wide Python failed to create the staging venv.' }
            $stagingPython = Join-Path $stagingPath 'Scripts\python.exe'
            & $stagingPython -I -m pip install --disable-pip-version-check --no-input `
                --no-cache-dir --only-binary=:all: --require-hashes -r $lockPath
            if ($LASTEXITCODE -ne 0) { throw 'Hash-locked dependency installation failed.' }
            [void](Assert-Venv $stagingPath)

            $oldMoved = $false
            if (Test-Path -LiteralPath $venvPath -PathType Container) {
                Move-Item -LiteralPath $venvPath -Destination $backupPath
                $oldMoved = $true
            }
            try {
                Move-Item -LiteralPath $stagingPath -Destination $venvPath
                [void](Assert-Venv $venvPath)
            } catch {
                if (Test-Path -LiteralPath $venvPath) {
                    $failedPath = Join-Path $maintenanceRoot "venv-failed-$runId"
                    Move-Item -LiteralPath $venvPath -Destination $failedPath
                    Protect-ExactRuntimeTree $failedPath $false
                }
                if ($oldMoved -and -not (Test-Path -LiteralPath $venvPath)) {
                    Move-Item -LiteralPath $backupPath -Destination $venvPath
                }
                throw
            }
            if ($oldMoved) {
                Protect-ExactRuntimeTree $backupPath $false
                $report.old_venv_backup = $backupPath
            }
            $report.venv_rebuilt = $true
        } finally {
            if (Test-Path -LiteralPath $stagingPath) {
                Assert-NoReparseComponents $stagingPath
                [System.IO.Directory]::Delete($stagingPath, $true)
            }
        }
    }

    [void](Assert-Venv $venvPath)
    $report.gates.VENV_BASE_OUTSIDE_USER_PROFILE = 'PASS'
    $report.gates.VENV_HASH_LOCK_EXACT = 'PASS'
    $report.gates.VENV_SERVICE_IDENTITIES_MODIFY_DENY = 'PASS'
    $report.gates.GATEWAY_TEMP_OPERATIONAL_ONLY = 'PENDING_RUNTIME_IDENTITY_TEST'
    $report.status = 'PASS'
    Write-Report
    foreach ($gate in $report.gates.GetEnumerator()) {
        Write-Output "$($gate.Key)=$($gate.Value)"
    }
    Write-Output "PYTHON_RUNTIME_GATE_REPORT=$reportPath"
} catch {
    $report.status = 'FAIL'
    $report.error = $_.Exception.Message
    if ($Apply) { Write-Report }
    throw
}
