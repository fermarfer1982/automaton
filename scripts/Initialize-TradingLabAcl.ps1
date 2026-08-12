[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $GatewayIdentity,
    [Parameter(Mandatory = $true)] [string] $AutomatonIdentity,
    [string] $LabRoot = 'C:\ProgramData\AutomatonMT5Lab',
    [Parameter(Mandatory = $true)] [string] $AutomatonStateDir,
    [string] $WorkspaceRoot = 'C:\automaton',
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'

function Get-CanonicalPath([string] $Value) {
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        throw "All paths must be absolute: $Value"
    }
    return [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Test-PathOverlap([string] $First, [string] $Second) {
    $a = (Get-CanonicalPath $First) + '\'
    $b = (Get-CanonicalPath $Second) + '\'
    return $a.StartsWith($b, [System.StringComparison]::OrdinalIgnoreCase) -or
           $b.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-Sid([string] $Identity) {
    if ($Identity -match '^S-\d(-\d+)+$') {
        return [System.Security.Principal.SecurityIdentifier]::new($Identity)
    }
    return ([System.Security.Principal.NTAccount]::new($Identity)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    )
}

function Test-IsElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

$root = Get-CanonicalPath $LabRoot
$state = Get-CanonicalPath $AutomatonStateDir
$workspace = Get-CanonicalPath $WorkspaceRoot
$control = Join-Path $root 'control'
$configFile = Join-Path $control 'trading.yaml'
$killSwitchFile = Join-Path $control 'STOP_TRADING'
$demoAuthorization = Join-Path $control 'demo-authorization'
$demoAuthorizationFile = Join-Path $demoAuthorization 'authorization.json'
$ipc = Join-Path $root 'ipc'
$apiKeyFile = Join-Path $ipc 'automaton.key'
$operational = Join-Path $root 'operational'
$research = Join-Path $root 'research'
$audit = Join-Path $root 'audit'
$auditSqlite = Join-Path $audit 'sqlite'
$auditJournal = Join-Path $audit 'journal'
$auditJournalFile = Join-Path $auditJournal 'audit.jsonl'
$logs = Join-Path $root 'logs'
$gatewayLogs = Join-Path $logs 'gateway'
$securityLogs = Join-Path $logs 'security'
$securityLogFile = Join-Path $securityLogs 'security.log'
$driveRoot = [System.IO.Path]::GetPathRoot($root).TrimEnd('\')

if ($root -eq $driveRoot -or $root -ieq 'C:\ProgramData' -or $state -ieq 'C:\Users') {
    throw 'Refusing a broad ACL target.'
}
if (Test-PathOverlap $root $workspace -or Test-PathOverlap $state $workspace) {
    throw 'Laboratory ACL targets must remain outside the workspace.'
}
if (Test-PathOverlap $root $state) {
    throw 'Gateway paths and Automaton state must not overlap.'
}

$gatewaySid = Resolve-Sid $GatewayIdentity
$automatonSid = Resolve-Sid $AutomatonIdentity
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$usersGroupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
if ($gatewaySid.Value -eq $automatonSid.Value) {
    throw 'Gateway and Automaton identities must be distinct.'
}
function Get-DirectLocalGroupSids(
    [System.Security.Principal.SecurityIdentifier] $UserSid
) {
    $groupSids = [System.Collections.Generic.List[string]]::new()
    foreach ($group in Get-LocalGroup) {
        $members = @(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
        if ($members | Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $UserSid.Value }) {
            $groupSids.Add($group.SID.Value)
        }
    }
    return @($groupSids)
}

$identityChecks = [System.Collections.Generic.List[object]]::new()
foreach ($runtimeIdentity in @(
    [pscustomobject]@{ Name = 'Gateway'; Sid = $gatewaySid },
    [pscustomobject]@{ Name = 'Automaton'; Sid = $automatonSid }
)) {
    $localUser = Get-LocalUser -SID $runtimeIdentity.Sid -ErrorAction Stop
    if (-not $localUser.Enabled -or $localUser.PrincipalSource.ToString() -ne 'Local') {
        throw "$($runtimeIdentity.Name) identity must be an enabled local user."
    }
    $directGroups = @(Get-DirectLocalGroupSids $runtimeIdentity.Sid)
    if ($directGroups.Count -ne 1 -or $directGroups[0] -ne $usersGroupSid.Value) {
        throw "$($runtimeIdentity.Name) identity must belong directly only to BUILTIN\Users."
    }
    $identityChecks.Add([pscustomobject]@{
        role = $runtimeIdentity.Name
        sid = $runtimeIdentity.Sid.Value
        enabled = $true
        principal_source = 'Local'
        direct_local_group_sids = $directGroups
    })
}
$administratorMembers = @(Get-LocalGroupMember -SID $administratorsSid | ForEach-Object { $_.SID.Value })
if ($administratorMembers -contains $gatewaySid.Value -or $administratorMembers -contains $automatonSid.Value) {
    throw 'Gateway and Automaton identities must be non-administrators.'
}

function New-AclProposal(
    [string] $Path,
    [string] $Domain,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [string[]] $Rights,
    [string] $ChildPropagation,
    [string[]] $RepresentativeTargets
) {
    $entries = [System.Collections.Generic.List[object]]::new()
    $entries.Add([pscustomobject]@{
        principal = 'NT AUTHORITY\SYSTEM'; sid = $systemSid.Value
        rights = 'FullControl'; type = 'Allow'
    })
    $entries.Add([pscustomobject]@{
        principal = 'BUILTIN\Administrators'; sid = $administratorsSid.Value
        rights = 'FullControl'; type = 'Allow'
    })
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $entries.Add([pscustomobject]@{
            principal = $Principals[$index].Value; sid = $Principals[$index].Value
            rights = $Rights[$index]; type = 'Allow'
        })
    }
    return [pscustomobject]@{
        path = $Path
        domain = $Domain
        inheritance_protected = $true
        inherited_aces_preserved = $false
        deny_aces = 0
        child_propagation = $ChildPropagation
        owner = 'BUILTIN\Administrators'
        entries = @($entries)
        representative_targets = $RepresentativeTargets
    }
}

$aclProposals = @(
    New-AclProposal $root 'lab_root_navigation' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ThisObjectOnly' @('control', 'ipc', 'operational', 'research', 'audit', 'logs')
    New-AclProposal $workspace 'source_read_only' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ContainerInherit,ObjectInherit' @(
        'trading_lab', 'src', 'scripts', 'tests', 'config', 'package files',
        'Python source', 'TypeScript source', '.runtime', '.venv'
    )
    New-AclProposal $control 'human_managed_control_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('trading.yaml', 'STOP_TRADING', 'demo-authorization')
    New-AclProposal $configFile 'human_managed_config_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('trading.yaml')
    New-AclProposal $killSwitchFile 'human_kill_switch_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('STOP_TRADING')
    New-AclProposal $demoAuthorization 'human_demo_authorization_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('authorization.json')
    New-AclProposal $demoAuthorizationFile 'human_demo_authorization_file' @($gatewaySid) @(
        'Read'
    ) 'None' @('authorization.json')
    New-AclProposal $ipc 'shared_ipc_directory' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) 'ThisObjectOnly' @('automaton.key')
    New-AclProposal $apiKeyFile 'shared_ipc_key_file' @($gatewaySid, $automatonSid) @(
        'Read', 'Read'
    ) 'None' @('automaton.key')
    New-AclProposal $operational 'gateway_operational_data' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('gateway.lock', 'idempotency', 'lifecycle', 'reconciliation')
    New-AclProposal $research 'gateway_research_data' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('research.db', 'research.db-wal', 'research.db-shm')
    New-AclProposal $audit 'audit_navigation' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('sqlite', 'journal')
    New-AclProposal $auditSqlite 'gateway_audit_sqlite' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('audit.db', 'audit.db-wal', 'audit.db-shm')
    New-AclProposal $auditJournal 'gateway_audit_journal_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('audit.jsonl')
    New-AclProposal $auditJournalFile 'gateway_audit_journal_append_file' @($gatewaySid) @(
        'Read,AppendData,Synchronize'
    ) 'None' @('audit.jsonl; pre-created by Administrator')
    New-AclProposal $logs 'logs_navigation' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('gateway', 'security')
    New-AclProposal $gatewayLogs 'gateway_rotating_logs' @($gatewaySid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @('gateway.log', 'trading.log', 'UTC rotations')
    New-AclProposal $securityLogs 'gateway_security_log_directory' @($gatewaySid) @(
        'ReadAndExecute'
    ) 'ThisObjectOnly' @('security.log')
    New-AclProposal $securityLogFile 'gateway_security_log_append_file' @($gatewaySid) @(
        'Read,AppendData,Synchronize'
    ) 'None' @('security.log; pre-created by Administrator; no automatic rotation')
    New-AclProposal $state 'agent_private_state' @($automatonSid) @(
        'Modify'
    ) 'ContainerInherit,ObjectInherit' @(
        'Automaton context', 'agent memory', 'agent logs', 'last_processed_bar_timestamp'
    )
)

$plan = [pscustomobject]@{
    apply = [bool]$Apply
    gateway_sid = $gatewaySid.Value
    automaton_sid = $automatonSid.Value
    identity_checks = @($identityChecks)
    owner = 'BUILTIN\Administrators'
    inheritance = 'protected; inherited ACEs removed; explicit Allow ACEs only'
    deny_aces_used = $false
    sqlite_immutable = $false
    append_acl_claim = 'risk reduction only; negative runtime tests required after ACL application'
    precreated_by_administrator = @(
        $apiKeyFile, $auditJournalFile, $securityLogFile
    )
    optional_human_asserted_files = @($killSwitchFile, $demoAuthorizationFile)
    acl_proposals = $aclProposals
}
$plan | ConvertTo-Json -Depth 8
if (-not $Apply) {
    Write-Host 'Dry run only. No directory, file, owner, inheritance, or ACE was changed.'
    exit 0
}

if (-not (Test-IsElevated)) {
    throw 'ACL application requires an elevated Administrator console.'
}
if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
    throw 'Human-reviewed control\trading.yaml must exist before any ACL mutation.'
}
if (Test-Path -LiteralPath (Join-Path $state 'wallet.json')) {
    throw 'Refusing to use an Automaton state directory containing a signing wallet.'
}
foreach ($existingRoot in @($root, $state, $workspace)) {
    if (Test-Path -LiteralPath $existingRoot) {
        $rootItem = Get-Item -LiteralPath $existingRoot -Force
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing an ACL root that is a reparse point: $existingRoot"
        }
        if ($existingRoot -ne $workspace) {
            $unsafeReparse = Get-ChildItem -LiteralPath $existingRoot -Force -Recurse |
                Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
                Select-Object -First 1
            if ($null -ne $unsafeReparse) {
                throw "Refusing a protected data tree containing a reparse point: $($unsafeReparse.FullName)"
            }
        }
    }
}

$protectedSourceDirectories = @(
    'trading_lab', 'src', 'scripts', 'tests', 'config', 'docs', 'packages\cli\src'
) | ForEach-Object { Join-Path $workspace $_ }
foreach ($protectedSourceDirectory in $protectedSourceDirectories) {
    if (-not (Test-Path -LiteralPath $protectedSourceDirectory -PathType Container)) {
        throw "Protected source directory is absent: $protectedSourceDirectory"
    }
    $unsafeReparse = Get-ChildItem -LiteralPath $protectedSourceDirectory -Force -Recurse |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
        Select-Object -First 1
    if ($null -ne $unsafeReparse) {
        throw "Protected source tree contains a reparse point: $($unsafeReparse.FullName)"
    }
}

foreach ($directory in @(
    $root, $control, $demoAuthorization, $ipc, $operational, $research,
    $audit, $auditSqlite, $auditJournal, $logs, $gatewayLogs, $securityLogs, $state
)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $apiKeyFile -PathType Leaf)) {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $apiKey = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [System.IO.File]::WriteAllText($apiKeyFile, $apiKey, [System.Text.Encoding]::ASCII)
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
foreach ($appendFile in @($auditJournalFile, $securityLogFile)) {
    if (-not (Test-Path -LiteralPath $appendFile -PathType Leaf)) {
        [System.IO.File]::WriteAllText($appendFile, '', $utf8NoBom)
    }
}

function New-AccessRule(
    [System.Security.Principal.SecurityIdentifier] $Sid,
    [System.Security.AccessControl.FileSystemRights] $Rights,
    [bool] $Directory,
    [bool] $Propagate
) {
    $inheritance = if ($Directory -and $Propagate) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    return [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid, $Rights, $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

function Set-ExactAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights,
    [bool] $Directory,
    [bool] $RuntimeRulesPropagate
) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner($administratorsSid)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule((New-AccessRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory $Directory))
    $security.AddAccessRule((New-AccessRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory $Directory))
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $security.AddAccessRule((New-AccessRule $Principals[$index] $Rights[$index] $Directory $RuntimeRulesPropagate))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Set-ExactTreeAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights
) {
    Set-ExactAcl $Path $Principals $Rights $true $true
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
        Set-ExactAcl $item.FullName $Principals $Rights ([bool]$item.PSIsContainer) ([bool]$item.PSIsContainer)
    }
}

$read = [System.Security.AccessControl.FileSystemRights]::Read
$readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify = [System.Security.AccessControl.FileSystemRights]::Modify
$appendOnly = [System.Security.AccessControl.FileSystemRights](
    [int][System.Security.AccessControl.FileSystemRights]::Read -bor
    [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [int][System.Security.AccessControl.FileSystemRights]::Synchronize
)

Set-ExactAcl $root @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $false
Set-ExactAcl $workspace @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $true
foreach ($protectedSourceDirectory in $protectedSourceDirectories) {
    Set-ExactTreeAcl $protectedSourceDirectory @($gatewaySid, $automatonSid) @($readExecute, $readExecute)
}
foreach ($protectedRootFile in @(
    '.gitignore', 'package.json', 'pnpm-lock.yaml',
    'pnpm-workspace.yaml', 'tsconfig.json', 'vitest.config.ts',
    'requirements-gateway-win-py314.lock', 'requirements-gateway.in',
    'requirements-mt5.txt', 'packages\cli\package.json', 'packages\cli\tsconfig.json'
) | ForEach-Object { Join-Path $workspace $_ }) {
    if (-not (Test-Path -LiteralPath $protectedRootFile -PathType Leaf)) {
        throw "Protected root file is absent: $protectedRootFile"
    }
    Set-ExactAcl $protectedRootFile @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $false $false
}
Set-ExactAcl $control @($gatewaySid) @($readExecute) $true $false
Set-ExactAcl $configFile @($gatewaySid) @($read) $false $false
if (Test-Path -LiteralPath $killSwitchFile -PathType Leaf) {
    Set-ExactAcl $killSwitchFile @($gatewaySid) @($read) $false $false
}
Set-ExactAcl $demoAuthorization @($gatewaySid) @($readExecute) $true $false
if (Test-Path -LiteralPath $demoAuthorizationFile -PathType Leaf) {
    Set-ExactAcl $demoAuthorizationFile @($gatewaySid) @($read) $false $false
}
Set-ExactAcl $ipc @($gatewaySid, $automatonSid) @($readExecute, $readExecute) $true $false
Set-ExactAcl $apiKeyFile @($gatewaySid, $automatonSid) @($read, $read) $false $false
Set-ExactTreeAcl $operational @($gatewaySid) @($modify)
Set-ExactTreeAcl $research @($gatewaySid) @($modify)
Set-ExactAcl $audit @($gatewaySid) @($readExecute) $true $false
Set-ExactTreeAcl $auditSqlite @($gatewaySid) @($modify)
Set-ExactAcl $auditJournal @($gatewaySid) @($readExecute) $true $false
Set-ExactAcl $auditJournalFile @($gatewaySid) @($appendOnly) $false $false
Set-ExactAcl $logs @($gatewaySid) @($readExecute) $true $false
Set-ExactTreeAcl $gatewayLogs @($gatewaySid) @($modify)
Set-ExactAcl $securityLogs @($gatewaySid) @($readExecute) $true $false
Set-ExactAcl $securityLogFile @($gatewaySid) @($appendOnly) $false $false
Set-ExactTreeAcl $state @($automatonSid) @($modify)

Write-Host 'Least-privilege ACLs applied. DEMO_EXECUTION remains disabled.'
