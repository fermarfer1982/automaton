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

$root = Get-CanonicalPath $LabRoot
$state = Get-CanonicalPath $AutomatonStateDir
$workspace = Get-CanonicalPath $WorkspaceRoot
$control = Join-Path $root 'control'
$data = Join-Path $root 'data'
$ipc = Join-Path $root 'ipc'
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
if ($gatewaySid.Value -eq $automatonSid.Value) {
    throw 'Gateway and Automaton identities must be distinct.'
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
    [string[]] $RepresentativeTargets
) {
    $entries = [System.Collections.Generic.List[object]]::new()
    $entries.Add([pscustomobject]@{
        principal = 'NT AUTHORITY\SYSTEM'
        sid = $systemSid.Value
        rights = 'FullControl'
        type = 'Allow'
    })
    $entries.Add([pscustomobject]@{
        principal = 'BUILTIN\Administrators'
        sid = $administratorsSid.Value
        rights = 'FullControl'
        type = 'Allow'
    })
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $entries.Add([pscustomobject]@{
            principal = $Principals[$index].Value
            sid = $Principals[$index].Value
            rights = $Rights[$index]
            type = 'Allow'
        })
    }
    return [pscustomobject]@{
        path = $Path
        domain = $Domain
        inheritance_protected = $true
        inherited_aces_preserved = $false
        deny_aces = 0
        child_propagation = 'ContainerInherit,ObjectInherit'
        owner = 'BUILTIN\Administrators'
        entries = @($entries)
        representative_targets = $RepresentativeTargets
    }
}

$aclProposals = @(
    New-AclProposal $root 'lab_root_navigation' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) @('control', 'data', 'ipc')
    New-AclProposal $workspace 'source_read_only' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) @(
        'Automaton source and prompt', 'trading_lab gateway source',
        'risk_engine.py', 'account_guard.py', 'execution_engine.py',
        'mt5_adapter.py', 'src\trading', 'scripts', '.runtime', '.venv'
    )
    New-AclProposal $control 'human_managed_control' @($gatewaySid) @(
        'ReadAndExecute'
    ) @(
        'trading.yaml', 'KILL_SWITCH', 'demo.authorization',
        'readiness.json', 'readiness.json.sha256'
    )
    New-AclProposal $data 'gateway_writable_data' @($gatewaySid) @(
        'Modify'
    ) @(
        'audit.jsonl', 'audit.db', 'research.db', 'trading memory',
        'gateway.lock', 'logs\gateway', 'logs\security', 'logs\trading'
    )
    New-AclProposal $ipc 'shared_read_only_ipc' @($gatewaySid, $automatonSid) @(
        'ReadAndExecute', 'ReadAndExecute'
    ) @('automaton.key')
    New-AclProposal $state 'agent_private_state' @($automatonSid) @(
        'Modify'
    ) @(
        'Automaton context', 'agent memory', 'procedural memory',
        'agent logs', 'last_processed_bar_timestamp'
    )
)

$plan = [pscustomobject]@{
    apply = [bool]$Apply
    gateway_sid = $gatewaySid.Value
    automaton_sid = $automatonSid.Value
    control_directory = $control
    data_directory = $data
    ipc_directory = $ipc
    automaton_state_directory = $state
    read_only_workspace = $workspace
    security_config = (Join-Path $control 'trading.yaml')
    acl_model = 'protected inheritance with explicit Allow ACEs; no Deny ACEs'
    acl_proposals = $aclProposals
}
$plan | ConvertTo-Json -Depth 8
if (-not $Apply) {
    Write-Host 'Dry run only. Re-run with -Apply after reviewing the resolved SIDs and paths.'
    exit 0
}

if (Test-Path -LiteralPath (Join-Path $state 'wallet.json')) {
    throw 'Refusing to use an Automaton state directory containing a signing wallet.'
}
foreach ($existingRoot in @($root, $state)) {
    if (Test-Path -LiteralPath $existingRoot) {
        $rootItem = Get-Item -LiteralPath $existingRoot -Force
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing an ACL root that is a reparse point: $existingRoot"
        }
        $reparse = Get-ChildItem -LiteralPath $existingRoot -Force -Recurse |
            Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
            Select-Object -First 1
        if ($null -ne $reparse) {
            throw "Refusing an ACL tree containing a reparse point: $($reparse.FullName)"
        }
    }
}
$workspaceItem = Get-Item -LiteralPath $workspace -Force
if ($workspaceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "Refusing a workspace root that is a reparse point: $workspace"
}

foreach ($directory in @($root, $control, $data, $ipc, $state)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

$apiKeyPath = Join-Path $ipc 'automaton.key'
if (-not (Test-Path -LiteralPath $apiKeyPath)) {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $apiKey = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [System.IO.File]::WriteAllText($apiKeyPath, $apiKey, [System.Text.Encoding]::ASCII)
}

function New-AccessRule(
    [System.Security.Principal.SecurityIdentifier] $Sid,
    [System.Security.AccessControl.FileSystemRights] $Rights,
    [bool] $Directory
) {
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    return [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid,
        $Rights,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

function Set-ExactAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights,
    [bool] $Directory
) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner($administratorsSid)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule((New-AccessRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory))
    $security.AddAccessRule((New-AccessRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl) $Directory))
    for ($index = 0; $index -lt $Principals.Count; $index++) {
        $security.AddAccessRule((New-AccessRule $Principals[$index] $Rights[$index] $Directory))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Set-ExactTreeAcl(
    [string] $Path,
    [System.Security.Principal.SecurityIdentifier[]] $Principals,
    [System.Security.AccessControl.FileSystemRights[]] $Rights
) {
    Set-ExactAcl $Path $Principals $Rights $true
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
        Set-ExactAcl $item.FullName $Principals $Rights ([bool]$item.PSIsContainer)
    }
}

Set-ExactAcl $root @($gatewaySid, $automatonSid) @(
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
) $true
Set-ExactAcl $workspace @($gatewaySid, $automatonSid) @(
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
) $true
Set-ExactTreeAcl $control @($gatewaySid) @([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
Set-ExactTreeAcl $data @($gatewaySid) @([System.Security.AccessControl.FileSystemRights]::Modify)
Set-ExactTreeAcl $ipc @($gatewaySid, $automatonSid) @(
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
)
Set-ExactTreeAcl $state @($automatonSid) @([System.Security.AccessControl.FileSystemRights]::Modify)

foreach ($protectedDirectory in @(
    (Join-Path $workspace 'trading_lab'),
    (Join-Path $workspace 'src\trading')
)) {
    if (-not (Test-Path -LiteralPath $protectedDirectory -PathType Container)) {
        throw "Protected source directory is absent: $protectedDirectory"
    }
    $protectedReparse = Get-ChildItem -LiteralPath $protectedDirectory -Force -Recurse |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
        Select-Object -First 1
    if ($null -ne $protectedReparse) {
        throw "Protected source directory contains a reparse point: $($protectedReparse.FullName)"
    }
    Set-ExactTreeAcl $protectedDirectory @($gatewaySid, $automatonSid) @(
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    )
}

foreach ($relativeFile in @(
    'src\index.ts', 'src\config.ts', 'src\agent\loop.ts', 'src\agent\tools.ts',
    'src\conway\inference.ts', 'src\identity\wallet.ts', 'src\self-mod\code.ts',
    'src\types.ts', 'scripts\Initialize-TradingLabAcl.ps1', 'package.json',
    'scripts\setup.ps1', 'scripts\start_gateway.ps1', 'scripts\start_automaton.ps1',
    'scripts\status.ps1', 'scripts\stop.ps1', 'scripts\test_gateway.ps1',
    'scripts\enable_demo_trading.ps1', 'scripts\disable_trading.ps1',
    'scripts\emergency_stop.ps1', 'scripts\New-TradingLabUsers.ps1',
    'config\trading.security.example.json', 'config\trading.example.yaml',
    'requirements-mt5.txt', 'requirements-gateway-win-py314.lock',
    'requirements-gateway.in', 'docs\TRADING_LAB.md',
    'docs\SECURITY_INVARIANTS.md', 'docs\READINESS_AUDIT.md'
)) {
    $protectedFile = Join-Path $workspace $relativeFile
    if (-not (Test-Path -LiteralPath $protectedFile -PathType Leaf)) {
        throw "Protected source file is absent: $protectedFile"
    }
    Set-ExactAcl $protectedFile @($gatewaySid, $automatonSid) @(
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    ) $false
}

Write-Host 'ACLs applied. Copy trading.yaml as Administrator, then run readiness before starting either process.'
