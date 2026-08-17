#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $RunId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$workspace = 'C:\automaton'
$pythonExecutable = 'C:\automaton\.venv\Scripts\python.exe'
$configPath = 'C:\ProgramData\AutomatonMT5Lab\control\trading.yaml'
$authorizationRoot = 'C:\ProgramData\AutomatonMT5Lab\control\demo-authorization'
$policyPath = 'C:\automaton\config\windows-acl-policy.json'
$normalizedRunId = ([guid]::ParseExact($RunId, 'D')).ToString('D')
$authorizationPath = Join-Path $authorizationRoot "mt5-read-only-authorization-$normalizedRunId.json"

function Get-CanonicalPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-ExactChildPath([string] $Path, [string] $Parent) {
    $candidate = Get-CanonicalPath $Path
    $root = Get-CanonicalPath $Parent
    if (-not ([System.IO.Path]::GetDirectoryName($candidate)).Equals(
        $root, [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Authorization artifact path escapes the protected directory.'
    }
}

function Assert-RegularNonReparse([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -ne [bool]$item.PSIsContainer) {
        throw "Protected authorization path has the wrong type: $Path"
    }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Protected authorization path is a reparse point: $Path"
    }
}

function Invoke-BoundedProcess(
    [string] $Executable,
    [string] $Arguments,
    [string] $WorkingDirectory,
    [int] $TimeoutMilliseconds = 30000
) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['TRADING_MODE'] = 'OBSERVE_ONLY'
    $startInfo.EnvironmentVariables['MT5_ACCESS_ENABLED'] = 'false'
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Protected helper process did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw 'Protected helper process exceeded its bounded timeout.'
        }
        if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
            throw 'Protected helper output capture did not complete.'
        }
        if ($process.ExitCode -ne 0) {
            throw "Protected helper failed closed with exit code $($process.ExitCode)."
        }
        return [string]$stdoutTask.Result
    } finally {
        $process.Dispose()
    }
}

Assert-RegularNonReparse $workspace $true
Assert-RegularNonReparse $pythonExecutable $false
Assert-RegularNonReparse $configPath $false
Assert-RegularNonReparse $authorizationRoot $true
Assert-RegularNonReparse $policyPath $false
Assert-ExactChildPath $authorizationPath $authorizationRoot
if ([System.IO.File]::Exists($authorizationPath) -or [System.IO.Directory]::Exists($authorizationPath)) {
    throw 'Authorization artifact already exists. Use a new RunId.'
}

$policy = [System.IO.File]::ReadAllText($policyPath, [System.Text.Encoding]::UTF8) |
    ConvertFrom-Json -ErrorAction Stop
$maintenanceIdentity = [string]$policy.maintenance_identity
if ([string]::IsNullOrWhiteSpace($maintenanceIdentity) -or $maintenanceIdentity -notmatch '^[^\\]+\\[^\\]+$') {
    throw 'Canonical maintenance identity policy is invalid.'
}
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $currentIdentity.User.Value
if (-not $currentIdentity.Name.Equals(
    $maintenanceIdentity, [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw 'Current token is not the canonical maintenance identity.'
}
$maintenanceUserName = $maintenanceIdentity.Split('\', 2)[1]
$maintenanceUser = Get-LocalUser -Name $maintenanceUserName -ErrorAction Stop
if ($maintenanceUser.PrincipalSource.ToString() -ne 'Local' -or -not $maintenanceUser.Enabled) {
    throw 'Canonical maintenance identity is not an enabled local user.'
}
if ($maintenanceUser.SID.Value -ne $currentSid) {
    throw 'Current token SID does not match the canonical maintenance local user.'
}
foreach ($serviceUserName in @('AutomatonGateway', 'AutomatonAgent')) {
    $serviceUser = Get-LocalUser -Name $serviceUserName -ErrorAction Stop
    if ($serviceUser.SID.Value -eq $currentSid) {
        throw 'Service identities cannot issue MT5 read-only authorizations.'
    }
}
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$administratorsGroup = Get-LocalGroup -SID $administratorsSid -ErrorAction Stop
$directAdministratorSids = @(
    Get-LocalGroupMember -Group $administratorsGroup -ErrorAction Stop |
        ForEach-Object { $_.SID.Value }
)
if ($directAdministratorSids -notcontains $currentSid) {
    throw 'Canonical maintenance identity is not a direct local Administrator.'
}

$gitStatus = Invoke-BoundedProcess 'git.exe' '-C "C:\automaton" status --porcelain=v1 --untracked-files=all' $workspace
if (-not [string]::IsNullOrWhiteSpace($gitStatus)) {
    throw 'Working tree must be clean before issuing an MT5 read-only authorization.'
}
$gitCommit = (Invoke-BoundedProcess 'git.exe' '-C "C:\automaton" rev-parse --verify HEAD' $workspace).Trim()
if ($gitCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Exact Git HEAD commit could not be verified.'
}

$authorizationId = [guid]::NewGuid().ToString('D')
$renderArguments = @(
    '-B -m trading_lab.mt5_read_only_authorization render',
    '--config "C:\ProgramData\AutomatonMT5Lab\control\trading.yaml"',
    "--run-id $normalizedRunId",
    "--authorization-id $authorizationId",
    "--issuer-sid $currentSid"
) -join ' '
$authorizationJson = (Invoke-BoundedProcess $pythonExecutable $renderArguments $workspace).Trim()
$authorization = $authorizationJson | ConvertFrom-Json -ErrorAction Stop
if ([string]$authorization.run_id -ne $normalizedRunId -or
    [string]$authorization.authorization_id -ne $authorizationId -or
    [string]$authorization.issuer_sid -ne $currentSid -or
    [string]$authorization.git_commit -ne $gitCommit -or
    [string]$authorization.purpose -ne 'MT5_READ_ONLY_PREFLIGHT' -or
    [string]$authorization.trading_mode -ne 'OBSERVE_ONLY' -or
    [bool]$authorization.gateway_mt5_access_required) {
    throw 'Rendered authorization does not match the exact human-approved binding.'
}

$stream = [System.IO.File]::Open(
    $authorizationPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::Read
)
try {
    $writer = [System.IO.StreamWriter]::new(
        $stream, [System.Text.UTF8Encoding]::new($false)
    )
    try {
        $writer.Write($authorizationJson)
        $writer.Write([Environment]::NewLine)
        $writer.Flush()
    } finally { $writer.Dispose() }
} finally { $stream.Dispose() }

Assert-RegularNonReparse $authorizationPath $false
$verifyArguments = @(
    '-B -m trading_lab.mt5_read_only_authorization verify-artifact',
    '--config "C:\ProgramData\AutomatonMT5Lab\control\trading.yaml"',
    "--run-id $normalizedRunId"
) -join ' '
$verificationJson = Invoke-BoundedProcess $pythonExecutable $verifyArguments $workspace
$verification = $verificationJson | ConvertFrom-Json -ErrorAction Stop
if ([string]$verification.status -ne 'PASS' -or
    -not [bool]$verification.content_verified -or
    -not [bool]$verification.acl_verified -or
    [string]$verification.authorization_id -ne $authorizationId) {
    throw 'Created authorization artifact did not pass the exact protected ACL policy.'
}

Write-Output 'MT5_READ_ONLY_AUTHORIZATION_CREATED=PASS'
Write-Output 'TRADING_MODE=OBSERVE_ONLY'
Write-Output 'GATEWAY_MT5_ACCESS_REQUIRED=false'
Write-Output 'AUTHORIZATION_LIFETIME_MINUTES=15'
Write-Output "RUN_ID=$normalizedRunId"
Write-Output "AUTHORIZATION_ID=$authorizationId"
Write-Output "GIT_COMMIT=$gitCommit"
Write-Output "AUTHORIZATION_PATH=$authorizationPath"
