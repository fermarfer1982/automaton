[CmdletBinding()]
param(
    [string[]] $PidFiles = @('C:\ProgramData\AutomatonMT5Lab\data\gateway.pid'),
    [switch] $Apply
)
$ErrorActionPreference = 'Stop'
$targets = @()
foreach ($pidFile in $PidFiles) {
    $resolved = [System.IO.Path]::GetFullPath($pidFile)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { continue }
    $raw = [System.IO.File]::ReadAllText($resolved).Trim()
    if ($raw -notmatch '^\d+$' -or [int]$raw -le 4) { throw "Invalid PID file: $resolved" }
    $process = Get-Process -Id ([int]$raw) -ErrorAction Stop
    if ($process.ProcessName -notin @('python', 'node')) {
        throw "PID $raw is not an expected laboratory process."
    }
    $details = Get-CimInstance Win32_Process -Filter "ProcessId = $raw" -ErrorAction Stop
    $commandLine = [string]$details.CommandLine
    $isGateway = $process.ProcessName -eq 'python' -and $commandLine -match '(?i)trading_lab\.service'
    $isAutomaton = $process.ProcessName -eq 'node' -and $commandLine -match '(?i)dist[\\/]index\.js' -and $commandLine -match '(?i)--run'
    if (-not ($isGateway -or $isAutomaton)) {
        throw "PID $raw command line is not an exact laboratory entry point."
    }
    $targets += [pscustomobject]@{
        pid = [int]$raw
        role = $(if ($isGateway) { 'gateway' } else { 'automaton' })
        name = $process.ProcessName
        pid_file = $resolved
    }
}
$targets | ConvertTo-Json
if (-not $Apply) { Write-Host 'Dry run only; use -Apply to stop exactly these PIDs.'; exit 0 }
foreach ($target in $targets) {
    Stop-Process -Id $target.pid -ErrorAction Stop
    Remove-Item -LiteralPath $target.pid_file -Force
}
