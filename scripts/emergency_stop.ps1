[CmdletBinding()]
param(
    [string] $KillSwitch = 'C:\ProgramData\AutomatonMT5Lab\control\KILL_SWITCH'
)
$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$target = [System.IO.Path]::GetFullPath($KillSwitch)
$parent = [System.IO.Path]::GetDirectoryName($target)
if (-not [System.IO.Path]::IsPathRooted($KillSwitch) -or -not $parent) {
    throw 'Kill switch path must be an absolute file path.'
}
if ($target.StartsWith($workspace + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Kill switch must remain outside the workspace.'
}
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Protected kill switch directory is absent.'
}
$parentItem = Get-Item -LiteralPath $parent -Force
if ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw 'Protected kill switch directory cannot be a reparse point.'
}
if (Test-Path -LiteralPath $target) {
    $targetItem = Get-Item -LiteralPath $target -Force
    if ($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'Kill switch cannot be a reparse point.'
    }
}
$temporary = Join-Path $parent ('.KILL_SWITCH.' + [System.Diagnostics.Process]::GetCurrentProcess().Id + '.tmp')
[System.IO.File]::WriteAllText($temporary, "HALT`n", [System.Text.Encoding]::ASCII)
if (Test-Path -LiteralPath $target) {
    [System.IO.File]::Replace($temporary, $target, $null)
} else {
    [System.IO.File]::Move($temporary, $target)
}
Write-Host "Emergency stop engaged at $target"
