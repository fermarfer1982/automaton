Set-StrictMode -Version 2.0

function ConvertTo-ProtectedHelperDiagnostic(
    [AllowNull()] [string] $Text,
    [string[]] $SensitiveValues = @(),
    [int] $MaximumCharacters = 8192
) {
    if ($MaximumCharacters -lt 256 -or $MaximumCharacters -gt 65536) {
        throw 'Protected helper diagnostic limit is outside the reviewed range.'
    }
    $sanitized = if ($null -eq $Text) { '' } else { [string]$Text }
    foreach ($value in $SensitiveValues) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $sanitized = $sanitized.Replace($value, '[REDACTED]')
        }
    }
    $secretAssignment = '(?im)(?<key>\b(?:password|passwd|secret|token|api[ _-]*key|ipc[ _-]*key|credentials?)\b)' +
        '(?<separator>\s*["'']?\s*[:=]\s*)(?<value>"[^"\r\n]*"|''[^''\r\n]*''|[^\s,;\}\]\r\n]+)'
    $sanitized = [regex]::Replace(
        $sanitized,
        $secretAssignment,
        '${key}${separator}[REDACTED]'
    )
    if ($sanitized.Length -gt $MaximumCharacters) {
        $marker = '...[TRUNCATED]'
        $sanitized = $sanitized.Substring(0, $MaximumCharacters - $marker.Length) + $marker
    }
    return $sanitized
}

function Invoke-ProtectedIdentityHelperProcess(
    [Parameter(Mandatory = $true)]
    [ValidateSet('inspect', 'render', 'validate')]
    [string] $Operation,
    [Parameter(Mandatory = $true)]
    [ValidateSet('INSPECT', 'RENDER', 'VALIDATE_PRE_REPLACE', 'VALIDATE_POST_REPLACE')]
    [string] $Stage,
    [Parameter(Mandatory = $true)] [string] $Executable,
    [Parameter(Mandatory = $true)] [string] $Arguments,
    [Parameter(Mandatory = $true)] [string] $WorkingDirectory,
    [string[]] $SensitiveValues = @(),
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
    $startInfo.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
    $startInfo.EnvironmentVariables['TRADING_MODE'] = 'OBSERVE_ONLY'
    $startInfo.EnvironmentVariables['MT5_ACCESS_ENABLED'] = 'false'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $rawStdout = ''
    $rawStderr = ''
    $exitCode = -1
    $started = $false
    $timedOut = $false
    try {
        $started = [bool]$process.Start()
        if (-not $started) { throw 'Protected helper process did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $timedOut = $true
            $process.Kill()
            [void]$process.WaitForExit(5000)
        }
        if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) {
            throw 'Protected helper output capture did not complete.'
        }
        $rawStdout = [string]$stdoutTask.Result
        $rawStderr = [string]$stderrTask.Result
        $exitCode = if ($timedOut) { -2 } else { [int]$process.ExitCode }
        if ($timedOut) {
            $rawStderr = $rawStderr + [Environment]::NewLine + 'Protected helper timed out.'
        }
    } catch {
        if ($started -and -not $process.HasExited) {
            try {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($rawStderr)) {
            $rawStderr = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
        }
    } finally {
        $process.Dispose()
    }
    return [pscustomobject]@{
        operation = $Operation
        stage = $Stage
        process_started = $started
        exit_code = $exitCode
        timed_out = $timedOut
        stdout = ConvertTo-ProtectedHelperDiagnostic $rawStdout $SensitiveValues
        stderr = ConvertTo-ProtectedHelperDiagnostic $rawStderr $SensitiveValues
        raw_stdout = $rawStdout
        succeeded = ($started -and -not $timedOut -and $exitCode -eq 0)
    }
}

function Remove-ProtectedIdentityTransactionArtifacts(
    [string[]] $Paths,
    [Parameter(Mandatory = $true)] [string] $ExpectedParent,
    [Parameter(Mandatory = $true)] [guid] $RunId
) {
    $errors = [System.Collections.Generic.List[string]]::new()
    $canonicalParent = [System.IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $normalizedRunId = $RunId.ToString('D').ToLowerInvariant()
    $expectedNames = @(
        ".trading.identity-$normalizedRunId.tmp",
        ".trading.identity-$normalizedRunId.backup",
        ".trading.identity-$normalizedRunId.failed"
    )
    foreach ($path in $Paths) {
        $canonicalPath = try { [System.IO.Path]::GetFullPath($path) } catch { $null }
        $confined = $null -ne $canonicalPath -and
            [System.IO.Path]::GetDirectoryName($canonicalPath).TrimEnd('\').Equals(
                $canonicalParent,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            $expectedNames -contains [System.IO.Path]::GetFileName($canonicalPath)
        if (-not $confined) {
            $errors.Add("Rejected non-transaction cleanup path: $path")
        } elseif ([System.IO.File]::Exists($canonicalPath)) {
            try {
                Remove-Item -LiteralPath $canonicalPath -Force -ErrorAction Stop
            } catch {
                $errors.Add("Unable to remove transaction file: $canonicalPath")
            }
        } elseif ([System.IO.Directory]::Exists($canonicalPath)) {
            $errors.Add("Unexpected transaction directory was not removed: $canonicalPath")
        }
    }
    $remaining = @($Paths | Where-Object {
        [System.IO.File]::Exists($_) -or [System.IO.Directory]::Exists($_)
    })
    return [pscustomobject]@{
        attempted = $true
        removed = ($remaining.Count -eq 0 -and $errors.Count -eq 0)
        remaining = $remaining
        errors = @($errors)
    }
}
