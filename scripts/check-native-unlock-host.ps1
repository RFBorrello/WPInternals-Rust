# Run from an Administrator terminal when reviewing host access prerequisites.
# This helper never elevates itself, contacts a phone, installs a driver, changes
# disk attributes, or executes unlock-spec-a. Its only CLI call is read-only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedExecutableSha256
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$executable = Join-Path $repository 'target\release\wpi.exe'
$output = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $output) { throw 'Choose a new report path; existing files are preserved' }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $output) -PathType Container)) {
    throw 'Report parent directory must already exist'
}
$digest = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
if ($digest -ne $ExpectedExecutableSha256) { throw 'CLI executable digest changed; review and rebuild before continuing' }
$json = & $executable native-unlock-readiness
if ($LASTEXITCODE -ne 0) { throw 'Read-only host readiness failed; no report was published' }
$readiness = ($json -join "`n") | ConvertFrom-Json
if ($readiness.phone_contacted -ne $false -or
    $readiness.driver_changes_sent -ne $false -or
    $readiness.hardware_validated -ne $false) {
    throw 'Unexpected readiness report; no report was published'
}
$report = [ordered]@{
    schema = 'wpi-native-host-check-v1'
    collected_at_utc = [DateTime]::UtcNow.ToString('o')
    executable_sha256 = $digest.ToLowerInvariant()
    advisory_only = $true
    readiness = $readiness
}
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 10))
# CreateNew handles a collision after the precheck without replacing the file.
$file = [System.IO.File]::Open($output, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try {
    $file.Write($bytes, 0, $bytes.Length)
    $file.Flush($true)
} finally {
    $file.Dispose()
}
Write-Output "Read-only host report saved to $output"
