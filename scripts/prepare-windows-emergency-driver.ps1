# Build/validate an UNSIGNED local binding package. Never stages or installs it.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$InfVerifPath,
    [Parameter(Mandatory = $true)][string]$Inf2CatPath
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Microsoft WDK validation requires Windows' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Choose a NEW package directory; existing files are preserved' }
$parent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Output parent must already exist' }
foreach ($tool in @($InfVerifPath, $Inf2CatPath)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Both Microsoft WDK tools must already be available' }
}
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'resources/windows/emergency/wpi-emergency.inf'
$sourceDigest = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
# The report's fixed VID/PID/GUID describe only this reviewed source. Updating
# the INF requires reviewing its scope and this pin, not just passing InfVerif.
if ($sourceDigest -ne '7cbc413e8d74653a597531beabad26a4d3371199902d73ad70194cc668c1e3dd') {
    throw 'Unknown INF source; review binding scope before updating the source pin'
}
$null = New-Item -ItemType Directory -Path $output
$inf = Join-Path $output 'wpi-emergency.inf'
Copy-Item -LiteralPath $source -Destination $inf
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $source) 'README.md') -Destination (Join-Path $output 'README.md')
if ((Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash -ne $sourceDigest) { throw 'Source INF changed during copying' }
& $InfVerifPath /u $inf
if ($LASTEXITCODE -ne 0) { throw 'Microsoft universal INF validation failed; output is incomplete' }
$targets = '10_GE_ARM64,10_GE_X64,10_25H2_ARM64,10_25H2_X64'
& $Inf2CatPath (('/driver:' + $output)) ('/os:' + $targets) /uselocaltime
if ($LASTEXITCODE -ne 0) { throw 'Microsoft catalog signability checks failed; output is incomplete' }
if ((Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash -ne $sourceDigest -or
    (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $sourceDigest) {
    throw 'INF changed during validation; no completion manifest was published'
}
$catalog = Join-Path $output 'wpi-emergency.cat'
if (-not (Test-Path -LiteralPath $catalog -PathType Leaf)) { throw 'Expected unsigned catalog was not generated' }
$signature = Get-AuthenticodeSignature -LiteralPath $catalog
if ([string]$signature.Status -ne 'NotSigned') { throw 'Unexpected catalog signature state; review output separately' }
$manifest = [ordered]@{
    schema='wpi-emergency-driver-build-v1'
    generated_at_utc=[DateTime]::UtcNow.ToString('o')
    inf_sha256=$sourceDigest.ToLowerInvariant()
    readme_sha256=(Get-FileHash -LiteralPath (Join-Path $output 'README.md') -Algorithm SHA256).Hash.ToLowerInvariant()
    catalog_sha256=(Get-FileHash -LiteralPath $catalog -Algorithm SHA256).Hash.ToLowerInvariant()
    infverif_sha256=(Get-FileHash -LiteralPath $InfVerifPath -Algorithm SHA256).Hash.ToLowerInvariant()
    inf2cat_sha256=(Get-FileHash -LiteralPath $Inf2CatPath -Algorithm SHA256).Hash.ToLowerInvariant()
    universal_inf_validation_passed=$true
    catalog_signability_passed=$true
    catalog_targets=$targets.Split(',')
    catalog_signature_status=[string]$signature.Status
    model_hardware_id='USB\VID_05C6&PID_9008'
    interface_guid='{8F66C6E8-C607-4D4D-B107-7EC707A76620}'
    shared_qualcomm_id_not_lumia_authentication=$true
    signed=$false; installable_release=$false; staged_or_installed=$false
    phone_contacted=$false; driver_access_validated=$false; unlock_authorized=$false
}
$manifestPath = Join-Path $output 'build-manifest.json'
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(($manifest | ConvertTo-Json -Depth 5))
$stream = [IO.File]::Open($manifestPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
$manifest | ConvertTo-Json -Depth 5
