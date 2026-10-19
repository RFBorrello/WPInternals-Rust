# Operator-only host state helper. Preview is default; it never elevates itself.
# No raw handle, initialization, formatting, drive-letter or partition operation.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$UsbInstance,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPnpSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSerialSha256,
    [Parameter(Mandatory=$true)][uint64]$CapacityBytes,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$inventoryScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'crates\wpi-storage\src\discover-windows.ps1'
if ($UsbInstance.Length -gt 1024 -or $UsbInstance -notmatch '^USB\\(?:VID_(05C6|045E)&PID_9006|VID_(0421|045E)&PID_(0660|0713|0A01))(?:&REV_[0-9A-F]{4})?\\[^\\]+$' -or
    $UsbInstance -match '[^\x20-\x7e]' -or $CapacityBytes -lt 1GB -or $CapacityBytes -gt 256GB -or $CapacityBytes % 512 -ne 0) {
    throw 'A complete recognized mass-storage USB instance and bounded capacity are required'
}
function Get-TextSha256 {
    param([string]$Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}
function Resolve-BoundPhoneDisk {
    $records = @((& $inventoryScript) | ConvertFrom-Json)
    # ConvertFrom-Json can yield a single array object in older PowerShell.
    $records = @($records | ForEach-Object { $_ })
    if ($records.Count -gt 64) { throw 'Disk inventory exceeds bound' }
    $boundRecords = @($records | Where-Object { @($_.ancestors) -contains $UsbInstance })
    if ($boundRecords.Count -ne 1) { throw 'Need exactly one disk with the complete selected USB ancestor' }
    $record = $boundRecords[0]
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (@($record.ancestors).Count -gt 16) { throw 'Disk ancestry exceeds bound' }
    foreach ($ancestor in @($record.ancestors)) {
        if ([string]::IsNullOrWhiteSpace($ancestor) -or $ancestor.Length -gt 1024 -or -not $seen.Add($ancestor)) { throw 'Invalid disk ancestry' }
    }
    if ((Get-TextSha256 $record.pnp_id) -ne $ExpectedPnpSha256 -or
        (Get-TextSha256 $record.serial) -ne $ExpectedSerialSha256 -or
        [string]::IsNullOrWhiteSpace($record.serial) -or $record.serial.Length -gt 256 -or
        $record.pnp_id.Length -gt 1024 -or $record.model.Length -gt 256 -or
        [uint64]$record.size -ne $CapacityBytes -or $record.sector_size -ne 512 -or
        $record.bus_type -ne 7 -or $record.boot -ne $false -or $record.system -ne $false) {
        throw 'Bound phone disk fingerprint, geometry or host-disk protection failed'
    }
    $objects = @(Get-Disk -Number $record.number -ErrorAction Stop)
    if ($objects.Count -ne 1) { throw 'Ambiguous disk object' }
    $disk = $objects[0]
    foreach ($property in @('IsBoot','IsSystem','IsOffline','IsReadOnly')) {
        if ($disk.$property -isnot [bool]) { throw 'Disk state metadata is missing' }
    }
    if ($disk.IsBoot -or $disk.IsSystem -or [uint32]$disk.BusType -ne 7 -or
        [uint64]$disk.Size -ne $CapacityBytes -or $disk.LogicalSectorSize -ne 512 -or
        $disk.Number -ne $record.number -or [string]::IsNullOrWhiteSpace($disk.ObjectId) -or
        $disk.ObjectId.Length -gt 4096 -or [string]::IsNullOrWhiteSpace($disk.SerialNumber) -or
        $disk.SerialNumber.Trim() -cne $record.serial.Trim() -or
        $disk.IsOffline -ne $record.offline -or $disk.IsReadOnly -ne $record.read_only) {
        throw 'Current disk object disagrees with the pinned inventory'
    }
    [pscustomobject]@{ record=$record; disk=$disk }
}
function Assert-SameDiskObject {
    param($Initial, $Current)
    if ($Initial.disk.ObjectId -cne $Current.disk.ObjectId -or
        $Initial.record.number -ne $Current.record.number -or
        $Initial.record.pnp_id -cne $Current.record.pnp_id -or
        $Initial.record.serial -cne $Current.record.serial) {
        throw 'Disk object changed; no next state change was sent'
    }
}
function Invoke-BoundPhoneDiskPreparation {
    param([switch]$Apply)
    if ($Apply -and -not (Test-Administrator)) { throw 'Apply requires an Administrator terminal; no elevation was attempted' }
    $initial = Resolve-BoundPhoneDisk
    $changes = 0
    if ($Apply) {
        # Re-resolve before EACH mutation. Use the pinned CIM object, never a
        # disk number, wildcard, friendly label or unverified imported report.
        $current = Resolve-BoundPhoneDisk
        Assert-SameDiskObject $initial $current
        if (-not $current.disk.IsReadOnly) {
            Set-Disk -InputObject $current.disk -IsReadOnly $true -ErrorAction Stop
            $changes++
        }
        $current = Resolve-BoundPhoneDisk
        Assert-SameDiskObject $initial $current
        if (-not $current.disk.IsReadOnly) { throw 'Read-only state did not verify; no offline request was sent' }
        if (-not $current.disk.IsOffline) {
            Set-Disk -InputObject $current.disk -IsOffline $true -ErrorAction Stop
            $changes++
        }
        $current = Resolve-BoundPhoneDisk
        Assert-SameDiskObject $initial $current
        if (-not $current.disk.IsOffline -or -not $current.disk.IsReadOnly) { throw 'Host disk state did not verify; no retry or rollback was sent' }
    } else { $current = $initial }
    [pscustomobject]@{
        preview_only=(-not $Apply); disk_number=$current.record.number
        offline=$current.disk.IsOffline; read_only=$current.disk.IsReadOnly
        host_flag_changes=$changes; phone_payload_commands_sent=$false
        os_write_effects_unverified=($changes -gt 0); hardware_validated=$false
    } | ConvertTo-Json
}
Invoke-BoundPhoneDiskPreparation -Apply:$Apply
