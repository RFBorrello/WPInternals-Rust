# Bounded, read-only phone-file backup. No driver, mode or phone-storage changes.
# Preview is the default. This is not a raw-device or application-data backup.
[CmdletBinding()]
param(
    [switch]$Copy,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This helper requires Windows Shell MTP access' }
if ($Copy -and [string]::IsNullOrWhiteSpace($OutputDirectory)) { throw 'Copy requires a NEW OutputDirectory' }
if (-not $Copy -and $OutputDirectory) { throw 'OutputDirectory requires Copy; preview creates no files' }
$output = $null
if ($Copy) {
    $output = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $output) { throw 'Output directory already exists; existing files are preserved' }
    $parent = Split-Path -Parent $output
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Output parent must already exist' }
    if ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Choose an ordinary output parent directory'
    }
}
$shell = New-Object -ComObject Shell.Application
function Find-Phone {
    $matches = @($shell.Namespace(17).Items() | Where-Object {
        $_.IsFolder -and $_.Path -match '(?i)usb#vid_0421&pid_0661(&|#)'
    })
    if ($matches.Count -ne 1) { throw 'Expected exactly one exposed 0421:0661 phone in Normal mode' }
    return $matches[0]
}
function Assert-LeafName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 255 -or
        $Name -in @('.', '..') -or $Name -match '[. ]$' -or
        $Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
        $Name -match '^(?i:CON|CONIN\$|CONOUT\$|PRN|AUX|NUL|COM[0-9\u00b9\u00b2\u00b3]|LPT[0-9\u00b9\u00b2\u00b3])(?:\.|$)') {
        throw 'An exposed item has an unsafe or ambiguous Windows filename'
    }
}
function Read-Inventory {
    $phone = Find-Phone
    if ($phone.Path -ne $phonePath) { throw 'The selected phone path changed; stopping' }
    $storages = @($phone.GetFolder.Items())
    if ($storages.Count -ne 1 -or -not $storages[0].IsFolder) { throw 'Expected one exposed phone storage root' }
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $stack = [Collections.Generic.Stack[object]]::new()
    $stack.Push([pscustomobject]@{folder=$storages[0].GetFolder; relative=''; depth=0})
    [long]$total = 0
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        if ($current.depth -gt 16) { throw 'Phone folder depth exceeds backup bound' }
        foreach ($item in $current.folder.Items()) {
            # Shell display names can hide extensions. Use canonical FileName.
            $name = [string]$item.ExtendedProperty('System.FileName')
            if (-not $name -and $item.IsFolder) { $name = $item.Name }
            Assert-LeafName $name
            $relative = if ($current.relative) { $current.relative + '\' + $name } else { $name }
            if (-not $seen.Add($relative)) { throw 'Duplicate or case-colliding phone paths' }
            if ($entries.Count -ge 10000) { throw 'Phone item count exceeds backup bound' }
            [long]$size = 0
            if ($item.IsFolder) {
                $stack.Push([pscustomobject]@{folder=$item.GetFolder; relative=$relative; depth=($current.depth+1)})
            } else {
                $value = $item.ExtendedProperty('System.Size')
                if ($null -eq $value) { throw 'File size unavailable; stopping before copying' }
                $size = [long]$value
                if ($size -lt 0 -or $size -gt 268435456 -or $total -gt 268435456 - $size) {
                    throw 'Exposed files exceed this helper''s 256 MiB research bound'
                }
                $total += $size
            }
            $entries.Add([pscustomobject]@{relative=$relative; folder=[bool]$item.IsFolder; size=$size; item=$item})
        }
    }
    return $entries.ToArray()
}
function Assert-SamePhone {
    if ((Find-Phone).Path -ne $phonePath) { throw 'Phone path disappeared or changed; no retry' }
}
function Copy-AndHash {
    param($Entry, [string]$Root)
    Assert-SamePhone
    $target = Join-Path $Root $Entry.relative
    if (Test-Path -LiteralPath $target) { throw 'Unexpected local target collision; stopping' }
    $destination = $shell.Namespace((Split-Path -Parent $target))
    if ($null -eq $destination) { throw 'Cannot open the new local destination folder' }
    # CopyHere reads the phone and writes only to this new local folder. Flags:
    # SILENT, NOCONFIRMATION, NOCONFIRMMKDIR, NOERRORUI. No MOVE/DELETE is used.
    $destination.CopyHere($Entry.item, 1556)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        Assert-SamePhone
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $stream = $null
            try { $stream = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
            catch [IO.IOException] { }
            if ($null -ne $stream) {
                try {
                    if ($stream.Length -eq $Entry.size) {
                        $sha = [Security.Cryptography.SHA256]::Create()
                        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
                        finally { $sha.Dispose() }
                    }
                } finally { $stream.Dispose() }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    # Shell copies are asynchronous. Never clean up or claim a complete backup
    # on timeout; a background copy may still be finishing in the new directory.
    throw 'MTP copy did not verify before timeout; retain the incomplete local directory'
}
$phonePath = (Find-Phone).Path
$inventory = @(Read-Inventory)
$files = @($inventory | Where-Object { -not $_.folder })
[long]$totalBytes = ($files | Measure-Object -Property size -Sum).Sum
if (-not $Copy) {
    [pscustomobject]@{preview=$true; files=$files.Count; bytes=$totalBytes; copy_passes=2; full_device_backup=$false; app_data_included=$false; phone_writes=$false} | ConvertTo-Json
    return
}
if ($files.Count -eq 0) { throw 'No exposed files; no backup directory was created' }
# All inventory/path/size checks precede output creation. Preserve both passes.
$null = New-Item -ItemType Directory -Path $output
$firstRoot = Join-Path $output 'files'
$secondRoot = Join-Path $output 'verification-copy'
foreach ($root in @($firstRoot, $secondRoot)) {
    $null = New-Item -ItemType Directory -Path $root
    foreach ($entry in @($inventory | Where-Object { $_.folder } | Sort-Object { $_.relative.Length })) {
        $null = New-Item -ItemType Directory -Path (Join-Path $root $entry.relative)
    }
}
$records = [Collections.Generic.List[object]]::new()
foreach ($entry in $files) {
    $first = Copy-AndHash $entry $firstRoot
    $second = Copy-AndHash $entry $secondRoot
    if ($first -ne $second) { throw 'Independent MTP copies disagree; no completion manifest was published' }
    $records.Add([ordered]@{relative_path=$entry.relative; bytes=$entry.size; sha256=$first; independent_copy_matches=$true})
}
$after = @(Read-Inventory)
$beforeShape = @($inventory | ForEach-Object { '{0}|{1}|{2}' -f $_.relative, $_.folder, $_.size } | Sort-Object)
$afterShape = @($after | ForEach-Object { '{0}|{1}|{2}' -f $_.relative, $_.folder, $_.size } | Sort-Object)
if (@(Compare-Object $beforeShape $afterShape).Count -ne 0) { throw 'Exposed file inventory changed; no completion manifest published' }
Assert-SamePhone
$manifest = [ordered]@{
    schema='wpi-rm875-mtp-copy-v1'; completed_at_utc=[DateTime]::UtcNow.ToString('o')
    usb_vendor_id='0421'; usb_product_id='0661'; device_authenticated=$false
    files_verified=$records.Count; verified_bytes=$totalBytes; files=$records.ToArray()
    independent_read_passes=2; source_names_and_sizes_stable=$true
    full_device_backup=$false; app_data_included=$false; boot_partitions_included=$false
    phone_writes=$false; unlock_authorized=$false; data_preservation_validated=$false
}
$manifestPath = Join-Path $output 'manifest.json'
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(($manifest | ConvertTo-Json -Depth 8))
$writer = [IO.File]::Open($manifestPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $writer.Write($bytes, 0, $bytes.Length); $writer.Flush($true) } finally { $writer.Dispose() }
[pscustomobject]@{complete=$true; files_verified=$records.Count; verified_bytes=$totalBytes; output_directory=$output; full_device_backup=$false; app_data_included=$false; phone_writes=$false} | ConvertTo-Json
