# All Windows cmdlets are mocked. No disk, PnP, registry or privilege changes.
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'prepare-bound-phone-disk.ps1'
function Assert-True { param($Value,$Message) if (-not $Value) { throw $Message } }
function Invoke-Fixture {
    param([hashtable]$Fixture, [bool]$Mutate=$false)
    $calls = [Collections.Generic.List[string]]::new()
    $properties = @{
        Index=3; Model='Synthetic phone'; PNPDeviceID='USBSTOR\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE&REV_1\private'
        SerialNumber='PRIVATE-SERIAL'
    }
    $diskState = [pscustomobject]@{
        Number=3; ObjectId='pinned-cim-object'; SerialNumber='PRIVATE-SERIAL'
        Size=[uint64]34359738368; LogicalSectorSize=512; BusType=7
        IsBoot=$false; IsSystem=$false; IsOffline=$false; IsReadOnly=$false
    }
    if ($Fixture.Ready) { $diskState.IsReadOnly=$true; $diskState.IsOffline=$true }
    if ($Fixture.Boot) { $diskState.IsBoot=$true }
    if ($Fixture.System) { $diskState.IsSystem=$true }
    if ($Fixture.BadBus) { $diskState.BusType=0 }
    if ($Fixture.BadSize) { $diskState.Size=512 }
    if ($Fixture.SerialMismatch) { $diskState.SerialNumber='changed' }
    if ($Fixture.MissingBoolean) { $diskState.IsBoot=$null }
    if ($Fixture.MissingObjectId) { $diskState.ObjectId='' }
    function Get-CimInstance {
        param($ClassName)
        if ($Fixture.Empty) { return }
        if ($Fixture.InventoryFailure) { throw 'Synthetic inventory failure' }
        [pscustomobject]$properties
        if ($Fixture.Duplicate) { [pscustomobject]$properties }
    }
    function Get-PnpDeviceProperty {
        param($InstanceId,$KeyName,$ErrorAction)
        if ($InstanceId -eq $properties.PNPDeviceID) {
            $value = if ($Fixture.WrongAncestor) { 'USB\VID_05C6&PID_9006\OTHER' } else { 'USB\VID_05C6&PID_9006\PRIVATE-USB' }
            [pscustomobject]@{Data=$value}
        } else { [pscustomobject]@{Data=''} }
    }
    function Get-Disk {
        param($Number,$ErrorAction)
        if ($calls.Count -eq 1 -and $Fixture.SwapAfterReadonly) { $diskState.ObjectId='replaced-object' }
        $diskState.PSObject.Copy()
    }
    function Set-Disk {
        param($InputObject,$IsReadOnly,$IsOffline,$ErrorAction)
        if ($InputObject.ObjectId -ne 'pinned-cim-object') { throw 'Wrong mutation target' }
        if ($PSBoundParameters.ContainsKey('IsReadOnly')) {
            Assert-True ($IsReadOnly -eq $true) 'Read-only flag cleared'
            $calls.Add('readonly')
            if (-not $Fixture.IgnoreReadonly) { $diskState.IsReadOnly=$true }
        } elseif ($PSBoundParameters.ContainsKey('IsOffline')) {
            Assert-True ($IsOffline -eq $true) 'Offline flag cleared'
            $calls.Add('offline'); $diskState.IsOffline=$true
        } else { throw 'Unexpected state mutation' }
        if ($Fixture.SetFailure) { throw 'Synthetic uncertain Set-Disk failure' }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $pnpHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($properties.PNPDeviceID)))).Replace('-','')
        $serialHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($properties.SerialNumber)))).Replace('-','')
    } finally { $sha.Dispose() }
    if ($Fixture.BadPin) { $pnpHash = '0' * 64 }
    $failure = $null
    try {
        $selectedUsb = if ($Fixture.WrongMode) { 'USB\VID_05C6&PID_F006\PRIVATE-USB' } else { 'USB\VID_05C6&PID_9006\PRIVATE-USB' }
        $selectedCapacity = if ($Fixture.BadCapacity) { 512 } else { 34359738368 }
        $initial = . $helper -UsbInstance $selectedUsb -ExpectedPnpSha256 $pnpHash -ExpectedSerialSha256 $serialHash -CapacityBytes $selectedCapacity
        function Test-Administrator { return (-not $Fixture.NotAdmin) }
        $result = if ($Mutate) { Invoke-BoundPhoneDiskPreparation -Apply | ConvertFrom-Json } else { $initial | ConvertFrom-Json }
    } catch { $failure = $_.Exception.Message; $result=$null }
    [pscustomobject]@{ result=$result; failure=$failure; calls=@($calls.ToArray()) }
}
$r = Invoke-Fixture @{}
Assert-True ($null -eq $r.failure -and $r.result.preview_only -and $r.calls.Count -eq 0) 'Preview performed a mutation or failed'
$r = Invoke-Fixture @{} $true
Assert-True ($null -eq $r.failure -and $r.result.offline -and $r.result.read_only) ('Apply failed: ' + $r.failure)
Assert-True (($r.calls -join ',') -eq 'readonly,offline') 'Expected one guarded request per state flag'
Assert-True (($r.result | ConvertTo-Json) -notmatch 'PRIVATE|pinned-cim-object') 'Private identifiers leaked in report'
$r = Invoke-Fixture @{Ready=$true} $true
Assert-True ($null -eq $r.failure -and $r.calls.Count -eq 0) 'Already-ready disk was mutated'
foreach ($kind in @('Empty','Duplicate','Boot','System','BadBus','BadSize','SerialMismatch','MissingBoolean','MissingObjectId','WrongAncestor','BadPin','InventoryFailure','NotAdmin','WrongMode','BadCapacity')) {
    $fixture = @{}; $fixture[$kind]=$true
    $r = Invoke-Fixture $fixture $true
    Assert-True ($null -ne $r.failure -and $r.calls.Count -eq 0) ('Unsafe fixture did not fail before mutation: ' + $kind)
}
foreach ($kind in @('SwapAfterReadonly','IgnoreReadonly','SetFailure')) {
    $fixture = @{}; $fixture[$kind]=$true
    $r = Invoke-Fixture $fixture $true
    Assert-True ($null -ne $r.failure -and ($r.calls -join ',') -eq 'readonly') ('Failure caused an offline request or retry: ' + $kind)
}
Write-Output 'Synthetic bound-disk setup checks passed; all device and state APIs were mocked.'
