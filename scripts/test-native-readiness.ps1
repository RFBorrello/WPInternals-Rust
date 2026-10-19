# Exercise the actual embedded inventory script with synthetic Windows metadata.
# No PnP, registry, phone, driver or disk access occurs.
$ErrorActionPreference = 'Stop'
$inventoryScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'crates\wpi-transport\src\spec_a_native\readiness.ps1'
function Invoke-InventoryFixture {
    param([hashtable]$Fixture)
    function Get-PnpDevice {
        if ($Fixture.Empty) { return }
        [pscustomobject]@{ InstanceId = ('USB\VID_05C6&PID_' + $Fixture.Product + '\PRIVATE-SERIAL') }
    }
    function Get-PnpDeviceProperty {
        param($InstanceId, $KeyName)
        if ($Fixture.PropertyFailure) { throw 'Synthetic metadata failure' }
        $values = @{
            DEVPKEY_Device_Service = $Fixture.Service
            DEVPKEY_Device_ClassGuid = $Fixture.ClassGuid
            DEVPKEY_Device_IsPresent = $Fixture.Present
            DEVPKEY_Device_ProblemCode = $Fixture.ProblemCode
            DEVPKEY_Device_CompatibleIds = $Fixture.CompatibleIds
        }
        foreach ($key in $KeyName) { [pscustomobject]@{ KeyName = $key; Data = $values[$key] } }
    }
    function Test-Path { param($LiteralPath) return $Fixture.RegistryExists }
    function Get-ItemProperty {
        param($LiteralPath)
        [pscustomobject]@{ DeviceInterfaceGUIDs = $Fixture.Guids; DeviceInterfaceGUID = $Fixture.SingularGuid }
    }
    (& $inventoryScript) | ConvertFrom-Json
}
function Assert-True { param($Value, $Message) if (-not $Value) { throw $Message } }
$valid = @{
    Product = '9008'; Service = 'WINUSB'; ClassGuid = '{88bae032-5a81-49f0-bc3d-a4ff138216d6}'
    Present = $true; ProblemCode = 0; CompatibleIds = @('USB\Class_ff&SubClass_ff', 'USB\MS_COMP_WINUSB')
    RegistryExists = $true; Guids = @('{134e20e8-1348-4a8b-bc76-4e4fd370bffe}')
}
$result = Invoke-InventoryFixture $valid
$e = $result.endpoints[0]
Assert-True ($result.endpoints.Count -eq 1 -and $e.product_id -eq 36872) 'Exact download PID inventory failed'
Assert-True ($e.setup_class -eq 'usb_device' -and $e.service -eq 'winusb') 'Case-insensitive class/service normalization failed'
Assert-True ($e.present -and $e.problem_code -eq 0 -and -not $e.protected_class) 'Vendor interface metadata changed'
Assert-True ($e.interface_guid_registered -and $e.winusb_compatible_id) 'WinUSB discovery metadata missing'
Assert-True (($result | ConvertTo-Json -Depth 5) -notmatch 'PRIVATE-SERIAL|134e20e8') 'Private metadata leaked'
$hid = $valid.Clone()
$hid.Product = 'F006'; $hid.Service = 'HidUsb'
$hid.ClassGuid = '{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}'
$hid.Present = $false; $hid.ProblemCode = $null
$hid.CompatibleIds = @('USB\COMPAT_VID_05C6&Class_03&SubClass_00', 'USB\Class_03')
$hid.RegistryExists = $false
$e = (Invoke-InventoryFixture $hid).endpoints[0]
Assert-True ($e.product_id -eq 61446 -and $e.setup_class -eq 'hid' -and $e.service -eq 'hidusb') 'HID charging candidate was misclassified'
Assert-True ($e.protected_class -and -not $e.present -and -not $e.interface_guid_registered) 'Absent HID metadata became usable'
foreach ($ids in @('USB\Class_08', 'USB\COMPAT_VID_05C6&Class_03')) {
    $f = $valid.Clone(); $f.CompatibleIds = @($ids)
    Assert-True (Invoke-InventoryFixture $f).endpoints[0].protected_class 'Protected USB class was missed'
}
foreach ($guid in @('', 'not-a-guid', '{00000000-0000-0000-0000-000000000000}')) {
    $f = $valid.Clone(); $f.Guids = @($guid)
    Assert-True (-not (Invoke-InventoryFixture $f).endpoints[0].interface_guid_registered) 'Invalid/empty interface GUID accepted'
}
$f = $valid.Clone(); $f.Guids = @('not-a-guid', $valid.Guids[0])
Assert-True (-not (Invoke-InventoryFixture $f).endpoints[0].interface_guid_registered) 'Later plural GUID bypassed the nusb first-entry rule'
$f.SingularGuid = $valid.Guids[0]
Assert-True (Invoke-InventoryFixture $f).endpoints[0].interface_guid_registered 'Singular fallback was lost'
$f.Guids = @('{00000000-0000-0000-0000-000000000000}')
Assert-True (-not (Invoke-InventoryFixture $f).endpoints[0].interface_guid_registered) 'Parsed empty plural GUID incorrectly fell back to singular'
$f = $valid.Clone(); $f.Empty = $true
Assert-True ((Invoke-InventoryFixture $f).endpoints.Count -eq 0) 'Empty inventory shape changed'
$f = $valid.Clone(); $f.Product = '90080'
Assert-True ((Invoke-InventoryFixture $f).endpoints.Count -eq 0) 'Partial product ID match was accepted'
foreach ($fault in @('PropertyFailure', 'Present')) {
    $f = $valid.Clone()
    if ($fault -eq 'Present') { $f.Present = $null } else { $f.PropertyFailure = $true }
    $rejected = $false
    try { $null = Invoke-InventoryFixture $f } catch { $rejected = $true }
    Assert-True $rejected 'Missing/failed metadata did not stop inventory'
}
Write-Output 'Synthetic Windows inventory checks passed; no device or registry access.'
