# Read-only PnP/registry metadata. Never opens a phone, binds a driver or elevates.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$devices = @(Get-PnpDevice | Where-Object {
    $_.InstanceId -match '^USB\\VID_05C6&PID_(9008|F006)($|&|\\)'
} | Select-Object -First 65)
if ($devices.Count -gt 64) { throw 'Emergency device inventory exceeds bound' }
$entries = @(foreach ($device in $devices) {
    $properties = @{}
    Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName @(
        'DEVPKEY_Device_Service', 'DEVPKEY_Device_ClassGuid',
        'DEVPKEY_Device_IsPresent', 'DEVPKEY_Device_ProblemCode',
        'DEVPKEY_Device_CompatibleIds'
    ) | ForEach-Object { $properties[$_.KeyName] = $_.Data }
    if ($properties['DEVPKEY_Device_IsPresent'] -isnot [bool]) {
        throw 'Missing device presence metadata'
    }
    $setupClass = switch ([string]$properties['DEVPKEY_Device_ClassGuid']) {
        '{88BAE032-5A81-49f0-BC3D-A4FF138216D6}' { 'usb_device' }
        '{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}' { 'hid' }
        '{4D36E978-E325-11CE-BFC1-08002BE10318}' { 'ports' }
        '' { 'unknown' }
        default { 'other' }
    }
    $service = switch ([string]$properties['DEVPKEY_Device_Service']) {
        'WinUSB' { 'winusb' }
        'HidUsb' { 'hidusb' }
        'usbser' { 'serial' }
        'qcusbser' { 'serial' }
        'qcusbser2k' { 'serial' }
        '' { 'none' }
        default { 'other' }
    }
    $compatible = @($properties['DEVPKEY_Device_CompatibleIds'])
    if ($compatible.Count -gt 64) { throw 'Compatible ID inventory exceeds bound' }
    # Any USB class other than vendor-specific (FF) is not admitted by the
    # emergency bulk adapter. Setup class and USB compatible class are separate.
    $protectedClass = $false
    foreach ($id in $compatible) {
        if ($id -match '(^|&)Class_([0-9a-f]{2})($|&)') {
            if ($Matches[2] -ne 'ff') { $protectedClass = $true }
        }
        if ($id -match '^USB\\Class_([0-9a-f]{2})($|&)') {
            if ($Matches[1] -ne 'ff') { $protectedClass = $true }
        }
    }
    $registered = $false
    $parameterPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\' +
        $device.InstanceId + '\Device Parameters'
    if (Test-Path -LiteralPath $parameterPath) {
        $parameters = Get-ItemProperty -LiteralPath $parameterPath
        $guids = @($parameters.DeviceInterfaceGUIDs) + @($parameters.DeviceInterfaceGUID)
        if ($guids.Count -gt 64) { throw 'Device interface inventory exceeds bound' }
        foreach ($candidate in $guids) {
            $parsed = [guid]::Empty
            if ([guid]::TryParse([string]$candidate, [ref]$parsed) -and $parsed -ne [guid]::Empty) {
                $registered = $true
            }
        }
    }
    $product = [regex]::Match($device.InstanceId, 'PID_(9008|F006)').Groups[1].Value
    @{
        product_id = [Convert]::ToUInt16($product, 16)
        present = $properties['DEVPKEY_Device_IsPresent']
        setup_class = $setupClass
        service = $service
        problem_code = $properties['DEVPKEY_Device_ProblemCode']
        protected_class = $protectedClass
        winusb_compatible_id = ($compatible -contains 'USB\MS_COMP_WINUSB')
        interface_guid_registered = $registered
    }
})
@{ endpoints = $entries } | ConvertTo-Json -Depth 4 -Compress
