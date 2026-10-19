$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$result = @(Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {
    $_.PNPDeviceID -match '^(USBSTOR|SCSI)\\DISK&VEN_(QUALCOMM&PROD_MMC_STORAGE|MSFT&PROD_PHONE_MMC_STOR)&'
} | Select-Object -First 64 | ForEach-Object {
    $disk = Get-Disk -Number $_.Index -ErrorAction Stop
    $ancestors = [System.Collections.Generic.List[string]]::new()
    $current = [string]$_.PNPDeviceID
    for ($depth = 0; $depth -lt 16; $depth++) {
        $parent = Get-PnpDeviceProperty -InstanceId $current -KeyName 'DEVPKEY_Device_Parent' -ErrorAction Stop
        $value = [string]$parent.Data
        if ([string]::IsNullOrWhiteSpace($value)) { break }
        if ($value.Length -gt 1024 -or $ancestors.Contains($value)) { throw 'Invalid disk ancestry' }
        $ancestors.Add($value)
        $current = $value
    }
    [pscustomobject]@{
        number = [uint32]$_.Index
        model = [string]$_.Model
        pnp_id = [string]$_.PNPDeviceID
        serial = [string]$_.SerialNumber
        size = [string]$disk.Size
        sector_size = [uint32]$disk.LogicalSectorSize
        bus_type = [uint32]$disk.BusType
        offline = [bool]$disk.IsOffline
        read_only = [bool]$disk.IsReadOnly
        boot = [bool]$disk.IsBoot
        system = [bool]$disk.IsSystem
        ancestors = @($ancestors.ToArray())
    }
})
ConvertTo-Json -InputObject $result -Depth 4 -Compress
