$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$result = @(Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {
    $_.PNPDeviceID -match '^(USBSTOR|SCSI)\\DISK&VEN_(QUALCOMM&PROD_MMC_STORAGE|MSFT&PROD_PHONE_MMC_STOR)&'
} | Select-Object -First 64 | ForEach-Object {
    $disk = Get-Disk -Number $_.Index -ErrorAction Stop
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
    }
})
ConvertTo-Json -InputObject $result -Depth 3 -Compress
