# Synthetic Shell adapter: never contacts a real phone or registry.
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'backup-rm875-mtp.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('wpi-mtp-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($testRoot)
function Assert-True { param($Value, $Message) if (-not $Value) { throw $Message } }
function New-FixtureFile {
    $file = [pscustomobject]@{Name='Capture'; FileName='Capture.png'; IsFolder=$false; Data=[byte[]](1,2,3); Size=3L}
    $file | Add-Member ScriptMethod ExtendedProperty {
        param($key)
        if ($key -eq 'System.FileName') { return $this.FileName }
        if ($key -eq 'System.Size') { return $this.Size }
    }
    return $file
}
function New-FixtureFolder {
    param([object[]]$Children)
    $folder = [pscustomobject]@{Children=$Children}
    $folder | Add-Member ScriptMethod Items { return $this.Children }
    return $folder
}
$file = New-FixtureFile
$storageFolder = New-FixtureFolder @($file)
$storage = [pscustomobject]@{IsFolder=$true; GetFolder=$storageFolder}
$phone = [pscustomobject]@{IsFolder=$true; Path='::{fixture}\usb#vid_0421&pid_0661#fixture'; GetFolder=(New-FixtureFolder @($storage))}
$computer = New-FixtureFolder @($phone)
$fixtureState = [pscustomobject]@{copies=0; corruptSecond=$false}
$fakeShell = [pscustomobject]@{}
$fakeShell | Add-Member ScriptMethod Namespace {
    param($path)
    if ([string]$path -eq '17') { return $computer }
    if (-not [IO.Directory]::Exists($path)) { throw 'Unexpected synthetic destination' }
    $destination = [pscustomobject]@{Path=[string]$path}
    $destination | Add-Member ScriptMethod CopyHere {
        param($source, $flags)
        if ($flags -ne 1556) { throw 'Unexpected Shell operation flags' }
        $fixtureState.copies++
        $data = [byte[]]$source.Data.Clone()
        if ($fixtureState.corruptSecond -and $fixtureState.copies -eq 2) { $data[0] = 99 }
        [IO.File]::WriteAllBytes((Join-Path $this.Path $source.FileName), $data)
    }
    return $destination
}
function New-Object {
    param([string]$ComObject)
    if ($ComObject -ne 'Shell.Application') { throw 'Unexpected COM request' }
    return $fakeShell
}
function Expect-Rejection {
    param([scriptblock]$Action, [string]$Message)
    $rejected = $false
    try { $null = & $Action } catch { $rejected = $true }
    Assert-True $rejected $Message
}
$preview = (& $helper) | ConvertFrom-Json
Assert-True ($preview.preview -and $preview.files -eq 1 -and $fixtureState.copies -eq 0) 'Preview copied data'
$destination = Join-Path $testRoot 'complete'
$result = (& $helper -Copy -OutputDirectory $destination) | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $destination 'manifest.json') -Raw | ConvertFrom-Json
Assert-True ($result.complete -and $fixtureState.copies -eq 2) 'Independent copy verification did not complete'
Assert-True ($manifest.files[0].relative_path -eq 'Capture.png') 'Canonical filename lost its hidden extension'
Assert-True (-not $manifest.full_device_backup -and -not $manifest.app_data_included -and -not $manifest.phone_writes) 'Backup overclaimed its scope'
$originalHash = (Get-FileHash -LiteralPath (Join-Path $destination 'files/Capture.png')).Hash
Expect-Rejection { & $helper -Copy -OutputDirectory $destination } 'Existing directory was accepted'
Assert-True ((Get-FileHash -LiteralPath (Join-Path $destination 'files/Capture.png')).Hash -eq $originalHash) 'Existing backup changed'
Expect-Rejection { & $helper -Copy } 'Missing output path accepted'
Expect-Rejection { & $helper -OutputDirectory $destination } 'Output path accepted without Copy'
foreach ($badName in @('..\escape.png', 'C:\escape.png', 'CON', 'CONOUT$', 'NUL.txt', ('COM' + [char]0x00b9 + '.txt'), ('LPT' + [char]0x00b2), 'bad:name', 'trailing.', 'trailing ', '')) {
    $file.FileName = $badName
    $candidate = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
    Expect-Rejection { & $helper -Copy -OutputDirectory $candidate } 'Unsafe phone filename accepted'
    Assert-True (-not (Test-Path -LiteralPath $candidate)) 'Unsafe inventory created an output directory'
}
$file.FileName = 'Capture.png'
$collision = New-FixtureFile; $collision.FileName='CAPTURE.PNG'
$storageFolder.Children = @($file, $collision)
Expect-Rejection { & $helper -Copy -OutputDirectory (Join-Path $testRoot 'collision') } 'Case-colliding names accepted'
$storageFolder.Children = @($file)
$file.Size = $null
Expect-Rejection { & $helper -Copy -OutputDirectory (Join-Path $testRoot 'missing-size') } 'Missing file length accepted'
$file.Size = 268435457L
Expect-Rejection { & $helper -Copy -OutputDirectory (Join-Path $testRoot 'oversized') } 'Oversized file accepted'
$file.Size = 3L
$fixtureState.copies=0; $fixtureState.corruptSecond=$true
$incomplete = Join-Path $testRoot 'incomplete'
Expect-Rejection { & $helper -Copy -OutputDirectory $incomplete } 'Disagreeing read passes accepted'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $incomplete 'manifest.json'))) 'Failure published a completion manifest'
$computer.Children = @($phone, $phone)
Expect-Rejection { & $helper } 'Ambiguous phone selection accepted'
Write-Output 'Synthetic MTP preview, copies, filename boundaries, ambiguity and verification failures passed; no phone access.'
