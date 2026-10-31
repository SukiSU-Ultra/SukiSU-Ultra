# Generate a lightweight material-icons-custom.jar containing only needed and popular icons.
# Usage: powershell -ExecutionPolicy Bypass -File scripts/generate_material_icons.ps1

param(
    [string]$OutJar = "manager/app/libs/material-icons-custom.jar"
)

$ErrorActionPreference = "Stop"

$aar = Get-ChildItem -Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\androidx.compose.material\material-icons-extended-android" -Recurse -Filter "*.aar" | Select-Object -First 1
if (-not $aar) {
    Write-Error "material-icons-extended-android AAR not found in Gradle cache. Please build the project once with extended icons first."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($aar.FullName)
$classesJarEntry = $zip.GetEntry("classes.jar")
$stream = $classesJarEntry.Open()
$jarZip = New-Object System.IO.Compression.ZipArchive($stream)

# Selected icons (all needed in SukiSU-Ultra + popular utility icons, 139 in total)
$names = @(
    "Adb", "AdminPanelSettings", "Android", "Apps", "AspectRatio", "AutoAwesome", "Backup", 
    "BatteryFull", "Block", "BlurOn", "Brightness1", "Brightness3", "Brightness4", "Brightness7", 
    "BugReport", "CallToAction", "CheckCircleOutline", "ChevronRight", "Cloud", "Code", "Colorize", 
    "ContentCopy", "Contrast", "Cottage", "Crop", "DeleteForever", "DeleteOutline", "DeleteSweep", 
    "Description", "DesignServices", "DeveloperMode", "DisplaySettings", "Download", "DragHandle", 
    "Error", "ErrorOutline", "ExpandLess", "ExpandMore", "Extension", "Fence", "FileDownload", 
    "FileUpload", "FilterList", "Fingerprint", "FlashOn", "Folder", "FolderOpen", "Group", "Image", 
    "Inbox", "InstallMobile", "Language", "LayersClear", "Link", "Loop", "Memory", "Opacity", 
    "Palette", "PhotoLibrary", "Pin", "Policy", "PowerSettingsNew", "Remove", "RemoveModerator", 
    "RestartAlt", "Restore", "Save", "Science", "SdStorage", "Security", "Shield", "SignalCellularAlt", 
    "Style", "Swipe", "SystemUpdate", "SystemUpdateAlt", "Terminal", "Timer", "Tune", "Update", 
    "Verified", "VerifiedUser", "ViewCarousel", "VolunteerActivism", "Wallpaper", "WaterDrop", "Wifi",
    "Article", "MenuBook", "MenuOpen", "ReadMore", "Rule", "Sort", "DriveFileMove", "RotateRight", 
    "AddToHomeScreen", "ChromeReaderMode",
    "Notifications", "NotificationsActive", "NotificationsOff", "Visibility", "VisibilityOff",
    "Lock", "LockOpen", "VpnKey", "Camera", "CameraAlt", "Mic", "MicOff", "VolumeUp", "VolumeOff",
    "VolumeMute", "PlayCircle", "PauseCircle", "StopCircle", "FastForward", "FastRewind",
    "DarkMode", "LightMode", "Storage", "Usb", "Bluetooth", "BluetoothConnected", "WifiOff",
    "BatteryAlert", "BatteryChargingFull", "BatterySaver", "NetworkCheck", "Speed", "BuildCircle",
    "Help", "HelpOutline", "InfoOutline", "History", "Schedule", "Label", "Tag", "QrCode", "QrCodeScanner"
)

$matchedEntries = $jarZip.Entries | Where-Object {
    $path = $_.FullName
    if ($path -like "*/sharp/*" -or $path -like "*/twotone/*") { return $false }
    $entryName = $_.Name
    foreach ($n in $names) {
        if ($entryName -eq "${n}Kt.class") { return $true }
    }
    return $false
}

$outDir = Split-Path -Parent $OutJar
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
if (Test-Path $OutJar) { Remove-Item $OutJar -Force }

$outStream = [System.IO.File]::Create((Resolve-Path -Path $outDir).Path + "\" + (Split-Path -Leaf $OutJar))
$newJar = New-Object System.IO.Compression.ZipArchive($outStream, [System.IO.Compression.ZipArchiveMode]::Create)

foreach ($entry in $matchedEntries) {
    $newEntry = $newJar.CreateEntry($entry.FullName, [System.IO.Compression.CompressionLevel]::Optimal)
    $inStream = $entry.Open()
    $outEntryStream = $newEntry.Open()
    $inStream.CopyTo($outEntryStream)
    $outEntryStream.Dispose()
    $inStream.Dispose()
}

$newJar.Dispose()
$outStream.Dispose()
$stream.Dispose()
$zip.Dispose()

$sizeKB = [math]::Round((Get-Item $OutJar).Length / 1KB, 1)
Write-Host "Successfully generated $OutJar ($sizeKB KB, $($matchedEntries.Count) classes)"
