#Requires -RunAsAdministrator
# System Integrity Audit Script v2.1 (Fixed)
# Repo: https://github.com/developer-for-all-games/SystemAudit
# Run: irm "https://raw.githubusercontent.com/developer-for-all-games/SystemAudit/main/SystemAudit.ps1" | iex

param(
    [string]$OutputPath = "C:\SystemAudit",
    [switch]$Silent
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$OutputPath\Audit_$Timestamp.txt"
$CsvFolder = "$OutputPath\CSVs_$Timestamp"
New-Item -ItemType Directory -Path $CsvFolder -Force | Out-Null

function Write-Log {
    param([string]$Header, [object]$Data, [string]$CsvName = $null)
    $separator = "=" * 80
    Add-Content -Path $LogFile -Value "`n$separator`n$Header`n$separator`n"
    if ($Data) {
        $stringData = $Data | Out-String
        Add-Content -Path $LogFile -Value $stringData
        if ($CsvName) {
            $Data | Export-Csv -Path "$CsvFolder\$CsvName.csv" -NoTypeInformation -Force
        }
    } else {
        Add-Content -Path $LogFile -Value "[No data found or access denied]"
    }
}

Add-Content -Path $LogFile -Value "SYSTEM AUDIT REPORT - $(Get-Date)"
Add-Content -Path $LogFile -Value "Computer: $env:COMPUTERNAME | User: $env:USERNAME"

# ========== SYSTEM INFO & WINDOWS INSTALL DATE ==========
$os = Get-CimInstance Win32_OperatingSystem
$installDate = $os.InstallDate
$uptime = (Get-Date) - $os.LastBootUpTime

$osInfo = [PSCustomObject]@{
    Caption = $os.Caption
    Version = $os.Version
    BuildNumber = $os.BuildNumber
    Architecture = $os.OSArchitecture
    InstallDate = $installDate
    InstallDateFormatted = $installDate.ToString("yyyy-MM-dd HH:mm:ss")
    DaysSinceInstall = [math]::Round(((Get-Date) - $installDate).TotalDays, 0)
    LastBootTime = $os.LastBootUpTime
    Uptime = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    SerialNumber = $os.SerialNumber
    RegisteredUser = $os.RegisteredUser
    TotalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    FreeRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
}

Write-Log "WINDOWS INSTALL DATE & SYSTEM INFO" $osInfo "OS_Info"

# ========== BIOS & HARDWARE ==========
$bios = Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, SerialNumber, Version, @{N='ReleaseDate';E={$_.ReleaseDate}}
Write-Log "BIOS Information" $bios "BIOS_Info"

$mobo = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber, Version
Write-Log "Motherboard" $mobo "Motherboard"

$cpu = Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
Write-Log "CPU" $cpu "CPU"

$gpu = Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription
Write-Log "GPU" $gpu "GPU"

# ========== CURRENTLY PLUGGED IN DEVICES ==========
Write-Log "CURRENTLY CONNECTED HARDWARE" "[Analyzing active devices...]"

# USB devices currently plugged in
$pluggedUSB = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | 
    Select-Object Name, InstanceId, @{N='Type';E={$_.Class}}, Status, @{N='Present';E={$_.Present}}
Write-Log "USB DEVICES CURRENTLY PLUGGED IN" $pluggedUSB "USB_Currently_Connected"

# HID devices (keyboards, mice, gamepads)
$hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | 
    Select-Object Name, InstanceId, Status
Write-Log "HID DEVICES (Keyboards/Mice/Controllers)" $hidDevices "HID_Devices"

# Audio devices
$audioDevices = Get-PnpDevice -Class AudioEndpoint, MEDIA -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | 
    Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status
Write-Log "AUDIO DEVICES CURRENTLY CONNECTED" $audioDevices "Audio_Devices"

# Monitors/Displays - Fixed with try/catch for WMI class
$monitors = @()
try {
    $monitors = Get-CimInstance WmiMonitorBasicDisplayParams -ErrorAction Stop | ForEach-Object {
        $id = ($_.InstanceName -split '\\')[1]
        [PSCustomObject]@{
            MonitorID = $id
            SupportedDisplayModes = $_.SupportedDisplayModes
            NativeResolution = if ($_.NativeResolution) { "$($_.NativeResolution.X)x$($_.NativeResolution.Y)" } else { "N/A" }
        }
    }
} catch {
    $monitors = @([PSCustomObject]@{Note="WmiMonitorBasicDisplayParams not available on this system"; Error=$_.Exception.Message})
}
Write-Log "MONITORS CURRENTLY CONNECTED" $monitors "Monitors"

# Storage devices currently attached
$storage = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions
Write-Log "PHYSICAL STORAGE DRIVES" $storage "Storage_Drives"

# Network adapters
$netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | 
    Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, MediaConnectionState
Write-Log "ACTIVE NETWORK ADAPTERS" $netAdapters "Network_Adapters"

# Bluetooth devices - Fixed with error handling
$bluetooth = @()
try {
    $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object Name, InstanceId, Status
} catch {
    $bluetooth = @([PSCustomObject]@{Note="No Bluetooth devices found or Bluetooth disabled"; Error=$_.Exception.Message})
}
Write-Log "BLUETOOTH DEVICES" $bluetooth "Bluetooth"

# ========== PREFETCH ==========
$prefetch = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | 
    Select-Object Name, @{N='Executable';E={$_.BaseName -replace '-[A-F0-9]{8}$',''}}, LastWriteTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}
Write-Log "Prefetch Files ($($prefetch.Count) total)" $prefetch "Prefetch_All"

$susNames = 'cheat','hack','inject','aim','bot','trigger','esp','wall','spoofer','bypass','loader','processhacker','cheatengine','artmoney','speedhack'
$susPrefetch = $prefetch | Where-Object { $e=$_.Executable.ToLower(); $susNames | ForEach-Object { if($e -like "*$_*"){return $true}}; return $false }
Write-Log "SUSPICIOUS PREFETCH FILES" $susPrefetch "Prefetch_Suspicious"

# ========== REGISTRY RUN KEYS ==========
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
$runEntries = @()
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        (Get-ItemProperty $key -ErrorAction SilentlyContinue).PSObject.Properties | 
            Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne '(Default)' } | 
            ForEach-Object { $runEntries += [PSCustomObject]@{Path=$key; Name=$_.Name; Value=$_.Value} }
    }
}
Write-Log "Run Keys (Startup)" $runEntries "Registry_RunKeys"

# ========== IFEO DEBUGGERS ==========
$ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $d=(Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if($d){[PSCustomObject]@{Executable=$_.PSChildName; Debugger=$d}}
    }
Write-Log "IFEO Debuggers (Injection Check)" $ifeo "Registry_IFEO"

# ========== USB HISTORY (ALL EVER CONNECTED) ==========
$usb = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | ForEach-Object {
        Get-ChildItem $_.PSPath | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $usb += [PSCustomObject]@{
                DeviceID=$_.PSChildName
                FriendlyName=$p.FriendlyName
                Mfg=$p.Mfg
                Service=$p.Service
            }
        }
    }
}
Write-Log "USB STORAGE HISTORY (All Time)" $usb "USB_History"

# ========== INSTALLED SOFTWARE ==========
$software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation | Where-Object { $_.DisplayName }
Write-Log "Installed Software" $software "Installed_Software"

# ========== RUNNING PROCESSES ==========
$procs = Get-Process | Select-Object Id, ProcessName, Path, Company, @{N='StartTime';E={$_.StartTime}}, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,2)}}
Write-Log "Running Processes" $procs "Processes"

$susProcs = $procs | Where-Object { 
    $n=$_.ProcessName.ToLower(); 
    $susNames | ForEach-Object { if($n -like "*$_*"){return $true}} 
    if($_.Path -and ($_.Path -like "*\Temp\*" -or $_.Path -like "*\Downloads\*")){return $true}
    return $false
}
Write-Log "SUSPICIOUS PROCESSES" $susProcs "Suspicious_Processes"

# ========== NETWORK ==========
$net = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
    @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess
Write-Log "Active Connections" $net "Network_Connections"

# ========== SCHEDULED TASKS ==========
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | 
    Select-Object TaskName, Author, @{N='Action';E={($_.Actions|Select-Object -First 1).Execute}}, State
Write-Log "Scheduled Tasks" $tasks "Scheduled_Tasks"

# ========== TEMP FILES ==========
$tempFiles = @()
@($env:TEMP, "C:\Windows\Temp") | ForEach-Object {
    if (Test-Path $_) {
        $tempFiles += Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | 
            Select-Object FullName, Length, LastWriteTime
    }
}
Write-Log "Recent Temp Files (7 days)" $tempFiles "Temp_Files"

# ========== SUSPICIOUS FILE SEARCH ==========
$foundFiles = @()
$searchPaths = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:PROGRAMDATA)
$searchExts = '.exe','.dll','.sys','.bat','.cmd','.ps1','.ahk','.lua'
foreach ($dir in $searchPaths) {
    if (Test-Path $dir) {
        foreach ($ext in $searchExts) {
            $foundFiles += Get-ChildItem $dir -Filter "*$ext" -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $name = $_.Name.ToLower()
                    foreach ($s in $susNames) { if ($name -like "*$s*") { return $true } }
                    return $false
                } | Select-Object FullName, Length, LastWriteTime
        }
    }
}
Write-Log "SUSPICIOUS FILES FOUND" $foundFiles "Suspicious_Files"

# ========== WMI PERSISTENCE ==========
$wmiBindings = Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription -ErrorAction SilentlyContinue
Write-Log "WMI Event Bindings" $wmiBindings "WMI_Bindings"

# ========== COMPLETION ==========
$summary = @"
AUDIT COMPLETE: $(Get-Date)
Log: $LogFile
CSV Folder: $CsvFolder

WINDOWS INSTALL DATE: $($osInfo.InstallDateFormatted) ($($osInfo.DaysSinceInstall) days ago)
SYSTEM UPTIME: $($osInfo.Uptime)
CURRENTLY PLUGGED IN:
- USB Devices: $($pluggedUSB.Count)
- HID (Keyboard/Mouse): $($hidDevices.Count)
- Audio: $($audioDevices.Count)
- Monitors: $($monitors.Count)
- Storage Drives: $($storage.Count)
- Network Adapters: $($netAdapters.Count)
- Bluetooth: $($bluetooth.Count)

Prefetch: $($prefetch.Count) | USB History: $($usb.Count) | Software: $($software.Count)
Processes: $($procs.Count) | Suspicious Procs: $($susProcs.Count) | Suspicious Files: $($foundFiles.Count)
"@
Add-Content -Path $LogFile -Value "`n$summary"

if (-not $Silent) {
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    Write-Host "Windows Installed: $($osInfo.InstallDateFormatted) ($($osInfo.DaysSinceInstall) days ago)" -ForegroundColor Cyan
    Write-Host "Currently Plugged In: $($pluggedUSB.Count) USB, $($hidDevices.Count) HID, $($monitors.Count) Monitors" -ForegroundColor Cyan
    Write-Host "Log: $LogFile" -ForegroundColor Cyan
    Write-Host "CSV: $CsvFolder" -ForegroundColor Cyan
}
