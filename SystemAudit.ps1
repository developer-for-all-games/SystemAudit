#Requires -RunAsAdministrator
# System Integrity Audit Script v3.2 - Windows 10/11 Compatible (Forms Fix)
# Repo: https://github.com/developer-for-all-games/SystemAudit
# Run: irm "https://raw.githubusercontent.com/developer-for-all-games/SystemAudit/main/SystemAudit.ps1" | iex

param(
    [string]$OutputPath = "C:\SystemAudit",
    [switch]$Silent
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$OutputPath\Audit_$Timestamp.txt"
$CsvFolder = "$OutputPath\CSVs_$Timestamp"
New-Item -ItemType Directory -Path $CsvFolder -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Header, [object]$Data, [string]$CsvName = $null)
    $separator = "=" * 80
    Add-Content -Path $LogFile -Value "`n$separator`n$Header`n$separator`n" -ErrorAction SilentlyContinue
    if ($Data) {
        $stringData = $Data | Out-String
        Add-Content -Path $LogFile -Value $stringData -ErrorAction SilentlyContinue
        if ($CsvName) {
            $Data | Export-Csv -Path "$CsvFolder\$CsvName.csv" -NoTypeInformation -Force -ErrorAction SilentlyContinue
        }
    } else {
        Add-Content -Path $LogFile -Value "[No data found or access denied]" -ErrorAction SilentlyContinue
    }
}

Add-Content -Path $LogFile -Value "SYSTEM AUDIT REPORT - $(Get-Date)" -ErrorAction SilentlyContinue
Add-Content -Path $LogFile -Value "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -ErrorAction SilentlyContinue

# ========== WINDOWS VERSION DETECTION ==========
$winVer = [System.Environment]::OSVersion.Version
$isWin11 = $winVer.Build -ge 22000
$osName = if ($isWin11) { "Windows 11" } else { "Windows 10" }
Write-Log "WINDOWS VERSION" "Detected: $osName (Build $($winVer.Build))"

# ========== SYSTEM INFO & WINDOWS INSTALL DATE ==========
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
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
} catch {
    $osInfo = [PSCustomObject]@{
        Note = "Limited system info (WMI fallback)"
        Error = $_.Exception.Message
        InstallDate = "Unknown - check 'systeminfo' command manually"
    }
    Write-Log "WINDOWS INSTALL DATE & SYSTEM INFO" $osInfo "OS_Info"
}

# ========== BIOS & HARDWARE ==========
try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, SerialNumber, Version, @{N='ReleaseDate';E={$_.ReleaseDate}}
    Write-Log "BIOS Information" $bios "BIOS_Info"
} catch {
    $bios = Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Select-Object Manufacturer, Name, SerialNumber, Version
    Write-Log "BIOS Information (WMI Fallback)" $bios "BIOS_Info"
}

try {
    $mobo = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object Manufacturer, Product, SerialNumber, Version
    Write-Log "Motherboard" $mobo "Motherboard"
} catch {
    $mobo = Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object Manufacturer, Product, SerialNumber, Version
    Write-Log "Motherboard (WMI Fallback)" $mobo "Motherboard"
}

try {
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    Write-Log "CPU" $cpu "CPU"
} catch {
    $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    Write-Log "CPU (WMI Fallback)" $cpu "CPU"
}

try {
    $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription
    Write-Log "GPU" $gpu "GPU"
} catch {
    $gpu = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription
    Write-Log "GPU (WMI Fallback)" $gpu "GPU"
}

# ========== CURRENTLY PLUGGED IN DEVICES ==========
Write-Log "CURRENTLY CONNECTED HARDWARE" "[Analyzing active devices...]"

# USB devices currently plugged in
$pluggedUSB = @()
try {
    $pluggedUSB = Get-PnpDevice -Class USB -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object Name, InstanceId, @{N='Type';E={$_.Class}}, Status, @{N='Present';E={$_.Present}}
} catch {
    $pluggedUSB = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | 
        Where-Object { $_.PNPClass -eq 'USB' -and $_.Status -eq 'OK' } |
        Select-Object Name, DeviceID, @{N='Type';E={$_.PNPClass}}, Status
}
Write-Log "USB DEVICES CURRENTLY PLUGGED IN" $pluggedUSB "USB_Currently_Connected"

# HID devices (keyboards, mice, gamepads)
$hidDevices = @()
try {
    $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object Name, InstanceId, Status
} catch {
    $hidDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | 
        Where-Object { $_.PNPClass -eq 'HIDClass' -and $_.Status -eq 'OK' } |
        Select-Object Name, DeviceID, Status
}
Write-Log "HID DEVICES (Keyboards/Mice/Controllers)" $hidDevices "HID_Devices"

# Audio devices
$audioDevices = @()
try {
    $audioDevices = Get-PnpDevice -Class AudioEndpoint, MEDIA -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status
} catch {
    $audioDevices = Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue | 
        Where-Object { $_.Status -eq 'OK' } |
        Select-Object Name, DeviceID, @{N='Class';E={'Audio'}}, Status
}
Write-Log "AUDIO DEVICES CURRENTLY CONNECTED" $audioDevices "Audio_Devices"

# Monitors/Displays - FIXED: Pure registry detection, no System.Windows.Forms needed
$monitors = @()
try {
    # Try CIM first (Win11 preferred)
    $monitors = Get-CimInstance WmiMonitorBasicDisplayParams -ErrorAction Stop | ForEach-Object {
        $id = ($_.InstanceName -split '\\')[1]
        [PSCustomObject]@{
            MonitorID = $id
            SupportedDisplayModes = $_.SupportedDisplayModes
            NativeResolution = if ($_.NativeResolution) { "$($_.NativeResolution.X)x$($_.NativeResolution.Y)" } else { "N/A" }
        }
    }
} catch {
    try {
        # Win10 fallback via WMI
        $monitors = Get-WmiObject WmiMonitorBasicDisplayParams -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                MonitorID = $_.InstanceName
                SupportedDisplayModes = "Check manually"
                NativeResolution = "Check manually"
            }
        }
    } catch {
        # Final fallback: Registry-based monitor detection (NO System.Windows.Forms)
        $monitorRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
        if (Test-Path $monitorRegPath) {
            Get-ChildItem $monitorRegPath -ErrorAction SilentlyContinue | ForEach-Object {
                $displayKey = $_.PSPath
                Get-ChildItem $displayKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $monitorProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($monitorProps) {
                        $monitors += [PSCustomObject]@{
                            MonitorID = $_.PSChildName
                            FriendlyName = if ($monitorProps.FriendlyName) { $monitorProps.FriendlyName } else { "Unknown Display" }
                            DeviceDesc = if ($monitorProps.DeviceDesc) { $monitorProps.DeviceDesc } else { "N/A" }
                            Mfg = if ($monitorProps.Mfg) { $monitorProps.Mfg } else { "N/A" }
                            DetectionMethod = "Registry Fallback"
                        }
                    }
                }
            }
        }
        # If still empty, provide info message
        if ($monitors.Count -eq 0) {
            $monitors = @([PSCustomObject]@{
                MonitorID = "No monitors detected"
                FriendlyName = "WmiMonitorBasicDisplayParams not available on this system"
                DeviceDesc = "Use 'dxdiag' or Display Settings to view connected monitors"
                Mfg = "N/A"
                DetectionMethod = "Unavailable"
            })
        }
    }
}
Write-Log "MONITORS CURRENTLY CONNECTED" $monitors "Monitors"

# Storage devices currently attached
$storage = @()
try {
    $storage = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions
} catch {
    $storage = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions
}
Write-Log "PHYSICAL STORAGE DRIVES" $storage "Storage_Drives"

# Network adapters
$netAdapters = @()
try {
    $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | 
        Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, MediaConnectionState
} catch {
    $netAdapters = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue | 
        Where-Object { $_.NetConnectionStatus -eq 2 } |
        Select-Object Name, @{N='InterfaceDescription';E={$_.Description}}, MacAddress, @{N='LinkSpeed';E={$_.Speed}}, @{N='MediaConnectionState';E={'Connected'}}
}
Write-Log "ACTIVE NETWORK ADAPTERS" $netAdapters "Network_Adapters"

# Bluetooth devices
$bluetooth = @()
try {
    $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object Name, InstanceId, Status
} catch {
    try {
        $bluetooth = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | 
            Where-Object { $_.PNPClass -eq 'Bluetooth' -and $_.Status -eq 'OK' } |
            Select-Object Name, DeviceID, Status
    } catch {
        $bluetooth = @([PSCustomObject]@{Note="No Bluetooth devices found or Bluetooth disabled"; Status="N/A"})
    }
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
$net = @()
try {
    $net = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq "Established" } | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
        @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess
} catch {
    $netstat = netstat -ano | Select-String "ESTABLISHED"
    $net = $netstat | ForEach-Object {
        $parts = ($_ -split '\s+') | Where-Object { $_ }
        if ($parts.Count -ge 5) {
            [PSCustomObject]@{
                LocalAddress = $parts[1]
                RemoteAddress = $parts[2]
                State = "ESTABLISHED"
                OwningProcess = $parts[4]
                Process = (Get-Process -Id $parts[4] -ErrorAction SilentlyContinue).ProcessName
            }
        }
    }
}
Write-Log "Active Connections" $net "Network_Connections"

# ========== SCHEDULED TASKS ==========
$tasks = @()
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" } | 
        Select-Object TaskName, Author, @{N='Action';E={($_.Actions|Select-Object -First 1).Execute}}, State
} catch {
    $schtasks = schtasks /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.'Run As User' -ne 'N/A' }
    $tasks = $schtasks | Select-Object @{N='TaskName';E={$_.TaskName}}, @{N='Author';E={$_.'Run As User'}}, @{N='Action';E={$_.'Task To Run'}}, @{N='State';E={$_.'Scheduled Task State'}}
}
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
$wmiBindings = @()
try {
    $wmiBindings = Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription -ErrorAction Stop
} catch {
    $wmiBindings = Get-WmiObject __FilterToConsumerBinding -Namespace root/subscription -ErrorAction SilentlyContinue
}
Write-Log "WMI Event Bindings" $wmiBindings "WMI_Bindings"

# ========== COMPLETION ==========
$summary = @"
AUDIT COMPLETE: $(Get-Date)
Log: $LogFile
CSV Folder: $CsvFolder

WINDOWS INSTALL DATE: $(if($osInfo.InstallDateFormatted){$osInfo.InstallDateFormatted}else{"Unknown"})
SYSTEM UPTIME: $(if($osInfo.Uptime){$osInfo.Uptime}else{"Unknown"})
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
Add-Content -Path $LogFile -Value "`n$summary" -ErrorAction SilentlyContinue

if (-not $Silent) {
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    if ($osInfo.InstallDateFormatted) {
        Write-Host "Windows Installed: $($osInfo.InstallDateFormatted) ($($osInfo.DaysSinceInstall) days ago)" -ForegroundColor Cyan
    }
    Write-Host "Currently Plugged In: $($pluggedUSB.Count) USB, $($hidDevices.Count) HID, $($monitors.Count) Monitors" -ForegroundColor Cyan
    Write-Host "Log: $LogFile" -ForegroundColor Cyan
    Write-Host "CSV: $CsvFolder" -ForegroundColor Cyan
}
