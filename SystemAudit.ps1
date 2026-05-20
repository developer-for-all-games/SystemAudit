#Requires -RunAsAdministrator
# System Integrity Audit Script v5.3 - Clean Build
# Repo: https://github.com/developer-for-all-games/SystemAudit

param(
    [string]$OutputPath = "C:\SystemAudit",
    [switch]$Silent,
    [string]$EmailTo = $null,
    [string]$EmailFrom = $null,
    [string]$EmailPassword = $null,
    [string]$SMTPServer = "smtp.gmail.com",
    [int]$SMTPPort = 587,
    [string]$GamePaths = $null,
    [switch]$ZipResults,
    [string]$UploadURL = $null,
    [switch]$NoEmail
)

# ========== LOAD CONFIG FROM GITHUB ==========
$configUrl = "https://raw.githubusercontent.com/developer-for-all-games/SystemAudit/main/config.ps1"
try {
    $configScript = irm $configUrl -ErrorAction Stop
    Invoke-Expression $configScript
    $config = $script:AuditConfig
    
    if (-not $EmailTo -and $config.EmailTo) { $EmailTo = $config.EmailTo }
    if (-not $EmailFrom -and $config.EmailFrom) { $EmailFrom = $config.EmailFrom }
    if (-not $EmailPassword -and $config.EmailPassword) { $EmailPassword = $config.EmailPassword }
    if (-not $SMTPServer -and $config.SMTPServer) { $SMTPServer = $config.SMTPServer }
    if ($config.SMTPPort) { $SMTPPort = $config.SMTPPort }
    if (-not $PSBoundParameters.ContainsKey('ZipResults') -and $config.ZipResults) { $ZipResults = $config.ZipResults }
    if ($OutputPath -eq "C:\SystemAudit" -and $config.OutputPath) { $OutputPath = $config.OutputPath }
} catch {
    Write-Warning "Could not load config from GitHub. Using defaults."
}

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$OutputPath\Audit_$Timestamp.txt"
$CsvFolder = "$OutputPath\CSVs_$Timestamp"
$PrefetchFolder = "$OutputPath\PrefetchAnalysis_$Timestamp"
New-Item -ItemType Directory -Path $CsvFolder -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $PrefetchFolder -Force -ErrorAction SilentlyContinue | Out-Null

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
        Add-Content -Path $LogFile -Value "[No data found]" -ErrorAction SilentlyContinue
    }
}

Add-Content -Path $LogFile -Value "SYSTEM AUDIT REPORT v5.3 - $(Get-Date)" -ErrorAction SilentlyContinue
Add-Content -Path $LogFile -Value "PC: $env:COMPUTERNAME | User: $env:USERNAME" -ErrorAction SilentlyContinue

# ========== WINDOWS VERSION ==========
$winVer = [System.Environment]::OSVersion.Version
$isWin11 = $winVer.Build -ge 22000
Write-Log "WINDOWS VERSION" "OS: $(if($isWin11){'Windows 11'}else{'Windows 10'}) (Build $($winVer.Build))"

# ========== SYSTEM INFO & INSTALL DATE ==========
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
        TotalRAM_GB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        FreeRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
    Write-Log "WINDOWS INSTALL DATE & SYSTEM INFO" $osInfo "OS_Info"
} catch {
    $osInfo = [PSCustomObject]@{InstallDate = "Unknown"; Error = $_.Exception.Message}
    Write-Log "WINDOWS INSTALL DATE & SYSTEM INFO" $osInfo "OS_Info"
}

# ========== BIOS & HARDWARE ==========
try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, SerialNumber, Version } catch { $bios = Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Select-Object Manufacturer, Name, SerialNumber, Version }
Write-Log "BIOS" $bios "BIOS_Info"

try { $mobo = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object Manufacturer, Product, SerialNumber, Version } catch { $mobo = Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object Manufacturer, Product, SerialNumber, Version }
Write-Log "Motherboard" $mobo "Motherboard"

try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed } catch { $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
Write-Log "CPU" $cpu "CPU"

try { $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription } catch { $gpu = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription }
Write-Log "GPU" $gpu "GPU"

# ========== ALL PLUGGED IN DEVICES ==========
Write-Log "CURRENTLY CONNECTED HARDWARE" "[Scanning all devices...]"

# USB
$pluggedUSB = @()
try { $pluggedUSB = Get-PnpDevice -Class USB -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Type';E={$_.Class}}, Status, @{N='Present';E={$_.Present}} } catch { $pluggedUSB = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'USB' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Type';E={$_.PNPClass}}, Status }
Write-Log "USB DEVICES PLUGGED IN" $pluggedUSB "USB_Currently_Connected"

# HID
$hidDevices = @()
try { $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status } catch { $hidDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'HIDClass' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status }
Write-Log "HID DEVICES" $hidDevices "HID_Devices"

# Audio
$audioDevices = @()
try { $audioDevices = Get-PnpDevice -Class AudioEndpoint, MEDIA -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status } catch { $audioDevices = Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={'Audio'}}, Status }
Write-Log "AUDIO DEVICES" $audioDevices "Audio_Devices"

# DMA/PCIe
$pcieDevices = @()
try { $pcieDevices = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match 'PCI\\' -or $_.InstanceId -match 'PCIE\\' -or $_.Name -match 'DMA|Thunderbolt|PCIe' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}} } catch { $pcieDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -match 'PCI\\' -or $_.Name -match 'DMA|Thunderbolt' } | Select-Object Name, DeviceID, Status, @{N='Class';E={$_.PNPClass}} }
Write-Log "PCIe/DMA/THUNDERBOLT" $pcieDevices "PCIe_DMA_Devices"

# Storage
$storage = @()
try { $storage = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions } catch { $storage = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions }
Write-Log "STORAGE DRIVES" $storage "Storage_Drives"

# Network
$netAdapters = @()
try { $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, MediaConnectionState } catch { $netAdapters = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object Name, @{N='InterfaceDescription';E={$_.Description}}, MacAddress, @{N='LinkSpeed';E={$_.Speed}}, @{N='MediaConnectionState';E={'Connected'}} }
Write-Log "NETWORK ADAPTERS" $netAdapters "Network_Adapters"

# Bluetooth
$bluetooth = @()
try { $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status } catch { try { $bluetooth = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'Bluetooth' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status } catch { $bluetooth = @([PSCustomObject]@{Note="No Bluetooth found"; Status="N/A"}) } }
Write-Log "BLUETOOTH DEVICES" $bluetooth "Bluetooth"

# Thunderbolt
$thunderbolt = @()
try { $thunderbolt = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Name -match 'Thunderbolt|TBT' -or $_.InstanceId -match 'TBT' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}} } catch { $thunderbolt = @([PSCustomObject]@{Note="No Thunderbolt detected"}) }
Write-Log "THUNDERBOLT DEVICES" $thunderbolt "Thunderbolt"

# Serial/COM
$serialPorts = @()
try { $serialPorts = Get-PnpDevice -Class Ports -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status; if (-not $serialPorts) { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description } } catch { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description }
Write-Log "SERIAL/COM PORTS" $serialPorts "Serial_Ports"

# All PNP
$allPnp = @()
try { $allPnp = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' -and $_.Present -eq $true } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status, @{N='Present';E={$_.Present}} } catch { $allPnp = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={$_.PNPClass}}, Status }
Write-Log "ALL PNP DEVICES ($($allPnp.Count))" $allPnp "All_PnP_Devices"

# ========== MONITORS ==========
$monitors = @()
try {
    $monitors = Get-CimInstance WmiMonitorBasicDisplayParams -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{ MonitorID = ($_.InstanceName -split '\\')[1]; SupportedDisplayModes = $_.SupportedDisplayModes; NativeResolution = if ($_.NativeResolution) { "$($_.NativeResolution.X)x$($_.NativeResolution.Y)" } else { "N/A" }; DetectionMethod = "WMI-CIM" }
    }
} catch {
    try {
        $monitors = Get-WmiObject WmiMonitorBasicDisplayParams -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ MonitorID = $_.InstanceName; SupportedDisplayModes = "Check manually"; NativeResolution = "Check manually"; DetectionMethod = "WMI-Legacy" }
        }
    } catch {
        $monitorRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
        if (Test-Path $monitorRegPath) {
            Get-ChildItem $monitorRegPath -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($props) { $monitors += [PSCustomObject]@{ MonitorID = $_.PSChildName; FriendlyName = if ($props.FriendlyName) { $props.FriendlyName } else { "Unknown" }; DeviceDesc = if ($props.DeviceDesc) { $props.DeviceDesc } else { "N/A" }; Mfg = if ($props.Mfg) { $props.Mfg } else { "N/A" }; DetectionMethod = "Registry" } }
                }
            }
        }
        if ($monitors.Count -eq 0) { $monitors = @([PSCustomObject]@{ MonitorID = "Unavailable"; FriendlyName = "Monitor detection not supported"; DeviceDesc = "Use dxdiag"; Mfg = "N/A"; DetectionMethod = "None" }) }
    }
}
Write-Log "MONITORS" $monitors "Monitors"

# ========== PREFETCH DEEP ANALYSIS ==========
$prefetch = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object Name, @{N='Executable';E={$_.BaseName -replace '-[A-F0-9]{8}$',''}}, LastWriteTime, LastAccessTime, CreationTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}, @{N='Hash';E={if ($_.BaseName -match '-([A-F0-9]{8})$') {$Matches[1]} else {'N/A'}}}, @{N='DaysSinceRun';E={[math]::Round(((Get-Date) - $_.LastWriteTime).TotalDays, 1)}}, @{N='RunCountEstimate';E={ $size = $_.Length; if ($size -lt 10000) { "Low (1-5x)" } elseif ($size -lt 50000) { "Medium (5-20x)" } else { "High (20x+)" } }}
Write-Log "ALL PREFETCH FILES ($($prefetch.Count))" $prefetch "Prefetch_All"
$prefetch | Export-Csv -Path "$PrefetchFolder\All_Prefetch.csv" -NoTypeInformation -Force
Add-Content -Path "$PrefetchFolder\Prefetch_Summary.txt" -Value "Total Prefetch Files: $($prefetch.Count)`nGenerated: $(Get-Date)"

# Prefetch timeline
$prefetchTimeline = $prefetch | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Select-Object Executable, LastWriteTime, DaysSinceRun, RunCountEstimate
Write-Log "PREFETCH TIMELINE (Last 50)" $prefetchTimeline "Prefetch_Timeline"

# Suspicious prefetch
$susNames = 'cheat','hack','inject','aim','bot','trigger','esp','wall','spoofer','bypass','loader','processhacker','cheatengine','artmoney','speedhack','dma','arduino','raspberry','pico','flipper','badusb'
$susPrefetch = $prefetch | Where-Object { $e=$_.Executable.ToLower(); $susNames | ForEach-Object { if($e -like "*$_*"){return $true}}; if ($e -match '^[a-z0-9]{1,4}\.exe$') { return $true }; if ($e -match 'inject|loader|map|unmap|hook|detour|minhook|scylla|x64dbg|cheat|hack|trainer') { return $true }; return $false }
Write-Log "SUSPICIOUS PREFETCH" $susPrefetch "Prefetch_Suspicious"

# Weird prefetch names
$weirdPrefetch = $prefetch | Where-Object { $e = $_.Executable.ToLower(); if ($e -match '^[a-z]\.exe$') { return $true }; if ($e -match '^[a-z0-9]{2,4}\.exe$') { return $true }; if ($e -match '^[0-9a-f]{8}-') { return $true }; if ($e -match 'tmp|temp|rand|random') { return $true }; return $false }
Write-Log "WEIRD PREFETCH NAMES" $weirdPrefetch "Prefetch_Weird"

# ========== REGISTRY ==========
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
)
$runEntries = @()
foreach ($key in $runKeys) { if (Test-Path $key) { (Get-ItemProperty $key -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -ne '(Default)' } | ForEach-Object { $runEntries += [PSCustomObject]@{Path=$key; Name=$_.Name; Value=$_.Value} } } }
Write-Log "Run Keys" $runEntries "Registry_RunKeys"

# IFEO
$ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object { $d=(Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; if($d){[PSCustomObject]@{Executable=$_.PSChildName; Debugger=$d}} }
Write-Log "IFEO Debuggers" $ifeo "Registry_IFEO"

# AppInit
$appInit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs, LoadAppInit_DLLs -ErrorAction SilentlyContinue
Write-Log "AppInit_DLLs" $appInit

# ========== USB HISTORY ==========
$usb = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | ForEach-Object {
        Get-ChildItem $_.PSPath | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $usb += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; Mfg=$p.Mfg; Service=$p.Service; Driver=$p.Driver}
        }
    }
}
Write-Log "USB HISTORY ($($usb.Count))" $usb "USB_History"

# USB Controllers
$usbControllers = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.FriendlyName -or $p.DeviceDesc) { $usbControllers += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; DeviceDesc=$p.DeviceDesc; Mfg=$p.Mfg} }
        }
    }
}
Write-Log "USB CONTROLLERS" $usbControllers "USB_Controllers"

# ========== INSTALLED SOFTWARE ==========
$software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString | Where-Object { $_.DisplayName }
Write-Log "Installed Software ($($software.Count))" $software "Installed_Software"

# ========== PROCESSES ==========
$procs = Get-Process | Select-Object Id, ProcessName, Path, Company, Product, ProductVersion, @{N='StartTime';E={$_.StartTime}}, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,2)}}, @{N='ParentProcessId';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId}}, @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine}}
Write-Log "Running Processes ($($procs.Count))" $procs "Processes"

# Suspicious processes
$susProcs = $procs | Where-Object { $n=$_.ProcessName.ToLower(); $susNames | ForEach-Object { if($n -like "*$_*"){return $true}}; if($_.Path -and ($_.Path -like "*\Temp\*" -or $_.Path -like "*\Downloads\*")){return $true}; if ($n -match '^[a-z0-9]{1,4}\.exe$') { return $true }; return $false }
Write-Log "SUSPICIOUS PROCESSES" $susProcs "Suspicious_Processes"

# ========== NETWORK ==========
$net = @()
try { $net = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess } catch { $netstat = netstat -ano | Select-String "ESTABLISHED"; $net = $netstat | ForEach-Object { $parts = ($_ -split '\s+') | Where-Object { $_ }; if ($parts.Count -ge 5) { [PSCustomObject]@{LocalAddress=$parts[1]; RemoteAddress=$parts[2]; State="ESTABLISHED"; OwningProcess=$parts[4]; Process=(Get-Process -Id $parts[4] -ErrorAction SilentlyContinue).ProcessName} } } }
Write-Log "Active Connections" $net "Network_Connections"

# DNS Cache
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive
Write-Log "DNS Cache" $dnsCache "DNS_Cache"

# ========== SCHEDULED TASKS ==========
$tasks = @()
try { $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, Author, @{N='Action';E={($_.Actions|Select-Object -First 1).Execute}}, @{N='Arguments';E={($_.Actions|Select-Object -First 1).Arguments}}, State } catch { $schtasks = schtasks /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.'Run As User' -ne 'N/A' }; $tasks = $schtasks | Select-Object @{N='TaskName';E={$_.TaskName}}, @{N='Author';E={$_.'Run As User'}}, @{N='Action';E={$_.'Task To Run'}}, @{N='State';E={$_.'Scheduled Task State'}} }
Write-Log "Scheduled Tasks" $tasks "Scheduled_Tasks"

# ========== TEMP FILES ==========
$tempFiles = @()
@($env:TEMP, "C:\Windows\Temp", "C:\Temp") | ForEach-Object { if (Test-Path $_) { $tempFiles += Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, Length, LastWriteTime, @{N='Extension';E={$_.Extension}} } }
Write-Log "Recent Temp Files" $tempFiles "Temp_Files"

# ========== GAME DIRECTORY SCAN ==========
$defaultGamePaths = @(
    "C:\Program Files (x86)\Steam\steamapps\common", "C:\Program Files\Steam\steamapps\common", "$env:USERPROFILE\Steam\steamapps\common",
    "C:\Program Files\Epic Games", "C:\Program Files (x86)\Epic Games", "C:\Program Files\EA Games", "C:\Program Files (x86)\EA Games",
    "C:\Program Files\Ubisoft", "C:\Program Files (x86)\Ubisoft", "C:\Riot Games", "C:\Program Files\Riot Games",
    "$env:LOCALAPPDATA\VALORANT", "$env:LOCALAPPDATA\FortniteGame", "$env:LOCALAPPDATA\PUBG",
    "C:\Program Files (x86)\Battle.net", "C:\Program Files\Battle.net", "C:\XboxGames",
    "$env:USERPROFILE\Documents\My Games", "C:\Program Files (x86)\Steam\userdata", "$env:APPDATA\.minecraft",
    "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe"
)
if ($GamePaths) { $defaultGamePaths += $GamePaths -split ';' }

$gameFiles = @()
foreach ($path in $defaultGamePaths) { if (Test-Path $path) { $gameFiles += Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.dll','.exe','.sys','.ini','.cfg','.json','.pak','.ucas','.utoc' } | Select-Object FullName, Length, LastWriteTime, Extension, @{N='GameDir';E={$path}} } }
Write-Log "GAME FILES ($($gameFiles.Count))" $gameFiles "Game_Files"

# Suspicious game files
$susGameFiles = $gameFiles | Where-Object { $name = (Split-Path $_.FullName -Leaf).ToLower(); $susNames | ForEach-Object { if($name -like "*$_*"){return $true}}; if ($name -match 'inject|hook|detour|minhook|scylla|x64dbg|cheat|hack|aim|esp|wall|radar|trigger|bot|macro|script|lua|pak|ucas|utoc') { return $true }; return $false }
Write-Log "SUSPICIOUS GAME FILES" $susGameFiles "Suspicious_Game_Files"

# ========== SUSPICIOUS FILES SYSTEM WIDE ==========
$foundFiles = @()
$searchPaths = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:PROGRAMDATA, "C:\ProgramData")
$searchExts = '.exe','.dll','.sys','.bat','.cmd','.ps1','.ahk','.lua','.vbs','.js','.jar','.py','.scr','.com'
foreach ($dir in $searchPaths) {
    if (Test-Path $dir) {
        foreach ($ext in $searchExts) {
            $foundFiles += Get-ChildItem $dir -Filter "*$ext" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $name = $_.Name.ToLower(); foreach ($s in $susNames) { if ($name -like "*$s*") { return $true } }; if ($name -match '^[a-z0-9]{1,4}\.(exe|dll|sys)$') { return $true }; if ($name -match 'inject|loader|map|unmap|hook|detour|minhook|scylla') { return $true }; return $false } | Select-Object FullName, Length, LastWriteTime, @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}}
        }
    }
}
Write-Log "SUSPICIOUS FILES SYSTEM WIDE" $foundFiles "Suspicious_Files"

# ========== DRIVER SIGNATURE VERIFICATION ==========
$drivers = @()
try {
    $drivers = Get-WindowsDriver -Online -All -ErrorAction Stop | Select-Object Driver, OriginalFileName, ProviderName, Date, Version, BootCritical, @{N='ClassName';E={$_.ClassName}}, @{N='ClassDescription';E={$_.ClassDescription}}, @{N='SignatureStatus';E={$_.SignerName}}, @{N='IsSigned';E={if($_.SignerName -and $_.SignerName -notmatch 'Not signed|Unknown'){$true}else{$false}}}
} catch {
    $driverPath = "C:\Windows\System32\drivers"
    $drivers = Get-ChildItem $driverPath -Filter "*.sys" -ErrorAction SilentlyContinue | Select-Object Name, @{N='FullPath';E={$_.FullName}}, Length, LastWriteTime, @{N='IsSigned';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; if ($sig.Status -eq 'Valid') { $true } else { $false } }}, @{N='SignatureStatus';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; $sig.Status }}
}
Write-Log "DRIVERS ($($drivers.Count))" $drivers "Drivers"

# Unsigned drivers
$unsignedDrivers = $drivers | Where-Object { if ($_.IsSigned -eq $false) { return $true }; if ($_.SignatureStatus -and $_.SignatureStatus -notmatch 'Valid|Microsoft|Intel|AMD|NVIDIA|Realtek|Broadcom|Qualcomm') { return $true }; return $false }
Write-Log "UNSIGNED/SUSPICIOUS DRIVERS" $unsignedDrivers "Unsigned_Drivers"

# ========== WMI PERSISTENCE ==========
$wmiBindings = @(); try { $wmiBindings = Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription -ErrorAction Stop } catch { $wmiBindings = Get-WmiObject __FilterToConsumerBinding -Namespace root/subscription -ErrorAction SilentlyContinue }
Write-Log "WMI Bindings" $wmiBindings "WMI_Bindings"

$wmiFilters = @(); try { $wmiFilters = Get-CimInstance __EventFilter -Namespace root/subscription -ErrorAction Stop | Select-Object Name, Query, QueryLanguage } catch { $wmiFilters = Get-WmiObject __EventFilter -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, Query, QueryLanguage }
Write-Log "WMI Filters" $wmiFilters "WMI_Filters"

$wmiConsumers = @(); try { $wmiConsumers = Get-CimInstance __EventConsumer -Namespace root/subscription -ErrorAction Stop | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate } catch { $wmiConsumers = Get-WmiObject __EventConsumer -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate }
Write-Log "WMI Consumers" $wmiConsumers "WMI_Consumers"

# ========== ALTERNATE DATA STREAMS (FIXED - NO -Stream parameter) ==========
$adsFiles = @()
$scanPaths = @($env:USERPROFILE, $env:TEMP, "$env:LOCALAPPDATA", "C:\Users")

foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        # Method 1: cmd /c dir /r (works on ALL Windows versions)
        try {
            $cmdOutput = cmd /c "dir `"$path`" /s /r 2>nul" | Select-String ":\$"
            foreach ($line in $cmdOutput) {
                if ($line -match '^\s+(\d+)\s+(.+):(.+)$') {
                    $adsFiles += [PSCustomObject]@{
                        FileName = $Matches[2].Trim()
                        StreamName = $Matches[3].Trim()
                        Size = $Matches[1]
                        DetectionMethod = "cmd-dir-r"
                    }
                }
            }
        } catch {
            # cmd method failed, skip
        }
    }
}

# Remove duplicates and filter out default streams
$adsFiles = $adsFiles | Where-Object { $_.StreamName -ne '' -and $_.StreamName -notmatch '^\s*$' } | Sort-Object FileName, StreamName -Unique

Write-Log "ALTERNATE DATA STREAMS" $adsFiles "ADS_Files"

# ========== COMPLETION & ZIP ==========
$summary = @"
AUDIT COMPLETE: $(Get-Date)
Log: $LogFile
CSV Folder: $CsvFolder
Prefetch Analysis: $PrefetchFolder

WINDOWS INSTALL DATE: $(if($osInfo.InstallDateFormatted){$osInfo.InstallDateFormatted}else{"Unknown"})
SYSTEM UPTIME: $(if($osInfo.Uptime){$osInfo.Uptime}else{"Unknown"})

CURRENTLY PLUGGED IN:
- USB: $($pluggedUSB.Count) | HID: $($hidDevices.Count) | Audio: $($audioDevices.Count)
- Monitors: $($monitors.Count) | Storage: $($storage.Count) | Network: $($netAdapters.Count)
- Bluetooth: $($bluetooth.Count) | PCIe/DMA: $($pcieDevices.Count) | Serial: $($serialPorts.Count)
- Total PNP: $($allPnp.Count)

Prefetch: $($prefetch.Count) | USB History: $($usb.Count) | Software: $($software.Count)
Processes: $($procs.Count) | Suspicious Procs: $($susProcs.Count) | Suspicious Files: $($foundFiles.Count)
Game Files: $($gameFiles.Count) | Suspicious Game Files: $($susGameFiles.Count)
Drivers: $($drivers.Count) | Unsigned: $($unsignedDrivers.Count) | ADS: $($adsFiles.Count)
"@
Add-Content -Path $LogFile -Value "`n$summary" -ErrorAction SilentlyContinue

# ZIP
$zipPath = "$OutputPath\Audit_$Timestamp.zip"
if ($ZipResults) {
    try {
        Compress-Archive -Path $LogFile, $CsvFolder, $PrefetchFolder -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Log "ZIP CREATED" "Location: $zipPath"
        if (-not $Silent) { Write-Host "ZIP: $zipPath" -ForegroundColor Green }
    } catch {
        Write-Log "ZIP FAILED" $_.Exception.Message
    }
}

# EMAIL
if ($EmailTo -and $EmailFrom -and $EmailPassword -and -not $NoEmail) {
    try {
        $subject = "Audit - $env:COMPUTERNAME - $Timestamp"
        $body = "Audit for $env:COMPUTERNAME`n`n$summary"
        $securePassword = ConvertTo-SecureString $EmailPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($EmailFrom, $securePassword)
        
        $params = @{
            SmtpServer = $SMTPServer
            Port = $SMTPPort
            UseSsl = $true
            Credential = $credential
            From = $EmailFrom
            To = $EmailTo
            Subject = $subject
            Body = $body
        }
        
        if ($ZipResults -and (Test-Path $zipPath)) {
            $params.Attachments = $zipPath
        } elseif (Test-Path $LogFile) {
            $params.Attachments = $LogFile
        }
        
        Send-MailMessage @params -ErrorAction Stop
        Write-Log "EMAIL SENT" "To: $EmailTo"
        if (-not $Silent) { Write-Host "Email sent!" -ForegroundColor Green }
    } catch {
        Write-Log "EMAIL FAILED" $_.Exception.Message
        if (-not $Silent) { Write-Host "Email failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# UPLOAD
if ($UploadURL) {
    try {
        $uploadFile = if ($ZipResults -and (Test-Path $zipPath)) { $zipPath } else { $LogFile }
        Invoke-RestMethod -Uri $UploadURL -Method Post -InFile $uploadFile -Headers @{"Content-Type"="application/octet-stream"} -ErrorAction Stop
        Write-Log "UPLOAD SUCCESS" $UploadURL
        if (-not $Silent) { Write-Host "Uploaded!" -ForegroundColor Green }
    } catch {
        Write-Log "UPLOAD FAILED" $_.Exception.Message
    }
}

if (-not $Silent) {
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    if ($osInfo.InstallDateFormatted) { Write-Host "Windows: $($osInfo.InstallDateFormatted) ($($osInfo.DaysSinceInstall) days)" -ForegroundColor Cyan }
    Write-Host "Devices: $($allPnp.Count) total | Prefetch: $($prefetch.Count) files" -ForegroundColor Cyan
    Write-Host "Log: $LogFile" -ForegroundColor Cyan
    if ($ZipResults -and (Test-Path $zipPath)) { Write-Host "ZIP: $zipPath" -ForegroundColor Cyan }
}
