#Requires -RunAsAdministrator
# =============================================================================
#  SYSTEM INTEGRITY AUDIT SCRIPT v6.0
#  Enhanced Forensics Suite with AI Bot Detection
#  Repo: https://github.com/developer-for-all-games/SystemAudit
#  Run: irm "https://raw.githubusercontent.com/developer-for-all-games/SystemAudit/main/SystemAudit.ps1" | iex
# =============================================================================

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

# =============================================================================
#  CONFIG LOADER
# =============================================================================
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

# =============================================================================
#  SETUP OUTPUT
# =============================================================================
New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$OutputPath\Audit_$Timestamp.txt"
$CsvFolder = "$OutputPath\CSVs_$Timestamp"
$PrefetchFolder = "$OutputPath\PrefetchAnalysis_$Timestamp"
New-Item -ItemType Directory -Path $CsvFolder -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $PrefetchFolder -Force -ErrorAction SilentlyContinue | Out-Null

# =============================================================================
#  LOGGING FUNCTIONS
# =============================================================================
function Write-Log {
    param([string]$Header, [object]$Data, [string]$CsvName = $null)
    $separator = "=" * 80
    Add-Content -Path $LogFile -Value "`n`n$separator`n  >> $Header`n$separator" -ErrorAction SilentlyContinue
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

function Write-Banner {
    param([string]$Text)
    $banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║  $Text$(" " * (76 - $Text.Length))║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Add-Content -Path $LogFile -Value $banner -ErrorAction SilentlyContinue
}

function Write-Section {
    param([string]$Title)
    Add-Content -Path $LogFile -Value "`n┌─────────────────────────────────────────────────────────────────────────────┐`n│  $Title$(" " * (75 - $Title.Length))│`n└─────────────────────────────────────────────────────────────────────────────┘" -ErrorAction SilentlyContinue
}

function Write-WarningBox {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "`n⚠️  WARNING: $Message" -ErrorAction SilentlyContinue
}

function Write-AlertBox {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "`n🚨 ALERT: $Message" -ErrorAction SilentlyContinue
}

# =============================================================================
#  HEADER
# =============================================================================
Add-Content -Path $LogFile -Value @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           SYSTEM INTEGRITY AUDIT REPORT v6.0 - ENHANCED FORENSICS           ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Generated:  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")$(" " * (49 - (Get-Date -Format "yyyy-MM-dd HH:mm:ss").Length))║
║  Computer:  $env:COMPUTERNAME$(" " * (59 - $env:COMPUTERNAME.Length))║
║  User:     $env:USERNAME$(" " * (62 - $env:USERNAME.Length))║
║  Admin:    $([bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544'))$(" " * 69)║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ErrorAction SilentlyContinue

# =============================================================================
#  SECTION 1: SYSTEM INFORMATION
# =============================================================================
Write-Section "SECTION 1: SYSTEM INFORMATION & WINDOWS INSTALL DATE"

$winVer = [System.Environment]::OSVersion.Version
$isWin11 = $winVer.Build -ge 22000
$osName = if ($isWin11) { "Windows 11" } else { "Windows 10" }

Write-Log "OPERATING SYSTEM" "Detected: $osName (Build $($winVer.Build))"

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $installDate = $os.InstallDate
    $uptime = (Get-Date) - $os.LastBootUpTime
    $osInfo = [PSCustomObject]@{
        "OS Name" = $os.Caption
        "Version" = $os.Version
        "Build" = $os.BuildNumber
        "Architecture" = $os.OSArchitecture
        "Install Date" = $installDate.ToString("yyyy-MM-dd HH:mm:ss")
        "Days Since Install" = [math]::Round(((Get-Date) - $installDate).TotalDays, 0)
        "Last Boot" = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        "System Uptime" = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        "Serial Number" = $os.SerialNumber
        "Total RAM (GB)" = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        "Free RAM (GB)" = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
    Write-Log "WINDOWS INSTALL DATE & SYSTEM DETAILS" $osInfo "OS_Info"
} catch {
    Write-WarningBox "Could not retrieve full system information"
    Write-Log "SYSTEM INFO (LIMITED)" "Error: $($_.Exception.Message)"
}

# =============================================================================
#  SECTION 2: HARDWARE & BIOS
# =============================================================================
Write-Section "SECTION 2: HARDWARE & BIOS INFORMATION"

try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, SerialNumber, Version, @{N='ReleaseDate';E={$_.ReleaseDate}} } catch { $bios = Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Select-Object Manufacturer, Name, SerialNumber, Version }
Write-Log "BIOS INFORMATION" $bios "BIOS_Info"

try { $mobo = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object Manufacturer, Product, SerialNumber, Version } catch { $mobo = Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object Manufacturer, Product, SerialNumber, Version }
Write-Log "MOTHERBOARD" $mobo "Motherboard"

try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, @{N='MaxClock(GHz)';E={[math]::Round($_.MaxClockSpeed/1000,2)}} } catch { $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
Write-Log "CPU" $cpu "CPU"

try { $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object Name, @{N='VRAM(GB)';E={[math]::Round($_.AdapterRAM/1GB,2)}}, DriverVersion, @{N='Resolution';E={$_.VideoModeDescription}} } catch { $gpu = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription }
Write-Log "GPU" $gpu "GPU"

# =============================================================================
#  SECTION 3: CONNECTED DEVICES (DEEP SCAN)
# =============================================================================
Write-Section "SECTION 3: CONNECTED DEVICES - DEEP HARDWARE SCAN"
Write-Log "STATUS" "Scanning for USB, HID, PCIe, DMA, Thunderbolt, Serial, Bluetooth..."

# USB Devices
$pluggedUSB = @()
try { $pluggedUSB = Get-PnpDevice -Class USB -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Type';E={$_.Class}}, Status, @{N='Present';E={$_.Present}}, @{N='Problem';E={$_.Problem}} } catch { $pluggedUSB = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'USB' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Type';E={$_.PNPClass}}, Status }
Write-Log "🔌 USB DEVICES CURRENTLY PLUGGED IN ($($pluggedUSB.Count))" $pluggedUSB "USB_Currently_Connected"

# HID Devices
$hidDevices = @()
try { $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status, @{N='Problem';E={$_.Problem}} } catch { $hidDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'HIDClass' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status }
Write-Log "🖱️ HID DEVICES - KEYBOARDS, MICE, CONTROLLERS ($($hidDevices.Count))" $hidDevices "HID_Devices"

# Audio Devices
$audioDevices = @()
try { $audioDevices = Get-PnpDevice -Class AudioEndpoint, MEDIA -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status, @{N='Problem';E={$_.Problem}} } catch { $audioDevices = Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={'Audio'}}, Status }
Write-Log "🔊 AUDIO DEVICES ($($audioDevices.Count))" $audioDevices "Audio_Devices"

# PCIe / DMA / Thunderbolt (CRITICAL FOR CHEAT DETECTION)
$pcieDevices = @()
try { $pcieDevices = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match 'PCI\\|PCIE\\' -or $_.Name -match 'DMA|Thunderbolt|PCIe' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}}, @{N='Problem';E={$_.Problem}} } catch { $pcieDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -match 'PCI\\' -or $_.Name -match 'DMA|Thunderbolt' } | Select-Object Name, DeviceID, Status, @{N='Class';E={$_.PNPClass}} }
if ($pcieDevices.Count -gt 0) { Write-AlertBox "PCIe/DMA devices detected - review carefully!" }
Write-Log "⚡ PCIe / DMA / THUNDERBOLT DEVICES ($($pcieDevices.Count))" $pcieDevices "PCIe_DMA_Devices"

# Storage
$storage = @()
try { $storage = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object Model, @{N='Size(GB)';E={[math]::Round($_.Size/1GB,2)}}, InterfaceType, MediaType, SerialNumber, Partitions } catch { $storage = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions }
Write-Log "💾 STORAGE DRIVES ($($storage.Count))" $storage "Storage_Drives"

# Network
$netAdapters = @()
try { $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, MediaConnectionState } catch { $netAdapters = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object Name, @{N='InterfaceDescription';E={$_.Description}}, MacAddress, @{N='LinkSpeed';E={$_.Speed}}, @{N='MediaConnectionState';E={'Connected'}} }
Write-Log "🌐 NETWORK ADAPTERS ($($netAdapters.Count))" $netAdapters "Network_Adapters"

# Bluetooth
$bluetooth = @()
try { $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status, @{N='Problem';E={$_.Problem}} } catch { try { $bluetooth = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'Bluetooth' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status } catch { $bluetooth = @([PSCustomObject]@{Note="No Bluetooth found"; Status="N/A"}) } }
Write-Log "📶 BLUETOOTH DEVICES ($($bluetooth.Count))" $bluetooth "Bluetooth"

# Thunderbolt
$thunderbolt = @()
try { $thunderbolt = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Name -match 'Thunderbolt|TBT' -or $_.InstanceId -match 'TBT' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}} } catch { $thunderbolt = @([PSCustomObject]@{Note="No Thunderbolt detected"}) }
Write-Log "🔌 THUNDERBOLT DEVICES ($($thunderbolt.Count))" $thunderbolt "Thunderbolt"

# Serial/COM Ports
$serialPorts = @()
try { $serialPorts = Get-PnpDevice -Class Ports -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status; if (-not $serialPorts) { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description } } catch { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description }
Write-Log "🔌 SERIAL / COM PORTS ($($serialPorts.Count))" $serialPorts "Serial_Ports"

# ALL PNP DEVICES
$allPnp = @()
try { $allPnp = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' -and $_.Present -eq $true } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status, @{N='Problem';E={$_.Problem}}, @{N='Present';E={$_.Present}} } catch { $allPnp = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={$_.PNPClass}}, Status }
Write-Log "📋 ALL PLUGGED IN PNP DEVICES ($($allPnp.Count))" $allPnp "All_PnP_Devices"

# =============================================================================
#  SECTION 4: MONITORS
# =============================================================================
Write-Section "SECTION 4: DISPLAY DEVICES"

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
        if ($monitors.Count -eq 0) { $monitors = @([PSCustomObject]@{ MonitorID = "Unavailable"; FriendlyName = "Monitor detection not supported"; DeviceDesc = "Use dxdiag or Display Settings"; Mfg = "N/A"; DetectionMethod = "None" }) }
    }
}
Write-Log "🖥️ MONITORS CURRENTLY CONNECTED ($($monitors.Count))" $monitors "Monitors"

# =============================================================================
#  SECTION 5: PREFETCH DEEP ANALYSIS
# =============================================================================
Write-Section "SECTION 5: PREFETCH FORENSICS - EXECUTION HISTORY"

$prefetch = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object Name, @{N='Executable';E={$_.BaseName -replace '-[A-F0-9]{8}$',''}}, LastWriteTime, LastAccessTime, CreationTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}, @{N='Hash';E={if ($_.BaseName -match '-([A-F0-9]{8})$') {$Matches[1]} else {'N/A'}}}, @{N='DaysSinceRun';E={[math]::Round(((Get-Date) - $_.LastWriteTime).TotalDays, 1)}}, @{N='RunCountEstimate';E={ $size = $_.Length; if ($size -lt 10000) { "Low (1-5x)" } elseif ($size -lt 50000) { "Medium (5-20x)" } else { "High (20x+)" } }}

Write-Log "📁 ALL PREFETCH FILES ($($prefetch.Count) total)" $prefetch "Prefetch_All"
$prefetch | Export-Csv -Path "$PrefetchFolder\All_Prefetch.csv" -NoTypeInformation -Force
Add-Content -Path "$PrefetchFolder\Prefetch_Summary.txt" -Value "Total Prefetch Files: $($prefetch.Count)`nGenerated: $(Get-Date)`n`nFull data exported to All_Prefetch.csv"

# Prefetch Timeline
$prefetchTimeline = $prefetch | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Select-Object Executable, LastWriteTime, DaysSinceRun, RunCountEstimate
Write-Log "📅 PREFETCH TIMELINE (Last 50 Executions)" $prefetchTimeline "Prefetch_Timeline"

# Suspicious Prefetch Detection
$susNames = 'cheat','hack','inject','aim','bot','trigger','esp','wall','spoofer','bypass','loader','processhacker','cheatengine','artmoney','speedhack','dma','arduino','raspberry','pico','flipper','badusb','aimbot','wallhack','radar','macro','script','lua','trainer'
$susPrefetch = $prefetch | Where-Object { $e=$_.Executable.ToLower(); $susNames | ForEach-Object { if($e -like "*$_*"){return $true}}; if ($e -match '^[a-z0-9]{1,4}\.exe$') { return $true }; if ($e -match 'inject|loader|map|unmap|hook|detour|minhook|scylla|x64dbg|cheat|hack|trainer|aim|bot') { return $true }; return $false }
if ($susPrefetch.Count -gt 0) { Write-AlertBox "$($susPrefetch.Count) suspicious prefetch files detected!" }
Write-Log "🚨 SUSPICIOUS PREFETCH FILES ($($susPrefetch.Count))" $susPrefetch "Prefetch_Suspicious"

# Weird Random Names
$weirdPrefetch = $prefetch | Where-Object { $e = $_.Executable.ToLower(); if ($e -match '^[a-z]\.exe$') { return $true }; if ($e -match '^[a-z0-9]{2,4}\.exe$') { return $true }; if ($e -match '^[0-9a-f]{8}-') { return $true }; if ($e -match 'tmp|temp|rand|random') { return $true }; return $false }
if ($weirdPrefetch.Count -gt 0) { Write-WarningBox "$($weirdPrefetch.Count) prefetch files with random/weird names detected!" }
Write-Log "⚠️ WEIRD / RANDOM PREFETCH NAMES ($($weirdPrefetch.Count))" $weirdPrefetch "Prefetch_Weird"

# =============================================================================
#  SECTION 6: AI BOT & AUTOMATION DETECTION
# =============================================================================
Write-Section "SECTION 6: AI BOT, MACRO & AUTOMATION DETECTION"

$aiBotSignatures = @(
    # Known AI aimbot/bot software
    'aimbot','triggerbot','espbot','radarbot','recoilbot','aimassist',
    'pixelbot','colorbot','imagebot','screenbot','memorybot',
    # Macro software
    'autohotkey','ahk','macro','macrogamer','tinytask','mouse recorder',
    'keystroke recorder','input recorder','action recorder',
    # AI/ML frameworks used for cheating
    'tensorflow','pytorch','onnx','opencv','yolo','darknet',
    # Python automation
    'python.*bot','py.*aim','py.*cheat','pycheat','pybot',
    # Known bot platforms
    'synthetic','synthetix','interception','kmbox','km-box',
    'arduino leonardo','pro micro','usb rubber ducky','badusb',
    # Hardware automation
    'dma card','pcileech','screamer','facedancer','greatfet',
    # AI vision
    'tensorrt','cuda.*bot','gpu.*aim','nvidia.*cheat',
    # Mouse/keyboard automation
    'mouse_event','keybd_event','sendinput','interception driver',
    # Specific known tools
    'private cheat','public cheat','unknowncheats','unknown cheat',
    'cheat engine','cheatengine','artmoney','speedhack','x64dbg',
    'ollydbg','ida pro','ghidra','reclass','reclass.net'
)

# Scan processes for AI bot indicators
$aiBotProcesses = $procs | Where-Object {
    $n = $_.ProcessName.ToLower()
    $path = if ($_.Path) { $_.Path.ToLower() } else { "" }
    $company = if ($_.Company) { $_.Company.ToLower() } else { "" }
    
    foreach ($sig in $aiBotSignatures) {
        if ($n -like "*$sig*" -or $path -like "*$sig*" -or $company -like "*$sig*") { return $true }
    }
    # Detect Python running with suspicious arguments
    if ($n -match 'python' -and $_.CommandLine -match 'cv2|opencv|pyautogui|pynput|mss|pillow|numpy') { return $true }
    # Detect AutoHotkey
    if ($n -match 'autohotkey|ahk') { return $true }
    return $false
}

# Scan for automation libraries in Python paths
$pythonSusPaths = @("$env:LOCALAPPDATA\Programs\Python", "C:\Python*", "$env:APPDATA\Python", "$env:USERPROFILE\Anaconda3")
$pythonSusFiles = @()
foreach ($pyPath in $pythonSusPaths) {
    if (Test-Path $pyPath) {
        $pythonSusFiles += Get-ChildItem $pyPath -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match 'cv2|opencv|pyautogui|pynput|mss|pillow|numpy|tensor|torch|onnx|yolo' } | 
            Select-Object FullName, Length, LastWriteTime, @{N='SuspiciousLibrary';E={$_.Name}}
    }
}

# Scan for macro scripts
$macroPaths = @("$env:USERPROFILE\Documents", "$env:APPDATA", "$env:LOCALAPPDATA", "C:\Scripts")
$macroFiles = @()
foreach ($mPath in $macroPaths) {
    if (Test-Path $mPath) {
        $macroFiles += Get-ChildItem $mPath -Recurse -File -ErrorAction SilentlyContinue | 
            Where-Object { $_.Extension -in '.ahk','.macro','.mcr','.json','.xml' -and $_.Name -match 'aim|bot|macro|recoil|trigger|spam|auto' } | 
            Select-Object FullName, Length, LastWriteTime, Extension
    }
}

# Check for interception driver (common in hardware bots)
$interceptionDriver = @()
try {
    $interceptionDriver = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match 'interception' -or $_.DisplayName -match 'interception' } | 
        Select-Object Name, DisplayName, State, StartMode
} catch {}

# Check for suspicious scheduled tasks (automation)
$autoTasks = $tasks | Where-Object { 
    $_.TaskName -match 'bot|macro|auto|script|python|ahk' -or 
    $_.Action -match 'bot|macro|auto|script|python|ahk'
}

if ($aiBotProcesses.Count -gt 0) { Write-AlertBox "$($aiBotProcesses.Count) AI bot / automation processes detected!" }
if ($pythonSusFiles.Count -gt 0) { Write-AlertBox "$($pythonSusFiles.Count) suspicious Python libraries found!" }
if ($macroFiles.Count -gt 0) { Write-AlertBox "$($macroFiles.Count) macro/automation scripts found!" }
if ($interceptionDriver.Count -gt 0) { Write-AlertBox "Interception driver detected - hardware automation possible!" }

Write-Log "🤖 AI BOT / AUTOMATION PROCESSES ($($aiBotProcesses.Count))" $aiBotProcesses "AI_Bot_Processes"
Write-Log "🐍 SUSPICIOUS PYTHON LIBRARIES ($($pythonSusFiles.Count))" $pythonSusFiles "Python_Suspicious_Libraries"
Write-Log "⌨️ MACRO / AUTOMATION SCRIPTS ($($macroFiles.Count))" $macroFiles "Macro_Scripts"
Write-Log "🖱️ INTERCEPTION DRIVER STATUS" $interceptionDriver "Interception_Driver"
Write-Log "⏰ SUSPICIOUS SCHEDULED TASKS ($($autoTasks.Count))" $autoTasks "Suspicious_Auto_Tasks"

# =============================================================================
#  SECTION 7: REGISTRY ANALYSIS
# =============================================================================
Write-Section "SECTION 7: REGISTRY PERSISTENCE & HIJACKING"

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
Write-Log "🔑 RUN KEYS (Startup Persistence)" $runEntries "Registry_RunKeys"

# IFEO Debuggers
$ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object { $d=(Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; if($d){[PSCustomObject]@{Executable=$_.PSChildName; Debugger=$d}} }
if ($ifeo.Count -gt 0) { Write-AlertBox "IFEO Debugger hijacking detected!" }
Write-Log "🎯 IFEO DEBUGGERS (Injection Points)" $ifeo "Registry_IFEO"

# AppInit_DLLs
$appInit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs, LoadAppInit_DLLs -ErrorAction SilentlyContinue
if ($appInit.AppInit_DLLs -and $appInit.AppInit_DLLs -ne "") { Write-AlertBox "AppInit_DLLs is not empty - potential DLL injection!" }
Write-Log "📎 AppInit_DLLs" $appInit

# =============================================================================
#  SECTION 8: USB FORENSICS
# =============================================================================
Write-Section "SECTION 8: USB DEVICE FORENSICS - ALL TIME HISTORY"

$usb = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | ForEach-Object {
        Get-ChildItem $_.PSPath | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $usb += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; Mfg=$p.Mfg; Service=$p.Service; Driver=$p.Driver}
        }
    }
}
Write-Log "💾 USB STORAGE HISTORY ($($usb.Count) devices ever connected)" $usb "USB_History"

$usbControllers = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.FriendlyName -or $p.DeviceDesc) { $usbControllers += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; DeviceDesc=$p.DeviceDesc; Mfg=$p.Mfg} }
        }
    }
}
Write-Log "🔌 USB CONTROLLER HISTORY ($($usbControllers.Count))" $usbControllers "USB_Controllers"

# =============================================================================
#  SECTION 9: INSTALLED SOFTWARE
# =============================================================================
Write-Section "SECTION 9: INSTALLED SOFTWARE INVENTORY"

$software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString | Where-Object { $_.DisplayName }
Write-Log "📦 INSTALLED PROGRAMS ($($software.Count))" $software "Installed_Software"

# =============================================================================
#  SECTION 10: PROCESS ANALYSIS
# =============================================================================
Write-Section "SECTION 10: RUNNING PROCESS ANALYSIS"

$procs = Get-Process | Select-Object Id, ProcessName, Path, Company, Product, ProductVersion, @{N='StartTime';E={$_.StartTime}}, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,2)}}, @{N='ParentPID';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId}}, @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine}}
Write-Log "⚙️ RUNNING PROCESSES ($($procs.Count))" $procs "Processes"

$susProcs = $procs | Where-Object { $n=$_.ProcessName.ToLower(); $susNames | ForEach-Object { if($n -like "*$_*"){return $true}}; if($_.Path -and ($_.Path -like "*\Temp\*" -or $_.Path -like "*\Downloads\*")){return $true}; if ($n -match '^[a-z0-9]{1,4}\.exe$') { return $true }; return $false }
if ($susProcs.Count -gt 0) { Write-AlertBox "$($susProcs.Count) suspicious processes running!" }
Write-Log "🚨 SUSPICIOUS PROCESSES ($($susProcs.Count))" $susProcs "Suspicious_Processes"

# =============================================================================
#  SECTION 11: NETWORK FORENSICS
# =============================================================================
Write-Section "SECTION 11: NETWORK CONNECTIONS & TRAFFIC"

$net = @()
try { $net = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess } catch { $netstat = netstat -ano | Select-String "ESTABLISHED"; $net = $netstat | ForEach-Object { $parts = ($_ -split '\s+') | Where-Object { $_ }; if ($parts.Count -ge 5) { [PSCustomObject]@{LocalAddress=$parts[1]; RemoteAddress=$parts[2]; State="ESTABLISHED"; OwningProcess=$parts[4]; Process=(Get-Process -Id $parts[4] -ErrorAction SilentlyContinue).ProcessName} } } }
Write-Log "🌐 ACTIVE CONNECTIONS" $net "Network_Connections"

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive
Write-Log "📡 DNS CACHE" $dnsCache "DNS_Cache"

# =============================================================================
#  SECTION 12: SCHEDULED TASKS
# =============================================================================
Write-Section "SECTION 12: SCHEDULED TASKS & AUTOMATION"

$tasks = @()
try { $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, Author, @{N='Action';E={($_.Actions|Select-Object -First 1).Execute}}, @{N='Arguments';E={($_.Actions|Select-Object -First 1).Arguments}}, State } catch { $schtasks = schtasks /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.'Run As User' -ne 'N/A' }; $tasks = $schtasks | Select-Object @{N='TaskName';E={$_.TaskName}}, @{N='Author';E={$_.'Run As User'}}, @{N='Action';E={$_.'Task To Run'}}, @{N='State';E={$_.'Scheduled Task State'}} }
Write-Log "⏰ SCHEDULED TASKS ($($tasks.Count))" $tasks "Scheduled_Tasks"

# =============================================================================
#  SECTION 13: TEMP FILES & RECENT ACTIVITY
# =============================================================================
Write-Section "SECTION 13: TEMP FILES & RECENT ACTIVITY"

$tempFiles = @()
@($env:TEMP, "C:\Windows\Temp", "C:\Temp") | ForEach-Object { if (Test-Path $_) { $tempFiles += Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, Length, LastWriteTime, @{N='Extension';E={$_.Extension}} } }
Write-Log "🗑️ RECENT TEMP FILES (7 days)" $tempFiles "Temp_Files"

# =============================================================================
#  SECTION 14: GAME DIRECTORY SCAN
# =============================================================================
Write-Section "SECTION 14: GAME FILES & MODIFICATIONS"

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
Write-Log "🎮 GAME FILES ($($gameFiles.Count))" $gameFiles "Game_Files"

$susGameFiles = $gameFiles | Where-Object { $name = (Split-Path $_.FullName -Leaf).ToLower(); $susNames | ForEach-Object { if($name -like "*$_*"){return $true}}; if ($name -match 'inject|hook|detour|minhook|scylla|x64dbg|cheat|hack|aim|esp|wall|radar|trigger|bot|macro|script|lua|pak|ucas|utoc') { return $true }; return $false }
if ($susGameFiles.Count -gt 0) { Write-AlertBox "$($susGameFiles.Count) suspicious files found in game directories!" }
Write-Log "🚨 SUSPICIOUS GAME FILES ($($susGameFiles.Count))" $susGameFiles "Suspicious_Game_Files"

# =============================================================================
#  SECTION 15: SYSTEM WIDE SUSPICIOUS FILE SEARCH
# =============================================================================
Write-Section "SECTION 15: SYSTEM WIDE THREAT HUNT"

$foundFiles = @()
$searchPaths = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:PROGRAMDATA, "C:\ProgramData")
$searchExts = '.exe','.dll','.sys','.bat','.cmd','.ps1','.ahk','.lua','.vbs','.js','.jar','.py','.scr','.com'
foreach ($dir in $searchPaths) {
    if (Test-Path $dir) {
        foreach ($ext in $searchExts) {
            $foundFiles += Get-ChildItem $dir -Filter "*$ext" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $name = $_.Name.ToLower(); foreach ($s in $susNames) { if ($name -like "*$s*") { return $true } }; if ($name -match '^[a-z0-9]{1,4}\.(exe|dll|sys)$') { return $true }; if ($name -match 'inject|loader|map|unmap|hook|detour|minhook|scylla') { return $true }; return $false } | Select-Object FullName, Length, LastWriteTime, @{N='SHA256';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}}
        }
    }
}
if ($foundFiles.Count -gt 0) { Write-AlertBox "$($foundFiles.Count) suspicious files found system wide!" }
Write-Log "🔍 SUSPICIOUS FILES SYSTEM WIDE ($($foundFiles.Count))" $foundFiles "Suspicious_Files"

# =============================================================================
#  SECTION 16: DRIVER SIGNATURE VERIFICATION
# =============================================================================
Write-Section "SECTION 16: DRIVER SECURITY & SIGNATURES"

$drivers = @()
try {
    $drivers = Get-WindowsDriver -Online -All -ErrorAction Stop | Select-Object Driver, OriginalFileName, ProviderName, Date, Version, BootCritical, @{N='ClassName';E={$_.ClassName}}, @{N='ClassDescription';E={$_.ClassDescription}}, @{N='Signer';E={$_.SignerName}}, @{N='IsSigned';E={if($_.SignerName -and $_.SignerName -notmatch 'Not signed|Unknown'){$true}else{$false}}}
} catch {
    $driverPath = "C:\Windows\System32\drivers"
    $drivers = Get-ChildItem $driverPath -Filter "*.sys" -ErrorAction SilentlyContinue | Select-Object Name, @{N='FullPath';E={$_.FullName}}, Length, LastWriteTime, @{N='IsSigned';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; if ($sig.Status -eq 'Valid') { $true } else { $false } }}, @{N='SignatureStatus';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; $sig.Status }}
}
Write-Log "🔐 ALL DRIVERS ($($drivers.Count))" $drivers "Drivers"

$unsignedDrivers = $drivers | Where-Object { if ($_.IsSigned -eq $false) { return $true }; if ($_.SignatureStatus -and $_.SignatureStatus -notmatch 'Valid|Microsoft|Intel|AMD|NVIDIA|Realtek|Broadcom|Qualcomm') { return $true }; return $false }
if ($unsignedDrivers.Count -gt 0) { Write-AlertBox "$($unsignedDrivers.Count) unsigned or suspicious drivers detected!" }
Write-Log "⚠️ UNSIGNED / SUSPICIOUS DRIVERS ($($unsignedDrivers.Count))" $unsignedDrivers "Unsigned_Drivers"

# =============================================================================
#  SECTION 17: WMI PERSISTENCE
# =============================================================================
Write-Section "SECTION 17: WMI PERSISTENCE (HIDDEN BACKDOORS)"

$wmiBindings = @(); try { $wmiBindings = Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription -ErrorAction Stop } catch { $wmiBindings = Get-WmiObject __FilterToConsumerBinding -Namespace root/subscription -ErrorAction SilentlyContinue }
if ($wmiBindings.Count -gt 0) { Write-AlertBox "WMI event bindings found - potential persistence!" }
Write-Log "🔗 WMI EVENT BINDINGS ($($wmiBindings.Count))" $wmiBindings "WMI_Bindings"

$wmiFilters = @(); try { $wmiFilters = Get-CimInstance __EventFilter -Namespace root/subscription -ErrorAction Stop | Select-Object Name, Query, QueryLanguage } catch { $wmiFilters = Get-WmiObject __EventFilter -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, Query, QueryLanguage }
Write-Log "📋 WMI EVENT FILTERS ($($wmiFilters.Count))" $wmiFilters "WMI_Filters"

$wmiConsumers = @(); try { $wmiConsumers = Get-CimInstance __EventConsumer -Namespace root/subscription -ErrorAction Stop | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate } catch { $wmiConsumers = Get-WmiObject __EventConsumer -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate }
Write-Log "📤 WMI EVENT CONSUMERS ($($wmiConsumers.Count))" $wmiConsumers "WMI_Consumers"

# =============================================================================
#  SECTION 18: ALTERNATE DATA STREAMS
# =============================================================================
Write-Section "SECTION 18: ALTERNATE DATA STREAMS (HIDDEN FILE ATTACHMENTS)"

$adsFiles = @()
$scanPaths = @($env:USERPROFILE, $env:TEMP, "$env:LOCALAPPDATA", "C:\Users")
foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        try {
            $cmdOutput = cmd /c "dir `"$path`" /s /r 2>nul" | Select-String ":\$"
            foreach ($line in $cmdOutput) {
                if ($line -match '^\s+(\d+)\s+(.+):(.+)$') {
                    $adsFiles += [PSCustomObject]@{ FileName = $Matches[2].Trim(); StreamName = $Matches[3].Trim(); Size = $Matches[1]; DetectionMethod = "cmd-dir-r" }
                }
            }
        } catch {}
    }
}
$adsFiles = $adsFiles | Where-Object { $_.StreamName -ne '' -and $_.StreamName -notmatch '^\s*$' } | Sort-Object FileName, StreamName -Unique
if ($adsFiles.Count -gt 0) { Write-AlertBox "$($adsFiles.Count) alternate data streams found - potential hidden data!" }
Write-Log "📎 ALTERNATE DATA STREAMS ($($adsFiles.Count))" $adsFiles "ADS_Files"

# =============================================================================
#  FINAL SUMMARY
# =============================================================================
Write-Banner "AUDIT COMPLETE - FINAL SUMMARY"

$summary = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║  AUDIT STATISTICS                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  WINDOWS INSTALL DATE:  $(if($osInfo.'Install Date'){$osInfo.'Install Date'}else{"Unknown"})$(" " * (49 - $(if($osInfo.'Install Date'){$osInfo.'Install Date'.Length}else{7}))║
║  SYSTEM UPTIME:         $(if($osInfo.'System Uptime'){$osInfo.'System Uptime'}else{"Unknown"})$(" " * (49 - $(if($osInfo.'System Uptime'){$osInfo.'System Uptime'.Length}else{7}))║
╠══════════════════════════════════════════════════════════════════════════════╣
║  CONNECTED DEVICES:                                                          ║
║    USB Devices:         $($pluggedUSB.Count)$(" " * (49 - $pluggedUSB.Count.ToString().Length))║
║    HID (KBM/Gamepads):  $($hidDevices.Count)$(" " * (49 - $hidDevices.Count.ToString().Length))║
║    Audio Devices:       $($audioDevices.Count)$(" " * (49 - $audioDevices.Count.ToString().Length))║
║    Monitors:            $($monitors.Count)$(" " * (49 - $monitors.Count.ToString().Length))║
║    Storage Drives:      $($storage.Count)$(" " * (49 - $storage.Count.ToString().Length))║
║    Network Adapters:    $($netAdapters.Count)$(" " * (49 - $netAdapters.Count.ToString().Length))║
║    Bluetooth:           $($bluetooth.Count)$(" " * (49 - $bluetooth.Count.ToString().Length))║
║    PCIe/DMA/Thunderbolt:$($pcieDevices.Count)$(" " * (49 - $pcieDevices.Count.ToString().Length))║
║    Serial/COM Ports:    $($serialPorts.Count)$(" " * (49 - $serialPorts.Count.ToString().Length))║
║    Total PNP Devices: $($allPnp.Count)$(" " * (49 - $allPnp.Count.ToString().Length))║
╠══════════════════════════════════════════════════════════════════════════════╣
║  FORENSICS:                                                                  ║
║    Prefetch Files:      $($prefetch.Count)$(" " * (49 - $prefetch.Count.ToString().Length))║
║    USB History (all):    $($usb.Count)$(" " * (49 - $usb.Count.ToString().Length))║
║    Installed Software:  $($software.Count)$(" " * (49 - $software.Count.ToString().Length))║
║    Running Processes:   $($procs.Count)$(" " * (49 - $procs.Count.ToString().Length))║
║    Active Connections:  $($net.Count)$(" " * (49 - $net.Count.ToString().Length))║
║    Scheduled Tasks:     $($tasks.Count)$(" " * (49 - $tasks.Count.ToString().Length))║
╠══════════════════════════════════════════════════════════════════════════════╣
║  THREATS DETECTED:                                                           ║
║    Suspicious Prefetch: $($susPrefetch.Count)$(" " * (49 - $susPrefetch.Count.ToString().Length))║
║    Weird Prefetch:      $($weirdPrefetch.Count)$(" " * (49 - $weirdPrefetch.Count.ToString().Length))║
║    AI Bot Processes:     $($aiBotProcesses.Count)$(" " * (49 - $aiBotProcesses.Count.ToString().Length))║
║    Python Sus Libraries:$($pythonSusFiles.Count)$(" " * (49 - $pythonSusFiles.Count.ToString().Length))║
║    Macro Scripts:       $($macroFiles.Count)$(" " * (49 - $macroFiles.Count.ToString().Length))║
║    Suspicious Procs:    $($susProcs.Count)$(" " * (49 - $susProcs.Count.ToString().Length))║
║    Suspicious Files:     $($foundFiles.Count)$(" " * (49 - $foundFiles.Count.ToString().Length))║
║    Game Files:          $($gameFiles.Count)$(" " * (49 - $gameFiles.Count.ToString().Length))║
║    Suspicious Game:     $($susGameFiles.Count)$(" " * (49 - $susGameFiles.Count.ToString().Length))║
║    Unsigned Drivers:     $($unsignedDrivers.Count)$(" " * (49 - $unsignedDrivers.Count.ToString().Length))║
║    WMI Bindings:        $($wmiBindings.Count)$(" " * (49 - $wmiBindings.Count.ToString().Length))║
║    ADS Streams:         $($adsFiles.Count)$(" " * (49 - $adsFiles.Count.ToString().Length))║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Add-Content -Path $LogFile -Value $summary -ErrorAction SilentlyContinue

# =============================================================================
#  ZIP & EMAIL
# =============================================================================
$zipPath = "$OutputPath\Audit_$Timestamp.zip"
if ($ZipResults) {
    try {
        Compress-Archive -Path $LogFile, $CsvFolder, $PrefetchFolder -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Log "📦 ZIP ARCHIVE CREATED" "Location: $zipPath"
        if (-not $Silent) { Write-Host "ZIP: $zipPath" -ForegroundColor Green }
    } catch {
        Write-Log "ZIP FAILED" $_.Exception.Message
    }
}

if ($EmailTo -and $EmailFrom -and $EmailPassword -and -not $NoEmail) {
    try {
        $subject = "🔍 System Audit - $env:COMPUTERNAME - $Timestamp"
        $body = "Audit completed for $env:COMPUTERNAME`n`n$summary"
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
        Write-Log "📧 EMAIL SENT" "To: $EmailTo"
        if (-not $Silent) { Write-Host "Email sent to $EmailTo!" -ForegroundColor Green }
    } catch {
        Write-Log "EMAIL FAILED" $_.Exception.Message
        if (-not $Silent) { Write-Host "Email failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

if ($UploadURL) {
    try {
        $uploadFile = if ($ZipResults -and (Test-Path $zipPath)) { $zipPath } else { $LogFile }
        Invoke-RestMethod -Uri $UploadURL -Method Post -InFile $uploadFile -Headers @{"Content-Type"="application/octet-stream"} -ErrorAction Stop
        Write-Log "☁️ UPLOAD SUCCESS" $UploadURL
        if (-not $Silent) { Write-Host "Uploaded!" -ForegroundColor Green }
    } catch {
        Write-Log "UPLOAD FAILED" $_.Exception.Message
    }
}

if (-not $Silent) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                   AUDIT COMPLETE v6.0                         ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    if ($osInfo.'Install Date') { Write-Host "║  Windows: $($osInfo.'Install Date') ($($osInfo.'Days Since Install') days)" -ForegroundColor Cyan }
    Write-Host "║  Devices: $($allPnp.Count) total PNP | Prefetch: $($prefetch.Count) files" -ForegroundColor Cyan
    Write-Host "║  AI Bots: $($aiBotProcesses.Count) detected | Threats: $($susProcs.Count + $foundFiles.Count + $susGameFiles.Count)" -ForegroundColor Cyan
    Write-Host "║  Log: $LogFile" -ForegroundColor Cyan
    if ($ZipResults -and (Test-Path $zipPath)) { Write-Host "║  ZIP: $zipPath" -ForegroundColor Cyan }
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
