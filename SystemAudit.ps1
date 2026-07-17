#Requires -RunAsAdministrator
# =============================================================================
#  SYSTEM INTEGRITY AUDIT SCRIPT v6.6.0
#  Enhanced Forensics Suite with AI Bot Detection & R6S Stats Integration
#  Credits: Original by developer-for-all-games | R6S Lookup inspired by halfskid.net / lain.wtf
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
    [switch]$NoEmail,
    [switch]$OpenStats,           # NEW: Open stats.cc pages for discovered accounts
    [switch]$OpenForensicTools,   # NEW: Open forensic tool URLs
    [switch]$OpenSystemPaths      # NEW: Open system forensic paths
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

# ========== NEW: UTILITY FUNCTIONS (from halfskid.net / lain.wtf) ==========
function Open-URL {
    param([string]$url)
    if (-not $Silent) { Write-Host "  [>] Opening $url" -ForegroundColor Yellow }
    try { Start-Process $url } catch { Write-Warn "Could not open URL: $url" }
}

function Open-Path {
    param([string]$path)
    if (Test-Path $path) {
        if (-not $Silent) { Write-Host "  [>] Opening path: $path" -ForegroundColor Yellow }
        Start-Process $path
    } else {
        if (-not $Silent) { Write-Host "  [!] Path not found: $path" -ForegroundColor Red }
    }
}

function Open-Reg {
    param([string]$regPath)
    if (-not $Silent) { Write-Host "  [>] Opening Registry: $regPath" -ForegroundColor Yellow }
    try {
        Start-Process "regedit.exe"
        Start-Sleep -Seconds 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value $regPath
    } catch { Write-Warn "Could not open registry path: $regPath" }
}

# ========== HELPER: Get OneDrive Path ==========
function Get-OneDrivePath {
    $oneDrivePaths = @()
    # Check registry for OneDrive paths across all users
    $oneDriveKeys = @(
        "HKCU:\SOFTWARE\Microsoft\OneDrive",
        "HKLM:\SOFTWARE\Microsoft\OneDrive"
    )
    foreach ($key in $oneDriveKeys) {
        if (Test-Path $key) {
            try {
                $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
                if ($props.UserFolder) { $oneDrivePaths += $props.UserFolder }
                if ($props.DefaultPath) { $oneDrivePaths += $props.DefaultPath }
            } catch {}
        }
    }
    # Check environment variables
    if ($env:OneDrive) { $oneDrivePaths += $env:OneDrive }
    if ($env:OneDriveConsumer) { $oneDrivePaths += $env:OneDriveConsumer }
    if ($env:OneDriveCommercial) { $oneDrivePaths += $env:OneDriveCommercial }
    # Check common paths
    $oneDrivePaths += "$env:USERPROFILE\OneDrive"
    $oneDrivePaths += "$env:USERPROFILE\OneDrive - Personal"

    return $oneDrivePaths | Sort-Object -Unique
}

# ========== R6S ACCOUNT DISCOVERY v4.0 - FIXED ==========
function Find-R6SAccounts {
    $foundAccounts = @()

    function Add-Account {
        param([string]$Username, [int]$Score, [string]$Source)
        if ($Username.Length -lt 3 -or $Username.Length -gt 32) { return }
        if ($Username -match '^[0-9]+$') { return }
        if ($Username -match '^[._-]+$') { return }
        $Username = $Username.Trim()
        if ([string]::IsNullOrWhiteSpace($Username)) { return }

        $existing = $foundAccounts | Where-Object { $_.Username -eq $Username }
        if ($existing) {
            $existing.Score += $Score
            if ($existing.Sources -notcontains $Source) {
                $existing.Sources += $Source
            }
        } else {
            $foundAccounts += [PSCustomObject]@{
                Username = $Username
                Score = $Score
                Sources = @($Source)
            }
        }
    }

    $allUsers = @()
    try { $allUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name } catch {}
    $oneDrivePaths = Get-OneDrivePath

    # === METHOD 1: Ubisoft Connect CACHE (PRIMARY) ===
    $ubiPaths = @()
    $ubiPaths += "$env:LOCALAPPDATA\Ubisoft Game Launcher"
    $ubiPaths += "$env:APPDATA\Ubisoft Game Launcher"
    foreach ($u in $allUsers) {
        $ubiPaths += "C:\Users\$u\AppData\Local\Ubisoft Game Launcher"
        $ubiPaths += "C:\Users\$u\AppData\Roaming\Ubisoft Game Launcher"
    }
    $ubiPaths = $ubiPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($ubiBase in $ubiPaths) {
        # Recursively find ALL cache/user directories
        $cacheDirs = @()
        if (Test-Path "$ubiBase\cache") { 
            $cacheDirs += Get-ChildItem "$ubiBase\cache" -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
            $cacheDirs += "$ubiBase\cache"
        }
        $cacheDirs += "$ubiBase\logs"
        $cacheDirs += "$ubiBase\save"
        $cacheDirs = $cacheDirs | Sort-Object -Unique | Where-Object { Test-Path $_ }

        foreach ($cachePath in $cacheDirs) {
            if (-not $Silent) { Write-Host "    [i] Checking: $cachePath" -ForegroundColor DarkGray }
            $files = Get-ChildItem $cachePath -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Length -lt 5MB -and $_.Extension -notin '.exe','.dll','.sys' }
            
            foreach ($file in $files) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }
                    
                    # JSON patterns - CORRECTED REGEX (single backslash)
                    $patterns = @(
                        @('"nameOnPlatform"\s*:\s*"([^"]{3,32})"', 25, "UbiCache_nameOnPlatform"),
                        @('"username"\s*:\s*"([^"]{3,32})"', 20, "UbiCache_username"),
                        @('"uplay_name"\s*:\s*"([^"]{3,32})"', 20, "UbiCache_uplay_name"),
                        @('"displayName"\s*:\s*"([^"]{3,32})"', 15, "UbiCache_displayName"),
                        @('"nickname"\s*:\s*"([^"]{3,32})"', 15, "UbiCache_nickname"),
                        @('"gamertag"\s*:\s*"([^"]{3,32})"', 15, "UbiCache_gamertag"),
                        @('"personaName"\s*:\s*"([^"]{3,32})"', 15, "UbiCache_personaName")
                    )
                    foreach ($pat in $patterns) {
                        $matches = [regex]::Matches($content, $pat[0])
                        foreach ($m in $matches) {
                            Add-Account -Username $m.Groups[1].Value.Trim() -Score $pat[1] -Source $pat[2]
                        }
                    }
                    
                    # Binary/string extraction for .dat/.cache/.db files
                    if ($file.Extension -in '.dat','.cache','.db') {
                        try {
                            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                            $binMatches = [regex]::Matches($text, 'nameOnPlatform.{0,10}([a-zA-Z0-9_.\-]{3,32})')
                            foreach ($m in $binMatches) {
                                $val = $m.Groups[1].Value.Trim()
                                if ($val -notmatch '^(null|true|false|0|1)$') {
                                    Add-Account -Username $val -Score 10 -Source "UbiCache_Binary"
                                }
                            }
                        } catch {}
                    }
                } catch {}
            }
        }

        # Logs
        $logPath = "$ubiBase\logs"
        if (Test-Path $logPath) {
            $logFiles = Get-ChildItem $logPath -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 5MB }
            foreach ($file in $logFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $loginMatches = [regex]::Matches($content, '(?i)login\s*(?:successful|success|completed).*?(?:user|name|account)\s*[:=]\s*"?([a-zA-Z0-9_.\-]{3,32})"?')
                        foreach ($m in $loginMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "UbiLog" }
                        $asMatches = [regex]::Matches($content, '(?i)(?:logged\s*in\s*as|signed\s*in\s*as|authenticated\s*as)\s*[:=]?\s*"?([a-zA-Z0-9_.\-]{3,32})"?')
                        foreach ($m in $asMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "UbiLog" }
                    }
                } catch {}
            }
        }

        # Settings files
        $settingsFiles = @("$ubiBase\settings.yml", "$ubiBase\settings.yaml", "$ubiBase\settings.json")
        foreach ($sf in $settingsFiles) {
            if (Test-Path $sf) {
                try {
                    $content = Get-Content $sf -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $yamlMatches = [regex]::Matches($content, '(?im)^\s*username:\s*([a-zA-Z0-9_.\-]{3,32})\s*$')
                        foreach ($m in $yamlMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 25 -Source "UbiSettings" }
                        $jsonMatches = [regex]::Matches($content, '"username"\s*:\s*"([^"]{3,32})"')
                        foreach ($m in $jsonMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 25 -Source "UbiSettings_JSON" }
                    }
                } catch {}
            }
        }
    }

    # === METHOD 2: R6S Save Folder (secondary) ===
    $r6sPaths = @()
    $r6sPaths += "$env:USERPROFILE\Documents\My Games\Rainbow Six - Siege"
    foreach ($u in $allUsers) { $r6sPaths += "C:\Users\$u\Documents\My Games\Rainbow Six - Siege" }
    foreach ($od in $oneDrivePaths) { $r6sPaths += "$od\Documents\My Games\Rainbow Six - Siege" }
    $r6sPaths = $r6sPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($r6sSavePath in $r6sPaths) {
        if (-not $Silent) { Write-Host "    [i] Scanning R6S path: $r6sSavePath" -ForegroundColor DarkGray }
        $guidFolders = Get-ChildItem $r6sSavePath -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' }
        foreach ($folder in $guidFolders) {
            $allFiles = Get-ChildItem $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Length -lt 5MB -and $_.Extension -notin '.exe','.dll','.sys','.pak','.ucas','.utoc' }
            foreach ($file in $allFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }
                    $patterns = @(
                        '"nameOnPlatform"\s*:\s*"([^"]{3,32})"',
                        '"uplay_name"\s*:\s*"([^"]{3,32})"',
                        '"username"\s*:\s*"([^"]{3,32})"',
                        '"displayName"\s*:\s*"([^"]{3,32})"',
                        '"gamertag"\s*:\s*"([^"]{3,32})"',
                        '"nickname"\s*:\s*"([^"]{3,32})"',
                        '"player_name"\s*:\s*"([^"]{3,32})"'
                    )
                    foreach ($pattern in $patterns) {
                        $matches = [regex]::Matches($content, $pattern)
                        foreach ($m in $matches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 12 -Source "R6S_SaveFile" }
                    }
                } catch {}
            }
        }
    }

    # === METHOD 3: Registry ===
    $ubiRegPaths = @(
        "HKCU:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\WOW6432Node\Ubisoft\Ubisoft Game Launcher",
        "HKCU:\SOFTWARE\Ubisoft\Launcher"
    )
    $userHives = Get-ChildItem "Registry::HKU\" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21' }
    foreach ($hive in $userHives) { $ubiRegPaths += "Registry::$($hive.Name)\SOFTWARE\Ubisoft\Ubisoft Game Launcher" }

    foreach ($regPath in $ubiRegPaths) {
        if (Test-Path $regPath) {
            if (-not $Silent) { Write-Host "    [i] Checking registry: $regPath" -ForegroundColor DarkGray }
            try {
                $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
                foreach ($propName in $propNames) {
                    $val = $props.$propName
                    if ($val -and $val -is [string] -and $val.Length -ge 3 -and $val.Length -le 32) {
                        if ($propName -match '(?i)user|name|account|profile|player|nick|persona') {
                            if ($val -match '^[a-zA-Z0-9_.\-]+$') { Add-Account -Username $val -Score 15 -Source "Registry" }
                        }
                    }
                }
            } catch {}
        }
    }

    # === METHOD 4: Credential Manager ===
    try {
        if (-not $Silent) { Write-Host "    [i] Checking Credential Manager..." -ForegroundColor DarkGray }
        $creds = cmd /c "cmdkey /list" 2>$null
        $lines = $creds -split "`r?`n"
        foreach ($line in $lines) {
            if ($line -match '(?i)ubisoft|uplay') {
                $unameMatch = [regex]::Match($line, 'User:\s*([a-zA-Z0-9_.@-]{3,32})')
                if ($unameMatch.Success) {
                    $uname = $unameMatch.Groups[1].Value.Trim()
                    if ($uname -match '^([a-zA-Z0-9_.\-]{3,32})@') { $uname = $Matches[1] }
                    Add-Account -Username $uname -Score 25 -Source "CredentialManager"
                }
            }
        }
    } catch {}

    # === METHOD 5: Steam ===
    $steamPaths = @("C:\Program Files (x86)\Steam\userdata", "C:\Program Files\Steam\userdata", "$env:USERPROFILE\Steam\userdata")
    foreach ($u in $allUsers) { $steamPaths += "C:\Users\$u\Steam\userdata" }
    $steamPaths = $steamPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($sp in $steamPaths) {
        if (-not $Silent) { Write-Host "    [i] Checking Steam: $sp" -ForegroundColor DarkGray }
        $steamIDFolders = Get-ChildItem $sp -Directory -ErrorAction SilentlyContinue
        foreach ($sid in $steamIDFolders) {
            $configPath = "$($sid.FullName)\config\localconfig.vdf"
            if (Test-Path $configPath) {
                try {
                    $content = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $personaMatches = [regex]::Matches($content, '"PersonaName"\s*"([^"]{3,32})"')
                        foreach ($m in $personaMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "Steam_PersonaName" }
                    }
                } catch {}
            }
        }
    }

    # === METHOD 6: Media folders ===
    $mediaPaths = @()
    $mediaPaths += "$env:USERPROFILE\Videos\Rainbow Six - Siege"
    $mediaPaths += "$env:USERPROFILE\Pictures\Rainbow Six - Siege"
    foreach ($u in $allUsers) {
        $mediaPaths += "C:\Users\$u\Videos\Rainbow Six - Siege"
        $mediaPaths += "C:\Users\$u\Pictures\Rainbow Six - Siege"
    }
    foreach ($od in $oneDrivePaths) { $mediaPaths += "$od\Pictures\Rainbow Six - Siege" }
    $mediaPaths = $mediaPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($mPath in $mediaPaths) {
        if (-not $Silent) { Write-Host "    [i] Checking media: $mPath" -ForegroundColor DarkGray }
        try {
            $files = Get-ChildItem $mPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.png','.jpg','.jpeg','.bmp','.mp4' }
            foreach ($file in $files) {
                $base = $file.BaseName
                if ($base -match '^Rainbow Six-\d{4}\.\d{2}\.\d{2}') { continue }
                if ($base -match '^R6S?_\d{4}') { continue }
                if ($base -match '(?i)(?:by_|from_|player_|user_)([a-zA-Z0-9_.\-]{3,32})') {
                    Add-Account -Username $Matches[1] -Score 8 -Source "Media"
                }
                elseif ($base -match '^[a-zA-Z][a-zA-Z0-9_.\-]{2,30}$' -and $base -notmatch '\d{4}' -and $base -notmatch '^(screenshot|image|pic|photo|video|clip|recording)$') {
                    Add-Account -Username $base -Score 5 -Source "Media"
                }
            }
        } catch {}
    }

    # === METHOD 7: Web cache ===
    $webCachePaths = @()
    if (Test-Path "$env:LOCALAPPDATA\Ubisoft Game Launcher\cache") {
        $webCachePaths += Get-ChildItem "$env:LOCALAPPDATA\Ubisoft Game Launcher\cache" -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    $webCachePaths = $webCachePaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($wcPath in $webCachePaths) {
        if (-not $Silent) { Write-Host "    [i] Checking web cache: $wcPath" -ForegroundColor DarkGray }
        try {
            $files = Get-ChildItem $wcPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 2MB }
            foreach ($file in $files) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }
                    $urlMatches = [regex]::Matches($content, '(?i)/profile/([a-zA-Z0-9_.\-]{3,32})')
                    foreach ($m in $urlMatches) { Add-Account -Username $m.Groups[1].Value.Trim() -Score 10 -Source "WebCache" }
                } catch {}
            }
        } catch {}
    }

    # === FINAL FILTERING ===
    $blocklist = @(
        'Brawlhalla','Growtopia','MONOPOLY','Stadia','STEEP','Trackmania','UNO',
        'Classics','Live','Chinese','Dutch','English','French','German','Italian',
        'Japanese','Korean','Portuguese','Russian','Spanish','Interlingua',
        'app-game-properties','app-home-page','app-ingame-store','app-key-redemption',
        'app-library','app-preferences','app-product-details','app-web-browser',
        'auth-app','game-dl-mgr','gamer-profile','game-url-app','live-video-streaming',
        'marketplace','mini-dl-app','news','notifications','rewards','social','store-app',
        'splash-screen','spotlight','shellNav',
        'AccessibilityColorMode','AdaptiveRenderScalingTargetFPS',
        'ADSFullTiltBoostRampupDelay','ADSGamepadMultiplierUnit','ADSGamepadSensitivity',
        'AdvancedGamepadOptions','AimDownSights','AimDownSightsMouse','AntiAliasing',
        'AspectRatio','Atmospheric','AudioInputVoiceChatDevice','AudioOutputDevice',
        'AudioOutputVoiceChatDevice','Auto','autodetection','borderless','Brightness',
        'ca-central-1','calls','centering','centralus','Console','ControllerInputDevice',
        'ControllerStickRotationCurve','ControlSchemeIndex','CPUScore','crash','Custom',
        'CUSTOM_QUALITY','DataCenterHint','Deadzone','DefaultFOV','DefaultValuesVersion',
        'degrees','DeviceInstanceID','DirectX','disable','disabled','DISPLAY','DISPLAY_SETTINGS',
        'DLSSPerfQual','DOF','Dynamic','DynamicRangeMode','eastasia','eastus','enable',
        'EnableAMDMultiDraw','EnableIntelMultiDraw','EngineSettingsVersion','eu-central-1',
        'eu-north-1','eu-south-1','eu-west-1','eu-west-2','eu-west-3','field','fps',
        'FPSLimit','frame','frames','FSR2PerfQual','FSRPerfQual','fullscreen',
        'FullTiltBoostRampupDelay','gamelift','GamepadFullTiltBoostRampupTime',
        'GamepadLookDampeningTime','GAMEPLAY','GameplayPingEnable','GENERAL','Geometry',
        'GPUAdapter','GPUAdapterInfo','GPUAdapterSelectMode','GPUDedicatedMemoryMB',
        'GPUDeviceId','GPUInfo','GPUScore','GPUScoreConf','GPUSubSysId','GPUVendor',
        'HARDWARE_INFO','HardwareNotificationEnable','HearingFatigueAid','Hi-Fi',
        'InGameMusicVolume','InGameSFXVolume','InitialWindowPositionX','InitialWindowPositionY',
        'INPUT','InvertAxisY','InvertMouseAxisY','japaneast','latency','layers','LensEffects',
        'library','Lighting','Limit','Manual','mapped','MasterVolume','MaxGPUBufferedFrame',
        'MenuMusicVolume','MenuSFXVolume','metrics','Minimum','mode','Monitor','MonoOutput',
        'MousePitchSensitivity','MouseScroll','MouseSensitivity','MouseSensitivityMultiplierUnit',
        'MouseYawSensitivity','Mute','NegativeColorIndex','Night','NVReflex','NVReflexIndicator',
        'ObjectiveColorIndex','ONLINE','options','OuterDeadzoneRightStick',
        'OverallQualityLevelName','ping','PingColorIndex','PitchSensitivity','playfab',
        'PositiveColorIndex','Push','QUALITY','Range','RawInputMouseKeyboard','READ_ONLY',
        'Reflection','ReflexOn','ReflexWithBoost','RefreshRate','RenderScalingFactor',
        'resolution','ResolutionHeight','ResolutionWidth','Rumble','sa-east-1','select',
        'Semicolon','separated','set','Shadow','Sharpness','southafricanorth','southcentralus',
        'southeastasia','StunVFXMode','Subtitle','SubtitleType','SystemMemoryMB',
        'TeamColorAllyIndex','TeamColorEnemyIndex','TemporalUpscalerMode','Texture',
        'TextureFiltering','TextureStreaming','TextureVRAMLimit','TinnitusSFXMode',
        'ToggleAim','ToggleAimGamepad','ToggleCrouch','ToggleDroneBoost',
        'ToggleGadgetDeploymentGamepad','ToggleGadgetDeploymentKeyboard','ToggleLean',
        'ToggleProne','ToggleSprint','ToggleWalk','uaenorth','UbisoftConnectInstaller',
        'Upscaler','usage','UseAmdAGS','UseLetterbox','UseProxyAutoDiscovery','Version',
        'vertical','VeryHigh','VFX','Video','view','VK_LAYER_OW_OBS_HOOK',
        'VK_LAYER_OW_OVERLAY','VK_LAYER_RTSS','VK_LAYER_VALVE_steam_fossilize',
        'VoiceChatCaptureLevel','VoiceChatCaptureMode','VoiceChatCaptureThresholdV2',
        'VoiceChatEnabled','VoiceChatMuteAll','VoiceChatPlaybackLevel','VoiceChatTeamOnly',
        'VoiceVolume','VSync','Vulkan','VulkanWhitelistedLayers','westeurope','westus',
        'windowed','WindowMode','XFactorAiming','YawSensitivity',
        'af-south-1','ap-east-1','ap-northeast-1','ap-northeast-2','ap-northeast-3',
        'ap-south-1','ap-southeast-1','ap-southeast-2','australiaeast','brazilsouth',
        'ca-central-1','centralus','eastasia','eastus','japaneast','northeurope',
        'southafricanorth','southcentralus','southeastasia','uaenorth','westeurope','westus',
        'us-east-1','us-east-2','us-west-1','us-west-2',
        'access_denied','AllLogsDisabled','chromeAutofillStatesData',
        'Country_Included_In_Rollout','crl-set-','custom.news.impression',
        'DefaultPopulation','DESC','fileTypePolicies','GeneralPopulation','GroupL',
        'host_name','hyphens-data','newsTilesDisplayed','nonDevelopers','None','NULL',
        'OneClickBuy_Flow1_uApp','OneClickPlay_Eligible','opt_out','Performance',
        'performance.cls','performance.fcp','performance.lcp','performance.tti',
        'pkiMetadata','player.plhttps','Pop1','Premium','previews_v1','PRIMARY','promotab',
        'Promotabs','QV0JMOls6VhUVh1hGlxN5rC1MXAPJ91K','RememberDeviceAccounts',
        'rev-share-app','safetyTips','sslErrorAssistant','TABLE','tbyb','time',
        'trustToken','tvn.plC','upn-account','US_Uplay_PC','User_Live','VARCHAR',
        'Videos','Violence','WidevineCdm','zxcvbnData',
        'admin','test','guest','default','unknown','anonymous'
    )

    $blocklistLower = $blocklist | ForEach-Object { $_.ToLower() }

    $filtered = $foundAccounts | Where-Object {
        $acc = $_.Username
        $score = $_.Score
        $sources = $_.Sources

        $highConfidenceSources = $sources | Where-Object { 
            $_ -match 'UbiCache_nameOnPlatform|UbiCache_username|UbiSettings|Registry|CredentialManager|Steam_PersonaName' 
        }
        $multiSource = ($sources.Count -ge 2)
        $decentScore = ($score -ge 10)
        $highScore = ($score -ge 20)

        $accepted = ($highConfidenceSources.Count -gt 0) -or $multiSource -or $decentScore -or $highScore
        if (-not $accepted) { return $false }

        if ($blocklistLower -contains $acc.ToLower()) { return $false }
        if ($acc -match '^[0-9]+$') { return $false }
        if ($acc -match '^(.)\\1+$') { return $false }
        if ($acc -match '^[._\-]+$') { return $false }
        if ($acc -match '^\d{4}[._\-]?\d{2}[._\-]?\d{2}$') { return $false }
        if ($acc -match '^\d{2}[._\-]?\d{2}[._\-]?\d{2}[._\-]?\d{2}$') { return $false }
        if ($acc -match '^\d+\.\d+\.\d+') { return $false }
        if ($acc -match 'https?|www\.|\.com|\.net|\.org') { return $false }
        if ($acc -match '\s') { return $false }
        if ($acc -match '\.+$') { return $false }
        if ($acc -match '^[a-zA-Z0-9]{20,}$' -and $acc -notmatch '[._\-]') { return $false }

        return $true
    } | Sort-Object Score -Descending | Select-Object -ExpandProperty Username -Unique

    return $filtered
}
    

    $allUsers = @()
    try { $allUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name } catch {}

    $oneDrivePaths = @()
    if ($env:OneDrive) { $oneDrivePaths += $env:OneDrive }
    if ($env:OneDriveConsumer) { $oneDrivePaths += $env:OneDriveConsumer }
    $oneDrivePaths += "$env:USERPROFILE\OneDrive"
    $oneDrivePaths = $oneDrivePaths | Sort-Object -Unique

    # === METHOD 1: R6S Save Folder (Enhanced - now also checks GUID folder names as potential usernames) ===
    $r6sPaths = @()
    $r6sPaths += "$env:USERPROFILE\Documents\My Games\Rainbow Six - Siege"
    foreach ($u in $allUsers) {
        $r6sPaths += "C:\Users\$u\Documents\My Games\Rainbow Six - Siege"
    }
    foreach ($od in $oneDrivePaths) {
        $r6sPaths += "$od\Documents\My Games\Rainbow Six - Siege"
    }
    $r6sPaths = $r6sPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($r6sSavePath in $r6sPaths) {
        if (-not $Silent) { Write-Host "    [i] Scanning R6S path: $r6sSavePath" -ForegroundColor DarkGray }

        $guidFolders = Get-ChildItem $r6sSavePath -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' }

        foreach ($folder in $guidFolders) {
            $gameSettings = "$($folder.FullName)\GameSettings.ini"
            if (Test-Path $gameSettings) {
                try {
                    $content = Get-Content $gameSettings -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $iniMatches = [regex]::Matches($content, '(?im)^\s*([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_.\-]{3,32})\s*$')
                        foreach ($m in $iniMatches) {
                            $key = $m.Groups[1].Value.Trim().ToLower()
                            $val = $m.Groups[2].Value.Trim()
                            if ($key -match 'user|name|player|account|profile|persona') {
                                Add-Account -Username $val -Score 15 -Source "R6S_GameSettings"
                            }
                        }
                    }
                } catch {}
            }

            # Check ALL files in the GUID folder for username patterns
            $allFiles = Get-ChildItem $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Length -lt 5MB }
            foreach ($file in $allFiles) {
                if ($file.Extension -notin '.exe','.dll','.sys','.pak','.ucas','.utoc') {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content) {
                            $patterns = @(
                                '"nameOnPlatform"\s*:\s*"([^"]{3,32})"',
                                '"uplay_name"\s*:\s*"([^"]{3,32})"',
                                '"username"\s*:\s*"([^"]{3,32})"',
                                '"displayName"\s*:\s*"([^"]{3,32})"',
                                '"gamertag"\s*:\s*"([^"]{3,32})"',
                                '"nickname"\s*:\s*"([^"]{3,32})"',
                                '"player_name"\s*:\s*"([^"]{3,32})"'
                            )
                            foreach ($pattern in $patterns) {
                                $matches = [regex]::Matches($content, $pattern)
                                foreach ($m in $matches) {
                                    Add-Account -Username $m.Groups[1].Value.Trim() -Score 12 -Source "R6S_SaveFile"
                                }
                            }
                        }
                    } catch {}
                }
            }
        }
    }

    # === METHOD 2: Ubisoft Connect cache ===
    $ubiPaths = @()
    $ubiPaths += "$env:LOCALAPPDATA\Ubisoft Game Launcher"
    $ubiPaths += "$env:APPDATA\Ubisoft Game Launcher"
    foreach ($u in $allUsers) {
        $ubiPaths += "C:\Users\$u\AppData\Local\Ubisoft Game Launcher"
        $ubiPaths += "C:\Users\$u\AppData\Roaming\Ubisoft Game Launcher"
    }
    $ubiPaths = $ubiPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($ubiBase in $ubiPaths) {
        $cachePaths = @("$ubiBase\cache\users", "$ubiBase\cache\profiles", "$ubiBase\cache\account", "$ubiBase\cache")
        foreach ($cachePath in $cachePaths) {
            if (Test-Path $cachePath) {
                if (-not $Silent) { Write-Host "    [i] Checking Ubisoft cache: $cachePath" -ForegroundColor DarkGray }
                $files = Get-ChildItem $cachePath -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Length -lt 2MB }
                foreach ($file in $files) {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content) {
                            $patterns = @(
                                '"nameOnPlatform"\s*:\s*"([^"]{3,32})"',
                                '"uplay_name"\s*:\s*"([^"]{3,32})"',
                                '"username"\s*:\s*"([^"]{3,32})"',
                                '"displayName"\s*:\s*"([^"]{3,32})"'
                            )
                            foreach ($pattern in $patterns) {
                                $matches = [regex]::Matches($content, $pattern)
                                foreach ($m in $matches) {
                                    Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "UbiCache"
                                }
                            }
                        }

                        # For binary .dat files, try to extract strings
                        if ($file.Extension -in '.dat','.cache','.db') {
                            try {
                                $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                                # Look for nameOnPlatform in binary data
                                $binMatches = [regex]::Matches($text, 'nameOnPlatform.{0,5}([a-zA-Z0-9_.\-]{3,32})')
                                foreach ($m in $binMatches) {
                                    Add-Account -Username $m.Groups[1].Value.Trim() -Score 10 -Source "UbiCache_Binary"
                                }
                            } catch {}
                        }
                    } catch {}
                }
            }
        }

        # Check logs
        $logPath = "$ubiBase\logs"
        if (Test-Path $logPath) {
            if (-not $Silent) { Write-Host "    [i] Checking Ubisoft logs: $logPath" -ForegroundColor DarkGray }
            $logFiles = Get-ChildItem $logPath -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Extension -in '.log','.txt' -and $_.Length -lt 5MB }
            foreach ($file in $logFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $loginMatches = [regex]::Matches($content, '(?i)login\s*(?:successful|success|completed).*?(?:user|name|account)\s*[:=]\s*"?([a-zA-Z0-9_.\-]{3,32})"?')
                        foreach ($m in $loginMatches) {
                            Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "UbiLog"
                        }
                        $asMatches = [regex]::Matches($content, '(?i)(?:logged\s*in\s*as|signed\s*in\s*as|authenticated\s*as)\s*[:=]?\s*"?([a-zA-Z0-9_.\-]{3,32})"?')
                        foreach ($m in $asMatches) {
                            Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "UbiLog"
                        }
                    }
                } catch {}
            }
        }

        # Check settings
        $settingsFiles = @("$ubiBase\settings.yml", "$ubiBase\settings.yaml")
        foreach ($sf in $settingsFiles) {
            if (Test-Path $sf) {
                if (-not $Silent) { Write-Host "    [i] Checking settings: $sf" -ForegroundColor DarkGray }
                try {
                    $content = Get-Content $sf -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $yamlMatches = [regex]::Matches($content, '(?im)^\s*username:\s*([a-zA-Z0-9_.\-]{3,32})\s*$')
                        foreach ($m in $yamlMatches) {
                            Add-Account -Username $m.Groups[1].Value.Trim() -Score 20 -Source "UbiSettings"
                        }
                    }
                } catch {}
            }
        }
    }

    # === METHOD 3: Registry ===
    $ubiRegPaths = @(
        "HKCU:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\Ubisoft\Ubisoft Game Launcher",
        "HKLM:\SOFTWARE\WOW6432Node\Ubisoft\Ubisoft Game Launcher"
    )
    $userHives = Get-ChildItem "Registry::HKU\" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21' }
    foreach ($hive in $userHives) {
        $ubiRegPaths += "Registry::$($hive.Name)\SOFTWARE\Ubisoft\Ubisoft Game Launcher"
    }

    foreach ($regPath in $ubiRegPaths) {
        if (Test-Path $regPath) {
            if (-not $Silent) { Write-Host "    [i] Checking registry: $regPath" -ForegroundColor DarkGray }
            try {
                $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
                foreach ($propName in $propNames) {
                    $val = $props.$propName
                    if ($val -and $val -is [string] -and $val.Length -ge 3 -and $val.Length -le 32) {
                        if ($propName -match '(?i)user|name|account|profile|player') {
                            if ($val -match '^[a-zA-Z0-9_.\-]+$') {
                                Add-Account -Username $val -Score 12 -Source "Registry"
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    # === METHOD 4: Windows Credential Manager ===
    try {
        if (-not $Silent) { Write-Host "    [i] Checking Windows Credential Manager..." -ForegroundColor DarkGray }
        $creds = cmd /c "cmdkey /list" 2>$null
        $lines = $creds -split "`r?`n"
        foreach ($line in $lines) {
            if ($line -match '(?i)ubisoft|uplay') {
                $unameMatch = [regex]::Match($line, 'User:\s*([a-zA-Z0-9_.@-]{3,32})')
                if ($unameMatch.Success) {
                    $uname = $unameMatch.Groups[1].Value.Trim()
                    if ($uname -match '^([a-zA-Z0-9_.\-]{3,32})@') {
                        $uname = $Matches[1]
                    }
                    Add-Account -Username $uname -Score 20 -Source "CredentialManager"
                }
            }
        }
    } catch {}

    # === METHOD 5: Steam userdata ===
    $steamPaths = @(
        "C:\Program Files (x86)\Steam\userdata",
        "C:\Program Files\Steam\userdata",
        "$env:USERPROFILE\Steam\userdata"
    )
    foreach ($u in $allUsers) {
        $steamPaths += "C:\Users\$u\Steam\userdata"
    }
    $steamPaths = $steamPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($sp in $steamPaths) {
        if (-not $Silent) { Write-Host "    [i] Checking Steam userdata: $sp" -ForegroundColor DarkGray }
        $steamIDFolders = Get-ChildItem $sp -Directory -ErrorAction SilentlyContinue
        foreach ($sid in $steamIDFolders) {
            $configPath = "$($sid.FullName)\config\localconfig.vdf"
            if (Test-Path $configPath) {
                try {
                    $content = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $personaMatches = [regex]::Matches($content, '"PersonaName"\s*"([^"]{3,32})"')
                        foreach ($m in $personaMatches) {
                            Add-Account -Username $m.Groups[1].Value.Trim() -Score 15 -Source "Steam_PersonaName"
                        }
                    }
                } catch {}
            }
        }
    }

    # === METHOD 6: R6S Media folders ===
    $mediaPaths = @()
    $mediaPaths += "$env:USERPROFILE\Videos\Rainbow Six - Siege"
    $mediaPaths += "$env:USERPROFILE\Pictures\Rainbow Six - Siege"
    foreach ($u in $allUsers) {
        $mediaPaths += "C:\Users\$u\Videos\Rainbow Six - Siege"
        $mediaPaths += "C:\Users\$u\Pictures\Rainbow Six - Siege"
    }
    foreach ($od in $oneDrivePaths) {
        $mediaPaths += "$od\Pictures\Rainbow Six - Siege"
    }
    $mediaPaths = $mediaPaths | Sort-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($mPath in $mediaPaths) {
        if (-not $Silent) { Write-Host "    [i] Checking media folders: $mPath" -ForegroundColor DarkGray }
        try {
            $files = Get-ChildItem $mPath -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.Extension -in '.png','.jpg','.jpeg','.bmp','.mp4' }
            foreach ($file in $files) {
                $base = $file.BaseName
                # Skip default R6S screenshot names
                if ($base -match '^Rainbow Six-\d{4}\.\d{2}\.\d{2}') { continue }
                if ($base -match '^R6S?_\d{4}') { continue }

                # Look for username patterns
                if ($base -match '(?i)(?:by_|from_|player_|user_)([a-zA-Z0-9_.\-]{3,32})') {
                    Add-Account -Username $Matches[1] -Score 8 -Source "Media"
                }
                elseif ($base -match '^[a-zA-Z][a-zA-Z0-9_.\-]{2,30}$' -and 
                        $base -notmatch '\d{4}' -and
                        $base -notmatch '^(screenshot|image|pic|photo|video|clip|recording)$') {
                    Add-Account -Username $base -Score 5 -Source "Media"
                }
            }
        } catch {}
    }

    # === FINAL FILTERING - BALANCED ===
    # Blocklist: ONLY obvious non-usernames (app names, system terms, UI elements)
    # Real usernames like "Zombi", "yoboytrippin", "Blood" should NOT be here
    $blocklist = @(
        # App/Game names (these are actual product names, not people)
        'Brawlhalla','Growtopia','MONOPOLY','Stadia','STEEP','Trackmania','UNO',
        'Classics','Live','Chinese','Dutch','English','French','German','Italian',
        'Japanese','Korean','Portuguese','Russian','Spanish','Interlingua',
        # UI navigation / app components
        'app-game-properties','app-home-page','app-ingame-store','app-key-redemption',
        'app-library','app-preferences','app-product-details','app-web-browser',
        'auth-app','game-dl-mgr','gamer-profile','game-url-app','live-video-streaming',
        'marketplace','mini-dl-app','news','notifications','rewards','social','store-app',
        'splash-screen','spotlight','shellNav',
        # Settings/UI terms (all caps or camelCase chains)
        'ACCESSIBILITY','AccessibilityColorMode','AdaptiveRenderScalingTargetFPS',
        'ADSFullTiltBoostRampupDelay','ADSGamepadMultiplierUnit','ADSGamepadSensitivity',
        'AdvancedGamepadOptions','AimDownSights','AimDownSightsMouse','AntiAliasing',
        'AspectRatio','Atmospheric','AudioInputVoiceChatDevice','AudioOutputDevice',
        'AudioOutputVoiceChatDevice','Auto','autodetection','borderless','Brightness',
        'ca-central-1','calls','centering','centralus','Console','ControllerInputDevice',
        'ControllerStickRotationCurve','ControlSchemeIndex','CPUScore','crash','Custom',
        'CUSTOM_QUALITY','DataCenterHint','Deadzone','DefaultFOV','DefaultValuesVersion',
        'degrees','DeviceInstanceID','DirectX','disable','disabled','DISPLAY','DISPLAY_SETTINGS',
        'DLSSPerfQual','DOF','Dynamic','DynamicRangeMode','eastasia','eastus','enable',
        'EnableAMDMultiDraw','EnableIntelMultiDraw','EngineSettingsVersion','eu-central-1',
        'eu-north-1','eu-south-1','eu-west-1','eu-west-2','eu-west-3','field','fps',
        'FPSLimit','frame','frames','FSR2PerfQual','FSRPerfQual','fullscreen',
        'FullTiltBoostRampupDelay','gamelift','GamepadFullTiltBoostRampupTime',
        'GamepadLookDampeningTime','GAMEPLAY','GameplayPingEnable','GENERAL','Geometry',
        'GPUAdapter','GPUAdapterInfo','GPUAdapterSelectMode','GPUDedicatedMemoryMB',
        'GPUDeviceId','GPUInfo','GPUScore','GPUScoreConf','GPUSubSysId','GPUVendor',
        'HARDWARE_INFO','HardwareNotificationEnable','HearingFatigueAid','Hi-Fi',
        'InGameMusicVolume','InGameSFXVolume','InitialWindowPositionX','InitialWindowPositionY',
        'INPUT','InvertAxisY','InvertMouseAxisY','japaneast','latency','layers','LensEffects',
        'library','Lighting','Limit','Manual','mapped','MasterVolume','MaxGPUBufferedFrame',
        'MenuMusicVolume','MenuSFXVolume','metrics','Minimum','mode','Monitor','MonoOutput',
        'MousePitchSensitivity','MouseScroll','MouseSensitivity','MouseSensitivityMultiplierUnit',
        'MouseYawSensitivity','Mute','NegativeColorIndex','Night','NVReflex','NVReflexIndicator',
        'ObjectiveColorIndex','ONLINE','options','OuterDeadzoneRightStick',
        'OverallQualityLevelName','ping','PingColorIndex','PitchSensitivity','playfab',
        'PositiveColorIndex','Push','QUALITY','Range','RawInputMouseKeyboard','READ_ONLY',
        'Reflection','ReflexOn','ReflexWithBoost','RefreshRate','RenderScalingFactor',
        'resolution','ResolutionHeight','ResolutionWidth','Rumble','sa-east-1','select',
        'Semicolon','separated','set','Shadow','Sharpness','southafricanorth','southcentralus',
        'southeastasia','StunVFXMode','Subtitle','SubtitleType','SystemMemoryMB',
        'TeamColorAllyIndex','TeamColorEnemyIndex','TemporalUpscalerMode','Texture',
        'TextureFiltering','TextureStreaming','TextureVRAMLimit','TinnitusSFXMode',
        'ToggleAim','ToggleAimGamepad','ToggleCrouch','ToggleDroneBoost',
        'ToggleGadgetDeploymentGamepad','ToggleGadgetDeploymentKeyboard','ToggleLean',
        'ToggleProne','ToggleSprint','ToggleWalk','uaenorth','UbisoftConnectInstaller',
        'Upscaler','usage','UseAmdAGS','UseLetterbox','UseProxyAutoDiscovery','Version',
        'vertical','VeryHigh','VFX','Video','view','VK_LAYER_OW_OBS_HOOK',
        'VK_LAYER_OW_OVERLAY','VK_LAYER_RTSS','VK_LAYER_VALVE_steam_fossilize',
        'VoiceChatCaptureLevel','VoiceChatCaptureMode','VoiceChatCaptureThresholdV2',
        'VoiceChatEnabled','VoiceChatMuteAll','VoiceChatPlaybackLevel','VoiceChatTeamOnly',
        'VoiceVolume','VSync','Vulkan','VulkanWhitelistedLayers','westeurope','westus',
        'windowed','WindowMode','XFactorAiming','YawSensitivity',
        # Region codes
        'af-south-1','ap-east-1','ap-northeast-1','ap-northeast-2','ap-northeast-3',
        'ap-south-1','ap-southeast-1','ap-southeast-2','australiaeast','brazilsouth',
        'ca-central-1','centralus','eastasia','eastus','japaneast','northeurope',
        'southafricanorth','southcentralus','southeastasia','uaenorth','westeurope','westus',
        'us-east-1','us-east-2','us-west-1','us-west-2',
        # System/data terms
        'access_denied','AllLogsDisabled','chromeAutofillStatesData',
        'Country_Included_In_Rollout','crl-set-','custom.news.impression',
        'DefaultPopulation','DESC','fileTypePolicies','GeneralPopulation','GroupL',
        'host_name','hyphens-data','newsTilesDisplayed','nonDevelopers','None','NULL',
        'OneClickBuy_Flow1_uApp','OneClickPlay_Eligible','opt_out','Performance',
        'performance.cls','performance.fcp','performance.lcp','performance.tti',
        'pkiMetadata','player.plhttps','Pop1','Premium','previews_v1','PRIMARY','promotab',
        'Promotabs','QV0JMOls6VhUVh1hGlxN5rC1MXAPJ91K','RememberDeviceAccounts',
        'rev-share-app','safetyTips','sslErrorAssistant','TABLE','tbyb','time',
        'trustToken','tvn.plC','upn-account','US_Uplay_PC','User_Live','VARCHAR',
        'Videos','Violence','WidevineCdm','zxcvbnData',
        # Generic single words that aren't usernames
        'admin','test','guest','default','unknown','anonymous','player','gamer',
        'name','account','profile','login','password','pass','key','code','id','num',
        'no','yes','ok','cancel','error','warning','info','debug','trace','file',
        'folder','path','dir','root','home','cache','data','db','sql','api','url',
        'uri','ip','mac','host','server','client','pc','computer','desktop','laptop',
        'mobile','phone','tablet','device','system','os','win','windows','microsoft',
        'google','apple','linux','all','and','are','for','from','game','the','you'
    )

    $blocklistLower = $blocklist | ForEach-Object { $_.ToLower() }

    $filtered = $foundAccounts | Where-Object {
        $acc = $_.Username
        $score = $_.Score
        $sources = $_.Sources

        # === ACCEPTANCE RULES ===
        # Rule 1: High-confidence source (R6S save file, Ubisoft cache with nameOnPlatform, etc.)
        $highConfidenceSources = $sources | Where-Object { 
            $_ -match 'R6S_SaveFile|UbiCache|UbiLog|UbiSettings|Registry|CredentialManager|Steam_PersonaName' 
        }

        # Rule 2: Multiple independent sources found the same name
        $multiSource = ($sources.Count -ge 2)

        # Rule 3: Decent score from any source
        $decentScore = ($score -ge 8)

        # Rule 4: Very high score from single source
        $highScore = ($score -ge 15)

        # Must pass at least one acceptance rule
        $accepted = ($highConfidenceSources.Count -gt 0) -or $multiSource -or $decentScore -or $highScore
        if (-not $accepted) { return $false }

        # === REJECTION RULES ===
        # Blocklist check (case-insensitive)
        if ($blocklistLower -contains $acc.ToLower()) { return $false }

        # Must not be all numbers
        if ($acc -match '^[0-9]+$') { return $false }

        # Must not be a single repeated character
        if ($acc -match '^(.)\1+$') { return $false }

        # Must not contain only special chars
        if ($acc -match '^[._\-]+$') { return $false }

        # Must not look like a date
        if ($acc -match '^\d{4}[._\-]?\d{2}[._\-]?\d{2}$') { return $false }
        if ($acc -match '^\d{2}[._\-]?\d{2}[._\-]?\d{2}[._\-]?\d{2}$') { return $false }

        # Must not be a version number
        if ($acc -match '^\d+\.\d+\.\d+') { return $false }

        # Must not contain URL fragments
        if ($acc -match 'https?|www\.|\.com|\.net|\.org') { return $false }

        # Must not contain spaces
        if ($acc -match '\s') { return $false }

        # Must not end with dots (truncation artifact)
        if ($acc -match '\.+$') { return $false }

        # Must not be a random hash/ID
        if ($acc -match '^[a-zA-Z0-9]{20,}$' -and $acc -notmatch '[._\-]') { return $false }

        return $true
    } | Sort-Object Score -Descending | Select-Object -ExpandProperty Username -Unique

    return $filtered
}


# ========== HEADER ==========
$headerText = @"
================================================================================
  SYSTEM INTEGRITY AUDIT REPORT v6.6.0
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
