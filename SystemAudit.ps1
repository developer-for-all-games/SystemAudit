#Requires -RunAsAdministrator
# System Integrity Audit Script
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

# ========== SYSTEM INFO ==========
$os = Get-CimInstance Win32_OperatingSystem
Write-Log "Operating System" ($os | Select-Object Caption, Version, BuildNumber, OSArchitecture, @{N='InstallDate';E={$_.InstallDate}}, @{N='LastBoot';E={$_.LastBootUpTime}}) "OS_Info"

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

# ========== USB DEVICES ==========
$usb = @()
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR") {
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | ForEach-Object {
        Get-ChildItem $_.PSPath | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $usb += [PSCustomObject]@{DeviceID=$_.PSChildName; FriendlyName=$p.FriendlyName; Mfg=$p.Mfg}
        }
    }
}
Write-Log "USB Storage History" $usb "USB_History"

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
Prefetch: $($prefetch.Count) | USB Devices: $($usb.Count) | Software: $($software.Count)
Processes: $($procs.Count) | Suspicious Procs: $($susProcs.Count) | Suspicious Files: $($foundFiles.Count)
"@
Add-Content -Path $LogFile -Value "`n$summary"

if (-not $Silent) {
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    Write-Host "Log: $LogFile" -ForegroundColor Cyan
    Write-Host "CSV: $CsvFolder" -ForegroundColor Cyan
    Write-Host $summary
}
