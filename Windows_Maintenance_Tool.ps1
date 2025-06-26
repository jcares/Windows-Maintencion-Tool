# ===== ADMIN CHECK =====
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges."
    Write-Host "Requesting elevation now ..."
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Pause-Menu {
    Write-Host
    Read-Host "Press ENTER to return to menu"
}

function Show-Menu {
    Clear-Host
    Write-Host "====================================================="
    Write-Host "         WINDOWS MAINTENANCE TOOL V3.1.2 - By Lil_Batti"
    Write-Host "====================================================="
    Write-Host
    Write-Host "     === WINDOWS UPDATES ==="
    Write-Host "  [1]  Update Windows Apps / Programs (Winget upgrade)"
    Write-Host
    Write-Host "     === SYSTEM HEALTH CHECKS ==="
    Write-Host "  [2]  Scan for corrupt files (SFC /scannow) [Admin]"
    Write-Host "  [3]  Windows CheckHealth (DISM) [Admin]"
    Write-Host "  [4]  Restore Windows Health (DISM /RestoreHealth) [Admin]"
    Write-Host
    Write-Host "     === NETWORK TOOLS ==="
    Write-Host "  [5]  DNS Options (Flush/Set/Reset)"
    Write-Host "  [6]  Show network information (ipconfig /all)"
    Write-Host "  [7]  Restart Wi-Fi Adapters"
    Write-Host "  [8]  Network Repair - Automatic Troubleshooter"
    Write-Host
    Write-Host "     === CLEANUP & OPTIMIZATION ==="
    Write-Host "  [9]  Disk Cleanup (cleanmgr)"
    Write-Host " [10]  Run Advanced Error Scan (CHKDSK) [Admin]"
    Write-Host " [11]  Perform System Optimization (Delete Temporary Files)"
    Write-Host " [12]  Advanced Registry Cleanup-Optimization"
    Write-Host " [13]  Optimize SSDs (ReTrim)"
    Write-Host
    Write-Host "     === SUPPORT ==="
    Write-Host " [14]  Contact and Support information (Discord)"
    Write-Host
    Write-Host "     === UTILITIES & EXTRAS ==="
    Write-Host " [20]  Show installed drivers"
    Write-Host " [21]  Windows Update Repair Tool"
    Write-Host " [22]  Generate Full System Report"
    Write-Host " [23]  Windows Update Utility & Service Reset"
    Write-Host " [24]  View Network Routing Table [Advanced]"
    Write-Host
    Write-Host " [15]  EXIT"
    Write-Host "------------------------------------------------------"
}

function Choice-1 {
    Clear-Host
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget is not installed. Please install it from Microsoft Store."
        Pause-Menu
        return
    }
    Write-Host "==============================================="
    Write-Host "    Windows Update (via Winget)"
    Write-Host "==============================================="
    Write-Host "Listing available upgrades..."
    Write-Host
    winget upgrade --include-unknown
    Write-Host
    Pause-Menu
    while ($true) {
        Write-Host "==============================================="
        Write-Host "Options:"
        Write-Host "[1] Upgrade all packages"
        Write-Host "[2] Upgrade selected packages"
        Write-Host "[0] Cancel"
        Write-Host
        $upopt = Read-Host "Choose an option"
        $upopt = $upopt.Trim()
        switch ($upopt) {
            "0" {
                Write-Host "Cancelled. Returning to menu..."
                Pause-Menu
                return
            }
            "1" {
                Write-Host "Running full upgrade..."
                winget upgrade --all --include-unknown
                Pause-Menu
                return
            }
            "2" {
                Clear-Host
                Write-Host "==============================================="
                Write-Host "  Available Packages [Copy ID to upgrade]"
                Write-Host "==============================================="
                winget upgrade --include-unknown
                Write-Host
                Write-Host "Enter one or more package IDs to upgrade (comma-separated, no spaces)"
                $packlist = Read-Host "IDs"
                $packlist = $packlist -replace ' ', ''
                if ([string]::IsNullOrWhiteSpace($packlist)) {
                    Write-Host "No package IDs entered."
                    Pause-Menu
                    return
                }
                $ids = $packlist.Split(",")
                foreach ($id in $ids) {
                    Write-Host "Upgrading $id..."
                    winget upgrade --id $id --include-unknown
                    Write-Host
                }
                Pause-Menu
                return
            }
            default {
                Write-Host "Invalid option. Please choose 1, 2, or 0."
                continue
            }
        }
    }
}
function Choice-2 {
    Clear-Host
    Write-Host "Scanning for corrupt files (SFC /scannow)..."
    sfc /scannow
    Pause-Menu
}

function Choice-3 {
    Clear-Host
    Write-Host "Checking Windows health status (DISM /CheckHealth)..."
    dism /online /cleanup-image /checkhealth
    Pause-Menu
}

function Choice-4 {
    Clear-Host
    Write-Host "Restoring Windows health status (DISM /RestoreHealth)..."
    dism /online /cleanup-image /restorehealth
    Pause-Menu
}


function Choice-5 {
    function Get-ActiveAdapters {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name
    }
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "DNS / Network Tool"
        Write-Host "======================================================"
        Write-Host "[1] Set DNS to Google (8.8.8.8 / 8.8.4.4)"
        Write-Host "[2] Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1)"
        Write-Host "[3] Restore automatic DNS (DHCP)"
        Write-Host "[4] Use your own DNS"
        Write-Host "[5] Return to menu"
        Write-Host "======================================================"
        $dns_choice = Read-Host "Enter your choice"
        switch ($dns_choice) {
            "1" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!"; Pause-Menu; return }
                Write-Host "Applying Google DNS (8.8.8.8/8.8.4.4) to:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("8.8.8.8","8.8.4.4") -ErrorAction SilentlyContinue
                }
                Write-Host "Done. Google DNS set."
                Pause-Menu; return
            }
            "2" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!"; Pause-Menu; return }
                Write-Host "Applying Cloudflare DNS (1.1.1.1/1.0.0.1) to:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
                }
                Write-Host "Done. Cloudflare DNS set."
                Pause-Menu; return
            }
            "3" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!"; Pause-Menu; return }
                Write-Host "Restoring automatic DNS (DHCP) on:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    Set-DnsClientServerAddress -InterfaceAlias $adapter -ResetServerAddresses -ErrorAction SilentlyContinue
                }
                Write-Host "Done. DNS set to automatic."
                Pause-Menu; return
            }
            "4" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!"; Pause-Menu; return }
                while ($true) {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "          Enter your custom DNS"
                    Write-Host "==============================================="
                    $customDNS1 = Read-Host "Enter primary DNS"
                    $customDNS2 = Read-Host "Enter secondary DNS (optional)"
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         Validating DNS addresses..."
                    Write-Host "==============================================="
                    $primaryReachable = Test-Connection -ComputerName $customDNS1 -Count 1 -Quiet
                    if (-not $primaryReachable) {
                        Write-Host "[!] ERROR: The primary DNS `"$customDNS1`" is not reachable."
                        Write-Host "Please enter a valid DNS address."
                        Pause-Menu
                        continue
                    }
                    $secondaryReachable = $true
                    if ($customDNS2 -and $customDNS2.Trim() -ne "") {
                        $secondaryReachable = Test-Connection -ComputerName $customDNS2 -Count 1 -Quiet
                        if (-not $secondaryReachable) {
                            Write-Host "[!] ERROR: The secondary DNS `"$customDNS2`" is not reachable."
                            Write-Host "It will be skipped."
                            $customDNS2 = $null
                            Pause-Menu
                        }
                    }
                    break
                }
                Clear-Host
                Write-Host "==============================================="
                Write-Host "    Setting DNS for all active adapters..."
                Write-Host "==============================================="
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    if ($customDNS2) {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses @($customDNS1, $customDNS2) -ErrorAction SilentlyContinue
                    } else {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $customDNS1 -ErrorAction SilentlyContinue
                    }
                }
                Write-Host
                Write-Host "==============================================="
                Write-Host "    DNS has been successfully updated:"
                Write-Host "      Primary: $customDNS1"
                if ($customDNS2) { Write-Host "      Secondary: $customDNS2" }
                Write-Host "==============================================="
                Pause-Menu
                return
            }
            "5" { return }
            default { Write-Host "Invalid choice, please try again."; Pause-Menu }
        }
    }
}
function Choice-6 { Clear-Host; Write-Host "Displaying Network Information..."; ipconfig /all; Pause-Menu }

function Choice-7 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "    Restarting all Wi-Fi adapters..."
    Write-Host "=========================================="

    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless" -and $_.Status -eq "Up" -or $_.Status -eq "Disabled" }

    if (-not $wifiAdapters) {
        Write-Host "No Wi-Fi adapters found!"
        Pause-Menu
        return
    }

    foreach ($adapter in $wifiAdapters) {
        Write-Host "Restarting '$($adapter.Name)'..."

        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 5

        # Check connection
        $status = Get-NetAdapter -Name $adapter.Name
        if ($status.Status -eq "Up") {
            Write-Host "SUCCESS: '$($adapter.Name)' is back online!" -ForegroundColor Green
        } else {
            Write-Host "WARNING: '$($adapter.Name)' is still offline!" -ForegroundColor Yellow
        }
    }

    Pause-Menu
}


function Choice-8 {
    $Host.UI.RawUI.WindowTitle = "Network Repair - Automatic Troubleshooter"
    Clear-Host
    Write-Host
    Write-Host "==============================="
    Write-Host "    Automatic Network Repair"
    Write-Host "==============================="
    Write-Host
    Write-Host "Step 1: Renewing your IP address..."
    ipconfig /release | Out-Null
    ipconfig /renew  | Out-Null
    Write-Host
    Write-Host "Step 2: Refreshing DNS settings..."
    ipconfig /flushdns | Out-Null
    Write-Host
    Write-Host "Step 3: Resetting network components..."
    netsh winsock reset | Out-Null
    netsh int ip reset  | Out-Null
    Write-Host
    Write-Host "Your network settings have been refreshed."
    Write-Host "A system restart is recommended for full effect."
    Write-Host
    while ($true) {
        $restart = Read-Host "Would you like to restart now? (Y/N)"
        switch ($restart.ToUpper()) {
            "Y" { shutdown /r /t 5; return }
            "N" { return }
            default { Write-Host "Invalid input. Please enter Y or N." }
        }
    }
}

function Choice-9 { Clear-Host; Write-Host "Running Disk Cleanup..."; Start-Process "cleanmgr.exe"; Pause-Menu }

function Choice-10 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "Running advanced error scan on all drives..."
    Write-Host "==============================================="
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Select-Object -ExpandProperty Name
    foreach ($drive in $drives) {
        Write-Host
        Write-Host "Scanning drive $drive`:" ...
        chkdsk "${drive}:" /f /r /x
    }
    Write-Host
    Write-Host "All drives scanned."
    Pause-Menu
}

function Choice-11 {
    Clear-Host
    while ($true) {
        Write-Host "==============================================="
        Write-Host "   Delete Temporary Files and System Cache"
        Write-Host "==============================================="
        Write-Host
        Write-Host "This will permanently remove temp files for your user and Windows."
        Write-Host
        $confirm = Read-Host "Do you want to continue? (Y/N)"
        $c = $confirm.ToUpper().Trim()
        if ($c -eq "Y" -or $c -eq "YES") { break }
        if ($c -eq "N" -or $c -eq "NO") {
            Write-Host "Operation cancelled."
            Pause-Menu
            return
        }
        Write-Host "Invalid input. Please type Y or N."
    }
    $REAL_TEMP = [System.IO.Path]::GetTempPath()
    if (-not ($REAL_TEMP.ToLower() -like "*$env:USERNAME.ToLower()*")) {
        Write-Host "[ERROR] TEMP path unsafe or invalid: $REAL_TEMP"
        Write-Host "Aborting to prevent system damage."
        Pause-Menu
        return
    }
    Clear-Host
    Write-Host "Deleting temporary files using PowerShell..."
    try {
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host
        Write-Host "Temporary files deleted."
    } catch {
        Write-Host "Error deleting some temporary files." -ForegroundColor Yellow
    }
    Pause-Menu
}

function Choice-12 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host " Advanced Registry Cleanup & Optimization"
        Write-Host "======================================================"
        Write-Host "[1] List 'safe to delete' registry keys under Uninstall"
        Write-Host "[2] Delete all 'safe' registry keys"
        Write-Host "[3] Create Registry Backup"
        Write-Host "[4] Restore Registry Backup"
        Write-Host "[5] Scan for corrupt registry entries"
        Write-Host "[0] Return to main menu"
        Write-Host
        $rchoice = Read-Host "Enter your choice"
        switch ($rchoice) {
            "1" {
                Write-Host
                Write-Host "Listing registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
                powershell -NoLogo -NoProfile -Command "Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.Name -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } | ForEach-Object { Write-Host $_.Name }"
                Pause-Menu
            }
            "2" {
                Write-Host
                Write-Host "Deleting registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
                powershell -NoLogo -NoProfile -Command "Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.Name -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } | ForEach-Object { Remove-Item $_.PsPath -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Deleted:' $_.Name }"
                Pause-Menu
            }
            "3" {
                $backupFolder="$env:SystemRoot\Temp\RegistryBackups"
                if (-not (Test-Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Directory | Out-Null }
                $backupName = "RegistryBackup_{0}.reg" -f (Get-Date -Format "yyyy-MM-dd_HH-mm")
                $backupFile = Join-Path $backupFolder $backupName
                reg export HKLM $backupFile /y
                Write-Host "Backup created: $backupFile"
                Pause-Menu
            }
            "4" {
                $backupFolder="$env:SystemRoot\Temp\RegistryBackups"
                Write-Host "Available backups:"
                Get-ChildItem "$backupFolder\*.reg" | ForEach-Object { Write-Host $_.Name }
                $backupFile = Read-Host "Enter the filename to restore"
                $fullBackup = Join-Path $backupFolder $backupFile
                if (Test-Path $fullBackup) {
                    reg import $fullBackup
                    Write-Host "Backup successfully restored."
                } else {
                    Write-Host "File not found."
                }
                Pause-Menu
            }
            "5" {
                Clear-Host
                Write-Host "Scanning for corrupt registry entries..."
                Start-Process "cmd.exe" "/c sfc /scannow" -Wait
                Start-Process "cmd.exe" "/c dism /online /cleanup-image /checkhealth" -Wait
                Write-Host "Registry scan complete. If errors were found, restart your PC."
                Pause-Menu
            }
            "0" { return }
            default { Write-Host "Invalid input. Try again."; Pause-Menu }
        }
    }
}

function Choice-13 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "     Optimize SSDs (ReTrim/TRIM)"
    Write-Host "=========================================="
    Write-Host "This will automatically optimize (TRIM) all detected SSDs."
    Write-Host
    Write-Host "Listing all detected SSD drives..."

    $ssds = Get-PhysicalDisk | Where-Object MediaType -eq 'SSD'
    if (-not $ssds) {
        Write-Host "No SSDs detected."
        Pause-Menu
        return
    }

    $log = "$env:USERPROFILE\Desktop\SSD_OPTIMIZE_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
    $logContent = @()
    $logContent += "SSD Optimize Log - $(Get-Date)"

    foreach ($ssd in $ssds) {
        $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $ssd.FriendlyName }
        if ($disk) {
            $volumes = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null
            foreach ($vol in $volumes) {
                Write-Host "Optimizing SSD: $($vol.DriveLetter):"
                $logContent += "Optimizing SSD: $($vol.DriveLetter):"
                $result = Optimize-Volume -DriveLetter $($vol.DriveLetter) -ReTrim -Verbose 4>&1
                $logContent += $result
            }
        } else {
            $logContent += "Could not find Disk for SSD: $($ssd.FriendlyName)"
        }
    }
    Write-Host
    Write-Host "SSD optimization completed. Log file saved on Desktop: $log"
    $logContent | Out-File -FilePath $log -Encoding UTF8
    Pause-Menu
}

function Choice-14 {
    Clear-Host
    Write-Host
    Write-Host "=================================================="
    Write-Host "               CONTACT AND SUPPORT"
    Write-Host "=================================================="
    Write-Host "Do you have any questions or need help?"
    Write-Host "You are always welcome to contact me."
    Write-Host
    Write-Host "Discord-Username: Lil_Batti"
    Write-Host "Support-server: https://discord.gg/bCQqKHGxja"
    Write-Host
    Read-Host "Press ENTER to return to the main menu"
}

function Choice-15 { Clear-Host; Write-Host "Exiting script..."; exit }

function Choice-20 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Saving Installed Driver Report to Desktop"
    Write-Host "==============================================="
    $outfile = "$env:USERPROFILE\Desktop\Installed_Drivers.txt"
    driverquery /v > $outfile
    Write-Host
    Write-Host "Driver report has been saved to: $outfile"
    Pause-Menu
}

function Choice-21 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Windows Update Repair Tool [Admin]"
    Write-Host "==============================================="
    Write-Host
    Write-Host "[1/4] Stopping update-related services..."
    $services = @('wuauserv','bits','cryptsvc','msiserver','usosvc','trustedinstaller')
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "Stopping $service"
            try { Stop-Service -Name $service -Force -ErrorAction Stop } catch {}
        }
    }
    Start-Sleep -Seconds 2
    Write-Host
    Write-Host "[2/4] Renaming update cache folders..."
    $SUFFIX = ".bak_{0}" -f (Get-Random -Maximum 99999)
    $SD = "$env:windir\SoftwareDistribution"
    $CR = "$env:windir\System32\catroot2"
    $renamedSD = "$env:windir\SoftwareDistribution$SUFFIX"
    $renamedCR = "$env:windir\System32\catroot2$SUFFIX"
    if (Test-Path $SD) {
        try {
            Rename-Item $SD -NewName ("SoftwareDistribution" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedSD) {
                Write-Host "Renamed: $renamedSD"
            } else {
                Write-Host "Warning: Could not rename SoftwareDistribution."
            }
        } catch { Write-Host "Warning: Could not rename SoftwareDistribution." }
    } else { Write-Host "Info: SoftwareDistribution not found." }
    if (Test-Path $CR) {
        try {
            Rename-Item $CR -NewName ("catroot2" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedCR) {
                Write-Host "Renamed: $renamedCR"
            } else {
                Write-Host "Warning: Could not rename catroot2."
            }
        } catch { Write-Host "Warning: Could not rename catroot2." }
    } else { Write-Host "Info: catroot2 not found." }
    Write-Host
    Write-Host "[3/4] Restarting services..."
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Host "Starting $service"
            try { Start-Service -Name $service -ErrorAction Stop } catch {}
        }
    }
    Write-Host
    Write-Host "[4/4] Windows Update components have been reset."
    Write-Host
    Write-Host "Renamed folders:"
    Write-Host "  - $renamedSD"
    Write-Host "  - $renamedCR"
    Write-Host "You may delete them manually after reboot if all is working."
    Write-Host
    Pause-Menu
}

function Choice-22 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Generating Separated System Reports..."
    Write-Host "==============================================="
    Write-Host
    Write-Host "Choose output location:"
    Write-Host " [1] Desktop (recommended)"
    Write-Host " [2] Enter custom path"
    Write-Host " [3] Show guide for custom path setup"
    $opt = Read-Host ">"
    $outpath = ""
    if ($opt -eq "1") {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $reportdir = "SystemReports_{0}" -f (Get-Date -Format "yyyy-MM-dd_HHmm")
        $outpath = Join-Path $desktop $reportdir
        if (-not (Test-Path $outpath)) { New-Item -Path $outpath -ItemType Directory | Out-Null }
    } elseif ($opt -eq "2") {
        $outpath = Read-Host "Enter full path (e.g. D:\Reports)"
        if (-not (Test-Path $outpath)) {
            Write-Host
            Write-Host "[ERROR] Folder not found: $outpath"
            Pause-Menu
            return
        }
    } elseif ($opt -eq "3") {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "    How to Use a Custom Report Path"
        Write-Host "==============================================="
        Write-Host
        Write-Host "1. Open File Explorer and create a new folder, e.g.:"
        Write-Host "   C:\Users\YourName\Desktop\SystemReports"
        Write-Host "   or"
        Write-Host "   C:\Users\YourName\OneDrive\Documents\SystemReports"
        Write-Host
        Write-Host "2. Copy the folder's full path from the address bar."
        Write-Host "3. Re-run this and choose option [2], then paste it."
        Write-Host
        Pause-Menu
        return
    } else {
        Write-Host
        Write-Host "Invalid selection."
        Start-Sleep -Seconds 2
        return
    }
    $datestr = Get-Date -Format "yyyy-MM-dd"
    $sys   = Join-Path $outpath "System_Info_$datestr.txt"
    $net   = Join-Path $outpath "Network_Info_$datestr.txt"
    $drv   = Join-Path $outpath "Driver_List_$datestr.txt"
    Write-Host
    Write-Host "Writing system info to: $sys"
    systeminfo | Out-File -FilePath $sys -Encoding UTF8
    Write-Host "Writing network info to: $net"
    ipconfig /all | Out-File -FilePath $net -Encoding UTF8
    Write-Host "Writing driver list to: $drv"
    driverquery | Out-File -FilePath $drv -Encoding UTF8
    Write-Host
    Write-Host "Reports saved in:"
    Write-Host $outpath
    Write-Host
    Pause-Menu
}

function Choice-23 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "           Windows Update Utility & Service Reset"
        Write-Host "======================================================"
        Write-Host "This tool will restart core Windows Update services."
        Write-Host "Make sure no Windows Updates are installing right now."
        Pause-Menu
        Write-Host
        Write-Host "[1] Reset Update Services (wuauserv, cryptsvc, appidsvc, bits)"
        Write-Host "[2] Return to Main Menu"
        Write-Host
        $fixchoice = Read-Host "Select an option"
        switch ($fixchoice) {
            "1" {
                Clear-Host
                Write-Host "======================================================"
                Write-Host "    Resetting Windows Update & Related Services"
                Write-Host "======================================================"
                Write-Host "Stopping Windows Update service..."
                try { Stop-Service -Name wuauserv -Force -ErrorAction Stop } catch {}
                Write-Host "Stopping Cryptographic service..."
                try { Stop-Service -Name cryptsvc -Force -ErrorAction Stop } catch {}
                Write-Host "Starting Application Identity service..."
                try { Start-Service -Name appidsvc -ErrorAction Stop } catch {}
                Write-Host "Starting Windows Update service..."
                try { Start-Service -Name wuauserv -ErrorAction Stop } catch {}
                Write-Host "Starting Background Intelligent Transfer Service..."
                try { Start-Service -Name bits -ErrorAction Stop } catch {}
                Write-Host
                Write-Host "[OK] Update-related services have been restarted."
                Pause-Menu
                return
            }
            "2" { return }
            default { Write-Host "Invalid input. Try again."; Pause-Menu }
        }
    }
}

function Choice-24 {
    while ($true) {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "     View Network Routing Table  [Advanced]"
        Write-Host "==============================================="
        Write-Host "This shows how your system handles network traffic."
        Write-Host
        Write-Host "[1] Display routing table in this window"
        Write-Host "[2] Save routing table as a text file on Desktop"
        Write-Host "[3] Return to Main Menu"
        Write-Host
        $routeopt = Read-Host "Choose an option"
        switch ($routeopt) {
            "1" {
                Clear-Host
                route print
                Write-Host
                Pause-Menu
                return
            }
            "2" {
                $desktop = "$env:USERPROFILE\Desktop"
                if (-not (Test-Path $desktop)) {
                    Write-Host "Desktop folder not found."
                    Pause-Menu
                    return
                }
                $dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                if (-not $dt) { $dt = "manual_timestamp" }
                $file = Join-Path $desktop "routing_table_${dt}.txt"
                Clear-Host
                Write-Host "Saving routing table to: `"$file`""
                Write-Host
                route print | Out-File -FilePath $file -Encoding UTF8
                if (Test-Path $file) {
                    Write-Host "[OK] Routing table saved successfully."
                } else {
                    Write-Host "[ERROR] Failed to save routing table to file."
                }
                Write-Host
                Pause-Menu
                return
            }
            "3" { return }
            default {
                Write-Host "Invalid input. Please enter 1, 2 or 3."
                Pause-Menu
            }
        }
    }
}

# === MAIN MENU LOOP ===
while ($true) {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        "1"  { Choice-1; continue }
        "2"  { Choice-2; continue }
        "3"  { Choice-3; continue }
        "4"  { Choice-4; continue }
        "5"  { Choice-5; continue }
        "6"  { Choice-6; continue }
        "7"  { Choice-7; continue }
        "8"  { Choice-8; continue }
        "9"  { Choice-9; continue }
        "10" { Choice-10; continue }
        "11" { Choice-11; continue }
        "12" { Choice-12; continue }
        "13" { Choice-13; continue }
        "14" { Choice-14; continue }
        "15" { Choice-15 }
        "20" { Choice-20; continue }
        "21" { Choice-21; continue }
        "22" { Choice-22; continue }
        "23" { Choice-23; continue }
        "24" { Choice-24; continue }
        default { Write-Host "Invalid choice, please try again."; Pause-Menu }
    }
}