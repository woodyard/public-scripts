<#
.SYNOPSIS
    Winget Application Update Remediation Script

.DESCRIPTION
    This script performs application updates using winget based on a whitelist approach.
    It supports both system and user context applications and includes blocking process detection.
    The script is designed to work as a remediation script in Microsoft Intune remediation policies.

.NOTES
    Author: Henrik Skovgaard
    Version: 3.8
    Tag: 3M
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed user context detection, improved error handling, enhanced blocking process logic
    2.1 - Added Logitech.Options, Logitech.OptionsPlus, TrackerSoftware.PDF-XChangeEditor to whitelist
    2.2 - Implemented variable-based tag system for easier maintenance
    2.3 - Improved console output: tag moved to front, removed date from console (kept in log), added startup date log
    2.4 - ScriptTag now appears before timestamp in console output
    2.5 - Disabled Logitech.OptionsPlus due to upgrade issues
    2.6 - Improved date format from MM-dd-yy to dd.MM.yyyy for better readability
    2.7 - Added Microsoft.VCLibs.Desktop.14 to whitelist
    2.8 - Enhanced Adobe Reader blocking processes and improved multiple process support
    2.9 - Fixed Logitech.OptionsPlus AppID typo to match actual winget ID (OptonsPlus)
    3.0 - Added Microsoft.AzureDataStudio, Mythicsoft.AgentRansack, ParadoxInteractive.ParadoxLauncher, Foxit.FoxitReader.Inno, OBSProject.OBSStudio, Python.Launcher; Disabled Fortinet.FortiClientVPN
    3.1 - Added ARM64 support for winget path resolution
    3.2 - Added interactive popup to ask users about closing blocking processes
    3.3 - Added GitHub.GitHubDesktop to whitelist; Fixed winget output parsing bug causing character-by-character display
    3.4 - Moved whitelist configuration to external GitHub-hosted JSON file for centralized management
    3.5 - Removed redundant exclude list logic to streamline whitelist-only approach
    3.6 - Fixed wildcard matching bug that caused disabled apps to be processed when they contained enabled app names as substrings
    3.7 - Updated version to match detection script
    3.8 - Made context filtering logic more robust to handle apps without explicit SystemContext/UserContext properties; Added WiresharkFoundation.Wireshark to whitelist
    
    Exit Codes:
    0 - Script completed successfully
    1 - OOBE not complete
#>

#Requires -RunAsAdministrator
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match 'S-1-5-18')
	}
}
function Write-Log($message) #Log script messages to temp directory
{
    $LogMessage = ((Get-Date -Format "dd.MM.yyyy HH:mm:ss ") + $message)
    # Extract ScriptTag from message if present, or use global variable
    if ($message -match '^\[([A-Z0-9]+)\]\s*(.*)') {
        $tag = $matches[1]
        $cleanMessage = $matches[2]
        $ConsoleMessage = "[$tag] " + (Get-Date -Format "HH:mm:ss ") + $cleanMessage
    } else {
        $ConsoleMessage = "[$ScriptTag] " + (Get-Date -Format "HH:mm:ss ") + $message
    }
    $ConsoleMessage
	Out-File -InputObject $LogMessage -FilePath "$LogPath\$LogFullName" -Append -Encoding utf8
}

function OOBEComplete {
$TypeDef = @"

using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Api
{
public class Kernel32
{
[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern int OOBEComplete(ref int bIsOOBEComplete);
}
}
"@
        
        Add-Type -TypeDefinition $TypeDef -Language CSharp
        
        $IsOOBEComplete = $false
        $hr = [Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)
        
        return $IsOOBEComplete
}

function Show-ProcessCloseDialog {
    param(
        [string]$AppName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false,
        [string]$FriendlyName = ""
    )
    
    Write-Log -Message "Show-ProcessCloseDialog called for $AppName" | Out-Null
    
    # Use provided FriendlyName or fallback to AppName
    $friendlyName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }
    
    Write-Log -Message "Friendly name resolved to: $friendlyName" | Out-Null
    
    $defaultAction = if ($DefaultTimeoutAction) { "Yes" } else { "No" }
    $message = "An update is available for $friendlyName, but it cannot be installed while the application is running.`n`nWould you like to close $friendlyName now to allow the update to proceed?`n`nThis dialog will automatically choose '$defaultAction' in $TimeoutSeconds seconds."
    
    try {
        Write-Log -Message "Attempting to show Windows Forms dialog" | Out-Null
        
        # Try to use Windows Forms for interactive popup
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        # Create form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Application Update Available"
        $form.Size = New-Object System.Drawing.Size(500, 250)
        $form.StartPosition = "CenterScreen"
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.FormBorderStyle = "FixedDialog"
        $form.TopMost = $true
        
        # Create label
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 20)
        $label.Size = New-Object System.Drawing.Size(450, 120)
        $label.Text = $message
        $label.TextAlign = "MiddleLeft"
        $form.Controls.Add($label)
        
        # Create countdown label
        $countdownLabel = New-Object System.Windows.Forms.Label
        $countdownLabel.Location = New-Object System.Drawing.Point(20, 150)
        $countdownLabel.Size = New-Object System.Drawing.Size(450, 20)
        $countdownLabel.Text = "Time remaining: $TimeoutSeconds seconds"
        $countdownLabel.ForeColor = [System.Drawing.Color]::Red
        $form.Controls.Add($countdownLabel)
        
        # Create buttons
        $buttonYes = New-Object System.Windows.Forms.Button
        $buttonYes.Location = New-Object System.Drawing.Point(250, 180)
        $buttonYes.Size = New-Object System.Drawing.Size(100, 30)
        $buttonYes.Text = "Yes, Close App"
        $buttonYes.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $form.Controls.Add($buttonYes)
        
        $buttonNo = New-Object System.Windows.Forms.Button
        $buttonNo.Location = New-Object System.Drawing.Point(370, 180)
        $buttonNo.Size = New-Object System.Drawing.Size(100, 30)
        $buttonNo.Text = "No, Keep Open"
        $buttonNo.DialogResult = [System.Windows.Forms.DialogResult]::No
        $form.Controls.Add($buttonNo)
        
        # Create timer for countdown
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 1000
        $timer.Tag = $TimeoutSeconds  # Use Tag property to store countdown value
        
        $timer.add_Tick({
            $currentTimer = $this
            $timeLeft = [int]$currentTimer.Tag
            $timeLeft--
            $currentTimer.Tag = $timeLeft
            $countdownLabel.Text = "Time remaining: $timeLeft seconds"
            if ($timeLeft -le 0) {
                $currentTimer.Stop()
                if ($DefaultTimeoutAction) {
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
                } else {
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::No
                }
                $form.Close()
            }
        })
        
        $timer.Start()
        
        Write-Log -Message "About to show dialog" | Out-Null
        
        # Show dialog
        $result = $form.ShowDialog()
        $timer.Stop()
        $form.Dispose()
        
        Write-Log -Message "Dialog result for $friendlyName : $result" | Out-Null
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Write-Log -Message "User chose to close $friendlyName for update" | Out-Null
            return $true
        } else {
            Write-Log -Message "User chose to keep $friendlyName open (timeout or manual selection)" | Out-Null
            return $false
        }
        
    } catch {
        Write-Log -Message "Error showing GUI dialog: $($_.Exception.Message)" | Out-Null
        Write-Log -Message "Exception details: $($_.Exception.ToString())" | Out-Null
        
        # Fallback to command line approach for system context
        try {
            # Use msg.exe to show message to logged-in users
            $sessionId = (quser | Where-Object { $_ -match "Active" } | ForEach-Object { ($_ -split '\s+')[2] })[0]
            if ($sessionId) {
                Write-Log -Message "Sending message to session $sessionId using msg.exe" | Out-Null
                $msgResult = msg.exe $sessionId "/time:$TimeoutSeconds" "Update available for $friendlyName. Close the application? (This message will close automatically in $TimeoutSeconds seconds)"
                
                # Since msg.exe doesn't provide interactive response, default to No for safety
                Write-Log -Message "msg.exe sent, defaulting to No for safety" | Out-Null
                return $false
            } else {
                Write-Log -Message "No active user session found for popup" | Out-Null
                return $false
            }
        } catch {
            Write-Log -Message "Error with msg.exe fallback: $($_.Exception.Message)" | Out-Null
            return $false
        }
    }
}

function Stop-BlockingProcesses {
    param(
        [string]$ProcessNames
    )
    
    $processesToStop = $ProcessNames -split ','
    $stoppedAny = $false
    
    foreach ($processName in $processesToStop) {
        $processName = $processName.Trim()
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if ($processes) {
            try {
                foreach ($process in $processes) {
                    Write-Log -Message "Stopping process: $processName (PID: $($process.Id))"
                    $process.CloseMainWindow()
                    
                    # Wait up to 10 seconds for graceful shutdown
                    if (!$process.WaitForExit(10000)) {
                        Write-Log -Message "Process $processName did not exit gracefully, forcing termination"
                        $process.Kill()
                    }
                    $stoppedAny = $true
                }
                Write-Log -Message "Successfully stopped process: $processName"
            } catch {
                Write-Log -Message "Error stopping process $processName : $($_.Exception.Message)"
            }
        }
    }
    
    return $stoppedAny
}

<# Script variables #>
$ScriptTag = "3M" # Update this tag for each script version
$LogName = 'RemediateAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"
#$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath = "$env:Temp"
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useWhitelist = $true

<# ----------------------------------------------- #>

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Exit 1
}

<# ---------------------------------------------- #>

# Fetch whitelist configuration from GitHub
$whitelistUrl = "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/app-whitelist.json"
Write-Log -Message "Fetching whitelist configuration from GitHub"

try {
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "PowerShell-WingetScript/3.4")
    $whitelistJSON = $webClient.DownloadString($whitelistUrl)
    Write-Log -Message "Successfully downloaded whitelist configuration from GitHub"
} catch {
    Write-Log -Message "Error downloading whitelist from GitHub: $($_.Exception.Message)"
    Write-Log -Message "Falling back to local configuration"
    
    # Fallback to basic configuration if GitHub is unavailable
    $whitelistJSON = @'
[
    {"AppID": "Mozilla.Firefox", "FriendlyName": "Firefox", "BlockingProcess": "firefox"},
    {"AppID": "Google.Chrome", "FriendlyName": "Chrome", "BlockingProcess": "chrome"},
    {"AppID": "Microsoft.VisualStudioCode", "FriendlyName": "Visual Studio Code", "BlockingProcess": "Code"},
    {"AppID": "Notepad++.Notepad++", "FriendlyName": "Notepad++", "BlockingProcess": "notepad++", "DefaultTimeoutAction": true},
    {"AppID": "7zip.7zip", "FriendlyName": "7-Zip", "BlockingProcess": "7zFM", "DefaultTimeoutAction": true},
    {"AppID": "GitHub.GitHubDesktop", "FriendlyName": "GitHub Desktop", "BlockingProcess": "GitHubDesktop"}
]
'@
}

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*64__8wekyb3d8bbwe"
if ($ResolveWingetPath) {
    $WingetPath = $ResolveWingetPath[-1].Path
}

try {
    $whitelistConfig = $whitelistJSON | ConvertFrom-Json -ErrorAction Stop
    $whitelistConfig = $whitelistConfig | Where-Object { ($_.Disabled -eq $null -or $_.Disabled -eq $false) }
    Write-Log -Message "Successfully loaded whitelist configuration with $($whitelistConfig.Count) enabled apps"
} catch {
    Write-Log -Message "Error parsing whitelist JSON: $($_.Exception.Message)"
    exit 1
}

$ras = $true
If (-Not (Test-RunningAsSystem)) {
    $ras = $false

    #if (-not ($userIsAdmin)) {
    #    $whitelistConfig = $whitelistConfig | Where-Object { $_.UserContext -eq $true }
    #}

    $OUTPUT = $(winget upgrade --accept-source-agreements)
    
    # Check if first output is valid (contains actual app data)
    $hasValidOutput = $false
    foreach ($line in $OUTPUT) {
        if ($line -like "Name*Id*Version*Available*Source*") {
            $hasValidOutput = $true
            break
        }
    }
    
    # If first output is nonsense, run again
    if (-not $hasValidOutput) {
        Write-Log -Message "First winget run produced invalid output, retrying..."
        $OUTPUT = $(winget upgrade --accept-source-agreements)
    }
    
    Write-Log -Message "Local user mode"
}
elseif ($WingetPath) {
    Write-Log -Message $WingetPath
    Set-Location $WingetPath

    # In system context, we can upgrade both system and user context apps
    # Include apps if: no context properties defined, OR SystemContext is true, OR UserContext is true
    $whitelistConfig = $whitelistConfig | Where-Object {
        # If neither property exists, include the app
        ((-not $_.PSObject.Properties['SystemContext']) -and (-not $_.PSObject.Properties['UserContext'])) -or
        # Or if SystemContext is explicitly true
        ($_.SystemContext -eq $true) -or
        # Or if UserContext is explicitly true
        ($_.UserContext -eq $true)
    }

    # call winget and check if we need to retry
    $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
    
    # Check if first output is valid (contains actual app data)
    $hasValidOutput = $false
    foreach ($line in $OUTPUT) {
        if ($line -like "Name*Id*Version*Available*Source*") {
            $hasValidOutput = $true
            break
        }
    }
    
    # If first output is nonsense, run again
    if (-not $hasValidOutput) {
        Write-Log -Message "First winget run produced invalid output, retrying..."
        $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
    }
#    $OUTPUT = $OUTPUT.replace("Γ","").replace("Ç","").replace("ª","")
}

if ( (-Not ($ras)) -or $WingetPath) {
    $headerLine = -1
    $lineCount = 0

    foreach ($line in $OUTPUT) {
        if ($line -like "Name*" -and $headerLine -eq -1) {
            $headerLine = $lineCount
        }
        $lineCount++
    }

    if ($OUTPUT -and $lineCount -gt $headerLine+2) {
        $str = $OUTPUT[$headerLine]
        $idPos = $str.indexOf("Id")
        $versionPos = $str.indexOf("Version")-1

        $LIST= [System.Collections.ArrayList]::new()
        for ($i = $headerLine+2; $i -lt $OUTPUT.count; $i++ ) {
            $lineData = $OUTPUT[$i]
            # Stop parsing if we hit the second section or empty lines
            if ($lineData -like "*upgrade available, but require*" -or $lineData.Trim() -eq "" -or $lineData -like "*following packages*") {
                break
            }
            $appId = ($lineData[$idPos..$versionPos] -Join "").trim()
            if ($appId -ne "") {
                $null = $LIST.Add($appId)
            }
        }

        $count = 0
        $message = ""

        foreach ($app in $LIST) {
            if ($app -ne "") {
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($app -eq $okapp.AppID) {
                        $blockingProcessNames = $okapp.BlockingProcess
                        if (-not [string]::IsNullOrEmpty($blockingProcessNames)) {
                            $processesToCheck = $blockingProcessNames -split ','
                            $isBlocked = $false
                            $runningProcessName = ""
                            
                            foreach ($processName in $processesToCheck) {
                                $processName = $processName.Trim()
                                if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                    $runningProcessName = $processName
                                    $isBlocked = $true
                                    break
                                }
                            }
                            
                            if ($isBlocked) {
                                Write-Log -Message "Blocking process $runningProcessName is running for $($okapp.AppID)"
                                
                                # Check if we can auto-close only safe processes
                                $autoCloseProcesses = $okapp.AutoCloseProcesses
                                $canAutoClose = $false
                                $userChoice = $false
                                
                                if (-not [string]::IsNullOrEmpty($autoCloseProcesses)) {
                                    $autoCloseList = $autoCloseProcesses -split ','
                                    $runningProcesses = @()
                                    
                                    # Get all currently running blocking processes
                                    foreach ($processName in $processesToCheck) {
                                        $processName = $processName.Trim()
                                        if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                            $runningProcesses += $processName
                                        }
                                    }
                                    
                                    # Check if ALL running processes are in the auto-close list
                                    $canAutoClose = $true
                                    foreach ($runningProcess in $runningProcesses) {
                                        $isAutoCloseable = $false
                                        foreach ($autoCloseProcess in $autoCloseList) {
                                            if ($runningProcess -eq $autoCloseProcess.Trim()) {
                                                $isAutoCloseable = $true
                                                break
                                            }
                                        }
                                        if (-not $isAutoCloseable) {
                                            $canAutoClose = $false
                                            break
                                        }
                                    }
                                    
                                    if ($canAutoClose) {
                                        Write-Log -Message "Only auto-closeable processes running for $($okapp.AppID): $($runningProcesses -join ', '). Auto-closing without user prompt."
                                        $userChoice = $true
                                    }
                                }
                                
                                # If we can't auto-close, show the interactive popup
                                if (-not $canAutoClose) {
                                    $defaultTimeoutAction = if ($okapp.DefaultTimeoutAction -eq $true) { $true } else { $false }
                                    $userChoice = Show-ProcessCloseDialog -AppName $okapp.AppID -ProcessName $runningProcessName -TimeoutSeconds 60 -DefaultTimeoutAction $defaultTimeoutAction -FriendlyName $okapp.FriendlyName
                                    
                                    Write-Log -Message "Show-ProcessCloseDialog returned: $userChoice (type: $($userChoice.GetType().Name))"
                                }
                                
                                if ($userChoice) {
                                    if ($canAutoClose) {
                                        Write-Log -Message "Auto-closing safe processes for $($okapp.AppID)"
                                    } else {
                                        Write-Log -Message "User agreed to close blocking processes for $($okapp.AppID)"
                                    }
                                    
                                    # Try to stop the blocking processes
                                    $processesStopped = Stop-BlockingProcesses -ProcessNames $blockingProcessNames
                                    
                                    if ($processesStopped) {
                                        Write-Log -Message "Successfully stopped blocking processes for $($okapp.AppID)"
                                        # Wait a moment for processes to fully close
                                        Start-Sleep -Seconds 3
                                        
                                        # Verify processes are really stopped
                                        $stillRunning = $false
                                        foreach ($processName in $processesToCheck) {
                                            $processName = $processName.Trim()
                                            if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                                $stillRunning = $true
                                                break
                                            }
                                        }
                                        
                                        if ($stillRunning) {
                                            Write-Log -Message "Some processes still running after close attempt for $($okapp.AppID), skipping"
                                            continue
                                        }
                                    } else {
                                        Write-Log -Message "Failed to stop blocking processes for $($okapp.AppID), skipping"
                                        continue
                                    }
                                } else {
                                    Write-Log -Message "User chose not to close blocking processes for $($okapp.AppID), skipping"
                                    continue
                                }
                            }
                        }
                        
                        if ($ras -or $userIsAdmin) {
                            Write-Log -Message "Upgrade $($okapp.AppID) in system context"
                            $doUpgrade = $true
                            continue
                        }
                    }
                }

                if ($doUpgrade) {
                    $count++
                    Write-Log -Message "Starting upgrade for: $app"
                    
                    try {
                        Write-Log -Message "Executing winget upgrade for: $app"
                        
                        # First attempt: Standard upgrade
                        if ($ras) {
                            $upgradeResult = & .\winget.exe upgrade --silent --accept-source-agreements --id $app 2>&1
                        }
                        else {
                            $upgradeResult = & winget upgrade --silent --accept-source-agreements --id $app 2>&1
                        }
                        
                        $upgradeOutput = $upgradeResult -join "`n"
                        # Extract meaningful lines from winget output for logging
                        $meaningfulLines = @()
                        foreach ($line in $upgradeResult) {
                            $cleanLine = $line.Trim()
                            if ($cleanLine -ne "" -and $cleanLine.Length -gt 10 -and 
                                $cleanLine -notmatch '^[\-\\\|\/\s]*$' -and 
                                $cleanLine -notlike "*Progress:*" -and
                                $cleanLine -notlike "*.*%*") {
                                $meaningfulLines += $cleanLine
                            }
                        }
                        
                        if ($meaningfulLines.Count -gt 0) {
                            $logMessage = ($meaningfulLines | Select-Object -First 2) -join ' | '
                            Write-Log -Message "Winget result for $app : $logMessage"
                        } else {
                            Write-Log -Message "Winget result for $app : Processing completed"
                        }
                        
                        # Handle specific failure cases
                        if ($upgradeOutput -like "*install technology is different*") {
                            Write-Log -Message "Install technology mismatch detected for $app. Attempting uninstall and reinstall."
                            
                            # First uninstall
                            if ($ras) {
                                $uninstallResult = & .\winget.exe uninstall --silent --id $app 2>&1
                            } else {
                                $uninstallResult = & winget uninstall --silent --id $app 2>&1
                            }
                            
                            $uninstallOutput = $uninstallResult -join "`n"
                            if ($uninstallOutput -like "*Successfully uninstalled*") {
                                Write-Log -Message "Successfully uninstalled $app"
                            } else {
                                Write-Log -Message "Uninstall issue for $app"
                            }
                            
                            # Wait a moment for cleanup
                            Start-Sleep -Seconds 2
                            
                            # Then install fresh
                            if ($ras) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements --id $app 2>&1
                            } else {
                                $upgradeResult = & winget install --silent --accept-source-agreements --id $app 2>&1
                            }
                            
                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Fresh install completed for $app"
                            
                        } elseif ($upgradeOutput -like "*Uninstall failed*") {
                            Write-Log -Message "Uninstall failure detected for $app. Trying alternative approaches."
                            
                            # Try install with --force to override
                            if ($ras) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements --force --id $app 2>&1
                            } else {
                                $upgradeResult = & winget install --silent --accept-source-agreements --force --id $app 2>&1
                            }
                            
                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Force install completed for $app"
                        }
                        
                        # Evaluate success
                        if ($upgradeOutput -like "*Successfully installed*" -or $upgradeOutput -like "*No applicable update*" -or $upgradeOutput -like "*No newer version available*") {
                            Write-Log -Message "Upgrade completed successfully for: $app"
                            $message += $app + "|"
                        } else {
                            Write-Log -Message "Upgrade failed for $app - Exit code: $LASTEXITCODE"
                            $message += $app + " (FAILED)|"
                        }
                    } catch {
                        Write-Log -Message "Error upgrading $app : $($_.Exception.Message)"
                        $message += $app + " (ERROR)|"
                    }
                }
            }
        }

        Write-Log -Message "[$ScriptTag] Remediation completed: $count apps processed"
        if ($message -ne "") {
            Write-Log -Message "[$ScriptTag] Apps upgraded: $message"
        }
        exit 0
    }
    Write-Log -Message "[$ScriptTag] No upgrades (0x0000002)"
    exit 0
}
Write-Log -Message "[$ScriptTag] Winget not detected"
exit 0
