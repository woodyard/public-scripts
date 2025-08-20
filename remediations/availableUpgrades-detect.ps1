<#
.SYNOPSIS
    Winget Application Update Detection Script

.DESCRIPTION
    This script detects available application updates using winget and reports them to Intune.
    It supports both system and user context applications and uses a whitelist approach for security.
    The script is designed to work as a detection script in Microsoft Intune remediation policies.

.NOTES
    Author: Henrik Skovgaard
    Version: 4.0
    Tag: 3O
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed user context detection, improved error handling, added blocking process logic
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
    3.2 - Added GitHub.GitHubDesktop to whitelist
    3.3 - Moved whitelist configuration to external GitHub-hosted JSON file for centralized management
    3.4 - Removed redundant exclude list logic to streamline whitelist-only approach
    3.5 - Added debugging for disabled apps filtering to troubleshoot Logitech.OptionsPlus issue
    3.6 - Confirmed disabled apps filtering working correctly, removed debug logging
    3.7 - Fixed wildcard matching bug that caused disabled apps to be processed when they contained enabled app names as substrings
    3.8 - Made context filtering logic more robust to handle apps without explicit SystemContext/UserContext properties
    3.9 - Improved log management: dynamic path selection (Intune logs for system context), automatic cleanup of logs older than 1 month
    4.0 - Added PromptWhenBlocked property for granular control over interactive dialogs vs silent waiting when blocking processes are running
    
    Exit Codes:
    0 - No upgrades available or script completed successfully
    1 - Upgrades available (triggers remediation) or OOBE not complete
#>

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

function Remove-OldLogs {
    param([string]$LogPath)
    
    try {
        $cutoffDate = (Get-Date).AddMonths(-1)
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*AvailableUpgrades*.log" -ErrorAction SilentlyContinue
        foreach ($logFile in $logFiles) {
            if ($logFile.LastWriteTime -lt $cutoffDate) {
                Remove-Item -Path $logFile.FullName -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed old log file: $($logFile.Name)"
            }
        }
    } catch {
        # Don't use Write-Log here as it may not be ready yet - just silently continue
    }
}

<# Script variables #>
$ScriptTag = "3O" # Update this tag for each script version
$LogName = 'DetectAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"

# Dynamic log path selection based on execution context
if (Test-RunningAsSystem) {
    $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    # Ensure the directory exists
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
} else {
    $LogPath = "$env:Temp"
}
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useWhitelist = $true

<# ----------------------------------------------- #>

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Exit 0
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
    {"AppID": "Mozilla.Firefox", "BlockingProcess": "firefox"},
    {"AppID": "Google.Chrome", "BlockingProcess": "chrome"},
    {"AppID": "Microsoft.VisualStudioCode", "BlockingProcess": "Code"},
    {"AppID": "Notepad++.Notepad++", "BlockingProcess": "notepad++"},
    {"AppID": "7zip.7zip", "BlockingProcess": "7zFM"},
    {"AppID": "GitHub.GitHubDesktop", "BlockingProcess": "GitHubDesktop"}
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
        for ($i=$headerLine+2;($i -lt $OUTPUT.count);$i=$i+1) {
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
                        # Check for blocking processes
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
                                if ($okapp.PromptWhenBlocked -eq $true) {
                                    Write-Log -Message "$($okapp.AppID) has blocking process $runningProcessName running, but PromptWhenBlocked=true, allowing remediation"
                                    # Continue processing - app will reach remediation script for interactive handling
                                } else {
                                    Write-Log -Message "Skipping $($okapp.AppID) - blocking process $runningProcessName is running (PromptWhenBlocked not set)"
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
                    $message += $app + "|"
                }
            }
        }

        if ($count -eq 0) {
            Write-Log -Message "[$ScriptTag] No upgrades available"
            exit 0
        }
        if ($message -eq "") {
            $message = "[$ScriptTag] No upgrades available (0x0000001-$count)"
        }
        Write-Log -Message "[$ScriptTag] $message"
        exit 1
    }
    Write-Log -Message "No upgrades (0x0000002)"
    exit 0
}
Write-Log -Message "Winget not detected"
exit 0
