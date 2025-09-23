<#
.SYNOPSIS
    Heimdal Thor Detection Script for Microsoft Intune

.DESCRIPTION
    This script detects if Heimdal Thor Agent is installed on the system.
    It is designed to work as a detection script in Microsoft Intune remediation policies.
    
    The script searches the Windows registry for Heimdal/Thor applications and reports
    their presence to trigger remediation if needed.

.NOTES
    Author: Henrik Skovgaard
    Version: 1.0
    Tag: 1A
    
    Exit Codes:
    0 - Heimdal Thor not detected (compliant - no remediation needed)
    1 - Heimdal Thor detected (non-compliant - remediation required)
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
    [CmdletBinding()]
    param()
    process {
        return [bool]($(whoami -user) -match 'S-1-5-18')
    }
}

function Write-Log($message) {
    $LogMessage = ((Get-Date -Format "dd.MM.yyyy HH:mm:ss ") + $message)
    # Extract ScriptTag from message if present, or use global variable
    if ($message -match '^\[([A-Z0-9]+)\]\s*(.*)') {
        $tag = $matches[1]
        $cleanMessage = $matches[2]
        $ConsoleMessage = "[$tag] " + (Get-Date -Format "HH:mm:ss ") + $cleanMessage
    } else {
        $ConsoleMessage = "[$ScriptTag] " + (Get-Date -Format "HH:mm:ss ") + $message
    }
    Write-Host $ConsoleMessage
    Out-File -InputObject $LogMessage -FilePath "$LogPath\$LogFullName" -Append -Encoding utf8
}

function Test-OOBEComplete {
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

function Get-HeimdalInstallations {
    <#
    .SYNOPSIS
        Searches for Heimdal Thor installations in the Windows registry
    .DESCRIPTION
        Searches both 32-bit and 64-bit uninstall registry keys for Heimdal or Thor applications
    .OUTPUTS
        Array of installed Heimdal/Thor applications with their details
    #>
    
    try {
        Write-Log "Searching for Heimdal Thor installations"
        
        # Get all uninstall keys
        $uninstallKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        # Find Heimdal entries
        $heimdalApps = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*Heimdal*" -or $_.DisplayName -like "*Thor*" 
        }

        $installedApps = @()
        
        if ($heimdalApps) {
            foreach ($app in $heimdalApps) {
                Write-Log "Found installation: $($app.DisplayName)"
                
                $appInfo = @{
                    DisplayName = $app.DisplayName
                    Publisher = $app.Publisher
                    Version = $app.DisplayVersion
                    InstallDate = $app.InstallDate
                    ProductCode = $app.PSChildName
                    UninstallString = $app.UninstallString
                    QuietUninstallString = $app.QuietUninstallString
                }
                
                $installedApps += $appInfo
                
                # Log key details
                Write-Log "  Publisher: $($app.Publisher)"
                Write-Log "  Version: $($app.DisplayVersion)"
                Write-Log "  Product Code: $($app.PSChildName)"
            }
        }
        
        return $installedApps
        
    } catch {
        Write-Log "Error searching for Heimdal installations: $_" -Level Error
        return @()
    }
}

function Remove-OldLogs {
    param([string]$LogPath)
    
    try {
        $cutoffDate = (Get-Date).AddMonths(-1)
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*DetectHeimdal*.log" -ErrorAction SilentlyContinue
        foreach ($logFile in $logFiles) {
            if ($logFile.LastWriteTime -lt $cutoffDate) {
                Remove-Item -Path $logFile.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Removed old log file: $($logFile.Name)"
            }
        }
    } catch {
        # Don't use Write-Log here as it may not be ready yet - just silently continue
    }
}

# Script variables
$ScriptTag = "1A"
$LogName = 'DetectHeimdalThor'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm
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

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Log script start with full date
Write-Log "Detection script started on $(Get-Date -Format 'dd.MM.yyyy')"

# Check OOBE completion
if (-not (Test-OOBEComplete)) {
    Write-Log "OOBE not complete, exiting detection"
    "OOBE"
    exit 0
}

# Main detection logic
try {
    Write-Log "Starting Heimdal Thor detection"
    
    $installedApps = Get-HeimdalInstallations
    
    if ($installedApps.Count -gt 0) {
        Write-Log "[$ScriptTag] Heimdal Thor installations detected: $($installedApps.Count) found"
        
        foreach ($app in $installedApps) {
            Write-Log "[$ScriptTag] Found: $($app.DisplayName) v$($app.Version)"
        }
        
        Write-Log "[$ScriptTag] Non-compliant - remediation required"
        exit 1  # Non-compliant, trigger remediation
        
    } else {
        Write-Log "[$ScriptTag] No Heimdal Thor installations found"
        Write-Log "[$ScriptTag] Compliant - no remediation needed"
        exit 0  # Compliant, no remediation needed
    }
    
} catch {
    Write-Log "Error during detection: $_"
    Write-Log "[$ScriptTag] Detection failed - assuming non-compliant for safety"
    exit 1  # Assume non-compliant on error to trigger remediation
}