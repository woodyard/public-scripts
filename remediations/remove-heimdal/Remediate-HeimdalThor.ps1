<#
.SYNOPSIS
    Heimdal Thor Remediation Script for Microsoft Intune

.DESCRIPTION
    This script uninstalls Heimdal Thor Agent from the system.
    It is designed to work as a remediation script in Microsoft Intune remediation policies.
    
    The script searches the Windows registry for Heimdal/Thor applications and attempts
    to uninstall them using MSI product codes or uninstall strings.

.NOTES
    Author: Henrik Skovgaard
    Version: 1.0
    Tag: 1A
    
    Exit Codes:
    0 - Remediation completed successfully (uninstalled or nothing to uninstall)
    1 - Remediation failed (error during uninstall process)
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
        Write-Log "Error searching for Heimdal installations: $_"
        return @()
    }
}

function Uninstall-HeimdalApplication {
    <#
    .SYNOPSIS
        Attempts to uninstall a specific Heimdal application
    .PARAMETER AppInfo
        Application information object containing uninstall details
    .OUTPUTS
        Boolean indicating success or failure
    #>
    param(
        [hashtable]$AppInfo
    )
    
    try {
        Write-Log "Attempting to uninstall: $($AppInfo.DisplayName)"
        
        $uninstallSuccess = $false
        
        # Method 1: Use MSI product code if available
        if ($AppInfo.ProductCode -match '^{[A-Z0-9\-]+}$') {
            Write-Log "Attempting MSI uninstall with product code: $($AppInfo.ProductCode)"
            $process = Start-Process "msiexec.exe" -ArgumentList "/x $($AppInfo.ProductCode) /qn" -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Successfully uninstalled via MSI: $($AppInfo.DisplayName)"
                $uninstallSuccess = $true
            } else {
                Write-Log "MSI uninstall failed with exit code: $($process.ExitCode)"
            }
        }
        
        # Method 2: Use uninstall string if MSI failed or not available
        if (-not $uninstallSuccess -and $AppInfo.UninstallString) {
            Write-Log "Using uninstall string: $($AppInfo.UninstallString)"
            
            # Handle MSI uninstall strings
            if ($AppInfo.UninstallString -match "MsiExec.exe") {
                $productCode = $AppInfo.UninstallString | Select-String -Pattern "{[A-Z0-9\-]+}" | 
                             ForEach-Object { $_.Matches[0].Value }
                
                if ($productCode) {
                    Write-Log "Extracted product code from uninstall string: $productCode"
                    $process = Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn" -Wait -PassThru
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log "Successfully uninstalled via MSI product code: $($AppInfo.DisplayName)"
                        $uninstallSuccess = $true
                    } else {
                        Write-Log "MSI uninstall failed with exit code: $($process.ExitCode)"
                    }
                }
            } else {
                # Handle non-MSI uninstall strings
                $uninstallString = $AppInfo.UninstallString
                if ($uninstallString -notlike "* /quiet*") {
                    $uninstallString = "$uninstallString /quiet /norestart"
                }
                
                Write-Log "Executing uninstall string: $uninstallString"
                $process = Start-Process "cmd.exe" -ArgumentList "/c `"$uninstallString`"" -Wait -PassThru
                
                if ($process.ExitCode -eq 0) {
                    Write-Log "Successfully uninstalled via uninstall string: $($AppInfo.DisplayName)"
                    $uninstallSuccess = $true
                } else {
                    Write-Log "Uninstall failed with exit code: $($process.ExitCode)"
                }
            }
        }
        
        # Method 3: Use quiet uninstall string if available and previous methods failed
        if (-not $uninstallSuccess -and $AppInfo.QuietUninstallString) {
            Write-Log "Using quiet uninstall string: $($AppInfo.QuietUninstallString)"
            $process = Start-Process "cmd.exe" -ArgumentList "/c `"$($AppInfo.QuietUninstallString)`"" -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Successfully uninstalled via quiet uninstall string: $($AppInfo.DisplayName)"
                $uninstallSuccess = $true
            } else {
                Write-Log "Quiet uninstall failed with exit code: $($process.ExitCode)"
            }
        }
        
        if (-not $uninstallSuccess) {
            Write-Log "No valid uninstall method succeeded for: $($AppInfo.DisplayName)"
        }
        
        return $uninstallSuccess
        
    } catch {
        Write-Log "Error during uninstall of $($AppInfo.DisplayName): $_"
        return $false
    }
}

function Test-RemediationSuccess {
    <#
    .SYNOPSIS
        Verifies that Heimdal Thor has been successfully removed
    .OUTPUTS
        Boolean indicating whether remediation was successful
    #>
    
    try {
        Write-Log "Verifying remediation success"
        
        $remainingApps = Get-HeimdalInstallations
        
        if ($remainingApps.Count -eq 0) {
            Write-Log "Remediation verification successful - no Heimdal installations found"
            return $true
        } else {
            Write-Log "Remediation verification failed - $($remainingApps.Count) installations still present:"
            foreach ($app in $remainingApps) {
                Write-Log "  - $($app.DisplayName)"
            }
            return $false
        }
        
    } catch {
        Write-Log "Error during remediation verification: $_"
        return $false
    }
}

function Remove-OldLogs {
    param([string]$LogPath)
    
    try {
        $cutoffDate = (Get-Date).AddMonths(-1)
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*RemediateHeimdal*.log" -ErrorAction SilentlyContinue
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
$LogName = 'RemediateHeimdalThor'
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
Write-Log "Remediation script started on $(Get-Date -Format 'dd.MM.yyyy')"

# Check OOBE completion
if (-not (Test-OOBEComplete)) {
    Write-Log "OOBE not complete, exiting remediation"
    "OOBE"
    exit 0
}

# Main remediation logic
try {
    Write-Log "Starting Heimdal Thor remediation"
    
    $installedApps = Get-HeimdalInstallations
    
    if ($installedApps.Count -eq 0) {
        Write-Log "[$ScriptTag] No Heimdal Thor installations found - nothing to remediate"
        Write-Log "[$ScriptTag] Remediation completed successfully"
        exit 0  # Success - nothing to uninstall
    }
    
    Write-Log "[$ScriptTag] Found $($installedApps.Count) Heimdal Thor installation(s) to remove"
    
    $overallSuccess = $true
    $successCount = 0
    $failureCount = 0
    
    # Process each installation
    foreach ($app in $installedApps) {
        Write-Log "Processing: $($app.DisplayName)"
        
        $uninstallResult = Uninstall-HeimdalApplication -AppInfo $app
        
        if ($uninstallResult) {
            $successCount++
            Write-Log "Successfully processed: $($app.DisplayName)"
        } else {
            $failureCount++
            $overallSuccess = $false
            Write-Log "Failed to process: $($app.DisplayName)"
        }
    }
    
    Write-Log "Uninstall summary: $successCount successful, $failureCount failed"
    
    # Wait a moment for registry updates
    Start-Sleep -Seconds 3
    
    # Verify remediation success
    $verificationSuccess = Test-RemediationSuccess
    
    if ($verificationSuccess) {
        Write-Log "[$ScriptTag] Remediation completed successfully - all Heimdal installations removed"
        exit 0  # Success
    } else {
        Write-Log "[$ScriptTag] Remediation failed - some installations remain"
        exit 1  # Failure
    }
    
} catch {
    Write-Log "Error during remediation: $_"
    Write-Log "[$ScriptTag] Remediation failed with exception"
    exit 1  # Failure
}