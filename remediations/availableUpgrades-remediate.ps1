<#
.SYNOPSIS
    Winget Application Update Remediation Script

.DESCRIPTION
    This script performs application updates using winget based on a whitelist approach.
    It supports both system and user context applications and includes blocking process detection.
    The script is designed to work as a remediation script in Microsoft Intune remediation policies.

.NOTES
 Author: Henrik Skovgaard
 Version: 6.0
 Tag: 9R
    
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
    3.9 - Improved log management: dynamic path selection (Intune logs for system context), automatic cleanup of logs older than 1 month
    4.0 - Added PromptWhenBlocked property support for granular control over interactive dialogs vs silent waiting when blocking processes are running
    4.1 - Fixed Windows Forms dialog for non-interactive/system context execution, resolved quser command path issues, improved system context error handling, added user session dialog display for system context
    4.2 - Enhanced user session dialog display with multiple fallback approaches and improved reliability
    4.3 - Fixed quser.exe availability issues with multiple path detection and comprehensive WMI-based fallback mechanisms for user session detection and dialog display
    4.4 - Fixed scheduled task LogonType enumeration error (InteractiveToken to Interactive) for proper VBScript dialog execution in user context
    4.5 - Enhanced VBScript dialog execution with direct process approach and improved scheduled task debugging for better dialog reliability
    4.6 - Added multiple user notification methods: msg.exe alerts, balloon tip notifications, and simplified notification approach for better user visibility
    5.0 - MAJOR UPDATE: Implemented Windows 10/11 Toast Notifications with interactive Yes/No buttons for true user dialog capability from system service context
    6.0 - COMPLETE REWRITE: Replaced all problematic dialog systems with robust Windows Toast Notifications and PowerShell WPF dialogs with comprehensive fallback mechanisms
    
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

function Get-ActiveUserSessions {
    <#
    .SYNOPSIS
        Gets active user sessions using Explorer process detection
    .DESCRIPTION
        Finds active desktop sessions by looking for explorer.exe processes
        Uses the correct session ID format for user interaction
    .OUTPUTS
        Array of session objects with SessionId and UserName properties
    #>
    
    $activeSessions = @()
    
    try {
        Write-Log -Message "Detecting active user sessions via Explorer processes" | Out-Null
        
        # Primary method: Use Explorer process to find active desktop sessions
        # This gives us the correct session ID format for user interaction
        $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
        
        foreach ($process in $explorerProcesses) {
            Write-Log -Message "Found explorer.exe in session $($process.SessionId)" | Out-Null
            $activeSessions += [PSCustomObject]@{
                SessionId = $process.SessionId
                UserName = "User"
                LogonType = "Desktop"
                ProcessId = $process.Id
            }
        }
        
        # Sort by session ID to get the most likely user session first
        $activeSessions = $activeSessions | Sort-Object SessionId
        
        Write-Log -Message "Found $($activeSessions.Count) active desktop session(s)" | Out-Null
        
        # Log all sessions for debugging
        foreach ($session in $activeSessions) {
            Write-Log -Message "Session ID: $($session.SessionId)" | Out-Null
        }
        
        return $activeSessions
        
    } catch {
        Write-Log -Message "Error detecting user sessions: $($_.Exception.Message)" | Out-Null
        return @()
    }
}

function Show-ToastNotification {
    <#
    .SYNOPSIS
        Shows actual Windows Toast Notifications with interactive Yes/No buttons
    .DESCRIPTION
        Uses Windows Runtime to display native toast notifications from SYSTEM context to user sessions
        This provides true interactive notifications with proper user response handling
    .PARAMETER AppID
        Application ID for the update
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false
    )
    
    Write-Log -Message "Show-ToastNotification called for $AppID ($FriendlyName)" | Out-Null
    
    try {
        # Get active user sessions
        $activeSessions = Get-ActiveUserSessions
        if ($activeSessions.Count -eq 0) {
            Write-Log -Message "No active user sessions found for toast notification" | Out-Null
            return $DefaultTimeoutAction
        }
        
        $primarySession = $activeSessions[0]
        Write-Log -Message "Using session $($primarySession.SessionId) for toast notification" | Out-Null
        
        # Create unique response file for toast interaction
        $responseFile = "$env:TEMP\ToastResponse_$([guid]::NewGuid().ToString().Substring(0,8)).txt"
        
        # Create PowerShell script that shows actual Windows Toast notifications
        $toastScript = @'
        param([string]$ResponseFile, [string]$FriendlyName, [int]$TimeoutSeconds, [bool]$DefaultTimeoutAction)
        
        # Force execution via Windows PowerShell 5.1 if running from PowerShell 7+
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $windowsPSPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            Add-Content -Path "$ResponseFile.log" -Value "Detected PowerShell $($PSVersionTable.PSVersion) - redirecting to Windows PowerShell 5.1"
            
            $arguments = @(
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-File", "`"$PSCommandPath`"",
                "-ResponseFile", "`"$ResponseFile`"",
                "-FriendlyName", "`"$FriendlyName`"",
                "-TimeoutSeconds", "$TimeoutSeconds",
                "-DefaultTimeoutAction", "`$$DefaultTimeoutAction"
            )
            
            try {
                Start-Process -FilePath $windowsPSPath -ArgumentList $arguments -Wait -NoNewWindow
                Add-Content -Path "$ResponseFile.log" -Value "Successfully redirected to Windows PowerShell 5.1"
            } catch {
                Add-Content -Path "$ResponseFile.log" -Value "Failed to redirect to Windows PowerShell 5.1: $($_.Exception.Message)"
            }
            exit
        }
        
        # Log script execution
        Add-Content -Path "$ResponseFile.log" -Value "Toast script started at $(Get-Date)"
        Add-Content -Path "$ResponseFile.log" -Value "Current user: $(whoami)"
        Add-Content -Path "$ResponseFile.log" -Value "Session name: $env:SESSIONNAME"
        Add-Content -Path "$ResponseFile.log" -Value "PowerShell version: $($PSVersionTable.PSVersion)"
        Add-Content -Path "$ResponseFile.log" -Value "Execution policy: $(Get-ExecutionPolicy)"
        Add-Content -Path "$ResponseFile.log" -Value "FriendlyName: $FriendlyName"
        Add-Content -Path "$ResponseFile.log" -Value "TimeoutSeconds: $TimeoutSeconds"
        Add-Content -Path "$ResponseFile.log" -Value "DefaultTimeoutAction: $DefaultTimeoutAction"

try {
    # Check Windows version for toast support
    $osVersion = [System.Environment]::OSVersion.Version
    Add-Content -Path "$ResponseFile.log" -Value "OS Version: $($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)"
    
    if ($osVersion.Major -lt 10) {
        Add-Content -Path "$ResponseFile.log" -Value "Toast notifications require Windows 10 or later"
        # Fallback to MessageBox for older Windows
        Add-Type -AssemblyName System.Windows.Forms
        $message = "An update is available for $FriendlyName, but it cannot be installed while the application is running.`n`nWould you like to close $FriendlyName now to allow the update to proceed?"
        $result = [System.Windows.Forms.MessageBox]::Show($message, "Application Update Available", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
        } else {
            "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
        }
        return
    }
    
    Add-Content -Path "$ResponseFile.log" -Value "Loading Windows Runtime assemblies"
    
    # Load Windows Runtime assemblies for Toast notifications
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    
    # Alternative method if above fails
    if (-not ([System.Management.Automation.PSTypeName]'Windows.UI.Notifications.ToastNotificationManager').Type) {
        [void][Windows.UI.Notifications.ToastNotificationManager]
        [void][Windows.Data.Xml.Dom.XmlDocument]
    }
    
    Add-Content -Path "$ResponseFile.log" -Value "Windows Runtime assemblies loaded successfully"
    
    # Create toast XML template with protocol activation for button responses
        # For test mode, show a different message
        if ($FriendlyName -eq "Toast Test Application") {
            $toastXml = @"
    <toast duration="long">
        <visual>
            <binding template="ToastGeneric">
                <text>🎉 SYSTEM Toast Test Success!</text>
                <text>This toast notification was sent from SYSTEM context to your user session. The cross-session toast mechanism is working correctly!</text>
            </binding>
        </visual>
        <actions>
            <action content="Great!" arguments="action=success" activationType="background" />
            <action content="Dismiss" arguments="action=dismiss" activationType="background" />
        </actions>
    </toast>
    "@
        } else {
            $toastXml = @"
    <toast activationType="protocol" launch="action=timeout" duration="long">
        <visual>
            <binding template="ToastGeneric">
                <text>Application Update Available</text>
                <text>An update is available for $FriendlyName, but it cannot be installed while the application is running. Would you like to close $FriendlyName now to allow the update to proceed?</text>
            </binding>
        </visual>
        <actions>
            <action content="Yes, Close App" arguments="action=yes" activationType="protocol" />
            <action content="No, Keep Open" arguments="action=no" activationType="protocol" />
        </actions>
    </toast>
    "@
        }

    Add-Content -Path "$ResponseFile.log" -Value "Toast XML template created"
    
    # Create XmlDocument
    $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xmlDoc.LoadXml($toastXml)
    
    Add-Content -Path "$ResponseFile.log" -Value "XML document loaded"
    
    # Create toast notification
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xmlDoc
    
    # Set expiration time
    $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds($TimeoutSeconds)
    
    Add-Content -Path "$ResponseFile.log" -Value "Toast notification object created with expiration"
    
    # Get toast notifier for PowerShell
    $appId = "Microsoft.PowerShell_8wekyb3d8bbwe!powershell"
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
    
    Add-Content -Path "$ResponseFile.log" -Value "Toast notifier created for app ID: $appId"
    
    # Add event handlers for user interaction
    $activated = $false
    $activationArgs = ""
    
    # Register activation handler
    Register-ObjectEvent -InputObject $toast -EventName Activated -Action {
        $activationArgs = $Event.SourceEventArgs.Arguments
        $activated = $true
        Add-Content -Path "$ResponseFile.log" -Value "Toast activated with arguments: $activationArgs"
        
        if ($activationArgs -like "*action=yes*") {
            "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "User clicked YES"
        } elseif ($activationArgs -like "*action=no*") {
            "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "User clicked NO"
        } else {
            # Default action on timeout or unexpected activation
            if ($DefaultTimeoutAction) {
                "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
                Add-Content -Path "$ResponseFile.log" -Value "Timeout - used default action YES"
            } else {
                "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
                Add-Content -Path "$ResponseFile.log" -Value "Timeout - used default action NO"
            }
        }
    } | Out-Null
    
    # Register dismissed handler
    Register-ObjectEvent -InputObject $toast -EventName Dismissed -Action {
        $dismissedReason = $Event.SourceEventArgs.Reason
        Add-Content -Path "$ResponseFile.log" -Value "Toast dismissed with reason: $dismissedReason"
        
        if (-not (Test-Path $ResponseFile)) {
            # Only write default if no response was already recorded
            if ($DefaultTimeoutAction) {
                "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
                Add-Content -Path "$ResponseFile.log" -Value "Dismissed - used default action YES"
            } else {
                "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
                Add-Content -Path "$ResponseFile.log" -Value "Dismissed - used default action NO"
            }
        }
    } | Out-Null
    
    # Show the toast
    Add-Content -Path "$ResponseFile.log" -Value "About to show toast notification"
    $notifier.Show($toast)
    Add-Content -Path "$ResponseFile.log" -Value "Toast notification displayed successfully"
    
    # Wait for user response or timeout
    $waitTime = 0
    while ($waitTime -lt $TimeoutSeconds -and -not (Test-Path $ResponseFile)) {
        Start-Sleep -Seconds 1
        $waitTime++
    }
    
    # If no response file exists after timeout, create default response
    if (-not (Test-Path $ResponseFile)) {
        if ($DefaultTimeoutAction) {
            "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Final timeout - used default action YES"
        } else {
            "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Final timeout - used default action NO"
        }
    }
    
} catch {
    Add-Content -Path "$ResponseFile.log" -Value "Error in toast script: $($_.Exception.Message)"
    Add-Content -Path "$ResponseFile.log" -Value "Exception details: $($_.Exception.ToString())"
    
    # Fallback to MessageBox on toast failure
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $message = "An update is available for $FriendlyName, but it cannot be installed while the application is running.`n`nWould you like to close $FriendlyName now to allow the update to proceed?"
        $result = [System.Windows.Forms.MessageBox]::Show($message, "Application Update Available", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Fallback MessageBox - User clicked YES"
        } else {
            "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Fallback MessageBox - User clicked NO"
        }
    } catch {
        # Ultimate fallback
        if ($DefaultTimeoutAction) {
            "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Ultimate fallback - used default action YES"
        } else {
            "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
            Add-Content -Path "$ResponseFile.log" -Value "Ultimate fallback - used default action NO"
        }
    }
}

Add-Content -Path "$ResponseFile.log" -Value "Toast script completed at $(Get-Date)"
'@
        
        # Write the PowerShell script to temp file
        $scriptPath = "$env:TEMP\ToastScript_$([guid]::NewGuid().ToString().Substring(0,8)).ps1"
        $toastScript | Out-File -FilePath $scriptPath -Encoding UTF8
        
        # Execute toast script in user session
                $scriptExecuted = $false
                
                # Force Windows PowerShell 5.1 execution for Windows Runtime compatibility
                $windowsPSPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                if (-not (Test-Path $windowsPSPath)) {
                    $windowsPSPath = "powershell.exe"  # Fallback to PATH
                }
                
                Write-Log -Message "Using Windows PowerShell for toast notifications: $windowsPSPath" | Out-Null
                
                # Try direct user context execution first (more likely to work)
                try {
                    Write-Log -Message "Trying direct user context execution via PsExec if available" | Out-Null
                    $psexecPath = "$env:ProgramData\chocolatey\bin\PsExec.exe"
                    
                    if (Test-Path $psexecPath) {
                        Write-Log -Message "PsExec found, attempting direct user session execution" | Out-Null
                        $psexecArgs = "-accepteula -s -i $($primarySession.SessionId) -d `"$windowsPSPath`" -ExecutionPolicy Bypass -WindowStyle Normal -File `"$scriptPath`" -ResponseFile `"$responseFile`" -FriendlyName `"$FriendlyName`" -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction `$$DefaultTimeoutAction"
                        
                        Write-Log -Message "PsExec command: $psexecPath $psexecArgs" | Out-Null
                        Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -WindowStyle Hidden -Wait:$false
                        $scriptExecuted = $true
                        Write-Log -Message "PsExec execution started" | Out-Null
                    } else {
                        Write-Log -Message "PsExec not available, trying scheduled task approach" | Out-Null
                    }
                } catch {
                    Write-Log -Message "PsExec execution failed: $($_.Exception.Message)" | Out-Null
                }
                
                # Try scheduled task if PsExec wasn't available or failed
                if (-not $scriptExecuted) {
                    try {
                        Write-Log -Message "Executing toast notification via scheduled task with Windows PowerShell 5.1" | Out-Null
                        $taskName = "ToastTask_$([guid]::NewGuid().ToString().Substring(0,8))"
                        
                        # Enhanced task arguments with better logging
                        $taskArgs = "-ExecutionPolicy Bypass -WindowStyle Normal -NoProfile -Command `"& '$scriptPath' -ResponseFile '$responseFile' -FriendlyName '$FriendlyName' -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction `$$DefaultTimeoutAction`""
                        
                        $action = New-ScheduledTaskAction -Execute $windowsPSPath -Argument $taskArgs
                        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive -RunLevel Highest
                        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
                        
                        Write-Log -Message "Task arguments: $taskArgs" | Out-Null
                        Write-Log -Message "Registering scheduled task: $taskName" | Out-Null
                        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
                        Write-Log -Message "Starting scheduled task: $taskName" | Out-Null
                        Start-ScheduledTask -TaskName $taskName
                        
                        Write-Log -Message "Waiting 10 seconds for task execution" | Out-Null
                        Start-Sleep -Seconds 10
                        
                        # Check task status with more detail
                        try {
                            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                            if ($task) {
                                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                                Write-Log -Message "Task last run time: $($taskInfo.LastRunTime), Last result: 0x$([Convert]::ToString($taskInfo.LastTaskResult, 16))" | Out-Null
                                Write-Log -Message "Task state: $($task.State)" | Out-Null
                                
                                # Check if task is still running
                                if ($task.State -eq "Running") {
                                    Write-Log -Message "Task is still running, waiting additional 10 seconds" | Out-Null
                                    Start-Sleep -Seconds 10
                                }
                            }
                        } catch {
                            Write-Log -Message "Could not get task status: $($_.Exception.Message)" | Out-Null
                        }
                        
                        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-Log -Message "Scheduled task $taskName completed and removed" | Out-Null
                        $scriptExecuted = $true
                        
                    } catch {
                        Write-Log -Message "Scheduled task toast execution failed: $($_.Exception.Message)" | Out-Null
                    }
                }
        
        if (-not $scriptExecuted) {
            Write-Log -Message "Could not execute toast script, falling back to ServiceUI.exe approach" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            return Show-ServiceUIDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Wait for response with shorter timeout since scheduled tasks may not work
        Write-Log -Message "Waiting for toast response file: $responseFile" | Out-Null
        $waitTime = 0
        $maxWaitTime = 15  # Shorter wait time to fail fast to fallback
        
        while ($waitTime -lt $maxWaitTime -and -not (Test-Path $responseFile)) {
            Start-Sleep -Seconds 1
            $waitTime++
            if ($waitTime % 5 -eq 0) {
                Write-Log -Message "Still waiting for toast response... ($waitTime/$maxWaitTime seconds)" | Out-Null
            }
        }
        
        # Read response
        $userResponse = $DefaultTimeoutAction
        if (Test-Path $responseFile) {
            try {
                $responseContent = Get-Content $responseFile -Raw -ErrorAction SilentlyContinue
                $responseContent = $responseContent.Trim()
                
                if ($responseContent -eq "YES") {
                    $userResponse = $true
                    Write-Log -Message "User chose to close $FriendlyName via toast notification" | Out-Null
                } elseif ($responseContent -eq "NO") {
                    $userResponse = $false
                    Write-Log -Message "User chose to keep $FriendlyName open via toast notification" | Out-Null
                } else {
                    Write-Log -Message "Unexpected toast response: $responseContent, using default action" | Out-Null
                }
                
                Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading toast response: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No toast response file created after $maxWaitTime seconds - toast notification may have failed" | Out-Null
            Write-Log -Message "Falling back to ServiceUI dialog approach" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            return Show-ServiceUIDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Check for debug log and report information
        $debugLogFile = $responseFile + ".log"
        if (Test-Path $debugLogFile) {
            try {
                $debugContent = Get-Content $debugLogFile -ErrorAction SilentlyContinue
                Write-Log -Message "Toast debug log found with $($debugContent.Count) lines" | Out-Null
                
                # Report key lines from debug log
                foreach ($line in $debugContent) {
                    if (-not [string]::IsNullOrWhiteSpace($line) -and
                        ($line -like "*successfully*" -or $line -like "*error*" -or $line -like "*clicked*" -or $line -like "*timeout*")) {
                        Write-Log -Message "TOAST: $line" | Out-Null
                    }
                }
                
                Remove-Item $debugLogFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading toast debug log: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No toast debug log found" | Out-Null
        }
        
        # Clean up files
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        
        return $userResponse
        
    } catch {
        Write-Log -Message "Toast notification system failed: $($_.Exception.Message)" | Out-Null
        Write-Log -Message "Falling back to ServiceUI dialog" | Out-Null
        return Show-ServiceUIDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
    }
}

function Show-ServiceUIDialog {
    <#
    .SYNOPSIS
        Shows a user notification using ServiceUI.exe for cross-session messaging (fallback)
    .DESCRIPTION
        Uses ServiceUI.exe from Microsoft Deployment Toolkit to display dialogs from SYSTEM context to user sessions
        This is a fallback when toast notifications fail
    .PARAMETER AppID
        Application ID for the update
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false
    )
    
    Write-Log -Message "Show-ServiceUIDialog called for $AppID ($FriendlyName)" | Out-Null
    
    try {
        # Get active user sessions
        $activeSessions = Get-ActiveUserSessions
        if ($activeSessions.Count -eq 0) {
            Write-Log -Message "No active user sessions found for ServiceUI dialog" | Out-Null
            return $DefaultTimeoutAction
        }
        
        $primarySession = $activeSessions[0]
        Write-Log -Message "Using session $($primarySession.SessionId) for ServiceUI dialog" | Out-Null
        
        # Create unique response file
        $responseFile = "$env:TEMP\ServiceUIResponse_$([guid]::NewGuid().ToString().Substring(0,8)).txt"
        
        # Look for ServiceUI.exe in common locations
        $serviceUILocations = @(
            "$env:ProgramData\ServiceUI\ServiceUI.exe",  # Our download location (check first)
            "$env:SystemRoot\System32\ServiceUI.exe",
            "$env:SystemRoot\SysWOW64\ServiceUI.exe",
            "$env:ProgramFiles\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x64\ServiceUI.exe",
            "$env:ProgramFiles(x86)\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x86\ServiceUI.exe",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Deployment Toolkit\ServiceUI.exe"
        )
        
        $serviceUIPath = $null
        foreach ($location in $serviceUILocations) {
            if (Test-Path $location) {
                $serviceUIPath = $location
                Write-Log -Message "Found ServiceUI.exe at: $serviceUIPath" | Out-Null
                break
            }
        }
        
        if (-not $serviceUIPath) {
            Write-Log -Message "ServiceUI.exe not found, falling back to PowerShell dialog" | Out-Null
            return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Create PowerShell script that shows MessageBox
        $messageBoxScript = @'
param([string]$ResponseFile, [string]$FriendlyName)

# Log script execution
Add-Content -Path "$ResponseFile.log" -Value "ServiceUI script started at $(Get-Date)"
Add-Content -Path "$ResponseFile.log" -Value "Current user: $(whoami)"
Add-Content -Path "$ResponseFile.log" -Value "Session name: $env:SESSIONNAME"
Add-Content -Path "$ResponseFile.log" -Value "FriendlyName: $FriendlyName"

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Content -Path "$ResponseFile.log" -Value "System.Windows.Forms loaded successfully"
    
    $message = "An update is available for $FriendlyName, but it cannot be installed while the application is running.`n`nWould you like to close $FriendlyName now to allow the update to proceed?"
    $title = "Application Update Available"
    
    Add-Content -Path "$ResponseFile.log" -Value "About to show MessageBox"
    
    # Show MessageBox with TopMost to ensure visibility
    $result = [System.Windows.Forms.MessageBox]::Show($message, $title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question, [System.Windows.Forms.MessageBoxDefaultButton]::Button2, [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly)
    
    Add-Content -Path "$ResponseFile.log" -Value "MessageBox result: $result"
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
        Add-Content -Path "$ResponseFile.log" -Value "User clicked YES - wrote to response file"
    } else {
        "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
        Add-Content -Path "$ResponseFile.log" -Value "User clicked NO - wrote to response file"
    }
    
} catch {
    Add-Content -Path "$ResponseFile.log" -Value "Error: $($_.Exception.Message)"
    # Default to NO on error
    "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
    Add-Content -Path "$ResponseFile.log" -Value "Used default NO due to error"
}

Add-Content -Path "$ResponseFile.log" -Value "ServiceUI script completed at $(Get-Date)"
'@
        
        # Write the PowerShell script to temp file
        $scriptPath = "$env:TEMP\ServiceUIScript_$([guid]::NewGuid().ToString().Substring(0,8)).ps1"
        $messageBoxScript | Out-File -FilePath $scriptPath -Encoding UTF8
        
        # Execute using ServiceUI.exe
        try {
            Write-Log -Message "Executing dialog via ServiceUI.exe" | Out-Null
            
            # ServiceUI.exe syntax from help: serviceui -session:4 program "arguments"
            # All PowerShell arguments must be combined into single quoted string
            $powershellArgs = "-ExecutionPolicy Bypass -WindowStyle Normal -File \`"$scriptPath\`" -ResponseFile \`"$responseFile\`" -FriendlyName \`"$FriendlyName\`""
            $serviceUIArgs = @(
                "-session:$($primarySession.SessionId)",
                "powershell.exe",
                "`"$powershellArgs`""
            )
            
            Write-Log -Message "ServiceUI command: $serviceUIPath $($serviceUIArgs -join ' ')" | Out-Null
            
            # Start ServiceUI process and wait for completion
            $process = Start-Process -FilePath $serviceUIPath -ArgumentList $serviceUIArgs -Wait -PassThru -WindowStyle Hidden
            Write-Log -Message "ServiceUI.exe exit code: $($process.ExitCode)" | Out-Null
            
            $scriptExecuted = $true
            
        } catch {
            Write-Log -Message "ServiceUI.exe execution failed: $($_.Exception.Message)" | Out-Null
            $scriptExecuted = $false
        }
        
        if (-not $scriptExecuted) {
            Write-Log -Message "ServiceUI.exe failed, falling back to PowerShell dialog" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Read response
        $userResponse = $DefaultTimeoutAction
        if (Test-Path $responseFile) {
            try {
                $responseContent = Get-Content $responseFile -Raw -ErrorAction SilentlyContinue
                $responseContent = $responseContent.Trim()
                
                if ($responseContent -eq "YES") {
                    $userResponse = $true
                    Write-Log -Message "User chose to close $FriendlyName via ServiceUI dialog" | Out-Null
                } elseif ($responseContent -eq "NO") {
                    $userResponse = $false
                    Write-Log -Message "User chose to keep $FriendlyName open via ServiceUI dialog" | Out-Null
                } else {
                    Write-Log -Message "Unexpected ServiceUI response: $responseContent, using default action" | Out-Null
                }
                
                Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading ServiceUI response: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No ServiceUI response file created, using default action: $DefaultTimeoutAction" | Out-Null
        }
        
        # Check for debug log and report information
        $debugLogFile = $responseFile + ".log"
        if (Test-Path $debugLogFile) {
            try {
                $debugContent = Get-Content $debugLogFile -ErrorAction SilentlyContinue
                Write-Log -Message "ServiceUI debug log found with $($debugContent.Count) lines" | Out-Null
                
                # Report key lines from debug log
                foreach ($line in $debugContent) {
                    if (-not [string]::IsNullOrWhiteSpace($line) -and
                        ($line -like "*successfully*" -or $line -like "*error*" -or $line -like "*clicked*")) {
                        Write-Log -Message "SERVICEUI: $line" | Out-Null
                    }
                }
                
                Remove-Item $debugLogFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading ServiceUI debug log: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No ServiceUI debug log found" | Out-Null
        }
        
        # Clean up files
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        
        return $userResponse
        
    } catch {
        Write-Log -Message "ServiceUI dialog system failed: $($_.Exception.Message)" | Out-Null
        Write-Log -Message "Falling back to PowerShell dialog" | Out-Null
        return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
    }
}

function Show-PowerShellDialog {
    <#
    .SYNOPSIS
        Fallback dialog system using PowerShell runspace
    .DESCRIPTION
        Creates a PowerShell dialog in user context as fallback when toast notifications fail
    .PARAMETER AppID
        Application ID for the update
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false
    )
    
    Write-Log -Message "Show-PowerShellDialog called for $AppID ($FriendlyName)" | Out-Null
    
    try {
        # Get active user sessions
        $activeSessions = Get-ActiveUserSessions
        if ($activeSessions.Count -eq 0) {
            Write-Log -Message "No active user sessions found for PowerShell dialog" | Out-Null
            return $DefaultTimeoutAction
        }
        
        $primarySession = $activeSessions[0]
        Write-Log -Message "Using session $($primarySession.SessionId) for PowerShell dialog" | Out-Null
        
        # Create response file
        $responseFile = "$env:TEMP\PSDialogResponse_$([guid]::NewGuid().ToString().Substring(0,8)).txt"
        
        # Create dialog script - simplified to avoid syntax issues
        $dialogScript = @'
param([string]$FriendlyName, [int]$TimeoutSeconds, [bool]$DefaultTimeoutAction, [string]$ResponseFile)

try {
    Add-Type -AssemblyName System.Windows.Forms
    
    $message = "An update is available for $FriendlyName, but it cannot be installed while the application is running.`n`nWould you like to close $FriendlyName now to allow the update to proceed?"
    $result = [System.Windows.Forms.MessageBox]::Show($message, "Application Update Available", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
    } else {
        "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
    }
    
} catch {
    # Ultimate fallback
    if ($DefaultTimeoutAction) {
        "YES" | Out-File -FilePath $ResponseFile -Encoding ASCII
    } else {
        "NO" | Out-File -FilePath $ResponseFile -Encoding ASCII
    }
}
'@
        
        # Write dialog script to temp file
        $scriptPath = "$env:TEMP\PSDialogScript_$([guid]::NewGuid().ToString().Substring(0,8)).ps1"
        $dialogScript | Out-File -FilePath $scriptPath -Encoding UTF8
        
        # Execute dialog script
        $scriptExecuted = $false
        
        # Try PsExec approach first
        $psexecPath = "$env:ProgramData\chocolatey\bin\PsExec.exe"
        if (Test-Path $psexecPath) {
            try {
                Write-Log -Message "Executing PowerShell dialog via PsExec" | Out-Null
                $psexecArgs = "-accepteula -s -i $($primarySession.SessionId) powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`" -FriendlyName `"$FriendlyName`" -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction `$$DefaultTimeoutAction -ResponseFile `"$responseFile`""
                Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -WindowStyle Hidden -Wait:$false
                $scriptExecuted = $true
            } catch {
                Write-Log -Message "PsExec PowerShell dialog failed: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Fallback to scheduled task
        if (-not $scriptExecuted) {
            try {
                Write-Log -Message "Executing PowerShell dialog via scheduled task" | Out-Null
                $taskName = "PSDialogTask_$([guid]::NewGuid().ToString().Substring(0,8))"
                
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -FriendlyName `"$FriendlyName`" -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction `$$DefaultTimeoutAction -ResponseFile `"$responseFile`""
                $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                
                Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
                Start-ScheduledTask -TaskName $taskName
                
                Start-Sleep -Seconds 2
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                $scriptExecuted = $true
                
            } catch {
                Write-Log -Message "Scheduled task PowerShell dialog failed: $($_.Exception.Message)" | Out-Null
            }
        }
        
        if (-not $scriptExecuted) {
            Write-Log -Message "Could not execute PowerShell dialog script, using default action" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            return $DefaultTimeoutAction
        }
        
        # Wait for response
        $waitTime = 0
        $maxWaitTime = $TimeoutSeconds + 10
        
        while ($waitTime -lt $maxWaitTime -and -not (Test-Path $responseFile)) {
            Start-Sleep -Seconds 1
            $waitTime++
        }
        
        # Read response
        $userResponse = $DefaultTimeoutAction
        if (Test-Path $responseFile) {
            try {
                $responseContent = Get-Content $responseFile -Raw -ErrorAction SilentlyContinue
                $responseContent = $responseContent.Trim()
                
                if ($responseContent -eq "YES") {
                    $userResponse = $true
                    Write-Log -Message "User chose to close $FriendlyName via PowerShell dialog" | Out-Null
                } elseif ($responseContent -eq "NO") {
                    $userResponse = $false
                    Write-Log -Message "User chose to keep $FriendlyName open via PowerShell dialog" | Out-Null
                } else {
                    Write-Log -Message "Unexpected PowerShell dialog response: $responseContent" | Out-Null
                }
                
                Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading PowerShell dialog response: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No PowerShell dialog response file created, using default action: $DefaultTimeoutAction" | Out-Null
        }
        
        # Clean up
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        
        return $userResponse
        
    } catch {
        Write-Log -Message "PowerShell dialog system failed: $($_.Exception.Message)" | Out-Null
        return $DefaultTimeoutAction
    }
}

function Show-UserNotification {
    <#
    .SYNOPSIS
        Main entry point for user notifications - tries Toast first, then falls back to PowerShell dialog
    .DESCRIPTION
        Unified interface for showing user notifications with multiple fallback approaches
    .PARAMETER AppID
        Application ID for the update
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName = "",
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false
    )
    
    # Use AppID as FriendlyName fallback
    if ([string]::IsNullOrEmpty($FriendlyName)) {
        $FriendlyName = $AppID
    }
    
    Write-Log -Message "Show-UserNotification called for $AppID ($FriendlyName)" | Out-Null
    
    # Check execution context
    $isSystemContext = Test-RunningAsSystem
    $isInteractive = [Environment]::UserInteractive
    
    Write-Log -Message "Execution context - System: $isSystemContext, Interactive: $isInteractive" | Out-Null
    
    # If running in system context, use Toast notifications (primary approach)
    if ($isSystemContext) {
        Write-Log -Message "System context detected, using Toast notification system" | Out-Null
        return Show-ToastNotification -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
    } else {
        # In user context, try PowerShell dialog directly
        Write-Log -Message "User context detected, using PowerShell dialog" | Out-Null
        return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
    }
}

function Show-ProcessCloseDialog {
    <#
    .SYNOPSIS
        Shows a user dialog asking whether to close a blocking process for application update
    .DESCRIPTION
        Uses the new Toast notification system or PowerShell dialog fallback to prompt the user
        This function replaces the old problematic dialog system
    .PARAMETER AppName
        Application ID for the update
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .PARAMETER FriendlyName
        User-friendly name of the application
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
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

    # Use the new unified notification system
    return Show-UserNotification -AppID $AppName -FriendlyName $friendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
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
$ScriptTag = "9R" # Update this tag for each script version
$LogName = 'RemediateAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"

# Dynamic log path selection based on execution context
$isSystemContext = Test-RunningAsSystem
$isInteractive = [Environment]::UserInteractive

if ($isSystemContext) {
    $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    # Ensure the directory exists
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    Write-Host "Running in system context (non-interactive: $(-not $isInteractive))"
} else {
    $LogPath = "$env:Temp"
    Write-Host "Running in user context (interactive: $isInteractive)"
}
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useWhitelist = $true

<# ----------------------------------------------- #>

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

<# TEST MODE: Check for toast test trigger file #>
$testTriggerFile = "C:\Temp\toast-test-trigger.txt"
if (Test-Path $testTriggerFile) {
    Write-Log -Message "Toast test trigger file detected: $testTriggerFile"
    Write-Log -Message "Running toast notification test instead of normal remediation"
    
    try {
        # Test the toast notification system with a simple message
        Write-Log -Message "Testing SYSTEM-to-user toast notification"
        $testResult = Show-UserNotification -AppID "TestApp.ToastTest" -FriendlyName "Toast Test Application" -ProcessName "test" -TimeoutSeconds 30 -DefaultTimeoutAction $false
        
        Write-Log -Message "Toast test completed with result: $testResult"
        
        # Check if we have any evidence that the toast actually worked
        $toastWorked = $false
        $responseFiles = Get-ChildItem -Path "$env:TEMP" -Filter "ToastResponse_*.txt" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
        $debugFiles = Get-ChildItem -Path "$env:TEMP" -Filter "ToastResponse_*.log" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
        
        if ($responseFiles.Count -gt 0) {
            Write-Log -Message "Found recent toast response file(s) - toast mechanism worked"
            $toastWorked = $true
            
            # Show what was in the response files
            foreach ($responseFile in $responseFiles) {
                try {
                    $content = Get-Content $responseFile.FullName -ErrorAction SilentlyContinue
                    Write-Log -Message "Response file content: $content"
                } catch {
                    Write-Log -Message "Could not read response file: $($_.Exception.Message)"
                }
            }
        }
        
        if ($debugFiles.Count -gt 0) {
            Write-Log -Message "Found toast debug log(s), checking for evidence of successful display"
            foreach ($debugFile in $debugFiles) {
                try {
                    $debugContent = Get-Content $debugFile.FullName -ErrorAction SilentlyContinue
                    if ($debugContent -like "*Toast notification displayed successfully*") {
                        Write-Log -Message "Debug log shows toast was displayed successfully"
                        $toastWorked = $true
                        break
                    } elseif ($debugContent -like "*Error in toast script*" -or $debugContent -like "*Failed to redirect*") {
                        Write-Log -Message "Debug log shows toast script errors"
                    } elseif ($debugContent -like "*Windows Runtime assemblies loaded successfully*") {
                        Write-Log -Message "Debug log shows Windows Runtime loaded successfully"
                        # This suggests the toast should have worked
                        $toastWorked = $true
                    }
                } catch {
                    Write-Log -Message "Error reading debug file: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Log -Message "No toast debug log found - this means the scheduled task script never executed properly"
        }
        
        if ($toastWorked) {
            Write-Log -Message "✅ SUCCESS: Toast notification system is working!"
            Write-Log -Message "User response: $($testResult.ToString())"
            Write-Log -Message "Evidence: Toast was successfully displayed to the user"
        } else {
            Write-Log -Message "❌ FAILED: Toast notification system is not working properly"
            Write-Log -Message "No evidence of successful toast display found"
            Write-Log -Message "Returned value: $($testResult.ToString()) (but this doesn't indicate the toast was visible)"
            Write-Log -Message "Check: Windows notification settings, Focus Assist, scheduled task execution, PowerShell execution policy"
        }
        
        # Remove the trigger file so test doesn't run again immediately
        Remove-Item $testTriggerFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed trigger file: $testTriggerFile"
        
        Write-Log -Message "Toast test completed - exiting"
        exit 0
        
    } catch {
        Write-Log -Message "❌ ERROR: Toast test failed with exception: $($_.Exception.Message)"
        Write-Log -Message "Full exception: $($_.Exception.ToString())"
        exit 1
    }
}

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
    $webClient.Headers.Add("User-Agent", "PowerShell-WingetScript/6.0")
    $whitelistJSON = $webClient.DownloadString($whitelistUrl)
    Write-Log -Message "Successfully downloaded whitelist configuration from GitHub"
} catch {
    Write-Log -Message "Error downloading whitelist from GitHub: $($_.Exception.Message)"
    Write-Log -Message "Falling back to local configuration"
    
    # Fallback to basic configuration if GitHub is unavailable
    $whitelistJSON = @'
[
    {"AppID": "Mozilla.Firefox", "FriendlyName": "Firefox", "BlockingProcess": "firefox", "PromptWhenBlocked": true},
    {"AppID": "Google.Chrome", "FriendlyName": "Chrome", "BlockingProcess": "chrome", "PromptWhenBlocked": true},
    {"AppID": "Microsoft.VisualStudioCode", "FriendlyName": "Visual Studio Code", "BlockingProcess": "Code", "PromptWhenBlocked": true},
    {"AppID": "Notepad++.Notepad++", "FriendlyName": "Notepad++", "BlockingProcess": "notepad++", "DefaultTimeoutAction": true},
    {"AppID": "7zip.7zip", "FriendlyName": "7-Zip", "BlockingProcess": "7zFM", "DefaultTimeoutAction": true},
    {"AppID": "Adobe.Acrobat.Reader.64-bit", "FriendlyName": "Adobe Acrobat Reader", "BlockingProcess": "AcroRd32,Acrobat,AcroBroker,AdobeARM,AdobeCollabSync", "AutoCloseProcesses": "AdobeCollabSync", "PromptWhenBlocked": true},
    {"AppID": "GitHub.GitHubDesktop", "FriendlyName": "GitHub Desktop", "BlockingProcess": "GitHubDesktop", "PromptWhenBlocked": true}
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
    Write-Log -Message "User context mode detected"

    #if (-not ($userIsAdmin)) {
    #    $whitelistConfig = $whitelistConfig | Where-Object { $_.UserContext -eq $true }
    #}

    try {
        $OUTPUT = $(winget upgrade --accept-source-agreements)
        Write-Log -Message "Successfully executed winget upgrade in user context"
    } catch {
        Write-Log -Message "Error executing winget in user context: $($_.Exception.Message)"
        Write-Log -Message "Winget may not be available or properly configured"
        exit 1
    }
    
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
    Write-Log -Message "System context mode detected, using winget at: $WingetPath"
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

    try {
        # call winget and check if we need to retry
        $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
        Write-Log -Message "Successfully executed winget upgrade in system context"
    } catch {
        Write-Log -Message "Error executing winget in system context: $($_.Exception.Message)"
        Write-Log -Message "Winget execution failed, exiting"
        exit 1
    }
    
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
                                
                                # Check if this app should prompt when blocked
                                if ($okapp.PromptWhenBlocked -ne $true) {
                                    Write-Log -Message "Skipping $($okapp.AppID) - PromptWhenBlocked not set, waiting for next run"
                                    continue
                                }
                                
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
                                
                                # If we can't auto-close and PromptWhenBlocked is true, show the interactive popup
                                if (-not $canAutoClose) {
                                    Write-Log -Message "$($okapp.AppID) has PromptWhenBlocked=true, showing interactive dialog"
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
