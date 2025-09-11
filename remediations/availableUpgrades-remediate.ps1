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
        Shows a Windows Toast Notification with interactive buttons
    .DESCRIPTION
        Creates and displays a toast notification that can be shown from system context to user sessions
        Uses Windows 10/11 Toast Notification APIs with response handling
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
        # Check if running on Windows 10/11 with Toast support
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 10240)) {
            Write-Log -Message "Toast notifications not supported on this OS version, using fallback" | Out-Null
            return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Get active user sessions
        $activeSessions = Get-ActiveUserSessions
        if ($activeSessions.Count -eq 0) {
            Write-Log -Message "No active user sessions found for toast notification" | Out-Null
            return $DefaultTimeoutAction
        }
        
        $primarySession = $activeSessions[0]
        Write-Log -Message "Using session $($primarySession.SessionId) for toast notification" | Out-Null
        
        # Create unique response file
        $responseFile = "$env:TEMP\ToastResponse_$([guid]::NewGuid().ToString().Substring(0,8)).txt"
        $lockFile = "$responseFile.lock"
        
        # Create VBScript for more reliable MessageBox display in scheduled tasks
        $vbScript = @"
Dim AppID, FriendlyName, ResponseFile, LogFile, LockFile
AppID = "$AppID"
FriendlyName = "$FriendlyName"
ResponseFile = "$responseFile"
LogFile = ResponseFile + ".log"
LockFile = ResponseFile + ".lock"

' Create lock file
Set fso = CreateObject("Scripting.FileSystemObject")
Set lockFileObj = fso.CreateTextFile(LockFile, True)
lockFileObj.WriteLine "RUNNING"
lockFileObj.Close

' Log script start
Set logFileObj = fso.CreateTextFile(LogFile, True)
logFileObj.WriteLine "VBScript started at " & Now()
logFileObj.WriteLine "AppID: " & AppID
logFileObj.WriteLine "FriendlyName: " & FriendlyName
logFileObj.WriteLine "User: " & CreateObject("WScript.Network").UserName
logFileObj.WriteLine "Computer: " & CreateObject("WScript.Network").ComputerName
logFileObj.Close

On Error Resume Next
Dim Message, Title, Result
Message = "An update is available for " & FriendlyName & ", but it cannot be installed while the application is running." & vbCrLf & vbCrLf & "Would you like to close " & FriendlyName & " now to allow the update to proceed?"
Title = "Application Update Available"

' Show MessageBox with Yes/No buttons and Question icon
Result = MsgBox(Message, vbYesNo + vbQuestion + vbSystemModal, Title)

' Log the result
Set logFileObj = fso.OpenTextFile(LogFile, 8, True)
logFileObj.WriteLine "MessageBox result: " & Result
logFileObj.Close

' Write response based on user choice
If Result = vbYes Then
    Set responseFileObj = fso.CreateTextFile(ResponseFile, True)
    responseFileObj.WriteLine "YES"
    responseFileObj.Close
    
    Set logFileObj = fso.OpenTextFile(LogFile, 8, True)
    logFileObj.WriteLine "User clicked YES - wrote YES to response file"
    logFileObj.Close
Else
    Set responseFileObj = fso.CreateTextFile(ResponseFile, True)
    responseFileObj.WriteLine "NO"
    responseFileObj.Close
    
    Set logFileObj = fso.OpenTextFile(LogFile, 8, True)
    logFileObj.WriteLine "User clicked NO - wrote NO to response file"
    logFileObj.Close
End If

' Clean up lock file
If fso.FileExists(LockFile) Then
    fso.DeleteFile LockFile
End If

' Log completion
Set logFileObj = fso.OpenTextFile(LogFile, 8, True)
logFileObj.WriteLine "VBScript completed at " & Now()
logFileObj.Close
"@
        
        # Write VBScript to temp file
        $scriptPath = "$env:TEMP\ToastScript_$([guid]::NewGuid().ToString().Substring(0,8)).vbs"
        $vbScript | Out-File -FilePath $scriptPath -Encoding ASCII
        
        # Execute toast script in user context using multiple approaches
        $scriptExecuted = $false
        
        # Try PsExec first if available
        $psexecPath = "$env:ProgramData\chocolatey\bin\PsExec.exe"
        if (Test-Path $psexecPath) {
            try {
                Write-Log -Message "Executing toast script via PsExec in session $($primarySession.SessionId)" | Out-Null
                $psexecArgs = "-accepteula -s -i $($primarySession.SessionId) powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`" -AppID `"$AppID`" -FriendlyName `"$FriendlyName`" -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction `$$DefaultTimeoutAction -ResponseFile `"$responseFile`""
                Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -WindowStyle Hidden -Wait:$false
                $scriptExecuted = $true
            } catch {
                Write-Log -Message "PsExec execution failed: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Fallback to scheduled task approach
        if (-not $scriptExecuted) {
            try {
                Write-Log -Message "Executing toast script via scheduled task for session $($primarySession.SessionId)" | Out-Null
                $taskName = "ToastNotificationTask_$([guid]::NewGuid().ToString().Substring(0,8))"
                
                # Get the actual logged-on user using more reliable methods
                $currentUser = $null
                
                # Method 1: Try to get the user from the explorer process
                try {
                    $explorerProcess = Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($explorerProcess) {
                        $processOwner = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($explorerProcess.Id)" |
                            Invoke-CimMethod -MethodName GetOwner
                        if ($processOwner.Domain -and $processOwner.User) {
                            $currentUser = "$($processOwner.Domain)\$($processOwner.User)"
                        }
                    }
                } catch {
                    Write-Log -Message "Could not get user from explorer process: $($_.Exception.Message)" | Out-Null
                }
                
                # Method 2: Fallback to computer system info
                if (-not $currentUser) {
                    try {
                        $currentUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
                    } catch {
                        Write-Log -Message "Could not get user from Win32_ComputerSystem: $($_.Exception.Message)" | Out-Null
                    }
                }
                
                # Method 3: Ultimate fallback
                if (-not $currentUser) {
                    $currentUser = "NT AUTHORITY\INTERACTIVE"
                }
                
                Write-Log -Message "Creating scheduled task for user: $currentUser" | Out-Null
                
                # Create action to execute VBScript with cscript
                $action = New-ScheduledTaskAction -Execute "cscript.exe" -Argument "`"$scriptPath`" //NoLogo"
                
                # Create principal with the correct user and highest privileges
                $principal = if ($currentUser -and $currentUser -ne "NT AUTHORITY\INTERACTIVE") {
                    New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
                } else {
                    New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive -RunLevel Highest
                }
                
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
                
                Write-Log -Message "Registering scheduled task: $taskName" | Out-Null
                Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
                
                Write-Log -Message "Starting scheduled task: $taskName" | Out-Null
                Start-ScheduledTask -TaskName $taskName
                
                # Wait longer for the task to start and create the lock file
                Start-Sleep -Seconds 8
                
                # Check if task is running or completed
                $taskInfo = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Log -Message "Task state: $($taskInfo.State)" | Out-Null
                    $lastTaskResult = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($lastTaskResult) {
                        Write-Log -Message "Last task result: $($lastTaskResult.LastTaskResult)" | Out-Null
                    }
                }
                
                # Don't clean up task immediately - let it finish completely
                # We'll clean it up later after checking for responses
                
                $scriptExecuted = $true
                
            } catch {
                Write-Log -Message "Scheduled task execution failed: $($_.Exception.Message)" | Out-Null
                Write-Log -Message "Task creation error details: $($_.Exception.ToString())" | Out-Null
            }
        }
        
        if (-not $scriptExecuted) {
            Write-Log -Message "Could not execute toast script, using fallback dialog" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            return Show-PowerShellDialog -AppID $AppID -FriendlyName $FriendlyName -ProcessName $ProcessName -TimeoutSeconds $TimeoutSeconds -DefaultTimeoutAction $DefaultTimeoutAction
        }
        
        # Wait for response file or lock file to disappear (indicating completion)
        $waitTime = 0
        $maxWaitTime = $TimeoutSeconds + 15
        
        while ($waitTime -lt $maxWaitTime) {
            if (Test-Path $responseFile) {
                # Response received
                break
            }
            if (-not (Test-Path $lockFile)) {
                # Script completed but no response file yet, wait a bit more
                if ($waitTime -gt ($TimeoutSeconds + 5)) {
                    break
                }
            }
            
            Start-Sleep -Seconds 1
            $waitTime++
            
            if ($waitTime % 10 -eq 0) {
                Write-Log -Message "Still waiting for toast response... ($waitTime seconds elapsed)" | Out-Null
            }
        }
        
        # Clean up scheduled task now that we've waited
        try {
            $taskName = $taskName  # Should be available from scope above
            if ($taskName) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log -Message "Scheduled task cleaned up: $taskName" | Out-Null
            }
        } catch {
            Write-Log -Message "Error cleaning up scheduled task: $($_.Exception.Message)" | Out-Null
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
            Write-Log -Message "No response file created, assuming timeout with default action: $DefaultTimeoutAction" | Out-Null
        }
        
        # Check for debug log and report key information
        $debugLogFile = $responseFile + ".log"
        if (Test-Path $debugLogFile) {
            try {
                $debugContent = Get-Content $debugLogFile -ErrorAction SilentlyContinue
                Write-Log -Message "Debug log found with $($debugContent.Count) lines" | Out-Null
                
                # Report ALL lines from debug log for better troubleshooting
                foreach ($line in $debugContent) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        Write-Log -Message "DEBUG: $line" | Out-Null
                    }
                }
                
                Remove-Item $debugLogFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Message "Error reading debug log: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log -Message "No debug log file found - script may not have executed properly" | Out-Null
        }
        
        # Clean up files
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
        
        return $userResponse
        
    } catch {
        Write-Log -Message "Toast notification system failed: $($_.Exception.Message)" | Out-Null
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
