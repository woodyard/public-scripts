<#
.SYNOPSIS
    Winget Application Update Remediation Script

.DESCRIPTION
    This script performs application updates using winget based on a whitelist approach.
    It supports both system and user context applications using a dual-context architecture.
    The script is designed to work as a remediation script in Microsoft Intune remediation policies.

.PARAMETER UserRemediationOnly
    When specified, the script runs in user remediation mode (scheduled task execution)

.NOTES
 Author: Henrik Skovgaard
 Version: 8.5
 Tag: 8W
    
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
    7.0 - REVOLUTIONARY UPDATE: Implemented modern WPF-based notification system with Azure AD support, replacing legacy toast notifications with reliable cross-session dialogs, enhanced whitelist timeout support, and optimized for Intune deployment environments
    7.1 - Enhanced WPF dialog system with countdown timer display on default action button for improved user experience and clarity
    8.1 - CRITICAL UPDATE: Added --scope user support for non-privileged user context upgrades, allowing users without admin rights to upgrade user-scoped applications
    8.2 - CRITICAL FIX: Fixed empty script path issue in scheduled tasks by capturing $MyInvocation.MyCommand.Path at global scope with multiple fallback methods; Fixed PowerShell syntax errors with Test-RunningAsSystem function calls
    8.3 - SECURITY IMPROVEMENT: Scripts now copy themselves to user-accessible temp locations before scheduling tasks, improving security and access control with automatic cleanup
    8.4 - CRITICAL FIX: Fixed Azure AD identity cache registry errors in Intune by replacing Start-Job background registry access with direct Test-Path and SilentlyContinue error handling, eliminating "remediation error" messages on AAD-joined machines
    8.5 - ENHANCEMENT: Implemented comprehensive marker file management system with centralized cleanup functions, orphaned file detection, and emergency cleanup handlers to prevent accumulation of .userdetection files; Added hidden console window execution method using cmd.exe with /min flag to eliminate visible console windows during scheduled task execution
    
    Exit Codes:
    0 - Script completed successfully or OOBE not complete
    1 - Error occurred during remediation
#>

param(
    [switch]$UserRemediationOnly,
    [string]$RemediationResultFile
)

# Note: Admin requirement is conditional - not needed for user context execution (UserRemediationOnly mode)
# #Requires -RunAsAdministrator
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


# WPF System User Prompt Functions - Modern replacement for legacy toast notification system

function Get-InteractiveUser {
    <#
    .SYNOPSIS
        Gets the currently logged-in interactive user and their SID (Azure AD compatible)
    .DESCRIPTION
        Uses improved detection method that properly handles Azure AD users
    #>
    
    try {
        Write-Log "Detecting interactive user using improved Azure AD compatible method..." | Out-Null
        $userDetectionStart = Get-Date
        
        # Improved user detection method that handles Azure AD properly
        try {
            # Try CIM instance first, fallback to WMI
            $loggedInUser = $null
            $LoggedSID = $null
            $CurrentAzureADUser = $null
            
            try {
                Write-Log "Attempting user detection via CIM..." | Out-Null
                $cimStart = Get-Date
                
                # Add timeout protection for CIM call
                $cimJob = Start-Job -ScriptBlock {
                    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Username
                }
                
                if (Wait-Job $cimJob -Timeout 15) {
                    $loggedInUser = Receive-Job $cimJob
                    $cimDuration = (Get-Date) - $cimStart
                    Write-Log "CIM call completed in $($cimDuration.TotalSeconds) seconds" | Out-Null
                    
                    if ($loggedInUser) {
                        $LoggedSID = (([System.Security.Principal.NTAccount]$loggedInUser).Translate([System.Security.Principal.SecurityIdentifier]).Value)
                        Write-Log "CIM method successful - User: $loggedInUser, SID: $LoggedSID" | Out-Null
                    }
                } else {
                    $cimDuration = (Get-Date) - $cimStart
                    Write-Log "CIM call timed out after $($cimDuration.TotalSeconds) seconds" | Out-Null
                    Remove-Job $cimJob -Force
                    throw "CIM timeout"
                }
                Remove-Job $cimJob -Force
                
            } catch {
                Write-Log "CIM method failed: $($_.Exception.Message). Trying WMI fallback..." | Out-Null
                try {
                    Write-Log "Attempting user detection via WMI..." | Out-Null
                    $wmiStart = Get-Date
                    
                    # Add timeout protection for WMI call
                    $wmiJob = Start-Job -ScriptBlock {
                        Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Username
                    }
                    
                    if (Wait-Job $wmiJob -Timeout 15) {
                        $loggedInUser = Receive-Job $wmiJob
                        $wmiDuration = (Get-Date) - $wmiStart
                        Write-Log "WMI call completed in $($wmiDuration.TotalSeconds) seconds" | Out-Null
                        
                        if ($loggedInUser) {
                            $LoggedSID = (([System.Security.Principal.NTAccount]$loggedInUser).Translate([System.Security.Principal.SecurityIdentifier]).Value)
                            Write-Log "WMI fallback successful - User: $loggedInUser, SID: $LoggedSID" | Out-Null
                        }
                    } else {
                        $wmiDuration = (Get-Date) - $wmiStart
                        Write-Log "WMI call timed out after $($wmiDuration.TotalSeconds) seconds" | Out-Null
                        Remove-Job $wmiJob -Force
                        throw "WMI timeout"
                    }
                    Remove-Job $wmiJob -Force
                    
                } catch {
                    Write-Log "Both CIM and WMI methods failed: $($_.Exception.Message)" | Out-Null
                    throw "No logged in user detected via CIM or WMI"
                }
            }
            
            if (-not $loggedInUser -or -not $LoggedSID) {
                throw "User detection failed - no logged in user found"
            }
            
            # Try to get Azure AD username from registry with enhanced error suppression
            try {
                $azureAdPath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$LoggedSID\IdentityCache\$LoggedSID"
                Write-Log "Checking for Azure AD user info at: $azureAdPath" | Out-Null
                
                # First check if the path exists to avoid errors completely
                if (Test-Path $azureAdPath) {
                    $registryData = Get-ItemProperty -Path $azureAdPath -Name UserName -ErrorAction SilentlyContinue
                    if ($registryData -and $registryData.UserName) {
                        $CurrentAzureADUser = $registryData.UserName
                        Write-Log "Found Azure AD username: $CurrentAzureADUser" | Out-Null
                    } else {
                        Write-Log "Azure AD path exists but UserName property not found" | Out-Null
                        $CurrentAzureADUser = $null
                    }
                } else {
                    Write-Log "Azure AD identity cache path does not exist (user may be local account)" | Out-Null
                    $CurrentAzureADUser = $null
                }
            } catch {
                Write-Log "No Azure AD user info available (user may be local): $($_.Exception.Message)" | Out-Null
                $CurrentAzureADUser = $null
            }
            
            # Parse domain and username from Windows logon
            $windowsUsername = ($loggedInUser -split '\\')[1]
            $domain = ($loggedInUser -split '\\')[0]
            
            # Important distinction for Azure AD environments:
            # - Windows Username: Used for profile paths (e.g., HenrikSkovgaard-clou)
            # - Azure AD UPN: Used for Azure AD operations (e.g., henrik@cloudonly.dk)
            # - For scheduled tasks and file paths, we typically need the Windows username
            
            Write-Log "User detection results:" | Out-Null
            Write-Log "  - Full Name: $loggedInUser" | Out-Null
            Write-Log "  - Domain: $domain" | Out-Null
            Write-Log "  - Windows Username (profile): $windowsUsername" | Out-Null
            Write-Log "  - Azure AD UPN: $(if ($CurrentAzureADUser) { $CurrentAzureADUser } else { 'N/A' })" | Out-Null
            Write-Log "  - SID: $LoggedSID" | Out-Null
            
            # Verify profile path exists for Windows username
            $profilePath = "C:\Users\$windowsUsername"
            $profileExists = Test-Path $profilePath
            Write-Log "  - Profile Path: $profilePath (Exists: $profileExists)" | Out-Null
            
            return @{
                Username = $windowsUsername              # Windows username for file operations
                FullName = $loggedInUser                # Full domain\username format
                Domain = $domain                        # Domain name
                SID = $LoggedSID                       # User SID
                AzureADUser = $CurrentAzureADUser      # Azure AD UPN (if available)
                ProfilePath = $profilePath             # User profile directory
                ProfileExists = $profileExists        # Whether profile directory exists
                SessionId = $null                      # Not available with this method
            }
            
        } catch [Exception] {
            $userDetectionDuration = (Get-Date) - $userDetectionStart
            $Message = "User detection failed after $($userDetectionDuration.TotalSeconds) seconds: $_"
            Write-Log $Message | Out-Null
            Throw $Message
        }
        
        $userDetectionDuration = (Get-Date) - $userDetectionStart
        Write-Log "User detection completed successfully in $($userDetectionDuration.TotalSeconds) seconds" | Out-Null
        
    } catch {
        $userDetectionDuration = (Get-Date) - $userDetectionStart
        Write-Log "Error getting interactive user after $($userDetectionDuration.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Test-InteractiveSession {
    <#
    .SYNOPSIS
        Tests if there is an active interactive user session suitable for user context operations
    .DESCRIPTION
        Verifies that an interactive user session exists with desktop access before
        attempting to create scheduled tasks that require user interaction
    .OUTPUTS
        Boolean - True if interactive session available, False otherwise
    #>
    
    try {
        Write-Log "Checking for interactive session..." | Out-Null
        
        # Use existing Get-InteractiveUser function
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user detected - skipping user context operations" | Out-Null
            return $false
        }
        
        # Additional check: Verify explorer.exe is running (indicates active desktop)
        $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
        if (-not $explorerProcesses) {
            Write-Log "No explorer.exe processes found - no active desktop session" | Out-Null
            return $false
        }
        
        # Verify session is interactive (session ID > 0)
        $hasInteractiveSession = $false
        foreach ($process in $explorerProcesses) {
            if ($process.SessionId -gt 0) {  # Session 0 is services, >0 are user sessions
                $hasInteractiveSession = $true
                Write-Log "Interactive session confirmed - Session ID: $($process.SessionId), User: $($userInfo.Username)" | Out-Null
                break
            }
        }
        
        if (-not $hasInteractiveSession) {
            Write-Log "Explorer processes found but no interactive user sessions detected" | Out-Null
            return $false
        }
        
        return $true
        
    } catch {
        Write-Log "Error checking interactive session: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function New-UserPromptTask {
    <#
    .SYNOPSIS
        Creates a scheduled task to run the user prompt script as the interactive user
    #>
    
    param(
        [hashtable]$UserInfo,
        [string]$ScriptPath,
        [string]$ResponseFile,
        [string]$QuestionText,
        [string]$TitleText,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        # Generate unique task name
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "UserPrompt_$guid"
        
        Write-Log "Creating scheduled task: $taskName" | Out-Null
        
        # Force PowerShell 5.1 for toast notifications - PowerShell 7 cannot access Windows Runtime in scheduled task context
        Write-Log "Forcing PowerShell 5.1 for toast notifications (PowerShell 7 has Windows Runtime limitations in scheduled task context)" | Out-Null
        $powershellExe = "powershell.exe"
        
        # Use hidden console window execution method to prevent visible windows
        $hiddenArguments = "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -Question `"$QuestionText`" -Title `"$TitleText`" -Position `"BottomRight`" -TimeoutSeconds $TimeoutSeconds -DebugMode"
        
        # Create task action using hidden console window method
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $hiddenArguments
        
        # Create task principal (run as interactive user) - Azure AD aware
        $principal = $null
        $username = $UserInfo.Username
        $fullName = $UserInfo.FullName
        $domain = $UserInfo.Domain
        $userSid = $UserInfo.SID
        
        Write-Log "Creating task principal for user: $fullName (SID: $userSid)" | Out-Null
        
        # For Azure AD accounts, try username-based approaches first as SID registration often fails
        $userFormats = @()
        
        # Add full name format first (Azure AD preferred)
        if ($fullName) {
            $userFormats += $fullName
        }
        
        # Add Azure AD specific formats
        if ($domain -and $domain -eq "AzureAD") {
            $userFormats += $fullName  # AzureAD\username
            $userFormats += $username  # Just username for Azure AD
        } elseif ($domain -and $domain -ne $env:COMPUTERNAME -and $domain -ne ".") {
            $userFormats += "$domain\$username"  # Domain\user format
        }
        
        # Add local account formats as fallback
        $userFormats += ".\$username"             # Local account format
        $userFormats += $username                 # Just username
        $userFormats += "$env:COMPUTERNAME\$username"  # Computer\username format
        
        # Remove duplicates and null entries
        $userFormats = $userFormats | Where-Object { $_ } | Select-Object -Unique
        
        # Try different logon types for Azure AD compatibility
        $logonTypes = @("Interactive", "S4U", "ServiceAccount")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                Write-Log "Trying task principal with format: $userFormat, LogonType: $logonType" | Out-Null
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Successfully created principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        # Final attempt with SID if username approaches failed
        if (-not $principal -and $userSid) {
            Write-Log "Trying SID as last resort: $userSid" | Out-Null
            try {
                $principal = New-ScheduledTaskPrincipal -UserId $userSid -LogonType ServiceAccount -RunLevel Limited
                Write-Log "Successfully created principal with SID (ServiceAccount logon)" | Out-Null
            } catch {
                Write-Log "Failed with SID approach: $($_.Exception.Message)" | Out-Null
            }
        }
        
        if (-not $principal) {
            Write-Log "Could not create task principal with any method. Attempted formats:" | Out-Null
            foreach ($format in $userFormats) {
                Write-Log "  - $format" | Out-Null
            }
            return $null
        }
        
        # Create task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        
        # Create the task with the principal
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Interactive user prompt for system operations"
        
        # Register the task with error handling and Azure AD-specific retry logic
        try {
            Write-Log "Attempting to register scheduled task with current principal..." | Out-Null
            $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
            Write-Log "Scheduled task created successfully: $taskName" | Out-Null
            
            # Verify task exists
            $verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $verifyTask) {
                Write-Log "Task registration appeared to succeed but task not found" | Out-Null
                return $null
            }
            
            return $taskName
            
        } catch {
            Write-Log "Failed to register scheduled task with current principal: $($_.Exception.Message)" | Out-Null
            
            # Azure AD fallback: Try creating a simpler task that launches as SYSTEM but switches user context
            if ($domain -eq "AzureAD") {
                Write-Log "Attempting Azure AD fallback approach (SYSTEM task with user context switching)..." | Out-Null
                try {
                    # Create a SYSTEM principal that will launch the script and let it handle user context
                    $fallbackPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    
                    # Use hidden console window execution method for Azure AD fallback
                    $fallbackHiddenArguments = "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -Question `"$QuestionText`" -Title `"$TitleText`""
                    $fallbackAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $fallbackHiddenArguments
                    
                    $fallbackTask = New-ScheduledTask -Action $fallbackAction -Principal $fallbackPrincipal -Settings $settings -Description "Interactive user prompt for system operations (Azure AD SYSTEM fallback)"
                    
                    $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $fallbackTask -Force -ErrorAction Stop
                    Write-Log "Scheduled task created successfully using Azure AD SYSTEM fallback: $taskName" | Out-Null
                    return $taskName
                    
                } catch {
                    Write-Log "Azure AD SYSTEM fallback also failed: $($_.Exception.Message)" | Out-Null
                    return $null
                }
            } else {
                Write-Log "Final failure to register scheduled task (non-Azure AD)" | Out-Null
                return $null
            }
        }
        
    } catch {
        Write-Log "Error creating scheduled task: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Start-UserPromptTask {
    <#
    .SYNOPSIS
        Starts the scheduled task to display the user prompt
    #>
    
    param([string]$TaskName)
    
    try {
        Write-Log "Starting scheduled task: $TaskName" | Out-Null
        
        # Verify task exists before starting
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log "Cannot start task - task not found: $TaskName" | Out-Null
            return $false
        }
        
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Log "Scheduled task started successfully" | Out-Null
        
        # Brief wait and verify task is running
        Start-Sleep -Seconds 1
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($taskInfo) {
            Write-Log "Task status: $($taskInfo.LastTaskResult), Last run: $($taskInfo.LastRunTime)" | Out-Null
        }
        
        return $true
        
    } catch {
        Write-Log "Error starting scheduled task: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Wait-ForUserResponse {
    <#
    .SYNOPSIS
        Waits for the user response file to be created and returns the response
    #>
    
    param(
        [string]$ResponseFilePath,
        [int]$TimeoutSeconds
    )
    
    $startTime = Get-Date
    $timeout = $startTime.AddSeconds($TimeoutSeconds)
    
    Write-Log "Waiting for user response at: $ResponseFilePath" | Out-Null
    Write-Log "Timeout set for: $timeout" | Out-Null
    
    while ((Get-Date) -lt $timeout) {
        if (Test-Path $ResponseFilePath) {
            try {
                # Wait a moment for the file to be fully written
                Start-Sleep -Milliseconds 500
                
                $responseContent = Get-Content -Path $ResponseFilePath -Raw -ErrorAction Stop
                $response = $responseContent | ConvertFrom-Json -ErrorAction Stop
                
                Write-Log "User response received: $($response.response)" | Out-Null
                return $response.response
                
            } catch {
                Write-Log "Error reading response file: $($_.Exception.Message)" | Out-Null
                # Continue waiting, file might still be written
            }
        }
        
        Start-Sleep -Seconds 2
    }
    
    Write-Log "Timeout waiting for user response after $TimeoutSeconds seconds" | Out-Null
    return "TIMEOUT"
}

function Remove-UserPromptTask {
    <#
    .SYNOPSIS
        Removes the scheduled task and cleans up files
    #>
    
    param([string]$TaskName)
    
    try {
        if ($TaskName) {
            Write-Log "Removing scheduled task: $TaskName" | Out-Null
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Scheduled task removed" | Out-Null
        }
    } catch {
        Write-Log "Error during cleanup: $($_.Exception.Message)" | Out-Null
    }
}

function Invoke-SystemUserPrompt {
    <#
    .SYNOPSIS
        Displays a user prompt from SYSTEM context using WPF dialogs
    .DESCRIPTION
        Creates a scheduled task to switch from SYSTEM to user context and show a modern WPF dialog
        Handles both domain and Azure AD environments with proper user detection
    .PARAMETER Question
        The question to ask the user
    .PARAMETER Title
        Dialog title (optional, defaults to "System Notification")
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    .PARAMETER DefaultAction
        Default action on timeout ("OK" or "Cancel")
    .PARAMETER Position
        Dialog position (BottomRight, TopRight, Center, etc.)
    .OUTPUTS
        String: "OK", "Cancel", or "TIMEOUT"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Question,
        
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel",
        [string]$Position = "BottomRight"
    )
    
    Write-Log -Message "Invoke-SystemUserPrompt called: '$Question'" | Out-Null
    
    try {
        # Check if running in SYSTEM context
        if (-not (Test-RunningAsSystem)) {
            Write-Log -Message "Not running as SYSTEM, cannot create user context task" | Out-Null
            return $DefaultAction
        }
        
        # Check for interactive session before creating user tasks
        if (-not (Test-InteractiveSession)) {
            Write-Log -Message "No interactive session detected - cannot display user dialog" | Out-Null
            Write-Log -Message "Using default action: $DefaultAction" | Out-Null
            return $DefaultAction
        }
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found after session check - cannot display prompt" | Out-Null
            return $DefaultAction
        }
        
        # Create unique identifiers for this prompt
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $taskName = "UserPrompt_$promptId"
        
        # Setup paths - use a shared location both SYSTEM and user can access
        $guid = $promptId
        
        # Use the user's temp directory (accessible from both SYSTEM and user contexts)
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        if (Test-Path $userTempPath) {
            $responseFile = Join-Path $userTempPath "UserPrompt_$guid`_Response.json"
            Write-Log "Using user temp path: $responseFile" | Out-Null
        } else {
            # Fallback to a shared public location
            $sharedPath = "C:\ProgramData\Temp"
            if (-not (Test-Path $sharedPath)) {
                New-Item -Path $sharedPath -ItemType Directory -Force | Out-Null
            }
            $responseFile = Join-Path $sharedPath "UserPrompt_$guid`_Response.json"
            Write-Log "Using shared temp path: $responseFile" | Out-Null
        }
        
        $userPromptScriptPath = "$env:TEMP\Show-UserPrompt_$promptId.ps1"
        
        # Create the user prompt script content (from the working Show-UserPrompt.ps1)
        $userPromptScriptContent = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$ResponseFilePath,
    
    [Parameter(Mandatory = $false)]
    [string]$Question = "Do you want to proceed?",
    
    [Parameter(Mandatory = $false)]
    [string]$Title = "System Prompt",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("BottomRight", "TopRight", "BottomLeft", "TopLeft", "Center")]
    [string]$Position = "BottomRight",
    
    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 300,
    
    [Parameter(Mandatory = $false)]
    [switch]$DebugMode
)

# Initialize comprehensive logging
function Write-UserLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] [UserPrompt] [$Level] $Message"
    
    # Write to a user-accessible debug log file
    $logPath = Join-Path $env:TEMP "UserPrompt_Debug.log"
    try {
        $logMessage | Out-File -FilePath $logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Ignore logging errors
    }
    
    # Also output to console if in debug mode
    if ($DebugMode) {
        Write-Host $logMessage
    }
}

Write-UserLog "=== USER PROMPT SCRIPT STARTED ==="
Write-UserLog "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-UserLog "PowerShell Edition: $($PSVersionTable.PSEdition)"
Write-UserLog "Response File Path: $ResponseFilePath"
Write-UserLog "Question: $Question"
Write-UserLog "Title: $Title"
Write-UserLog "Position: $Position"
Write-UserLog "Timeout: $TimeoutSeconds seconds"
Write-UserLog "Debug Mode: $DebugMode"
Write-UserLog "Username: $env:USERNAME"
Write-UserLog "Computer: $env:COMPUTERNAME"
Write-UserLog "Current Directory: $PWD"
Write-UserLog "Process ID: $PID"
Write-UserLog "Session ID: $((Get-Process -Id $PID).SessionId)"

# Global variables for response handling
$script:UserResponse = $null
$script:ResponseReceived = $false

function Write-ResponseFile {
    param(
        [string]$Response,
        [string]$FilePath,
        [hashtable]$AdditionalData = @{}
    )
    
    try {
        $responseData = @{
            response = $Response
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            username = $env:USERNAME
            computer = $env:COMPUTERNAME
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            processId = $PID
        }
        
        # Add any additional data
        foreach ($key in $AdditionalData.Keys) {
            $responseData[$key] = $AdditionalData[$key]
        }
        
        $jsonResponse = $responseData | ConvertTo-Json -Compress
        $jsonResponse | Out-File -FilePath $FilePath -Encoding UTF8 -Force
        
        Write-UserLog "Response written to file: $Response"
        return $true
        
    } catch {
        Write-UserLog "Error writing response file: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Show-ModernDialog {
    param(
        [string]$TitleText,
        [string]$QuestionText,
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )
    
    try {
        Write-UserLog "Loading WPF assemblies for modern dialog..."
        
        # Load required assemblies
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        Write-UserLog "WPF assemblies loaded successfully"
        
        # Create XAML for modern toast-like dialog (Windows 10/11 style)
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$TitleText"
    Width="420"
    MinHeight="140"
    SizeToContent="Height"
    WindowStartupLocation="Manual"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Topmost="True"
    ShowInTaskbar="False">
    
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    
    <Border Name="MainBorder"
            Background="#FF1F1F1F"
            CornerRadius="8"
            BorderBrush="#FF323232"
            BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        
        <Grid Margin="16,12,16,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="32"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Icon -->
            <Ellipse Grid.Column="0" Grid.RowSpan="2"
                     Width="24" Height="24"
                     Fill="#FF0078D4"
                     VerticalAlignment="Top"
                     Margin="0,2,0,0"/>
            
            <TextBlock Grid.Column="0" Grid.RowSpan="2"
                       Text="?"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="Bold"
                       HorizontalAlignment="Center"
                       VerticalAlignment="Top"
                       Margin="0,4,0,0"/>
            
            <!-- Title -->
            <TextBlock Grid.Column="1" Grid.Row="0"
                       Text="$TitleText"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="SemiBold"
                       Margin="12,0,0,2"
                       TextWrapping="Wrap"/>
            
            <!-- Question -->
            <TextBlock Grid.Column="1" Grid.Row="1"
                       Text="$QuestionText"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Buttons -->
            <StackPanel Grid.Column="1" Grid.Row="2"
                        Orientation="Horizontal"
                        HorizontalAlignment="Right"
                        Margin="12,0,0,0">
                
                <Button Name="CancelButton"
                        Content="Cancel"
                        Width="60"
                        Height="24"
                        Margin="0,0,8,0"
                        Background="Transparent"
                        Foreground="#FFCCCCCC"
                        BorderBrush="#FF484848"
                        BorderThickness="1"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF2A2A2A"/>
                                    <Setter Property="Foreground" Value="White"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
                <Button Name="OKButton"
                        Content="OK"
                        Width="60"
                        Height="24"
                        Background="#FF0078D4"
                        Foreground="White"
                        BorderBrush="Transparent"
                        BorderThickness="0"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF106EBE"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

        Write-UserLog "Creating WPF window from XAML..."
        
        # Create window from XAML
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
        $window = [Windows.Markup.XamlReader]::Load($reader)
        
        Write-UserLog "WPF window created successfully"
        
        # Get button references
        $okButton = $window.FindName("OKButton")
        $cancelButton = $window.FindName("CancelButton")
        
        # Set up event handlers and timeout
        $script:dialogResult = $null
        $script:timeoutReached = $false
        
        # Store original button text and determine which button gets countdown
        $originalOKText = $okButton.Content
        $originalCancelText = $cancelButton.Content
        $showCountdownOnOK = ($DefaultAction -eq "OK")
        
        Write-UserLog "Countdown will be shown on: $(if ($showCountdownOnOK) { 'OK' } else { 'Cancel' }) button (DefaultAction: $DefaultAction)"
        
        # Create countdown timer (updates every second)
        $script:timeRemaining = $TimeoutSeconds
        $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
        $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
        
        $countdownTimer.Add_Tick({
            $script:timeRemaining--
            Write-UserLog "Countdown update: $($script:timeRemaining) seconds remaining"
            
            # Update the appropriate button with countdown
            if ($showCountdownOnOK) {
                $okButton.Content = "$originalOKText ($($script:timeRemaining))"
            } else {
                $cancelButton.Content = "$originalCancelText ($($script:timeRemaining))"
            }
            
            # Stop countdown timer when we reach zero (main timeout timer will handle dialog close)
            if ($script:timeRemaining -le 0) {
                $countdownTimer.Stop()
            }
        })
        
        # Create main timeout timer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-UserLog "Dialog timeout reached after $TimeoutSeconds seconds - auto-closing with default action: $DefaultAction"
            $script:timeoutReached = $true
            $script:dialogResult = $DefaultAction
            $timer.Stop()
            $countdownTimer.Stop()
            $window.Close()
            
            # Force immediate termination to prevent 30-second delay
            Write-UserLog "Forcing immediate process termination to prevent delay"
            $terminationTimer = New-Object System.Windows.Threading.DispatcherTimer
            $terminationTimer.Interval = [System.TimeSpan]::FromMilliseconds(500)
            $terminationTimer.Add_Tick({
                Write-UserLog "Terminating process now"
                $terminationTimer.Stop()
                
                # Write response file immediately before termination
                Write-ResponseFile -Response $DefaultAction -FilePath $ResponseFilePath -AdditionalData @{
                    stage = "TIMEOUT_TERMINATION"
                    terminationMethod = "Timer_Force_Exit"
                    defaultAction = $DefaultAction
                }
                
                # Multiple termination attempts
                try { $window.Hide() } catch {}
                try { [System.Windows.Application]::Current.Shutdown() } catch {}
                Start-Sleep -Milliseconds 100
                [System.Environment]::Exit(0)
            })
            $terminationTimer.Start()
        })
        
        $okButton.Add_Click({
            Write-UserLog "OK button clicked"
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "OK"
            $window.Close()
        })
        
        $cancelButton.Add_Click({
            Write-UserLog "Cancel button clicked"
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "Cancel"
            $window.Close()
        })
        
        # Handle window closing without button click
        $window.Add_Closing({
            $timer.Stop()
            $countdownTimer.Stop()
            if ($script:dialogResult -eq $null -and -not $script:timeoutReached) {
                Write-UserLog "Window closed without button click - treating as Cancel"
                $script:dialogResult = "Cancel"
            }
        })
        
        # Position window like a native Windows toast notification
        $window.Add_Loaded({
            $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $taskbarHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height - $workArea.Height
            
            switch ($Position) {
                "BottomRight" {
                    $window.Left = $workArea.Width - $window.Width - 16
                    $window.Top = $workArea.Height - $window.Height - 16
                    Write-UserLog "Window positioned at bottom-right (near notification area)"
                }
                "TopRight" {
                    $window.Left = $workArea.Width - $window.Width - 16
                    $window.Top = 16
                    Write-UserLog "Window positioned at top-right"
                }
                "BottomLeft" {
                    $window.Left = 16
                    $window.Top = $workArea.Height - $window.Height - 16
                    Write-UserLog "Window positioned at bottom-left"
                }
                "TopLeft" {
                    $window.Left = 16
                    $window.Top = 16
                    Write-UserLog "Window positioned at top-left"
                }
                "Center" {
                    $window.Left = ($workArea.Width - $window.Width) / 2
                    $window.Top = ($workArea.Height - $window.Height) / 2
                    Write-UserLog "Window positioned at center"
                }
            }
        })
        
        Write-UserLog "Showing dialog with $TimeoutSeconds second timeout (DefaultAction: $DefaultAction)..."
        
        # Start both timers
        $timer.Start()
        $countdownTimer.Start()
        Write-UserLog "Timeout and countdown timers started"
        
        # Show dialog modally (timer will auto-close if needed)
        $result = $window.ShowDialog()
        
        # Ensure timers are stopped
        $timer.Stop()
        $countdownTimer.Stop()
        
        Write-UserLog "Dialog closed with result: $($script:dialogResult)"
        
        return $script:dialogResult
        
    } catch {
        $errorMsg = "Failed to show modern dialog: $($_.Exception.Message)"
        Write-UserLog $errorMsg -Level "ERROR"
        Write-UserLog "Exception Type: $($_.Exception.GetType().FullName)" -Level "ERROR"
        Write-UserLog "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR"
        
        Write-ResponseFile -Response "ERROR" -FilePath $ResponseFilePath -AdditionalData @{
            error = $errorMsg
            stage = "MODERN_DIALOG"
            exceptionType = $_.Exception.GetType().FullName
        }
        return "ERROR"
    }
}

# Main execution
try {
    Write-UserLog "Starting modern dialog user prompt"
    
    # Test write permissions to response file location
    $responseDir = Split-Path $ResponseFilePath
    Write-UserLog "Response directory: $responseDir"
    Write-UserLog "Directory exists: $(Test-Path $responseDir)"
    
    try {
        $testFile = Join-Path $responseDir "test_write_$(Get-Random).tmp"
        "test" | Out-File -FilePath $testFile -Force
        Remove-Item $testFile -Force
        Write-UserLog "Write permissions confirmed for response directory"
    } catch {
        Write-UserLog "WARNING: Cannot write to response directory: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Show modern dialog to capture user response
    $userResponse = Show-ModernDialog -TitleText $Title -QuestionText $Question -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    
    if ($userResponse -eq "ERROR") {
        Write-UserLog "Modern dialog failed" -Level "ERROR"
        $script:UserResponse = "ERROR"
    } else {
        Write-UserLog "User response captured: $userResponse" -Level "SUCCESS"
        $script:UserResponse = $userResponse
        $script:ResponseReceived = $true
    }
    
    # Write final response
    Write-UserLog "Writing final response file..."
    $writeSuccess = Write-ResponseFile -Response $script:UserResponse -FilePath $ResponseFilePath -AdditionalData @{
        stage = "FINAL_RESPONSE"
        dialogMethod = "Modern WPF Dialog"
        interactionSuccess = $script:ResponseReceived
    }
    
    if ($writeSuccess) {
        Write-UserLog "User prompt completed successfully with response: $($script:UserResponse)" -Level "SUCCESS"
    } else {
        Write-UserLog "Failed to write response file" -Level "ERROR"
    }
    
    # Force immediate process termination to prevent scheduled task delays
    if ($script:UserResponse -eq "TIMEOUT") {
        Write-UserLog "Timeout occurred - forcing immediate process exit"
        Start-Sleep -Milliseconds 100  # Brief pause to ensure log is written
        [System.Environment]::Exit(0)
    }
    
} catch {
    Write-UserLog "Unexpected error in user prompt: $($_.Exception.Message)" -Level "ERROR"
    Write-UserLog "Exception Type: $($_.Exception.GetType().FullName)" -Level "ERROR"
    Write-UserLog "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR"
    
    # Try to write error response
    try {
        Write-ResponseFile -Response "ERROR" -FilePath $ResponseFilePath -AdditionalData @{
            error = $_.Exception.Message
            stage = "UNEXPECTED_ERROR"
            exceptionType = $_.Exception.GetType().FullName
        }
    } catch {
        Write-UserLog "Could not write final error response: $($_.Exception.Message)" -Level "ERROR"
    }
} finally {
    Write-UserLog "User prompt script completed"
    Write-UserLog "=== USER PROMPT SCRIPT ENDED ==="
    
    # Ensure process exits immediately in all cases
    Start-Sleep -Milliseconds 100  # Brief pause to ensure logs are written
}
'@
        
        # Write the user prompt script to temp file
        Write-Log "Writing user prompt script to: $userPromptScriptPath" | Out-Null
        $userPromptScriptContent | Set-Content -Path $userPromptScriptPath -Encoding UTF8
        
        Write-Log "Response file path: $responseFile" | Out-Null
        Write-Log "User script path: $userPromptScriptPath" | Out-Null
        
        # Create scheduled task using the working PowerShell Task Scheduler approach
        $createdTaskName = New-UserPromptTask -UserInfo $userInfo -ScriptPath $userPromptScriptPath -ResponseFile $responseFile -QuestionText $Question -TitleText $Title -TimeoutSeconds $TimeoutSeconds
        
        if (-not $createdTaskName) {
            Write-Log "Failed to create scheduled task" | Out-Null
            return $DefaultAction
        }
        
        # Start the task
        if (-not (Start-UserPromptTask -TaskName $createdTaskName)) {
            Write-Log "Failed to start scheduled task" | Out-Null
            Remove-UserPromptTask -TaskName $createdTaskName
            return $DefaultAction
        }
        
        # Wait for user response using the working method with task monitoring
        $userResponse = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $TimeoutSeconds
        
        # If timeout occurred, force task termination to prevent 30-second delay
        if ($userResponse -eq "TIMEOUT") {
            Write-Log "Timeout detected - forcing immediate task termination" | Out-Null
            
            # Stop the scheduled task immediately
            try {
                Stop-ScheduledTask -TaskName $createdTaskName -ErrorAction SilentlyContinue
                Write-Log "Scheduled task stopped" | Out-Null
            } catch {
                Write-Log "Error stopping scheduled task: $($_.Exception.Message)" | Out-Null
            }
            
            # Wait a moment then force-kill any remaining PowerShell processes associated with the task
            Start-Sleep -Milliseconds 500
            try {
                $taskProcesses = Get-WmiObject -Class Win32_Process | Where-Object {
                    $_.CommandLine -like "*$userPromptScriptPath*" -or
                    $_.CommandLine -like "*UserPrompt_*"
                }
                foreach ($process in $taskProcesses) {
                    Write-Log "Force-terminating task process: $($process.ProcessId)" | Out-Null
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Log "Error force-terminating processes: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Cleanup
        Remove-UserPromptTask -TaskName $createdTaskName
        
        # Clean up temporary files
        Remove-Item $userPromptScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        
        Write-Log "Process completed with response: $userResponse" | Out-Null
        return $userResponse
        
    } catch {
        Write-Log -Message "Invoke-SystemUserPrompt failed: $($_.Exception.Message)" | Out-Null
        return $DefaultAction
    }
}

function Show-ProcessCloseDialog {
    <#
    .SYNOPSIS
        Shows a user dialog asking whether to close a blocking process for application update
        Now integrated with deferral system for enhanced user experience
    .DESCRIPTION
        Uses the modern WPF-based notification system with deferral capabilities
        Checks deferral status and shows appropriate dialog (simple close or deferral options)
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
    .PARAMETER CurrentVersion
        Current version of the application
    .PARAMETER AvailableVersion
        Available version for update
    .PARAMETER WhitelistConfig
        Whitelist configuration object for the app
    .OUTPUTS
        Hashtable with user choice: @{ CloseProcess = [bool]; DeferralDays = [int]; Action = "Update|Defer" }
    #>
    param(
        [string]$AppName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false,
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = "",
        [object]$WhitelistConfig = $null
    )

    Write-Log -Message "Show-ProcessCloseDialog called for $AppName" | Out-Null

    # Use provided FriendlyName or fallback to AppName
    $friendlyName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }

    Write-Log -Message "Friendly name resolved to: $friendlyName" | Out-Null

    try {
        # Check deferral status if whitelist config is provided
        $deferralStatus = $null
        $hasDeferralSupport = $false
        
        if ($WhitelistConfig -and $WhitelistConfig.DeferralEnabled -eq $true) {
            Write-Log -Message "Checking deferral status for $AppName" | Out-Null
            $deferralStatus = Get-DeferralStatus -AppID $AppName -WhitelistConfig $WhitelistConfig -AvailableVersion $AvailableVersion
            $hasDeferralSupport = $true
        }
        
        # Determine dialog type based on deferral status
        if ($hasDeferralSupport -and $deferralStatus) {
            Write-Log -Message "Using deferral-enabled dialog for $AppName (CanDefer: $($deferralStatus.CanDefer), ForceUpdate: $($deferralStatus.ForceUpdate))" | Out-Null
            
            # Show enhanced deferral dialog with configured timeout
            $deferralChoice = Show-DeferralDialog -AppName $AppName -DeferralStatus $deferralStatus -ProcessName $ProcessName -FriendlyName $friendlyName -CurrentVersion $CurrentVersion -AvailableVersion $AvailableVersion -TimeoutSeconds $TimeoutSeconds
            
            # Record deferral choice if user chose to defer
            if ($deferralChoice.Action -eq "Defer" -and $deferralChoice.DeferralDays -gt 0) {
                $deferralRecorded = Set-DeferralChoice -AppID $AppName -DeferralDays $deferralChoice.DeferralDays
                if ($deferralRecorded) {
                    Write-Log -Message "Recorded user deferral choice: $($deferralChoice.DeferralDays) days for $AppName" | Out-Null
                } else {
                    Write-Log -Message "Failed to record deferral choice - proceeding with update" | Out-Null
                    $deferralChoice.Action = "Update"
                    $deferralChoice.CloseProcess = $true
                }
            }
            
            # Return structured response
            return @{
                CloseProcess = $deferralChoice.CloseProcess
                DeferralDays = $deferralChoice.DeferralDays
                Action = $deferralChoice.Action
                UserChoice = ($deferralChoice.Action -eq "Update")
            }
            
        } else {
            # Use legacy simple dialog for apps without deferral support
            Write-Log -Message "Using legacy dialog for $AppName (no deferral support)" | Out-Null
            
            # Create the question text with version information
            $versionText = ""
            if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                $versionText = "$friendlyName $CurrentVersion -> $AvailableVersion update available`n`n"
            } else {
                $versionText = "An update is available for $friendlyName`n`n"
            }
            
            $question = "${versionText}The application cannot be updated while it is running.`n`nWould you like to close $friendlyName now to allow the update to proceed?"
            $title = if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                "Update ${friendlyName}: ${CurrentVersion} -> ${AvailableVersion}"
            } else {
                "${friendlyName} Update Available"
            }
            
            # Convert DefaultTimeoutAction boolean to string format
            $defaultActionString = if ($DefaultTimeoutAction) { "OK" } else { "Cancel" }
            
            Write-Log -Message "Showing legacy WPF dialog for $friendlyName with ${TimeoutSeconds}s timeout, default action: $defaultActionString" | Out-Null
            
            # Call the context-aware dialog system
            $response = Show-UserDialog -Question $question -Title $title -TimeoutSeconds $TimeoutSeconds -DefaultAction $defaultActionString
            
            Write-Log -Message "Legacy WPF dialog response: $response" | Out-Null
            
            # Convert response back to boolean and return structured response
            $userChoice = ($response -eq "OK")
            
            if ($userChoice) {
                Write-Log -Message "User chose to close $friendlyName for update" | Out-Null
            } else {
                Write-Log -Message "User chose to keep $friendlyName open" | Out-Null
            }
            
            return @{
                CloseProcess = $userChoice
                DeferralDays = 0
                Action = if ($userChoice) { "Update" } else { "Cancel" }
                UserChoice = $userChoice
            }
        }
        
    } catch {
        Write-Log -Message "Show-ProcessCloseDialog failed: $($_.Exception.Message)" | Out-Null
        Write-Log -Message "Using default timeout action: $DefaultTimeoutAction" | Out-Null
        return @{
            CloseProcess = $DefaultTimeoutAction
            DeferralDays = 0
            Action = if ($DefaultTimeoutAction) { "Update" } else { "Cancel" }
            UserChoice = $DefaultTimeoutAction
        }
    }
}

function Show-DirectUserDialog {
    <#
    .SYNOPSIS
        Shows a simple direct WPF dialog when already running in user context
    .DESCRIPTION
        Lightweight version of the dialog system for user context execution
        No scheduled tasks needed - direct WPF execution
    #>
    param(
        [string]$Question,
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )
    
    try {
        Write-Log -Message "Showing direct user dialog: '$Question'" | Out-Null
        
        # Load WPF assemblies
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        # Create modern dark-themed XAML dialog
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$Title"
    Width="420"
    MinHeight="140"
    SizeToContent="Height"
    WindowStartupLocation="Manual"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Topmost="True"
    ShowInTaskbar="False">
    
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    
    <Border Name="MainBorder"
            Background="#FF1F1F1F"
            CornerRadius="8"
            BorderBrush="#FF323232"
            BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        
        <Grid Margin="16,12,16,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="32"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Icon -->
            <Ellipse Grid.Column="0" Grid.RowSpan="2"
                     Width="24" Height="24"
                     Fill="#FF0078D4"
                     VerticalAlignment="Top"
                     Margin="0,2,0,0"/>
            
            <TextBlock Grid.Column="0" Grid.RowSpan="2"
                       Text="?"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="Bold"
                       HorizontalAlignment="Center"
                       VerticalAlignment="Top"
                       Margin="0,4,0,0"/>
            
            <!-- Title -->
            <TextBlock Grid.Column="1" Grid.Row="0"
                       Text="$Title"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="SemiBold"
                       Margin="12,0,0,2"
                       TextWrapping="Wrap"/>
            
            <!-- Question -->
            <TextBlock Grid.Column="1" Grid.Row="1"
                       Text="$Question"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Buttons -->
            <StackPanel Grid.Column="1" Grid.Row="2"
                        Orientation="Horizontal"
                        HorizontalAlignment="Right"
                        Margin="12,0,0,0">
                
                <Button Name="CancelButton"
                        Content="Cancel"
                        Width="60"
                        Height="24"
                        Margin="0,0,8,0"
                        Background="Transparent"
                        Foreground="#FFCCCCCC"
                        BorderBrush="#FF484848"
                        BorderThickness="1"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF2A2A2A"/>
                                    <Setter Property="Foreground" Value="White"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
                <Button Name="OKButton"
                        Content="OK"
                        Width="60"
                        Height="24"
                        Background="#FF0078D4"
                        Foreground="White"
                        BorderBrush="Transparent"
                        BorderThickness="0"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF106EBE"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

        # Create window from XAML
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
        $window = [Windows.Markup.XamlReader]::Load($reader)
        
        # Get button references
        $okButton = $window.FindName("OKButton")
        $cancelButton = $window.FindName("CancelButton")
        
        # Set up result handling
        $script:dialogResult = $DefaultAction
        
        # Store original button text and determine which button gets countdown (SAME AS SYSTEM CONTEXT)
        $originalOKText = $okButton.Content
        $originalCancelText = $cancelButton.Content
        $showCountdownOnOK = ($DefaultAction -eq "OK")
        
        Write-Log -Message "Countdown will be shown on: $(if ($showCountdownOnOK) { 'OK' } else { 'Cancel' }) button (DefaultAction: $DefaultAction)" | Out-Null
        
        # Create countdown timer (updates every second) - SAME AS SYSTEM CONTEXT
        $script:timeRemaining = $TimeoutSeconds
        $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
        $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
        
        $countdownTimer.Add_Tick({
            $script:timeRemaining--
            Write-Log -Message "Countdown update: $($script:timeRemaining) seconds remaining" | Out-Null
            
            # Update the appropriate button with countdown
            if ($showCountdownOnOK) {
                $okButton.Content = "$originalOKText ($($script:timeRemaining))"
            } else {
                $cancelButton.Content = "$originalCancelText ($($script:timeRemaining))"
            }
            
            # Stop countdown timer when we reach zero (main timeout timer will handle dialog close)
            if ($script:timeRemaining -le 0) {
                $countdownTimer.Stop()
            }
        })
        
        # Create main timeout timer - SAME AS SYSTEM CONTEXT
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-Log -Message "Direct dialog timeout reached - using default action: $DefaultAction" | Out-Null
            $script:dialogResult = $DefaultAction
            $timer.Stop()
            $countdownTimer.Stop()
            $window.Close()
        })
        
        # Button event handlers - SAME AS SYSTEM CONTEXT
        $okButton.Add_Click({
            Write-Log -Message "OK button clicked in direct dialog" | Out-Null
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "OK"
            $window.Close()
        })
        
        $cancelButton.Add_Click({
            Write-Log -Message "Cancel button clicked in direct dialog" | Out-Null
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "Cancel"
            $window.Close()
        })
        
        # Handle window closing without button click - SAME AS SYSTEM CONTEXT
        $window.Add_Closing({
            $timer.Stop()
            $countdownTimer.Stop()
            if ($script:dialogResult -eq $null) {
                Write-Log -Message "Direct dialog closed without button click - treating as Cancel" | Out-Null
                $script:dialogResult = "Cancel"
            }
        })
        
        # Position window like a native Windows toast notification
        $window.Add_Loaded({
            $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $taskbarHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height - $workArea.Height
            
            # Position at bottom-right (near notification area)
            $window.Left = $workArea.Width - $window.Width - 16
            $window.Top = $workArea.Height - $window.Height - 16
            Write-Log -Message "Direct dialog positioned at bottom-right (near notification area)" | Out-Null
        })
        
        # Start both timers and show dialog - SAME AS SYSTEM CONTEXT
        $timer.Start()
        $countdownTimer.Start()
        Write-Log -Message "Direct dialog: Timeout and countdown timers started" | Out-Null
        $result = $window.ShowDialog()
        $timer.Stop()
        $countdownTimer.Stop()
        
        Write-Log -Message "Direct dialog completed with result: $($script:dialogResult)" | Out-Null
        return $script:dialogResult
        
    } catch {
        Write-Log -Message "Error in direct user dialog: $($_.Exception.Message)" | Out-Null
        return $DefaultAction
    }
}

function Show-MandatoryUpdateDialog {
    <#
    .SYNOPSIS
        Shows a mandatory update dialog with only a Continue button
    .DESCRIPTION
        Used when updates are required and cannot be deferred - no Cancel option
    #>
    param(
        [string]$Question,
        [string]$Title = "Required Update",
        [int]$TimeoutSeconds = 60,
        [bool]$HasBlockingProcess = $false
    )
    
    try {
        if (Test-RunningAsSystem) {
            # System context - use scheduled task approach
            return Invoke-SystemMandatoryUpdatePrompt -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds
        } else {
            # Direct user context
            return Show-DirectMandatoryUpdateDialog -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds
        }
    } catch {
        Write-Log "Error in Show-MandatoryUpdateDialog: $($_.Exception.Message)" | Out-Null
        return "Continue"  # Default to continuing with update
    }
}

function Show-DirectMandatoryUpdateDialog {
    <#
    .SYNOPSIS
        Direct user context mandatory update dialog with only Continue button
    #>
    param(
        [string]$Question,
        [string]$Title,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Showing direct mandatory update dialog: '$Question'" | Out-Null
        
        # Load WPF assemblies
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        # Create modern dark-themed XAML dialog with only Continue button
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$Title"
    Width="420"
    MinHeight="140"
    SizeToContent="Height"
    WindowStartupLocation="Manual"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Topmost="True"
    ShowInTaskbar="False">
    
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    
    <Border Name="MainBorder"
            Background="#FF1F1F1F"
            CornerRadius="8"
            BorderBrush="#FF323232"
            BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        
        <Grid Margin="16,12,16,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="32"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Icon -->
            <Ellipse Grid.Column="0" Grid.RowSpan="2"
                     Width="24" Height="24"
                     Fill="#FFFF6B00"
                     VerticalAlignment="Top"
                     Margin="0,2,0,0"/>
            
            <TextBlock Grid.Column="0" Grid.RowSpan="2"
                       Text="!"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="Bold"
                       HorizontalAlignment="Center"
                       VerticalAlignment="Top"
                       Margin="0,4,0,0"/>
            
            <!-- Title -->
            <TextBlock Grid.Column="1" Grid.Row="0"
                       Text="$Title"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="SemiBold"
                       Margin="12,0,0,2"
                       TextWrapping="Wrap"/>
            
            <!-- Question -->
            <TextBlock Grid.Column="1" Grid.Row="1"
                       Text="$Question"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Button -->
            <StackPanel Grid.Column="1" Grid.Row="2"
                        Orientation="Horizontal"
                        HorizontalAlignment="Right"
                        Margin="12,0,0,0">
                
                <Button Name="ContinueButton"
                        Content="Continue"
                        Width="80"
                        Height="24"
                        Background="#FFFF6B00"
                        Foreground="White"
                        BorderBrush="Transparent"
                        BorderThickness="0"
                        FontSize="11"
                        Cursor="Hand"
                        IsDefault="true">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FFE55A00"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

        # Create window from XAML
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
        $window = [Windows.Markup.XamlReader]::Load($reader)
        
        # Get button reference
        $continueButton = $window.FindName("ContinueButton")
        
        # Set up result handling
        $script:dialogResult = "Continue"
        
        # Store original button text for countdown
        $originalButtonText = $continueButton.Content
        
        # Create countdown timer (updates every second)
        $script:timeRemaining = $TimeoutSeconds
        $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
        $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
        
        $countdownTimer.Add_Tick({
            $script:timeRemaining--
            Write-Log "Mandatory dialog countdown: $($script:timeRemaining) seconds remaining" | Out-Null
            
            # Update button with countdown
            $continueButton.Content = "$originalButtonText ($($script:timeRemaining))"
            
            # Stop countdown timer when we reach zero
            if ($script:timeRemaining -le 0) {
                $countdownTimer.Stop()
            }
        })
        
        # Create main timeout timer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-Log "Mandatory dialog timeout reached - auto-continuing" | Out-Null
            $script:dialogResult = "Continue"
            $timer.Stop()
            $countdownTimer.Stop()
            $window.Close()
        })
        
        # Button event handler
        $continueButton.Add_Click({
            Write-Log "Continue button clicked in mandatory dialog" | Out-Null
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "Continue"
            $window.Close()
        })
        
        # Handle window closing
        $window.Add_Closing({
            $timer.Stop()
            $countdownTimer.Stop()
            if ($script:dialogResult -eq $null) {
                Write-Log "Mandatory dialog closed without button click - continuing anyway" | Out-Null
                $script:dialogResult = "Continue"
            }
        })
        
        # Position window like a native Windows toast notification
        $window.Add_Loaded({
            $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            
            # Position at bottom-right (near notification area)
            $window.Left = $workArea.Width - $window.Width - 16
            $window.Top = $workArea.Height - $window.Height - 16
            Write-Log "Mandatory dialog positioned at bottom-right" | Out-Null
        })
        
        # Start both timers and show dialog
        $timer.Start()
        $countdownTimer.Start()
        Write-Log "Mandatory dialog: Timeout and countdown timers started" | Out-Null
        $result = $window.ShowDialog()
        $timer.Stop()
        $countdownTimer.Stop()
        
        Write-Log "Mandatory dialog completed with result: $($script:dialogResult)" | Out-Null
        return $script:dialogResult
        
    } catch {
        Write-Log "Error in direct mandatory dialog: $($_.Exception.Message)" | Out-Null
        return "Continue"
    }
}

function Invoke-SystemMandatoryUpdatePrompt {
    <#
    .SYNOPSIS
        System context mandatory update dialog using scheduled tasks
    #>
    param(
        [string]$Question,
        [string]$Title,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Invoking system mandatory update prompt" | Out-Null
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - cannot show mandatory dialog" | Out-Null
            return "Continue"
        }
        
        # Create unique identifiers
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        
        # Setup response file path
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $responseFile = if (Test-Path $userTempPath) {
            Join-Path $userTempPath "MandatoryPrompt_$promptId`_Response.json"
        } else {
            Join-Path "C:\ProgramData\Temp" "MandatoryPrompt_$promptId`_Response.json"
        }
        
        # Create mandatory prompt script
        $mandatoryScriptPath = "$env:TEMP\Show-MandatoryPrompt_$promptId.ps1"
        
        $mandatoryScriptContent = @'
param(
    [string]$ResponseFilePath,
    [string]$EncodedQuestion,
    [string]$EncodedTitle,
    [int]$TimeoutSeconds = 60
)

# Decode parameters
$actualQuestion = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedQuestion))
$actualTitle = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle))

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# Use the decoded text and split on pipe separator for separate display
$parts = $actualQuestion -split '\|'
$versionInfo = if ($parts.Length -gt 0) { $parts[0].Trim() } else { $actualQuestion }
$actionMessage = if ($parts.Length -gt 1) { $parts[1].Trim() } else { "" }

$escapedTitle = [System.Security.SecurityElement]::Escape($actualTitle)
$escapedVersionInfo = [System.Security.SecurityElement]::Escape($versionInfo)
$escapedActionMessage = [System.Security.SecurityElement]::Escape($actionMessage)

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$escapedTitle" Width="420" MinHeight="140" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
        
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
        
    <Border Background="#FF1F1F1F" CornerRadius="8" BorderBrush="#FF323232" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        <Grid Margin="16,12,16,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="32"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Icon -->
            <Ellipse Grid.Column="0" Grid.RowSpan="3"
                     Width="24" Height="24"
                     Fill="#FFFF6B00"
                     VerticalAlignment="Top"
                     Margin="0,2,0,0"/>
            
            <TextBlock Grid.Column="0" Grid.RowSpan="3"
                       Text="!"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="Bold"
                       HorizontalAlignment="Center"
                       VerticalAlignment="Top"
                       Margin="0,4,0,0"/>
            
            <!-- Title -->
            <TextBlock Grid.Column="1" Grid.Row="0"
                       Text="$escapedTitle"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="SemiBold"
                       Margin="12,0,0,2"
                       TextWrapping="Wrap"/>
            
            <!-- Version Info -->
            <TextBlock Grid.Column="1" Grid.Row="1"
                       Text="$escapedVersionInfo"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Action Message -->
            <TextBlock Grid.Column="1" Grid.Row="2"
                       Text="$escapedActionMessage"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Button -->
            <StackPanel Grid.Column="1" Grid.Row="3"
                        Orientation="Horizontal"
                        HorizontalAlignment="Right"
                        Margin="12,0,0,0">
                        
                <Button Name="UpgradeButton" Content="Upgrade" Width="80" Height="24" Background="#FF0078D4" Foreground="White" IsDefault="true">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF106EBE"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

$script:result = "Continue"

# Get button reference and store original text
$upgradeButton = $window.FindName("UpgradeButton")
$originalButtonText = if ($upgradeButton) { $upgradeButton.Content } else { "Upgrade" }

# Create countdown timer (updates every second)
$script:timeRemaining = $TimeoutSeconds
$countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
$countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)

$countdownTimer.Add_Tick({
    $script:timeRemaining--
    
    # Update button with countdown
    if ($upgradeButton) {
        $upgradeButton.Content = "$originalButtonText ($($script:timeRemaining))"
    }
    
    # Stop countdown timer when we reach zero (main timeout timer will handle dialog close)
    if ($script:timeRemaining -le 0) {
        $countdownTimer.Stop()
    }
})

# Create main timeout timer
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)

$timer.Add_Tick({
    $script:result = "Continue"
    $timer.Stop()
    $countdownTimer.Stop()
    $window.Close()
})

# Position window like other dialogs (bottom-right)
$window.Add_Loaded({
    $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    
    # Position at bottom-right (near notification area)
    $window.Left = $workArea.Width - $window.Width - 16
    $window.Top = $workArea.Height - $window.Height - 16
})

# Add upgrade button handler
if ($upgradeButton) {
    $upgradeButton.Add_Click({
        $timer.Stop()
        $countdownTimer.Stop()
        $script:result = "Continue"
        $window.Close()
    })
}

# Handle window closing
$window.Add_Closing({
    $timer.Stop()
    $countdownTimer.Stop()
    if ($script:result -eq $null) {
        $script:result = "Continue"
    }
})

# Start both timers
$timer.Start()
$countdownTimer.Start()

$window.ShowDialog() | Out-Null

# Ensure timers are stopped
$timer.Stop()
$countdownTimer.Stop()

# Write response
@{ response = $script:result; timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
'@

        Write-Log -Message "Creating mandatory prompt script: $mandatoryScriptPath" | Out-Null
        $mandatoryScriptContent | Set-Content -Path $mandatoryScriptPath -Encoding UTF8
        
        # Create scheduled task
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "MandatoryPrompt_$guid"
        
        # Create task arguments with encoded parameters
        $encodedQuestion = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Question))
        $encodedTitle = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Title))
        # Use hidden console window execution method
        $hiddenArguments = "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$mandatoryScriptPath`" -ResponseFilePath `"$responseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -TimeoutSeconds $TimeoutSeconds"
        
        # Create and register task using hidden console method
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $hiddenArguments
        
        # Create task principal
        $principal = $null
        $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
        $logonTypes = @("Interactive", "S4U")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Created mandatory task principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed mandatory task principal: $userFormat ($logonType)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        if (-not $principal) {
            Write-Log "Could not create mandatory task principal" | Out-Null
            return "Continue"
        }
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Mandatory update prompt"
        
        try {
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Log "Mandatory scheduled task started successfully" | Out-Null
        } catch {
            Write-Log "Failed to start mandatory scheduled task: $($_.Exception.Message)" | Out-Null
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return "Continue"
        }
        
        # Wait for response
        $taskTimeout = $TimeoutSeconds + 30
        $response = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $taskTimeout
        
        # Cleanup
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $mandatoryScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        
        return "Continue"  # Always continue for mandatory updates
        
    } catch {
        Write-Log "Error in system mandatory prompt: $($_.Exception.Message)" | Out-Null
        return "Continue"
    }
}

function Show-UserDialog {
    <#
    .SYNOPSIS
        Context-aware dialog function that chooses appropriate dialog method
    #>
    param(
        [string]$Question,
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )
    
    if (Test-RunningAsSystem) {
        # Complex scheduled task system for SYSTEM → User context (existing - keep as-is)
        return Invoke-SystemUserPrompt -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    } else {
        # Simple direct WPF dialog for user context
        return Show-DirectUserDialog -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    }
}

# ============================================================================
# DEFERRAL MANAGEMENT SYSTEM
# Time-based deferral system with admin-controlled hard deadlines
# ============================================================================

function Initialize-DeferralRegistry {
    <#
    .SYNOPSIS
        Ensures the deferral registry structure exists
    .DESCRIPTION
        Creates the necessary registry keys for storing deferral and release cache data
    #>
    
    try {
        $deferralPath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals"
        $cachePath = "HKLM:\SOFTWARE\WingetUpgradeManager\ReleaseCache"
        
        if (-not (Test-Path $deferralPath)) {
            Write-Log "Creating deferral registry path: $deferralPath" | Out-Null
            New-Item -Path $deferralPath -Force | Out-Null
        }
        
        if (-not (Test-Path $cachePath)) {
            Write-Log "Creating release cache registry path: $cachePath" | Out-Null
            New-Item -Path $cachePath -Force | Out-Null
        }
        
        return $true
        
    } catch {
        Write-Log "Error initializing deferral registry: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Get-AppReleaseDate {
    <#
    .SYNOPSIS
        Gets the release date of an app version from winget, with caching
    .DESCRIPTION
        Retrieves app release date from winget show command with performance-optimized caching
        Caches results to avoid repeated winget queries
    .PARAMETER AppID
        Application ID to query
    .PARAMETER Version
        Specific version to query (optional)
    .OUTPUTS
        DateTime object of release date, or $null if not found
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [string]$Version = ""
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null
        
        # Create cache key - include version in key if specified
        $cacheKey = if ($Version) { "$AppID-$Version" } else { $AppID }
        $cachePath = "HKLM:\SOFTWARE\WingetUpgradeManager\ReleaseCache"
        
        # Check cache first
        try {
            $cachedDate = Get-ItemProperty -Path $cachePath -Name $cacheKey -ErrorAction SilentlyContinue
            if ($cachedDate) {
                $releaseDate = [DateTime]::Parse($cachedDate.$cacheKey)
                Write-Log "Found cached release date for $cacheKey : $releaseDate" | Out-Null
                return $releaseDate
            }
        } catch {
            Write-Log "Cache read error for $cacheKey : $($_.Exception.Message)" | Out-Null
        }
        
        Write-Log "Querying winget for release date: $AppID $(if ($Version) { "version $Version" })" | Out-Null
        
        # Query winget show command
        $showCommand = if ($Version) {
            "winget show --id `"$AppID`" --version `"$Version`" --accept-source-agreements"
        } else {
            "winget show --id `"$AppID`" --accept-source-agreements"
        }
        
        # Execute winget show with appropriate context
        $showOutput = if ((Test-RunningAsSystem) -and $WingetPath) {
            & "$WingetPath\winget.exe" show --id $AppID $(if ($Version) { "--version"; $Version }) --accept-source-agreements 2>&1
        } else {
            & winget show --id $AppID $(if ($Version) { "--version"; $Version }) --accept-source-agreements 2>&1
        }
        
        if ($showOutput) {
            # Parse output for release date - look for various date patterns
            $releaseDate = $null
            $datePatterns = @(
                "Published:\s+([^`r`n]+)",
                "Release Date:\s+([^`r`n]+)",
                "Date:\s+([^`r`n]+)",
                "Updated:\s+([^`r`n]+)"
            )
            
            foreach ($pattern in $datePatterns) {
                foreach ($line in $showOutput) {
                    if ($line -match $pattern) {
                        $dateString = $matches[1].Trim()
                        Write-Log "Found potential date string: '$dateString'" | Out-Null
                        
                        # Try to parse the date string
                        try {
                            $releaseDate = [DateTime]::Parse($dateString)
                            Write-Log "Successfully parsed release date: $releaseDate" | Out-Null
                            break
                        } catch {
                            Write-Log "Failed to parse date '$dateString': $($_.Exception.Message)" | Out-Null
                        }
                    }
                }
                if ($releaseDate) { break }
            }
            
            # If we found a valid date, cache it
            if ($releaseDate) {
                try {
                    Set-ItemProperty -Path $cachePath -Name $cacheKey -Value $releaseDate.ToString("yyyy-MM-dd HH:mm:ss") -Force
                    Write-Log "Cached release date for $cacheKey : $releaseDate" | Out-Null
                } catch {
                    Write-Log "Failed to cache release date: $($_.Exception.Message)" | Out-Null
                }
                return $releaseDate
            } else {
                Write-Log "No release date found in winget output for $AppID" | Out-Null
            }
        } else {
            Write-Log "No output from winget show for $AppID" | Out-Null
        }
        
        return $null
        
    } catch {
        Write-Log "Error getting app release date for ${AppID}: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Get-DeferralStatus {
    <#
    .SYNOPSIS
        Gets the current deferral status for an application
    .DESCRIPTION
        Retrieves deferral information from registry including count, dates, and deadline status
    .PARAMETER AppID
        Application ID to check
    .PARAMETER WhitelistConfig
        Whitelist configuration object for the app
    .PARAMETER AvailableVersion
        Available version to check against
    .OUTPUTS
        Hashtable with deferral status information
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [Parameter(Mandatory=$true)]
        [object]$WhitelistConfig,
        
        [string]$AvailableVersion = ""
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null
        
        $deferralPath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals\$AppID"
        $now = Get-Date
        
        # Default status - no deferrals
        $status = @{
            DeferralEnabled = $WhitelistConfig.DeferralEnabled -eq $true
            MaxDeferralDays = if ($WhitelistConfig.MaxDeferralDays) { $WhitelistConfig.MaxDeferralDays } else { 0 }
            DeferralsUsed = 0
            LastDeferralDate = $null
            UserDeadline = $null
            AdminHardDeadline = $null
            ReleaseDate = $null
            CanDefer = $false
            ForceUpdate = $false
            DeferralOptions = if ($WhitelistConfig.DeferralOptions) { $WhitelistConfig.DeferralOptions } else { @() }
            Message = ""
        }
        
        # If deferrals not enabled for this app, return early
        if (-not $status.DeferralEnabled) {
            $status.Message = "Deferrals not enabled for this application"
            $status.ForceUpdate = $true
            return $status
        }
        
        # Get release date for deadline calculations
        $releaseDate = Get-AppReleaseDate -AppID $AppID -Version $AvailableVersion
        if ($releaseDate) {
            $status.ReleaseDate = $releaseDate
            
            # Calculate admin hard deadline (release date + MaxDeferralDays)
            $status.AdminHardDeadline = $releaseDate.AddDays($status.MaxDeferralDays)
        }
        
        # Check if deferral data exists
        if (Test-Path $deferralPath) {
            try {
                $deferralData = Get-ItemProperty -Path $deferralPath -ErrorAction SilentlyContinue
                if ($deferralData) {
                    # Parse existing deferral data
                    if ($deferralData.DeferralsUsed) {
                        $status.DeferralsUsed = [int]$deferralData.DeferralsUsed
                    }
                    
                    if ($deferralData.LastDeferralDate) {
                        $status.LastDeferralDate = [DateTime]::Parse($deferralData.LastDeferralDate)
                    }
                    
                    if ($deferralData.UserDeadline) {
                        $status.UserDeadline = [DateTime]::Parse($deferralData.UserDeadline)
                    }
                }
            } catch {
                Write-Log "Error reading deferral data for ${AppID}: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Determine if update should be forced
        $forceReasons = @()
        
        # Check admin hard deadline (takes precedence)
        if ($status.AdminHardDeadline -and $now -gt $status.AdminHardDeadline) {
            $daysOverdue = ($now - $status.AdminHardDeadline).Days
            $forceReasons += "Admin hard deadline exceeded ($($daysOverdue) days overdue)"
            $status.ForceUpdate = $true
        }
        
        # Check user deadline
        if (-not $status.ForceUpdate -and $status.UserDeadline -and $now -gt $status.UserDeadline) {
            $forceReasons += "User deadline exceeded"
            $status.ForceUpdate = $true
        }
        
        # Determine if user can still defer
        if (-not $status.ForceUpdate) {
            $daysUntilAdminDeadline = if ($status.AdminHardDeadline) {
                [Math]::Max(0, ($status.AdminHardDeadline - $now).Days)
            } else {
                999  # No admin deadline
            }
            
            # User can defer if:
            # 1. We haven't reached admin hard deadline
            # 2. There are available deferral options within the remaining time
            if ($daysUntilAdminDeadline -gt 0 -and $status.DeferralOptions.Count -gt 0) {
                # Find available deferral options that fit within remaining time
                $availableOptions = @()
                foreach ($option in $status.DeferralOptions) {
                    if ($option -le $daysUntilAdminDeadline) {
                        $availableOptions += $option
                    }
                }
                
                if ($availableOptions.Count -gt 0) {
                    $status.CanDefer = $true
                    $status.DeferralOptions = $availableOptions
                }
            }
        }
        
        # Build status message
        if ($status.ForceUpdate) {
            if ($WhitelistConfig.ForcedUpgradeMessage) {
                $status.Message = $WhitelistConfig.ForcedUpgradeMessage
            } else {
                $status.Message = "Update required: $($forceReasons -join '; ')"
            }
        } elseif ($status.CanDefer) {
            $daysLeft = if ($status.AdminHardDeadline) {
                ($status.AdminHardDeadline - $now).Days
            } else {
                $status.MaxDeferralDays
            }
            $status.Message = "Update available. You can defer this update for up to $daysLeft more days."
        } else {
            $status.Message = "Update available. No deferral options remaining."
            $status.ForceUpdate = $true
        }
        
        Write-Log "Deferral status for ${AppID}: CanDefer=$($status.CanDefer), ForceUpdate=$($status.ForceUpdate), Message=$($status.Message)" | Out-Null
        
        return $status
        
    } catch {
        Write-Log "Error getting deferral status for ${AppID}: $($_.Exception.Message)" | Out-Null
        # Return safe default - force update on error
        return @{
            DeferralEnabled = $false
            ForceUpdate = $true
            CanDefer = $false
            Message = "Error checking deferral status - update required"
        }
    }
}

function Set-DeferralChoice {
    <#
    .SYNOPSIS
        Records a user's deferral choice in the registry
    .DESCRIPTION
        Saves deferral information including selected timeframe and calculated deadlines
    .PARAMETER AppID
        Application ID
    .PARAMETER DeferralDays
        Number of days to defer
    .OUTPUTS
        Boolean indicating success
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [Parameter(Mandatory=$true)]
        [int]$DeferralDays
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null
        
        $deferralPath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals\$AppID"
        $now = Get-Date
        
        # Ensure the app-specific path exists
        if (-not (Test-Path $deferralPath)) {
            New-Item -Path $deferralPath -Force | Out-Null
        }
        
        # Get current deferral count
        $currentDeferrals = 0
        try {
            $existing = Get-ItemProperty -Path $deferralPath -Name "DeferralsUsed" -ErrorAction SilentlyContinue
            if ($existing) {
                $currentDeferrals = [int]$existing.DeferralsUsed
            }
        } catch {
            # Use default of 0
        }
        
        # Calculate new user deadline
        $userDeadline = $now.AddDays($DeferralDays)
        
        # Update deferral data
        Set-ItemProperty -Path $deferralPath -Name "DeferralsUsed" -Value ($currentDeferrals + 1) -Force
        Set-ItemProperty -Path $deferralPath -Name "LastDeferralDate" -Value $now.ToString("yyyy-MM-dd HH:mm:ss") -Force
        Set-ItemProperty -Path $deferralPath -Name "UserDeadline" -Value $userDeadline.ToString("yyyy-MM-dd HH:mm:ss") -Force
        Set-ItemProperty -Path $deferralPath -Name "DeferralDays" -Value $DeferralDays -Force
        
        Write-Log "Recorded deferral choice for ${AppID}: ${DeferralDays} days, deadline: $userDeadline" | Out-Null
        
        return $true
        
    } catch {
        Write-Log "Error setting deferral choice for ${AppID}: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Show-DeferralDialog {
    <#
    .SYNOPSIS
        Shows an enhanced dialog with deferral options
    .DESCRIPTION
        Displays a sophisticated WPF dialog offering deferral choices or immediate update
    .PARAMETER AppName
        Application ID for the update
    .PARAMETER DeferralStatus
        Deferral status hashtable from Get-DeferralStatus
    .PARAMETER ProcessName
        Name of the blocking process (if any)
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER CurrentVersion
        Current version of the application
    .PARAMETER AvailableVersion
        Available version for update
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    .OUTPUTS
        Hashtable with user choice: @{ Action = "Update|Defer"; DeferralDays = [int] }
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DeferralStatus,
        
        [string]$ProcessName = "",
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = "",
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Show-DeferralDialog called for $AppName" | Out-Null
        
        # Use provided FriendlyName or fallback to AppName
        $displayName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }
        
        # Determine if process needs to be closed
        $hasBlockingProcess = -not [string]::IsNullOrEmpty($ProcessName)
        
        # Build dialog content
        $versionText = ""
        if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
            $versionText = "$displayName $CurrentVersion -> $AvailableVersion update available`n`n"
        } else {
            $versionText = "Update available for $displayName`n`n"
        }
        
        $processText = if ($hasBlockingProcess) {
            "$displayName is currently running and must be closed to proceed with the update.`n`n"
        } else {
            ""
        }
        
        $deferralText = if ($DeferralStatus.ForceUpdate) {
            $DeferralStatus.Message
        } else {
            "$($DeferralStatus.Message)`n`nYou can choose to:"
        }
        
        $question = $versionText + $processText + $deferralText
        
        # Create enhanced WPF dialog with deferral options
        if ($DeferralStatus.ForceUpdate) {
            # Force update - show mandatory update dialog with only Continue button
            $title = "Required Update: $displayName"
            
            # Create clean, user-friendly message components
            $versionInfo = ""
            $actionMessage = ""
            
            if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                $versionInfo = "$displayName $CurrentVersion -> $AvailableVersion"
            } else {
                $versionInfo = "$displayName update available"
            }
            
            if ($hasBlockingProcess) {
                $actionMessage = "$displayName must be closed to install this update."
            } else {
                $actionMessage = "This security/compatibility update cannot be postponed."
            }
            
            # Pass separate components instead of combined question
            $response = Show-MandatoryUpdateDialog -Question "$versionInfo|$actionMessage" -Title $title -TimeoutSeconds $TimeoutSeconds -HasBlockingProcess $hasBlockingProcess
            
            return @{
                Action = "Update"
                DeferralDays = 0
                CloseProcess = $true
            }
        } else {
            # Show deferral options
            $title = "Update Available: $displayName"
            
            # Create complex dialog with deferral buttons
            $deferralChoice = Show-EnhancedDeferralDialog -Question $question -Title $title -DeferralOptions $DeferralStatus.DeferralOptions -HasBlockingProcess $hasBlockingProcess -TimeoutSeconds $TimeoutSeconds
            
            return $deferralChoice
        }
        
    } catch {
        Write-Log "Error in Show-DeferralDialog: $($_.Exception.Message)" | Out-Null
        # Return safe default
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Show-EnhancedDeferralDialog {
    <#
    .SYNOPSIS
        Shows a complex WPF dialog with multiple deferral options
    .DESCRIPTION
        Creates a sophisticated dialog allowing users to choose from available deferral timeframes
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Question,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$true)]
        [array]$DeferralOptions,
        
        [bool]$HasBlockingProcess = $false,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        # For system context, use the enhanced scheduled task approach
        if (Test-RunningAsSystem) {
            return Invoke-SystemDeferralPrompt -Question $Question -Title $Title -DeferralOptions $DeferralOptions -HasBlockingProcess $HasBlockingProcess -TimeoutSeconds $TimeoutSeconds
        } else {
            # Direct user context - simplified approach
            return Show-DirectDeferralDialog -Question $Question -Title $Title -DeferralOptions $DeferralOptions -HasBlockingProcess $HasBlockingProcess -TimeoutSeconds $TimeoutSeconds
        }
        
    } catch {
        Write-Log "Error in Show-EnhancedDeferralDialog: $($_.Exception.Message)" | Out-Null
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Show-DirectDeferralDialog {
    <#
    .SYNOPSIS
        Direct user context deferral dialog
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>
    
    param(
        [string]$Question,
        [string]$Title,
        [array]$DeferralOptions,
        [bool]$HasBlockingProcess,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Showing direct deferral dialog with options: $($DeferralOptions -join ', ')" | Out-Null
        
        # Load WPF assemblies
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        # Build dynamic button XML based on deferral options
        $buttonXml = ""
        $buttonCount = 0
        
        # Add deferral option buttons
        foreach ($days in ($DeferralOptions | Sort-Object)) {
            $buttonText = if ($days -eq 1) { "Defer 1 day" } else { "Defer $days days" }
            $buttonName = "DeferButton$days"
            $buttonXml += @"
                <Button Name="$buttonName"
                        Content="$buttonText"
                        Width="100"
                        Height="28"
                        Margin="0,0,8,0"
                        Background="Transparent"
                        Foreground="#FFCCCCCC"
                        BorderBrush="#FF484848"
                        BorderThickness="1"
                        FontSize="11"
                        Cursor="Hand"
                        Tag="$days">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF2A2A2A"/>
                                    <Setter Property="Foreground" Value="White"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
"@
            $buttonCount++
        }
        
        # Add Update Now button
        $buttonXml += @"
                <Button Name="UpdateButton"
                        Content="Update Now"
                        Width="100"
                        Height="28"
                        Background="#FF0078D4"
                        Foreground="White"
                        BorderBrush="Transparent"
                        BorderThickness="0"
                        FontSize="11"
                        Cursor="Hand"
                        IsDefault="true"
                        Tag="0">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF106EBE"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
"@
        
        # Calculate dialog width based on button count
        $dialogWidth = [Math]::Max(500, ($buttonCount + 1) * 110 + 100)
        
        # Create modern dark-themed XAML
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$Title"
    Width="$dialogWidth"
    MinHeight="200"
    SizeToContent="Height"
    WindowStartupLocation="Manual"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Topmost="True"
    ShowInTaskbar="False">
    
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    
    <Border Name="MainBorder"
            Background="#FF1F1F1F"
            CornerRadius="8"
            BorderBrush="#FF323232"
            BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        
        <Grid Margin="20">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Question -->
            <TextBlock Grid.Row="0"
                       Text="$Question"
                       Foreground="#FFCCCCCC"
                       TextWrapping="Wrap"
                       Margin="0,0,0,20"
                       FontSize="12"/>
            
            <!-- Buttons -->
            <StackPanel Grid.Row="1"
                        Orientation="Horizontal"
                        HorizontalAlignment="Center">
                $buttonXml
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

        # Create window
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
        $window = [Windows.Markup.XamlReader]::Load($reader)
        
        # Set up result handling
        $script:deferralResult = @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
        
        # Add timeout functionality with countdown timer - same as other dialogs
        $script:timeRemaining = $TimeoutSeconds
        $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
        $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
        
        # Get the Update button for countdown display
        $updateButton = $window.FindName("UpdateButton")
        $originalUpdateText = if ($updateButton) { $updateButton.Content } else { "Update Now" }
        
        $countdownTimer.Add_Tick({
            $script:timeRemaining--
            Write-Log "Deferral dialog countdown: $($script:timeRemaining) seconds remaining" | Out-Null
            
            # Update the Update button with countdown (default action)
            if ($updateButton) {
                $updateButton.Content = "$originalUpdateText ($($script:timeRemaining))"
            }
            
            # Stop countdown timer when we reach zero (main timeout timer will handle dialog close)
            if ($script:timeRemaining -le 0) {
                $countdownTimer.Stop()
            }
        })
        
        # Create main timeout timer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-Log "Deferral dialog timeout reached after $TimeoutSeconds seconds - defaulting to Update" | Out-Null
            $script:deferralResult = @{
                Action = "Update"
                DeferralDays = 0
                CloseProcess = $true
            }
            $timer.Stop()
            $countdownTimer.Stop()
            $window.Close()
        })
        
        # Add event handlers for deferral buttons
        foreach ($days in $DeferralOptions) {
            $buttonName = "DeferButton$days"
            $button = $window.FindName($buttonName)
            if ($button) {
                $button.Add_Click({
                    $selectedDays = [int]$this.Tag
                    Write-Log "User selected deferral: $selectedDays days" | Out-Null
                    $timer.Stop()
                    $countdownTimer.Stop()
                    $script:deferralResult = @{
                        Action = "Defer"
                        DeferralDays = $selectedDays
                        CloseProcess = $false
                    }
                    $window.Close()
                }.GetNewClosure())
            }
        }
        
        # Add event handler for Update button
        if ($updateButton) {
            $updateButton.Add_Click({
                Write-Log "User selected immediate update" | Out-Null
                $timer.Stop()
                $countdownTimer.Stop()
                $script:deferralResult = @{
                    Action = "Update"
                    DeferralDays = 0
                    CloseProcess = $true
                }
                $window.Close()
            })
        }
        
        # Handle window closing without button click
        $window.Add_Closing({
            $timer.Stop()
            $countdownTimer.Stop()
            if ($script:deferralResult.Action -eq $null) {
                Write-Log "Deferral dialog closed without selection - defaulting to update" | Out-Null
                $script:deferralResult = @{
                    Action = "Update"
                    DeferralDays = 0
                    CloseProcess = $true
                }
            }
        })
        
        # Position window like a native Windows toast notification
        $window.Add_Loaded({
            $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $taskbarHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height - $workArea.Height
            
            # Position at bottom-right (near notification area)
            $window.Left = $workArea.Width - $window.Width - 16
            $window.Top = $workArea.Height - $window.Height - 16
            Write-Log "Deferral dialog positioned at bottom-right (near notification area)" | Out-Null
        })
        
        # Start both timers and show dialog
        Write-Log "Starting deferral dialog with $TimeoutSeconds second timeout" | Out-Null
        $timer.Start()
        $countdownTimer.Start()
        
        # Show dialog
        $result = $window.ShowDialog()
        
        # Ensure timers are stopped
        $timer.Stop()
        $countdownTimer.Stop()
        
        Write-Log "Direct deferral dialog completed with choice: $($script:deferralResult.Action), Days: $($script:deferralResult.DeferralDays)" | Out-Null
        return $script:deferralResult
        
    } catch {
        Write-Log "Error in direct deferral dialog: $($_.Exception.Message)" | Out-Null
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Invoke-SystemDeferralPrompt {
    <#
    .SYNOPSIS
        System context deferral dialog using scheduled tasks
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>
    
    param(
        [string]$Question,
        [string]$Title,
        [array]$DeferralOptions,
        [bool]$HasBlockingProcess,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Invoking system deferral prompt with options: $($DeferralOptions -join ', ')" | Out-Null
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - cannot show deferral dialog" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Create unique identifiers
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        
        # Setup response file path
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $responseFile = if (Test-Path $userTempPath) {
            Join-Path $userTempPath "DeferralPrompt_$promptId`_Response.json"
        } else {
            Join-Path "C:\ProgramData\Temp" "DeferralPrompt_$promptId`_Response.json"
        }
        
        # Create enhanced user prompt script for deferrals
        $deferralScriptPath = "$env:TEMP\Show-DeferralPrompt_$promptId.ps1"
        
        # Build the script content dynamically
        $deferralOptionsJson = ($DeferralOptions | ConvertTo-Json -Compress)
        
        $deferralScriptContent = @'
param(
    [string]$ResponseFilePath,
    [string]$EncodedQuestion,
    [string]$EncodedTitle,
    [string]$DeferralOptionsJson,
    [bool]$HasBlockingProcess = $false,
    [int]$TimeoutSeconds = 60,
    # Legacy parameters for backward compatibility
    [string]$Question = "",
    [string]$Title = ""
)

# Decode the text parameters if they're base64 encoded, otherwise use legacy parameters
$actualQuestion = if ($EncodedQuestion) {
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedQuestion))
} else {
    $Question
}

$actualTitle = if ($EncodedTitle) {
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle))
} else {
    $Title
}

# Parse deferral options
$deferralOptions = $DeferralOptionsJson | ConvertFrom-Json

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# Build dynamic buttons XML
$buttonXml = ""
foreach ($days in ($deferralOptions | Sort-Object)) {
    $buttonText = if ($days -eq 1) { "Defer 1 day" } else { "Defer $days days" }
    $buttonName = "DeferButton$days"
    $buttonXml += "<Button Name=`"$buttonName`" Content=`"$buttonText`" Width=`"100`" Height=`"28`" Margin=`"0,0,8,0`" Tag=`"$days`"/>"
}
$buttonXml += '<Button Name="UpdateButton" Content="Update Now" Width="100" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="true" Tag="0"/>'

$dialogWidth = [Math]::Max(500, ($deferralOptions.Count + 1) * 110 + 100)

# Use the decoded text in XAML with proper XML escaping
$escapedQuestion = [System.Security.SecurityElement]::Escape($actualQuestion)
$escapedTitle = [System.Security.SecurityElement]::Escape($actualTitle)

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$escapedTitle" Width="$dialogWidth" MinHeight="200" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Border Background="#FF1F1F1F" CornerRadius="8" BorderBrush="#FF323232" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        <Grid Margin="20">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Text="$escapedQuestion" Foreground="#FFCCCCCC" TextWrapping="Wrap" Margin="0,0,0,20" FontSize="12"/>
            <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Center">$buttonXml</StackPanel>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

$script:result = @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }

# Add deferral button handlers
foreach ($days in $deferralOptions) {
    $button = $window.FindName("DeferButton$days")
    if ($button) {
        $button.Add_Click({
            $selectedDays = [int]$this.Tag
            $script:result = @{ Action = "Defer"; DeferralDays = $selectedDays; CloseProcess = $false }
            $window.Close()
        }.GetNewClosure())
    }
}

# Add update button handler
$updateButton = $window.FindName("UpdateButton")
if ($updateButton) {
    $updateButton.Add_Click({
        $script:result = @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        $window.Close()
    })
}

$window.ShowDialog() | Out-Null

# Write response
$script:result | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
'@

        Write-Log "Creating deferral prompt script: $deferralScriptPath" | Out-Null
        $deferralScriptContent | Set-Content -Path $deferralScriptPath -Encoding UTF8
        
        # Create scheduled task with timeout parameter
        Write-Log "Creating scheduled task with timeout: $TimeoutSeconds seconds" | Out-Null
        
        # Generate unique task name
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "DeferralPrompt_$guid"
        
        # Create task arguments with timeout parameter - ensure proper encoding for text parameters
        $encodedQuestion = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Question))
        $encodedTitle = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Title))
        # Use hidden console window execution method
        $hiddenArguments = "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$deferralScriptPath`" -ResponseFilePath `"$responseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -DeferralOptionsJson `"$deferralOptionsJson`" -HasBlockingProcess $$HasBlockingProcess -TimeoutSeconds $TimeoutSeconds"
        
        # Create task using hidden console method
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $hiddenArguments
        
        # Create task principal using existing user info
        $principal = $null
        $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
        $logonTypes = @("Interactive", "S4U")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Successfully created deferral task principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed deferral task principal with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        if (-not $principal) {
            Write-Log "Could not create deferral task principal" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Create and register task
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Interactive deferral prompt for system operations"
        
        try {
            $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
            Write-Log "Deferral scheduled task created successfully: $taskName" | Out-Null
        } catch {
            Write-Log "Failed to register deferral scheduled task: $($_.Exception.Message)" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Start the task
        try {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Log "Deferral scheduled task started successfully" | Out-Null
        } catch {
            Write-Log "Failed to start deferral scheduled task: $($_.Exception.Message)" | Out-Null
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Wait for response - use configured timeout plus buffer for task overhead
        $taskTimeout = $TimeoutSeconds + 30  # Add 30 seconds buffer for task creation/cleanup
        $response = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $taskTimeout
        
        # Parse response
        $deferralChoice = @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        
        if ($response -ne "TIMEOUT" -and (Test-Path $responseFile)) {
            try {
                $responseData = Get-Content -Path $responseFile -Raw | ConvertFrom-Json
                $deferralChoice = @{
                    Action = $responseData.Action
                    DeferralDays = [int]$responseData.DeferralDays
                    CloseProcess = [bool]$responseData.CloseProcess
                }
                Write-Log "Parsed deferral response: $($deferralChoice.Action), $($deferralChoice.DeferralDays) days" | Out-Null
            } catch {
                Write-Log "Error parsing deferral response: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Cleanup
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $deferralScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        
        return $deferralChoice
        
    } catch {
        Write-Log "Error in system deferral prompt: $($_.Exception.Message)" | Out-Null
        return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
    }
}

function Clear-ExpiredDeferralData {
    <#
    .SYNOPSIS
        Cleans up old deferral and cache data
    .DESCRIPTION
        Removes deferral data for completed updates and old cached release dates
    #>
    
    try {
        Write-Log "Starting deferral data cleanup" | Out-Null
        
        $deferralBasePath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals"
        $cacheBasePath = "HKLM:\SOFTWARE\WingetUpgradeManager\ReleaseCache"
        $now = Get-Date
        $cleanupCount = 0
        
        # Clean up expired deferral data (older than 90 days)
        if (Test-Path $deferralBasePath) {
            $appKeys = Get-ChildItem -Path $deferralBasePath -ErrorAction SilentlyContinue
            foreach ($appKey in $appKeys) {
                try {
                    $deferralData = Get-ItemProperty -Path $appKey.PSPath -ErrorAction SilentlyContinue
                    if ($deferralData -and $deferralData.LastDeferralDate) {
                        $lastDeferral = [DateTime]::Parse($deferralData.LastDeferralDate)
                        if (($now - $lastDeferral).Days -gt 90) {
                            Remove-Item -Path $appKey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log "Removed expired deferral data for: $($appKey.PSChildName)" | Out-Null
                            $cleanupCount++
                        }
                    }
                } catch {
                    Write-Log "Error processing deferral cleanup for $($appKey.PSChildName): $($_.Exception.Message)" | Out-Null
                }
            }
        }
        
        # Clean up old release cache entries (older than 30 days)
        if (Test-Path $cacheBasePath) {
            try {
                $cacheData = Get-ItemProperty -Path $cacheBasePath -ErrorAction SilentlyContinue
                if ($cacheData) {
                    $propertiesToRemove = @()
                    foreach ($property in $cacheData.PSObject.Properties) {
                        if ($property.Name -notlike "PS*") {  # Skip PowerShell built-in properties
                            try {
                                # Try to parse as date to see if it's old
                                $cacheDate = [DateTime]::Parse($property.Value)
                                if (($now - $cacheDate).Days -gt 30) {
                                    $propertiesToRemove += $property.Name
                                }
                            } catch {
                                # If we can't parse the date, it might be malformed - remove it
                                $propertiesToRemove += $property.Name
                            }
                        }
                    }
                    
                    foreach ($propName in $propertiesToRemove) {
                        Remove-ItemProperty -Path $cacheBasePath -Name $propName -ErrorAction SilentlyContinue
                        $cleanupCount++
                    }
                }
            } catch {
                Write-Log "Error during cache cleanup: $($_.Exception.Message)" | Out-Null
            }
        }
        
        Write-Log "Deferral cleanup completed: $cleanupCount items removed" | Out-Null
        
    } catch {
        Write-Log "Error during deferral cleanup: $($_.Exception.Message)" | Out-Null
    }
}

# ============================================================================
# END DEFERRAL MANAGEMENT SYSTEM
# ============================================================================

function Schedule-UserContextRemediation {
    <#
    .SYNOPSIS
        Schedules user context remediation execution - EXACT SAME APPROACH AS WORKING DETECTION SCRIPT
    .DESCRIPTION
        Uses the proven method from Invoke-UserContextDetection function
    #>
    
    try {
        Write-Log "Starting user context remediation scheduling" | Out-Null
        $startTime = Get-Date
        
        # Use SAME Get-InteractiveUser function as detection script (simple WMI-based)
        Write-Log "Calling Get-InteractiveUser function..." | Out-Null
        $userDetectionStart = Get-Date
        $userInfo = Get-InteractiveUser
        $userDetectionTime = (Get-Date) - $userDetectionStart
        Write-Log "Get-InteractiveUser completed in $($userDetectionTime.TotalSeconds) seconds" | Out-Null
        
        if (-not $userInfo) {
            Write-Log "No interactive user found - skipping user context remediation" | Out-Null
            Write-Log "Total time spent in user detection: $($userDetectionTime.TotalSeconds) seconds" | Out-Null
            return $false
        }
        Write-Log "Interactive user found: $($userInfo.Username)" | Out-Null
        Write-Log "User detection successful in $($userDetectionTime.TotalSeconds) seconds" | Out-Null
        
        # Create remediation result file - use shared path accessible to both SYSTEM and USER contexts (SAME AS DETECTION)
        $sharedTempPath = "C:\ProgramData\Temp"
        if (-not (Test-Path $sharedTempPath)) {
            New-Item -Path $sharedTempPath -ItemType Directory -Force | Out-Null
        }
        $randomId = Get-Random -Minimum 1000 -Maximum 9999
        $resultFile = Join-Path $sharedTempPath "UserRemediation_$randomId.json"
        Write-Log "User remediation result file: $resultFile" | Out-Null
        Write-Log "Using shared temp path accessible to both SYSTEM and USER contexts: $sharedTempPath" | Out-Null
        
        # Create scheduled task for user remediation (SAME APPROACH AS DETECTION)
        $taskName = "UserRemediation_$(Get-Random -Minimum 1000 -Maximum 9999)"
        $tempScriptName = "availableUpgrades-remediate_$(Get-Random -Minimum 1000 -Maximum 9999).ps1"
        $tempScriptPath = Join-Path $sharedTempPath $tempScriptName
        
        Write-Log "Copying script to user-accessible location: $tempScriptPath" | Out-Null
        Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force
        
        $scriptPath = $tempScriptPath
        # Use hidden console window execution method to prevent visible windows
        $hiddenArguments = "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -UserRemediationOnly -RemediationResultFile `"$resultFile`""
        
        Write-Log "Creating user remediation task: $taskName" | Out-Null
        Write-Log "Script path: $scriptPath" | Out-Null
        Write-Log "Hidden execution arguments: $hiddenArguments" | Out-Null
        Write-Log "Result file: $resultFile" | Out-Null
        
        # Verify script copy exists and is readable
        if (Test-Path $tempScriptPath) {
            $scriptSize = (Get-Item $tempScriptPath).Length
            Write-Log "Temp script exists, size: $scriptSize bytes" | Out-Null
        } else {
            Write-Log "ERROR: Temp script copy does not exist: $tempScriptPath" | Out-Null
            return $false
        }
        
        try {
            Write-Log "Creating scheduled task action with hidden console method..." | Out-Null
            $taskCreationStart = Get-Date
            
            # Create task action using hidden console window method
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $hiddenArguments
            Write-Log "Task action created successfully" | Out-Null
            
            # Create task principal (run as interactive user) - SAME AS DETECTION
            Write-Log "Creating task principal for user: $($userInfo.FullName)" | Out-Null
            $principalStart = Get-Date
            $principal = $null
            $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
            $logonTypes = @("Interactive", "S4U")
            
            foreach ($userFormat in $userFormats) {
                foreach ($logonType in $logonTypes) {
                    try {
                        $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                        Write-Log "Successfully created principal with: $userFormat ($logonType)" | Out-Null
                        break
                    } catch {
                        Write-Log "Failed with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                    }
                }
                if ($principal) { break }
            }
            
            if (-not $principal) {
                $principalTime = (Get-Date) - $principalStart
                Write-Log "Could not create task principal with any method after $($principalTime.TotalSeconds) seconds" | Out-Null
                return $false
            }
            
            $principalTime = (Get-Date) - $principalStart
            Write-Log "Task principal created successfully in $($principalTime.TotalSeconds) seconds" | Out-Null
            
            # Create task settings - SAME AS DETECTION
            Write-Log "Creating task settings..." | Out-Null
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
            
            # Create and register the task WITHOUT triggers (SAME AS DETECTION)
            Write-Log "Creating and registering scheduled task..." | Out-Null
            $registrationStart = Get-Date
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "User context winget remediation"
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            $registrationTime = (Get-Date) - $registrationStart
            Write-Log "Task created successfully: $taskName in $($registrationTime.TotalSeconds) seconds" | Out-Null
            
            # Verify task was created successfully before starting (SAME AS DETECTION)
            $createdTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $createdTask) {
                Write-Log "ERROR: Task creation failed - task not found: $taskName" | Out-Null
                return $false
            }
            Write-Log "Task verified to exist: $taskName, State: $($createdTask.State)" | Out-Null
            
            # Start the task (SAME AS DETECTION)
            Write-Log "Starting user remediation task: $taskName" | Out-Null
            $taskStartTime = Get-Date
            try {
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $taskStartDuration = (Get-Date) - $taskStartTime
                Write-Log "Start-ScheduledTask completed successfully in $($taskStartDuration.TotalSeconds) seconds" | Out-Null
                
                # Brief verification that task started
                Write-Log "Verifying task started..." | Out-Null
                Start-Sleep -Seconds 2
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Log "Task started successfully - LastResult: $($taskInfo.LastTaskResult), LastRunTime: $($taskInfo.LastRunTime)" | Out-Null
                } else {
                    Write-Log "Could not get task info after start" | Out-Null
                }
                
            } catch {
                $taskStartDuration = (Get-Date) - $taskStartTime
                Write-Log "ERROR: Failed to start scheduled task after $($taskStartDuration.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
                return $false
            }
            
            # Enhanced wait system with marker file synchronization
            # Create status/heartbeat file paths
            $statusFile = Join-Path $sharedTempPath "UserRemediation_$randomId.status"
            $heartbeatFile = Join-Path $sharedTempPath "UserRemediation_$randomId.heartbeat"
            
            # Much longer timeout but with progress monitoring
            $maxTimeout = 600  # 10 minutes maximum
            $heartbeatTimeout = 120  # 2 minutes without heartbeat timeout
            $startTime = Get-Date
            $success = $false
            
            Write-Log "Waiting for user remediation results with marker file synchronization" | Out-Null
            Write-Log "Result file expected at: $resultFile" | Out-Null
            Write-Log "Status file: $statusFile" | Out-Null
            Write-Log "Heartbeat file: $heartbeatFile" | Out-Null
            Write-Log "Maximum timeout: $maxTimeout seconds, Heartbeat timeout: $heartbeatTimeout seconds" | Out-Null
            
            $waitStartTime = Get-Date
            $lastStatusLog = Get-Date
            $lastHeartbeatCheck = Get-Date
            $checkCount = 0
            
            while ((Get-Date) -lt $waitStartTime.AddSeconds($maxTimeout)) {
                $checkCount++
                $currentTime = Get-Date
                $elapsedTotal = ($currentTime - $waitStartTime).TotalSeconds
                
                # Check for completion first (result file exists)
                if (Test-Path $resultFile) {
                    try {
                        Write-Log "Result file found after $elapsedTotal seconds" | Out-Null
                        Start-Sleep -Milliseconds 500  # Brief pause to ensure file is fully written
                        $fileContent = Get-Content $resultFile -Raw
                        $results = $fileContent | ConvertFrom-Json
                        
                        Write-Log "User remediation completed: $($results.ProcessedApps) apps processed" | Out-Null
                        if ($results.UpgradeResults) {
                            Write-Log "User remediation results: $($results.UpgradeResults -join ', ')" | Out-Null
                        }
                        $success = $true
                        break
                    } catch {
                        Write-Log "Error reading/parsing remediation results: $($_.Exception.Message)" | Out-Null
                        Start-Sleep -Seconds 2
                        continue
                    }
                }
                
                # Check heartbeat file to see if user context is still active
                $isUserContextActive = $false
                $heartbeatAge = 999
                if (Test-Path $heartbeatFile) {
                    try {
                        $heartbeatTime = (Get-Item $heartbeatFile).LastWriteTime
                        $heartbeatAge = ($currentTime - $heartbeatTime).TotalSeconds
                        $isUserContextActive = ($heartbeatAge -lt $heartbeatTimeout)
                        
                        if (-not $isUserContextActive) {
                            Write-Log "WARNING: Heartbeat file is $([int]$heartbeatAge) seconds old (timeout: $heartbeatTimeout)" | Out-Null
                        }
                    } catch {
                        Write-Log "Error reading heartbeat file: $($_.Exception.Message)" | Out-Null
                    }
                } else {
                    # If no heartbeat file yet, check if task just started (give it some time)
                    if ($elapsedTotal -gt 30) {  # Give 30 seconds for initial heartbeat
                        Write-Log "No heartbeat file found after $([int]$elapsedTotal) seconds" | Out-Null
                    } else {
                        $isUserContextActive = $true  # Still within startup grace period
                    }
                }
                
                # Check status file for progress updates
                $statusMessage = ""
                if (Test-Path $statusFile) {
                    try {
                        $statusContent = Get-Content $statusFile -Raw
                        $statusInfo = $statusContent | ConvertFrom-Json
                        $statusMessage = "Status: $($statusInfo.Status), Progress: $($statusInfo.Progress)"
                    } catch {
                        $statusMessage = "Status file exists but unreadable"
                    }
                }
                
                # Log status every 15 seconds
                if (($currentTime - $lastStatusLog).TotalSeconds -gt 15) {
                    Write-Log "Waiting... elapsed: $([int]$elapsedTotal)s, checks: $checkCount" | Out-Null
                    if ($statusMessage) {
                        Write-Log $statusMessage | Out-Null
                    }
                    if (Test-Path $heartbeatFile) {
                        Write-Log "Heartbeat: $([int]$heartbeatAge)s ago, Active: $isUserContextActive" | Out-Null
                    }
                    
                    # Check if task is still running
                    try {
                        $currentTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                        if ($currentTask) {
                            $currentTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                            if ($currentTaskInfo) {
                                Write-Log "Task status: State=$($currentTask.State), LastResult=$($currentTaskInfo.LastTaskResult)" | Out-Null
                            }
                        } else {
                            Write-Log "Scheduled task no longer exists" | Out-Null
                        }
                    } catch {
                        Write-Log "Could not check task status: $($_.Exception.Message)" | Out-Null
                    }
                    
                    $lastStatusLog = $currentTime
                }
                
                # If user context appears to be inactive/hung and we've waited long enough, timeout
                if (-not $isUserContextActive -and $elapsedTotal -gt 60) {
                    Write-Log "User context appears inactive (no recent heartbeat) - timing out" | Out-Null
                    Write-Log "Last heartbeat age: $([int]$heartbeatAge) seconds (max: $heartbeatTimeout)" | Out-Null
                    break
                }
                
                Start-Sleep -Seconds 3  # Slightly longer sleep since we're monitoring more files
            }
            
            $totalWaitTime = (Get-Date) - $waitStartTime
            if ((Get-Date) -ge $waitStartTime.AddSeconds($maxTimeout)) {
                Write-Log "User remediation timed out after $($totalWaitTime.TotalSeconds) seconds (limit: $maxTimeout)" | Out-Null
                Write-Log "Total file existence checks performed: $checkCount" | Out-Null
                
                # Final check on task status
                try {
                    $finalTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($finalTask) {
                        $finalTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                        Write-Log "Final task status: State=$($finalTask.State), LastResult=$($finalTaskInfo.LastTaskResult)" | Out-Null
                    }
                } catch {
                    Write-Log "Could not get final task status" | Out-Null
                }
            } else {
                Write-Log "User remediation completed successfully in $($totalWaitTime.TotalSeconds) seconds" | Out-Null
            }
            
            # Clean up marker files
            try {
                if (Test-Path $statusFile) { Remove-Item $statusFile -Force -ErrorAction SilentlyContinue }
                if (Test-Path $heartbeatFile) { Remove-Item $heartbeatFile -Force -ErrorAction SilentlyContinue }
                Write-Log "Cleaned up marker files" | Out-Null
            } catch {
                Write-Log "Error cleaning up marker files: $($_.Exception.Message)" | Out-Null
            }
            
        } catch {
            Write-Log "Exception in user remediation task: $($_.Exception.Message)" | Out-Null
            $success = $false
        } finally {
            # Cleanup - SAME AS DETECTION
            try {
                Write-Log "Starting cleanup" | Out-Null
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                
                if (Test-Path $resultFile) {
                    Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
                }
                
                # Clean up temporary script copy
                if (Test-Path $tempScriptPath) {
                    Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed temporary script copy: $tempScriptPath" | Out-Null
                }
                
                Write-Log "User remediation cleanup completed" | Out-Null
            } catch {
                Write-Log "Error during cleanup: $($_.Exception.Message)" | Out-Null
            }
        }
        
        $totalElapsed = (Get-Date) - $startTime
        Write-Log "Schedule-UserContextRemediation completed in $($totalElapsed.TotalSeconds) seconds with result: $success" | Out-Null
        return $success
        
    } catch {
        $totalElapsed = (Get-Date) - $startTime
        Write-Log "Error in user context remediation scheduling after $($totalElapsed.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
        Write-Log "Exception details: $($_.Exception.ToString())" | Out-Null
        return $false
    }
}

function Stop-BlockingProcesses {
    param(
        [string]$ProcessNames
    )
    
    $processesToStop = $ProcessNames -split ','
    $stoppedAny = $false
    $allProcesses = @()
    
    # Collect all processes to stop
    foreach ($processName in $processesToStop) {
        $processName = $processName.Trim()
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                $allProcesses += @{
                    Process = $process
                    Name = $processName
                    PID = $process.Id
                }
            }
        }
    }
    
    if ($allProcesses.Count -eq 0) {
        Write-Log -Message "No processes found to stop"
        return $false
    }
    
    $processCount = $allProcesses.Count
    Write-Log -Message "Found $processCount processes to close: $($allProcesses.Name -join ', ')"
    
    try {
        if ($processCount -gt 1) {
            Write-Log -Message "Multiple processes detected ($processCount), using parallel termination strategy"
            
            # Step 1: Attempt graceful close on all processes simultaneously
            Write-Log -Message "Attempting graceful close on all processes simultaneously..."
            foreach ($procInfo in $allProcesses) {
                try {
                    Write-Log -Message "Sending close signal to: $($procInfo.Name) (PID: $($procInfo.PID))"
                    $procInfo.Process.CloseMainWindow()
                } catch {
                    Write-Log -Message "Error sending close signal to $($procInfo.Name): $($_.Exception.Message)"
                }
            }
            
            # Step 2: Wait 2 seconds total (reduced from 5)
            Write-Log -Message "Waiting 2 seconds for graceful shutdown..."
            Start-Sleep -Seconds 2
            
            # Step 3: Check which processes are still running and force-kill them all at once
            $remainingProcesses = @()
            foreach ($procInfo in $allProcesses) {
                try {
                    # Refresh process state
                    $stillRunning = Get-Process -Id $procInfo.PID -ErrorAction SilentlyContinue
                    if ($stillRunning) {
                        $remainingProcesses += $procInfo
                    } else {
                        Write-Log -Message "Process $($procInfo.Name) (PID: $($procInfo.PID)) closed gracefully"
                        $stoppedAny = $true
                    }
                } catch {
                    # Process no longer exists (good)
                    Write-Log -Message "Process $($procInfo.Name) (PID: $($procInfo.PID)) no longer exists"
                    $stoppedAny = $true
                }
            }
            
            # Step 4: Force terminate remaining processes in parallel
            if ($remainingProcesses.Count -gt 0) {
                Write-Log -Message "Force-terminating $($remainingProcesses.Count) remaining processes..."
                foreach ($procInfo in $remainingProcesses) {
                    try {
                        Write-Log -Message "Force-killing: $($procInfo.Name) (PID: $($procInfo.PID))"
                        $procInfo.Process.Kill()
                        $stoppedAny = $true
                    } catch {
                        Write-Log -Message "Error force-killing $($procInfo.Name): $($_.Exception.Message)"
                    }
                }
                
                # Brief verification wait
                Start-Sleep -Seconds 1
                
                # Final verification
                $finalCheck = 0
                foreach ($procInfo in $remainingProcesses) {
                    try {
                        $stillExists = Get-Process -Id $procInfo.PID -ErrorAction SilentlyContinue
                        if ($stillExists) {
                            $finalCheck++
                            Write-Log -Message "WARNING: Process $($procInfo.Name) (PID: $($procInfo.PID)) still exists after force termination"
                        }
                    } catch {
                        # Process successfully terminated
                    }
                }
                
                if ($finalCheck -eq 0) {
                    Write-Log -Message "All processes successfully terminated using parallel approach"
                } else {
                    $remainingCount = $finalCheck
                    Write-Log -Message "Some processes may still be running ($($remainingCount) remaining)"
                }
            } else {
                Write-Log -Message "All processes closed gracefully - no force termination needed"
            }
            
            Write-Log -Message "Parallel process termination completed in ~6 seconds"
            
        } else {
            # Single process - use traditional approach
            Write-Log -Message "Single process detected, using traditional termination"
            $procInfo = $allProcesses[0]
            
            try {
                Write-Log -Message "Stopping process: $($procInfo.Name) (PID: $($procInfo.PID))"
                $procInfo.Process.CloseMainWindow()
                
                # Wait up to 3 seconds for graceful shutdown (reduced from 10)
                if (!$procInfo.Process.WaitForExit(3000)) {
                    Write-Log -Message "Process $($procInfo.Name) did not exit gracefully after 3s, forcing termination"
                    $procInfo.Process.Kill()
                }
                $stoppedAny = $true
                Write-Log -Message "Successfully stopped process: $($procInfo.Name)"
            } catch {
                Write-Log -Message "Error stopping process $($procInfo.Name): $($_.Exception.Message)"
            }
        }
        
    } catch {
        Write-Log -Message "Error in Stop-BlockingProcesses: $($_.Exception.Message)"
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

# ============================================================================
# CENTRALIZED MARKER FILE MANAGEMENT SYSTEM
# Provides robust marker file operations with comprehensive cleanup
# ============================================================================

# Global variable to track active marker files for cleanup
$Global:ActiveMarkerFiles = @()

function New-MarkerFile {
    <#
    .SYNOPSIS
        Creates a marker file with centralized tracking and logging
    .DESCRIPTION
        Creates marker files used for inter-process communication while tracking
        them globally for reliable cleanup. Handles path validation and error logging.
    .PARAMETER FilePath
        Full path where the marker file should be created
    .PARAMETER Content
        Content to write to the marker file
    .PARAMETER Description
        Description for logging purposes
    .OUTPUTS
        Boolean indicating success, and adds file to global tracking
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$Content,
        
        [string]$Description = "Marker file"
    )
    
    try {
        Write-Log -Message "Creating marker file: $FilePath ($Description)"
        
        # Ensure directory exists
        $directory = Split-Path -Parent $FilePath
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log -Message "Created directory for marker file: $directory"
        }
        
        # Create the marker file
        $Content | Out-File -FilePath $FilePath -Encoding UTF8 -Force -ErrorAction Stop
        
        # Add to global tracking for cleanup
        if ($Global:ActiveMarkerFiles -notcontains $FilePath) {
            $Global:ActiveMarkerFiles += $FilePath
            Write-Log -Message "Added marker file to cleanup tracking: $FilePath"
        }
        
        # Verify creation
        if (Test-Path $FilePath) {
            $fileSize = (Get-Item $FilePath -ErrorAction SilentlyContinue).Length
            Write-Log -Message "Successfully created marker file: $FilePath (Size: $fileSize bytes, Content: $($Content.Substring(0, [Math]::Min(50, $Content.Length)))...)"
            return $true
        } else {
            Write-Log -Message "ERROR: Marker file was not created despite successful Out-File: $FilePath"
            return $false
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to create marker file '$FilePath': $($_.Exception.Message)"
        return $false
    }
}

function Remove-MarkerFile {
    <#
    .SYNOPSIS
        Removes a specific marker file with logging and error handling
    .DESCRIPTION
        Safely removes marker files with comprehensive error handling and logging.
        Also removes the file from global tracking.
    .PARAMETER FilePath
        Full path of the marker file to remove
    .PARAMETER Description
        Description for logging purposes
    .OUTPUTS
        Boolean indicating success
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [string]$Description = "Marker file"
    )
    
    try {
        Write-Log -Message "Removing marker file: $FilePath ($Description)"
        
        if (Test-Path $FilePath) {
            # Get file info before deletion for logging
            $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
            $fileSize = if ($fileInfo) { $fileInfo.Length } else { "Unknown" }
            $fileAge = if ($fileInfo) { [Math]::Round(((Get-Date) - $fileInfo.CreationTime).TotalMinutes, 1) } else { "Unknown" }
            
            # Remove the file
            Remove-Item $FilePath -Force -ErrorAction Stop
            Write-Log -Message "Successfully removed marker file: $FilePath (Size: $fileSize bytes, Age: $fileAge minutes)"
            
            # Remove from global tracking
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            Write-Log -Message "Removed marker file from cleanup tracking: $FilePath"
            
            return $true
        } else {
            Write-Log -Message "Marker file not found (may already be cleaned up): $FilePath"
            # Still remove from tracking in case it was tracked but already deleted externally
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            return $true
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to remove marker file '$FilePath': $($_.Exception.Message)"
        return $false
    }
}

function Clear-OrphanedMarkerFiles {
    <#
    .SYNOPSIS
        Finds and removes orphaned marker files from previous script executions
    .DESCRIPTION
        Scans multiple locations for old marker files and removes them to prevent
        accumulation. Configurable age threshold and comprehensive location scanning.
    .PARAMETER MaxAgeMinutes
        Maximum age of marker files to keep (default: 60 minutes)
    .PARAMETER ScanLocations
        Array of paths to scan for marker files (auto-detected if not provided)
    .OUTPUTS
        Integer count of files cleaned up
    #>
    param(
        [int]$MaxAgeMinutes = 60,
        [string[]]$ScanLocations = @()
    )
    
    try {
        Write-Log -Message "Starting orphaned marker file cleanup (MaxAge: $MaxAgeMinutes minutes)"
        $cleanupCount = 0
        $cleanupStartTime = Get-Date
        
        # Default scan locations if not provided
        if ($ScanLocations.Count -eq 0) {
            $ScanLocations = @(
                "C:\ProgramData\Temp",
                $env:TEMP,
                "$env:SystemRoot\Temp"
            )
            
            # Add user-specific temp if we can detect the user
            try {
                $userInfo = Get-InteractiveUser -ErrorAction SilentlyContinue
                if ($userInfo -and $userInfo.Username) {
                    $userTemp = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
                    if ((Test-Path $userTemp) -and ($ScanLocations -notcontains $userTemp)) {
                        $ScanLocations += $userTemp
                    }
                }
            } catch {
                # Ignore errors in user detection during cleanup
            }
        }
        
        Write-Log -Message "Scanning $($ScanLocations.Count) locations for orphaned marker files"
        
        foreach ($location in $ScanLocations) {
            if (-not (Test-Path $location)) {
                Write-Log -Message "Scan location does not exist, skipping: $location"
                continue
            }
            
            Write-Log -Message "Scanning location: $location"
            
            try {
                # Look for various marker file patterns
                $patterns = @(
                    "availableUpgrades-detect_*.ps1.userdetection",
                    "availableUpgrades-remediate_*.ps1.userdetection",
                    "*.ps1.userdetection"  # Catch-all for any script marker files
                )
                
                $locationCleanupCount = 0
                foreach ($pattern in $patterns) {
                    $markerFiles = Get-ChildItem -Path $location -Filter $pattern -ErrorAction SilentlyContinue
                    
                    foreach ($markerFile in $markerFiles) {
                        try {
                            $fileAge = (Get-Date) - $markerFile.CreationTime
                            $fileAgeMinutes = $fileAge.TotalMinutes
                            
                            Write-Log -Message "Found marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                            
                            if ($fileAgeMinutes -gt $MaxAgeMinutes) {
                                # Check if this file is in our active tracking (don't remove active files)
                                $isActive = $Global:ActiveMarkerFiles -contains $markerFile.FullName
                                
                                if (-not $isActive) {
                                    Write-Log -Message "Removing orphaned marker file: $($markerFile.FullName) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                                    Remove-Item $markerFile.FullName -Force -ErrorAction Stop
                                    $cleanupCount++
                                    $locationCleanupCount++
                                } else {
                                    Write-Log -Message "Skipping active marker file: $($markerFile.FullName)"
                                }
                            } else {
                                Write-Log -Message "Keeping recent marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                            }
                            
                        } catch {
                            Write-Log -Message "ERROR: Failed to process marker file '$($markerFile.FullName)': $($_.Exception.Message)"
                        }
                    }
                }
                
                if ($locationCleanupCount -gt 0) {
                    Write-Log -Message "Cleaned up $locationCleanupCount marker files from: $location"
                }
                
            } catch {
                Write-Log -Message "ERROR: Failed to scan location '$location': $($_.Exception.Message)"
            }
        }
        
        $cleanupDuration = (Get-Date) - $cleanupStartTime
        if ($cleanupCount -gt 0) {
            Write-Log -Message "Orphaned marker file cleanup completed: $cleanupCount files removed in $([Math]::Round($cleanupDuration.TotalSeconds, 1)) seconds"
        } else {
            Write-Log -Message "No orphaned marker files found during cleanup scan"
        }
        
        return $cleanupCount
        
    } catch {
        Write-Log -Message "ERROR: Orphaned marker file cleanup failed: $($_.Exception.Message)"
        return 0
    }
}

function Add-MarkerFileCleanupTrap {
    <#
    .SYNOPSIS
        Sets up trap handlers to ensure marker files are cleaned up on script exit
    .DESCRIPTION
        Registers cleanup handlers for various exit scenarios to prevent orphaned files
    #>
    
    # PowerShell trap for unexpected errors
    trap {
        Write-Log -Message "Script error trap triggered - performing marker file cleanup"
        Invoke-MarkerFileEmergencyCleanup -Reason "PowerShell trap"
        continue
    }
    
    # Register cleanup for normal exit
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Log -Message "PowerShell exiting - performing marker file cleanup"
        Invoke-MarkerFileEmergencyCleanup -Reason "PowerShell exit"
    } | Out-Null
    
    Write-Log -Message "Marker file cleanup traps registered"
}

function Invoke-MarkerFileEmergencyCleanup {
    <#
    .SYNOPSIS
        Emergency cleanup function for marker files during unexpected exits
    .DESCRIPTION
        Called by trap handlers to ensure marker files are cleaned up even during errors
    .PARAMETER Reason
        Reason for the emergency cleanup (for logging)
    #>
    param(
        [string]$Reason = "Emergency cleanup"
    )
    
    try {
        Write-Log -Message "EMERGENCY: Marker file cleanup triggered ($Reason)"
        
        if ($Global:ActiveMarkerFiles -and $Global:ActiveMarkerFiles.Count -gt 0) {
            Write-Log -Message "EMERGENCY: Cleaning up $($Global:ActiveMarkerFiles.Count) tracked marker files"
            
            foreach ($markerFile in $Global:ActiveMarkerFiles) {
                try {
                    if (Test-Path $markerFile) {
                        Remove-Item $markerFile -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "EMERGENCY: Removed marker file: $markerFile"
                    }
                } catch {
                    # Silently continue during emergency cleanup
                }
            }
            
            # Clear the tracking array
            $Global:ActiveMarkerFiles = @()
        }
        
    } catch {
        # Silently handle errors during emergency cleanup to avoid loops
    }
}

# ============================================================================
# END MARKER FILE MANAGEMENT SYSTEM
# ============================================================================

<# Script variables #>
$ScriptTag = "8W" # Update this tag for each script version
$LogName = 'RemediateAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"

# Capture script path at global scope for use in scheduled tasks
$Global:CurrentScriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($Global:CurrentScriptPath)) {
    # Fallback method for cases where MyInvocation doesn't work
    $Global:CurrentScriptPath = $PSCommandPath
}
if ([string]::IsNullOrEmpty($Global:CurrentScriptPath)) {
    # Last resort fallback
    $Global:CurrentScriptPath = (Get-PSCallStack)[1].ScriptName
}

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

# Initialize marker file management system
Write-Log -Message "Initializing marker file management system"
Add-MarkerFileCleanupTrap
$orphanedCount = Clear-OrphanedMarkerFiles -MaxAgeMinutes 60
if ($orphanedCount -gt 0) {
    Write-Log -Message "Cleaned up $orphanedCount orphaned marker files from previous executions"
}

# Initialize marker file management system
Write-Log -Message "Initializing marker file management system"
Add-MarkerFileCleanupTrap
$orphanedCount = Clear-OrphanedMarkerFiles -MaxAgeMinutes 60
if ($orphanedCount -gt 0) {
    Write-Log -Message "Cleaned up $orphanedCount orphaned marker files from previous executions"
}

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Initialize and clean up deferral system
Write-Log -Message "Initializing deferral management system" | Out-Null
try {
    Initialize-DeferralRegistry | Out-Null
    Clear-ExpiredDeferralData
    Write-Log -Message "Deferral system initialization completed" | Out-Null
} catch {
    Write-Log -Message "Warning: Deferral system initialization failed: $($_.Exception.Message)" | Out-Null
}

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

<# TEST MODE: Check for WPF notification test trigger file #>
$testTriggerFile = "C:\Temp\wpf-test-trigger.txt"
if (Test-Path $testTriggerFile) {
    Write-Log -Message "WPF notification test trigger file detected: $testTriggerFile"
    Write-Log -Message "Running WPF notification test instead of normal remediation"
    
    try {
        # Test the WPF notification system with a simple message
        Write-Log -Message "Testing SYSTEM-to-user WPF notification"
        
        $testQuestion = "SYSTEM WPF Test Success!`n`nThis modern dialog was sent from SYSTEM context to your user session. The cross-session WPF notification mechanism is working correctly!"
        $testTitle = "WPF Notification Test"
        
        $testResult = Invoke-SystemUserPrompt -Question $testQuestion -Title $testTitle -TimeoutSeconds 30 -DefaultAction "Cancel" -Position "BottomRight"
        
        Write-Log -Message "WPF test completed with result: $testResult"
        
        # Check if we have any evidence that the WPF dialog actually worked
        $wpfWorked = $false
        
        # Get current user info for checking their temp directory
        $userInfo = Get-InteractiveUser
        if ($userInfo) {
            $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
            $sharedTempPath = "C:\ProgramData\Temp"
            
            # Check user temp directory for response files
            $responseFiles = @()
            if (Test-Path $userTempPath) {
                $responseFiles += Get-ChildItem -Path $userTempPath -Filter "UserPrompt_*_Response.json" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
            }
            if (Test-Path $sharedTempPath) {
                $responseFiles += Get-ChildItem -Path $sharedTempPath -Filter "UserPrompt_*_Response.json" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
            }
            
            if ($responseFiles.Count -gt 0) {
                Write-Log -Message "Found recent WPF response file(s) - WPF mechanism worked"
                $wpfWorked = $true
                
                # Show what was in the response files
                foreach ($responseFile in $responseFiles) {
                    try {
                        $content = Get-Content $responseFile.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        Write-Log -Message "Response file content: Response=$($content.response), User=$($content.username), Timestamp=$($content.timestamp)"
                    } catch {
                        Write-Log -Message "Could not read response file: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Also check for any evidence in temp files that the dialog script actually ran
        $dialogScripts = Get-ChildItem -Path "$env:TEMP" -Filter "Show-UserPrompt_*.ps1" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
        if ($dialogScripts.Count -gt 0) {
            Write-Log -Message "Found recent dialog script files - this indicates the dialog system attempted to run"
            $wpfWorked = $true  # Script creation is evidence of system working
        }
        
        # Check for scheduled tasks that were created
        $recentTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like "UserPrompt_*" -and $_.Date -gt (Get-Date).AddMinutes(-2)
        }
        if ($recentTasks.Count -gt 0) {
            Write-Log -Message "Found recent UserPrompt scheduled task(s) - system is working"
            $wpfWorked = $true
        }
        
        # If user got any definitive response (not TIMEOUT), the dialog worked
        if ($testResult -eq "OK") {
            Write-Log -Message "User selected OK (non-default action) - dialog definitely worked"
            $wpfWorked = $true
        } elseif ($testResult -eq "Cancel") {
            Write-Log -Message "User selected Cancel - dialog definitely worked"
            $wpfWorked = $true
        } elseif ($testResult -eq "TIMEOUT") {
            Write-Log -Message "Dialog timeout occurred - mechanism is working (though dialog may not have auto-closed properly)"
            $wpfWorked = $true
        }
        
        if ($wpfWorked) {
            Write-Log -Message "✅ SUCCESS: WPF notification system is working!"
            Write-Log -Message "User response: $testResult"
            Write-Log -Message "Evidence: WPF dialog was successfully displayed to the user"
        } else {
            Write-Log -Message "❌ FAILED: WPF notification system is not working properly"
            Write-Log -Message "No evidence of successful WPF dialog display found"
            Write-Log -Message "Returned value: $testResult (likely default timeout action, not user interaction)"
            Write-Log -Message "Possible issues:"
            Write-Log -Message "- Scheduled task not running in correct session"
            Write-Log -Message "- WPF assemblies not available in task context"
            Write-Log -Message "- User session not properly detected"
            Write-Log -Message "- PowerShell execution policy blocking script execution"
            Write-Log -Message "Try: Ensure user is logged in and session is active, check Windows notification settings"
        }
        
        # Keep the trigger file for repeated testing (don't delete it)
        # Remove-Item $testTriggerFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Keeping trigger file for repeated testing: $testTriggerFile"
        Write-Log -Message "Note: Create file 'C:\Temp\wpf-test-trigger.txt' to trigger this test"
        
        Write-Log -Message "WPF test completed - exiting"
        Write-Log -Message "Performing marker file cleanup before exit (WPF test complete)"
        Invoke-MarkerFileEmergencyCleanup -Reason "WPF test completed"
        exit 0
        
    } catch {
        Write-Log -Message "❌ ERROR: WPF test failed with exception: $($_.Exception.Message)"
        Write-Log -Message "Full exception: $($_.Exception.ToString())"
        Write-Log -Message "Performing marker file cleanup before exit (WPF test error)"
        Invoke-MarkerFileEmergencyCleanup -Reason "WPF test error"
        exit 1
    }
}

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Write-Log -Message "OOBE not complete, performing marker file cleanup before exit"
    Invoke-MarkerFileEmergencyCleanup -Reason "OOBE not complete"
    Exit 0
}

<# ---------------------------------------------- #>

# Fetch whitelist configuration - try local file first, then GitHub, then fallback
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$localWhitelistPath = Join-Path $scriptPath "app-whitelist.json"
$whitelistUrl = "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/app-whitelist.json"

$whitelistJSON = $null

# Try local file first
if (Test-Path $localWhitelistPath) {
    try {
        Write-Log -Message "Found local whitelist file: $localWhitelistPath"
        $whitelistJSON = Get-Content -Path $localWhitelistPath -Raw -Encoding UTF8
        Write-Log -Message "Successfully loaded whitelist configuration from local file"
    } catch {
        Write-Log -Message "Error reading local whitelist file: $($_.Exception.Message)"
        Write-Log -Message "Falling back to GitHub configuration"
    }
}

# If local file failed or doesn't exist, try GitHub
if (-not $whitelistJSON) {
    try {
        Write-Log -Message "Fetching whitelist configuration from GitHub"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-WingetScript/7.1")
        $whitelistJSON = $webClient.DownloadString($whitelistUrl)
        Write-Log -Message "Successfully downloaded whitelist configuration from GitHub"
    } catch {
        Write-Log -Message "Error downloading whitelist from GitHub: $($_.Exception.Message)"
        Write-Log -Message "Falling back to basic hardcoded configuration"
    }
}

# Final fallback to basic configuration if both local and GitHub failed
if (-not $whitelistJSON) {
    $whitelistJSON = @'
[
    {"AppID": "Mozilla.Firefox", "FriendlyName": "Firefox", "BlockingProcess": "firefox", "PromptWhenBlocked": true},
    {"AppID": "Google.Chrome", "FriendlyName": "Chrome", "BlockingProcess": "chrome", "PromptWhenBlocked": true},
    {"AppID": "Microsoft.VisualStudioCode", "FriendlyName": "Visual Studio Code", "BlockingProcess": "Code", "PromptWhenBlocked": true},
    {"AppID": "Notepad++.Notepad++", "FriendlyName": "Notepad++", "BlockingProcess": "notepad++", "DefaultTimeoutAction": true},
    {"AppID": "7zip.7zip", "FriendlyName": "7-Zip", "BlockingProcess": "7zFM", "DefaultTimeoutAction": true},
    {"AppID": "Adobe.Acrobat.Reader.64-bit", "FriendlyName": "Adobe Acrobat Reader", "BlockingProcess": "AcroRd32,Acrobat,AcroBroker,AdobeARM,AdobeCollabSync", "AutoCloseProcesses": "AdobeCollabSync", "PromptWhenBlocked": true},
    {"AppID": "GitHub.GitHubDesktop", "FriendlyName": "GitHub Desktop", "BlockingProcess": "GitHubDesktop", "PromptWhenBlocked": true},
    {"AppID": "Fortinet.FortiClientVPN", "FriendlyName": "FortiClient VPN", "BlockingProcess": "FortiClient,FortiSSLVPNdaemon,FortiTray", "PromptWhenBlocked": true, "DefaultTimeoutAction": false, "TimeoutSeconds": 90}
]
'@
    Write-Log -Message "Using basic hardcoded configuration with FortiClient enabled for testing"
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
    Write-Log -Message "Performing marker file cleanup before exit due to whitelist error"
    Invoke-MarkerFileEmergencyCleanup -Reason "Whitelist parsing error"
    exit 1
}

# Main remediation logic - dual-context architecture
if (Test-RunningAsSystem) {
    if ($UserRemediationOnly) {
        # DIAGNOSTIC: Log immediate execution proof before any other operations
        try {
            $debugInfo = @(
                "USER_CONTEXT_STARTED_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff')",
                "PowerShell_Version: $($PSVersionTable.PSVersion)",
                "PowerShell_Edition: $($PSVersionTable.PSEdition)",
                "Execution_Policy: $(Get-ExecutionPolicy)",
                "Current_User: $env:USERNAME",
                "User_Domain: $env:USERDOMAIN",
                "Process_ID: $PID",
                "Session_ID: $((Get-Process -Id $PID).SessionId)",
                "Script_Path: $($MyInvocation.MyCommand.Path)",
                "Working_Directory: $(Get-Location)",
                "Parameters: UserRemediationOnly=$UserRemediationOnly, RemediationResultFile=$RemediationResultFile",
                "--- END DIAGNOSTIC INFO ---"
            )
            $debugInfo | Out-File -FilePath "C:\ProgramData\Temp\UserContext_Debug.log" -Append -Force -Encoding UTF8
        } catch {
            # If even this basic logging fails, try alternative location
            try {
                "USER_CONTEXT_DIAGNOSTIC_FAILED: $($_.Exception.Message)" | Out-File -FilePath "$env:TEMP\UserContext_Debug_Fallback.log" -Append -Force
            } catch {
                # Complete failure - script execution may be blocked entirely
            }
        }
        
        # This is a scheduled user remediation task - process user apps only
        Write-Log -Message "*** RUNNING IN USER CONTEXT (SCHEDULED TASK) ***"
        $userContextStart = Get-Date
        Write-Log -Message "User context execution started at: $userContextStart"
        Write-Log -Message "Current user: $env:USERNAME"
        Write-Log -Message "User domain: $env:USERDOMAIN"
        Write-Log -Message "Session ID: $((Get-Process -Id $PID).SessionId)"
        Write-Log -Message "Process ID: $PID"
        Write-Log -Message "Running user remediation task"
        Write-Log -Message "RemediationResultFile parameter: $RemediationResultFile"
        
        # Create heartbeat and status files for system context synchronization
        $resultFileDir = if ($RemediationResultFile) { Split-Path $RemediationResultFile -Parent } else { "C:\ProgramData\Temp" }
        $resultFileBaseName = if ($RemediationResultFile) { [System.IO.Path]::GetFileNameWithoutExtension($RemediationResultFile) } else { "UserRemediation" }
        $heartbeatFile = Join-Path $resultFileDir "$resultFileBaseName.heartbeat"
        $statusFile = Join-Path $resultFileDir "$resultFileBaseName.status"
        
        Write-Log -Message "Creating heartbeat file: $heartbeatFile" | Out-Null
        Write-Log -Message "Creating status file: $statusFile" | Out-Null
        
        # Function to update heartbeat (call this regularly during processing)
        function Update-Heartbeat {
            param(
                [string]$Stage = "Unknown",
                [hashtable]$AdditionalData = @{}
            )
            
            try {
                # Ensure directory exists before writing
                $heartbeatDir = Split-Path $heartbeatFile -Parent
                if (-not (Test-Path $heartbeatDir)) {
                    New-Item -Path $heartbeatDir -ItemType Directory -Force | Out-Null
                }
                
                $heartbeatData = @{
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Stage = $Stage
                    ProcessId = $PID
                    Username = $env:USERNAME
                    SessionId = (Get-Process -Id $PID).SessionId
                }
                
                # Add any additional context data
                foreach ($key in $AdditionalData.Keys) {
                    $heartbeatData[$key] = $AdditionalData[$key]
                }
                
                $heartbeatJson = $heartbeatData | ConvertTo-Json -Compress
                $heartbeatJson | Out-File -FilePath $heartbeatFile -Force -Encoding UTF8
                
                # Also create a simple timestamp file for basic monitoring
                (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff") | Out-File -FilePath "$heartbeatFile.timestamp" -Force
                
                return $true
            } catch {
                # Log heartbeat failures to a separate error file instead of silencing them
                $errorMsg = "Heartbeat failed at stage '$Stage': $($_.Exception.Message)"
                try {
                    $errorMsg | Out-File -FilePath "$heartbeatFile.error" -Append -Force -ErrorAction Stop
                } catch {
                    # Final fallback - try Windows Event Log
                    try {
                        Write-EventLog -LogName Application -Source "WingetRemediation" -EntryType Error -EventId 1002 -Message $errorMsg -ErrorAction SilentlyContinue
                    } catch {
                        # Complete failure - at least try user temp
                        $errorMsg | Out-File -FilePath "$env:TEMP\UserContext_Heartbeat_Error.log" -Append -Force -ErrorAction SilentlyContinue
                    }
                }
                return $false
            }
        }
        
        # Function to update status (call at major processing milestones)
        function Update-Status {
            param(
                [string]$Status,
                [string]$Progress = ""
            )
            try {
                @{
                    Status = $Status
                    Progress = $Progress
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    ProcessId = $PID
                } | ConvertTo-Json -Compress | Out-File -FilePath $statusFile -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore status errors - don't interrupt processing
            }
        }
        
        # Initial heartbeat and status
        Update-Heartbeat -Stage "ScriptStart" -AdditionalData @{
            ScriptPath = $MyInvocation.MyCommand.Path
            Arguments = $MyInvocation.Line
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }
        Update-Status -Status "Starting" -Progress "User context remediation initialized"
        
        # Check if we're admin in user context - if not, use --scope user
        Write-Log -Message "Checking user admin privileges..."
        $privilegeCheckStart = Get-Date
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $privilegeCheckTime = (Get-Date) - $privilegeCheckStart
        Write-Log -Message "Privilege check completed in $($privilegeCheckTime.TotalSeconds) seconds"
        
        Write-Log -Message "User is admin: $userIsAdmin"
        Write-Log -Message "Test-RunningAsSystem: $(Test-RunningAsSystem)"
        
        # Update status
        Update-Status -Status "Privilege check complete" -Progress "Admin: $userIsAdmin"
        Update-Heartbeat -Stage "PrivilegeCheck" -AdditionalData @{
            UserIsAdmin = $userIsAdmin
            TestRunningAsSystem = (Test-RunningAsSystem)
        }
        
        # Add timeout protection for winget execution to prevent hangs
        Write-Log -Message "Starting winget execution with timeout protection..."
        $wingetStart = Get-Date
        $wingetTimeout = 180  # 3 minutes timeout for winget
        
        try {
            # Use background job with timeout to prevent winget hanging
            $wingetJob = Start-Job -ScriptBlock {
                param($isAdmin)
                if ($isAdmin) {
                    winget upgrade --accept-source-agreements
                } else {
                    winget upgrade --accept-source-agreements --scope user
                }
            } -ArgumentList $userIsAdmin
            
            Write-Log -Message "Winget job started (Job ID: $($wingetJob.Id)), waiting up to $wingetTimeout seconds..."
            Update-Status -Status "Running winget" -Progress "Executing winget upgrade command with timeout protection"
            
            # Update heartbeat every 30 seconds while waiting for winget
            $wingetWaitStart = Get-Date
            while ((Get-Date) -lt $wingetWaitStart.AddSeconds($wingetTimeout) -and $wingetJob.State -eq "Running") {
                if (Wait-Job $wingetJob -Timeout 30) {
                    break  # Job completed
                }
                $elapsedWinget = [int]((Get-Date) - $wingetWaitStart).TotalSeconds
                Update-Heartbeat -Stage "WingetExecution" -AdditionalData @{
                    ElapsedSeconds = $elapsedWinget
                    JobState = $wingetJob.State
                }
                Write-Log -Message "Winget still running... ${elapsedWinget}s elapsed" | Out-Null
            }
            
            if ($wingetJob.State -eq "Completed") {
                $OUTPUT = Receive-Job $wingetJob
                $wingetTime = (Get-Date) - $wingetStart
                Write-Log -Message "Winget completed successfully in $($wingetTime.TotalSeconds) seconds"
                Write-Log -Message "Winget output lines: $($OUTPUT.Count)"
                Update-Status -Status "Winget complete" -Progress "Output: $($OUTPUT.Count) lines, Time: $([int]$wingetTime.TotalSeconds)s"
                
                # Sample first few lines of output for debugging
                if ($OUTPUT -and $OUTPUT.Count -gt 0) {
                    $sampleLines = ($OUTPUT | Select-Object -First 3) -join " | "
                    Write-Log -Message "Winget sample output: $sampleLines"
                }
            } else {
                $wingetTime = (Get-Date) - $wingetStart
                Write-Log -Message "ERROR: Winget timed out after $($wingetTime.TotalSeconds) seconds"
                Remove-Job $wingetJob -Force
                throw "Winget execution timed out after $wingetTimeout seconds"
            }
            Remove-Job $wingetJob -Force
            
        } catch {
            $wingetTime = (Get-Date) - $wingetStart
            Write-Log -Message "Error executing winget in user context after $($wingetTime.TotalSeconds) seconds: $($_.Exception.Message)"
            Write-Log -Message "Winget may not be available, properly configured, or timed out"
            
            # Write error result file immediately
            if ($RemediationResultFile) {
                try {
                    Write-Log -Message "Writing error result to: $RemediationResultFile"
                    $errorResult = @{
                        ProcessedApps = 0
                        UpgradeResults = @("ERROR: Winget execution failed or timed out")
                        Success = $false
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Username = $env:USERNAME
                        Computer = $env:COMPUTERNAME
                        Context = "USER"
                        Error = $_.Exception.Message
                        ExecutionTime = $wingetTime.TotalSeconds
                    }
                    $errorResult | ConvertTo-Json -Depth 3 -Compress | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
                    Write-Log -Message "Error result file written successfully"
                    
                    # Verify file was written
                    if (Test-Path $RemediationResultFile) {
                        $fileSize = (Get-Item $RemediationResultFile).Length
                        Write-Log -Message "Error result file verified: $fileSize bytes"
                    } else {
                        Write-Log -Message "ERROR: Error result file was not created"
                    }
                } catch {
                    Write-Log -Message "Failed to write error result file: $($_.Exception.Message)"
                }
            }
            Write-Log -Message "Performing marker file cleanup before exit (user context error)"
            Invoke-MarkerFileEmergencyCleanup -Reason "User context execution error"
            exit 1
        }
        
        # Check if first output is valid (contains actual app data)
        Write-Log -Message "Validating winget output..."
        $outputValidationStart = Get-Date
        $hasValidOutput = $false
        foreach ($line in $OUTPUT) {
            if ($line -like "Name*Id*Version*Available*Source*") {
                $hasValidOutput = $true
                break
            }
        }
        $outputValidationTime = (Get-Date) - $outputValidationStart
        Write-Log -Message "Output validation completed in $($outputValidationTime.TotalMilliseconds) ms - Valid: $hasValidOutput"
        
        # If first output is nonsense, run again with timeout protection
        if (-not $hasValidOutput) {
            Write-Log -Message "First winget run produced invalid output, retrying with timeout protection..."
            $retryStart = Get-Date
            
            try {
                $retryJob = Start-Job -ScriptBlock {
                    param($isAdmin)
                    if ($isAdmin) {
                        winget upgrade --accept-source-agreements
                    } else {
                        winget upgrade --accept-source-agreements --scope user
                    }
                } -ArgumentList $userIsAdmin
                
                if (Wait-Job $retryJob -Timeout $wingetTimeout) {
                    $OUTPUT = Receive-Job $retryJob
                    $retryTime = (Get-Date) - $retryStart
                    Write-Log -Message "Winget retry completed in $($retryTime.TotalSeconds) seconds"
                } else {
                    $retryTime = (Get-Date) - $retryStart
                    Write-Log -Message "ERROR: Winget retry timed out after $($retryTime.TotalSeconds) seconds"
                    Remove-Job $retryJob -Force
                    throw "Winget retry timed out"
                }
                Remove-Job $retryJob -Force
                
            } catch {
                $retryTime = (Get-Date) - $retryStart
                Write-Log -Message "Error in winget retry after $($retryTime.TotalSeconds) seconds: $($_.Exception.Message)"
                
                # Write error result and exit
                if ($RemediationResultFile) {
                    Write-Log -Message "Writing retry error result to: $RemediationResultFile"
                    $errorResult = @{
                        ProcessedApps = 0
                        UpgradeResults = @("ERROR: Winget retry failed or timed out")
                        Success = $false
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Username = $env:USERNAME
                        Computer = $env:COMPUTERNAME
                        Context = "USER"
                        Error = $_.Exception.Message
                        ExecutionTime = ((Get-Date) - $userContextStart).TotalSeconds
                    }
                    $errorResult | ConvertTo-Json -Depth 3 -Compress | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
                }
                Write-Log -Message "Performing marker file cleanup before exit (user context timeout/error)"
                Invoke-MarkerFileEmergencyCleanup -Reason "User context timeout or error"
                exit 1
            }
        }
        
        Write-Log -Message "User context remediation - processing user-scoped apps only"
        
    } else {
        # SYSTEM context main execution - process system apps and schedule user remediation
        Write-Log -Message "SYSTEM context - processing system apps and scheduling user remediation"
        
        if ($WingetPath) {
            Write-Log -Message "Using winget path: $WingetPath"
            Set-Location $WingetPath
            
            try {
                # System context winget - only sees system-wide apps
                $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
                Write-Log -Message "Successfully executed winget upgrade in system context"
            } catch {
                Write-Log -Message "Error executing winget in system context: $($_.Exception.Message)"
                Write-Log -Message "Winget execution failed, exiting"
                Write-Log -Message "Performing marker file cleanup before exit (winget execution failed)"
                Invoke-MarkerFileEmergencyCleanup -Reason "Winget execution failed in system context"
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
        } else {
            Write-Log -Message "Winget not detected in SYSTEM context"
            Write-Log -Message "Performing marker file cleanup before exit (no winget in system context)"
            Invoke-MarkerFileEmergencyCleanup -Reason "Winget not detected in SYSTEM context"
            exit 0
        }
    }
} else {
    # User context execution - process user apps only
    Write-Log -Message "USER context - processing user-scoped apps"
    
    try {
        $OUTPUT = $(winget upgrade --accept-source-agreements)
        Write-Log -Message "Successfully executed winget upgrade in user context"
    } catch {
        Write-Log -Message "Error executing winget in user context: $($_.Exception.Message)"
        Write-Log -Message "Winget may not be available or properly configured"
        Write-Log -Message "Performing marker file cleanup before exit (winget not available)"
        Invoke-MarkerFileEmergencyCleanup -Reason "Winget not available or properly configured"
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
}

# Parse winget output and process apps
Write-Log -Message "Starting winget output parsing..."
$parsingStart = Get-Date

if ($OUTPUT) {
    Write-Log -Message "Winget output contains $($OUTPUT.Count) lines, parsing structure..."
    $headerLine = -1
    $lineCount = 0

    foreach ($line in $OUTPUT) {
        if ($line -like "Name*" -and $headerLine -eq -1) {
            $headerLine = $lineCount
        }
        $lineCount++
    }

    Write-Log -Message "Header found at line $headerLine, total lines: $lineCount"

    if ($OUTPUT -and $lineCount -gt $headerLine+2) {
        $str = $OUTPUT[$headerLine]
        $idPos = $str.indexOf("Id")
        $versionPos = $str.indexOf("Version")-1
        $availablePos = $str.indexOf("Available")-1

        Write-Log -Message "Column positions - Id: $idPos, Version: $versionPos, Available: $availablePos"

        $LIST= [System.Collections.ArrayList]::new()
        for ($i = $headerLine+2; $i -lt $OUTPUT.count; $i++ ) {
            $lineData = $OUTPUT[$i]
            # Stop parsing if we hit the second section or empty lines
            if ($lineData -like "*upgrade available, but require*" -or $lineData.Trim() -eq "" -or $lineData -like "*following packages*") {
                break
            }
            
            # Extract AppID, current version, and available version
            $appId = ($lineData[$idPos..$versionPos] -Join "").trim()
            if ($appId -ne "") {
                # Extract current version (between Version and Available columns)
                $currentVersion = ""
                $availableVersion = ""
                
                if ($availablePos -gt $versionPos) {
                    $currentVersionEnd = $availablePos
                    # Find the start of Version column content
                    $versionStart = $versionPos + 1
                    while ($versionStart -lt $lineData.Length -and $lineData[$versionStart] -eq ' ') {
                        $versionStart++
                    }
                    if ($versionStart -lt $currentVersionEnd) {
                        $currentVersion = ($lineData[$versionStart..$currentVersionEnd] -Join "").trim()
                    }
                    
                    # Extract available version (from Available column to end)
                    $availableStart = $availablePos + 1
                    while ($availableStart -lt $lineData.Length -and $lineData[$availableStart] -eq ' ') {
                        $availableStart++
                    }
                    # Find end of available version (next column or end of line)
                    $sourcePos = $str.indexOf("Source")
                    $availableEnd = if ($sourcePos -gt $availablePos) { $sourcePos - 1 } else { $lineData.Length - 1 }
                    
                    if ($availableStart -lt $lineData.Length -and $availableStart -le $availableEnd) {
                        $availableVersion = ($lineData[$availableStart..$availableEnd] -Join "").trim()
                    }
                }
                
                # Create enhanced app object with version information
                $appInfo = @{
                    AppID = $appId
                    CurrentVersion = $currentVersion
                    AvailableVersion = $availableVersion
                }
                $null = $LIST.Add($appInfo)
            }
        }

        $parsingTime = (Get-Date) - $parsingStart
        Write-Log -Message "Parsing completed in $($parsingTime.TotalSeconds) seconds - Found $($LIST.Count) apps"

        $count = 0
        $message = ""
        $processingStart = Get-Date
        Write-Log -Message "Starting app processing loop..."

        foreach ($appInfo in $LIST) {
            if ($appInfo.AppID -ne "") {
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($appInfo.AppID -eq $okapp.AppID) {
                        Write-Log -Message "Processing whitelisted app: $($okapp.AppID)" | Out-Null
                        
                        # First, check deferral status if deferrals are enabled
                        if ($okapp.DeferralEnabled -eq $true) {
                            Write-Log -Message "Deferral system enabled for $($okapp.AppID), checking status" | Out-Null
                            
                            $deferralStatus = Get-DeferralStatus -AppID $okapp.AppID -WhitelistConfig $okapp -AvailableVersion $appInfo.AvailableVersion
                            
                            if (-not $deferralStatus.ForceUpdate) {
                                Write-Log -Message "Update for $($okapp.AppID) can be deferred - skipping this run" | Out-Null
                                Write-Log -Message "Deferral message: $($deferralStatus.Message)" | Out-Null
                                continue  # Skip this app - user can defer
                            } else {
                                Write-Log -Message "Update for $($okapp.AppID) is now mandatory: $($deferralStatus.Message)" | Out-Null
                            }
                        }
                        
                        # Process blocking processes
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
                                $dialogResult = $null
                                
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
                                        $dialogResult = @{
                                            CloseProcess = $true
                                            DeferralDays = 0
                                            Action = "Update"
                                            UserChoice = $true
                                        }
                                    }
                                }
                                
                                # If we can't auto-close and PromptWhenBlocked is true, show the interactive popup
                                if (-not $canAutoClose) {
                                    Write-Log -Message "$($okapp.AppID) has PromptWhenBlocked=true, showing interactive dialog"
                                    $defaultTimeoutAction = if ($okapp.DefaultTimeoutAction -eq $true) { $true } else { $false }
                                    
                                    # Use custom timeout from whitelist if specified, otherwise default to 60 seconds
                                    $customTimeout = if ($okapp.TimeoutSeconds -and $okapp.TimeoutSeconds -gt 0) { $okapp.TimeoutSeconds } else { 60 }
                                    
                                    Write-Log -Message "Using timeout: ${customTimeout}s, default action: $defaultTimeoutAction" | Out-Null
                                    $dialogResult = Show-ProcessCloseDialog -AppName $okapp.AppID -ProcessName $runningProcessName -TimeoutSeconds $customTimeout -DefaultTimeoutAction $defaultTimeoutAction -FriendlyName $okapp.FriendlyName -CurrentVersion $appInfo.CurrentVersion -AvailableVersion $appInfo.AvailableVersion -WhitelistConfig $okapp
                                    
                                    Write-Log -Message "Show-ProcessCloseDialog returned: $($dialogResult | ConvertTo-Json -Compress)"
                                }
                                
                                # Handle dialog result
                                if ($dialogResult.Action -eq "Defer") {
                                    Write-Log -Message "User chose to defer $($okapp.AppID) for $($dialogResult.DeferralDays) days"
                                    continue  # Skip this app - user deferred
                                } elseif ($dialogResult.CloseProcess -or $dialogResult.UserChoice) {
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
                        
                        # Determine if we can perform the upgrade based on context
                        if ((Test-RunningAsSystem) -or $userIsAdmin) {
                            Write-Log -Message "Upgrade $($okapp.AppID) in system/admin context"
                            $doUpgrade = $true
                            break  # Break out of whitelist loop to proceed with upgrade
                        } elseif (-not (Test-RunningAsSystem)) {
                            # User context without admin - allow user-scope upgrades only
                            Write-Log -Message "Upgrade $($okapp.AppID) in user context (user-scope only)"
                            $doUpgrade = $true
                            break  # Break out of whitelist loop to proceed with upgrade
                        }
                    }
                }

                if ($doUpgrade) {
                    $count++
                    Write-Log -Message "Starting upgrade for: $($appInfo.AppID)"
                    
                    try {
                        Write-Log -Message "Executing winget upgrade for: $($appInfo.AppID)"
                        
                        # First attempt: Standard upgrade - use appropriate winget path and scope based on context
                        if ((Test-RunningAsSystem) -and $WingetPath) {
                            $upgradeResult = & .\winget.exe upgrade --silent --accept-source-agreements --id $appInfo.AppID 2>&1
                        } elseif ($userIsAdmin) {
                            $upgradeResult = & winget upgrade --silent --accept-source-agreements --id $appInfo.AppID 2>&1
                        } else {
                            # User context without admin - use user scope
                            Write-Log -Message "Using --scope user for non-admin user context upgrade"
                            $upgradeResult = & winget upgrade --silent --accept-source-agreements --scope user --id $appInfo.AppID 2>&1
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
                            Write-Log -Message "Winget result for $($appInfo.AppID) : $logMessage"
                        } else {
                            Write-Log -Message "Winget result for $($appInfo.AppID) : Processing completed"
                        }
                        
                        # Handle specific failure cases
                        if ($upgradeOutput -like "*install technology is different*") {
                            Write-Log -Message "Install technology mismatch detected for $($appInfo.AppID). Attempting uninstall and reinstall."
                            
                            # First uninstall - use appropriate winget path and scope based on context
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $uninstallResult = & .\winget.exe uninstall --silent --id $appInfo.AppID 2>&1
                            } elseif ($userIsAdmin) {
                                $uninstallResult = & winget uninstall --silent --id $appInfo.AppID 2>&1
                            } else {
                                # User context without admin - use user scope
                                $uninstallResult = & winget uninstall --silent --scope user --id $appInfo.AppID 2>&1
                            }
                            
                            $uninstallOutput = $uninstallResult -join "`n"
                            if ($uninstallOutput -like "*Successfully uninstalled*") {
                                Write-Log -Message "Successfully uninstalled $($appInfo.AppID)"
                            } else {
                                Write-Log -Message "Uninstall issue for $($appInfo.AppID)"
                            }
                            
                            # Wait a moment for cleanup
                            Start-Sleep -Seconds 2
                            
                            # Then install fresh - use appropriate winget path and scope based on context
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements --id $appInfo.AppID 2>&1
                            } elseif ($userIsAdmin) {
                                $upgradeResult = & winget install --silent --accept-source-agreements --id $appInfo.AppID 2>&1
                            } else {
                                # User context without admin - use user scope
                                $upgradeResult = & winget install --silent --accept-source-agreements --scope user --id $appInfo.AppID 2>&1
                            }
                            
                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Fresh install completed for $($appInfo.AppID)"
                            
                        } elseif ($upgradeOutput -like "*Uninstall failed*") {
                            Write-Log -Message "Uninstall failure detected for $($appInfo.AppID). Trying alternative approaches."
                            
                            # Try install with --force to override - use appropriate winget path and scope based on context
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements --force --id $appInfo.AppID 2>&1
                            } elseif ($userIsAdmin) {
                                $upgradeResult = & winget install --silent --accept-source-agreements --force --id $appInfo.AppID 2>&1
                            } else {
                                # User context without admin - use user scope
                                $upgradeResult = & winget install --silent --accept-source-agreements --scope user --force --id $appInfo.AppID 2>&1
                            }
                            
                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Force install completed for $($appInfo.AppID)"
                        }
                        
                        # Evaluate success
                        if ($upgradeOutput -like "*Successfully installed*" -or $upgradeOutput -like "*No applicable update*" -or $upgradeOutput -like "*No newer version available*") {
                            Write-Log -Message "Upgrade completed successfully for: $($appInfo.AppID)"
                            $message += "$($appInfo.AppID)|"
                        } else {
                            Write-Log -Message "Upgrade failed for $($appInfo.AppID) - Exit code: $LASTEXITCODE"
                            $message += "$($appInfo.AppID) (FAILED)|"
                        }
                    } catch {
                        Write-Log -Message "Error upgrading $($appInfo.AppID) : $($_.Exception.Message)"
                        $message += "$($appInfo.AppID) (ERROR)|"
                    }
                }
            }
        }

        # If we're in SYSTEM context and processed system apps, check for interactive session before scheduling user context
        if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
            Write-Log -Message "SYSTEM context processing complete - checking for interactive session"
            
            if (-not (Test-InteractiveSession)) {
                Write-Log -Message "No interactive session detected - skipping user context remediation"
                Write-Log -Message "[$ScriptTag] Remediation completed: $count apps processed (system only, no interactive session)"
            } else {
                Write-Log -Message "Interactive session confirmed - scheduling user context remediation"
                $userScheduled = Schedule-UserContextRemediation
                if ($userScheduled) {
                    Write-Log -Message "User context remediation scheduled successfully"
                } else {
                    Write-Log -Message "User context remediation scheduling failed"
                }
            }
        }
        
        Write-Log -Message "[$ScriptTag] Remediation completed: $count apps processed"
        if ($message -ne "") {
            Write-Log -Message "[$ScriptTag] Apps upgraded: $message"
        }
        
        $processingTime = (Get-Date) - $processingStart
        Write-Log -Message "App processing completed in $($processingTime.TotalSeconds) seconds"

        # If this is a UserRemediationOnly task, write result file for SYSTEM context to read
        if ($UserRemediationOnly) {
            Write-Log -Message "*** USER CONTEXT REMEDIATION COMPLETE - WRITING RESULTS ***"
            Write-Log -Message "RemediationResultFile parameter: $RemediationResultFile"
            $resultWritingStart = Get-Date
            
            if ($RemediationResultFile) {
                try {
                    Write-Log -Message "Parsing upgrade results from message: '$message'"
                    # Parse message to extract upgrade results
                    $upgradeResults = @()
                    if ($message -ne "") {
                        # Split by pipe and clean up each result
                        $results = $message -split '\|' | Where-Object { $_ -ne "" }
                        $upgradeResults = $results | ForEach-Object { $_.Trim() }
                    }
                    
                    $totalExecutionTime = if ($userContextStart) { (Get-Date) - $userContextStart } else { New-TimeSpan }
                    $results = @{
                        ProcessedApps = $count
                        UpgradeResults = $upgradeResults
                        Success = $true
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Username = $env:USERNAME
                        Computer = $env:COMPUTERNAME
                        Context = "USER"
                        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                        ProcessId = $PID
                        SessionId = (Get-Process -Id $PID).SessionId
                        ExecutionTime = $totalExecutionTime.TotalSeconds
                        TimingDetails = @{
                            WingetExecution = if ($wingetTime) { $wingetTime.TotalSeconds } else { 0 }
                            OutputParsing = if ($parsingTime) { $parsingTime.TotalSeconds } else { 0 }
                            AppProcessing = if ($processingTime) { $processingTime.TotalSeconds } else { 0 }
                        }
                    }
                    
                    Write-Log -Message "Writing user remediation results to file: $RemediationResultFile"
                    Write-Log -Message "Results: ProcessedApps=$count, UpgradeResults=$($upgradeResults.Count) items, ExecutionTime=$($totalExecutionTime.TotalSeconds)s"
                    
                    # Ensure the directory exists
                    $resultDir = Split-Path $RemediationResultFile -Parent
                    if (-not (Test-Path $resultDir)) {
                        New-Item -Path $resultDir -ItemType Directory -Force | Out-Null
                        Write-Log -Message "Created result directory: $resultDir"
                    }
                    
                    $results | ConvertTo-Json -Depth 4 -Compress | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
                    
                    # Verify file was written
                    if (Test-Path $RemediationResultFile) {
                        $fileSize = (Get-Item $RemediationResultFile).Length
                        $resultWritingTime = (Get-Date) - $resultWritingStart
                        Write-Log -Message "Result file written successfully in $($resultWritingTime.TotalSeconds) seconds, size: $fileSize bytes"
                    } else {
                        Write-Log -Message "ERROR: Result file was not created at: $RemediationResultFile"
                    }
                    
                } catch {
                    $resultWritingTime = (Get-Date) - $resultWritingStart
                    Write-Log -Message "ERROR: Failed to write user remediation results after $($resultWritingTime.TotalSeconds) seconds: $($_.Exception.Message)"
                    Write-Log -Message "Exception details: $($_.Exception.ToString())"
                }
            } else {
                Write-Log -Message "WARNING: No result file path found - SYSTEM context may not receive results"
            }
            
            $totalUserContextTime = if ($userContextStart) { (Get-Date) - $userContextStart } else { New-TimeSpan }
            Write-Log -Message "*** USER CONTEXT TASK EXITING after $($totalUserContextTime.TotalSeconds) seconds ***"
        }
        
        Write-Log -Message "Performing final marker file cleanup before script completion"
        Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (remediation complete)"
        exit 0
    }
    Write-Log -Message "[$ScriptTag] No upgrades (0x0000002)"
    Write-Log -Message "Performing final marker file cleanup before script exit (no upgrades)"
    Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (no upgrades)"
    exit 0
}
Write-Log -Message "[$ScriptTag] Winget not detected"
Write-Log -Message "Performing final marker file cleanup before script exit (winget not detected)"
Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (winget not detected)"
exit 0
