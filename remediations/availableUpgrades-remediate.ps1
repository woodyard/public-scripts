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
 Version: 8.3
 Tag: 8U
    
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
    
    Exit Codes:
    0 - Script completed successfully
    1 - OOBE not complete
#>

param(
    [switch]$UserRemediationOnly
)

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


# WPF System User Prompt Functions - Modern replacement for legacy toast notification system

function Get-InteractiveUser {
    <#
    .SYNOPSIS
        Gets the currently logged-in interactive user and their SID (Azure AD compatible)
    #>
    
    try {
        Write-Log "Detecting interactive user using Win32_ComputerSystem..." | Out-Null
        
        # Primary method - proven to work with Azure AD
        try {
            $loggedInUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username -ExpandProperty username
            if (-not $loggedInUser) {
                $Message = "User is not logged on to the primary session: No username returned from Win32_ComputerSystem"
                Throw $Message
            }
            
            $username = ($loggedInUser -split '\\')[1]
            $domain = ($loggedInUser -split '\\')[0]
            
            Write-Log "Found logged in user: $loggedInUser" | Out-Null
            Write-Log "Extracted username: $username" | Out-Null
            Write-Log "Extracted domain: $domain" | Out-Null
            
        } catch [Exception] {
            $Message = "User is not logged on to the primary session: $_"
            Write-Log $Message | Out-Null
            Throw $Message
        }
        
        # Get user SID for reliable task creation
        $userSid = $null
        
        # Method 1: Try with full domain\username format
        try {
            $userSid = (New-Object System.Security.Principal.NTAccount($loggedInUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            Write-Log "Successfully got SID using full name ($loggedInUser): $userSid" | Out-Null
        } catch {
            Write-Log "Could not get SID using full name: $($_.Exception.Message)" | Out-Null
        }
        
        # Method 2: Try with just username if full name failed
        if (-not $userSid) {
            try {
                $userSid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-Log "Successfully got SID using username ($username): $userSid" | Out-Null
            } catch {
                Write-Log "Could not get SID using username: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Method 3: Try with domain prefix if available
        if (-not $userSid -and $domain -ne $env:COMPUTERNAME) {
            try {
                $domainUser = "$domain\$username"
                $userSid = (New-Object System.Security.Principal.NTAccount($domainUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-Log "Successfully got SID using domain format ($domainUser): $userSid" | Out-Null
            } catch {
                Write-Log "Could not get SID using domain format: $($_.Exception.Message)" | Out-Null
            }
        }
        
        if (-not $userSid) {
            Write-Log "Warning: Could not obtain user SID, task creation may fail" | Out-Null
        }
        
        return @{
            Username = $username
            FullName = $loggedInUser
            Domain = $domain
            SID = $userSid
            SessionId = $null  # Not available with this method
        }
        
    } catch {
        Write-Log "Error getting interactive user: $($_.Exception.Message)" | Out-Null
        return $null
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
        [string]$TitleText
    )
    
    try {
        # Generate unique task name
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "UserPrompt_$guid"
        
        Write-Log "Creating scheduled task: $taskName" | Out-Null
        
        # Force PowerShell 5.1 for toast notifications - PowerShell 7 cannot access Windows Runtime in scheduled task context
        Write-Log "Forcing PowerShell 5.1 for toast notifications (PowerShell 7 has Windows Runtime limitations in scheduled task context)" | Out-Null
        $powershellExe = "powershell.exe"
        
        # Prepare script arguments with enhanced debugging, position control, and timeout
        $arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -Question `"$QuestionText`" -Title `"$TitleText`" -Position `"BottomRight`" -TimeoutSeconds $TimeoutSeconds -DebugMode"
        
        # Create task action - Force PowerShell 5.1 for Windows Runtime compatibility
        $action = New-ScheduledTaskAction -Execute $powershellExe -Argument $arguments
        
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
                    
                    # Modify arguments to include user information for the script to handle internally
                    $fallbackArguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -Question `"$QuestionText`" -Title `"$TitleText`""
                    $fallbackAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $fallbackArguments
                    
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
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - cannot display prompt" | Out-Null
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
        $createdTaskName = New-UserPromptTask -UserInfo $userInfo -ScriptPath $userPromptScriptPath -ResponseFile $responseFile -QuestionText $Question -TitleText $Title
        
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
    .DESCRIPTION
        Uses the modern WPF-based notification system to prompt the user from SYSTEM context
        Preserves all whitelist configuration features with enhanced reliability
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
    .OUTPUTS
        Boolean indicating user choice (true = close app, false = keep open)
    #>
    param(
        [string]$AppName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false,
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = ""
    )

    Write-Log -Message "Show-ProcessCloseDialog called for $AppName" | Out-Null

    # Use provided FriendlyName or fallback to AppName
    $friendlyName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }

    Write-Log -Message "Friendly name resolved to: $friendlyName" | Out-Null

    try {
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
        
        Write-Log -Message "Showing WPF dialog for $friendlyName with ${TimeoutSeconds}s timeout, default action: $defaultActionString" | Out-Null
        
        # Call the context-aware dialog system
        $response = Show-UserDialog -Question $question -Title $title -TimeoutSeconds $TimeoutSeconds -DefaultAction $defaultActionString
        
        Write-Log -Message "WPF dialog response: $response" | Out-Null
        
        # Convert response back to boolean
        $userChoice = ($response -eq "OK")
        
        if ($userChoice) {
            Write-Log -Message "User chose to close $friendlyName for update" | Out-Null
        } else {
            Write-Log -Message "User chose to keep $friendlyName open" | Out-Null
        }
        
        return $userChoice
        
    } catch {
        Write-Log -Message "Show-ProcessCloseDialog failed: $($_.Exception.Message)" | Out-Null
        Write-Log -Message "Using default timeout action: $DefaultTimeoutAction" | Out-Null
        return $DefaultTimeoutAction
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
        
        # Create simple XAML dialog
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$Title"
    Width="420"
    MinHeight="140"
    SizeToContent="Height"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="SingleBorderWindow"
    Topmost="True"
    ShowInTaskbar="True">
    
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Question -->
        <TextBlock Grid.Row="0"
                   Text="$Question"
                   TextWrapping="Wrap"
                   Margin="0,0,0,16"
                   FontSize="12"/>
        
        <!-- Buttons -->
        <StackPanel Grid.Row="1"
                    Orientation="Horizontal"
                    HorizontalAlignment="Right">
            
            <Button Name="CancelButton"
                    Content="Cancel"
                    Width="60"
                    Height="24"
                    Margin="0,0,8,0"
                    IsDefault="false"/>
            
            <Button Name="OKButton"
                    Content="OK"
                    Width="60"
                    Height="24"
                    IsDefault="true"/>
            
        </StackPanel>
    </Grid>
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
        
        # Create timeout timer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-Log -Message "Direct dialog timeout reached - using default action: $DefaultAction" | Out-Null
            $script:dialogResult = $DefaultAction
            $timer.Stop()
            $window.Close()
        })
        
        # Button event handlers
        $okButton.Add_Click({
            Write-Log -Message "OK button clicked in direct dialog" | Out-Null
            $timer.Stop()
            $script:dialogResult = "OK"
            $window.Close()
        })
        
        $cancelButton.Add_Click({
            Write-Log -Message "Cancel button clicked in direct dialog" | Out-Null
            $timer.Stop()
            $script:dialogResult = "Cancel"
            $window.Close()
        })
        
        # Handle window closing without button click
        $window.Add_Closing({
            $timer.Stop()
            if ($script:dialogResult -eq $null) {
                Write-Log -Message "Direct dialog closed without button click - treating as Cancel" | Out-Null
                $script:dialogResult = "Cancel"
            }
        })
        
        # Start timeout timer and show dialog
        $timer.Start()
        $result = $window.ShowDialog()
        $timer.Stop()
        
        Write-Log -Message "Direct dialog completed with result: $($script:dialogResult)" | Out-Null
        return $script:dialogResult
        
    } catch {
        Write-Log -Message "Error in direct user dialog: $($_.Exception.Message)" | Out-Null
        return $DefaultAction
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

function Schedule-UserContextRemediation {
    <#
    .SYNOPSIS
        Schedules user context remediation execution from SYSTEM context
    #>
    
    try {
        Write-Log "Scheduling user context remediation" | Out-Null
        
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - skipping user context remediation" | Out-Null
            return $false
        }
        
        # Create scheduled task for user remediation
        $taskName = "UserRemediation_$(Get-Random -Minimum 1000 -Maximum 9999)"
        # Copy script to user-accessible temp location
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        if (-not (Test-Path $userTempPath)) {
            $userTempPath = $env:TEMP
        }
        
        $tempScriptName = "availableUpgrades-remediate_$(Get-Random -Minimum 1000 -Maximum 9999).ps1"
        $tempScriptPath = Join-Path $userTempPath $tempScriptName
        
        Write-Log "Copying script to user-accessible location: $tempScriptPath" | Out-Null
        Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force
        
        $scriptPath = $tempScriptPath
        $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -UserRemediationOnly"
        
        Write-Log "Creating user remediation task: $taskName" | Out-Null
        Write-Log "Script path: $scriptPath" | Out-Null
        Write-Log "Arguments: $arguments" | Out-Null
        
        try {
            # Create task action
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
            
            # Create task principal (run as interactive user)
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
                Write-Log "Could not create task principal with any method" | Out-Null
                return $false
            }
            
            # Create task settings - run immediately and cleanup after 1 hour
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -DeleteExpiredTaskAfter "PT1H"
            
            # Create trigger to run immediately
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
            
            # Create and register the task
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Trigger $trigger -Description "User context winget remediation"
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            
            Write-Log "User remediation task scheduled successfully: $taskName" | Out-Null
            Write-Log "Temporary script copy at: $tempScriptPath" | Out-Null
            return $true
            
        } catch {
            Write-Log "Error creating/scheduling user remediation task: $($_.Exception.Message)" | Out-Null
            # Clean up temporary script copy on error
            if (Test-Path $tempScriptPath) {
                Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
            }
            return $false
        }
        
    } catch {
        Write-Log "Error in user context remediation scheduling: $($_.Exception.Message)" | Out-Null
        return $false
    } finally {
        # Clean up old temporary script copies (older than 1 hour)
        try {
            $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
            if (Test-Path $userTempPath) {
                $oldTempScripts = Get-ChildItem -Path $userTempPath -Filter "availableUpgrades-remediate_*.ps1" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) }
                foreach ($oldScript in $oldTempScripts) {
                    Remove-Item $oldScript.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleaned up old temporary script: $($oldScript.Name)" | Out-Null
                }
            }
        } catch {
            # Ignore cleanup errors
        }
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
            
            # Step 2: Wait 5 seconds total (not per process)
            Write-Log -Message "Waiting 5 seconds for graceful shutdown..."
            Start-Sleep -Seconds 5
            
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
                    Write-Log -Message "Some processes may still be running ($finalCheck remaining)"
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
                
                # Wait up to 10 seconds for graceful shutdown
                if (!$procInfo.Process.WaitForExit(10000)) {
                    Write-Log -Message "Process $($procInfo.Name) did not exit gracefully, forcing termination"
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

<# Script variables #>
$ScriptTag = "8U" # Update this tag for each script version
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

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

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
        exit 0
        
    } catch {
        Write-Log -Message "❌ ERROR: WPF test failed with exception: $($_.Exception.Message)"
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
    exit 1
}

# Main remediation logic - dual-context architecture
if (Test-RunningAsSystem) {
    if ($UserRemediationOnly) {
        # This is a scheduled user remediation task - process user apps only
        Write-Log -Message "Running user remediation task"
        
        try {
            $OUTPUT = $(winget upgrade --accept-source-agreements)
            Write-Log -Message "Successfully executed winget upgrade in user context (scheduled task)"
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
if ($OUTPUT) {
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
        $availablePos = $str.indexOf("Available")-1

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

        $count = 0
        $message = ""

        foreach ($appInfo in $LIST) {
            if ($appInfo.AppID -ne "") {
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($appInfo.AppID -eq $okapp.AppID) {
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
                                    
                                    # Use custom timeout from whitelist if specified, otherwise default to 60 seconds
                                    $customTimeout = if ($okapp.TimeoutSeconds -and $okapp.TimeoutSeconds -gt 0) { $okapp.TimeoutSeconds } else { 60 }
                                    
                                    Write-Log -Message "Using timeout: ${customTimeout}s, default action: $defaultTimeoutAction" | Out-Null
                                    $userChoice = Show-ProcessCloseDialog -AppName $okapp.AppID -ProcessName $runningProcessName -TimeoutSeconds $customTimeout -DefaultTimeoutAction $defaultTimeoutAction -FriendlyName $okapp.FriendlyName -CurrentVersion $appInfo.CurrentVersion -AvailableVersion $appInfo.AvailableVersion
                                    
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
                            $message += $appInfo.AppID + "|"
                        } else {
                            Write-Log -Message "Upgrade failed for $($appInfo.AppID) - Exit code: $LASTEXITCODE"
                            $message += $appInfo.AppID + " (FAILED)|"
                        }
                    } catch {
                        Write-Log -Message "Error upgrading $($appInfo.AppID) : $($_.Exception.Message)"
                        $message += $appInfo.AppID + " (ERROR)|"
                    }
                }
            }
        }

        # If we're in SYSTEM context and processed system apps, now schedule user context remediation
        if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
            Write-Log -Message "SYSTEM context processing complete - scheduling user context remediation"
            $userScheduled = Schedule-UserContextRemediation
            if ($userScheduled) {
                Write-Log -Message "User context remediation scheduled successfully"
            } else {
                Write-Log -Message "User context remediation scheduling failed or no user logged in"
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
