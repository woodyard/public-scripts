<#
.SYNOPSIS
    Winget Application Update Detection Script

.DESCRIPTION
    This script detects available application updates using winget and reports them to Intune.
    It supports both system and user context applications using a dual-context architecture.
    The script is designed to work as a detection script in Microsoft Intune remediation policies.

.PARAMETER UserDetectionOnly
    When set to "true", the script runs in user detection mode (scheduled task execution)

.PARAMETER DetectionResultFile
    Path to write user detection results (used by scheduled task)

.PARAMETER Debug
    When set to "true", enables debug logging output

.NOTES
    Author: Henrik Skovgaard
    Version: 5.24
    Tag: 5B
    
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
    4.1 - Updated to work with new Toast notification remediation system (Version 6.0/9R), enhanced app configuration with TimeoutSeconds and DefaultTimeoutAction support
    4.2 - Added local whitelist file support with intelligent fallback system (local file > GitHub > hardcoded)
    4.3 - Fixed critical whitelist loop logic bug: changed 'continue' to 'break' after app match (synchronize with remediation script fix)
    5.1 - CRITICAL UPDATE: Added --scope user support for non-privileged user context detection, allowing proper detection of user-scoped applications without admin rights; Removed legacy toast test trigger code
    5.2 - Enhanced logging: Added detailed user context execution logging to verify dual-context architecture is working properly; Fixed PowerShell syntax errors with Test-RunningAsSystem function calls
    5.3 - CRITICAL FIX: Fixed empty script path issue in scheduled tasks by capturing $MyInvocation.MyCommand.Path at global scope with multiple fallback methods
    5.4 - SECURITY IMPROVEMENT: Scripts now copy themselves to user-accessible temp locations before scheduling tasks, improving security and access control with automatic cleanup
    5.5 - BUG FIX: Fixed logging output contamination in Invoke-UserContextDetection function that was causing log messages to appear as detected app names instead of actual application IDs
    5.6 - DEBUG: Added comprehensive debugging to diagnose app detection issues
    5.7 - CRITICAL FIX: Fixed inter-context communication by using shared temp location (C:\ProgramData) accessible to both SYSTEM and user contexts, resolving file permission issues that prevented user detection results from being transferred back
    5.8 - ALIGNMENT FIX: Aligned detection result file paths with proven dialog system locations (C:\Users\{user}\AppData\Local\Temp primary, C:\ProgramData\Temp fallback) for consistent cross-context communication
    5.9 - FINAL FIX: Suppressed remaining debug logging output that was contaminating user context app detection results
    5.10 - ENHANCED DEBUG: Added comprehensive scheduled task monitoring and user context execution debugging to diagnose why user detection shows 0 apps despite manual detection finding 3 apps
    5.11 - BREAKTHROUGH: Fixed PowerShell compatibility issue with DeleteExpiredTaskAfter parameter (ISO 8601 string to TimeSpan object) and suppressed error debug contamination - DUAL-CONTEXT ARCHITECTURE NOW FULLY WORKING
    5.12 - CRITICAL FIX: Added required trigger to scheduled task creation to resolve XML validation error "The task XML is missing a required element or attribute. (44,4):EndBoundary:" - scheduled tasks must have triggers for valid XML
    5.13 - ENHANCED TASK CREATION: Removed problematic DeleteExpiredTaskAfter parameter and implemented dual creation strategy (New-ScheduledTask + Register-ScheduledTask with fallback to direct Register-ScheduledTask) for maximum compatibility
    5.14 - CRITICAL FIX: Aligned task creation with proven dialog system approach - create tasks WITHOUT triggers and manually start them, eliminating XML validation errors that prevented scheduled task creation
    5.15 - ENHANCED DEBUG: Added comprehensive scheduled task execution debugging, timeout handling, and direct winget --scope user testing to diagnose user context detection issues
    5.16 - NODE.JS DEBUGGING: Added specific Node.js (OpenJS.NodeJS) detection debugging to verify dual-context architecture handles user-scoped applications correctly
    5.17 - FUNCTION HANG DEBUG: Enhanced Invoke-UserContextDetection function debugging to identify where execution hangs by removing Out-Null suppressions
    5.18 - CRITICAL FIX: Resolved logging contamination bug - restored Out-Null suppressions in Invoke-UserContextDetection to prevent debug messages from being returned as app names (function was working but returning log messages instead of real apps)
    5.19 - PERFORMANCE OPTIMIZATION: Detection script now exits immediately with code 1 when system apps are found, skipping expensive user context detection for faster execution
    5.20 - CRITICAL FIX: Fixed user context communication timeout - JSON result file now ALWAYS written regardless of app count, preventing 30-second timeout when no user apps found
    5.21 - CRITICAL FIX: Fixed parameter detection logic - moved UserDetectionOnly check outside Test-RunningAsSystem condition and changed switch parameters to int parameters for reliable scheduled task parameter passing, ensuring JSON file creation
    5.22 - CRITICAL FIX: Implemented marker file workaround for scheduled task parameter passing issues - uses file-based communication to ensure user detection tasks always execute correct code path and create JSON result files
    5.23 - ENHANCEMENT: Implemented comprehensive marker file management system with centralized cleanup functions, orphaned file detection, and emergency cleanup handlers to prevent accumulation of .userdetection files; Added hidden console window execution method using cmd.exe with /min flag to eliminate visible console windows during scheduled task execution
    5.24 - PERFORMANCE OPTIMIZATION: Implemented user info caching to eliminate redundant WMI calls, enhanced scheduled task execution with -NoProfile flag for better reliability, eliminated double marker file initialization
    
    Exit Codes:
    0 - No upgrades available, script completed successfully, or OOBE not complete
    1 - Upgrades available (triggers remediation)
#>

param(
    [string]$UserDetectionOnly = "",
    [string]$DetectionResultFile,
    [string]$Debug = ""
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match 'S-1-5-18')
	}
}
function Write-Log($message, [switch]$IsDebug) #Log script messages to temp directory
{
    # Skip debug messages if Debug parameter is not set
    if ($IsDebug -and $Debug -ne "true") {
        return
    }
    
    $LogMessage = ((Get-Date -Format "dd.MM.yyyy HH:mm:ss ") + $message)
    # Extract ScriptTag from message if present, or use global variable
    if ($message -match '^\[([A-Z0-9]+)\]\s*(.*)') {
        $tag = $matches[1]
        $cleanMessage = $matches[2]
        $ConsoleMessage = "[$tag] " + (Get-Date -Format "HH:mm:ss ") + $cleanMessage
    } else {
        $ConsoleMessage = "[$ScriptTag] " + (Get-Date -Format "HH:mm:ss ") + $message
    }
    # Output to console (but prevent pipeline contamination in functions)
    Write-Host $ConsoleMessage
	# Log to file
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
        Write-Log -Message "Creating marker file: $FilePath ($Description)" -IsDebug
        
        # Ensure directory exists
        $directory = Split-Path -Parent $FilePath
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log -Message "Created directory for marker file: $directory" -IsDebug
        }
        
        # Create the marker file
        $Content | Out-File -FilePath $FilePath -Encoding UTF8 -Force -ErrorAction Stop
        
        # Add to global tracking for cleanup
        if ($Global:ActiveMarkerFiles -notcontains $FilePath) {
            $Global:ActiveMarkerFiles += $FilePath
            Write-Log -Message "Added marker file to cleanup tracking: $FilePath" -IsDebug
        }
        
        # Verify creation
        if (Test-Path $FilePath) {
            $fileSize = (Get-Item $FilePath -ErrorAction SilentlyContinue).Length
            Write-Log -Message "Successfully created marker file: $FilePath (Size: $fileSize bytes, Content: $($Content.Substring(0, [Math]::Min(50, $Content.Length)))...)" -IsDebug
            return $true
        } else {
            Write-Log -Message "ERROR: Marker file was not created despite successful Out-File: $FilePath"
            return $false
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to create marker file '$FilePath': $($_.Exception.Message)"
        Write-Log -Message "ERROR: Exception details: $($_.Exception.ToString())" -IsDebug
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
        Write-Log -Message "Removing marker file: $FilePath ($Description)" -IsDebug
        
        if (Test-Path $FilePath) {
            # Get file info before deletion for logging
            $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
            $fileSize = if ($fileInfo) { $fileInfo.Length } else { "Unknown" }
            $fileAge = if ($fileInfo) { [Math]::Round(((Get-Date) - $fileInfo.CreationTime).TotalMinutes, 1) } else { "Unknown" }
            
            # Remove the file
            Remove-Item $FilePath -Force -ErrorAction Stop
            Write-Log -Message "Successfully removed marker file: $FilePath (Size: $fileSize bytes, Age: $fileAge minutes)" -IsDebug
            
            # Remove from global tracking
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            Write-Log -Message "Removed marker file from cleanup tracking: $FilePath" -IsDebug
            
            return $true
        } else {
            Write-Log -Message "Marker file not found (may already be cleaned up): $FilePath" -IsDebug
            # Still remove from tracking in case it was tracked but already deleted externally
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            return $true
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to remove marker file '$FilePath': $($_.Exception.Message)"
        Write-Log -Message "ERROR: Exception details: $($_.Exception.ToString())" -IsDebug
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
        Write-Log -Message "Starting orphaned marker file cleanup (MaxAge: $MaxAgeMinutes minutes)" -IsDebug
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
        
        Write-Log -Message "Scanning $($ScanLocations.Count) locations for orphaned marker files" -IsDebug
        
        foreach ($location in $ScanLocations) {
            if (-not (Test-Path $location)) {
                Write-Log -Message "Scan location does not exist, skipping: $location" -IsDebug
                continue
            }
            
            Write-Log -Message "Scanning location: $location" -IsDebug
            
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
                            
                            Write-Log -Message "Found marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)" -IsDebug
                            
                            if ($fileAgeMinutes -gt $MaxAgeMinutes) {
                                # Check if this file is in our active tracking (don't remove active files)
                                $isActive = $Global:ActiveMarkerFiles -contains $markerFile.FullName
                                
                                if (-not $isActive) {
                                    Write-Log -Message "Removing orphaned marker file: $($markerFile.FullName) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)" -IsDebug
                                    Remove-Item $markerFile.FullName -Force -ErrorAction Stop
                                    $cleanupCount++
                                    $locationCleanupCount++
                                } else {
                                    Write-Log -Message "Skipping active marker file: $($markerFile.FullName)" -IsDebug
                                }
                            } else {
                                Write-Log -Message "Keeping recent marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)" -IsDebug
                            }
                            
                        } catch {
                            Write-Log -Message "ERROR: Failed to process marker file '$($markerFile.FullName)': $($_.Exception.Message)" -IsDebug
                        }
                    }
                }
                
                if ($locationCleanupCount -gt 0) {
                    Write-Log -Message "Cleaned up $locationCleanupCount marker files from: $location" -IsDebug
                }
                
            } catch {
                Write-Log -Message "ERROR: Failed to scan location '$location': $($_.Exception.Message)" -IsDebug
            }
        }
        
        $cleanupDuration = (Get-Date) - $cleanupStartTime
        if ($cleanupCount -gt 0) {
            Write-Log -Message "Orphaned marker file cleanup completed: $cleanupCount files removed in $([Math]::Round($cleanupDuration.TotalSeconds, 1)) seconds"
        } else {
            Write-Log -Message "No orphaned marker files found during cleanup scan" -IsDebug
        }
        
        return $cleanupCount
        
    } catch {
        Write-Log -Message "ERROR: Orphaned marker file cleanup failed: $($_.Exception.Message)"
        Write-Log -Message "ERROR: Exception details: $($_.Exception.ToString())" -IsDebug
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
        Write-Log -Message "Script error trap triggered - performing marker file cleanup" -IsDebug
        Invoke-MarkerFileEmergencyCleanup -Reason "PowerShell trap"
        continue
    }
    
    # Register cleanup for normal exit
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Log -Message "PowerShell exiting - performing marker file cleanup" -IsDebug
        Invoke-MarkerFileEmergencyCleanup -Reason "PowerShell exit"
    } | Out-Null
    
    Write-Log -Message "Marker file cleanup traps registered" -IsDebug
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
        Write-Log -Message "EMERGENCY: Marker file cleanup triggered ($Reason)" -IsDebug
        
        if ($Global:ActiveMarkerFiles -and $Global:ActiveMarkerFiles.Count -gt 0) {
            Write-Log -Message "EMERGENCY: Cleaning up $($Global:ActiveMarkerFiles.Count) tracked marker files" -IsDebug
            
            foreach ($markerFile in $Global:ActiveMarkerFiles) {
                try {
                    if (Test-Path $markerFile) {
                        Remove-Item $markerFile -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "EMERGENCY: Removed marker file: $markerFile" -IsDebug
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
        Write-Log "Checking for interactive session..." -IsDebug
        
        # Use existing Get-InteractiveUser function
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user detected - skipping user context operations"
            return $false
        }
        
        # Additional check: Verify explorer.exe is running (indicates active desktop)
        $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
        if (-not $explorerProcesses) {
            Write-Log "No explorer.exe processes found - no active desktop session"
            return $false
        }
        
        # Verify session is interactive (session ID > 0)
        $hasInteractiveSession = $false
        foreach ($process in $explorerProcesses) {
            if ($process.SessionId -gt 0) {  # Session 0 is services, >0 are user sessions
                $hasInteractiveSession = $true
                Write-Log "Interactive session confirmed - Session ID: $($process.SessionId), User: $($userInfo.Username)" -IsDebug
                break
            }
        }
        
        if (-not $hasInteractiveSession) {
            Write-Log "Explorer processes found but no interactive user sessions detected"
            return $false
        }
        
        return $true
        
    } catch {
        Write-Log "Error checking interactive session: $($_.Exception.Message)"
        return $false
    }
}

# Global user info cache to prevent redundant expensive WMI calls
$Script:CachedUserInfo = $null
$Script:UserInfoCacheTime = $null

function Get-InteractiveUser {
    <#
    .SYNOPSIS
        Gets the currently logged-in interactive user and their SID (Azure AD compatible)
    #>
    
    try {
        # Check cache first (valid for 5 minutes)
        if ($Script:CachedUserInfo -and
            $Script:UserInfoCacheTime -and
            ((Get-Date) - $Script:UserInfoCacheTime).TotalMinutes -lt 5) {
            Write-Log "Using cached user info (age: $([Math]::Round(((Get-Date) - $Script:UserInfoCacheTime).TotalMinutes, 1)) minutes)"
            return $Script:CachedUserInfo
        }
        
        Write-Log "Detecting interactive user using Win32_ComputerSystem..."
        
        # Primary method - proven to work with Azure AD
        try {
            $loggedInUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username -ExpandProperty username
            if (-not $loggedInUser) {
                $Message = "User is not logged on to the primary session: No username returned from Win32_ComputerSystem"
                Throw $Message
            }
            
            $username = ($loggedInUser -split '\\')[1]
            $domain = ($loggedInUser -split '\\')[0]
            
            Write-Log "Found logged in user: $loggedInUser"
            Write-Log "Extracted username: $username"
            Write-Log "Extracted domain: $domain"
            
        } catch [Exception] {
            $Message = "User is not logged on to the primary session: $_"
            Write-Log $Message
            Throw $Message
        }
        
        # Get user SID for reliable task creation
        $userSid = $null
        
        # Method 1: Try with full domain\username format
        try {
            $userSid = (New-Object System.Security.Principal.NTAccount($loggedInUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            Write-Log "Successfully got SID using full name ($loggedInUser): $userSid"
        } catch {
            Write-Log "Could not get SID using full name: $($_.Exception.Message)"
        }
        
        # Method 2: Try with just username if full name failed
        if (-not $userSid) {
            try {
                $userSid = (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-Log "Successfully got SID using username ($username): $userSid"
            } catch {
                Write-Log "Could not get SID using username: $($_.Exception.Message)"
            }
        }
        
        if (-not $userSid) {
            Write-Log "Warning: Could not obtain user SID, task creation may fail"
        }
        
        $userInfo = @{
            Username = $username
            FullName = $loggedInUser
            Domain = $domain
            SID = $userSid
        }
        
        # Cache the result
        $Script:CachedUserInfo = $userInfo
        $Script:UserInfoCacheTime = Get-Date
        
        return $userInfo
        
    } catch {
        Write-Log "Error getting interactive user: $($_.Exception.Message)"
        return $null
    }
}

function Write-DetectionResults {
    param(
        [array]$Apps,
        [string]$FilePath
    )
    
    try {
        Write-Log "DEBUG: Write-DetectionResults function entered" -IsDebug
        Write-Log "DEBUG: Target file path: $FilePath" -IsDebug
        Write-Log "DEBUG: Apps to write: $($Apps.Count)" -IsDebug
        Write-Log "DEBUG: Apps list: $($Apps -join ', ')" -IsDebug
        
        $results = @{
            Apps = $Apps
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Username = $env:USERNAME
            Computer = $env:COMPUTERNAME
            Context = if (Test-RunningAsSystem) { "SYSTEM" } else { "USER" }
            ProcessId = $PID
            SessionId = (Get-Process -Id $PID).SessionId
        }
        
        Write-Log "DEBUG: Results object created successfully" -IsDebug
        
        $jsonResults = $results | ConvertTo-Json -Depth 3 -Compress
        Write-Log "DEBUG: JSON conversion successful, length: $($jsonResults.Length) chars" -IsDebug
        Write-Log "DEBUG: JSON content: $jsonResults" -IsDebug
        Write-Log "DEBUG: About to write to file: $FilePath" -IsDebug
        
        $jsonResults | Out-File -FilePath $FilePath -Encoding UTF8 -Force
        Write-Log "DEBUG: Out-File command completed" -IsDebug
        
        # Verify file was actually created
        if (Test-Path $FilePath) {
            $fileSize = (Get-Item $FilePath).Length
            Write-Log "DEBUG: File creation verified - size: $fileSize bytes" -IsDebug
            
            # Read back and verify content
            try {
                $verifyContent = Get-Content $FilePath -Raw
                Write-Log "DEBUG: File read verification successful - content length: $($verifyContent.Length)" -IsDebug
                $verifyJson = $verifyContent | ConvertFrom-Json
                Write-Log "DEBUG: JSON verification successful - apps: $($verifyJson.Apps.Count)" -IsDebug
            } catch {
                Write-Log "ERROR: File verification failed: $($_.Exception.Message)"
            }
        } else {
            Write-Log "ERROR: File was not created despite Out-File success"
        }
        
        Write-Log "Detection results written: $($Apps.Count) apps found"
        return $true
        
    } catch {
        Write-Log "ERROR: Write-DetectionResults failed: $($_.Exception.Message)"
        Write-Log "ERROR: Exception type: $($_.Exception.GetType().FullName)"
        Write-Log "ERROR: Stack trace: $($_.Exception.StackTrace)"
        return $false
    }
}

function Invoke-UserContextDetection {
    <#
    .SYNOPSIS
        Schedules user context detection and waits for results
    #>
    
    try {
        Write-Log "DEBUG: *** INVOKE-USERCONTEXTDETECTION FUNCTION ENTERED ***" -IsDebug
        Write-Log "DEBUG: Function starting execution..." -IsDebug
        Write-Log "Starting user context detection scheduling"
        
        # First, let's test if we can manually run winget in user context to verify apps exist
        Write-Log "DEBUG: Testing direct winget execution in SYSTEM context with --scope user..." -IsDebug
        try {
            if ($WingetPath) {
                Set-Location $WingetPath
                Write-Log "DEBUG: Executing winget --scope user from SYSTEM context..." -IsDebug
                $testOutput = $(.\winget.exe upgrade --accept-source-agreements --scope user 2>&1)
                Write-Log "DEBUG: Direct --scope user test completed, output: $($testOutput.Count) lines" -IsDebug
                # Show first few lines to see if user apps are visible
                for ($i = 0; $i -lt [Math]::Min(5, $testOutput.Count); $i++) {
                    Write-Log "DEBUG: Direct test line $i`: $($testOutput[$i])" -IsDebug
                }
                
                # Check if apps were found in direct test
                $appsFoundInTest = ($testOutput | Where-Object { $_ -like "*.*" -and $_ -notlike "*No applicable update*" }).Count -gt 0
                Write-Log "DEBUG: Direct --scope user test found apps: $appsFoundInTest" -IsDebug
            }
        } catch {
            Write-Log "DEBUG: Direct --scope user test failed: $($_.Exception.Message)" -IsDebug
        }
        
        Write-Log "DEBUG: Getting interactive user info..." -IsDebug
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "DEBUG: ERROR - No interactive user found - skipping user context detection" -IsDebug
            return @()
        }
        Write-Log "DEBUG: Interactive user found: $($userInfo.Username)" -IsDebug
        
        # Create detection result file - use shared path accessible to both SYSTEM and USER contexts
        $sharedTempPath = "C:\ProgramData\Temp"
        if (-not (Test-Path $sharedTempPath)) {
            New-Item -Path $sharedTempPath -ItemType Directory -Force | Out-Null
        }
        $randomId = Get-Random -Minimum 1000 -Maximum 9999
        $resultFile = Join-Path $sharedTempPath "UserDetection_$randomId.json"
        Write-Log "DEBUG: *** FILE TRACKING START ***" -IsDebug
        Write-Log "DEBUG: Generated result filename: UserDetection_$randomId.json" -IsDebug
        Write-Log "DEBUG: Full result file path: $resultFile" -IsDebug
        Write-Log "DEBUG: Shared temp directory: $sharedTempPath" -IsDebug
        Write-Log "DEBUG: Directory exists: $(Test-Path $sharedTempPath)" -IsDebug
        if (Test-Path $sharedTempPath) {
            $dirFiles = Get-ChildItem -Path $sharedTempPath -Filter "UserDetection_*.json" -ErrorAction SilentlyContinue
            Write-Log "DEBUG: Existing UserDetection files in directory: $($dirFiles.Count)" -IsDebug
            foreach ($file in $dirFiles) {
                Write-Log "DEBUG: - Existing file: $($file.Name) (size: $($file.Length) bytes, modified: $($file.LastWriteTime))" -IsDebug
            }
        }
        Write-Log "User detection result file: $resultFile"
        Write-Log "Using shared temp path accessible to both SYSTEM and USER contexts: $sharedTempPath"
        
        # Create scheduled task for user detection
        $taskName = "UserDetection_$(Get-Random -Minimum 1000 -Maximum 9999)"
        $tempScriptName = "availableUpgrades-detect_$(Get-Random -Minimum 1000 -Maximum 9999).ps1"
        $tempScriptPath = Join-Path $sharedTempPath $tempScriptName
        
        Write-Log "Copying script to user-accessible location: $tempScriptPath" | Out-Null
        Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force
        
        $scriptPath = $tempScriptPath
        
        # Create a marker file to indicate this is a user detection task (workaround for parameter passing issues)
        $markerFile = "$tempScriptPath.userdetection"
        $markerCreated = New-MarkerFile -FilePath $markerFile -Content "USERDETECTION:$resultFile" -Description "User detection task marker"
        
        if (-not $markerCreated) {
            Write-Log -Message "ERROR: Failed to create user detection marker file - user detection may not work properly"
        }
        
        # Use hidden console window execution method to prevent visible windows
        $hiddenArguments = "/c start /min `"`" powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        
        Write-Log "Creating user detection task: $taskName" | Out-Null
        Write-Log "Script path: $scriptPath" | Out-Null
        Write-Log "Hidden execution arguments: $hiddenArguments" | Out-Null
        Write-Log "Result file: $resultFile" | Out-Null
        Write-Log "Marker file: $markerFile" | Out-Null
        
        # Verify script copy exists and is readable
        if (Test-Path $tempScriptPath) {
            $scriptSize = (Get-Item $tempScriptPath).Length
            Write-Log "DEBUG: Temp script exists, size: $scriptSize bytes" -IsDebug
        } else {
            Write-Log "ERROR: Temp script copy does not exist: $tempScriptPath" | Out-Null
            return @()
        }
        
        # Verify result directory is writable
        $resultDir = Split-Path $resultFile
        try {
            $testFile = Join-Path $resultDir "test_$(Get-Random).tmp"
            "test" | Out-File -FilePath $testFile -Force
            Remove-Item $testFile -Force
            Write-Log "DEBUG: Result directory is writable: $resultDir" -IsDebug
        } catch {
            Write-Log "ERROR: Result directory not writable: $resultDir - $($_.Exception.Message)" -IsDebug | Out-Null
        }
        
        try {
            # Create task action using hidden console window method
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $hiddenArguments
            
            # Create task principal (run as interactive user)
            $principal = $null
            $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
            $logonTypes = @("Interactive", "S4U")
            
            foreach ($userFormat in $userFormats) {
                foreach ($logonType in $logonTypes) {
                    try {
                        $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                        Write-Log "Successfully created principal with: $userFormat ($logonType)"
                        break
                    } catch {
                        Write-Log "Failed with format '$userFormat' ($logonType): $($_.Exception.Message)"
                    }
                }
                if ($principal) { break }
            }
            
            if (-not $principal) {
                Write-Log "DEBUG: ERROR - Could not create task principal with any method"
                return @()
            }
            
            # Create task settings - match working dialog system approach
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
            
            # Create and register the task WITHOUT triggers (same as working dialog system)
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "User context winget detection"
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            Write-Log "Task created successfully: $taskName" | Out-Null
            
            # Verify task was created successfully before starting
            $createdTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $createdTask) {
                Write-Log "ERROR: Task creation failed - task not found: $taskName" | Out-Null
                return @()
            }
            Write-Log "DEBUG: Task verified to exist: $taskName, State: $($createdTask.State)" -IsDebug | Out-Null
            
            # Start the task with enhanced error handling
            Write-Log "Starting user detection task: $taskName"
            try {
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                Write-Log "DEBUG: Start-ScheduledTask completed successfully" -IsDebug
                
                # Verify task actually started and monitor its execution
                Start-Sleep -Seconds 1
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Log "DEBUG: Task info - LastResult: $($taskInfo.LastTaskResult), LastRunTime: $($taskInfo.LastRunTime)" -IsDebug
                    Write-Log "DEBUG: Task info - NextRunTime: $($taskInfo.NextRunTime), NumberOfMissedRuns: $($taskInfo.NumberOfMissedRuns)" -IsDebug
                } else {
                    Write-Log "ERROR: Cannot get task info after start attempt" -IsDebug
                }
                
                # Brief verification that task started, then proceed to file monitoring
                Start-Sleep -Seconds 2
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Log "DEBUG: Task started successfully - LastResult: $($taskInfo.LastTaskResult), LastRunTime: $($taskInfo.LastRunTime)" -IsDebug
                } else {
                    Write-Log "DEBUG: Could not get task info after start" -IsDebug
                }
                
            } catch {
                Write-Log "ERROR: Failed to start scheduled task: $($_.Exception.Message)"
                return @()
            }
            
            # Wait for results with reduced timeout for faster detection
            $timeout = 30  # Reduced from 60 to 30 seconds
            $startTime = Get-Date
            $apps = @()
            
            Write-Log "DEBUG: *** STARTING FILE WAIT LOOP ***" -IsDebug
            Write-Log "DEBUG: Listening for file: $resultFile" -IsDebug
            Write-Log "DEBUG: Timeout: $timeout seconds" -IsDebug
            Write-Log "DEBUG: Start time: $startTime" -IsDebug
            Write-Log "Waiting for user detection results (timeout: $timeout seconds)" | Out-Null
            
            $waitCount = 0
            while ((Get-Date) -lt $startTime.AddSeconds($timeout)) {
                $waitCount++
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                Write-Log "DEBUG: Wait cycle $waitCount (elapsed: $([math]::Round($elapsed, 1))s) - checking for file: $resultFile" -IsDebug
                
                if (Test-Path $resultFile) {
                    Write-Log "DEBUG: *** FILE DETECTED *** - $resultFile found after $([math]::Round($elapsed, 1)) seconds" -IsDebug
                    try {
                        Write-Log "DEBUG: Result file found: $resultFile" -IsDebug | Out-Null
                        $fileSize = (Get-Item $resultFile).Length
                        Write-Log "DEBUG: Result file size: $fileSize bytes" -IsDebug | Out-Null
                        
                        Start-Sleep -Milliseconds 500  # Brief pause to ensure file is fully written
                        $fileContent = Get-Content $resultFile -Raw
                        Write-Log "DEBUG: Raw file content: $fileContent" -IsDebug | Out-Null
                        
                        $results = $fileContent | ConvertFrom-Json
                        Write-Log "DEBUG: JSON parsed successfully" -IsDebug | Out-Null
                        Write-Log "DEBUG: Results object - Apps count: $($results.Apps.Count), Context: $($results.Context), Username: $($results.Username)" -IsDebug | Out-Null
                        
                        $apps = $results.Apps
                        Write-Log "User detection completed: $($apps.Count) apps found" | Out-Null
                        if ($apps.Count -gt 0) {
                            Write-Log "DEBUG: User context apps found: $($apps -join ', ')" -IsDebug | Out-Null
                        } else {
                            Write-Log "DEBUG: No apps found in parsed results - Apps array is empty" -IsDebug | Out-Null
                        }
                        break
                    } catch {
                        Write-Log "Error reading/parsing detection results: $($_.Exception.Message)" | Out-Null
                        Write-Log "DEBUG: Exception type: $($_.Exception.GetType().FullName)" -IsDebug | Out-Null
                        if (Test-Path $resultFile) {
                            $rawContent = Get-Content $resultFile -Raw -ErrorAction SilentlyContinue
                            Write-Log "DEBUG: Raw file content on error: $rawContent" -IsDebug | Out-Null
                        }
                        Start-Sleep -Seconds 2
                        continue
                    }
                } else {
                    Write-Log "DEBUG: File not found yet (cycle $waitCount) - checking directory contents" -IsDebug
                    if (Test-Path $sharedTempPath) {
                        $currentFiles = Get-ChildItem -Path $sharedTempPath -Filter "UserDetection_*.json" -ErrorAction SilentlyContinue
                        Write-Log "DEBUG: Current UserDetection files in directory: $($currentFiles.Count)" -IsDebug
                        foreach ($file in $currentFiles) {
                            Write-Log "DEBUG: - Found file: $($file.Name) (size: $($file.Length) bytes)" -IsDebug
                        }
                    }
                }
                Start-Sleep -Seconds 2
            }
            
            if ((Get-Date) -ge $startTime.AddSeconds($timeout)) {
                Write-Log "User detection timed out after $timeout seconds - proceeding with system apps only"
                
                # Check final task state to understand what happened
                try {
                    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($task) {
                        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                        Write-Log "DEBUG: TIMEOUT - Final task state: $($task.State)" -IsDebug
                        Write-Log "DEBUG: TIMEOUT - Final task result: $($taskInfo.LastTaskResult)" -IsDebug
                        Write-Log "DEBUG: TIMEOUT - Task last run: $($taskInfo.LastRunTime)" -IsDebug
                        
                        if ($task.State -eq "Running") {
                            Write-Log "DEBUG: Task still running - stopping it" -IsDebug
                            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                        }
                    }
                } catch {
                    Write-Log "DEBUG: Error checking final task state: $($_.Exception.Message)" -IsDebug
                }
            }
            
        } catch {
            Write-Log "DEBUG: ERROR - Exception in user detection task: $($_.Exception.Message)" -IsDebug
            Write-Log "DEBUG: ERROR - Exception type: $($_.Exception.GetType().FullName)" -IsDebug
            $apps = @()
        } finally {
            # Cleanup
            try {
                Write-Log "DEBUG: *** STARTING CLEANUP ***" -IsDebug
                Write-Log "DEBUG: Unregistering scheduled task: $taskName" -IsDebug
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "DEBUG: Task unregistered successfully" -IsDebug
                
                if (Test-Path $resultFile) {
                    Write-Log "DEBUG: *** DELETING RESULT FILE *** - $resultFile" -IsDebug
                    $fileSize = (Get-Item $resultFile -ErrorAction SilentlyContinue).Length
                    Write-Log "DEBUG: File size before deletion: $fileSize bytes" -IsDebug
                    Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
                    Write-Log "DEBUG: Result file deleted: $resultFile" -IsDebug
                    # Verify deletion
                    if (Test-Path $resultFile) {
                        Write-Log "WARNING: Result file still exists after deletion attempt!"
                    } else {
                        Write-Log "DEBUG: Result file deletion confirmed" -IsDebug
                    }
                } else {
                    Write-Log "DEBUG: Result file not found during cleanup: $resultFile" -IsDebug
                }
                
                # Clean up temporary script copy
                if (Test-Path $tempScriptPath) {
                    Write-Log "DEBUG: *** DELETING TEMP SCRIPT *** - $tempScriptPath" -IsDebug
                    Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed temporary script copy: $tempScriptPath" | Out-Null
                } else {
                    Write-Log "DEBUG: Temp script not found during cleanup: $tempScriptPath" -IsDebug | Out-Null
                }
                
                # Clean up marker file using centralized function
                $markerFileCleanup = "$tempScriptPath.userdetection"
                $markerRemoved = Remove-MarkerFile -FilePath $markerFileCleanup -Description "User detection task marker (finally block)"
                if (-not $markerRemoved) {
                    Write-Log "WARNING: Failed to clean up marker file during finally block: $markerFileCleanup" | Out-Null
                }
                
                Write-Log "DEBUG: *** CLEANUP COMPLETED ***" -IsDebug
                Write-Log "User detection cleanup completed" | Out-Null
            } catch {
                Write-Log "Error during cleanup: $($_.Exception.Message)" | Out-Null
            }
        }
        
        return $apps
        
    } catch {
        Write-Log "DEBUG: ERROR - Outer catch in user context detection: $($_.Exception.Message)" -IsDebug | Out-Null
        Write-Log "DEBUG: ERROR - Outer exception type: $($_.Exception.GetType().FullName)" -IsDebug | Out-Null
        return @()
    } finally {
        # Clean up old temporary script copies (older than 1 hour)
        try {
            if ($userInfo) {
                $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
                if (Test-Path $userTempPath) {
                    $oldTempScripts = Get-ChildItem -Path $userTempPath -Filter "availableUpgrades-detect_*.ps1" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) }
                    foreach ($oldScript in $oldTempScripts) {
                        Remove-Item $oldScript.FullName -Force -ErrorAction SilentlyContinue
                        Write-Log "Cleaned up old temporary script: $($oldScript.Name)" | Out-Null
                    }
                }
            }
        } catch {
            # Ignore cleanup errors
        }
    }
}

<# Script variables #>
$ScriptTag = "5B" # Update this tag for each script version
$LogName = 'DetectAvailableUpgrades'
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

# Initialize marker file management system (with guard to prevent double initialization)
$Script:MarkerSystemInitialized = $false
if (-not $Script:MarkerSystemInitialized) {
    Write-Log -Message "Initializing marker file management system" -IsDebug
    Add-MarkerFileCleanupTrap
    $orphanedCount = Clear-OrphanedMarkerFiles -MaxAgeMinutes 60
    if ($orphanedCount -gt 0) {
        Write-Log -Message "Cleaned up $orphanedCount orphaned marker files from previous executions"
    }
    $Script:MarkerSystemInitialized = $true
}

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

# Legacy toast test code removed - no longer needed with WPF dialog system

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Write-Log -Message "OOBE not complete, performing marker file cleanup before exit" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "OOBE not complete"
    Exit 0
}

<# ---------------------------------------------- #>

# Load whitelist configuration with priority: Local file > GitHub > Hardcoded fallback
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$localWhitelistPath = Join-Path $scriptDirectory "app-whitelist.json"
$whitelistJSON = $null

# First, try to load from local file
if (Test-Path $localWhitelistPath) {
    try {
        Write-Log -Message "Loading whitelist configuration from local file: $localWhitelistPath"
        $whitelistJSON = Get-Content -Path $localWhitelistPath -Raw -Encoding UTF8
        Write-Log -Message "Successfully loaded local whitelist configuration"
    } catch {
        Write-Log -Message "Error reading local whitelist file: $($_.Exception.Message)"
        $whitelistJSON = $null
    }
}

# If no local file or local file failed, try GitHub
if ([string]::IsNullOrEmpty($whitelistJSON)) {
    $whitelistUrl = "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/app-whitelist.json"
    Write-Log -Message "Loading whitelist configuration from GitHub"
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-WingetScript/4.2")
        $whitelistJSON = $webClient.DownloadString($whitelistUrl)
        Write-Log -Message "Successfully downloaded whitelist configuration from GitHub"
    } catch {
        Write-Log -Message "Error downloading whitelist from GitHub: $($_.Exception.Message)"
        $whitelistJSON = $null
    }
}

# If both local file and GitHub failed, use hardcoded fallback
if ([string]::IsNullOrEmpty($whitelistJSON)) {
    Write-Log -Message "Using hardcoded fallback configuration"
    
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
    Write-Log -Message "Performing marker file cleanup before exit due to whitelist error" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "Whitelist parsing error"
    exit 1
}

# Main detection logic - dual-context architecture - FIXED PARAMETER DETECTION
# Check for marker file (workaround for scheduled task parameter passing issues)
$currentScriptPath = $MyInvocation.MyCommand.Path
$markerFile = "$currentScriptPath.userdetection"
$isUserDetectionTask = $false
$markerResultFile = ""

if (Test-Path $markerFile) {
    try {
        $markerContent = Get-Content $markerFile -Raw
        if ($markerContent -match "USERDETECTION:(.+)") {
            $isUserDetectionTask = $true
            $markerResultFile = $matches[1].Trim()
            Write-Log -Message "DEBUG: Found user detection marker file with result path: $markerResultFile" -IsDebug
        }
    } catch {
        Write-Log -Message "DEBUG: Error reading marker file: $($_.Exception.Message)" -IsDebug
    }
}

Write-Log -Message "DEBUG: Marker detection - isUserDetectionTask: $isUserDetectionTask, markerResultFile: '$markerResultFile'" -IsDebug

if ($UserDetectionOnly -eq "true" -or $isUserDetectionTask) {
    # This is a scheduled user detection task - detect user apps only
    # CRITICAL FIX: Check UserDetectionOnly parameter first, before context checks
    Write-Log -Message "*** RUNNING IN USER CONTEXT (SCHEDULED TASK) ***"
    Write-Log -Message "Current user: $env:USERNAME"
    Write-Log -Message "User domain: $env:USERDOMAIN"
    Write-Log -Message "Session ID: $((Get-Process -Id $PID).SessionId)"
    Write-Log -Message "Process ID: $PID"
    Write-Log -Message "Running user detection task"
    # Use marker file result path if parameter is empty
    $effectiveResultFile = if (-not [string]::IsNullOrEmpty($DetectionResultFile)) {
        $DetectionResultFile
    } else {
        $markerResultFile
    }
    Write-Log -Message "DetectionResultFile parameter: $DetectionResultFile"
    Write-Log -Message "Effective result file (from marker): $effectiveResultFile"
    
    # Check if we're admin in user context - if not, use --scope user
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Write-Log -Message "User is admin: $userIsAdmin"
    Write-Log -Message "Test-RunningAsSystem: $(Test-RunningAsSystem)"
    
    if ($userIsAdmin) {
        Write-Log -Message "Admin user context - detecting all apps"
        $OUTPUT = $(winget upgrade --accept-source-agreements)
    } else {
        Write-Log -Message "Non-admin user context - using --scope user for detection"
        $OUTPUT = $(winget upgrade --accept-source-agreements --scope user)
    }
    
    Write-Log -Message "DEBUG: User context winget output received, $($OUTPUT.Count) lines" -IsDebug
    # Show first few lines of user context output for debugging
    for ($debugLine = 0; $debugLine -lt [Math]::Min(5, $OUTPUT.Count); $debugLine++) {
        Write-Log -Message "DEBUG: User Line $debugLine`: $($OUTPUT[$debugLine])" -IsDebug
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
        if ($userIsAdmin) {
            $OUTPUT = $(winget upgrade --accept-source-agreements)
        } else {
            $OUTPUT = $(winget upgrade --accept-source-agreements --scope user)
        }
    }
    
    Write-Log -Message "User context detection - processing user-scoped apps only"
    
} elseif (Test-RunningAsSystem) {
    # SYSTEM context main execution - detect system apps and schedule user detection
    Write-Log -Message "SYSTEM context - detecting system apps and scheduling user detection"
    
    if ($WingetPath) {
        Write-Log -Message "Using winget path: $WingetPath"
        Set-Location $WingetPath
        
        # System context winget - only sees system-wide apps
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
    } else {
        Write-Log -Message "Winget not detected in SYSTEM context"
        Write-Log -Message "Performing marker file cleanup before exit (no winget in system context)" -IsDebug
        Invoke-MarkerFileEmergencyCleanup -Reason "Winget not detected in SYSTEM context"
        exit 0
    }
} else {
    # Direct user context execution - detect user apps only
    Write-Log -Message "USER context - detecting user-scoped apps"
    
    # Check if we're admin in user context - if not, use --scope user
    if ($userIsAdmin) {
        $OUTPUT = $(winget upgrade --accept-source-agreements)
    } else {
        Write-Log -Message "Non-admin user context - using --scope user for detection"
        $OUTPUT = $(winget upgrade --accept-source-agreements --scope user)
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
        if ($userIsAdmin) {
            $OUTPUT = $(winget upgrade --accept-source-agreements)
        } else {
            $OUTPUT = $(winget upgrade --accept-source-agreements --scope user)
        }
    }
}

# Parse winget output and process apps
if ($OUTPUT) {
    Write-Log -Message "DEBUG: Winget output received, $($OUTPUT.Count) lines" -IsDebug
    # Show first few lines of output for debugging
    for ($debugLine = 0; $debugLine -lt [Math]::Min(5, $OUTPUT.Count); $debugLine++) {
        Write-Log -Message "DEBUG: Line $debugLine`: $($OUTPUT[$debugLine])" -IsDebug
    }
    
    $headerLine = -1
    $lineCount = 0

    foreach ($line in $OUTPUT) {
        if ($line -like "Name*" -and $headerLine -eq -1) {
            $headerLine = $lineCount
            Write-Log -Message "DEBUG: Found header line at position $headerLine`: $line" -IsDebug
        }
        $lineCount++
    }
    
    if ($OUTPUT -and $lineCount -gt $headerLine+2) {
        $str = $OUTPUT[$headerLine]
        $idPos = $str.indexOf("Id")
        $versionPos = $str.indexOf("Version")-1

        $LIST= [System.Collections.ArrayList]::new()
        Write-Log -Message "DEBUG: Parsing apps from line $($headerLine+2) to $($OUTPUT.count-1)" -IsDebug
        for ($i=$headerLine+2;($i -lt $OUTPUT.count);$i=$i+1) {
            $lineData = $OUTPUT[$i]
            Write-Log -Message "DEBUG: Processing line $i`: $lineData" -IsDebug
            # Stop parsing if we hit the second section or empty lines
            if ($lineData -like "*upgrade available, but require*" -or $lineData.Trim() -eq "" -or $lineData -like "*following packages*") {
                Write-Log -Message "DEBUG: Stopping parsing at line $i` due to: $lineData" -IsDebug
                break
            }
            $appId = ($lineData[$idPos..$versionPos] -Join "").trim()
            Write-Log -Message "DEBUG: Extracted appId: '$appId'" -IsDebug
            if ($appId -ne "") {
                $null = $LIST.Add($appId)
                Write-Log -Message "DEBUG: Added app to list: $appId" -IsDebug
            }
        }
        Write-Log -Message "DEBUG: Total apps found in winget output: $($LIST.Count)" -IsDebug

        $contextApps = @()

        foreach ($app in $LIST) {
            if ($app -ne "") {
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($app -eq $okapp.AppID) {
                        # FAST DEFERRAL CHECK - Only check existing registry data (no expensive winget queries)
                        if ($okapp.DeferralEnabled -eq $true) {
                            $deferralPath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals\$app"
                            $now = Get-Date
                            
                            # Quick check - only look at existing user deadline (no expensive admin deadline calculation)
                            if (Test-Path $deferralPath) {
                                try {
                                    $deferralData = Get-ItemProperty -Path $deferralPath -ErrorAction SilentlyContinue
                                    if ($deferralData -and $deferralData.UserDeadline) {
                                        $userDeadline = [DateTime]::Parse($deferralData.UserDeadline)
                                        if ($now -lt $userDeadline) {
                                            Write-Log -Message "Skipping $($okapp.AppID) - user has deferred until $userDeadline"
                                            continue  # Skip this app - still deferred
                                        } else {
                                            Write-Log -Message "User deferral for $($okapp.AppID) has expired - allowing detection"
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "Error reading deferral data for $app : $($_.Exception.Message)"
                                    # On error, allow detection to proceed
                                }
                            }
                        }
                        
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
                        
                        $doUpgrade = $true
                        break
                    }
                }

                if ($doUpgrade) {
                    $contextApps += $app
                    Write-Log -Message "DEBUG: App '$app' added to context apps (whitelisted)" -IsDebug
                } else {
                    Write-Log -Message "DEBUG: App '$app' not in whitelist, skipping" -IsDebug
                }
            }
        }

        # Handle different execution contexts
        Write-Log -Message "DEBUG: *** EXECUTION CONTEXT ANALYSIS ***" -IsDebug
        Write-Log -Message "DEBUG: Test-RunningAsSystem: $(Test-RunningAsSystem)" -IsDebug
        Write-Log -Message "DEBUG: UserDetectionOnly parameter: $UserDetectionOnly" -IsDebug
        Write-Log -Message "DEBUG: DetectionResultFile parameter: '$DetectionResultFile'" -IsDebug
        Write-Log -Message "DEBUG: Checking execution path conditions..." -IsDebug
        
        if ($UserDetectionOnly -eq "true" -or $isUserDetectionTask) {
            Write-Log -Message "DEBUG: *** TAKING USER CONTEXT SCHEDULED TASK PATH ***" -IsDebug
            # User context scheduled task - write results and exit
            Write-Log -Message "User detection found $($contextApps.Count) apps"
            if ($contextApps.Count -gt 0) {
                Write-Log -Message "DEBUG: User context apps: $($contextApps -join ', ')" -IsDebug
            }
            Write-Log -Message "*** USER CONTEXT DETECTION COMPLETE - WRITING RESULTS ***"
            
            # CRITICAL FIX: Always write JSON result file, even when no apps found
            # The system context waits for this file regardless of app count
            if ($effectiveResultFile) {
                Write-Log -Message "DEBUG: *** USER CONTEXT FILE CREATION START ***" -IsDebug
                Write-Log -Message "DEBUG: Target result file: $effectiveResultFile" -IsDebug
                $targetDir = Split-Path $effectiveResultFile
                Write-Log -Message "DEBUG: File directory: $targetDir" -IsDebug
                Write-Log -Message "DEBUG: File name: $(Split-Path $effectiveResultFile -Leaf)" -IsDebug
                Write-Log -Message "DEBUG: Directory exists: $(Test-Path $targetDir)" -IsDebug
                Write-Log -Message "DEBUG: About to write $($contextApps.Count) apps to result file" -IsDebug
                Write-Log -Message "DEBUG: Apps to write: $($contextApps -join ', ')" -IsDebug
                Write-Log -Message "Writing results to file: $effectiveResultFile"
                
                # COMPREHENSIVE PERMISSIONS TESTING FROM SCHEDULED TASK CONTEXT
                Write-Log -Message "DEBUG: *** TESTING DIRECTORY PERMISSIONS ***" -IsDebug
                Write-Log -Message "DEBUG: Current user in scheduled task: $env:USERNAME" -IsDebug
                Write-Log -Message "DEBUG: Current domain: $env:USERDOMAIN" -IsDebug
                Write-Log -Message "DEBUG: Process ID: $PID" -IsDebug
                Write-Log -Message "DEBUG: Session ID: $((Get-Process -Id $PID).SessionId)" -IsDebug
                
                # Test directory accessibility
                try {
                    if (Test-Path $targetDir) {
                        Write-Log -Message "DEBUG: Target directory exists and is accessible" -IsDebug
                        $dirInfo = Get-Item $targetDir
                        Write-Log -Message "DEBUG: Directory creation time: $($dirInfo.CreationTime)" -IsDebug
                        Write-Log -Message "DEBUG: Directory last write: $($dirInfo.LastWriteTime)" -IsDebug
                        
                        # Test directory ACL
                        try {
                            $acl = Get-Acl $targetDir
                            Write-Log -Message "DEBUG: Directory owner: $($acl.Owner)" -IsDebug
                            Write-Log -Message "DEBUG: Directory access rules: $($acl.Access.Count)" -IsDebug
                        } catch {
                            Write-Log -Message "DEBUG: Could not read directory ACL: $($_.Exception.Message)" -IsDebug
                        }
                    } else {
                        Write-Log -Message "ERROR: Target directory does not exist or is not accessible"
                    }
                } catch {
                    Write-Log -Message "ERROR: Cannot access target directory: $($_.Exception.Message)"
                }
                
                # Test file creation capability
                Write-Log -Message "DEBUG: Testing file creation capability in target directory" -IsDebug
                $testFileName = "test_$(Get-Random)_$PID.tmp"
                $testFilePath = Join-Path $targetDir $testFileName
                try {
                    "test content" | Out-File -FilePath $testFilePath -Force -Encoding UTF8
                    if (Test-Path $testFilePath) {
                        Write-Log -Message "DEBUG: File creation test successful" -IsDebug
                        Remove-Item $testFilePath -Force
                    } else {
                        Write-Log -Message "ERROR: Test file creation failed - file does not exist after write"
                    }
                } catch {
                    Write-Log -Message "ERROR: Test file creation failed: $($_.Exception.Message)"
                }
                
                # Check if file already exists (shouldn't happen)
                if (Test-Path $effectiveResultFile) {
                    Write-Log -Message "WARNING: Result file already exists before writing!"
                    $existingSize = (Get-Item $effectiveResultFile).Length
                    Write-Log -Message "DEBUG: Existing file size: $existingSize bytes" -IsDebug
                }
                
                $writeSuccess = Write-DetectionResults -Apps $contextApps -FilePath $effectiveResultFile
                Write-Log -Message "DEBUG: Write-DetectionResults returned: $writeSuccess" -IsDebug
                
                # Verify file was created and contains expected data
                if (Test-Path $effectiveResultFile) {
                    $fileSize = (Get-Item $effectiveResultFile).Length
                    $fileCreationTime = (Get-Item $effectiveResultFile).CreationTime
                    $fileModifiedTime = (Get-Item $effectiveResultFile).LastWriteTime
                    Write-Log -Message "DEBUG: *** FILE CREATED SUCCESSFULLY ***" -IsDebug
                    Write-Log -Message "DEBUG: Result file path: $effectiveResultFile" -IsDebug
                    Write-Log -Message "DEBUG: File size: $fileSize bytes" -IsDebug
                    Write-Log -Message "DEBUG: Created: $fileCreationTime" -IsDebug
                    Write-Log -Message "DEBUG: Modified: $fileModifiedTime" -IsDebug
                    try {
                        $verifyContent = Get-Content $effectiveResultFile -Raw
                        $verifyJson = $verifyContent | ConvertFrom-Json
                        Write-Log -Message "DEBUG: File verification successful - Apps count: $($verifyJson.Apps.Count)" -IsDebug
                    } catch {
                        Write-Log -Message "ERROR: File verification failed: $($_.Exception.Message)"
                    }
                    
                } else {
                    Write-Log -Message "ERROR: *** FILE CREATION FAILED *** - Result file was not created: $DetectionResultFile"
                    # Check if directory is writable
                    $dir = Split-Path $DetectionResultFile
                    try {
                        $testFile = Join-Path $dir "test_$(Get-Random).tmp"
                        "test" | Out-File -FilePath $testFile -Force
                        Remove-Item $testFile -Force
                        Write-Log -Message "DEBUG: Directory is writable: $dir" -IsDebug
                    } catch {
                        Write-Log -Message "ERROR: Directory not writable: $dir - $($_.Exception.Message)"
                    }
                }
                Write-Log -Message "DEBUG: *** USER CONTEXT FILE CREATION END ***" -IsDebug
            } else {
                Write-Log -Message "ERROR: No DetectionResultFile parameter provided to user context task"
                # Still write a basic result file to prevent system context timeout
                $fallbackFile = "C:\ProgramData\Temp\UserDetection_Fallback_$(Get-Random).json"
                Write-Log -Message "Writing fallback result to: $fallbackFile"
                $writeSuccess = Write-DetectionResults -Apps $contextApps -FilePath $fallbackFile
                Write-Log -Message "DEBUG: Fallback write result: $writeSuccess" -IsDebug
            }
            Write-Log -Message "*** USER CONTEXT TASK EXITING ***"
            
            # Clean up marker file using centralized function
            $markerRemoved = Remove-MarkerFile -FilePath $markerFile -Description "User detection completion marker"
            if (-not $markerRemoved) {
                Write-Log -Message "WARNING: Failed to clean up completion marker file: $markerFile" -IsDebug
            }
            
            # Perform final marker file cleanup for user context task
            Write-Log -Message "Performing final marker file cleanup for user context task" -IsDebug
            Invoke-MarkerFileEmergencyCleanup -Reason "User context task completion"
            exit 0
            
        } elseif (Test-RunningAsSystem) {
            Write-Log -Message "DEBUG: *** TAKING SYSTEM CONTEXT MAIN EXECUTION PATH ***" -IsDebug
            # SYSTEM context main execution - check system apps first, only run user detection if none found
            $systemApps = $contextApps
            Write-Log -Message "System detection found $($systemApps.Count) apps: $($systemApps -join ', ')"
            
            # PERFORMANCE OPTIMIZATION: Exit immediately if system apps are found
            if ($systemApps.Count -gt 0) {
                Write-Log -Message "[$ScriptTag] System apps found - skipping user detection for faster execution"
                Write-Log -Message "[$ScriptTag] System apps: $($systemApps -join '|')"
                Write-Log -Message "[$ScriptTag] Total apps found: $($systemApps.Count) (system only, user detection skipped)"
                Write-Log -Message "Performing marker file cleanup before exit (system apps found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "System apps found, triggering remediation"
                exit 1  # Trigger remediation immediately
            }
            
            # Only run user detection if no system apps were found AND interactive session exists
            Write-Log -Message "No system apps found - checking for interactive session before user context detection"
            if (-not (Test-InteractiveSession)) {
                Write-Log -Message "[$ScriptTag] No interactive session detected - skipping user context detection"
                Write-Log -Message "[$ScriptTag] No upgrades available in any context (no system apps, no interactive session)"
                Write-Log -Message "Performing marker file cleanup before exit (no interactive session)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "No interactive session"
                exit 0
            }

            Write-Log -Message "Interactive session confirmed - proceeding with user context detection"
            Write-Log -Message "DEBUG: About to call Invoke-UserContextDetection function" -IsDebug
            $userApps = Invoke-UserContextDetection
            Write-Log -Message "DEBUG: Invoke-UserContextDetection returned $($userApps.Count) apps" -IsDebug
            Write-Log -Message "User detection found $($userApps.Count) apps: $($userApps -join ', ')"
            
            if ($userApps.Count -gt 0) {
                Write-Log -Message "[$ScriptTag] User apps found: $($userApps -join '|')"
                Write-Log -Message "[$ScriptTag] Total apps found: $($userApps.Count) (user only, no system apps)"
                Write-Log -Message "Performing marker file cleanup before exit (user apps found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "User apps found, triggering remediation"
                exit 1  # Trigger remediation
            } else {
                Write-Log -Message "[$ScriptTag] No upgrades available in any context"
                Write-Log -Message "Performing marker file cleanup before exit (no upgrades found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "No upgrades available in any context"
                exit 0
            }
            
        } else {
            Write-Log -Message "DEBUG: *** TAKING DIRECT USER CONTEXT EXECUTION PATH ***" -IsDebug
            Write-Log -Message "DEBUG: This path is for direct user context execution (not scheduled task)" -IsDebug
            # Direct user context execution
            if ($contextApps.Count -gt 0) {
                Write-Log -Message "[$ScriptTag] User context apps found: $($contextApps -join '|')"
                Write-Log -Message "Performing marker file cleanup before exit (direct user context apps found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "Direct user context apps found"
                exit 1  # Trigger remediation
            } else {
                Write-Log -Message "[$ScriptTag] No user context upgrades available"
                Write-Log -Message "Performing marker file cleanup before exit (no user context upgrades)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "No user context upgrades available"
                exit 0
            }
        }
    }
    
    Write-Log -Message "[$ScriptTag] No apps found in winget output"
    # Cleanup marker files before exit
    Write-Log -Message "Performing final marker file cleanup before script exit" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (no apps found)"
    exit 0
} else {
    Write-Log -Message "[$ScriptTag] No winget output received"
    # Cleanup marker files before exit
    Write-Log -Message "Performing final marker file cleanup before script exit" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (no winget output)"
    exit 0
}
