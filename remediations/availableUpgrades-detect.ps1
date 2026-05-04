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
    Version: 5.45
    Tag: 75
    
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
    5.25 - ENHANCEMENT: Detection output now reports deferred apps with their deadline in the script tag message, providing visibility into postponed updates in Intune logs
    5.26 - FIX: Fixed whitelist loading via iex bootstrapper - added global scope fallback for $whitelistUrl and TLS 1.2 enforcement for WebClient downloads
    5.27 - FIX: Replaced WebClient.DownloadString with Invoke-RestMethod for whitelist loading to avoid AV/AMSI blocks
    5.28 - FIX: Fixed winget output validation to handle stderr ErrorRecord objects and trailing whitespace; improved retry log message for source updates
    5.29 - FEATURE: Added category-based whitelist defaults; supports new { CategoryDefaults, Apps } JSON structure with backward compatibility for legacy flat array format
    5.30 - FIX: Detection script now cleans up stale temp files and orphaned scheduled tasks from both detection and remediation scripts; expanded Remove-OldTempFiles to scan user temp directories with 10-minute cutoff; added Remove-StaleScheduledTasks to remove orphaned tasks from all known prefixes; ensures cleanup runs every Intune check cycle even when remediation is not triggered
    5.31 - FIX: Added --scope user dual-listing to SYSTEM context detection so apps like Perplexity.Comet (user-scoped in winget but installed to Program Files) are detected and trigger remediation in SYSTEM context
    5.32 - REVERT: Removed --scope user from SYSTEM context detection — SYSTEM cannot see user-registered winget packages; user context detection already handles this via scheduled task
    5.33 - FIX: User-context detection now runs BOTH the default `winget upgrade` listing AND `--scope user`, then merges by AppID. Previously it only ran `--scope user`, which misses apps like Mozilla.Firefox that winget tracks under the user account but installs machine-wide (C:\Program Files). Such apps were invisible to BOTH SYSTEM (per-user tracking gap) and user `--scope user` (filter excludes machine-installed binaries), so detection never reported them and remediation was never triggered. Mirrors the dual-listing logic remediate.ps1 has used since v9.11.
    5.34 - REFACTOR: Detection now writes a static task file (C:\ProgramData\Temp\availableUpgrades-tasks.json) listing the upgrades it found, so remediate.ps1 can use it as an authoritative work list and skip its own discovery pass. ConvertFrom-WingetOutput now returns full records (AppID + CurrentVersion + AvailableVersion) so the task file carries version info for dialogs without a second winget query. Added Get-RecordAppId and Format-AppList helpers to keep logging readable across the heterogeneous record types (string, hashtable, PSCustomObject from ConvertFrom-Json).
    5.35 - FEATURE: Each task entry now records InstalledScope (machine/user/unknown) determined via the registry uninstall keys (HKLM + HKU\SID under SYSTEM, HKLM + HKCU under user). Lets remediate.ps1 route entries to the right context without re-walking the registry per app. Get-AppInstalledScope ported from remediate.ps1 with HKCU support added for the user-context path.
    5.36 - FIX: SYSTEM-context flow was deleting the task file and reporting "No upgrades available" even when user-context detection found apps. Two issues: (a) PS5.1's ConvertFrom-Json unwraps single-element arrays, so $results.Apps for one task became a bare PSCustomObject with no .Count property, making `.Count -gt 0` false; (b) Invoke-UserContextDetection's return value was polluted by unsuppressed Write-Log output and cmdlet objects, so $userApps was a heterogeneous mix rather than just the apps. Both fixed: @() wrap inside the function for array context, and a Where-Object filter at the call site to keep only records that have an AppID.
    5.37 - FIX: Get-AppInstalledScope was silently returning "unknown" for Firefox when called from SYSTEM-context Write-UpgradeTaskFile (task file showed InstalledScope="unknown" despite Firefox being in HKLM uninstall). Replaced the `Get-ChildItem | Get-ItemProperty | Where-Object` pipeline with the more robust `Get-ItemProperty <path>\*` wildcard form — empirically the pipeline can short-circuit silently in some SYSTEM-context environments, the wildcard form does not. Also added match-count diagnostic logging (machine matches=N, user matches=N -> scope) so future drift is visible in the log without needing to instrument.
    5.38 - FIX: SYSTEM-context detection no longer skips user-context detection when system apps are found. The v5.19 "performance optimization" caused the task file to omit user-scoped upgrades on any machine that also had a system-scoped upgrade pending, leaving them indefinitely undone (remediate.ps1 now relies solely on the task file). New flow: always run user-context detection when an interactive session exists, then merge system + user records by AppID into a single task file. SYSTEM record wins on AppID conflict so the more accurate InstalledScope (HKLM + HKU\SID) is preserved.
    5.39 - FIX: Detection script's last stdout line is now always the [ScriptTag] summary so Intune reads the right detection result. Previously Write-UpgradeTaskFile and Remove-UpgradeTaskFile (both non-debug) ran AFTER the summary, so on some runs the final visible line was "Wrote upgrade task file with N tasks" or "Removed upgrade task file" instead of the upgrade-list/no-upgrade summary, which Intune surfaces as the detection state. Reordered all four main exit paths (SYSTEM merged-apps, SYSTEM no-apps, direct-user apps-found, direct-user no-apps, plus the no-winget-output path) to do task-file IO first and emit the [ScriptTag] line last.
    5.40 - FIX: Get-AppInstalledScope was returning "unknown" for apps like Google.Chrome whose registry layout doesn't fit the simple "DisplayName contains FriendlyName, hive determines scope" model. Two improvements: (a) search by multiple terms — FriendlyName plus AppID parts (e.g. "Google Chrome", "Chrome", "Google") — so apps where the whitelist FriendlyName doesn't substring-match the registry DisplayName are still found; (b) use InstallLocation as the authoritative scope signal. A binary in C:\Users\...\AppData\... is per-user even when the uninstall key sits in HKLM, and a Program Files install is machine-wide even when the uninstall key sits in HKCU. Hive membership is now only the fallback when InstallLocation is empty. When both scopes show installs, prefer "machine" so SYSTEM remediation runs (covers the Program Files binary; the per-user copy comes along via the same upgrade).
    5.41 - PERF: Orphan marker cleanup at startup no longer calls Get-InteractiveUser to find the user temp dir — replaced with a disk enumeration of C:\Users\* (skipping well-known non-user profile dirs). The CIM-based user detection costs ~7s on Azure AD machines and was the first thing every Intune cycle paid for; disk enumeration is sub-millisecond and additionally catches orphans from any user profile rather than just the active one.
    5.42 - FIX: Get-AppInstalledScope returned "unknown" for Notepad++ (and likely other apps) on ARM64 because the `Get-ItemProperty <basepath>\*` wildcard form silently returned $null when -ErrorAction SilentlyContinue swallowed a single bad subkey. Replaced with explicit per-subkey enumeration: Get-ChildItem to list subkeys, then Get-ItemProperty per subkey wrapped in try/catch so individual unreadable entries don't abort the whole walk. Also extended the match function to check PSChildName (the literal subkey name, e.g. "Notepad++") in addition to DisplayName, providing a second signal when DisplayName is missing or formatted unexpectedly. Confirmed via diagnostic log line "machine hits=0, user hits=0" for Notepad++.Notepad++ that the previous walk found nothing.
    5.43 - FIX: Notepad++ still returned "unknown" after v5.42 because the underlying problem was WoW64 redirection, not enumeration. When this script runs in a 32-bit PowerShell host (Intune Remediation policies default to 32-bit unless "Run script in 64-bit PowerShell host" is enabled), accesses to HKLM:\SOFTWARE\... are silently redirected to WOW6432Node, hiding native 64-bit and ARM64 uninstall entries entirely. Listing WOW6432Node explicitly didn't help — that's still the same redirected view a 32-bit process gets when reading SOFTWARE\. Switched the registry walk to [Microsoft.Win32.RegistryKey]::OpenBaseKey() with explicit Registry64 and Registry32 views for HKLM, and Default view for HKU/HKCU (user hives have no 32/64 split). This bypasses the WoW64 redirector and guarantees both views are read regardless of host process architecture. Diagnostic log line now also includes [32-bit host] / [64-bit host] for visibility.
    5.44 - PERF: Two cost reductions. (a) Get-InteractiveUser now uses Get-Process explorer -IncludeUserName as the PRIMARY detection method (~50ms) and falls back to Win32_ComputerSystem (~5s) only when Explorer isn't running. Explorer is the desktop shell so its owner is by definition the interactive user — same answer as the WMI Username property in 99%+ of sessions, much faster. (b) Whitelist fetch now uses an on-disk cache (C:\ProgramData\Temp\availableUpgrades-whitelist.cache.*) with a 60-min TTL plus ETag/If-Modified-Since revalidation. Within the TTL window we skip the network entirely; after TTL we send If-None-Match and reuse the cached body on a 304. Reduces external dependency from once-per-cycle to at most once-per-hour. Stale cache is also used as a fallback when the network is unavailable.
    5.45 - TUNE: Whitelist cache TTL bumped from 60 min to 36 hours (2160 min). At a once-a-day client cadence the 60-min default never reached the fast-path (cache always >60 min old at next run, always revalidated). 36 h is comfortably longer than a daily cycle including check-in jitter, so the fast-path normally hits and we skip the network entirely. Whitelist edits propagate within ~1.5 days worst case.

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

function Remove-OldTempFiles {
    <#
    .SYNOPSIS
        Cleans up stale temp files created by detection and remediation scripts
    .DESCRIPTION
        Scans C:\ProgramData\Temp and all user temp directories for leftover files
        from both the detection and remediation scripts (VBS launchers, dialog scripts,
        response files, etc.). Uses a 10-minute cutoff since these files are only
        needed while a dialog or task is active.
    #>
    # 10-minute cutoff: these files are only needed while a task/dialog is active.
    # Anything older is leftover from a previous run and safe to remove.
    $cutoff = (Get-Date).AddMinutes(-10)
    $removed = 0

    # Match file patterns from both detection and remediation scripts
    # Using regex instead of -Filter because Windows filter matching is unreliable with multiple dots (e.g. .ps1.userdetection)
    $nameRegex = '^(UserDetection_(Fallback_)?\d+\.json$|availableUpgrades-detect_\d+\.ps1|availableUpgrades-remediate_\d+\.ps1|UserRemediation_\d+\.|UserRemediationHeartbeat_|MandatoryPrompt_.*_(Response|Progress)|Show-MandatoryPrompt_|DeferralPrompt_.*_Response|Show-DeferralPrompt_|UserPrompt_.*_Response|Show-UserPrompt_|UpgradeProgress_.*_(Signal|Status)|Show-UpgradeProgress_|CompletionNotification_|Show-CompletionNotification_|SkipPrompt_.*_Response|Show-SkipPrompt_|UserContext_Debug|UserContext_Heartbeat_Error_|HiddenLaunch_\d+\.vbs$)'

    # Scan C:\ProgramData\Temp
    $tempPath = "C:\ProgramData\Temp"
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $nameRegex -and $_.LastWriteTime -lt $cutoff } |
            ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $removed++
            }
    }

    # Scan user temp directories for VBS launchers and dialog script/response files
    try {
        $userTempPaths = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "AppData\Local\Temp" } |
            Where-Object { Test-Path $_ }

        foreach ($userTemp in $userTempPaths) {
            Get-ChildItem -Path $userTemp -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $nameRegex -and $_.LastWriteTime -lt $cutoff } |
                ForEach-Object {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    $removed++
                }
        }
    } catch {
        # Don't let user temp cleanup failures block the main script
    }

    if ($removed -gt 0) {
        Write-Log -Message "Cleaned up $removed old temp files"
    }
}

function Remove-StaleScheduledTasks {
    <#
    .SYNOPSIS
        Removes orphaned scheduled tasks left behind by previous script executions
    .DESCRIPTION
        Sweeps Task Scheduler for tasks matching known prefixes from both detection
        and remediation scripts. Handles cases where cleanup never ran (process
        terminated or remediation not triggered).
    #>
    param(
        [int]$MaxAgeMinutes = 10
    )

    $prefixes = @(
        "UserPrompt_",
        "UpgradeProgress_",
        "CompletionNotification_",
        "MandatoryPrompt_",
        "DeferralPrompt_",
        "SkipPrompt_",
        "UserRemediation_",
        "UserDetection_"
    )

    try {
        $cutoff = (Get-Date).AddMinutes(-$MaxAgeMinutes)
        $allTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue
        if (-not $allTasks) { return 0 }

        $removed = 0
        foreach ($task in $allTasks) {
            $matched = $false
            foreach ($prefix in $prefixes) {
                if ($task.TaskName.StartsWith($prefix)) {
                    $matched = $true
                    break
                }
            }
            if (-not $matched) { continue }

            try {
                $taskDate = [datetime]::Parse($task.Date)
                if ($taskDate -lt $cutoff) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                    $removed++
                }
            } catch {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                $removed++
            }
        }

        if ($removed -gt 0) {
            Write-Log -Message "Cleaned up $removed stale scheduled tasks (older than $MaxAgeMinutes minutes)"
        }
        return $removed
    } catch {
        return 0
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
            
            # Enumerate user profile temp dirs from disk instead of calling Get-InteractiveUser.
            # The CIM-based user detection costs ~7s on Azure AD machines and we'd be paying it
            # at the very start of every Intune cycle just to find one path; disk enumeration
            # is sub-millisecond and also catches orphans from any user profile, not just the
            # currently active one. Skip well-known non-user profile dirs.
            try {
                $skipProfiles = @('Default', 'Default User', 'DefaultUser', 'All Users', 'Public', 'defaultuser0', 'WDAGUtilityAccount')
                Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skipProfiles -notcontains $_.Name } |
                    ForEach-Object {
                        $userTemp = Join-Path $_.FullName 'AppData\Local\Temp'
                        if ((Test-Path $userTemp) -and ($ScanLocations -notcontains $userTemp)) {
                            $ScanLocations += $userTemp
                        }
                    }
            } catch {
                # Ignore — orphan cleanup is best-effort
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

function New-HiddenLaunchAction {
    <#
    .SYNOPSIS
        Creates a scheduled task action that launches PowerShell without any visible window flash.
    .DESCRIPTION
        Uses wscript.exe with a temporary VBS launcher instead of cmd.exe.
        wscript.exe is a GUI subsystem application and never creates a console window,
        eliminating the brief window flash that cmd.exe /c start /min causes.
    .PARAMETER PowerShellArguments
        The full PowerShell command-line arguments (e.g. "-NoProfile -WindowStyle Hidden -File ...")
    .PARAMETER VbsDirectory
        Directory where the temporary VBS launcher file will be created
    .OUTPUTS
        Hashtable with Action (ScheduledTaskAction) and VbsPath (for cleanup)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PowerShellArguments,

        [Parameter(Mandatory=$true)]
        [string]$VbsDirectory
    )

    try {
        # Ensure directory exists
        if (-not (Test-Path $VbsDirectory)) {
            New-Item -Path $VbsDirectory -ItemType Directory -Force | Out-Null
        }

        $vbsPath = Join-Path $VbsDirectory "HiddenLaunch_$(Get-Random).vbs"

        # Escape double quotes for VBS string (VBS uses "" to escape quotes)
        $escapedArgs = $PowerShellArguments.Replace('"', '""')
        $vbsContent = "CreateObject(""WScript.Shell"").Run ""$escapedArgs"", 0, True"

        $vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII -Force

        Write-Log "Created VBS hidden launcher: $vbsPath" -IsDebug

        return @{
            Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument """$vbsPath"""
            VbsPath = $vbsPath
        }
    } catch {
        Write-Log "ERROR: Failed to create hidden launch action: $($_.Exception.Message)"
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
        
        Write-Log "Detecting interactive user..."

        # Primary: Get-Process explorer -IncludeUserName. Typically ~50ms vs several seconds
        # for Win32_ComputerSystem on Azure AD machines. Explorer is the desktop shell so its
        # owner is by definition the interactive user. WMI is now only the fallback for cases
        # where Explorer isn't running (e.g. session not yet fully initialized).
        $loggedInUser = $null
        try {
            $explorerProc = Get-Process explorer -IncludeUserName -ErrorAction Stop |
                Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1
            if ($explorerProc -and $explorerProc.UserName) {
                $loggedInUser = $explorerProc.UserName
                Write-Log "Explorer-based detection successful - User: $loggedInUser"
            }
        } catch {
            Write-Log "Explorer-based detection unavailable: $($_.Exception.Message) - trying Win32_ComputerSystem fallback..."
        }

        # Fallback: Win32_ComputerSystem (slower, but works when Explorer isn't running yet)
        if (-not $loggedInUser) {
            try {
                $loggedInUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object username -ExpandProperty username
                if ($loggedInUser) {
                    Write-Log "Win32_ComputerSystem fallback successful - User: $loggedInUser"
                }
            } catch {
                Write-Log "Win32_ComputerSystem fallback failed: $($_.Exception.Message)"
            }
        }

        if (-not $loggedInUser) {
            $Message = "User is not logged on to the primary session: neither Explorer nor Win32_ComputerSystem returned a user"
            Write-Log $Message
            Throw $Message
        }

        $username = ($loggedInUser -split '\\')[1]
        $domain = ($loggedInUser -split '\\')[0]

        Write-Log "Found logged in user: $loggedInUser"
        Write-Log "Extracted username: $username"
        Write-Log "Extracted domain: $domain"
        
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

function Get-AppInstalledScope {
    <#
    .SYNOPSIS
        Detects whether an app is installed per-user or machine-wide via the Windows
        uninstall registry. Returns "user", "machine", or "unknown".
    .DESCRIPTION
        Scans HKLM (machine-wide) and the current user's HKU/HKCU (user-scope) uninstall
        keys for entries whose DisplayName matches one of several search terms derived
        from the FriendlyName and the AppID (e.g. "Google.Chrome" -> "Google Chrome",
        "Chrome", "Google"). For each match found the function then inspects
        InstallLocation as the authoritative scope signal — a binary living in the user
        profile is per-user even if the uninstall key happens to be in HKLM, and a
        Program Files install is machine-wide even if the uninstall key is in HKCU
        (Chrome and similar apps that mix per-user winget metadata with machine binaries).
        Hive membership is used only as a fallback when InstallLocation is empty.
        - From SYSTEM context the user hive is reached via HKU\<interactive-user-SID>.
        - From user context HKCU is the current user's own hive.
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName
    )

    try {
        # Build a list of candidate DisplayName fragments. Order matters only for the log
        # line; the search is OR-across-terms.
        $searchTerms = New-Object System.Collections.Generic.List[string]
        if ($FriendlyName) { [void]$searchTerms.Add($FriendlyName) }
        if ($AppID) {
            $idParts = $AppID -split '\.'
            if ($idParts.Count -gt 1) {
                [void]$searchTerms.Add(($idParts -join ' '))   # "Google Chrome"
                [void]$searchTerms.Add($idParts[-1])           # "Chrome"
                [void]$searchTerms.Add($idParts[0])            # "Google" (catches publisher-prefixed DisplayNames)
            } else {
                [void]$searchTerms.Add($AppID)
            }
        }
        $searchTerms = @($searchTerms | Where-Object { $_ } | Select-Object -Unique)

        $matchEntry = {
            param($e)
            foreach ($t in $searchTerms) {
                if ($e.DisplayName -and $e.DisplayName -like "*$t*") { return $true }
                # Also match the subkey name itself — for many apps (e.g. "Notepad++") the
                # uninstall key is literally named after the product. This is a second signal
                # independent of DisplayName, useful when DisplayName is missing or differs.
                if ($e.PSChildName -and $e.PSChildName -like "*$t*") { return $true }
            }
            return $false
        }

        # Walk uninstall registry via the .NET RegistryKey API with explicit registry views,
        # bypassing the WoW64 redirector. Critical on ARM64 / 64-bit Windows when this script
        # runs in a 32-bit PowerShell host (e.g. Intune Remediation with "Run as 64-bit"
        # toggled off): in that case `HKLM:\SOFTWARE\...` access is silently redirected to
        # WOW6432Node, hiding native 64-bit (and ARM64) uninstall entries entirely. Reading
        # both Registry64 and Registry32 views guarantees we see entries regardless of host
        # process architecture. Per-subkey iteration with try/catch isolates malformed
        # entries that would otherwise abort a batch read.
        $walkUninstallHive = {
            param([Microsoft.Win32.RegistryKey]$Root)
            $hits = New-Object System.Collections.Generic.List[object]
            if (-not $Root) { return $hits }
            try {
                foreach ($subName in $Root.GetSubKeyNames()) {
                    try {
                        $subKey = $Root.OpenSubKey($subName)
                        if (-not $subKey) { continue }
                        try {
                            $entry = [pscustomobject]@{
                                PSChildName     = $subName
                                DisplayName     = $subKey.GetValue('DisplayName')
                                InstallLocation = $subKey.GetValue('InstallLocation')
                                Publisher       = $subKey.GetValue('Publisher')
                            }
                            if (& $matchEntry $entry) { [void]$hits.Add($entry) }
                        } finally { $subKey.Close() }
                    } catch {
                        # Skip individual unreadable subkeys
                    }
                }
            } finally { $Root.Close() }
            return $hits
        }

        $hostBits = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
        $machineHits = New-Object System.Collections.Generic.List[object]
        # Read both 64-bit and 32-bit views of HKLM\SOFTWARE\...\Uninstall — Registry64 is the
        # native ARM64/x64 view, Registry32 is the WOW6432Node 32-bit view.
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
                $root = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($root) {
                    foreach ($h in (& $walkUninstallHive $root)) { [void]$machineHits.Add($h) }
                }
                $base.Close()
            } catch {
                Write-Log "Scope detection: error opening LocalMachine ($view): $($_.Exception.Message)" | Out-Null
            }
        }

        # User-scope uninstall registry — open via the same explicit-view API so a 32-bit
        # host doesn't get redirected. From SYSTEM context we open the interactive user's
        # hive under HKEY_USERS\<SID>; from user context we open HKCU directly.
        $userHits = New-Object System.Collections.Generic.List[object]
        try {
            if (Test-RunningAsSystem) {
                $userInfo = Get-InteractiveUser
                if ($userInfo -and $userInfo.SID) {
                    $usersBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
                    $root = $usersBase.OpenSubKey("$($userInfo.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                    if ($root) {
                        foreach ($h in (& $walkUninstallHive $root)) { [void]$userHits.Add($h) }
                    }
                    $usersBase.Close()
                }
            } else {
                $hkcuBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Default)
                $root = $hkcuBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($root) {
                    foreach ($h in (& $walkUninstallHive $root)) { [void]$userHits.Add($h) }
                }
                $hkcuBase.Close()
            }
        } catch {
            Write-Log "Scope detection: error reading user hive: $($_.Exception.Message)" | Out-Null
        }

        # Authoritative signal: InstallLocation. A binary in C:\Users\...\AppData\... is
        # per-user; one in C:\Program Files... is machine-wide. Look at every matched
        # entry's path regardless of which hive it came from.
        $installLocHints = @{ machine = 0; user = 0 }
        $sampleLoc = ""
        foreach ($e in ($machineHits + $userHits)) {
            $loc = if ($e.PSObject.Properties['InstallLocation']) { [string]$e.InstallLocation } else { "" }
            if ([string]::IsNullOrWhiteSpace($loc)) { continue }
            if (-not $sampleLoc) { $sampleLoc = $loc }
            if ($loc -match '(?i)\\Users\\[^\\]+\\(AppData|Local|Roaming)\\' -or
                $loc -match '(?i)^[A-Z]:\\Users\\[^\\]+\\') {
                $installLocHints.user++
            } elseif ($loc -match '(?i)^[A-Z]:\\Program Files( \(x86\))?\\') {
                $installLocHints.machine++
            } elseif ($loc -match '(?i)\\ProgramData\\') {
                $installLocHints.machine++
            }
        }

        # Decision: InstallLocation wins when present; otherwise fall back to hive membership.
        $resolvedScope = "unknown"
        $decisionBy = "none"
        if ($installLocHints.machine -gt 0 -and $installLocHints.user -eq 0) {
            $resolvedScope = "machine"; $decisionBy = "InstallLocation"
        } elseif ($installLocHints.user -gt 0 -and $installLocHints.machine -eq 0) {
            $resolvedScope = "user"; $decisionBy = "InstallLocation"
        } elseif ($installLocHints.machine -gt 0 -and $installLocHints.user -gt 0) {
            # Both scopes installed — let SYSTEM handle it (machine wins) so the user
            # binary is also covered if Program Files is the active install.
            $resolvedScope = "machine"; $decisionBy = "InstallLocation(both)"
        } elseif ($machineHits.Count -gt 0 -and $userHits.Count -eq 0) {
            $resolvedScope = "machine"; $decisionBy = "hive"
        } elseif ($userHits.Count -gt 0 -and $machineHits.Count -eq 0) {
            $resolvedScope = "user"; $decisionBy = "hive"
        } elseif ($machineHits.Count -gt 0) {
            $resolvedScope = "machine"; $decisionBy = "hive(both)"
        }

        $sampleSuffix = if ($sampleLoc) { " sample='$sampleLoc'" } else { "" }
        Write-Log "Scope detection $AppID [$hostBits host] (terms='$($searchTerms -join '|')'): machine hits=$($machineHits.Count), user hits=$($userHits.Count), pathHints=m:$($installLocHints.machine)/u:$($installLocHints.user) -> $resolvedScope (by $decisionBy)$sampleSuffix" | Out-Null
        return $resolvedScope
    } catch {
        Write-Log "Scope detection error for $AppID : $($_.Exception.Message)" | Out-Null
        return "unknown"
    }
}

function Get-RecordAppId {
    <#
    .SYNOPSIS
        Extracts the AppID from an upgrade record regardless of whether it is a string,
        hashtable, or PSCustomObject (ConvertFrom-Json output).
    #>
    param($Record)
    if ($null -eq $Record) { return "" }
    if ($Record -is [string]) { return $Record }
    if ($Record -is [hashtable] -or $Record -is [System.Collections.IDictionary]) { return [string]$Record['AppID'] }
    if ($Record.PSObject -and $Record.PSObject.Properties['AppID']) { return [string]$Record.AppID }
    return ""
}

function Format-AppList {
    <#
    .SYNOPSIS
        Formats a heterogeneous app list (strings, hashtables, PSCustomObjects) as a
        comma-separated AppID string for logging — avoids "System.Collections.Hashtable" noise.
    #>
    param([object[]]$Apps)
    if (-not $Apps -or $Apps.Count -eq 0) { return "" }
    return (($Apps | ForEach-Object { Get-RecordAppId -Record $_ } | Where-Object { $_ }) -join ', ')
}

# Static task file shared between detect.ps1 and remediate.ps1.
# Detection writes this file when upgrades are found; remediation reads it as the
# authoritative work list and removes entries as they are processed (success or final-failure).
$Script:UpgradeTaskFile = "C:\ProgramData\Temp\availableUpgrades-tasks.json"

function Write-UpgradeTaskFile {
    <#
    .SYNOPSIS
        Writes the current set of detected upgrades to the static task file consumed by
        the remediation script. Overwrites any existing content.
    .PARAMETER Records
        Array of upgrade records (hashtables / PSCustomObjects with at least AppID;
        CurrentVersion / AvailableVersion / FriendlyName preserved when present).
    #>
    param([object[]]$Records)

    try {
        $taskDir = Split-Path -Parent $Script:UpgradeTaskFile
        if (-not (Test-Path $taskDir)) {
            New-Item -Path $taskDir -ItemType Directory -Force | Out-Null
        }

        $entries = @()
        foreach ($r in $Records) {
            if (-not $r) { continue }
            $appId = Get-RecordAppId -Record $r
            if ([string]::IsNullOrEmpty($appId)) { continue }
            $current = ""
            $available = ""
            $friendly = ""
            if ($r -is [hashtable] -or $r -is [System.Collections.IDictionary]) {
                $current = [string]$r['CurrentVersion']
                $available = [string]$r['AvailableVersion']
                $friendly = [string]$r['FriendlyName']
            } elseif ($r.PSObject) {
                if ($r.PSObject.Properties['CurrentVersion']) { $current = [string]$r.CurrentVersion }
                if ($r.PSObject.Properties['AvailableVersion']) { $available = [string]$r.AvailableVersion }
                if ($r.PSObject.Properties['FriendlyName']) { $friendly = [string]$r.FriendlyName }
            }
            # Determine the install scope so remediation can route the upgrade to the right context
            # without re-walking the registry per app.
            $scope = Get-AppInstalledScope -AppID $appId -FriendlyName $friendly
            $entries += [pscustomobject]@{
                AppID = $appId
                FriendlyName = $friendly
                CurrentVersion = $current
                AvailableVersion = $available
                InstalledScope = $scope
                DiscoveredAt = (Get-Date).ToString("o")
            }
        }

        $payload = [pscustomobject]@{
            Generated = (Get-Date).ToString("o")
            GeneratedByScriptTag = $ScriptTag
            Tasks = @($entries)
        }
        $payload | ConvertTo-Json -Depth 4 | Out-File -FilePath $Script:UpgradeTaskFile -Encoding UTF8 -Force
        Write-Log -Message "Wrote upgrade task file with $($entries.Count) tasks: $Script:UpgradeTaskFile"
    } catch {
        Write-Log -Message "ERROR writing upgrade task file: $($_.Exception.Message)"
    }
}

function Remove-UpgradeTaskFile {
    param([string]$Reason = "")
    try {
        if (Test-Path $Script:UpgradeTaskFile) {
            Remove-Item -Path $Script:UpgradeTaskFile -Force -ErrorAction Stop
            Write-Log -Message "Removed upgrade task file ($Reason): $Script:UpgradeTaskFile"
        }
    } catch {
        Write-Log -Message "ERROR removing upgrade task file: $($_.Exception.Message)"
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
        Write-Log "DEBUG: Apps list: $(Format-AppList $Apps)" -IsDebug
        
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
                $wingetExe = Join-Path $WingetPath "winget.exe"
                Write-Log "DEBUG: Executing winget --scope user from SYSTEM context..." -IsDebug
                $testOutput = $(& $wingetExe upgrade --accept-source-agreements --source winget --scope user 2>&1)
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
        $sourceSize = (Get-Item $Global:CurrentScriptPath).Length
        Write-Log "Source script size: $sourceSize bytes" | Out-Null

        # Detect bootstrapper/wrapper scenario (small file that downloads the real script via iex/irm)
        if ($sourceSize -lt 1000) {
            Write-Log "Source appears to be a bootstrapper wrapper ($sourceSize bytes) - downloading full script" | Out-Null
            try {
                $bootstrapContent = Get-Content $Global:CurrentScriptPath -Raw
                if ($bootstrapContent -match 'irm\s+[''"]([^''"]+)[''"]') {
                    $scriptUrl = $Matches[1]
                    Write-Log "Extracted download URL from bootstrapper: $scriptUrl" | Out-Null
                    $fullScript = Invoke-RestMethod -Uri $scriptUrl -ErrorAction Stop
                    $fullScript | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
                    $dlSize = (Get-Item $tempScriptPath).Length
                    Write-Log "Downloaded full script to temp: $dlSize bytes" | Out-Null
                } else {
                    Write-Log "ERROR: Could not extract download URL from bootstrapper content" | Out-Null
                    return @()
                }
            } catch {
                Write-Log "ERROR: Failed to download full script from bootstrapper URL: $($_.Exception.Message)" | Out-Null
                return @()
            }
        } else {
            Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force
        }
        
        $scriptPath = $tempScriptPath
        
        # Create a marker file to indicate this is a user detection task (workaround for parameter passing issues)
        # Include whitelistUrl so the user-context child process uses the same whitelist source
        $markerFile = "$tempScriptPath.userdetection"
        $markerContent = "USERDETECTION:$resultFile"
        if ($whitelistUrl) {
            $markerContent += "`nWHITELISTURL:$whitelistUrl"
        }
        $markerCreated = New-MarkerFile -FilePath $markerFile -Content $markerContent -Description "User detection task marker"
        
        if (-not $markerCreated) {
            Write-Log -Message "ERROR: Failed to create user detection marker file - user detection may not work properly"
        }
        
        # Create hidden launch action using VBS wrapper (no console window flash)
        $psArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $launch = New-HiddenLaunchAction -PowerShellArguments $psArgs -VbsDirectory $sharedTempPath
        if (-not $launch) {
            Write-Log "ERROR: Failed to create hidden launch action - falling back to direct PowerShell"
            $launch = @{
                Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
                VbsPath = $null
            }
        }

        Write-Log "Creating user detection task: $taskName" | Out-Null
        Write-Log "Script path: $scriptPath" | Out-Null
        Write-Log "Launch method: $(if ($launch.VbsPath) { 'VBS hidden launcher' } else { 'Direct PowerShell' })" | Out-Null
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
            # Use pre-created hidden launch action (VBS wrapper)
            $action = $launch.Action
            
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
            $timeout = 90  # Allow time for whitelist download + winget enumeration
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
                        # @() forces array context: PS5.1's ConvertFrom-Json unwraps single-element
                        # JSON arrays to a bare object, which then has no .Count property.
                        $apps = @($results.Apps)
                        Write-Log "DEBUG: Results object - Apps count: $($apps.Count), Context: $($results.Context), Username: $($results.Username)" -IsDebug | Out-Null
                        Write-Log "User detection completed: $($apps.Count) apps found" | Out-Null
                        if ($apps.Count -gt 0) {
                            Write-Log "DEBUG: User context apps found: $(Format-AppList $apps)" -IsDebug | Out-Null
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

                # Clean up VBS hidden launcher file
                if ($launch.VbsPath -and (Test-Path $launch.VbsPath)) {
                    Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed VBS hidden launcher: $($launch.VbsPath)" -IsDebug | Out-Null
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
$Script:TestMode = $false  # Set to $true to simulate finding an app update and trigger remediation
$ScriptTag = "75" # Update this tag for each script version
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

# Clean up stale temp files from previous runs (detection + remediation leftovers)
Remove-OldTempFiles

# Clean up orphaned scheduled tasks from previous runs (detection + remediation leftovers)
Remove-StaleScheduledTasks

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

# Scope-safe: pick up $whitelistUrl from parent/global scope (iex bootstrapper scenario)
if (-not $whitelistUrl -and $global:whitelistUrl) {
    $whitelistUrl = $global:whitelistUrl
    Write-Log -Message "Restored whitelistUrl from global scope: $whitelistUrl"
}

# Early marker file check — restore whitelistUrl BEFORE whitelist loading
# (scheduled task child process needs this to use the correct whitelist source)
if ($MyInvocation.MyCommand.Path) {
    $earlyMarkerFile = "$($MyInvocation.MyCommand.Path).userdetection"
    if (Test-Path $earlyMarkerFile) {
        try {
            $earlyMarkerContent = Get-Content $earlyMarkerFile -Raw
            if ($earlyMarkerContent -match "WHITELISTURL:(.+)") {
                $whitelistUrl = $matches[1].Trim()
                Write-Log -Message "Restored whitelistUrl from marker file: $whitelistUrl"
            }
        } catch { }
    }
}

function Get-CachedWhitelistJSON {
    <#
    .SYNOPSIS
        Fetches whitelist JSON from a URL using a local cache with TTL + ETag revalidation.
    .DESCRIPTION
        Cache lives at C:\ProgramData\Temp\availableUpgrades-whitelist.cache.json with a
        sibling .meta.json holding the source URL, ETag, and timestamp.
        - Within $TtlMinutes of the last successful fetch: skip network entirely.
        - After TTL: revalidate via If-None-Match. 304 -> use cache; 200 -> save new body.
        - On network failure with a stale cache present: use the stale copy.
        - On network failure with no cache: return $null (caller falls back to hardcoded).
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TtlMinutes = 2160,   # 36 hours — longer than a daily cycle so the fast-path normally hits
        [string]$CachePath = "C:\ProgramData\Temp\availableUpgrades-whitelist.cache.json"
    )

    $metaPath = "$CachePath.meta.json"
    $cachedJson = $null
    $cachedEtag = $null
    $cacheAge = $null

    if ((Test-Path $CachePath) -and (Test-Path $metaPath)) {
        try {
            $meta = Get-Content -Path $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            if ($meta.Url -eq $Url -and $meta.Timestamp) {
                $cachedJson = Get-Content -Path $CachePath -Raw -Encoding UTF8
                $cachedEtag = $meta.ETag
                $cacheAge = (Get-Date) - [datetime]$meta.Timestamp
            }
        } catch { }
    }

    # Fresh cache window — skip network entirely.
    if ($cachedJson -and $cacheAge -and $cacheAge.TotalMinutes -lt $TtlMinutes) {
        Write-Log -Message "Using cached whitelist (age $([Math]::Round($cacheAge.TotalMinutes, 1)) min, TTL $TtlMinutes min)"
        return $cachedJson
    }

    # TTL expired (or no cache): revalidate / fetch.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $headers = @{ 'User-Agent' = 'PowerShell-WingetScript' }
    if ($cachedEtag) { $headers['If-None-Match'] = $cachedEtag }

    try {
        $resp = Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -ErrorAction Stop
        $newJson = $resp.Content
        $newEtag = $resp.Headers['ETag']
        if ($newEtag -is [array]) { $newEtag = $newEtag[0] }
        Write-Log -Message "Fetched whitelist from $Url ($($newJson.Length) bytes)"

        try {
            $cacheDir = Split-Path -Parent $CachePath
            if ($cacheDir -and -not (Test-Path $cacheDir)) { New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null }
            $newJson | Out-File -FilePath $CachePath -Encoding UTF8 -Force
            @{ Url = $Url; ETag = $newEtag; Timestamp = (Get-Date).ToString('o') } |
                ConvertTo-Json | Out-File -FilePath $metaPath -Encoding UTF8 -Force
        } catch {
            Write-Log -Message "Whitelist cache write failed (non-fatal): $($_.Exception.Message)"
        }
        return $newJson
    } catch {
        # 304 Not Modified: PowerShell treats it as an exception. Reuse cache and refresh
        # the timestamp so the next TTL window starts now.
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        if ($statusCode -eq 304 -and $cachedJson) {
            Write-Log -Message "Whitelist unchanged on server (304) — reusing cache"
            try {
                @{ Url = $Url; ETag = $cachedEtag; Timestamp = (Get-Date).ToString('o') } |
                    ConvertTo-Json | Out-File -FilePath $metaPath -Encoding UTF8 -Force
            } catch { }
            return $cachedJson
        }
        Write-Log -Message "Whitelist fetch failed: $($_.Exception.Message)"
        if ($cachedJson) {
            Write-Log -Message "Falling back to stale whitelist cache"
            return $cachedJson
        }
        return $null
    }
}

# Load whitelist configuration with priority: Local file > GitHub (cached) > Hardcoded fallback
$whitelistJSON = $null
$localWhitelistPath = $null
if ($MyInvocation.MyCommand.Path) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $localWhitelistPath = Join-Path $scriptDirectory "app-whitelist.json"
}

# First, try to load from local file
if ($localWhitelistPath -and (Test-Path $localWhitelistPath)) {
    try {
        Write-Log -Message "Loading whitelist configuration from local file: $localWhitelistPath"
        $whitelistJSON = Get-Content -Path $localWhitelistPath -Raw -Encoding UTF8
        Write-Log -Message "Successfully loaded local whitelist configuration"
    } catch {
        Write-Log -Message "Error reading local whitelist file: $($_.Exception.Message)"
        $whitelistJSON = $null
    }
}

# If no local file or local file failed, fetch from GitHub via the cache helper.
# The cache (C:\ProgramData\Temp\availableUpgrades-whitelist.cache.*) keeps a copy of the
# last response plus its ETag; for the next TTL window we skip the network call entirely,
# and after that we revalidate with If-None-Match (a 304 response means we keep using the
# cached body). Significantly reduces external dependency on every Intune cycle.
if ([string]::IsNullOrEmpty($whitelistJSON)) {
    if (-not $whitelistUrl) {
        $whitelistUrl = "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/app-whitelist.json"
    }
    $whitelistJSON = Get-CachedWhitelistJSON -Url $whitelistUrl
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
    $parsedWhitelist = $whitelistJSON | ConvertFrom-Json -ErrorAction Stop

    # Support both new format { CategoryDefaults, Apps } and legacy flat array
    if ($parsedWhitelist.Apps) {
        $categoryDefaults = @{}
        if ($parsedWhitelist.CategoryDefaults) {
            $parsedWhitelist.CategoryDefaults.PSObject.Properties | ForEach-Object {
                $categoryDefaults[$_.Name] = $_.Value
            }
            Write-Log -Message "Loaded category defaults for: $($categoryDefaults.Keys -join ', ')"
        }

        $whitelistConfig = $parsedWhitelist.Apps | ForEach-Object {
            $app = $_
            $category = $app.Category
            if ($category -and $categoryDefaults.ContainsKey($category)) {
                $defaults = $categoryDefaults[$category]
                # Merge: category defaults first, then app-level properties override
                $defaults.PSObject.Properties | ForEach-Object {
                    $propName = $_.Name
                    # Only apply default if the app doesn't already define this property
                    if ($null -eq $app.PSObject.Properties[$propName]) {
                        $app | Add-Member -NotePropertyName $propName -NotePropertyValue $_.Value -Force
                    }
                }
            }
            $app
        }
        Write-Log -Message "Loaded whitelist with category support ($($whitelistConfig.Count) apps)"
    } else {
        # Legacy flat array format
        $whitelistConfig = $parsedWhitelist
        Write-Log -Message "Loaded legacy whitelist format ($($whitelistConfig.Count) apps)"
    }

    $whitelistConfig = $whitelistConfig | Where-Object { ($_.Disabled -eq $null -or $_.Disabled -eq $false) }
    Write-Log -Message "Successfully loaded whitelist configuration with $($whitelistConfig.Count) enabled apps"
} catch {
    Write-Log -Message "Error parsing whitelist JSON: $($_.Exception.Message)"
    Write-Log -Message "Performing marker file cleanup before exit due to whitelist error" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "Whitelist parsing error"
    exit 1
}

function Invoke-WingetUpgradeList {
    <#
    .SYNOPSIS
        Runs winget upgrade and returns the raw output, with validation and retry.
    .PARAMETER WingetExe
        Full path to winget.exe. If not specified, uses winget from PATH.
    .PARAMETER Scope
        Optional scope filter (e.g. "user"). If not specified, no scope filter is applied.
    #>
    param(
        [string]$WingetExe = "winget.exe",
        [string]$Scope = ""
    )

    $wingetArgs = @("upgrade", "--accept-source-agreements", "--source", "winget")
    if ($Scope) { $wingetArgs += "--scope"; $wingetArgs += $Scope }

    Write-Log -Message "Running: $WingetExe $($wingetArgs -join ' ')"
    # First run may return only source-update progress output; discard stderr to avoid capturing spinner
    $output = & $WingetExe @wingetArgs 2>$null

    # Validate output contains a separator line (row of dashes below the header)
    $hasSeparator = $false
    foreach ($line in $output) {
        if ($line -is [string] -and $line.Trim() -match '^-{10,}$') { $hasSeparator = $true; break }
    }

    if (-not $hasSeparator) {
        Write-Log -Message "Winget source update in progress, running again..."
        $output = & $WingetExe @wingetArgs 2>$null
    }

    return $output
}

function ConvertFrom-WingetOutput {
    <#
    .SYNOPSIS
        Parses winget upgrade text output into structured app objects.
    .DESCRIPTION
        Uses the separator line (dashes) to locate the header, then extracts
        column positions from the header text. Locale-safe header detection.
    .PARAMETER Output
        The raw winget output lines.
    #>
    param([array]$Output)

    if (-not $Output -or $Output.Count -eq 0) { return @() }

    # Find the separator line (row of dashes) - this is locale-safe
    $separatorIndex = -1
    for ($i = 0; $i -lt $Output.Count; $i++) {
        if ($Output[$i] -match '^-{10,}$') {
            $separatorIndex = $i
            break
        }
    }

    if ($separatorIndex -lt 1) {
        Write-Log -Message "No separator line found in winget output"
        return @()
    }

    $headerLine = $Output[$separatorIndex - 1]
    Write-Log -Message "DEBUG: Header line: $headerLine" -IsDebug
    Write-Log -Message "DEBUG: Separator at line $separatorIndex" -IsDebug

    # Find column positions from header - use word boundaries to avoid substring matches
    # Match column names at their exact positions by finding each column header word
    $columns = @{}
    foreach ($col in @("Id", "Version", "Available", "Source")) {
        # Find the column position - must be preceded by whitespace (or be at start) to avoid matching substrings
        $pos = -1
        for ($p = 0; $p -le $headerLine.Length - $col.Length; $p++) {
            $substr = $headerLine.Substring($p, $col.Length)
            if ($substr -ceq $col) {
                # Check it's a real column header: preceded by space (or start) and followed by space (or end)
                $prevOk = ($p -eq 0) -or ($headerLine[$p - 1] -eq ' ')
                $nextOk = ($p + $col.Length -ge $headerLine.Length) -or ($headerLine[$p + $col.Length] -eq ' ')
                if ($prevOk -and $nextOk) { $pos = $p; break }
            }
        }
        if ($pos -ge 0) { $columns[$col] = $pos }
    }

    if (-not $columns.ContainsKey("Id")) {
        Write-Log -Message "Could not find Id column in header: $headerLine"
        return @()
    }

    $idPos = $columns["Id"]
    $idEnd = if ($columns.ContainsKey("Version")) { $columns["Version"] - 1 } else { $headerLine.Length - 1 }
    $versionPos = if ($columns.ContainsKey("Version")) { $columns["Version"] } else { -1 }
    $availablePos = if ($columns.ContainsKey("Available")) { $columns["Available"] } else { -1 }
    $sourcePos = if ($columns.ContainsKey("Source")) { $columns["Source"] } else { -1 }

    Write-Log -Message "Column positions - Id: $idPos, end: $idEnd, Version: $versionPos, Available: $availablePos"

    $apps = [System.Collections.ArrayList]::new()
    for ($i = $separatorIndex + 1; $i -lt $Output.Count; $i++) {
        $line = $Output[$i]
        # Stop at empty lines, summary lines, or the "require explicit targeting" section
        if ($line.Trim() -eq "" -or $line -match 'upgrades? available' -or $line -match 'following packages') {
            break
        }
        if ($line.Length -le $idPos) { continue }

        $appId = ($line[$idPos..$idEnd] -join "").Trim()
        if ($appId -eq "") { continue }

        $currentVersion = ""
        $availableVersion = ""
        if ($versionPos -ge 0 -and $availablePos -gt $versionPos -and $line.Length -gt $versionPos) {
            $verEnd = $availablePos - 1
            $currentVersion = ($line[$versionPos..$verEnd] -join "").Trim()
        }
        if ($availablePos -ge 0 -and $line.Length -gt $availablePos) {
            $avEnd = if ($sourcePos -gt $availablePos) { $sourcePos - 1 } else { $line.Length - 1 }
            $availableVersion = ($line[$availablePos..$avEnd] -join "").Trim()
        }

        $null = $apps.Add(@{
            AppID = $appId
            CurrentVersion = $currentVersion
            AvailableVersion = $availableVersion
        })
        Write-Log -Message "DEBUG: Found app: $appId ($currentVersion -> $availableVersion)" -IsDebug
    }

    Write-Log -Message "Parsed $($apps.Count) apps from winget output"
    return $apps
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
        # Restore whitelistUrl from marker file (passed from SYSTEM context bootstrapper)
        if ($markerContent -match "WHITELISTURL:(.+)") {
            $whitelistUrl = $matches[1].Trim()
            Write-Log -Message "DEBUG: Restored whitelistUrl from marker file: $whitelistUrl" -IsDebug
        }
    } catch {
        Write-Log -Message "DEBUG: Error reading marker file: $($_.Exception.Message)" -IsDebug
    }
}

Write-Log -Message "DEBUG: Marker detection - isUserDetectionTask: $isUserDetectionTask, markerResultFile: '$markerResultFile'" -IsDebug

if ($UserDetectionOnly -eq "true" -or $isUserDetectionTask) {
    # This is a scheduled user detection task - detect user apps only
    Write-Log -Message "*** RUNNING IN USER CONTEXT (SCHEDULED TASK) ***"
    Write-Log -Message "Current user: $env:USERNAME"
    Write-Log -Message "User domain: $env:USERDOMAIN"
    Write-Log -Message "Session ID: $((Get-Process -Id $PID).SessionId)"
    Write-Log -Message "Process ID: $PID"
    Write-Log -Message "Running user detection task"
    $effectiveResultFile = if (-not [string]::IsNullOrEmpty($DetectionResultFile)) {
        $DetectionResultFile
    } else {
        $markerResultFile
    }
    Write-Log -Message "DetectionResultFile parameter: $DetectionResultFile"
    Write-Log -Message "Effective result file (from marker): $effectiveResultFile"

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Log -Message "User is admin: $userIsAdmin"

    # Run BOTH the default `winget upgrade` listing AND `--scope user`. Default catches apps
    # that winget tracks under the user account but installs machine-wide (e.g. Mozilla.Firefox
    # in C:\Program Files), which SYSTEM context cannot see. `--scope user` catches genuinely
    # user-scoped apps the default listing sometimes hides. Mirrors remediate.ps1 v9.11+.
    $OUTPUT = Invoke-WingetUpgradeList
    $OUTPUT_USER_SCOPE = @()
    try {
        $OUTPUT_USER_SCOPE = Invoke-WingetUpgradeList -Scope "user"
    } catch {
        Write-Log -Message "Error running winget --scope user (non-fatal): $($_.Exception.Message)"
    }
    Write-Log -Message "User context detection - default + --scope user dual listing"

} elseif (Test-RunningAsSystem) {
    Write-Log -Message "SYSTEM context - detecting system apps and scheduling user detection"

    if ($WingetPath) {
        Write-Log -Message "Using winget path: $WingetPath"
        $wingetExe = Join-Path $WingetPath "winget.exe"
        $OUTPUT = Invoke-WingetUpgradeList -WingetExe $wingetExe
    } else {
        Write-Log -Message "Winget not detected in SYSTEM context"
        Invoke-MarkerFileEmergencyCleanup -Reason "Winget not detected in SYSTEM context"
        exit 0
    }
} else {
    Write-Log -Message "USER context - detecting user-scoped apps"

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Log -Message "User is admin: $userIsAdmin"

    # Same dual-listing rationale as the scheduled-task branch above.
    $OUTPUT = Invoke-WingetUpgradeList
    $OUTPUT_USER_SCOPE = @()
    try {
        $OUTPUT_USER_SCOPE = Invoke-WingetUpgradeList -Scope "user"
    } catch {
        Write-Log -Message "Error running winget --scope user (non-fatal): $($_.Exception.Message)"
    }
}

# Parse winget output and process apps
$LIST = ConvertFrom-WingetOutput -Output $OUTPUT

# Merge user-scoped listing into the main list (dedup by AppID).
# Only present in user-context paths; SYSTEM leaves $OUTPUT_USER_SCOPE undefined.
if ($OUTPUT_USER_SCOPE -and $OUTPUT_USER_SCOPE.Count -gt 0) {
    $userScopeList = ConvertFrom-WingetOutput -Output $OUTPUT_USER_SCOPE
    if ($userScopeList -and $userScopeList.Count -gt 0) {
        $seenAppIDs = @{}
        $mergedList = [System.Collections.ArrayList]::new()
        foreach ($app in $LIST) {
            if ($app.AppID) { $seenAppIDs[$app.AppID] = $true }
            $null = $mergedList.Add($app)
        }
        $addedCount = 0
        foreach ($app in $userScopeList) {
            if ($app.AppID -and -not $seenAppIDs.ContainsKey($app.AppID)) {
                $null = $mergedList.Add($app)
                $seenAppIDs[$app.AppID] = $true
                $addedCount++
            }
        }
        if ($addedCount -gt 0) {
            Write-Log -Message "Merged $addedCount user-scoped apps into detection list (total: $($mergedList.Count))"
        }
        $LIST = $mergedList
    }
}

if ($LIST -and $LIST.Count -gt 0) {

        $contextApps = @()
        $deferredApps = @()

        foreach ($app in $LIST) {
            $appId = if ($app -is [hashtable] -or $app -is [System.Collections.IDictionary]) { $app.AppID } else { $app }
            if (-not [string]::IsNullOrEmpty($appId)) {
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($appId -like $okapp.AppID) {
                        # FAST DEFERRAL CHECK - Only check existing registry data (no expensive winget queries)
                        if ($okapp.DeferralEnabled -eq $true) {
                            $deferralPath = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals\$appId"
                            $now = Get-Date

                            # Quick check - only look at existing user deadline (no expensive admin deadline calculation)
                            if (Test-Path $deferralPath) {
                                try {
                                    $deferralData = Get-ItemProperty -Path $deferralPath -ErrorAction SilentlyContinue
                                    if ($deferralData -and $deferralData.UserDeadline) {
                                        $userDeadline = [DateTime]::Parse($deferralData.UserDeadline)
                                        if ($now -lt $userDeadline) {
                                            $deferredApps += "$($okapp.AppID) (until $($userDeadline.ToString('dd.MM.yyyy HH:mm')))"
                                            Write-Log -Message "Skipping $($okapp.AppID) - user has deferred until $userDeadline"
                                            continue  # Skip this app - still deferred
                                        } else {
                                            Write-Log -Message "User deferral for $($okapp.AppID) has expired - allowing detection"
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "Error reading deferral data for $appId : $($_.Exception.Message)"
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
                        # Capture friendlyName onto the record so the task file gets it without another whitelist lookup
                        if ($app -is [hashtable] -or $app -is [System.Collections.IDictionary]) {
                            $app['FriendlyName'] = $okapp.FriendlyName
                        }
                        break
                    }
                }

                if ($doUpgrade) {
                    $contextApps += $app
                    Write-Log -Message "DEBUG: App '$appId' added to context apps (whitelisted)" -IsDebug
                } else {
                    Write-Log -Message "DEBUG: App '$appId' not in whitelist, skipping" -IsDebug
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
                Write-Log -Message "DEBUG: User context apps: $(Format-AppList $contextApps)" -IsDebug
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
                Write-Log -Message "DEBUG: Apps to write: $(Format-AppList $contextApps)" -IsDebug
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
            # SYSTEM context main execution - run BOTH system and user detection, merge results,
            # then write the combined task file. The two contexts are not mutually exclusive: a
            # machine has both system-scoped and user-scoped upgrades, and the task file is the
            # sole input remediate.ps1 uses, so missing either side leaves work undone.
            $systemApps = $contextApps
            # Write-Log -Message "System detection found $($systemApps.Count) apps: $($systemApps -join ', ')"

            # TEST MODE: Simulate finding an app that needs updating
            if ($Script:TestMode) {
                Write-Log -Message "TEST MODE: Simulating detected upgrade for Test.DemoApp"
                Write-Log -Message "[$ScriptTag] Test.DemoApp"
                Invoke-MarkerFileEmergencyCleanup -Reason "Test mode - simulated detection"
                exit 1
            }

            $userApps = @()
            if (Test-InteractiveSession) {
                Write-Log -Message "Interactive session confirmed - proceeding with user context detection"
                Write-Log -Message "DEBUG: About to call Invoke-UserContextDetection function" -IsDebug
                # Filter the function's return stream down to actual app records: Write-Log emits the
                # formatted line to the success stream and several cmdlets inside Invoke-UserContextDetection
                # also output objects, so unfiltered $userApps is a mix of strings + task-info objects + apps.
                $userApps = @((Invoke-UserContextDetection) | Where-Object {
                    ($_ -is [hashtable] -or $_ -is [System.Collections.IDictionary]) -or
                    ($_.PSObject -and $_.PSObject.Properties['AppID'])
                })
                Write-Log -Message "DEBUG: Invoke-UserContextDetection returned $($userApps.Count) apps after filtering" -IsDebug
            } else {
                Write-Log -Message "No interactive session detected - skipping user context detection (system-only run)"
            }

            # Merge by AppID. SYSTEM record wins on conflict because its InstalledScope was
            # determined from HKLM + HKU\SID (the SYSTEM-context path of Get-AppInstalledScope
            # has visibility into all loaded user hives; the user-context path only sees HKCU).
            $mergedApps = @()
            $seenIds = @{}
            foreach ($r in $systemApps) {
                $id = Get-RecordAppId -Record $r
                if ([string]::IsNullOrEmpty($id)) { continue }
                if (-not $seenIds.ContainsKey($id)) {
                    $mergedApps += $r
                    $seenIds[$id] = $true
                }
            }
            foreach ($r in $userApps) {
                $id = Get-RecordAppId -Record $r
                if ([string]::IsNullOrEmpty($id)) { continue }
                if (-not $seenIds.ContainsKey($id)) {
                    $mergedApps += $r
                    $seenIds[$id] = $true
                }
            }
            Write-Log -Message "Merged detection: $($systemApps.Count) system + $($userApps.Count) user = $($mergedApps.Count) unique apps"

            if ($mergedApps.Count -gt 0) {
                # Write the task file BEFORE the [ScriptTag] summary so the summary line is the
                # last non-debug line on stdout — Intune reads the final stdout line as the
                # detection result.
                Write-UpgradeTaskFile -Records $mergedApps
                Write-Log -Message "Performing marker file cleanup before exit (merged apps found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "Merged apps found, triggering remediation"
                if ($deferredApps.Count -gt 0) {
                    Write-Log -Message "[$ScriptTag] Deferred: $($deferredApps -join ', ')"
                }
                Write-Log -Message "[$ScriptTag] $(Format-AppList $mergedApps)"
                exit 1  # Trigger remediation
            } else {
                Remove-UpgradeTaskFile -Reason "No upgrades available"
                Write-Log -Message "Performing marker file cleanup before exit (no upgrades found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "No upgrades available in any context"
                if ($deferredApps.Count -gt 0) {
                    Write-Log -Message "[$ScriptTag] Deferred: $($deferredApps -join ', ')"
                }
                Write-Log -Message "[$ScriptTag] No upgrades available in any context"
                exit 0
            }

        } else {
            Write-Log -Message "DEBUG: *** TAKING DIRECT USER CONTEXT EXECUTION PATH ***" -IsDebug
            Write-Log -Message "DEBUG: This path is for direct user context execution (not scheduled task)" -IsDebug
            # Direct user context execution
            if ($contextApps.Count -gt 0) {
                # Write the task file BEFORE the [ScriptTag] summary — Intune reads the final
                # stdout line as the detection result, so the summary must come last.
                Write-UpgradeTaskFile -Records $contextApps
                Write-Log -Message "Performing marker file cleanup before exit (direct user context apps found)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "Direct user context apps found"
                if ($deferredApps.Count -gt 0) {
                    Write-Log -Message "[$ScriptTag] Deferred: $($deferredApps -join ', ')"
                }
                Write-Log -Message "[$ScriptTag] $(Format-AppList $contextApps)"
                exit 1  # Trigger remediation
            } else {
                Remove-UpgradeTaskFile -Reason "No user context upgrades available"
                Write-Log -Message "Performing marker file cleanup before exit (no user context upgrades)" -IsDebug
                Invoke-MarkerFileEmergencyCleanup -Reason "No user context upgrades available"
                if ($deferredApps.Count -gt 0) {
                    Write-Log -Message "[$ScriptTag] Deferred: $($deferredApps -join ', ')"
                }
                Write-Log -Message "[$ScriptTag] No user context upgrades available"
                exit 0
            }
        }
} else {
    Remove-UpgradeTaskFile -Reason "No upgrades in winget output"
    Write-Log -Message "[$ScriptTag] No upgrades found in winget output"
    Write-Log -Message "Performing final marker file cleanup before script exit" -IsDebug
    Invoke-MarkerFileEmergencyCleanup -Reason "Script completion (no upgrades found)"
    exit 0
}
