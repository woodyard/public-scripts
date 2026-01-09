#########################################################################
# Windows Time Synchronization Detection Script
# 
# Description:
# This script detects if Windows Time synchronization is properly configured.
# It checks:
# 1. Windows Time service state
# 2. NTP server configuration
# 3. Recent successful synchronization
# 4. Poll interval setting
#
# Usage:
# Use as the detection part of an Intune Remediation script
# - Exit code 0 = No issues found
# - Exit code 1 = Issues found, remediation needed
#
# Version History:
# 1.0 - 2025-03-06 - Initial script creation
# 1.1 - 2025-03-06 - Improved date parsing to handle different regional formats
#                   - Added more robust sync status detection based on multiple indicators
#########################################################################

# Script configuration
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\TimeSyncDetection.log"
$ExpectedServers = "time.windows.com,0.pool.ntp.org,1.pool.ntp.org,time.nist.gov"
$ExpectedPollInterval = 900 # 15 minutes in seconds
$MaxSyncAgeHours = 24 # How many hours since last sync is acceptable

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    try {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    catch {
        # Continue even if we can't create the log directory
    }
}

# Function to write to log file
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
    
    # Also output to console for Intune log capture
    Write-Output $LogMessage
}

# Initialize issues counter
$IssuesFound = 0

# Start detection
Write-Log "Starting time synchronization detection"

# Check 1: Windows Time service status
try {
    $W32TimeService = Get-Service -Name "W32Time" -ErrorAction Stop
    Write-Log "W32Time service status: $($W32TimeService.Status), StartType: $($W32TimeService.StartType)"
    
    if ($W32TimeService.Status -ne "Running" -or $W32TimeService.StartType -eq "Disabled") {
        Write-Log "ISSUE: Windows Time service is not running or is disabled"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Unable to query Windows Time service: $_"
    $IssuesFound++
}

# Check 2: NTP server configuration
try {
    $NtpServerConfig = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -ErrorAction Stop).NtpServer
    Write-Log "Configured NTP servers: $NtpServerConfig"
    
    # Check if expected servers are configured
    if ($NtpServerConfig -ne $ExpectedServers) {
        Write-Log "ISSUE: NTP server configuration doesn't match expected value"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Unable to query NTP server configuration: $_"
    $IssuesFound++
}

# Check 3: Poll interval configuration
try {
    $PollInterval = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -ErrorAction Stop).SpecialPollInterval
    Write-Log "Configured poll interval: $PollInterval seconds"
    
    if ($PollInterval -ne $ExpectedPollInterval) {
        Write-Log "ISSUE: Poll interval doesn't match expected value of $ExpectedPollInterval seconds"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Unable to query poll interval configuration: $_"
    $IssuesFound++
}

# Check 4: Recent successful synchronization
try {
    $W32TimeStatus = w32tm /query /status
    $LastSyncLine = $W32TimeStatus | Where-Object { $_ -match "Last Successful Sync Time:" }
    
    if ($LastSyncLine) {
        # Rather than relying on date parsing, check if sync happened by looking at other indicators
        $TimeSourceLine = $W32TimeStatus | Where-Object { $_ -match "Source:" }
        $ReferenceIdLine = $W32TimeStatus | Where-Object { $_ -match "ReferenceId:" }
        
        # If we have a time source and reference ID, sync is likely working
        if ($TimeSourceLine -and $ReferenceIdLine -and $ReferenceIdLine -notmatch "0x00000000") {
            Write-Log "Time synchronization appears to be working based on source and reference ID"
            
            # Try to parse the date, but don't fail if we can't
            try {
                $LastSyncTimeStr = ($LastSyncLine -split "Last Successful Sync Time:")[1].Trim()
                $LastSyncTime = [DateTime]::Parse($LastSyncTimeStr)
                $SyncAge = (Get-Date) - $LastSyncTime
                Write-Log "Last successful sync was approximately $([math]::Round($SyncAge.TotalHours, 2)) hours ago"
                
                if ($SyncAge.TotalHours -gt $MaxSyncAgeHours) {
                    Write-Log "ISSUE: Last successful sync too old (more than $MaxSyncAgeHours hours)"
                    $IssuesFound++
                }
            }
            catch {
                # Log but don't count as an issue since we have other indicators that sync is working
                Write-Log "NOTE: Could not precisely determine sync age, but sync appears to be working"
            }
        }
        else {
            Write-Log "ISSUE: Time synchronization appears to be inactive"
            $IssuesFound++
        }
    }
    else {
        Write-Log "ISSUE: No successful time synchronization recorded"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Unable to query time sync status: $_"
    $IssuesFound++
}

# Check 5: Phase correction settings
try {
    $MaxPosPhaseCorrection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxPosPhaseCorrection" -ErrorAction Stop).MaxPosPhaseCorrection
    $MaxNegPhaseCorrection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxNegPhaseCorrection" -ErrorAction Stop).MaxNegPhaseCorrection
    
    Write-Log "MaxPosPhaseCorrection: $MaxPosPhaseCorrection, MaxNegPhaseCorrection: $MaxNegPhaseCorrection"
    
    if ($MaxPosPhaseCorrection -lt 86400 -or $MaxNegPhaseCorrection -lt 86400) {
        Write-Log "ISSUE: Phase correction settings are too restrictive"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Unable to query phase correction settings: $_"
    $IssuesFound++
}

# Check 6: Try a time sync and verify it works
try {
    $SyncResult = w32tm /resync /force 2>&1
    Write-Log "Time sync test result: $SyncResult"
    
    if (-not ($SyncResult -match "completed successfully")) {
        Write-Log "ISSUE: Time sync test failed"
        $IssuesFound++
    }
}
catch {
    Write-Log "ISSUE: Error running time sync test: $_"
    $IssuesFound++
}

# Summarize findings
Write-Log "Detection completed. Total issues found: $IssuesFound"

# Exit with appropriate code for Intune
if ($IssuesFound -gt 0) {
    Write-Log "Remediation needed"
    exit 1  # Issues found, remediation needed
} else {
    Write-Log "No remediation needed"
    exit 0  # No issues found
}