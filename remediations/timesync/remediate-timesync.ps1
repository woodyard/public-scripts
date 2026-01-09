#########################################################################
# Windows Time Synchronization Fix Script
# 
# Description:
# This script fixes time synchronization issues on Windows devices by:
# 1. Checking and enabling the Windows Time service
# 2. Configuring reliable NTP servers
# 3. Forcing time synchronization
# 4. Setting up proper synchronization intervals
# 5. Logging all actions and results
#
# Usage:
# Deploy as an Intune Remediation Script or run manually with admin privileges
#
# Version History:
# 1.0 - 2025-03-06 - Initial script creation
# 1.1 - 2025-03-06 - Replaced firewall service restart with proper NTP firewall rule creation
# 1.2 - 2025-03-06 - Fixed w32tm command ordering to ensure service is running before configuration 
# 1.3 - 2025-03-06 - Added multiple methods to set SpecialPollInterval including GPO registry path
#                   - Added verification of interval settings and debugging output
# 1.4 - 2025-03-06 - Removed unnecessary inbound firewall rule, keeping only outbound NTP traffic rule
# 1.5 - 2025-03-06 - Enhanced firewall handling to only create rules if needed based on connection test
# 1.6 - 2025-03-06 - Fixed connectivity testing by using Test-NetConnection instead of w32tm command
#                   - Changed to RemotePort from LocalPort in firewall rule
# 1.7 - 2025-03-06 - Fixed testing method to properly detect UDP NTP communication
#########################################################################

# Script configuration
$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "$LogPath\TimeSyncFix.log"
$NTPServers = "time.windows.com,0.pool.ntp.org,1.pool.ntp.org,time.nist.gov"
$SyncInterval = 900 # 15 minutes in seconds

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    try {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        Write-Output "Created log directory at $LogPath"
    }
    catch {
        Write-Output "Failed to create log directory: $_"
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
    
    # Also output to console
    Write-Output $LogMessage
}

# Log script start
Write-Log "Time synchronization fix script started"

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "ERROR: Script must be run as administrator! Exiting."
    exit 1
}

# Check the Windows Time service status
try {
    $W32TimeService = Get-Service -Name "W32Time"
    Write-Log "Current W32Time service status: $($W32TimeService.Status), StartType: $($W32TimeService.StartType)"
    
    # Enable and start the service if needed
    if ($W32TimeService.StartType -eq "Disabled") {
        Set-Service -Name "W32Time" -StartupType Automatic
        Write-Log "Changed W32Time service startup type to Automatic"
    }
    
    if ($W32TimeService.Status -ne "Running") {
        Start-Service -Name "W32Time"
        Write-Log "Started W32Time service"
    }
}
catch {
    Write-Log "ERROR checking/configuring W32Time service: $_"
}

# Configure NTP servers
try {
    # Stop the time service first
    Stop-Service -Name "W32Time" -Force
    Write-Log "Stopped W32Time service to apply configuration changes"
    
    # Set the Windows Time service to use NTP client mode
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP"
    Write-Log "Set time synchronization type to NTP"
    
    # Configure NTP servers
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -Value $NTPServers
    Write-Log "Configured NTP servers: $NTPServers"
    
    # Force the specific poll interval using direct registry modification and GPO settings
    # Set the special poll interval directly in registry 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Value $SyncInterval
    
    # Also set it via w32tm command with specific parameter
    & w32tm /config /update
    
    # Additional step - use Group Policy method to set poll interval
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegPath -Name "SpecialPollInterval" -Value $SyncInterval -Type DWord
    
    # Restart the service to apply all changes
    Restart-Service -Name "W32Time" -Force
    Write-Log "Set time synchronization interval to $SyncInterval seconds through multiple methods"
    
    # Increase the MaxPosPhaseCorrection (maximum positive time correction in seconds)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxPosPhaseCorrection" -Value 86400
    # Increase the MaxNegPhaseCorrection (maximum negative time correction in seconds)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxNegPhaseCorrection" -Value 86400
    Write-Log "Set MaxPosPhaseCorrection and MaxNegPhaseCorrection to 86400 (1 day)"
    
    # Service already restarted earlier, just log the status
    $W32TimeStatus = (Get-Service -Name "W32Time").Status
    Write-Log "W32Time service is now $W32TimeStatus with new configuration"
}
catch {
    Write-Log "ERROR configuring NTP settings: $_"
}

# Verify the poll interval was set correctly
try {
    Start-Sleep -Seconds 2  # Brief pause to let settings apply
    
    # Get the current SpecialPollInterval value
    $CurrentPollInterval = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval").SpecialPollInterval
    Write-Log "Current SpecialPollInterval in registry: $CurrentPollInterval"
    
    # If it's not our desired value, try one more approach
    if ($CurrentPollInterval -ne $SyncInterval) {
        Write-Log "SpecialPollInterval is not set to the desired value. Trying additional method..."
        
        # Try to set it using a direct command
        & cmd /c "w32tm /config /update /manualpeerlist:`"$NTPServers`" /syncfromflags:manual /reliable:yes"
        & cmd /c "w32tm /config /update"
        
        # Re-read the setting
        $CurrentPollInterval = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "SpecialPollInterval").SpecialPollInterval
        Write-Log "Updated SpecialPollInterval in registry: $CurrentPollInterval"
    }
}
catch {
    Write-Log "WARNING: Error verifying poll interval: $_"
}

# Force time synchronization after verification
try {
    # Resync the time
    $SyncResult = w32tm /resync /force
    Write-Log "Force time resync result: $SyncResult"
}
catch {
    Write-Log "ERROR forcing time resync: $_"
}

# Check if time sync is now working by testing connectivity to the servers
try {
    $TestResult = w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly
    Write-Log "Time server connectivity test: $TestResult"
}
catch {
    Write-Log "ERROR testing time server connectivity: $_"
}

# Verify time server connectivity and only create firewall rule if needed
try {
    # Since Test-NetConnection uses TCP and NTP uses UDP, we'll check if w32tm already works
    $TimeServer = $NTPServers.Split(',')[0]  # Get first server for testing
    Write-Log "Testing NTP communication with $TimeServer..."
    
    # Try a time sync and see if it works
    $SyncResult = w32tm /resync /force
    
    # If we successfully synced, no firewall rule is needed
    if ($SyncResult -match "completed successfully") {
        Write-Log "NTP time synchronization is working. No firewall rule needed."
    } else {
        Write-Log "NTP time synchronization has issues. Creating firewall rule..."
        
        # Create outbound firewall rule
        $RuleName = "NTP-UDP-123-Outbound"
        $RuleExists = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if (-not $RuleExists) {
            # Create a new outbound firewall rule for NTP
            New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow -Enabled True | Out-Null
            Write-Log "Created outbound firewall rule to allow NTP traffic on UDP port 123"
            
            # Try sync again to see if it helped
            $SyncResult = w32tm /resync /force
            Write-Log "Time sync after firewall rule: $SyncResult"
        } else {
            Write-Log "NTP outbound firewall rule already exists"
        }
    }
}
catch {
    Write-Log "WARNING: Error checking NTP connectivity: $_"
}

# Log script completion
Write-Log "Time synchronization fix script completed"

# Return success for Intune Remediation
exit 0