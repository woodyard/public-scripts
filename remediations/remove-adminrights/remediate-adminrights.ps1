# Intune Remediation Script - Remediation
# Version: 1.6.0
# Purpose: Remove administrator rights from local user accounts and Entra ID users (excluding built-in Administrator)
# Output: Returns success or failure message
# Target: Entra ID joined PCs

# Initialize variables
$ErrorActionPreference = "Stop"
$scriptVersion = "1.6.0"
$outputPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$outputFile = "$outputPath\AdminUsersRemediation.log"
$localUsersRemediated = @()
$entraIdUsersRemediated = @()
$usersRemediated = @()

# Allowlist of SIDs that are permitted to have admin rights
$allowedSIDs = @(
    "S-1-12-1-3914632327-1237360286-195342256-2169457663",
    "S-1-12-1-319104407-1327126072-2996309410-2010026311",
    "S-1-12-1-456866545-1239502261-648193966-3792668366"
)

# Create log directory if it doesn't exist
if (!(Test-Path -Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
}

# Function to write logs
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $outputFile -Append
}

# Start logging
Write-Log "Starting admin rights remediation script"

try {
    # Get the Administrators group name (accounts for different language versions of Windows)
    $adminGroupSID = "S-1-5-32-544" # This is the SID for the Administrators group
    $adminGroup = Get-LocalGroup -SID $adminGroupSID
    Write-Log "Administrator group found: $($adminGroup.Name)"
    
    # Get all members of the Administrators group with error handling
    try {
        $adminMembers = Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop
        Write-Log "Found $($adminMembers.Count) members in the Administrators group"
    }
    catch {
        Write-Log "WARNING: Error getting all group members: $($_.Exception.Message)"
        Write-Log "Attempting to get members individually..."
        $adminMembers = @()
        
        # Alternative approach: use WMI to get group members
        $groupObj = [ADSI]"WinNT://./$($adminGroup.Name)"
        $members = @($groupObj.Invoke("Members"))
        
        foreach ($member in $members) {
            try {
                $memberPath = $member.GetType().InvokeMember("ADsPath", "GetProperty", $null, $member, $null)
                $memberName = $memberPath.Replace("WinNT://", "").Replace("/", "\")
                
                # Create a custom object to mimic Get-LocalGroupMember output
                $customMember = [PSCustomObject]@{
                    Name = $memberName
                    SID = $null
                    ObjectClass = "User"
                    PrincipalSource = "Local"
                }
                
                # Try to get SID if possible
                try {
                    $objUser = New-Object System.Security.Principal.NTAccount($memberName)
                    $sid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
                    $customMember.SID = $sid
                }
                catch {
                    Write-Log "WARNING: Could not get SID for $memberName : $($_.Exception.Message)"
                }
                
                $adminMembers += $customMember
                Write-Log "Added member: $memberName"
            }
            catch {
                Write-Log "WARNING: Could not process a member: $($_.Exception.Message)"
            }
        }
        
        Write-Log "Found $($adminMembers.Count) members using alternative method"
    }
    
    Write-Log "Allowed SIDs for reference: $($allowedSIDs -join ', ')"
    
    # Debug: Output all allowed SIDs for reference
    Write-Log "DEBUG: Allowed SIDs list:"
    foreach ($sid in $allowedSIDs) {
        Write-Log "DEBUG: Allowed SID: '$sid'"
    }
    
    # Process each member individually
    foreach ($member in $adminMembers) {
        # Skip built-in Administrator account (SID ends with -500)
        if ($member.SID.Value -match "-500$") {
            Write-Log "Skipping built-in Administrator account: $($member.Name)"
            continue
        }
        
        # Skip built-in system accounts
        if ($member.SID.Value -match "^S-1-5-(18|19|20)$") {
            Write-Log "Skipping system account: $($member.Name)"
            continue
        }
        
        # Skip Azure AD device accounts (typically have format AzureAD\Device-*)
        if ($member.Name -match "AzureAD\\Device-" -or $member.Name -match "NT AUTHORITY\\") {
            Write-Log "Skipping Entra ID device account: $($member.Name)"
            continue
        }
        
        # Skip Microsoft Intune Management Extension account
        if ($member.Name -match "Microsoft Intune Management Extension") {
            Write-Log "Skipping Intune Management account: $($member.Name)"
            continue
        }
        
        # Special case: If the member name itself is a SID string that's in our allowed list, skip it
        if ($member.Name -match "^S-1-12-1-" -and $allowedSIDs -contains $member.Name) {
            Write-Log "SPECIAL CASE: Member name is an allowed SID string: $($member.Name)"
            continue
        }
        
        # Get the SID value as a string with null check
        $sidValue = if ($null -eq $member.SID) {
            Write-Log "WARNING: Null SID for member: $($member.Name)"
            # Special case: If the member name itself is a SID string, use that
            if ($member.Name -match "^S-1-12-1-") {
                Write-Log "SPECIAL CASE: Using member name as SID: $($member.Name)"
                $member.Name
            } else {
                "UNKNOWN"
            }
        } elseif ($member.SID -is [string]) { 
            $member.SID 
        } elseif ($member.SID -is [System.Security.Principal.SecurityIdentifier]) {
            $member.SID.ToString()
        } elseif ($null -ne $member.SID.Value) { 
            $member.SID.Value 
        } else {
            Write-Log "WARNING: Unable to determine SID for member: $($member.Name)"
            # Special case: If the member name itself is a SID string, use that
            if ($member.Name -match "^S-1-12-1-") {
                Write-Log "SPECIAL CASE: Using member name as SID: $($member.Name)"
                $member.Name
            } else {
                "UNKNOWN"
            }
        }
        
        # Debug: Output the SID value for this member
        Write-Log "DEBUG: Member: $($member.Name), SID: '$sidValue'"
        
        # Check if this SID is in our allowlist
        $isAllowed = $false
        
        # Debug: Compare this SID with each allowed SID
        foreach ($allowedSID in $allowedSIDs) {
            Write-Log "DEBUG: Comparing '$sidValue' with allowed SID '$allowedSID'"
            if ($sidValue -eq $allowedSID) {
                $isAllowed = $true
                Write-Log "DEBUG: MATCH FOUND - SIDs are equal"
                break
            }
        }
        
        if ($isAllowed) {
            Write-Log "DEBUG: Skipping allowed SID: $($member.Name) with SID: $sidValue"
            continue
        }
        
        # FINAL APPROACH: Explicitly check if this is one of the allowed SIDs
        if ($sidValue -eq "S-1-12-1-3914632327-1237360286-195342256-2169457663" -or
            $sidValue -eq "S-1-12-1-319104407-1327126072-2996309410-2010026311" -or
            $sidValue -eq "S-1-12-1-456866545-1239502261-648193966-3792668366") {
            Write-Log "FINAL FILTERING: Explicitly skipping allowed SID: $sidValue"
            continue
        }
        
        # This account is not in the allowed list, proceed with remediation
        try {
            
            if (($sidValue -and $sidValue -match "^S-1-12-1-") -or $member.Name -match "AzureAD\\") {
                # This is an Entra ID account
                Write-Log "Removing admin rights from Entra ID user: $($member.Name)"
                
                # Try different methods to remove the member
                try {
                    Remove-LocalGroupMember -Group $adminGroup.Name -Member $member.Name -ErrorAction Stop
                }
                catch {
                    Write-Log "WARNING: Standard removal failed, trying alternative method: $($_.Exception.Message)"
                    
                    # Alternative removal using ADSI
                    try {
                        $groupObj = [ADSI]"WinNT://./$($adminGroup.Name),group"
                        $memberName = $member.Name
                        
                        # Handle different name formats
                        if ($memberName -match "\\") {
                            $parts = $memberName -split "\\"
                            $domain = $parts[0]
                            $username = $parts[1]
                            $memberObj = [ADSI]"WinNT://$domain/$username"
                        }
                        else {
                            $memberObj = [ADSI]"WinNT://./$memberName"
                        }
                        
                        $groupObj.Remove($memberObj.Path)
                        Write-Log "Successfully removed member using ADSI method"
                    }
                    catch {
                        Write-Log "ERROR: Alternative removal also failed: $($_.Exception.Message)"
                        throw
                    }
                }
                
                $entraIdUsersRemediated += $member.Name
                $usersRemediated += $member.Name
                Write-Log "Successfully removed admin rights from Entra ID user: $($member.Name)"
            } 
            elseif ($member.ObjectClass -eq "User" -or $sidValue -ne "UNKNOWN") {
                # This is a local user account
                Write-Log "Removing admin rights from local user: $($member.Name)"
                Remove-LocalGroupMember -Group $adminGroup.Name -Member $member.Name
                $localUsersRemediated += $member.Name
                $usersRemediated += $member.Name
                Write-Log "Successfully removed admin rights from local user: $($member.Name)"
            }
            else {
                # This is some other type of account - log but don't remediate
                Write-Log "Skipping other account type: $($member.Name)"
            }
        }
        catch {
            Write-Log "ERROR: Failed to remove admin rights from $($member.Name): $($_.Exception.Message)"
        }
    }
    
    # Report results
    if ($usersRemediated.Count -gt 0) {
        # Log detailed breakdown
        if ($localUsersRemediated.Count -gt 0) {
            $localUsersList = $localUsersRemediated -join ', '
            Write-Log "Removed admin rights from $($localUsersRemediated.Count) local user accounts: $localUsersList"
        }
        
        if ($entraIdUsersRemediated.Count -gt 0) {
            $entraIdUsersList = $entraIdUsersRemediated -join ', '
            Write-Log "Removed admin rights from $($entraIdUsersRemediated.Count) Entra ID accounts: $entraIdUsersList"
        }
        
        Write-Log "RESULT: Successfully removed admin rights from $($usersRemediated.Count) total users: $($usersRemediated -join ', ')"
        Write-Log "Script version: $scriptVersion"
        Write-Output "v$scriptVersion Successfully removed administrator rights from $($usersRemediated.Count) users"
        exit 0
    }
    else {
        Write-Log "RESULT: No users required remediation"
        Write-Log "Script version: $scriptVersion"
        Write-Output "v$scriptVersion No users required remediation"
        exit 0
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "Script version: $scriptVersion"
    Write-Output "v$scriptVersion Error: $($_.Exception.Message)"
    exit 1
}
