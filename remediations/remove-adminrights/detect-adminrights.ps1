# Intune Remediation Script - Detection
# Version: 1.6.0
# Purpose: Detect if there are any local user accounts or Entra ID users with administrator rights on Entra ID joined machines
# Output: Returns "NonCompliant" if admin user accounts exist, otherwise "Compliant"
# Target: Entra ID joined PCs

# Initialize variables
$ErrorActionPreference = "Stop"
$scriptVersion = "1.6.0"
$adminAccounts = @()
$localAdminAccounts = @()
$entraIdAdminAccounts = @()
$outputPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$outputFile = "$outputPath\AdminUsersDetection.log"

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
Write-Log "Starting admin account detection script"

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
        
        # Skip built-in system accounts and Entra ID device accounts
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
        
        # This account is not in the allowed list, add it to the appropriate list
        if (($sidValue -and $sidValue -match "^S-1-12-1-") -or $member.Name -match "AzureAD\\") {
            # This is an Entra ID account
            $entraIdAdminAccounts += $member.Name
            $adminAccounts += $member.Name
            Write-Log "Found Entra ID user with admin rights: $($member.Name)"
        } 
        elseif ($member.ObjectClass -eq "User" -or $sidValue -ne "UNKNOWN") {
            # This is a local user account
            $localAdminAccounts += $member.Name
            $adminAccounts += $member.Name
            Write-Log "Found local user with admin rights: $($member.Name)"
        }
        else {
            # This is some other type of account
            $adminAccounts += $member.Name
            Write-Log "Found other account type with admin rights: $($member.Name)"
        }
    }
    
    # Debug: Output the final admin accounts list
    Write-Log "DEBUG: Final admin accounts list:"
    foreach ($account in $adminAccounts) {
        Write-Log "DEBUG: Admin account: $account"
    }
    
    # FINAL APPROACH: Explicitly filter out the allowed SIDs from the final output
    Write-Log "FINAL FILTERING: Explicitly removing allowed SIDs from output"
    
    # Create a filtered list that excludes the allowed SIDs
    $filteredAdminAccounts = @()
    
    foreach ($account in $adminAccounts) {
        # Skip if the account is one of the allowed SIDs
        if ($account -eq "S-1-12-1-3914632327-1237360286-195342256-2169457663" -or
            $account -eq "S-1-12-1-319104407-1327126072-2996309410-2010026311" -or
            $account -eq "S-1-12-1-456866545-1239502261-648193966-3792668366") {
            Write-Log "FINAL FILTERING: Explicitly excluding allowed SID: $account"
            continue
        }
        
        $filteredAdminAccounts += $account
    }
    
    # Determine compliance status using the filtered list
    if ($filteredAdminAccounts.Count -gt 0) {
        $adminAccountsList = $filteredAdminAccounts -join ','
        
        # Log detailed breakdown
        if ($localAdminAccounts.Count -gt 0) {
            $localAdminList = $localAdminAccounts -join ','
            Write-Log "Found $($localAdminAccounts.Count) local user accounts with admin rights: $localAdminList"
        }
        
        if ($entraIdAdminAccounts.Count -gt 0) {
            $entraIdAdminList = $entraIdAdminAccounts -join ','
            Write-Log "Found $($entraIdAdminAccounts.Count) Entra ID accounts with admin rights: $entraIdAdminList"
        }
        
        Write-Log "RESULT: NonCompliant - Found $($filteredAdminAccounts.Count) total accounts with admin rights: $adminAccountsList"
        Write-Log "Script version: $scriptVersion"
        Write-Output "v$scriptVersion NonCompliant: $adminAccountsList"
        exit 1
    } 
    else {
        Write-Log "RESULT: Compliant - No user accounts with admin rights found"
        Write-Log "Script version: $scriptVersion"
        Write-Output "v$scriptVersion Compliant"
        exit 0
    }
} 
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "Script version: $scriptVersion"
    Write-Output "v$scriptVersion Error: $($_.Exception.Message)"
    exit 1
}
