<#
.SYNOPSIS
    Winget Application Update Detection Script (All Apps)

.DESCRIPTION
    This script detects available application updates using winget and reports them to Intune.
    It uses an exclude list approach instead of a whitelist to detect all available updates.
    The script is designed to work as a detection script in Microsoft Intune remediation policies.

.NOTES
    Author: Henrik Skovgaard
    Version: 2.2
    Tag: 2D
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed parsing bugs, improved error handling, clean output
    2.1 - Fixed progress indicator parsing bug that captured winget spinner characters as app names
    2.2 - Added 2-character tag system for version tracking
    
    Exit Codes:
    0 - No upgrades available or script completed successfully
    1 - Upgrades available (triggers remediation) or ESP not complete
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match 'S-1-5-18')
	}
}

$ScriptTag = "2D"
$LogName = 'DetectAvailableUpgradesAll'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"
#$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath = "$env:Temp"
$regPath = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
$esp = $true

try{
    $devicePreperationCategory = (Get-ItemProperty -Path $regPath -Name 'DevicePreparationCategory.Status' -ErrorAction 'Ignore').'DevicePreparationCategory.Status'
    $deviceSetupCategory = (Get-ItemProperty -Path $regPath -Name 'DeviceSetupCategory.Status' -ErrorAction 'Ignore').'DeviceSetupCategory.Status'
    $sccountSetupCategory = (Get-ItemProperty -Path $regPath -Name 'AccountSetupCategory.Status' -ErrorAction 'Ignore').'AccountSetupCategory.Status'

}catch{
    $esp = $false
}

if (-not (($devicePreperationCategory.categorySucceeded -eq 'True') -or ($devicePreperationCategory.categoryState -eq 'succeeded'))) {$esp = $false}
if (-not (($deviceSetupCategory.categorySucceeded -eq 'True') -or ($deviceSetupCategory.categoryState -eq 'succeeded'))) {$esp = $false}
if (-not (($sccountSetupCategory.categorySucceeded -eq 'True') -or ($sccountSetupCategory.categoryState -eq 'succeeded'))) {$esp = $false}

if ($esp) {
    "ESP"
    exit 0
}

function Write-Log($message) #Log script messages to temp directory
{
    $LogMessage = ((Get-Date -Format "MM-dd-yy HH:MM:ss ") + $message)
    $LogMessage
	Out-File -InputObject $LogMessage -FilePath "$LogPath\$LogFullName" -Append -Encoding utf8
}

<#
#Only run this on AAD joined machine!
If ((Get-WmiObject -Class win32_computersystem).partofdomain) {
	Write-Log -Message "Skipping due to AAD join requirement"
	exit 0 #Exiting with a 'Good' status, to avoid re-run on this PC
}
#>

$excludeapps = 'Microsoft.Office','Microsoft.Teams','Microsoft.VisualStudio','VMware.HorizonClient','Microsoft.SQLServer','TeamViewer','Docker','DisplayLink.GraphicsDriver','Microsoft.VCRedist','Microsoft.Edge','Cisco.WebexTeams','Amazon.WorkspacesClient','Salesforce.sfdx-cli','Microsoft.WindowsPCHealthCheck','Azul.Zulu'

$whitelist = ''

$useWhitelist = $false

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
if ($ResolveWingetPath) {
    $WingetPath = $ResolveWingetPath[-1].Path
}

$ras = $true
If (-Not (Test-RunningAsSystem)) {
    $ras = $false
    $OUTPUT = $(winget upgrade --accept-source-agreements)
    
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
    Write-Log -Message $WingetPath
    Set-Location $WingetPath

    # call winget and check if we need to retry
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
            # Filter out progress indicators and single characters
            if ($appId -ne "" -and $appId.Length -gt 2 -and $appId -notmatch '^[-\\|/]+$') {
                $null = $LIST.Add($appId)
            }
        }

        $count = 0
        $approvedApps = @()

        foreach ($app in $LIST) {
            if ($app -ne "") {

                if ($useWhitelist) {
                    $doUpgrade = $false
                    foreach ($okapp in $whitelist) {
                        if ($app -like "*$okapp*") {
                            $doUpgrade = $true
                            continue
                        }
                    }
                }
                else {
                    $doUpgrade = $true
                    foreach ($exclude in $excludeapps) {
                        if ($app -like "*$exclude*") {
                            $doUpgrade = $false
                            continue
                        }
                    }  
                }

                if ($doUpgrade) {
                    $count++
                    $approvedApps += $app
                }
            }
        }

        if ($count -eq 0) {
            Write-Log -Message "No upgrades available [$ScriptTag]"
            exit 0
        }
        
        $appList = $approvedApps -join ", "
        Write-Log -Message "Found $count apps ready for upgrade: $appList [$ScriptTag]"
        exit 1
    }
    Write-Log -Message "No upgrades (0x0000002) [$ScriptTag]"
    exit 0
}
Write-Log -Message "Winget not detected [$ScriptTag]"
exit 0 #change to 1 if the remediation script can install winget :)
