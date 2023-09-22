[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match 'S-1-5-18')
	}
}

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
    $OUTPUT = $(winget upgrade --accept-source-agreements)
    Write-Log -Message "Local user mode"
    Write-Log -Message $OUTPUT
}
elseif ($wingetpath) {
    Write-Log -Message $wingetpath
    Set-Location $wingetpath

    # call this command twice, to see if output is better
    $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
    $OUTPUT = $(.\winget.exe upgrade --accept-source-agreements)
#    $OUTPUT = $OUTPUT.replace("Γ","").replace("Ç","").replace("ª","")
}

if ( (-Not ($ras)) -or $wingetpath) {
    $headerLine = -1
    $lineCount = 0

    foreach ($line in $OUTPUT) {
        if ($line -like "Name*") {
            $headerLine = $lineCount
            continue
        }
        $lineCount++
    }
    Write-Log -Message "Found header"

    if ($OUTPUT -and $lineCount -gt $headerLine+2) {
        $str = $OUTPUT[$headerLine]
        $idPos = $str.indexOf("Id")
        $versionPos = $str.indexOf("Version")-1

        Write-Log -Message "Detecting app ids"

        $LIST= [System.Collections.ArrayList]::new()
        for ($i = $headerLine+2; $i -lt $OUTPUT.count-1; $i++ ) {
            $lineData = $OUTPUT[$i]
            $LIST.Add(($lineData[$idPos..$versionPos] -Join "").trim())
        }

        Write-Log -Message "Done detecting app ids"

        $count = 0
        $message = ""

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
                    $message += $app + "|"
                }
            }
        }

        if ($count -eq 0) {
            Write-Log -Message "No upgrades available"
            exit 0
        }
        if ($message -eq "") {
            $message = "No upgrades available (0x0000001-$count)"
        }
        Write-Log -Message $message
        exit 1
    }
    Write-Log -Message "No upgrades (0x0000002)"
    exit 0
}
Write-Log -Message "Winget not detected"
exit 0 #change to 1 if the remediation script can install winget :)
