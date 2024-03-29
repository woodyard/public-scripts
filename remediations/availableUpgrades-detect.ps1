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
    $LogMessage = ((Get-Date -Format "MM-dd-yy HH:mm:ss ") + $message)
    $LogMessage
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

<# Script variables #>
$LogName = 'DetectAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy_HH-mm # go with the EU format day / month / year
$LogFullName = "$LogName-$LogDate.log"
#$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogPath = "$env:Temp"
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useWhitelist = $true

<# ----------------------------------------------- #>

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Exit 1
}

<# ---------------------------------------------- #>

$whitelistJSON = @'
[
    {
        AppID:              "Mozilla.Firefox",
        Disabled:           false,
        SystemContext:      true,
        UserContext:        true,
        UserContextPath:    "$Env:LocalAppData\\Mozilla Firefox\\firefox.exe"
    }
    ,{
        AppID:              "Google.Chrome",
        SystemContext:      true,
        UserContext:        true,
        UserContextPath:    "$Env:LocalAppData\\Google\\Chrome\\Application\\chrome.exe"
    }
    ,{
        AppID:              "Microsoft.VisualStudioCode",
        SystemContext:      true,
        UserContext:        true,
        UserContextPath:    "$Env:LocalAppData\\Programs\\Microsoft VS Code\\Code.exe"
    }
    ,{
        AppID:              "Salesforce.sfdx-cli",
        Disabled:           true
    }
    ,{        
        AppID:              "Microsoft.WindowsPCHealthCheck",
        Disabled:           true
    }
    ,{        
        AppID:              "Azul.Zulu",
        Disabled:           true
    }
    ,{        
        AppID:              "Microsoft.Edge",
        Disabled:           true
    }
    ,{
        AppID:              "Oracle.JavaRuntimeEnvironment",
        Disabled:           true
    }
    ,{        
        AppID:              "RStudio.RStudio.OpenSource"
    }
    ,{        
        AppID:              "Posit.RStudio",
        BlockingProcess:    "rstudio"
    }
    ,{        
        AppID:              "RProject.R",
        BlockingProcess:    "rgui"
    }
    ,{        
        AppID:              "Citrix.Workspace",
        BlockingProcess:    "cdviewer"
    }
    ,{        AppID:              "Notepad++.Notepad++"    }
    ,{        AppID:              "7zip.7zip"    }
    ,{        AppID:              "Zoom.Zoom"    }
    ,{        AppID:              "Microsoft.PowerToys"    }
    ,{        AppID:              "AgileBits.1Password"    }
    ,{        AppID:              "Logitech.SetPoint"    }
    ,{        AppID:              "TheDocumentFoundation.LibreOffice"    }
    ,{        AppID:              "Lenovo.QuickClean"    }
    ,{        AppID:              "Bitwarden.Bitwarden"    }
    ,{        AppID:              "SumatraPDF.SumatraPDF"    }
    ,{        AppID:              "Microsoft.WindowsTerminal"    }
    ,{        AppID:              "Logitech.UnifyingSoftware"    }
    ,{        AppID:              "Microsoft.Azure.StorageExplorer"    }
    ,{        AppID:              "calibre.calibre"    }
    ,{        AppID:              "wethat.onenotetaggingkit"    }
    ,{        AppID:              "LogMeIn.LastPass"    }
    ,{        AppID:              "Microsoft.PowerShell.Preview"    }
    ,{        AppID:              "PuTTY.PuTTY"    }
    ,{        AppID:              "Git.Git"    }
    ,{        AppID:              "RARLab.WinRAR"    }
    ,{        AppID:              "JGraph.Draw"    }
    ,{        AppID:              "Meld.Meld"    }
    ,{        AppID:              "Kitware.CMake"    }
    ,{        AppID:              "VideoLAN.VLC"    }
    ,{        AppID:              "Jabra.Direct"    }
    ,{        AppID:              "ArtifexSoftware.GhostScript"    }
    ,{        AppID:              "ImageMagick.ImageMagick"    }
    ,{        AppID:              "IrfanSkiljan.IrfanView"    }
    ,{        AppID:              "OpenJS.NodeJS.LTS"    }
    ,{        AppID:              "Microsoft.webpicmd"    }
    ,{        AppID:              "Apache.OpenOffice"    }
    ,{        AppID:              "DominikReichl.KeePass"    }
    ,{        AppID:              "Microsoft.UpdateAssistant"    }
    ,{        AppID:              "Amazon.AWSCLI"    }
    ,{        AppID:              "Keybase.Keybase" }
    ,{        AppID:              "Anki.Anki" }
    ,{        AppID:              "PostgreSQL.PostgreSQL" }
    ,{        AppID:              "WinSCP.WinSCP" }
    ,{        AppID:              "WinMerge.WinMerge" }
    ,{        AppID:              "Adobe.Acrobat.Reader.64-bit"}
    ,{        AppID:              "RazerInc.RazerInstaller"}
]
'@

$excludeapps = 'Microsoft.Office','Microsoft.Teams','Microsoft.VisualStudio','VMware.HorizonClient','Microsoft.SQLServer','TeamViewer','Docker','DisplayLink.GraphicsDriver','Microsoft.VCRedist','Microsoft.Edge','Cisco.WebexTeams','Amazon.WorkspacesClient'


$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
if ($ResolveWingetPath) {
    $WingetPath = $ResolveWingetPath[-1].Path
}

$whitelistConfig = $whitelistJSON | ConvertFrom-Json -ErrorAction Stop
$whitelistConfig = $whitelistConfig | Where-Object { ($_.Disabled -eq $null -or $_.Disabled -eq $false) }

$ras = $true
If (-Not (Test-RunningAsSystem)) {
    $ras = $false

    #if (-not ($userIsAdmin)) {
    #    $whitelistConfig = $whitelistConfig | Where-Object { $_.UserContext -eq $true }
    #}

    $OUTPUT = $(winget upgrade --accept-source-agreements)
    $OUTPUT = $(winget upgrade --accept-source-agreements)
    Write-Log -Message "Local user mode"
}
elseif ($wingetpath) {
    Write-Log -Message $wingetpath
    Set-Location $wingetpath

    $whitelistConfig = $whitelistConfig | Where-Object { ($_.SystemContext -eq $null -or $_.SystemContext -eq $true) -or ($_.UserContext -eq $null -or $_.UserContext -eq $false) }

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

    if ($OUTPUT -and $lineCount -gt $headerLine+2) {
        $str = $OUTPUT[$headerLine]
        $idPos = $str.indexOf("Id")
        $versionPos = $str.indexOf("Version")-1

        $LIST= [System.Collections.ArrayList]::new()
        for ($i=$headerLine+2;($i -lt $OUTPUT.count-1);$i=$i+1) {
            $lineData = $OUTPUT[$i]
            $LIST.Add(($lineData[$idPos..$versionPos] -Join "").trim())
        }

        $count = 0
        $message = ""

        foreach ($app in $LIST) {
            if ($app -ne "") {
                if ($useWhitelist) {
                    $doUpgrade = $false
                    foreach ($okapp in $whitelistConfig) {
                        if ($app -like "*$($okapp.AppID)*") {
                            if ($ras -or $userIsAdmin) {
                                Write-Log -Message "Upgrade $($okapp.AppID) in system context"
                                $doUpgrade = $true
                                continue
                            }
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
