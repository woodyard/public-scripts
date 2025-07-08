<#
.SYNOPSIS
    Winget Application Update Detection Script

.DESCRIPTION
    This script detects available application updates using winget and reports them to Intune.
    It supports both system and user context applications and uses a whitelist approach for security.
    The script is designed to work as a detection script in Microsoft Intune remediation policies.

.NOTES
    Author: Henrik Skovgaard
    Version: 2.1
    Tag: 2B
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed user context detection, improved error handling, added blocking process logic
    2.1 - Added Logitech.Options, Logitech.OptionsPlus, TrackerSoftware.PDF-XChangeEditor to whitelist
    
    Exit Codes:
    0 - No upgrades available or script completed successfully
    1 - Upgrades available (triggers remediation) or OOBE not complete
#>

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
        UserContextPath:    "$Env:LocalAppData\\Mozilla Firefox\\firefox.exe",
        BlockingProcess:    "firefox"
    }
    ,{
        AppID:              "Google.Chrome",
        SystemContext:      true,
        UserContext:        true,
        UserContextPath:    "$Env:LocalAppData\\Google\\Chrome\\Application\\chrome.exe",
        BlockingProcess:    "chrome"
    }
    ,{
        AppID:              "Microsoft.VisualStudioCode",
        SystemContext:      true,
        UserContext:        true,
        UserContextPath:    "$Env:LocalAppData\\Programs\\Microsoft VS Code\\Code.exe",
        BlockingProcess:    "Code"
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
    ,{        AppID:              "Notepad++.Notepad++",              BlockingProcess:    "notepad++" }
    ,{        AppID:              "7zip.7zip",                        BlockingProcess:    "7zFM" }
    ,{        AppID:              "Zoom.Zoom",                        BlockingProcess:    "Zoom" }
    ,{        AppID:              "Microsoft.PowerToys",              BlockingProcess:    "PowerToys" }
    ,{        AppID:              "AgileBits.1Password",              BlockingProcess:    "1Password" }
    ,{        AppID:              "Logitech.SetPoint" }
    ,{        AppID:              "TheDocumentFoundation.LibreOffice", BlockingProcess:    "soffice" }
    ,{        AppID:              "Lenovo.QuickClean" }
    ,{        AppID:              "Bitwarden.Bitwarden",              BlockingProcess:    "Bitwarden" }
    ,{        AppID:              "SumatraPDF.SumatraPDF",            BlockingProcess:    "SumatraPDF" }
    ,{        AppID:              "Microsoft.WindowsTerminal",        BlockingProcess:    "WindowsTerminal" }
    ,{        AppID:              "Logitech.UnifyingSoftware" }
    ,{        AppID:              "Microsoft.Azure.StorageExplorer",  BlockingProcess:    "StorageExplorer" }
    ,{        AppID:              "calibre.calibre",                  BlockingProcess:    "calibre" }
    ,{        AppID:              "wethat.onenotetaggingkit" }
    ,{        AppID:              "LogMeIn.LastPass",                 BlockingProcess:    "LastPass" }
    ,{        AppID:              "Microsoft.PowerShell.Preview",     BlockingProcess:    "pwsh" }
    ,{        AppID:              "PuTTY.PuTTY",                      BlockingProcess:    "putty" }
    ,{        AppID:              "Git.Git" }
    ,{        AppID:              "RARLab.WinRAR",                    BlockingProcess:    "WinRAR" }
    ,{        AppID:              "JGraph.Draw" }
    ,{        AppID:              "Meld.Meld",                        BlockingProcess:    "Meld" }
    ,{        AppID:              "Kitware.CMake" }
    ,{        AppID:              "VideoLAN.VLC",                     BlockingProcess:    "vlc" }
    ,{        AppID:              "Jabra.Direct",                     BlockingProcess:    "JabraDirectCoreService" }
    ,{        AppID:              "ArtifexSoftware.GhostScript" }
    ,{        AppID:              "ImageMagick.ImageMagick" }
    ,{        AppID:              "IrfanSkiljan.IrfanView",           BlockingProcess:    "i_view64" }
    ,{        AppID:              "OpenJS.NodeJS.LTS" }
    ,{        AppID:              "Microsoft.webpicmd" }
    ,{        AppID:              "Apache.OpenOffice",                BlockingProcess:    "soffice" }
    ,{        AppID:              "DominikReichl.KeePass",            BlockingProcess:    "KeePass" }
    ,{        AppID:              "Microsoft.UpdateAssistant" }
    ,{        AppID:              "Amazon.AWSCLI" }
    ,{        AppID:              "Keybase.Keybase",                  BlockingProcess:    "Keybase" }
    ,{        AppID:              "Anki.Anki",                        BlockingProcess:    "anki" }
    ,{        AppID:              "PostgreSQL.PostgreSQL" }
    ,{        AppID:              "WinSCP.WinSCP",                    BlockingProcess:    "WinSCP" }
    ,{        AppID:              "WinMerge.WinMerge",                BlockingProcess:    "WinMergeU" }
    ,{        AppID:              "Adobe.Acrobat.Reader.64-bit",      BlockingProcess:    "AcroRd32" }
    ,{        AppID:              "RazerInc.RazerInstaller"}
    ,{        AppID:              "Cloudflare.cloudflared"}
    ,{        AppID:              "Microsoft.Bicep"}
    ,{        AppID:              "JanDeDobbeleer.OhMyPosh"}
    ,{        AppID:              "Logitech.Options"}
    ,{        AppID:              "Logitech.OptionsPlus"}
    ,{        AppID:              "TrackerSoftware.PDF-XChangeEditor"}
]
'@

$excludeapps = 'Microsoft.Office','Microsoft.Teams','Microsoft.VisualStudio','VMware.HorizonClient','Microsoft.SQLServer','TeamViewer','Docker','DisplayLink.GraphicsDriver','Microsoft.VCRedist','Microsoft.Edge','Cisco.WebexTeams','Amazon.WorkspacesClient'


$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
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

$ras = $true
If (-Not (Test-RunningAsSystem)) {
    $ras = $false

    #if (-not ($userIsAdmin)) {
    #    $whitelistConfig = $whitelistConfig | Where-Object { $_.UserContext -eq $true }
    #}

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

    # In system context, we can upgrade both system and user context apps
    $whitelistConfig = $whitelistConfig | Where-Object { ($_.SystemContext -eq $null -or $_.SystemContext -eq $true) -or ($_.UserContext -eq $null -or $_.UserContext -eq $true) }

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
        for ($i=$headerLine+2;($i -lt $OUTPUT.count);$i=$i+1) {
            $lineData = $OUTPUT[$i]
            # Stop parsing if we hit the second section or empty lines
            if ($lineData -like "*upgrade available, but require*" -or $lineData.Trim() -eq "" -or $lineData -like "*following packages*") {
                break
            }
            $appId = ($lineData[$idPos..$versionPos] -Join "").trim()
            if ($appId -ne "") {
                $null = $LIST.Add($appId)
            }
        }

        $count = 0
        $message = ""

        foreach ($app in $LIST) {
            if ($app -ne "") {
                if ($useWhitelist) {
                    $doUpgrade = $false
                    foreach ($okapp in $whitelistConfig) {
                        if ($app -like "*$($okapp.AppID)*") {
                            # Check for blocking processes
                            $blockingProcessName = $okapp.BlockingProcess
                            if (-not [string]::IsNullOrEmpty($blockingProcessName)) {
                                if (Get-Process -Name $blockingProcessName -ErrorAction SilentlyContinue) {
                                    Write-Log -Message "Skipping $($okapp.AppID) - blocking process $blockingProcessName is running"
                                    continue
                                }
                            }
                            
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
            Write-Log -Message "No upgrades available [2B]"
            exit 0
        }
        if ($message -eq "") {
            $message = "No upgrades available (0x0000001-$count) [2B]"
        }
        Write-Log -Message "$message [2B]"
        exit 1
    }
    Write-Log -Message "No upgrades (0x0000002)"
    exit 0
}
Write-Log -Message "Winget not detected"
exit 0 #change to 1 if the remediation script can install winget :)
