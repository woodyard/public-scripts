# Uninstall-HeimdalThor.ps1
# Script to uninstall Heimdal Thor Agent

# Function to write logs
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    
    $LogTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "$LogTime [$Level] $Message"
    
    # Write to console with color coding
    switch ($Level) {
        'Warning' { Write-Host $LogLine -ForegroundColor Yellow }
        'Error' { Write-Host $LogLine -ForegroundColor Red }
        default { Write-Host $LogLine }
    }
    
    # Also write to log file
    $LogPath = Join-Path $env:TEMP "HeimdalUninstall.log"
    Add-Content -Path $LogPath -Value $LogLine
}

function Uninstall-HeimdalThor {
    try {
        Write-Log "Starting Heimdal Thor uninstallation process"
        
        # Get all uninstall keys
        $uninstallKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        # Find Heimdal entries
        $heimdalApps = Get-ItemProperty $uninstallKeys | Where-Object { 
            $_.DisplayName -like "*Heimdal*" -or $_.DisplayName -like "*Thor*" 
        }

        if (-not $heimdalApps) {
            Write-Log "No Heimdal installation found" -Level Warning
            return $false
        }

        # Process each found installation
        foreach ($app in $heimdalApps) {
            Write-Log "Found installation: $($app.DisplayName)"
            
            if ($app.PSChildName -match '^{[A-Z0-9\-]+}$') {
                # Use MSI uninstall if product code is available
                Write-Log "Attempting MSI uninstall with product code: $($app.PSChildName)"
                $process = Start-Process "msiexec.exe" -ArgumentList "/x $($app.PSChildName) /qn" -Wait -PassThru
                
                if ($process.ExitCode -eq 0) {
                    Write-Log "Successfully uninstalled via MSI"
                } else {
                    Write-Log "MSI uninstall failed with exit code: $($process.ExitCode)" -Level Warning
                }
            }
            elseif ($app.UninstallString) {
                Write-Log "Using uninstall string: $($app.UninstallString)"
                
                # Handle MSI uninstall strings
                if ($app.UninstallString -match "MsiExec.exe") {
                    $productCode = $app.UninstallString | Select-String -Pattern "{[A-Z0-9\-]+}" | 
                                 ForEach-Object { $_.Matches[0].Value }
                    
                    if ($productCode) {
                        $process = Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn" -Wait -PassThru
                        
                        if ($process.ExitCode -eq 0) {
                            Write-Log "Successfully uninstalled via MSI product code"
                        } else {
                            Write-Log "MSI uninstall failed with exit code: $($process.ExitCode)" -Level Warning
                        }
                    }
                }
                else {
                    # Handle non-MSI uninstall strings
                    $uninstallString = $app.UninstallString
                    if ($uninstallString -notlike "* /quiet*") {
                        $uninstallString = "$uninstallString /quiet /norestart"
                    }
                    
                    $process = Start-Process "cmd.exe" -ArgumentList "/c $uninstallString" -Wait -PassThru
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log "Successfully uninstalled via uninstall string"
                    } else {
                        Write-Log "Uninstall failed with exit code: $($process.ExitCode)" -Level Warning
                    }
                }
            }
            else {
                Write-Log "No valid uninstall method found for: $($app.DisplayName)" -Level Warning
            }
        }

        # Check if uninstall was successful
        $remainingApps = Get-ItemProperty $uninstallKeys | Where-Object { 
            $_.DisplayName -like "*Heimdal*" -or $_.DisplayName -like "*Thor*" 
        }

        if ($remainingApps) {
            Write-Log "Some Heimdal components remain installed" -Level Warning
            return $false
        } else {
            Write-Log "Uninstallation completed successfully"
            return $true
        }

    } catch {
        Write-Log "Error during uninstallation: $_" -Level Error
        return $false
    }
}

# Execute the uninstallation
$result = Uninstall-HeimdalThor

# Set exit code based on result
if ($result) {
    exit 0
} else {
    exit 1
}