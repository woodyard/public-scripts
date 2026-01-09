# Intune Remediation Script - Remediation
# Version: 1.0.0
# Purpose: Configure Outlook DelegateWastebasketStyle to store deleted items in mailbox owner's folder
# Output: Returns success or failure message
# Target: Office 2016-2021, Microsoft 365 (user context)

# Initialize variables
$ErrorActionPreference = "Stop"
$scriptVersion = "1.0.0"

# Define registry path for Outlook (supports Office 2016-2021, Microsoft 365)
$outlookPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\General"
$valueName = "DelegateWastebasketStyle"
$targetValue = 4

try {
    # Check if path exists, if not create it
    if (!(Test-Path $outlookPath)) {
        Write-Output "Registry path does not exist, creating: $outlookPath"
        New-Item -Path $outlookPath -Force | Out-Null
    }

    # Set DelegateWastebasketStyle to 4 (Stores deleted items in the mailbox owner's folder)
    New-ItemProperty -Path $outlookPath -Name $valueName -Value $targetValue -PropertyType DWORD -Force | Out-Null

    # Verify the setting was applied correctly
    $verifyValue = Get-ItemProperty -Path $outlookPath -Name $valueName -ErrorAction Stop
    $currentValue = $verifyValue.$valueName

    if ($currentValue -eq $targetValue) {
        Write-Output "v$scriptVersion Success: DelegateWastebasketStyle configured successfully to store deleted items in mailbox owner's folder (value: $currentValue)"
        exit 0
    } else {
        Write-Output "v$scriptVersion Error: Failed to set correct value - current: $currentValue, expected: $targetValue"
        exit 1
    }
}
catch {
    Write-Output "v$scriptVersion Error: Failed to configure DelegateWastebasketStyle: $($_.Exception.Message)"
    exit 1
}