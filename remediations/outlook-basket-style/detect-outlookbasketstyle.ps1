# Intune Remediation Script - Detection
# Version: 1.0.0
# Purpose: Detect if Outlook DelegateWastebasketStyle is properly configured to store deleted items in mailbox owner's folder
# Output: Returns "Compliant" if value is set to 4, otherwise "NonCompliant"
# Target: Office 2016-2021, Microsoft 365 (user context)

# Initialize variables
$ErrorActionPreference = "Stop"
$scriptVersion = "1.0.0"

# Define registry path for Outlook (supports Office 2016-2021, Microsoft 365)
$outlookPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\General"
$valueName = "DelegateWastebasketStyle"
$expectedValue = 4

try {
    # Check if the Outlook registry path exists
    if (!(Test-Path $outlookPath)) {
        Write-Output "v$scriptVersion NonCompliant: Outlook registry path does not exist"
        exit 1
    }

    # Check if the DelegateWastebasketStyle value exists
    $registryValue = Get-ItemProperty -Path $outlookPath -Name $valueName -ErrorAction SilentlyContinue
    
    if ($null -eq $registryValue) {
        Write-Output "v$scriptVersion NonCompliant: DelegateWastebasketStyle value does not exist"
        exit 1
    }

    # Get the current value
    $currentValue = $registryValue.$valueName

    # Check if the value is set to the expected value (4)
    if ($currentValue -eq $expectedValue) {
        Write-Output "v$scriptVersion Compliant: DelegateWastebasketStyle is correctly set to $expectedValue"
        exit 0
    } else {
        Write-Output "v$scriptVersion NonCompliant: DelegateWastebasketStyle is set to $currentValue, expected $expectedValue"
        exit 1
    }
}
catch {
    Write-Output "v$scriptVersion Error: $($_.Exception.Message)"
    exit 1
}