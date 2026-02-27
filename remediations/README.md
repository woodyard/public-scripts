# Intune Remediation: Winget Application Update Manager

Automated application update solution for Microsoft Intune using winget. The remediation package detects outdated whitelisted applications and upgrades them, supporting both **system context** and **user context** execution with interactive user prompts.

## Architecture Overview

```
Intune Remediation Policy
    |
    +-- Detection Script (runs as SYSTEM)
    |       |
    |       +-- System context: checks winget for available upgrades
    |       +-- User context: creates a scheduled task as the logged-in user
    |       |   to detect user-scoped apps (e.g. VS Code, Chrome user installs)
    |       +-- Merges results, exits 1 if upgrades found
    |
    +-- Remediation Script (runs as SYSTEM, triggered on exit 1)
            |
            +-- Loads whitelist (local file > GitHub > hardcoded fallback)
            +-- Filters disabled apps, checks deferral status
            +-- For each whitelisted app with an available upgrade:
            |       +-- Check if version was skipped (failure tracking)
            |       +-- Check blocking processes
            |       +-- Show WPF dialog if process is running (user prompt)
            |       +-- Handle deferral choices
            |       +-- Execute winget upgrade --silent
            |       +-- Post-upgrade verification (confirms version changed)
            |       +-- On failure: increment count, show skip dialog after 3
            +-- Schedules user context task for user-scoped apps
```

## Files

| File | Version | Tag | Purpose |
|------|---------|-----|---------|
| `availableUpgrades-detect.ps1` | 5.25 | 5D | Main detection script (whitelist-based, dual-context) |
| `availableUpgrades-remediate.ps1` | 8.8 | 8X | Main remediation script (upgrades apps, shows user prompts) |
| `availableUpgrades-detect-all.ps1` | - | - | Alternative detection script (exclude-list approach, simpler) |
| `app-whitelist.json` | - | - | Centralized whitelist configuration for all managed apps |
| `available-detect.ps1` | - | - | Wrapper: downloads and runs the detect script from GitHub |
| `available-remediate.ps1` | - | - | Wrapper: downloads and runs the remediate script from GitHub |
| `available-detect-all.ps1` | - | - | Wrapper: downloads and runs the detect-all script from GitHub |

## Intune Deployment

### Option A: Direct Scripts

Upload `availableUpgrades-detect.ps1` and `availableUpgrades-remediate.ps1` directly into the Intune remediation policy. Place `app-whitelist.json` alongside the scripts or host it on GitHub.

### Option B: Wrapper Scripts (Recommended)

Upload the small wrapper scripts (`available-detect.ps1` and `available-remediate.ps1`) as the Intune remediation scripts. These download and execute the latest versions from GitHub at runtime, so updates to the logic or whitelist are picked up automatically without redeploying through Intune.

```powershell
# Example wrapper (available-detect.ps1):
iex (irm "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/availableUpgrades-detect.ps1")
$exitCode = $LASTEXITCODE
```

### Remediation Policy Settings

- **Run this script using the logged-on credentials**: No (run as SYSTEM)
- **Run script in 64-bit PowerShell**: Yes
- **Schedule**: Hourly or as desired

## Whitelist Configuration (app-whitelist.json)

The whitelist controls which applications are managed. It is loaded with a three-tier fallback:

1. **Local file** - `app-whitelist.json` next to the script
2. **GitHub** - Downloaded from the repository
3. **Hardcoded fallback** - Basic set of common apps built into the script

### Whitelist Entry Properties

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `AppID` | string | Yes | - | Winget package ID (e.g. `Mozilla.Firefox`) |
| `FriendlyName` | string | No | AppID | Display name shown in user prompts |
| `Disabled` | bool | No | `false` | Set to `true` to exclude from upgrades |
| `SystemContext` | bool | No | `true` | Allow upgrade in system context |
| `UserContext` | bool | No | `false` | Allow upgrade in user context (`--scope user`) |
| `UserContextPath` | string | No | - | Path to verify user-context installation exists |
| `BlockingProcess` | string | No | - | Comma-separated process names that block upgrade |
| `AutoCloseProcesses` | string | No | - | Subset of blocking processes safe to kill silently |
| `PromptWhenBlocked` | bool | No | `false` | Show interactive WPF dialog when a blocking process runs |
| `DefaultTimeoutAction` | bool | No | `false` | `true` = proceed with upgrade on timeout; `false` = skip |
| `TimeoutSeconds` | int | No | `60` | Seconds before the dialog times out |
| `DeferralEnabled` | bool | No | `false` | Allow users to postpone the update |
| `MaxDeferralDays` | int | No | `0` | Maximum days the update can be deferred |
| `DeferralOptions` | array | No | `[]` | Options shown in the deferral dialog |
| `ForcedUpgradeMessage` | string | No | - | Message shown when deferrals are exhausted |

### Example Entries

**Full-featured entry with deferrals:**

```json
{
    "AppID": "Mozilla.Firefox",
    "FriendlyName": "Firefox",
    "SystemContext": true,
    "UserContext": true,
    "UserContextPath": "$Env:LocalAppData\\Mozilla Firefox\\firefox.exe",
    "BlockingProcess": "firefox",
    "PromptWhenBlocked": true,
    "DefaultTimeoutAction": false,
    "TimeoutSeconds": 60,
    "DeferralEnabled": true,
    "MaxDeferralDays": 5,
    "DeferralOptions": [
        {"Days": 1, "Label": "1 day"},
        {"Days": 3, "Label": "3 days"},
        {"Days": 5, "Label": "5 days"}
    ],
    "ForcedUpgradeMessage": "Firefox security updates can no longer be deferred."
}
```

**Minimal entry (no blocking process, silent upgrade):**

```json
{
    "AppID": "Git.Git"
}
```

**Disabled entry (detected but not upgraded):**

```json
{
    "AppID": "Microsoft.Edge",
    "Disabled": true
}
```

## Dual-Context Architecture

Intune remediations run as SYSTEM, but some apps are installed per-user (e.g. VS Code, Chrome user installs). The scripts solve this with a dual-context approach:

1. **System context** (default): The script runs `winget upgrade` as SYSTEM to detect/upgrade machine-wide installations.
2. **User context** (scheduled task): The script creates a temporary scheduled task that runs as the logged-in user with `--scope user` to detect/upgrade user-scoped installations.

Communication between contexts uses JSON files in shared temp directories (`C:\ProgramData\Temp`). Marker files (`.userdetection`) coordinate the handoff and are managed by a centralized marker file management system that handles creation, tracking, orphan cleanup, and emergency cleanup on script exit.

### Hidden Task Execution

User-context scheduled tasks are launched via a temporary VBS wrapper (`wscript.exe`) instead of `cmd.exe`. Since `wscript.exe` is a GUI subsystem application, it never creates a console window, eliminating the brief window flash that users would otherwise see during detection and remediation.

### Interactive Session Checks

Before creating user-context tasks, the script verifies:
- An interactive user is logged in (via `Win32_ComputerSystem`, with Explorer process fallback for RDP/Windows 365 sessions)
- `explorer.exe` is running (active desktop session)
- Session ID > 0 (not a service session)

Azure AD / Entra ID environments are fully supported with SID-based user detection and multiple fallback methods for scheduled task principal creation.

## User Interaction

When a blocking process is running and `PromptWhenBlocked` is `true`, the remediation script displays a modern WPF dialog from SYSTEM context:

### Process Close Dialog
- Asks the user to close the blocking application
- Shows current version and available version
- Countdown timer on the default action button
- Positioned in the bottom-right corner (toast-style)
- Dark theme, Windows 11 style

### Deferral Dialog
When `DeferralEnabled` is `true`, users get additional options:
- **Update Now** - Close the app and upgrade immediately
- **Defer** - Postpone the upgrade by a selectable number of days

Deferral state is stored in the registry at `HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals\{AppID}` and tracks:
- Number of deferrals used
- Last deferral date
- User-chosen deadline
- First seen date (for admin hard deadline calculation)

When `MaxDeferralDays` is reached, the update becomes mandatory and the `ForcedUpgradeMessage` is displayed.

### Version Failure Tracking

The remediation script tracks consecutive upgrade failures per application version. When an upgrade fails repeatedly, the user is offered the option to skip that specific version until a newer one is released.

**How it works:**

1. Each failed upgrade increments a per-version failure counter stored in the registry at `HKLM:\SOFTWARE\WingetUpgradeManager\Failures\{AppID}`
2. After **3 consecutive failures** for the same version, a WPF dialog appears with two options:
   - **Skip this version** — the script will not attempt this version again
   - **Try again later** — the script will retry on the next remediation cycle
3. If no choice is made within 60 seconds, the default is "Try again later" (safe default)
4. When a **newer version** becomes available, the skip is automatically cleared and the upgrade proceeds normally
5. On a **successful upgrade**, all failure data for that app is removed

**Registry structure:**

```
HKLM:\SOFTWARE\WingetUpgradeManager\Failures\{AppID}
    FailedVersion   (String)  – version that accumulated failures
    FailureCount    (DWORD)   – number of consecutive failures
    Skipped         (String)  – "true" / "false"
    SkippedAt       (String)  – ISO 8601 datetime
```

### Post-Upgrade Verification

When winget reports exit code 0 but no explicit success message (e.g. "Successfully installed") appears in the output, the script runs a post-upgrade verification step. It checks `winget list --id {AppID} --source winget` to confirm the installed version was actually updated. If the "Available" column is still present (meaning the update didn't take effect), the upgrade is counted as a failure instead of a false-positive success. This prevents endless upgrade loops for apps whose installer exits successfully without changing the installed version.

### Timeout Behavior

| `DefaultTimeoutAction` | Behavior on timeout |
|------------------------|---------------------|
| `true` | Proceeds with upgrade (closes blocking process) |
| `false` | Skips the upgrade (waits for next run) |

## Detection Script: Detect-All Variant

`availableUpgrades-detect-all.ps1` is an alternative, simpler detection script that uses an **exclude-list** approach instead of a whitelist. It detects all available winget upgrades except those explicitly excluded.

Current exclude list:
```powershell
$excludeapps = @('Fortinet.FortiClientVPN', 'Microsoft.Office')
```

This variant does not support dual-context detection or user-scoped apps. It is useful for broad coverage where managing individual app entries is not required.

## Exit Codes

### Detection Scripts
| Code | Meaning |
|------|---------|
| `0` | No upgrades available / compliant / OOBE not complete |
| `1` | Upgrades available (triggers remediation) |

### Remediation Script
| Code | Meaning |
|------|---------|
| `0` | Completed successfully / OOBE not complete |
| `1` | Error occurred during remediation |

## Logging

Logs are written to both the console (for Intune visibility) and to files:

| Context | Log Location |
|---------|--------------|
| System context | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\` |
| User context | `%TEMP%` |

Log files are named with the pattern `{ScriptName}-{dd-MM-yy_HH-mm}.log` and are automatically cleaned up after 1 month.

Each log line includes a script tag (e.g. `5D`, `8X`) for version tracking across Intune log output.

When apps have been deferred by the user, the detection script outputs an additional line:

```
[5D] Deferred: Mozilla.Firefox (until 28.02.2026 14:30)
```

This makes postponed updates visible in the Intune remediation output without requiring log file analysis.

## OOBE / Autopilot Safety

Both scripts check that the Out-Of-Box Experience (OOBE) is complete before running. During Autopilot enrollment or ESP (Enrollment Status Page), the scripts exit with code `0` to avoid interfering with the provisioning process.

## Winget Path Resolution

The scripts resolve the winget executable path dynamically to support both x64 and ARM64 architectures:

```powershell
Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*64__8wekyb3d8bbwe"
```

The first `winget upgrade` call is validated for output quality. If the output is invalid (winget initialization noise), the command is retried automatically.

## Bootstrapper Detection

When running via wrapper scripts, the main scripts detect that the source file is a small bootstrapper (< 1 KB) and automatically download the full script from the URL embedded in the wrapper before creating user-context scheduled tasks. This ensures scheduled tasks always execute the complete script logic.

## Test Environment

The `test/` subdirectory contains development versions of the scripts that point to test-path URLs. To promote test to production, copy the scripts to the parent directory and update internal URLs from `remediations/test/` to `remediations/`.

## Install Technology Mismatch Handling

When winget reports an "install technology is different" error (e.g. MSI vs EXE installer change between versions), the remediation script automatically:
1. Uninstalls the current version
2. Waits for cleanup
3. Installs the new version fresh
