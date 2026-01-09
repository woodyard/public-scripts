<#
.SYNOPSIS
    Retrieves allowed DNS lookups from Cloudflare Zero Trust Gateway for the last 24 hours.
.DESCRIPTION
    This script fetches DNS query logs from Cloudflare Zero Trust Gateway, filtering for
    allowed queries from the last 24 hours. Results are sorted by frequency to show the
    most frequently queried domains at the top.
.PARAMETER ConfigFile
    Path to a JSON configuration file containing ApiToken and AccountId.
    Default locations checked: ./cloudflare-config.json, ~/.cloudflare-config.json
.PARAMETER ApiToken
    Cloudflare API token with Zero Trust read permissions.
    Priority: Parameter > Config file > Environment variable
.PARAMETER AccountId
    Cloudflare Account ID. Found in the Zero Trust dashboard URL.
    Priority: Parameter > Config file > Environment variable
.PARAMETER HoursBack
    Number of hours to look back for DNS logs. Default: 24
.PARAMETER MinimumCount
    Minimum number of occurrences to include in results. Default: 1
.PARAMETER Top
    Number of top domains to display. Default: all
.EXAMPLE
    # Run with default settings (last 24 hours)
    .\Get-CloudflareAllowedDnsLookups.ps1 -ApiToken "your_token" -AccountId "your_account_id"
.EXAMPLE
    # Using a config file (recommended for security)
    .\Get-CloudflareAllowedDnsLookups.ps1 -ConfigFile "~/.cloudflare-config.json"
.EXAMPLE
    # Get top 50 domains from last 12 hours
    .\Get-CloudflareAllowedDnsLookups.ps1 -HoursBack 12 -Top 50
.EXAMPLE
    # Only show domains queried at least 10 times
    .\Get-CloudflareAllowedDnsLookups.ps1 -MinimumCount 10
.NOTES
    Version:        1.0
    Author:         Henrik Skovgaard
    Creation Date:  2025-12-06
    
    API Token Requirements:
    - Account > Zero Trust > Read
    - Account > Gateway > Read
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigFile,
    
    [Parameter()]
    [string]$ApiToken,
    
    [Parameter()]
    [string]$AccountId,
    
    [Parameter()]
    [int]$HoursBack = 24,
    
    [Parameter()]
    [int]$MinimumCount = 1,
    
    [Parameter()]
    [int]$Top = 0
)

#region Config File Loading

# Default config file locations to check
$DefaultConfigPaths = @(
    (Join-Path $PSScriptRoot "cloudflare-config.json"),
    (Join-Path $HOME ".cloudflare-config.json"),
    (Join-Path $HOME "cloudflare-config.json")
)

# Determine which config file to use
$ConfigToUse = $null
if ($ConfigFile) {
    # User specified a config file
    $ExpandedPath = [System.Environment]::ExpandEnvironmentVariables($ConfigFile)
    if ($ExpandedPath.StartsWith("~")) {
        $ExpandedPath = Join-Path $HOME $ExpandedPath.Substring(2)
    }
    if (Test-Path $ExpandedPath) {
        $ConfigToUse = $ExpandedPath
    } else {
        Write-Error "Config file not found: $ConfigFile"
        exit 1
    }
} else {
    # Check default locations
    foreach ($path in $DefaultConfigPaths) {
        if (Test-Path $path) {
            $ConfigToUse = $path
            break
        }
    }
}

# Load config file if found
if ($ConfigToUse) {
    Write-Verbose "Loading configuration from: $ConfigToUse"
    try {
        $Config = Get-Content $ConfigToUse -Raw | ConvertFrom-Json
        
        # Only use config values if parameters weren't explicitly provided
        if (-not $ApiToken -and $Config.ApiToken) {
            $ApiToken = $Config.ApiToken
        }
        if (-not $AccountId -and $Config.AccountId) {
            $AccountId = $Config.AccountId
        }
    }
    catch {
        Write-Error "Failed to parse config file: $_"
        exit 1
    }
}

# Fall back to environment variables if still not set
if (-not $ApiToken) {
    $ApiToken = $env:CLOUDFLARE_API_TOKEN
}
if (-not $AccountId) {
    $AccountId = $env:CLOUDFLARE_ACCOUNT_ID
}

#endregion

#region Configuration

$script:CloudflareApiBase = "https://api.cloudflare.com/client/v4"

#endregion

#region Functions

function Get-CloudflareHeaders {
    @{
        "Authorization" = "Bearer $ApiToken"
        "Content-Type"  = "application/json"
    }
}

function Invoke-CloudflareApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        
        [Parameter()]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE')]
        [string]$Method = 'GET',
        
        [Parameter()]
        [object]$Body,
        
        [Parameter()]
        [hashtable]$QueryParams
    )
    
    $uri = "$script:CloudflareApiBase$Endpoint"
    
    # Add query parameters if provided
    if ($QueryParams) {
        $queryString = ($QueryParams.GetEnumerator() | ForEach-Object { 
            "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))" 
        }) -join '&'
        $uri += "?$queryString"
    }
    
    $headers = Get-CloudflareHeaders
    
    $params = @{
        Uri     = $uri
        Method  = $Method
        Headers = $headers
    }
    
    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }
    
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        
        if (-not $response.success) {
            $errorMsg = ($response.errors | ForEach-Object { $_.message }) -join "; "
            throw "Cloudflare API error: $errorMsg"
        }
        
        return $response
    }
    catch {
        # PowerShell Core (Mac/Linux) error handling
        if ($_.ErrorDetails.Message) {
            try {
                $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorBody.errors) {
                    $errorMsg = ($errorBody.errors | ForEach-Object { "$($_.code): $($_.message)" }) -join "; "
                    throw "Cloudflare API error: $errorMsg"
                }
            }
            catch [System.ArgumentException] {
                # Not JSON, throw original error
            }
        }
        throw $_
    }
}

function Get-GatewayDnsLogs {
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime,
        
        [Parameter()]
        [datetime]$EndTime
    )
    
    Write-Verbose "Fetching Gateway DNS logs from $StartTime to $EndTime..."
    
    # Format timestamps in RFC3339 format
    $startTimeStr = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    $endTimeStr = $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    
    # Build GraphQL query for Gateway DNS logs
    # Note: Cloudflare Gateway logs API uses GraphQL
    $query = @"
{
  viewer {
    accounts(filter: {accountTag: "$AccountId"}) {
      gatewayDnsActivityLog(
        filter: {
          datetime_geq: "$startTimeStr",
          datetime_leq: "$endTimeStr",
          actionType: "allow"
        }
        limit: 10000
      ) {
        queryName
        actionType
        datetime
      }
    }
  }
}
"@

    $body = @{
        query = $query
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/graphql" `
            -Method POST `
            -Headers (Get-CloudflareHeaders) `
            -Body ($body | ConvertTo-Json -Depth 10) `
            -ErrorAction Stop
        
        if ($response.errors) {
            $errorMsg = ($response.errors | ForEach-Object { $_.message }) -join "; "
            throw "GraphQL API error: $errorMsg"
        }
        
        return $response.data.viewer.accounts[0].gatewayDnsActivityLog
    }
    catch {
        Write-Error "Failed to fetch DNS logs: $_"
        throw
    }
}

function Test-ApiConnection {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Testing API connection..."
    try {
        $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId" -Method GET
        return $true
    }
    catch {
        Write-Error "Failed to connect to Cloudflare API: $_"
        return $false
    }
}

#endregion

#region Main

# Banner
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Cloudflare Gateway - Allowed DNS Lookups Report (24h)          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Show config file status
if ($ConfigToUse) {
    Write-Host "Configuration loaded from: $ConfigToUse" -ForegroundColor Gray
    Write-Host ""
}

# Validate required parameters
if (-not $ApiToken) {
    Write-Error "API Token is required. Provide via -ApiToken parameter, config file, or CLOUDFLARE_API_TOKEN environment variable."
    exit 1
}

if (-not $AccountId) {
    Write-Error "Account ID is required. Provide via -AccountId parameter, config file, or CLOUDFLARE_ACCOUNT_ID environment variable."
    exit 1
}

# Test API connection
Write-Host "Testing API connection..." -ForegroundColor Yellow
if (-not (Test-ApiConnection)) {
    exit 1
}
Write-Host "  API connection successful!" -ForegroundColor Green
Write-Host ""

# Calculate time range
$endTime = Get-Date
$startTime = $endTime.AddHours(-$HoursBack)

Write-Host "Fetching DNS logs..." -ForegroundColor Yellow
Write-Host "  Time range: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  Hours back: $HoursBack" -ForegroundColor Gray
Write-Host ""

# Fetch DNS logs
try {
    $dnsLogs = Get-GatewayDnsLogs -StartTime $startTime -EndTime $endTime
    
    if (-not $dnsLogs -or $dnsLogs.Count -eq 0) {
        Write-Host "No allowed DNS queries found in the specified time range." -ForegroundColor Yellow
        exit 0
    }
    
    Write-Host "  Retrieved $($dnsLogs.Count) DNS query records" -ForegroundColor Gray
    Write-Host ""
    
    # Group and count domains
    Write-Host "Processing and aggregating results..." -ForegroundColor Yellow
    $domainStats = $dnsLogs | 
        Where-Object { $_.queryName } |
        Group-Object -Property queryName |
        Select-Object @{Name='Domain';Expression={$_.Name}}, 
                      @{Name='Count';Expression={$_.Count}} |
        Where-Object { $_.Count -ge $MinimumCount } |
        Sort-Object -Property Count -Descending
    
    if ($Top -gt 0) {
        $domainStats = $domainStats | Select-Object -First $Top
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Allowed DNS Lookups Report                     ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # Display results
    Write-Host "Top domains by query frequency:" -ForegroundColor Cyan
    Write-Host "$(if ($MinimumCount -gt 1) { "(Minimum $MinimumCount queries) " })$(if ($Top -gt 0) { "Showing top $Top" })" -ForegroundColor Gray
    Write-Host ""
    Write-Host ("{0,-8} {1}" -f "Count", "Domain") -ForegroundColor Yellow
    Write-Host ("{0,-8} {1}" -f "-----", "------") -ForegroundColor Yellow
    
    foreach ($stat in $domainStats) {
        $countColor = if ($stat.Count -gt 100) { "Red" } 
                     elseif ($stat.Count -gt 50) { "Yellow" } 
                     elseif ($stat.Count -gt 10) { "Cyan" } 
                     else { "White" }
        
        Write-Host ("{0,-8} {1}" -f $stat.Count, $stat.Domain) -ForegroundColor $countColor
    }
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Total unique domains: $($domainStats.Count)" -ForegroundColor Gray
    Write-Host "  Total queries analyzed: $($dnsLogs.Count)" -ForegroundColor Gray
    Write-Host "  Time period: Last $HoursBack hours" -ForegroundColor Gray
    Write-Host ""
    
    # Export option
    $exportPath = Join-Path $PSScriptRoot "cloudflare-dns-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $domainStats | Export-Csv -Path $exportPath -NoTypeInformation
    Write-Host "Results exported to: $exportPath" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Error "Failed to retrieve DNS logs: $_"
    Write-Host ""
    Write-Host "Note: This script requires Cloudflare Gateway DNS logs to be available." -ForegroundColor Yellow
    Write-Host "Ensure that:" -ForegroundColor Yellow
    Write-Host "  1. Zero Trust Gateway is properly configured" -ForegroundColor Yellow
    Write-Host "  2. DNS logging is enabled" -ForegroundColor Yellow
    Write-Host "  3. Your API token has the required permissions" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

#endregion