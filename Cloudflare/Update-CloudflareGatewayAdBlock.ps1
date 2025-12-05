<#
.SYNOPSIS
    Automatically updates Cloudflare Zero Trust Gateway DNS policy for ad blocking,
    including an optional whitelist policy.
.DESCRIPTION
    This script creates or updates DNS policies in Cloudflare Zero Trust Gateway.
    It includes a high-precedence 'Allow' policy (Whitelist) for essential domains
    that may be false-positively blocked, and a high-precedence 'Block' policy
    for common ad/tracker/malware domain fragments (Ad Blocker) using regex pattern matching.

    It uses the Cloudflare API to manage the policies automatically.
.PARAMETER ConfigFile
    Path to a JSON configuration file containing ApiToken and AccountId.
    Default locations checked: ./cloudflare-config.json, ~/.cloudflare-config.json
.PARAMETER ApiToken
    Cloudflare API token with Zero Trust edit permissions.
    Priority: Parameter > Config file > Environment variable
.PARAMETER AccountId
    Cloudflare Account ID. Found in the Zero Trust dashboard URL.
    Priority: Parameter > Config file > Environment variable
.PARAMETER PolicyName
    Name of the DNS policy to create/update. Default: "Ad Blocker"
.PARAMETER WhitelistedDomains
    An array of additional domains to add to the whitelist (on top of config file domains).
    Example: -WhitelistedDomains @('extra.domain.com', 'another.domain.net')
.PARAMETER EnableWhitelistPolicy
    A switch to control whether the Whitelist Policy is created or updated.
    Whitelist domains are loaded from config file (WhitelistDomains array) or defaults.
    Default is $true (enabled).
.PARAMETER WhitelistPolicyName
    Name of the Whitelist DNS policy to create/update. Default: "Whitelist (Allow Explicit)"
.PARAMETER IncludeAbusedTlds
    A switch to control whether the Abused TLDs Blocker policy is created or updated.
.PARAMETER AbusedTldPolicyName
    Name of the Abused TLDs policy to create/update. Default: "Abused TLDs Blocker"
.PARAMETER WhatIf
    Shows what would happen without making changes.
.EXAMPLE
    # Run with default settings, creating the Ad Blocker and Whitelist policies
    .\Update-CloudflareGatewayAdBlock.ps1 -ApiToken "your_token" -AccountId "your_account_id"

.EXAMPLE
    # Using a config file (recommended for security)
    .\Update-CloudflareGatewayAdBlock.ps1 -ConfigFile "~/.cloudflare-config.json"
    
    # Config file format (JSON):
    # {
    #     "ApiToken": "your_api_token_here",
    #     "AccountId": "your_account_id_here",
    #     "WhitelistDomains": [
    #         "officeapps.live.com"
    #     ]
    # }

.EXAMPLE
    # Disable the whitelist policy but keep the ad blocker
    .\Update-CloudflareGatewayAdBlock.ps1 -EnableWhitelistPolicy:$false

.EXAMPLE
    # Add extra domains to the whitelist (in addition to config file)
    .\Update-CloudflareGatewayAdBlock.ps1 -WhitelistedDomains @("my.safe.domain.net")
.NOTES
    Version:        1.8 (Whitelist in config)
    Author:         Henrik Skovgaard / Modified by AI
    Creation Date:  2025-11-30
    
    Version History:
    1.5 - Hardcoded Whitelist and Policy Control
    1.6 - Regex v2.3: Added adskeeper, clevertap, kochava, leanplum
    1.7 - Added config file support for secure credential storage
    1.8 - Moved whitelist domains to config file (WhitelistDomains array)

    API Token Requirements:
    - Account > Zero Trust > Edit
    - Account > Account Firewall Access Rules > Edit
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ConfigFile,
    
    [Parameter()]
    [string]$ApiToken,
    
    [Parameter()]
    [string]$AccountId,
    
    [Parameter()]
    [string]$PolicyName = "Ad Blocker",

    [Parameter()]
    [string[]]$WhitelistedDomains,
    
    [Parameter()]
    [switch]$EnableWhitelistPolicy = $true,
    
    [Parameter()]
    [string]$WhitelistPolicyName = "Whitelist (Allow Explicit)",
    
    [Parameter()]
    [switch]$IncludeAbusedTlds,
    
    [Parameter()]
    [string]$AbusedTldPolicyName = "Abused TLDs Blocker"
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
        # Load whitelist domains from config
        if ($Config.WhitelistDomains -and $Config.WhitelistDomains.Count -gt 0) {
            $script:ConfigWhitelistDomains = @($Config.WhitelistDomains)
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

# Default whitelist domains (used if no config file specifies WhitelistDomains)
$script:DefaultWhitelistDomains = @(
    "officeapps.live.com",                   # Office 365 services (Word, PowerPoint, Excel telemetry and features)
    "clients4.google.com",                   # Common false positive for Chrome/Android updates
    "aiv-delivery.net"                       # Amazon Prime Video / Interactive Video service (all regions)
)

# Build the full whitelist: Config domains (or defaults) + any command-line domains
$script:FullWhitelistDomains = @()

# Use config whitelist if provided, otherwise use defaults
if ($script:ConfigWhitelistDomains -and $script:ConfigWhitelistDomains.Count -gt 0) {
    $script:FullWhitelistDomains += $script:ConfigWhitelistDomains
} else {
    $script:FullWhitelistDomains += $script:DefaultWhitelistDomains
}

# Add any domains provided via command-line parameter
if ($WhitelistedDomains) {
    $script:FullWhitelistDomains += $WhitelistedDomains
}
$script:FullWhitelistDomains = $script:FullWhitelistDomains | Select-Object -Unique

# Main ad-blocking regex pattern (v2.3)
# Changes in v2.3:
#   - Added: adskeeper, clevertap, kochava, leanplum (emerging ad-tech/marketing platforms from 2024-2025 blocklists)
#   - Note: Standalone 'lytics' was removed in v1.3 (caused false positives on *analytics* domains)
$script:AdBlockRegex = '(advert|adserv|adsystem|adtrack|adserver|adtech|adnetwork|doubleclick|2mdn|2o7|33across|360yield|3lift|aax|aaxads|adcash|adclick|adcolony|addthis|adform|adhaven|adhese|adition|adjust|adloox|adlooxtracking|admantx|admicro|admixer|admob|adnami|adnxs|adskeeper|adomik|adpushup|adroll|adsafeprotected|adsrvr|adsterra|adswizz|adtelligent|adventori|adzerk|aerserv|agkn|amazon-adsystem|amplitude|aniview|anzuinfra|apester|applovin|appsflyer|aralego|atdmt|atwola|aumago|avazu|bannersnack|batmobi|bidswitch|bidtheatre|bizible|bluecore|bluecava|blueconic|bounceexchange|braze|btloader|bttrack|carambo|casalemedia|cedexis|chartbeat|cheabit|cleverads|clevertap|clickagy|clicktale|cluep|cohesion|contextly|contextweb|convertkit|convertmedia|crazymedia|criteo|crwdcntrl|custhelp|demdex|dftrack|districtm|dotomi|doubleverify|dstillery|dtscout|dynatrace|dyntrk|efectivoads|emxdgt|engagio|enquisite|eulerian|everesttech|exelator|eyeota|fastly-insights|fidelity-media|flashtalking|foresee|foxpush|freeskreen|freewheel|fuseplatform|fwmrm|fyber|geniee|getclicky|getdrip|getintent|glassboxdigital|gmads|google-analytics|googleadservices|googlesyndication|googletagmanager|googletagservices|gridsum|gwallet|heapanalytics|hotjar|hubspot|iasds|ijinshan|imprva|imrworldwide|indexww|infolinks|inmobi|innovid|insightexpressai|inspectlet|integralads|intelliad|intellitxt|intergi|intermarkets|ipredictive|iqzone|ironsrc|iterable|jetpack|jivox|juicyads|justpremium|kameleoon|kissmetrics|klarnaservices|klaviyo|kochava|komoona|krxd|launchbit|leanplum|liadm|lijit|liveintent|liveramp|liveperson|loggly|lqcdn|madebymagnitude|magnite|mailchimp|marinsm|marketo|mathads|mathtag|mautic|maxmind|mczbf|mdhv|measurementapi|mediabrix|mediaforge|medialytics|mediaplex|mediavine|medscape|merkle|metricode|mgid|mktoresp|mixpanel|ml314|mlcdn|moatads|moatpixel|mobileapptracking|mobtop|mobileadtrading|moengage|monetizer|mookie|mopub|mparticle|mplxtms|mxpnl|myhome360|mytads|nanigans|nativeads|nativo|nbcume|ndsr|netcore|netmng|netratings|neuralone|newrelic|nexac|nextroll|npttech|nuggad|o333o|ogury|omnisnippet|omnitagjs|omtrdc|oneall|onead|onecount|onesignal|onetag|onetrust|onthe|openx|optimizely|optinmonster|outbrain|owneriq|pardot|parsely|pathweb|pbstck|pepperjam|perfectaudience|permutive|phoenix-tracking|pinger|pippio|pixalate|pixfuture|placecast|plista|pointroll|polare|powerlinks|ppjol|pressidium|primis|prmutv|programattik|propellerads|psyma|ptengine|pubmatic|pubmine|pushengage|pushpad|pushwoosh|pvnsolutions|quantcast|quantserve|rayjump|reachforce|realmatch|realnex|redshell|reembed|reporo|revjet|revcontent|rfihub|richrelevance|rlcdn|rockerbox|rqmob|rtbhouse|rtbidder|rubiconproject|sailthru|salesforce-sites|scarabresearch|scheduleonce|scorecardresearch|sddan|sekindo|sendgrid|sensic|sentifi|shareaholic|sharethis|sharethrough|signifyd|simpleanalytics|siteimprove|sitescout|six-degrees|skimlinks|smartadserver|smaato|snapads|snigelweb|snssdk|speedcurve|speedshiftmedia|splicky|spotx|spotxchange|springserve|stackadapt|stackpathr|statcounter|steelhousemedia|stickyadstv|streamrail|supersonicads|supership|sushim|swrve|synacor|taboola|tapad|tapjoy|tapnative|teads|techlab-cdn|telemetry|terabytemedia|theadex|thetradingdesk|thirdpresence|tidaltv|tiffanyoption|tkqlhce|tlnk|tm-tracking|tns-counter|tovery|trackcmp|trackingcheese|trackingio|trackmytarget|tradedoubler|tradelab|tradelabtech|traffichaus|trafficroots|trafmag|treasuredata|tremorhub|tresensa|trueffect|trueleadid|trustpilot|tsyndicate|tubemogul|turnto|tvpixel|tvsquared|twilio|typekit|ubimo|udmserve|undertone|unrulymedia|urbanairship|usebutton|usercentrics|uservoice|userzoom|utarget|uuidksinc|uwezi|veinteractive|verticalresearch|vertamedia|videohub|vidible|volcanoaffiliates|voluumtrk|volvelle|vungle|webgains|webengage|webtrekk|wishabi|wizads|woopra|wootracker|wunderkind|wzrkt|xad|xiaomi|xiti|xplosion|xtremepush|yandex|yapto|yektanet|yieldbot|yieldify|yieldlab|yieldlove|yieldmo|yieldoptimizer|yotpo|zeotap|zestadz|zeta|zopim|zuuvi)'

# Abused TLD regex pattern (anchored at end)
$script:AbusedTldRegex = '[.](surf|rest|tokyo|ml|cam|icu|cf|gq|best|tk|cn|ru|xyz|top|buzz|live|cfd|boats|beauty|mom|skin|okinawa|zip|mobi|hair|quest)$'

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
        [object]$Body
    )
    
    $uri = "$script:CloudflareApiBase$Endpoint"
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

function Get-GatewayPolicies {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Fetching existing Gateway DNS policies..."
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules"
    return $response.result
}

function Get-PolicyByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    
    $policies = Get-GatewayPolicies
    return $policies | Where-Object { $_.name -eq $Name }
}

function New-GatewayPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$Regex,
        
        [Parameter()]
        [string]$Description = "Auto-managed by PowerShell script",
        
        [Parameter()]
        [string]$Action = "block",
        
        [Parameter()]
        [int]$Precedence = 10000
    )
    
    # Cloudflare API traffic field structure: any(dns.domains[*] matches "regex")
    $TrafficCondition = "any(dns.domains[*] matches `"$Regex`")"
    
    $body = @{
        name        = $Name
        description = $Description
        enabled     = $true
        action      = $Action
        filters     = @("dns")
        traffic     = $TrafficCondition
        precedence  = $Precedence
    }
    
    Write-Verbose "Creating new policy: $Name (Action: $Action, Precedence: $Precedence)"
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules" -Method POST -Body $body
    return $response.result
}

function Update-GatewayPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyId,
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$Regex,
        
        [Parameter()]
        [string]$Description = "Auto-managed by PowerShell script. Last updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        
        [Parameter()]
        [string]$Action = "block",
        
        [Parameter()]
        [int]$Precedence = 10000
    )
    
    $TrafficCondition = "any(dns.domains[*] matches `"$Regex`")"
    
    $body = @{
        name        = $Name
        description = $Description
        enabled     = $true
        action      = $Action
        filters     = @("dns")
        traffic     = $TrafficCondition
        precedence  = $Precedence
    }
    
    Write-Verbose "Updating policy: $Name (ID: $PolicyId, Action: $Action, Precedence: $Precedence)"
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules/$PolicyId" -Method PUT -Body $body
    return $response.result
}

function New-GatewayWhitelistPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string[]]$Domains,
        
        [Parameter()]
        [string]$Description = "Explicitly allowed domains (Whitelist)",
        
        [Parameter()]
        [string]$Action = "allow", 
        
        [Parameter()]
        [int]$Precedence = 1000
    )
    
    # Convert domain list to multiple any() conditions joined with OR
    # Use regex to match domain and all subdomains: (^|\.)domain\.com$
    $conditions = $Domains | ForEach-Object {
        $escapedDomain = [regex]::Escape($_)
        "any(dns.domains[*] matches `"(^|\\.)$escapedDomain`$`")"
    }
    $TrafficCondition = $conditions -join ' or '

    $body = @{
        name        = $Name
        description = $Description
        enabled     = $true
        action      = $Action
        filters     = @("dns")
        traffic     = $TrafficCondition
        precedence  = $Precedence
    }
    
    Write-Verbose "Creating new policy: $Name (Action: $Action, Precedence: $Precedence)"
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules" -Method POST -Body $body
    return $response.result
}

function Update-GatewayWhitelistPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyId,
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string[]]$Domains,
        
        [Parameter()]
        [string]$Description = "Explicitly allowed domains (Whitelist). Last updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        
        [Parameter()]
        [string]$Action = "allow", 
        
        [Parameter()]
        [int]$Precedence = 1000
    )

    # Convert domain list to multiple any() conditions joined with OR
    # Use regex to match domain and all subdomains: (^|\.)domain\.com$
    $conditions = $Domains | ForEach-Object {
        $escapedDomain = [regex]::Escape($_)
        "any(dns.domains[*] matches `"(^|\\.)$escapedDomain`$`")"
    }
    $TrafficCondition = $conditions -join ' or '

    Write-Host "DEBUG: Generated Traffic Condition: $TrafficCondition" -ForegroundColor Magenta

    $body = @{
        name        = $Name
        description = $Description
        enabled     = $true
        action      = $Action
        filters     = @("dns")
        traffic     = $TrafficCondition
        precedence  = $Precedence
    }
    
    Write-Verbose "Updating policy: $Name (ID: $PolicyId, Action: $Action, Precedence: $Precedence)"
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules/$PolicyId" -Method PUT -Body $body
    return $response.result
}


function Test-ApiConnection {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Testing API connection..."
    try {
        $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules" -Method GET
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
Write-Host "║   Cloudflare Zero Trust Gateway - Ad Block Policy Updater v1.8   ║" -ForegroundColor Cyan
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

# --- Process Whitelist Policy ---
if ($EnableWhitelistPolicy -and ($script:FullWhitelistDomains.Count -gt 0)) {
    Write-Host "Processing '$WhitelistPolicyName' policy..." -ForegroundColor Yellow
    $sourceInfo = if ($script:ConfigWhitelistDomains) { "config file" } else { "defaults" }
    Write-Host "  Whitelist source: $sourceInfo ($($script:FullWhitelistDomains.Count) domains)" -ForegroundColor Gray
    
    $existingWhitelistPolicy = Get-PolicyByName -Name $WhitelistPolicyName
    
    if ($existingWhitelistPolicy) {
        Write-Host "  Found existing policy (ID: $($existingWhitelistPolicy.id))" -ForegroundColor Gray
        
        if ($PSCmdlet.ShouldProcess($WhitelistPolicyName, "Update DNS Whitelist policy (Precedence 1000)")) {
            $result = Update-GatewayWhitelistPolicy -PolicyId $existingWhitelistPolicy.id -Name $WhitelistPolicyName -Domains $script:FullWhitelistDomains -Precedence 1000
            Write-Host "  Whitelist Policy updated successfully! Total domains: $($script:FullWhitelistDomains.Count)" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  No existing Whitelist policy found, creating new..." -ForegroundColor Gray
        
        if ($PSCmdlet.ShouldProcess($WhitelistPolicyName, "Create DNS Whitelist policy (Precedence 1000)")) {
            $result = New-GatewayWhitelistPolicy -Name $WhitelistPolicyName -Domains $script:FullWhitelistDomains -Precedence 1000
            Write-Host "  Whitelist Policy created successfully! (ID: $($result.id))" -ForegroundColor Green
        }
    }
    Write-Host ""
}
elseif ($EnableWhitelistPolicy -and ($script:FullWhitelistDomains.Count -eq 0)) {
    Write-Host "Skipping Whitelist policy: EnableWhitelistPolicy is $true, but no domains are configured." -ForegroundColor Yellow
}
else {
    Write-Host "Skipping Whitelist policy as -EnableWhitelistPolicy was explicitly set to $false." -ForegroundColor Gray
}

# --- Process Ad Blocker Policy ---
Write-Host "Processing '$PolicyName' policy..." -ForegroundColor Yellow

$existingPolicy = Get-PolicyByName -Name $PolicyName
$adBlockPrecedence = 10000 

if ($existingPolicy) {
    Write-Host "  Found existing policy (ID: $($existingPolicy.id))" -ForegroundColor Gray
    
    if ($PSCmdlet.ShouldProcess($PolicyName, "Update DNS Block policy (Precedence $adBlockPrecedence)")) {
        $result = Update-GatewayPolicy -PolicyId $existingPolicy.id -Name $PolicyName -Regex $script:AdBlockRegex -Action "block" -Precedence $adBlockPrecedence
        Write-Host "  Ad Blocker Policy updated successfully!" -ForegroundColor Green
    }
}
else {
    Write-Host "  No existing policy found, creating new..." -ForegroundColor Gray
    
    if ($PSCmdlet.ShouldProcess($PolicyName, "Create DNS Block policy (Precedence $adBlockPrecedence)")) {
        $result = New-GatewayPolicy -Name $PolicyName -Regex $script:AdBlockRegex -Action "block" -Precedence $adBlockPrecedence
        Write-Host "  Ad Blocker Policy created successfully! (ID: $($result.id))" -ForegroundColor Green
    }
}

# --- Process Abused TLDs Policy (optional) ---
if ($IncludeAbusedTlds) {
    Write-Host ""
    Write-Host "Processing '$AbusedTldPolicyName' policy..." -ForegroundColor Yellow
    
    $existingTldPolicy = Get-PolicyByName -Name $AbusedTldPolicyName
    $tldPrecedence = 10001 

    if ($existingTldPolicy) {
        Write-Host "  Found existing policy (ID: $($existingTldPolicy.id))" -ForegroundColor Gray
        
        if ($PSCmdlet.ShouldProcess($AbusedTldPolicyName, "Update DNS policy (Precedence $tldPrecedence)")) {
            $result = Update-GatewayPolicy -PolicyId $existingTldPolicy.id -Name $AbusedTldPolicyName -Regex $script:AbusedTldRegex -Action "block" -Precedence $tldPrecedence
            Write-Host "  Policy updated successfully!" -ForegroundColor Green
        }
    }
    else {
        Write-Host "  No existing policy found, creating new..." -ForegroundColor Gray
        
        if ($PSCmdlet.ShouldProcess($AbusedTldPolicyName, "Create DNS policy (Precedence $tldPrecedence)")) {
            $result = New-GatewayPolicy -Name $AbusedTldPolicyName -Regex $script:AbusedTldRegex -Description "Blocks commonly abused TLDs" -Action "block" -Precedence $tldPrecedence
            Write-Host "  Policy created successfully! (ID: $($result.id))" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "Done! Policy changes may take up to 60 seconds to take effect." -ForegroundColor Cyan
Write-Host "Summary: Whitelist (Allow) policies use a LOWER Precedence number (e.g., 1000) than Block policies (e.g., 10000)." -ForegroundColor Yellow
Write-Host ""

#endregion