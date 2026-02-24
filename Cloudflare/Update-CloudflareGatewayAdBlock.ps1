<#
.SYNOPSIS
    Automatically updates Cloudflare Zero Trust Gateway DNS policy for ad blocking,
    including an optional whitelist policy and multiple external block lists.
.DESCRIPTION
    This script creates or updates DNS policies in Cloudflare Zero Trust Gateway.
    It includes:
    1. A Whitelist policy (Allow) for essential domains.
    2. Multiple Block policies based on external lists (1Host, OISD, etc.).
    3. A generic Ad Block policy using regex pattern matching.
    4. An Abused TLDs policy.

    It uses the Cloudflare API to manage the lists and policies automatically.
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
    Name of the generic Regex Ad Blocker policy. Default: "Ad Blocker"
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
.PARAMETER BlockListName
    Optional filter to process only a specific block list by name. Supports partial matching.
.PARAMETER WhatIf
    Shows what would happen without making changes.
.EXAMPLE
    # Run with default settings
    .\Update-CloudflareGatewayAdBlock.ps1 -ApiToken "your_token" -AccountId "your_account_id"

.EXAMPLE
    # Using a config file
    .\Update-CloudflareGatewayAdBlock.ps1 -ConfigFile "~/.cloudflare-config.json"

.EXAMPLE
    # Process only the OISD list
    .\Update-CloudflareGatewayAdBlock.ps1 -ConfigFile "~/.cloudflare-config.json" -BlockListName "OISD"

.NOTES
    Version:        3.2
    Author:         Henrik Skovgaard / Modified by AI
    Creation Date:  2025-11-30

    Version History:
    ...
    3.0 - Added support for multiple external block lists (1Host, OISD, etc.) using Cloudflare Gateway Lists.
    3.1 - Fixed duplicate BlockLists definition that silently overwrote the first.
          Fixed OISD list: changed to plain domains endpoint (small.oisd.nl/domains) with Type "Domains".
          Removed Anti PopAds (repository deleted/renamed, URL returns 404).
          Removed debug output statements.
          Updated KADHosts URL to current repository location.
    3.2 - Fixed critical performance issue in Fetch-And-Parse-List: replaced O(n²) array += concatenation
          with HashSet[string] for O(1) dedup and List[string] collection. Pre-compiled validation regex.
          210K domain lists now parse in seconds instead of hanging indefinitely.
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
    [string]$AbusedTldPolicyName = "Abused TLDs Blocker",

    [Parameter()]
    [string]$BlockListName,

    [Parameter()]
    [switch]$WhitelistOnly
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

# External Block Lists Configuration (single consolidated definition)
$script:BlockLists = @(
    @{
        Name = "1Host Lite"
        Url  = "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt"
        Type = "Domains"
    },
    @{
        Name = "KADHosts"
        Url  = "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt"
        Type = "Hosts"
    },
    @{
        Name = "NoCoin"
        Url  = "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
        Type = "Hosts"
    },
    @{
        Name = "Peter Lowe"
        Url  = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
        Type = "Hosts"
    },
    @{
        Name = "URLhaus"
        Url  = "https://urlhaus.abuse.ch/downloads/hostfile/"
        Type = "Hosts"
    }
)

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

# Main ad-blocking regex pattern (v2.6)
$script:AdBlockRegex = '(advert|adserv|adsystem|adtrack|adserver|adtech|adnetwork|doubleclick|2mdn|2o7|33across|360yield|3lift|aax|aaxads|abtasty|adcash|adclick|adcolony|addthis|adform|adhaven|adhese|adition|adjust|adloox|adlooxtracking|admantx|admicro|admixer|admob|adnami|adnxs|adskeeper|adomik|adpushup|adroll|adsafeprotected|adsrvr|adsterra|adswizz|adtelligent|adventori|adzerk|aerserv|agkn|airbridge|amazon-adsystem|amplitude|aniview|anzuinfra|apester|applovin|appsflyer|aralego|atdmt|atwola|aumago|avazu|bannersnack|batmobi|bidmachine|bidswitch|bidtheatre|bizible|bluecore|bluecava|blueconic|bounceexchange|branch|braze|btloader|bttrack|carambo|casalemedia|cedexis|chartbeat|cheabit|cleverads|clevertap|clickagy|clicktale|cluep|cohesion|comscore|contentsquare|contextly|contextweb|convertkit|convertmedia|crazymedia|crisp|criteo|crwdcntrl|custhelp|customerio|demdex|dftrack|districtm|dotomi|doubleverify|drift|dstillery|dtscout|dynatrace|dyntrk|efectivoads|emarsys|emxdgt|engagio|enquisite|eulerian|everesttech|exelator|eyeota|fastly-insights|fidelity-media|flashtalking|foresee|foxpush|freeskreen|freewheel|fullstory|fuseplatform|fwmrm|fyber|geniee|getclicky|getdrip|getintent|glassboxdigital|gmads|google-analytics|googleadservices|googlesyndication|googletagmanager|googletagservices|gridsum|gtag|gwallet|heapanalytics|hotjar|hubspot|iasds|ijinshan|imprva|imrworldwide|indexww|infolinks|inmobi|innovid|insider|insightexpressai|inspectlet|integralads|intelliad|intellitxt|intercom|intergi|intermarkets|ipredictive|iqzone|ironsrc|iterable|jetpack|jivox|juicyads|justpremium|kameleoon|kissmetrics|klarnaservices|klaviyo|kochava|komoona|krxd|launchbit|leanplum|liadm|lijit|livechat|liveintent|liveramp|liveperson|loggly|logrocket|lqcdn|madebymagnitude|magnite|mailchimp|marinsm|marketo|mathads|mathtag|mautic|maxmind|mczbf|mdhv|measurementapi|mediabrix|mediaforge|medialytics|mediaplex|mediavine|medscape|merkle|metricode|mgid|mktoresp|mixpanel|ml314|mlcdn|moatads|moatpixel|mobileapptracking|mookie1|mparticle|mtgglobals|mxpnl|mybestlogs|myvisualiq|nativeads|nativo|navdmp|netmng|nexac|nextdns|nielsen|nr-data|ns1p|obclick|observerapp|omguk|omnitag|omniture|onemobile|onetag|onlinesolution|openx|optimizely|outbrain|pardot|parsely|pendo|perfectaudience|permutive|phluant|pippio|pixel|pkmn|platform161|playwire|plista|polarcdn|popads|popcash|posthog|postrelease|powerlinks|propellerads|pubmatic|pubmine|pulsepoint|quantcount|quantserve|qubit|r1908|r2018|rakuten|rdtk|reapleaf|redirect|reddit-ad|reklam|resonate|revcontent|revenuehit|rlcdn|rotaban|rubicon|rudderstack|run-syndicate|rutarget|s2s-web|salesforce|sbscrbr|scanscout|scorecardresearch|searchforce|segment|semasio|sessioncam|sharethis|shopifysvc|simpli|skimresources|slicktext|smetrics|smartadserver|snapads|snowplow|sonobi|sovern|spdttr|specificclick|spotxchange|springserve|sprout|startapp|statcounter|statif|stats|storyly|streamrail|strossle|supership|taboola|tagcommander|tagsrv|tapfiliate|tapjoy|tapad|tawk|tealium|teads|tenjin|thebrighttag|themoneytizer|tinypass|tjsrc|tm-awx|trafficjunky|trafficstars|traffichunt|travelaudience|tremorhub|tribalfusion|trkn|truoptik|trustarc|trustpilot|tt-10000|turn|twiq|tynt|uam|uberads|uedas|umeng|undertone|unrulymedia|upfluence|useinsider|usergram|userreport|v12group|veinteractive|verizon-media|vungle|w55c|wappingers|webtrekk|webtrends|wibbitz|widespace|wigetmedia|wizaly|wrapps|xad|xaxis|xplosion|yandex|ybrant|ydraw|yeb-svc|yhd|yieldlab|yieldmo|yieldoptimizer|yllix|yoc|yrmn|zemanta|zendesk|zeus|zmnn)'

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
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
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
    # Supports wildcards (*) by replacing them with .*
    $conditions = $Domains | ForEach-Object {
        $escapedDomain = [regex]::Escape($_)
        if ($escapedDomain -match "\\\*") {
            # Un-escape the asterisk to make it a regex wildcard
            $regexPattern = $escapedDomain.Replace("\*", ".*")
            "any(dns.domains[*] matches `"(^|\\.)$regexPattern`$`")"
        } else {
            "any(dns.domains[*] matches `"(^|\\.)$escapedDomain`$`")"
        }
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
    # Supports wildcards (*) by replacing them with .*
    $conditions = $Domains | ForEach-Object {
        $escapedDomain = [regex]::Escape($_)
        if ($escapedDomain -match "\\\*") {
            # Un-escape the asterisk to make it a regex wildcard
            $regexPattern = $escapedDomain.Replace("\*", ".*")
            "any(dns.domains[*] matches `"(^|\\.)$regexPattern`$`")"
        } else {
            "any(dns.domains[*] matches `"(^|\\.)$escapedDomain`$`")"
        }
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

    Write-Verbose "Updating policy: $Name (ID: $PolicyId, Action: $Action, Precedence: $Precedence)"
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules/$PolicyId" -Method PUT -Body $body
    return $response.result
}

# --- List Management Functions ---

function Get-GatewayLists {
    [CmdletBinding()]
    param()

    Write-Verbose "Fetching existing Gateway Lists..."
    $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists"
    return $response.result
}

function Sync-GatewayList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Domains,

        [Parameter()]
        [string]$Description = "Managed by PowerShell"
    )

    Write-Host "Syncing Gateway List(s): $Name ($($Domains.Count) domains)" -ForegroundColor Yellow

    $lists = Get-GatewayLists

    # Strategy: Split domains into chunks of 1000 items.
    # Create/Update multiple lists named "$Name - Part X"
    # Returns an array of List IDs.

    $chunkSize = 1000
    $listIds = @()

    $parts = if ($Domains.Count -gt 0) { [Math]::Ceiling($Domains.Count / $chunkSize) } else { 1 }

    # Pre-cleanup: delete obsolete parts BEFORE the create/update loop so freed slots
    # are available when we need to create new parts (important when near the list cap)
    $potentialOldLists = $lists | Where-Object { $_.name -like "$Name - Part *" }
    foreach ($oldList in $potentialOldLists) {
        # Extract the part number from the name and check if it's beyond the new part count
        if ($oldList.name -match ' - Part (\d+)$') {
            $oldPartNum = [int]$Matches[1]
            if ($oldPartNum -gt $parts) {
                Write-Host "  Deleting obsolete list part: $($oldList.name)..." -ForegroundColor DarkGray
                try {
                    Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists/$($oldList.id)" -Method DELETE | Out-Null
                    # Refresh lists cache to reflect the deletion
                    $lists = $lists | Where-Object { $_.id -ne $oldList.id }
                } catch {
                    Write-Warning "Failed to delete old list $($oldList.name): $_"
                }
            }
        }
    }

    for ($i = 0; $i -lt $parts; $i++) {
        $partNum = $i + 1
        $listName = "$Name - Part $partNum"

        # Calculate slice
        $start = $i * $chunkSize
        $end = [Math]::Min($start + $chunkSize - 1, $Domains.Count - 1)

        if ($Domains.Count -gt 0) {
            $chunkDomains = $Domains[$start..$end]
        } else {
            $chunkDomains = @()
        }

        $formattedItems = $chunkDomains | ForEach-Object { @{ value = $_ } }
        $existingList = $lists | Where-Object { $_.name -eq $listName }

        if ($existingList) {
            Write-Host "  Updating '$listName' ($($formattedItems.Count) items)..." -ForegroundColor Gray
            # Atomic replace using PUT (limit 1000 items)
            $body = @{
                name        = $listName
                description = "$Description (Part $partNum/$parts)"
                items       = $formattedItems
                type        = "DOMAIN"
            }
            try {
                $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists/$($existingList.id)" -Method PUT -Body $body
                $listIds += $existingList.id
            } catch {
                Write-Error "Failed to update list $listName : $_"
            }
        } else {
            Write-Host "  Creating '$listName' ($($formattedItems.Count) items)..." -ForegroundColor Gray
            $body = @{
                name        = $listName
                description = "$Description (Part $partNum/$parts)"
                items       = $formattedItems
                type        = "DOMAIN"
            }
            try {
                $response = Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists" -Method POST -Body $body
                $listIds += $response.result.id
            } catch {
                Write-Error "Failed to create list $listName : $_"
            }
        }
    }

    # Cleanup old parts if the list shrank (e.g. formerly had 5 parts, now only 3)
    $potentialOldLists = $lists | Where-Object { $_.name -like "$Name - Part *" }
    foreach ($oldList in $potentialOldLists) {
        if ($listIds -notcontains $oldList.id) {
            Write-Host "  Deleting obsolete list part: $($oldList.name)..." -ForegroundColor DarkGray
            try {
                Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists/$($oldList.id)" -Method DELETE | Out-Null
            } catch {
                Write-Warning "Failed to delete old list $($oldList.name): $_"
            }
        }
    }

    # Also handle the legacy single list if it exists (named just "$Name")
    $legacyList = $lists | Where-Object { $_.name -eq $Name }
    if ($legacyList) {
        Write-Host "  Deleting legacy single list '$Name' (replaced by parts)..." -ForegroundColor DarkGray
        try {
            Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists/$($legacyList.id)" -Method DELETE | Out-Null
        } catch {
            Write-Warning "Failed to delete legacy list: $_"
        }
    }

    return $listIds
}

function Update-GatewayPolicyForList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ListIds,

        [Parameter(Mandatory)]
        [string]$ListName,

        [Parameter()]
        [int]$Precedence = 11000
    )

    $blockListPolicyName = "Block - $ListName"
    Write-Host "Processing Policy '$blockListPolicyName'..." -ForegroundColor Yellow

    # Traffic: any(dns.domains[*] in $ListId1) or any(dns.domains[*] in $ListId2) ...
    $conditions = $ListIds | ForEach-Object { "any(dns.domains[*] in `$$($_))" }
    $traffic = $conditions -join " or "

    $existingPolicy = Get-PolicyByName -Name $blockListPolicyName

    if ($existingPolicy) {
        # Check if we need to update (e.g. if List ID changed)
        if ($existingPolicy.traffic -ne $traffic -or $existingPolicy.precedence -ne $Precedence) {
            Write-Host "  Updating policy traffic/precedence..." -ForegroundColor Gray

             $body = @{
                name        = $blockListPolicyName
                description = "Block policy for list: $ListName"
                enabled     = $true
                action      = "block"
                filters     = @("dns")
                traffic     = $traffic
                precedence  = $Precedence
            }
            Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules/$($existingPolicy.id)" -Method PUT -Body $body | Out-Null
            Write-Host "  Policy updated." -ForegroundColor Green
        } else {
            Write-Host "  Policy already up to date." -ForegroundColor Gray
        }
    } else {
        Write-Host "  Creating new policy..." -ForegroundColor Gray
        $body = @{
            name        = $blockListPolicyName
            description = "Block policy for list: $ListName"
            enabled     = $true
            action      = "block"
            filters     = @("dns")
            traffic     = $traffic
            precedence  = $Precedence
        }
        Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules" -Method POST -Body $body | Out-Null
        Write-Host "  Policy created." -ForegroundColor Green
    }
}

function Fetch-And-Parse-List {
    param(
        [string]$Url,
        [string]$Type
    )

    Write-Host "  Downloading from: $Url" -ForegroundColor DarkGray
    try {
        $content = Invoke-RestMethod -Uri $Url -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -ErrorAction Stop

        # Some endpoints return an array of strings; join them into a single string
        if ($content -is [array]) {
            $content = $content -join "`n"
        }
    } catch {
        Write-Error "  Failed to download list: $_"
        return @()
    }

    # Use HashSet for O(1) dedup instead of Select-Object -Unique (O(n²))
    $uniqueDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Robust splitting for mixed line endings
    $lines = $content -split "\r?\n"
    Write-Host "  Parsing $($lines.Count) lines ($Type format)..." -ForegroundColor DarkGray

    # Pre-compile the per-label validation regex for performance
    # Each DNS label must start and end with alphanumeric, and only contain alphanumeric or hyphens
    $labelRegex = [regex]::new('^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', 'Compiled')
    $skipDomains = @('localhost', 'broadcasthost', 'local', '127.0.0.1', '0.0.0.0', '::1')

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) { continue }

        $raw = $null

        switch ($Type) {
            "Hosts" {
                if ($line[0] -eq '#') { continue }
                $parts = $line -split "\s+"
                if ($parts.Count -ge 2) {
                    $raw = $parts[1]
                }
            }
            "AdblockPlus" {
                if ($line[0] -eq '!' -or ($line[0] -eq '[' -and $line[-1] -eq ']')) { continue }
                if ($line.StartsWith("||") -and $line.EndsWith("^")) {
                    $raw = $line.Substring(2, $line.Length - 3)
                }
            }
            "Domains" {
                if ($line[0] -eq '#') { continue }
                $raw = $line
            }
        }

        if (-not $raw) { continue }

        # Cleanup
        $clean = $raw.TrimEnd("^").Trim()
        if ([string]::IsNullOrEmpty($clean)) { continue }
        if ($clean -in $skipDomains) { continue }

        # Validate each DNS label individually: must start/end with alphanumeric, no leading/trailing hyphens
        $labels = $clean -split '\.'
        $valid = $labels.Count -ge 2
        if ($valid) {
            foreach ($label in $labels) {
                if ([string]::IsNullOrEmpty($label) -or -not $labelRegex.IsMatch($label)) {
                    $valid = $false
                    break
                }
            }
        }
        if ($valid) {
            [void]$uniqueDomains.Add($clean)
        }
    }

    Write-Host "  Extracted $($uniqueDomains.Count) unique valid domains." -ForegroundColor Gray
    return @($uniqueDomains)
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
Write-Host "║   Cloudflare Zero Trust Gateway - Ad Block Policy Updater v3.2   ║" -ForegroundColor Cyan
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

# --- Process External Block Lists ---
if (-not $WhitelistOnly) {
    Write-Host ""
    Write-Host "Processing External Block Lists..." -ForegroundColor Yellow

    # Cleanup lists and policies on Cloudflare that belong to block lists no longer in config
    # This frees slots before syncing, preventing "Maximum number of lists reached" errors
    if (-not $BlockListName) {
        Write-Host "Checking for obsolete lists to clean up..." -ForegroundColor DarkGray
        $allGatewayLists = Get-GatewayLists
        $configuredNames = $script:BlockLists | ForEach-Object { $_.Name }

        # Find base names of removed lists
        $removedBaseNames = @()
        foreach ($gwList in $allGatewayLists) {
            if ($gwList.name -match '^(.+) - Part \d+$') {
                $baseName = $Matches[1]
                if ($baseName -notin $configuredNames -and $baseName -notin $removedBaseNames) {
                    $removedBaseNames += $baseName
                }
            }
        }

        # First delete the associated policies (lists can't be deleted while in use by a policy)
        foreach ($baseName in $removedBaseNames) {
            $policyName = "Block - $baseName"
            $obsoletePolicy = Get-PolicyByName -Name $policyName
            if ($obsoletePolicy) {
                Write-Host "  Deleting obsolete policy: $policyName..." -ForegroundColor DarkGray
                try {
                    Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/rules/$($obsoletePolicy.id)" -Method DELETE | Out-Null
                } catch {
                    Write-Warning "  Failed to delete policy $policyName : $_"
                }
            }
        }

        # Then delete the lists
        foreach ($gwList in $allGatewayLists) {
            if ($gwList.name -match '^(.+) - Part \d+$') {
                $baseName = $Matches[1]
                if ($baseName -notin $configuredNames) {
                    Write-Host "  Deleting removed list: $($gwList.name)..." -ForegroundColor DarkGray
                    try {
                        Invoke-CloudflareApi -Endpoint "/accounts/$AccountId/gateway/lists/$($gwList.id)" -Method DELETE | Out-Null
                    } catch {
                        Write-Warning "  Failed to delete $($gwList.name): $_"
                    }
                }
            }
        }
    }

    $currentPrecedence = 11000

foreach ($listDef in $script:BlockLists) {
    # If a specific list name is requested via parameter, skip others
    if ($BlockListName -and $listDef.Name -ne $BlockListName -and $listDef.Name -notlike "*$BlockListName*") {
        $currentPrecedence += 10 # Keep precedence consistent
        continue
    }

    Write-Host "Checking List: $($listDef.Name)..." -ForegroundColor Cyan

    # Check ShouldProcess for the overarching operation first
    if ($PSCmdlet.ShouldProcess($listDef.Name, "Sync List and Policy")) {

        # 1. Download and Parse
        Write-Host "  Downloading list..." -ForegroundColor DarkGray
        $domains = Fetch-And-Parse-List -Url $listDef.Url -Type $listDef.Type
        if ($domains.Count -eq 0) {
            Write-Warning "  No domains found for $($listDef.Name) or download failed. Skipping."
            continue
        }
        Write-Host "  Parsed $($domains.Count) domains." -ForegroundColor Gray

        # 2. Sync Gateway List (Returns array of IDs to support splitting)
        $listIds = Sync-GatewayList -Name $listDef.Name -Domains $domains -Description "Source: $($listDef.Url)"

        # 3. Update Policy (Accepts array of IDs)
        $null = Update-GatewayPolicyForList -ListIds $listIds -ListName $listDef.Name -Precedence $currentPrecedence

        $currentPrecedence += 10 # Increment precedence for next list
    }
}
} # End if (-not $WhitelistOnly)

# --- Process Generic Ad Blocker Policy (Regex) ---
if (-not $WhitelistOnly) {
Write-Host ""
Write-Host "Processing '$PolicyName' policy (Regex)..." -ForegroundColor Yellow

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
} # End if (-not $WhitelistOnly)

Write-Host ""
Write-Host "Done! Policy changes may take up to 60 seconds to take effect." -ForegroundColor Cyan
Write-Host "Summary: Whitelist (Allow) policies use a LOWER Precedence number (e.g., 1000) than Block policies (e.g., 10000+)." -ForegroundColor Yellow
Write-Host ""

#endregion