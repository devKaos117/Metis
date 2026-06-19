# ============================================================================
# INFO
# ============================================================================
# ============ Author
# https://www.linkedin.com/in/kaos/
# ============ Description
# Elenchus
# The philosophical art of cross-examination and refutation. SSL/TLS and HTTP security scanner designed to identify common misconfigurations in web applications
# ============ Usage
# ============ References
# https://github.com/rbsec/sslscan
# https://github.com/santoru/shcheck
# https://github.com/OWASP/www-project-secure-headers

# ============================================================================
# INITIALIZATIONS
# ============================================================================
$ErrorActionPreference = "Stop"

# ============================================================================
# LOGGER
# ============================================================================
# ============ Constants
Set-Variable -Name LOG_NONE -Option Constant -Scope Script -Visibility Private -Value 99
Set-Variable -Name LOG_CRITICAL -Option Constant -Scope Script -Visibility Private -Value 50
Set-Variable -Name LOG_ERROR -Option Constant -Scope Script -Visibility Private -Value 40
Set-Variable -Name LOG_WARNING -Option Constant -Scope Script -Visibility Private -Value 30
Set-Variable -Name LOG_INFO -Option Constant -Scope Script -Visibility Private -Value 20
Set-Variable -Name LOG_DEBUG -Option Constant -Scope Script -Visibility Private -Value 10

Set-Variable -Name LogLevelNames -Option Constant -Scope Script -Visibility Private -Value @{
	99 = "NONE"
	50 = "CRITICAL"
	40 = "ERROR"
	30 = "WARNING"
	20 = "INFO"
	10 = "DEBUG"
}

Set-Variable -Name LogColors -Option Constant -Scope Script -Visibility Private -Value @{
	99 = "Gray"		# Reset/None
	50 = "Magenta"	# Critical
	40 = "Red"		# Error
	30 = "Yellow"	# Warning
	20 = "Green"	# Info
	10 = "Cyan"		# Debug
	0 = "White"		# Custom
}

Set-Variable -Name TimestampFormat -Option Constant -Scope Script -Visibility Private -Value "HH:mm:ss.fff"
Set-Variable -Name ColorizeMessage -Option Constant -Scope Script -Visibility Private -Value $true
Set-Variable -Name CurrentLogLevel -Scope Script -Visibility Private -Value $LOG_INFO

# ============ Traceback the calling stack
function Get-CallerInfo {
	[CmdletBinding()]
	param()

	# Get call stack
	$callStack = Get-PSCallStack

	# Skip internal logger functions
	$callerFrame = $null
	foreach ($frame in $callStack) {
		if ($frame.Command -notlike "*Log*" -and
			$frame.Command -ne "Get-CallerInfo" -and
			$frame.Command -ne "<ScriptBlock>") {
			$callerFrame = $frame
			break
		}
	}

	# Default values if we can"t find a caller
	if (-not $callerFrame) {
		$callerFrame = $callStack[-1]
	}

	# Get caller info
	$processId = $PID

	$fileName = if ($callerFrame.ScriptName) {
		Split-Path -Leaf $callerFrame.ScriptName
	} else {
		"Interactive"
	}

	$functionName = if ($callerFrame.Command) {
		$callerFrame.Command
	} else {
		"main"
	}

	return "${processId}:${fileName}:${functionName}"
}

# ============ Write the log to the host
function Write-LogMessage {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[int]$Level,

		[Parameter(Mandatory)]
		[string]$Message
	)

	# Check if we should log this level
	if ($Level -lt $CurrentLogLevel) {
		return
	}

	# Gather metadata
	$timestamp = Get-Date -Format $TimestampFormat
	$levelName = $LogLevelNames[$Level]
	$callerInfo = Get-CallerInfo

	# Format the message
	if ($ColorizeMessage) {
		# Build colored output
		Write-Host "[" -NoNewline -ForegroundColor Gray
		Write-Host $timestamp -NoNewline -ForegroundColor Cyan
		Write-Host "] [" -NoNewline -ForegroundColor Gray
		Write-Host $callerInfo -NoNewline -ForegroundColor Cyan
		Write-Host "] [" -NoNewline -ForegroundColor Gray
		Write-Host $levelName -NoNewline -ForegroundColor $LogColors[$Level]
		Write-Host "] " -NoNewline -ForegroundColor Gray
		Write-Host $Message -ForegroundColor White
	} else {
		# Plain text output
		Write-Host "[$timestamp] [$callerInfo] [$levelName] $Message"
	}
}

# ============ Logging API
function Write-Log {
	[CmdletBinding()]
	param (
		# Log level
		[Parameter(Mandatory=$true, Position=0)]
		[ValidateSet("Critical", "Error", "Warning", "Info", "Debug")]
		[string] $Level,

		# Log message
		[Parameter(Mandatory=$true, Position=1)]
		[string] $Message
	)

	process {
		switch ($Level) {
			"Critical" {
				Write-LogMessage -Level $LOG_CRITICAL -Message $Message
			}
			"Error" {
				Write-LogMessage -Level $LOG_ERROR -Message $Message
			}
			"Warning" {
				Write-LogMessage -Level $LOG_WARNING -Message $Message
			}
			"Info" {
				Write-LogMessage -Level $LOG_INFO -Message $Message
			}
			"Debug" {
				Write-LogMessage -Level $LOG_DEBUG -Message $Message
			}
		}
	}
}

# ============================================================================
# PROXY
# ============================================================================
# Initialize-ProxyConnection "HTTP" "proxy:8080/" "kaos"
<#
	.SYNOPSIS
		Detect proxy authentication method
	.DESCRIPTION
		...
	.PARAMETER ...
		...
	.EXAMPLE
		...
	.INPUTS
		...
	.OUTPUTS
		...
	.COMPONENT
		...
	.LINK
		...
	.NOTES
		...
#>
function Get-ProxyAuthMethod {
	param(
		[Parameter(Mandatory)]
		[System.Uri] $ProxyUri
	)

	try {
		Write-Log "Debug" "Detecting proxy authentication method for: $ProxyUri"
		
		# Make a test request without credentials to get auth challenge
		$testParams = @{
			Uri = "https://www.google.com/"
			Method = "GET"
			Proxy = $ProxyUri.AbsoluteUri
			UseBasicParsing = $true
			TimeoutSec = 10
		}

		try {
			$null = Invoke-WebRequest @testParams -ErrorAction Stop
			Write-Log "Info" "Proxy does not require authentication"
			return "None"
		} catch {
			# Check if the response code is Proxy Authentication Required
			if ([string]::IsNullOrEmpty($_.Exception.Response.StatusCode) -or $_.Exception.Response.StatusCode -ne 407) {
				Write-Log "Warning" "Unable to detect proxy auth method: $($_.Exception.Message)"
				return "Unknown"
			}

			# Get the Proxy-Authenticate header
			$authHeader = $_.Exception.Response.Headers["Proxy-Authenticate"]
			
			if ([string]::IsNullOrEmpty($authHeader)){
				Write-Log "Warning" "No Proxy-Authenticate header was found"
				return "Unknown"
			}

			$authMethods = @()
			foreach ($method in $authHeader) {
				if ($method -match "^(\w+)") {
					$authMethods += $matches[1]
				}
			}
			
			Write-Log "Debug" "Proxy supports authentication methods: $($authMethods -join ", ")"
			
			# Prioritize: Negotiate > NTLM > Digest > Basic
			if ($authMethods -contains "Negotiate") {
				return "Negotiate"
			}
			
			if ($authMethods -contains "NTLM") {
				return "NTLM"
			}
			
			if ($authMethods -contains "Digest") {
				return "Digest"
			}
			
			if ($authMethods -contains "Basic") {
				return "Basic"
			}
			
			return $authMethods[0]
		}
	} catch {
		Write-Log "Error" "Failed to detect proxy authentication: $($_.Exception.Message)"
		return "Unknown"
	}
}

<#
	.SYNOPSIS
		Prepare proxy connection
	.DESCRIPTION
		...
	.PARAMETER ...
		...
	.EXAMPLE
		...
	.INPUTS
		...
	.OUTPUTS
		...
	.COMPONENT
		...
	.LINK
		...
	.NOTES
		...
#>
function Initialize-ProxyConnection {
	param(
		# Protocol
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet("HTTP", "HTTPS", "SOCKS4", "SOCKS5")]
		[string] $ProxyProtocol,

		# URI
		[Parameter(Mandatory, Position = 1)]
		[System.Uri] $ProxyUri,

		# Username (use domain\username for Windows auth)
		[Parameter(Position = 2)]
		[string] $Username,

		# Use current Windows credentials (default credentials)
		[Parameter()]
		[switch] $UseDefaultCredentials = $false,

		# Force specific authentication method
		[Parameter()]
		[ValidateSet("Auto", "Basic", "NTLM", "Negotiate", "Digest", "None")]
		[string] $AuthMethod = "Auto"
	)

	if ($ProxyProtocol -ne "HTTP") {
		throw "$ProxyProtocol proxy protocol is not yet implemented"
	}

	# Detect authentication method if Auto
	$selectedAuthMethod = $AuthMethod
	if ($selectedAuthMethod -eq "Auto") {
		$selectedAuthMethod = Get-ProxyAuthMethod -ProxyUri $ProxyUri
	}
	Write-Log "Info" "Selected proxy authentication method: $selectedAuthMethod"

	# Configure credentials
	$credentials = $null

	if ($selectedAuthMethod -ne "None") {
		if ($UseDefaultCredentials) {
			# Use current Windows credentials (works for NTLM/Negotiate)
			Write-Log "Info" "Using default Windows credentials for proxy authentication"
			$credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
		}
		elseif ($Username) {
			Write-Host "Enter with the password for proxy user ${Username}:" -ForegroundColor White
			$securePassword = Read-Host -AsSecureString
			$credentials = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
		}
		else {
			Write-Log "Warning" "Proxy requires authentication but no credentials provided. Attempting with default credentials"
			$credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
		}
	}

	# Store credentials at script scope
	$Script:ProxyCredentials = $credentials

	# Return proxy configuration object
	$proxyConfig = @{
		Uri = $ProxyUri
		Protocol = $ProxyProtocol
		Credentials = $credentials
		AuthMethod = $selectedAuthMethod
		UseDefaultCredentials = $UseDefaultCredentials
	}

	Write-Log "Info" "$ProxyProtocol proxy configured: $ProxyUri (Auth: $selectedAuthMethod)"

	return $proxyConfig
}
# ============================================================================
# SSL/TLS
# ============================================================================

# ============================================================================
# HTTP HEADERS
# ============================================================================

$HEADER_RULES = @(
	# @{
	# 	Name			= ""
	# 	Policy			= "Required|Inadvisable|Conditional"
	# 	# 
	# 	IsSecure		= { $null -eq $args[0] } 
	# 	Recommendation	= ""
	# 	References		= @(
	# 		"https://"
	# 	)
	# },
	@{
		Name			= "Server"
		Policy			= "Inadvisable"
		# Secure if the header is null
		IsSecure		= { $null -eq $args[0] } 
		Recommendation	= "Disable or mask this header in the server configuration to prevent fingerprinting"
		References		= @(
			"https://"
		)
	},
	@{
		Name			= "Content-Security-Policy"
		Policy			= "Required"
		# 
		IsSecure		= { $null -ne $args[0] } 
		Recommendation	= "Implement a strong CSP policy tailored to your application to significantly reduce attack surface"
		References		= @(
			"https://"
		)
	},
	@{
		Name			= "Access-Control-Allow-Origin"
		Policy			= "Required"
		# Secure if present and not set to wildcard
		IsSecure		= { $null -ne $args[0] -and $args[0] -ne "*" } 
		Recommendation	= "Set this header to a specific origin or remove it if CORS is not needed to prevent data leaks and CSRF attacks"
		References		= @(
			"https://"
		)
	}
)

# --- Add
# Cache-Control: "no-store, max-age=0"
# Clear-Site-Data: "cache", "cookies", "storage"
# Content-Security-Policy: "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
# Cross-Origin-Embedder-Policy: "require-corp"
# Cross-Origin-Opener-Policy: "same-origin"
# Cross-Origin-Resource-Policy: "same-origin"
# Permissions-Policy: "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()"
# Referrer-Policy: "no-referrer"
# Strict-Transport-Security: "max-age=63072000; includeSubDomains"
# X-Content-Type-Options: "nosniff"
# X-DNS-Prefetch-Control: "off"
# X-Frame-Options: "deny"
# X-Permitted-Cross-Domain-Policies: "none"

# --- Remove
# $wsep
# Host-Header
# K-Proxy-Request
# Liferay-Portal
# OracleCommerceCloud-Version
# Pega-Host
# Powered-By
# Product
# Server
# SourceMap
# X-AspNet-Version
# X-AspNetMvc-Version
# X-Atmosphere-error
# X-Atmosphere-first-request
# X-Atmosphere-tracking-id
# X-B3-ParentSpanId
# X-B3-Sampled
# X-B3-SpanId
# X-B3-TraceId
# X-BEServer
# X-Backside-Transport
# X-CF-Powered-By
# X-CMS
# X-CalculatedBETarget
# X-Cocoon-Version
# X-Content-Encoded-By
# X-DiagInfo
# X-Envoy-Attempt-Count
# X-Envoy-External-Address
# X-Envoy-Internal
# X-Envoy-Original-Dst-Host
# X-Envoy-Upstream-Service-Time
# X-FEServer
# X-Framework
# X-Generated-By
# X-Generator
# X-Gitlab-Meta
# X-Jitsi-Release
# X-Joomla-Version
# X-Kong-Admin-Latency
# X-Kong-Client-Latency
# X-Kong-Proxy-Latency
# X-Kong-Request-Id
# X-Kong-Response-Latency
# X-Kong-Third-Party-Latency
# X-Kong-Total-Latency
# X-Kong-Upstream-Latency
# X-Kong-Upstream-Status
# X-Kubernetes-PF-FlowSchema-UI
# X-Kubernetes-PF-PriorityLevel-UID
# X-LiteSpeed-Cache
# X-LiteSpeed-Purge
# X-LiteSpeed-Tag
# X-LiteSpeed-Vary
# X-Litespeed-Cache-Control
# X-Mod-Pagespeed
# X-Nextjs-Cache
# X-Nextjs-Matched-Path
# X-Nextjs-Page
# X-Nextjs-Redirect
# X-OWA-Version
# X-Old-Content-Length
# X-OneAgent-JS-Injection
# X-Page-Speed
# X-Php-Version
# X-Powered-By
# X-Powered-By-Plesk
# X-Powered-CMS
# X-Redirect-By
# X-Server-Powered-By
# X-SourceFiles
# X-SourceMap
# X-Turbo-Charged-By
# X-Umbraco-Version
# X-Varnish-Backend
# X-Varnish-Server
# X-Woodpecker-Version
# X-dtAgentId
# X-dtHealthCheck
# X-dtInjectedServlet
# X-ruxit-JS-Agent

# ============================================================================
# HTTP COOKIES
# ============================================================================

# ============================================================================
# MAIN
# ============================================================================
<#
	.SYNOPSIS
		
	.DESCRIPTION
		...
	.PARAMETER ...
		...
	.EXAMPLE
		...
	.INPUTS
		...
	.OUTPUTS
		...
	.COMPONENT
		...
	.LINK
		...
	.NOTES
		...
#>
function Invoke-HeaderAudit {
	[CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSObject]])]
	param(
		[Parameter(Mandatory, Position = 0)]
		[System.Collections.IDictionary]$Headers
	)

	process {
		Write-Log "Info" "Starting header audit"

		$report = new-object System.Collections.Generic.List[PSObject]

		# Process header rules
		foreach ($rule in $HEADER_RULES) {
			try {
				$currentHeader = $Headers[$rule.Name]
				
				Write-Log "Debug" "Evaluating rule $($rule.Name)"

				# If not inadvisable but present, it's insecure
				if ($rule.Policy -eq "Inadvisable" -and $null -ne $currentHeader) {
					Write-Log "Warning" "Inadvisable header $($rule.Name) is present"
					# Append results to report object and continue
					$report.Add([PSCustomObject]@{
						Name = $rule.Name
						Value = $currentHeader
						Policy = $rule.Policy
						IsSecure = $false
						Recommendation = $rule.Recommendation
						References = $rule.References
					})
					continue
				}

				# If required but missing, it's insecure
				if ($rule.Policy -eq "Required" -and $null -eq $currentHeader) {
					Write-Log "Warning" "Required header $($rule.Name) is missing"
					# Append results to report object and continue
					$report.Add([PSCustomObject]@{
						Name = $rule.Name
						Value = $currentHeader
						Policy = $rule.Policy
						IsSecure = $false
						Recommendation = $rule.Recommendation
						References = $rule.References
					})
					continue
				}

				# It's not inadvisable or missing, perform assessment
				if (Invoke-Command -ScriptBlock $rule.IsSecure -ArgumentList $currentHeader){
					Write-Log "Debug" "Header $($rule.Name) is secure according to assessment"
					$isSecure = $true
				} else {
					Write-Log "Warning" "Header $($rule.Name) is insecure according to assessment"
					$isSecure = $false
				}
				
				$report.Add([PSCustomObject]@{
					Name = $rule.Name
					Value = $currentHeader
					Policy = $rule.Policy
					IsSecure = $isSecure
					Recommendation = $rule.Recommendation
					References = $rule.References
				})
			} catch {
				Write-Log "Error" "Error evaluating rule $($rule.Name): $($_.Exception.Message)"
			}
		}		
		Write-Log "Info" "Completed header audit"
		return $report
	}
}

<#
	.SYNOPSIS
		
	.DESCRIPTION
		...
	.PARAMETER ...
		...
	.EXAMPLE
		...
	.INPUTS
		...
	.OUTPUTS
		...
	.COMPONENT
		...
	.LINK
		...
	.NOTES
		...
#>
function Invoke-Elenchus {
	[CmdletBinding()]
    [OutputType([System.Void])]
	param(
		[Parameter(Mandatory, Position = 0)]
		[string]$Target,

		[Parameter()]
		[switch]$DebugMode
	)

	process {
		Write-Log "Info" "Starting Elenchus scan"

		if ($DebugMode) {
			$CurrentLogLevel = $LOG_DEBUG
			Write-Log "Debug" "Debug mode enabled"
		}

		try {
			# Check for proxy

			# Perform request and log details on debug
			$ResponseHeaders = (Invoke-WebRequest -Uri $Target -Method GET -UseBasicParsing -ErrorAction Stop).Headers

			# Log response headers and cookies on debug
			Write-Log "Debug" "Fetched response headers:`n$( ($ResponseHeaders.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`n" )"

			# invoke audits
			$HeaderAuditReport = Invoke-HeaderAudit -Headers $ResponseHeaders

			Write-Log "Info" "Completed Elenchus scan"
			# Write report
			$HeaderAuditReport | Format-Table -AutoSize
		} catch {
			Write-Log "Critical" "Error during main execution: $($_.Exception.Message)"
			exit 1
		}
	}
}