# ============================================================================
# INFO
# ============================================================================
# ============ Description
# HTTP client with proxy support and retry mechanism
# ============ Usage
# ./http.ps1
# $proxy = Initialize-ProxyConnection "HTTP" "proxy:8080/" "kaos"
# $res = Send-HttpReq "GET" "www.google.com" -ProxyConfig $proxy

$ErrorActionPreference = "Stop"

# ============================================================================
# LOGGER
# ============================================================================
# ============ Initializations
# Constants
Set-Variable LOG_NONE -Option ReadOnly -Value 99
Set-Variable LOG_CRITICAL -Option ReadOnly -Value 50
Set-Variable LOG_ERROR -Option ReadOnly -Value 40
Set-Variable LOG_WARNING -Option ReadOnly -Value 30
Set-Variable LOG_INFO -Option ReadOnly -Value 20
Set-Variable LOG_DEBUG -Option ReadOnly -Value 10

Set-Variable LogLevelNames -Option ReadOnly -Value @{
	99 = "NONE"
	50 = "CRITICAL"
	40 = "ERROR"
	30 = "WARNING"
	20 = "INFO"
	10 = "DEBUG"
}

Set-Variable LogColors -Option ReadOnly -Value @{
	99 = "Gray"		# Reset/None
	50 = "Magenta"	# Critical
	40 = "Red"		# Error
	30 = "Yellow"	# Warning
	20 = "Green"	# Info
	10 = "Cyan"		# Debug
	0 = "White"		# Custom
}

# Configurations
Set-Variable TimestampFormat -Option ReadOnly -Value "HH:mm:ss.fff"
Set-Variable CurrentLogLevel -Option ReadOnly -Value $LOG_INFO
Set-Variable ColorizeMessage -Option ReadOnly -Value $true

# ============ Private functions
<#
	.SYNOPSIS
		Traceback the calling stack
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

<#
	.SYNOPSIS
		Write the log to the host
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

# ============ Public API
<#
	.SYNOPSIS
		Logging function
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
# HTTP CLIENT
# ============================================================================
# ============ Initializations
# Variables
Set-Variable ProxyCredentials -Scope Script -Visibility Private -Value $null
$retryableStatusCodes = @(
	408,	# Request Timeout
	429,	# Too Many Requests
	500,	# Internal Server Error
	502,	# Bad Gateway
	503,	# Service Unavailable
	504		# Gateway Timeout
)

# ============ Private functions
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
			Uri = "http://www.google.com/"
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
			foreach ($header in $authHeader) {
				if ($header -match "^(\w+)") {
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

# ============ Public API
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

<#
	.SYNOPSIS
		Perform HTTP request
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
function Send-HttpReq {
	[CmdletBinding()]
	param (
		# Method
		[Parameter(Mandatory, Position=0)]
		[ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")]
		[string] $Method,

		# URL
		[Parameter(Mandatory, Position=1)]
		[System.Uri] $Uri,

		# Headers
		[Parameter()]
		[hashtable] $Headers = @{},

		# Request Body
		[Parameter()]
		[string] $Body,

		# Timeout in seconds
		[Parameter()]
		[ValidateRange(1, 3600)]
		[int] $Timeout = 30,

		# Expected HTTP response code
		[Parameter()]
		[ValidateRange(100, 599)]
		[int] $ExpectedResponseCode = 200,

		# Max request attempts
		[Parameter()]
		[ValidateRange(1, 100)]
		[int] $MaxAttempts = 3,

		# Proxy configuration object
		[Parameter()]
		[object] $ProxyConfig = $null,

		# Session name
		[Parameter()]
		[string] $SessionName = "session"

	)
	process {
		$attemptCount = 0
		$lastError = $null

		while ($attemptCount -lt $MaxAttempts) {
			$attemptCount++

			try {
				# Prepare Invoke-WebRequest parameters
				$requestParams = @{
					Uri = $Uri
					Method = $Method
					Headers = $Headers.Clone()
					TimeoutSec = $Timeout
					UseBasicParsing = $true
				}

				# Add body if provided
				if ($Body) {
					$requestParams["Body"] = $Body
				}

				# Add proxy if configured
				if ($ProxyConfig) {
					$requestParams["Proxy"] = $ProxyConfig.Uri.AbsoluteUri
					$requestParams["ProxyUseDefaultCredentials"] = $ProxyConfig.UseDefaultCredentials

					if ($ProxyConfig.Credentials) {
						$requestParams["ProxyCredential"] = $ProxyConfig.Credentials
					}
				}

				# Managing web session
				$session = Get-Variable -Name $SessionName -Scope Script -ErrorAction SilentlyContinue

				if ($session -and $session.Value -is [Microsoft.PowerShell.Commands.WebRequestSession]) {
					$requestParams["WebSession"] = $session.Value
					Write-Log "Debug" "Using web session: $SessionName"
				} else {
					$requestParams["SessionVariable"] = $SessionName
					Write-Log "Debug" "Creating new web session: $SessionName"
				}

				# Send the request
				Write-Log "Debug" "HTTP $Method $Uri"
				$response = Invoke-WebRequest @requestParams

				# Check the response code
				if ($response.StatusCode -eq $ExpectedResponseCode) {
					return $response.Content
				}
				else {
					throw "Unexpected status code ($($response.StatusCode))"
				}
			} catch {
				$statusCode = $null

				# Extract status code from error if available
				if ($_.Exception.Response) {
					$statusCode = [int]$_.Exception.Response.StatusCode
				}

				# Check if this is a retryable attempt
				if ($statusCode -and $statusCode -in $retryableStatusCodes -and $attemptCount -lt $MaxAttempts) {
					# Calculate backoff delay (exponential backoff)
					$delaySeconds = [Math]::Min(2, [Math]::Pow(2, $attemptCount - 1))
					Write-Log "Warning" "Waiting $delaySeconds seconds before retry..."
					Start-Sleep -Seconds $delaySeconds
					continue
				}

				# Non-retryable error - give up immediately
				$lastError = $_
				Write-Log "Error" "HTTP request error: $($_.Exception.Message)"

				if ($attemptCount -lt $MaxAttempts) {
					Write-Log "Warning" "Non-retryable error. Giving up"
				}

				break
			}
		}

		Write-Log "Critical" "Failed to perform HTTP request after $attemptCount attempts"
		throw "HTTP request failed: $($lastError.Exception.Message)"
	}
}