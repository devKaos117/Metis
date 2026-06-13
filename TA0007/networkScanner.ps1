# ============================================================================
# INITIALIZATIONS
# ============================================================================
$ErrorActionPreference = "Stop"

# ============================================================================
# LOGGER
# ============================================================================
# ============ Constants
Set-Variable LOG_NONE -Option ReadOnly -Scope Script -Visibility Private -Value 99
Set-Variable LOG_CRITICAL -Option ReadOnly -Scope Script -Visibility Private -Value 50
Set-Variable LOG_ERROR -Option ReadOnly -Scope Script -Visibility Private -Value 40
Set-Variable LOG_WARNING -Option ReadOnly -Scope Script -Visibility Private -Value 30
Set-Variable LOG_INFO -Option ReadOnly -Scope Script -Visibility Private -Value 20
Set-Variable LOG_DEBUG -Option ReadOnly -Scope Script -Visibility Private -Value 10

Set-Variable LogLevelNames -Option ReadOnly -Scope Script -Visibility Private -Value @{
	99 = "NONE"
	50 = "CRITICAL"
	40 = "ERROR"
	30 = "WARNING"
	20 = "INFO"
	10 = "DEBUG"
}

Set-Variable LogColors -Option ReadOnly -Scope Script -Visibility Private -Value @{
	99 = "Gray"		# Reset/None
	50 = "Magenta"	# Critical
	40 = "Red"		# Error
	30 = "Yellow"	# Warning
	20 = "Green"	# Info
	10 = "Cyan"		# Debug
	0 = "White"		# Custom
}

Set-Variable TimestampFormat -Option ReadOnly -Scope Script -Visibility Private -Value "HH:mm:ss.fff"
SET-Variable CurrentLogLevel -Option ReadOnly -Scope Script -Visibility Private -Value $LOG_INFO
SET-Variable ColorizeMessage -Option ReadOnly -Scope Script -Visibility Private -Value $true

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
# SCANNER
# ============================================================================
function Test-TcpPort {
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[System.Net.IPAddress]$Target,

		[Parameter(Mandatory)]
		[ValidateRange(1, [UInt16]::MaxValue)]
		[int]$Port,

		[Parameter(Mandatory)]
		[ValidateRange(1,[int]::MaxValue)]
		[int]$Timeout
	)

	process {
		Write-Log "Debug" "Testing ${Target}:${Port} (${Timeout}ms)"

		$tcp = New-Object System.Net.Sockets.TcpClient
		$async = $null
		$waitHandle = $null
		$sw = [System.Diagnostics.Stopwatch]::StartNew()

		try {
			$async = $tcp.BeginConnect($Target, $Port, $null, $null)
			$waitHandle = $async.AsyncWaitHandle

			if ($waitHandle.WaitOne($Timeout, $false)) {
				$tcp.EndConnect($async)
				$sw.Stop()

				if ($tcp.Connected) {
					$elapsed = $sw.ElapsedMilliseconds
					Write-Log "Debug" "${Target}:${Port} responded in ${elapsed}ms"
					return $true
				}
			}

			return $false
		}
		catch {
			Write-Log "Error" "$($_.Exception.Message)"
			Write-Log "Warning" "Failed testing ${Target}:${Port}"
			return $false
		}
		finally {
			if ($waitHandle) { $waitHandle.Close() }
			if ($tcp) { $tcp.Close() }
			if ($sw -and $sw.IsRunning) { $sw.Stop() }
		}
	}
}

function Test-Host {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[string]$Target,

		[Parameter(Mandatory)]
		[ValidateRange(1, [UInt16]::MaxValue)]
		[int[]]$Ports,

		[Parameter(Mandatory)]
		[ValidateRange(1,[int]::MaxValue)]
		[int]$Timeout,

		[Parameter]
		[switch]$PerformPing = $false
	)

	process {
		$alive = $false
		$reason = "No port responded"

		if ($PerformPing -and (Test-Connection -ComputerName $Target -Count 1 -Quiet -TimeoutSeconds ([math]::Ceiling($Timeout / 1000)))) {
			$alive = $true
			$reason = "Host responded to ICMP"
		} else {
			Write-Log "Debug" "Host did not respond to ICMP, falling back to port scan"

			$ports = $Ports | Sort-Object -Unique
			foreach ($port in $ports) {
				if (Test-TcpPort -Target $Target -Port $port -Timeout $Timeout) {
					$alive = $true
					$reason = "Port $port responded"
					break
				}
			}
		}

		return [PSCustomObject]@{
			alive = $alive
			reason = $reason
		}
	}
}

function Test-Hosts {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[string[]]$Targets,

		[Parameter(Mandatory)]
		[ValidateRange(1, [UInt16]::MaxValue)]
		[int[]]$Ports,

		[Parameter(Mandatory)]
		[ValidateRange(1,[int]::MaxValue)]
		[int]$Timeout
	)

	process {
		Write-Log "Info" "Initializing tests against ${Targets.Count} hosts"

		$result = New-Object System.Collections.Generic.List[object]

		foreach ($target in $Targets) {
			try {
				$ip = [System.Net.Dns]::GetHostAddresses($target).IPAddressToString
				Write-Log "Debug" "$target resolved to $ip"
			}
			catch {
				Write-Log "Warning" "Failed resolving hostname ${target}"
				Continue
			}

			try {
				Write-Log "Info" "Testing host ${target} on $ip"
				$test = Test-Host -Target $ip -Ports $Ports -Timeout $Timeout

				if ($test.alive) {
					$result.Add([PSCustomObject]@{
						hostname = $target
						ip = $ip
						reason = $test.reason
					})
				}
			}
			catch {
				Write-Log "Error" "$($_.Exception.Message)"
				Write-Log "Warning" "Failed to test server ${target}"
			}
		}

		return $result
	}
}