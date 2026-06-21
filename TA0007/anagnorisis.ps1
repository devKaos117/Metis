# ============================================================================
# INFO
# ============================================================================
# ============ Author
# https://www.linkedin.com/in/kaos/
# ============ Description
# Anagnorisis
# The sudden moment of critical discovery and revelation. Windows modern enumeration script for a rapid environment contextualization
# ============ Usage
# ============ References
# https://github.com/peass-ng/PEASS-ng

# ============================================================================
# INITIALIZATIONS
# ============================================================================
$ErrorActionPreference = "Stop"

Set-Variable -Name ESCAPE_CHAR -Option Constant -Scope Script -Visibility Private -Value [char]27
Set-Variable -Name RED -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[31m"
Set-Variable -Name YELLOW -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[33m"
Set-Variable -Name GREEN -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[32m"
Set-Variable -Name CYAN -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[36m"
Set-Variable -Name RESET -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[0m"

# ============================================================================
# PLATFORM
# ============================================================================
# Device Model and Manufacturer
# Get-CimInstance Win32_Bios -Property SerialNumber,SMBIOSBIOSVersion,Manufacturer,Name
# Get-CimInstance -ClassName Win32_ComputerSystem -Property Model, Manufacturer -ErrorAction Stop
# Motherboard
# CPU
# GPU
# RAM
# Storage Devices
# Connected Devices

# ============================================================================
# SYSINFO
# ============================================================================
function Temp-Sysinfo {
	# hostname, Current Time
	$hostname = [System.Net.Dns]::GetHostName()
	$time = [System.DateTime]::UtcNow.ToString("s")
	Write-Host "$hostname - $time"
	# OS Name SystemLang Architecture (build)
	$os_name = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
	$os_displayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
	$os_lang = [System.Globalization.CultureInfo]::InstalledUICulture.Name
	$os_kernel = [System.Environment]::OSVersion.Platform
	$os_version = (Get-CimInstance Win32_OperatingSystem).Version
	$os_arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
	Write-Host "$os_name $os_displayVersion $os_lang ($os_kernel $os_version $os_arch)"
	# Non security updates
	$updates = (Get-HotFix | Where-Object {$_.Description -notlike '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
	Write-Host "Updates: $updates"
	# Security updates
	$security_updates = (Get-HotFix | Where-Object {$_.Description -like '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
	Write-Host "Security Updates: $security_updates"
}

# ============================================================================
# SECURITY STATE
# ============================================================================
<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER None
	.EXAMPLE
	.INPUTS
	.OUTPUTS
		System.Management.Automation.PSCustomObject
	.COMPONENT
		SecurityState/VirtualEnvironment
	.LINK
	.NOTES
		Date: June 2026
#>
function Test-VirtualEnvironment {
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	param()
	process {
		$results = @{
			CIMComputerSystem = $null
			CIMBios = $null
			CIMBaseBoard = $null
		}
		$message = $null

		# VirtualBox
		# VMware
		# KVM
		# Hyper-V
		# QEMU
		# Parallels
		# Xen
		
		# Microsoft Corporation
		# Oracle
		# VMware, Inc.
		# Xen

		try {
			Get-CimInstance -ClassName Win32_ComputerSystem -Property Model, Manufacturer -ErrorAction Stop
		} catch {
			$results.CIMComputerSystem = "Unknown"
		}

		try {
			Get-CimInstance -ClassName Win32_Bios -Property SerialNumber -ErrorAction Stop
		}
		catch {
			$results.CIMBios = "Unknown"
		}

		try {
			Get-CimInstance -ClassName Win32_BaseBoard -Property Product, Manufacturer -ErrorAction Stop
		}
		catch {
			$results.CIMBaseBoard = "Unknown"
		}

		# Discrepancy Check
		$consistencyReport = Test-Consistency -InputData $results

		# Determine result
		if ($consistencyReport.Consistency -eq 1 -and $consistencyReport.Result -ne "Unknown") {
			if ($consistencyReport.Result) {
				$message = "`t$($CYAN)[*]$($RESET) Virtual environment isolation $($GREEN)Detected$($RESET)"
			} else {
				$message = "`t$($CYAN)[*]$($RESET) Virtual environment isolation $($RED)Absent$($RESET)"
			}
		} else {
			$message = "`t$($YELLOW)[?]$($RESET) $(consistencyReport.Result) virtual environment isolation state:$($consistencyReport.Message)"
		}

		# Return report object
		return [PSCustomObject]@{
			Component = "VirtualEnvironment"
			Consistency = $consistencyReport.Consistency
			Uncertainty = $consistencyReport.Uncertainty
			Values = $results
			Result = $consistencyReport.Result
			Message = $message
		}
	}
}

<#
	.SYNOPSIS
		Checks if Secure Boot is enabled by querying multiple registry paths and CIM classes
	.DESCRIPTION
		The Test-SecureBoot function enumerates the Secure Boot status of a Windows host by cross-referencing three separate data sources: the Local Security Authority (LSA) registry key, the UEFI Secure Boot State registry key, and the Win32_Tpm CIM class
		To ensure consistency, a verification is performed to detect any discrepancies from the three sources, returning a consolidated status object
	.PARAMETER None
		No parameters are required
	.EXAMPLE
		Test-SecureBoot
	.INPUTS
		No inputs accepted
	.OUTPUTS
		System.Management.Automation.PSCustomObject
	.COMPONENT
		SecurityState/SecureBoot
	.LINK
	.NOTES
		Date: June 2026
		Requires administrative privileges, otherwise registry and CIM queries will fail
#>
function Test-SecureBoot {
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	param()
	process {
		$results = @{
			RegKeyLSA = $null
			RegKeyUEFI = $null
			CIMClass = $null
		}
		$message = $null

		# LSA Registry Key
		try {
			$regkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
			if ($null -ne $regkey.SecureBoot) {
				$results.RegKeyLSA = [bool]$regkey.SecureBoot
			} else {
				throw "SecureBoot value not found in LSA registry key"
			}
		} catch {
			$results.RegKeyLSA = "Unknown"
		}

		# UEFI Registry Key
		try {
			$regkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction Stop
			$results.RegKeyUEFI = [bool]$regkey.UEFISecureBootEnabled
		} catch {
			$results.RegKeyUEFI = "Unknown"
		}

		# Common Information Model Class
		try {
			throw "Not implemented yet"
			# $cimInstance = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
		} catch {
			$results.CIMClass = "Unknown"
		}

		# Discrepancy Check
		$consistencyReport = Test-Consistency -InputData $results

		# Determine result
		if ($consistencyReport.Consistency -eq 1 -and $consistencyReport.Result -is [bool]) {
			if ($consistencyReport.Result) {
				$message = "`t$($CYAN)[*]$($RESET) SecureBoot $($GREEN)Enabled$($RESET)"
			} else {
				$message = "`t$($CYAN)[*]$($RESET) SecureBoot $($RED)Disabled$($RESET)"
			}
		} else {
			$message = "`t$($YELLOW)[?]$($RESET) $(consistencyReport.Result) SecureBoot state:$($consistencyReport.Message)"
		}

		# Return report object
		return [PSCustomObject]@{
			Component = "SecureBoot"
			Consistency = $consistencyReport.Consistency
			Uncertainty = $consistencyReport.Uncertainty
			Values = $results
			Result = $consistencyReport.Result
			Message = $message
		}
	}
}

function Temp-SecurityState {
	# LSA Protection
	(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
	# Credentials Guard
	# Av Information
	# $cmd = if ($psv -ge 3) { 'Get-CimInstance' } else { 'Get-WmiObject' }
	# $avList = & $cmd -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike 'windows' } | Select-Object -ExpandProperty displayName
	WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
	Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue
}


# ============================================================================
# NETWORK
# ============================================================================
# Network shares
# network ifaces and known hosts
# seatbelt arp tables
# current ipv4/ipv6 tcp listening ports and associated process
# current ipv4/ipv6 udp listening ports and associated process
# firewall rules
# dns cache

# ============================================================================
# IDENTITIES
# ============================================================================
function Temp-Identities {
	$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	# Logged in with Authentication Type
	Write-Host "Logged in with $($identity.AuthenticationType)"
	# hostname\username (SID)
	Write-Host "$($identity.Name) ($sid)"
	# Privileges
	# Current groups (SID)
	
	# hostname\username (SID) IsDisabled? IsAdmin?
	# groups (SID)
	# Last logon time
}

# ============================================================================
# DOMAIN
# ============================================================================
# [System.DirectoryServices.ActiveDirectory.Domain]
# $domain = try {[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { $null }

# ============================================================================
# RESOURCES
# ============================================================================
# ====== Services (powersploit privesc get modifiable service)
# running services with name,startmode,serviceaccount,permissions,pathname

# ====== Tasks
# scheduled tasks with hostname\taskname, trigger, action (permissions)

# ============================================================================
# FILES
# ============================================================================
# Recieve a target dir, check permissions, list files based on a filetype list, regex match into the files and report back

# ====== Useful Software and Related Files
# ssh
# putty
# browsers
# password managers
# web application
# DBMS

# ====== Files
# look for files in userdir
# regex match of interesting findings
# look for permission in interesing dirs

# ============================================================================
# UTILITIES
# ============================================================================
<#
	.SYNOPSIS
		Evaluates multiple data sources for homogeneous results and returns a consistency and uncertainty report
	.DESCRIPTION
		The Test-Consistency function analyzes a hashtable of state data. It logically isolates "Unknown" or null values from explicit values
        It calculates an Uncertainty Index (ratio of unknown to total values) and a Consistency Index (ratio of the statistical mode to the known values)
		If a single mode exists, it is returned as the consolidated result. Any discrepancies or unknown values are formatted into a message for review
	.PARAMETER StateData
		Specifies the hashtable containing the state information. The keys should be the name of the source, and the values should be its raw information
	.EXAMPLE
		$data = @{
			"ApiEEndpoint" = "Running"
			"DbQuery"      = "Unknown"
			"LocalLog"     = "Running"
		}
		Test-Consistency -StateData $data
		# Consistency: 1.0
		# Uncertainty: 0.333
		# Message:
		#	ApiEEndpoint: Running
		#	DbQuery: Unknown
		#	LocalLog: Running
		# Result: Running
	.INPUTS
		System.Collections.Hashtable
	.OUTPUTS
		System.Management.Automation.PSCustomObject
	.COMPONENT
		Utilities/Consistency
	.LINK
	.NOTES
		Date: June 2026
		Strict Type Evaluation: This function performs strict variable types evaluation
#>
function Test-Consistency {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputData
    )

    process {
		function Build-Message {
			[CmdletBinding()]
			[OutputType([string])]
			param (
				[System.Object[]]$Entries
			)
			process {
				$msgBuilder = [System.Text.StringBuilder]::new()
	
				foreach ($entry in ($Entries | Sort-Object Name)) {
					[void]$msgBuilder.Append("`n`t`t$($entry.Name): $($entry.Value)")
				}
				return $msgBuilder.ToString()
			}
		}
        
		[int]$totalCount = $InputData.Count

        if ($totalCount -eq 0) {
            return [PSCustomObject]@{
                Consistency = 0.0
                Uncertainty = 1.0
                Message     = "No data provided"
                Result      = "Unknown"
            }
        }

        # Isolate known and unknown datasets
        $entries = @($InputData.GetEnumerator())
		[array]$unknowns = $entries | Where-Object { $_.Value -eq "Unknown" -or [string]::IsNullOrWhiteSpace($_.Value) }
		[array]$knowns = $entries | Where-Object { $_.Value -ne "Unknown" -and -not [string]::IsNullOrWhiteSpace($_.Value) }

        [int]$uCount = $unknowns.Count
        [int]$kCount = $knowns.Count

        [double]$uncertainty = [double]$uCount / $totalCount
        [double]$consistency = 0.0
        [string]$result = "Unknown"
		[string]$message = $null

        if ($kCount -gt 0) {
            # Group known values to determine statistical mode and consistency
            $groupedKnowns = $knowns | Group-Object -Property Value | Sort-Object Count -Descending
			[int]$mode = $groupedKnowns[0].Count
            $consistency = [double]$mode / $kCount

            $result = $groupedKnowns[0].Name
			# Redefine result in the presence of known discrepancies
			if ($consistency -lt 1) {
				$result = "Inconsistent"
				$message = "$(Build-Message -Entries $entries)"
			}
        } else {
			$message = "$(Build-Message -Entries $entries)"
        }

        return [PSCustomObject]@{
            Consistency = [math]::Round($consistency, 3)
            Uncertainty = [math]::Round($uncertainty, 3)
            Message     = $message
            Result      = $result
        }
    }
}

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
function Invoke-Anagnorisis{
	[CmdletBinding()]
	[OutputType([System.Void])]
	param(
		[Parameter()]
		[switch]$EnumerateDomain
	)

	process {
		$tests = [ordered]@{
			Platform = @()
			SysInfo = @(
				{Temp-Sysinfo}
			)
			SecurityState = @(
				{Test-VirtualEnvironment}
				{Test-SecureBoot}
				{Temp-SecurityState}
			)
			Network = @()
			Identities = @(
				{Temp-Identities}
			)
			Domain = @()
			Resources = @()
			Files = @()
		}

		$stopwatch = [system.diagnostics.stopwatch]::StartNew()

		foreach ($section in $tests.GetEnumerator()) {
			Write-Host "[+] $($section.Name) Enumeration ($($section.Value.Count))"
			foreach ($test in $section.Value) {
				try {
					$result = Invoke-Command -ScriptBlock $test
					if ($null -ne $result.Message) {
						Write-Host $result.Message
					} else {
						Write-Host "`t$($YELLOW)[?]$($RESET) Component execution returned no message: $($test)"
					}
				}
				catch {
					Write-Host "`t$($RED)[!]$($RESET) Error during component execution:`n`t`t$($test)`n`t`t$($_.Exception.Message)"
				}
			}
		}

		Write-Host "$($GREEN)Done in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)).$($stopwatch.Elapsed.Milliseconds) seconds$($RESET)"
	}
}


# DESKTOP-0OOLLC2 - 2026-04-03T06:19:22
# Windows 10 Pro 21H2 en-US (Win32NT 10.0.22000 64-bit)
# Updates: KB5025186,KB5011048,KB5030842,KB5031591,KB5008295
# Security Updates: KB5031358
# Hypervisor: VMware, Inc. (VMware7,1)
# SecureBoot is Enabled
# Logged in with NTLM
# DESKTOP-0OOLLC2\Administrator
# Done in 0.505 seconds