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
Set-Variable -Name GREEN -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[32m"
Set-Variable -Name CYAN -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[36m"
Set-Variable -Name RESET -Option Constant -Scope Script -Visibility Private -Value "$ESCAPE_CHAR[0m"

# ============================================================================
# SYSINFO
# ============================================================================
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

# ============================================================================
# SECURITY STATE
# ============================================================================
<#
	.SYNOPSIS
		Checks if Secure Boot is enabled by querying multiple registry paths and CIM classes
	.DESCRIPTION
		The Assert-SecureBoot function enumerates the Secure Boot status of a Windows host by cross-referencing three separate data sources: the Local Security Authority (LSA) registry key, the UEFI Secure Boot State registry key, and the Win32_Tpm CIM class
		To ensure consistency, a verification is performed to detect any discrepancies from the three sources, returning a consolidated status object
	.PARAMETER None
		No parameters are required
	.EXAMPLE
		Assert-SecureBoot
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
function Assert-SecureBoot {
	[CmdletBinding()]
	param()
	process {
		$regKeyLsa = $null
		$regKeyUefi = $null
		$cim = $null
		$result = $null
		$message = ""

		# LSA Registry Key
		try {
			$regkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
			if ($null -ne $regkey.SecureBoot) { $regkey = [bool]$regkey.SecureBoot }
		} catch {
			$regKeyLsa = "Unknown"
		}

		# UEFI Registry Key
		try {
			$regkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction Stop
			$regKeyUefi = [bool]$regkey.UEFISecureBootEnabled
		} catch {
			$regKeyUefi = "Unknown"
		}

		# Common Information Model Class
		try {
			throw "Not implemented yet"
			# $cimInstance = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
		} catch {
			$cim = "Unknown"
		}

		# Discrepancy Check
		$validResults = @($regKeyLsa, $regKeyUefi, $cim) | Where-Object { $_ -is [bool] }
		$isConsistent = ($validResults | Select-Object -Unique).Count -le 1

		# Determine result
		if ($isConsistent -and $validResults.Count -gt 0) {
			$result = $validResults[0]

			if ($result) {
				$message = "$($CYAN)SecureBoot $($GREEN)Enabled$($RESET)"
			} else {
				$message = "$($CYAN)SecureBoot $($RED)Disabled$($RESET)"
			}
		} else {
			$message = "Unknown $($CYAN)SecureBoot$($RESET) state:`n`tLSA Registry: $regKeyLsa`n`tUEFI Registry: $regKeyUefi`n`tCIM Class: $cim"
		}

		# Return report object
		return [PSCustomObject]@{
			Component = "SecureBoot"
			IsConsistent = $isConsistent
			Values = @{
				RegKeyLSA = $regKeyLsa
				RegKeyUEFI = $regKeyUefi
				CIMClass = $cim
			}
			Result = $result
			Message = $message
		}
	}
}

# Virtualization?
$virt = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, HypervisorPresent
if ($virt.HypervisorPresent) {
	Write-Host "Hypervisor: $($virt.Model) ($($virt.Manufacturer))"
}
# SecureBoot?
Write-Host (Assert-SecureBoot).Message
# LSA Protection
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
# Credentials Guard
# Av Information
# $cmd = if ($psv -ge 3) { 'Get-CimInstance' } else { 'Get-WmiObject' }
# $avList = & $cmd -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike 'windows' } | Select-Object -ExpandProperty displayName
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue

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
		try {
			$stopwatch = [system.diagnostics.stopwatch]::StartNew()
			Write-Host "Done in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)).$($stopwatch.Elapsed.Milliseconds) seconds"
		}
		catch {
			Write-Host "Error during main execution: $($_.Exception.Message)"
			exit 1
		}
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