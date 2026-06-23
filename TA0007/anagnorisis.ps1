<#
	.SYNOPSIS
		Anagnorisis: The sudden moment of critical discovery and revelation. Windows modern enumeration script for a rapid environment contextualization
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
		Author: https://www.linkedin.com/in/kaos/
		References:
			https://github.com/peass-ng/PEASS-ng
#>
# ============================================================================
# INITIALIZATIONS
# ============================================================================
[CmdletBinding()]
[OutputType([System.Void])]
param(
	[switch]$SkipPlatform,
	[switch]$SkipSysInfo,
	[switch]$SkipSecurityState,
	[switch]$SkipNetwork,
	[switch]$SkipIdentities,
	[switch]$SkipDomain,
	[switch]$SkipResources,
	[switch]$SkipFiles
)

$ErrorActionPreference = "Stop"

# Try to execute script using PowerShell 7+
if ($PSVersionTable.PSVersion.Major -lt 7) {
	$pwshPaths = @(
		"$Env:ProgramFiles\PowerShell\7\pwsh.exe",
		"$Env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe",
		"${Env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe",
		"$Env:ProgramFiles\PowerShell\7-preview\pwsh.exe"
	)
	$pwshPath = $pwshPaths | Where-Object { Test-Path $_ -PathType Leaf } | Select-Object -First 1

	if ($pwshPath) {
		Write-Host "[!] Relaunching script in PowerShell 7 using $pwshPath" -ForegroundColor Yellow
		& $pwshPath -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
		exit
	} else {
		Write-Host "[!] Failed to relaunch script in PowerShell 7" -ForegroundColor Red
	}
}

# Measure execution timing
$stopwatch = [system.diagnostics.stopwatch]::StartNew()

# ============================================================================
# UTILITIES
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
function Write-Color {
	[CmdletBinding()]
	[OutputType([System.Void])]
	param(
		[Parameter(Mandatory)]
		[string]$Msg
	)
	process {
		# Default color
		$defaultColor = "White"	
		# Find pattern
		$pattern = '\{\{(?<color>\w+):(?<text>.*?)\}\}' # {{Color:Text}}
		$patternMatches = [regex]::Matches($Msg, $pattern)
		# Iterate through the message
		$lastIndex = 0
		foreach ($m in $patternMatches) {
			# Write text before match
			if ($m.Index -gt $lastIndex) {
				$plainText = $Msg.Substring($lastIndex, $m.Index - $lastIndex)
				Write-Host $plainText -NoNewline -ForegroundColor $defaultColor
			}
			# Extract components
			$color = $m.Groups["color"].Value
			$txt = $m.Groups["text"].Value
			# Validate color
			if (-not [Enum]::GetNames([ConsoleColor]).Contains($color)) {
				$color = $defaultColor
			}
			# Write message segment
			Write-Host $txt -ForegroundColor $color -NoNewline
			$lastIndex = $m.Index + $m.Length
		}
		# Remaining text
		if ($lastIndex -lt $Msg.Length) {
			Write-Host $Msg.Substring($lastIndex) -NoNewline -ForegroundColor $defaultColor
		}
		# Final newline
		Write-Host ""
	}
}

# ============================================================================
# PLATFORM
# ============================================================================
Write-Color "{{Magenta:[*] Platform}}:"
$CIMWin32 = Get-CimInstance -ClassName Win32_ComputerSystem -Property Model, Manufacturer -ErrorAction Stop
$CIMWinBIOS = Get-CimInstance -ClassName Win32_Bios -Property Version, SerialNumber, SMBIOSBIOSVersion -ErrorAction Stop
$CIMWin32Board = Get-CimInstance -ClassName Win32_BaseBoard -Property Manufacturer, Product, SerialNumber -ErrorAction Stop
$CIMCPU = Get-CimInstance -ClassName Win32_Processor -Property  DeviceID,Name,Manufacturer,Architecture,Family,NumberOfCores,NumberOfLogicalProcessors,ThreadCount -ErrorAction Stop
$CIMGPU = Get-CimInstance -ClassName Win32_VideoController -Property DeviceID,Status,Name,AdapterRAM,AdapterCompatibility,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentNumberOfColors,CurrentRefreshRate,CurrentBitsPerPixel -ErrorAction Stop
$CIMRAM = Get-CimInstance -ClassName Win32_PhysicalMemory -Property Manufacturer,PartNumber,SerialNumber,FormFactor,SMBIOSMemoryType,ConfiguredVoltage,Capacity,ConfiguredClockSpeed,Speed -ErrorAction Stop
$CIMDisks = Get-CimInstance -ClassName Win32_DiskDrive -Property Index,InterfaceType,MediaType,Model,Size,BytesPerSector,Partitions,FirmwareRevision,SerialNumber -ErrorAction Stop
$CIMDevices = Get-CimInstance -ClassName Win32_PnPEntity -Property Status,Present,PNPDeviceID,PNPClass,Name,Description -ErrorAction Stop
# ======== Device name
# Device Model and Manufacturer
$device = "$($CIMWin32.Manufacturer) $($CIMWin32.Model) $($CIMWinBIOS.SerialNumber)"
Write-Color "`t{{Cyan:[+] Device}}: $device"
# ======== BIOS information
$BIOSVersion = "$($CIMWinBIOS.Version) ($($CIMWinBIOS.SMBIOSBIOSVersion))"
Write-Color "`t{{Cyan:[+] BIOS}}: $BIOSVersion"
# ======== Motherboard
$motherboard = "$($CIMWin32Board.Manufacturer) $($CIMWin32Board.Product) (SN: $($CIMWin32Board.SerialNumber))"
Write-Color "`t{{Cyan:[+] Motherboard}}: $motherboard"
# ======== CPU
Write-Color "`t{{Cyan:[+] CPUs}} ($($CIMCPU.Count)):"
foreach ($cpu in $CIMCPU) {
	Write-Color "`t`t{{Cyan:[>]}} $($cpu.DeviceID): $($cpu.Name) ($($cpu.NumberOfCores)/$($cpu.NumberOfLogicalProcessors) $($cpu.ThreadCount)T) ($($cpu.Manufacturer) $($cpu.Architecture):$($cpu.Family))"
}
# ======== GPU
Write-Color "`t{{Cyan:[+] GPUs}} ($($CIMGPU.Count)):"
foreach ($gpu in $CIMGPU) {
	Write-Color "`t`t{{Cyan:[>]}} $($gpu.DeviceID) ($($gpu.status)): $($gpu.Name) ($([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB), $($gpu.AdapterCompatibility) driver $($gpu.DriverVersion), video $($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution)x$($gpu.CurrentNumberOfColors) ($($gpu.CurrentRefreshRate)Hz $($gpu.CurrentBitsPerPixel)b)"
}
# ======== RAM
Write-Color "`t{{Cyan:[+] RAM modules}} ($($CIMRAM.Count)):"
foreach ($ram in $CIMRAM) {
	$moduleType = switch ($ram.FormFactor) {
		8 { "DIMM" }
		12 { "SODIMM" }
		Default { "Module Type $($ram.FormFactor)" }
	}
	$memoryType = switch ($ram.SMBIOSMemoryType) {
		20 { "DDR" }
		21 { "DDR2" }
		24 { "DDR3" }
		26 { "DDR4" }
		34 { "DDR5" }
		Default { "Memory Type $($ram.FormFactor)" }
	}
	Write-Color "`t`t{{Cyan:[>]}} $($ram.Manufacturer) $($ram.PartNumber) (SN: $($ram.SerialNumber)), $moduleType $memoryType $([math]::Round($ram.Capacity / 1GB, 1))GB $($ram.ConfiguredClockSpeed)/$($ram.Speed)MHz ($([math]::Round($ram.ConfiguredVoltage / 1000, 1))v)"
}
# ======== Storage Devices
Write-Color "`t{{Cyan:[+] Storage devices}} ($($CIMDisks.Count)):"
foreach ($disk in $CIMDisks) {
	Write-Color "`t`t{{Cyan:[>]}} $($disk.Index): $($disk.InterfaceType) $($disk.MediaType) $($disk.Model) (SN: $($disk.SerialNumber)), $([math]::Round($disk.Size / 1GB, 1))GB $($disk.BytesPerSector)b sector ($($disk.Partitions) partitions), Firmware $($disk.FirmwareRevision)"
}
# ======== PNP Devices
# PrintQueue
# Network Adapters

# === PNPClass
# AudioEndpoint
# Battery
# Bluetooth
# Camera
# Computer
# DiskDrive
# Display
# Firmware
# HIDClass
# Keyboard
# MEDIA
# Monitor
# Mouse
# Net
# Ports
# Printer
# PrintQueue
# Processor
# SCSIAdapter
# SecurityDevices
# SmartCardFilter
# SmartCardReader
# SoftwareComponent
# SoftwareDevice
# System
# USB
# USBDevice
# Volume

# === PNPDeviceID


# ============================================================================
# SYSINFO
# ============================================================================
Write-Color "{{Magenta:[*] SysInfo}}:"
$kernel = [System.Environment]::OSVersion.Platform
$CIMWin32OS = Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,OSArchitecture,LastBootUpTime -ErrorAction Stop
$language = [System.Globalization.CultureInfo]::InstalledUICulture.Name
$winNtVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
# ======== Windows Name
$winName = "$($winNtVersion.Name ?? $winNtVersion.ProductName) $($winNtVersion.DisplayVersion) $($language)"
Write-Color "`t{{Cyan:[+] Operating system}}: $winName"
# ======== Windows Version
$winVer = "$($kernel) $($CIMWin32OS.Version) $($CIMWin32OS.OSArchitecture)"
Write-Color "`t{{Cyan:[+] OS version}}: $winVer"
# ======== Owner
$winOwner = "$($winNtVersion.RegisteredOwner) ($($winNtVersion.RegisteredOrganization))"
Write-Color "`t{{Cyan:[+] Owner}}: $winOwner"
# ======== Initialization Time
Write-Color "`t{{Cyan:[+] Initialized}}: $($CIMWin32OS.LastBootUpTime)"
# ======== Hotfixes
# Non security updates
$updates = (Get-HotFix | Where-Object {$_.Description -notlike '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
Write-Color "`t{{Cyan:[+] Hotfixes}}: $updates"
# Security updates
$securityUpdates = (Get-HotFix | Where-Object {$_.Description -like '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
Write-Color "`t{{Cyan:[+] Security hotfixes}}: $securityUpdates"

# ============================================================================
# SECURITY STATE
# ============================================================================
Write-Color "{{Magenta:[*] Security State}}:"
$Lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
# $avList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -Property displayName -ErrorAction Stop
# Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -Property displayName -ErrorAction Stop
# Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction Stop
# ======== Virtual Environment
# Pattern for virtual environment indicators
$indicators = @( "VirtualBox", "innotek GmbH", "VBOX", "VMware", "KVM", "QEMU", "Bochs", "Parallels", "Xen", "Bhyve", "Virtual Machine" )
$pattern = ($indicators | ForEach-Object { [regex]::Escape($_) }) -join '|'
# Targeted properties
$properties = @( $CIMWin32.Model, $CIMWin32.Manufacturer, $CIMWinBIOS.Version, $CIMWinBIOS.SerialNumber, $CIMWinBIOS.SMBIOSBIOSVersion, $CIMWin32Board.Manufacturer, $CIMWin32Board.Product, $CIMWin32Board.SerialNumber )
# Iterate properties
$isVirtual = $false
foreach ($p in $properties) {
	if ([string]::IsNullOrWhiteSpace($p)) { continue } # Ignore empty property
	if ($p -match $pattern) { $isVirtual = $true } # Perform case insensitive match
}
Write-Color ($isVirtual ? "`t{{Cyan:[+] Virtual Environment}} {{Green:detected}}" : "`t{{Cyan:[+] Virtual Environment}} {{Red:absent}}")
# ======== Secure Boot
# ADMIN $CIMWin32TPM = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
$secureBoot = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction Stop).UEFISecureBootEnabled
Write-Color ($secureBoot ? "`t{{Cyan:[+] Secure Boot}} {{Green:enabled}}" : "`t{{Cyan:[+] Secure Boot}} {{Red:disabled}}")
# ======== LSA Protection
# $Lsa
# ======== Credentials Guard
# ======== Av Information


# ============================================================================
# NETWORK
# ============================================================================
Write-Color "{{Magenta:[*] Network}}:"
# ======== Hostname
$hostname = [System.Net.Dns]::GetHostName()
$time = [System.DateTime]::UtcNow.ToString("s")
Write-Color "`t{{Cyan:[+]}} $($hostname) - $($time)"
# ======== Interfaces 
# ======== Seatbelt arp tables
# ======== Shares
# ======== Known hosts
# ======== IPv4/IPv6 listening ports and associated process
# TCP
# UDP
# ======== Firewall rules
# ======== DNS cache

# ============================================================================
# IDENTITIES
# ============================================================================
Write-Color "{{Magenta:[*] Identities}}:"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
# ======== Current user
Write-Color "`t{{Cyan:[+] Identity}}: $($identity.Name) ($($identity.User.Value))"
# ======== Authentication type
Write-Color "`t{{Cyan:[+] AuthN type}}: $($identity.AuthenticationType)"
# ======== Privileges
$isAdmin = [bool]($identity.Groups -match 'S-1-5-32-544')
# ======== Current groups (SID)
# ======== Other users
# hostname\username (SID) IsDisabled? IsAdmin?
# groups (SID)
# Last logon time

# ============================================================================
# DOMAIN
# ============================================================================
Write-Color "{{Magenta:[*] Domain}}:"
# [System.DirectoryServices.ActiveDirectory.Domain]
# $domain = try {[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { $null }
# ======== Domain
# name
# time
# ======== Domain Controllers
# DC
# kerberos / auth server

# ============================================================================
# RESOURCES
# ============================================================================
Write-Color "{{Magenta:[*] Resources}}:"
# ====== Services (powersploit privesc get modifiable service)
# running services with name,startmode,serviceaccount,permissions,pathname

# ====== Tasks
# scheduled tasks with hostname\taskname, trigger, action (permissions)

# ============================================================================
# FILES
# ============================================================================
Write-Color "{{Magenta:[*] Files}}:"
# Recieve a target dir, check permissions, list files based on a filetype list, regex match into the files and report back

# ====== Useful Software and Related Files
# ssh
# putty
# browsers
# password managers
# web application
# DBMS

# if (-not (Test-Path $FilePath)) { throw }

# ======== Interesting files
# look for files in userdir
# regex match of interesting findings
# look for permission in interesing dirs

# ============================================================================
# END
# ============================================================================
Write-Color "{{Green:[*]}} Done in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)).$($stopwatch.Elapsed.Milliseconds) seconds"