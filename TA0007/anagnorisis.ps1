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
			https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
			https://github.com/411Hall/JAWS
			https://github.com/GhostPack/Seatbelt
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
# Notes:
#	Get-ItemProperty -> [Microsoft.Win32.Registry]
#	Get-CimInstance -> [System.Management.ManagementObjectSearcher]

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
		System.Void
	.COMPONENT
		Utilities
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

<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER None
	.EXAMPLE
	.INPUTS
	.OUTPUTS
		System.Void
	.COMPONENT
		Utilities
	.LINK
	.NOTES
		Date: June 2026
#>
function Invoke-SafeBlock {
	param(
		[Parameter(Mandatory)]
		[string]$BlockName,

		[Parameter(Mandatory)]
		[hashtable]$Arguments,

		[Parameter(Mandatory)]
		[scriptblock]$ScriptBlock
	)
	try {
		& $ScriptBlock @Arguments
	} catch {
		Write-Color "`t{{Red:[!] Error}}: Failed during execution of $($BlockName): $_"
	}
}

# ============================================================================
# PLATFORM
# ============================================================================
Write-Color "{{DarkBlue:[*] Platform}}:"
$CIMWin32CS = Get-CimInstance -ClassName Win32_ComputerSystem -Property Model, Manufacturer -ErrorAction SilentlyContinue
$CIMWin32BIOS = Get-CimInstance -ClassName Win32_Bios -Property Version, SerialNumber, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion -ErrorAction SilentlyContinue
$CIMWin32Board = Get-CimInstance -ClassName Win32_BaseBoard -Property Manufacturer, Product, SerialNumber -ErrorAction SilentlyContinue
$CIMWin32CPU = Get-CimInstance -ClassName Win32_Processor -Property  DeviceID,Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,ThreadCount -ErrorAction SilentlyContinue
$CIMWin32GPU = Get-CimInstance -ClassName Win32_VideoController -Property DeviceID,Status,Name,AdapterRAM,AdapterCompatibility,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentNumberOfColors,CurrentRefreshRate,CurrentBitsPerPixel -ErrorAction SilentlyContinue
$CIMWin32RAM = Get-CimInstance -ClassName Win32_PhysicalMemory -Property Manufacturer,PartNumber,SerialNumber,FormFactor,SMBIOSMemoryType,ConfiguredVoltage,Capacity,ConfiguredClockSpeed,Speed -ErrorAction SilentlyContinue
$CIMWin32Disks = Get-CimInstance -ClassName Win32_DiskDrive -Property Index,InterfaceType,MediaType,Model,Size,BytesPerSector,Partitions,FirmwareRevision,SerialNumber -ErrorAction SilentlyContinue
$CIMWin32PnP = Get-CimInstance -ClassName Win32_PnPEntity -Property Status,Present,PNPDeviceID,PNPClass,Name,Description -ErrorAction SilentlyContinue
# ================ Device name
Invoke-SafeBlock -BlockName "DeviceName" -ScriptBlock {
	param ($CompSys, $BIOS)
	process {
		# Ensure needed variables
		if (-not ($CompSys.Manufacturer -and $CompSys.Model -and $BIOS.SerialNumber)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Device}}:"
		$txt += " $($CompSys.Manufacturer) $($CompSys.Model) $($BIOS.SerialNumber)"
		Write-Color $txt
	}
} -Arguments @{ CompSys = $CIMWin32CS; BIOS = $CIMWin32BIOS }
# ================ BIOS information
Invoke-SafeBlock -BlockName "BIOS" -ScriptBlock {
	param ($BIOS)
	process {
		# Ensure needed variables
		if (-not ($BIOS.Version -and $BIOS.SMBIOSBIOSVersion -and $BIOS.SMBIOSMajorVersion -and $BIOS.SMBIOSMinorVersion)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] BIOS}}:"
		$txt += " $($BIOS.Version) ($($BIOS.SMBIOSBIOSVersion))"
		$txt += " (SMBIOS $($BIOS.SMBIOSMajorVersion).$($BIOS.SMBIOSMinorVersion))"
		Write-Color $txt
	}
} -Arguments @{ BIOS = $CIMWin32BIOS }
# ================ Motherboard
Invoke-SafeBlock -BlockName "Motherboard" -ScriptBlock {
	param($Motherboard)
	process{
		# Ensure needed variables
		if (-not ($Motherboard.Manufacturer -and $Motherboard.Product -and $Motherboard.SerialNumber)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Motherboard}}:"
		$txt += " $($Motherboard.Manufacturer) $($Motherboard.Product) (SN: $($Motherboard.SerialNumber))"
		Write-Color $txt
	}
} -Arguments @{ Motherboard = $CIMWin32Board }
# ================ CPU
Invoke-SafeBlock -BlockName "CPU" -ScriptBlock {
	param($CPUs)
	process{
		if ($CPUs.Count -gt 0) {
			Write-Color "`t{{Cyan:[+] CPUs}} ($($CPUs.Count)):"
			foreach ($cpu in $CPUs) {
				$txt = "`t`t{{Cyan:[>]}}"
				$txt += " $($cpu.DeviceID): $($cpu.Name)"
				$txt += " ($($cpu.NumberOfCores)/$($cpu.NumberOfLogicalProcessors) $($cpu.ThreadCount)T)"
				$txt +=  " ($($cpu.Manufacturer))"
				Write-Color $txt
			}
		}
	}
} -Arguments @{ CPUs = $CIMWin32CPU }
# ================ GPU
Invoke-SafeBlock -BlockName "GPU" -ScriptBlock {
	param($GPUs)
	process{
		if ($GPUs.Count -gt 0) {
			Write-Color "`t{{Cyan:[+] GPUs}} ($($GPUs.Count)):"
			foreach ($gpu in $GPUs) {
				$txt = "`t`t{{Cyan:[>]}}"
				$txt += " $($gpu.DeviceID) ($($gpu.status)):"
				$txt += " $($gpu.Name) ($([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB)"
				$txt += "`n`t`t`tDriver: $($gpu.AdapterCompatibility) $($gpu.DriverVersion)"
				$txt += "`n`t`t`tVideo: $($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution)x$($gpu.CurrentNumberOfColors) ($($gpu.CurrentRefreshRate)Hz $($gpu.CurrentBitsPerPixel)b)"
				Write-Color $txt
			}
		}
	}
} -Arguments @{ GPUs = $CIMWin32GPU }
# ================ RAM
Invoke-SafeBlock -BlockName "RAM" -ScriptBlock {
	param($RAMModules)
	process{
		if ($RAMModules.Count -gt 0) {
			Write-Color "`t{{Cyan:[+] RAM modules}} ($($RAMModules.Count)):"
			foreach ($ram in $RAMModules) {
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

				$txt = "`t`t{{Cyan:[>]}}"
				$txt += " $($ram.Manufacturer) $($ram.PartNumber) (SN: $($ram.SerialNumber))"
				$txt += "`n`t`t`t$moduleType $memoryType $([math]::Round($ram.Capacity / 1GB, 1))GB $($ram.ConfiguredClockSpeed)/$($ram.Speed)MHz ($([math]::Round($ram.ConfiguredVoltage / 1000, 1))v)"
				Write-Color $txt
			}
		}
	}
} -Arguments @{ RAMModules = $CIMWin32RAM }
# ================ Storage Devices
Invoke-SafeBlock -BlockName "StorageDevice" -ScriptBlock {
	param($Disks)
	process{
		if ($Disks.Count -gt 0) {
			Write-Color "`t{{Cyan:[+] Storage devices}} ($($Disks.Count)):"
			foreach ($disk in $Disks) {
				$txt = "`t`t{{Cyan:[>]}}"
				$txt += " $($disk.Index): $($disk.InterfaceType) $($disk.MediaType) $($disk.Model) (SN: $($disk.SerialNumber))"
				$txt += "`n`t`t`t$([math]::Round($disk.Size / 1GB, 1))GB $($disk.BytesPerSector)b sector ($($disk.Partitions) partitions)"
				$txt += "`n`t`t`tFirmware $($disk.FirmwareRevision)"
				Write-Color $txt
			}
		}
	}
} -Arguments @{ Disks = $CIMWin32Disks }
# ================ PnP Devices
Invoke-SafeBlock -BlockName "PnPDevs" -ScriptBlock {
	param()
	process{
	}
} -Arguments @{}
# PrintQueue

# === PNPClass
# Bluetooth
# SCSIAdapter
# SecurityDevices
# SmartCardReader
# System
# USB

# ============================================================================
# SYSINFO
# ============================================================================
Write-Color "{{DarkBlue:[*] SysInfo}}:"
$OSPlatform = [System.Environment]::OSVersion.Platform
$CIMWin32OS = Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,OSArchitecture,LastBootUpTime -ErrorAction SilentlyContinue
$language = [System.Globalization.CultureInfo]::InstalledUICulture.Name
$winNtVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
# $hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue
# $hotfixes = ([wmisearcher]"SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering").Get()
$hotfixes = Get-HotFix
# ================ Windows Name
Invoke-SafeBlock -BlockName "WinName" -ScriptBlock {
	param($winVer, $lang)
	process{
		# Ensure needed variables
		if (-not (($winVer.Name -or $winVer.ProductName) -and $winVer.DisplayVersion -and $lang)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Operating system}}:"
		if ($winVer.Name) {
			$txt += " $($winVer.Name)"
		} else {
			$txt += " $($winVer.ProductName)"
		}
		$txt += " $($winVer.DisplayVersion) $($lang)"
		Write-Color $txt
	}
} -Arguments @{ winVer = $winNtVersion; lang = $language }
# ================ Windows Version
Invoke-SafeBlock -BlockName "WinVer" -ScriptBlock {
	param($Kernel, $OS)
	process{
		# Ensure needed variables
		if (-not ($Kernel -and $OS.Version -and $OS.OSArchitecture)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] OS version}}:"
		$txt += " $($Kernel) $($OS.Version) $($OS.OSArchitecture)"
		Write-Color $txt
	}
} -Arguments @{ Kernel = $OSPlatform; OS = $CIMWin32OS }
# ================ Owner
Invoke-SafeBlock -BlockName "WinOwner" -ScriptBlock {
	param($winVer)
	process{
		# Ensure needed variables
		if (-not ($winVer.RegisteredOwner -and $winVer.RegisteredOrganization)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Owner}}:"
		$txt += " $($winVer.RegisteredOwner) ($($winVer.RegisteredOrganization))"
		Write-Color $txt
	}
} -Arguments @{ winVer = $winNtVersion }
# ================ Initialization Time
Invoke-SafeBlock -BlockName "InitTime" -ScriptBlock {
	param($OS)
	process{
		# Ensure needed variables
		if (-not ($OS.LastBootUpTime)) {
			throw "Failed to fetch data"
		}

		Write-Color "`t{{Cyan:[+] Initialized}}: $($OS.LastBootUpTime)"
	}
} -Arguments @{ OS = $CIMWin32OS }
# ================ Hotfixes
Invoke-SafeBlock -BlockName "Hotfixes" -ScriptBlock {
	param($KBs)
	process{
		$commonUpdates = ($KBs | Where-Object {$_.Description -notlike '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
		if ($commonUpdates) {
			Write-Color "`t{{Cyan:[+] Hotfixes}}: $commonUpdates"
		} else {
			Write-Color "`t{{Yellow:[-] Hotfixes}}: No KB found"
		}
	}
} -Arguments @{ KBs = $hotfixes }
# ================ Security Hotfixes
Invoke-SafeBlock -BlockName "SecurityHotfixes" -ScriptBlock {
	param($KBs)
	process{
		$securityUpdates = ($KBs | Where-Object {$_.Description -like '*security*'} | Sort-Object -Descending -Property InstalledOn,HotFixID -ErrorAction SilentlyContinue).HotFixID -join ","
		if ($securityUpdates) {
			Write-Color "`t{{Cyan:[+] Security hotfixes}}: $securityUpdates"
		} else {
			Write-Color "`t{{Yellow:[-] Security hotfixes}}: No KB found"
		}
	}
} -Arguments @{ KBs = $hotfixes }

# ============================================================================
# SECURITY STATE
# ============================================================================
Write-Color "{{DarkBlue:[*] Security State}}:"
# ADMIN $CIMWin32TPM = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm
$secureBoot = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", $null)
$LSA = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
# ADMIN Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions'
$antiVirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -Property displayName -ErrorAction SilentlyContinue
# ================ Virtual Environment
Invoke-SafeBlock -BlockName "VirtEnv" -ScriptBlock {
	param($CompSys, $BIOS, $Motherboard)
	process{
		# Targeted properties
		$properties = @( $CompSys.Model, $CompSys.Manufacturer, $BIOS.Version, $BIOS.SerialNumber, $BIOS.SMBIOSBIOSVersion, $Motherboard.Manufacturer, $Motherboard.Product, $Motherboard.SerialNumber )
		# Ensure needed variables
		if ($null -in $properties -or $properties -contains '') {
			throw "Failed to fetch data"
		}
		# Pattern for virtual environment indicators
		$indicators = @( "VirtualBox", "innotek GmbH", "VBOX", "VMware", "KVM", "QEMU", "Bochs", "Parallels", "Xen", "Bhyve", "Virtual Machine" )
		$pattern = ($indicators | ForEach-Object { [regex]::Escape($_) }) -join '|'
		# Perform case insensitive match
		$isVirtual = [bool]($properties -match $pattern)

		if ($isVirtual) {
			$txt = "`t{{Cyan:[+] Virtual Environment}} {{Yellow:detected}}"
		} else {
			$txt = "`t{{Cyan:[-] Virtual Environment}} absent"
		}
		Write-Color $txt
	}
} -Arguments @{CompSys = $CIMWin32CS; BIOS = $CIMWin32BIOS; Motherboard = $CIMWin32Board}
# ================ Secure Boot
Invoke-SafeBlock -BlockName "SecureBoot" -ScriptBlock {
	param($SecureBoot)
	process{
		# Ensure needed variables
		if ($null -eq $secureBoot) {
			throw "Failed to fetch data"
		}

		if ($secureBoot) {
			$txt = "`t{{Cyan:[+] Secure Boot}} {{Green:enabled}}"
		} else {
			$txt = "`t{{Cyan:[-] Secure Boot}} {{Yellow:disabled}}"
		}
		Write-Color $txt
	}
} -Arguments @{ SecureBoot = $secureBoot }
# ================ LSA Protection
# $Lsa
# ================ Credentials Guard
# ================ Av Information


# ============================================================================
# NETWORK
# ============================================================================
Write-Color "{{DarkBlue:[*] Network}}:"
$hostname = [System.Net.Dns]::GetHostName()
$getEpoch = { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
# $netInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
$netInterfaces = Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue
# ================ Hostname
Invoke-SafeBlock -BlockName "Hostname" -ScriptBlock {
	param ($Hostname)
	process {
		if (-not ($Hostname)) {
			throw "Failed to fetch data"
		}

		Write-Color "`t{{Cyan:[+] Hostname:}} $($Hostname)"
	}
} -Arguments @{ Hostname = $hostname }
# ================ Time
Invoke-SafeBlock -BlockName "Time" -ScriptBlock {
	param ($Epoch)
	process {
		if (-not ($Epoch)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Time:}}"
		$txt += " $([DateTimeOffset]::FromUnixTimeSeconds($Epoch).ToLocalTime().ToString("s")) ($Epoch)"
		Write-Color $txt
	}
} -Arguments @{ Epoch = (& $getEpoch) }
# ================ Interfaces
Invoke-SafeBlock -BlockName "Interfaces" -ScriptBlock {
	param($Interfaces)
	process {
		Write-Color "`t{{Cyan:[+] Network Interfaces:}}"
		foreach ($interface in $Interfaces) {
			$txt = "`t`t{{Cyan:[>]}}"
			$txt += " $($interface.InterfaceAlias) ($($interface.InterfaceDescription)):"
			$txt += "`n`t`t`tMAC: $($interface.NetAdapter.LinkLayerAddress) (MTU $($interface.NetIPv4Interface.NlMTU))"
			if ($interface.IPv4Address.Count -gt 0) {
				$txt += "`n`t`t`tIPv4: (DHCP $($interface.NetIPv4Interface.DHCP)) $(($interface.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ",")"
			}
			if ($interface.DNSServer.ServerAddresses.Count -gt 0) {
				$txt += "`n`t`t`tDNS Servers: $(($interface.DNSServer.ServerAddresses -join ","))"
			}
			# Include IPv6
			Write-Color $txt
		}
	}
} -Arguments @{ Interfaces = $netInterfaces }
# ================ Seatbelt arp tables
# ================ Shares
# ================ Known hosts
# ================ IPv4/IPv6 listening ports and associated process
# TCP
# UDP
# ================ Firewall rules
# ================ DNS cache

# ============================================================================
# IDENTITIES
# ============================================================================
Write-Color "{{DarkBlue:[*] Identities}}:"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
# ================ Current user
Invoke-SafeBlock -BlockName "CurrentUser" -ScriptBlock {
	param ($Identity)
	process {
		if (-not ($Identity)) {
			throw "Failed to fetch data"
		}

		Write-Color "`t{{Cyan:[+] Identity}}: $($Identity.Name) ($($Identity.User.Value))"
	}
} -Arguments @{ Identity = $identity }
# ================ Authentication type
Invoke-SafeBlock -BlockName "AuthenticationType" -ScriptBlock {
	param ($Identity)
	process {
		if (-not ($Identity)) {
			throw "Failed to fetch data"
		}

		Write-Color "`t{{Cyan:[+] AuthN type}}: $($Identity.AuthenticationType)"
	}
} -Arguments @{ Identity = $identity }
# ================ Privileges
# $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
# $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$isAdmin = [bool]($identity.Groups -match 'S-1-5-32-544')
# ================ Current groups (SID)
# ================ Other users
# hostname\username (SID) IsDisabled? IsAdmin?
# groups (SID)
# Last logon time

# ============================================================================
# DOMAIN
# ============================================================================
Write-Color "{{DarkBlue:[*] Domain}}:"
# [System.DirectoryServices.ActiveDirectory.Domain]
# $domain = try {[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { $null }
# ================ Domain
# name
# time
# ================ Domain Controllers
# Global Catalog
# kerberos / PDC owner
# DCs
# ================ Identities
# Admin users and groups
# adminCount attribute objects
# ================ Resources
# SYSVOL
# GPOs
# Services
# Shared folders
# ================ ADSI
# $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
# $adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
# 	$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
# 	$output = $output +  "----------`r`n"
# 	$output = $output +  "Username: " + $_.Name +  "`r`n"
# 	$output = $output +  "Groups:   "  + $groups +  "`r`n"
# }

# ============================================================================
# RESOURCES
# ============================================================================
Write-Color "{{DarkBlue:[*] Resources}}:"
# ====== Services (powersploit privesc get modifiable service)
# running services with name,startmode,serviceaccount,permissions,pathname

# ====== Tasks
# scheduled tasks with hostname\taskname, trigger, action (permissions)

# ====== DLLs

# ============================================================================
# FILES
# ============================================================================
Write-Color "{{DarkBlue:[*] Files}}:"
# Recieve a target dir, check permissions, list files based on a filetype list, regex match into the files and report back
# ====== Useful Software and Related Files
# (get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096)
# ssh
# putty
# browsers
# password managers
# web application
# DBMS

# $files = get-childitem C:\
# foreach ($file in $files){
# 	try {
# 		$output = $output +  (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
# 		where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
# 		ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
# 	} catch {
# 		$output = $output +   "`nFailed to read more files`r`n"
# 	}
# }

# $folders = get-childitem C:\
# foreach ($folder in $folders){
# 	try {
# 		$output = $output +  (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
# 		where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
# 		select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
# 	}
# 	catch {
# 		$output = $output +  "`nFailed to read more folders`r`n"
# 	}
# }

# (get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string )
# (get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string)
# (Get-ChildItem 'C:\Users' -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string)

# (cmdkey /list | out-string)

# if (get-itemproperty -path $Winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue) 
#         {
#         if ((get-itemproperty -path $Winlogon -Name AutoAdminLogon).AutoAdminLogon -eq 1) 
#             {
#             $Username = (get-itemproperty -path $Winlogon -Name DefaultUserName).DefaultUsername
#             $output = $output + "The default username is $Username `r`n"
#             $Password = (get-itemproperty -path $Winlogon -Name DefaultPassword).DefaultPassword
#             $output = $output + "The default password is $Password `r`n"
#             $DefaultDomainName = (get-itemproperty -path $Winlogon -Name DefaultDomainName).DefaultDomainName
#             $output = $output + "The default domainname is $DefaultDomainName `r`n"
#             }
#         }
#     $output = $output +  "`r`n"
#     if ($OutputFilename.length -gt 0)
#        {
#         $output | Out-File -FilePath $OutputFileName -encoding utf8
#         }
#     else
#         {
#         clear-host
#         write-output $output
#         }
# }

# if (-not (Test-Path $FilePath)) { throw }

# ================ Interesting files
# look for files in userdir
# regex match of interesting findings
# look for permission in interesing dirs

# ============================================================================
# END
# ============================================================================
Write-Color "{{Green:[*]}} Done in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)).$($stopwatch.Elapsed.Milliseconds) seconds"

if ($Error.Count -gt 0) {
	Write-Color "{{Red:[!] Error Stack}}: The execution throwed $($Error.Count) omitted errors:"
	$Error | Select-Object -Property @{N='Error Message'; E={$_.Exception.Message}}, CategoryInfo, InvocationInfo | Format-Table -Wrap
}