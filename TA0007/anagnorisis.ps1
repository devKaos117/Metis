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
			https://github.com/samratashok/nishang
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
		# Original and default color
		$originalColor = [Console]::ForegroundColor
		$defaultColor = [ConsoleColor]::White
		# Find pattern
		$pattern = '\{\{(?<color>\w+):(?<text>.*?)\}\}' # {{Color:Text}}
		$patternMatches = [regex]::Matches($Msg, $pattern)
		# Iterate through the message
		$lastIndex = 0
		try {
			foreach ($m in $patternMatches) {
				# Write text before match
				if ($m.Index -gt $lastIndex) {
					[Console]::ForegroundColor = $defaultColor
					[Console]::Write($Msg.Substring($lastIndex, $m.Index - $lastIndex))
				}
				# Extract components
				$color = $m.Groups["color"].Value
				$txt = $m.Groups["text"].Value
				# Validate color
				if (-not ([Enum]::GetNames([ConsoleColor])).Contains($color)) {
					$color = $defaultColor
				}
				# Write message segment
				[Console]::ForegroundColor = $color
				[Console]::Write($txt)
				$lastIndex = $m.Index + $m.Length
			}
			# Remaining text
			if ($lastIndex -lt $Msg.Length) {
				[Console]::ForegroundColor = $defaultColor
				[Console]::Write($Msg.Substring($lastIndex))
			}
			[Console]::WriteLine()
		}
		finally {
			[Console]::ForegroundColor = $originalColor
		}
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
# https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/sample-powershell-script-to-query-smbios-locally
Write-Color "{{DarkBlue:[*] Platform}}:"
$CIMWin32CS = Get-CimInstance -ClassName Win32_ComputerSystem -Property Model, Manufacturer -ErrorAction SilentlyContinue
$CIMWin32BIOS = Get-CimInstance -ClassName Win32_Bios -Property Version, SerialNumber, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion -ErrorAction SilentlyContinue
$CIMWin32Board = Get-CimInstance -ClassName Win32_BaseBoard -Property Manufacturer, Product, SerialNumber -ErrorAction SilentlyContinue
$CIMWin32CPU = Get-CimInstance -ClassName Win32_Processor -Property DeviceID,Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,ThreadCount -ErrorAction SilentlyContinue
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
# MotherBoard UUID: (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
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
				$txt += " ($($cpu.Manufacturer))"
				Write-Color $txt
			}
		} else {
			Write-Color "`t{{Yellow:[-] CPUs}}: No CPUs identified"
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
		} else {
			Write-Color "`t{{Yellow:[-] GPUs}}: No GPUs identified"
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
		} else {
			Write-Color "`t{{Yellow:[-] RAM modules}}: No RAM modules identified"
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
		} else {
			Write-Color "`t{{Yellow:[-] Storage devices}}: No disks identified"
		}
	}
} -Arguments @{ Disks = $CIMWin32Disks }
# ================ PnP Devices
$CIMWin32PnP = Get-CimInstance -ClassName Win32_PnPEntity -Property Name,Status,PNPDeviceID,Manufacturer,PNPClass,Present,Service -ErrorAction SilentlyContinue
Invoke-SafeBlock -BlockName "PnPDevs" -ScriptBlock {
	param($Devices)
	process{
		if ($Devices.Count -gt 0) {
			$classes = @(
				"PrintQueue",			#
				"SecurityDevices",		#
				"SmartCardReader"		#
			)
			$orderedDevs = $Devices | Sort-Object -Property PNPClass | Where-Object { $_.PNPClass -in $classes }
			if ($orderedDevs.Count -gt 0) {
				Write-Color "`t{{Cyan:[+] PnP devices}} ($($orderedDevs.Count)):"
				foreach ($dev in $orderedDevs) {
					$txt = "`t`t{{Cyan:[>] $($dev.PNPClass)}}:"
					$txt += " $($dev.Manufacturer) $($dev.Name)"
					if ($dev.Present) {
						$txt += " (Present)"
					} else {
						$txt += " (Absent)"
					}
					$txt += " (Status: $($dev.Status))"
					$txt += "`n`t`t`tID: $($dev.PNPDeviceID)"
					$txt += "`n`t`t`tService: $($dev.Service)"
					Write-Color $txt
				}
			} else {
				Write-Color "`t{{Yellow:[-] PnP devices}}: No interesting device was found"
			}
		} else {
			Write-Color "`t{{Yellow:[-] PnP devices}}: No device was found"
		}
	}
} -Arguments @{ Devices = $CIMWin32PnP }

# ============================================================================
# SYSINFO
# ============================================================================
Write-Color "{{DarkBlue:[*] SysInfo}}:"
$OSPlatform = [System.Environment]::OSVersion.Platform
$CIMWin32OS = Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,OSArchitecture,LastBootUpTime -ErrorAction SilentlyContinue
$language = [System.Globalization.CultureInfo]::InstalledUICulture.Name
$winNtVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$hotfixes = ([wmisearcher]"SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering").Get()
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
		if (-not [System.String]::IsNullOrWhiteSpace($winVer.RegisteredOwner)) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Owner}}: $($winVer.RegisteredOwner)"

		if (-not [System.String]::IsNullOrWhiteSpace($winVer.RegisteredOrganization)) {
			$txt += " ($($winVer.RegisteredOrganization))"
		}

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
# ================ Crypt
$CryptGuid = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", $null)
Invoke-SafeBlock -BlockName "CryptGuid" -ScriptBlock {
	param($Guid)
	process{
		# Ensure needed variables
		if ($null -eq $Guid) {
			throw "Failed to fetch data"
		}

		$txt = "`t{{Cyan:[+] Cryptographic GUID}}: $($Guid)"
		Write-Color $txt
	}
} -Arguments @{ Guid = $CryptGuid }

# ============================================================================
# SECURITY STATE
# ============================================================================
Write-Color "{{DarkBlue:[*] Security State}}:"
# ADMIN $CIMWin32TPM = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm
$secureBoot = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", $null)
$LsaPpl = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "IsPplAutoEnabled", $null) # Review method, it is not reliable
$LsaPid = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LsaPid", $null)
$devGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -Property SecurityServicesConfigured,SecurityServicesRunning,VirtualizationBasedSecurityStatus
$lsaIsoProcess = [System.Diagnostics.Process]::GetProcessesByName("LsaIso")
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
Invoke-SafeBlock -BlockName "Lsa" -ScriptBlock {
	param($LsaPpl, $LsaPid)
	process{
		# Ensure needed variables
		if ($null -eq $LsaPpl) {
			throw "Failed to fetch data"
		}

		if ($LsaPpl) {
			$txt = "`t{{Cyan:[+] LSA Protection}}: {{Green:enabled}}"
		} else {
			$txt = "`t{{Cyan:[-] LSA Protection}}: {{Yellow:disabled}}"
		}

		if ($LsaPid -is [int] -and $LsaPid -gt 0) {
			$txt += " (PID: $($LsaPid))"
		}
		Write-Color $txt
	}
} -Arguments @{ LsaPpl = $LsaPpl; LsaPid = $LsaPid }
# ================ VBS
Invoke-SafeBlock -BlockName "VBS" -ScriptBlock {
	param($VBSStatus)
	process {
		# Ensure needed variables
		if ($null -eq $VBSStatus) {
			throw "Failed to fetch data"
		}

		switch ([int]$VBSStatus) {
			0 { $txt += "`t{{Cyan:[-] VBS}}: {{Red:disabled}}" }
			1 { $txt += "`t{{Cyan:[-] VBS}}: {{Green:enabled}} but {{Red:inactive}}" }
			2 { $txt += "`t{{Cyan:[+] VBS}}: {{Green:enabled}} and {{Green:running}}" }
			Default { $txt += "`t{{Cyan:[+] VBS}}: {{Yellow:unknown}}" }
		}
		Write-Color $txt
	}
} -Arguments @{ VBSStatus = $devGuard.VirtualizationBasedSecurityStatus }
# ================ Credential Guard
Invoke-SafeBlock -BlockName "CredentialGuard" -ScriptBlock {
	param($CredGuard, $LsaIsoPID)
	process {
		# Ensure needed variables
		if ($null -eq $CredGuard) {
			throw "Failed to fetch data"
		}

		switch ($CredGuard) {
			0 { $txt = "`t{{Cyan:[-] Credential Guard}}: {{Red:not configured}}" }
			1 { $txt = "`t{{Cyan:[+] Credential Guard}}: {{Green:configured}}" }
			Default { $txt = "`t{{Cyan:[+] Credential Guard}}: {{Yellow:unknown}}" }
		}

		if ($LsaIsoPID -is [int] -and $LsaIsoPID -gt 0) {
			$txt += " (LSAIso PID: $($LsaIsoPID))"
		}

		Write-Color $txt
	}
} -Arguments @{ CredGuard = $devGuard.SecurityServicesConfigured; LsaIsoPID = $lsaIsoProcess.Id }
# ================ Security Services
Invoke-SafeBlock -BlockName "SecurityServices" -ScriptBlock {
	param($SecurityServices)
	process {
		# Ensure needed variables
		if ($null -eq $SecurityServices) {
			throw "Failed to fetch data"
		}

		switch ($SecurityServices) {
			0 { $txt += "`t{{Cyan:[-] Security Services}}: VBS security service {{Red:inactive}}" }
			1 { $txt += "`t{{Cyan:[+] Security Services}}: Credential Guard {{Green:running}}" }
			2 { $txt += "`t{{Cyan:[+] Security Services}}: Memory integrity/HVCI {{Green:running}}" }
			3 { $txt += "`t{{Cyan:[+] Security Services}}: System Guard Secure Launch {{Green:running}}" }
			4 { $txt += "`t{{Cyan:[+] Security Services}}: SMM firmware measurement {{Green:running}}" }
			Default { $txt += "`t{{Cyan:[+] Security Services}}: {{Yellow:unknown}}" }
		}

		Write-Color $txt
	}
} -Arguments @{ SecurityServices = $devGuard.SecurityServicesRunning }
# ================ Av Information
# Windows Security Center COM API
# implement wscAPI.WSCProductList in C#
# DisplayName, ProductState, SignatureStatus, RemediationPath, IsActive, IsUpToDate, IsHealthy
$antiVirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -Property displayName,productState -ErrorAction SilentlyContinue
Invoke-SafeBlock -BlockName "AvInformation" -ScriptBlock {
	param($Av)
	process{
		# Ensure needed variables
		if ([String]::IsNullOrEmpty($Av.displayName) -or [String]::IsNullOrEmpty($Av.productState)) {
			throw "Failed to fetch data"
		}

		# Convert state to hex
		$hex = [Convert]::ToString($Av.productState, 16).PadLeft(6,'0')
		# Substring(int startIndex, int length)
		$WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2)
		$WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2)

		$RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE)
		{
			"00" {"Disabled"}
			"01" {"Expired"}
			"10" {"Enabled"}
			"11" {"Snoozed"}
			default {"Unknown"}
		}

		$DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS)
		{
			"00" {"Updated"}
			"10" {"Outdated"}
			default {"Unknown"}
		}

		$txt = "`t{{Cyan:[+] Antivirus}}:"
		$txt += " $($Av.displayName)"
		$txt += " ($($RealTimeProtectionStatus)) ($($DefinitionStatus))"
		Write-Color $txt
	}
} -Arguments @{ Av = $antiVirus }
# ============================================================================
# NETWORK
# ============================================================================
Write-Color "{{DarkBlue:[*] Network}}:"
$hostname = [System.Net.Dns]::GetHostName()
$getEpoch = { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
# $netInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
$netInterfaces = Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue
$ARP = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetNeighbor -Property IPAddress
$DNSCache = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_DNSClientCache -Property Data
$proxy = [Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings","AutoConfigURL",$null)
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
# ================ Known hosts
Invoke-SafeBlock -BlockName "KnownHosts" -ScriptBlock {
	param($ARP, $DNS)
	process {
		if (-not $ARP -or -not $DNS) {
			throw "Failed to fetch data"
		}

		<#
			.SYNOPSIS
			.DESCRIPTION
			.PARAMETER None
			.EXAMPLE
			.INPUTS
			.OUTPUTS
				System.Net.IPAddress
			.COMPONENT
				Network
			.LINK
			.NOTES
				Date: August 2026
		#>
		function Normalize-IPAddress {
			[OutputType([System.Net.IPAddress])]
			param(
				[Parameter(Mandatory)]
				[object]$Address
			)
			process {
				# Try to parse the address
				$ip = $null
				if (-not [System.Net.IPAddress]::TryParse([string]$Address, [ref]$ip)) {
					return $null
				}
				$bytes = $ip.GetAddressBytes()
				# Verify if it is a null host
				$nullHost = $true
				for ($i = 0; $i -lt $bytes.Length; $i++) {
					if ($bytes[$i] -ne 0) {
						$nullHost = $false
						break
					}
				}
				if ($nullHost) {
					return $null
				}
				# Resolve map back to IPv4
				if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.IsIPv4MappedToIPv6) {
					return $ip.MapToIPv4()
				}
				# Return [System.Net.IPAddress]
				return $ip
			}
		}

		<#
			.SYNOPSIS
			.DESCRIPTION
			.PARAMETER None
			.EXAMPLE
			.INPUTS
			.OUTPUTS
				System.Net.IPAddress
			.COMPONENT
				Network
			.LINK
			.NOTES
				Date: August 2026
		#>
		function Test-IPInSubnet {
			param(
				[Parameter(Mandatory)]
				[System.Net.IPAddress]$IPAddress,

				[Parameter(Mandatory)]
				[string]$Subnet
			)
			process {
				$parts = $Subnet.Split('/')
				$network = Normalize-IPAddress -Address $parts[0]
				$prefixLength = [int]$parts[1]

				if ($ip.AddressFamily -ne $network.AddressFamily) {
					return $false
				}

				$ipBytes = $ip.GetAddressBytes()
				$networkBytes = $network.GetAddressBytes()
				if ($prefixLength -lt 0 -or $prefixLength -gt ($ipBytes.Length * 8)) {
					throw "Invalid prefix length $prefixLength for address family"
				}

				$fullBytes = [int]([System.Math]::Floor($prefixLength / 8))
				$remainingBits = $prefixLength % 8
				for ($i = 0; $i -lt $fullBytes; $i++) {
					if ($ipBytes[$i] -ne $networkBytes[$i]) {
						return $false
					}
				}

				if ($remainingBits -eq 0) {
					return $true
				}

				$mask = [byte]((0xFF -shl (8 - $remainingBits)) -band 0xFF)
				return (($ipBytes[$fullBytes] -band $mask) -eq ($networkBytes[$fullBytes] -band $mask))
			}
		}

		$knownHosts = New-Object System.Collections.Generic.List[System.Net.IPAddress]
		# Collecting entries from ARP table
		foreach ($entry in $ARP) {
			$ip = Normalize-IPAddress -Address $entry.IPAddress
			if ($null -eq $ip) {
				continue
			}
			if ($knownHosts.Contains($ip)) {
				continue
			}
			$knownHosts.Add($ip)
		}
		# Collecting entries from DNS cache
		foreach ($entry in $DNSCache) {
			if ([System.String]::IsNullOrEmpty($entry.Data)) {
				continue
			}
			$ip = Normalize-IPAddress -Address $entry.Data
			if ($null -eq $ip) {
				continue
			}
			if ($knownHosts.Contains($ip)) {
				continue
			}
			$knownHosts.Add($ip)
		}
		$txt = "`t{{Cyan:[+] Known Hosts:}}"
		$knownHosts = $knownHosts | Sort-Object -Property IPAddressToString # review type casting and sorting behavior
		foreach ($ip in $knownHosts) {
			# Pass on loopback addresses
			if ([System.Net.IPAddress]::IsLoopback($ip)) {
				continue
			}

			$bytes = $ip.GetAddressBytes()
			if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
				# Pass on IPv4 multicast: 224.0.0.0/4
				if ($bytes[0] -ge 224 -and $bytes[0] -le 239) {
					continue
				}

				$internalRanges = @(
					'10.0.0.0/8',
					'172.16.0.0/12',
					'192.168.0.0/16',
					'169.254.0.0/16', # LinkLocal
					'100.64.0.0/10' # CGNAT
				)
			} elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
				# Pass on IPv6 multicast: ff00::/8
				if ($bytes[0] -eq 0xFF) {
					continue
				}

				$internalRanges = @(
					'fc00::/7',
					'fe80::/10' # LinkLocal
				)
			} else {
				continue
			}
			# Test if the address is in the internal subnets
			foreach ($range in $internalRanges) {
				if (Test-IPInSubnet -IPAddress $ip -Subnet $range) {
					try {
						$name = [System.Net.Dns]::GetHostEntry($ip).HostName # review string format and timeout behavior
						$txt += "`n`t`t{{Cyan:[>]}} $($ip) ($($name))"
					}
					catch {
						$txt += "`n`t`t{{Cyan:[>]}} $($ip)"
					}
				}
			}
		}
		Write-Color $txt
	}
} -Arguments @{ ARP = $ARP; DNS = $DNSCache }
# ================ Shares
# ================ Proxy settings
Invoke-SafeBlock -BlockName "Proxy" -ScriptBlock {
	param($Proxy)
	process {
		if ($Proxy) {
			$txt = "`t{{Cyan:[+] Proxy:}} Proxy configured: $($Proxy)"
		} else {
			$txt = "`t{{Cyan:[-] Proxy:}} No proxy configuration detected"
		}
		Write-Color $txt
	}
} -Arguments @{ Proxy = $proxy }
# ================ Firewall rules
# ================ IPv4/IPv6 listening ports and associated process
# TCP
# UDP

# ============================================================================
# BLUETOOTH
# ============================================================================
Write-Color "{{DarkBlue:[*] Bluetooth}}:"
# ================

# ============================================================================
# USB
# ============================================================================
Write-Color "{{DarkBlue:[*] USB}}:"
# ================

# ============================================================================
# IDENTITIES
# ============================================================================
Write-Color "{{DarkBlue:[*] Identities}}:"
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
# $isAdmin = [bool]($identity.Groups -match 'S-1-5-32-544')
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
# ================ Current user
Invoke-SafeBlock -BlockName "CurrentUser" -ScriptBlock {
	param ($Identity, $IsAdmin)
	process {
		if (-not ($Identity)) {
			throw "Failed to fetch data"
		}
		$txt = "`t{{Cyan:[+] Identity}}: $($Identity.Name) ($($Identity.AuthenticationType))"
		if ($Identity.IsSystem) {
			$txt += " ({{Magenta:System}})"
		} elseif ($IsAdmin) {
			$txt += " ({{DarkRed:Admin}})"
		}
		Write-Color $txt
	}
} -Arguments @{ Identity = $principal.Identities; IsAdmin = $isAdmin }
# ================ Privileges
# ================ Current groups (SID)
# ================ Other users
# hostname\username (SID) IsDisabled? IsAdmin?
# groups (SID)
# Last logon time
# ================ Certificates
# Get-ChildItem -Path Cert:\LocalMachine\Root | ? {$_.Subject -like "*Caixa*"} | % {Export-Certificate -Cert $_ -FilePath "$($Env:USERPROFILE)/Downloads/$($_.Subject -replace '[^a-zA-Z0-9]', '_').cer"}

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