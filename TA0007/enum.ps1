# ============================================================================
# WIN_ENUM
# ============================================================================
# ============ Description
# Windows modern enumeration script for a rapid environment contextualization
# ============ Usage
# ./.ps1
# ============ Initializations
$ErrorActionPreference = "Stop"
# ============ Functions
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
# Recieve a target dir, check permissions, list files based on a filetype list, regex match into the files and report back

# ============ Main
$stopwatch = [system.diagnostics.stopwatch]::StartNew()
# ====== Sysinfo
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

# ====== Security state
# Virtualization?
$virt = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, HypervisorPresent
if ($virt.HypervisorPresent) {
	Write-Host "Hypervisor: $($virt.Manufacturer) ($($virt.Model))"
}
# SecureBoot?
# (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").SecureBoot
if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State").UEFISecureBootEnabled) {
	Write-Host "SecureBoot is Enabled"
}
# LSA Protection
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
# Credentials Guard
# Av Information
# $cmd = if ($psv -ge 3) { 'Get-CimInstance' } else { 'Get-WmiObject' }
# $avList = & $cmd -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike 'windows' } | Select-Object -ExpandProperty displayName
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue

# ====== Network
# Network shares
# network ifaces and known hosts
# seatbelt arp tables
# current ipv4/ipv6 tcp listening ports and associated process
# current ipv4/ipv6 udp listening ports and associated process
# firewall rules
# dns cache

# ====== Local Groups and Users
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

# ====== Domain
# [System.DirectoryServices.ActiveDirectory.Domain]
# $domain = try {[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { $null }

# ====== Services (powersploit privesc get modifiable service)
# running services with name,startmode,serviceaccount,permissions,pathname

# ====== Tasks
# scheduled tasks with hostname\taskname, trigger, action (permissions)

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

# ====== Final
# elapsed time
Write-Host "Done in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)).$($stopwatch.Elapsed.Milliseconds) seconds"



# DESKTOP-0OOLLC2 - 2026-04-03T06:19:22
# Windows 10 Pro 21H2 en-US (Win32NT 10.0.22000 64-bit)
# Updates: KB5025186,KB5011048,KB5030842,KB5031591,KB5008295
# Security Updates: KB5031358
# Hypervisor: VMware, Inc. (VMware7,1)
# SecureBoot is Enabled
# Logged in with NTLM
# DESKTOP-0OOLLC2\Administrator
# Done in 0.505 seconds