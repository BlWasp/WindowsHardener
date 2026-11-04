<#
.SYNOPSIS
    Interactive hardening of a Windows machine.
.DESCRIPTION
    Windows audit and hardening script, based on the recommendations of the ANSSI, CIS, and Microsoft. For every check, the script:
      1. displays the current state and skips the check if it is already compliant;
      2. tells whether the correction is relevant in the context of this machine
         (domain / Entra ID / standalone, workstation / server, laptop, edition, hardware...);
      3. describes the impact, then asks for confirmation before applying anything.
    Every change is recorded in a rollback journal (rollback.json) that can be replayed with -Restore.
    Some recommendations cannot be automated safely (LAPS, AppLocker, BIOS...): the script then gives guidance.
.PARAMETER ReportOnly
    Only display states and relevance: nothing is asked and nothing is changed.
.PARAMETER Restore
    Path to a rollback.json file written by a previous run: reverts the recorded changes, newest first.
.PARAMETER OutputDirectory
    Folder for the transcript, rollback journal and summary. Default: hardening_<date> next to the script.
.PARAMETER InactivityTimeoutSecs
    Target for the automatic session lock (default 600 seconds, recommendation: 10 minutes or less).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1 -ReportOnly
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1 -Restore .\hardening_20261103_150000\rollback.json
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [string]$Restore,
    [string]$OutputDirectory,
    [ValidateRange(60, 900)]
    [int]$InactivityTimeoutSecs = 600
)

$script:Journal = New-Object System.Collections.Generic.List[object]
$script:Corrections = New-Object System.Collections.Generic.List[object]
$script:Results = New-Object System.Collections.Generic.List[object]
$script:JournalFile = $null
$script:TranscriptFile = $null
$script:OutDir = $null
$script:RebootNeeded = $false
$script:QuitRequested = $false
$script:UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

#region Display helpers

function Write-Title {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Read-Choice {
    param([string]$Prompt, [string[]]$Choices = @('Y', 'N'), [string]$Default)
    $label = ($Choices | ForEach-Object { if ($_ -eq $Default) { "$_*" } else { $_ } }) -join '/'
    while ($true) {
        $answer = Read-Host "$Prompt [$label]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        $answer = $answer.Trim().Substring(0, 1).ToUpper()
        if ($Choices -contains $answer) { return $answer }
    }
}

function New-State {
    param([bool]$Compliant, [string[]]$Details)
    [pscustomobject]@{ Compliant = $Compliant; Details = @($Details) }
}

function New-Relevance {
    param([ValidateSet('Recommended', 'Optional', 'NotRelevant')][string]$Level, [string]$Reason)
    [pscustomobject]@{ Level = $Level; Reason = $Reason }
}

#endregion

#region Rollback journal

function Add-JournalEntry {
    param([hashtable]$Entry)
    $Entry.Timestamp = (Get-Date).ToString('s')
    $script:Journal.Add([pscustomobject]$Entry)
    if ($script:JournalFile) {
        ConvertTo-Json -InputObject $script:Journal.ToArray() -Depth 6 | Set-Content -LiteralPath $script:JournalFile -Encoding UTF8
    }
}

#endregion

#region Registry helpers

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) { return $item.$Name }
    return $null
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $keyExisted = Test-Path -LiteralPath $Path
    $existed = $false
    $oldValue = $null
    $oldType = $null
    if ($keyExisted) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            $existed = $true
            $oldValue = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $oldType = $key.GetValueKind($Name).ToString()
        }
    } else {
        New-Item -Path $Path -Force | Out-Null
    }
    Add-JournalEntry @{ Type = 'Registry'; Path = $Path; Name = $Name; Existed = $existed; OldValue = $oldValue; OldType = $oldType }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -notcontains $Name) { return }
    Add-JournalEntry @{
        Type = 'Registry'; Path = $Path; Name = $Name; Existed = $true
        OldValue = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); OldType = $key.GetValueKind($Name).ToString()
    }
    Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
}

function New-RegSetting {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [switch]$AbsentOk, [scriptblock]$Check)
    @{ Path = $Path; Name = $Name; Value = $Value; Type = $Type; AbsentIsCompliant = [bool]$AbsentOk; Check = $Check }
}

function Test-RegSetting {
    param($Setting, $Current)
    if ($null -eq $Current) { return [bool]$Setting.AbsentIsCompliant }
    # A custom check receives the current value and the setting (target in $s.Value)
    if ($Setting.Check) { return [bool](& $Setting.Check $Current $Setting) }
    return "$Current" -eq "$($Setting.Value)"
}

function Test-RegistrySettings {
    param([object[]]$Settings)
    $allCompliant = $true
    $details = foreach ($s in $Settings) {
        $current = Get-RegValue $s.Path $s.Name
        $ok = Test-RegSetting $s $current
        if (-not $ok) { $allCompliant = $false }
        $shown = if ($null -eq $current) { 'not defined' } else { $current }
        '{0} {1}\{2} = {3} (target: {4})' -f $(if ($ok) { '[OK]' } else { '[KO]' }), $s.Path, $s.Name, $shown, $s.Value
    }
    New-State $allCompliant $details
}

function Set-RegistrySettings {
    param([object[]]$Settings)
    foreach ($s in $Settings) {
        if (-not (Test-RegSetting $s (Get-RegValue $s.Path $s.Name))) {
            Set-RegValue $s.Path $s.Name $s.Value $s.Type
        }
    }
}

#endregion

#region Local security policy helpers (secedit)

function Get-SecurityPolicy {
    $tmp = Join-Path $env:TEMP "secpol_$([guid]::NewGuid()).inf"
    secedit.exe /export /cfg $tmp /areas USER_RIGHTS SECURITYPOLICY /quiet 2>&1 | Out-Null
    if (-not (Test-Path -LiteralPath $tmp)) { throw 'Unable to export the local security policy (secedit /export failed).' }
    $policy = @{}
    $section = $null
    foreach ($line in Get-Content -LiteralPath $tmp) {
        if ($line -match '^\[(.+)\]\s*$') { $section = $Matches[1]; $policy[$section] = @{}; continue }
        if ($section -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $policy[$section][$Matches[1]] = $Matches[2].Trim() }
    }
    Remove-Item -LiteralPath $tmp -Force
    if (-not $policy.ContainsKey('System Access')) { throw 'Unexpected content in the security policy export.' }
    return $policy
}

function Invoke-SecEditConfigure {
    param([string]$Section, [hashtable]$Values, [string]$Area)
    $id = [guid]::NewGuid()
    $inf = Join-Path $env:TEMP "secpol_$id.inf"
    $db = Join-Path $env:TEMP "secpol_$id.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', "[$Section]")
    $lines += $Values.Keys | ForEach-Object { "$_ = $($Values[$_])" }
    Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
    $output = secedit.exe /configure /db $db /cfg $inf /areas $Area /quiet 2>&1
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $inf, $db -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $env:TEMP "secpol_$id.jfm") -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) { Write-Warning "secedit returned exit code $code. $output" }
}

function Set-SecurityPolicy {
    param([string]$Section, [hashtable]$Values, [string]$Area)
    $current = Get-SecurityPolicy
    foreach ($name in $Values.Keys) {
        $old = $null
        if ($current.ContainsKey($Section) -and $current[$Section].ContainsKey($name)) { $old = $current[$Section][$name] }
        Add-JournalEntry @{ Type = 'SecurityPolicy'; Section = $Section; Area = $Area; Name = $name; OldValue = $old }
    }
    Invoke-SecEditConfigure -Section $Section -Values $Values -Area $Area
}

function ConvertTo-SidList {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    foreach ($member in $Value.Split(',')) {
        $member = $member.Trim()
        if (-not $member) { continue }
        if ($member.StartsWith('*')) {
            $member.Substring(1)
        } else {
            try { (New-Object System.Security.Principal.NTAccount($member)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $member }
        }
    }
}

function ConvertTo-AccountName {
    param([string]$Sid)
    try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid }
}

function Get-UserRightSids {
    param([string]$Right)
    $policy = Get-SecurityPolicy
    $value = $null
    if ($policy.ContainsKey('Privilege Rights')) { $value = $policy['Privilege Rights'][$Right] }
    @(ConvertTo-SidList $value)
}

function Set-UserRight {
    param([string]$Right, [string[]]$Sids)
    $value = (@($Sids) | Where-Object { $_ } | ForEach-Object { if ($_ -like 'S-1-*') { "*$_" } else { $_ } }) -join ','
    Set-SecurityPolicy -Section 'Privilege Rights' -Area 'USER_RIGHTS' -Values @{ $Right = $value }
}

function Format-SidList {
    param([string[]]$Sids)
    if (-not $Sids -or $Sids.Count -eq 0) { return '(nobody)' }
    ($Sids | ForEach-Object { "$(ConvertTo-AccountName $_) ($_)" }) -join ', '
}

#endregion

#region Service, feature and account helpers

function ConvertTo-StartTypeName {
    param($Start)
    switch ($Start) { 0 { 'Boot' } 1 { 'System' } 2 { 'Automatic' } 3 { 'Manual' } 4 { 'Disabled' } default { "$Start" } }
}

function Disable-ServiceSafe {
    param([string]$Name)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $regPath)) { return }
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        # Disabling a service whose dependents run or start automatically breaks them (e.g. WinHttpAutoProxySvc -> Wcmsvc, WlanSvc, iphlpsvc)
        $blocking = @($svc.DependentServices | Where-Object { $_.Status -ne 'Stopped' -or "$($_.StartType)" -in 'Boot', 'System', 'Automatic' })
        if ($blocking.Count -gt 0) {
            throw "Service '$Name' not changed: the following services depend on it and are running or start automatically: $(($blocking | ForEach-Object { $_.Name }) -join ', ')."
        }
    }
    $wasRunning = $svc -and $svc.Status -ne 'Stopped'
    if ($wasRunning) { Add-JournalEntry @{ Type = 'ServiceStart'; Name = $Name } }
    Add-JournalEntry @{ Type = 'ServiceStartType'; Name = $Name; OldStart = (Get-RegValue $regPath 'Start') }
    # No registry fallback: when the SCM denies the change, the service is protected and must not be disabled behind its back
    try {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
    } catch {
        throw "Windows refused to change the start type of service '$Name' (protected service): $($_.Exception.Message)"
    }
    if ($wasRunning) {
        try {
            Stop-Service -Name $Name -ErrorAction Stop
        } catch {
            Write-Warning "Service '$Name' is disabled but could not be stopped now; it will stop at the next restart. $($_.Exception.Message)"
        }
    }
}

function Get-AdminMembers {
    try { $members = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop } catch { return }
    foreach ($m in $members) {
        $enabled = $true
        if ("$($m.PrincipalSource)" -eq 'Local') {
            $user = Get-LocalUser -SID $m.SID -ErrorAction SilentlyContinue
            if ($user) { $enabled = $user.Enabled }
        }
        [pscustomobject]@{ Name = $m.Name; Sid = $m.SID.Value; Source = "$($m.PrincipalSource)"; Enabled = [bool]$enabled }
    }
}

function Get-LapsState {
    $details = @()
    $configured = $false
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') -eq 1) {
        $configured = $true
        $details += 'Legacy LAPS is enabled by GPO (AdmPwdEnabled = 1).'
    }
    $roots = [ordered]@{
        'CSP'                 = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
        'GPO'                 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        'local configuration' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
    }
    foreach ($source in $roots.Keys) {
        $backup = Get-RegValue $roots[$source] 'BackupDirectory'
        if ($null -ne $backup) {
            $details += "Windows LAPS configured via $source (BackupDirectory = $($backup); 1 = Entra ID, 2 = Active Directory)."
            if ($backup -in 1, 2) { $configured = $true }
        }
    }
    if ($details.Count -eq 0) { $details = @('Neither legacy LAPS nor Windows LAPS is configured.') }
    [pscustomobject]@{ Configured = $configured; Details = $details }
}

function Get-ServiceExecutablePath {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $exePath = [Environment]::ExpandEnvironmentVariables($PathName.Trim())
    if ($exePath -match '^"([^"]+)"') {
        $exePath = $Matches[1]
    } elseif ($exePath -match '^(.+?\.(exe|com|sys))(\s|$)') {
        $exePath = $Matches[1]
    } else {
        $exePath = ($exePath -split '\s+')[0]
    }
    $exePath = $exePath -replace '^\\\?\?\\', ''
    $exePath = $exePath -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    if ($exePath -match '^system32\\') { $exePath = Join-Path $env:SystemRoot $exePath }
    return $exePath
}

function Get-UnquotedServicePath {
    foreach ($key in Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
        $imagePath = $key.GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames')
        $type = $key.GetValue('Type')
        # 0x10 / 0x20 = Win32 services (drivers are excluded)
        if (-not $imagePath -or -not ($type -band 0x30) -or $imagePath -match '^\s*"') { continue }
        if ($imagePath -notmatch '^(?<exe>.+?\.exe)(?<arguments>(\s.*)?)$') { continue }
        $exe = $Matches['exe']
        $arguments = $Matches['arguments']
        if ($exe -notmatch '\s') { continue }
        [pscustomobject]@{ Name = $key.PSChildName; ImagePath = $imagePath; Exe = $exe; Arguments = $arguments }
    }
}

# Principals that should never have write access to a service executable or its folder
$script:WeakSids = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'Users'; 'S-1-5-4' = 'INTERACTIVE' }
# WriteData, AppendData, Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

function Test-WeakAce {
    param($Ace)
    if ("$($Ace.AccessControlType)" -ne 'Allow') { return $false }
    try { $sid = $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $Ace.IdentityReference.Value }
    return ($script:WeakSids.ContainsKey($sid) -and (([int]$Ace.FileSystemRights -band $script:WriteMask) -ne 0))
}

function Get-WeakServicePermission {
    $checked = @{}
    foreach ($service in Get-CimInstance -ClassName Win32_Service) {
        $exe = Get-ServiceExecutablePath $service.PathName
        if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
        foreach ($target in $exe, (Split-Path -Parent $exe)) {
            if ($checked.ContainsKey($target)) { continue }
            $checked[$target] = $true
            try { $acl = (Get-Item -LiteralPath $target -Force).GetAccessControl('Access') } catch { continue }
            foreach ($ace in $acl.Access) {
                if (Test-WeakAce $ace) {
                    [pscustomobject]@{ Target = $target; Service = $service.Name; Identity = $ace.IdentityReference.Value; Rights = $ace.FileSystemRights; Inherited = $ace.IsInherited }
                }
            }
        }
    }
}

function Get-NetbiosInterface {
    $names = @{}
    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.SettingID) { $names[$_.SettingID.ToUpper()] = $_.Description }
    }
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    foreach ($key in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
        $guid = ($key.PSChildName -replace '^Tcpip_', '').ToUpper()
        [pscustomobject]@{
            Path   = "$root\$($key.PSChildName)"
            Guid   = $guid
            Name   = $(if ($names.ContainsKey($guid)) { $names[$guid] } else { $guid })
            Option = $key.GetValue('NetbiosOptions')
        }
    }
}

function Get-AuditSubcategoryGuid {
    param([string]$CategoryGuid)
    # Subcategory lines are indented; GUIDs make the parsing independent of the OS language
    foreach ($line in (auditpol.exe /list /subcategory:"$CategoryGuid" /v 2>$null)) {
        if ($line -match '^\s{2,}.*(\{[0-9A-Fa-f-]{36}\})\s*$') { $Matches[1].ToUpper() }
    }
}

function Get-AuditPolicySetting {
    # Setting Value: 0 = no auditing, 1 = success, 2 = failure, 3 = success and failure
    $tmp = Join-Path $env:TEMP "auditpol_$([guid]::NewGuid()).csv"
    auditpol.exe /backup /file:"$tmp" 2>&1 | Out-Null
    if (-not (Test-Path -LiteralPath $tmp)) { throw 'Unable to read the audit policy (auditpol /backup failed).' }
    $result = @{}
    Import-Csv -LiteralPath $tmp | Where-Object { $_.'Subcategory GUID' } | ForEach-Object {
        $result[$_.'Subcategory GUID'.ToUpper()] = [int]$_.'Setting Value'
    }
    Remove-Item -LiteralPath $tmp -Force
    return $result
}

function Get-AsrState {
    $state = @{}
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref -and $pref.AttackSurfaceReductionRules_Ids) {
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) { $state[$ids[$i].ToLower()] = [int]$actions[$i] }
    }
    return $state
}

function ConvertFrom-SecureStringToPlain {
    param([securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

#endregion

#region Machine context

function Get-MachineContext {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $apps = @(Get-ItemProperty -Path $script:UninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName })
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $c = [ordered]@{}
    $c.OSCaption = $os.Caption
    $c.Build = [int]$cv.CurrentBuild
    $c.UBR = $cv.UBR
    $c.Edition = $cv.EditionID
    $c.IsWorkstation = $os.ProductType -eq 1
    $c.IsDomainController = $os.ProductType -eq 2
    $c.IsServer = $os.ProductType -ne 1
    $c.IsEnterpriseEdition = $cv.EditionID -match 'Enterprise|Education|Server'
    $c.IsHomeEdition = $cv.EditionID -match '^Core'
    $c.DomainJoined = [bool]$cs.PartOfDomain
    $c.Domain = $cs.Domain
    $c.EntraJoined = [bool](Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue)
    $c.MdmEnrolled = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | Where-Object { $_.GetValue('ProviderID') -eq 'MS DM Server' })
    $c.Managed = $c.DomainJoined -or $c.EntraJoined -or $c.MdmEnrolled
    $c.IsLaptop = ($cs.PCSystemType -eq 2) -or [bool](Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    $c.IsVirtualMachine = ($cs.Model -match 'Virtual|VMware|KVM|QEMU|HVM domU') -or ($cs.Manufacturer -match 'QEMU|Xen|innotek|VMware|Parallels')
    $c.HypervisorApps = @($apps | Where-Object { $_ -match 'VirtualBox|VMware Workstation|VMware Player' } | Select-Object -Unique)
    $c.DeveloperTools = @($apps | Where-Object { $_ -match 'Visual Studio (Community|Professional|Enterprise|Build Tools)|Debugging Tools for Windows|WinDbg|JetBrains|x64dbg' } | Select-Object -Unique)
    $c.VpnApps = @($apps | Where-Object { $_ -match 'OpenVPN|WireGuard|AnyConnect|Cisco Secure Client|GlobalProtect|FortiClient|Pulse Secure|Ivanti Secure Access|NordVPN|ProtonVPN|Check Point Endpoint|Zscaler|Tailscale' } | Select-Object -Unique)
    $c.OneDriveInstalled = [bool]($apps -match 'OneDrive') -or (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe") -or (Test-Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe")
    $c.ChromeInstalled = [bool]($apps -match '^Google Chrome') -or (Test-Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") -or (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")

    $c.TpmPresent = $false
    $c.TpmReady = $false
    try { $tpm = Get-Tpm -ErrorAction Stop; $c.TpmPresent = [bool]$tpm.TpmPresent; $c.TpmReady = [bool]$tpm.TpmReady } catch { }
    try { $c.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $c.SecureBoot = $false }

    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $c.VbsCapable = [bool]($dg -and (@($dg.AvailableSecurityProperties) -contains 1))
    $c.WdacEnforced = [bool]($dg -and $dg.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2)

    $c.DefenderActive = $false
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $c.DefenderActive = [bool]$mp.AntivirusEnabled -and ((-not $mp.AMRunningMode) -or $mp.AMRunningMode -eq 'Normal')
    } catch { }
    $c.ThirdPartyAV = @()
    $c.ThirdPartyFirewall = @()
    if ($c.IsWorkstation) {
        $c.ThirdPartyAV = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
            Where-Object { $_.displayName -notmatch 'Defender' } | ForEach-Object { $_.displayName })
        $c.ThirdPartyFirewall = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction SilentlyContinue |
            ForEach-Object { $_.displayName })
    }

    $c.RdpEnabled = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0
    $c.Shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special } | ForEach-Object { $_.Name })
    $c.PhysicalPrinters = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' -and $_.PortName -notmatch '^(PORTPROMPT:|nul:|SHRFAX:)' } | ForEach-Object { $_.Name })
    $c.IPv6InUse = [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(fe80:|::1$)' -and "$($_.AddressState)" -eq 'Preferred' })
    $c.AppLockerConfigured = $false
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $c.AppLockerConfigured = [bool]($policy.RuleCollections | Where-Object { $_.Count -gt 0 })
    } catch { }
    $c.LapsConfigured = (Get-LapsState).Configured
    $c.BitLockerAvailable = (-not $c.IsHomeEdition) -and [bool](Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)

    $c.CurrentUserSid = $identity.User.Value
    $c.CurrentUserName = $identity.Name
    $c.CurrentUserIsMicrosoftAccount = $false
    try { $c.CurrentUserIsMicrosoftAccount = "$((Get-LocalUser -SID $identity.User -ErrorAction Stop).PrincipalSource)" -eq 'MicrosoftAccount' } catch { }

    $c.DomainSid = $null
    if ($c.DomainJoined) {
        try {
            $rootDse = [ADSI]'LDAP://RootDSE'
            $domainEntry = [ADSI]("LDAP://" + $rootDse.defaultNamingContext[0])
            $c.DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($domainEntry.objectSid[0], 0)).Value
        } catch { }
    }

    if ($c.IsDomainController) { $c.Profile = 'Domain controller' }
    elseif ($c.IsServer -and $c.DomainJoined) { $c.Profile = 'Member server' }
    elseif ($c.IsServer) { $c.Profile = 'Standalone server' }
    elseif ($c.DomainJoined) { $c.Profile = 'Enterprise workstation (Active Directory)' }
    elseif ($c.EntraJoined) { $c.Profile = 'Enterprise workstation (Microsoft Entra ID)' }
    elseif ($c.MdmEnrolled) { $c.Profile = 'Managed workstation (MDM)' }
    else { $c.Profile = 'Personal / standalone workstation' }
    if ($c.IsVirtualMachine) { $c.FormFactor = 'virtual machine' } elseif ($c.IsLaptop) { $c.FormFactor = 'laptop' } else { $c.FormFactor = 'desktop or physical server' }

    [pscustomobject]$c
}

function Show-MachineContext {
    param($Context)
    $yesNo = { param($v) if ($v) { 'yes' } else { 'no' } }
    $list = { param($v) if ($v -and @($v).Count -gt 0) { @($v) -join ', ' } else { 'none' } }
    Write-Host "  Machine profile        : $($Context.Profile), $($Context.FormFactor)" -ForegroundColor Yellow
    Write-Host "  Operating system       : $($Context.OSCaption) (build $($Context.Build).$($Context.UBR), edition $($Context.Edition))"
    Write-Host "  AD domain / Entra / MDM: $(& $yesNo $Context.DomainJoined) ($($Context.Domain)) / $(& $yesNo $Context.EntraJoined) / $(& $yesNo $Context.MdmEnrolled)"
    Write-Host "  TPM / Secure Boot / VBS: $(& $yesNo $Context.TpmPresent) / $(& $yesNo $Context.SecureBoot) / $(& $yesNo $Context.VbsCapable)"
    Write-Host "  Defender active        : $(& $yesNo $Context.DefenderActive) (third-party antivirus: $(& $list $Context.ThirdPartyAV))"
    Write-Host "  RDP enabled            : $(& $yesNo $Context.RdpEnabled)"
    Write-Host "  Non-admin SMB shares   : $(& $list $Context.Shares)"
    Write-Host "  Physical printers      : $(& $list $Context.PhysicalPrinters)"
    Write-Host "  IPv6 in use            : $(& $yesNo $Context.IPv6InUse)"
    Write-Host "  Hypervisors installed  : $(& $list $Context.HypervisorApps)"
    Write-Host "  Developer tools        : $(& $list $Context.DeveloperTools)"
    Write-Host "  Current user           : $($Context.CurrentUserName)$(if ($Context.CurrentUserIsMicrosoftAccount) { ' (Microsoft account)' })"
    Write-Host '  Note: HKCU settings apply to the account running this script.' -ForegroundColor DarkGray
}

#endregion

#region Correction engine

function Add-Correction {
    param([Parameter(Mandatory)][hashtable]$Definition)
    $d = $Definition
    $script:Corrections.Add([pscustomobject]@{
        Id = $d.Id; Category = $d.Category; Title = $d.Title; Reference = $d.Reference; Impact = $d.Impact
        Test = $d.Test; Relevance = $d.Relevance; Apply = $d.Apply; Guidance = $d.Guidance
        Data = $(if ($d.Data) { $d.Data } else { @{} }); RebootRequired = [bool]$d.RebootRequired
    })
}

function Add-RegistryCorrection {
    param([Parameter(Mandatory)][hashtable]$Definition)
    $Definition.Data = @{ Settings = $Definition.Settings }
    $Definition.Test = { param($c) Test-RegistrySettings $c.Data.Settings }
    $Definition.Apply = { param($c) Set-RegistrySettings $c.Data.Settings }
    Add-Correction $Definition
}

function Add-Result {
    param($Correction, [string]$Relevance, [string]$Status)
    $script:Results.Add([pscustomobject]@{
        Id = $Correction.Id; Category = $Correction.Category; Title = $Correction.Title; Relevance = $Relevance; Status = $Status
    })
}

function Invoke-Correction {
    param($c)
    Write-Host ''
    Write-Host ('-' * 78) -ForegroundColor DarkGray
    Write-Host "[$($c.Id)] $($c.Title)" -ForegroundColor White
    $reference = if ($c.Reference) { " | Reference: $($c.Reference)" } else { '' }
    Write-Host "  $($c.Category)$reference" -ForegroundColor DarkGray

    try { $state = & $c.Test $c } catch { $state = New-State $false @("Unable to check the current state: $($_.Exception.Message)") }
    Write-Host '  Current state:'
    foreach ($line in $state.Details) { Write-Host "    $line" }
    if ($state.Compliant) {
        Write-Host '  => Compliant, nothing to do.' -ForegroundColor Green
        Add-Result $c '-' 'Compliant'
        return
    }

    try { $relevance = & $c.Relevance $c } catch { $relevance = New-Relevance Optional "Unable to evaluate the relevance: $($_.Exception.Message)" }
    $color = @{ Recommended = 'Yellow'; Optional = 'Cyan'; NotRelevant = 'DarkGray' }[$relevance.Level]
    Write-Host "  Relevance: $($relevance.Level.ToUpper()) - $($relevance.Reason)" -ForegroundColor $color
    if ($c.Impact) { Write-Host "  Impact   : $($c.Impact)" -ForegroundColor DarkYellow }
    if ($c.RebootRequired -and $c.Apply) { Write-Host '  A restart is required for this change to take full effect.' -ForegroundColor DarkYellow }

    if (-not $c.Apply) {
        Write-Host '  Manual action (not automated):' -ForegroundColor Magenta
        foreach ($line in ($c.Guidance -split "`r?`n")) { Write-Host "    $line" }
        Add-Result $c $relevance.Level 'Manual action'
        return
    }
    if ($ReportOnly) {
        Add-Result $c $relevance.Level 'Not compliant (report only)'
        return
    }

    $default = if ($relevance.Level -eq 'Recommended') { 'Y' } else { 'N' }
    $answer = Read-Choice '  Apply this correction? (Y = yes, N = no, Q = quit)' @('Y', 'N', 'Q') $default
    if ($answer -eq 'Q') { $script:QuitRequested = $true; Add-Result $c $relevance.Level 'Skipped (quit)'; return }
    if ($answer -eq 'N') { Add-Result $c $relevance.Level 'Declined'; return }

    try {
        $null = & $c.Apply $c
        $after = & $c.Test $c
        if ($c.RebootRequired) { $script:RebootNeeded = $true }
        if ($after.Compliant) { $status = 'Applied' }
        elseif ($c.RebootRequired) { $status = 'Applied (pending restart)' }
        else { $status = 'Applied (not verified)' }
        Write-Host "  => $status" -ForegroundColor Green
        Add-Result $c $relevance.Level $status
    } catch {
        Write-Host "  => Failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-Result $c $relevance.Level "Failed: $($_.Exception.Message)"
    }
}

#endregion

#region Restore

function Format-JournalEntry {
    param($Entry)
    switch ($Entry.Type) {
        'Registry'         { "Registry $($Entry.Path)\$($Entry.Name)"; break }
        'ServiceStartType' { "Start type of service $($Entry.Name)"; break }
        'ServiceStart'     { "Start of service $($Entry.Name)"; break }
        'LocalUserEnabled' { "Local account $($Entry.Sid)"; break }
        'GroupMember'      { "Member $($Entry.MemberSid) of group $($Entry.GroupSid)"; break }
        'SecurityPolicy'   { "Security policy [$($Entry.Section)] $($Entry.Name)"; break }
        'Feature'          { "Optional feature $($Entry.Name)"; break }
        'AuditPolicy'      { "Audit policy (backup $($Entry.File))"; break }
        'EventLogSize'     { "Maximum size of log $($Entry.LogName)"; break }
        'FirewallProfile'  { "Firewall profile $($Entry.Name)"; break }
        'Acl'              { "Permissions of $($Entry.Path)"; break }
        'MpPreference'     { "Defender preference $($Entry.Name)"; break }
        'AsrRule'          { "ASR rule $($Entry.Id)"; break }
        default            { "$($Entry.Type)" }
    }
}

function Restore-JournalEntry {
    param($Entry)
    switch ($Entry.Type) {
        'Registry' {
            if ($Entry.Existed) {
                $value = $Entry.OldValue
                switch ($Entry.OldType) {
                    'Binary'      { $value = [byte[]]@($value) }
                    'MultiString' { $value = [string[]]@($value) }
                    'DWord'       { $value = [int]$value }
                    'QWord'       { $value = [long]$value }
                }
                if (-not (Test-Path -LiteralPath $Entry.Path)) { New-Item -Path $Entry.Path -Force | Out-Null }
                New-ItemProperty -LiteralPath $Entry.Path -Name $Entry.Name -Value $value -PropertyType $Entry.OldType -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $Entry.Path -Name $Entry.Name -ErrorAction SilentlyContinue
            }
        }
        'ServiceStartType' {
            $startName = @{ 0 = 'boot'; 1 = 'system'; 2 = 'auto'; 3 = 'demand'; 4 = 'disabled' }[[int]$Entry.OldStart]
            sc.exe config $Entry.Name start= $startName 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($Entry.Name)" -Name 'Start' -Value ([int]$Entry.OldStart)
            }
        }
        'ServiceStart' { Start-Service -Name $Entry.Name -ErrorAction Stop }
        'LocalUserEnabled' { Enable-LocalUser -SID $Entry.Sid }
        'GroupMember' { Add-LocalGroupMember -SID $Entry.GroupSid -Member $Entry.MemberSid -ErrorAction Stop }
        'SecurityPolicy' {
            $old = if ($null -eq $Entry.OldValue) { '' } else { $Entry.OldValue }
            Invoke-SecEditConfigure -Section $Entry.Section -Values @{ $Entry.Name = $old } -Area $Entry.Area
        }
        'Feature' {
            if ($Entry.OldState -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $Entry.Name -All -NoRestart -WarningAction SilentlyContinue | Out-Null }
        }
        'AuditPolicy' { auditpol.exe /restore /file:"$($Entry.File)" 2>&1 | Out-Null }
        'EventLogSize' { wevtutil.exe sl $Entry.LogName /ms:$($Entry.OldSize) 2>&1 | Out-Null }
        'FirewallProfile' {
            Set-NetFirewallProfile -Name $Entry.Name -Enabled $Entry.OldEnabled -DefaultInboundAction $Entry.OldDefaultInboundAction
        }
        'Acl' {
            $item = Get-Item -LiteralPath $Entry.Path -Force
            $acl = $item.GetAccessControl('Access')
            $acl.SetSecurityDescriptorSddlForm($Entry.OldSddl, 'Access')
            $item.SetAccessControl($acl)
        }
        'MpPreference' {
            $parameters = @{ $Entry.Name = $Entry.OldValue }
            Set-MpPreference @parameters
        }
        'AsrRule' {
            if ($null -eq $Entry.OldAction) {
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $Entry.Id
            } else {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $Entry.Id -AttackSurfaceReductionRules_Actions ([int]$Entry.OldAction)
            }
        }
        default { throw "Unknown journal entry type: $($Entry.Type)" }
    }
}

function Invoke-Restore {
    param([string]$File)
    if (-not (Test-Path -LiteralPath $File)) { throw "Rollback journal not found: $File" }
    $entries = @(Get-Content -LiteralPath $File -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    [array]::Reverse($entries)
    Write-Title "Restoring $($entries.Count) change(s) from $File"
    if ((Read-Choice 'Revert all these changes?' @('Y', 'N') 'N') -ne 'Y') { return }
    foreach ($entry in $entries) {
        try {
            Restore-JournalEntry $entry
            Write-Host "  [OK] $(Format-JournalEntry $entry)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAILED] $(Format-JournalEntry $entry): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ''
    Write-Host 'BitLocker changes are never reverted automatically (use manage-bde or Disable-BitLocker if needed).' -ForegroundColor DarkYellow
    Write-Host 'Restart the computer to complete the restoration.' -ForegroundColor Yellow
}

#endregion

#region BitLocker helpers

function Read-BitLockerPin {
    while ($true) {
        $first = Read-Host '  Enter the BitLocker startup PIN (6 to 20 digits)' -AsSecureString
        $second = Read-Host '  Confirm the PIN' -AsSecureString
        $a = ConvertFrom-SecureStringToPlain $first
        $b = ConvertFrom-SecureStringToPlain $second
        $valid = ($a -eq $b) -and ($a -match '^\d{6,20}$')
        $a = $null
        $b = $null
        if ($valid) { return $first }
        Write-Host '  The PINs do not match or are not made of 6 to 20 digits. Try again.' -ForegroundColor Red
    }
}

function Save-RecoveryKey {
    param($Protector)
    # The recovery password must not end up in the transcript
    if ($script:TranscriptFile) { Stop-Transcript | Out-Null }
    try {
        Write-Host ''
        Write-Host '  ===== BITLOCKER RECOVERY KEY - STORE IT SAFELY OUTSIDE THIS COMPUTER =====' -ForegroundColor Yellow
        Write-Host "  Key ID           : $($Protector.KeyProtectorId)" -ForegroundColor Yellow
        Write-Host "  Recovery password: $($Protector.RecoveryPassword)" -ForegroundColor Yellow
        if ($ctx.DomainJoined) {
            try {
                Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $Protector.KeyProtectorId -ErrorAction Stop | Out-Null
                Write-Host '  Recovery key backed up to Active Directory.' -ForegroundColor Green
            } catch { Write-Warning "Backup to Active Directory failed: $($_.Exception.Message)" }
        }
        if ($ctx.EntraJoined) {
            try {
                BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $Protector.KeyProtectorId -ErrorAction Stop | Out-Null
                Write-Host '  Recovery key backed up to Microsoft Entra ID.' -ForegroundColor Green
            } catch { Write-Warning "Backup to Microsoft Entra ID failed: $($_.Exception.Message)" }
        }
        $folder = Read-Host '  Folder where a recovery key file should be written (e.g. a USB drive, NOT the system drive). Empty = skip'
        if ($folder) {
            if ($folder.StartsWith($env:SystemDrive, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning 'The folder is on the system drive: the file was not written.'
            } elseif (Test-Path -LiteralPath $folder -PathType Container) {
                $file = Join-Path $folder "BitLocker-Recovery-$env:COMPUTERNAME-$($Protector.KeyProtectorId.Trim('{}')).txt"
                @("Computer: $env:COMPUTERNAME", "Key ID: $($Protector.KeyProtectorId)", "Recovery password: $($Protector.RecoveryPassword)") |
                    Set-Content -LiteralPath $file -Encoding UTF8
                Write-Host "  Recovery key written to $file" -ForegroundColor Green
            } else {
                Write-Warning "Folder not found: $folder"
            }
        }
        do { $confirm = Read-Host '  Type YES once the recovery key is safely stored' } while ($confirm -ne 'YES')
    } finally {
        if ($script:TranscriptFile) { Start-Transcript -Path $script:TranscriptFile -Append | Out-Null }
    }
}

#endregion

#region Main - initialization

if ($Restore) {
    Invoke-Restore -File $Restore
    return
}

if (-not $OutputDirectory) {
    $baseFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputDirectory = Join-Path $baseFolder "hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$script:OutDir = (Resolve-Path -LiteralPath $OutputDirectory).Path
$script:JournalFile = Join-Path $script:OutDir 'rollback.json'
$script:TranscriptFile = Join-Path $script:OutDir 'transcript.txt'
Start-Transcript -Path $script:TranscriptFile | Out-Null

Write-Title 'Windows hardening - machine context'
$ctx = Get-MachineContext
Show-MachineContext $ctx
if ($ReportOnly) { Write-Host '  Report-only mode: nothing will be changed.' -ForegroundColor Cyan }

$catAccounts = 'Accounts and access'
$catServices = 'Services and applications'
$catNetwork = 'Network'
$catSystem = 'Operating system'
$catDevices = 'Devices'
$catUpdates = 'Updates'
$catLogging = 'Logging'
$catPrivacy = 'Privacy'
$polWin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$systemPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

#endregion

#region Corrections - accounts and access

Add-Correction @{
    Id = 'A01'; Category = $catAccounts; Reference = 'ANSSI AD administration guide; CIS Benchmark - Accounts: Administrator account status'
    Title = 'Disable the built-in Administrator account (RID 500)'
    Impact = 'The built-in account can no longer log on. Check that another administrator account works before applying.'
    Test = {
        param($c)
        $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
        New-State (-not $admin.Enabled) @("Built-in administrator account '$($admin.Name)' enabled: $($admin.Enabled)")
    }
    Relevance = {
        param($c)
        $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
        if ($ctx.CurrentUserSid -eq $admin.SID.Value) {
            return New-Relevance NotRelevant 'You are logged on with this account: create and test another administrator account first.'
        }
        $others = @(Get-AdminMembers | Where-Object { $_.Sid -ne $admin.SID.Value -and $_.Enabled })
        if ($others.Count -eq 0) { return New-Relevance NotRelevant 'No other enabled administrator account or group found: disabling it could lock you out.' }
        if ($ctx.LapsConfigured) { return New-Relevance Optional 'LAPS already randomizes its password, which limits Pass-the-Hash.' }
        New-Relevance Recommended "Other administrators available: $($others.Name -join ', '). Limits Pass-the-Hash with the well-known RID 500."
    }
    Apply = {
        param($c)
        $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
        Add-JournalEntry @{ Type = 'LocalUserEnabled'; Sid = $admin.SID.Value }
        Disable-LocalUser -SID $admin.SID
    }
}

Add-Correction @{
    Id = 'A02'; Category = $catAccounts; Reference = 'CIS Benchmark - Accounts: Guest account status'
    Title = 'Disable the Guest account (RID 501)'
    Impact = 'Anonymous/guest access to shares stops working (intended).'
    Test = {
        param($c)
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        New-State (-not $guest.Enabled) @("Guest account '$($guest.Name)' enabled: $($guest.Enabled)")
    }
    Relevance = { param($c) New-Relevance Recommended 'An enabled Guest account gives password-less access to shares open to Everyone.' }
    Apply = {
        param($c)
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        Add-JournalEntry @{ Type = 'LocalUserEnabled'; Sid = $guest.SID.Value }
        Disable-LocalUser -SID $guest.SID
    }
}

Add-Correction @{
    Id = 'A03'; Category = $catAccounts; Reference = 'CIS Benchmark - MSS: AutoAdminLogon'
    Title = 'Disable Autologon and remove the stored password'
    Impact = 'The logon screen is displayed at startup. For kiosks, prefer Assigned Access. If Sysinternals Autologon was used, the password is an LSA secret: run Autologon.exe and click Disable.'
    Test = {
        param($c)
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $auto = Get-RegValue $winlogon 'AutoAdminLogon'
        $defaultPassword = Get-RegValue $winlogon 'DefaultPassword'
        New-State (("$auto" -ne '1') -and ($null -eq $defaultPassword)) @(
            "AutoAdminLogon = $(if ($null -eq $auto) { 'not defined' } else { $auto })",
            "DefaultPassword stored in clear text in the registry: $(if ($null -ne $defaultPassword) { 'YES' } else { 'no' })"
        )
    }
    Relevance = { param($c) New-Relevance Recommended 'Autologon credentials in the registry can be read by any logged-on user.' }
    Apply = {
        param($c)
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-RegValue $winlogon 'AutoAdminLogon' '0' 'String'
        Remove-RegValue $winlogon 'DefaultPassword'
    }
}

Add-Correction @{
    Id = 'A04'; Category = $catAccounts; Reference = 'ANSSI password recommendations; CIS Benchmark - Account Policies'
    Title = 'Password and lockout policy (12 characters, complexity, lockout after 3 failures)'
    Impact = 'Existing passwords stay valid until changed. ANSSI: 12+ characters for standard accounts, 15+ for privileged accounts, 32 for service accounts (cannot be differentiated locally). Locked accounts are released after 15 minutes.'
    Test = {
        param($c)
        $sa = (Get-SecurityPolicy)['System Access']
        $minLength = [int]$sa['MinimumPasswordLength']
        $complexity = [int]$sa['PasswordComplexity']
        $lockout = [int]$sa['LockoutBadCount']
        New-State (($minLength -ge 12) -and ($complexity -eq 1) -and ($lockout -ge 1) -and ($lockout -le 5)) @(
            "Minimum password length = $minLength (target: 12 or more)",
            "Password complexity = $complexity (target: 1)",
            "Lockout threshold = $lockout (target: 1 to 5, 3 suggested; 0 = never locked)"
        )
    }
    Relevance = {
        param($c)
        if ($ctx.DomainJoined) { return New-Relevance NotRelevant 'Domain-joined: the domain password policy (Default Domain Policy / fine-grained policies) applies; change it there.' }
        if ($ctx.CurrentUserIsMicrosoftAccount -or $ctx.EntraJoined) { return New-Relevance Optional 'Only applies to local accounts: Microsoft / Entra ID accounts follow their cloud password policy.' }
        New-Relevance Recommended 'Local accounts are used on this machine.'
    }
    Apply = {
        param($c)
        $sa = (Get-SecurityPolicy)['System Access']
        $values = @{}
        if ([int]$sa['MinimumPasswordLength'] -lt 12) { $values['MinimumPasswordLength'] = 12 }
        if ([int]$sa['PasswordComplexity'] -ne 1) { $values['PasswordComplexity'] = 1 }
        $lockout = [int]$sa['LockoutBadCount']
        if ($lockout -lt 1 -or $lockout -gt 5) {
            $values['LockoutBadCount'] = 3
            $values['ResetLockoutCount'] = 15
            $values['LockoutDuration'] = 15
        }
        Set-SecurityPolicy -Section 'System Access' -Area 'SECURITYPOLICY' -Values $values
    }
}

Add-Correction @{
    Id = 'A05'; Category = $catAccounts; Reference = 'Microsoft Learn - Implementing least-privilege administrative models'
    Title = 'Remove broad groups (Everyone, Users, Domain Users...) from the Administrators group'
    Impact = 'Members of these groups lose administrator rights. Individual accounts listed above must be reviewed manually: daily-use accounts should not be administrators.'
    Test = {
        param($c)
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-7')
        $members = @(Get-AdminMembers)
        $details = @($members | ForEach-Object {
                $flag = if ($broad -contains $_.Sid -or $_.Sid -match '-513$') { '[KO]' } else { '    ' }
                "$flag $($_.Name) ($($_.Sid), source: $($_.Source), enabled: $($_.Enabled))"
            })
        $bad = @($members | Where-Object { $broad -contains $_.Sid -or $_.Sid -match '-513$' })
        New-State ($bad.Count -eq 0) $details
    }
    Relevance = { param($c) New-Relevance Recommended 'Every user of these groups is a full administrator of the machine.' }
    Apply = {
        param($c)
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-7')
        foreach ($member in @(Get-AdminMembers | Where-Object { $broad -contains $_.Sid -or $_.Sid -match '-513$' })) {
            Add-JournalEntry @{ Type = 'GroupMember'; GroupSid = 'S-1-5-32-544'; MemberSid = $member.Sid }
            Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $member.Sid
        }
    }
}

Add-Correction @{
    Id = 'A06'; Category = $catAccounts; Reference = 'Microsoft Learn - Windows LAPS overview'
    Title = 'Deploy LAPS (randomized local administrator password)'
    Test = { param($c) $laps = Get-LapsState; New-State $laps.Configured $laps.Details }
    Relevance = {
        param($c)
        if ($ctx.DomainJoined -or $ctx.EntraJoined) { return New-Relevance Recommended 'Directory available to store and rotate the local administrator password.' }
        New-Relevance NotRelevant 'No directory (Active Directory / Entra ID) to store the passwords: LAPS is not relevant on a standalone or personal computer. Use a unique strong password for each local administrator instead.'
    }
    Guidance = @'
Windows LAPS is built into Windows (April 2023 updates and later); it must be configured centrally:
 - Active Directory: Update-LapsADSchema ; Set-LapsADComputerSelfPermission -Identity "<computers OU>"
   then GPO: Computer Configuration > Administrative Templates > System > LAPS
   > "Configure password backup directory" = Active Directory (+ "Enable password encryption").
 - Microsoft Entra ID: enable LAPS in Entra ID > Devices > Device settings,
   then Intune > Endpoint security > Account protection > Local admin password solution.
Retrieve a password with Get-LapsADPassword or Get-LapsAADPassword.
'@
}

Add-Correction @{
    Id = 'A07'; Category = $catAccounts; Reference = 'Microsoft Learn - Windows Hello for Business overview'
    Title = 'Strong authentication with Windows Hello for Business'
    Test = {
        param($c)
        $gpo = (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' 'Enabled') -eq 1
        $csp = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork' -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.GetValue('UsePassportForWork') -eq 1 })
        New-State ($gpo -or $csp) @("Enabled by GPO: $gpo", "Enabled by CSP (Intune): $csp")
    }
    Relevance = {
        param($c)
        if ($ctx.IsServer) { return New-Relevance NotRelevant 'Windows Hello for Business targets user workstations, not servers.' }
        if ($ctx.Managed) { return New-Relevance Recommended 'Phishing-resistant authentication bound to the TPM.' }
        New-Relevance NotRelevant 'Windows Hello for Business is an enterprise feature. On a personal computer, use Windows Hello (PIN, fingerprint, face) from Settings > Accounts > Sign-in options; mind the privacy of biometric data.'
    }
    Guidance = @'
Deploy Windows Hello for Business centrally (Cloud Kerberos trust is the simplest model):
 - GPO: Computer Configuration > Administrative Templates > Windows Components > Windows Hello for Business
   > "Use Windows Hello for Business" = Enabled (+ "Use cloud Kerberos trust for on-premises authentication").
 - Intune: Devices > Enrollment > Windows Hello for Business, or an account protection policy.
'@
}

Add-RegistryCorrection @{
    Id = 'A08'; Category = $catAccounts; Reference = 'CIS Benchmark - Interactive logon: Machine inactivity limit'
    Title = "Automatic session lock after inactivity ($InactivityTimeoutSecs seconds)"
    Impact = 'The session locks after the inactivity period: the user must authenticate again.'
    Settings = @(New-RegSetting $systemPolicyPath 'InactivityTimeoutSecs' $InactivityTimeoutSecs -Check { param($v, $s) $v -ge 1 -and $v -le $s.Value })
    Relevance = { param($c) New-Relevance Recommended 'Protects an unattended open session (recommendation: 10 minutes or less).' }
}

Add-RegistryCorrection @{
    Id = 'A09'; Category = $catAccounts; Reference = 'Microsoft Learn - User Account Control settings and configuration'
    Title = 'User Account Control (UAC) hardening'
    Impact = 'Administrators get a consent prompt on the secure desktop for every elevation; the built-in Administrator also runs in Admin Approval Mode.'
    RebootRequired = $true
    Settings = @(
        New-RegSetting $systemPolicyPath 'EnableLUA' 1
        New-RegSetting $systemPolicyPath 'ConsentPromptBehaviorAdmin' 2 -Check { param($v, $s) $v -in 1, 2 }
        New-RegSetting $systemPolicyPath 'PromptOnSecureDesktop' 1
        New-RegSetting $systemPolicyPath 'EnableInstallerDetection' 1
        New-RegSetting $systemPolicyPath 'EnableSecureUIAPaths' 1
        New-RegSetting $systemPolicyPath 'EnableVirtualization' 1
        New-RegSetting $systemPolicyPath 'EnableUIADesktopToggle' 0 -AbsentOk
        New-RegSetting $systemPolicyPath 'FilterAdministratorToken' 1
    )
    Relevance = { param($c) New-Relevance Recommended 'UAC limits silent privilege escalation by malware running in an administrator session.' }
}

Add-RegistryCorrection @{
    Id = 'A10'; Category = $catAccounts; Reference = 'Microsoft Security Baseline - Apply UAC restrictions to local accounts on network logons'
    Title = 'Keep UAC remote restrictions for local accounts (LocalAccountTokenFilterPolicy = 0)'
    Impact = 'Remote administration with LOCAL administrator accounts (SMB admin shares, WMI, PsExec) receives a filtered token and fails. Domain accounts are not affected.'
    Settings = @(New-RegSetting $systemPolicyPath 'LocalAccountTokenFilterPolicy' 0 -AbsentOk)
    Relevance = { param($c) New-Relevance Recommended 'Blocks lateral movement with stolen local administrator hashes (Pass-the-Hash).' }
}

Add-RegistryCorrection @{
    Id = 'A11'; Category = $catAccounts; Reference = 'CIS Benchmark - UAC: Behavior of the elevation prompt for standard users'
    Title = 'Automatically deny elevation requests from standard users (ConsentPromptBehaviorUser = 0)'
    Impact = 'Standard users can no longer elevate by typing administrator credentials: they must switch to an administrator session.'
    Settings = @(New-RegSetting $systemPolicyPath 'ConsentPromptBehaviorUser' 0)
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Recommended 'Prevents administrator credentials from being typed into a potentially compromised user session.' }
        New-Relevance Optional 'On a personal computer, this mainly changes how you elevate from a standard account (no effect if you use an administrator account).'
    }
}

Add-Correction @{
    Id = 'A12'; Category = $catAccounts; Reference = 'CIS Benchmark - User Rights Assignment: Debug programs'
    Title = 'Remove the "Debug programs" privilege (SeDebugPrivilege) from Administrators'
    Impact = 'Administrators can no longer debug processes of other accounts (Visual Studio attach to services, WinDbg, ProcDump on system processes). Some installers (e.g. SQL Server) need it: grant it back temporarily.'
    Test = {
        param($c)
        $sids = @(Get-UserRightSids 'SeDebugPrivilege')
        New-State ($sids.Count -eq 0) @("SeDebugPrivilege granted to: $(Format-SidList $sids)")
    }
    Relevance = {
        param($c)
        if ($ctx.DeveloperTools.Count -gt 0) { return New-Relevance Optional "Developer/debugging tools detected ($($ctx.DeveloperTools -join ', ')): removing the privilege prevents debugging other processes." }
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Blocks LSASS memory dumping by tools such as Mimikatz (deploy it by GPO).' }
        New-Relevance Optional 'Limited gain on a single-user computer, but it makes LSASS dumping harder.'
    }
    Apply = { param($c) Set-UserRight 'SeDebugPrivilege' @() }
}

Add-Correction @{
    Id = 'A13'; Category = $catAccounts; Reference = 'Microsoft Learn - Access this computer from the network'
    Title = 'Network logon right (SeNetworkLogonRight): Administrators and Authenticated Users only'
    Impact = 'Only administrators and authenticated users can access this computer from the network (SMB, RPC...). Everyone, Users and Backup Operators lose this right.'
    Test = {
        param($c)
        $allowed = @('S-1-5-32-544', 'S-1-5-11')
        $sids = @(Get-UserRightSids 'SeNetworkLogonRight')
        $extra = @($sids | Where-Object { $allowed -notcontains $_ })
        New-State (($sids.Count -gt 0) -and ($extra.Count -eq 0)) @("SeNetworkLogonRight granted to: $(Format-SidList $sids)", "Target: $(Format-SidList $allowed)")
    }
    Relevance = {
        param($c)
        if ($ctx.IsDomainController) { return New-Relevance NotRelevant 'Domain controller: this right is managed by the Default Domain Controllers Policy (ENTERPRISE DOMAIN CONTROLLERS is required).' }
        New-Relevance Recommended 'Microsoft recommendation for workstations and member servers (remove Everyone).'
    }
    Apply = { param($c) Set-UserRight 'SeNetworkLogonRight' @('S-1-5-32-544', 'S-1-5-11') }
}

$denyNetworkTargets = @('S-1-5-32-546')
if ($ctx.DomainJoined -and -not $ctx.IsDomainController) { $denyNetworkTargets += 'S-1-5-114' }
Add-Correction @{
    Id = 'A14'; Category = $catAccounts; Reference = 'Microsoft Learn - Deny access to this computer from the network'
    Title = 'Deny network logon (SeDenyNetworkLogonRight) to Guests and, on domain members, local administrator accounts'
    Impact = 'On domain members, local administrator accounts can no longer be used remotely (SMB, WMI, WinRM...): use domain accounts for remote administration.'
    Data = @{ Targets = $denyNetworkTargets }
    Test = {
        param($c)
        $sids = @(Get-UserRightSids 'SeDenyNetworkLogonRight')
        $missing = @($c.Data.Targets | Where-Object { $sids -notcontains $_ })
        New-State ($missing.Count -eq 0) @("SeDenyNetworkLogonRight: $(Format-SidList $sids)", "Must include: $(Format-SidList $c.Data.Targets)")
    }
    Relevance = {
        param($c)
        if ($ctx.DomainJoined -and -not $ctx.IsDomainController) { return New-Relevance Recommended 'Blocks lateral movement with local administrator accounts (Pass-the-Hash).' }
        New-Relevance Recommended 'Denies network access to the Guests group.'
    }
    Apply = {
        param($c)
        $sids = @(Get-UserRightSids 'SeDenyNetworkLogonRight')
        Set-UserRight 'SeDenyNetworkLogonRight' (@($sids) + @($c.Data.Targets | Where-Object { $sids -notcontains $_ }))
    }
}

if ($ctx.DomainSid -and -not $ctx.IsDomainController) {
    Add-Correction @{
        Id = 'A15'; Category = $catAccounts; Reference = 'Microsoft Learn - Enterprise access model (tiering)'
        Title = 'Tiering: deny network logon to Domain Admins on this machine'
        Impact = 'Domain Admins can no longer administer this machine remotely. Use dedicated tier 1 (servers) / tier 2 (workstations) administration accounts.'
        Data = @{ Target = "$($ctx.DomainSid)-512" }
        Test = {
            param($c)
            $sids = @(Get-UserRightSids 'SeDenyNetworkLogonRight')
            New-State ($sids -contains $c.Data.Target) @("SeDenyNetworkLogonRight: $(Format-SidList $sids)", "Must include: $(Format-SidList @($c.Data.Target))")
        }
        Relevance = { param($c) New-Relevance Optional 'Only if a tiered administration model with dedicated admin accounts exists; deploy it by GPO for all workstations / member servers.' }
        Apply = {
            param($c)
            $sids = @(Get-UserRightSids 'SeDenyNetworkLogonRight')
            Set-UserRight 'SeDenyNetworkLogonRight' (@($sids) + $c.Data.Target)
        }
    }
}

Add-RegistryCorrection @{
    Id = 'A16'; Category = $catAccounts; Reference = 'CIS Benchmark - Windows Installer: Always install with elevated privileges'
    Title = 'Disable AlwaysInstallElevated'
    Impact = 'MSI packages are no longer installed with SYSTEM rights for standard users.'
    Settings = @(
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 -AbsentOk
        New-RegSetting 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 -AbsentOk
    )
    Relevance = { param($c) New-Relevance Recommended 'Enabled in both HKLM and HKCU, any user can get SYSTEM rights with a crafted MSI.' }
}

Add-Correction @{
    Id = 'A17'; Category = $catAccounts; Reference = 'Microsoft Learn - Just Enough Administration overview'
    Title = 'Just Enough Administration (JEA) for delegated administration'
    Test = {
        param($c)
        $endpoints = @(Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Where-Object { "$($_.SessionType)" -eq 'RestrictedRemoteServer' })
        New-State ($endpoints.Count -gt 0) @("JEA endpoints (RestrictedRemoteServer): $(if ($endpoints) { $endpoints.Name -join ', ' } else { 'none' })")
    }
    Relevance = {
        param($c)
        if ($ctx.IsServer) { return New-Relevance Optional 'Useful to delegate specific tasks (restart a service...) without granting administrator rights.' }
        New-Relevance NotRelevant 'JEA is meant for servers administered remotely by several teams.'
    }
    Guidance = @'
1. New-PSRoleCapabilityFile -Path "C:\Program Files\WindowsPowerShell\Modules\JEA\RoleCapabilities\Helpdesk.psrc"
   then set VisibleCmdlets = @('Restart-Service','Get-Service')
2. New-PSSessionConfigurationFile -Path .\Helpdesk.pssc -SessionType RestrictedRemoteServer
   -RunAsVirtualAccount -RoleDefinitions @{ 'DOMAIN\Helpdesk' = @{ RoleCapabilities = 'Helpdesk' } }
3. Register-PSSessionConfiguration -Name Helpdesk -Path .\Helpdesk.pssc -Force
'@
}

#endregion

#region Corrections - services and applications

function Add-ServiceCorrection {
    param([string]$Id, [string]$Name, [string]$Title, [string]$Impact, [scriptblock]$Relevance)
    Add-Correction @{
        Id = $Id; Category = $catServices; Reference = 'Microsoft Learn - Guidance on disabling system services on Windows Server'; Title = $Title; Impact = $Impact
        Data = @{ Service = $Name }; Relevance = $Relevance
        Test = {
            param($c)
            $name = $c.Data.Service
            $start = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$name" 'Start'
            if ($null -eq $start) { return New-State $true @("Service '$name' is not installed.") }
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            $status = if ($svc) { $svc.Status } else { 'unknown' }
            New-State ($start -eq 4) @("Service '$name': start type = $(ConvertTo-StartTypeName $start), status = $status")
        }
        Apply = { param($c) Disable-ServiceSafe $c.Data.Service }
    }
}

Add-ServiceCorrection 'S01' 'AJRouter' 'Disable AllJoyn Router (AJRouter)' 'AllJoyn-based IoT devices can no longer be discovered.' {
    param($c) New-Relevance Recommended 'Deprecated IoT discovery service, useless on almost all machines.'
}
Add-ServiceCorrection 'S02' 'DiagTrack' 'Disable Connected User Experiences and Telemetry (DiagTrack)' 'Diagnostic data is no longer sent to Microsoft.' {
    param($c)
    if ($ctx.Managed) { return New-Relevance Optional 'Used by Intune / Windows Update for Business reports and Endpoint analytics: check with the management team.' }
    New-Relevance Recommended 'Telemetry collection service (privacy).'
}
Add-ServiceCorrection 'S03' 'dmwappushservice' 'Disable Device Management WAP Push routing (dmwappushservice)' 'MDM push messages are no longer routed.' {
    param($c)
    if ($ctx.MdmEnrolled) { return New-Relevance NotRelevant 'This device is enrolled in an MDM (Intune): the service is needed for device management.' }
    New-Relevance Recommended 'Only needed for MDM enrollment and synchronization.'
}
Add-ServiceCorrection 'S04' 'icssvc' 'Disable Windows Mobile Hotspot (icssvc)' 'The connection can no longer be shared as a mobile hotspot.' {
    param($c)
    if ($ctx.IsLaptop) { return New-Relevance Optional 'Laptop: the mobile hotspot feature may be used to share a connection.' }
    New-Relevance Recommended 'Connection sharing is not expected on this machine.'
}
Add-ServiceCorrection 'S05' 'LanmanServer' 'Disable the SMB server (LanmanServer)' 'No file/printer sharing, no administrative shares (C$, ADMIN$), no remote administration relying on SMB.' {
    param($c)
    if ($ctx.IsServer) { return New-Relevance NotRelevant 'Servers usually need SMB (shares, administration, domain services).' }
    if ($ctx.Shares.Count -gt 0) { return New-Relevance NotRelevant "Shares are published by this machine: $($ctx.Shares -join ', ')." }
    if ($ctx.DomainJoined) { return New-Relevance Optional 'Remote management tools (ConfigMgr, remote event viewer, PsExec...) may rely on it.' }
    New-Relevance Recommended 'No share published: SMB server exposure is useless on this standalone workstation.'
}
Add-ServiceCorrection 'S06' 'SNMPTrap' 'Disable SNMP Trap (SNMPTrap)' 'SNMP traps are no longer received.' {
    param($c) New-Relevance Recommended 'Only needed by SNMP monitoring tools.'
}
Add-ServiceCorrection 'S07' 'SSDPSRV' 'Disable SSDP Discovery (SSDPSRV)' 'UPnP devices (media players, some printers) are no longer discovered automatically.' {
    param($c) New-Relevance Recommended 'UPnP discovery increases the network attack surface.'
}
Add-ServiceCorrection 'S08' 'Spooler' 'Disable the Print Spooler (Spooler)' 'Printing is impossible, including "Microsoft Print to PDF".' {
    param($c)
    if ($ctx.IsDomainController) { return New-Relevance Recommended 'Domain controller: the spooler allows coercion (PrinterBug) and PrintNightmare-like attacks (ANSSI).' }
    if ($ctx.PhysicalPrinters.Count -gt 0) { return New-Relevance NotRelevant "Printers are installed: $($ctx.PhysicalPrinters -join ', ')." }
    if ($ctx.IsServer) { return New-Relevance Recommended 'Server without printers: the spooler is an unnecessary attack surface.' }
    New-Relevance Optional 'No physical printer found, but disabling it also removes "Print to PDF".'
}
Add-ServiceCorrection 'S09' 'usbcir' 'Disable the USB infrared receiver driver (usbcir)' 'Infrared remote controls stop working.' {
    param($c) New-Relevance Recommended 'Kernel driver useless without an infrared receiver.'
}
# The WinHttpAutoProxySvc service itself must not be disabled: Wcmsvc, WlanSvc, iphlpsvc and NcaSvc depend on it (no network at all)
Add-RegistryCorrection @{
    Id = 'S10'; Category = $catServices; Reference = 'Microsoft Learn - How to disable HTTP proxy features'
    Title = 'Disable WPAD proxy auto-discovery for WinHTTP (DisableWpad = 1)'
    Impact = 'Automatic proxy detection (WPAD) stops for WinHTTP applications; proxies must be configured explicitly. The WinHttpAutoProxySvc service stays enabled. Also disable "Automatically detect settings" in Settings > Network > Proxy for browsers.'
    RebootRequired = $true
    Settings = @(New-RegSetting 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 1)
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Optional 'Corporate networks often rely on WPAD/PAC to find the proxy: check before disabling.' }
        New-Relevance Recommended 'WPAD can be abused (IPv4/IPv6) to redirect traffic and capture credentials.'
    }
}
Add-ServiceCorrection 'S11' 'WebClient' 'Disable the WebDAV client (WebClient)' 'WebDAV mapped drives and SharePoint "Open in Explorer" stop working.' {
    param($c) New-Relevance Recommended 'WebClient allows NTLM authentication coercion over HTTP (NTLM relay).'
}
Add-ServiceCorrection 'S12' 'AppIDSvc' 'Disable Application Identity (AppIDSvc)' 'AppLocker rules can no longer be enforced.' {
    param($c)
    if ($ctx.AppLockerConfigured) { return New-Relevance NotRelevant 'An AppLocker policy is configured: this service is required to enforce it.' }
    New-Relevance Optional 'Low gain: the service only starts on demand; keep it if AppLocker may be deployed.'
}

Add-Correction @{
    Id = 'S13'; Category = $catServices; Reference = 'MITRE ATT&CK T1574.009 - Path Interception by Unquoted Path'
    Title = 'Quote service paths that contain spaces (unquoted service path)'
    Impact = 'None expected; takes effect at the next service start.'
    Test = {
        param($c)
        $items = @(Get-UnquotedServicePath)
        New-State ($items.Count -eq 0) $(if ($items) { $items | ForEach-Object { "[KO] $($_.Name): $($_.ImagePath)" } } else { @('No unquoted service path.') })
    }
    Relevance = { param($c) New-Relevance Recommended 'A writable intermediate folder allows privilege escalation to the service account (often SYSTEM).' }
    Apply = {
        param($c)
        foreach ($item in @(Get-UnquotedServicePath)) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($item.Name)"
            $kind = (Get-Item -LiteralPath $path).GetValueKind('ImagePath').ToString()
            Set-RegValue $path 'ImagePath' ('"' + $item.Exe + '"' + $item.Arguments) $kind
        }
    }
}

Add-Correction @{
    Id = 'S14'; Category = $catServices; Reference = 'MITRE ATT&CK T1574.010 - Services File Permissions Weakness'
    Title = 'Remove write permissions of Everyone / Users / Authenticated Users on service executables and folders'
    Impact = 'Standard users can no longer modify these files/folders. An application writing into its own installation folder may need a dedicated permission. Inherited permissions are converted to explicit ones on the fixed objects.'
    Test = {
        param($c)
        $findings = @(Get-WeakServicePermission)
        New-State ($findings.Count -eq 0) $(if ($findings) {
                $findings | ForEach-Object { "[KO] $($_.Target) (service $($_.Service)): $($_.Identity) has $($_.Rights)$(if ($_.Inherited) { ' (inherited)' })" }
            } else { @('No weak permission found on service executables.') })
    }
    Relevance = { param($c) New-Relevance Recommended 'A standard user able to replace a service binary or plant a DLL gets the rights of the service (often SYSTEM).' }
    Apply = {
        param($c)
        $targets = @(Get-WeakServicePermission | Select-Object -ExpandProperty Target -Unique |
                Sort-Object { -not (Test-Path -LiteralPath $_ -PathType Container) })
        foreach ($target in $targets) {
            $item = Get-Item -LiteralPath $target -Force
            $acl = $item.GetAccessControl('Access')
            $weak = @($acl.Access | Where-Object { Test-WeakAce $_ })
            if ($weak.Count -eq 0) { continue }
            Add-JournalEntry @{ Type = 'Acl'; Path = $target; OldSddl = $acl.GetSecurityDescriptorSddlForm('Access') }
            if ($weak | Where-Object { $_.IsInherited }) {
                $acl.SetAccessRuleProtection($true, $true)
                $item.SetAccessControl($acl)
                $acl = $item.GetAccessControl('Access')
            }
            foreach ($ace in @($acl.Access)) {
                if (Test-WeakAce $ace) { [void]$acl.RemoveAccessRuleSpecific($ace) }
            }
            $item.SetAccessControl($acl)
        }
    }
}

$rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
Add-RegistryCorrection @{
    Id = 'S20'; Category = $catServices; Reference = 'CIS Benchmark - Remote Desktop Session Host: Security'
    Title = 'RDP server: TLS, Network Level Authentication and encryption'
    Impact = 'Clients must support NLA (all supported Windows versions do). Applies to new connections.'
    Settings = @(
        New-RegSetting $rdpTcpPath 'SecurityLayer' 2
        New-RegSetting $rdpTcpPath 'UserAuthentication' 1
        New-RegSetting $rdpTcpPath 'MinEncryptionLevel' 3 -Check { param($v, $s) $v -ge 3 }
        New-RegSetting $tsPolicyPath 'fEncryptRPCTraffic' 1
    )
    Relevance = {
        param($c)
        if ($ctx.RdpEnabled) { return New-Relevance Recommended 'RDP is enabled on this machine.' }
        New-Relevance Optional 'RDP is disabled: harmless, the settings will apply if RDP is enabled later.'
    }
}

Add-RegistryCorrection @{
    Id = 'S21'; Category = $catServices; Reference = 'Microsoft Learn - Remote Credential Guard (Restricted Admin mode)'
    Title = 'Disable RDP Restricted Admin mode on this host (DisableRestrictedAdmin = 1)'
    Impact = 'Incoming RDP connections in Restricted Admin mode, and with Remote Credential Guard, are refused.'
    Settings = @(New-RegSetting $lsaPath 'DisableRestrictedAdmin' 1 -AbsentOk)
    Relevance = { param($c) New-Relevance Recommended 'Restricted Admin allows RDP logon with an NTLM hash (Pass-the-Hash). Keep it only if this host is administered with Remote Credential Guard.' }
}

Add-RegistryCorrection @{
    Id = 'S22'; Category = $catServices; Reference = 'Microsoft Learn - Remote Credential Guard'
    Title = 'RDP client: require Windows Remote Credential Guard for outgoing connections'
    Impact = 'Outgoing RDP connections to hosts that do not support Remote Credential Guard fail.'
    Settings = @(
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'RestrictedRemoteAdministration' 1
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'RestrictedRemoteAdministrationType' 2
    )
    Relevance = {
        param($c)
        if ($ctx.DomainJoined) { return New-Relevance Recommended 'Credentials are not sent to the administered servers (useful on administration workstations).' }
        New-Relevance NotRelevant 'Remote Credential Guard needs Kerberos (domain accounts): requiring it would block RDP to non-domain hosts.'
    }
}

Add-RegistryCorrection @{
    Id = 'S23'; Category = $catServices; Reference = 'CIS Benchmark - Remote Desktop Connection Client: Configure server authentication for client'
    Title = 'RDP client: do not connect to servers without a valid certificate (AuthenticationLevel = 1)'
    Impact = 'Connections to servers using self-signed or untrusted certificates are refused.'
    Settings = @(New-RegSetting $tsPolicyPath 'AuthenticationLevel' 1)
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Recommended 'Relevant if servers use certificates from a trusted (enterprise) PKI.' }
        New-Relevance NotRelevant 'Standalone hosts usually use self-signed certificates: connections would be blocked.'
    }
}

$winrmPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'
Add-RegistryCorrection @{
    Id = 'S24'; Category = $catServices; Reference = 'CIS Benchmark - Windows Remote Management (WinRM)'
    Title = 'WinRM: disable Basic/Digest authentication, unencrypted traffic and RunAs credentials'
    Impact = 'Clients/servers relying on Basic or Digest authentication or unencrypted HTTP stop working; session configurations can no longer store RunAs credentials.'
    Settings = @(
        New-RegSetting "$winrmPolicy\Service" 'AllowBasic' 0
        New-RegSetting "$winrmPolicy\Service" 'AllowUnencryptedTraffic' 0
        New-RegSetting "$winrmPolicy\Service" 'DisableRunAs' 1
        New-RegSetting "$winrmPolicy\Client" 'AllowBasic' 0
        New-RegSetting "$winrmPolicy\Client" 'AllowDigest' 0
        New-RegSetting "$winrmPolicy\Client" 'AllowUnencryptedTraffic' 0
    )
    Relevance = { param($c) New-Relevance Recommended 'Basic and Digest send credentials that are easy to steal or relay.' }
}

Add-Correction @{
    Id = 'S25'; Category = $catServices; Reference = 'Microsoft Learn - Installation and configuration for Windows Remote Management'
    Title = 'Disable the WinRM service on a workstation'
    Impact = 'PowerShell remoting and WinRM-based management (including Windows Event Forwarding) no longer work on this machine.'
    Test = {
        param($c)
        $start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM' 'Start'
        $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        New-State (($start -eq 4) -or ($svc.Status -ne 'Running' -and $start -ne 2)) @("WinRM: start type = $(ConvertTo-StartTypeName $start), status = $($svc.Status)")
    }
    Relevance = {
        param($c)
        if ($ctx.IsServer) { return New-Relevance NotRelevant 'WinRM is used to manage servers (Server Manager, PowerShell remoting).' }
        if ($ctx.Managed) { return New-Relevance Optional 'May be used by remote management tools or Windows Event Forwarding.' }
        New-Relevance Recommended 'WinRM is not needed on a standalone workstation (disabled by default on workstations).'
    }
    Apply = { param($c) Disable-ServiceSafe 'WinRM' }
}

$lanmanServer = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$lanmanWorkstation = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Add-RegistryCorrection @{
    Id = 'S30'; Category = $catServices; Reference = 'Microsoft Learn - Overview of Server Message Block signing'
    Title = 'Require SMB signing (client and server)'
    Impact = 'Old NAS / printers / devices that do not support SMB signing can no longer connect; small performance cost.'
    RebootRequired = $true
    Settings = @(
        New-RegSetting $lanmanServer 'EnableSecuritySignature' 1
        New-RegSetting $lanmanServer 'RequireSecuritySignature' 1
        New-RegSetting $lanmanWorkstation 'EnableSecuritySignature' 1
        New-RegSetting $lanmanWorkstation 'RequireSecuritySignature' 1
    )
    Relevance = { param($c) New-Relevance Recommended 'SMB signing prevents NTLM relay attacks over SMB.' }
}

function Add-FeatureCorrection {
    param([string]$Id, [string]$Category, [string]$Reference, [string]$Feature, [string]$Title, [string]$Reason, [string]$Impact)
    Add-Correction @{
        Id = $Id; Category = $Category; Reference = $Reference; Title = $Title; Impact = $Impact; RebootRequired = $true
        Data = @{ Feature = $Feature; Reason = $Reason }
        Test = {
            param($c)
            $f = Get-WindowsOptionalFeature -Online -FeatureName $c.Data.Feature -ErrorAction SilentlyContinue
            if (-not $f) { return New-State $true @("Feature $($c.Data.Feature) is not available on this system.") }
            New-State ("$($f.State)" -notin 'Enabled', 'EnablePending') @("Feature $($c.Data.Feature): $($f.State)")
        }
        Relevance = { param($c) New-Relevance Recommended $c.Data.Reason }
        Apply = {
            param($c)
            Add-JournalEntry @{ Type = 'Feature'; Name = $c.Data.Feature; OldState = 'Enabled' }
            Disable-WindowsOptionalFeature -Online -FeatureName $c.Data.Feature -NoRestart -WarningAction SilentlyContinue | Out-Null
        }
    }
}

Add-FeatureCorrection -Id 'S31' -Category $catServices -Reference 'Microsoft Learn - How to detect, enable and disable SMBv1, SMBv2, and SMBv3' -Feature 'SMB1Protocol' -Title 'Remove SMBv1' `
    -Reason 'SMBv1 is obsolete and vulnerable (EternalBlue / WannaCry).' `
    -Impact 'Very old devices (Windows XP/2003, old NAS, scan-to-folder printers) can no longer connect.'

Add-RegistryCorrection @{
    Id = 'S32'; Category = $catServices; Reference = 'CIS Benchmark - Network access: anonymous enumeration settings'
    Title = 'Restrict anonymous access (RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous)'
    Impact = 'Legacy applications relying on anonymous enumeration (null sessions) stop working.'
    Settings = @(
        New-RegSetting $lsaPath 'RestrictAnonymous' 1
        New-RegSetting $lsaPath 'RestrictAnonymousSAM' 1
        New-RegSetting $lsaPath 'EveryoneIncludesAnonymous' 0
    )
    Relevance = { param($c) New-Relevance Recommended 'Prevents anonymous enumeration of accounts, groups and shares.' }
}

#endregion

#region Corrections - network

Add-RegistryCorrection @{
    Id = 'N01'; Category = $catNetwork; Reference = 'Microsoft Learn - Guidance for configuring IPv6 in Windows'
    Title = 'Disable IPv6 when it is not used (DisabledComponents = 0xFF)'
    Impact = 'Microsoft does not recommend disabling IPv6 (some components assume it); if problems appear, use 0x20 (prefer IPv4) instead. Restart required.'
    RebootRequired = $true
    Settings = @(New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' 255 -Check { param($v, $s) ($v -band 0xFF) -eq 0xFF })
    Relevance = {
        param($c)
        if ($ctx.IPv6InUse) { return New-Relevance NotRelevant 'Global IPv6 addresses are configured: IPv6 is in use on this network.' }
        if ($ctx.IsDomainController) { return New-Relevance Optional 'Domain controller: Microsoft strongly advises against disabling IPv6.' }
        New-Relevance Recommended 'IPv6 is not used: disabling it removes mitm6 / rogue DHCPv6 attacks.'
    }
}

Add-RegistryCorrection @{
    Id = 'N02'; Category = $catNetwork; Reference = 'Microsoft Learn - Network security: LAN Manager authentication level'
    Title = 'NTLM: send NTLMv2 only, refuse LM and NTLMv1 (LmCompatibilityLevel = 5)'
    Impact = 'Legacy devices or applications that only support LM/NTLMv1 can no longer authenticate. In a domain, deploy it by GPO on all machines, domain controllers included.'
    Settings = @(New-RegSetting $lsaPath 'LmCompatibilityLevel' 5 -Check { param($v, $s) $v -ge 5 })
    Relevance = { param($c) New-Relevance Recommended 'NTLMv1 responses are trivially cracked and easier to relay.' }
}

Add-RegistryCorrection @{
    Id = 'N03'; Category = $catNetwork; Reference = 'Microsoft Learn - Do not store LAN Manager hash value on next password change'
    Title = 'Do not store LM hashes (NoLMHash = 1)'
    Impact = 'None (LM hashes are obsolete). Existing LM hashes disappear at the next password change.'
    Settings = @(New-RegSetting $lsaPath 'NoLMHash' 1)
    Relevance = { param($c) New-Relevance Recommended 'LM hashes are cracked in seconds.' }
}

Add-RegistryCorrection @{
    Id = 'N04'; Category = $catNetwork; Reference = 'CIS Benchmark - DNS Client: Turn off multicast name resolution'
    Title = 'Disable LLMNR (EnableMulticast = 0)'
    Impact = 'Name resolution only uses DNS (names unknown to DNS are no longer resolved by multicast).'
    Settings = @(New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0)
    Relevance = { param($c) New-Relevance Recommended 'LLMNR poisoning (Responder) captures NTLM hashes on the local network.' }
}

Add-RegistryCorrection @{
    Id = 'N05'; Category = $catNetwork; Reference = 'CIS Benchmark - MSS: NoNameReleaseOnDemand'
    Title = 'Ignore NetBIOS name release requests (NoNameReleaseOnDemand = 1)'
    Impact = 'None expected.'
    Settings = @(New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1)
    Relevance = { param($c) New-Relevance Recommended 'Prevents an attacker from forcing the release of the NetBIOS name of this machine.' }
}

Add-Correction @{
    Id = 'N06'; Category = $catNetwork; Reference = 'MITRE ATT&CK T1557.001 - LLMNR/NBT-NS Poisoning'
    Title = 'Disable NetBIOS over TCP/IP (NBT-NS) on all network interfaces'
    Impact = 'Devices only reachable by their NetBIOS name (old NAS, printers) must be accessed by DNS name or IP address.'
    Test = {
        param($c)
        $interfaces = @(Get-NetbiosInterface)
        $details = $interfaces | ForEach-Object {
            $state = switch ($_.Option) { 1 { 'enabled' } 2 { 'disabled' } default { 'DHCP setting (enabled by default)' } }
            "$(if ($_.Option -eq 2) { '[OK]' } else { '[KO]' }) $($_.Name): $state"
        }
        New-State (@($interfaces | Where-Object { $_.Option -ne 2 }).Count -eq 0) $details
    }
    Relevance = {
        param($c)
        if ($ctx.DomainJoined) { return New-Relevance Optional 'Legacy applications or WINS may still rely on NetBIOS names: test first.' }
        New-Relevance Recommended 'NBT-NS poisoning (Responder) captures NTLM hashes on the local network.'
    }
    Apply = {
        param($c)
        foreach ($interface in @(Get-NetbiosInterface | Where-Object { $_.Option -ne 2 })) {
            Set-RegValue $interface.Path 'NetbiosOptions' 2
        }
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' | ForEach-Object {
            Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
        }
    }
}

Add-RegistryCorrection @{
    Id = 'N07'; Category = $catNetwork; Reference = 'MITRE ATT&CK T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay'
    Title = 'Disable mDNS (EnableMDNS = 0)'
    Impact = 'Discovery of network printers, casting devices and other mDNS services may stop working. Restart required.'
    RebootRequired = $true
    Settings = @(New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0)
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'mDNS poisoning can be used like LLMNR to capture credentials.' }
        New-Relevance Optional 'On a home network, mDNS is used to discover printers and casting devices.'
    }
}

Add-Correction @{
    Id = 'N08'; Category = $catNetwork; Reference = 'Microsoft Learn - Windows Firewall best practices'
    Title = 'Windows Firewall enabled on all profiles, inbound connections blocked by default'
    Impact = 'Inbound connections not allowed by a rule are blocked. A firewall GPO takes precedence over local settings.'
    Test = {
        param($c)
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        $details = $profiles | ForEach-Object {
            $ok = ("$($_.Enabled)" -eq 'True') -and ("$($_.DefaultInboundAction)" -in 'Block', 'NotConfigured')
            "$(if ($ok) { '[OK]' } else { '[KO]' }) Profile $($_.Name): enabled = $($_.Enabled), default inbound action = $($_.DefaultInboundAction)"
        }
        New-State (@($details | Where-Object { $_ -like '`[KO`]*' }).Count -eq 0) $details
    }
    Relevance = {
        param($c)
        if ($ctx.ThirdPartyFirewall.Count -gt 0) { return New-Relevance NotRelevant "A third-party firewall is registered: $($ctx.ThirdPartyFirewall -join ', ')." }
        New-Relevance Recommended 'Host filtering is a basic defense against network attacks and lateral movement.'
    }
    Apply = {
        param($c)
        foreach ($p in Get-NetFirewallProfile -PolicyStore PersistentStore) {
            Add-JournalEntry @{ Type = 'FirewallProfile'; Name = $p.Name; OldEnabled = "$($p.Enabled)"; OldDefaultInboundAction = "$($p.DefaultInboundAction)" }
        }
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block
    }
}

Add-Correction @{
    Id = 'N09'; Category = $catNetwork; Reference = 'ANSSI recommendations on mobile working (nomadisme numerique)'
    Title = 'VPN for remote and public network connections'
    Test = {
        param($c)
        $connections = @(Get-VpnConnection -ErrorAction SilentlyContinue) + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)
        $found = @($ctx.VpnApps) + @($connections | ForEach-Object { "$($_.Name) (Windows VPN)" })
        New-State ($found.Count -gt 0) @("VPN clients / connections found: $(if ($found) { $found -join ', ' } else { 'none' })")
    }
    Relevance = {
        param($c)
        if ($ctx.IsLaptop) { return New-Relevance Recommended 'Laptop: it is likely to be used on public or untrusted networks.' }
        New-Relevance NotRelevant 'Fixed machine: a VPN is only needed for remote access.'
    }
    Guidance = @'
Install the VPN client of your organization (or a trusted VPN for personal use) and enable it on public networks.
Check that the active firewall profile is "Public" on untrusted networks (Get-NetConnectionProfile).
'@
}

#endregion

#region Corrections - operating system

$featureCandidates = [ordered]@{
    'TelnetClient'                     = @('Telnet client', 'Clear-text protocol; use Test-NetConnection -Port to test TCP ports.', 'The telnet command is no longer available.')
    'TFTP'                             = @('TFTP client', 'Unauthenticated clear-text transfer, often used to download payloads.', 'The tftp command is no longer available.')
    'SimpleTCP'                        = @('Simple TCP/IP services (echo, daytime, chargen...)', 'Legacy services usable for denial of service.', 'None expected.')
    'MicrosoftWindowsPowerShellV2Root' = @('Windows PowerShell 2.0 engine', 'PowerShell 2.0 allows downgrade attacks bypassing script block logging, AMSI and Constrained Language Mode.', 'Scripts explicitly requiring "powershell -Version 2" no longer run.')
}
$featureIndex = 0
foreach ($featureName in $featureCandidates.Keys) {
    try { $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop } catch { $feature = $null }
    if (-not $feature) { continue }
    $featureIndex++
    $info = $featureCandidates[$featureName]
    Add-FeatureCorrection -Id ('O01.{0}' -f $featureIndex) -Category $catSystem -Reference 'CIS Benchmark - Windows optional features' -Feature $featureName `
        -Title "Remove the optional feature: $($info[0])" -Reason $info[1] -Impact $info[2]
}

Add-RegistryCorrection @{
    Id = 'O02'; Category = $catSystem; Reference = 'Microsoft Learn - Configure Windows diagnostic data in your organization'
    Title = 'Reduce telemetry to the minimum level (AllowTelemetry = 1 or less)'
    Impact = 'Microsoft only receives required diagnostic data. Level 0 (Security) is only honored on Enterprise, Education and Server editions.'
    Settings = @(New-RegSetting "$polWin\DataCollection" 'AllowTelemetry' 1 -Check { param($v, $s) $v -le 1 })
    Relevance = { param($c) New-Relevance Recommended 'ANSSI recommends the lowest telemetry level compatible with your needs.' }
}

Add-Correction @{
    Id = 'O03'; Category = $catSystem; Reference = 'Microsoft Learn - Microsoft Defender Antivirus in Windows'
    Title = 'Antivirus: Microsoft Defender enabled with real-time protection and recent signatures'
    Impact = 'Tamper Protection may block some changes: re-enable protection from Windows Security if needed.'
    Test = {
        param($c)
        if ($ctx.ThirdPartyAV.Count -gt 0) { return New-State $true @("Third-party antivirus registered: $($ctx.ThirdPartyAV -join ', ')") }
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { return New-State $false @('Microsoft Defender status unavailable (not installed or disabled).') }
        $ok = $mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled -and $mp.AntivirusSignatureAge -le 7
        New-State $ok @(
            "Antivirus enabled: $($mp.AntivirusEnabled), real-time protection: $($mp.RealTimeProtectionEnabled), mode: $($mp.AMRunningMode)",
            "Engine $($mp.AMEngineVersion), signatures $($mp.AntivirusSignatureVersion) ($($mp.AntivirusSignatureAge) day(s) old)"
        )
    }
    Relevance = { param($c) New-Relevance Recommended 'No active antivirus was found on this machine.' }
    Apply = {
        param($c)
        foreach ($name in 'DisableAntiSpyware', 'DisableAntiVirus') { Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' $name }
        foreach ($name in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableIOAVProtection') {
            Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' $name
        }
        Add-JournalEntry @{ Type = 'MpPreference'; Name = 'DisableRealtimeMonitoring'; OldValue = [bool](Get-MpPreference).DisableRealtimeMonitoring }
        Set-MpPreference -DisableRealtimeMonitoring $false
        Update-MpSignature -ErrorAction SilentlyContinue
    }
}

$asrRules = [ordered]@{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}
Add-Correction @{
    Id = 'O04'; Category = $catSystem; Reference = 'Microsoft Learn - Attack surface reduction rules reference'
    Title = 'Exploit Guard: Attack Surface Reduction (ASR) rules'
    Impact = 'Some legitimate behaviors may be blocked (Office macros launching programs, unsigned tools on USB drives...). Audit mode only logs events 1121/1122 in Microsoft-Windows-Windows Defender/Operational.'
    Data = @{ Rules = $asrRules }
    Test = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-State $false @('Microsoft Defender Antivirus is not the active antivirus: ASR rules do not apply.') }
        $state = Get-AsrState
        $allOk = $true
        $details = foreach ($id in $c.Data.Rules.Keys) {
            $action = $state[$id]
            $label = if ($null -eq $action) { 'not configured' } else { switch ($action) { 0 { 'disabled' } 1 { 'block' } 2 { 'audit' } 6 { 'warn' } default { "$action" } } }
            $ok = $action -in 1, 6
            if (-not $ok) { $allOk = $false }
            "$(if ($ok) { '[OK]' } else { '[KO]' }) $($c.Data.Rules[$id]): $label"
        }
        New-State $allOk $details
    }
    Relevance = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-Relevance NotRelevant 'ASR rules require Microsoft Defender Antivirus as the active antivirus.' }
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Start in audit mode, review the events, then switch to block mode (preferably via Intune / GPO).' }
        New-Relevance Recommended 'Blocks common attack techniques (malicious macros, scripts, credential theft).'
    }
    Apply = {
        param($c)
        $defaultMode = if ($ctx.Managed -or $ctx.IsServer) { 'A' } else { 'B' }
        $mode = Read-Choice '  Mode: B = block, A = audit only' @('B', 'A') $defaultMode
        $action = if ($mode -eq 'B') { 'Enabled' } else { 'AuditMode' }
        $state = Get-AsrState
        $ids = @($c.Data.Rules.Keys | Where-Object { $state[$_] -notin 1, 6 })
        foreach ($id in $ids) { Add-JournalEntry @{ Type = 'AsrRule'; Id = $id; OldAction = $state[$id] } }
        if ($ids.Count -gt 0) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions @($ids | ForEach-Object { $action })
        }
    }
}

Add-Correction @{
    Id = 'O05'; Category = $catSystem; Reference = 'Microsoft Learn - Network protection'
    Title = 'Exploit Guard: Network Protection'
    Impact = 'Connections to malicious or low-reputation domains are blocked for all applications, not only Edge.'
    Test = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-State $false @('Microsoft Defender Antivirus is not the active antivirus.') }
        $value = (Get-MpPreference).EnableNetworkProtection
        New-State ($value -eq 1) @("EnableNetworkProtection = $value (0 = disabled, 1 = enabled, 2 = audit)")
    }
    Relevance = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-Relevance NotRelevant 'Requires Microsoft Defender Antivirus as the active antivirus.' }
        New-Relevance Recommended 'Blocks phishing and malware download sites at the network level.'
    }
    Apply = {
        param($c)
        Add-JournalEntry @{ Type = 'MpPreference'; Name = 'EnableNetworkProtection'; OldValue = [int](Get-MpPreference).EnableNetworkProtection }
        Set-MpPreference -EnableNetworkProtection Enabled
        if ($ctx.IsServer) {
            Add-JournalEntry @{ Type = 'MpPreference'; Name = 'AllowNetworkProtectionOnWinServer'; OldValue = [bool](Get-MpPreference).AllowNetworkProtectionOnWinServer }
            Set-MpPreference -AllowNetworkProtectionOnWinServer $true
        }
    }
}

Add-Correction @{
    Id = 'O06'; Category = $catSystem; Reference = 'Microsoft Learn - Controlled folder access'
    Title = 'Exploit Guard: Controlled Folder Access (ransomware protection)'
    Impact = 'Unknown applications can no longer write into protected folders (Documents, Pictures, Desktop...) until allowed in Windows Security > Ransomware protection.'
    Test = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-State $false @('Microsoft Defender Antivirus is not the active antivirus.') }
        $value = (Get-MpPreference).EnableControlledFolderAccess
        New-State ($value -eq 1) @("EnableControlledFolderAccess = $value (0 = disabled, 1 = enabled, 2 = audit)")
    }
    Relevance = {
        param($c)
        if (-not $ctx.DefenderActive) { return New-Relevance NotRelevant 'Requires Microsoft Defender Antivirus as the active antivirus.' }
        if ($ctx.IsServer) { return New-Relevance NotRelevant 'Designed for user data on workstations.' }
        New-Relevance Optional 'Effective against ransomware, but often blocks legitimate applications: start in audit mode.'
    }
    Apply = {
        param($c)
        $mode = Read-Choice '  Mode: E = enabled, A = audit only' @('E', 'A') 'A'
        Add-JournalEntry @{ Type = 'MpPreference'; Name = 'EnableControlledFolderAccess'; OldValue = [int](Get-MpPreference).EnableControlledFolderAccess }
        Set-MpPreference -EnableControlledFolderAccess $(if ($mode -eq 'E') { 'Enabled' } else { 'AuditMode' })
    }
}

$runAsPplValue = if ($ctx.Build -ge 22621) { 2 } else { 1 }
Add-RegistryCorrection @{
    Id = 'O07'; Category = $catSystem; Reference = 'Microsoft Learn - Configure added LSA protection'
    Title = "LSA protection: run LSASS as a protected process (RunAsPPL = $runAsPplValue)"
    Impact = 'Third-party LSA plug-ins (smart card, password filters, old security software) must be signed by Microsoft; check CodeIntegrity events 3033/3063 if a component no longer loads. Restart required.'
    RebootRequired = $true
    Settings = @(New-RegSetting $lsaPath 'RunAsPPL' $runAsPplValue -Check { param($v, $s) $v -in 1, 2 })
    Relevance = { param($c) New-Relevance Recommended 'Prevents non-protected processes (Mimikatz...) from reading LSASS memory.' }
}

Add-RegistryCorrection @{
    Id = 'O08'; Category = $catSystem; Reference = 'Microsoft Security Baseline - WDigest Authentication'
    Title = 'Disable WDigest clear-text credential caching (UseLogonCredential = 0)'
    Impact = 'None on supported systems (WDigest authentication is obsolete).'
    Settings = @(New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0)
    Relevance = { param($c) New-Relevance Recommended 'Explicitly prevents clear-text passwords from being kept in LSASS memory.' }
}

$cachedLogonsTarget = if ($ctx.IsServer) { 0 } elseif ($ctx.IsLaptop) { 2 } else { 1 }
Add-RegistryCorrection @{
    Id = 'O09'; Category = $catSystem; Reference = 'ANSSI AD administration guide; CIS Benchmark - Interactive logon: Number of previous logons to cache'
    Title = "Limit cached domain credentials (CachedLogonsCount = $cachedLogonsTarget)"
    Impact = "If no domain controller is reachable, only the last $cachedLogonsTarget user(s) can log on$(if ($cachedLogonsTarget -eq 0) { ' (nobody with a domain account)' })."
    Settings = @(New-RegSetting 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' "$cachedLogonsTarget" 'String' -Check { param($v, $s) [int]$v -le [int]$s.Value })
    Relevance = {
        param($c)
        if (-not $ctx.DomainJoined) { return New-Relevance NotRelevant 'Only domain accounts are cached: no effect on a computer that is not joined to an AD domain.' }
        if ($ctx.IsDomainController) { return New-Relevance NotRelevant 'Not applicable to domain controllers.' }
        New-Relevance Recommended 'Cached credentials can be extracted and cracked to escalate privileges in the domain.'
    }
}

Add-Correction @{
    Id = 'O10'; Category = $catSystem; Reference = 'Microsoft Learn - Configure Credential Guard'
    Title = 'Enable Credential Guard (virtualization-based isolation of secrets)'
    Impact = 'Enables Hyper-V-based security: VirtualBox / VMware run on top of Hyper-V with reduced performance; NTLMv1, unconstrained Kerberos delegation and saved credentials for NTLM/CredSSP stop working. Restart required.'
    RebootRequired = $true
    Test = {
        param($c)
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        $running = [bool]($dg -and (@($dg.SecurityServicesRunning) -contains 1))
        New-State $running @(
            "Credential Guard running: $running",
            "Configured: LsaCfgFlags = $(Get-RegValue $lsaPath 'LsaCfgFlags'), EnableVirtualizationBasedSecurity = $(Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity')"
        )
    }
    Relevance = {
        param($c)
        if ($ctx.IsDomainController) { return New-Relevance NotRelevant 'Credential Guard does not protect the AD database and is not supported on domain controllers.' }
        if (-not $ctx.IsEnterpriseEdition) { return New-Relevance NotRelevant "Requires the Enterprise, Education or Server edition (current: $($ctx.Edition))." }
        if (-not $ctx.VbsCapable -or -not $ctx.SecureBoot) { return New-Relevance NotRelevant 'Hardware prerequisites missing (virtualization support, UEFI Secure Boot, TPM).' }
        if ($ctx.HypervisorApps.Count -gt 0) { return New-Relevance Optional "Hypervisors detected ($($ctx.HypervisorApps -join ', ')): they will run on top of Hyper-V with reduced performance." }
        if ($ctx.DomainJoined) { return New-Relevance Recommended 'Protects NTLM hashes and Kerberos tickets of domain accounts against extraction.' }
        New-Relevance Optional 'Mainly protects domain credentials; limited benefit on a standalone computer.'
    }
    Apply = {
        param($c)
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 1
        # 2 = enabled without UEFI lock (can be disabled later without physical access)
        Set-RegValue $lsaPath 'LsaCfgFlags' 2
    }
}

Add-Correction @{
    Id = 'O11'; Category = $catSystem; Reference = 'Microsoft Learn - Enable memory integrity'
    Title = 'Enable Memory integrity (HVCI - hypervisor-protected code integrity)'
    Impact = 'Incompatible (old) drivers are blocked: check Windows Security > Device security > Core isolation before enabling. Hypervisors such as VirtualBox / VMware run on top of Hyper-V. Restart required.'
    RebootRequired = $true
    Test = {
        param($c)
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        $running = [bool]($dg -and (@($dg.SecurityServicesRunning) -contains 2))
        New-State $running @("Memory integrity (HVCI) running: $running")
    }
    Relevance = {
        param($c)
        if (-not $ctx.VbsCapable) { return New-Relevance NotRelevant 'Virtualization-based security is not available on this hardware.' }
        if ($ctx.HypervisorApps.Count -gt 0) { return New-Relevance Optional "Hypervisors detected ($($ctx.HypervisorApps -join ', ')): they will run on top of Hyper-V with reduced performance." }
        New-Relevance Recommended 'Prevents malicious or vulnerable drivers from running unsigned code in the kernel.'
    }
    Apply = {
        param($c)
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 1
        Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1
    }
}

Add-Correction @{
    Id = 'O12'; Category = $catSystem; Reference = 'Microsoft Learn - Application Control for Windows'
    Title = 'Application control (AppLocker or App Control for Business / WDAC)'
    Test = {
        param($c)
        New-State ($ctx.AppLockerConfigured -or $ctx.WdacEnforced) @("AppLocker rules configured: $($ctx.AppLockerConfigured)", "User-mode code integrity policy enforced (WDAC / Smart App Control): $($ctx.WdacEnforced)")
    }
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Only approved applications and scripts can run; PowerShell switches to Constrained Language Mode automatically.' }
        New-Relevance Optional 'On a personal computer, Smart App Control (Windows 11) is the simpler alternative.'
    }
    Guidance = @'
A policy must be designed for each environment, it cannot be generated blindly:
 - AppLocker: set the Application Identity service (AppIDSvc) to Automatic, create the default rules
   (secpol.msc > Application Control Policies), add publisher rules, run in "Audit only" mode,
   review the AppLocker event logs, then enforce. Default rules do not cover DLLs and allow C:\Windows and Program Files.
 - App Control for Business (WDAC): build a policy with the "App Control Policy Wizard", deploy it in audit mode,
   then in enforced mode (Intune, GPO or CiTool.exe).
'@
}

Add-Correction @{
    Id = 'O13'; Category = $catSystem; Reference = 'Microsoft Learn - Software Restriction Policies (deprecated)'
    Title = 'Software Restriction Policies (deprecated): migrate to AppLocker / App Control'
    Test = {
        param($c)
        $configured = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\{' }) -or
            ($null -ne (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers' 'DefaultLevel'))
        New-State (-not $configured) @("SRP configured: $configured")
    }
    Relevance = { param($c) New-Relevance Recommended 'SRP is deprecated and easy to bypass.' }
    Guidance = 'Re-create the SRP rules as AppLocker or App Control rules (see O12), test them, then remove the SRP policy.'
}

if ($ctx.IsWorkstation -and $ctx.Build -ge 22621) {
    Add-Correction @{
        Id = 'O14'; Category = $catSystem; Reference = 'Microsoft Learn - Smart App Control'
        Title = 'Smart App Control'
        Test = {
            param($c)
            $value = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
            New-State ($value -eq 1) @("VerifiedAndReputablePolicyState = $value (0 = off, 1 = on, 2 = evaluation)")
        }
        Relevance = {
            param($c)
            if ($ctx.Managed) { return New-Relevance NotRelevant 'Managed devices should use App Control for Business / AppLocker instead.' }
            $value = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
            if ($value -eq 2) { return New-Relevance Optional 'Evaluation mode: Windows decides automatically whether to turn it on; leave it as is.' }
            New-Relevance Optional 'Smart App Control is off: on most Windows 11 builds it can only be turned on again by reinstalling Windows.'
        }
        Guidance = 'Windows Security > App & browser control > Smart App Control settings (cannot be safely automated by a script).'
    }
}

Add-Correction @{
    Id = 'O15'; Category = $catSystem; Reference = 'Microsoft Learn - about_Language_Modes'
    Title = 'PowerShell Constrained Language Mode'
    Test = {
        param($c)
        $lockdown = [Environment]::GetEnvironmentVariable('__PSLockdownPolicy', 'Machine')
        New-State ($ctx.WdacEnforced -or $ctx.AppLockerConfigured) @("Enforced through WDAC / AppLocker: $($ctx.WdacEnforced -or $ctx.AppLockerConfigured)", "__PSLockdownPolicy (machine) = $(if ($lockdown) { $lockdown } else { 'not defined' })")
    }
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Enforced automatically by an App Control / AppLocker script policy (see O12).' }
        New-Relevance Optional 'Breaks many administration scripts; only meaningful together with application control.'
    }
    Guidance = @'
Do not rely on the __PSLockdownPolicy environment variable: it is not a security boundary (easily bypassed)
and it also restricts administrators. Constrained Language Mode is reliably enforced by an
App Control for Business (WDAC) or AppLocker policy that includes script rules (see O12).
'@
}

if ($ctx.IsServer) {
    Add-Correction @{
        Id = 'O16'; Category = $catSystem; Reference = 'Microsoft Learn - What is the Server Core installation option'
        Title = 'Server Core installation (no graphical interface)'
        Test = {
            param($c)
            $gui = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels' 'Server-Gui-Shell') -eq 1
            New-State (-not $gui) @("Graphical shell installed: $gui")
        }
        Relevance = { param($c) New-Relevance Optional 'Server Core reduces the attack surface and the number of patches.' }
        Guidance = 'Since Windows Server 2016 the GUI cannot be removed: plan Server Core for the next (re)installation of this server.'
    }
}

#endregion

#region Corrections - devices

$explorerPolicy = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
Add-RegistryCorrection @{
    Id = 'D01'; Category = $catDevices; Reference = 'CIS Benchmark - AutoPlay Policies'
    Title = 'Disable AutoRun / AutoPlay on all drive types'
    Impact = 'Inserted media no longer start anything automatically. HKCU applies to the account running this script.'
    Settings = @(
        New-RegSetting "HKLM:\$explorerPolicy" 'NoDriveTypeAutoRun' 255 -Check { param($v, $s) ($v -band 0xFF) -eq 0xFF }
        New-RegSetting "HKCU:\$explorerPolicy" 'NoDriveTypeAutoRun' 255 -Check { param($v, $s) ($v -band 0xFF) -eq 0xFF }
        New-RegSetting "HKLM:\$explorerPolicy" 'NoAutorun' 1
    )
    Relevance = { param($c) New-Relevance Recommended 'Removable media can automatically run malicious code.' }
}

Add-Correction @{
    Id = 'D02'; Category = $catDevices; Reference = 'Microsoft Learn - BitLocker countermeasures (pre-boot authentication)'
    Title = 'BitLocker encryption of the system drive with TPM + PIN'
    Impact = 'A PIN is required at every startup. Encryption runs in the background after the restart (hardware test). BitLocker changes are NOT reverted by -Restore. KEEP THE RECOVERY KEY.'
    RebootRequired = $true
    Test = {
        param($c)
        if (-not $ctx.BitLockerAvailable) { return New-State $false @('BitLocker is not available on this system.') }
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if (-not $vol) { return New-State $false @('Unable to read the BitLocker status of the system drive.') }
        $types = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
        $ok = ("$($vol.ProtectionStatus)" -eq 'On') -and (($types -contains 'TpmPin') -or ($types -contains 'TpmPinStartupKey'))
        New-State $ok @(
            "$($env:SystemDrive) volume status: $($vol.VolumeStatus) ($($vol.EncryptionPercentage)%), method: $($vol.EncryptionMethod), protection: $($vol.ProtectionStatus)",
            "Key protectors: $(if ($types) { $types -join ', ' } else { 'none' }) (target: TpmPin + RecoveryPassword)"
        )
    }
    Relevance = {
        param($c)
        if (-not $ctx.BitLockerAvailable) { return New-Relevance NotRelevant "BitLocker is not available on the $($ctx.Edition) edition (use Device Encryption or VeraCrypt)." }
        if ($ctx.IsVirtualMachine) { return New-Relevance Optional 'Virtual machine: the disks may already be encrypted by the hypervisor; a virtual TPM is required.' }
        if (-not $ctx.TpmReady) { return New-Relevance Optional 'No usable TPM: BitLocker would need a USB startup key or a password (manual configuration).' }
        if ($ctx.IsLaptop) { return New-Relevance Recommended 'Laptop: protects the data if it is lost or stolen; the PIN protects against TPM bypass attacks.' }
        if ($ctx.IsServer) { return New-Relevance Optional 'A PIN at every startup is hard to manage on a server (remote restarts).' }
        New-Relevance Recommended 'Protects the data against physical access.'
    }
    Apply = {
        param($c)
        if (-not $ctx.TpmReady) { throw 'TPM not present or not ready: configure BitLocker manually.' }
        $mountPoint = $env:SystemDrive
        # Allow TPM + PIN at startup ("Require additional authentication at startup" policy)
        $fve = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Set-RegValue $fve 'UseAdvancedStartup' 1
        Set-RegValue $fve 'EnableBDEWithNoTPM' 0
        Set-RegValue $fve 'UseTPM' 2
        Set-RegValue $fve 'UseTPMPIN' 2
        Set-RegValue $fve 'UseTPMKey' 2
        Set-RegValue $fve 'UseTPMKeyPIN' 2
        $pin = Read-BitLockerPin

        $vol = Get-BitLockerVolume -MountPoint $mountPoint
        $recovery = $vol.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'RecoveryPassword' } | Select-Object -First 1
        if (-not $recovery) {
            $vol = Add-BitLockerKeyProtector -MountPoint $mountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction Stop
            $recovery = $vol.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'RecoveryPassword' } | Select-Object -First 1
        }
        Save-RecoveryKey $recovery

        if ("$($vol.VolumeStatus)" -eq 'FullyDecrypted') {
            Enable-BitLocker -MountPoint $mountPoint -EncryptionMethod XtsAes256 -TpmAndPinProtector -Pin $pin -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        } else {
            # Already encrypted with TPM only: replace the TPM protector with a TPM + PIN protector
            $tpm = $vol.KeyProtector | Where-Object { "$($_.KeyProtectorType)" -eq 'Tpm' } | Select-Object -First 1
            if ($tpm) { Remove-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $tpm.KeyProtectorId -ErrorAction Stop | Out-Null }
            try {
                Add-BitLockerKeyProtector -MountPoint $mountPoint -TpmAndPinProtector -Pin $pin -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            } catch {
                if ($tpm) { Add-BitLockerKeyProtector -MountPoint $mountPoint -TpmProtector -WarningAction SilentlyContinue | Out-Null }
                throw
            }
            if ("$((Get-BitLockerVolume -MountPoint $mountPoint).ProtectionStatus)" -eq 'Off') { Resume-BitLocker -MountPoint $mountPoint | Out-Null }
        }
        Write-Host '  The PIN will be requested at the next startup.' -ForegroundColor Yellow
    }
}

Add-Correction @{
    Id = 'D03'; Category = $catDevices; Reference = 'ANSSI hardware configuration recommendations for x86 clients and servers'
    Title = 'BIOS / UEFI configuration (physical access required)'
    Test = { param($c) New-State $false @("UEFI Secure Boot enabled: $($ctx.SecureBoot)", 'The BIOS password and boot order cannot be verified from Windows.') }
    Relevance = {
        param($c)
        if ($ctx.IsVirtualMachine) { return New-Relevance NotRelevant 'Virtual machine: firmware settings are managed by the hypervisor.' }
        New-Relevance Recommended 'Without a firmware password, anyone with physical access can boot another system and bypass Windows protections.'
    }
    Guidance = @'
In the BIOS / UEFI setup: set an administrator (supervisor) password, enable Secure Boot,
disable booting from USB / network / optical drives (or put the internal disk first and lock the order),
and disable USB ports if they are not needed.
'@
}

#endregion

#region Corrections - updates

Add-RegistryCorrection @{
    Id = 'U01'; Category = $catUpdates; Reference = 'Microsoft Learn - Manage additional Windows Update settings'
    Title = 'Automatic updates must not be disabled (NoAutoUpdate = 0)'
    Impact = 'Windows Update downloads and installs updates automatically again.'
    Settings = @(New-RegSetting "$polWin\WindowsUpdate\AU" 'NoAutoUpdate' 0 -AbsentOk)
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Optional 'Updates may be deployed by WSUS / ConfigMgr / Intune: check with the management team.' }
        New-Relevance Recommended 'Missing patches are the main entry point of ransomware.'
    }
}

Add-Correction @{
    Id = 'U02'; Category = $catUpdates; Reference = 'Microsoft Learn - Secure WSUS with the Secure Sockets Layer protocol'
    Title = 'WSUS server reached over HTTPS'
    Test = {
        param($c)
        $server = Get-RegValue "$polWin\WindowsUpdate" 'WUServer'
        if (-not $server) { return New-State $true @('No WSUS server configured.') }
        New-State ($server -like 'https://*') @("WUServer = $server")
    }
    Relevance = { param($c) New-Relevance Recommended 'Over HTTP, a man-in-the-middle attacker can push malicious updates (WSUSpect).' }
    Guidance = 'Configure SSL on the WSUS server (port 8531), then update the GPO "Specify intranet Microsoft update service location" with the https:// URL.'
}

Add-Correction @{
    Id = 'U03'; Category = $catUpdates; Reference = 'Microsoft Learn - Windows release health'
    Title = 'Patch level: recent updates installed and no pending restart'
    Test = {
        param($c)
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $uptimeDays = [int]((Get-Date) - $os.LastBootUpTime).TotalDays
        $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        $lastHotfix = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $hotfixDays = if ($lastHotfix) { [int]((Get-Date) - $lastHotfix.InstalledOn).TotalDays } else { 9999 }
        New-State (($uptimeDays -le 30) -and (-not $pending) -and ($hotfixDays -le 45)) @(
            "Build: $($ctx.Build).$($ctx.UBR)",
            "Last restart: $($os.LastBootUpTime) ($uptimeDays day(s) ago)",
            "Restart pending: $pending",
            "Last update installed: $(if ($lastHotfix) { "$($lastHotfix.HotFixID) on $($lastHotfix.InstalledOn.ToShortDateString()) ($hotfixDays day(s) ago)" } else { 'unknown' })"
        )
    }
    Relevance = { param($c) New-Relevance Recommended 'Monthly security updates must be installed and the machine restarted.' }
    Guidance = 'Settings > Windows Update > Check for updates, install them and restart. Compare the build number with the Windows release health pages.'
}

#endregion

#region Corrections - logging

$auditCategories = [ordered]@{
    '{69979848-797A-11D9-BED3-505054503030}' = 'System'
    '{69979849-797A-11D9-BED3-505054503030}' = 'Logon/Logoff'
    '{6997984C-797A-11D9-BED3-505054503030}' = 'Detailed Tracking'
    '{6997984D-797A-11D9-BED3-505054503030}' = 'Policy Change'
    '{6997984E-797A-11D9-BED3-505054503030}' = 'Account Management'
    '{69979850-797A-11D9-BED3-505054503030}' = 'Account Logon'
}
if ($ctx.IsDomainController) { $auditCategories['{6997984F-797A-11D9-BED3-505054503030}'] = 'DS Access' }
Add-Correction @{
    Id = 'L01'; Category = $catLogging; Reference = 'Microsoft Learn - Audit policy recommendations; ANSSI Windows logging recommendations'
    Title = 'Advanced audit policy (success and failure) and process command lines'
    Impact = 'More events in the Security log (see L02). Process command lines may contain secrets passed as arguments.'
    Data = @{ Categories = $auditCategories }
    Test = {
        param($c)
        $settings = Get-AuditPolicySetting
        $allOk = $true
        $details = foreach ($guid in $c.Data.Categories.Keys) {
            $subcategories = @(Get-AuditSubcategoryGuid $guid)
            $okCount = @($subcategories | Where-Object { $settings[$_] -eq 3 }).Count
            if ($okCount -lt $subcategories.Count) { $allOk = $false }
            "$(if ($okCount -eq $subcategories.Count) { '[OK]' } else { '[KO]' }) $($c.Data.Categories[$guid]): $okCount/$($subcategories.Count) subcategories audited for success and failure"
        }
        $forceSubcategories = (Get-RegValue $lsaPath 'SCENoApplyLegacyAuditPolicy') -eq 1
        $commandLine = (Get-RegValue "$systemPolicyPath\Audit" 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
        New-State ($allOk -and $forceSubcategories -and $commandLine) (@($details) + @(
                "Force subcategory settings (SCENoApplyLegacyAuditPolicy): $forceSubcategories",
                "Include command line in process creation events: $commandLine"))
    }
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Recommended 'Deploy it by GPO (Advanced Audit Policy Configuration): local settings may be overwritten.' }
        New-Relevance Optional 'Useful for investigations; increases the Security log volume.'
    }
    Apply = {
        param($c)
        $backup = Join-Path $script:OutDir "auditpol_backup_$(Get-Date -Format 'HHmmss').csv"
        auditpol.exe /backup /file:"$backup" 2>&1 | Out-Null
        Add-JournalEntry @{ Type = 'AuditPolicy'; File = $backup }
        Set-RegValue $lsaPath 'SCENoApplyLegacyAuditPolicy' 1
        Set-RegValue "$systemPolicyPath\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1
        foreach ($guid in $c.Data.Categories.Keys) {
            auditpol.exe /set /category:"$guid" /success:enable /failure:enable 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for category $($c.Data.Categories[$guid])" }
        }
    }
}

$logTargetsKb = [ordered]@{ 'Security' = $(if ($ctx.IsServer) { 1024000 } else { 409600 }); 'Application' = 204800; 'System' = 204800 }
Add-Correction @{
    Id = 'L02'; Category = $catLogging; Reference = 'ANSSI Windows logging recommendations (journalisation des systemes Microsoft Windows)'
    Title = 'Event log maximum sizes (Security, Application, System)'
    Impact = "Disk usage up to about $([int](($logTargetsKb.Values | Measure-Object -Sum).Sum / 1024)) MB. A GPO defining the sizes takes precedence."
    Data = @{ Targets = $logTargetsKb }
    Test = {
        param($c)
        $allOk = $true
        $details = foreach ($name in $c.Data.Targets.Keys) {
            $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
            $currentKb = if ($log) { [int]($log.MaximumSizeInBytes / 1KB) } else { 0 }
            $ok = $currentKb -ge $c.Data.Targets[$name]
            if (-not $ok) { $allOk = $false }
            "$(if ($ok) { '[OK]' } else { '[KO]' }) $($name): $currentKb KB (target: $($c.Data.Targets[$name]) KB)"
        }
        New-State $allOk $details
    }
    Relevance = { param($c) New-Relevance Recommended 'Too small logs are overwritten in a few hours and make investigations impossible.' }
    Apply = {
        param($c)
        foreach ($name in $c.Data.Targets.Keys) {
            $log = Get-WinEvent -ListLog $name -ErrorAction Stop
            $targetBytes = [long]$c.Data.Targets[$name] * 1KB
            if ($log.MaximumSizeInBytes -lt $targetBytes) {
                Add-JournalEntry @{ Type = 'EventLogSize'; LogName = $name; OldSize = $log.MaximumSizeInBytes }
                wevtutil.exe sl $name /ms:$targetBytes 2>&1 | Out-Null
            }
        }
    }
}

Add-RegistryCorrection @{
    Id = 'L03'; Category = $catLogging; Reference = 'Microsoft Learn - about_Logging_Windows'
    Title = 'PowerShell Script Block Logging'
    Impact = 'Executed PowerShell code is logged in Microsoft-Windows-PowerShell/Operational (event 4104); secrets written in scripts may be logged.'
    Settings = @(New-RegSetting "$polWin\PowerShell\ScriptBlockLogging" 'EnableScriptBlockLogging' 1)
    Relevance = { param($c) New-Relevance Recommended 'Records the (de-obfuscated) PowerShell code, a key source to detect attacks.' }
}

Add-Correction @{
    Id = 'L04'; Category = $catLogging; Reference = 'Microsoft Learn - Sysmon (Sysinternals)'
    Title = 'Sysmon (detailed system activity logging)'
    Test = {
        param($c)
        $sysmon = @(Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue)
        New-State ($sysmon.Count -gt 0) @("Sysmon service: $(if ($sysmon) { $sysmon.Name -join ', ' } else { 'not found' })")
    }
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Process, network, registry and DLL events greatly improve detection, ideally collected by a SIEM.' }
        New-Relevance Optional 'Useful for advanced users who analyze their logs.'
    }
    Guidance = @'
Download Sysmon from Sysinternals (https://learn.microsoft.com/sysinternals/downloads/sysmon), check its signature,
choose a configuration (SwiftOnSecurity sysmon-config or Olaf Hartong sysmon-modular), then run:
  sysmon64.exe -accepteula -i sysmonconfig.xml
'@
}

Add-Correction @{
    Id = 'L05'; Category = $catLogging; Reference = 'Microsoft Learn - Use Windows Event Forwarding to help with intrusion detection'
    Title = 'Log centralization (Windows Event Forwarding or SIEM agent)'
    Test = {
        param($c)
        $manager = Get-ItemProperty -Path "$polWin\EventLog\EventForwarding\SubscriptionManager" -ErrorAction SilentlyContinue
        New-State ([bool]$manager) @("WEF subscription manager configured: $([bool]$manager)")
    }
    Relevance = {
        param($c)
        if ($ctx.DomainJoined) { return New-Relevance Recommended 'Logs kept outside the machine cannot be erased by an attacker and can be correlated.' }
        New-Relevance NotRelevant 'WEF needs a collector reachable through WinRM, typically in an AD domain.'
    }
    Guidance = 'Configure a WEF collector (wecutil qc), create subscriptions, then deploy the GPO "Configure target Subscription Manager" (or install the agent of your SIEM).'
}

#endregion

#region Corrections - privacy

Add-RegistryCorrection @{
    Id = 'P01'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Linguistic data collection, feedback notifications and Live Tile data collection'
    Impact = 'Windows no longer asks for feedback and no longer sends typing/inking data.'
    Settings = @(
        New-RegSetting 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput' 'AllowLinguisticDataCollection' 0
        New-RegSetting "$polWin\DataCollection" 'DoNotShowFeedbackNotifications' 1
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' 'PreventLiveTileDataCollection' 1
    )
    Relevance = { param($c) New-Relevance Recommended 'Limits data sent to Microsoft.' }
}

Add-RegistryCorrection @{
    Id = 'P02'; Category = $catPrivacy; Reference = 'Microsoft Learn - Windows Error Reporting'
    Title = 'Disable Windows Error Reporting'
    Impact = 'Crash reports are no longer sent: Microsoft can no longer suggest solutions for known problems.'
    Settings = @(
        New-RegSetting "$polWin\Windows Error Reporting" 'Disabled' 1
        New-RegSetting "$polWin\Windows Error Reporting" 'DontSendAdditionalData' 1
        New-RegSetting "$polWin\Windows Error Reporting" 'AutoApproveOSDumps' 0
    )
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Optional 'Crash reports may be used by the support team or reporting tools.' }
        New-Relevance Recommended 'Crash dumps may contain sensitive data from memory.'
    }
}

Add-RegistryCorrection @{
    Id = 'P03'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Disable the advertising ID'
    Impact = 'Applications can no longer use the advertising ID for targeted ads.'
    Settings = @(New-RegSetting "$polWin\AdvertisingInfo" 'DisabledByGroupPolicy' 1)
    Relevance = { param($c) New-Relevance Recommended 'Prevents cross-application user tracking.' }
}

Add-RegistryCorrection @{
    Id = 'P04'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Disable the Microsoft Store application (RemoveWindowsStore = 1)'
    Impact = 'The Store application is blocked. DisableStoreApps is deliberately NOT set: it would disable all Store apps (Calculator, Photos, Terminal...).'
    Settings = @(New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'RemoveWindowsStore' 1)
    Relevance = {
        param($c)
        if (-not $ctx.IsEnterpriseEdition -or $ctx.IsServer) { return New-Relevance NotRelevant 'This policy is only honored on Enterprise and Education editions.' }
        if (-not $ctx.Managed) { return New-Relevance NotRelevant 'Personal computer: the Store is used to install and update applications.' }
        New-Relevance Optional 'Relevant on administration workstations; elsewhere prefer the private Store / Company Portal.'
    }
}

Add-RegistryCorrection @{
    Id = 'P05'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Disable Cortana (including on the lock screen)'
    Impact = 'Cortana is no longer available.'
    Settings = @(
        New-RegSetting "$polWin\Windows Search" 'AllowCortana' 0
        New-RegSetting "$polWin\Windows Search" 'AllowCortanaAboveLock' 0
    )
    Relevance = { param($c) New-Relevance Recommended 'Cortana sends voice and search data to Microsoft.' }
}

Add-RegistryCorrection @{
    Id = 'P06'; Category = $catPrivacy; Reference = 'Microsoft Learn - Prevent users from syncing files with OneDrive'
    Title = 'Disable OneDrive file synchronization (DisableFileSyncNGSC = 1)'
    Impact = 'OneDrive no longer synchronizes files: data stored only in OneDrive must be accessed through the web.'
    Settings = @(New-RegSetting "$polWin\OneDrive" 'DisableFileSyncNGSC' 1)
    Relevance = {
        param($c)
        if ($ctx.IsServer) { return New-Relevance Recommended 'Cloud synchronization has no place on a server.' }
        if ($ctx.OneDriveInstalled) { return New-Relevance Optional 'OneDrive is installed: it may be used for synchronization and backup. Recommended on administration workstations.' }
        New-Relevance Recommended 'OneDrive does not seem to be used.'
    }
}

Add-RegistryCorrection @{
    Id = 'P07'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage Recall; Policy CSP - WindowsAI'
    Title = 'Disable Windows Copilot and Recall snapshots'
    Impact = 'TurnOffWindowsCopilot applies to the account running this script and only to the legacy Copilot sidebar (the new Copilot app must be uninstalled or blocked). DisableAIDataAnalysis turns off Recall snapshots.'
    Settings = @(
        New-RegSetting 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
        New-RegSetting "$polWin\WindowsAI" 'DisableAIDataAnalysis' 1
    )
    Relevance = {
        param($c)
        if ($ctx.Managed) { return New-Relevance Recommended 'Avoids sending corporate data to AI services that were not approved.' }
        New-Relevance Optional 'Privacy preference: Copilot and Recall process what you type and display.'
    }
}

Add-RegistryCorrection @{
    Id = 'P08'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Disable input personalization (keyboard, voice, handwriting)'
    Impact = 'Typing suggestions and handwriting recognition no longer learn from your input.'
    Settings = @(
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' 0
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 1
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 1
    )
    Relevance = { param($c) New-Relevance Recommended 'Limits the collection of typed text and handwriting.' }
}

Add-RegistryCorrection @{
    Id = 'P09'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Windows Search: no web results and no location'
    Impact = 'The Start menu search only returns local results.'
    Settings = @(
        New-RegSetting "$polWin\Windows Search" 'DisableWebSearch' 1
        New-RegSetting "$polWin\Windows Search" 'ConnectedSearchUseWeb' 0
        New-RegSetting "$polWin\Windows Search" 'AllowSearchToUseLocation' 0
        New-RegSetting "$polWin\Windows Search" 'ConnectedSearchPrivacy' 3
    )
    Relevance = { param($c) New-Relevance Recommended 'Local searches (file names...) are no longer sent to Bing.' }
}

$geoSettings = @(
    New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation' 'PolicyDisableGeolocation' 1
    New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'DefaultGeolocationSetting' 2
)
if ($ctx.ChromeInstalled) { $geoSettings += New-RegSetting 'HKLM:\SOFTWARE\Policies\Google\Chrome' 'DefaultGeolocationSetting' 2 }
Add-RegistryCorrection @{
    Id = 'P10'; Category = $catPrivacy; Reference = 'Microsoft Edge / Chrome Enterprise policy - DefaultGeolocationSetting'
    Title = 'Browsers: deny geolocation to websites'
    Impact = 'Websites can no longer use your location (maps, weather, store locators). Edge/Chrome display "Managed by your organization".'
    Settings = $geoSettings
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Websites have no reason to locate corporate machines.' }
        New-Relevance Optional 'Privacy preference; some websites need your location.'
    }
}

Add-RegistryCorrection @{
    Id = 'P11'; Category = $catPrivacy; Reference = 'Microsoft Learn - Manage connections from Windows OS components to Microsoft services'
    Title = 'Disable the Windows location service for all users'
    Impact = 'No application can locate the device (Find my device, automatic time zone, maps, weather).'
    Settings = @(New-RegSetting 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'Deny' 'String')
    Relevance = {
        param($c)
        if ($ctx.IsLaptop) { return New-Relevance Optional 'Laptop: location is useful for "Find my device" and the automatic time zone.' }
        New-Relevance Recommended 'A fixed machine does not need location services.'
    }
}

$appPrivacySettings = @(
    'LetAppsAccessRadios', 'LetAppsAccessAccountInfo', 'LetAppsAccessCallHistory', 'LetAppsAccessTasks',
    'LetAppsAccessMessaging', 'LetAppsAccessMotion', 'LetAppsAccessEmail', 'LetAppsAccessCalendar',
    'LetAppsAccessContacts', 'LetAppsAccessPhone', 'LetAppsAccessTrustedDevices', 'LetAppsSyncWithDevices',
    'LetAppsGetDiagnosticInfo', 'LetAppsActivateWithVoiceAboveLock'
) | ForEach-Object { New-RegSetting "$polWin\AppPrivacy" $_ 2 }
Add-RegistryCorrection @{
    Id = 'P12'; Category = $catPrivacy; Reference = 'Microsoft Learn - Policy CSP - Privacy (LetApps* policies)'
    Title = 'App privacy: force deny of non-essential capabilities for Store apps'
    Impact = 'Store apps (Mail, Calendar, People, Phone Link...) lose access to these data. Camera, microphone, location and notifications stay under user control (new Teams is a Store app).'
    Settings = $appPrivacySettings
    Relevance = {
        param($c)
        if ($ctx.Managed -or $ctx.IsServer) { return New-Relevance Recommended 'Applications get no access to personal data they do not need.' }
        New-Relevance Optional 'Privacy preference: built-in Mail/Calendar/People apps would no longer work.'
    }
}

#endregion

#region Main - execution

if (-not $ReportOnly -and $ctx.IsWorkstation) {
    Write-Host ''
    if ((Read-Choice 'Create a System Restore point before applying changes? (System Restore is enabled on the system drive if needed)' @('Y', 'N') 'Y') -eq 'Y') {
        try {
            Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
            Checkpoint-Computer -Description 'Before hardeningScript.ps1' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction Continue
            Write-Host 'Restore point created (Windows creates at most one restore point every 24 hours).' -ForegroundColor Green
        } catch {
            Write-Warning "Unable to create a restore point: $($_.Exception.Message)"
        }
    }
}

Write-Title "Checks and corrections ($($script:Corrections.Count))"
Write-Host '  For each item: current state, relevance for this machine, impact, then confirmation.'
Write-Host '  Press Enter to accept the default answer (marked with *). Default is Yes only for RECOMMENDED corrections.'
foreach ($correction in $script:Corrections) {
    if ($script:QuitRequested) { Add-Result $correction '-' 'Skipped (quit)'; continue }
    Invoke-Correction $correction
}

Write-Title 'Summary'
$script:Results | Format-Table -Property Id, Relevance, Status, Title -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$script:Results | Group-Object -Property { $_.Status -replace '\s*\(.*$', '' -replace ':.*$', '' } | Sort-Object Name |
    ForEach-Object { Write-Host ("  {0,-14}: {1}" -f $_.Name, $_.Count) }
$summaryFile = Join-Path $script:OutDir 'summary.csv'
$script:Results | Export-Csv -LiteralPath $summaryFile -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Summary         : $summaryFile"
Write-Host "Transcript      : $script:TranscriptFile"
if ($script:Journal.Count -gt 0) {
    Write-Host "Rollback journal: $script:JournalFile ($($script:Journal.Count) change(s))"
    Write-Host "To revert       : powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Restore `"$script:JournalFile`""
}

if ($script:RebootNeeded) {
    Write-Host ''
    Write-Host 'Some changes require a restart to take effect.' -ForegroundColor Yellow
    if ((Read-Choice 'Restart now?' @('Y', 'N') 'N') -eq 'Y') {
        Stop-Transcript | Out-Null
        Restart-Computer -Force
        return
    }
}
Stop-Transcript | Out-Null

#endregion
