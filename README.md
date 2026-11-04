# WindowsHardener

`hardeningScript.ps1` is an interactive PowerShell script that audits and hardens a Windows machine, based on ANSSI, CIS and Microsoft recommendations.

The script never changes anything without asking. For each security check, it:

1. shows the **current state** and skips the check if the machine is already compliant;
2. explains whether the correction is **relevant for this machine** (domain-joined or standalone, workstation or server, laptop, edition, hardware...);
3. describes the **impact** (what may stop working, whether a restart is needed);
4. asks for **confirmation** before applying anything.

Every change is recorded in a rollback journal, so it can be reverted.

> ⚠️ Hardening can break applications, remote access or legacy devices. Run the script in `-ReportOnly` mode first, and preferably test it on a non-production machine or a VM.
> 
> **Be careful with Bitlocker settings.** The script allows to automate PIN code setup, but this operation has not been thoroughly tested. It would be preferable to setup everything manually, with the Bitlocker menu.

## Requirements

- Windows 10 / 11 or Windows Server 2016 and later
- Windows PowerShell 5.1
- An elevated session (**Run as administrator**)

## Usage

```powershell
# Report only: show the state and relevance of every check, change nothing
powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1 -ReportOnly

# Interactive hardening
powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1

# Revert the changes of a previous run
powershell -ExecutionPolicy Bypass -File .\hardeningScript.ps1 -Restore .\hardening_20261103_150000\rollback.json
```

`-ExecutionPolicy Bypass` only applies to this PowerShell process; it does not change the system configuration.

### Parameters

| Parameter | Description |
|---|---|
| `-ReportOnly` | Displays states and relevance without asking or changing anything. |
| `-Restore <file>` | Reverts the changes recorded in a `rollback.json` file, newest first. |
| `-OutputDirectory <folder>` | Folder for the transcript, rollback journal and summary. Default: `hardening_<date>` next to the script. |
| `-InactivityTimeoutSecs <60-900>` | Target for the automatic session lock. Default: `600` (10 minutes). |

## How it works

### Machine context

At startup, the script detects the context used to evaluate the relevance of each correction:

- AD domain, Microsoft Entra ID or MDM (Intune) enrollment;
- workstation, member server or domain controller; laptop, desktop or virtual machine;
- Windows edition and build, TPM, Secure Boot, virtualization-based security support;
- Microsoft Defender or third-party antivirus / firewall;
- RDP status, SMB shares, physical printers, IPv6 usage;
- installed hypervisors (VirtualBox, VMware), developer tools, VPN clients, OneDrive, Chrome;
- current account (local or Microsoft account).

### Relevance levels

| Level | Meaning | Default answer |
|---|---|---|
| **RECOMMENDED** | Should be applied in this context. | Yes |
| **OPTIONAL** | Useful, but with a trade-off for this machine. | No |
| **NOTRELEVANT** | Useless or harmful here (e.g. LAPS on a personal computer). | No |

At each prompt, answer `Y` (apply), `N` (skip) or `Q` (skip all remaining checks). Pressing Enter selects the default answer, marked with `*`.

### Manual actions

Some recommendations cannot be applied safely by a script (LAPS, AppLocker/WDAC policies, BIOS settings...). For those, the script displays the state, the relevance and step-by-step guidance instead of a prompt.

## Checks

| Category | ID | Check |
|---|---|---|
| **Accounts and access** | A01 | Disable the built-in Administrator account (RID 500) |
| | A02 | Disable the Guest account |
| | A03 | Disable Autologon and remove the stored password |
| | A04 | Password and lockout policy (12 characters, complexity, lockout threshold) |
| | A05 | Remove broad groups (Everyone, Users, Domain Users...) from Administrators |
| | A06 | LAPS *(manual)* |
| | A07 | Windows Hello for Business *(manual)* |
| | A08 | Automatic session lock after inactivity |
| | A09 | User Account Control hardening |
| | A10 | UAC remote restrictions for local accounts (`LocalAccountTokenFilterPolicy`) |
| | A11 | Deny elevation requests from standard users |
| | A12 | Remove `SeDebugPrivilege` from Administrators |
| | A13 | Restrict `SeNetworkLogonRight` to Administrators and Authenticated Users |
| | A14 | Deny network logon to Guests and, on domain members, local administrators |
| | A15 | Tiering: deny network logon to Domain Admins (domain members only) |
| | A16 | Disable `AlwaysInstallElevated` |
| | A17 | Just Enough Administration *(manual)* |
| **Services and applications** | S01-S09, S11-S12 | Disable unnecessary services: AJRouter, DiagTrack, dmwappushservice, icssvc, LanmanServer, SNMPTrap, SSDPSRV, Spooler, usbcir, WebClient, AppIDSvc |
| | S10 | Disable WPAD for WinHTTP (`DisableWpad = 1`). The WinHttpAutoProxySvc service itself is left enabled: Wcmsvc, WlanSvc and iphlpsvc depend on it |
| | S13 | Quote unquoted service paths |
| | S14 | Remove weak write permissions on service executables and folders |
| | S20 | RDP server: TLS, NLA, encryption |
| | S21 | Disable RDP Restricted Admin mode on the host |
| | S22 | RDP client: require Remote Credential Guard |
| | S23 | RDP client: require a valid server certificate |
| | S24 | WinRM: no Basic/Digest, no unencrypted traffic, no RunAs |
| | S25 | Disable the WinRM service on workstations |
| | S30 | Require SMB signing |
| | S31 | Remove SMBv1 |
| | S32 | Restrict anonymous access |
| **Network** | N01 | Disable IPv6 when unused |
| | N02 | NTLMv2 only (`LmCompatibilityLevel = 5`) |
| | N03 | Do not store LM hashes |
| | N04 | Disable LLMNR |
| | N05 | `NoNameReleaseOnDemand` |
| | N06 | Disable NetBIOS over TCP/IP on all interfaces |
| | N07 | Disable mDNS |
| | N08 | Windows Firewall enabled, inbound blocked by default |
| | N09 | VPN for remote connections *(manual)* |
| **Operating system** | O01.x | Remove dangerous optional features (Telnet, TFTP, Simple TCP/IP, PowerShell 2.0) |
| | O02 | Minimum telemetry level |
| | O03 | Microsoft Defender enabled with recent signatures |
| | O04 | Attack Surface Reduction rules (block or audit mode) |
| | O05 | Network Protection |
| | O06 | Controlled Folder Access (enabled or audit mode) |
| | O07 | LSA protection (`RunAsPPL`) |
| | O08 | Disable WDigest credential caching |
| | O09 | Limit cached domain credentials |
| | O10 | Credential Guard |
| | O11 | Memory integrity (HVCI) |
| | O12 | Application control: AppLocker / App Control for Business *(manual)* |
| | O13 | Migrate deprecated Software Restriction Policies *(manual)* |
| | O14 | Smart App Control *(manual)* |
| | O15 | PowerShell Constrained Language Mode *(manual)* |
| | O16 | Server Core *(manual, servers only)* |
| **Devices** | D01 | Disable AutoRun / AutoPlay |
| | D02 | BitLocker on the system drive with TPM + PIN |
| | D03 | BIOS / UEFI configuration *(manual)* |
| **Updates** | U01 | Automatic updates not disabled |
| | U02 | WSUS over HTTPS *(manual)* |
| | U03 | Patch level and pending restart *(manual)* |
| **Logging** | L01 | Advanced audit policy and process command lines |
| | L02 | Event log maximum sizes |
| | L03 | PowerShell Script Block Logging |
| | L04 | Sysmon *(manual)* |
| | L05 | Log centralization / Windows Event Forwarding *(manual)* |
| **Privacy** | P01-P12 | Telemetry and feedback, Windows Error Reporting, advertising ID, Microsoft Store, Cortana, OneDrive, Copilot and Recall, input personalization, web search, browser geolocation, location service, app privacy |

## References

Each check displays the public reference it is based on:

- [Microsoft Learn](https://learn.microsoft.com/windows/security/) and the [Microsoft Security Baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [ANSSI guides](https://cyber.gouv.fr/publications): Active Directory administration, Windows logging, passwords, hardware configuration
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [MITRE ATT&CK](https://attack.mitre.org/) techniques for attack-oriented checks

## Output files

Each run creates a `hardening_<date>` folder containing:

| File | Content |
|---|---|
| `transcript.txt` | Full console transcript (the BitLocker recovery key is never written to it). |
| `summary.csv` | One line per check: ID, category, title, relevance and final status. |
| `rollback.json` | Previous value of every changed setting. Only created when something was changed. |
| `auditpol_backup_*.csv` | Backup of the audit policy, created before L01 is applied. |

## Rollback

The script records the previous state before each change. This covers registry values, service start types, local accounts and group members, user rights and password policy, optional features, audit policy, event log sizes, firewall profiles, file permissions, and Defender settings and ASR rules. `-Restore` replays this journal in reverse order. Restart the computer afterwards.

It can also create a **System Restore point** before the first change (workstations only).

**BitLocker is never reverted automatically.** Keep the recovery key: the script displays it, can save it to a folder outside the system drive, and backs it up to Active Directory or Entra ID when the machine is joined.

## Notes and limitations

- Settings under `HKCU` apply to the account running the script, not to all users.
- On domain-joined machines, Group Policy takes precedence and may overwrite local changes. Deploy these settings by GPO or Intune instead of running the script on each machine.
- Several changes only take effect after a restart; the script offers to restart at the end.
- Some changes can be blocked by Tamper Protection (Defender) or by protected services; they are then reported as `Failed`. The script never bypasses a refused service change through the registry.
- A service is not disabled when other services that depend on it are running or start automatically; the correction is reported as `Failed` with the list of those services.
- Commands that depend on the OS language (local group names, audit categories) use SIDs and GUIDs, so the script works on any Windows language.
