#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS-aligned audit / hardening / rollback for Windows Server 2016, 2019 and 2022.

.DESCRIPTION
    Mode Audit    : read-only, compares the server against the control list, writes CSV + JSON report.
    Mode Apply    : takes a backup, remediates failing controls, then re-audits.
    Mode Rollback : restores registry values, service start types, security policy and audit policy
                    from a backup folder created by Apply.

    The control list covers a Level 1 baseline subset. It is NOT the full CIS Benchmark.
    Use CIS-CAT Pro for an official score.

.EXAMPLE
    .\Invoke-CISHardening.ps1 -Mode Audit
    .\Invoke-CISHardening.ps1 -Mode Apply -Skip CIS-RDP-01,CIS-SVC-03
    .\Invoke-CISHardening.ps1 -Mode Rollback -BackupPath .\output\backup-20261015-101500
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Apply', 'Rollback')][string]$Mode = 'Audit',
    [ValidateSet('MS', 'DC')][string]$Role,
    [string]$OutputDir = (Join-Path $PSScriptRoot 'output'),
    [string]$BackupPath,
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ---------------------------------------------------------------- environment
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$osName = switch ($build) { 14393 { '2016' } 17763 { '2019' } 20348 { '2022' } default { $null } }
if (-not $osName) { Write-Warning "Build $build is not Windows Server 2016/2019/2022. Results may be unreliable." }
if (-not $Role) { $Role = if ($os.ProductType -eq 2) { 'DC' } else { 'MS' } }
Write-Host "Host: $env:COMPUTERNAME | OS: $($os.Caption) (build $build) | Role: $Role | Mode: $Mode"

# ---------------------------------------------------------------- control list
$controls = New-Object System.Collections.Generic.List[object]
$idCounter = @{ FW = 6; LOG = 12; SVC = 9 }   # groups that continue numbering from the core list
function NextId($Group) {
    $idCounter[$Group] = 1 + [int]$idCounter[$Group]
    return 'CIS-{0}-{1:00}' -f $Group, $idCounter[$Group]
}
function Add-Reg($Id, $Title, $Path, $Name, $Op, $Expected, $Set, $Roles = @('MS', 'DC'), $Kind = 'DWord') {
    $controls.Add([pscustomobject]@{ Id = $Id; Title = $Title; Type = 'Registry'; Path = $Path; Name = $Name
            Op = $Op; Expected = $Expected; Set = $Set; Roles = $Roles; Kind = $Kind })
}
function Add-Sec($Id, $Title, $Key, $Op, $Expected, $Set, $Roles = @('MS')) {
    $controls.Add([pscustomobject]@{ Id = $Id; Title = $Title; Type = 'SecPol'; Name = $Key
            Op = $Op; Expected = $Expected; Set = $Set; Roles = $Roles })
}
function Add-Audit($Id, $Title, $Guid, $Expected) {
    $controls.Add([pscustomobject]@{ Id = $Id; Title = $Title; Type = 'Audit'; Name = $Guid
            Op = 'eq'; Expected = $Expected; Set = $Expected; Roles = @('MS', 'DC') })
}
function Add-Svc($Id, $Title, $Name, $Roles = @('MS', 'DC')) {
    $controls.Add([pscustomobject]@{ Id = $Id; Title = $Title; Type = 'Service'; Name = $Name
            Op = 'eq'; Expected = 'Disabled'; Set = 'Disabled'; Roles = $Roles })
}

# Account / password policy (secedit). On a DC these are domain policy -> set via Default Domain Policy GPO.
Add-Sec 'CIS-ACC-01' 'Password history >= 24'            'PasswordHistorySize'   'ge'    24 24
Add-Sec 'CIS-ACC-02' 'Maximum password age 1-365 days'   'MaximumPasswordAge'    'range' @(1, 365) 365
Add-Sec 'CIS-ACC-03' 'Minimum password age >= 1 day'     'MinimumPasswordAge'    'ge'    1  1
Add-Sec 'CIS-ACC-04' 'Minimum password length >= 14'     'MinimumPasswordLength' 'ge'    14 14
Add-Sec 'CIS-ACC-05' 'Password complexity enabled'       'PasswordComplexity'    'eq'    1  1
Add-Sec 'CIS-ACC-06' 'Reversible encryption disabled'    'ClearTextPassword'     'eq'    0  0
Add-Sec 'CIS-ACC-07' 'Lockout duration >= 15 min'        'LockoutDuration'       'ge'    15 15
Add-Sec 'CIS-ACC-08' 'Lockout threshold 1-5 attempts'    'LockoutBadCount'       'range' @(1, 5) 5
Add-Sec 'CIS-ACC-09' 'Reset lockout counter >= 15 min'   'ResetLockoutCount'     'ge'    15 15

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$nlg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$ts  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$fw  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$el  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog'

# Network / authentication
Add-Reg 'CIS-NET-01' 'LAN Manager auth level = 5 (NTLMv2 only, refuse LM/NTLM)' $lsa 'LmCompatibilityLevel' eq 5 5
Add-Reg 'CIS-NET-02' 'Do not store LM hash'                      $lsa 'NoLMHash' eq 1 1
Add-Reg 'CIS-NET-03' 'Restrict anonymous enumeration of SAM accounts' $lsa 'RestrictAnonymousSAM' eq 1 1
Add-Reg 'CIS-NET-04' 'Restrict anonymous enumeration of shares'  $lsa 'RestrictAnonymous' eq 1 1
Add-Reg 'CIS-NET-05' 'Everyone permissions do not apply to anonymous' $lsa 'EveryoneIncludesAnonymous' eq 0 0
Add-Reg 'CIS-NET-06' 'Limit blank password use to console'       $lsa 'LimitBlankPasswordUse' eq 1 1
Add-Reg 'CIS-NET-07' 'NTLM min client session security (NTLMv2 + 128-bit)' "$lsa\MSV1_0" 'NTLMMinClientSec' eq 537395200 537395200
Add-Reg 'CIS-NET-08' 'NTLM min server session security (NTLMv2 + 128-bit)' "$lsa\MSV1_0" 'NTLMMinServerSec' eq 537395200 537395200
Add-Reg 'CIS-NET-09' 'WDigest does not keep plaintext credentials' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' eq 0 0
Add-Reg 'CIS-NET-10' 'SMB server requires signing'               $srv 'RequireSecuritySignature' eq 1 1
Add-Reg 'CIS-NET-11' 'SMB client requires signing'               $wks 'RequireSecuritySignature' eq 1 1
Add-Reg 'CIS-NET-12' 'SMB client: no plaintext password to third-party servers' $wks 'EnablePlainTextPassword' eq 0 0
Add-Reg 'CIS-NET-13' 'SMBv1 server disabled'                     $srv 'SMB1' eq 0 0
Add-Reg 'CIS-NET-14' 'Restrict null session access (MS only)'    $srv 'RestrictNullSessAccess' eq 1 1 @('MS')
Add-Reg 'CIS-NET-15' 'Secure channel: always sign or seal'       $nlg 'RequireSignOrSeal' eq 1 1
Add-Reg 'CIS-NET-16' 'Secure channel: encrypt when possible'     $nlg 'SealSecureChannel' eq 1 1
Add-Reg 'CIS-NET-17' 'Secure channel: sign when possible'        $nlg 'SignSecureChannel' eq 1 1
Add-Reg 'CIS-NET-18' 'Machine account password changes enabled'  $nlg 'DisablePasswordChange' eq 0 0
Add-Reg 'CIS-NET-19' 'Machine account password max age 1-30 days' $nlg 'MaximumPasswordAge' range @(1, 30) 30
Add-Reg 'CIS-NET-20' 'LLMNR (multicast name resolution) disabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' eq 0 0

# UAC / interactive logon
Add-Reg 'CIS-UAC-01' 'UAC enabled (Admin Approval Mode)'        $pol 'EnableLUA' eq 1 1
Add-Reg 'CIS-UAC-02' 'Built-in admin also uses Admin Approval Mode' $pol 'FilterAdministratorToken' eq 1 1
Add-Reg 'CIS-UAC-03' 'Admin elevation prompt = consent on secure desktop' $pol 'ConsentPromptBehaviorAdmin' eq 2 2
Add-Reg 'CIS-UAC-04' 'Standard users: auto-deny elevation'      $pol 'ConsentPromptBehaviorUser' eq 0 0
Add-Reg 'CIS-UAC-05' 'Elevation prompt on secure desktop'       $pol 'PromptOnSecureDesktop' eq 1 1
Add-Reg 'CIS-LOG-01' 'Do not display last signed-in user'        $pol 'DontDisplayLastUserName' eq 1 1
Add-Reg 'CIS-LOG-02' 'Machine inactivity limit 1-900 s'          $pol 'InactivityTimeoutSecs' range @(1, 900) 900
Add-Reg 'CIS-LOG-03' 'Shutdown not allowed without logon'        $pol 'ShutdownWithoutLogon' eq 0 0

# Remote Desktop
Add-Reg 'CIS-RDP-01' 'RDP requires Network Level Authentication' $ts 'UserAuthentication' eq 1 1
Add-Reg 'CIS-RDP-02' 'RDP security layer = SSL/TLS'              $ts 'SecurityLayer' eq 2 2
Add-Reg 'CIS-RDP-03' 'RDP encryption level = High'               $ts 'MinEncryptionLevel' eq 3 3
Add-Reg 'CIS-RDP-04' 'RDP always prompts for password'           $ts 'fPromptForPassword' eq 1 1

# Misc Windows components
Add-Reg 'CIS-WIN-01' 'AutoPlay disabled on all drives'           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' eq 255 255
Add-Reg 'CIS-WIN-02' 'Default AutoRun behaviour = do not execute' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' eq 1 1
Add-Reg 'CIS-WIN-03' 'Installer: AlwaysInstallElevated disabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' eq 0 0
Add-Reg 'CIS-WIN-04' 'PowerShell script block logging enabled'   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' eq 1 1
Add-Reg 'CIS-WIN-05' 'Telemetry limited to Security/Basic (0-1)' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' range @(0, 1) 1

# Event log sizes (KB)
Add-Reg 'CIS-LOG-10' 'Application log >= 32768 KB'  "$el\Application" 'MaxSize' ge 32768  32768
Add-Reg 'CIS-LOG-11' 'Security log >= 196608 KB'    "$el\Security"    'MaxSize' ge 196608 196608
Add-Reg 'CIS-LOG-12' 'System log >= 32768 KB'       "$el\System"      'MaxSize' ge 32768  32768

# Windows Firewall (Private profile policy key is named StandardProfile)
foreach ($p in @(@('DomainProfile', 'Domain', 'FW-01'), @('StandardProfile', 'Private', 'FW-02'), @('PublicProfile', 'Public', 'FW-03'))) {
    Add-Reg "CIS-$($p[2])a" "Firewall $($p[1]): enabled"                "$fw\$($p[0])" 'EnableFirewall'       eq 1 1
    Add-Reg "CIS-$($p[2])b" "Firewall $($p[1]): inbound default = block" "$fw\$($p[0])" 'DefaultInboundAction' eq 1 1
}

# Advanced audit policy (by subcategory GUID, so it works on non-English Windows)
$g = '-69AE-11D9-BED3-505054503030'
Add-Audit 'CIS-AUD-01' 'Audit Credential Validation'            "{0CCE923F$g}" 'Success and Failure'
Add-Audit 'CIS-AUD-02' 'Audit Security Group Management'        "{0CCE9237$g}" 'Success'
Add-Audit 'CIS-AUD-03' 'Audit User Account Management'          "{0CCE9235$g}" 'Success and Failure'
Add-Audit 'CIS-AUD-04' 'Audit Process Creation'                 "{0CCE922B$g}" 'Success'
Add-Audit 'CIS-AUD-05' 'Audit Account Lockout'                  "{0CCE9217$g}" 'Failure'
Add-Audit 'CIS-AUD-06' 'Audit Logoff'                           "{0CCE9216$g}" 'Success'
Add-Audit 'CIS-AUD-07' 'Audit Logon'                            "{0CCE9215$g}" 'Success and Failure'
Add-Audit 'CIS-AUD-08' 'Audit Special Logon'                    "{0CCE921B$g}" 'Success'
Add-Audit 'CIS-AUD-09' 'Audit Other Logon/Logoff Events'        "{0CCE921C$g}" 'Success and Failure'
Add-Audit 'CIS-AUD-10' 'Audit Audit Policy Change'              "{0CCE922F$g}" 'Success'
Add-Audit 'CIS-AUD-11' 'Audit Authentication Policy Change'     "{0CCE9230$g}" 'Success'
Add-Audit 'CIS-AUD-12' 'Audit Sensitive Privilege Use'          "{0CCE9228$g}" 'Success and Failure'
Add-Audit 'CIS-AUD-13' 'Audit Security State Change'            "{0CCE9210$g}" 'Success'
Add-Audit 'CIS-AUD-14' 'Audit Security System Extension'        "{0CCE9211$g}" 'Success'
Add-Audit 'CIS-AUD-15' 'Audit System Integrity'                 "{0CCE9212$g}" 'Success and Failure'

# Services that should be disabled if present
Add-Svc 'CIS-SVC-01' 'Computer Browser disabled'                'Browser'
Add-Svc 'CIS-SVC-02' 'Remote Registry disabled'                 'RemoteRegistry'
Add-Svc 'CIS-SVC-03' 'Print Spooler disabled (DC; MS if no printing role)' 'Spooler' @('DC')
Add-Svc 'CIS-SVC-04' 'Xbox Live Auth Manager disabled'          'XblAuthManager'
Add-Svc 'CIS-SVC-05' 'Xbox Live Game Save disabled'             'XblGameSave'
Add-Svc 'CIS-SVC-06' 'Geolocation Service disabled'             'lfsvc'
Add-Svc 'CIS-SVC-07' 'Downloaded Maps Manager disabled'         'MapsBroker'
Add-Svc 'CIS-SVC-08' 'SNMP Service disabled'                    'SNMP'
Add-Svc 'CIS-SVC-09' 'Microsoft FTP Service disabled'           'FTPSVC'

# ---- Extended coverage: firewall logging/notifications, event log, services, security options, user rights
foreach ($p in @(@('DomainProfile', 'Domain'), @('StandardProfile', 'Private'), @('PublicProfile', 'Public'))) {
    Add-Reg (NextId 'FW') "Firewall $($p[1]): outbound default = allow"      "$fw\$($p[0])" 'DefaultOutboundAction' eq 0 0
    Add-Reg (NextId 'FW') "Firewall $($p[1]): notifications disabled"        "$fw\$($p[0])" 'DisableNotifications' eq 1 1
    Add-Reg (NextId 'FW') "Firewall $($p[1]): log size >= 16384 KB"          "$fw\$($p[0])\Logging" 'LogFileSize' ge 16384 16384
    Add-Reg (NextId 'FW') "Firewall $($p[1]): log dropped packets"           "$fw\$($p[0])\Logging" 'LogDroppedPackets' eq 1 1
    Add-Reg (NextId 'FW') "Firewall $($p[1]): log successful connections"    "$fw\$($p[0])\Logging" 'LogSuccessfulConnections' eq 1 1
}
foreach ($k in 'AllowLocalPolicyMerge', 'AllowLocalIPsecPolicyMerge') {
    Add-Reg (NextId 'FW') "Firewall Public: $k = 0" "$fw\PublicProfile" $k eq 0 0
}
Add-Reg (NextId 'LOG') 'Setup log >= 32768 KB' "$el\Setup" 'MaxSize' ge 32768 32768

foreach ($s in 'IISADMIN', 'irmon', 'LxssManager', 'sshd', 'RpcLocator', 'RemoteAccess', 'simptcp', 'sacsvr', 'SSDPSRV',
               'upnphost', 'WMSvc', 'WMPNetworkSvc', 'icssvc', 'W3SVC', 'XboxNetApiSvc', 'MSiSCSI', 'TlntSvr') {
    Add-Svc (NextId 'SVC') "$s service disabled (skip if the role is required)" $s @('MS')
}

# Security options in [System Access]; Set = $null means manual (never auto-applied)
Add-Sec (NextId 'SA') 'Block anonymous SID/name translation'       'LSAAnonymousNameLookup' eq 0 0 @('MS', 'DC')
Add-Sec (NextId 'SA') 'Guest account disabled'                      'EnableGuestAccount'     eq 0 0 @('MS', 'DC')
Add-Sec (NextId 'SA') 'Built-in Administrator disabled (MS) [manual]' 'EnableAdminAccount'   eq 0 $null @('MS')
Add-Sec (NextId 'SA') 'Built-in Administrator renamed [manual]'     'NewAdministratorName'   ne 'Administrator' $null @('MS', 'DC')
Add-Sec (NextId 'SA') 'Built-in Guest renamed [manual]'             'NewGuestName'           ne 'Guest' $null @('MS', 'DC')
if ($build -ge 20348) {
    Add-Reg (NextId 'SA') 'Relax minimum password length limits (2022)' 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits' eq 1 1
}

# Registry-based controls. Columns: Group|Title|Path|Name|Op|Expected|Set|Roles|Kind  (Set empty = manual)
$alias = @{
    '@lsa@' = $lsa; '@pol@' = $pol; '@srv@' = $srv; '@wks@' = $wks; '@nlg@' = $nlg; '@ts@' = $ts
    '@pw@'  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    '@wd@'  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    '@wl@'  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    '@sm@'  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    '@tcp@' = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    '@pr@'  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    '@ex@'  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
}
$table = @'
SO|Force audit policy subcategory settings to override category|@lsa@|SCENoApplyLegacyAuditPolicy|eq|1|1||
SO|Do not shut down if unable to log security audits|@lsa@|CrashOnAuditFail|eq|0|0||
SO|Do not require CTRL+ALT+DEL is disabled|@pol@|DisableCAD|eq|0|0||
SO|Do not display locked user ID details (3)|@pol@|DontDisplayLockedUserId|eq|3|3||
SO|Logon message text configured [manual]|@pol@|LegalNoticeText|ne||||String
SO|Logon message title configured [manual]|@pol@|LegalNoticeCaption|ne||||String
SO|Cached logons <= 4 (MS)|@wl@|CachedLogonsCount|range|0..4|4|MS|String
SO|Prompt for password change 5-14 days before expiry|@wl@|PasswordExpiryWarning|range|5..14|14||
SO|Smart card removal: lock workstation or higher|@wl@|ScRemoveOption|range|1..3|1||String
SO|Automatic logon disabled|@wl@|AutoAdminLogon|eq|0|0||String
SO|Domain member: require strong session key|@nlg@|RequireStrongKey|eq|1|1||
SO|SMB client: sign if server agrees|@wks@|EnableSecuritySignature|eq|1|1||
SO|SMB server: sign if client agrees|@srv@|EnableSecuritySignature|eq|1|1||
SO|SMB server: idle session timeout 1-15 min|@srv@|AutoDisconnect|range|1..15|15||
SO|SMB server: disconnect when logon hours expire|@srv@|EnableForcedLogoff|eq|1|1||
SO|SMB server name hardening level >= 1 (MS)|@srv@|SmbServerNameHardeningLevel|ge|1|1|MS|
SO|Restrict remote SAM calls to Administrators (MS)|@lsa@|RestrictRemoteSAM|eq|O:BAG:BAD:(A;;RC;;;BA)|O:BAG:BAD:(A;;RC;;;BA)|MS|String
SO|Classic sharing model, no forced guest (MS)|@lsa@|ForceGuest|eq|0|0|MS|
SO|Do not store passwords for network authentication|@lsa@|DisableDomainCreds|eq|1|1||
SO|NTLM uses computer identity|@lsa@|UseMachineId|eq|1|1||
SO|NTLM: no null session fallback|@lsa@\MSV1_0|AllowNullSessionFallback|eq|0|0||
SO|Online ID (PKU2U) authentication disabled|@lsa@\pku2u|AllowOnlineID|eq|0|0||
SO|Kerberos: AES encryption types only|@pol@\Kerberos\Parameters|SupportedEncryptionTypes|eq|2147483640|2147483640||
SO|LDAP client signing >= negotiate|HKLM:\SYSTEM\CurrentControlSet\Services\LDAP|LDAPClientIntegrity|ge|1|1||
SO|LDAP server signing required (DC)|HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity|eq|2|2|DC|
SO|Netlogon full secure channel protection (DC)|@nlg@|FullSecureChannelProtection|eq|1|1|DC|
SO|Case insensitivity for non-Windows subsystems|@sm@\Kernel|ObjectCaseInsensitive|eq|1|1||
SO|Strengthen default permissions of internal objects|@sm@|ProtectionMode|eq|1|1||
SO|SEHOP enabled|@sm@\kernel|DisableExceptionChainValidation|eq|0|0||
SO|Safe DLL search mode|@sm@|SafeDllSearchMode|eq|1|1||
SO|UAC: detect application installations|@pol@|EnableInstallerDetection|eq|1|1||
SO|UAC: elevate UIAccess apps only from secure locations|@pol@|EnableSecureUIAPaths|eq|1|1||
SO|UAC: virtualize file and registry write failures|@pol@|EnableVirtualization|eq|1|1||
SO|UAC: do not require signed-only executables|@pol@|ValidateAdminCodeSignatures|eq|0|0||
SO|Local account token filter policy (MS)|@pol@|LocalAccountTokenFilterPolicy|eq|0|0|MS|
SO|SMBv1 client driver disabled [manual: needs dependency change]|HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10|Start|eq|4|||
NW|IPv4 source routing disabled (highest protection)|@tcp@|DisableIPSourceRouting|eq|2|2||
NW|IPv6 source routing disabled (highest protection)|HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIPSourceRouting|eq|2|2||
NW|ICMP redirects do not override OSPF routes|@tcp@|EnableICMPRedirect|eq|0|0||
NW|Ignore NetBIOS name release requests|HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters|NoNameReleaseOnDemand|eq|1|1||
NW|Insecure guest SMB logons disabled|@pw@\LanmanWorkstation|AllowInsecureGuestAuth|eq|0|0||
NW|Font providers disabled|@pw@\System|EnableFontProviders|eq|0|0||
NW|Internet Connection Sharing prohibited|@pw@\Network Connections|NC_ShowSharedAccessUI|eq|0|0||
NW|Network Bridge prohibited|@pw@\Network Connections|NC_AllowNetBridge_NLA|eq|0|0||
NW|Domain users must elevate to set network location|@pw@\Network Connections|NC_StdDomainUserSetLocation|eq|1|1||
NW|HTTP printing disabled|@pr@|DisableHTTPPrinting|eq|1|1||
NW|Download of print drivers over HTTP disabled|@pr@|DisableWebPnPDownload|eq|1|1||
NW|Point and Print: restrict driver install to administrators|@pr@\PointAndPrint|RestrictDriverInstallationToAdministrators|eq|1|1||
NW|Point and Print: warn on install|@pr@\PointAndPrint|NoWarningNoElevationOnInstall|eq|0|0||
NW|Point and Print: warn on update|@pr@\PointAndPrint|UpdatePromptSettings|eq|0|0||
ADM|Include command line in process creation events|@pol@\Audit|ProcessCreationIncludeCmdLine_Enabled|eq|1|1||
ADM|CredSSP encryption oracle: force updated clients|@pol@\CredSSP\Parameters|AllowEncryptionOracle|eq|0|0||
ADM|Early launch drivers: good, unknown and bad-but-critical|HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch|DriverLoadPolicy|eq|3|3||
ADM|Group Policy: process even if GPOs unchanged (registry)|@pw@\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoGPOListChanges|eq|0|0||
ADM|Group Policy: background refresh allowed|@pw@\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoBackgroundPolicy|eq|0|0||
ADM|Hide account details on sign-in|@pw@\System|BlockUserFromShowingAccountDetailsOnSignin|eq|1|1||
ADM|No network selection UI at sign-in|@pw@\System|DontDisplayNetworkSelectionUI|eq|1|1||
ADM|Do not enumerate connected users|@pw@\System|DontEnumerateConnectedUsers|eq|1|1||
ADM|Do not enumerate local users on domain computers (MS)|@pw@\System|EnumerateLocalUsers|eq|0|0|MS|
ADM|No app notifications on lock screen|@pw@\System|DisableLockScreenAppNotifications|eq|1|1||
ADM|Convenience PIN sign-in disabled|@pw@\System|AllowDomainPINLogon|eq|0|0||
ADM|Require password on wake (on battery)|@pw@\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|DCSettingIndex|eq|1|1||
ADM|Require password on wake (plugged in)|@pw@\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|ACSettingIndex|eq|1|1||
ADM|Offer Remote Assistance disabled|@ts@|fAllowUnsolicited|eq|0|0||
ADM|Solicited Remote Assistance disabled|@ts@|fAllowToGetHelp|eq|0|0||
ADM|RPC endpoint mapper client authentication (MS)|HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc|EnableAuthEpResolution|eq|1|1|MS|
ADM|Restrict unauthenticated RPC clients (MS)|HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc|RestrictRemoteClients|eq|1|1|MS|
ADM|Application inventory collector disabled|@pw@\AppCompat|DisableInventory|eq|1|1||
ADM|AutoPlay off for non-volume devices|@pw@\Explorer|NoAutoplayfornonVolume|eq|1|1||
ADM|Explorer DEP not turned off|@pw@\Explorer|NoDataExecutionPrevention|eq|0|0||
ADM|Explorer heap termination on corruption not turned off|@pw@\Explorer|NoHeapTerminationOnCorruption|eq|0|0||
ADM|Shell protocol protected mode on|@ex@|PreXPSP2ShellProtocolBehavior|eq|0|0||
ADM|Order prints online wizard off|@ex@|NoOnlinePrintsWizard|eq|1|1||
ADM|Publish to web wizard off|@ex@|NoPublishingWizard|eq|1|1||
ADM|Feedback notifications off|@pw@\DataCollection|DoNotShowFeedbackNotifications|eq|1|1||
ADM|OneSettings downloads disabled|@pw@\DataCollection|DisableOneSettingsDownloads|eq|1|1||
ADM|Windows Error Reporting disabled|@pw@\Windows Error Reporting|Disabled|eq|1|1||
ADM|Customer Experience Improvement Program off|HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows|CEIPEnable|eq|0|0||
ADM|Handwriting data sharing off|@pw@\TabletPC|PreventHandwritingDataSharing|eq|1|1||
ADM|Handwriting error reports off|@pw@\HandwritingErrorReports|PreventHandwritingErrorReports|eq|1|1||
ADM|Internet Connection Wizard off|@pw@\Internet Connection Wizard|ExitOnMSICW|eq|1|1||
ADM|Registration wizard off|HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Registration Wizard Control|NoRegistration|eq|1|1||
ADM|Search Companion content updates off|HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion|DisableContentFileUpdates|eq|1|1||
ADM|Messenger CEIP off|HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client|CEIP|eq|2|2||
ADM|Do not enumerate admin accounts on elevation|HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI|EnumerateAdministrators|eq|0|0||
ADM|Password reveal button disabled|HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI|DisablePasswordReveal|eq|1|1||
ADM|No indexing of encrypted files|@pw@\Windows Search|AllowIndexingEncryptedStoresOrItems|eq|0|0||
ADM|Windows Update: no auto-restart with signed-in users|@pw@\WindowsUpdate\AU|NoAutoRebootWithLoggedOnUsers|eq|0|0||
ADM|Windows Update: automatic updates not disabled|@pw@\WindowsUpdate\AU|NoAutoUpdate|eq|0|0||
RDS|RDP: do not allow saved passwords|@ts@|DisablePasswordSaving|eq|1|1||
RDS|RDP: no drive redirection (MS)|@ts@|fDisableCdm|eq|1|1|MS|
RDS|RDP: encrypt RPC traffic|@ts@|fEncryptRPCTraffic|eq|1|1||
RDS|RDP: idle session limit <= 15 min (ms)|@ts@|MaxIdleTime|range|1..900000|900000||
RDS|RDP: disconnected session limit <= 1 min (ms)|@ts@|MaxDisconnectionTime|range|1..60000|60000||
RDS|RDP: delete temp folders on exit|@ts@|DeleteTempDirsOnExit|eq|1|1||
RDS|RDP: per-session temp folders|@ts@|PerSessionTempDir|eq|1|1||
WRM|WinRM client: Basic auth off|@pw@\WinRM\Client|AllowBasic|eq|0|0||
WRM|WinRM client: unencrypted traffic off|@pw@\WinRM\Client|AllowUnencryptedTraffic|eq|0|0||
WRM|WinRM client: Digest auth off|@pw@\WinRM\Client|AllowDigest|eq|0|0||
WRM|WinRM service: Basic auth off|@pw@\WinRM\Service|AllowBasic|eq|0|0||
WRM|WinRM service: unencrypted traffic off|@pw@\WinRM\Service|AllowUnencryptedTraffic|eq|0|0||
WRM|WinRM service: RunAs credentials not stored|@pw@\WinRM\Service|DisableRunAs|eq|1|1||
DEF|Defender: PUA protection on|@wd@|PUAProtection|eq|1|1||
DEF|Defender: MAPS local override off|@wd@\Spynet|LocalSettingOverrideSpynetReporting|eq|0|0||
DEF|Defender: real-time protection on|@wd@\Real-Time Protection|DisableRealtimeMonitoring|eq|0|0||
DEF|Defender: behavior monitoring on|@wd@\Real-Time Protection|DisableBehaviorMonitoring|eq|0|0||
DEF|Defender: scan downloads and attachments|@wd@\Real-Time Protection|DisableIOAVProtection|eq|0|0||
DEF|Defender: scan removable drives|@wd@\Scan|DisableRemovableDriveScanning|eq|0|0||
DEF|Defender: email scanning on|@wd@\Scan|DisableEmailScanning|eq|0|0||
'@
foreach ($line in ($table -split "`r?`n")) {
    if (-not $line.Trim()) { continue }
    $f = @($line -split '\|')
    while ($f.Count -lt 9) { $f += '' }
    $path = $f[2]; foreach ($a in $alias.Keys) { $path = $path.Replace($a, $alias[$a]) }
    $conv = { param($v) if ($v -match '^-?\d+$') { [int64]$v } else { $v } }
    $exp = if ($f[4] -eq 'range') { $r = $f[5] -split '\.\.'; @([int64]$r[0], [int64]$r[1]) } else { & $conv $f[5] }
    $set = if ($f[6] -eq '') { $null } else { & $conv $f[6] }
    $roles = if ($f[7]) { $f[7] -split ',' } else { @('MS', 'DC') }
    $kind = if ($f[8]) { $f[8] } else { 'DWord' }
    if ($kind -eq 'String' -and $null -ne $set) { $set = "$set" }
    Add-Reg (NextId $f[0]) $f[1] $path $f[3] $f[4] $exp $set $roles $kind
}

# User Rights Assignment. sidset = exact match, sidhas = required SIDs must be present (others are kept)
$A = 'S-1-5-32-544'; $AU = 'S-1-5-11'; $LS = 'S-1-5-19'; $NS = 'S-1-5-20'; $SV = 'S-1-5-6'; $US = 'S-1-5-32-545'
$RD = 'S-1-5-32-555'; $GU = 'S-1-5-32-546'; $ED = 'S-1-5-9'; $WDI = 'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'
function Add-UR($Name, $Title, $Sids, $Roles = @('MS', 'DC'), $Op = 'sidset') {
    $controls.Add([pscustomobject]@{ Id = (NextId 'UR'); Title = "Right $Name`: $Title"; Type = 'UserRight'; Name = $Name
            Op = $Op; Expected = @($Sids | Sort-Object -Unique); Set = $null; Roles = $Roles })
}
Add-UR SeTrustedCredManAccessPrivilege 'Access Credential Manager as trusted caller: No One' @()
Add-UR SeNetworkLogonRight 'Access this computer from the network' @($A, $AU) @('MS')
Add-UR SeNetworkLogonRight 'Access this computer from the network' @($A, $AU, $ED) @('DC')
Add-UR SeTcbPrivilege 'Act as part of the operating system: No One' @()
Add-UR SeMachineAccountPrivilege 'Add workstations to domain' @($A)
Add-UR SeIncreaseQuotaPrivilege 'Adjust memory quotas for a process' @($A, $LS, $NS)
Add-UR SeInteractiveLogonRight 'Allow log on locally' @($A) @('MS')
Add-UR SeInteractiveLogonRight 'Allow log on locally' @($A, $ED) @('DC')
Add-UR SeRemoteInteractiveLogonRight 'Allow log on through Remote Desktop' @($A, $RD) @('MS')
Add-UR SeRemoteInteractiveLogonRight 'Allow log on through Remote Desktop' @($A) @('DC')
Add-UR SeBackupPrivilege 'Back up files and directories' @($A)
Add-UR SeSystemTimePrivilege 'Change the system time' @($A, $LS)
Add-UR SeTimeZonePrivilege 'Change the time zone' @($A, $LS, $US)
Add-UR SeCreatePagefilePrivilege 'Create a pagefile' @($A)
Add-UR SeCreateTokenPrivilege 'Create a token object: No One' @()
Add-UR SeCreateGlobalPrivilege 'Create global objects' @($A, $LS, $NS, $SV)
Add-UR SeCreatePermanentPrivilege 'Create permanent shared objects: No One' @()
Add-UR SeCreateSymbolicLinkPrivilege 'Create symbolic links (Administrators must be present)' @($A) @('MS', 'DC') 'sidhas'
Add-UR SeDebugPrivilege 'Debug programs' @($A)
Add-UR SeDenyNetworkLogonRight 'Deny access from the network (Guests)' @($GU) @('MS', 'DC') 'sidhas'
Add-UR SeDenyBatchLogonRight 'Deny log on as a batch job (Guests)' @($GU) @('MS', 'DC') 'sidhas'
Add-UR SeDenyServiceLogonRight 'Deny log on as a service (Guests)' @($GU) @('MS', 'DC') 'sidhas'
Add-UR SeDenyInteractiveLogonRight 'Deny log on locally (Guests)' @($GU) @('MS', 'DC') 'sidhas'
Add-UR SeDenyRemoteInteractiveLogonRight 'Deny log on through Remote Desktop (Guests)' @($GU) @('MS', 'DC') 'sidhas'
Add-UR SeEnableDelegationPrivilege 'Enable accounts to be trusted for delegation: No One' @() @('MS')
Add-UR SeEnableDelegationPrivilege 'Enable accounts to be trusted for delegation' @($A) @('DC')
Add-UR SeRemoteShutdownPrivilege 'Force shutdown from a remote system' @($A)
Add-UR SeAuditPrivilege 'Generate security audits' @($LS, $NS)
Add-UR SeImpersonatePrivilege 'Impersonate a client after authentication' @($A, $LS, $NS, $SV)
Add-UR SeIncreaseBasePriorityPrivilege 'Increase scheduling priority (Administrators must be present)' @($A) @('MS', 'DC') 'sidhas'
Add-UR SeLoadDriverPrivilege 'Load and unload device drivers' @($A)
Add-UR SeLockMemoryPrivilege 'Lock pages in memory: No One' @()
Add-UR SeSecurityPrivilege 'Manage auditing and security log' @($A)
Add-UR SeRelabelPrivilege 'Modify an object label: No One' @()
Add-UR SeSystemEnvironmentPrivilege 'Modify firmware environment values' @($A)
Add-UR SeManageVolumePrivilege 'Perform volume maintenance tasks' @($A)
Add-UR SeProfileSingleProcessPrivilege 'Profile single process' @($A)
Add-UR SeSystemProfilePrivilege 'Profile system performance' @($A, $WDI)
Add-UR SeAssignPrimaryTokenPrivilege 'Replace a process level token' @($LS, $NS)
Add-UR SeRestorePrivilege 'Restore files and directories' @($A)
Add-UR SeShutdownPrivilege 'Shut down the system' @($A)
Add-UR SeSyncAgentPrivilege 'Synchronize directory service data: No One' @()
Add-UR SeTakeOwnershipPrivilege 'Take ownership of files or other objects' @($A)
Add-UR SeUndockPrivilege 'Remove computer from docking station' @($A)

# ---------------------------------------------------------------- helpers
function Test-Value($Actual, $Op, $Expected) {
    if ($null -eq $Actual) { return $false }
    switch ($Op) {
        'eq'    { return "$Actual" -eq "$Expected" }
        'ge'    { return [int64]$Actual -ge [int64]$Expected }
        'ne'    { return "$Actual" -ne "$Expected" }
        'range' { return ([int64]$Actual -ge [int64]$Expected[0]) -and ([int64]$Actual -le [int64]$Expected[1]) }
        'sidset' { $e = if (@($Expected).Count) { (@($Expected) -join ',') } else { 'none' }; return "$Actual" -eq $e }
        'sidhas' { $have = "$Actual" -split ','; foreach ($x in @($Expected)) { if ($have -notcontains $x) { return $false } }; return $true }
    }
}

function ConvertTo-SidList($raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $out = foreach ($t in ($raw -split ',')) {
        $t = $t.Trim().TrimStart('*')
        if (-not $t) { continue }
        if ($t -match '^S-1-') { $t }
        else { try { (New-Object Security.Principal.NTAccount($t)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $t } }
    }
    return @($out | Sort-Object -Unique)
}

function Get-SecPolMap {
    $f = Join-Path $env:TEMP "secpol-$stamp.inf"
    & secedit.exe /export /cfg $f /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    $map = @{}
    foreach ($l in Get-Content $f -Encoding Unicode) {
        if ($l -match '^\s*(\w+)\s*=\s*(.+?)\s*$') { $map[$Matches[1]] = $Matches[2].Trim('"') }
    }
    Remove-Item $f -Force -ErrorAction SilentlyContinue
    return $map
}

function Get-AuditMap {
    $map = @{}
    $rows = & auditpol.exe /get /category:* /r | ConvertFrom-Csv
    foreach ($r in $rows) { $map[$r.'Subcategory GUID'.ToLower()] = $r.'Inclusion Setting' }
    return $map
}

function Get-Actual($c, $sec, $aud) {
    switch ($c.Type) {
        'Registry' {
            try { return (Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction Stop).($c.Name) } catch { return $null }
        }
        'SecPol'  { if ($sec.ContainsKey($c.Name)) { return $sec[$c.Name] } else { return $null } }
        'UserRight' {
            $l = @(ConvertTo-SidList $sec[$c.Name])
            if ($l.Count) { return ($l -join ',') } else { return 'none' }
        }
        'Audit'   { return $aud[$c.Name.ToLower()] }
        'Service' {
            $s = Get-Service -Name $c.Name -ErrorAction SilentlyContinue
            if (-not $s) { return 'NotInstalled' }
            return [string]$s.StartType
        }
    }
}

function Invoke-Audit($list) {
    $sec = Get-SecPolMap
    $aud = Get-AuditMap
    foreach ($c in $list) {
        $actual = Get-Actual $c $sec $aud
        $pass = ($actual -eq 'NotInstalled') -or (Test-Value $actual $c.Op $c.Expected)
        [pscustomobject]@{
            Id = $c.Id; Title = $c.Title; Type = $c.Type
            Expected = $(if ($c.Op -eq 'range') { "$($c.Expected[0])..$($c.Expected[1])" } elseif ($c.Op -eq 'ne') { "not '$($c.Expected)'" } elseif ($c.Type -eq 'UserRight' -and -not @($c.Expected).Count) { 'none' } else { $c.Expected -join ',' }); Actual = if ($null -eq $actual) { '<not set>' } else { "$actual" }
            Status = if ($pass) { 'Pass' } else { 'Fail' }
        }
    }
}

function Write-Report($results, $tag) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $base = Join-Path $OutputDir "$env:COMPUTERNAME-$tag-$stamp"
    $results | Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8
    $results | ConvertTo-Json -Depth 3 | Set-Content "$base.json" -Encoding UTF8
    $pass = @($results | Where-Object Status -eq 'Pass').Count
    $total = @($results).Count
    $results | Where-Object Status -eq 'Fail' | Format-Table Id, Title, Expected, Actual -AutoSize | Out-Host
    Write-Host ("Score: {0}/{1} ({2:P0}) | report: {3}.csv" -f $pass, $total, ($pass / [math]::Max($total, 1)), $base)
}

# ---------------------------------------------------------------- backup / apply / rollback
function Save-Backup($list) {
    $dir = Join-Path $OutputDir "backup-$stamp"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $items = foreach ($c in $list) {
        if ($c.Type -eq 'Registry') {
            $v = $null; $existed = $false
            try { $v = (Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction Stop).($c.Name); $existed = $true } catch {}
            [pscustomobject]@{ Type = 'Registry'; Path = $c.Path; Name = $c.Name; Kind = $c.Kind; Existed = $existed; Value = $v }
        }
        elseif ($c.Type -eq 'Service') {
            $s = Get-Service -Name $c.Name -ErrorAction SilentlyContinue
            if ($s) { [pscustomobject]@{ Type = 'Service'; Name = $c.Name; StartType = [string]$s.StartType; Running = ($s.Status -eq 'Running') } }
        }
    }
    $items | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $dir 'state.json') -Encoding UTF8
    & secedit.exe /export /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    & auditpol.exe /backup /file:(Join-Path $dir 'audit.csv') | Out-Null
    Write-Host "Backup saved: $dir"
    return $dir
}

function Set-Control($c) {
    switch ($c.Type) {
        'Registry' {
            if (-not (Test-Path $c.Path)) { New-Item -Path $c.Path -Force | Out-Null }
            New-ItemProperty -Path $c.Path -Name $c.Name -Value $c.Set -PropertyType $c.Kind -Force | Out-Null
        }
        'Audit' {
            $s = if ($c.Set -match 'Success') { 'enable' } else { 'disable' }
            $f = if ($c.Set -match 'Failure') { 'enable' } else { 'disable' }
            & auditpol.exe /set /subcategory:$($c.Name) /success:$s /failure:$f | Out-Null
        }
        'Service' {
            Stop-Service -Name $c.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $c.Name -StartupType Disabled
        }
    }
}

function Set-SecPol($failed) {
    if (-not $failed) { return }
    $cur = Get-SecPolMap
    $sa = New-Object System.Collections.Generic.List[string]
    $ur = New-Object System.Collections.Generic.List[string]
    foreach ($c in $failed) {
        if ($c.Type -eq 'UserRight') {
            $sids = @($c.Expected)
            if ($c.Op -eq 'sidhas') { $sids = @(ConvertTo-SidList $cur[$c.Name]) + $sids }
            $sids = @($sids | Where-Object { $_ } | Sort-Object -Unique)
            $ur.Add("$($c.Name) = " + (($sids | ForEach-Object { "*$_" }) -join ','))
        }
        else { $sa.Add("$($c.Name) = $($c.Set)") }
    }
    $lines = @('[Unicode]', 'Unicode=yes')
    if ($sa.Count) { $lines += '[System Access]'; $lines += $sa }
    if ($ur.Count) { $lines += '[Privilege Rights]'; $lines += $ur }
    $lines += @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    $inf = Join-Path $env:TEMP "secpol-apply-$stamp.inf"
    $lines | Set-Content $inf -Encoding Unicode
    & secedit.exe /configure /db (Join-Path $env:TEMP "secpol-$stamp.sdb") /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    Remove-Item $inf -Force -ErrorAction SilentlyContinue
}

function Invoke-Rollback($dir) {
    if (-not $dir) {
        $dir = Get-ChildItem $OutputDir -Directory -Filter 'backup-*' -ErrorAction SilentlyContinue |
            Sort-Object Name | Select-Object -Last 1 -ExpandProperty FullName
    }
    if (-not $dir -or -not (Test-Path $dir)) { throw 'No backup folder found. Use -BackupPath.' }
    Write-Host "Rolling back from $dir"
    foreach ($i in (Get-Content (Join-Path $dir 'state.json') -Raw | ConvertFrom-Json)) {
        if ($i.Type -eq 'Registry') {
            if ($i.Existed) {
                if (-not (Test-Path $i.Path)) { New-Item -Path $i.Path -Force | Out-Null }
                New-ItemProperty -Path $i.Path -Name $i.Name -Value $i.Value -PropertyType $i.Kind -Force | Out-Null
            }
            else { Remove-ItemProperty -Path $i.Path -Name $i.Name -ErrorAction SilentlyContinue }
        }
        elseif ($i.Type -eq 'Service') {
            Set-Service -Name $i.Name -StartupType $i.StartType
            if ($i.Running) { Start-Service -Name $i.Name -ErrorAction SilentlyContinue }
        }
    }
    & secedit.exe /configure /db (Join-Path $env:TEMP "secpol-rb-$stamp.sdb") /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    & auditpol.exe /restore /file:(Join-Path $dir 'audit.csv') | Out-Null
    Write-Host 'Rollback complete. Run gpupdate /force and re-audit; reboot recommended.'
}

# ---------------------------------------------------------------- main
if ($Mode -eq 'Rollback') { Invoke-Rollback $BackupPath; return }

$active = @($controls | Where-Object { $_.Roles -contains $Role -and $Skip -notcontains $_.Id })
# On a DC, password policy and user rights come from the Default Domain (Controllers) Policy GPOs.
$localPolicyTypes = if ($Role -eq 'DC') { @('SecPol', 'UserRight') } else { @() }

$before = @(Invoke-Audit $active)
if ($Mode -eq 'Audit') { Write-Report $before 'audit'; return }

# Apply
$failedIds = @($before | Where-Object Status -eq 'Fail' | ForEach-Object Id)
$failed = @($active | Where-Object { $failedIds -contains $_.Id })
$manual = @($failed | Where-Object { $null -eq $_.Set -and $_.Type -ne 'UserRight' })
$gpoOnly = @($failed | Where-Object { $localPolicyTypes -contains $_.Type })
$toFix = @($failed | Where-Object { $manual -notcontains $_ -and $gpoOnly -notcontains $_ })
if ($manual) { Write-Warning ("Manual review needed (not auto-applied): " + (($manual | ForEach-Object Id) -join ', ')) }
if ($gpoOnly) { Write-Warning "DC: $($gpoOnly.Count) password-policy / user-right findings must be fixed in the Default Domain (Controllers) Policy GPO." }
if (-not $toFix) { Write-Host 'Nothing to remediate.'; Write-Report $before 'audit'; return }

Save-Backup $toFix | Out-Null
$polTypes = @('SecPol', 'UserRight')
Set-SecPol @($toFix | Where-Object { $polTypes -contains $_.Type })
foreach ($c in ($toFix | Where-Object { $polTypes -notcontains $_.Type })) {
    try { Set-Control $c; Write-Host "Applied $($c.Id): $($c.Title)" }
    catch { Write-Warning "Failed $($c.Id): $($_.Exception.Message)" }
}
Write-Report @(Invoke-Audit $active) 'after-apply'
Write-Host 'Some settings (SMB, RDP, NTLM) need a reboot or gpupdate to fully take effect.'
