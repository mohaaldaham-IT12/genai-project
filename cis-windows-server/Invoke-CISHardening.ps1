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

# ---------------------------------------------------------------- helpers
function Test-Value($Actual, $Op, $Expected) {
    if ($null -eq $Actual) { return $false }
    switch ($Op) {
        'eq'    { return "$Actual" -eq "$Expected" }
        'ge'    { return [int64]$Actual -ge [int64]$Expected }
        'range' { return ([int64]$Actual -ge [int64]$Expected[0]) -and ([int64]$Actual -le [int64]$Expected[1]) }
    }
}

function Get-SecPolMap {
    $f = Join-Path $env:TEMP "secpol-$stamp.inf"
    & secedit.exe /export /cfg $f /areas SECURITYPOLICY /quiet | Out-Null
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
            Expected = ($c.Expected -join '-'); Actual = if ($null -eq $actual) { '<not set>' } else { "$actual" }
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
    & secedit.exe /export /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY /quiet | Out-Null
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
    $inf = Join-Path $env:TEMP "secpol-apply-$stamp.inf"
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]') + ($failed | ForEach-Object { "$($_.Name) = $($_.Set)" }) +
             @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    $lines | Set-Content $inf -Encoding Unicode
    & secedit.exe /configure /db (Join-Path $env:TEMP "secpol-$stamp.sdb") /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
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
    & secedit.exe /configure /db (Join-Path $env:TEMP "secpol-rb-$stamp.sdb") /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY /quiet | Out-Null
    & auditpol.exe /restore /file:(Join-Path $dir 'audit.csv') | Out-Null
    Write-Host 'Rollback complete. Run gpupdate /force and re-audit; reboot recommended.'
}

# ---------------------------------------------------------------- main
if ($Mode -eq 'Rollback') { Invoke-Rollback $BackupPath; return }

$active = @($controls | Where-Object { $_.Roles -contains $Role -and $Skip -notcontains $_.Id })
if ($Role -eq 'DC') {
    Write-Warning 'DC: account/password policy (CIS-ACC-*) is domain-wide. Skipping local secedit changes; set it in the Default Domain Policy GPO.'
    $active = @($active | Where-Object { $_.Type -ne 'SecPol' })
}

$before = @(Invoke-Audit $active)
if ($Mode -eq 'Audit') { Write-Report $before 'audit'; return }

# Apply
$failedIds = @($before | Where-Object Status -eq 'Fail' | ForEach-Object Id)
$toFix = @($active | Where-Object { $failedIds -contains $_.Id })
if (-not $toFix) { Write-Host 'Nothing to remediate.'; Write-Report $before 'audit'; return }

Save-Backup $toFix | Out-Null
Set-SecPol @($toFix | Where-Object Type -eq 'SecPol')
foreach ($c in ($toFix | Where-Object Type -ne 'SecPol')) {
    try { Set-Control $c; Write-Host "Applied $($c.Id): $($c.Title)" }
    catch { Write-Warning "Failed $($c.Id): $($_.Exception.Message)" }
}
Write-Report @(Invoke-Audit $active) 'after-apply'
Write-Host 'Some settings (SMB, RDP, NTLM) need a reboot or gpupdate to fully take effect.'
