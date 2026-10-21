# CIS Hardening – Windows Server 2016 / 2019 / 2022

تطبيق عملي لمعايير **CIS Benchmark (Level 1)** على Windows Server 2016 و2019 و2022.
سكربت واحد (`Invoke-CISHardening.ps1`) يعمل على الثلاث إصدارات (PowerShell 5.1) ويكتشف النسخة والدور (Member Server / Domain Controller) تلقائيًا.

## What it does

| Mode | Action |
|------|--------|
| `Audit` | قراءة فقط. يقارن السيرفر مع قائمة الضوابط ويصدر تقرير CSV + JSON |
| `Apply` | يأخذ نسخة احتياطية → يعالج الضوابط الفاشلة فقط → يعيد الفحص |
| `Rollback` | يسترجع الريجستري والخدمات وسياسة الأمان وسياسة الـ Audit من النسخة الاحتياطية |

Controls covered: **273 checks** (about 266 on a Member Server, 232 on a DC):

| Area | Checks |
|------|--------|
| Account / password / lockout policy, Guest/Admin account | secedit |
| **User Rights Assignment** (44) | secedit, SID-based, per role (MS / DC) |
| Security Options (NTLM, SMB, LDAP, Kerberos, UAC, logon, secure channel) | registry |
| Network (TCP/IP, SMBv1, LLMNR, printing, network bridge) | registry |
| Windows Firewall (3 profiles: state, defaults, logging, merge) | registry |
| Advanced Audit Policy (15 subcategories, by GUID) | auditpol |
| Administrative Templates (logon, RPC, AutoPlay, Explorer, telemetry, WER, CredUI, Windows Update...) | registry |
| Remote Desktop Session Host, WinRM client/service, Windows Defender | registry |
| Event log sizes, PowerShell logging | registry |
| Services to disable (26) | service |

Controls whose title ends with `[manual]` (rename Administrator/Guest, logon banner text, disable built-in Administrator,
SMBv1 client driver) are audited but never auto-applied: Apply lists them for you to handle.

## Usage

```powershell
# 1. افحص أولًا (آمن، لا يغيّر شيء)
.\Invoke-CISHardening.ps1 -Mode Audit

# 2. طبّق على سيرفر تجريبي أولًا
.\Invoke-CISHardening.ps1 -Mode Apply

# استثناء ضوابط تؤثر على خدمة عندك (مثلاً Print Server أو RDP بدون NLA)
.\Invoke-CISHardening.ps1 -Mode Apply -Skip CIS-SVC-03,CIS-RDP-01

# 3. تراجع عند الحاجة
.\Invoke-CISHardening.ps1 -Mode Rollback -BackupPath .\output\backup-<timestamp>
```

Run as Administrator. إذا السياسة تمنع السكربتات: `powershell -ExecutionPolicy Bypass -File .\Invoke-CISHardening.ps1 -Mode Audit`

## Rollout plan (recommended)

1. **Snapshot / backup** the server (and system state for DCs).
2. Run `Audit` on all servers → collect the CSVs → agree on exceptions with the app owners.
3. `Apply` on a **test** server per OS version (2016, 2019, 2022) and test applications, RDP, file shares, backup, monitoring.
4. Roll out in waves. For many servers / domain-joined, convert the same settings to **GPO** (import via Microsoft LGPO / Security Compliance Toolkit, or CIS Build Kits) instead of running the script everywhere – a GPO will override local settings anyway.
5. Re-audit monthly; track exceptions.

## Important notes

- **This covers most of Level 1 but is not a certified copy of the benchmark.** It was written from the benchmark's structure without access to the licensed document, so verify the expected values against your benchmark version before relying on a score. CIS Benchmark PDFs/Build Kits are licensed by CIS (free with registration). For an official compliance score use **CIS-CAT Pro** and map this script's IDs (`CIS-xxx-nn` are internal IDs) to the recommendation numbers of your benchmark version (2016 v3.0.0, 2019 v3.0.0 / 2022 v3.0.0 or newer – check your copy).
- **Parsed and the control list built with PowerShell 7 on Linux, but not run on a live Windows host.** Test on a lab VM before production.
- **Domain Controllers:** password/lockout policy is domain-wide → set in the Default Domain Policy; the script skips local `secedit` changes on DCs. Several “MS only” controls are skipped on DCs. Print Spooler is only flagged on DCs.
- Things that commonly break: SMB signing required (old NAS / Linux clients), NTLMv2-only (legacy apps), RDP NLA (old RDP clients), inbound-default-block firewall (make sure your allow rules exist **before** applying – otherwise you can lock yourself out of RDP/WinRM), 15-minute inactivity lock.
- Not covered (add per environment): Level 2 items, BitLocker, Credential Guard, AppLocker/WDAC, ASR rules, Hardened UNC Paths, per-feature settings (IIS, SQL, Hyper-V), and per-version differences beyond `RelaxMinimumPasswordLengthLimits` (2022).
- **User rights:** Apply replaces the assignment lists with the CIS values (e.g. only Administrators can log on locally). Service accounts, backup agents, Hyper-V (`NT VIRTUAL MACHINE\\Virtual Machines`) and IIS (`IIS_IUSRS`) may need extra entries: use `-Skip CIS-UR-xx` for those. On a DC these are fixed in the Default Domain Controllers Policy, not locally.
- **Services:** the extended list includes `W3SVC`, `WMSvc`, `MSiSCSI`, `sshd`, `RemoteAccess` and others; skip any that the server's role needs.
- Audit subcategories are matched by GUID, so it works on non-English Windows; verify with `auditpol /list /subcategory:* /v`.
