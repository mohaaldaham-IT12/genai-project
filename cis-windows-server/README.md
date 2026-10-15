# CIS Hardening – Windows Server 2016 / 2019 / 2022

تطبيق عملي لمعايير **CIS Benchmark (Level 1)** على Windows Server 2016 و2019 و2022.
سكربت واحد (`Invoke-CISHardening.ps1`) يعمل على الثلاث إصدارات (PowerShell 5.1) ويكتشف النسخة والدور (Member Server / Domain Controller) تلقائيًا.

## What it does

| Mode | Action |
|------|--------|
| `Audit` | قراءة فقط. يقارن السيرفر مع قائمة الضوابط ويصدر تقرير CSV + JSON |
| `Apply` | يأخذ نسخة احتياطية → يعالج الضوابط الفاشلة فقط → يعيد الفحص |
| `Rollback` | يسترجع الريجستري والخدمات وسياسة الأمان وسياسة الـ Audit من النسخة الاحتياطية |

Controls covered (~80 checks): password/lockout policy, NTLM/LM, SMB signing & SMBv1, anonymous access,
UAC, interactive logon, RDP (NLA/TLS), Windows Firewall profiles, AutoPlay, LLMNR, WDigest,
PowerShell logging, event-log sizes, advanced audit policy, risky services.

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

- **This is a Level 1 subset, not the full benchmark.** CIS Benchmark PDFs/Build Kits are licensed by CIS (free with registration). For an official compliance score use **CIS-CAT Pro** and map this script's IDs (`CIS-xxx-nn` are internal IDs) to the recommendation numbers of your benchmark version (2016 v3.0.0, 2019 v3.0.0 / 2022 v3.0.0 or newer – check your copy).
- **Not tested on a live Windows host from this repo's environment.** Test on a lab VM before production.
- **Domain Controllers:** password/lockout policy is domain-wide → set in the Default Domain Policy; the script skips local `secedit` changes on DCs. Several “MS only” controls are skipped on DCs. Print Spooler is only flagged on DCs.
- Things that commonly break: SMB signing required (old NAS / Linux clients), NTLMv2-only (legacy apps), RDP NLA (old RDP clients), inbound-default-block firewall (make sure your allow rules exist **before** applying – otherwise you can lock yourself out of RDP/WinRM), 15-minute inactivity lock.
- Not covered here (add per environment): User Rights Assignment, local admin rename, banner text, BitLocker, Credential Guard, AppLocker/WDAC, Defender settings, IIS/SQL-specific benchmarks, Level 2 items.
- Audit subcategories are matched by GUID, so it works on non-English Windows; verify with `auditpol /list /subcategory:* /v`.
