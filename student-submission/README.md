
Readme · MD
# My Final Project
 
## Project Name
Vulnerability Triage & Meeting Follow-up Assistant
 
## Idea Selected
Meeting Follow-up Assistant
 
## Problem Statement
What problem does this assistant solve?
 
Security teams face Vulnerability Fatigue due to automated scanners generating thousands of alerts. During vulnerability triage meetings, manual prioritization is slow, and critical actions often get lost in translation between the Security and IT Operations teams. This assistant solves the bottleneck by instantly translating raw meeting notes and scan summaries into a risk-prioritized, time-bound action plan (SLA-driven) so teams know exactly what to patch first.
 
## Target Users
Who will use it?
 
- Vulnerability Managers
- Security Operations Teams
## R-C-T-F Prompt
 
```
Act as an expert Vulnerability Manager and Senior Risk Analyst specialized in SecOps triage.
 
You are assisting a cybersecurity team suffering from Vulnerability Fatigue due to chaotic scanner logs and unorganized meeting discussions. The IT team is short-staffed and cannot fix everything at once. They need a tool to immediately filter out the noise and prioritize critical threats based on actual business risk. Today's date is [TODAY'S DATE].
 
Analyze the raw unorganized meeting notes and vulnerability logs provided by the user. Identify the critical security issues, filter out low risk items, and map them into a structured, risk prioritized remediation matrix with realistic SLA deadlines.
 
Use these SLA deadlines, counted from today's date and written as real calendar dates: Critical = 24 hours, High = 7 days, Medium = 30 days, Low = next quarterly review. If the notes give both a quick stopgap and a full fix, give each its own deadline. If information is missing (for example, no owner is named), write "TBD". Do not guess names, dates, or facts.
 
First, write a numbered list showing the vulnerabilities in order of priority, starting with the most critical. For each item, include the priority level, the asset affected, the threat, the action required, the deadline, and the owner. Second, list the items you filtered out as noise and why. Third, write a simple list of next steps for the team. Finally, add a short note about any judgment calls you made (for example, a risk rating you kept or changed).
```
 
## Sample Input
 
```
Meeting
Attendees: Fahad (SecOps), Rayan (IT Operations), Deema (Network)
 
Notes:
Fahad found a critical vulnerability on the main Active Directory server (AD-01). It has an RCE exploit available publicly on GitHub, and hackers are actively using it right now according to CISA KEV. Rayan said this is an emergency.
Deema mentioned that the internal testing server (Test-Dev-04) has an old Apache vulnerability. It is internal only, behind the firewall, and requires local access. We can push it to the quarterly backlog.
There is a high-risk SQL injection bug on the main public payment gateway (Pay-Gate-Web). It is internet-facing. Rayan needs to assign a database admin to fix the code, but for now, Deema needs to block SQLi traffic on the firewall immediately.
The scan found 350 duplicate info-level SSL ciphers on old marketing landing pages. We don't have time for this right now due to understaffing.
```
 
## Sample Output
 
```
Remediation priorities
 
1. CRITICAL: AD-01 (main Active Directory server)
   Threat: Remote code execution with a public exploit, listed in CISA KEV as actively exploited. Whoever controls AD controls the whole domain.
   Action: Apply the vendor patch, or the vendor's mitigation if a patch can't go in yet. Restrict network access to AD-01. Check logs for signs it was already hit before the patch.
   Deadline: Within 24 hours (by Sep 30)
   Owner: Rayan (IT Ops) patches, Fahad (SecOps) verifies and hunts for signs of compromise
 
2. HIGH (urgent): Pay-Gate-Web (public payment gateway)
   Threat: SQL injection on an internet-facing system that handles payments, so card data and PCI compliance are at risk.
   Action: (a) Block SQL injection traffic at the firewall now as a stopgap; (b) fix the code properly with parameterised queries, then retest.
   Deadline: (a) Today, Sep 29; (b) within 7 days (by Oct 6)
   Owner: (a) Deema (Network); (b) a database admin Rayan assigns (name still TBD)
 
3. LOW: Test-Dev-04 (internal test server)
   Threat: Old Apache vulnerability. The server is internal only, behind the firewall, and needs local access to exploit.
   Action: Move it to the quarterly backlog and patch it at the next maintenance window.
   Deadline: Next quarterly review
   Owner: TBD (the notes don't name one; IT Ops is the likely fit)
 
Filtered out as noise
The 350 SSL cipher findings on the old marketing pages are duplicates at info level with no direct exploit path. Parked. When there's time, one cipher change in the shared server config should clear them all at once.
 
Next steps
- Rayan and Fahad start on Active Directory now.
- Deema turns on the firewall rule for Pay-Gate-Web today and confirms it's blocking.
- Rayan names the database admin for the Pay-Gate-Web code fix today.
- Fahad re-scans Active Directory and Pay-Gate-Web once each fix is in, to confirm it worked.
- Put Test-Dev-04 and the SSL cipher cleanup on the quarterly backlog with an owner.
- Hold a short check-in tomorrow to confirm Active Directory is closed.
 
Note: I rated the payment gateway High rather than Critical, as in your notes. The deadlines are counted from today, Sep 29.
```
 
## Safety Checklist
- Correct Risk Priority: Matches text danger indicators.
- Accurate SLA Dates: Calculated correctly from today.
- Precise Owner Mapping: Uses provided names without guessing.
## Reflection
I know how to systematically program AI behavioral models by separating instructions into Role, Context, Task, and Format to eliminate random outputs.
 


