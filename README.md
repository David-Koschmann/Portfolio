# Cyber Security Portfolio

Hands-on security work from my role as a Cyber Security Support Analyst (Vulnerability Management and SecOps) at Log(N) Pacific, and from threat hunting scenarios in its cyber range. Most of this work uses **Microsoft Sentinel, Microsoft Defender for Endpoint, KQL, Tenable and PowerShell**.

---

## 🔎 Threat Hunting and Incident Investigation

| Project | What it covers |
|---|---|
| [Operation Helpline](threat-hunts/operation-helpline) | Hybrid cloud and on-prem intrusion: stolen session cookie, stolen MFA seed, an AI helpdesk agent tricked into a password reset, ESC13 certificate abuse and DCSync. Includes MITRE ATT&CK mapping and full KQL queries. |
| [Unauthorized TOR Usage](threat-hunts/tor-browser-usage) | Hunting for TOR Browser installation and use on a workstation with Defender for Endpoint tables and KQL. |
| [Live Honeypot: MySQL Ransom Attack](https://github.com/David-Koschmann/mysql-honeypot-live-breach) | A Windows VM running MySQL, deliberately exposed to the internet. Bots wiped the databases and left a Bitcoin ransom note within hours. *(Separate repo.)* |

---

## 🛡️ Vulnerability Management

| Project | What it covers |
|---|---|
| [Vulnerability Management](vulnerability-management) | A vulnerability management program built around Tenable scanning, plus scripted remediations in PowerShell and Bash. |

---

## ⚙️ Hardening

| Project | What it covers |
|---|---|
| [STIG Remediations](stigs) | PowerShell scripts that remediate Windows 11 DISA STIG findings, with testing notes. |

---

## Tools

**Microsoft Sentinel · Defender for Endpoint · KQL · Azure · Tenable · PowerShell · Bash · MySQL**

*David Koschmann · [LinkedIn](https://www.linkedin.com/in/davidkoschmann)*
