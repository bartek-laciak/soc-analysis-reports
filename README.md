# SOC Analysis Reports

Security investigation write-ups from SOC training labs: alert triage, phishing analysis, incident response, IDS detection, SIEM hunting and web log analysis. Every scenario runs in a simulated lab environment. IOCs are defanged with `[.]`.

| # | Report | Platform | MITRE ATT&CK | Verdict |
|---|--------|----------|--------------|---------|
| 1 | [SOC137 – Malicious Word macro blocked on host NicolasPRD](reports/letsdefend-soc137-blocked-word-macro/) | LetsDefend | T1204.002, T1059.005, T1059.001, T1105, T1497, T1622 | True Positive, no infection from this alert |
| 2 | [SOC138 – Malicious Excel macro on host Sofia](reports/letsdefend-soc138-malicious-excel-macro/) | LetsDefend | T1566.001, T1204.002, T1059.005, T1203, TA0011 | True Positive |
| 3 | [SOC147 – Authorized SSH scan from PentestMachine](reports/letsdefend-soc147-authorized-ssh-scan/) | LetsDefend | T1046 | False Positive |
| 4 | [Phishing Email Analysis: The Greenholt Phish](reports/thm-greenholt-phishing/) | TryHackMe | T1656, T1566.001, T1036.008 | True Positive |
| 5 | [Incident Response: Boogeyman 1](reports/thm-boogeyman-incident-response/) | TryHackMe | T1566.001, T1036, T1204.002, T1059.001, T1027, T1555.005, T1041, T1048 | True Positive |
| 6 | [Snort IDS: Detecting a Log4j Exploit Attempt](reports/thm-snort-log4j/) | TryHackMe | T1190, T1027, T1105, T1059.004 | Log4j (CVE-2021-44228) exploit attempt; execution not confirmed |
| 7 | [SIEM Triage with ELK and Splunk (ItsyBitsy & Benign)](reports/thm-siem-triage-elk-splunk/) | TryHackMe | T1197, T1105, T1053.005, T1036.010 | LOLBin downloads, escalation needed |
| 8 | [Web Log Analysis: Nikto Scan, Brute Force and PHP Code Injection](reports/bwapp-web-log-analysis/) | bWAPP lab | T1595.002, T1595.003, T1110, T1190, T1033, T1136.001 | Confirmed compromise |

Each folder contains the full report (`README.md`) and its screenshots (`images/`).
