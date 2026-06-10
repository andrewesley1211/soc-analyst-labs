#  Lab 01  SIEM Setup & Log Ingestion with Splunk

**Analyst:** Andre Wesley  
**Date:** June 2026  
**Duration:** ~3 hours  
**Difficulty:**  Intermediate  
**MITRE Tactic:** TA0007  Discovery  

---

##  Objective

Configure a functional Splunk SIEM environment, ingest Windows Event Logs and Linux syslog data, build detection queries, and create an operational dashboard for real-time threat visibility.

---

##  Environment

| Component | Details |
|---|---|
| SIEM Platform | Splunk Enterprise (Free Trial / TryHackMe) |
| Log Sources | Windows Event Logs (Security, System), Linux syslog |
| Data Volume | ~50,000 events ingested |
| Index Created | `security_logs`, `windows_events` |

---

##  Step-by-Step Methodology

### Phase 1: Installation & Configuration

```bash
# Splunk installed on Ubuntu 22.04 VM
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
curl http://localhost:8000
```

**Key configurations applied:**
- Created dedicated `security_logs` index with 30-day retention
- Configured Universal Forwarder on Windows endpoint
- Set up receiving on port `9997`
- Enabled `inputs.conf` for Windows Event Log monitoring

### Phase 2: Log Ingestion

```ini
# inputs.conf on Windows Forwarder
[WinEventLog://Security]
disabled = 0
index = windows_events
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = 0
index = windows_events
sourcetype = WinEventLog:System
```

---

### Phase 3: Detection Queries (SPL)

**Query 1  Failed Login Detection (Brute Force Indicator)**

```splunk
index=windows_events EventCode=4625
| stats count by Account_Name, src_ip, Failure_Reason
| where count > 5
| sort - count
| rename Account_Name as "Target Account", count as "Failed Attempts"
```

**Query 2  New User Account Created (Privilege Escalation Watch)**

```splunk
index=windows_events EventCode=4720
| table _time, Account_Name, Subject_Account_Name, ComputerName
| sort - _time
```

**Query 3  Suspicious PowerShell Execution**

```splunk
index=windows_events EventCode=4688 CommandLine="*powershell*"
| search CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*"
| table _time, ComputerName, Account_Name, CommandLine
| sort - _time
```

---

##  Findings

| Finding | Severity | EventCode | Action Taken |
|---|---|---|---|
| 47 failed logins from single IP in 10 min |  High | 4625 | IP flagged, alert created |
| New local admin account created off-hours |  High | 4720 | Escalated for investigation |
| PowerShell with `-enc` flag executed |  Medium | 4688 | Added to watch list |
| 3 workstations with no log activity 24h |  Low | N/A | Checked agent status |

---

##  Key Takeaways

- Splunk Universal Forwarder is the most reliable method for Windows log ingestion
- EventCode `4625` alone is noisy  thresholds and time windows are essential
- PowerShell encoded commands (`-enc`) are a high-fidelity indicator of living-off-the-land attacks
- Building a dashboard early accelerates threat hunting by surfacing anomalies visually

---

##  References

- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435)
- [Windows Security Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing)
- [MITRE ATT&CK TA0007  Discovery](https://attack.mitre.org/tactics/TA0007/)
