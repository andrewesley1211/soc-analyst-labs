#  Splunk SPL Query Reference Library
### Andre Chiguta  SOC Analyst Labs

---

##  Authentication & Account Events

```splunk
# Failed login attempts (brute force detection)
index=windows_events EventCode=4625
| stats count by Account_Name, src_ip, Failure_Reason
| where count > 5
| sort -count

# Successful login after multiple failures (account compromise)
index=windows_events (EventCode=4625 OR EventCode=4624)
| transaction Account_Name maxspan=10m
| where eventcount > 5
| table _time, Account_Name, src_ip, ComputerName

# New user account creation (T1136)
index=windows_events EventCode=4720
| table _time, Account_Name, Subject_Account_Name, ComputerName

# User added to privileged group (T1078)
index=windows_events EventCode=4732
| table _time, Account_Name, Group_Name, Subject_Account_Name
```

---

##  Process & Execution Events

```splunk
# Suspicious PowerShell (T1059.001)
index=windows_events EventCode=4688 CommandLine="*powershell*"
| search CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*" OR CommandLine="*iex*"
| table _time, ComputerName, Account_Name, CommandLine

# Living-off-the-land binaries (LOLBins)
index=windows_events EventCode=4688
| search Process_Name IN ("certutil.exe","mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe")
| table _time, ComputerName, Account_Name, Process_Name, CommandLine
```

---

##  Network & C2 Detection

```splunk
# High-frequency outbound connections (beaconing)
index=network_logs
| stats count, dc(dest_port) as unique_ports by src_ip, dest_ip
| where count > 100 AND unique_ports > 3
| sort -count

# DNS query length anomaly (DNS tunneling)
index=dns_logs
| eval query_length=len(query)
| where query_length > 60
| table _time, src_ip, query, query_length
| sort -query_length

# Outbound connections to rare/new destinations
index=network_logs earliest=-24h
| stats first(_time) as first_seen, count by dest_ip
| where first_seen > relative_time(now(),"-1h")
| table first_seen, dest_ip, count
```

---

##  Threat Hunting Searches

```splunk
# Scheduled task creation (T1053.005)
index=windows_events EventCode=4698
| table _time, ComputerName, Account_Name, TaskName, TaskContent

# Registry persistence (T1547.001)
index=windows_events EventCode=13
| search TargetObject="*CurrentVersion\\Run*"
| table _time, ComputerName, Account_Name, TargetObject, Details

# Volume shadow copy deletion (ransomware indicator)
index=windows_events EventCode=4688
| search CommandLine="*vssadmin*delete*" OR CommandLine="*wbadmin*delete*"
| table _time, ComputerName, Account_Name, CommandLine
```

---

##  Dashboard Queries

```splunk
# Top 10 event types (overview panel)
index=windows_events
| top limit=10 EventCode
| rename EventCode as "Event Code", count as "Occurrences"

# Events by hour (timechart panel)
index=windows_events (EventCode=4625 OR EventCode=4624 OR EventCode=4720)
| timechart span=1h count by EventCode

# Geographic source IP mapping
index=network_logs action=blocked
| iplocation src_ip
| geostats count by Country
```
