#  Lab 02  Network Traffic Analysis with Wireshark & Nmap

**Analyst:** Andre Wesley  
**Date:** June 2026  
**Duration:** ~2.5 hours  
**Difficulty:**  Intermediate  
**MITRE Tactic:** TA0011  Command and Control (C2)  

---

##  Objective

Capture and analyze live network traffic to identify suspicious patterns, detect potential C2 communication, and document findings using industry-standard methodology. Perform host discovery and port scanning with Nmap to build a network inventory and identify exposed services.

---

##  Environment

| Component | Details |
|---|---|
| Capture Tool | Wireshark 4.x |
| Scanning Tool | Nmap 7.94 |
| Test Network | Isolated lab VM network (192.168.56.0/24) |
| OS | Kali Linux 2024 |

---

##  Methodology

### Phase 1: Host Discovery with Nmap

```bash
# Discover live hosts on the subnet
nmap -sn 192.168.56.0/24 -oN host-discovery.txt

# Full port scan on identified hosts
nmap -sV -sC -O -p- 192.168.56.101 -oN full-scan-101.txt

# Check for common vulnerabilities
nmap --script vuln 192.168.56.101
```

**Hosts Discovered:**

| IP Address | Hostname | Open Ports | OS Guess |
|---|---|---|---|
| 192.168.56.1 | gateway | 22, 80 | Linux |
| 192.168.56.101 | victim-win10 | 135, 139, 445, 3389 | Windows 10 |
| 192.168.56.102 | attacker-kali | 22 | Linux |

### Phase 2: Wireshark Traffic Analysis

**Key Wireshark Filters Used:**

```wireshark
# Show only HTTP traffic
http

# Filter by IP address
ip.addr == 192.168.56.101

# Detect beaconing  regular intervals to same IP
ip.dst == 10.10.10.55 && tcp.flags.syn == 1

# DNS queries (potential tunneling)
dns && ip.src == 192.168.56.101

# Large data transfers (exfiltration indicator)
http.request.method == "POST" && http.content_length > 10000
```

### Phase 3: C2 Beaconing Detection

**Findings from PCAP analysis:**

Identified regular 60-second interval connections from `192.168.56.101` to external IP `45.33.32.156`:

```
Frame 1024:  10:15:00  192.168.56.101 -> 45.33.32.156  TCP SYN port 4444
Frame 1187:  10:16:00  192.168.56.101 -> 45.33.32.156  TCP SYN port 4444
Frame 1350:  10:17:00  192.168.56.101 -> 45.33.32.156  TCP SYN port 4444
```

**Beaconing Indicators:**
- Consistent 60-second jitter (> 2s variance)  automated, not human
- Non-standard port 4444 (common Metasploit default)
- Small payload size (~128 bytes) consistent with C2 heartbeat
- Destination IP flagged on AbuseIPDB (95/100 confidence score)

---

##  IOC Table

| Indicator | Type | Confidence | Source |
|---|---|---|---|
| 45.33.32.156 | IP Address | High | Wireshark + AbuseIPDB |
| TCP/4444 | Port | Medium | Wireshark PCAP |
| 60s beacon interval | Behavior | High | PCAP timing analysis |
| DNS query length > 60 chars | Behavior | Medium | Wireshark DNS filter |

---

##  Key Takeaways

- Nmap `-sV -sC` provides rich service version data critical for vuln assessment
- Regular beacon intervals with low jitter are a strong C2 indicator
- Port 4444 with external IP connections warrants immediate escalation
- Wireshark display filters dramatically accelerate packet analysis

---

##  References

- [Wireshark Display Filters Reference](https://wiki.wireshark.org/DisplayFilters)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [MITRE ATT&CK TA0011  Command and Control](https://attack.mitre.org/tactics/TA0011/)
