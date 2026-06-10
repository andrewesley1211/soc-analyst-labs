#  SOC Analyst Labs
### Hands-On Security Operations Center Training Portfolio

[![Labs](https://img.shields.io/badge/Labs-4%20Completed-58a6ff?style=for-the-badge)](#)
[![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Wireshark%20%7C%20Nmap-0d1b2a?style=for-the-badge)](#)
[![Focus](https://img.shields.io/badge/Focus-Threat%20Detection%20%26%20Response-red?style=for-the-badge)](#)

---

##  Overview

This repository documents my **hands-on SOC analyst training labs**  each designed to simulate real-world security events that a Tier 1/Tier 2 analyst encounters daily. Labs are structured to demonstrate detection, investigation, and response capabilities aligned with the **MITRE ATT&CK framework** and **NIST SP 800-61** incident handling guidelines.

**Target Role:** SOC Analyst (Tier 1 / Tier 2), Security Operations Engineer

---

##  Lab Index

| Lab | Title | Tools | MITRE Tactic | Difficulty |
|---|---|---|---|---|
| [Lab 01](./lab-01-splunk-siem-setup/) | SIEM Setup & Log Ingestion | Splunk | TA0007 Discovery |  Intermediate |
| [Lab 02](./lab-02-network-traffic-analysis/) | Network Traffic Analysis | Wireshark, Nmap | TA0011 C2 |  Intermediate |
| [Lab 03](./lab-03-phishing-investigation/) | Phishing Email Investigation | Splunk, VirusTotal, MXToolbox | TA0001 Initial Access |  Advanced |
| [Lab 04](./lab-04-malware-analysis/) | Malware Behavior Analysis | Any.run, FLOSS, Strings | TA0002 Execution |  Advanced |

---

##  Learning Objectives

- Configure and query a SIEM to detect anomalous behavior
- - Analyze packet captures to identify command-and-control (C2) traffic
  - - Investigate phishing campaigns from header analysis to IOC extraction
    - - Conduct static and dynamic malware analysis to identify threat behavior
      - - Document findings in professional, recruiter-ready investigation reports
       
        - ---

        ##  Tools Used

        ```
        SIEM:              Splunk (Free Tier / TryHackMe Labs)
        Network Analysis:  Wireshark, Nmap, NetworkMiner
        Threat Intel:      VirusTotal, AbuseIPDB, AlienVault OTX
        Email Analysis:    MXToolbox, PhishTool, Email Header Analyzer
        Malware Analysis:  Any.run, FLOSS, PEStudio, strings (Linux)
        Frameworks:        MITRE ATT&CK, NIST SP 800-61, Cyber Kill Chain
        ```

        ---

        ##  Repository Structure

        ```
        soc-analyst-labs/
         README.md
         lab-01-splunk-siem-setup/
            README.md
            screenshots/
            spl-queries.md
         lab-02-network-traffic-analysis/
            README.md
            screenshots/
            pcap-findings.md
         lab-03-phishing-investigation/
            README.md
            screenshots/
            ioc-report.md
         lab-04-malware-analysis/
             README.md
             screenshots/
             malware-behavior-report.md
        ```

        ---

        ##  Related Resources

        -  [Incident Response Repository](../incident-response/)
        -  -  [Cloud Security Projects](../cloud-security-aws/)
           -  -  [NIST CSF Gap Analysis](../nist-csf-gap-analysis/)
