# 🎣 Lab 03 — Phishing Email Investigation

**Analyst:** Andre Wesley  
**Date:** June 2026  
**Difficulty:** 🔴 Advanced  
**MITRE Tactic:** TA0001 — Initial Access (T1566)  
**Case ID:** PHI-2026-0312  

---

## 🎯 Objective

Investigate a suspected phishing email reported by an employee. Extract all IOCs, determine whether the email resulted in credential compromise or malware execution, and produce a formal investigation report.

---

## 📋 Reported Incident

**Employee Report:**
> *"I received an email from IT Support asking me to verify my Microsoft 365 credentials. The link looked slightly off but I clicked it before I realized. I didn't enter my password."*

- **From:** `IT-Support@micros0ft-helpdesk.com`
- **Subject:** `[URGENT] Your Microsoft 365 account will be suspended in 24 hours`
- **Time:** June 10, 2026 at 08:14 EST
- **Attachment:** `AccountVerification.html`

---

## 🔍 Phase 1: Email Header Analysis

```
Return-Path: <bounce@spammer-relay.ru>
Received: from mail.micros0ft-helpdesk.com (45.89.230.12)
  by corp-mail.acme.com with ESMTP
From: IT Support <it-support@micros0ft-helpdesk.com>
Reply-To: data-collect@suspiciousdomain.xyz
X-Originating-IP: 45.89.230.12
```

| Field | Value | Issue |
|---|---|---|
| Sending Domain | `micros0ft-helpdesk.com` | Typosquat — zero instead of 'o' |
| Reply-To | `data-collect@suspiciousdomain.xyz` | Replies go to attacker |
| Originating IP | `45.89.230.12` | Registered in Russia (RU) |
| SPF Check | `FAIL` | Domain not authorized to send |
| DKIM Check | `FAIL` | Signature invalid |
| DMARC | `FAIL` | Policy: reject — should have been blocked |

##  Phase 2: URL & Attachment Analysis

**Malicious URL:**
```
https://micros0ft-helpdesk.com/365/verify?token=aGVsbG8tcGhpc2hpbmc=
```

**VirusTotal Results:** 23/94 engines flagged as phishing

**URL Red Flags:**
- Domain typosquat: `micros0ft-helpdesk.com`
- - Token is base64-encoded: `hello-phishing` (decoded)
  - - Redirects to credential harvesting page
    - - HTTPS certificate issued just 3 days prior
     
      - **HTML Attachment Analysis (AccountVerification.html):**
      - - Contains JavaScript that submits credentials to `https://collect.suspiciousdomain.xyz/submit`
        - - Uses HTML smuggling to bypass email gateway scanners
          - - Mimics Microsoft 365 login page pixel-for-pixel
           
            - ---

            ##  IOC Summary

            | Indicator | Type | Confidence | Action |
            |---|---|---|---|
            | `micros0ft-helpdesk.com` | Domain | High | Block on DNS/proxy |
            | `45.89.230.12` | IP Address | High | Block on firewall |
            | `suspiciousdomain.xyz` | Domain | High | Block on DNS/proxy |
            | `collect.suspiciousdomain.xyz` | URL | High | Block on proxy |
            | `AccountVerification.html` | File | High | Add to AV signatures |
            | `aGVsbG8tcGhpc2hpbmc=` | Token | Medium | Log for threat intel |

            ---

            ##  Key Takeaways

            - SPF/DKIM/DMARC failures are definitive phishing signals  block at email gateway
            - - HTML attachments with JavaScript are high-risk  strip or sandbox all HTML email attachments
              - - Typosquatting domains (0 vs o) are a common attacker technique  monitor lookalike domains
                - - Base64-encoded URL tokens mask attack intent from signature-based scanners
                 
                  - ---

                  ##  References

                  - [MITRE ATT&CK T1566  Phishing](https://attack.mitre.org/techniques/T1566/)
                  - - [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
                    - - [VirusTotal](https://www.virustotal.com)
