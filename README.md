# Splunk — Learning Notes & Practical Exercises

## Overview

This document covers my hands-on learning of Splunk as part of the TryHackMe SOC Level 1 learning path (completed August 2026). It includes Splunk architecture fundamentals, core search queries, and practical alert triage exercises performed in a simulated SOC environment.

---

## 1. What is Splunk?

Splunk is a Security Information and Event Management (SIEM) platform used to collect, index, search, and analyze machine-generated data from across an organization's IT infrastructure.

In a SOC context, Splunk is used to:
- Aggregate logs from multiple sources — firewalls, endpoints, servers, applications
- Search and correlate events to detect suspicious activity
- Build dashboards for real-time security monitoring
- Create alerts that trigger when specific conditions are met
- Support incident investigation and threat hunting

---

## 2. Splunk Architecture

```
Data Sources
(Firewalls, Endpoints, Servers, Applications)
        ↓
Universal Forwarder
(Lightweight agent installed on data sources — forwards raw data to indexer)
        ↓
Heavy Forwarder (optional)
(Parses and filters data before forwarding)
        ↓
Indexer
(Receives, parses, and indexes data — stores it for search)
        ↓
Search Head
(Interface where analysts run searches, build dashboards, create alerts)
```

### Core Components

| Component | Role |
|---|---|
| Universal Forwarder | Lightweight agent that collects and forwards logs from endpoints |
| Heavy Forwarder | Parses and filters data before sending to indexer |
| Indexer | Receives, processes, and stores indexed data |
| Search Head | Interface for running SPL queries, dashboards, and alerts |
| Deployment Server | Manages forwarder configurations at scale |

---

## 3. Splunk Processing Pipeline

When data enters Splunk it goes through a processing pipeline:

```
Raw Data Ingestion
        ↓
Line Breaking — splits raw data into individual events
        ↓
Timestamp Extraction — assigns time to each event
        ↓
Field Extraction — identifies key-value pairs
        ↓
Index Storage — data written to index
        ↓
Search — analysts query indexed data via SPL
```

---

## 4. SPL — Search Processing Language

SPL is Splunk's query language. Searches follow a pipeline structure where the output of one command feeds into the next.

### Basic Search Syntax

```splunk
index=main sourcetype=WinEventLog EventCode=4625
```

- `index=main` — search within the main index
- `sourcetype=WinEventLog` — filter by log source type
- `EventCode=4625` — Windows Event ID for failed logon

### Core SPL Commands

| Command | Purpose | Example |
|---|---|---|
| `search` | Filter events | `search EventCode=4625` |
| `stats` | Statistical calculations | `stats count by src_ip` |
| `table` | Display specific fields | `table _time, src_ip, user` |
| `sort` | Sort results | `sort -count` |
| `dedup` | Remove duplicates | `dedup user` |
| `rex` | Extract fields using regex | `rex field=message "user=(?<username>\w+)"` |
| `eval` | Create calculated fields | `eval status=if(count>10,"brute_force","normal")` |
| `where` | Filter after stats | `where count > 5` |
| `timechart` | Time-based visualization | `timechart count by EventCode` |
| `top` | Most frequent values | `top limit=10 src_ip` |
| `rare` | Least frequent values | `rare user` |

---

## 5. Practical Queries — SOC Use Cases

### Failed Login Detection

```splunk
index=main sourcetype=WinEventLog EventCode=4625
| stats count as FailedAttempts by src_ip, user
| where FailedAttempts > 5
| sort -FailedAttempts
| table src_ip, user, FailedAttempts
```

**What this does:** Counts failed logon attempts grouped by source IP and username. Filters for accounts with more than 5 failures — potential brute force indicator.

---

### Brute Force Detection

```splunk
index=main sourcetype=WinEventLog EventCode=4625
| bucket _time span=5m
| stats count as attempts by _time, src_ip
| where attempts > 20
| table _time, src_ip, attempts
```

**What this does:** Groups failed logons into 5-minute windows. Flags source IPs generating more than 20 failures within a 5-minute window — consistent with automated brute force activity.

---

### Successful Login After Multiple Failures (Credential Attack Success)

```splunk
index=main sourcetype=WinEventLog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as Failures,
        count(eval(EventCode=4624)) as Successes by src_ip, user
| where Failures > 5 AND Successes > 0
| table src_ip, user, Failures, Successes
```

**What this does:** Identifies accounts that had multiple failures followed by a successful logon — pattern consistent with a successful brute force or credential stuffing attack.

---

### Detect Logons Outside Business Hours

```splunk
index=main sourcetype=WinEventLog EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, user, src_ip, hour
```

**What this does:** Flags successful logons occurring outside 7AM-7PM — potential indicator of unauthorized after-hours access.

---

## 6. Alert Triage in Splunk (TryHackMe Exercise)

As part of the TryHackMe SOC Level 1 Alert Triage room, I practiced:

- Navigating the Splunk interface to review triggered alerts
- Examining alert details — source, destination, event timeline
- Searching for related events to build investigation context
- Classifying alerts as true positive or false positive based on evidence
- Documenting findings and recommended actions

### Alert Triage Workflow in Splunk

```
Alert Triggered
        ↓
Review Alert Details in Splunk
(Source IP, Destination, Time, Event Count)
        ↓
Run Supporting SPL Queries
(What happened before? What happened after?)
        ↓
Enrich with Context
(Asset lookup, user history, threat intel)
        ↓
Classify: True Positive / False Positive
        ↓
Document Findings
(What was observed, what was confirmed, recommended action)
        ↓
Escalate or Close
```

---

## 7. Key Windows Event IDs for SOC Monitoring

| Event ID | Description | SOC Relevance |
|---|---|---|
| 4624 | Successful logon | Baseline — look for anomalies |
| 4625 | Failed logon | Brute force detection |
| 4648 | Logon with explicit credentials | Pass-the-hash, lateral movement |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | New process created | Malware execution detection |
| 4698 | Scheduled task created | Persistence mechanism |
| 4720 | User account created | Unauthorized account creation |
| 4732 | User added to security group | Privilege escalation |
| 7045 | New service installed | Persistence or malware installation |

---

## 8. Splunk in SOC Operations

**How Splunk fits into the SOC workflow:**

```
Log Sources → Splunk Indexer → Search Head
                                    ↓
                            Correlation Rules
                                    ↓
                            Alert Generated
                                    ↓
                            SOC Analyst Reviews
                                    ↓
                    SPL Queries for Investigation
                                    ↓
                    True Positive / False Positive
                                    ↓
                    Escalate / Remediate / Close
```

**Splunk strengths for SOC:**
- Fast search across large volumes of log data
- Flexible SPL queries for custom investigation
- Dashboard creation for real-time monitoring
- Alert scheduling for automated detection
- Integration with threat intelligence feeds

---

## 9. Connection to Investigation Series

The Splunk skills developed here directly complement the network forensics work in my [10-day PCAP investigation series](../soc-pcap-investigations/):

- **Day 5 DNS Covert C2** → DNS query volume anomaly query above would detect this
- **Day 8 Screen Capture Exfiltration** → High volume outbound traffic query would flag the 3.59MB POST
- **Day 9 SSH Brute Force** → Failed login detection query maps directly to this attack pattern
- **Day 10 SMB Authentication** → Failed logon EventCode 4625 query would surface the NTLM failures

---

## 10. References & Resources

- [TryHackMe SOC Level 1 Learning Path](https://tryhackme.com/path/outline/soclevel1) — Completed August 2026
- [Splunk Documentation](https://docs.splunk.com)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

## Certification

**TryHackMe SOC Level 1** — Completed August 2026 | Top 5% Globally
Credential ID: THM-QDOOMSJGYT

---

*This document represents my foundational Splunk knowledge developed through structured SOC training. Actively building on this through ongoing investigation work and security lab exercises.*
