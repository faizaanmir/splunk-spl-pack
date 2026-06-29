# Splunk SPL Query Pack

A curated library of Splunk SPL (Search Processing Language) queries for detection, threat hunting, and incident investigation. Built from hands-on SOC experience and aligned with MITRE ATT&CK.

Useful for SPLK-1002 exam prep and real SOC operations.

---

## Structure

```
splunk-spl-pack/
├── authentication/     # Login failures, brute force, privilege escalation
├── endpoint/           # Process execution, file activity, registry changes
├── network/            # DNS, proxy, firewall, traffic anomalies
├── email/              # Phishing, malicious attachments, email flow
└── threat-hunting/     # Proactive hunt queries across multiple data sources
```

---

## Query Index

### Authentication
| File | Technique | Description |
|---|---|---|
| `authentication/brute-force-detection.spl` | T1110 | Detects repeated failed logins from a single source |
| `authentication/password-spray.spl` | T1110.003 | Low-and-slow failed logins across many accounts |
| `authentication/after-hours-login.spl` | T1078 | Successful logins outside business hours |
| `authentication/privilege-escalation-sudo.spl` | T1548.003 | Linux sudo usage by non-standard accounts |

### Endpoint
| File | Technique | Description |
|---|---|---|
| `endpoint/powershell-suspicious.spl` | T1059.001 | Encoded or obfuscated PowerShell commands |
| `endpoint/new-service-installed.spl` | T1543.003 | New Windows services created (lateral movement / persistence) |
| `endpoint/lolbas-execution.spl` | T1218 | Living off the Land binary abuse |
| `endpoint/ransomware-file-extension.spl` | T1486 | Mass file extension changes indicating ransomware |

### Network
| File | Technique | Description |
|---|---|---|
| `network/dns-exfiltration.spl` | T1048.003 | High-volume DNS queries with long subdomains |
| `network/beaconing-detection.spl` | T1071 | Regular outbound connections at fixed intervals (C2 beaconing) |
| `network/port-scan-detection.spl` | T1046 | Single source connecting to many ports/hosts |
| `network/large-outbound-transfer.spl` | T1048 | Unusual large data uploads to external destinations |

### Email
| File | Technique | Description |
|---|---|---|
| `email/phishing-attachment-types.spl` | T1566.001 | Emails with high-risk attachment extensions |
| `email/spoofed-sender-detection.spl` | T1566 | Sender domain mismatch / SPF-DKIM failures |

### Threat Hunting
| File | Description |
|---|---|
| `threat-hunting/rare-processes.spl` | Identify processes that rarely run across the environment |
| `threat-hunting/first-time-seen-connections.spl` | External connections to destinations never seen before |

---

## SPL Cheat Sheet

### Core Commands
```spl
| stats count by field             # Count events grouped by field
| table field1 field2              # Select specific fields
| sort -count                      # Sort descending by count
| dedup field                      # Remove duplicate values
| eval newfield=if(x>5,"high","low")  # Conditional field creation
| rex field=_raw "(?<myfield>pattern)"  # Extract field with regex
| transaction host maxspan=5m      # Group related events into transactions
| timechart span=1h count by src   # Time-based chart grouped by field
| rename old AS new                # Rename field
| where count > 10                 # Filter after stats
```

### Time Modifiers
```spl
earliest=-24h latest=now           # Last 24 hours
earliest=-7d@d latest=@d           # Last 7 days (snapped to day)
earliest=@w0 latest=@w0+7d         # Current week
```

### Lookups
```spl
| lookup threat_intel_ips ip AS src_ip OUTPUT threat_category
| inputlookup my_watchlist.csv
| outputlookup updated_watchlist.csv
```

---

## Usage Notes

- All queries use `index=*` as placeholder — replace with your actual index names
- Adjust time ranges and thresholds to match your environment baseline
- Test queries in Splunk's Search & Reporting app before deploying as alerts
- Use `| head 100` during testing to limit result sets

---

*Author: Faizaan Sajjad — Security Specialist, Orange Cyber Defense*
*All examples use sanitized data. No production or client data present.*
