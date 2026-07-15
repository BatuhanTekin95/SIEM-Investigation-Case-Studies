# SIEM Investigation Case Studies

[![Documentation Check](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/actions/workflows/documentation-check.yml/badge.svg)](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/actions/workflows/documentation-check.yml)

This repository contains the SIEM labs I completed while developing my investigation and log-analysis skills. I used Splunk and Elastic Security to work through authentication attacks, persistence, lateral movement, credential abuse, Active Directory compromise, and ransomware activity.

My aim is to show the way I approach an alert: start with the initial evidence, build a timeline, pivot between related events, and keep the final conclusion within what the logs can actually prove.

## Case Studies

| Case study | Platform | Main focus | Key data sources |
| --- | --- | --- | --- |
| [Splunk Fundamentals](docs/01-Splunk-Fundamentals.md) | Splunk | Ingestion, SPL, filtering, statistics, and visualization | VPN, Windows, Linux, and web log examples |
| [Three SIEM Alert Investigations](docs/02-Multi-Stage-Attack-Investigations-Splunk.md) | Splunk | Linux brute force, scheduled-task persistence, and suspected WordPress web shell | Authentication, task, process, and web logs |
| [Active Directory Lateral Movement](docs/03-Active-Directory-Lateral-Movement-Investigation-Splunk.md) | Splunk | SMB, PsExec, named pipes, RDP, and Domain Controller access | Windows Security, System, Sysmon, and PowerShell |
| [Malvertising and Fake Software Delivery](docs/04-Malvertising-Fake-Software-Investigation-Elastic.md) | Elastic | Fake installer, credential dumping, Pass-the-Hash, DCSync, and ransomware | Sysmon, PowerShell, DNS, process, file, and authentication events |

## Detection Content

The investigation notes are supported by reusable detection searches with documented telemetry requirements, false positives, tuning ideas, and triage steps.

| Detection | Platform |
| --- | --- |
| [Linux SSH Brute Force](detections/01-linux-ssh-brute-force-spl.md) | Splunk |
| [Scheduled Task and Certutil Download](detections/02-scheduled-task-certutil-spl.md) | Splunk |
| [PsExec Lateral Movement](detections/03-psexec-lateral-movement-spl.md) | Splunk |
| [WordPress Web-Shell Activity](detections/04-wordpress-web-shell-spl.md) | Splunk |
| [Suspicious MSI and PowerShell Chain](detections/05-malicious-msi-powershell-kql.md) | Elastic |

The full rule index is available in the [detections directory](detections/README.md).

## Investigation Method

For each case I followed the same basic workflow:

1. Review the alert and define what needs to be proven.
2. Identify the affected host, account, source, and time range.
3. Pivot through related authentication, process, network, and file events.
4. Separate confirmed evidence from assumptions.
5. Map the observed behavior to MITRE ATT&CK.
6. Record the verdict, limitations, and response actions.

## Skills Demonstrated

- SPL and KQL investigation searches
- Windows Security, Sysmon, Linux authentication, and web-log analysis
- Alert validation and True Positive assessment
- Timeline reconstruction and cross-host correlation
- Active Directory lateral-movement analysis
- MITRE ATT&CK mapping
- Containment and follow-up recommendations
- Detection-rule design, false-positive analysis, and tuning

## Lab Scope

These investigations were completed in controlled training environments. The IP addresses, domains, users, passwords, hashes, and other indicators shown in the case studies are lab artifacts. Sensitive-looking values are masked where appropriate.

The queries reflect the fields available in the lab datasets. In a production environment I would first confirm the data model, parsing, time zone, retention, and asset context before using the same searches.

## Related Project

The investigation work in this repository builds on my earlier [SOC Phishing Case Studies](https://github.com/BatuhanTekin95/SOC-Phishing-Case-Studies), including a phishing-to-ransomware investigation completed with Elastic Security.

## License

This repository is available under the [MIT License](LICENSE).
