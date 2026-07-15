# Detection Content

These rules were derived from the investigation cases in this repository. I kept them separate from the case-study notes so the detection logic, expected data, false positives, and triage steps can be reviewed quickly.

| Detection | Platform | Main ATT&CK technique |
| --- | --- | --- |
| [Linux SSH Brute Force](01-linux-ssh-brute-force-spl.md) | Splunk | T1110 — Brute Force |
| [Scheduled Task and Certutil Download](02-scheduled-task-certutil-spl.md) | Splunk | T1053.005 / T1105 |
| [PsExec Lateral Movement](03-psexec-lateral-movement-spl.md) | Splunk | T1569.002 / T1021.002 |
| [WordPress Web-Shell Activity](04-wordpress-web-shell-spl.md) | Splunk | T1505.003 |
| [Suspicious MSI and PowerShell Chain](05-malicious-msi-powershell-kql.md) | Elastic | T1218.007 / T1059.001 |

## How I Use These Rules

The searches are starting points rather than copy-and-paste production rules. Index names, field names, thresholds, and allowlists need to be adjusted to the available data and normal administrative activity.

For each rule I documented:

- Required telemetry
- Detection query
- What the rule is intended to catch
- Likely false positives
- Tuning ideas
- Initial triage steps

A detection should be tested against known-good activity before it is enabled as an alert.
