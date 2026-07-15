# Scheduled Task with Certutil or PowerShell Download

## Detection Summary

| Field | Value |
| --- | --- |
| Platform | Splunk |
| Data source | Windows Security, Task Scheduler, Sysmon, or EDR process telemetry |
| ATT&CK | T1053.005 — Scheduled Task/Job; T1105 — Ingress Tool Transfer |
| Severity | High |
| Goal | Detect scheduled tasks that retrieve or immediately execute an external payload |

## SPL

```spl
index=*
(
  EventCode=4698
  OR TaskName=*
  OR process_name="schtasks.exe"
  OR Image="*\\schtasks.exe"
)
(
  "certutil.exe"
  OR "Invoke-WebRequest"
  OR "DownloadString"
  OR "Start-BitsTransfer"
)
(
  "http://"
  OR "https://"
)
| table _time host user TaskName process_name process_command_line CommandLine _raw
| sort 0 _time
```

## Why It Works

Scheduled tasks are common in Windows environments, so task creation alone is noisy. This search becomes more useful by requiring both task-related activity and a command that can retrieve content over HTTP or HTTPS.

## Tuning and False Positives

- Software deployment tools
- Approved update mechanisms
- Administrative maintenance scripts
- Security products that schedule downloads

I would allowlist a task only after validating its owner, path, signing information, destination domain, and normal execution schedule.

## Triage

1. Export and review the complete task XML.
2. Identify the task author, trigger, execution account, and command.
3. Check the destination domain, downloaded filename, hash, and signature.
4. Follow the parent-child process chain after the task runs.
5. Hunt for the same task name, URL, and payload across other hosts.
