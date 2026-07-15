# PsExec Lateral Movement

## Detection Summary

| Field | Value |
| --- | --- |
| Platform | Splunk |
| Data source | Windows System, Security, and Sysmon |
| ATT&CK | T1569.002 — Service Execution; T1021.002 — SMB/Windows Admin Shares |
| Severity | High |
| Goal | Identify PsExec service creation, command execution, or named-pipe artifacts |

## SPL

```spl
index=*
(
  (EventCode=7045 AND (ServiceName="PSEXESVC" OR ImagePath="*PSEXESVC*"))
  OR (EventCode=1 AND (ParentImage="*PSEXESVC.exe" OR parent_process_name="PSEXESVC.exe"))
  OR (EventCode=17 AND PipeName="*PSEXESVC*")
)
| stats min(_time) as first_seen
        max(_time) as last_seen
        values(user) as users
        values(ServiceName) as services
        values(Image) as processes
        values(CommandLine) as commands
        values(PipeName) as pipes
  by host
| convert ctime(first_seen) ctime(last_seen)
```

## Why It Works

PsExec normally creates the temporary `PSEXESVC` service on the destination. Sysmon process and named-pipe events can provide additional evidence and help distinguish a service installation from actual remote command execution.

## Tuning and False Positives

- Approved help-desk or server administration
- Software deployment systems
- Incident-response tools used by the security team

Rather than permanently allowlisting PsExec, I would baseline approved source hosts, administrator accounts, change windows, and destination groups.

## Triage

1. Identify the source IP and account used for the connection.
2. Review Event IDs 5140/5145 for ADMIN$ and IPC$ access.
3. Check Event ID 7045 and the service image path.
4. Review child processes and commands launched by `PSEXESVC.exe`.
5. Correlate Logon ID, source host, destination host, and named-pipe activity.
