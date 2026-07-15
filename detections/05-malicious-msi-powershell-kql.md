# Suspicious MSI and PowerShell Execution Chain

## Detection Summary

| Field | Value |
| --- | --- |
| Platform | Elastic Security |
| Data source | ECS process and endpoint events |
| ATT&CK | T1218.007 — Msiexec; T1059.001 — PowerShell |
| Severity | High |
| Goal | Detect an MSI launched from a user-writable directory followed by suspicious PowerShell activity |

## KQL

```kql
(
  process.name : "msiexec.exe" and
  process.command_line : ("*\\Downloads\\*.msi*" or "*\\AppData\\Local\\Temp\\*.msi*")
)
or
(
  process.parent.name : "msiexec.exe" and
  process.name : "powershell.exe" and
  process.command_line : (
    "*http*"
    or "*DownloadString*"
    or "*Invoke-WebRequest*"
    or "*-EncodedCommand*"
  )
)
```

## Why It Works

MSI installation is common, so the first condition is context rather than a final verdict. The second condition looks for PowerShell launched by `msiexec.exe` with download or encoded-command behavior, which is much more suspicious.

## Tuning and False Positives

- Legitimate user-installed software
- Enterprise installers that use PowerShell
- Approved deployment and packaging tools

I would tune on trusted signer, known installer hash, approved download domain, parent process, user, and software-deployment host.

## Triage

1. Confirm the MSI download source and Zone Identifier.
2. Review signer, hash, file path, and prevalence.
3. Follow the process tree from `msiexec.exe` to PowerShell and later children.
4. Check network connections, downloaded scripts, services, and credential-access behavior.
5. Isolate the host if the chain reaches persistence or credential dumping.
