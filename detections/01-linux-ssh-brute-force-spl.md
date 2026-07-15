# Linux SSH Brute Force

## Detection Summary

| Field | Value |
| --- | --- |
| Platform | Splunk |
| Data source | Linux authentication logs |
| ATT&CK | T1110 — Brute Force |
| Severity | Medium; raise to High when followed by a successful login |
| Goal | Identify one source generating a high number of failed SSH authentications in a short window |

## SPL

```spl
index=linux_secure ("Failed password" OR "Invalid user")
| bin _time span=5m
| stats count as failed_attempts
        dc(user) as targeted_accounts
        values(user) as users
  by _time src_ip host
| where failed_attempts >= 20
| sort 0 - failed_attempts
```

## Why It Works

The search groups failed SSH activity into five-minute windows. A single source producing at least 20 failures is unusual enough to review, while the distinct-user count helps separate password guessing against one account from username enumeration.

## Tuning and False Positives

- Approved vulnerability scanners
- Misconfigured automation or monitoring accounts
- Users repeatedly entering an old password
- NAT addresses shared by many legitimate users

I would tune the threshold using the normal login volume for each server and allowlist known scanners only after confirming their ownership.

## Triage

1. Check whether the source IP is internal or external.
2. Review targeted accounts and determine whether any are privileged.
3. Search for an `Accepted password` event from the same source after the failures.
4. Review new sessions, sudo/su activity, account creation, and persistence events.
5. Reset or disable the account and isolate the host if post-authentication activity confirms compromise.
