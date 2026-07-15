# WordPress Web-Shell Activity

## Detection Summary

| Field | Value |
| --- | --- |
| Platform | Splunk |
| Data source | Web-server or reverse-proxy access logs |
| ATT&CK | T1505.003 — Web Shell |
| Severity | High |
| Goal | Detect repeated POST activity involving the WordPress editor and suspicious PHP files |

## SPL

```spl
index=web_logs http_method=POST
(
  uri_path="*admin-ajax.php*"
  OR uri_path="*theme-editor.php*"
  OR referer="*theme-editor.php*"
)
(
  uri_path="*.php*"
  OR referer="*.php*"
)
| stats count
        values(status) as status_codes
        values(user_agent) as user_agents
        values(referer) as referrers
  by src_ip uri_path
| where count >= 3
| sort 0 - count
```

## Why It Works

The rule focuses on repeated POST requests involving WordPress administrative functionality and PHP resources. It does not treat HTTP 200 alone as proof of command execution; it identifies activity that should be correlated with application and endpoint telemetry.

## Tuning and False Positives

- Legitimate theme or plugin editing
- WordPress administrators using `admin-ajax.php`
- Security scanners testing the application

Useful tuning fields include approved administrator IPs, maintenance windows, authenticated usernames, known plugin paths, and expected user agents.

## Triage

1. Review the full URI, referrer, user agent, response size, and request count.
2. Check whether the source first performed brute-force or Hydra activity.
3. Preserve the suspicious PHP file and calculate its hash.
4. Review web-server, PHP, audit, and endpoint process logs for execution evidence.
5. Search for the same filename and source across other web servers.
