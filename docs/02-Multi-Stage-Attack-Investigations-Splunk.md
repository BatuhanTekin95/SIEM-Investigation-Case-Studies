# Three SIEM Alert Investigations (Splunk)

These are three separate lab investigations rather than one confirmed campaign. I kept them together because they use the same investigation method: validate the alert, pivot through the logs, separate confirmed facts from assumptions, and finish with a clear verdict.

| Case | Main evidence | Verdict |
| --- | --- | --- |
| Linux brute force | Failed and accepted SSH activity, privileged sessions, new local account | True Positive |
| Scheduled task persistence | Task XML, PowerShell, certutil download, payload execution | True Positive |
| WordPress attack | Hydra activity, HTTP POST requests, references to `b374k.php` | True Positive; web-shell interaction strongly suspected |

> Lab note: IP addresses, accounts, hosts, and credentials shown here belong to a controlled training environment.

## Lab and Documentation Details

| Item | Details |
| --- | --- |
| Environment | Simulated SOC training environment |
| Evidence | Authentication, scheduled-task, process, and web-server logs |
| Scope | Three separate alerts; no shared campaign is assumed |
| Last reviewed | July 2026 |

## Investigation Sequence

The dataset did not provide one reliable timestamp format across all three alerts, so I used the observed event order instead of inventing exact times.

| Order | Case | System | Evidence | Assessment |
| --- | --- | --- | --- | --- |
| 1 | Linux brute force | tryhackme-2404 | Repeated failed and invalid-user SSH events | Password guessing and username enumeration |
| 2 | Linux brute force | tryhackme-2404 | Accepted login for john.smith after the failures | Account compromise confirmed |
| 3 | Linux brute force | tryhackme-2404 | Privileged session activity | Privilege escalation supported |
| 4 | Linux brute force | tryhackme-2404 | Local account system-utm created | Persistence suspected |
| 5 | Scheduled task | Windows workstation | AssessmentTaskOne reviewed in task data | Persistence mechanism identified |
| 6 | Scheduled task | Windows workstation | Certutil download and PowerShell execution | External payload delivery confirmed |
| 7 | WordPress | Public web server | Hydra user agent and repeated login attempts | Automated brute force identified |
| 8 | WordPress | Public web server | POST activity involving b374k.php | Web-shell interaction strongly suspected |

## Case 1 — Linux Brute Force and Account Compromise

### Introduction

In this investigation, I analyzed a security alert generated within a Linux environment using Splunk.

The alert, **Brute Force Activity Detection**, indicated a high volume of authentication attempts originating from the internal IP address `10.10.242.248` and targeting the host `tryhackme-2404`. At first glance, the activity appeared suspicious, but additional analysis was required to determine whether the alert represented a genuine security incident or a false positive.

Using Splunk, I examined authentication logs, reviewed failed and successful login attempts, identified the targeted accounts, and investigated the attacker's actions following initial access. As the investigation progressed, evidence of account compromise, privilege escalation, and persistence activities was uncovered.

The objective of this investigation was to determine the validity of the alert, reconstruct the attack timeline, and understand the overall impact of the activity on the affected system.


<img width="920" height="379" alt="Ekran görüntüsü 2026-06-13 145753" src="https://github.com/user-attachments/assets/b6eb2a5b-266c-4184-b95b-e2989d7aac6f" />

> Initial security alert indicating potential brute force activity against host tryhackme-2404 from source IP 10.10.242.248.

### Initial Log Analysis

To begin the investigation, I searched for authentication-related events associated with the source IP address provided by the alert. My goal was to determine whether the activity consisted of failed logins, successful logins, or attempts against non-existent accounts.

Using the source IP address (`10.10.242.248`), I filtered authentication events within the `linux_secure` logs and reviewed login activity associated with the host `tryhackme-2404`.

The results revealed a large number of authentication attempts originating from the same source IP address. More importantly, several events referenced invalid user accounts, indicating that the attacker may have been attempting to enumerate valid usernames before launching a brute force attack.

At this stage, the activity appeared suspicious; however, there was not yet enough evidence to confirm whether a legitimate account had been successfully compromised.

<img width="1913" height="781" alt="Ekran görüntüsü 2026-06-13 150537" src="https://github.com/user-attachments/assets/6a3176db-ba9f-4334-92f5-f484826eeffc" />

> Initial authentication log review showing failed login attempts and invalid user activity originating from source IP 10.10.242.248.

### Identifying the Targeted User

After confirming the presence of suspicious authentication activity, the next step was to determine whether a specific account was being targeted.

To answer this question, I analyzed the number of login attempts associated with each username observed in the authentication logs. This approach helped identify which accounts attracted the highest level of attention from the source IP address.

The results revealed that four user accounts were present within the dataset; however, one account stood out significantly from the others.

<img width="1898" height="437" alt="Ekran görüntüsü 2026-06-13 154052" src="https://github.com/user-attachments/assets/70dd6412-a598-4750-99b6-5cce07713d94" />

> Authentication attempts grouped by username, revealing that john.smith was targeted by 503 login attempts from source IP 10.10.242.248.


The analysis revealed that four different user accounts were targeted by authentication attempts originating from the source IP address 10.10.242.248.

Among them, the account john.smith stood out significantly, receiving a total of 503 login attempts. This volume was substantially higher than that observed for the other accounts and provided strong evidence that john.smith was the primary target of the attack.

At this stage, the investigation confirmed clear indicators of brute force activity. However, it was still necessary to determine whether any of these authentication attempts were successful and whether the attacker had gained access to the system.


### Evidence of Successful Compromise


At this stage, the investigation had already identified john.smith as the primary target of the brute force activity. However, a critical question still remained:

Were any of the authentication attempts successful?

To answer this question, I expanded the analysis to include both failed and successful authentication events associated with each username. This allowed me to determine whether the attacker was able to obtain valid credentials and gain access to the target system.

<img width="1743" height="470" alt="Ekran görüntüsü 2026-06-13 154825" src="https://github.com/user-attachments/assets/f8fa4d05-ae3a-4488-accd-b4d71e562e20" />

> Authentication results showing both failed and successful login attempts for john.smith, confirming account compromise.

The results showed that the account john.smith contained both Failed and Accepted authentication events. In contrast, all other accounts were associated only with failed authentication attempts.

This finding confirmed that the attacker was eventually able to authenticate successfully after multiple failed login attempts, indicating that valid credentials had been obtained through brute force activity.

Based on the available evidence, the attacker successfully gained access to the host tryhackme-2404, allowing the alert to be classified as a True Positive security incident.

With account compromise confirmed, the next step was to investigate the attacker's actions after gaining access to the system.

### Privilege Escalation Activity

After confirming that the attacker had successfully authenticated to the system using the compromised `john.smith` account, the next step was to determine whether any post-compromise activity had taken place.

A successful login alone does not necessarily indicate the full extent of an intrusion. Attackers often attempt to elevate their privileges after gaining initial access in order to obtain administrative control over the target system.

To investigate this possibility, I reviewed successful authentication events associated with the compromised account and searched for evidence of privileged session creation.


<img width="1525" height="702" alt="Ekran görüntüsü 2026-06-13 155617" src="https://github.com/user-attachments/assets/8013023c-ec75-44a7-813f-786b3a7a13b8" />

> Successful authentication and privilege escalation activity showing john.smith obtaining root-level access on the target system.


The investigation revealed multiple successful authentication events associated with the `john.smith` account. More importantly, the logs showed privileged sessions being opened for the `root` account through both `sudo` and `su` activity.

These events confirmed that the attacker was able to escalate privileges after gaining access to the system, ultimately obtaining root-level permissions on the host `tryhackme-2404`.

The presence of privileged session creation significantly increased the severity of the incident, as root access provides unrestricted control over the affected Linux system.

With privilege escalation confirmed, the next step was to determine whether the attacker established persistence by creating additional user accounts or implementing mechanisms to maintain long-term access.

### Persistence Mechanism


After obtaining root-level access, the next objective was to determine whether the attacker attempted to maintain long-term access to the compromised system.

Attackers frequently establish persistence mechanisms following privilege escalation to ensure they can regain access even if the original compromised credentials are changed or revoked.

To investigate potential persistence activity, I searched for evidence of new account creation and other administrative actions performed after the attacker obtained root privileges.

<img width="1908" height="440" alt="Ekran görüntüsü 2026-06-13 160125" src="https://github.com/user-attachments/assets/7ec90c33-62e3-41c0-b275-c5e5e39b2e54" />

> Evidence of a newly created user account, indicating an attempt to establish persistence on the compromised system.


The investigation revealed a `useradd` event indicating that a new user account named `system-utm` was created on the host `tryhackme-2404`.

Because this activity occurred after the attacker successfully authenticated and obtained root-level access, the account creation is highly suspicious and consistent with a persistence mechanism.

Creating additional user accounts is a common attacker technique used to maintain access to compromised systems while reducing reliance on the originally compromised credentials.

This finding confirmed that the attacker not only gained access to the system but also took steps to establish long-term persistence within the environment.


### Investigation Findings

The investigation identified multiple indicators confirming that the alert represented a genuine security incident rather than a false positive.

#### Key Findings

- Source IP `10.10.242.248` generated a large volume of authentication attempts against the host `tryhackme-2404`.
- Multiple invalid user login attempts suggested username enumeration activity.
- The account `john.smith` was targeted by **503 authentication attempts**, indicating a brute force attack.
- Successful authentication events confirmed that the attacker gained access using the compromised `john.smith` account.
- The attacker escalated privileges and obtained **root-level access** through `sudo` and `su` activity.
- A new user account named `system-utm` was created, indicating an attempt to establish persistence on the compromised host.

Based on the collected evidence, the alert was classified as a **True Positive** security incident requiring immediate escalation and remediation.

The investigation confirmed that the attacker successfully compromised the `john.smith` account through brute force activity, escalated privileges to `root`, and established persistence by creating a new local account.

While the initial intrusion had been identified and validated, the investigation was not yet complete. The next alert focused on determining whether the attacker maintained ongoing access to the environment through persistence mechanisms.

## Case 2 — Scheduled Task Persistence

### Introduction

Following the investigation of the initial access alert, a second alert was generated involving potential persistence activity on a Windows workstation.

The alert indicated that a scheduled task named `AssessmentTaskOne` had been created on the host `WIN-H015` under the user account `oliver.thompson`.

Scheduled tasks are commonly used by administrators for automation purposes; however, they are also frequently abused by attackers to maintain persistence and execute malicious payloads at predefined intervals.

The objective of this investigation was to determine whether the scheduled task represented legitimate administrative activity or an attacker persistence mechanism.

### Alert Scenario

<img width="901" height="392" alt="Ekran görüntüsü 2026-06-13 161355" src="https://github.com/user-attachments/assets/4315ca5b-a00c-41f6-a85c-7af3fa3af3b3" />

> Alert indicating the creation of a scheduled task named AssessmentTaskOne on host WIN-H015 under the account oliver.thompson.

### Initial Alert Assessment

Before moving directly into Splunk, I first reviewed the alert details to establish context around the activity.

The alert was generated on the workstation `WIN-H015` and was associated with the user account `oliver.thompson`. Unlike server systems, user workstations are less likely to require the creation of recurring scheduled tasks, making this activity worthy of further investigation.

Additionally, the task name `AssessmentTaskOne` did not immediately indicate a legitimate business function. Combined with the persistence-related alert classification, this provided sufficient reason to continue the investigation within Splunk.

At this stage, the objective was to determine what the scheduled task was designed to execute and whether it represented legitimate administrative activity or malicious persistence.

### Scheduled Task Analysis

After validating the alert details, I queried Event ID 4698 to review the scheduled task creation event associated with AssessmentTaskOne.

The search returned a single task creation event on the workstation WIN-H015 under the user account oliver.thompson. This confirmed that the alert was based on a legitimate scheduled task creation event rather than a logging anomaly or duplicate detection.

More importantly, the event contained the full task definition within the Message field, providing valuable information about how the task was configured and what actions it was designed to perform.

At this stage, the task itself had not yet been confirmed as malicious. Therefore, the next step was to examine the task configuration in greater detail, focusing on its execution schedule and associated commands.


<img width="1398" height="763" alt="Ekran görüntüsü 2026-06-13 163247" src="https://github.com/user-attachments/assets/d39e600a-9e17-4117-9c7a-e9219e448b9b" />

> Scheduled task creation event (Event ID 4698) showing AssessmentTaskOne created on WIN-H015 by oliver.thompson.

The search returned a single scheduled task creation event associated with the task `AssessmentTaskOne`. The event confirmed that the task was created on the workstation `WIN-H015` under the user account `oliver.thompson`.

At this stage, the alert appeared legitimate and the scheduled task creation was successfully verified within the logs. However, the event itself did not immediately indicate whether the task was benign or malicious.

To make that determination, it was necessary to examine the task configuration stored within the Message field and identify how the task was scheduled to execute.

After confirming the task creation event, I shifted my focus to the task configuration contained within the Message field.

Scheduled tasks can provide valuable insight into attacker objectives, particularly when reviewing trigger conditions, execution frequency, and associated actions.

The first area of interest was the task's trigger configuration, which determines when and how often the task executes.

A closer review of the trigger configuration showed that the task was scheduled to begin execution at **10:15 AM on 30 August 2025** and was configured to repeat on a **daily basis**.

This meant that once created, the task would automatically execute every day without requiring any further user interaction. While recurring scheduled tasks can be legitimate, attacker-created persistence mechanisms often rely on the same approach to maintain continuous access or repeatedly execute malicious payloads.

The combination of a newly created task and a recurring execution schedule increased the level of suspicion and justified further analysis of the commands associated with the task.

### Malicious Command Analysis

After reviewing the task schedule, the next step was to examine the commands executed by the scheduled task.

The Exec section of the task configuration revealed both the executable responsible for launching the task and the arguments passed to it during execution. This information is often critical for determining whether a scheduled task is performing legitimate administrative actions or executing malicious activity.

<img width="1168" height="241" alt="Ekran görüntüsü 2026-06-13 164337" src="https://github.com/user-attachments/assets/6c277797-9ecd-4b69-978c-b84c28a5d726" />

> Exec and Principals sections showing the command executed by AssessmentTaskOne and the user context under which it runs.

Reviewing the Exec section revealed that the task was configured to launch `powershell.exe` and execute a command containing `certutil.exe`, a legitimate Windows utility commonly abused by attackers for file downloads.

The command attempted to download a file named `rv.exe` from the host shown in the lab data as `tryhotme:9876` and save it locally as `DataCollector.exe` within the user's temporary directory. Because the value does not include a full URL scheme, I kept it as an observed artifact instead of treating it as a verified production IOC. After the download completed, the task used `Start-Process` to immediately execute the downloaded file.

The Principals section showed that the task would run under the context of the user account `oliver.thompson`, ensuring that the downloaded payload would execute whenever the scheduled task was triggered.

At this stage, the activity could no longer be considered normal administrative behavior. The use of `certutil.exe` for file retrieval, followed by execution of a downloaded executable, strongly suggested malicious intent and provided clear evidence of a persistence mechanism designed to deliver and run malware.

### Persistence Findings


The investigation confirmed that the scheduled task `AssessmentTaskOne` was not performing legitimate administrative activity.

Analysis of the task configuration revealed that it was designed to execute daily, download an external executable using `certutil.exe`, save it locally as `DataCollector.exe`, and immediately launch the payload through PowerShell.

The task was configured to run under the user account `oliver.thompson`, ensuring that the payload would execute automatically whenever the scheduled trigger was activated.

Taken together, these findings strongly indicate an attacker persistence mechanism designed to maintain access and facilitate malware execution on the compromised workstation.

Based on the available evidence, the alert was classified as a True Positive security incident. The identified persistence mechanism, combined with the automated download and execution of an external payload, warranted immediate escalation for containment and further incident response activities.

### Investigation Findings

#### Key Findings

- A scheduled task named `AssessmentTaskOne` was created on host `WIN-H015`.
- The task was configured to execute daily under the context of `oliver.thompson`.
- The task used `certutil.exe` to download an external executable (`rv.exe`).
- The downloaded file was saved as `DataCollector.exe` and executed through PowerShell.
- The activity demonstrated a persistence mechanism designed to maintain attacker access.
- The alert was classified as a **True Positive** security incident.

The persistence mechanism was successfully identified and validated. However, the investigation was not yet complete.

The next alert focused on determining whether the downloaded payload had been executed successfully and whether it had resulted in further compromise of the affected system.

## Case 3 — WordPress Brute Force and Suspected Web Shell

### Introduction

Following the investigation of the persistence alert, a third alert was generated involving potential web shell activity on a public-facing web server.

The alert indicated suspicious activity originating from the IP address `171.251.232.40` targeting the web application hosted at `http://web.trywinme.thm`.

Web shells are commonly used by attackers after gaining access to a server, providing a remote interface for command execution, file management, and further post-exploitation activities. Because of their capabilities, web shell activity is often considered a high-severity security event.

The objective of this investigation was to determine whether the observed activity represented a legitimate web request pattern or evidence of web shell deployment and attacker interaction with the server.

<img width="920" height="357" alt="Ekran görüntüsü 2026-06-13 171832" src="https://github.com/user-attachments/assets/1e447c25-f094-4bb8-b0fd-6e7a831e98ff" />

> Alert indicating potential web shell activity originating from source IP 171.251.232.40 against the web application hosted on web.trywinme.thm.


### Threat Intelligence Review

Before reviewing the web server logs, I performed a quick threat intelligence check on the source IP address identified in the alert.

Threat intelligence enrichment can provide valuable context during an investigation by revealing whether an IP address has previously been associated with malicious activity.

The source IP `171.251.232.40` was reviewed using publicly available threat intelligence sources before proceeding with deeper log analysis.

<img width="648" height="546" alt="Ekran görüntüsü 2026-06-13 172310" src="https://github.com/user-attachments/assets/b6c8874e-fdd3-45f4-b8df-1d61a0c75e65" />

> Threat intelligence enrichment showing that source IP 171.251.232.40 had been reported thousands of times for suspicious activity.

During the lab, a public reputation source showed many previous reports for the IP address. I treated this as supporting context only. The final decision was based on the web-server evidence, not on reputation data.

With the source IP already associated with suspicious activity, the next step was to examine the web server logs and determine what actions were performed against the target application.

### Initial Web Log Analysis

After completing the threat intelligence review, I shifted my focus to the web server logs associated with the suspicious IP address identified in the alert.

My objective was to understand how the source IP interacted with the target application, identify the resources being accessed, and determine whether the activity was consistent with legitimate user behavior or malicious reconnaissance and exploitation attempts.

To begin the investigation, I reviewed all web requests associated with the source IP address `171.251.232.40`, including the requested URI paths, HTTP methods, response codes, and user-agent strings.


<img width="1909" height="571" alt="Ekran görüntüsü 2026-06-13 173052" src="https://github.com/user-attachments/assets/aac062d8-3ab5-4704-951d-fa375d2c522e" />

> Initial web log review showing HTTP requests originating from source IP 171.251.232.40 against the target web application.

The search returned more than 300 web requests associated with the source IP address.

Several observations immediately stood out during the initial review of the web traffic.

First, all activity originated from the same source IP address identified in the alert.

Second, the User-Agent field consistently contained `Mozilla/5.0 (Hydra)`, indicating the use of Hydra, a well-known password brute-force tool commonly used to automate large-scale authentication attempts against login portals.

Finally, the requests were targeting the WordPress authentication page `wp-login.php`, with both GET and POST requests being observed throughout the activity.

At this stage, the evidence strongly suggested an ongoing brute-force attack against the web application's login portal. However, the alert was related to potential web shell activity, making it necessary to continue the investigation and determine whether the attacker successfully gained access to the application.

To better understand whether the attacker successfully progressed beyond the brute-force phase, I excluded the Hydra-generated requests and reviewed the remaining web traffic for signs of post-authentication activity and potential web shell interaction.

### Filtering Hydra Activity

After identifying clear evidence of Hydra-based brute-force activity, I excluded the automated authentication attempts from the search results to focus on potential post-authentication actions.

My goal was to determine whether the attacker had successfully progressed beyond the login phase and interacted with other areas of the web application.

<img width="1898" height="690" alt="Ekran görüntüsü 2026-06-13 173733" src="https://github.com/user-attachments/assets/8fc6852f-efe4-4771-abf1-6811c5da277e" />

> Web requests remaining after excluding Hydra-generated traffic, revealing potential post-authentication activity within the application.

The filtered results immediately revealed a significant change in activity.

Unlike the previous search, the User-Agent string no longer contained Hydra and instead reflected a standard web browser, suggesting manual interaction with the application.

More importantly, a POST request was observed against `admin-ajax.php`, with a referer pointing to:

`theme-editor.php?file=b374k.php`

The request returned HTTP 200, showing that the server accepted the request. This supports successful interaction with the suspicious file, but it does not prove which command, if any, was executed on the host.

This finding was highly unusual. The WordPress theme editor is not typically associated with files named `b374k.php`, and the presence of this filename strongly suggested the existence of a web shell on the server.

At this stage, the investigation shifted away from brute-force activity and toward potential web shell access and post-exploitation behavior.

To test this suspicion, I performed a focused search for activity associated with `b374k.php` and looked for repeated requests, response codes, referrers, and changes in the user agent.

### Web Shell Activity Analysis

After identifying references to `b374k.php`, I performed a focused search to determine whether the file had been actively used by the attacker.

The search returned five events directly associated with `b374k.php`.

The first event showed a successful GET request to:

`/wp-admin/theme-editor.php`

with a referer pointing to the same file. This suggested that the attacker had accessed the WordPress theme editor and interacted with the malicious PHP file.

More importantly, four subsequent POST requests were observed against:

`/wp-admin/admin-ajax.php`

with referers containing:

`theme-editor.php?file=b374k.php`

All requests returned HTTP status code `200`, indicating successful communication between the attacker and the server.

The repeated POST requests strongly suggested active interaction with the web shell rather than a simple file upload or accidental access. This behavior is consistent with command execution or post-exploitation activity performed through a web shell interface.

<img width="1905" height="554" alt="Ekran görüntüsü 2026-06-13 174022" src="https://github.com/user-attachments/assets/31c3d7bf-c0ba-4db5-ad24-adaae5a586d5" />

> Web shell related activity showing successful access to b374k.php and multiple POST requests consistent with attacker interaction.

### Web Shell Findings

The investigation confirmed that the attacker successfully progressed beyond the initial brute-force activity and gained access to a web shell identified as `b374k.php`.

Key observations included:

- Hydra-based brute-force activity targeting `wp-login.php`.
- Successful authentication and subsequent access to the WordPress theme editor.
- Discovery and access of the file `b374k.php`.
- Multiple POST requests referencing `b374k.php`.
- Repeated HTTP 200 responses indicating successful communication with the server.
- Evidence of active post-exploitation activity through the web shell.

Based on the available evidence, the investigation confirmed that the attacker successfully progressed from initial access attempts to active interaction with a web shell on the target server.

Evidence of Hydra-based brute-force activity, successful access to the WordPress administration interface, and repeated interaction with the identified web shell strongly indicated active post-exploitation behavior.

As a result, the alert was classified as a True Positive security incident requiring immediate containment, escalation, and further incident response activities.

## SPL Search Notes

The exact field names depend on the lab parsing. These are the search patterns I used to document the pivots; in a production environment I would replace `index=*` and confirm the available fields first.

### Linux authentication activity

```spl
index=linux_secure "10.10.242.248"
("Failed password" OR "Accepted password" OR "Invalid user")
| table _time host user src_ip _raw
| sort 0 _time
```

### Scheduled task and payload artifacts

```spl
index=* ("AssessmentTaskOne" OR "certutil.exe" OR "DataCollector.exe" OR "rv.exe")
| table _time host user process_name process_command_line TaskName _raw
| sort 0 _time
```

### WordPress and suspected web-shell activity

```spl
index=* "171.251.232.40"
("Hydra" OR "b374k.php" OR "admin-ajax.php")
| table _time src_ip http_method uri_path status user_agent referer
| sort 0 _time
```

## Containment and Follow-up

- Disable or reset the compromised accounts and review active sessions.
- Isolate affected hosts before removing the scheduled task, downloaded payload, or suspected web shell.
- Review other systems for the same source IPs, task name, filenames, hashes, and account activity.
- Preserve authentication, endpoint, scheduled-task, and web logs before cleanup.
- Confirm whether the local account `system-utm` has privileged group membership and remove it if unauthorized.
- For the WordPress case, preserve the suspicious PHP file and review web-server and process telemetry before deletion.

## Investigation Limitations

- The cases use lab data and do not contain every log source that would be available during a production incident.
- HTTP 200 responses and repeated POST requests are strongly consistent with active web-shell use, but command execution would require request-body, response-content, PHP, or endpoint process evidence.
- Successful authentication followed by privileged activity supports account compromise, but session identifiers and audit logs would provide stronger attribution.

## MITRE ATT&CK Mapping

Throughout the investigation, multiple attacker techniques were identified and mapped to the MITRE ATT&CK framework.

| Tactic                       | Technique                                                | ID        |
| ---------------------------- | -------------------------------------------------------- | --------- |
| Credential Access            | Brute Force                                              | T1110     |
| Initial Access / Persistence | Valid Accounts                                           | T1078     |
| Privilege Escalation         | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 |
| Persistence                  | Create Account: Local Account                            | T1136.001 |
| Persistence                  | Scheduled Task/Job                                       | T1053.005 |
| Execution                    | PowerShell                                               | T1059.001 |
| Command and Control          | Ingress Tool Transfer                                    | T1105     |
| Persistence                  | Web Shell                                                | T1505.003 |
| Command and Control          | Application Layer Protocol: Web Protocols                | T1071.001 |


The table combines techniques observed across the three lab alerts. I did not treat them as one campaign because the available evidence does not establish a shared timeline, operator, or infrastructure.

## Conclusion

All three alerts were valid, but they represented separate investigation paths.

The Linux case showed a clear sequence from repeated authentication failures to a successful login, privileged access, and creation of a local account. The scheduled-task case showed a task configured to retrieve and execute an external payload. The WordPress case showed Hydra activity followed by repeated interaction with a suspicious PHP file, which is strongly consistent with web-shell use.

The main lesson for me was to avoid stopping at the alert title. The useful evidence came from the pivots: accepted logins after failures, the account and process context behind a scheduled task, and the web requests that remained after automated scanner traffic was removed.
