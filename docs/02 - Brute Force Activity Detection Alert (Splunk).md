# Initial Access Alert

## Introduction

In this investigation, I analyzed a security alert generated within a Linux environment using Splunk.

The alert, **Brute Force Activity Detection**, indicated a high volume of authentication attempts originating from the internal IP address `10.10.242.248` and targeting the host `tryhackme-2404`. At first glance, the activity appeared suspicious, but additional analysis was required to determine whether the alert represented a genuine security incident or a false positive.

Using Splunk, I examined authentication logs, reviewed failed and successful login attempts, identified the targeted accounts, and investigated the attacker's actions following initial access. As the investigation progressed, evidence of account compromise, privilege escalation, and persistence activities was uncovered.

The objective of this investigation was to determine the validity of the alert, reconstruct the attack timeline, and understand the overall impact of the activity on the affected system.


<img width="920" height="379" alt="Ekran görüntüsü 2026-06-13 145753" src="https://github.com/user-attachments/assets/b6eb2a5b-266c-4184-b95b-e2989d7aac6f" />

> Initial security alert indicating potential brute force activity against host tryhackme-2404 from source IP 10.10.242.248.

## Initial Log Analysis

To begin the investigation, I searched for authentication-related events associated with the source IP address provided by the alert. My goal was to determine whether the activity consisted of failed logins, successful logins, or attempts against non-existent accounts.

Using the source IP address (`10.10.242.248`), I filtered authentication events within the `linux_secure` logs and reviewed login activity associated with the host `tryhackme-2404`.

The results revealed a large number of authentication attempts originating from the same source IP address. More importantly, several events referenced invalid user accounts, indicating that the attacker may have been attempting to enumerate valid usernames before launching a brute force attack.

At this stage, the activity appeared suspicious; however, there was not yet enough evidence to confirm whether a legitimate account had been successfully compromised.

<img width="1913" height="781" alt="Ekran görüntüsü 2026-06-13 150537" src="https://github.com/user-attachments/assets/6a3176db-ba9f-4334-92f5-f484826eeffc" />

> Initial authentication log review showing failed login attempts and invalid user activity originating from source IP 10.10.242.248.

## Identifying the Targeted User

After confirming the presence of suspicious authentication activity, the next step was to determine whether a specific account was being targeted.

To answer this question, I analyzed the number of login attempts associated with each username observed in the authentication logs. This approach helped identify which accounts attracted the highest level of attention from the source IP address.

The results revealed that four user accounts were present within the dataset; however, one account stood out significantly from the others.

<img width="1898" height="437" alt="Ekran görüntüsü 2026-06-13 154052" src="https://github.com/user-attachments/assets/70dd6412-a598-4750-99b6-5cce07713d94" />

> Authentication attempts grouped by username, revealing that john.smith was targeted by 503 login attempts from source IP 10.10.242.248.


The analysis revealed that four different user accounts were targeted by authentication attempts originating from the source IP address 10.10.242.248.

Among them, the account john.smith stood out significantly, receiving a total of 503 login attempts. This volume was substantially higher than that observed for the other accounts and provided strong evidence that john.smith was the primary target of the attack.

At this stage, the investigation confirmed clear indicators of brute force activity. However, it was still necessary to determine whether any of these authentication attempts were successful and whether the attacker had gained access to the system.


## Evidence of Successful Compromise


At this stage, the investigation had already identified john.smith as the primary target of the brute force activity. However, a critical question still remained:

Were any of the authentication attempts successful?

To answer this question, I expanded the analysis to include both failed and successful authentication events associated with each username. This allowed me to determine whether the attacker was able to obtain valid credentials and gain access to the target system.

<img width="1743" height="470" alt="Ekran görüntüsü 2026-06-13 154825" src="https://github.com/user-attachments/assets/f8fa4d05-ae3a-4488-accd-b4d71e562e20" />

> Authentication results showing both failed and successful login attempts for john.smith, confirming account compromise.

The results showed that the account john.smith contained both Failed and Accepted authentication events. In contrast, all other accounts were associated only with failed authentication attempts.

This finding confirmed that the attacker was eventually able to authenticate successfully after multiple failed login attempts, indicating that valid credentials had been obtained through brute force activity.

Based on the available evidence, the attacker successfully gained access to the host tryhackme-2404, allowing the alert to be classified as a True Positive security incident.

With account compromise confirmed, the next step was to investigate the attacker's actions after gaining access to the system.

## Privilege Escalation Activity

After confirming that the attacker had successfully authenticated to the system using the compromised `john.smith` account, the next step was to determine whether any post-compromise activity had taken place.

A successful login alone does not necessarily indicate the full extent of an intrusion. Attackers often attempt to elevate their privileges after gaining initial access in order to obtain administrative control over the target system.

To investigate this possibility, I reviewed successful authentication events associated with the compromised account and searched for evidence of privileged session creation.


<img width="1525" height="702" alt="Ekran görüntüsü 2026-06-13 155617" src="https://github.com/user-attachments/assets/8013023c-ec75-44a7-813f-786b3a7a13b8" />

> Successful authentication and privilege escalation activity showing john.smith obtaining root-level access on the target system.


The investigation revealed multiple successful authentication events associated with the `john.smith` account. More importantly, the logs showed privileged sessions being opened for the `root` account through both `sudo` and `su` activity.

These events confirmed that the attacker was able to escalate privileges after gaining access to the system, ultimately obtaining root-level permissions on the host `tryhackme-2404`.

The presence of privileged session creation significantly increased the severity of the incident, as root access provides unrestricted control over the affected Linux system.

With privilege escalation confirmed, the next step was to determine whether the attacker established persistence by creating additional user accounts or implementing mechanisms to maintain long-term access.

## Persistence Mechanism


After obtaining root-level access, the next objective was to determine whether the attacker attempted to maintain long-term access to the compromised system.

Attackers frequently establish persistence mechanisms following privilege escalation to ensure they can regain access even if the original compromised credentials are changed or revoked.

To investigate potential persistence activity, I searched for evidence of new account creation and other administrative actions performed after the attacker obtained root privileges.

<img width="1908" height="440" alt="Ekran görüntüsü 2026-06-13 160125" src="https://github.com/user-attachments/assets/7ec90c33-62e3-41c0-b275-c5e5e39b2e54" />

> Evidence of a newly created user account, indicating an attempt to establish persistence on the compromised system.


The investigation revealed a `useradd` event indicating that a new user account named `system-utm` was created on the host `tryhackme-2404`.

Because this activity occurred after the attacker successfully authenticated and obtained root-level access, the account creation is highly suspicious and consistent with a persistence mechanism.

Creating additional user accounts is a common attacker technique used to maintain access to compromised systems while reducing reliance on the originally compromised credentials.

This finding confirmed that the attacker not only gained access to the system but also took steps to establish long-term persistence within the environment.


## Investigation Findings

The investigation identified multiple indicators confirming that the alert represented a genuine security incident rather than a false positive.

### Key Findings

- Source IP `10.10.242.248` generated a large volume of authentication attempts against the host `tryhackme-2404`.
- Multiple invalid user login attempts suggested username enumeration activity.
- The account `john.smith` was targeted by **503 authentication attempts**, indicating a brute force attack.
- Successful authentication events confirmed that the attacker gained access using the compromised `john.smith` account.
- The attacker escalated privileges and obtained **root-level access** through `sudo` and `su` activity.
- A new user account named `system-utm` was created, indicating an attempt to establish persistence on the compromised host.

Based on the collected evidence, the alert was classified as a **True Positive** security incident requiring immediate escalation and remediation.

The investigation confirmed that the attacker successfully compromised the `john.smith` account through brute force activity, escalated privileges to `root`, and established persistence by creating a new local account.

While the initial intrusion had been identified and validated, the investigation was not yet complete. The next alert focused on determining whether the attacker maintained ongoing access to the environment through persistence mechanisms.

# Persistence Alert

## Introduction

Following the investigation of the initial access alert, a second alert was generated involving potential persistence activity on a Windows workstation.

The alert indicated that a scheduled task named `AssessmentTaskOne` had been created on the host `WIN-H015` under the user account `oliver.thompson`.

Scheduled tasks are commonly used by administrators for automation purposes; however, they are also frequently abused by attackers to maintain persistence and execute malicious payloads at predefined intervals.

The objective of this investigation was to determine whether the scheduled task represented legitimate administrative activity or an attacker persistence mechanism.

## Alert Scenario

<img width="901" height="392" alt="Ekran görüntüsü 2026-06-13 161355" src="https://github.com/user-attachments/assets/4315ca5b-a00c-41f6-a85c-7af3fa3af3b3" />

> Alert indicating the creation of a scheduled task named AssessmentTaskOne on host WIN-H015 under the account oliver.thompson.

## Initial Alert Assessment

Before moving directly into Splunk, I first reviewed the alert details to establish context around the activity.

The alert was generated on the workstation `WIN-H015` and was associated with the user account `oliver.thompson`. Unlike server systems, user workstations are less likely to require the creation of recurring scheduled tasks, making this activity worthy of further investigation.

Additionally, the task name `AssessmentTaskOne` did not immediately indicate a legitimate business function. Combined with the persistence-related alert classification, this provided sufficient reason to continue the investigation within Splunk.

At this stage, the objective was to determine what the scheduled task was designed to execute and whether it represented legitimate administrative activity or malicious persistence.

## Scheduled Task Analysis

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

## Malicious Command Analysis

After reviewing the task schedule, the next step was to examine the commands executed by the scheduled task.

The Exec section of the task configuration revealed both the executable responsible for launching the task and the arguments passed to it during execution. This information is often critical for determining whether a scheduled task is performing legitimate administrative actions or executing malicious activity.

<img width="1168" height="241" alt="Ekran görüntüsü 2026-06-13 164337" src="https://github.com/user-attachments/assets/6c277797-9ecd-4b69-978c-b84c28a5d726" />

> Exec and Principals sections showing the command executed by AssessmentTaskOne and the user context under which it runs.

Reviewing the Exec section revealed that the task was configured to launch `powershell.exe` and execute a command containing `certutil.exe`, a legitimate Windows utility commonly abused by attackers for file downloads.

The command attempted to download a file named `rv.exe` from the external domain `tryhotme:9876` and save it locally as `DataCollector.exe` within the user's temporary directory. After the download completed, the task used `Start-Process` to immediately execute the downloaded file.

The Principals section showed that the task would run under the context of the user account `oliver.thompson`, ensuring that the downloaded payload would execute whenever the scheduled task was triggered.

At this stage, the activity could no longer be considered normal administrative behavior. The use of `certutil.exe` for file retrieval, followed by execution of a downloaded executable, strongly suggested malicious intent and provided clear evidence of a persistence mechanism designed to deliver and run malware.

## Persistence Findings


The investigation confirmed that the scheduled task `AssessmentTaskOne` was not performing legitimate administrative activity.

Analysis of the task configuration revealed that it was designed to execute daily, download an external executable using `certutil.exe`, save it locally as `DataCollector.exe`, and immediately launch the payload through PowerShell.

The task was configured to run under the user account `oliver.thompson`, ensuring that the payload would execute automatically whenever the scheduled trigger was activated.

Taken together, these findings strongly indicate an attacker persistence mechanism designed to maintain access and facilitate malware execution on the compromised workstation.

Based on the available evidence, the alert was classified as a True Positive security incident. The identified persistence mechanism, combined with the automated download and execution of an external payload, warranted immediate escalation for containment and further incident response activities.

## Investigation Findings

### Key Findings

- A scheduled task named `AssessmentTaskOne` was created on host `WIN-H015`.
- The task was configured to execute daily under the context of `oliver.thompson`.
- The task used `certutil.exe` to download an external executable (`rv.exe`).
- The downloaded file was saved as `DataCollector.exe` and executed through PowerShell.
- The activity demonstrated a persistence mechanism designed to maintain attacker access.
- The alert was classified as a **True Positive** security incident.

The persistence mechanism was successfully identified and validated. However, the investigation was not yet complete.

The next alert focused on determining whether the downloaded payload had been executed successfully and whether it had resulted in further compromise of the affected system.

# Web Shell Alert





































