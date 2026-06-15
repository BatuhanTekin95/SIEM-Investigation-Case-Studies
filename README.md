# SIEM-Investigation-Case-Studies

## Overview

After completing my **SOC Phishing Case Studies** project, I wanted to focus on another core responsibility of a SOC Analyst: **SIEM investigation and log analysis**.

One of the final investigations in my previous project, **[Boogeyman3: Phishing-to-Ransomware Investigation (Elastic Security)](https://github.com/BatuhanTekin95/SOC-Phishing-Case-Studies/blob/main/docs/03-Boogeyman3-Phishing-to-Ransomware-Investigation-Elastic-Security.md)**, involved analyzing a multi-stage attack that progressed from an initial phishing email to credential theft, lateral movement, Active Directory compromise, and ransomware deployment. Throughout that investigation, Elastic Security played a key role in helping me trace attacker activity, correlate events, and reconstruct the attack timeline.

Building on that experience, I created this repository to further develop and document my SIEM investigation skills through hands-on analysis and practical security scenarios.

This project focuses on how security events are collected, analyzed, and investigated within a SIEM platform. Using Splunk, I explore log analysis techniques, detection methodologies, alert validation, and incident investigation workflows commonly used in Security Operations Centers (SOCs).

Each lab is documented step-by-step to demonstrate the investigation process, highlight important findings, and provide insight into the reasoning behind each analytical decision.

The goal of this repository is not only to strengthen my understanding of SIEM technologies but also to build a collection of practical investigations that showcase my approach to security monitoring, threat detection, and incident analysis.

I enjoyed working through these investigations and documenting the findings along the way. Hopefully, anyone exploring this repository will find the content both informative and engaging while following the investigation process.


## Repository Structure

### 01 - [Splunk Fundamentals](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/blob/main/docs/01-Splunk-Fundamentals.md)

An introduction to SIEM concepts, log analysis fundamentals, Windows and Linux log sources, SPL queries, data visualization, and the MITRE ATT&CK framework.

### 02 - [Multi-Stage Attack Investigation (Splunk)](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/blob/main/docs/02%20-%20Multi-Stage%20Attack%20Investigation%20%28Splunk%29.md)

Investigation of a multi-stage intrusion involving initial access, privilege escalation, persistence, and web shell activity through Splunk log analysis. The investigation focuses on correlating security events, validating alerts, and reconstructing the attack timeline.

### 03 - [Active Directory Lateral Movement Investigation (Splunk)](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/blob/main/docs/03%20-%20Active%20Directory%20Lateral%20Movement%20Investigation%20%28Splunk%29.md)

Investigation of attacker activity within an Active Directory environment, including PowerShell-based discovery, SMB access, PsExec execution, named pipe artifacts, RDP activity, and Domain Controller compromise.

### 04 - [Threat Hunting Investigation: Software Supply Chain Compromise (Elastic)](https://github.com/BatuhanTekin95/SIEM-Investigation-Case-Studies/blob/main/docs/04-Threat%20Hunting%20Investigation%3A%20Software%20Supply%20Chain%20Compromise%20%28Elastic%29.md)

A threat hunting investigation that follows a malicious software supply chain compromise from initial access to ransomware deployment. The investigation covers PowerShell-based payload delivery, service-based persistence, credential dumping, Pass-the-Hash abuse, DCSync activity, domain compromise, and ransomware impact analysis using Elastic Security.











