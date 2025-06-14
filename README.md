# Brute Force Investigation in Exposed Azure VMs

This project documents a simulated threat hunting operation to identify brute-force attacks against exposed Azure virtual machines (VMs) using Microsoft Defender for Endpoint and Azure Sentinel. It showcases structured investigation phases, KQL queries, findings, mapped MITRE ATT&CK TTPs, and recommended mitigations. It is tailored to support interview discussions.

## 🧭 1. Preparation
**Goal:** Set up the hunt by defining the objective.

During a routine maintenance cycle, our security team received a directive to assess all shared services VMs—especially those handling DNS, DHCP, and Active Directory functions—for exposure to the public internet. The intent was to identify misconfigurations and assess the risk of brute-force login attempts.

**Hypothesis:**
Older systems without account lockout policies may have been targeted by brute-force login attacks. If successful, this could allow lateral movement within the network.

> 📸 Screenshot:
![Screenshot 2025-06-14 103627](https://github.com/user-attachments/assets/dad94bc4-8e4e-4b7f-b90d-54a0f9b7b6bd)

---

## 📥 2. Data Collection
**Goal:** Gather data from critical sources: endpoints, logs, and network signals.

- Verified that Defender for Endpoint and Azure Sentinel were ingesting logs via the Log Analytics Workspace.
- Queried `DeviceInfo` to identify internet-exposed systems.
- Queried `DeviceLogonEvents` to gather information on failed and successful login attempts from remote IPs.

> 📸 Screenshot:
![Screenshot 2025-06-14 114504](https://github.com/user-attachments/assets/af7a6f9b-f4e1-409f-884b-8396b344f303)

---

## 🧪 3. Data Analysis
**Goal:** Test the hypothesis through data inspection.

Used KQL queries to:
- Identify high-volume failed login attempts from external IPs.
- Check for any subsequent successful logons from those same IPs.

### 🔍 Query 1: Top failed logons
```kusto
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
> 📸 Screenshot:
![Screenshot 2025-06-14 114725](https://github.com/user-attachments/assets/721c3a55-4483-49a3-b027-43466a996c1d)

### 🔍 Query 2: Logon success from suspicious IPs
```kusto
let RemoteIPsInQuestion = dynamic(["119.42.115.235", "183.81.169.238", "74.39.190.50"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
> 📸 Screenshot:
![Screenshot 2025-06-14 121716](https://github.com/user-attachments/assets/4009a907-2d04-4700-95af-e9bd574f37a5)

---

## 🔎 4. Investigation
**Goal:** Examine and validate potential threats.

### 📊 Query 3: Failed vs. successful logons by IP
```kusto
let FailedLogons = DeviceLogonEvents
| where ActionType == "LogonFailed" and isnotempty(RemoteIP);
let SuccessfulLogons = DeviceLogonEvents
| where ActionType == "LogonSuccess" and isnotempty(RemoteIP);
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

Findings:
- No overlap of failed and successful logons.
- One legitimate account had a single success with no prior failures.

---

## 🛡️ 5. Response
**Goal:** Remediate confirmed issues and secure the environment.

Actions taken:
- Hardened NSG (Network Security Group) rules to restrict RDP to known IPs.
- Enforced account lockout policies to prevent brute force.
- Enabled MFA (Multi-Factor Authentication) on all privileged accounts.

---

## 📝 6. Documentation
**Goal:** Maintain clear records of findings and actions.

Logged:
- Timeline of VM exposure.
- Volume and origin of failed login attempts.
- Outcome of each analysis query.

---

## 🔄 7. Improvement
**Goal:** Enhance visibility and prevent future misconfigurations.

- Integrated NSG alerts with Sentinel.
- Set up alert rules in Microsoft Defender for excessive login failures.
- Recommended scheduled reviews of internet exposure status using KQL automation.

---

## 🎯 MITRE ATT&CK Mapping
| Technique ID     | Description                                              |
|------------------|----------------------------------------------------------|
| T1595            | Active Scanning of externally exposed services          |
| T1110.001        | Brute Force: Password Guessing                          |
| T1082            | System Information Discovery                            |
| T1046            | Network Service Scanning                                |
| T1078            | Valid Accounts (potential use of compromised credentials)|
| T1056.001        | Input Capture: Keylogging (related investigation path)  |
| T1071.001        | Application Layer Protocol: Web Protocols (C2 vector)   |
| T1562.001        | Impair Defenses: Disable or Modify Tools                |
| T1587            | Develop Capabilities (Detection engineering phase)      |
| T1588.002        | Obtain Capabilities: Tool (hunt automation, scripts)    |
| T1560            | Archive Collected Data (for long-term detection trends) |
| T1489            | Service Stop (if required as containment method)        |

---
**Author:** Felipe Restrepo  
**Date:** June 14, 2025  
**Tools:** Microsoft Defender for Endpoint, Azure Sentinel, KQL
