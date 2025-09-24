# Brute Force Incident Response Lifecycle  

<img width="710" height="400" alt="image" src="https://github.com/user-attachments/assets/3c8c0b18-f62a-45c0-8882-2d3de8e4d290" />


[Investigation Report](https://docs.google.com/document/d/10tWE1wahkRUgn_Joy-IpGosjWXdQ6cyWPEBmc7GBCcQ/edit?tab=t.0)

## Introduction  
This project demonstrates the **incident response lifecycle** for a suspected brute force attack. Using Microsoft Sentinel and Defender for Endpoint, I walk through detection, analysis, containment, eradication, recovery, and post-incident activities — mirroring real SOC workflows.  

---

## 🔎 Detection  
To detect brute force attempts, I created a custom rule in **Microsoft Sentinel**. The rule identifies when the same remote IP address has failed to log in to the same local host **10 times or more within a 5-hour window**.  

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where TimeGenerated >= ago(5h)
| summarize BruteForceAttempts = count() by RemoteIP, DeviceName
| where BruteForceAttempts >= 10
```
<img width="800"  alt="image6" src="https://github.com/user-attachments/assets/9c926517-d1ad-4a6f-a61c-11069cc4fea7" />


Once deployed, the rule triggered an incident in Sentinel. I assigned the case to myself and marked it **Active**.  
<img width="800"  alt="image2" src="https://github.com/user-attachments/assets/0752f86e-6daf-40d7-bf9e-a0e976ab0e91" />


---

## 📊 Analysis  
I investigated the triggered incident in Sentinel.  

- **Scope of activity:**  
  - 8 separate assets targeted  
  - 28 source IP addresses involved  
  - 9 unique public IPs confirmed as sources  
<img width="800" alt="image1" src="https://github.com/user-attachments/assets/5c3a91cb-184b-43ff-9d2d-50d9a0127a0c" />

To validate whether any of these brute force attempts were successful, I ran the following query:  

```kql
DeviceLogonEvents
| where ActionType != "LogonFailed"
| where RemoteIP in ("07.136","196.251.88.103","134.199.197.70","183.4.22.154",
"85.122.94.52","59.18.141.14","210.222.67.223","222.114.67.46","222.252.97.171")
```

**Result:** No successful logons were observed.  
<img width="800"  alt="image5" src="https://github.com/user-attachments/assets/8d2b8180-e208-4c24-8d1c-b1e041858771" />

---

## 🛡 Containment, Eradication, Recovery  
Although the brute force attempts were unsuccessful, I carried out containment and recovery actions to ensure no further exposure:  

- Isolated the affected assets and scanned with **Microsoft Defender Endpoint**.  
- Hardened the **Network Security Group (NSG)** to block inbound RDP (TCP/3389) from the public internet.  
<img width="600"  alt="image3" src="https://github.com/user-attachments/assets/706c4c45-fc59-4b97-8dca-787835aa13b0" />

At this point, no compromise was detected and systems were confirmed clean.  

---

## 📑 Post-Incident Activities  
All investigation details were documented in Sentinel’s activity log. To strengthen long-term defenses, I proposed a security policy requiring all company assets to follow a similar NSG rule.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/bd73ea04-b5ee-4be7-8103-b81db95d4f05" />

[Policy Proposal](https://docs.google.com/document/d/14U9vmfhzLg65EiOlY1ilhv7NJKfhCnphinoaE_oh3cw/edit?tab=t.0)  

---

## ✅ Closure  
- Reviewed incident notes and finalized the investigation report.
- Closed the case in Sentinel as a **Benign Positive**.  
- Lessons learned were rolled into updated access control policy.  

---

## MITRE ATT&CK Mapping  
- **T1110 – Brute Force**: Multiple failed authentication attempts.  
- **T1078 – Valid Accounts (Prevented)**: Potential objective was credential compromise.  
- **T1133 – External Remote Services**: Targeting of RDP services.  
- **T1046 – Network Service Scanning (Implied)**: Reconnaissance prior to brute force attempts.  

---

## References  
- [MITRE ATT&CK Framework](https://attack.mitre.org/)  
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)  
- [Microsoft Defender for Endpoint](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/)  
