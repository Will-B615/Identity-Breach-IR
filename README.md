# Sentinel Incident Response Walkthrough (RangeForce Lab)

---
# Incident Overview 

On October 16, 2025, a Microsoft Sentinel analytics rule was triggered by known indicators of compromise (IOCs) associated with a recognized DPRK threat actor. The incident signaled suspicious login activity and subsequent malicious actions, suggesting a probable identity compromise in the enterprise environment. This report summarizes the incident’s investigation, findings, and recommendations.  

- Log Sources and Investigation Tools 

- SignInLogsCL: Detailed Entra ID sign-ins, geolocation, session ID, and IP mapping. 

- AuditLogsCL: Tracks user actions, application permission changes, and configuration events. 

- Kusto Query Language (KQL): Used to query and analyze the above log sources for investigative clarity.Sentinel-Investigation1.pdf  

---
 

# Investigation Steps 

**1. Incident Identification** 


  - Identified the incident triggered by a Microsoft Sentinel analytics rule, matching known IOCs associated with a specific threat actor. 

**2. Rule and MITRE Technique Confirmation** 


  - Determined the analytics rule responsible and confirmed the number of MITRE ATT&CK technique IDs assigned to the incident. 

**3. User Attribution** 


  - Used log sources to identify the user account (jthomas@QuantrexPartners.com) involved in activity that triggered the rule. 

**4. Event Association** 


  - Confirmed the quantity of events linked to the incident in the logs. 

**5. Suspicious IP Analysis**

   
  - Queried SignInLogsCL for user activity associated with these IPs.
  
  - Extracted suspicious IP addresses from incident IOCs.
      
SignInLogs_CL

      | summarize Count = count() by  
          UserDisplayName,  
          IPAddress,  
          Country = tostring(LocationDetails.countryOrRegion)

  - Correlated activities with the geolocation and country of origin for each IP.

<img width="680" height="552" alt="Screenshot 2025-10-16 161900" src="https://github.com/user-attachments/assets/4d0b955c-4f28-4b93-99de-54abefae7d86" />


**6. First Compromise Analysis**

   - Identified the application used and extracted corresponding session IDs.

SignInLogs_CL

      | summarize Count = count() by  
          UserDisplayName,  
          IPAddress,  
          Country = tostring(LocationDetails.countryOrRegion),  
          AppDisplayName 
      | order by Count desc



  - Located the initial login from the malicious IP addresses. 

<img width="680" height="552" alt="Screenshot 2025-10-16 161900" src="https://github.com/user-attachments/assets/d675a80e-58d8-4c80-bbd5-05589c1a08de" />


**7. Session Hijacking Investigation**

- Pinpointed evidence of MITM/On-Path attack by confirming the same session ID originating from both legitimate and malicious IPs.
   
SignInLogs_CL

    | where IPAddress in ("154.47.16.50", "154.47.16.42")
    | summarize  
        Count = count(),  
        FirstSeen = min(TimeGenerated),  
        LastSeen = max(TimeGenerated)  
      by  
        UserDisplayName,  
        IPAddress,  
        Country = tostring(LocationDetails.countryOrRegion),  
        AppDisplayName,  
        SessionId 
    | order by FirstSeen asc


SignInLogs_CL

    | where SessionId == "003f81e9-cd6b-a865-9b60-fdb958285be3"
    | project  
        TimeGenerated,  
        UserDisplayName,  
        IPAddress,  
        Country = tostring(LocationDetails.countryOrRegion),  
        AppDisplayName,  
        SessionId 
    | order by TimeGenerated asc


**8. User-Agent Profiling** 

- Reviewed user-agent strings for sign-ins with the compromised session ID to determine attacker technique. 

SignInLogs_CL

    | where SessionId == "003f81e9-cd6b-a865-9b60-fdb958285be3"
    | project  
        TimeGenerated,  
        UserDisplayName,  
        IPAddress,  
        Country = tostring(LocationDetails.countryOrRegion),  
        AppDisplayName,  
        SessionId,  
        UserAgent 
    | order by TimeGenerated asc


**9. Post-Compromise Activity Investigation** 

- Switched the focus to AuditLogsCL for non-login actions following the compromise. 

- Identified the first application-related activity (OperationName) performed after the threat actor's login. 

**10. Persistence Technique Discovery** 

- Discovered that the threat actor created a new application (“production-important”) for persistent access. 

<img width="957" height="657" alt="Screenshot 2025-10-16 165232" src="https://github.com/user-attachments/assets/283721f9-0f2a-4323-991f-16dadd3d22d2" />


**11. Privilege Escalation and Lateral Movement Investigation** 

- Investigated attempted invitations for external users (bluelagoon@protonmail.com) to expand access. 

- Verified that policy enforcement thwarted these attempts. 

<img width="920" height="471" alt="Screenshot 2025-10-16 171154" src="https://github.com/user-attachments/assets/a24b959c-d20b-45a5-9989-8aa189d7020f" />


**12. Result Validation** 

- Assessed the final results of malicious actions, confirming that restrictive policies resulted in “clientError” outcomes for unauthorized activities. 

<img width="919" height="535" alt="Screenshot 2025-10-16 171637" src="https://github.com/user-attachments/assets/abd8e893-6550-42cc-a946-9c565af51fde" />


--- 
 

# Incident Timeline 

- Alert Trigger: Sentinel analytics rule with multiple IOC-matching IPs. 

- Initial Compromise: Sign-in by user jthomas@QuantrexPartners.com from suspicious IPs associated with Colombia. 

- Advanced Tactics: Signs of MITM (Man-in-the-Middle) due to duplication of session IDs between legitimate and attacker IPs. 

- Persistence Attempt: Malicious post-login creation of a new application for persistence. 

- Privilege Escalation/Expansion: Attempt to invite an external user for lateral access, blocked by tenant policy.

---

# Key Findings 

| Category                    | Details                                                                                                      |
|-----------------------------|--------------------------------------------------------------------------------------------------------------|
| Trigger Rule                | Near Real-Time (NRT) IOC-based indicator rule                                                                |
| User Account Involved       | jthomas@quantrexPartners.com                                                                                 |
| Initial Compromise Vector   | OfficeHome login from Colombia using IOCs                                                                    |
| MITRE Techniques Observed   | MITM/On-Path attack, persistence via application registration, attempted external user invitation             |
| Malicious IPs Detected      | 154.47.16.50, 154.47.16.42 (plus additional IOCs)                                                            |
| Session Hijacking           | Same Session ID used from multiple IP addresses (legitimate and malicious)                                   |
| New App Created             | `production-important`                                                                                       |
| External User Targeted      | bluelagoon@protonmail.com (invite failed due to client policy)                                               |
| Post-Compromise Actions     | Non-login events mainly involved app creation and external account invitation attempts                        |
| Result of Malicious Actions | Invite failures (clientError), indicating some protective policy effectiveness                                |

---

# Analysis and Conclusions 

- The compromise originated from a login using known IOC-tagged IPs, followed by MITM-style session hijacking and malicious post-login persistence activities. 

- Creation of a suspicious application indicated an attempt at persistent access typical of advanced threat actors. 

- External invitation attempts were unsuccessful, highlighting the importance of strict external collaboration controls. 

- Investigation steps were guided and validated with KQL queries, leveraging best practices in log analysis for speed and accuracy.Sentinel-Investigation1.pdf  

---

# Recommendations 

- Review and enhance analytic rules in Sentinel to prioritize IOC-based triggers and MITM signature detections. 

- Ensure application creation and external user invitations are highly restricted via policy. 

- Regularly monitor for duplicate session ID activity and cross-IP session anomalies. 

- Conduct targeted user-awareness training, especially around session hijacking and privilege escalation vectors. 

- Perform retrospective hunting for similar IOC use and session duplication patterns in historic log data. 
