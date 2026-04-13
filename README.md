### Part 2: Microsoft Sentinel Alert Configuration


*   **Alert Name:** `SOC Alert: Coordinated Phishing & Malware Delivery Campaign`
*   **Description:** `Detects the delivery or execution of known malicious IoCs associated with a multi-vector phishing campaign, including NjRAT, fake Adobe updates, and malicious HTML attachments.`
*   **Severity:** **High** 
*   **MITRE ATT&CK Tactics:** `Initial Access`, `Execution`, `Command and Control`, `Credential Access`

---

### Part 3: The All-In-One Master KQL Query 

*Why this query is expert-level:* It queries `EmailEvents` to see if the email hit an inbox, `EmailUrlInfo` to see if the specific bad link was in the email, `DeviceFileEvents` to see if the user downloaded the attachment, and `DeviceNetworkEvents` to see if the user clicked the link and connected to the bad server. **It tracks the entire lifecycle of a phishing attack.**

```kusto
let maliciousSenders = dynamic([
    "zelatcol@gmail.com", 
    "alfredegov@gmail.com"
]);

let maliciousDomains = dynamic([
    "vmi1159541.contaboserver.net", 
    "theannoyingsite.com", 
    "haproxy-storage.infomaniak.ch"
]);
let maliciousIPs = dynamic([
    "188.166.15.204", "209.145.51.44", "50.116.11.184", "192.178.210.101"
]);

let maliciousHashes = dynamic([
    "6d370823edf23ff298c38403621d1a1f5977877b4393a3dba1049831a91e72fb",
    "9f31aa08f90b6129b89d877fd26ac850e1c990e36e49f6a3c6879ecc036e1cb7",
    "e2b58df558ac5619175171c2e005e60e23aa0379cac876b80ae8b5512d864fd0",
    "547aa126a73ed64b64ec9e0342b85b92effdeb97176363ff0a80f97322f0619b"
]);

let emailHits = EmailEvents
| where SenderFromAddress in~ (maliciousSenders)
| project TimeGenerated, Target = RecipientEmailAddress, DetectionType = "Malicious Email Delivered", Evidence = SenderFromAddress, Action = DeliveryAction;

let urlHits = EmailUrlInfo
| where Url has_any ("wtools.io/paste-code/bOs4", "payload.exe") or UrlDomain in~ (maliciousDomains)
| project TimeGenerated, Target = NetworkMessageId, DetectionType = "Malicious URL in Email", Evidence = Url, Action = "URL Detected";

let networkHits = DeviceNetworkEvents
| where RemoteUrl in~ (maliciousDomains) or RemoteIP in~ (maliciousIPs)
| project TimeGenerated, Target = DeviceName, DetectionType = "Malicious Network Connection", Evidence = coalesce(RemoteUrl, RemoteIP), Action = ActionType;

let fileHits = DeviceFileEvents
| where SHA256 in~ (maliciousHashes)
| project TimeGenerated, Target = DeviceName, DetectionType = "Malicious File Downloaded", Evidence = FileName, Action = ActionType;

union isfuzzy=true emailHits, urlHits, networkHits, fileHits
| sort by TimeGenerated desc
```

