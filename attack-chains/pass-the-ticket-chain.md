#  Pass-the-Ticket (PtT) / Kerberos Ticket Abuse – T1558: Lateral Movement

**Explanation:** This playbook analyzes the **Pass-the-Ticket (PtT)** attack, where an adversary steals a valid **Kerberos Ticket Granting Ticket (TGT)** or **Service Ticket (ST)** from memory (LSASS) and reuses it to authenticate to remote services without knowing the user's password. This attack is highly effective and stealthy, as it leverages the trusted Kerberos protocol. The most reliable **Anchor Point** is the successful **extraction of a Kerberos Ticket** from the LSASS process, followed immediately by its **unusual reuse** on a peer system.

---

## 1. Attack Flow, Log Artifacts, and Investigation Focus

| Phase | MITRE ID & Technique | Primary Investigative Focus (IOCs) | Key Log Event / Action |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.003 (Valid Accounts) | **Identity/Endpoint:** Attacker gains initial access and establishes a foothold. | *(User successful login)* `Event ID 4624` on initial access host. |
| **Execution/Foothold** | T1003.001 (LSASS Memory) | **Process/File:** Credentials/Tickets are stolen from the LSASS process memory. | **Process: `Mimikatz.exe`** executing **`kerberos::list`** or **`sekurlsa::tickets`** commands. |
| **PtT Abuse (ANCHOR)**| **T1558 (Kerberos Ticket Theft)** | **DC/Identity:** A stolen ticket is injected and used on a peer system, resulting in a successful logon that bypasses typical password checks. | **Event ID 4624** (Successful Logon) on the target host, with a **Logon Type 9** (NewCredentials) or **Logon Type 3** (Network), where the ticket time/use is suspicious. |
| **Lateral Movement** | T1550.003 (Kerberoasting) | **Identity/Network:** The attacker uses the stolen tickets to request **Service Tickets (STs)** to access targets like file shares or databases. | **DC Event ID 4769** (Service Ticket granted) where the request comes from an unusual source IP. |
| **Impact / Persistence** | T1558.003 (Golden Ticket) | **DC/Identity:** The attacker steals the **`krbtgt`** hash and forges an unstoppable **Golden Ticket**. | **DC Event ID 4768** (TGT request) with suspicious TGT attributes, such as an **extended lifetime or altered privileges**. |

---

## 2. Key Forensic Artifacts (Data Pivot Points)

### High-Confidence Identity & Authentication IOCs

1.  **Ticket Injection Artifact:** The highest-fidelity IOC is the **injection artifact** on the initial compromised host. Look for the execution of tools like Mimikatz or Rubeus using arguments like **`/ptt`** (Pass-the-Ticket) or **`/ticket`** to inject the stolen Kerberos tickets into the current user's session.
2.  **Logon Type Anomaly:** On the **target** peer machine, check **Windows Security Event ID 4624** (Successful Logon). While a standard Kerberos logon uses Logon Type 3 (Network), a successful PtT/injection event often presents as a **Logon Type 9 (NewCredentials)** or a Logon Type 3 that is **not preceded by a TGT request** (Event ID 4768) from that machine, suggesting the ticket was already present or injected.
3.  **Ticket Metadata:** On the Domain Controller (DC), review **Kerberos events (4768/4769)**. Look for **TGT or ST requests** originating from a non-DC machine or an account that should not have access to the specific service. In advanced attacks (like **Golden Ticket**), the ticket's **lifetime** may be suspiciously long, or the **privilege attributes** may be inflated.

### Process, File, and Network IOCs

1.  **Preceding Credential Dump:** On the **source** (initial) host, the PtT event must be preceded by artifacts indicating credential or ticket theft (e.g., execution of tools like **`rubeus.exe`** or **`mimikatz.exe`** and corresponding access to the **`lsass.exe`** process memory).
2.  **File Artifacts:** Look for the creation of files with the **`.kirbi`** extension, which is the standard format Mimikatz uses to export Kerberos tickets. The presence of these files in non-standard directories is a critical IOC.
3.  **Network Protocol:** Analyze network flow from the source IP to the target IP. The authentication will use the Kerberos protocol (typically **TCP/88**). Look for the traffic, ensuring the *absence* of a password hash being sent, and the presence of the ticket itself.

---

## 3. Mitigation and Hardening

| Area | Best Practice / Policy | Analyst Action / Remediation |
| :--- | :--- | :--- |
| **Containment** | Limit attacker access to peer systems and invalidate the stolen tickets. | **Purge the session/ticket cache** on the source and target machines (e.g., using **`klist purge`**). **Revoke all active sessions** and force a **password reset** for the compromised account. |
| **Credential Protection** | **Implement Protected Users Group:** Accounts placed in this group cannot use cached credentials for long periods and cannot use NTLM. | Add high-value accounts (admins, service accounts) to the **Protected Users Group**. |
| **Mitigation (Golden Ticket)** | **Krbtgt Account Security:** The **`krbtgt`** account key must be securely protected, as its compromise enables the creation of unstoppable tickets. | **Perform a double password reset** on the **`krbtgt`** account to invalidate all Golden Tickets. This is a critical domain remediation step. |
| **Detection** | **Advanced Endpoint Controls:** Utilize security solutions to block or alert on **`lsass.exe` process access** and monitor for the execution of known Kerberos exploitation tools. | Configure EDR to alert on **`.kirbi` file creation** or command-line strings containing **`kerberos::`**, **`/ptt`**, or **`/ticket`**. |
