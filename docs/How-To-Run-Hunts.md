## Comprehensive Threat Hunter's Guide (L2-L3 Analysts)

This guide provides a structured approach for Level 2 and Level 3 Security Analysts to conduct proactive threat hunts using **Microsoft 365 Defender (MDE)** and **Microsoft Sentinel**. All hunts are **100% native**, utilizing only the data within the Microsoft security ecosystem, eliminating the need for external Threat Intelligence feeds.

---

### How to Run These Hunts (Native Only)

All rules in this project are 100% native hunts using **Microsoft 365 Defender** and **Microsoft Sentinel**. No external Threat Intelligence is required. The primary language for these hunts is **Kusto Query Language (KQL)**.

---

### Run in MDE Advanced Hunting

Advanced Hunting in MDE provides direct, real-time access to raw event data from endpoints, identity, email, and cloud applications.

1.  **Access Advanced Hunting:** Open **Microsoft Defender for Endpoint** $\rightarrow$ **Hunting** $\rightarrow$ **Advanced Hunting**.
2.  **Input the KQL:** Paste the KQL query from the corresponding hunt rule file (e.g., `rules/<category>/<rule>.md`).
3.  **Define Lookback:** Use a suitable time range for the hunt. For most historical hunts, a lookback of **`14d`** (14 days) is recommended, provided your data retention policy allows it.
4.  **Execute the Query:** Run the KQL query.
5.  **Inspect and Triage Results:** Scrutinize the returned records by focusing on the following synthesized fields, which aid in rapid prioritization and investigation:
    * **`ConfidenceScore`**: This score indicates the **statistical strength** or rarity of the observed behavior signal. A higher score suggests the activity is less common and warrants closer review.
    * **`Severity`**: This field assigns a **suspiciousness level** to the activity (e.g., Low, Medium, High). Use this to prioritize investigation efforts; High severity results should be acted upon immediately.
    * **`HuntingDirectives`**: These provide **actionable context** for the analyst, outlining the suspected technique, potential impact, and the recommended next steps for validation or response (e.g., "Confirm legitimate administrative tool use," "Isolate endpoint," or "Investigate parent process").

**L2/L3 Analyst Action:** Triage High-Severity hits immediately. For Medium/Low-Severity hits, document findings and investigate the **`HuntingDirectives`** to confirm if the activity is benign or malicious.

---

### Run in Sentinel

Sentinel offers a unified view across the enterprise, integrating MDE data alongside other log sources for correlation.

1.  **Access Logs:** Go to **Logs** in the Sentinel workspace connected to MDE (ensuring the necessary tables, like `DeviceProcessEvents` or `SecurityEvent`, are enabled and ingested).
2.  **Input the KQL:** Paste the **same KQL** used in MDE Advanced Hunting. KQL queries designed for MDE are generally portable to Sentinel logs if the underlying table schema is available.
3.  **Execute and Triage:** Run the query. Triage the results primarily based on the **`Severity`** and the **`HuntingDirectives`** fields, using the same principles as in MDE.

**L2/L3 Analyst Action:** Utilize Sentinel's capabilities to pivot to related logs (e.g., firewall, network, or cloud audit logs) for correlation and broader context surrounding the MDE event.

---

### Turn into Analytic Rules

Converting successful, high-fidelity hunts into scheduled Analytic Rules ensures continuous, automated monitoring for the identified threat behavior.

1.  **Locate Rule Stub:** Navigate to the `sentinel-rules/` directory within the project. Each hunt has a corresponding JSON or YAML stub file.
2.  **Edit the Query Block:** Open the desired stub file. Locate the `query` block within the rule definition.
3.  **Promote the Hunt:** Replace the placeholder content in the `query` block with the validated, high-fidelity KQL from the corresponding `.md` file.
4.  **Configure and Deploy:** Configure the rule's **scheduling**, **alert details**, **MITRE ATT&CK tactics**, and **automated response playbooks** (if applicable) before deploying it as a scheduled analytic rule within the Sentinel UI.

**L2/L3 Analyst Action:** Only promote hunts that have demonstrated a **low false-positive rate** during the initial hunt period to avoid alert fatigue. Regularly review and tune these analytic rules.

---

### 📚 Key Principles for L2/L3 Analysts

* **Understand MITRE ATT&CK:** Map the hunt logic to relevant MITRE ATT&CK techniques (e.g., **T1059** for Command and Scripting Interpreter).
* **Establish Baseline:** Understand your organization's environment to quickly differentiate between **normal, benign activity** and **suspicious outliers**.
* **Document Everything:** Document the rationale, the results, the false-positive rate, and the final decision (e.g., "Escalated to Incident," or "Closed as Benign") for every hunt.
