# Statement of Work (SOW)
## Exhibit A — Cybersecurity Assessment Services

---

**SOW Number:** SOW-[YYYY]-[###]
**Date:** [DATE]
**Client:** [CLIENT COMPANY NAME]
**Consultant:** [YOUR COMPANY NAME]
**Reference:** Master Services Agreement dated [DATE]

---

## 1. Engagement Summary

| Field | Details |
|-------|---------|
| **Project Name** | [Client Name] Security Assessment — [Quarter/Year] |
| **Engagement Type** | [Penetration Test / Vulnerability Assessment / Compliance Audit] |
| **Approach** | [Black Box / Gray Box / White Box] |
| **Start Date** | [DATE] |
| **End Date** | [DATE] |
| **Testing Hours** | [24/7 / Business hours / After hours] |
| **Primary Tester** | [Your Name] |
| **Client POC** | [Name, Title, Phone, Email] |

## 2. Services & Pricing

### 2.1 Core Services

| # | Service | Description | Days | Rate | Total |
|---|---------|-------------|------|------|-------|
| 1 | External Penetration Test | Test public-facing infrastructure for exploitable vulnerabilities | [X] | $[X,XXX]/day | $[X,XXX] |
| 2 | Internal Penetration Test | Assess internal network from authenticated/drop box perspective | [X] | $[X,XXX]/day | $[X,XXX] |
| 3 | Web Application Assessment | OWASP Top 10 testing of [X] web applications | [X] | $[X,XXX]/day | $[X,XXX] |
| 4 | Cloud Security Audit | Configuration review of [AWS/Azure/GCP] environment | [X] | $[X,XXX]/day | $[X,XXX] |
| 5 | Reporting & Debrief | Final report generation and presentation | [X] | Included | Included |
| 6 | Remediation Retest | Verify critical/high findings (within 30 days) | [X] | Included | Included |
| | | | | **Total:** | **$[XX,XXX]** |

### 2.2 Optional Services (if requested)

| # | Service | Description | Price |
|---|---------|-------------|-------|
| A | Wireless Assessment | Test [X] wireless networks for security issues | $[X,XXX] |
| B | Social Engineering | Phishing campaign targeting [X] employees | $[X,XXX] |
| C | Monthly Monitoring | Continuous vulnerability monitoring (per month) | $[X,XXX]/mo |
| D | AD Security Assessment | Active Directory attack path analysis | $[X,XXX] |

## 3. Scope Definition

### 3.1 In-Scope Assets

**External:**
| Asset | Target | Notes |
|-------|--------|-------|
| Public IP Range | [X.X.X.0/24] | |
| Web Application | [https://app.client.com] | |
| Web Application | [https://portal.client.com] | |
| API Endpoint | [https://api.client.com] | |
| Mail Server | [mail.client.com] | |

**Internal (if applicable):**
| Asset | Target | Notes |
|-------|--------|-------|
| Internal Network | [10.0.0.0/8] | |
| Domain Controller | [10.0.0.5] | |
| File Server | [10.0.0.10] | |
| Database Server | [10.0.0.20] | |

**Cloud (if applicable):**
| Provider | Account/Subscription | Services |
|----------|---------------------|----------|
| [AWS/Azure/GCP] | [Account ID] | [EC2, S3, RDS, etc.] |

### 3.2 Exclusions

- [List specific systems/IPs excluded]
- Production database writes
- DoS/DDoS testing
- Third-party hosted services not owned by Client

## 4. Access Requirements

The Client will provide the following before testing begins:

- [ ] VPN credentials or network access method
- [ ] Test user accounts (for gray/white box testing)
- [ ] API documentation (for API testing)
- [ ] Cloud console read-only access (for cloud audit)
- [ ] Source IP whitelist confirmation
- [ ] Notification to hosting/cloud providers (if required)
- [ ] Emergency contact availability confirmed

## 5. Deliverables & Timeline

| Milestone | Deliverable | Target Date |
|-----------|-------------|-------------|
| Kick-off | Scope confirmation call | [Date] |
| Phase 1 | Reconnaissance & scanning complete | [Date] |
| Phase 2 | Exploitation & testing complete | [Date] |
| Phase 3 | Draft report delivered | [Date] |
| Phase 4 | Findings debrief presentation | [Date] |
| Phase 5 | Final report delivered | [Date] |
| Phase 6 | Retest window opens | [Date] |
| Phase 7 | Retest window closes | [Date + 30 days] |

### Deliverable Formats

| Deliverable | Format |
|-------------|--------|
| Executive Summary | PDF |
| Technical Report | HTML + PDF |
| Findings Data | JSON / CSV (machine-readable) |
| Remediation Roadmap | PDF |
| Presentation | Live meeting + slide deck |

## 6. Payment Schedule

| Milestone | Amount | Due Date |
|-----------|--------|----------|
| SOW Execution (50%) | $[X,XXX] | Upon signing |
| Final Report Delivery (50%) | $[X,XXX] | Upon delivery |
| **Total** | **$[XX,XXX]** | |

**Payment Method:** [Wire transfer / ACH / Check]
**Payment Terms:** Net 30

## 7. Assumptions & Dependencies

- Client systems will be available and accessible during the testing window
- Client will respond to questions/requests within 1 business day
- Testing will not coincide with major releases, migrations, or maintenance windows
- Client maintains current backups of all in-scope systems
- Any scope changes after SOW signing may result in timeline and cost adjustments

## 8. Change Control

Any changes to scope, timeline, or deliverables must be documented in a written Change Order signed by both parties. Changes may affect pricing and timeline.

---

## ACCEPTANCE

By signing below, both parties agree to the terms of this Statement of Work and the referenced Master Services Agreement.

**CONSULTANT: [YOUR COMPANY NAME]**

Signature: ________________________________  Date: ____________

Name: ________________________________  Title: ________________________________


**CLIENT: [CLIENT COMPANY NAME]**

Signature: ________________________________  Date: ____________

Name: ________________________________  Title: ________________________________
