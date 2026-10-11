# Reference Material

## Key Concepts

| Term | Definition |
|------|------------|
| **Sensitivity Label** | A classification tag applied to documents and emails that can enforce encryption, content marking (headers/footers/watermarks), and access restrictions. Labels persist with the content and travel with files when shared externally. |
| **Sensitive Information Type (SIT)** | A pattern-based classifier that detects specific data patterns (credit card numbers, SSNs, custom regex) in content. Each SIT has a confidence level (low/medium/high) determined by primary pattern match plus corroborating evidence (keywords, proximity). |
| **DLP Policy** | A set of rules that detect sensitive information in Microsoft 365 locations (Exchange, SharePoint, OneDrive, Teams, Endpoints) and apply protective actions (audit, warn with override, block) based on the sensitivity of matched content and the sharing context. |
| **Endpoint DLP** | Extension of DLP protection to managed Windows and macOS devices that monitors and controls file operations including copy-to-USB, print, upload-to-cloud, copy-to-clipboard, and access by unallowed applications for files containing sensitive information. |
| **Activity Explorer** | A monitoring dashboard in Microsoft Purview that displays a historical view (up to 30 days) of labeled content activities, DLP policy matches, and user interactions with classified data across all monitored locations. |
| **Auto-Labeling** | Service-side automatic classification that applies sensitivity labels to documents and emails matching specified SIT patterns without requiring user interaction. Runs in simulation mode first to preview matches before enforcement. |
| **Content Marking** | Visual indicators (headers, footers, watermarks) applied by sensitivity labels to documents and emails. Markings persist in the file and are visible when printed or shared, serving as a visual classification reminder. |
| **DLP Alert** | A notification generated when a DLP rule match meets the configured severity threshold. Alerts appear in the Microsoft Purview DLP alerts dashboard and can be routed to Microsoft Sentinel or other SIEM platforms. |

## Tools & Systems

- **Microsoft Purview Compliance Portal**: Web-based administration interface for creating and managing sensitivity labels, DLP policies, auto-labeling rules, and reviewing Activity Explorer data and DLP alerts.
- **Security & Compliance PowerShell**: PowerShell module (Connect-IPPSSession) providing cmdlets for programmatic management of labels (New-Label, Set-Label), label policies (New-LabelPolicy), DLP policies (New-DlpCompliancePolicy, New-DlpComplianceRule), and sensitive information types.
- **Microsoft Graph Security API**: REST API providing programmatic access to DLP alerts (security/alerts_v2), data classification insights, and protection scope evaluation for integrating Purview DLP with custom applications and SIEM platforms.
- **Microsoft Intune**: Endpoint management platform used to onboard Windows and macOS devices to endpoint DLP, deploy configuration profiles, and manage device compliance states.
- **Microsoft Sentinel**: Cloud-native SIEM that ingests DLP alerts and audit logs from Microsoft Purview via the Microsoft 365 Defender data connector for correlation with other security events and automated incident response.
- **Unified Audit Log**: Microsoft 365 audit service recording all DLP policy match events (RecordType "DLP") with detailed match metadata for compliance reporting and forensic investigation.

## Common Scenarios

### Scenario: Protecting Financial Data Across a Multinational Organization

**Context**: A financial services company with 15,000 users across 12 countries needs to prevent credit card numbers, bank account details, and financial statements from being shared externally through email, Teams, SharePoint, and endpoint file operations. The company must comply with PCI-DSS and GDPR.

**Approach**:
1. Design a four-tier sensitivity label taxonomy: Public, Internal, Confidential (with sub-labels for Finance, Legal, HR), and Highly Confidential. Publish labels to all users with "Internal" as the default label and mandatory labeling enabled for email.
2. Create a DLP policy "PCI-DSS Financial Data Protection" scoped to all Exchange, SharePoint, OneDrive, Teams, and Endpoint locations. Configure two rules: a warning rule for 1-4 credit card numbers (notify user, allow override with justification) and a blocking rule for 5+ credit card numbers (block external sharing, generate incident report to compliance team).
3. Deploy endpoint DLP with rules blocking copy-to-USB and upload-to-unapproved-cloud for any file containing credit card numbers or labeled "Confidential - Finance". Allow printing with audit logging. Configure approved USB device exceptions for encrypted corporate drives by vendor/product ID.
4. Create auto-labeling policies that scan existing SharePoint finance sites and OneDrive locations, automatically applying "Confidential - Finance" to documents matching credit card number or bank account number SITs with confidence level 85+.
5. Run all policies in simulation mode for 14 days. Review Activity Explorer for false positive rates, override patterns, and unprotected sensitive content locations. Tune SIT confidence thresholds from 75 to 85 on the credit card SIT after identifying false positives from partial number sequences in meeting notes.
6. Switch to enforcement mode after stakeholder sign-off. Configure DLP alerts with Microsoft Sentinel integration for real-time incident correlation. Schedule monthly Activity Explorer reviews to track policy effectiveness metrics.

**Pitfalls**:
- Deploying DLP policies in enforcement mode without simulation, causing mass blocking of legitimate business communications and user productivity disruption
- Using low confidence thresholds (65) for SITs, generating excessive false positives that erode user trust and lead to policy override fatigue
- Not configuring endpoint DLP exceptions for approved encrypted USB devices, blocking legitimate data transfers to authorized external parties
- Forgetting to publish sensitivity labels via a label policy after creation, resulting in labels being invisible to end users in Office applications
- Not coordinating auto-labeling deployment with document library owners, leading to unexpected label changes on existing content that alter access permissions

### Scenario: Implementing Custom DLP for Intellectual Property Protection

**Context**: A pharmaceutical company needs to prevent research data identified by internal project codes (format: RX-YYYY-NNNN) and compound identifiers from being shared outside the research department. The data appears in lab reports, research presentations, and email communications.

**Approach**:
1. Create a custom sensitive information type using regex `RX-20[2-3][0-9]-[0-9]{4}` with corroborating keywords ("compound", "trial", "formulation", "assay", "efficacy") within 300-character proximity. Set primary pattern at 85% confidence and keyword-corroborated pattern at 95%.
2. Create a second custom SIT for compound identifiers using regex `CPD-[A-Z]{3}-[0-9]{5}` with keywords ("molecule", "synthesis", "pharmacokinetics") for higher confidence matching.
3. Deploy a DLP policy scoped to the Research department's Exchange distribution list, SharePoint research site collection, and research team OneDrive accounts. Block external sharing, block forwarding to non-research internal users, and generate alerts for the research compliance officer.
4. Configure endpoint DLP to prevent copy-to-USB and screen capture of documents containing the custom SITs on research department laptops. Allow printing only to approved secure printers in the research facility.
5. Create a sensitivity label "Highly Confidential - Research" with encryption restricting access to the Research security group. Configure auto-labeling to apply this label to documents matching either custom SIT.
6. Monitor Activity Explorer weekly for 30 days post-deployment. The compliance team identifies that the RX-YYYY-NNNN regex matches historical project codes in archived documents. Refine the regex to `RX-202[4-6]-[0-9]{4}` to target only active project codes and reduce false positives by 60%.

**Pitfalls**:
- Using positional regex anchors (^ and $) in custom SITs, which do not work as expected in Microsoft Purview regex evaluation and cause pattern match failures
- Setting MinCount too low (1) for the project code SIT without keyword corroboration, matching isolated instances in general business correspondence that happen to follow the same format
- Not testing the custom SIT against a representative sample corpus before deploying the DLP policy, missing edge cases in the regex pattern
- Scoping the policy too broadly (entire organization) instead of targeting the research department, causing alerts on legitimate references to project codes in executive summaries

## Output Format

```
## DLP Policy Deployment Report

**Policy Name**: PCI-DSS Financial Data Protection
**Deployment Date**: 2026-03-19
**Current Mode**: Simulation (TestWithNotifications)
**Locations**: Exchange Online, SharePoint Online, OneDrive, Teams, Endpoints

---

### Simulation Results (14-Day Period)

**Total Policy Matches**: 4,287
**Unique Users Affected**: 892
**Unique Files/Messages**: 3,641

| Rule | Matches | Action | Override Rate |
|------|---------|--------|---------------|
| Block Bulk Credit Card Sharing (5+) | 47 | Block | N/A |
| Warn on Credit Card Sharing (1-4) | 4,240 | Warn | 12.3% |

### Sensitive Information Type Breakdown

| SIT | Matches | Avg Confidence | False Positive Est. |
|-----|---------|----------------|---------------------|
| Credit Card Number | 3,891 | 87% | 8.2% |
| U.S. Bank Account Number | 312 | 82% | 15.1% |
| ABA Routing Number | 84 | 79% | 22.6% |

### Recommendations

1. **Enable enforcement** for "Block Bulk Credit Card Sharing" rule -
   47 matches are all true positives involving bulk credit card data in
   spreadsheet attachments.

2. **Increase confidence threshold** for ABA Routing Number from 75 to 85 -
   22.6% false positive rate driven by 9-digit numbers in invoice references
   matching the routing number pattern.

3. **Add file type exception** for password-protected ZIP attachments that
   trigger false positives when the credit card SIT matches encrypted content
   metadata.

4. **Deploy endpoint DLP** in audit mode for 7 additional days before
   enabling block actions on USB copy and cloud upload.

---

### DLP Alert Summary (Last 7 Days)

| Severity | Count | Top Policy | Top User |
|----------|-------|------------|----------|
| High | 12 | Financial Data Protection | j.smith@contoso.com |
| Medium | 89 | IP Protection - Research | r.chen@contoso.com |
| Low | 234 | General PII Protection | (distributed) |

### Activity Explorer Insights

- Peak DLP match activity: Monday 09:00-11:00 UTC (weekly report distribution)
- Top matched location: Finance SharePoint site (62% of all matches)
- Most overridden rule: "Warn on Credit Card Sharing" (523 overrides, 12.3%)
- Override justification analysis: 78% "Business requirement", 15% "False positive",
  7% "Other"
```
