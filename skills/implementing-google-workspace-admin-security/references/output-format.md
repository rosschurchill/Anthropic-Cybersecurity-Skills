# Output Format

## Output Format

```
GOOGLE WORKSPACE SECURITY ASSESSMENT REPORT
=============================================
Tenant:            corp.com
License:           Enterprise Plus
Total Users:       3,847
Organizational Units: 12

AUTHENTICATION SECURITY
2SV Enforced:           YES (all OUs)
2SV Enrollment:         3,712 / 3,847 (96.5%)
Security Keys Only:     Executive OU (47 users)
Advanced Protection:    3 super admin accounts
Super Admin Count:      3 (within recommended limit)

EMAIL AUTHENTICATION
SPF:                    CONFIGURED (hard fail: -all)
DKIM:                   CONFIGURED (2048-bit, selector: google)
DMARC:                  ENFORCED (p=reject, 100%)
Anti-Phishing:          ALL PROTECTIONS ENABLED
Anti-Spoofing:          ENABLED (domain + employee name)

DATA PROTECTION
DLP Rules Active:       7
  PII Detection:        SSN, Credit Card, Passport
  Content Labels:       Confidential, Restricted
  Custom Patterns:      3 organization-specific rules
DLP Violations (30d):   89 (67 blocked, 22 warned)

APPLICATION CONTROL
Third-Party App Policy: BLOCKED (allowlist mode)
Approved Apps:          12
Unauthorized Tokens:    0 (all revoked)
API Scope Restrictions: ENABLED

SHARING CONTROLS
External Sharing:       RESTRICTED (allowlisted domains only)
Public Link Sharing:    DISABLED
External Group Members: DISABLED
Shared Drive Creation:  ADMIN ONLY
```
