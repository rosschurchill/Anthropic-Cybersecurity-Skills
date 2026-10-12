# Ransomware on finance file server — CISO brief (filled example)

Document:   Ransomware on finance file server — CISO brief
Reference:  INC-2026-014-C
Version:    1.0    Status: FINAL
Marking:    TLP:AMBER
Owner:      Head of Security Operations
Date:       2026-10-12    Review by: 2026-10-19
Audience:   CISO

## Bottom line

Ransomware encrypted 1 finance file server on 2026-10-10. We restored it from backup in 9 hours. The server held payroll data, and we cannot yet rule out access. We need a decision by 2026-10-13T12:00Z on whether to tell the Information Commissioner's Office (ICO).

## Decisions needed

**Decision:** Do we notify the ICO?

**Options:** (a) Notify now. This costs little and shows good faith. (b) Do not notify. We have no evidence that the attacker read the data, but if we are wrong we miss the legal deadline.

**We recommend:** (a), because we cannot yet prove the attacker did not read the payroll records.

**Needed by:** 2026-10-13T12:00Z. The legal deadline is 2026-10-13T16:00Z.

## Business impact

Finance had no access to shared files for 9 hours. Payroll ran on time. The server held 1,240 employee payroll records. We do not know yet whether the attacker read them, and we will know by 2026-10-16. Recovery cost 46 staff hours. We paid no ransom.

## Status

| Area | Status | Owner | Next date |
|---|---|---|---|
| Containment | GREEN | Security Operations Manager | Done |
| Data access investigation | AMBER | Incident Response Lead | 2026-10-16 |
| ICO notification | RED | Data Protection Officer | 2026-10-13T12:00Z |
| Patch the remote access appliance | AMBER | Infrastructure Lead | 2026-10-21 |
| Reduce service account rights | AMBER | Identity Team Lead | 2026-11-14 |

## What we are doing

- The remote access appliance gets its patch by 2026-10-21.
- Network appliances join the monthly patch process by 2026-10-31.
- Service accounts lose rights they do not need by 2026-11-14.
