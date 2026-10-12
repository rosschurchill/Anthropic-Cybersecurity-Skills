---
name: writing-ciso-security-briefs
description: >-
  Writes a 2-page CISO brief from a finished incident, risk or audit report, in controlled
  plain English based on ASD-STE100 Simplified Technical English applied at about 80 percent,
  with ISO 8601 dates and TLP marking, then scores it with scripts/agent.py. Use when a full security report must become a short decision document
  for a CISO, board or risk committee. Keywords: CISO brief, executive summary, board report,
  STE100, Simplified Technical English, plain language, ISO 24495-1, 750 words, bottom line.
  Do not use for intelligence products for security teams - use
  generating-threat-intelligence-reports; for malware incident notification templates use
  building-malware-incident-communication-template.
domain: cybersecurity
subdomain: compliance-governance
tags:
- ciso-brief
- executive-reporting
- plain-language
- asd-ste100
- iso-31000
- itil
- tlp
version: '1.0'
author: rosschurchill
license: Apache-2.0
nist_csf:
- GV.OV-01
- GV.RM-03
- RS.CO-02
- RS.CO-03
---

# Writing CISO Security Briefs

## When to Use

Use this skill when:
- A full incident report is finished and the CISO needs a decision document within hours
- A risk assessment has risks above appetite and the board must treat or accept them
- An ISO/IEC 27001 readiness audit is done and certification dates or budget need a decision
- An existing executive summary is too long, too technical, or does not ask for a decision

**Do not use** this skill to write the full report itself. The brief is derived from a full
report. It never contains a fact that the full report does not contain.

## Prerequisites

- A finished full report: incident, risk assessment or audit, with owners and dates on actions
- Python 3.8 or later, standard library only, for `scripts/agent.py`
- The organisation's risk appetite and priority scales, or the defaults in `references/standards.md`
- A marking decision: TLP:CLEAR, GREEN, AMBER, AMBER+STRICT or RED, or the internal classification

## Workflow

### Step 1: Build a fact ledger from the full report

List every number, date, owner and decision in the full report with its section reference.
The brief may use only these facts. Missing impact figures become "Not known yet", with the
owner who will find them and the date. Start from the lines that carry numbers or dates, then
add owners and decisions by reading:

```bash
grep -nE '[0-9]' report-full.md > ledger.txt
```

### Step 2: Write the brief in the fixed order

Use `assets/template.md`. The order does not change:

1. **Bottom line**: 3 sentences maximum, copied word for word from the full report. What happened
   or is at risk, how bad it is, and what you need from the reader.
2. **Decisions needed**: 3 maximum. Each has options with cost and effect, a recommendation, and
   a deadline with what happens if it is late.
3. **Business impact**: money, downtime hours, records, customers, regulatory exposure.
4. **Status**: 1 table, 8 rows maximum. Write RED, AMBER or GREEN as words, not only colours.
5. **What we are doing**: 3 to 5 lines, each with an action and a date.

Leave out IOCs, tool names, log extracts, CVE lists and control IDs. They stay in the full report.

### Step 3: Apply the STE-80 writing rules

Apply the 10 rules in `references/standards.md`. The main ones:

- 20 words maximum for an instruction, 25 for a descriptive sentence
- Active voice, simple tenses, no "would", "could" or "might"
- 1 word, 1 meaning: "vulnerability" every time, never "flaw", "weakness" or "hole"
- Expand every abbreviation at first use: "Information Commissioner's Office (ICO)"
- Digits for numbers. Dates as `2026-10-13`, times as `2026-10-13T16:00Z`

At least 80% of sentences must meet every rule. The other 20% lets the text read naturally.
The bottom line, steps and warnings have no leeway.

### Step 4: Score the brief

```bash
python3 scripts/agent.py --tier ciso brief.md
python3 scripts/agent.py --tier ciso --json brief.md > score.json
```

Exit code 0 means PASS. Exit code 1 means REVISE: fix each listed line and run it again.
The script also enforces the cap: 750 words, plus 1 table of 8 rows and 200 words or fewer.

### Step 5: Run the cold-reader test

Give only the brief to a reviewer who has not seen the full report. From the brief alone, they
must answer 3 questions: what is the risk, what must I decide, and by when. If they cannot, rewrite
the bottom line and the decisions. Change the bottom line in the full report too, so the 2
documents still match. Do not add length.

## Key Concepts

| Term | Definition |
|------|-----------|
| **ASD-STE100** | Simplified Technical English, Issue 9 (2025): 53 writing rules and a controlled dictionary of about 900 words |
| **STE-80** | The STE writing rules applied to at least 80% of sentences, with security terms allowed through a glossary instead of the full STE dictionary |
| **Strict zone** | The bottom line, numbered steps and warnings, where every sentence must comply |
| **Derived brief** | A brief built only from facts in the full report, so the 2 documents cannot disagree |
| **Risk statement** | "There is a risk that [event], caused by [cause], resulting in [consequence]", consistent with ISO 31000:2018 |
| **ITIL priority** | Impact × urgency, giving P1 to P5 |
| **ISO 24495-1:2023** | Plain language standard: readers can find, understand and use what they need |

## Tools & Systems

- **scripts/agent.py**: STE-80 scorer, standard library only, text or JSON output
- **ASD-STE100 Issue 9**: free from asd-ste100.org
- **ISO 24495-1:2023**: plain language principles and guidelines
- **FIRST TLP 2.0**: marking for sharing limits

## Common Scenarios

### Scenario: Ransomware incident, regulator deadline

**Context**: Ransomware encrypted a finance file server. The server held payroll data. The
72-hour ICO deadline ends in 30 hours.

**Approach**:
1. Copy the bottom line from the full report. Make sure it names the ICO decision and its deadline.
2. Write 1 decision: notify now, or do not notify. Give the cost and risk of each.
3. State the 1,240 records and say that access is "Not known yet", with the forensic owner and date.
4. Score with `agent.py --tier ciso` and fix until PASS.

**Pitfalls**: Do not write "breach" until access is confirmed. The word has legal effect.

### Scenario: Audit not ready for certification

**Context**: 2 major nonconformities 8 weeks before the certification audit.

**Approach**:
1. Decision: move the audit date, or fund extra work. Give cost, date and certainty for each.
2. Business impact: name the contracts and tenders that depend on the certificate, with dates.
3. Status table: 1 row for each major nonconformity, then 1 row for the minor nonconformities.

**Pitfalls**: Clause and control numbers belong in the full report. The CISO needs the consequence.

## Output Format

```
Document:   <title> — CISO brief
Reference:  <full report reference>-C
Version:    1.0    Status: FINAL
Marking:    TLP:AMBER
Owner:      <role>
Date:       YYYY-MM-DD    Review by: YYYY-MM-DD
Audience:   CISO

## Bottom line
## Decisions needed
## Business impact
## Status
## What we are doing
```

Scorer output:

```
SENTENCES: 20   COMPLIANT: 20 (100%)   STRICT-ZONE BREACHES: 0
CISO: 202/750 words · tables 1/1 · rows 5/8 · table words 44/200
TIER: CISO   VERDICT: PASS
```
