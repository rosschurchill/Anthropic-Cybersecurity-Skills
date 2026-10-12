# Standards: Writing CISO Security Briefs

## STE-80 writing rules

ASD-STE100 Simplified Technical English, Issue 9 (January 2025), has 53 writing rules and a
controlled dictionary of about 900 words. STE-80 keeps the writing rules and relaxes the
dictionary: security terms are allowed if each one has 1 meaning and is used the same way every
time. At least 80% of sentences must meet all 10 rules below. The bottom line, numbered steps
and warnings must meet them 100%.

| # | Rule | STE section |
|---|---|---|
| R1 | Instruction sentences: 20 words maximum. Descriptive sentences: 25 words maximum. | Procedures, descriptive writing |
| R2 | 1 instruction per sentence. Steps start with a verb. | Procedures |
| R3 | Active voice. Use the passive only when the actor is unknown. | Verbs |
| R4 | 1 word, 1 meaning. Never vary a term for style. | Words |
| R5 | Put a warning before the step it applies to. | Safety instructions |
| R6 | No noun cluster longer than 3 words. | Noun clusters |
| R7 | Simple tenses. No "would", "could", "might", "may wish to". | Verbs |
| R8 | 1 topic per paragraph, 6 sentences maximum. | Descriptive writing |
| R9 | Expand each abbreviation at first use. | House rule |
| R10 | Digits for numbers. ISO 8601 dates and times, with a time zone. | ISO 8601; the time zone is a house rule |

`scripts/agent.py` checks R1, R2, R3, R7, R8, R9, R10, a banned-word list and the CISO cap. A
reviewer checks R4, R5 and R6.

## Controlled terms (extract)

| Use | Not |
|---|---|
| vulnerability | weakness, flaw, hole |
| attacker | hacker, bad actor, threat actor |
| supplier | vendor, third party |
| incident | compromise, attack (as a noun for the case) |
| breach | leak. Use only when data access is confirmed: the word has legal effect. |
| control | safeguard, countermeasure |
| risk rating | risk score, risk level |

## Supporting standards

| Standard | Used for |
|---|---|
| ISO 24495-1:2023 Plain language | The test for the whole brief: can the reader find, understand and use it? |
| ISO 31000:2018 | Risk management vocabulary. The statement "There is a risk that [event], caused by [cause], resulting in [consequence]" is consistent with it; the standard does not prescribe a wording |
| ISO/IEC 27035-1:2023 | 5 incident phases: plan and prepare, detect and report, assess and decide, respond, learn |
| ISO/IEC 27001:2022 | Audit findings and Annex A control IDs (full report only) |
| ITIL 4 | Incident priority = impact × urgency (P1 to P5); problem and root cause records |
| ISO 8601 | `2026-10-13` and `2026-10-13T16:00Z` |
| FIRST TLP 2.0 | CLEAR, GREEN, AMBER, AMBER+STRICT, RED |
| UK GDPR Article 33 | 72 hours from awareness to notify the ICO of a personal data breach |

## References

- ASD-STE100 Issue 9: https://www.asd-ste100.org/
- ISO 24495-1:2023: https://www.iso.org/standard/78907.html
- FIRST TLP 2.0: https://www.first.org/tlp/
- ICO personal data breaches: https://ico.org.uk/for-organisations/report-a-breach/
