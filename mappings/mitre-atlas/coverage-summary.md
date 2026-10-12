# MITRE ATLAS Coverage Summary

**GENERATED FILE — do not edit by hand.** Run `python tools/generate-atlas-coverage.py` to regenerate.

Maps this repository's AI/LLM-security skills to [MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for AI Systems) techniques. ATLAS — not ATT&CK or NIST CSF — is the framework that models adversary behavior against AI systems, so the catalogue's AI-security skills carry `atlas_techniques:` in their frontmatter alongside their ATT&CK and CSF mappings.

- ATLAS data version: **5.6.0**
- Skills mapped to ATLAS: **93**
- Distinct ATLAS techniques covered: **22**

## Technique coverage

| ATLAS ID | Technique | Skills |
|----------|-----------|-------:|
| `AML.T0066` | Retrieval Content Crafting | 45 |
| `AML.T0070` | RAG Poisoning | 45 |
| `AML.T0082` | RAG Credential Harvesting | 45 |
| `AML.T0052` | Phishing | 13 |
| `AML.T0056` | Extract LLM System Prompt | 12 |
| `AML.T0051` | LLM Prompt Injection | 11 |
| `AML.T0054` | LLM Jailbreak | 11 |
| `AML.T0024` | Exfiltration via AI Inference API | 9 |
| `AML.T0018` | Manipulate AI Model | 6 |
| `AML.T0043` | Craft Adversarial Data | 5 |
| `AML.T0088` | Generate Deepfakes | 5 |
| `AML.T0010` | AI Supply Chain Compromise | 4 |
| `AML.T0057` | LLM Data Leakage | 3 |
| `AML.T0073` | Impersonation | 3 |
| `AML.T0020` | Poison Training Data | 2 |
| `AML.T0035` | AI Artifact Collection | 2 |
| `AML.T0067` | LLM Trusted Output Components Manipulation | 2 |
| `AML.T0068` | LLM Prompt Obfuscation | 2 |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | 2 |
| `AML.T0051.001` | Indirect | 1 |
| `AML.T0053` | AI Agent Tool Invocation | 1 |
| `AML.T0062` | Discover LLM Hallucinations | 1 |

## Skills by technique

### `AML.T0066` — Retrieval Content Crafting

- `analyzing-security-logs-with-splunk`
- `analyzing-threat-actor-ttps-with-mitre-navigator`
- `building-cloud-siem-with-sentinel`
- `building-soc-metrics-and-kpi-tracking`
- `conducting-cloud-penetration-testing`
- `conducting-mobile-app-penetration-test`
- `configuring-hsm-for-key-storage`
- `deploying-edr-agent-with-crowdstrike`
- `detecting-attacks-on-scada-systems`
- `detecting-azure-storage-account-misconfigurations`
- `detecting-misconfigured-azure-storage`
- `detecting-modbus-protocol-anomalies`
- `implementing-api-key-security-controls`
- `implementing-azure-defender-for-cloud`
- `implementing-cloud-dlp-for-data-protection`
- `implementing-dragos-platform-for-ot-monitoring`
- `implementing-runtime-security-with-tetragon`
- `implementing-fuzz-testing-in-cicd-with-aflplusplus`
- `implementing-gdpr-data-protection-controls`
- `implementing-immutable-backup-with-restic`
- `implementing-mitre-attack-coverage-mapping`
- `implementing-ot-network-traffic-analysis-with-nozomi`
- `implementing-ransomware-backup-strategy`
- `implementing-runtime-security-with-tetragon`
- `implementing-security-chaos-engineering`
- `implementing-siem-use-cases-for-detection`
- `implementing-threat-modeling-with-mitre-attack`
- `implementing-web-application-logging-with-modsecurity`
- `mapping-mitre-attack-techniques`
- `monitoring-darkweb-sources`
- `performing-cloud-storage-forensic-acquisition`
- `performing-cve-prioritization-with-kev-catalog`
- `performing-fuzzing-with-aflplusplus`
- `performing-gcp-penetration-testing-with-gcpbucketbrute`
- `performing-gcp-security-assessment-with-forseti`
- `performing-hardware-security-module-integration`
- `performing-ics-asset-discovery-with-claroty`
- `performing-purple-team-atomic-testing`
- `performing-thick-client-application-penetration-test`
- `performing-threat-emulation-with-atomic-red-team`
- `performing-threat-hunting-with-elastic-siem`
- `performing-threat-modeling-with-owasp-threat-dragon`
- `recovering-deleted-files-with-photorec`
- `securing-azure-with-microsoft-defender`
- `testing-for-sensitive-data-exposure`

### `AML.T0070` — RAG Poisoning

- `analyzing-security-logs-with-splunk`
- `analyzing-threat-actor-ttps-with-mitre-navigator`
- `building-cloud-siem-with-sentinel`
- `building-soc-metrics-and-kpi-tracking`
- `conducting-cloud-penetration-testing`
- `conducting-mobile-app-penetration-test`
- `configuring-hsm-for-key-storage`
- `deploying-edr-agent-with-crowdstrike`
- `detecting-attacks-on-scada-systems`
- `detecting-azure-storage-account-misconfigurations`
- `detecting-misconfigured-azure-storage`
- `detecting-modbus-protocol-anomalies`
- `implementing-api-key-security-controls`
- `implementing-azure-defender-for-cloud`
- `implementing-cloud-dlp-for-data-protection`
- `implementing-dragos-platform-for-ot-monitoring`
- `implementing-runtime-security-with-tetragon`
- `implementing-fuzz-testing-in-cicd-with-aflplusplus`
- `implementing-gdpr-data-protection-controls`
- `implementing-immutable-backup-with-restic`
- `implementing-mitre-attack-coverage-mapping`
- `implementing-ot-network-traffic-analysis-with-nozomi`
- `implementing-ransomware-backup-strategy`
- `implementing-runtime-security-with-tetragon`
- `implementing-security-chaos-engineering`
- `implementing-siem-use-cases-for-detection`
- `implementing-threat-modeling-with-mitre-attack`
- `implementing-web-application-logging-with-modsecurity`
- `mapping-mitre-attack-techniques`
- `monitoring-darkweb-sources`
- `performing-cloud-storage-forensic-acquisition`
- `performing-cve-prioritization-with-kev-catalog`
- `performing-fuzzing-with-aflplusplus`
- `performing-gcp-penetration-testing-with-gcpbucketbrute`
- `performing-gcp-security-assessment-with-forseti`
- `performing-hardware-security-module-integration`
- `performing-ics-asset-discovery-with-claroty`
- `performing-purple-team-atomic-testing`
- `performing-thick-client-application-penetration-test`
- `performing-threat-emulation-with-atomic-red-team`
- `performing-threat-hunting-with-elastic-siem`
- `performing-threat-modeling-with-owasp-threat-dragon`
- `recovering-deleted-files-with-photorec`
- `securing-azure-with-microsoft-defender`
- `testing-for-sensitive-data-exposure`

### `AML.T0082` — RAG Credential Harvesting

- `analyzing-security-logs-with-splunk`
- `analyzing-threat-actor-ttps-with-mitre-navigator`
- `building-cloud-siem-with-sentinel`
- `building-soc-metrics-and-kpi-tracking`
- `conducting-cloud-penetration-testing`
- `conducting-mobile-app-penetration-test`
- `configuring-hsm-for-key-storage`
- `deploying-edr-agent-with-crowdstrike`
- `detecting-attacks-on-scada-systems`
- `detecting-azure-storage-account-misconfigurations`
- `detecting-misconfigured-azure-storage`
- `detecting-modbus-protocol-anomalies`
- `implementing-api-key-security-controls`
- `implementing-azure-defender-for-cloud`
- `implementing-cloud-dlp-for-data-protection`
- `implementing-dragos-platform-for-ot-monitoring`
- `implementing-runtime-security-with-tetragon`
- `implementing-fuzz-testing-in-cicd-with-aflplusplus`
- `implementing-gdpr-data-protection-controls`
- `implementing-immutable-backup-with-restic`
- `implementing-mitre-attack-coverage-mapping`
- `implementing-ot-network-traffic-analysis-with-nozomi`
- `implementing-ransomware-backup-strategy`
- `implementing-runtime-security-with-tetragon`
- `implementing-security-chaos-engineering`
- `implementing-siem-use-cases-for-detection`
- `implementing-threat-modeling-with-mitre-attack`
- `implementing-web-application-logging-with-modsecurity`
- `mapping-mitre-attack-techniques`
- `monitoring-darkweb-sources`
- `performing-cloud-storage-forensic-acquisition`
- `performing-cve-prioritization-with-kev-catalog`
- `performing-fuzzing-with-aflplusplus`
- `performing-gcp-penetration-testing-with-gcpbucketbrute`
- `performing-gcp-security-assessment-with-forseti`
- `performing-hardware-security-module-integration`
- `performing-ics-asset-discovery-with-claroty`
- `performing-purple-team-atomic-testing`
- `performing-thick-client-application-penetration-test`
- `performing-threat-emulation-with-atomic-red-team`
- `performing-threat-hunting-with-elastic-siem`
- `performing-threat-modeling-with-owasp-threat-dragon`
- `recovering-deleted-files-with-photorec`
- `securing-azure-with-microsoft-defender`
- `testing-for-sensitive-data-exposure`

### `AML.T0052` — Phishing

- `analyzing-certificate-transparency-for-phishing`
- `analyzing-email-headers-for-phishing-investigation`
- `analyzing-indicators-of-compromise`
- `analyzing-malicious-url-with-urlscan`
- `analyzing-tls-certificate-transparency-logs`
- `analyzing-typosquatting-domains-with-dnstwist`
- `conducting-social-engineering-penetration-test`
- `conducting-social-engineering-pretext-call`
- `detecting-business-email-compromise`
- `detecting-business-email-compromise-with-ai`
- `detecting-deepfake-audio-in-vishing-attacks`
- `detecting-qr-code-phishing-with-email-security`
- `implementing-identity-verification-for-zero-trust`

### `AML.T0056` — Extract LLM System Prompt

- `analyzing-cloud-storage-access-patterns`
- `analyzing-dns-logs-for-exfiltration`
- `deploying-cloudflare-access-for-zero-trust`
- `detecting-ai-model-prompt-injection-attacks`
- `detecting-ntlm-relay-with-event-correlation`
- `extracting-config-from-agent-tesla-rat`
- `hunting-for-data-exfiltration-indicators`
- `implementing-endpoint-dlp-controls`
- `implementing-hardware-security-key-authentication`
- `implementing-llm-guardrails-for-security`
- `implementing-passwordless-authentication-with-fido2`
- `performing-ai-driven-osint-correlation`

### `AML.T0051` — LLM Prompt Injection

- `continuous-llm-red-teaming-with-promptfoo`
- `deploying-cloudflare-access-for-zero-trust`
- `detecting-ai-model-prompt-injection-attacks`
- `detecting-ntlm-relay-with-event-correlation`
- `implementing-hardware-security-key-authentication`
- `implementing-llm-guardrails-for-security`
- `implementing-passwordless-authentication-with-fido2`
- `orchestrating-llm-attacks-with-pyrit`
- `performing-ai-driven-osint-correlation`
- `red-teaming-llms-with-garak`
- `testing-prompt-injection-in-rag-pipelines`

### `AML.T0054` — LLM Jailbreak

- `analyzing-ios-app-security-with-objection`
- `defending-llms-with-guardrails`
- `deploying-cloudflare-access-for-zero-trust`
- `detecting-ai-model-prompt-injection-attacks`
- `detecting-ntlm-relay-with-event-correlation`
- `implementing-hardware-security-key-authentication`
- `implementing-llm-guardrails-for-security`
- `implementing-passwordless-authentication-with-fido2`
- `orchestrating-llm-attacks-with-pyrit`
- `performing-ai-driven-osint-correlation`
- `red-teaming-llms-with-garak`

### `AML.T0024` — Exfiltration via AI Inference API

- `analyzing-cloud-storage-access-patterns`
- `analyzing-dns-logs-for-exfiltration`
- `assessing-vector-and-embedding-weaknesses`
- `detecting-model-extraction-attacks`
- `detecting-qr-code-phishing-with-email-security`
- `extracting-config-from-agent-tesla-rat`
- `hunting-for-data-exfiltration-indicators`
- `implementing-endpoint-dlp-controls`
- `performing-clickjacking-attack-test`

### `AML.T0018` — Manipulate AI Model

- `detecting-anomalies-in-industrial-control-systems`
- `detecting-anomalous-authentication-patterns`
- `detecting-data-and-model-poisoning`
- `detecting-deepfake-audio-in-vishing-attacks`
- `detecting-dnp3-protocol-anomalies`
- `implementing-aws-macie-for-data-classification`

### `AML.T0043` — Craft Adversarial Data

- `detecting-anomalies-in-industrial-control-systems`
- `detecting-anomalous-authentication-patterns`
- `detecting-deepfake-audio-in-vishing-attacks`
- `detecting-dnp3-protocol-anomalies`
- `implementing-aws-macie-for-data-classification`

### `AML.T0088` — Generate Deepfakes

- `conducting-social-engineering-penetration-test`
- `conducting-social-engineering-pretext-call`
- `detecting-business-email-compromise`
- `detecting-business-email-compromise-with-ai`
- `detecting-deepfake-audio-in-vishing-attacks`

### `AML.T0010` — AI Supply Chain Compromise

- `analyzing-sbom-for-supply-chain-vulnerabilities`
- `analyzing-supply-chain-malware-artifacts`
- `auditing-mcp-servers-for-tool-poisoning`
- `detecting-supply-chain-attacks-in-ci-cd`

### `AML.T0057` — LLM Data Leakage

- `exploiting-insecure-data-storage-in-mobile`
- `implementing-llm-guardrails-for-security`
- `testing-for-system-prompt-leakage`

### `AML.T0073` — Impersonation

- `analyzing-tls-certificate-transparency-logs`
- `analyzing-typosquatting-domains-with-dnstwist`
- `detecting-business-email-compromise-with-ai`

### `AML.T0020` — Poison Training Data

- `detecting-data-and-model-poisoning`
- `detecting-ntlm-relay-with-event-correlation`

### `AML.T0035` — AI Artifact Collection

- `detecting-qr-code-phishing-with-email-security`
- `performing-clickjacking-attack-test`

### `AML.T0067` — LLM Trusted Output Components Manipulation

- `analyzing-macro-malware-in-office-documents`
- `detecting-ai-model-prompt-injection-attacks`

### `AML.T0068` — LLM Prompt Obfuscation

- `analyzing-macro-malware-in-office-documents`
- `detecting-ai-model-prompt-injection-attacks`

### `AML.T0086` — Exfiltration via AI Agent Tool Invocation

- `analyzing-dns-logs-for-exfiltration`
- `extracting-config-from-agent-tesla-rat`

### `AML.T0051.001` — Indirect

- `detecting-indirect-prompt-injection`

### `AML.T0053` — AI Agent Tool Invocation

- `securing-agentic-ai-tool-invocation`

### `AML.T0062` — Discover LLM Hallucinations

- `implementing-llm-guardrails-for-security`
