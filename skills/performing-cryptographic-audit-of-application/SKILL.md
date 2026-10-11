---
name: performing-cryptographic-audit-of-application
description: >-
  Builds and runs an automated cryptographic audit of an application, scanning source and config
  for deprecated algorithms (MD5, SHA-1, DES, 3DES, RC4), ECB mode, hardcoded keys and secrets,
  weak KDF parameters (low-iteration PBKDF2), and poor entropy, and inspecting live TLS with
  Python ssl/socket and the cryptography library for weak protocols (TLS 1.0/1.1), weak cipher
  suites, undersized RSA/EC keys, SHA-1 certificate signatures, expiry, and missing HSTS, then
  emitting findings with severity, location, and remediation. Use when auditing an application's
  cryptography or flagging weak crypto in code review. Keywords: MD5, SHA-1, DES, RC4, ECB,
  PBKDF2, RSA 2048, TLSv1.0, cipher suites, x509, HSTS, Strict-Transport-Security. Do not use for
  a full external TLS/SSL server posture assessment - use performing-ssl-tls-security-assessment.
domain: cybersecurity
subdomain: cryptography
tags:
- cryptography
- audit
- security-review
- compliance
- vulnerability-assessment
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
mitre_attack:
- T1600
- T1573
- T1553
mitre_f3:
  version: '1.1'
  tactics:
  - reconnaissance
  - initial-access
  - positioning
  techniques:
  - id: T1557
    name: Adversary-in-the-Middle
    tactic: positioning
    source: attack
  - id: T1555
    name: Credentials from Password Stores
    tactic: reconnaissance
    source: attack
  - id: F1006.001
    name: 'Account Takeover: Exposed API Key'
    tactic: initial-access
    source: f3
  - id: F1004
    name: Access with Stolen Session Cookie
    tactic: initial-access
    source: f3
---
# Performing Cryptographic Audit of Application

## Overview

A cryptographic audit systematically reviews an application's use of cryptographic primitives, protocols, and key management to identify vulnerabilities such as weak algorithms, insecure modes, hardcoded keys, insufficient entropy, and protocol misconfigurations. This skill covers building an automated crypto audit tool that scans Python and configuration files for common cryptographic weaknesses.


## When to Use

- When conducting security assessments that involve performing cryptographic audit of application
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Detect usage of deprecated algorithms (MD5, SHA-1, DES, RC4)
- Identify insecure cipher modes (ECB) and padding schemes
- Find hardcoded keys, passwords, and secrets in source code
- Verify TLS/SSL configuration strength
- Check key derivation function parameters
- Validate random number generator usage
- Produce a structured audit report with findings and remediation

## Key Concepts

### Cryptographic Weakness Categories

| Category | Examples | Risk Level |
|----------|----------|------------|
| Weak Hashing | MD5, SHA-1 for integrity/signatures | High |
| Insecure Encryption | DES, 3DES, RC4, Blowfish | High |
| Bad Cipher Mode | ECB mode for any block cipher | High |
| Insufficient Key Size | RSA < 2048, AES-128 for long-term | Medium |
| Hardcoded Secrets | Keys/passwords in source code | Critical |
| Weak KDF | Low iteration PBKDF2, plain MD5 | High |
| Poor Entropy | time-based seeds, predictable IVs | High |
| Deprecated Protocols | SSLv3, TLS 1.0, TLS 1.1 | High |

## Security Considerations

- Review both application code and configuration files
- Check third-party dependencies for known crypto vulnerabilities
- Verify certificates and TLS configurations on deployed servers
- Ensure secrets are loaded from environment variables or vaults
- Review key storage and rotation practices

## Validation Criteria

- [ ] Scanner detects all injected test weaknesses
- [ ] MD5/SHA-1 usage for security purposes is flagged
- [ ] ECB mode usage is flagged
- [ ] Hardcoded keys/passwords are detected
- [ ] Weak KDF parameters are identified
- [ ] Report includes severity, location, and remediation
- [ ] False positive rate is below 10%
