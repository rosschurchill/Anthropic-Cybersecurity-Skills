---
name: analyzing-ethereum-smart-contract-vulnerabilities
description: >-
  Performs static and symbolic analysis of Solidity smart contracts using Slither and Mythril to
  detect reentrancy, integer overflow, access-control, and other vulnerability classes before
  deployment to Ethereum mainnet. Use when auditing a Solidity contract for vulnerabilities,
  gating a contract before mainnet deployment, or triaging a reported DeFi exploit against its
  source. Keywords: Solidity, Slither, Mythril, reentrancy, integer overflow, access control,
  Ethereum. Do not use for Foundry-based test and invariant security assessment - use
  auditing-foundry-smart-contract-security.
domain: cybersecurity
subdomain: blockchain-security
tags:
- ethereum
- solidity
- smart-contract
- slither
- mythril
- blockchain
- defi
- audit
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- ID.RA-01
mitre_attack:
- T1190
- T1059
---

# Analyzing Ethereum Smart Contract Vulnerabilities

## Overview

Smart contract vulnerabilities have led to billions of dollars in losses across DeFi protocols. Unlike traditional software, deployed smart contracts are immutable and handle real financial assets, making pre-deployment security analysis critical. Slither performs fast static analysis using an intermediate representation to detect over 90 vulnerability patterns in seconds, while Mythril uses symbolic execution and SMT solving to discover complex execution path vulnerabilities like reentrancy and integer overflows. This skill covers running both tools against Solidity contracts, interpreting results, triaging findings by severity, and generating audit reports.


## When to Use

- Use when auditing a Solidity contract with Slither and Mythril before mainnet deployment.
- Use when hunting reentrancy, integer overflow, unchecked external calls, or broken access control in contract source.
- Use when gating a contract in CI so a high-severity Slither/Mythril finding blocks the deploy.
- Use when triaging a reported DeFi exploit against the contract's source to confirm the vulnerable function and path.
- Use when asked to "run a Slither/Mythril audit on this contract" or "find vulnerabilities in this Solidity code."

## Prerequisites

- Python 3.10+ with pip
- Slither (pip install slither-analyzer) and solc compiler
- Mythril (pip install mythril) with solc-select for compiler version management
- Solidity source code or compiled contract bytecode
- Foundry or Hardhat development framework (optional, for project-level analysis)

## Steps

### Step 1: Run Slither Static Analysis

Execute Slither against the contract codebase to identify vulnerability patterns, optimization opportunities, and code quality issues using its 90+ built-in detectors.

```bash
# Pin the compiler to the pragma version, then emit machine-readable results
solc-select install 0.8.20 && solc-select use 0.8.20
slither contracts/Vault.sol --json slither-out.json
```

```python
import json

with open("slither-out.json") as f:
    report = json.load(f)

# Surface high/medium impact detectors (e.g. reentrancy-eth, arbitrary-send)
for det in report.get("results", {}).get("detectors", []):
    if det["impact"] in ("High", "Medium"):
        where = det["elements"][0].get("name", "?") if det["elements"] else "?"
        print(f"[{det['impact']}] {det['check']} -> {where}")
```

### Step 2: Run Mythril Symbolic Execution

Run Mythril deep analysis to explore execution paths and discover reentrancy, unchecked external calls, and arithmetic vulnerabilities that require path-sensitive analysis.

### Step 3: Triage and Correlate Findings

Combine results from both tools, deduplicate findings, assess severity based on exploitability and financial impact, and filter false positives.

### Step 4: Generate Audit Report

Produce a structured audit report with vulnerability descriptions, affected code locations, exploit scenarios, and remediation recommendations.

## Expected Output

JSON report listing vulnerabilities with SWC (Smart Contract Weakness Classification) identifiers, severity ratings, affected functions, and suggested fixes.
