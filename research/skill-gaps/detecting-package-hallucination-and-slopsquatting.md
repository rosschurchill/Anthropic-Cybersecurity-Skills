# Detecting Package Hallucination and Slopsquatting — research notes

- **Proposed slug:** detecting-package-hallucination-and-slopsquatting
- **ATLAS:** AML.T0060 Publish Hallucinated Entities (Resource Development)
- **Status:** research (not yet a skill)

## Defensive goal
Detect and respond to slopsquatting: an LLM coding assistant recommends a non-existent
package (or command, URL, or dependency) that an attacker has pre-registered on a public
registry, so a developer who follows the suggestion installs attacker-controlled malware.
The defensive goal is to catch, in the dev/CI/coding-assistant workflow, (a) AI-suggested
dependencies that do not resolve to a known-good, pre-existing package, and (b) installs of
newly-registered names that match the shape of hallucinated or typo'd popular libraries,
before they reach a build or production.

## Data sources / telemetry
- **Coding-assistant / LLM I/O logs** — completions that emit `pip install`, `npm install`,
  `import`/`require`, or `package.json`/`requirements.txt` edits; extract suggested package
  names for resolution (Langfuse / assistant audit logs).
- **Dependency-resolution & private-registry logs** — registry proxy (Artifactory,
  Sonatype Nexus, Google Artifact Registry, Azure Artifacts, GitHub Packages, Verdaccio)
  resolve/install events: package name, version, first-seen-in-org, upstream source, and
  whether the name was previously unknown to the org.
- **Package-registry metadata** — PyPI/npm package age (creation date), maintainer history,
  download count, and whether the name existed before the AI suggested it.
- **CI/CD + SCA tooling output** — lockfile diffs adding new/unpinned deps, and
  software-composition-analysis / malware-artifact scan results on new dependencies.

## Detection logic / approach
1. **Resolve-before-install gate** — for every AI-suggested or newly-added dependency, check
   it against an allowlist / known-good set and registry metadata:
   ```
   # pseudo-rule (CI or pre-commit / resolver hook)
   for pkg in new_dependencies:
     if pkg not in org_allowlist and pkg.registry_age < 90d
        and pkg.download_count low
        and name_similarity(pkg, popular_libs) high   # typo/slop shape
     -> block + alert: possible slopsquat (AML.T0060)
   ```
2. **Hallucination corroboration** — flag names that appear only in assistant output and not
   in any first-party dependency manifest or the upstream index (the Spracklen et al. study
   found ~20% of LLM-suggested packages hallucinated and ~43% of hallucinations recur across
   re-runs — recurrence is what makes pre-registration profitable; figures to **verify**).
3. **New-dependency malware scan** — route any first-seen dependency through SCA / malware
   scanning (install-script, typosquat heuristics) before it enters the lockfile or image.

This is a **supply-chain / resource-development** defense in the *coding workflow*: the trigger
is an AI-recommended name that resolves to an attacker-registered or non-existent package.

## Response / mitigation
Enforce a **private-registry allowlist** (resolve only vetted, pre-existing packages; block
direct public-index pulls) and **dependency pinning with hashes** (lockfiles, `--require-hashes`,
`npm ci`) so a hallucinated name cannot silently resolve. Add a CI gate that fails on new deps
below an age/reputation floor or matching typosquat heuristics, and quarantine + SCA-scan all
first-seen packages. Instruct coding assistants / developers to verify every AI-suggested
package against the official index before install. On a hit, remove the dependency, scan for
install-time execution, and rotate any exposed secrets.

## Real tools
Private registries / proxies: JFrog Artifactory, Sonatype Nexus/Firewall, Google Artifact
Registry, Azure Artifacts, GitHub Packages, Verdaccio. SCA / supply-chain: Socket, OSV-Scanner,
Snyk, Semgrep Supply Chain, Dependabot, pip-audit, npm audit, Sigstore/SLSA provenance. LLM
I/O: Langfuse / assistant audit logs. (For scanning a captured malicious package, cross-ref
the existing analyzing-supply-chain-malware-artifacts skill.)

## Draft frontmatter mappings
- atlas: [AML.T0060]
- nist_csf: [DE.CM-09, DE.AE-02, RS.MI-01, PR.PS-01, ID.AM-02]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): analyzing-supply-chain-malware-artifacts

## Draft description (<=1024 chars)
Detects slopsquatting and AI package hallucination: LLM coding assistants recommending
non-existent package names that attackers pre-register on PyPI/npm so developers install
malware. Uses coding-assistant/LLM output logs, dependency-resolution and private-registry
proxy logs (Artifactory, Nexus, Artifact Registry), registry age/reputation metadata, and
CI/CD plus SCA tooling (Socket, OSV-Scanner, pip-audit) to flag AI-suggested dependencies that
do not resolve to a known-good pre-existing package or that match typosquat/hallucination
shapes, before install. Use when securing an AI-assisted dev/CI workflow against hallucinated
or pre-registered package names. Keywords: slopsquatting, package hallucination, AML.T0060,
dependency confusion, typosquat, private registry allowlist, dependency pinning, SCA, PyPI,
npm. Do not use for reverse-engineering an already-obtained malicious package - use
analyzing-supply-chain-malware-artifacts.

## Key references
- MITRE ATLAS AML.T0060 Publish Hallucinated Entities; case study AML.CS0022 ChatGPT package
  hallucination (verify ID): https://atlas.mitre.org/
- Spracklen et al., "We Have a Package for You!" — LLM package hallucination / slopsquatting
  study (hallucination and recurrence rates — verify figures)
- Vulcan Cyber / Lanyado "AI package hallucination" research (verify)
- OWASP LLM Top 10 — LLM09 Misinformation / overreliance; supply-chain guidance: https://owasp.org/
- SLSA framework & Sigstore: https://slsa.dev/ , https://www.sigstore.dev/

## Open questions / scope boundaries
- Confirm AML.T0060 tactic (Resource Development) and case study AML.CS0022 — **verify**;
  confirm the exact hallucination/recurrence percentages before quoting.
- Name-similarity / typosquat thresholds cause false positives on legitimate new internal
  packages; pair with allowlist + org-first-seen context.
- Boundary: this skill is *pre-install detection in the coding/CI workflow*; deep analysis of a
  captured malicious package belongs to analyzing-supply-chain-malware-artifacts.
