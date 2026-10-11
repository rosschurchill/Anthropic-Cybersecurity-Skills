# Suricata Rules for Known DNS C2 Tools

```
# suricata-dns-c2.rules
# DNS Tunneling and C2 Detection Rules

# Iodine DNS tunnel detection
alert dns any any -> any any (msg:"ET TROJAN Iodine DNS Tunnel Activity - NULL Query"; \
    dns.query; content:"."; pcre:"/^[a-z0-9]{50,}\.[a-z0-9.-]+$/i"; \
    dns_query; content:"|00 0a|"; \
    classtype:trojan-activity; sid:2030001; rev:1;)

# dnscat2 DNS tunnel detection
alert dns any any -> any any (msg:"ET TROJAN dnscat2 DNS Tunnel - Handshake"; \
    dns.query; content:"dnscat."; nocase; fast_pattern; \
    classtype:trojan-activity; sid:2030002; rev:1;)

alert dns any any -> any any (msg:"ET TROJAN dnscat2 DNS Tunnel - Data Channel"; \
    dns.query; pcre:"/^[a-f0-9]{16,}\./i"; \
    dns_query; content:"|00 10|"; \
    classtype:trojan-activity; sid:2030003; rev:1;)

# Cobalt Strike DNS beacon
alert dns any any -> any any (msg:"ET TROJAN Cobalt Strike DNS Beacon - A Record"; \
    dns.query; pcre:"/^[a-f0-9]{12,}\.[a-z0-9.-]+$/i"; \
    threshold:type both, track by_src, count 20, seconds 60; \
    classtype:trojan-activity; sid:2030004; rev:1;)

# Generic DNS tunneling - high volume TXT queries to single domain
alert dns any any -> any any (msg:"ET POLICY Excessive TXT DNS Queries - Possible Tunneling"; \
    dns_query; content:"|00 10|"; \
    threshold:type threshold, track by_src, count 50, seconds 300; \
    classtype:policy-violation; sid:2030005; rev:1;)

# Long subdomain query (generic tunneling indicator)
alert dns any any -> any any (msg:"ET POLICY Unusually Long DNS Subdomain - Possible Tunneling"; \
    dns.query; pcre:"/^[a-z0-9-]{52,}\./i"; \
    threshold:type limit, track by_src, count 1, seconds 60; \
    classtype:policy-violation; sid:2030006; rev:1;)

# DNS query for known C2 TXT payload staging
alert dns any any -> any any (msg:"ET TROJAN DNS TXT Record Staged Payload Request"; \
    dns_query; content:"|00 10|"; \
    dns.query; pcre:"/^(stage|payload|cmd|exec|download|update|config)\d*\./i"; \
    classtype:trojan-activity; sid:2030007; rev:1;)
```
