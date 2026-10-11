# SIEM Detection Rules (Splunk SPL, Elastic KQL, Zeek)

```
Splunk SPL - DNS Tunneling Detection:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- High entropy subdomain queries
index=dns sourcetype="bro:dns:json" OR sourcetype="suricata:dns"
| eval subdomain=mvindex(split(query,"."),0)
| eval sub_len=len(subdomain)
| where sub_len > 30
| eval char_counts=mvmap(split(subdomain,""),1)
| lookup dns_entropy_lookup subdomain OUTPUT entropy
| where entropy > 3.5
| stats count as query_count dc(query) as unique_queries
    avg(sub_len) as avg_sub_len values(query) as sample_queries
    by src_ip, domain
| where query_count > 20
| sort -query_count

-- DNS TXT record abuse
index=dns (qtype="TXT" OR qtype_name="TXT")
  NOT (query="*._domainkey.*" OR query="*._dmarc.*" OR query="*._spf.*")
| stats count as txt_queries dc(query) as unique_txt_queries
    values(query) as domains
    by src_ip
| where txt_queries > 50
| sort -txt_queries

-- DNS beaconing (regular interval queries)
index=dns sourcetype="bro:dns:json"
| bin _time span=60s
| stats count by src_ip, query, _time
| streamstats window=10 current=t avg(count) as avg_count stdev(count) as std_count by src_ip, query
| eval cv = if(avg_count>0, (std_count/avg_count)*100, 100)
| where cv < 20 AND avg_count > 0
| stats count as beacon_windows avg(cv) as avg_jitter
    min(_time) as first_seen max(_time) as last_seen
    by src_ip, query
| where beacon_windows > 10
| sort -beacon_windows

-- Unusual record type volume (NULL, KEY, SRV for tunneling)
index=dns (qtype_name="NULL" OR qtype_name="KEY" OR qtype_name="SRV"
    OR qtype_name="CNAME" OR qtype_name="MX")
  NOT qtype_name="A" NOT qtype_name="AAAA" NOT qtype_name="PTR"
| stats count by src_ip, qtype_name, query
| where count > 10
| sort -count
```

```
Elastic KQL - DNS C2 Detection:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- Long subdomain queries (potential tunneling)
dns.question.name: * and not dns.question.name: *.in-addr.arpa
| where length(dns.question.subdomain) > 40

-- High volume DNS to single domain
event.dataset: "zeek.dns" or event.dataset: "suricata.dns"
| stats count by source.ip, dns.question.registered_domain
| where count > 500

-- TXT record queries to non-standard domains
dns.question.type: "TXT"
  and not dns.question.name: (*._domainkey.* or *._dmarc.* or *._spf.*)
```

```
Zeek Script - DNS Tunneling Indicator:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# dns_tunnel_detect.zeek
@load base/protocols/dns

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Suspected,
        DNS_High_Entropy_Query,
        DNS_Excessive_TXT_Queries,
    };

    const entropy_threshold = 3.5 &redef;
    const subdomain_length_threshold = 40 &redef;
    const txt_query_threshold = 50 &redef;
    const tracking_interval = 5min &redef;
}

global txt_query_tracker: table[addr] of count &create_expire=5min &default=0;
global domain_query_tracker: table[addr, string] of count &create_expire=10min &default=0;

function shannon_entropy(s: string): double
{
    local counts: table[string] of count;
    local total = |s|;

    if (total == 0) return 0.0;

    for (i in s)
        {
        local c = s[i];
        if (c !in counts) counts[c] = 0;
        ++counts[c];
        }

    local ent = 0.0;
    for (ch, cnt in counts)
        {
        local p = cnt * 1.0 / total;
        ent -= p * log2(p);
        }

    return ent;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count,
                  qclass: count)
{
    if (|query| == 0) return;

    # Track TXT queries
    if (qtype == 16)  # TXT
    {
        ++txt_query_tracker[c$id$orig_h];
        if (txt_query_tracker[c$id$orig_h] == txt_query_threshold)
        {
            NOTICE([
                $note=DNS_Excessive_TXT_Queries,
                $conn=c,
                $msg=fmt("Host %s made %d TXT queries in tracking window",
                         c$id$orig_h, txt_query_threshold),
                $identifier=cat(c$id$orig_h),
            ]);
        }
    }

    # Extract subdomain and check entropy
    local parts = split_string(query, /\./);
    if (|parts| < 3) return;

    # Subdomain = everything except last two labels
    local subdomain = "";
    local i = 0;
    for (idx in parts)
    {
        if (i < |parts| - 2)
            subdomain += parts[idx];
        ++i;
    }

    if (|subdomain| > subdomain_length_threshold)
    {
        local ent = shannon_entropy(subdomain);
        if (ent > entropy_threshold)
        {
            NOTICE([
                $note=DNS_High_Entropy_Query,
                $conn=c,
                $msg=fmt("High entropy DNS query: entropy=%.2f len=%d query=%s",
                         ent, |subdomain|, query),
                $identifier=cat(c$id$orig_h, query),
            ]);
        }
    }
}
```
