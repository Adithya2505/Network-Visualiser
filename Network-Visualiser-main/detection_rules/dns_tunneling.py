from collections import defaultdict

DNS_TUNNEL_LENGTH      = 52
DNS_TUNNEL_QUERY_COUNT = 10
DNS_TUNNEL_MIN_LONG    = 3

def detect(flows):
    alerts = []
    src_queries = defaultdict(list)

    for f in flows:
        if f["dns_query"] is not None:
            src_queries[f["src_ip"]].append(f["dns_query"])

    for src, queries in src_queries.items():
        if len(queries) < DNS_TUNNEL_QUERY_COUNT:
            continue
        long_queries = [q for q in queries if len(q) > DNS_TUNNEL_LENGTH]
        if len(long_queries) >= DNS_TUNNEL_MIN_LONG:
            alerts.append({
                "type":    "DNS Tunneling",
                "source":  src,
                "target":  "DNS",
                "details": (
                    f"{src} made {len(long_queries)} DNS queries with names "
                    f">{DNS_TUNNEL_LENGTH} chars out of {len(queries)} total. "
                    f"Sample: {long_queries[0][:80]}"
                ),
            })
    print(f"dns_tunneling detection done: {len(alerts)} alerts")
    return alerts