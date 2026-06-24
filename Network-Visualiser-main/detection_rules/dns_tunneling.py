import math
from collections import defaultdict, Counter

DNS_LABEL_MAX      = 52   # per-label threshold (Elastic/Endgame research)
DNS_FULL_QUERY_MAX = 100  # full FQDN threshold
DNS_QUERY_COUNT    = 10   # min total queries before evaluating a source
DNS_MIN_SUSPICIOUS = 5    # min suspicious queries to raise an alert
DNS_ENTROPY_MIN    = 4.0  # Shannon entropy floor; tunneled subdomains typically > 4.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _extract_subdomain(query: str) -> str:
    # Strip the last two labels (SLD + TLD) and return the subdomain portion.
    parts = query.rstrip(".").split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else ""


def _is_suspicious(query: str) -> bool:
    labels = query.rstrip(".").split(".")
    if any(len(label) > DNS_LABEL_MAX for label in labels):
        return True
    if len(query) > DNS_FULL_QUERY_MAX:
        return True
    subdomain = _extract_subdomain(query)
    if subdomain and _shannon_entropy(subdomain) > DNS_ENTROPY_MIN:
        return True
    return False


def detect(flows):
    alerts = []
    src_queries = defaultdict(list)

    for f in flows:
        if f["dns_query"] is not None:
            src_queries[f["src_ip"]].append(f["dns_query"])

    for src, queries in src_queries.items():
        if len(queries) < DNS_QUERY_COUNT:
            continue

        suspicious = [q for q in queries if _is_suspicious(q)]

        if len(suspicious) >= DNS_MIN_SUSPICIOUS:
            alerts.append({
                "type":    "DNS Tunneling",
                "source":  src,
                "target":  "DNS",
                "details": (
                    f"{src} made {len(suspicious)} suspicious DNS queries "
                    f"(long labels, long FQDNs, or high-entropy subdomains) "
                    f"out of {len(queries)} total. "
                    f"Sample: {suspicious[0][:80]}"
                ),
            })

    return alerts