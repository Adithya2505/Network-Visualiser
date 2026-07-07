import math
from collections import defaultdict, Counter

DNS_LABEL_MAX      = 52
DNS_FULL_QUERY_MAX = 100
DNS_QUERY_COUNT    = 10
DNS_MIN_SUSPICIOUS = 5
DNS_ENTROPY_MIN    = 4.0
_EVIDENCE_CAP      = 50


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def _extract_subdomain(query: str) -> str:
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

def _suspicious_reasons(query: str) -> list:
    """Return a list of human-readable reason strings for why a query is suspicious."""
    reasons = []
    labels = query.rstrip(".").split(".")
    if any(len(label) > DNS_LABEL_MAX for label in labels):
        reasons.append("long_label")
    if len(query) > DNS_FULL_QUERY_MAX:
        reasons.append("long_fqdn")
    subdomain = _extract_subdomain(query)
    if subdomain and _shannon_entropy(subdomain) > DNS_ENTROPY_MIN:
        reasons.append("high_entropy")
    return reasons


def _enrich_event(ev):
    """Add computed fields so Unity can 'show the math' without reimplementing."""
    query = ev["dns_query"]
    subdomain = _extract_subdomain(query)
    entropy = round(_shannon_entropy(subdomain), 2) if subdomain else 0.0
    return {
        **ev,
        "suspicious": _is_suspicious(query),
        "entropy": entropy,
        "subdomain": subdomain,
        "suspicious_reasons": _suspicious_reasons(query),
    }


def _build_replay(evidence, total_queries, total_suspicious):
    """Pre-compute everything Unity needs to render the forensic replay.

    Note: evidence only contains *suspicious* queries (filtered in finalize()).
    total_queries comes from state["src_queries"] which includes non-suspicious
    queries.  running_state.total_queries is therefore the final total on every
    frame — it can't be incrementally tracked from the evidence alone.
    """

    # ── Bucket evidence into 1-second time windows ──────────────────
    buckets = defaultdict(list)
    for ev in evidence:
        buckets[int(ev["timestamp"])].append(ev)

    # ── Build frames with cumulative running state ──────────────────
    frames = []
    running_suspicious = 0
    gate_already_passed = False

    for time_bucket in sorted(buckets):
        raw_events = buckets[time_bucket]
        enriched_events = [_enrich_event(ev) for ev in raw_events]

        running_suspicious += len(enriched_events)

        gate_now = (total_queries >= DNS_QUERY_COUNT
                    and running_suspicious >= DNS_MIN_SUSPICIOUS)
        gate_passed = gate_now and not gate_already_passed
        if gate_passed:
            gate_already_passed = True

        # ── Per-edge aggregation for this frame ─────────────────────
        edge_map = defaultdict(lambda: {"event_count": 0, "queries": []})
        for ev in enriched_events:
            ekey = (ev["src_ip"], ev["dst_ip"])
            edge_map[ekey]["event_count"] += 1
            edge_map[ekey]["queries"].append(ev["dns_query"])

        edges = [
            {
                "src": src,
                "dst": dst,
                "event_count": info["event_count"],
                "queries": info["queries"],
            }
            for (src, dst), info in edge_map.items()
        ]

        frames.append({
            "time_bucket": time_bucket,
            "events": enriched_events,
            "running_state": {
                "total_queries": total_queries,
                "suspicious_count": running_suspicious,
            },
            "gate_now": gate_now,
            "gate_passed": gate_passed,
            "edges": edges,
        })

    return {
        "detector_type": "dns_tunneling",
        "thresholds": {
            "min_total_queries": DNS_QUERY_COUNT,
            "min_suspicious": DNS_MIN_SUSPICIOUS,
            "entropy_min": DNS_ENTROPY_MIN,
            "label_max": DNS_LABEL_MAX,
            "full_query_max": DNS_FULL_QUERY_MAX,
        },
        "final_values": {
            "total_queries": total_queries,
            "suspicious_count": total_suspicious,
        },
        "evidence_capped": len(evidence) >= _EVIDENCE_CAP,
        "evidence_cap": _EVIDENCE_CAP,
        "frames": frames,
    }


def new_state():
    return {
        "src_queries": defaultdict(list),
        "evidence":    defaultdict(list),
    }

def update(state, f):
    if f["dns_query"] is not None:
        state["src_queries"][f["src_ip"]].append(f["dns_query"])
        state["evidence"][f["src_ip"]].append({
            "timestamp": f["timestamp"],
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
            "dns_query": f["dns_query"],
        })

def finalize(state):
    alerts = []
    for src, queries in state["src_queries"].items():
        if len(queries) < DNS_QUERY_COUNT:
            continue
        suspicious = [q for q in queries if _is_suspicious(q)]
        if len(suspicious) >= DNS_MIN_SUSPICIOUS:
            evidence = [
                record for record in sorted(state["evidence"].get(src, []), key=lambda item: item["timestamp"])
                if _is_suspicious(record["dns_query"])
            ][:_EVIDENCE_CAP]
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
                "evidence": evidence,
                "replay": _build_replay(
                    evidence,
                    total_queries=len(queries),
                    total_suspicious=len(suspicious),
                ),
            })
    return alerts