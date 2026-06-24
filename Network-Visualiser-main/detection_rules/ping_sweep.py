from collections import defaultdict

PING_SWEEP_THRESHOLD = 10

def detect(flows):
    alerts = []
    icmp_dsts = defaultdict(set)

    for f in flows:
        # Protocol 1 = ICMP, dst_port stores ICMP type (8 = echo request)
        if f["protocol"] == 1 and f["dst_port"] == 8:
            icmp_dsts[f["src_ip"]].add(f["dst_ip"])

    for src, dsts in icmp_dsts.items():
        if len(dsts) >= PING_SWEEP_THRESHOLD:
            alerts.append({
                "type":    "Ping Sweep",
                "source":  src,
                "target":  "multiple",
                "details": (
                    f"{src} sent ICMP echo requests to {len(dsts)} unique destinations. "
                    f"Consistent with network reconnaissance."
                ),
            })
    return alerts