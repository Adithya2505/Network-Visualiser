from collections import defaultdict

PING_SWEEP_THRESHOLD = 10

def new_state():
    return {
        "icmp_dsts": defaultdict(set),
    }

def update(state, f):
    if f["protocol"] == 1 and f["dst_port"] == 8:
        state["icmp_dsts"][f["src_ip"]].add(f["dst_ip"])

def finalize(state):
    alerts = []
    for src, dsts in state["icmp_dsts"].items():
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