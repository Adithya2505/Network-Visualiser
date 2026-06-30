from collections import defaultdict

SYN_FLOOD_RATIO    = 5.0
SYN_FLOOD_MIN_SYNS = 100

def new_state():
    return {
        "syn_cnt":    defaultdict(int),
        "synack_cnt": defaultdict(int),
        "evidence":   defaultdict(list),
    }

def update(state, f):
    if f["tcp_flags"] is None:
        return
    flags = f["tcp_flags"]
    if (flags & 0x02) and not (flags & 0x10):
        state["syn_cnt"][f["src_ip"]] += 1
        if len(state["evidence"][f["src_ip"]]) < 50:
            state["evidence"][f["src_ip"]].append({
                "timestamp": f["timestamp"],
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "dst_port": f["dst_port"],
                "tcp_flags": f["tcp_flags"],
            })
    if (flags & 0x12) == 0x12:
        state["synack_cnt"][f["dst_ip"]] += 1

def finalize(state):
    alerts = []
    for src, syns in state["syn_cnt"].items():
        if syns < SYN_FLOOD_MIN_SYNS:
            continue
        synacks = state["synack_cnt"].get(src, 0)
        ratio = syns / max(synacks, 1)
        if ratio > SYN_FLOOD_RATIO:
            evidence = sorted(state["evidence"].get(src, []), key=lambda x: x["timestamp"])
            alerts.append({
                "type":    "SYN Flood",
                "source":  src,
                "target":  "multiple",
                "details": (
                    f"{src} sent {syns} SYNs but received only {synacks} SYN-ACKs "
                    f"(ratio {ratio:.1f}:1). Likely SYN flood or aggressive scan."
                ),
                "evidence": evidence,
            })
    return alerts