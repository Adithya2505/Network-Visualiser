from collections import defaultdict

SYN_FLOOD_RATIO    = 5.0
SYN_FLOOD_MIN_SYNS = 100

def detect(flows):
    alerts = []
    syn_cnt    = defaultdict(int)
    synack_cnt = defaultdict(int)

    for f in flows:
        if f["tcp_flags"] is None:
            continue
        flags = f["tcp_flags"]
        if (flags & 0x02) and not (flags & 0x10):
            syn_cnt[f["src_ip"]] += 1
        if (flags & 0x12) == 0x12:
            synack_cnt[f["dst_ip"]] += 1

    for src, syns in syn_cnt.items():
        if syns < SYN_FLOOD_MIN_SYNS:
            continue
        synacks = synack_cnt.get(src, 0)
        ratio = syns / max(synacks, 1)
        if ratio > SYN_FLOOD_RATIO:
            alerts.append({
                "type":    "SYN Flood",
                "source":  src,
                "target":  "multiple",
                "details": (
                    f"{src} sent {syns} SYNs but received only {synacks} SYN-ACKs "
                    f"(ratio {ratio:.1f}:1). Likely SYN flood or aggressive scan."
                ),
            })
    print(f"syn_flood detection done: {len(alerts)} alerts")
    return alerts