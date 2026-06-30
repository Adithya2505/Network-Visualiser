from collections import defaultdict

PORT_SCAN_MIN_PORTS = 20
PORT_SCAN_MIN_SYNS  = 5

def new_state():
    return {
        "port_sets":  defaultdict(set),
        "syn_counts": defaultdict(int),
        "evidence":    defaultdict(list),
    }

def update(state, f):
    if f["tcp_flags"] is None or f["dst_port"] is None:
        return
    flags = f["tcp_flags"]
    if not ((flags & 0x02) and not (flags & 0x10)):
        return
    key = (f["src_ip"], f["dst_ip"])
    state["port_sets"][key].add(f["dst_port"])
    state["syn_counts"][key] += 1
    if len(state["evidence"][key]) < 50:
        state["evidence"][key].append({
            "timestamp": f["timestamp"],
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
            "dst_port": f["dst_port"],
            "tcp_flags": f["tcp_flags"],
        })

def finalize(state):
    alerts = []
    for (src, dst), ports in state["port_sets"].items():
        if len(ports) <= PORT_SCAN_MIN_PORTS:
            continue
        if state["syn_counts"][(src, dst)] < PORT_SCAN_MIN_SYNS:
            continue
        alerts.append({
            "type":    "Port Scan",
            "source":  src,
            "target":  dst,
            "details": (
                f"{src} sent SYN-only packets to {len(ports)} unique ports on {dst} "
                f"({state['syn_counts'][(src, dst)]} total SYNs). Consistent with port reconnaissance."
            ),
            "evidence": sorted(state["evidence"][(src, dst)], key=lambda item: item["timestamp"]),
        })
    return alerts