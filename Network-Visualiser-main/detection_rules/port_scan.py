import random
from collections import defaultdict

PORT_SCAN_MIN_PORTS = 20
PORT_SCAN_MIN_SYNS  = 5
_EVIDENCE_CAP       = 50


def _build_replay(evidence, total_unique_ports, total_syn_count):
    """Pre-compute everything Unity needs to render the forensic replay."""

    # ── Bucket evidence into 1-second time windows ──────────────────
    buckets = defaultdict(list)
    for ev in evidence:
        buckets[int(ev["timestamp"])].append(ev)

    # ── Build frames with cumulative running state ──────────────────
    frames = []
    running_ports = set()
    running_syn_count = 0
    gate_already_passed = False

    for time_bucket in sorted(buckets):
        events = buckets[time_bucket]

        for ev in events:
            running_ports.add(ev["dst_port"])
            running_syn_count += 1

        cur_unique = len(running_ports)
        cur_syns   = running_syn_count

        gate_now = (cur_unique > PORT_SCAN_MIN_PORTS
                    and cur_syns >= PORT_SCAN_MIN_SYNS)
        gate_passed = gate_now and not gate_already_passed
        if gate_passed:
            gate_already_passed = True

        # ── Per-edge aggregation for this frame ─────────────────────
        edge_map = defaultdict(lambda: {"event_count": 0, "ports": set()})
        for ev in events:
            ekey = (ev["src_ip"], ev["dst_ip"])
            edge_map[ekey]["event_count"] += 1
            edge_map[ekey]["ports"].add(ev["dst_port"])

        edges = [
            {
                "src": src,
                "dst": dst,
                "event_count": info["event_count"],
                "ports": sorted(info["ports"]),
            }
            for (src, dst), info in edge_map.items()
        ]

        frame = {
            "time_bucket": time_bucket,
            "events": events,
            "running_state": {
                "unique_ports": cur_unique,
                "syn_count": cur_syns,
            },
            "gate_now": gate_now,
            "gate_passed": gate_passed,
            "edges": edges,
        }
        if len(frames) < 2 or gate_now:
            frames.append(frame)

    return {
        "detector_type": "port_scan",
        "thresholds": {
            "unique_ports": PORT_SCAN_MIN_PORTS,
            "min_syns": PORT_SCAN_MIN_SYNS,
        },
        "final_values": {
            "unique_ports": total_unique_ports,
            "syn_count": total_syn_count,
        },
        "evidence_capped": len(evidence) >= _EVIDENCE_CAP,
        "evidence_cap": _EVIDENCE_CAP,
        "frames": frames,
    }


def new_state():
    return {
        "port_sets":  defaultdict(set),
        "syn_counts": defaultdict(int),
        "evidence":    defaultdict(list),
        "evidence_count": defaultdict(int),
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
    state["evidence_count"][key] += 1
    ev_item = {
        "timestamp": f["timestamp"],
        "src_ip": f["src_ip"],
        "dst_ip": f["dst_ip"],
        "dst_port": f["dst_port"],
        "tcp_flags": f["tcp_flags"],
    }
    if len(state["evidence"][key]) < _EVIDENCE_CAP:
        state["evidence"][key].append(ev_item)
    else:
        j = random.randint(0, state["evidence_count"][key] - 1)
        if j < _EVIDENCE_CAP:
            state["evidence"][key][j] = ev_item

def finalize(state):
    alerts = []
    for (src, dst), ports in state["port_sets"].items():
        if len(ports) <= PORT_SCAN_MIN_PORTS:
            continue
        if state["syn_counts"][(src, dst)] < PORT_SCAN_MIN_SYNS:
            continue

        evidence = sorted(state["evidence"][(src, dst)], key=lambda item: item["timestamp"])

        alerts.append({
            "type":    "Port Scan",
            "source":  src,
            "target":  dst,
            "details": (
                f"{src} sent SYN-only packets to {len(ports)} unique ports on {dst} "
                f"({state['syn_counts'][(src, dst)]} total SYNs). Consistent with port reconnaissance."
            ),
            "evidence": evidence,
            "replay": _build_replay(
                evidence,
                total_unique_ports=len(ports),
                total_syn_count=state["syn_counts"][(src, dst)],
            ),
        })
    return alerts