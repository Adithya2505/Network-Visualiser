import random
from collections import defaultdict

SYN_FLOOD_RATIO    = 5.0
SYN_FLOOD_MIN_SYNS = 100
_EVIDENCE_CAP      = 125


def _build_replay(evidence, total_syn_count, total_synack_count):
    """Pre-compute everything Unity needs to render the forensic replay.

    Note: evidence only contains SYN packets (collected in the SYN branch
    of update()).  SYN-ACK count is a global total computed at finalize time,
    so running_state.synack_count is the same final value on every frame.
    The ratio is derived as running_syn_count / max(final_synack_count, 1).
    """

    # ── Bucket evidence into 1-second time windows ──────────────────
    buckets = defaultdict(list)
    for ev in evidence:
        buckets[int(ev["timestamp"])].append(ev)

    # ── Build frames with cumulative running state ──────────────────
    frames = []
    running_syn_count = 0
    gate_already_passed = False

    for time_bucket in sorted(buckets):
        events = buckets[time_bucket]

        running_syn_count += len(events)
        ratio = running_syn_count / max(total_synack_count, 1)

        gate_now = (running_syn_count >= SYN_FLOOD_MIN_SYNS
                    and ratio > SYN_FLOOD_RATIO)
        gate_passed = gate_now and not gate_already_passed
        if gate_passed:
            gate_already_passed = True

        # ── Per-edge aggregation for this frame ─────────────────────
        edge_map = defaultdict(int)
        for ev in events:
            edge_map[(ev["src_ip"], ev["dst_ip"])] += 1

        edges = [
            {"src": src, "dst": dst, "event_count": count}
            for (src, dst), count in edge_map.items()
        ]

        frame = {
            "time_bucket": time_bucket,
            "events": events,
            "running_state": {
                "syn_count": running_syn_count,
                "synack_count": total_synack_count,
                "ratio": round(ratio, 2),
            },
            "gate_now": gate_now,
            "gate_passed": gate_passed,
            "edges": edges,
        }
        if len(frames) < 2 or gate_now:
            frames.append(frame)

    final_ratio = total_syn_count / max(total_synack_count, 1)

    return {
        "detector_type": "syn_flood",
        "thresholds": {
            "min_syns": SYN_FLOOD_MIN_SYNS,
            "syn_synack_ratio": SYN_FLOOD_RATIO,
        },
        "final_values": {
            "syn_count": total_syn_count,
            "synack_count": total_synack_count,
            "ratio": round(final_ratio, 2),
        },
        "evidence_capped": len(evidence) >= _EVIDENCE_CAP,
        "evidence_cap": _EVIDENCE_CAP,
        "frames": frames,
    }


def new_state():
    return {
        "syn_cnt":    defaultdict(int),
        "synack_cnt": defaultdict(int),
        "evidence":   defaultdict(list),
        "evidence_count": defaultdict(int),
    }

def update(state, f):
    if f["tcp_flags"] is None:
        return
    flags = f["tcp_flags"]
    if (flags & 0x02) and not (flags & 0x10):
        state["syn_cnt"][f["src_ip"]] += 1
        state["evidence_count"][f["src_ip"]] += 1
        ev_item = {
            "timestamp": f["timestamp"],
            "src_ip": f["src_ip"],
            "dst_ip": f["dst_ip"],
            "dst_port": f["dst_port"],
            "tcp_flags": f["tcp_flags"],
        }
        if len(state["evidence"][f["src_ip"]]) < _EVIDENCE_CAP:
            state["evidence"][f["src_ip"]].append(ev_item)
        else:
            j = random.randint(0, state["evidence_count"][f["src_ip"]] - 1)
            if j < _EVIDENCE_CAP:
                state["evidence"][f["src_ip"]][j] = ev_item
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
                "replay": _build_replay(
                    evidence,
                    total_syn_count=syns,
                    total_synack_count=synacks,
                ),
            })
    return alerts