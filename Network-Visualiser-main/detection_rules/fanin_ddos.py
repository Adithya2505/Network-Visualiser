from collections import defaultdict
from sortedcontainers import SortedList

FANIN_THRESHOLD  = 50
TIME_WINDOW_SECS = 60.0
COOLDOWN_SECS    = 30.0

def new_state():
    return {
        "dst_events": defaultdict(list),
    }

def update(state, f):
    state["dst_events"][f["dst_ip"]].append((f["timestamp"], f["src_ip"]))

def finalize(state):
    alerts = []

    for dst, events in state["dst_events"].items():
        events.sort(key=lambda e: e[0])

        window_times  = SortedList(key=lambda e: e[0])
        src_counts    = defaultdict(int)
        last_alert_ts = None

        for ts, src in events:
            window_times.add((ts, src))
            src_counts[src] += 1

            cutoff = ts - TIME_WINDOW_SECS
            while window_times and window_times[0][0] < cutoff:
                old_ts, old_src = window_times.pop(0)
                src_counts[old_src] -= 1
                if src_counts[old_src] == 0:
                    del src_counts[old_src]

            unique_srcs = len(src_counts)

            if unique_srcs > FANIN_THRESHOLD:
                if last_alert_ts is None or (ts - last_alert_ts) >= COOLDOWN_SECS:
                    last_alert_ts = ts
                    window_start  = window_times[0][0]
                    alerts.append({
                        "type":      "DDoS / Fan-In",
                        "source":    "multiple",
                        "target":    dst,
                        "timestamp": round(ts, 3),
                        "details": (
                            f"{dst} received traffic from {unique_srcs} unique source IPs "
                            f"within {TIME_WINDOW_SECS:.0f}s "
                            f"(window {round(window_start, 3)}–{round(ts, 3)}). "
                            f"Potential DDoS or botnet coordination."
                        ),
                    })

    return alerts