from collections import defaultdict
from sortedcontainers import SortedList

FANIN_THRESHOLD  = 50    # unique source IPs within the window to trigger
TIME_WINDOW_SECS = 60.0  # sliding window size in seconds
COOLDOWN_SECS    = 30.0  # suppress repeat alerts for the same dst within this period


def detect(flows):
    # Group flows by dst_ip, sorted by timestamp, for the sliding window sweep.
    # We only need (timestamp, src_ip) per destination.
    dst_events = defaultdict(list)
    for f in flows:
        dst_events[f["dst_ip"]].append((f["timestamp"], f["src_ip"]))

    alerts = []

    for dst, events in dst_events.items():
        events.sort(key=lambda e: e[0])  # sort by timestamp

        # Sliding window: maintain a SortedList of timestamps in the window
        # and a count-map of src_ip -> occurrences so we can track unique IPs.
        window_times  = SortedList(key=lambda e: e[0])
        src_counts    = defaultdict(int)
        last_alert_ts = None

        for ts, src in events:
            # Add incoming event
            window_times.add((ts, src))
            src_counts[src] += 1

            # Evict events that have fallen outside the window
            cutoff = ts - TIME_WINDOW_SECS
            while window_times and window_times[0][0] < cutoff:
                old_ts, old_src = window_times.pop(0)
                src_counts[old_src] -= 1
                if src_counts[old_src] == 0:
                    del src_counts[old_src]

            unique_srcs = len(src_counts)

            if unique_srcs > FANIN_THRESHOLD:
                # Suppress if we already alerted for this dst recently
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