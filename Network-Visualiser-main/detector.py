from detection_rules import (
    port_scan,
    syn_flood,
    brute_force,
    fanin_ddos,
    arp_spoofing,
    ping_sweep,
    large_outbound,
    dns_tunneling,
)

_DETECTORS = [
    port_scan,
    syn_flood,
    brute_force,
    fanin_ddos,
    arp_spoofing,
    ping_sweep,
    large_outbound,
    dns_tunneling,
]

def run_detections(flows):
    states = {d: d.new_state() for d in _DETECTORS}

    for flow in flows:
        for d in _DETECTORS:
            d.update(states[d], flow)

    alerts = []
    for d in _DETECTORS:
        res = d.finalize(states[d])
        alerts.extend(res)
        print(f"{d.__name__.split('.')[-1]} detection done: {len(res)} alerts")

    print(f"Anomaly detection finished: total {len(alerts)} alerts")
    return alerts