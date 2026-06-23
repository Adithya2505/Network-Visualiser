# detector.py
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

def run_detections(flows):
    alerts = []
    res = port_scan.detect(flows)
    alerts.extend(res)
    print(f"port_scan detection done: {len(res)} alerts")

    res = syn_flood.detect(flows)
    alerts.extend(res)
    print(f"syn_flood detection done: {len(res)} alerts")

    res = brute_force.detect(flows)
    alerts.extend(res)
    print(f"brute_force detection done: {len(res)} alerts")

    res = fanin_ddos.detect(flows)
    alerts.extend(res)
    print(f"fanin_ddos detection done: {len(res)} alerts")

    res = arp_spoofing.detect(flows)
    alerts.extend(res)
    print(f"arp_spoofing detection done: {len(res)} alerts")

    res = ping_sweep.detect(flows)
    alerts.extend(res)
    print(f"ping_sweep detection done: {len(res)} alerts")

    res = large_outbound.detect(flows)
    alerts.extend(res)
    print(f"large_outbound detection done: {len(res)} alerts")

    res = dns_tunneling.detect(flows)
    alerts.extend(res)
    print(f"dns_tunneling detection done: {len(res)} alerts")

    print(f"Anomaly detection finished: total {len(alerts)} alerts")
    return alerts