from collections import defaultdict
import ipaddress

LARGE_OUTBOUND_BYTES = 2 * 1024 * 1024  # 2 MB

_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False

def detect(flows):
    alerts = []
    flow_bytes = defaultdict(int)

    for f in flows:
        if f["pkt_len"] and _is_private(f["src_ip"]) and not _is_private(f["dst_ip"]):
            flow_bytes[(f["src_ip"], f["dst_ip"])] += f["pkt_len"]

    for (src, dst), total in flow_bytes.items():
        if total > LARGE_OUTBOUND_BYTES:
            alerts.append({
                "type":    "Large Outbound Transfer",
                "source":  src,
                "target":  dst,
                "details": (
                    f"{src} transferred {total / (1024*1024):.2f} MB to external IP {dst}. "
                    f"Potential data exfiltration."
                ),
            })
    print(f"large_outbound detection done: {len(alerts)} alerts")
    return alerts