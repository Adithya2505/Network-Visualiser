from collections import defaultdict

def detect(flows):
    alerts = []
    mac_to_ips = defaultdict(set)
    ip_to_macs = defaultdict(set)

    for f in flows:
        if f["protocol"] != "ARP" or f["arp_hwsrc"] is None:
            continue
        if f["arp_hwsrc"] == "00:00:00:00:00:00":
            continue
        mac_to_ips[f["arp_hwsrc"]].add(f["src_ip"])
        ip_to_macs[f["src_ip"]].add(f["arp_hwsrc"])

    seen = set()

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            key = ("mac", mac)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":    "ARP Spoofing",
                    "source":  mac,
                    "target":  ", ".join(sorted(ips)),
                    "details": (
                        f"MAC {mac} claims to be {len(ips)} different IPs: "
                        f"{sorted(ips)}. Indicates ARP cache poisoning."
                    ),
                })

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            key = ("ip", ip)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":    "ARP Spoofing",
                    "source":  ", ".join(sorted(macs)),
                    "target":  ip,
                    "details": (
                        f"IP {ip} claimed by {len(macs)} different MACs: "
                        f"{sorted(macs)}. Indicates IP conflict or spoofing."
                    ),
                })
    print(f"arp_spoofing detection done: {len(alerts)} alerts")
    return alerts