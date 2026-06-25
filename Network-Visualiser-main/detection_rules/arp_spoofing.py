from collections import defaultdict

_WHITELISTED_MAC_PREFIXES = (
    "00:00:5e:00:01:",  # VRRP
    "00:00:0c:07:ac:",  # HSRP
)

MAC_MULTI_IP_THRESHOLD = 2

def _is_whitelisted(mac: str) -> bool:
    return any(mac.lower().startswith(prefix) for prefix in _WHITELISTED_MAC_PREFIXES)

def new_state():
    return {
        "mac_to_ips": defaultdict(set),
        "ip_to_macs": defaultdict(set),
    }

def update(state, f):
    if f["protocol"] != "ARP" or f["arp_hwsrc"] is None:
        return
    if f["arp_hwsrc"] == "00:00:00:00:00:00":
        return
    if _is_whitelisted(f["arp_hwsrc"]):
        return
    state["mac_to_ips"][f["arp_hwsrc"]].add(f["src_ip"])
    state["ip_to_macs"][f["src_ip"]].add(f["arp_hwsrc"])

def finalize(state):
    alerts = []
    seen = set()

    for mac, ips in state["mac_to_ips"].items():
        if len(ips) >= MAC_MULTI_IP_THRESHOLD:
            key = ("mac", mac)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":    "ARP Spoofing",
                    "source":  sorted(ips)[0],
                    "target":  ", ".join(sorted(ips)),
                    "details": (
                        f"MAC {mac} claims to be {len(ips)} different IPs: "
                        f"{sorted(ips)}. Possible ARP cache poisoning."
                    ),
                })

    for ip, macs in state["ip_to_macs"].items():
        if len(macs) > 1:
            key = ("ip", ip)
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":    "ARP Spoofing",
                    "source":  ip,
                    "target":  ip,
                    "details": (
                        f"IP {ip} claimed by {len(macs)} different MACs: "
                        f"{sorted(macs)}. Indicates IP conflict or spoofing."
                    ),
                })
    return alerts