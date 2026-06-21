# parser.py
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ARP, ICMP, DNS, DNSQR


def read_pcap(file_path):
    packets = rdpcap(file_path)
    print(f"PCAP read successfully: {file_path}")
    return packets


def preprocess_packets(packets):
    flows = []

    for packet in packets:

        # ── ARP packets (no IP layer) ──────────────────────────────────
        if packet.haslayer(ARP):
            flows.append({
                "src_ip":    packet[ARP].psrc,
                "dst_ip":    packet[ARP].pdst,
                "protocol":  "ARP",
                "timestamp": float(packet.time),
                "src_port":  None,
                "dst_port":  None,
                "tcp_flags": None,
                "pkt_len":   0,
                "arp_op":    packet[ARP].op,        # 1=request, 2=reply
                "arp_hwsrc": packet[ARP].hwsrc,
                "arp_hwdst": packet[ARP].hwdst,
                "dns_query": None,
            })
            continue

        # ── Skip non-IP packets ────────────────────────────────────────
        if not packet.haslayer(IP):
            continue

        # ── Base IP flow record ────────────────────────────────────────
        flow = {
            "src_ip":    packet[IP].src,
            "dst_ip":    packet[IP].dst,
            "protocol":  packet[IP].proto,
            "timestamp": float(packet.time),
            "src_port":  None,
            "dst_port":  None,
            "tcp_flags": None,
            "pkt_len":   packet[IP].len,
            "arp_op":    None,
            "arp_hwsrc": None,
            "arp_hwdst": None,
            "dns_query": None,
        }

        if packet.haslayer(TCP):
            flow["src_port"]  = packet[TCP].sport
            flow["dst_port"]  = packet[TCP].dport
            flow["tcp_flags"] = int(packet[TCP].flags)

        elif packet.haslayer(UDP):
            flow["src_port"] = packet[UDP].sport
            flow["dst_port"] = packet[UDP].dport
            # DNS tunneling: capture query name from UDP/53
            if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                try:
                    flow["dns_query"] = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    pass

        elif packet.haslayer(ICMP):
            # Store type/code as pseudo-ports so the rest of the pipeline
            # doesn't need special cases. Protocol 1 + dst_port 8 = echo request.
            flow["src_port"] = packet[ICMP].type
            flow["dst_port"] = packet[ICMP].code

        flows.append(flow)

    print(f"Preprocessed packets into {len(flows)} flows")
    return flows


def build_topology(flows):
    nodes = set()
    edge_counts = defaultdict(int)

    for flow in flows:
        nodes.add(flow["src_ip"])
        nodes.add(flow["dst_ip"])
        edge_counts[(flow["src_ip"], flow["dst_ip"])] += 1

    edges = [
        {"src": src, "dst": dst, "count": count}
        for (src, dst), count in edge_counts.items()
    ]
    topology = {"nodes": list(nodes), "edges": edges}
    print(f"Built topology with {len(topology['nodes'])} nodes and {len(topology['edges'])} edges")
    return topology