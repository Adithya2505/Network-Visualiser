import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
# import matplotlib.pyplot as plt

from collections import defaultdict

PROTOCOL_MAP = {
    6:    "TCP",
    17:   "UDP",
    1:    "ICMP",
    "ARP": "ARP",
}

def add_layout_positions(topology, flows):
    G = nx.Graph()
    for node in topology["nodes"]:
        G.add_node(node)
    for edge in topology["edges"]:
        G.add_edge(edge["src"], edge["dst"])

    # print("DEBUG: Graph nodes:", list(G.nodes()))
    # print("DEBUG: Graph edges:", list(G.edges()))

    pos = graphviz_layout(G, prog="sfdp")
    # ── Normalize positions to -1..1 range (preserves relative layout) ──
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    x_min, x_max = min(xs), max(xs)
    y_min, y_max = min(ys), max(ys)

    def normalize(val, vmin, vmax):
        if vmax - vmin == 0:
            return 0.0
        return 2 * (val - vmin) / (vmax - vmin) - 1

    pos = {
        node: (normalize(x, x_min, x_max), normalize(y, y_min, y_max))
        for node, (x, y) in pos.items()
    }
    
    # print("DEBUG: Layout positions:", pos)

    # Optional temporary visual check
    #nx.draw(G, pos, with_labels=True, node_size=300, font_size=8)
    # plt.title("DEBUG: NetworkX Graph Layout")
    # plt.show()

    # ── Per-node activity and protocol counts (outbound + inbound) ──
    activity  = defaultdict(int)
    protocols = defaultdict(lambda: defaultdict(int))
    first_seen = {}
    last_seen  = {}
    inbound_bytes  = defaultdict(int)
    outbound_bytes = defaultdict(int)
    dst_ports = defaultdict(lambda: defaultdict(int))   
    peers = defaultdict(set)

    # ── Per-edge protocol counts (merged bidirectional) ─────────────
    # Key: frozenset({src, dst}) so A→B and B→A merge
    edge_protocols = defaultdict(lambda: defaultdict(int))
    edge_counts    = defaultdict(int)

    for f in flows:
        src  = f["src_ip"]
        dst  = f["dst_ip"]
        if src is None or dst is None:
            continue

        proto = f["protocol"]
        label = "ARP" if proto == "ARP" else PROTOCOL_MAP.get(proto, "Other")

        # Node-level (bidirectional)
        outbound_bytes[src] += f["pkt_len"]
        inbound_bytes[dst]  += f["pkt_len"]
        activity[src]       += f["pkt_len"]
        if f["dst_port"] is not None and f["protocol"] != "ARP":
            dst_ports[src][f["dst_port"]] += 1
        peers[src].add(dst)
        peers[dst].add(src)

        ts = f["timestamp"]
        if src not in first_seen:
            first_seen[src] = ts
            last_seen[src]  = ts
        else:
            if ts < first_seen[src]:
                first_seen[src] = ts
            if ts > last_seen[src]:
                last_seen[src] = ts
        protocols[src][label]   += 1
        protocols[dst][label]   += 1

        # Edge-level (merged)
        key = frozenset({src, dst})
        edge_protocols[key][label] += 1
        edge_counts[key]           += 1

    # ── Build nodes ──────────────────────────────────────────────────
    nodes_with_pos = [
        {
            "ip":             node,
            "x":              pos[node][0],
            "y":              pos[node][1],
            "activity_bytes": activity.get(node, 0),
            "protocols":      dict(protocols[node]) if node in protocols else {},
            "first_seen": first_seen.get(node, None),
            "last_seen":  last_seen.get(node, None),
            "outbound_bytes": outbound_bytes.get(node, 0),
            "inbound_bytes":  inbound_bytes.get(node, 0),
            "top_ports": [{"port": p, "count": c} for p, c in sorted(dst_ports[node].items(), key=lambda x: x[1], reverse=True)[:5]] if node in dst_ports else [],
            "unique_peers": len(peers[node]) if node in peers else 0
        }
        for node in topology["nodes"]
    ]

    # ── Build edges (deduplicated, with protocol breakdown) ──────────
    seen = set()
    edges_out = []
    for edge in topology["edges"]:
        key = frozenset({edge["src"], edge["dst"]})
        if key in seen:
            continue
        seen.add(key)
        edges_out.append({
            "src":       edge["src"],
            "dst":       edge["dst"],
            "count":     edge_counts[key],
            "protocols": dict(edge_protocols[key])
        })

    result = {
        "nodes": nodes_with_pos,
        "edges": edges_out
    }
    print(f"Layout positions added for {len(result['nodes'])} nodes, "
          f"{len(result['edges'])} edges")
    return result
