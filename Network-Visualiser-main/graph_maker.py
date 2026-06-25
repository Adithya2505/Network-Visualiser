import networkx as nx
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

    pos = nx.kamada_kawai_layout(G, scale=2.5)

    # ── Per-node activity and protocol counts (outbound + inbound) ──
    activity  = defaultdict(int)
    protocols = defaultdict(lambda: defaultdict(int))
    first_seen = {}
    last_seen  = {}

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
        activity[src]           += f["pkt_len"]
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
            "last_seen":  last_seen.get(node, None)
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