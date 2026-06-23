import networkx as nx

def add_layout_positions(topology):
    """
    Takes topology dict with nodes/edges.
    Returns topology dict with x, y coords added to each node.
    """
    G = nx.Graph()  # Undirected, not DiGraph
    
    # Add nodes
    for node in topology["nodes"]:
        G.add_node(node)
    
    # Add edges (treat bidirectional)
    for edge in topology["edges"]:
        G.add_edge(edge["src"], edge["dst"])
    
    # Compute spring layout
    pos = nx.spring_layout(G, k=0.5, iterations=50, seed=42)
    
    # Add x, y to each node
    nodes_with_pos = [
        {
            "ip": node,
            "x": pos[node][0],
            "y": pos[node][1]
        }
        for node in topology["nodes"]
    ]
    
    # Return modified topology
    result = {
        "nodes": nodes_with_pos,
        "edges": topology["edges"]
    }
    print(f"Layout positions added for {len(result['nodes'])} nodes")
    return result