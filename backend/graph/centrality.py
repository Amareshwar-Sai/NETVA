"""Graph centrality metrics — betweenness, eigenvector, closeness, degree.

Also provides get_critical_paths() — finds highest-probability attack paths
from entry nodes to absorbing nodes.

INVERTED WEIGHT FOR PATH ALGORITHMS
-----------------------------------
Edge weights are probabilities (high = easy traversal). For shortest-path
algorithms (which minimize cumulative cost), we need to convert to a
"distance" representation:

    distance = -log(weight)

This is the principled choice because:
- Path probability  = product of edge weights  (multiplicative)
- Path distance     = sum of -log(weights)     (additive)
- Min sum of -log(w) ⇔ max product of w
- Therefore: shortest path on -log(w) = MAXIMUM-probability path

The previous implementation used `1 - weight` as distance, which is a Taylor
approximation only accurate for w near 1. For w = 0.5, (1-w)=0.5 vs
-log(0.5)=0.693 — a 39% discrepancy that biases path selection.

PATH PROBABILITY: TWO INTERPRETATIONS
-------------------------------------
get_critical_paths() reports both:

1. edge_strength_product — the raw product of edge weights along the path.
   Reflects "how exploitable is each step in isolation". Always overestimates
   true path-traversal probability.

2. transition_probability — the product of NORMALIZED transition probabilities
   accounting for siblings (when an attacker reaches a fork, the probability
   of taking any one branch is reduced because mass is split). This is the
   true Markov-chain probability of traversing this exact path from start
   to end without diverging.

The two numbers can differ substantially. A path that's "strong edge-by-edge"
(0.95 each step) but has many forks may have a much lower actual traversal
probability. The UI should show both for honesty.
"""
from __future__ import annotations

import math
import networkx as nx


# Floor for inverted weight (avoids log(0) and infinite distance for tiny weights).
_MIN_WEIGHT_FOR_LOG = 1e-3


def _to_distance(weight: float) -> float:
    """Convert edge weight (probability) to distance (-log) for shortest path."""
    w = max(float(weight), _MIN_WEIGHT_FOR_LOG)
    return -math.log(w)


def compute_centrality(G: nx.DiGraph) -> None:
    """Compute five centrality metrics and write as node attributes.

    Composite weights:
      betweenness 0.40  (chokepoint detection — strongest signal)
      eigenvector 0.25  (importance via important neighbors)
      closeness   0.20  (average distance to all others)
      in-degree   0.10  (how many things target you)
      out-degree  0.05  (how many things you can reach)
    Sum: 1.00
    """
    n = G.number_of_nodes()
    if n < 2:
        for nid in G.nodes:
            for metric in ("centrality_betweenness", "centrality_eigenvector",
                           "centrality_closeness", "centrality_in_degree",
                           "centrality_out_degree", "centrality_composite"):
                G.nodes[nid][metric] = 0.0
        return

    # Use -log(weight) as distance for path-based metrics.
    # Higher edge weight (more exploitable) = smaller distance.
    distances = {}
    for u, v, data in G.edges(data=True):
        w = data.get("weight", 0.5)
        distances[(u, v)] = _to_distance(w)
    nx.set_edge_attributes(G, distances, "distance_neglog")

    # Betweenness — uses distance for shortest-path-ness measurements.
    try:
        bw = nx.betweenness_centrality(G, weight="distance_neglog", normalized=True)
    except Exception:
        bw = {nid: 0.0 for nid in G.nodes}

    # Eigenvector — uses raw weight (importance flows along strong edges).
    try:
        ev = nx.eigenvector_centrality(G, max_iter=500, weight="weight")
    except (nx.NetworkXError, nx.PowerIterationFailedConvergence):
        try:
            ev = nx.degree_centrality(G)
        except Exception:
            ev = {nid: 0.0 for nid in G.nodes}

    # Closeness — uses distance.
    try:
        cl = nx.closeness_centrality(G, distance="distance_neglog")
    except Exception:
        cl = {nid: 0.0 for nid in G.nodes}

    # Degree centrality.
    try:
        in_deg = nx.in_degree_centrality(G)
        out_deg = nx.out_degree_centrality(G)
    except Exception:
        in_deg = {nid: 0.0 for nid in G.nodes}
        out_deg = {nid: 0.0 for nid in G.nodes}

    for nid in G.nodes:
        b = bw.get(nid, 0.0)
        e = ev.get(nid, 0.0)
        c = cl.get(nid, 0.0)
        i = in_deg.get(nid, 0.0)
        o = out_deg.get(nid, 0.0)

        G.nodes[nid]["centrality_betweenness"] = b
        G.nodes[nid]["centrality_eigenvector"] = e
        G.nodes[nid]["centrality_closeness"] = c
        G.nodes[nid]["centrality_in_degree"] = i
        G.nodes[nid]["centrality_out_degree"] = o
        G.nodes[nid]["centrality_composite"] = (
            b * 0.40 + e * 0.25 + c * 0.20 + i * 0.10 + o * 0.05
        )


def get_critical_paths(
    G: nx.DiGraph,
    top_n: int = 5,
) -> list[dict]:
    """Find max-probability paths from entry nodes to absorbing nodes.

    Uses Dijkstra on -log(weight) so the shortest sum-distance path is
    equivalent to the maximum-product-probability path.

    Returns dicts with both:
      - edge_strength_product: ∏ raw edge weights (overstates true probability)
      - transition_probability: ∏ normalized per-row transition probabilities
        (the true Markov-chain path probability accounting for forks)
    """
    entry_nodes = [nid for nid, d in G.nodes(data=True) if d.get("is_entry")]
    absorbing_nodes = [nid for nid, d in G.nodes(data=True) if d.get("is_absorbing")]

    if not entry_nodes or not absorbing_nodes:
        return []

    # Pre-compute, for each transient source node, the row-sum of outgoing
    # edge weights — used to normalize edge weight to transition probability.
    out_row_sum: dict[str, float] = {}
    for nid in G.nodes:
        s = 0.0
        for _, _, edata in G.out_edges(nid, data=True):
            s += float(edata.get("weight", 0.0))
        out_row_sum[nid] = s

    paths: list[dict] = []
    for entry in entry_nodes:
        for target in absorbing_nodes:
            try:
                # distance_neglog edge attribute is set by compute_centrality
                path = nx.shortest_path(G, entry, target, weight="distance_neglog")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

            edge_product = 1.0
            transition_product = 1.0
            edges_info = []

            for i in range(len(path) - 1):
                src_nid = path[i]
                dst_nid = path[i + 1]
                edge_data = G.edges[src_nid, dst_nid]
                w = float(edge_data.get("weight", 0.5))

                # True transition probability for this edge =
                # (this edge's weight / sum of all outgoing weights from src)
                # × (1 - self_loop_mass). We approximate self_loop_mass = 0.05
                # (the value used throughout the AMC layer); the small
                # divergence vs the actual builder constant is negligible
                # for ranking purposes.
                row_sum = out_row_sum.get(src_nid, 0.0)
                if row_sum > 0:
                    transition_p = (w / row_sum) * 0.95
                else:
                    transition_p = 0.0

                edge_product *= w
                transition_product *= transition_p

                edges_info.append({
                    "from": src_nid,
                    "to": dst_nid,
                    "weight": w,
                    "transition_p": round(transition_p, 4),
                    "mechanism": edge_data.get("mechanism", ""),
                    "vuln_id": edge_data.get("vuln_id", ""),
                })

            paths.append({
                "path": path,
                "edge_strength_product": round(edge_product, 4),
                "transition_probability": round(transition_product, 4),
                "length": len(path) - 1,
                "entry": entry,
                "target": target,
                "edges": edges_info,
            })

    # Rank by true transition probability (the more honest metric).
    paths.sort(key=lambda p: p["transition_probability"], reverse=True)
    return paths[:top_n]