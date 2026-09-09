"""Build NetworkX DiGraph from MulVALResult + NormalizedNetwork.

Architecture:
  - external entry node (renamed from "internet")
  - perimeter_waf synthetic defense node — represents WAF/perimeter firewall
  - internal_firewall_acl synthetic defense node — represents ACL traversal
  - host states: (host, user|root|admin)

Edge builders:
1. External → perimeter_waf (always exists, weight=1.0 — WAF is the only path in)
2. perimeter_waf → DMZ host[user] (only if public-facing service has CVE)
3. Privilege escalation edges (USER → ROOT/ADMIN on same host)
4. Lateral movement edges via IAM trust (SSH keys, credential reuse)
5. Lateral edges via ACL-permitted network traversal
   - Cross-zone edges route THROUGH internal_firewall_acl
   - Intra-zone edges go direct

Post-construction:
- Promote dead-end nodes to absorbing
- Compute termination reasons for absorbing nodes
"""
from __future__ import annotations

import networkx as nx

from backend.normalization.schema import (
    NormalizedNetwork, NetworkAsset, PrivilegeLevel, Zone,
)
from backend.graph.state import (
    AttackState, is_absorbing, enumerate_states, termination_reason,
)
from backend.graph.mulval_runner import MulVALResult


# ── Constants ───────────────────────────────────────────────────────────────

# Public-facing ports that an external attacker could conventionally reach
PUBLIC_FACING_PORTS = {80, 443, 8080, 8443, 3000, 8000}

# Synthetic node IDs (these aren't real hosts — they represent defense layers)
EXTERNAL_NODE = "external"
PERIMETER_WAF_NODE = "perimeter_waf"
INTERNAL_FW_NODE = "internal_firewall_acl"

# Backwards-compat alias used by build_attack_graph()
ENTRY_NODE_ID = EXTERNAL_NODE


def build_nx_graph(
    mulval_result: MulVALResult,
    network: NormalizedNetwork,
    attacker_location: str = ENTRY_NODE_ID,
) -> nx.DiGraph:
    """Build the full attack graph as a NetworkX DiGraph."""
    G = nx.DiGraph()

    # ── 1. Create per-host attack states ────────────────────────────────────
    for ip, asset in network.assets.items():
        for state in enumerate_states(asset):
            absorbing = is_absorbing(state, asset)
            G.add_node(state.state_id, **_make_host_node_data(state, asset, absorbing))

    # ── 2. Add the synthetic defense-layer nodes ────────────────────────────
    _add_synthetic_node(G, EXTERNAL_NODE, "External Entry Point",
                        node_role="entry",
                        description="Public internet — represents any attacker source reaching public IPs")
    _add_synthetic_node(G, PERIMETER_WAF_NODE, "Perimeter WAF / Firewall",
                        node_role="defense",
                        description="WAF and perimeter filtering — first defensive layer")
    _add_synthetic_node(G, INTERNAL_FW_NODE, "Internal Firewall (ACL)",
                        node_role="defense",
                        description="DMZ-to-Internal segmentation enforced by iptables ACLs")

    # ── 3. Build edges ──────────────────────────────────────────────────────
    _add_perimeter_edges(G, network, attacker_location)
    _add_privilege_escalation_edges(G, network)
    _add_iam_lateral_edges(G, network)
    _add_network_lateral_edges(G, network)

    # ── 4. Mark entry-reachable host nodes ──────────────────────────────────
    for node_id in list(G.nodes):
        if G.nodes[node_id].get("node_role") in ("entry", "defense"):
            continue
        # A host is an entry foothold if perimeter_waf has an edge to it
        if G.has_edge(PERIMETER_WAF_NODE, node_id):
            G.nodes[node_id]["is_entry"] = True

    # ── 5. Post-process: promote dead-ends to absorbing ─────────────────────
    _promote_dead_ends_to_absorbing(G)

    # ── 6. Post-process: annotate absorbing nodes with termination reason ──
    _compute_termination_reasons(G)

    return G


# ── Node-data factories ─────────────────────────────────────────────────────

def _make_host_node_data(state: AttackState, asset: NetworkAsset, absorbing: bool) -> dict:
    """Build the dict of attributes for a host attack state node."""
    return {
        "state_id": state.state_id,
        "host_id": state.host_id,
        "privilege": state.privilege.value,
        "is_absorbing": absorbing,
        "is_entry": False,
        "node_role": "host",
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "risk_score": 0.0,
        "zone": asset.zone.value,
        "label": state.short_label,
        "ip": asset.ip,
        "hostname": asset.hostname,
        "open_ports": asset.open_ports,
        "vuln_count": asset.vuln_count,
        "max_cvss": asset.max_cvss,
        "has_exploit": asset.has_exploit,
        "termination_reason": "",
    }


def _add_synthetic_node(G: nx.DiGraph, node_id: str, label: str,
                        node_role: str, description: str) -> None:
    """Add a synthetic (non-host) node like external, perimeter_waf, etc."""
    G.add_node(node_id, **{
        "state_id": node_id,
        "host_id": node_id,
        "privilege": "none",
        "is_absorbing": False,
        "is_entry": (node_role == "entry"),
        "node_role": node_role,
        "asset_type": "external" if node_role == "entry" else "defense",
        "criticality": 0.0,
        "risk_score": 0.0,
        "zone": "external" if node_role == "entry" else "perimeter",
        "label": label,
        "ip": "",
        "hostname": node_id,
        "open_ports": [],
        "vuln_count": 0,
        "max_cvss": 0.0,
        "has_exploit": False,
        "termination_reason": "",
        "description": description,
    })


# ── Edge builders ───────────────────────────────────────────────────────────

def _add_perimeter_edges(G: nx.DiGraph, network: NormalizedNetwork,
                         attacker_location: str) -> None:
    """Build edges: external → perimeter_waf → DMZ public-facing host[user]."""
    # external -> perimeter_waf
    G.add_edge(attacker_location, PERIMETER_WAF_NODE, **{
        "weight": 1.0,
        "vuln_id": "",
        "cvss": 0.0,
        "mechanism": "public_internet_access",
        "requires_port": 0,
        "exploit_available": False,
        "edge_type": "perimeter_traversal",
    })

    # perimeter_waf -> DMZ host[user] for each DMZ asset with a public-facing CVE
    for ip, asset in network.assets.items():
        if asset.zone != Zone.DMZ:
            continue
        if asset.asset_type == "firewall":
            continue

        target_state = f"{ip}::user"
        if target_state not in G:
            continue

        public_vulns = [
            v for v in asset.vulns
            if v.port in PUBLIC_FACING_PORTS and v.cvss >= 4.0
        ]
        if not public_vulns:
            continue

        best = max(public_vulns, key=lambda v: v.cvss)

        waf_bypass_factor = 0.7
        weight = (best.cvss / 10.0) * waf_bypass_factor
        if best.exploit_available:
            weight += 0.10
        weight = min(weight, 0.92)

        G.add_edge(PERIMETER_WAF_NODE, target_state, **{
            "weight": weight,
            "vuln_id": best.vuln_id,
            "cvss": best.cvss,
            "mechanism": f"waf_bypass:{best.name}",
            "requires_port": best.port,
            "exploit_available": best.exploit_available,
            "edge_type": "perimeter_bypass",
        })


def _add_privilege_escalation_edges(G: nx.DiGraph, network: NormalizedNetwork) -> None:
    """USER → ROOT/ADMIN on same host via local vuln or weak credentials."""
    for ip, asset in network.assets.items():
        user_state = f"{ip}::user"
        root_state = f"{ip}::root"
        admin_state = f"{ip}::admin"

        if user_state in G and root_state in G:
            local_vulns = [
                v for v in asset.vulns
                if (v.port == 0
                    or "local" in v.name.lower()
                    or "suid" in v.name.lower()
                    or "world-writable" in v.name.lower()
                    or "sudo" in v.name.lower()
                    or "kernel" in v.name.lower())
                and v.cvss > 0
            ]
            if local_vulns:
                best = max(local_vulns, key=lambda v: v.cvss)
                weight = best.cvss / 10.0
                if best.exploit_available:
                    weight += 0.10
                weight = min(weight, 0.95)
                G.add_edge(user_state, root_state, **{
                    "weight": weight,
                    "vuln_id": best.vuln_id,
                    "cvss": best.cvss,
                    "mechanism": f"privesc:{best.name}",
                    "requires_port": 0,
                    "exploit_available": best.exploit_available,
                    "edge_type": "privilege_escalation",
                })
            elif asset.has_suid_binary or asset.has_world_writable_files:
                G.add_edge(user_state, root_state, **{
                    "weight": 0.65,
                    "vuln_id": "MISCONFIG-LOCAL-PRIVESC",
                    "cvss": 7.0,
                    "mechanism": "privesc:local_misconfiguration",
                    "requires_port": 0,
                    "exploit_available": True,
                    "edge_type": "privilege_escalation",
                })

        if user_state in G and admin_state in G:
            db_vulns = [
                v for v in asset.vulns
                if "default" in v.name.lower()
                or "mysql" in v.name.lower()
                or "weak" in v.name.lower()
                or "credential" in v.name.lower()
            ]
            if db_vulns:
                best = max(db_vulns, key=lambda v: v.cvss)
                G.add_edge(user_state, admin_state, **{
                    "weight": min(best.cvss / 10.0, 0.95),
                    "vuln_id": best.vuln_id,
                    "cvss": best.cvss,
                    "mechanism": f"db_admin_access:{best.name}",
                    "requires_port": best.port,
                    "exploit_available": best.exploit_available,
                    "edge_type": "privilege_escalation",
                })
            elif asset.has_default_credentials:
                G.add_edge(user_state, admin_state, **{
                    "weight": 0.85,
                    "vuln_id": "MISCONFIG-DEFAULT-CREDS",
                    "cvss": 9.0,
                    "mechanism": "db_admin_access:default_credentials",
                    "requires_port": 0,
                    "exploit_available": True,
                    "edge_type": "privilege_escalation",
                })


def _add_iam_lateral_edges(G: nx.DiGraph, network: NormalizedNetwork) -> None:
    """Lateral movement via SSH key reuse, credential reuse, IAM trust."""
    for edge in network.edges:
        if edge.edge_type != "iam":
            continue
        if not edge.src_id or not edge.dst_id:
            continue

        dst_priv_value = edge.privilege_level.value
        dst_state_id = f"{edge.dst_id}::{dst_priv_value}"

        if dst_state_id not in G:
            dst_asset = network.assets.get(edge.dst_id)
            if dst_asset is None:
                continue
            absorbing = is_absorbing(
                AttackState(edge.dst_id, edge.privilege_level), dst_asset
            )
            G.add_node(dst_state_id, **_make_host_node_data(
                AttackState(edge.dst_id, edge.privilege_level),
                dst_asset, absorbing,
            ))

        if edge.link_type == "ssh_key":
            weight = 0.85
        elif edge.link_type in ("password", "cred_reuse"):
            weight = 0.65
        else:
            weight = 0.50

        for src_priv in ("user", "root"):
            src_state_id = f"{edge.src_id}::{src_priv}"
            if src_state_id not in G:
                continue
            if G.has_edge(src_state_id, dst_state_id):
                continue
            edge_weight = weight if src_priv == "user" else min(weight + 0.05, 0.95)

            G.add_edge(src_state_id, dst_state_id, **{
                "weight": edge_weight,
                "vuln_id": "",
                "cvss": 0.0,
                "mechanism": f"lateral_iam:{edge.link_type}",
                "requires_port": 22,
                "exploit_available": False,
                "edge_type": "lateral_movement",
                "permitted_by": edge.permitted_by,
            })


def _add_network_lateral_edges(G: nx.DiGraph, network: NormalizedNetwork) -> None:
    """ACL-permitted network lateral movement, routed through internal_firewall_acl for cross-zone."""
    for edge in network.edges:
        if edge.edge_type != "network":
            continue

        is_acl_permitted = edge.permitted_by and "ACL" in edge.permitted_by
        is_same_subnet = edge.permitted_by == "same-subnet"
        if not (is_acl_permitted or is_same_subnet):
            continue

        src_asset = network.assets.get(edge.src_id)
        dst_asset = network.assets.get(edge.dst_id)
        if not src_asset or not dst_asset:
            continue
        if dst_asset.max_cvss < 4.0:
            continue

        src_state = f"{edge.src_id}::user"
        dst_state = f"{edge.dst_id}::user"
        if src_state not in G or dst_state not in G:
            continue

        candidate_vulns = [v for v in dst_asset.vulns if v.cvss >= 4.0]
        if edge.ports:
            candidate_vulns = [v for v in candidate_vulns if v.port in edge.ports]
        if not candidate_vulns:
            continue

        best_vuln = max(candidate_vulns, key=lambda v: v.cvss)
        weight = best_vuln.cvss / 10.0
        if best_vuln.exploit_available:
            weight += 0.08
        weight = min(weight, 0.92)

        cross_zone = (src_asset.zone != dst_asset.zone)

        if cross_zone:
            for src_priv in ("user", "root"):
                src_state_full = f"{edge.src_id}::{src_priv}"
                if src_state_full not in G:
                    continue
                if not G.has_edge(src_state_full, INTERNAL_FW_NODE):
                    G.add_edge(src_state_full, INTERNAL_FW_NODE, **{
                        "weight": 0.95,
                        "vuln_id": "",
                        "cvss": 0.0,
                        "mechanism": "fw_traversal_attempt",
                        "requires_port": 0,
                        "exploit_available": False,
                        "edge_type": "fw_approach",
                    })

            if not G.has_edge(INTERNAL_FW_NODE, dst_state):
                G.add_edge(INTERNAL_FW_NODE, dst_state, **{
                    "weight": weight * 0.9,
                    "vuln_id": best_vuln.vuln_id,
                    "cvss": best_vuln.cvss,
                    "mechanism": f"fw_permitted_exploit:{best_vuln.name}",
                    "requires_port": best_vuln.port,
                    "exploit_available": best_vuln.exploit_available,
                    "edge_type": "network_exploit_via_fw",
                    "permitted_by": edge.permitted_by,
                })
        else:
            for src_priv in ("user", "root"):
                src_state_full = f"{edge.src_id}::{src_priv}"
                if src_state_full not in G:
                    continue
                if G.has_edge(src_state_full, dst_state):
                    continue
                G.add_edge(src_state_full, dst_state, **{
                    "weight": weight,
                    "vuln_id": best_vuln.vuln_id,
                    "cvss": best_vuln.cvss,
                    "mechanism": f"intrazone_exploit:{best_vuln.name}",
                    "requires_port": best_vuln.port,
                    "exploit_available": best_vuln.exploit_available,
                    "edge_type": "network_exploit",
                    "permitted_by": edge.permitted_by,
                })


# ── Post-processing ─────────────────────────────────────────────────────────

def _promote_dead_ends_to_absorbing(G: nx.DiGraph) -> None:
    """Mark nodes with no useful outgoing edges as absorbing."""
    for _ in range(2):
        for node_id, data in G.nodes(data=True):
            if data.get("node_role") in ("entry", "defense"):
                continue
            if data.get("is_absorbing"):
                continue

            useful_successors = [
                t for _, t in G.out_edges(node_id)
                if t != node_id and not G.nodes[t].get("is_absorbing")
            ]

            if not useful_successors:
                G.nodes[node_id]["is_absorbing"] = True


def _compute_termination_reasons(G: nx.DiGraph) -> None:
    """Annotate every absorbing node with a human-readable termination reason."""
    for node_id, data in G.nodes(data=True):
        if not data.get("is_absorbing"):
            continue
        if data.get("node_role") in ("entry", "defense"):
            continue
        outgoing = G.out_degree(node_id)
        G.nodes[node_id]["termination_reason"] = termination_reason(data, outgoing)


# ── Serialization ───────────────────────────────────────────────────────────

def graph_to_dict(G: nx.DiGraph) -> dict:
    """Serialise graph to {nodes: [...], edges: [...]} for the API."""
    nodes = []
    for nid, data in G.nodes(data=True):
        nodes.append({**data})

    edges = []
    for src, dst, data in G.edges(data=True):
        edges.append({"source": src, "target": dst, **data})

    return {"nodes": nodes, "edges": edges}