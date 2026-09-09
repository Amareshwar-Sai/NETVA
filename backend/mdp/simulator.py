"""Simulator — before/after comparison with full graph + AMC recompute."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.mdp.action_space import DefenderAction, ACTION_MAP
from backend.mdp.state_space import DefenderState
from backend.mdp.transitions import TransitionFunction
from backend.graph.attack_graph import graph_to_dict
from backend.graph.centrality import compute_centrality, get_critical_paths
from backend.amc import run_amc
from backend.amc.risk_scorer import RiskScorer


@dataclass
class SimulationResult:
    """Before/after comparison for a simulated action."""
    risk_before: float = 0.0
    risk_after: float = 0.0
    absorption_prob_before: float = 0.0
    absorption_prob_after: float = 0.0
    nodes_before: int = 0
    edges_before: int = 0
    nodes_after: int = 0
    edges_after: int = 0
    removed_edges: list[dict] = field(default_factory=list)
    risk_reduced_nodes: list[dict] = field(default_factory=list)
    graph_before: dict = field(default_factory=dict)
    graph_after: dict = field(default_factory=dict)
    paths_after: list[dict] = field(default_factory=list)
    state_metrics_after: list[dict] = field(default_factory=list)
    summary_after: dict = field(default_factory=dict)
    succeeded: bool = True
    action_id: str = ""
    target_asset_id: str = ""

    def to_dict(self) -> dict:
        return {
            "risk_before": round(self.risk_before, 4),
            "risk_after": round(self.risk_after, 4),
            "risk_delta": round(self.risk_before - self.risk_after, 4),
            "absorption_prob_before": round(self.absorption_prob_before, 4),
            "absorption_prob_after": round(self.absorption_prob_after, 4),
            "nodes_before": self.nodes_before,
            "edges_before": self.edges_before,
            "nodes_after": self.nodes_after,
            "edges_after": self.edges_after,
            "removed_edges": self.removed_edges,
            "risk_reduced_nodes": self.risk_reduced_nodes,
            "graph_after": self.graph_after,
            "paths_after": self.paths_after,
            "state_metrics_after": self.state_metrics_after,
            "summary_after": self.summary_after,
            "succeeded": self.succeeded,
            "action_id": self.action_id,
            "target_asset_id": self.target_asset_id,
        }


class Simulator:
    """Simulate the effect of a defender action on the live graph + AMC."""

    def __init__(self):
        self.transition_fn = TransitionFunction()
        self.last_graph_after = None  # live nx.DiGraph from last simulation
        self.last_amc_after = None    # AMCResults from last simulation

    def simulate_action(
        self,
        action_id: str,
        target_asset_id: str,
        state: DefenderState,
        amc: AMCResults,
        G: nx.DiGraph,
        network: NormalizedNetwork,
        rerun_amc: bool = True,  # changed default — always do real recompute
    ) -> SimulationResult:
        """Apply action to a graph copy, recompute AMC + paths + risk."""
        action = ACTION_MAP.get(action_id)
        if action is None:
            return SimulationResult(
                succeeded=False, action_id=action_id,
                target_asset_id=target_asset_id,
            )

        # Before metrics
        # risk_before = absorption probability from external on the live graph
        if amc and "external" in amc.transient_states:
            risk_before = float(amc.absorption_prob("external"))
        else:
          risk_before = state.overall_risk if state else 0.0
        absorb_before = state.max_absorption_prob if state else 0.0
        nodes_before = G.number_of_nodes()
        edges_before = G.number_of_edges()

        # Apply graph mutation
        graph_after = deepcopy(G)
        removed_edges = self._apply_action_to_graph(
            graph_after, action, target_asset_id, network,
        )

        # Recompute centrality on modified graph
        try:
            compute_centrality(graph_after)
        except Exception:
            pass

        # Recompute AMC on modified graph
        risk_after = risk_before
        absorb_after = absorb_before
        paths_after: list[dict] = []
        state_metrics_after: list[dict] = []
        summary_after: dict = {}

        try:
            new_amc = run_amc(graph_after, network)
            self.last_amc_after = new_amc

            # State metrics from new AMC
            for nid in new_amc.transient_states:
                state_metrics_after.append({
                    "state_id": nid,
                    "absorption_prob": new_amc.absorption_prob(nid),
                    "expected_steps": (
                        new_amc.expected_steps(nid)
                        if new_amc.expected_steps(nid) != float("inf")
                        else 0.0
                    ),
                    "visit_frequency": new_amc.visit_frequency(nid),
                    "risk_score": new_amc.node_risk.get(nid, 0.0),
                    "hostname": graph_after.nodes.get(nid, {}).get("hostname", ""),
                })

            # Aggregate risk after = absorption probability from external entry node
            # This is what truly changes when defenses cut attack paths.
            # Falls back to max-host-risk if external isn't a transient state (shouldn't happen).
            ext_id = "external"
            if ext_id in new_amc.transient_states:
              risk_after = float(new_amc.absorption_prob(ext_id))
            else:
              host_risks = [
                   graph_after.nodes[nid].get("risk_score", 0.0)
                   for nid in graph_after.nodes
                   if graph_after.nodes[nid].get("node_role") == "host"
                ]
              risk_after = max(host_risks) if host_risks else 0.0

            # Max absorption probability across transient states
            absorb_values = [
                new_amc.absorption_prob(nid)
                for nid in new_amc.transient_states
            ]
            absorb_after = max(absorb_values) if absorb_values else 0.0

            # Recompute critical paths
            paths_after = get_critical_paths(graph_after, top_n=5)

            # Build summary_after to mirror /risk/summary endpoint
            total_assets = len(network.assets) if network else 0
            total_vulns = sum(a.vuln_count for a in network.assets.values()) if network else 0
            critical_vulns = sum(a.critical_vuln_count for a in network.assets.values()) if network else 0
            high_vulns = sum(a.high_vuln_count for a in network.assets.values()) if network else 0
            crown_jewels = sum(
                1 for d in graph_after.nodes(data=True)
                if d[1].get("is_absorbing") and d[1].get("criticality", 0) >= 0.8
            )

            summary_after = {
                "total_assets": total_assets,
                "total_vulns": total_vulns,
                "critical_vulns": critical_vulns,
                "high_vulns": high_vulns,
                "max_risk_score": float(risk_after),
                "avg_risk_score": (
                    sum(host_risks) / len(host_risks) if host_risks else 0.0
                ),
                "max_absorption_prob": float(absorb_after),
                "crown_jewels": crown_jewels,
                "attack_paths": len(paths_after),
            }

        except Exception as e:
            # If AMC recompute fails, fall back to lightweight estimate
            try:
                next_state, _ = self.transition_fn.apply(state, action, target_asset_id)
                risk_after = next_state.overall_risk
                absorb_after = next_state.max_absorption_prob
            except Exception:
                pass
        
        self.last_graph_after = graph_after
        return SimulationResult(
            risk_before=risk_before,
            risk_after=risk_after,
            absorption_prob_before=absorb_before,
            absorption_prob_after=absorb_after,
            nodes_before=nodes_before,
            edges_before=edges_before,
            nodes_after=graph_after.number_of_nodes(),
            edges_after=graph_after.number_of_edges(),
            removed_edges=removed_edges,
            risk_reduced_nodes=[],
            graph_before=graph_to_dict(G),
            graph_after=graph_to_dict(graph_after),
            paths_after=paths_after,
            state_metrics_after=state_metrics_after,
            summary_after=summary_after,
            succeeded=True,
            action_id=action_id,
            target_asset_id=target_asset_id,
        )

    # ── Action → graph mutation ──────────────────────────────────────────

    def _apply_action_to_graph(
        self,
        G: nx.DiGraph,
        action: DefenderAction,
        target_id: str,
        network: NormalizedNetwork,
    ) -> list[dict]:
        """Modify graph based on action. Returns list of removed/modified edges."""
        removed = []
        atype = action.action_type
        aid = action.action_id

        # ─── ISOLATE: remove all edges touching the target host ────────
        if atype == "isolate":
            edges_to_remove = []
            for u, v in list(G.edges()):
                u_host = G.nodes.get(u, {}).get("host_id", "")
                v_host = G.nodes.get(v, {}).get("host_id", "")
                if target_id in (u_host, v_host) or u.startswith(target_id) or v.startswith(target_id):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": f"isolate:{target_id}"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        # ─── REVOKE SSH KEYS / CREDS: kill IAM lateral edges from target ───
        elif atype == "revoke" or aid == "revoke_ssh_keys":
            edges_to_remove = []
            for u, v, data in list(G.edges(data=True)):
                u_host = G.nodes.get(u, {}).get("host_id", "")
                v_host = G.nodes.get(v, {}).get("host_id", "")
                if (data.get("edge_type") == "lateral_movement"
                        and (target_id in (u_host, v_host) or u.startswith(target_id) or v.startswith(target_id))):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "revoke_ssh_keys"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        # ─── SEGMENT: remove cross-zone edges ──────────────────────────
        elif atype == "segment":
            edges_to_remove = []
            for u, v, data in list(G.edges(data=True)):
                src_zone = G.nodes.get(u, {}).get("zone", "")
                dst_zone = G.nodes.get(v, {}).get("zone", "")
                if aid == "segment_dmz_internal" and src_zone == "dmz" and dst_zone == "internal":
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "segment_dmz_internal"})
                elif aid == "segment_internal_prod" and src_zone == "internal" and dst_zone == "prod":
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "segment_internal_prod"})
                elif aid not in ("segment_dmz_internal", "segment_internal_prod"):
                    # Generic segment — remove all cross-zone host edges
                    if (src_zone in ("dmz", "internal", "prod")
                            and dst_zone in ("dmz", "internal", "prod")
                            and src_zone != dst_zone):
                        edges_to_remove.append((u, v))
                        removed.append({"from": u, "to": v, "reason": f"segment:{src_zone}->{dst_zone}"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        # ─── BLOCK PORT: remove edges that require the blocked port ────
        elif atype == "block_port" and action.applies_to_port:
            edges_to_remove = []
            for u, v, data in list(G.edges(data=True)):
                v_host = G.nodes.get(v, {}).get("host_id", "")
                if (target_id == v_host
                        and data.get("requires_port") == action.applies_to_port):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": f"block_port:{action.applies_to_port}"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        # ─── PATCH: remove the highest-CVSS exploit edge into target ───
        elif atype == "patch":
            self._weaken_or_remove_edges_to_target(
                G, target_id, removed,
                edge_types_to_target=("network_exploit", "perimeter_bypass",
                                      "network_exploit_via_fw", "privilege_escalation"),
                reduce_factor=0.0,  # 0 = remove edge entirely (fully patched)
                reason="patch_os",
            )

        # ─── HARDEN (e.g. disable_ssh_root_login, disable_phpinfo) ─────
        elif atype == "harden":
            # Remove privilege-escalation edges on the target (USER → ROOT/ADMIN)
            edges_to_remove = []
            for u, v, data in list(G.edges(data=True)):
                u_host = G.nodes.get(u, {}).get("host_id", "")
                v_host = G.nodes.get(v, {}).get("host_id", "")
                if (data.get("edge_type") == "privilege_escalation"
                        and target_id in (u_host, v_host)):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": f"harden:{aid}"})
                # Also remove perimeter_bypass that exploits a public-facing
                # CVE related to this hardening action
                if (data.get("edge_type") == "perimeter_bypass"
                        and v_host == target_id and aid == "disable_phpinfo"):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "disable_phpinfo"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        # ─── MONITOR: doesn't remove edges, but reduces their weight ───
        elif atype == "monitor":
            modified = 0
            for u, v, data in G.edges(data=True):
                v_host = G.nodes.get(v, {}).get("host_id", "")
                u_host = G.nodes.get(u, {}).get("host_id", "")
                if target_id in (u_host, v_host):
                    old_w = data.get("weight", 0.5)
                    new_w = max(old_w * 0.7, 0.1)  # 30% reduction (detection deters)
                    G.edges[u, v]["weight"] = new_w
                    modified += 1
            if modified > 0:
                removed.append({
                    "from": target_id, "to": "(all neighbors)",
                    "reason": f"monitor: {modified} edges weakened by 30%",
                })

        # ─── ISOLATE_FROM_INTERNET: cut external entry edges to target ─
        elif aid == "isolate_from_internet":
            edges_to_remove = []
            for u, v, data in list(G.edges(data=True)):
                v_host = G.nodes.get(v, {}).get("host_id", "")
                if (target_id == v_host
                        and data.get("edge_type") in ("external_entry", "perimeter_bypass")):
                    edges_to_remove.append((u, v))
                    removed.append({"from": u, "to": v, "reason": "isolate_from_internet"})
            for u, v in edges_to_remove:
                if G.has_edge(u, v):
                    G.remove_edge(u, v)

        return removed

    def _weaken_or_remove_edges_to_target(
        self,
        G: nx.DiGraph,
        target_id: str,
        removed: list[dict],
        edge_types_to_target: tuple,
        reduce_factor: float,
        reason: str,
    ) -> None:
        """Helper: remove (factor=0) or weaken (factor>0) matching edges."""
        edges_to_remove = []
        for u, v, data in list(G.edges(data=True)):
            v_host = G.nodes.get(v, {}).get("host_id", "")
            u_host = G.nodes.get(u, {}).get("host_id", "")
            if data.get("edge_type") not in edge_types_to_target:
                continue
            # Edge must touch the target host (incoming or local privesc)
            if target_id not in (u_host, v_host):
                continue
            if reduce_factor <= 0.0:
                edges_to_remove.append((u, v))
                removed.append({"from": u, "to": v, "reason": reason})
            else:
                old_w = data.get("weight", 0.5)
                G.edges[u, v]["weight"] = max(old_w * reduce_factor, 0.05)
                removed.append({
                    "from": u, "to": v,
                    "reason": f"{reason}:weight {old_w:.2f}→{old_w * reduce_factor:.2f}",
                })
        for u, v in edges_to_remove:
            if G.has_edge(u, v):
                G.remove_edge(u, v)