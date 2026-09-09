"""Risk scorer — composite risk score per attack state using AMC metrics.

ARCHITECTURE
------------
The composite risk score for a transient state combines six factors, each
in [0, 1], with weights α / β / γ / δ / ε / ζ that sum to 1.0:

    risk(state) = α·vuln + β·reach + γ·visit_freq + δ·crit + ε·next_step + ζ·privilege

Where:
    vuln       — vulnerability severity at the host (CVSS-driven, with
                 bonuses for available exploits and high-severity volume)
    reach      — probability of reaching a CROWN-JEWEL absorbing state from
                 here, blended with graph centrality
    visit_freq — expected number of times this state is visited before
                 absorption (normalized to [0,1] across the graph)
    crit       — CMDB-sourced criticality of the host
    next_step  — worst single-step lookahead: max(dst_criticality × edge_weight)
                 over outgoing edges. Captures "best move from here".
    privilege  — attacker's current privilege level on this state. Captures
                 "if attacker is here, how much capability do they have".
                 Crucial for distinguishing user-on-host from root-on-host.

For ABSORBING states (dead-ends, crown jewels, terminal compromise), risk
is just the asset's criticality — not a hardcoded 1.0.

Synthetic nodes (external, perimeter_waf, internal_firewall_acl) are SKIPPED.

The CROWN_JEWEL_THRESHOLD constant is imported from graph.state — single
source of truth for what counts as a crown jewel across the codebase.
"""
from __future__ import annotations

import logging
import os

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.graph.state import CROWN_JEWEL_THRESHOLD

logger = logging.getLogger(__name__)


# Threshold for "high-severity volume bonus" in vuln factor.
HIGH_SEV_VOLUME_THRESHOLD = 3

# Privilege-level → numeric capability mapping.
PRIVILEGE_SCORE = {
    "none": 0.0,
    "user": 0.30,
    "sudo": 0.55,
    "admin": 0.80,
    "root": 1.0,
}


class RiskScorer:
    """Compute composite risk score per state from AMC analysis."""

    def __init__(
        self,
        alpha: float | None = None,
        beta: float | None = None,
        gamma: float | None = None,
        delta: float | None = None,
        epsilon: float | None = None,
        zeta: float | None = None,
    ):
        """Initialize with explicit weights, or read from env vars as fallback."""
        self.alpha   = alpha   if alpha   is not None else float(os.environ.get("RISK_ALPHA",   0.22))
        self.beta    = beta    if beta    is not None else float(os.environ.get("RISK_BETA",    0.18))
        self.gamma   = gamma   if gamma   is not None else float(os.environ.get("RISK_GAMMA",   0.20))
        self.delta   = delta   if delta   is not None else float(os.environ.get("RISK_DELTA",   0.18))
        self.epsilon = epsilon if epsilon is not None else float(os.environ.get("RISK_EPSILON", 0.10))
        self.zeta    = zeta    if zeta    is not None else float(os.environ.get("RISK_ZETA",    0.12))

        total = self.alpha + self.beta + self.gamma + self.delta + self.epsilon + self.zeta
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"RiskScorer weights (α+β+γ+δ+ε+ζ) must sum to 1.0; got {total:.6f}. "
                f"Got α={self.alpha}, β={self.beta}, γ={self.gamma}, "
                f"δ={self.delta}, ε={self.epsilon}, ζ={self.zeta}"
            )

    def score(
        self,
        amc: AMCResults,
        G: nx.DiGraph,
        network: NormalizedNetwork,
    ) -> None:
        """Compute and write risk scores into amc.node_risk and G.nodes[*].risk_score."""

        crown_jewel_absorbing = self._identify_crown_jewel_absorbing(amc, G)
        if not crown_jewel_absorbing:
            logger.warning(
                "RiskScorer: no crown-jewel absorbing states found "
                f"(threshold={CROWN_JEWEL_THRESHOLD}); reach factor will be 0 for all nodes"
            )

        max_vf = 1.0
        if amc.visit_freq is not None and len(amc.visit_freq) > 0:
            max_vf = max(float(amc.visit_freq.max()), 1.0)

        for state_id in amc.transient_states:
            data = G.nodes.get(state_id, {})
            host_id = data.get("host_id", "")
            asset = network.assets.get(host_id)

            node_role = data.get("node_role", "host")
            if node_role != "host" or asset is None:
                amc.node_risk[state_id] = 0.0
                if state_id in G:
                    G.nodes[state_id]["risk_score"] = 0.0
                continue

            # Factor 1: vuln
            vuln = asset.max_cvss / 10.0
            if asset.has_exploit:
                vuln += 0.15
            high_count = asset.critical_vuln_count + asset.high_vuln_count
            if high_count >= HIGH_SEV_VOLUME_THRESHOLD:
                vuln += 0.10
            vuln = min(vuln, 1.0)

            # Factor 2: reach (probability of reaching a crown jewel)
            crown_reach = (
                amc.absorption_to_set(state_id, crown_jewel_absorbing)
                if crown_jewel_absorbing
                else 0.0
            )
            cent = float(data.get("centrality_composite", 0.0))
            reach = 0.6 * crown_reach + 0.4 * cent

            # Factor 3: visit frequency (normalized)
            vf = amc.visit_frequency(state_id) / max_vf

            # Factor 4: criticality (from CMDB)
            crit = asset.criticality

            # Factor 5: next-step lookahead
            next_step = 0.0
            for _, dst_id, edata in G.out_edges(state_id, data=True):
                dst_data = G.nodes.get(dst_id, {})
                dst_crit = float(dst_data.get("criticality", 0.0))
                edge_w = float(edata.get("weight", 0.0))
                next_step = max(next_step, dst_crit * edge_w)

            # Factor 6: privilege
            priv_str = str(data.get("privilege", "none")).lower()
            privilege = PRIVILEGE_SCORE.get(priv_str, 0.0)

            risk = (
                self.alpha   * vuln
                + self.beta  * reach
                + self.gamma * vf
                + self.delta * crit
                + self.epsilon * next_step
                + self.zeta  * privilege
            )
            risk = max(0.0, min(1.0, risk))

            amc.node_risk[state_id] = risk
            if state_id in G:
                G.nodes[state_id]["risk_score"] = risk

        # Absorbing states: risk = asset criticality
        for state_id in amc.absorbing_states:
            data = G.nodes.get(state_id, {})
            host_id = data.get("host_id", "")
            asset = network.assets.get(host_id)
            if asset:
                risk = asset.criticality
            else:
                risk = float(data.get("criticality", 0.0))
            amc.node_risk[state_id] = risk
            if state_id in G:
                G.nodes[state_id]["risk_score"] = risk

    @staticmethod
    def _identify_crown_jewel_absorbing(
        amc: AMCResults, G: nx.DiGraph
    ) -> list[str]:
        """Return absorbing state_ids whose host has criticality ≥ threshold."""
        result = []
        for state_id in amc.absorbing_states:
            data = G.nodes.get(state_id, {})
            crit = float(data.get("criticality", 0.0))
            if crit >= CROWN_JEWEL_THRESHOLD:
                result.append(state_id)
        return result