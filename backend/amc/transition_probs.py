"""Transition probability computation for AMC edges.

ARCHITECTURE
------------
Each edge in the attack graph carries a probability that the attacker, having
reached the source state, will choose to (and successfully) traverse to the
destination state. This probability is computed as a weighted sum of six
factor scores, each in [0, 1]:

    score = w_v · vuln + w_r · reach + w_p · priv + w_m · misconfig + w_t · telemetry

The five "transition feasibility" weights (w_v + w_r + w_p + w_m + w_t) sum
to 1.0, producing a base score in [0, 1].

Optionally, a "centrality blend" mixes in the destination's strategic value:

    final = (1 - α) · score + α · centrality

where α defaults to 0.0 (pure transition feasibility, mathematically clean
absorbing-Markov-chain semantics). Setting α > 0 produces a "value-weighted"
Markov chain where attackers prefer high-value targets — defensible heuristic,
but no longer a strict probabilistic transition model. Use α=0 for the
purest math, α≈0.15 for the heuristic mode.

ROW NORMALIZATION
-----------------
For each transient state, raw factor scores are computed for every outgoing
edge, then normalized to sum to (1 − self_loop_mass). The remaining mass is
returned to the caller (builder.py) as a self-loop, ensuring each row of the
final transition matrix sums to exactly 1.0 (proper stochastic matrix).

CALIBRATION NOTE
----------------
The constants in this file (factor weights, zone scores, misconfig values)
are illustrative defaults reflecting security-domain intuition. In production
they should be calibrated against historical incident data — for example,
fitting weights so that high-scoring paths agree with known attacker TTPs
from MITRE ATT&CK or Verizon DBIR. The TransitionWeights dataclass is
designed to make this calibration painless: tune the values, swap the
defaults, no code change needed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx

from backend.normalization.schema import NormalizedNetwork, NetworkAsset, Zone


# ── Tuning constants (defensive defaults for the lab) ──────────────────────

# Self-loop mass: probability that attacker stalls at this state for one
# timestep (failed exploit, hesitation, network glitch, etc.). 0.05 means 5%
# of probability mass stays put per turn. This is what makes (I-Q) invertible
# and gives finite expected absorption time.
DEFAULT_SELF_LOOP_MASS = 0.05

# Centrality blend factor α. 0.0 = pure transition feasibility (clean Markov
# semantics). 0.15 = original behavior (slight bias toward strategic targets).
# Set via TransitionWeights.alpha_centrality.
DEFAULT_CENTRALITY_BLEND = 0.0

# Numerical guardrails for edge probabilities.
MIN_EDGE_PROB = 0.01   # never zero (avoids degenerate rows)
MAX_EDGE_PROB = 0.99   # never one  (avoids deterministic absorption)


# ── Configurable weight bundle ─────────────────────────────────────────────

@dataclass
class TransitionWeights:
    """Configurable weights for the transition-probability factors.

    The five 'feasibility' weights below MUST sum to 1.0. They reflect the
    relative contribution of each factor to attack success probability:

      w_vuln (0.35)         — Strongest signal. The CVE being exploited and
                              its severity directly drive success.
      w_reachability (0.25) — Network-topology realism. Cross-zone moves are
                              less likely than intra-zone, etc.
      w_privilege (0.20)    — Attacker's current privilege level on the
                              source host. Higher privilege → easier next step.
      w_misconfig (0.12)    — Target's misconfigurations (default creds, weak
                              passwords, etc.) compound exploitability.
      w_telemetry (0.08)    — Detection avoidance. Targets in well-monitored
                              zones are less attractive (or rather, an
                              attacker is more likely to be stopped before
                              succeeding).

    The alpha_centrality field controls whether we blend in the destination's
    centrality score:
      0.0 (default)  — Pure feasibility. Strict absorbing Markov chain.
      > 0.0          — Value-weighted heuristic. Documented departure from
                       pure Markov semantics.

    self_loop_mass is the probability that attacker stalls at a state per
    timestep. The remainder (1 − self_loop_mass) is split among outgoing
    edges according to relative scores.
    """
    w_vuln: float = 0.35
    w_reachability: float = 0.25
    w_privilege: float = 0.20
    w_misconfig: float = 0.12
    w_telemetry: float = 0.08

    alpha_centrality: float = DEFAULT_CENTRALITY_BLEND
    self_loop_mass: float = DEFAULT_SELF_LOOP_MASS

    def __post_init__(self) -> None:
        # Soft validation: feasibility weights should sum to 1.0 (within tol).
        total = (self.w_vuln + self.w_reachability + self.w_privilege
                 + self.w_misconfig + self.w_telemetry)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"TransitionWeights feasibility weights must sum to 1.0; got {total:.6f}"
            )
        if not 0.0 <= self.alpha_centrality <= 1.0:
            raise ValueError(f"alpha_centrality must be in [0,1]; got {self.alpha_centrality}")
        if not 0.0 <= self.self_loop_mass < 1.0:
            raise ValueError(f"self_loop_mass must be in [0,1); got {self.self_loop_mass}")


# ── Factor functions (each returns a score in [0, 1]) ─────────────────────

def _vuln_score(edge_data: dict, dst_data: dict) -> float:
    """Vulnerability-driven exploitability for THIS specific edge.

    Uses the edge's own CVSS (i.e., the specific CVE being exploited on this
    transition). Falls back to the destination asset's max CVSS only if the
    edge has no CVSS recorded (e.g., misconfiguration-only edges).

    Adds a +0.15 'exploit available' bonus when public exploit code exists.
    The bonus only meaningfully affects edges with CVSS < 8.5, since higher
    scores already saturate at 1.0 after the bonus.
    """
    edge_cvss = float(edge_data.get("cvss", 0.0)) / 10.0
    exploit_bonus = 0.15 if edge_data.get("exploit_available", False) else 0.0

    if edge_cvss > 0.0:
        # Edge has its own CVE — use it directly. This preserves edge
        # differentiation (two edges to the same asset using different CVEs
        # produce different scores).
        return min(edge_cvss + exploit_bonus, 1.0)

    # Edge has no CVE (misconfig-only edge, IAM trust, etc.). Fall back to
    # asset-wide max CVSS as a proxy for "how dangerous is this destination".
    dst_cvss = float(dst_data.get("max_cvss", 0.0)) / 10.0
    return min(dst_cvss + exploit_bonus, 1.0)


def _reachability_score(edge_data: dict, src_data: dict, dst_data: dict) -> float:
    """How realistic is this transition given network topology?

    Lateral movement (already inside) > intra-zone > cross-zone moves.
    Returns a value in [0.40, 0.85]; never zero (every modeled edge is at
    least possible, otherwise it wouldn't be in the graph).
    """
    etype = edge_data.get("edge_type", "")
    if "lateral" in etype:
        return 0.85
    src_zone = src_data.get("zone", "unknown")
    dst_zone = dst_data.get("zone", "unknown")
    if src_zone == dst_zone:
        return 0.75
    if src_zone == "dmz" and dst_zone == "internal":
        return 0.55
    if src_zone == "internal" and dst_zone == "prod":
        return 0.50
    if src_zone == "internet" or src_zone == "external":
        return 0.65
    return 0.40


def _privilege_score(edge_data: dict, src_data: dict) -> float:
    """How much the attacker's CURRENT privilege helps the next step.

    Attackers with higher privilege on a foothold (root vs user) have access
    to cached credentials, SSH agent forwarding, sudo timestamps, etc., which
    materially ease further movement.

    Note: this overlaps slightly with graph topology (privilege escalation
    is also represented as separate edges). The dual representation is
    intentional — privilege influences both 'where can I go' (topology) and
    'how reliably' (this score).
    """
    priv = src_data.get("privilege", "none")
    return {
        "none": 0.10,
        "user": 0.40,
        "sudo": 0.65,
        "admin": 0.80,
        "root": 0.95,
    }.get(priv, 0.10)


def _misconfig_score(dst_data: dict, asset: Optional[NetworkAsset]) -> float:
    """Compound effect of misconfigurations on the destination.

    Flags are additive but capped at 1.0. The values reflect security-domain
    severity ordering: default credentials > weak SSH > root login > rest.
    A target with default creds AND command injection (the worst case) gets
    a score of 0.55; a target with every flag clamps at 1.0.

    NOTE on additivity: in reality these flags are correlated (default creds
    and root SSH login often co-occur). A future refinement could use a
    weighted-max instead of sum to avoid double-counting. The current additive
    scheme is a defensible first approximation.
    """
    if asset is None:
        return 0.0
    score = 0.0
    if asset.has_default_credentials:
        score += 0.30
    if asset.has_weak_ssh_password:
        score += 0.25
    if asset.ssh_root_login_enabled:
        score += 0.20
    if asset.has_world_writable_files:
        score += 0.15
    if asset.has_exposed_backup_files:
        score += 0.10
    if asset.has_command_injection:
        score += 0.25
    if asset.has_suid_binary:
        score += 0.15
    return min(score, 1.0)


def _telemetry_score(dst_data: dict) -> float:
    """1 − P(detection). Higher means attacker is less likely to be stopped.

    Zone-based detection priors reflect a typical mature-org SIEM coverage
    matrix: production systems get the most monitoring, internet-edge sees
    raw scans (low signal), DMZ has moderate coverage. These priors should
    be replaced with org-specific values from CMDB/SIEM in production.
    """
    zone = dst_data.get("zone", "unknown")
    detection_prior = {
        "prod": 0.70,
        "internal": 0.45,
        "dmz": 0.25,
        "internet": 0.05,
        "external": 0.05,
    }.get(zone, 0.30)
    return 1.0 - detection_prior


def _centrality_score(dst_data: dict) -> float:
    """Strategic value of the destination (graph-theoretic centrality).

    Only used when alpha_centrality > 0 in TransitionWeights. Pulled from
    pre-computed centrality_composite attribute on the node.
    """
    return float(dst_data.get("centrality_composite", 0.0))


# ── Composite edge score ───────────────────────────────────────────────────

def compute_edge_score(
    edge_data: dict,
    src_data: dict,
    dst_data: dict,
    dst_asset: Optional[NetworkAsset],
    network: NormalizedNetwork,
    weights: TransitionWeights,
) -> float:
    """Weighted sum of all feasibility factors plus optional centrality blend.

    Returns a value clamped to [MIN_EDGE_PROB, MAX_EDGE_PROB].
    """
    v = _vuln_score(edge_data, dst_data)
    r = _reachability_score(edge_data, src_data, dst_data)
    p = _privilege_score(edge_data, src_data)
    m = _misconfig_score(dst_data, dst_asset)
    t = _telemetry_score(dst_data)

    feasibility = (
        weights.w_vuln * v
        + weights.w_reachability * r
        + weights.w_privilege * p
        + weights.w_misconfig * m
        + weights.w_telemetry * t
    )

    if weights.alpha_centrality > 0.0:
        c = _centrality_score(dst_data)
        score = (1.0 - weights.alpha_centrality) * feasibility + weights.alpha_centrality * c
    else:
        score = feasibility

    return max(MIN_EDGE_PROB, min(MAX_EDGE_PROB, score))


# ── Per-row normalization ──────────────────────────────────────────────────

def compute_transition_matrix_row(
    G: nx.DiGraph,
    state_id: str,
    network: NormalizedNetwork,
    weights: TransitionWeights,
    self_loop_mass: Optional[float] = None,
) -> dict[str, float]:
    """Compute normalised transition probabilities for one transient state.

    Returns a dict {dst_state_id: probability}. The probabilities sum to
    exactly (1 − self_loop_mass). The caller (builder.py) is responsible for
    adding the self-loop diagonal entry so that the full matrix row sums to 1.

    If `self_loop_mass` is None, falls back to weights.self_loop_mass.
    """
    if self_loop_mass is None:
        self_loop_mass = weights.self_loop_mass

    if state_id not in G:
        return {}

    src_data = G.nodes[state_id]
    successors = list(G.successors(state_id))
    if not successors:
        return {}

    raw_scores: dict[str, float] = {}
    for dst_id in successors:
        edge_data = G.edges[state_id, dst_id]
        dst_data = G.nodes[dst_id]
        dst_ip = dst_data.get("host_id", "")
        dst_asset = network.assets.get(dst_ip)
        raw_scores[dst_id] = compute_edge_score(
            edge_data, src_data, dst_data, dst_asset, network, weights,
        )

    total = sum(raw_scores.values())
    if total <= 0:
        return {}

    target_sum = 1.0 - self_loop_mass
    return {dst: (score / total) * target_sum for dst, score in raw_scores.items()}