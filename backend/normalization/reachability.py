"""Reachability matrix — port-level and privilege-level reachability between assets.

Combines three sources:
1. Explicit ACL rules from firewall configuration
2. Same-subnet implicit reachability (intra-zone hosts can talk freely)
3. IAM trust relationships (SSH key reuse, credential sharing)

The resulting matrix is consumed by the attack graph builder to decide
which lateral-movement edges should exist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.normalization.schema import (
    PrivilegeLevel, NetworkEdge, NormalizedNetwork,
)


@dataclass
class ReachabilityMatrix:
    """Encodes which assets can reach which, on which ports, at which privilege.

    Fields:
    - reach[src][dst] = list of allowed ports (empty list = all ports allowed)
    - privilege_reach[src][dst] = highest privilege accessible via trust
    - reason[src][dst] = textual justification for why this reach exists
    """
    reach: dict[str, dict[str, list[int]]] = field(default_factory=dict)
    privilege_reach: dict[str, dict[str, PrivilegeLevel]] = field(default_factory=dict)
    reason: dict[str, dict[str, str]] = field(default_factory=dict)

    def can_reach(self, src: str, dst: str) -> bool:
        return dst in self.reach.get(src, {})

    def allowed_ports(self, src: str, dst: str) -> list[int]:
        """Return permitted ports for src→dst. Empty list means all ports."""
        return self.reach.get(src, {}).get(dst, [])

    def is_port_allowed(self, src: str, dst: str, port: int) -> bool:
        """Check if a specific port is permitted from src to dst."""
        ports = self.allowed_ports(src, dst)
        return self.can_reach(src, dst) and (not ports or port in ports)

    def privilege_to(self, src: str, dst: str) -> PrivilegeLevel:
        return self.privilege_reach.get(src, {}).get(dst, PrivilegeLevel.NONE)

    def reach_reason(self, src: str, dst: str) -> str:
        return self.reason.get(src, {}).get(dst, "")


def build_reachability(network: NormalizedNetwork) -> ReachabilityMatrix:
    """Build a ReachabilityMatrix from the NormalizedNetwork edges + topology."""
    matrix = ReachabilityMatrix()

    # ── 1. ACL/IaC/IAM edges from the network ───────────────────────────────
    for edge in network.edges:
        src, dst = edge.src_id, edge.dst_id
        if not src or not dst or src == dst:
            continue

        # Port-level reachability
        matrix.reach.setdefault(src, {}).setdefault(dst, [])

        if edge.ports:
            for p in edge.ports:
                if p not in matrix.reach[src][dst]:
                    matrix.reach[src][dst].append(p)
        # Empty ports list = all ports allowed (the existing default)

        # Reason annotation
        if edge.permitted_by:
            existing_reason = matrix.reason.setdefault(src, {}).get(dst, "")
            new_reason = edge.permitted_by
            if existing_reason and new_reason not in existing_reason:
                matrix.reason[src][dst] = f"{existing_reason}; {new_reason}"
            else:
                matrix.reason[src][dst] = new_reason

        # Privilege-level reachability — keep the highest
        matrix.privilege_reach.setdefault(src, {})
        current_priv = matrix.privilege_reach[src].get(dst, PrivilegeLevel.NONE)
        if edge.privilege_level.numeric > current_priv.numeric:
            matrix.privilege_reach[src][dst] = edge.privilege_level

    # ── 2. Same-subnet implicit reachability ────────────────────────────────
    # Hosts in the same /24 can communicate freely, but ONLY within zone.
    # Cross-zone reachability requires an explicit ACL rule (already added above).
    ips = list(network.assets.keys())
    for i, a in enumerate(ips):
        asset_a = network.assets.get(a)
        if asset_a is None:
            continue
        subnet_a = ".".join(a.split(".")[:3]) if "." in a else ""
        if not subnet_a or subnet_a == "0.0.0":
            continue

        for b in ips[i + 1:]:
            asset_b = network.assets.get(b)
            if asset_b is None:
                continue
            subnet_b = ".".join(b.split(".")[:3]) if "." in b else ""
            if subnet_a != subnet_b:
                continue
            # Both ways
            matrix.reach.setdefault(a, {}).setdefault(b, [])
            matrix.reach.setdefault(b, {}).setdefault(a, [])
            # Annotate reason if not already set by ACL
            if not matrix.reason.get(a, {}).get(b):
                matrix.reason.setdefault(a, {})[b] = "same-subnet"
            if not matrix.reason.get(b, {}).get(a):
                matrix.reason.setdefault(b, {})[a] = "same-subnet"

    return matrix


def effective_reachability_summary(matrix: ReachabilityMatrix) -> list[dict]:
    """Produce a human-readable summary of all reachability paths.

    Useful for debugging and for the UI to explain "why does this edge exist?".
    """
    summary = []
    for src, dsts in matrix.reach.items():
        for dst, ports in dsts.items():
            summary.append({
                "src": src,
                "dst": dst,
                "ports": ports if ports else "all",
                "privilege": matrix.privilege_reach.get(src, {}).get(
                    dst, PrivilegeLevel.NONE).value,
                "reason": matrix.reason.get(src, {}).get(dst, ""),
            })
    return summary