"""Attack graph state representation — frozen (hashable) for graph nodes.

Provides:
- AttackState dataclass (host, privilege)
- is_absorbing() — initial absorbing-state detection (crown jewels)
- enumerate_states() — meaningful states per asset
- termination_reason() — human-readable explanation for path termination

CROWN-JEWEL THRESHOLD
---------------------
A "crown jewel" is an asset whose compromise represents game-over from the
attacker's perspective. Reaching a crown-jewel state at high privilege makes
the state absorbing — the AMC chain terminates there.

Threshold of 0.85 (raised from 0.80 to prevent the appserver, criticality
0.80, from prematurely terminating chains that would realistically continue
to the database). With 0.85, only assets explicitly designated as crown
jewels in the CMDB (database 0.98, firewall 0.90) become absorbing crown
jewels. Lower-criticality assets remain transient and chains can continue
through them to the actual data layer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from backend.normalization.schema import NetworkAsset, PrivilegeLevel, Zone


# Single source of truth — imported by other modules that need it.
CROWN_JEWEL_THRESHOLD = 0.85


@dataclass(frozen=True)
class AttackState:
    """A single state in the attack graph: (host, privilege level)."""
    host_id: str
    privilege: PrivilegeLevel

    @property
    def state_id(self) -> str:
        return f"{self.host_id}::{self.privilege.value}"

    @property
    def short_label(self) -> str:
        return f"{self.host_id} [{self.privilege.value}]"

    def __str__(self) -> str:
        return self.state_id


def is_absorbing(state: AttackState, asset: Optional[NetworkAsset]) -> bool:
    """Determine if a state is absorbing during initial graph construction.

    Initial absorbing states (crown jewels):
    1. Crown-jewel asset (criticality >= CROWN_JEWEL_THRESHOLD) at high
       privilege (ADMIN/ROOT)
    2. PROD-zone asset at SUDO+ privilege

    Additional absorbing states (dead-end nodes with no useful outgoing
    edges) are detected post-construction in attack_graph.py via
    promote_dead_ends_to_absorbing().
    """
    if asset is None:
        return False

    high_priv = state.privilege in (PrivilegeLevel.ADMIN, PrivilegeLevel.ROOT)
    if asset.criticality >= CROWN_JEWEL_THRESHOLD and high_priv:
        return True

    if asset.zone == Zone.PROD and state.privilege.numeric >= PrivilegeLevel.SUDO.numeric:
        return True

    return False


def enumerate_states(asset: NetworkAsset) -> list[AttackState]:
    """Return meaningful AttackStates for an asset.

    Rules:
    - USER state always present (every host can be reached at user level)
    - ROOT state present if any privesc indicator exists (flag-based check;
      keyword match in normalizer's _set_flags handles most CVE-driven cases)
    - ADMIN state present for databases and domain controllers
      (ADMIN is conventionally the data-tier privilege; OS-level uses ROOT)
    """
    states = [AttackState(host_id=asset.ip, privilege=PrivilegeLevel.USER)]

    has_privesc_indicator = (
        asset.ssh_root_login_enabled
        or asset.has_world_writable_files
        or asset.has_suid_binary
        or asset.has_default_credentials
        or asset.has_command_injection
    )
    if has_privesc_indicator:
        states.append(AttackState(host_id=asset.ip, privilege=PrivilegeLevel.ROOT))

    if asset.asset_type in ("database", "domain_controller"):
        states.append(AttackState(host_id=asset.ip, privilege=PrivilegeLevel.ADMIN))

    return states


def termination_reason(node_data: dict, outgoing_count: int) -> str:
    """Human-readable explanation of why a node is absorbing."""
    privilege = node_data.get("privilege", "")
    asset_type = node_data.get("asset_type", "host")
    criticality = node_data.get("criticality", 0.0)
    hostname = node_data.get("hostname") or node_data.get("host_id", "host")

    # Crown jewel reached
    if criticality >= CROWN_JEWEL_THRESHOLD and privilege in ("admin", "root"):
        return (
            f"Crown jewel compromised: full {privilege} access on critical "
            f"{asset_type} '{hostname}'. Worst-case impact realized."
        )

    # Dead-end at high privilege
    if outgoing_count == 0 and privilege in ("root", "admin", "sudo"):
        return (
            f"Dead-end: attacker has {privilege} on '{hostname}' but no further "
            f"reachability or privilege-escalation path is available. "
            f"Damage scope limited to this host."
        )

    # Foothold-only (user level, no privesc)
    if privilege == "user" and outgoing_count == 0:
        return (
            f"Foothold-only: user-level shell on '{hostname}'. No local "
            f"privilege-escalation vulnerability present. Limited impact: "
            f"can read service-context files only."
        )

    # Generic dead-end
    return (
        f"No further attacker actions available from {privilege} on '{hostname}'. "
        f"Path absorbs here."
    )