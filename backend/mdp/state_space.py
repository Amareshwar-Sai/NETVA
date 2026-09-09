"""MDP state space — defender posture representation."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults


@dataclass
class AssetPosture:
    """Per-asset control flags — which defences are currently active."""
    is_patched: bool = False
    ssh_hardened: bool = False
    service_stopped: bool = False
    is_isolated: bool = False
    keys_revoked: bool = False
    files_hardened: bool = False
    db_restricted: bool = False
    backup_removed: bool = False
    cgi_disabled: bool = False
    weak_accounts_disabled: bool = False
    db_password_changed: bool = False

    def risk_reduction_factor(self) -> float:
        """Multiplier product — lower = more risk removed."""
        factor = 1.0
        if self.is_isolated:
            factor *= 0.05
        if self.is_patched:
            factor *= 0.35
        if self.service_stopped:
            factor *= 0.50
        if self.ssh_hardened:
            factor *= 0.65
        if self.keys_revoked:
            factor *= 0.70
        if self.db_restricted:
            factor *= 0.60
        if self.files_hardened:
            factor *= 0.80
        if self.backup_removed:
            factor *= 0.85
        if self.cgi_disabled:
            factor *= 0.90
        if self.weak_accounts_disabled:
            factor *= 0.90
        if self.db_password_changed:
            factor *= 0.55
        return factor

    def to_dict(self) -> dict:
        return {
            "is_patched": self.is_patched,
            "ssh_hardened": self.ssh_hardened,
            "service_stopped": self.service_stopped,
            "is_isolated": self.is_isolated,
            "keys_revoked": self.keys_revoked,
            "files_hardened": self.files_hardened,
            "db_restricted": self.db_restricted,
            "backup_removed": self.backup_removed,
            "cgi_disabled": self.cgi_disabled,
            "weak_accounts_disabled": self.weak_accounts_disabled,
            "db_password_changed": self.db_password_changed,
        }


@dataclass
class DefenderState:
    """Complete defender posture across all assets."""
    asset_postures: dict[str, AssetPosture] = field(default_factory=dict)
    dmz_segmented: bool = False
    prod_segmented: bool = False
    overall_risk: float = 1.0
    max_absorption_prob: float = 1.0

    @property
    def state_id(self) -> str:
        """MD5 hash of flags dict for Q-table key."""
        flags = {
            ip: posture.to_dict()
            for ip, posture in sorted(self.asset_postures.items())
        }
        flags["__dmz_seg"] = self.dmz_segmented
        flags["__prod_seg"] = self.prod_segmented
        raw = json.dumps(flags, sort_keys=True)
        return hashlib.md5(raw.encode()).hexdigest()

    @property
    def is_terminal(self) -> bool:
        """Terminal when overall risk drops below 0.15."""
        return self.overall_risk < 0.15

    def copy_with(self, **kwargs) -> DefenderState:
        """Immutable update — return new state with changed fields."""
        new = DefenderState(
            asset_postures={k: deepcopy(v) for k, v in self.asset_postures.items()},
            dmz_segmented=self.dmz_segmented,
            prod_segmented=self.prod_segmented,
            overall_risk=self.overall_risk,
            max_absorption_prob=self.max_absorption_prob,
        )
        for key, val in kwargs.items():
            setattr(new, key, val)
        return new


class StateSpaceBuilder:
    """Build the initial defender state from network + AMC data."""

    def build_initial(
        self, network: NormalizedNetwork, amc: AMCResults
    ) -> DefenderState:
        """All controls off, risk from AMC initial values."""
        postures: dict[str, AssetPosture] = {}
        for ip in network.assets:
            postures[ip] = AssetPosture()

        # Compute initial risk
        max_risk = 0.0
        max_absorb = 0.0
        for sid, risk in amc.node_risk.items():
            max_risk = max(max_risk, risk)
        if amc.B is not None and amc.B.size > 0:
            max_absorb = float(amc.B.max())

        return DefenderState(
            asset_postures=postures,
            overall_risk=max_risk,
            max_absorption_prob=max_absorb,
        )
