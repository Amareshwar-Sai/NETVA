"""MDP transition function — apply defender actions to state."""
from __future__ import annotations

import random
from copy import deepcopy

from backend.mdp.action_space import DefenderAction
from backend.mdp.state_space import DefenderState, AssetPosture


# Per-action-type success probabilities
_SUCCESS_PROB = {
    "patch": 0.90,
    "isolate": 0.98,
    "block_port": 0.99,
    "harden": 0.95,
    "revoke": 0.97,
    "segment": 0.95,
    "monitor": 0.99,
}


class TransitionFunction:
    """Apply a defender action to the current state."""

    def apply(
        self,
        state: DefenderState,
        action: DefenderAction,
        target_asset_id: str,
    ) -> tuple[DefenderState, bool]:
        """Apply action → (new_state, succeeded).

        Returns a new state with updated posture and recalculated risk.
        """
        # Stochastic success
        prob = _SUCCESS_PROB.get(action.action_type, 0.90)
        succeeded = random.random() < prob

        if not succeeded:
            return state.copy_with(), False

        # Deep copy postures
        new_state = state.copy_with()
        new_state.asset_postures = {
            k: deepcopy(v) for k, v in state.asset_postures.items()
        }

        # Apply effect
        self._apply_effect(new_state, action, target_asset_id)

        # Recalculate risk
        new_state.overall_risk = self._estimate_risk(new_state)

        return new_state, True

    def _apply_effect(
        self,
        state: DefenderState,
        action: DefenderAction,
        target_asset_id: str,
    ) -> None:
        """Map each action_id to the correct posture flag flip."""
        posture = state.asset_postures.get(target_asset_id)

        # Segment actions target the firewall but affect global state
        if action.action_id == "segment_dmz_internal":
            state.dmz_segmented = True
            return
        if action.action_id == "segment_internal_prod":
            state.prod_segmented = True
            return

        if posture is None:
            return

        effect_map = {
            "patch_os": lambda p: setattr(p, "is_patched", True),
            "patch_web_server": lambda p: setattr(p, "is_patched", True),
            "patch_app": lambda p: setattr(p, "is_patched", True),
            "patch_db": lambda p: setattr(p, "is_patched", True),
            "isolate_host": lambda p: setattr(p, "is_isolated", True),
            "isolate_from_internet": lambda p: setattr(p, "is_isolated", True),
            "block_port_80": lambda p: setattr(p, "service_stopped", True),
            "block_port_22": lambda p: setattr(p, "ssh_hardened", True),
            "block_port_3306": lambda p: setattr(p, "db_restricted", True),
            "block_port_3000": lambda p: setattr(p, "service_stopped", True),
            "disable_ssh_root_login": lambda p: setattr(p, "ssh_hardened", True),
            "fix_world_writable_files": lambda p: setattr(p, "files_hardened", True),
            "remove_backup_files": lambda p: setattr(p, "backup_removed", True),
            "disable_cgi": lambda p: setattr(p, "cgi_disabled", True),
            "change_db_password": lambda p: setattr(p, "db_password_changed", True),
            "bind_db_localhost": lambda p: setattr(p, "db_restricted", True),
            "revoke_ssh_keys": lambda p: setattr(p, "keys_revoked", True),
            "disable_weak_accounts": lambda p: setattr(p, "weak_accounts_disabled", True),
            "enable_auditd": lambda p: None,  # monitoring, no posture change
            "stop_vulnerable_service": lambda p: setattr(p, "service_stopped", True),
        }

        fn = effect_map.get(action.action_id)
        if fn:
            fn(posture)

    def _estimate_risk(self, state: DefenderState) -> float:
        """Estimate overall risk from posture flags."""
        if not state.asset_postures:
            return 1.0

        factors = []
        for posture in state.asset_postures.values():
            factors.append(posture.risk_reduction_factor())

        base_risk = sum(factors) / len(factors)

        if state.dmz_segmented:
            base_risk *= 0.60
        if state.prod_segmented:
            base_risk *= 0.65

        return min(max(base_risk, 0.0), 1.0)
