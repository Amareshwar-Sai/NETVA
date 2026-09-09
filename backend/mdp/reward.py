"""MDP reward function.

R = λ1·RiskReduction − λ2·Cost − λ3·Disruption + λ4·CriticalityGain
Plus shaping terms for lateral break, no-op penalty, isolation, terminal.
"""
from __future__ import annotations

import os
from typing import Optional

from backend.mdp.action_space import DefenderAction
from backend.mdp.state_space import DefenderState
from backend.normalization.schema import NormalizedNetwork


class RewardFunction:
    """Compute the reward for a (state, action, next_state) transition."""

    def __init__(self):
        self.lambda1 = float(os.environ.get("MDP_LAMBDA1", 0.40))
        self.lambda2 = float(os.environ.get("MDP_LAMBDA2", 0.15))
        self.lambda3 = float(os.environ.get("MDP_LAMBDA3", 0.10))
        self.lambda4 = float(os.environ.get("MDP_LAMBDA4", 0.35))

    def compute(
        self,
        state: DefenderState,
        action: DefenderAction,
        next_state: DefenderState,
        target_id: str,
        succeeded: bool,
        network: Optional[NormalizedNetwork] = None,
    ) -> float:
        """Compute reward for taking action in state."""
        if not succeeded:
            return -0.05  # Small penalty for failed action

        risk_reduction = state.overall_risk - next_state.overall_risk
        cost = action.cost
        disruption = action.disruption
        crit_gain = self._criticality_gain(state, next_state, target_id, network)

        reward = (
            self.lambda1 * risk_reduction
            - self.lambda2 * cost
            - self.lambda3 * disruption
            + self.lambda4 * crit_gain
        )

        # ── Shaping terms ───────────────────────────────────────────────────

        # No-op penalty: action already applied
        if risk_reduction <= 0.001 and succeeded:
            reward -= 0.10

        # Lateral movement break bonus
        if action.action_id in ("revoke_ssh_keys", "segment_dmz_internal", "segment_internal_prod"):
            reward += 0.20

        # Isolation penalty (high disruption)
        if action.action_type == "isolate":
            reward -= 0.05

        # Terminal bonus
        if next_state.is_terminal:
            reward += 1.00

        return reward

    def _criticality_gain(
        self,
        state: DefenderState,
        next_state: DefenderState,
        target_id: str,
        network: Optional[NormalizedNetwork],
    ) -> float:
        """criticality × risk_delta for the targeted asset."""
        if network is None:
            return 0.0

        asset = network.assets.get(target_id)
        if asset is None:
            return 0.0

        risk_delta = state.overall_risk - next_state.overall_risk
        return asset.criticality * max(risk_delta, 0.0)
