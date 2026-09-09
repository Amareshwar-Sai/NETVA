"""Q-learning agent for the MDP defender problem."""
from __future__ import annotations

import os
import random
import logging
from collections import defaultdict
from typing import Optional

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.mdp.action_space import DefenderAction, get_applicable_actions, ACTION_MAP
from backend.mdp.state_space import DefenderState, StateSpaceBuilder
from backend.mdp.transitions import TransitionFunction
from backend.mdp.reward import RewardFunction

logger = logging.getLogger(__name__)


class QLearner:
    """Tabular Q-learning agent."""

    def __init__(
        self,
        network: NormalizedNetwork,
        amc: AMCResults,
        alpha: float | None = None,
        gamma: float | None = None,
        epsilon: float | None = None,
        epsilon_decay: float | None = None,
        epsilon_min: float | None = None,
        episodes: int | None = None,
    ):
        self.network = network
        self.amc = amc

        # Hyperparameters
        self.alpha = alpha or float(os.environ.get("QL_ALPHA", 0.10))
        self.gamma = gamma or float(os.environ.get("QL_GAMMA", 0.90))
        self.epsilon = epsilon or float(os.environ.get("QL_EPSILON", 0.30))
        self.epsilon_decay = epsilon_decay or float(os.environ.get("QL_EPSILON_DECAY", 0.995))
        self.epsilon_min = epsilon_min or float(os.environ.get("QL_EPSILON_MIN", 0.01))
        self.episodes = episodes or int(os.environ.get("QL_EPISODES", 500))

        # Q-table: (state_id, action_id, target_asset_id) → float
        self.q_table: dict[tuple[str, str, str], float] = defaultdict(float)

        # Components
        self.transition_fn = TransitionFunction()
        self.reward_fn = RewardFunction()
        self.state_builder = StateSpaceBuilder()

        # Build initial state
        self.initial_state = self.state_builder.build_initial(network, amc)

        # Build action/target pairs
        self.action_target_pairs = self._build_action_target_pairs()

        # Training stats
        self.training_rewards: list[float] = []

    def _build_action_target_pairs(self) -> list[tuple[DefenderAction, str]]:
        """Cross product of applicable actions × assets, plus firewall actions."""
        pairs: list[tuple[DefenderAction, str]] = []

        for ip, asset in self.network.assets.items():
            applicable = get_applicable_actions(asset.asset_type)
            for action in applicable:
                pairs.append((action, ip))

        # Firewall/segment actions target the firewall
        firewall_ip = None
        for ip, asset in self.network.assets.items():
            if asset.asset_type == "firewall":
                firewall_ip = ip
                break

        # If no firewall asset, use first asset as target for segment actions
        segment_target = firewall_ip or (list(self.network.assets.keys())[0] if self.network.assets else "")

        for action_id in ("segment_dmz_internal", "segment_internal_prod"):
            action = ACTION_MAP.get(action_id)
            if action and segment_target:
                # Avoid duplicate
                if (action, segment_target) not in pairs:
                    pairs.append((action, segment_target))

        return pairs

    def train(self) -> dict:
        """Run Q-learning training loop."""
        logger.info(f"Q-Learning: training for {self.episodes} episodes")
        stats = {"episode_rewards": [], "avg_rewards": []}

        for ep in range(self.episodes):
            state = self.initial_state.copy_with()
            # Reset posture
            from copy import deepcopy
            state.asset_postures = {
                k: deepcopy(v) for k, v in self.initial_state.asset_postures.items()
            }
            state.overall_risk = self.initial_state.overall_risk
            state.dmz_segmented = False
            state.prod_segmented = False

            episode_reward = 0.0

            for step in range(30):
                if state.is_terminal:
                    break

                # ε-greedy action selection
                if random.random() < self.epsilon:
                    action, target = random.choice(self.action_target_pairs)
                else:
                    action, target = self._greedy_action(state)

                # Transition
                next_state, succeeded = self.transition_fn.apply(state, action, target)

                # Reward
                reward = self.reward_fn.compute(
                    state, action, next_state, target, succeeded, self.network
                )

                # Q-update
                state_key = (state.state_id, action.action_id, target)
                old_q = self.q_table[state_key]

                # max_a' Q(s', a')
                max_next_q = self._max_q(next_state)

                new_q = old_q + self.alpha * (reward + self.gamma * max_next_q - old_q)
                self.q_table[state_key] = new_q

                episode_reward += reward
                state = next_state

            # Decay epsilon
            self.epsilon = max(self.epsilon * self.epsilon_decay, self.epsilon_min)

            stats["episode_rewards"].append(episode_reward)
            self.training_rewards.append(episode_reward)

            if (ep + 1) % 100 == 0:
                avg = sum(stats["episode_rewards"][-100:]) / min(100, len(stats["episode_rewards"]))
                stats["avg_rewards"].append(avg)
                logger.info(f"Q-Learning: Episode {ep+1}/{self.episodes}, avg_reward={avg:.4f}, ε={self.epsilon:.4f}")

        return stats

    def _greedy_action(self, state: DefenderState) -> tuple[DefenderAction, str]:
        """Select the action with highest Q-value for current state."""
        best_q = float("-inf")
        best_pair = self.action_target_pairs[0]

        sid = state.state_id
        for action, target in self.action_target_pairs:
            q = self.q_table.get((sid, action.action_id, target), 0.0)
            if q > best_q:
                best_q = q
                best_pair = (action, target)

        return best_pair

    def _max_q(self, state: DefenderState) -> float:
        """max_a Q(state, a) over all action-target pairs."""
        sid = state.state_id
        max_q = 0.0
        for action, target in self.action_target_pairs:
            q = self.q_table.get((sid, action.action_id, target), 0.0)
            if q > max_q:
                max_q = q
        return max_q

    def get_optimal_policy(self, max_steps: int = 30) -> list[dict]:
        """Greedy run (ε=0) — return list of step dicts."""
        from copy import deepcopy

        state = DefenderState(
            asset_postures={k: deepcopy(v) for k, v in self.initial_state.asset_postures.items()},
            overall_risk=self.initial_state.overall_risk,
            max_absorption_prob=self.initial_state.max_absorption_prob,
        )

        steps: list[dict] = []
        used_actions: set[tuple[str, str]] = set()

        for step_num in range(1, max_steps + 1):
            if state.is_terminal:
                break

            action, target = self._greedy_action(state)

            # Skip already-applied actions
            key = (action.action_id, target)
            attempt = 0
            while key in used_actions and attempt < len(self.action_target_pairs):
                # Find next best
                sid = state.state_id
                candidates = [
                    (self.q_table.get((sid, a.action_id, t), 0.0), a, t)
                    for a, t in self.action_target_pairs
                    if (a.action_id, t) not in used_actions
                ]
                if not candidates:
                    break
                candidates.sort(key=lambda x: x[0], reverse=True)
                _, action, target = candidates[0]
                key = (action.action_id, target)
                attempt += 1

            if key in used_actions:
                break

            risk_before = state.overall_risk
            next_state, succeeded = self.transition_fn.apply(state, action, target)

            if not succeeded:
                continue

            used_actions.add(key)

            risk_after = next_state.overall_risk
            risk_delta = risk_before - risk_after

            # Only include actions that actually reduce risk
            if risk_delta <= 0.001:
                continue

            target_asset = self.network.assets.get(target)
            q_val = self.q_table.get((state.state_id, action.action_id, target), 0.0)

            steps.append({
                "step": step_num,
                "action_id": action.action_id,
                "action_label": action.label,
                "action_type": action.action_type,
                "target_asset_id": target,
                "target_hostname": target_asset.hostname if target_asset else target,
                "cost": action.cost,
                "disruption": action.disruption,
                "reward": self.reward_fn.compute(state, action, next_state, target, True, self.network),
                "risk_before": round(risk_before, 4),
                "risk_after": round(risk_after, 4),
                "risk_delta": round(risk_delta, 4),
                "q_value": round(q_val, 4),
                "description": action.description,
            })

            state = next_state

        return steps
