"""Policy result dataclasses and extraction logic."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from backend.amc.results import AMCResults
from backend.mdp.q_learner import QLearner


@dataclass
class PolicyStep:
    """One step in the optimal policy."""
    step: int = 0
    action_id: str = ""
    action_label: str = ""
    action_type: str = ""
    target_asset_id: str = ""
    target_hostname: str = ""
    cost: float = 0.0
    disruption: float = 0.0
    reward: float = 0.0
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_delta: float = 0.0
    q_value: float = 0.0
    description: str = ""


@dataclass
class PolicyResult:
    """Complete output of MDP policy extraction."""
    steps: list[PolicyStep] = field(default_factory=list)
    initial_risk: float = 0.0
    final_risk: float = 0.0
    total_risk_reduction: float = 0.0
    total_cost: float = 0.0
    total_disruption: float = 0.0
    cumulative_reward: float = 0.0
    converged: bool = True
    training_episodes: int = 0
    improved_nodes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "steps": [
                {
                    "step": s.step,
                    "action_id": s.action_id,
                    "action_label": s.action_label,
                    "action_type": s.action_type,
                    "target_asset_id": s.target_asset_id,
                    "target_hostname": s.target_hostname,
                    "cost": s.cost,
                    "disruption": s.disruption,
                    "reward": round(s.reward, 4),
                    "risk_before": s.risk_before,
                    "risk_after": s.risk_after,
                    "risk_delta": s.risk_delta,
                    "q_value": s.q_value,
                    "description": s.description,
                }
                for s in self.steps
            ],
            "initial_risk": round(self.initial_risk, 4),
            "final_risk": round(self.final_risk, 4),
            "total_risk_reduction": round(self.total_risk_reduction, 4),
            "total_cost": round(self.total_cost, 4),
            "total_disruption": round(self.total_disruption, 4),
            "cumulative_reward": round(self.cumulative_reward, 4),
            "converged": self.converged,
            "training_episodes": self.training_episodes,
            "improved_nodes": self.improved_nodes,
        }


class PolicyExtractor:
    """Extract a PolicyResult from a trained QLearner."""

    def extract(
        self,
        learner: QLearner,
        stats: dict,
        G: nx.DiGraph,
        amc: AMCResults,
    ) -> PolicyResult:
        """Run get_optimal_policy() and package into PolicyResult."""
        raw_steps = learner.get_optimal_policy()

        steps = [PolicyStep(**s) for s in raw_steps]

        initial_risk = steps[0].risk_before if steps else learner.initial_state.overall_risk
        final_risk = steps[-1].risk_after if steps else initial_risk
        total_reduction = initial_risk - final_risk

        total_cost = sum(s.cost for s in steps)
        total_disruption = sum(s.disruption for s in steps)
        cumulative_reward = sum(s.reward for s in steps)

        # Find improved nodes
        improved: list[dict] = []
        for s in steps:
            improved.append({
                "node_id": s.target_asset_id,
                "label": s.target_hostname,
                "risk_delta": s.risk_delta,
                "action_id": s.action_id,
                "step": s.step,
            })

        return PolicyResult(
            steps=steps,
            initial_risk=initial_risk,
            final_risk=final_risk,
            total_risk_reduction=total_reduction,
            total_cost=total_cost,
            total_disruption=total_disruption,
            cumulative_reward=cumulative_reward,
            converged=True,
            training_episodes=learner.episodes,
            improved_nodes=improved,
        )
