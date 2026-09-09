"""MDP + Q-Learning module.

Usage:
    policy = run_mdp(G, network, amc, episodes=300)
"""
from __future__ import annotations

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.mdp.q_learner import QLearner
from backend.mdp.policy import PolicyExtractor, PolicyResult
from backend.mdp.simulator import Simulator, SimulationResult


def run_mdp(
    G: nx.DiGraph,
    network: NormalizedNetwork,
    amc: AMCResults,
    episodes: int = 300,
) -> PolicyResult:
    """Full MDP pipeline: build Q-learner → train → extract policy."""
    learner = QLearner(network, amc, episodes=episodes)
    stats = learner.train()

    extractor = PolicyExtractor()
    policy = extractor.extract(learner, stats, G, amc)

    return policy


__all__ = [
    "run_mdp",
    "QLearner",
    "PolicyResult",
    "PolicyExtractor",
    "Simulator",
    "SimulationResult",
]
