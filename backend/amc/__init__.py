"""AMC module — Absorbing Markov Chain analysis.

Usage:
    amc = run_amc(G, network)
"""
from __future__ import annotations

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.transition_probs import TransitionWeights
from backend.amc.builder import MatrixBuilder
from backend.amc.solver import AMCSolver
from backend.amc.risk_scorer import RiskScorer
from backend.amc.results import AMCResults


def run_amc(
    G: nx.DiGraph,
    network: NormalizedNetwork,
    weights: TransitionWeights | None = None,
) -> AMCResults:
    """Full AMC pipeline: build matrices → solve → score risk."""
    if weights is None:
        weights = TransitionWeights()

    # Build Q and R matrices
    builder = MatrixBuilder()
    bundle = builder.build(G, network, weights)

    # Solve: N = (I-Q)^-1, B = N·R, t = N·1
    solver = AMCSolver()
    amc = solver.solve(bundle)

    # Compute risk scores
    scorer = RiskScorer()
    scorer.score(amc, G, network)

    return amc


__all__ = [
    "run_amc",
    "AMCResults",
    "TransitionWeights",
    "MatrixBuilder",
    "AMCSolver",
    "RiskScorer",
]
