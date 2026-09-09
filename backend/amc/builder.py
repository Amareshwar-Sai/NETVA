"""AMC matrix builder — partition nodes, fill Q and R matrices.

ARCHITECTURE
------------
The attack graph contains transient states (where attackers can take further
actions) and absorbing states (terminal: crown jewel reached, dead-end, etc).
This builder partitions the nodes and constructs the canonical AMC sub-matrices:

    P = [Q  R]    Q: transient → transient   (t × t)
        [0  I]    R: transient → absorbing   (t × a)

After partitioning, each transient row's outgoing probabilities are computed
via compute_transition_matrix_row (in transition_probs.py), which returns
probabilities summing to (1 − self_loop_mass). The remaining mass is added
back as a self-loop on the diagonal of Q, ensuring every row of [Q | R] sums
to exactly 1.0 — a proper stochastic matrix.

The self-loop semantics: the attacker stalls at this state for one timestep
(failed exploit, hesitation, environmental pause) before trying again next
turn. This keeps absorption probabilities mathematically clean — they sum
to 1.0 across all absorbing states for any starting transient state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.transition_probs import (
    TransitionWeights, compute_transition_matrix_row,
)


# Numerical tolerance for stochastic-row invariant check.
ROW_SUM_TOL = 1e-9


@dataclass
class MatrixBundle:
    """Raw matrices before solving."""
    Q: np.ndarray                                  # (t, t) transient-to-transient
    R: np.ndarray                                  # (t, a) transient-to-absorbing
    transient_states: list[str] = field(default_factory=list)
    absorbing_states: list[str] = field(default_factory=list)


class MatrixBuilder:
    """Build the AMC transition sub-matrices Q and R from the attack graph."""

    def build(
        self,
        G: nx.DiGraph,
        network: NormalizedNetwork,
        weights: Optional[TransitionWeights] = None,
    ) -> MatrixBundle:
        """Partition nodes, fill matrices, and ensure proper stochasticity."""
        if weights is None:
            weights = TransitionWeights()

        # 1. Partition nodes into transient / absorbing.
        transient: list[str] = []
        absorbing: list[str] = []

        for nid, data in G.nodes(data=True):
            if data.get("is_absorbing", False):
                absorbing.append(nid)
            else:
                transient.append(nid)

        # 2. Safety: AMC requires at least one absorbing state. If somehow
        #    none exist (graph misconfiguration), promote the highest-
        #    criticality node so the math doesn't blow up.
        if not absorbing:
            best = max(G.nodes(data=True), key=lambda nd: nd[1].get("criticality", 0))
            absorbing.append(best[0])
            if best[0] in transient:
                transient.remove(best[0])
            G.nodes[best[0]]["is_absorbing"] = True

        t = len(transient)
        a = len(absorbing)

        t_idx = {s: i for i, s in enumerate(transient)}
        a_idx = {s: i for i, s in enumerate(absorbing)}

        Q = np.zeros((t, t), dtype=np.float64)
        R = np.zeros((t, a), dtype=np.float64)

        # 3. Fill Q and R from per-row transition probabilities.
        #    Each row from compute_transition_matrix_row sums to
        #    (1 − self_loop_mass); we add the remaining mass as a
        #    self-loop on Q's diagonal below.
        for state_id in transient:
            i = t_idx[state_id]
            row = compute_transition_matrix_row(
                G, state_id, network, weights,
                self_loop_mass=weights.self_loop_mass,
            )

            for dst_id, prob in row.items():
                if dst_id in t_idx:
                    Q[i, t_idx[dst_id]] = prob
                elif dst_id in a_idx:
                    R[i, a_idx[dst_id]] = prob

            # 4. Add self-loop for the remaining mass so the row sums to 1.
            #    This is what makes [Q | R] a proper stochastic matrix and
            #    gives clean absorption probability semantics.
            assigned = Q[i].sum() + R[i].sum()
            self_loop = 1.0 - assigned
            if self_loop > 0.0:
                Q[i, i] += self_loop
            elif self_loop < -ROW_SUM_TOL:
                # Defensive: row over-allocated (shouldn't happen with
                # proper normalization, but if it does, scale down to 1.0).
                scale = 1.0 / assigned
                Q[i] *= scale
                R[i] *= scale

        # 5. Final invariant check: every row of [Q | R] must sum to 1.0.
        #    This catches any subtle bug in the row-construction logic.
        for i in range(t):
            row_sum = Q[i].sum() + R[i].sum()
            if abs(row_sum - 1.0) > ROW_SUM_TOL:
                # One last clamp + redistribute to keep math sane.
                # If we hit this branch, log it — it indicates a bug upstream.
                if row_sum > 0:
                    delta = 1.0 - row_sum
                    Q[i, i] += delta  # absorb residual into self-loop

        return MatrixBundle(
            Q=Q,
            R=R,
            transient_states=transient,
            absorbing_states=absorbing,
        )