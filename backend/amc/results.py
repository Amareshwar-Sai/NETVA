"""AMCResults — single output object for the Absorbing Markov Chain analysis.

This is a data container, not a computation engine. It holds the solved
sub-matrices (Q, R, N, B), expected-steps vector, visit frequencies, and
per-node risk scores — and exposes them via convenient lookups by state_id.

After construction, index dictionaries are cached so all per-state lookups
are O(1) instead of O(n).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np


# Numerical tolerance for invariant validation.
_INVARIANT_TOL = 1e-6


@dataclass
class AMCResults:
    """Complete output of the AMC analysis."""
    transient_states: list[str] = field(default_factory=list)  # ordered state_ids
    absorbing_states: list[str] = field(default_factory=list)
    Q: Optional[np.ndarray] = None         # (t, t) sub-stochastic
    R: Optional[np.ndarray] = None         # (t, a)
    N: Optional[np.ndarray] = None         # (t, t) fundamental matrix
    B: Optional[np.ndarray] = None         # (t, a) absorption probabilities
    t_vec: Optional[np.ndarray] = None     # (t,) expected steps
    visit_freq: Optional[np.ndarray] = None  # (t,) row sums of N
    node_risk: dict[str, float] = field(default_factory=dict)
    solver_converged: bool = True
    solver_method: str = ""
    condition_number: float = 0.0

    # Lazy-built index dicts for O(1) state_id lookups.
    _t_idx_cache: Optional[dict[str, int]] = field(default=None, repr=False, compare=False)
    _a_idx_cache: Optional[dict[str, int]] = field(default=None, repr=False, compare=False)

    # ── Convenience properties ─────────────────────────────────────────────
    @property
    def num_transient(self) -> int:
        return len(self.transient_states)

    @property
    def num_absorbing(self) -> int:
        return len(self.absorbing_states)

    # ── Cached index lookups (O(1) after first call) ──────────────────────
    def _t_index(self, state_id: str) -> Optional[int]:
        if self._t_idx_cache is None:
            self._t_idx_cache = {sid: i for i, sid in enumerate(self.transient_states)}
        return self._t_idx_cache.get(state_id)

    def _a_index(self, state_id: str) -> Optional[int]:
        if self._a_idx_cache is None:
            self._a_idx_cache = {sid: i for i, sid in enumerate(self.absorbing_states)}
        return self._a_idx_cache.get(state_id)

    # ── Per-state accessors ────────────────────────────────────────────────
    def absorption_prob(self, state_id: str) -> float:
        """Total absorption probability from a transient state.

        For a properly constructed AMC (rows of [Q | R] sum to 1.0), this
        is exactly 1.0 for every transient state. Variation across states
        only appears if the matrix is sub-stochastic.
        """
        i = self._t_index(state_id)
        if i is None or self.B is None:
            return 0.0
        return float(self.B[i].sum())

    def absorption_prob_to(self, state_id: str, absorbing_id: str) -> float:
        """Probability that an attacker starting at `state_id` is eventually
        absorbed at the specific absorbing state `absorbing_id`.

        This is THE key per-state metric for risk: P(reach this absorbing
        target | start here). Sums to 1.0 across all absorbing states (for
        a proper AMC).
        """
        i = self._t_index(state_id)
        j = self._a_index(absorbing_id)
        if i is None or j is None or self.B is None:
            return 0.0
        return float(self.B[i, j])

    def absorption_to_set(self, state_id: str, absorbing_ids: list[str]) -> float:
        """Cumulative absorption probability into a SET of absorbing states.

        Useful for asking 'P(reach any crown jewel | start here)'. Pass the
        list of crown-jewel state_ids; returns the summed probability.
        """
        i = self._t_index(state_id)
        if i is None or self.B is None:
            return 0.0
        total = 0.0
        for aid in absorbing_ids:
            j = self._a_index(aid)
            if j is not None:
                total += float(self.B[i, j])
        return total

    def expected_steps(self, state_id: str) -> float:
        """Expected number of timesteps from state_id to absorption."""
        i = self._t_index(state_id)
        if i is None or self.t_vec is None:
            return float("inf")
        return float(self.t_vec[i])

    def visit_frequency(self, state_id: str) -> float:
        """Expected total visits to this transient state before absorption."""
        i = self._t_index(state_id)
        if i is None or self.visit_freq is None:
            return 0.0
        return float(self.visit_freq[i])

    # ── Invariant checks (call after solver populates fields) ─────────────
    def validate(self) -> list[str]:
        """Run sanity checks on the solved matrices. Returns warnings list."""
        warnings: list[str] = []
        if self.B is not None:
            for i in range(self.B.shape[0]):
                row_sum = float(self.B[i].sum())
                if abs(row_sum - 1.0) > _INVARIANT_TOL:
                    warnings.append(
                        f"B row {i} ({self.transient_states[i]}) sums to {row_sum:.6f}, expected 1.0"
                    )
                if (self.B[i] < -_INVARIANT_TOL).any():
                    warnings.append(
                        f"B row {i} ({self.transient_states[i]}) has negative entries"
                    )
        if self.t_vec is not None:
            if (self.t_vec < 1.0 - _INVARIANT_TOL).any():
                warnings.append("t_vec has entries < 1.0 (impossible — minimum is 1 step)")
            if not np.isfinite(self.t_vec).all():
                warnings.append("t_vec contains inf or nan")
        if self.visit_freq is not None:
            if (self.visit_freq < 1.0 - _INVARIANT_TOL).any():
                warnings.append("visit_freq has entries < 1.0 (impossible — at least 1 self-visit)")
        return warnings

    # ── Serialization ──────────────────────────────────────────────────────
    def to_dict(self, include_matrices: bool = True) -> dict:
        """JSON-serialisable dict.

        Set include_matrices=False to omit Q/R/N/B/t_vec/visit_freq raw arrays
        (useful for large graphs where the per-state-metrics summary suffices).
        """
        out: dict = {
            "transient_states": self.transient_states,
            "absorbing_states": self.absorbing_states,
            "num_transient": self.num_transient,
            "num_absorbing": self.num_absorbing,
            "node_risk": self.node_risk,
            "solver_converged": self.solver_converged,
            "solver_method": self.solver_method,
            "condition_number": self.condition_number,
            "state_metrics": [
                {
                    "state_id": sid,
                    "absorption_prob": self.absorption_prob(sid),
                    "expected_steps": self.expected_steps(sid),
                    "visit_frequency": self.visit_frequency(sid),
                    "risk_score": self.node_risk.get(sid, 0.0),
                }
                for sid in self.transient_states
            ],
        }
        if include_matrices:
            out["Q"] = self.Q.tolist() if self.Q is not None else []
            out["R"] = self.R.tolist() if self.R is not None else []
            out["N"] = self.N.tolist() if self.N is not None else []
            out["B"] = self.B.tolist() if self.B is not None else []
            out["t_vec"] = self.t_vec.tolist() if self.t_vec is not None else []
            out["visit_freq"] = self.visit_freq.tolist() if self.visit_freq is not None else []
        return out