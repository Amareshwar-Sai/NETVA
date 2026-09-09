"""AMC solver — compute fundamental matrix N, absorption B, expected steps t.

Three inversion strategies (tried in order):
1. scipy LU decomposition (fast, stable, default)
2. numpy SVD pseudo-inverse (robust to rank deficiency)
3. Neumann series (always converges for sub-stochastic Q)

The fallback chain provides robustness against ill-conditioned matrices that
might arise when Q has near-unit eigenvalues (very long expected paths) or
when (I-Q) has a high condition number.

After solving, validates the result via AMCResults.validate() and logs any
invariant violations (row sums, negative entries, nonfinite values).
"""
from __future__ import annotations

import logging

import numpy as np
from scipy import linalg as sp_linalg

from backend.amc.builder import MatrixBundle
from backend.amc.results import AMCResults

logger = logging.getLogger(__name__)


# Condition number above this triggers a warning. 1e10 is a conservative
# threshold for float64 — beyond this, we lose ~10 of 16 digits of precision
# in the inversion. Float32 would warn at ~1e4. We use float64 throughout.
_COND_WARN_THRESHOLD = 1e10

# Maximum Neumann iterations. For sub-stochastic Q with spectral radius ρ < 1,
# convergence is geometric: after k iterations, error ~ ρ^k. For ρ = 0.99,
# 1000 iterations gives ~10^-5 precision, which is plenty.
_NEUMANN_MAX_ITER = 1000
_NEUMANN_TOL = 1e-8


class AMCSolver:
    """Solve the AMC from a MatrixBundle."""

    def solve(self, bundle: MatrixBundle) -> AMCResults:
        """Compute N = (I - Q)^-1, B = N·R, t = N·1."""
        t = bundle.Q.shape[0]
        if t == 0:
            return AMCResults(
                transient_states=bundle.transient_states,
                absorbing_states=bundle.absorbing_states,
                solver_converged=True,
                solver_method="trivial",
            )

        I = np.eye(t, dtype=np.float64)
        IminusQ = I - bundle.Q

        cond = float(np.linalg.cond(IminusQ))
        if cond > _COND_WARN_THRESHOLD:
            logger.warning(
                f"AMC: (I-Q) condition number = {cond:.2e} exceeds "
                f"threshold {_COND_WARN_THRESHOLD:.0e}; results may be unstable"
            )

        N, method, converged = self._invert(IminusQ, I)

        # Clean numerical noise: clip negatives that come from float roundoff.
        # N has non-negative entries by construction (sum of non-negative
        # powers of Q); negatives indicate float roundoff.
        N = np.clip(N, 0.0, None)

        # Absorption matrix B = N · R.
        B = N @ bundle.R

        # Clean numerical noise: clip B to [0, 1]. With proper stochastic
        # input, each row of B should already sum to ≤ 1.0 within float
        # tolerance. We clip individual entries to handle accumulated
        # roundoff, then check the row-sum invariant below.
        B = np.clip(B, 0.0, 1.0)

        # Validate row sums. With self-loops in Q (proper stochastic matrix),
        # each row of B should sum to 1.0. If a row sums to slightly more
        # than 1.0 due to clipping artifacts, renormalize it. If it sums to
        # less than 1.0, that's the sign Q is not properly stochastic — log
        # a warning but don't silently inflate, since that would hide the
        # upstream bug.
        for i in range(B.shape[0]):
            row_sum = float(B[i].sum())
            if row_sum > 1.0 + 1e-9:
                B[i] /= row_sum
            elif row_sum < 1.0 - 1e-3:
                # More than 0.1% deficit indicates the matrix is sub-stochastic
                # (missing self-loops upstream). Log and proceed.
                logger.warning(
                    f"AMC: B row {i} ({bundle.transient_states[i]}) sums to "
                    f"{row_sum:.6f} (< 1.0). Q may be sub-stochastic."
                )

        # Expected steps: t_vec = N · 1.  This is at least 1.0 per entry.
        t_vec = N @ np.ones(t)

        # Visit frequency = row sums of N. By construction ≥ 1.0 (you visit
        # your own start state at least once).
        visit_freq = N.sum(axis=1)

        results = AMCResults(
            transient_states=bundle.transient_states,
            absorbing_states=bundle.absorbing_states,
            Q=bundle.Q,
            R=bundle.R,
            N=N,
            B=B,
            t_vec=t_vec,
            visit_freq=visit_freq,
            solver_converged=converged,
            solver_method=method,
            condition_number=cond,
        )

        # Run invariant checks; surface any violations as warnings.
        warnings = results.validate()
        for w in warnings:
            logger.warning(f"AMC invariant: {w}")

        return results

    # ── Inversion strategies ──────────────────────────────────────────────
    def _invert(
        self, IminusQ: np.ndarray, I: np.ndarray
    ) -> tuple[np.ndarray, str, bool]:
        """Try three strategies to compute N = (I-Q)^-1, in order of speed."""

        # Strategy 1: LU decomposition (fast, stable for well-conditioned matrices)
        try:
            N = sp_linalg.solve(IminusQ, I)
            logger.info("AMC: solved via LU decomposition (scipy)")
            return N, "lu_decomposition", True
        except (np.linalg.LinAlgError, sp_linalg.LinAlgError) as e:
            logger.warning(f"AMC: LU failed — {e}")

        # Strategy 2: SVD pseudo-inverse (handles rank-deficient cases)
        try:
            N = np.linalg.pinv(IminusQ)
            logger.info("AMC: solved via SVD pseudo-inverse")
            return N, "svd_pseudoinverse", True
        except np.linalg.LinAlgError as e:
            logger.warning(f"AMC: SVD failed — {e}")

        # Strategy 3: Neumann series N = I + Q + Q² + Q³ + ...
        # Always converges when spectral radius of Q < 1 (i.e., when chain
        # is genuinely absorbing). Slowest but most robust.
        logger.info("AMC: falling back to Neumann series")
        Q = I - IminusQ  # recover Q
        N = I.copy()
        Q_power = Q.copy()
        for k in range(1, _NEUMANN_MAX_ITER):
            N += Q_power
            if np.linalg.norm(Q_power) < _NEUMANN_TOL:
                logger.info(f"AMC: Neumann converged at iteration {k}")
                return N, "neumann_series", True
            Q_power = Q_power @ Q

        logger.error(
            f"AMC: Neumann series did not converge in {_NEUMANN_MAX_ITER} iterations"
        )
        return N, "neumann_series", False