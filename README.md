# NETVA

Network Vulnerability Assessment Tool — a full-stack cybersecurity research
system implementing a hybrid Absorbing Markov Chain (AMC) + Markov Decision
Process (MDP) framework for attack-graph risk analysis and automated
defensive policy generation.

## Architecture

- Docker lab network simulating a vulnerable enterprise (webserver,
  appserver, database, firewall containers)
- Ingestion parsers (Nessus/Nmap/IaC/ACL/IAM) and a normalization layer
- MulVAL-based attack graph with NetworkX and D3 centrality
- AMC engine with LU/SVD/Neumann solver strategies
- MDP state space with Q-learning (ε-greedy) and policy extraction
- FastAPI backend + SSH executor layer (Paramiko) for automated remediation
- React/Redux/D3 frontend dashboard

## Setup

```bash
cp .env.example .env   # fill in real lab credentials -- .env is gitignored
pip install -r backend/requirements.txt --break-system-packages
```

`NETVA_SIMULATE=1` bypasses the SSH executor for offline testing/dev.

## Independent validation

NETVA's core math and learned policies are cross-checked against
independent, authoritative sources rather than trusted at face value —
using [PRISM](https://www.prismmodelchecker.org), a peer-reviewed
probabilistic model checker, plus exact dynamic programming where PRISM's
state space becomes intractable. All validation code and raw results live
under `validation/`.

### ✅ AMC layer — exact match against PRISM

The AMC engine (`backend/amc/`) computes, for every attack-graph state: the
probability of eventual compromise of each target asset, and the expected
number of attacker moves until compromise — via the standard fundamental-
matrix method (`N = (I - Q)⁻¹`, `B = N·R`, `t = N·1`).

Validated three independent ways on the real lab topology: NETVA's own
solver (LU decomposition), a fresh independent matrix inversion, and PRISM
solving the identical Markov chain via its own iterative method. **All
three agree to within floating-point/solver tolerance (≤1e-5) across every
reachable state.**

```
--- Absorption probability into: 10.20.0.20::root ---
state                  NETVA P(absorb)   PRISM P(absorb)   diff        status
10.10.0.2::user        0.7371            0.7371            0.000003    PASS
10.10.0.10::user       0.7339            0.7339            0.000003    PASS
...
OVERALL: PASS -- all values agree within tolerance (0.001).
```

Reproduce: `cd validation/prism && python3 validate_against_prism.py`

**Scope note:** this validates the AMC's *linear algebra*, not whether the
underlying transition-probability formula (`backend/amc/transition_probs.py`)
or the MulVAL-derived attack graph itself accurately reflect real-world
attacker behaviour — those are modelling choices, not correctness bugs.

### 🔍 MDP / Q-learning layer — mechanics validated, real undertraining found

Rather than a single pass/fail, this validation surfaced three concrete,
evidence-backed findings:

**1. Translation is exact, Q-values can be badly undertrained.** On a
reduced single-asset scenario (512-state posture-MDP, built by enumerating
NETVA's *real* `TransitionFunction`/`RewardFunction` — nothing
reimplemented), PRISM's optimal policy matched a hand-derived analytical
reward exactly. But the same asset's Q-learning, at the framework's
original 2,000-episode default, converged `isolate_host`'s learned
Q-value to `0.75`-`0.81` against a true value of `1.41` — roughly half.
At 50,000 episodes it converged correctly (`1.39`-`1.42`) in every trial.

Reproduce: `cd validation/prism_mdp && python3 validate_mdp_against_prism.py`

**2. The full-pipeline headline metric is more robust than the raw
Q-values suggest.** Re-running the actual production pipeline
(`run_mdp`) at 200/2,000/20,000/50,000 episodes, averaged over multiple
seeds, shows the reported risk-reduction figure staying in an **84–88%**
band throughout — greedy policy extraction turns out to be fairly
forgiving of individual Q-value noise as long as relative action ranking
is roughly right.

**3. A real, fixable reward-shaping issue.** A properly joint ceiling
analysis (accounting for the two network-wide segmentation actions, which
an earlier per-asset-only ceiling missed) revealed that
`revoke_ssh_keys`'s flat `+0.20` "lateral movement break" bonus
(`backend/mdp/reward.py`) doesn't scale with current risk — once
segmentation has already cut risk substantially, that flat bonus becomes
several times larger than the action's *actual* risk-reduction
contribution, creating a local-optimum trap for any myopic policy. NETVA's
real TD-learned Q-learning (85.9%) actually outperforms a naive
perfect-information greedy oracle (70.7%) *because* multi-step
bootstrapping partially sees past this trap — a genuine point in favor of
the algorithm design, and a concrete, identified fix for future work
(make the bonus proportional to `risk_reduction`, not flat).

Reproduce: `cd validation/prism_ceiling && python3 cost_aware_ceiling.py`
and `python3 joint_greedy_ceiling.py`

**Honest scope note:** no formally-proven optimal ceiling exists yet for
the full joint multi-asset problem — the combined state space
(`2^(11 × num_assets)`) is intractable for exact enumeration, and naive
greedy has been shown to be an invalid upper bound (it can underperform
the real system). Establishing a tight formal ceiling is a natural next
step, not a solved problem.

## Security

Before pushing or sharing this repo:

```bash
bash scripts/security_scan.sh
```

Checks for tracked credential files, secret-like string patterns,
hardcoded password defaults, and confirms `.env` is gitignored. Lab SSH
passwords have **no source-code default** — they must be set in a local
`.env` (see `.env.example`), which is gitignored and never committed.
`lab/seed_vulns.sh` intentionally contains obviously-fake credential
strings (e.g. `sk-fake-api-key-...`) — these are planted test fixtures for
NETVA's own vulnerability scanner to detect in the local Docker lab, not
real secrets.

For a full history scan (not just current files), run
[gitleaks](https://github.com/gitleaks/gitleaks) or
[trufflehog](https://github.com/trufflesecurity/trufflehog) once before
your first push.