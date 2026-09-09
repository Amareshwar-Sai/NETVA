#!/usr/bin/env python3
"""
validate_mdp_against_prism.py

Cross-validates NETVA's MDP/Q-learning defender model (backend/mdp) against
PRISM, on a REDUCED but exact scenario: a single asset (webserver), whose
posture has 9 relevant boolean flags (2 flags -- db_restricted,
db_password_changed -- never apply to a webserver, so they're fixed at
False and dropped). That's 2^9 = 512 states, small enough to fully
enumerate and hand to PRISM as an exact `mdp` model, using NETVA's REAL
TransitionFunction/RewardFunction/AssetPosture classes directly -- nothing
about the transition or reward math is reimplemented by hand here, only
enumerated and re-expressed in PRISM's syntax.

Full multi-asset validation isn't attempted: NETVA's real state space is
combinatorial across all assets (2^(11*num_assets)) and isn't tractable to
hand off to a model checker whole. This validates the *mechanics* --
transition probabilities, reward shaping, and greedy-policy correctness --
on a slice big enough to be non-trivial, not the full production state
space.

What it does:
  1. Enumerates the full 512-state single-asset MDP using NETVA's real
     backend.mdp classes (no reimplementation).
  2. Writes a PRISM `mdp` model + properties file from that enumeration.
  3. Runs PRISM with -exportstrategy to get PRISM's OPTIMAL policy
     (provably best action per state, maximizing expected cumulative
     reward over a step-bounded horizon).
  4. Separately trains NETVA's real QLearner on the exact same reduced
     scenario, and extracts its learned greedy policy.
  5. Compares: does NETVA's learned first action match PRISM's optimal
     first action from the initial (all-defenses-off) state? How close is
     NETVA's achieved cumulative reward to PRISM's provably-optimal value?

IMPORTANT CAVEAT (read before trusting a mismatch as a bug):
NETVA's Q-learning uses a discount factor (gamma=0.90) during TRAINING.
PRISM's standard R{}=?[C<=k] property is UNDISCOUNTED cumulative reward.
These are not identical objective functions, so don't expect exact numeric
equality -- expect NETVA's learned policy to be a close, not necessarily
identical, approximation of PRISM's undiscounted optimum. Large,
systematic gaps (not just a different but comparably-good action) are
what's actually worth investigating.

Usage:
    python3 validate_mdp_against_prism.py
    python3 validate_mdp_against_prism.py --asset-ip 10.10.0.10 --steps 15
"""
from __future__ import annotations

import argparse
import itertools
import re
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

NETVA_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(NETVA_ROOT))

OUT_DIR = Path(__file__).resolve().parent
PM_FILE = OUT_DIR / "netva_mdp.pm"
PCTL_FILE = OUT_DIR / "netva_mdp.pctl"
STRATEGY_PCTL_FILE = OUT_DIR / "netva_mdp_strategy.pctl"
STRATEGY_FILE = OUT_DIR / "prism_strategy.txt"
PRISM_LOG = OUT_DIR / "prism_mdp_raw_output.txt"
STRATEGY_LOG = OUT_DIR / "prism_strategy_raw_output.txt"

# The 9 posture flags relevant to a webserver-type asset (see
# get_applicable_actions('webserver') + _apply_effect mapping -- verified
# directly against backend/mdp/action_space.py + transitions.py).
FLAGS = [
    "is_patched", "is_isolated", "service_stopped", "ssh_hardened",
    "files_hardened", "backup_removed", "cgi_disabled", "keys_revoked",
    "weak_accounts_disabled",
]


def build_reduced_network(asset_ip: str):
    """A NormalizedNetwork containing just the one target asset, built from
    NETVA's real pipeline (so criticality etc. are real, not made up)."""
    import os
    os.environ.setdefault("NETVA_SIMULATE", "1")
    from backend.ingestion import ingest_all
    from backend.normalization import Normalizer, Deduplicator, schema

    raw = ingest_all(use_lab_defaults=True)
    network = Normalizer().normalize(**{k: raw[k] for k in raw})
    network = Deduplicator().deduplicate(network)

    asset = network.assets[asset_ip]
    reduced = schema.NormalizedNetwork(assets={asset_ip: asset}, edges=[])
    return reduced, asset


def enumerate_mdp(asset_ip: str, network) -> dict:
    """Full enumeration of the reduced single-asset MDP using NETVA's real
    mdp classes. Returns a dict describing every (state, action) -> outcomes
    for direct translation into PRISM, plus the same data structured for
    driving NETVA's own QLearner later."""
    from backend.mdp.action_space import get_applicable_actions
    from backend.mdp.state_space import AssetPosture, DefenderState
    from backend.mdp.transitions import TransitionFunction, _SUCCESS_PROB
    from backend.mdp.reward import RewardFunction

    actions = get_applicable_actions(network.assets[asset_ip].asset_type)
    tf = TransitionFunction()
    rf = RewardFunction()

    def make_posture(bits: tuple[bool, ...]) -> AssetPosture:
        p = AssetPosture()
        for flag, val in zip(FLAGS, bits):
            setattr(p, flag, val)
        return p

    def make_state(bits: tuple[bool, ...]) -> DefenderState:
        posture = make_posture(bits)
        s = DefenderState(asset_postures={asset_ip: posture})
        s.overall_risk = posture.risk_reduction_factor()  # single asset, no segmentation
        return s

    all_bits = list(itertools.product([False, True], repeat=len(FLAGS)))
    table = {}  # bits -> {action_id: {"succ_prob", "reward_succ", "bits_succ", "reward_fail"}}
    terminal_bits = set()  # bits where DefenderState.is_terminal is True (risk < 0.15)

    for bits in all_bits:
        state = make_state(bits)
        if state.is_terminal:
            terminal_bits.add(bits)
        row = {}
        for action in actions:
            succ_prob = _SUCCESS_PROB.get(action.action_type, 0.90)

            # Deterministic "if it succeeds" outcome (bypass the coin flip
            # inside TransitionFunction.apply(), call the pure effect fn
            # directly -- exactly what apply() does when succeeded=True).
            next_state = state.copy_with()
            next_state.asset_postures = {k: deepcopy(v) for k, v in state.asset_postures.items()}
            tf._apply_effect(next_state, action, asset_ip)
            next_state.overall_risk = tf._estimate_risk(next_state)

            reward_succ = rf.compute(state, action, next_state, asset_ip, True, network)
            reward_fail = rf.compute(state, action, state, asset_ip, False, network)

            next_bits = tuple(getattr(next_state.asset_postures[asset_ip], f) for f in FLAGS)

            row[action.action_id] = {
                "succ_prob": succ_prob,
                "bits_succ": next_bits,
                "reward_succ": reward_succ,
                "reward_fail": reward_fail,
                "action_type": action.action_type,
            }
        table[bits] = row

    return {"table": table, "actions": actions, "all_bits": all_bits, "terminal_bits": terminal_bits}


def write_prism_mdp(enum_data: dict, steps: int) -> None:
    table = enum_data["table"]
    actions = enum_data["actions"]

    lines = [
        "mdp",
        "",
        "// Auto-generated by validate_mdp_against_prism.py from a full",
        "// enumeration of NETVA's real TransitionFunction/RewardFunction",
        "// on a reduced single-asset (webserver) scenario. 2^9 = 512 states.",
        "",
        "module netva_mdp",
    ]
    for f in FLAGS:
        lines.append(f"    {f} : bool init false;")
    lines.append("")

    # Determine, per action, which flag(s) it sets True on success -- using
    # the all-False starting state's outcome (safe: _apply_effect only ever
    # sets flags True on success, verified against transitions.py).
    baseline_bits = tuple(False for _ in FLAGS)
    for action in actions:
        aid = action.action_id
        entry = table[baseline_bits][aid]
        succ_prob = entry["succ_prob"]
        touched = [f for f, before, after in zip(FLAGS, baseline_bits, entry["bits_succ"]) if after and not before]

        updates_succ = " & ".join(f"({f}'=true)" for f in touched) or None
        if updates_succ is None:
            # Action has no posture effect (e.g. enable_auditd) -- self-loop
            # on "success" (no change) and on "failure" alike.
            rhs = f"1.0 : ({FLAGS[0]}'={FLAGS[0]})"  # no-op transition (trivial identity update)
        else:
            fail_updates = " & ".join(f"({f}'={f})" for f in FLAGS)  # identity (no-op) update
            # NOTE: do NOT wrap fail_updates in an extra outer "(...)" -- each
            # individual (f'=f) assignment already has its own parens, and
            # PRISM's grammar rejects a further-wrapped conjunction (this was
            # the exact cause of a "Syntax error (\"(\"...)" on a real run).
            rhs = f"{succ_prob:.6f} : {updates_succ} + {1 - succ_prob:.6f} : {fail_updates}"

        lines.append(f"    [{aid}] true -> {rhs};")

    lines += ["endmodule", ""]

    # Reward structure: state-action reward = the EXPECTED immediate reward
    # for taking this action in this state (probability-weighted average of
    # the success/fail reward). This matches E[cumulative reward] correctly
    # via linearity of expectation, though it is UNDISCOUNTED (see the
    # module docstring's caveat about gamma).
    #
    # PRISM's Rmax=?[C<=k] requires a NON-NEGATIVE reward structure (a hard
    # constraint of its value-iteration algorithm for MDPs) -- but NETVA's
    # real reward function legitimately produces negative values (failure
    # penalty, no-op penalty, isolate penalty). Fix: shift every reward by a
    # constant REWARD_SHIFT so the minimum becomes >=0. Since the horizon is
    # a FIXED k steps (every path accumulates exactly k rewards, no early
    # termination is modeled here), this shift is exactly invertible:
    #   true_optimal_value = prism_result - REWARD_SHIFT * k
    # main() performs that correction after parsing PRISM's result.
    all_rewards = [
        entry["succ_prob"] * entry["reward_succ"] + (1 - entry["succ_prob"]) * entry["reward_fail"]
        for row in table.values() for entry in row.values()
    ]
    reward_shift = -min(all_rewards) + 0.01 if all_rewards else 0.0

    lines.append('rewards "defender_reward"')
    for action in actions:
        aid = action.action_id
        # Build a formula: sum over flag-combinations of the guard-specific
        # expected reward. Since reward depends on the CURRENT state (via
        # risk_reduction computed from current posture), we need one line
        # per distinct current-state bucket that yields a different reward.
        # To keep this exact (not approximated), emit one reward line per
        # reachable state for this action.
        for bits in enum_data["all_bits"]:
            entry = table[bits][aid]
            guard = " & ".join(f"{f}" if b else f"!{f}" for f, b in zip(FLAGS, bits))
            expected_r = entry["succ_prob"] * entry["reward_succ"] + (1 - entry["succ_prob"]) * entry["reward_fail"]
            shifted_r = expected_r + reward_shift
            lines.append(f"    [{aid}] {guard} : {shifted_r:.6f};")
    lines.append("endrewards")
    lines.append("")

    # "done" label: exactly NETVA's own is_terminal condition (overall_risk
    # < 0.15), enumerated explicitly per matching state rather than via a
    # PRISM formula/ternary expression -- safer, and consistent with how the
    # reward lines above are built (explicit per-state guards, not formulas).
    terminal_bits = enum_data["terminal_bits"]
    if terminal_bits:
        done_guards = [
            "(" + " & ".join(f"{f}" if b else f"!{f}" for f, b in zip(FLAGS, bits)) + ")"
            for bits in terminal_bits
        ]
        lines.append(f'label "done" = {" | ".join(done_guards)};')
    else:
        lines.append('label "done" = false;')
    lines.append("")

    PM_FILE.write_text("\n".join(lines))

    props = [
        f'Rmax=? [ C<={steps} ]',
    ]
    PCTL_FILE.write_text("\n".join(props) + "\n")

    # Separate properties file for the strategy-exportable query. PRISM does
    # NOT support -exportstrat for step-bounded C<=k properties (the optimal
    # action there depends on remaining steps, not just current state, so
    # there's no single stationary "state -> action" table to export).
    #
    # An F-based REWARD property (Rmax=?[F "done"]) doesn't work either: the
    # reward shift needed to satisfy PRISM's non-negativity requirement turns
    # every action into a non-negative payoff, so the "optimal" policy can
    # rack up infinite reward by simply never reaching "done" and looping
    # forever collecting small positive rewards (confirmed: a real run
    # returned Result: Infinity, target=343/inf=169 -- PRISM correctly
    # solving the now ill-posed question, not a bug in PRISM).
    #
    # Fix: use a pure PROBABILITY reachability property instead. It doesn't
    # touch the reward structure at all, so the shift/infinite-loop issue
    # cannot arise, and it matches PRISM's own documented -exportstrat
    # examples (Pmax=?[F "goal"]) exactly.
    STRATEGY_PCTL_FILE.write_text('Pmax=? [ F "done" ]\n')

    return reward_shift


def run_prism_mdp() -> str:
    if shutil.which("prism") is None:
        print("\n[ERROR] `prism` not found on PATH.\n")
        sys.exit(1)
    result = subprocess.run(
        ["prism", str(PM_FILE), str(PCTL_FILE),
         "-exportstrat", str(STRATEGY_FILE)],
        capture_output=True, text=True, timeout=600,
    )
    output = result.stdout + "\n" + result.stderr
    PRISM_LOG.write_text(output)
    return output


def run_prism_strategy_query() -> str:
    """Separate run using the F-based "done" reachability property, which
    DOES support -exportstrat (unlike the step-bounded C<=k property used
    for the headline value comparison -- see write_prism_mdp's comment)."""
    result = subprocess.run(
        ["prism", str(PM_FILE), str(STRATEGY_PCTL_FILE),
         "-exportstrat", str(STRATEGY_FILE)],
        capture_output=True, text=True, timeout=600,
    )
    output = result.stdout + "\n" + result.stderr
    STRATEGY_LOG.write_text(output)
    return output


def train_netva_qlearner(asset_ip: str, network, episodes: int, steps: int):
    """Train NETVA's REAL QLearner on the exact same reduced scenario."""
    from backend.mdp.q_learner import QLearner
    from backend.amc.results import AMCResults

    # QLearner needs an AMCResults for StateSpaceBuilder.build_initial(), but
    # only uses it to seed initial risk -- give it a trivial empty one and
    # override the initial state's risk to match our reduced scenario
    # (all-defenses-off => risk_reduction_factor() == 1.0).
    fake_amc = AMCResults()
    ql = QLearner(network, fake_amc, episodes=episodes)
    ql.initial_state.overall_risk = 1.0

    # Restrict action_target_pairs to just our asset's applicable actions
    # (QLearner would otherwise also include the 2 firewall/segment actions,
    # which don't apply to our single-asset reduced network at all).
    from backend.mdp.action_space import get_applicable_actions
    applicable = get_applicable_actions(network.assets[asset_ip].asset_type)
    ql.action_target_pairs = [(a, asset_ip) for a in applicable]

    ql.train()
    policy = ql.get_optimal_policy(max_steps=steps)
    return ql, policy


def parse_prism_strategy(path: Path) -> dict:
    """PRISM's -exportstrat action-list format is one line per state:
        (val1,val2,...)=action_name
    (confirmed against a real PRISM 4.10.1 run -- note it's "=", not ":" as
    the manual's abbreviated example showed). Returns
    {state_bits_tuple: action_name}."""
    if not path.exists():
        return {}
    text = path.read_text()
    result = {}
    for line in text.splitlines():
        m = re.match(r"^\(([^)]*)\)\s*[:=]\s*(\S+)", line.strip())
        if m:
            raw_vals = [v.strip() for v in m.group(1).split(",")]
            # Booleans may print as true/false or 1/0 depending on version --
            # handle both.
            vals = tuple(v in ("true", "1") for v in raw_vals)
            result[vals] = m.group(2)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset-ip", default="10.10.0.10", help="Asset to validate (default: lab webserver)")
    parser.add_argument("--steps", type=int, default=3,
                         help="Step horizon for both PRISM and NETVA. NOTE: PRISM's Rmax=?[C<=k] "
                              "always runs the FULL k steps -- there's no early-stop-on-terminal "
                              "modeled (unlike NETVA's actual training loop, which stops once "
                              "risk drops below 0.15). Keep this small and close to NETVA's typical "
                              "episode length for this scenario, or the totals become hard to "
                              "compare directly; the per-step action comparison is more robust "
                              "than the raw cumulative-reward totals when horizons diverge.")
    parser.add_argument("--episodes", type=int, default=2000, help="Q-learning training episodes")
    args = parser.parse_args()

    print("[1/5] Building reduced single-asset network...")
    network, asset = build_reduced_network(args.asset_ip)
    print(f"      -> {args.asset_ip} ({asset.asset_type}, criticality={asset.criticality})")

    print("[2/5] Enumerating full single-asset MDP (2^{} = {} states) via NETVA's real classes...".format(
        len(FLAGS), 2 ** len(FLAGS)))
    enum_data = enumerate_mdp(args.asset_ip, network)
    print(f"      -> {len(enum_data['actions'])} applicable actions")

    print("[3/5] Writing PRISM MDP model + properties...")
    reward_shift = write_prism_mdp(enum_data, args.steps)
    print(f"      -> {PM_FILE}\n      -> {PCTL_FILE}")
    print(f"      -> reward shift applied: +{reward_shift:.6f} per step "
          f"(PRISM requires non-negative rewards; corrected back out below)")

    print("[4/5] Running PRISM (Rmax with strategy export)...")
    raw = run_prism_mdp()
    print(f"      -> raw output saved to {PRISM_LOG}")
    result_match = re.search(r"Result:\s*([-\d.Ee+]+)", raw)
    prism_shifted_value = float(result_match.group(1)) if result_match else None
    prism_optimal_value = (
        prism_shifted_value - reward_shift * args.steps if prism_shifted_value is not None else None
    )
    print(f"      -> PRISM raw (shifted) result: {prism_shifted_value}")
    print(f"      -> PRISM optimal expected reward (undiscounted, {args.steps} FORCED steps, "
          f"shift corrected): {prism_optimal_value}")

    print(f"[5/5] Training NETVA's real QLearner ({args.episodes} episodes) on the same scenario...")
    ql, policy = train_netva_qlearner(args.asset_ip, network, args.episodes, args.steps)
    netva_cumulative = sum(s["reward"] for s in policy)
    print(f"      -> NETVA achieved cumulative reward over {len(policy)} steps: {netva_cumulative:.4f}")

    print("\n" + "=" * 90)
    print("NETVA Q-learning vs PRISM optimal -- comparison")
    print("=" * 90)
    print(f"PRISM provably-optimal expected cumulative reward (undiscounted, {args.steps}-step horizon): "
          f"{prism_optimal_value}")
    print(f"NETVA Q-learning achieved cumulative reward (greedy rollout, {len(policy)} steps):          "
          f"{netva_cumulative:.4f}")
    if prism_optimal_value:
        gap = prism_optimal_value - netva_cumulative
        pct = 100 * gap / abs(prism_optimal_value) if prism_optimal_value else float("nan")
        print(f"Gap: {gap:.4f} ({pct:.1f}% of PRISM's optimum)")
        print("(Remember: PRISM's value is undiscounted; NETVA trained with gamma=0.90 -- some gap is expected.)")

    print("\nNETVA's learned policy (first few steps):")
    for s in policy[:5]:
        print(f"  step {s['step']}: {s['action_id']:<28} reward={s['reward']:.4f}  "
              f"risk {s['risk_before']:.4f} -> {s['risk_after']:.4f}")

    print("\n[Strategy] Running PRISM's Pmax query (F \"done\") for strategy export...")
    print("           (probability-maximizing, not reward-maximizing -- see script comments")
    print("           for why the reward-based version returns Infinity)")
    strategy_raw = run_prism_strategy_query()
    print(f"      -> raw output saved to {STRATEGY_LOG}")

    strategy = parse_prism_strategy(STRATEGY_FILE)
    if strategy:
        baseline = tuple(False for _ in FLAGS)
        prism_first_action = strategy.get(baseline)
        print(f"\nPRISM's action from the initial state, maximizing P(eventually reach 'done'): "
              f"{prism_first_action}")
        netva_first_action = policy[0]["action_id"] if policy else None
        print(f"NETVA's first action from the initial state:                                  "
              f"{netva_first_action}")
        if prism_first_action and netva_first_action:
            if prism_first_action == netva_first_action:
                print("MATCH -- both agree on the best first move.")
            else:
                print("DIFFERENT -- not necessarily a bug (this PRISM query optimizes probability")
                print("of termination, not reward, so a difference doesn't by itself indicate NETVA")
                print("is wrong -- but worth checking against the Q-value undertraining note above.")
    else:
        print(f"\n[!] Could not parse PRISM's strategy file ({STRATEGY_FILE}).")
        print(f"    Check {STRATEGY_LOG} for what PRISM actually printed for the strategy run --")
        print("    if the file still wasn't created, PRISM may need a different flag/version")
        print("    for strategy export on this property type; paste me that log and I'll adjust.")

    print("=" * 90)


if __name__ == "__main__":
    main()