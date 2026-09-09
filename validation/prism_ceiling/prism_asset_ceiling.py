#!/usr/bin/env python3
"""
prism_asset_ceiling.py

Computes, for EVERY asset in the network, the provably-optimal minimum
achievable risk_reduction_factor within a fixed action budget -- using
PRISM to solve each asset's reduced posture-MDP exactly (Rmin=?[I=k]).
Combines the per-asset ceilings (simple average, matching NETVA's own
_estimate_risk() formula) into a network-wide "best possible" risk figure,
and compares it against what NETVA's actual trained policy achieves.

This answers "how much better could we realistically do" with a real,
provable number instead of guesswork -- it's the natural extension of the
single-asset AMC/MDP validation already done, generalized across all
assets and reusing the same "enumerate the real backend classes, hand the
exact result to PRISM" methodology throughout.

Design notes:
  - Reward here is a STATE reward equal to the asset's own
    AssetPosture.risk_reduction_factor() -- NOT NETVA's compound
    cost/disruption-weighted reward. This deliberately asks a different,
    simpler question: "how low can this asset's risk factor go", ignoring
    the cost/disruption tradeoffs that make NETVA's Q-learning intentionally
    conservative. It's a ceiling on achievable RISK REDUCTION, not a
    recommendation to actually take these actions for free.
  - Because risk_reduction_factor() is always in [0, 1], this reward is
    already non-negative -- no reward-shift trick needed here (unlike the
    single-asset Q-learning validation, whose reward could go negative).
  - Only the flags each asset type's applicable actions can actually touch
    are modeled (verified directly against action_space.py / transitions.py
    for each asset type) -- untouched flags stay permanently False and
    contribute a fixed 1.0 multiplier, so dropping them from the state
    space doesn't change the computed risk factor at all.

Usage:
    python3 prism_asset_ceiling.py
    python3 prism_asset_ceiling.py --steps 3
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import itertools
from copy import deepcopy
from pathlib import Path

NETVA_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(NETVA_ROOT))

OUT_DIR = Path(__file__).resolve().parent
# Matches AssetPosture's field order exactly (backend/mdp/state_space.py)
ALL_FLAGS = [
    "is_patched", "ssh_hardened", "service_stopped", "is_isolated",
    "keys_revoked", "files_hardened", "db_restricted", "backup_removed",
    "cgi_disabled", "weak_accounts_disabled", "db_password_changed",
]


def get_relevant_flags(asset_type: str) -> list[str]:
    """Flags actually touched by this asset type's applicable actions
    (verified against action_space.py's effect map, per-asset-type)."""
    from backend.mdp.action_space import get_applicable_actions
    from backend.mdp.transitions import TransitionFunction
    from backend.mdp.state_space import AssetPosture

    tf = TransitionFunction()
    actions = get_applicable_actions(asset_type)
    touched = []
    for action in actions:
        p = AssetPosture()
        fake_state = type("S", (), {
            "asset_postures": {"x": p}, "dmz_segmented": False, "prod_segmented": False,
        })()
        tf._apply_effect(fake_state, action, "x")
        d = p.to_dict()
        for f in ALL_FLAGS:
            if d.get(f) and f not in touched:
                touched.append(f)
    return touched, actions


def enumerate_asset_mdp(asset_ip: str, asset_type: str) -> dict:
    """Full enumeration of one asset's posture-MDP transitions (success
    probability + resulting flags per action), using NETVA's real
    TransitionFunction._apply_effect directly."""
    from backend.mdp.transitions import TransitionFunction, _SUCCESS_PROB
    from backend.mdp.state_space import AssetPosture

    flags, actions = get_relevant_flags(asset_type)
    tf = TransitionFunction()

    def make_posture(bits):
        p = AssetPosture()
        for flag, val in zip(flags, bits):
            setattr(p, flag, val)
        return p

    all_bits = list(itertools.product([False, True], repeat=len(flags)))
    table = {}
    for bits in all_bits:
        posture = make_posture(bits)
        row = {}
        for action in actions:
            succ_prob = _SUCCESS_PROB.get(action.action_type, 0.90)
            fake_state = type("S", (), {
                "asset_postures": {asset_ip: deepcopy(posture)},
                "dmz_segmented": False, "prod_segmented": False,
            })()
            tf._apply_effect(fake_state, action, asset_ip)
            next_bits = tuple(getattr(fake_state.asset_postures[asset_ip], f) for f in flags)
            row[action.action_id] = {"succ_prob": succ_prob, "bits_succ": next_bits}
        table[bits] = row
        table[bits]["_risk_factor"] = posture.risk_reduction_factor()

    return {"table": table, "actions": actions, "flags": flags, "all_bits": all_bits}


def write_prism_ceiling_mdp(enum_data: dict, pm_file: Path, pctl_file: Path, steps: int):
    table, actions, flags = enum_data["table"], enum_data["actions"], enum_data["flags"]
    all_bits = enum_data["all_bits"]

    lines = [
        "mdp", "",
        "// Auto-generated by prism_asset_ceiling.py",
        "", "module asset_ceiling",
    ]
    for f in flags:
        lines.append(f"    {f} : bool init false;")
    lines.append("")

    baseline_bits = tuple(False for _ in flags)
    for action in actions:
        aid = action.action_id
        entry = table[baseline_bits][aid]
        succ_prob = entry["succ_prob"]
        touched = [f for f, before, after in zip(flags, baseline_bits, entry["bits_succ"]) if after and not before]
        updates_succ = " & ".join(f"({f}'=true)" for f in touched)
        if not updates_succ:
            rhs = f"1.0 : ({flags[0]}'={flags[0]})"
        else:
            fail_updates = " & ".join(f"({f}'={f})" for f in flags)
            rhs = f"{succ_prob:.6f} : {updates_succ} + {1 - succ_prob:.6f} : {fail_updates}"
        lines.append(f"    [{aid}] true -> {rhs};")
    lines += ["endmodule", ""]

    # State reward = this posture's own risk_reduction_factor -- already in
    # [0,1], no shift needed.
    lines.append('rewards "risk_factor"')
    for bits in all_bits:
        guard = " & ".join(f"{f}" if b else f"!{f}" for f, b in zip(flags, bits))
        lines.append(f"    {guard} : {table[bits]['_risk_factor']:.6f};")
    lines.append("endrewards")
    lines.append("")

    pm_file.write_text("\n".join(lines))
    # I=k: instantaneous reward (the risk factor) AT exactly step k, under
    # the policy that MINIMIZES it -- "how low can we push this asset's
    # risk in k actions, optimally".
    pctl_file.write_text(f'Rmin=? [ I={steps} ]\n')


def run_prism(pm_file: Path, pctl_file: Path, log_file: Path) -> str:
    if shutil.which("prism") is None:
        print("\n[ERROR] `prism` not found on PATH.\n")
        sys.exit(1)
    result = subprocess.run(
        ["prism", str(pm_file), str(pctl_file)],
        capture_output=True, text=True, timeout=600,
    )
    output = result.stdout + "\n" + result.stderr
    log_file.write_text(output)
    return output


def parse_result(raw: str) -> float | None:
    m = re.search(r"Result:\s*([-\d.Ee+]+)", raw)
    return float(m.group(1)) if m else None


def build_reduced_network():
    import os
    os.environ.setdefault("NETVA_SIMULATE", "1")
    from backend.ingestion import ingest_all
    from backend.normalization import Normalizer, Deduplicator
    raw = ingest_all(use_lab_defaults=True)
    network = Normalizer().normalize(**{k: raw[k] for k in raw})
    network = Deduplicator().deduplicate(network)
    return network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=3,
                         help="Action budget per asset (default 3 -- matches roughly what "
                              "NETVA's actual policies allocate per asset across the full run)")
    args = parser.parse_args()

    network = build_reduced_network()
    print(f"[1/2] Found {len(network.assets)} assets: "
          f"{[(ip, a.asset_type) for ip, a in network.assets.items()]}")

    ceilings = {}
    for ip, asset in network.assets.items():
        print(f"\n[2/2] Asset {ip} ({asset.asset_type})...")
        enum_data = enumerate_asset_mdp(ip, asset.asset_type)
        print(f"      {len(enum_data['flags'])} flags, {len(enum_data['actions'])} actions, "
              f"{len(enum_data['all_bits'])} states")

        safe_ip = ip.replace(".", "_")
        pm_file = OUT_DIR / f"ceiling_{safe_ip}.pm"
        pctl_file = OUT_DIR / f"ceiling_{safe_ip}.pctl"
        log_file = OUT_DIR / f"ceiling_{safe_ip}_raw.txt"
        write_prism_ceiling_mdp(enum_data, pm_file, pctl_file, args.steps)

        raw = run_prism(pm_file, pctl_file, log_file)
        value = parse_result(raw)
        print(f"      -> PRISM minimum achievable risk_reduction_factor in {args.steps} steps: {value}")
        if value is None:
            print(f"      [!] Could not parse result -- check {log_file}")
        ceilings[ip] = value

    print("\n" + "=" * 90)
    print("Per-asset provable ceilings")
    print("=" * 90)
    valid = [(ip, v) for ip, v in ceilings.items() if v is not None]
    for ip, v in valid:
        print(f"  {ip:<16} ({network.assets[ip].asset_type:<12}) "
              f"min achievable risk_reduction_factor = {v:.4f}")

    if valid:
        network_ceiling = sum(v for _, v in valid) / len(valid)
        print(f"\nNetwork-wide provable ceiling (simple average, matches NETVA's own "
              f"_estimate_risk() formula): {network_ceiling:.4f}")
        print(f"  -> best POSSIBLE risk reduction under NETVA's action set/success "
              f"probabilities, {args.steps} actions/asset: {(1 - network_ceiling) * 100:.1f}%")
        print("\nCompare this against NETVA's actual achieved risk reduction to see how much")
        print("headroom is left -- the gap (if any) is attributable to policy quality, not to")
        print("a hard limit of the action set itself.")
    print("=" * 90)


if __name__ == "__main__":
    main()