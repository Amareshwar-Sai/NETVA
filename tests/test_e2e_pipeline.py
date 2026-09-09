"""End-to-end verification test — confirms the full NETVA pipeline works."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ingestion import ingest_all
from backend.normalization import Normalizer
from backend.normalization.deduplicator import Deduplicator
from backend.graph import build_attack_graph
from backend.amc import run_amc
from backend.mdp import run_mdp


def main():
    print("=" * 60)
    print("NETVA End-to-End Pipeline Test")
    print("=" * 60)

    # Full pipeline
    print("\n[1/5] Ingesting lab data...")
    raw = ingest_all(use_lab_defaults=True)

    print("[2/5] Normalizing and deduplicating...")
    network = Normalizer().normalize(**{k: raw[k] for k in raw})
    network = Deduplicator().deduplicate(network)

    print("[3/5] Building attack graph...")
    G, paths = build_attack_graph(network)

    print("[4/5] Running AMC engine...")
    amc = run_amc(G, network)

    print("[5/5] Training Q-learner (200 episodes)...")
    policy = run_mdp(G, network, amc, episodes=200)

    # Print results
    print("\n" + "=" * 60)
    print(f"Assets: {len(network.assets)}")
    print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print(f"AMC: {amc.num_transient} transient, {amc.num_absorbing} absorbing")
    print(f"Solver: {amc.solver_method} (converged={amc.solver_converged})")
    print(f"Condition number: {amc.condition_number:.2f}")
    print(f"Max absorption prob: {amc.B.max():.4f}")
    print(f"Policy: {len(policy.steps)} steps, {policy.total_risk_reduction*100:.1f}% reduction")
    print(f"Risk: {policy.initial_risk:.4f} → {policy.final_risk:.4f}")

    if policy.steps:
        print("\nOptimal Defense Sequence:")
        for s in policy.steps:
            print(f"  Step {s.step}: {s.action_label} on {s.target_hostname} "
                  f"(Δrisk={s.risk_delta:.4f}, cost={s.cost:.2f})")

    # Assertions
    print("\n" + "-" * 60)
    errors = []

    if len(network.assets) < 3:
        errors.append(f"Expected ≥3 assets, got {len(network.assets)}")
    if G.number_of_nodes() < 6:
        errors.append(f"Expected ≥6 graph nodes, got {G.number_of_nodes()}")
    if not amc.solver_converged:
        errors.append("AMC solver did not converge")
    if amc.B.max() < 0.2:
        errors.append(f"Max absorption prob too low: {amc.B.max():.4f}")
    if len(policy.steps) < 3:
        errors.append(f"Expected ≥3 policy steps, got {len(policy.steps)}")
    if policy.total_risk_reduction < 0.5:
        errors.append(f"Expected >50% risk reduction, got {policy.total_risk_reduction*100:.1f}%")

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")
        print(f"\n{len(errors)} ASSERTION(S) FAILED")
        sys.exit(1)
    else:
        print("  ALL ASSERTIONS PASSED")
        print("=" * 60)


if __name__ == "__main__":
    main()
