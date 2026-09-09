"""Tests for AMC engine."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ingestion import ingest_all
from backend.normalization import Normalizer, Deduplicator
from backend.graph import build_attack_graph
from backend.amc import run_amc


@pytest.fixture
def lab_network():
    raw = ingest_all(use_lab_defaults=True)
    network = Normalizer().normalize(**{k: raw[k] for k in raw})
    network = Deduplicator().deduplicate(network)
    return network


@pytest.fixture
def lab_graph(lab_network):
    G, paths = build_attack_graph(lab_network)
    return G, paths, lab_network


class TestAMC:
    def test_run_amc(self, lab_graph):
        G, paths, network = lab_graph
        amc = run_amc(G, network)

        assert amc.solver_converged
        assert amc.num_transient >= 5
        assert amc.num_absorbing >= 1
        assert amc.N is not None
        assert amc.B is not None
        assert amc.t_vec is not None

    def test_absorption_probabilities(self, lab_graph):
        G, paths, network = lab_graph
        amc = run_amc(G, network)

        # All transient states should eventually be absorbed
        for sid in amc.transient_states:
            prob = amc.absorption_prob(sid)
            assert prob >= 0.0
            assert prob <= 1.01  # allow small floating point

    def test_risk_scores(self, lab_graph):
        G, paths, network = lab_graph
        amc = run_amc(G, network)

        assert len(amc.node_risk) > 0
        # Absorbing states should have risk 1.0
        for sid in amc.absorbing_states:
            assert amc.node_risk[sid] == 1.0

    def test_expected_steps(self, lab_graph):
        G, paths, network = lab_graph
        amc = run_amc(G, network)

        for sid in amc.transient_states:
            steps = amc.expected_steps(sid)
            assert steps >= 1.0
            assert steps < 100  # reasonable bound

    def test_to_dict(self, lab_graph):
        G, paths, network = lab_graph
        amc = run_amc(G, network)
        d = amc.to_dict()

        assert "transient_states" in d
        assert "absorbing_states" in d
        assert "state_metrics" in d
        assert len(d["state_metrics"]) == amc.num_transient
