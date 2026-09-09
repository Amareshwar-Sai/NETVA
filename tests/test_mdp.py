"""Tests for MDP + Q-learning."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ingestion import ingest_all
from backend.normalization import Normalizer, Deduplicator
from backend.graph import build_attack_graph
from backend.amc import run_amc
from backend.mdp import run_mdp
from backend.mdp.action_space import get_all_actions, get_applicable_actions, ACTION_MAP


@pytest.fixture
def lab_pipeline():
    raw = ingest_all(use_lab_defaults=True)
    network = Normalizer().normalize(**{k: raw[k] for k in raw})
    network = Deduplicator().deduplicate(network)
    G, paths = build_attack_graph(network)
    amc = run_amc(G, network)
    return G, network, amc


class TestActionSpace:
    def test_all_actions(self):
        actions = get_all_actions()
        assert len(actions) >= 20

    def test_action_map(self):
        assert "revoke_ssh_keys" in ACTION_MAP
        assert "patch_os" in ACTION_MAP
        assert "segment_dmz_internal" in ACTION_MAP

    def test_applicable_actions(self):
        web_actions = get_applicable_actions("webserver")
        assert any(a.action_id == "patch_web_server" for a in web_actions)
        db_actions = get_applicable_actions("database")
        assert any(a.action_id == "change_db_password" for a in db_actions)


class TestMDP:
    def test_run_mdp(self, lab_pipeline):
        G, network, amc = lab_pipeline
        policy = run_mdp(G, network, amc, episodes=100)

        assert len(policy.steps) >= 2
        assert policy.total_risk_reduction > 0.3
        assert policy.initial_risk > policy.final_risk

    def test_policy_steps_ordered(self, lab_pipeline):
        G, network, amc = lab_pipeline
        policy = run_mdp(G, network, amc, episodes=100)

        # Steps should have decreasing risk
        for i in range(len(policy.steps) - 1):
            assert policy.steps[i].risk_before >= policy.steps[i + 1].risk_before

    def test_policy_to_dict(self, lab_pipeline):
        G, network, amc = lab_pipeline
        policy = run_mdp(G, network, amc, episodes=50)
        d = policy.to_dict()

        assert "steps" in d
        assert "initial_risk" in d
        assert "total_risk_reduction" in d
        assert d["training_episodes"] == 50
