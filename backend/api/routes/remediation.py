"""Remediation routes — MDP policy, action catalogue, simulation."""
from __future__ import annotations

from copy import deepcopy
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.api.state import app_state
from backend.api.schemas import RemediationResponse, RemediationStep
from backend.mdp.action_space import get_all_actions, ACTION_MAP
from backend.mdp.simulator import Simulator

router = APIRouter()


class SimulateRequest(BaseModel):
    action_id: str
    target_asset_id: str


@router.get("/remediation")
async def get_remediation() -> RemediationResponse:
    """MDP optimal policy steps."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    policy = app_state.current_run.policy
    if policy is None:
        raise HTTPException(status_code=425, detail="MDP policy not yet computed.")

    steps = [RemediationStep(**s) for s in policy.to_dict()["steps"]]

    return RemediationResponse(
        steps=steps,
        initial_risk=policy.initial_risk,
        final_risk=policy.final_risk,
        total_risk_reduction=policy.total_risk_reduction,
        total_cost=policy.total_cost,
        total_disruption=policy.total_disruption,
        cumulative_reward=policy.cumulative_reward,
        training_episodes=policy.training_episodes,
    )


@router.get("/remediation/actions")
async def get_action_catalogue() -> list[dict]:
    """Return all available defender actions."""
    actions = get_all_actions()
    return [
        {
            "action_id": a.action_id,
            "action_type": a.action_type,
            "label": a.label,
            "description": a.description,
            "target_type": a.target_type,
            "cost": a.cost,
            "disruption": a.disruption,
            "applies_to_port": a.applies_to_port,
        }
        for a in actions
    ]


@router.post("/remediation/simulate")
async def simulate_action(req: SimulateRequest) -> dict:
    """Cumulative what-if simulation — applies on top of any prior simulations.

    The backend tracks `simulated_G` and `simulated_amc` per run. Each call
    applies the action to the current simulated state (or to the original
    graph on the first call after a reset).
    """
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    run = app_state.current_run

    if req.action_id not in ACTION_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action_id}")

    # Use the simulated graph if any prior remediations have been applied;
    # otherwise start from the original post-scan graph.
    G_input = run.simulated_G if run.simulated_G is not None else run.G
    amc_input = run.simulated_amc if run.simulated_amc is not None else run.amc

    simulator = Simulator()
    result = simulator.simulate_action(
        action_id=req.action_id,
        target_asset_id=req.target_asset_id,
        state=run.posture,
        amc=amc_input,
        G=G_input,
        network=run.network,
    )

    # Persist the new simulated state for the NEXT simulate call to build on.
    if result.succeeded:
        # The simulator returns graph_after as a dict; we need the live nx.DiGraph
        # that was built inside it. Re-build from result.graph_after dict.
        # Easier: since simulator already deep-copies internally, we need it to
        # expose the live graph. We do this via a side channel:
        run.simulated_G = simulator.last_graph_after
        run.simulated_amc = simulator.last_amc_after
        run.applied_actions.append({
            "action_id": req.action_id,
            "target": req.target_asset_id,
            "removed_edges": len(result.removed_edges),
        })

    response = result.to_dict()
    response["applied_count"] = len(run.applied_actions)
    response["applied_actions"] = run.applied_actions
    return response


@router.post("/remediation/reset")
async def reset_simulation() -> dict:
    """Clear all accumulated simulated remediations — revert to original graph."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    run = app_state.current_run
    run.simulated_G = None
    run.simulated_amc = None
    run.applied_actions = []

    return {
        "reset": True,
        "applied_count": 0,
    }