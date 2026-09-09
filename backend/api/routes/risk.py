"""Risk routes — AMC metrics, paths, dashboard summary."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.api.state import app_state
from backend.api.schemas import (
    RiskResponse, StateMetric, CriticalPath, RiskSummary,
)

router = APIRouter()


@router.get("/risk")
async def get_risk() -> RiskResponse:
    """Full AMC metrics for all states."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    amc = app_state.current_run.amc
    G = app_state.current_run.G
    metrics = []
    for sid in amc.transient_states:
        hostname = ""
        if G and sid in G.nodes:
            hostname = G.nodes[sid].get("hostname", "")
        metrics.append(StateMetric(
            state_id=sid,
            hostname=hostname,
            absorption_prob=amc.absorption_prob(sid),
            expected_steps=amc.expected_steps(sid),
            visit_frequency=amc.visit_frequency(sid),
            risk_score=amc.node_risk.get(sid, 0.0),
        ))

    paths_data = app_state.current_run.paths or []
    paths = [CriticalPath(**p) for p in paths_data]

    return RiskResponse(
        state_metrics=metrics,
        critical_paths=paths,
        solver_method=amc.solver_method,
        solver_converged=amc.solver_converged,
        condition_number=amc.condition_number,
    )


@router.get("/risk/paths")
async def get_risk_paths() -> list[CriticalPath]:
    """Critical attack paths ranked by probability."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    paths_data = app_state.current_run.paths or []
    return [CriticalPath(**p) for p in paths_data]


@router.get("/risk/summary")
async def get_risk_summary() -> RiskSummary:
    """Dashboard header cards."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    run = app_state.current_run
    network = run.network
    amc = run.amc
    G = run.G

    total_vulns = sum(a.vuln_count for a in network.assets.values())
    critical_vulns = sum(a.critical_vuln_count for a in network.assets.values())
    high_vulns = sum(a.high_vuln_count for a in network.assets.values())

    risk_scores = [v for v in amc.node_risk.values()]
    max_risk = max(risk_scores) if risk_scores else 0.0
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    crown_jewels = sum(1 for _, d in G.nodes(data=True) if d.get("is_absorbing"))
    attack_paths = len(run.paths)

    max_absorb = float(amc.B.max()) if amc.B is not None and amc.B.size > 0 else 0.0

    return RiskSummary(
        total_assets=len(network.assets),
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        max_risk_score=round(max_risk, 4),
        avg_risk_score=round(avg_risk, 4),
        max_absorption_prob=round(max_absorb, 4),
        crown_jewels=crown_jewels,
        attack_paths=attack_paths,
    )
