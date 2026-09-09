"""Scan routes — trigger pipeline, poll status."""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, BackgroundTasks

from backend.api.schemas import ScanRequest, ScanStatus
from backend.api.state import app_state, PipelineRun
from backend.api.ws import broadcast

from backend.ingestion import ingest_all
from backend.normalization import Normalizer, Deduplicator
from backend.graph import build_attack_graph
from backend.amc import run_amc
from backend.mdp import run_mdp
from backend.mdp.state_space import StateSpaceBuilder

logger = logging.getLogger(__name__)

router = APIRouter()


async def _update(run: PipelineRun, stage: str, progress: float, message: str) -> None:
    """Update run state and broadcast via WebSocket."""
    run.stage = stage
    run.progress = progress
    run.message = message
    run.status = "running"
    await broadcast({
        "type": "progress",
        "job_id": run.job_id,
        "stage": stage,
        "progress": progress,
        "message": message,
    })


async def _run_pipeline(run: PipelineRun, req: ScanRequest) -> None:
    """Execute the full NETVA pipeline as a background task."""
    loop = asyncio.get_event_loop()
    try:
        # Stage 1: Ingestion
        await _update(run, "ingestion", 5.0, "Ingesting scan data...")
        raw = await loop.run_in_executor(None, lambda: ingest_all(
            use_lab_defaults=req.use_lab_defaults,
            nessus_xml=req.nessus_xml,
            nmap_xml=req.nmap_xml,
            iac_json=req.iac_json,
            acl_text=req.acl_text,
            iam_json=req.iam_json,
        ))

        # Stage 2: Normalization
        await _update(run, "normalization", 20.0, "Normalizing and deduplicating...")
        network = await loop.run_in_executor(None, lambda: Normalizer().normalize(
            **{k: raw[k] for k in raw}
        ))
        network = await loop.run_in_executor(None, lambda: Deduplicator().deduplicate(network))
        run.network = network

        await _update(run, "assets", 35.0, f"Found {len(network.assets)} assets")

        # Stage 3: Attack Graph
        await _update(run, "graph_building", 40.0, "Building attack graph...")
        G, paths = await loop.run_in_executor(None, lambda: build_attack_graph(network))
        run.G = G
        run.paths = paths

        await _update(run, "graph_complete", 55.0,
                      f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Stage 4: AMC
        await _update(run, "amc_solving", 60.0, "Solving Absorbing Markov Chain...")
        amc = await loop.run_in_executor(None, lambda: run_amc(G, network))
        run.amc = amc

        await _update(run, "amc_complete", 75.0,
                      f"AMC: {amc.num_transient} transient, {amc.num_absorbing} absorbing")

        # Stage 5: MDP + Q-Learning
        episodes = req.episodes
        await _update(run, "mdp_training", 80.0, f"Training Q-learner ({episodes} episodes)...")
        policy = await loop.run_in_executor(None, lambda: run_mdp(G, network, amc, episodes=episodes))
        run.policy = policy

        # Build initial posture
        run.posture = StateSpaceBuilder().build_initial(network, amc)

        # Done
        run.status = "complete"
        run.progress = 100.0
        run.stage = "done"
        run.message = f"Pipeline complete. {len(policy.steps)} remediation steps, {policy.total_risk_reduction*100:.1f}% risk reduction"

        await broadcast({
            "type": "complete",
            "job_id": run.job_id,
            "message": run.message,
        })

        logger.info(f"Pipeline {run.job_id} complete: {run.message}")

    except Exception as e:
        logger.exception(f"Pipeline {run.job_id} failed")
        run.status = "error"
        run.error = str(e)
        run.message = f"Error: {e}"
        await broadcast({
            "type": "error",
            "job_id": run.job_id,
            "error": str(e),
        })


@router.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> ScanStatus:
    """Trigger the full pipeline. Returns immediately with job_id."""
    run = app_state.new_run()
    run.status = "running"
    background_tasks.add_task(_run_pipeline, run, req)
    return ScanStatus(
        job_id=run.job_id,
        status="running",
        stage="starting",
        progress=0.0,
        message="Pipeline started",
    )


@router.get("/scan/{job_id}")
async def get_scan_status(job_id: str) -> ScanStatus:
    """Poll pipeline status."""
    run = app_state.get_run(job_id)
    if run is None:
        return ScanStatus(job_id=job_id, status="not_found", message="Unknown job ID")
    return ScanStatus(
        job_id=run.job_id,
        status=run.status,
        stage=run.stage,
        progress=run.progress,
        message=run.message,
    )


@router.get("/scan/latest/status")
async def get_latest_status() -> ScanStatus:
    """Get status of the most recent pipeline run."""
    run = app_state.current_run
    if run is None:
        return ScanStatus(job_id="", status="idle", message="No scan has been run yet")
    return ScanStatus(
        job_id=run.job_id,
        status=run.status,
        stage=run.stage,
        progress=run.progress,
        message=run.message,
    )
