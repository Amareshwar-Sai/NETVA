"""Execute routes — real SSH remediation or dry-run."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException

from backend.api.schemas import ExecuteRequest, ExecuteResponse
from backend.api.state import app_state
from backend.api.ws import broadcast
from backend.config import get_settings
from backend.mdp.action_space import ACTION_MAP
from backend.mdp.transitions import TransitionFunction
from backend.mdp.simulator import Simulator
from backend.normalization.schema import NetworkAsset

logger = logging.getLogger(__name__)

router = APIRouter()

# Action type → executor module mapping
_EXECUTOR_MAP = {
    "patch": "backend.executor.actions.patch",
    "isolate": "backend.executor.actions.isolate",
    "block_port": "backend.executor.actions.block_port",
    "harden": "backend.executor.actions.stop_service",
    "revoke": "backend.executor.actions.revoke_creds",
    "segment": "backend.executor.actions.segment",
    "monitor": "backend.executor.actions.stop_service",
}


def _resolve_creds(ip: str) -> dict:
    """Map IP to SSH credentials."""
    settings = get_settings()
    cred_map = {
        "10.10.0.10": {
            "host": settings.lab_webserver_host,
            "port": settings.lab_webserver_port,
            "username": settings.lab_webserver_user,
            "password": settings.lab_webserver_pass,
        },
        "10.10.0.20": {
            "host": settings.lab_appserver_host,
            "port": settings.lab_appserver_port,
            "username": settings.lab_appserver_user,
            "password": settings.lab_appserver_pass,
        },
        "10.20.0.20": {
            "host": settings.lab_database_host,
            "port": settings.lab_database_port,
            "username": settings.lab_database_user,
            "password": settings.lab_database_pass,
        },
        "10.10.0.1": {
            "host": settings.lab_firewall_host,
            "port": settings.lab_firewall_port,
            "username": settings.lab_firewall_user,
            "password": settings.lab_firewall_pass,
        },
    }
    return cred_map.get(ip, {})


async def _execute_ssh(action, asset, network) -> str:
    """Execute remediation via SSH using Paramiko."""
    creds = _resolve_creds(asset.ip)
    if not creds:
        return f"No SSH credentials configured for {asset.ip}"

    try:
        from backend.executor.ssh_client import SSHClient
        import importlib

        with SSHClient(
            host=creds["host"],
            port=creds["port"],
            username=creds["username"],
            password=creds["password"],
        ) as client:
            # Dispatch to correct executor module
            module_name = _EXECUTOR_MAP.get(action.action_type, "")
            if module_name:
                mod = importlib.import_module(module_name)
                output = mod.run(client, action, asset)
                return output
            else:
                # Fallback: run the executor_cmd directly
                if action.executor_cmd:
                    return client.run_sudo(action.executor_cmd)
                return "No executor available for this action type"

    except Exception as e:
        logger.error(f"SSH execution failed: {e}")
        return f"SSH Error: {e}"


@router.post("/execute")
async def execute_action(req: ExecuteRequest) -> ExecuteResponse:
    """Execute a remediation action (real SSH or dry-run)."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    run = app_state.current_run
    action = ACTION_MAP.get(req.action_id)
    if action is None:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action_id}")

    asset = run.network.assets.get(req.target_asset_id)
    if asset is None:
        raise HTTPException(status_code=400, detail=f"Unknown asset: {req.target_asset_id}")

    # Always simulate first
    simulator = Simulator()
    sim_result = simulator.simulate_action(
        action_id=req.action_id,
        target_asset_id=req.target_asset_id,
        state=run.posture,
        amc=run.amc,
        G=run.G,
        network=run.network,
    )

    ssh_output = ""
    success = True

    if not req.dry_run:
        # Real SSH execution
        ssh_output = await _execute_ssh(action, asset, run.network)
        success = "Error" not in ssh_output

        if success:
            # Update posture
            tf = TransitionFunction()
            new_posture, _ = tf.apply(run.posture, action, req.target_asset_id)
            run.posture = new_posture

            # Broadcast graph update
            await broadcast({
                "type": "graph_update",
                "action_id": req.action_id,
                "target_asset_id": req.target_asset_id,
            })

    return ExecuteResponse(
        action_id=req.action_id,
        target_asset_id=req.target_asset_id,
        success=success,
        dry_run=req.dry_run,
        ssh_output=ssh_output,
        simulation=sim_result.to_dict(),
    )
