"""Graph routes — attack graph data and asset details."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.api.state import app_state
from backend.api.schemas import (
    GraphResponse, GraphNode, GraphEdge,
    AssetListResponse, AssetDetail, VulnSummary,
)
from backend.graph.attack_graph import graph_to_dict

router = APIRouter()


@router.get("/graph")
async def get_graph() -> GraphResponse:
    """Full attack graph — nodes + edges."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete. Run /scan first.")

    G = app_state.current_run.G
    data = graph_to_dict(G)

    nodes = [GraphNode(**{k: v for k, v in n.items() if k in GraphNode.model_fields}) for n in data["nodes"]]
    edges = [GraphEdge(**{k: v for k, v in e.items() if k in GraphEdge.model_fields}) for e in data["edges"]]

    return GraphResponse(nodes=nodes, edges=edges)


@router.get("/graph/assets")
async def get_assets() -> AssetListResponse:
    """Per-asset vulnerability details."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    network = app_state.current_run.network
    assets = []

    for ip, asset in network.assets.items():
        vulns = [
            VulnSummary(
                vuln_id=v.vuln_id,
                name=v.name,
                severity=v.severity.value,
                cvss=v.cvss,
                exploit_available=v.exploit_available,
                port=v.port,
            )
            for v in asset.vulns
        ]

        flags = {
            "ssh_root_login_enabled": asset.ssh_root_login_enabled,
            "has_weak_ssh_password": asset.has_weak_ssh_password,
            "has_world_writable_files": asset.has_world_writable_files,
            "has_exposed_backup_files": asset.has_exposed_backup_files,
            "has_default_credentials": asset.has_default_credentials,
            "has_suid_binary": asset.has_suid_binary,
            "has_command_injection": asset.has_command_injection,
        }

        assets.append(AssetDetail(
            asset_id=asset.asset_id,
            hostname=asset.hostname,
            ip=asset.ip,
            asset_type=asset.asset_type,
            zone=asset.zone.value,
            criticality=asset.criticality,
            risk_score=asset.risk_score,
            open_ports=asset.open_ports,
            vuln_count=asset.vuln_count,
            max_cvss=asset.max_cvss,
            vulns=vulns,
            flags=flags,
        ))

    return AssetListResponse(assets=assets)
