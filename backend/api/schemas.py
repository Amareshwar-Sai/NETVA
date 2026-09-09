"""Pydantic models for API requests and responses."""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


# ── Scan ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    use_lab_defaults: bool = True
    nessus_xml: Optional[str] = None
    nmap_xml: Optional[str] = None
    iac_json: Optional[str] = None
    acl_text: Optional[str] = None
    iam_json: Optional[str] = None
    episodes: int = 300


class ScanStatus(BaseModel):
    job_id: str
    status: str            # pending / running / complete / error
    stage: str = ""
    progress: float = 0.0
    message: str = ""


# ── Graph ───────────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    state_id: str = ""
    host_id: str = ""
    privilege: str = "none"
    is_absorbing: bool = False
    is_entry: bool = False
    node_role: str = "host"  # host | entry | defense
    asset_type: str = ""
    criticality: float = 0.0
    risk_score: float = 0.0
    zone: str = ""
    label: str = ""
    ip: str = ""
    hostname: str = ""
    open_ports: list[int] = []
    vuln_count: int = 0
    max_cvss: float = 0.0
    has_exploit: bool = False
    centrality_composite: float = 0.0
    termination_reason: str = ""
    description: str = ""


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: float = 0.0
    vuln_id: str = ""
    cvss: float = 0.0
    mechanism: str = ""
    requires_port: int = 0
    exploit_available: bool = False
    edge_type: str = ""


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ── Risk / AMC ──────────────────────────────────────────────────────────────

class StateMetric(BaseModel):
    state_id: str
    hostname: str = ""
    absorption_prob: float
    expected_steps: float
    visit_frequency: float
    risk_score: float


class CriticalPath(BaseModel):
    path: list[str]
    probability: float
    length: int
    entry: str
    target: str
    edges: list[dict] = []


class RiskResponse(BaseModel):
    state_metrics: list[StateMetric]
    critical_paths: list[CriticalPath] = []
    solver_method: str = ""
    solver_converged: bool = True
    condition_number: float = 0.0


class RiskSummary(BaseModel):
    total_assets: int = 0
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    max_risk_score: float = 0.0
    avg_risk_score: float = 0.0
    max_absorption_prob: float = 0.0
    crown_jewels: int = 0
    attack_paths: int = 0


# ── Remediation ─────────────────────────────────────────────────────────────

class RemediationStep(BaseModel):
    step: int
    action_id: str
    action_label: str
    action_type: str
    target_asset_id: str
    target_hostname: str = ""
    cost: float = 0.0
    disruption: float = 0.0
    reward: float = 0.0
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_delta: float = 0.0
    q_value: float = 0.0
    description: str = ""


class RemediationResponse(BaseModel):
    steps: list[RemediationStep]
    initial_risk: float
    final_risk: float
    total_risk_reduction: float
    total_cost: float
    total_disruption: float
    cumulative_reward: float
    training_episodes: int = 0


# ── Execute ─────────────────────────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    action_id: str
    target_asset_id: str
    dry_run: bool = True


class ExecuteResponse(BaseModel):
    action_id: str
    target_asset_id: str
    success: bool
    dry_run: bool
    ssh_output: str = ""
    simulation: dict = {}
    error: str = ""


# ── Assets ──────────────────────────────────────────────────────────────────

class VulnSummary(BaseModel):
    vuln_id: str
    name: str
    severity: str
    cvss: float
    exploit_available: bool = False
    port: int = 0


class AssetDetail(BaseModel):
    asset_id: str
    hostname: str
    ip: str
    asset_type: str
    zone: str
    criticality: float
    risk_score: float
    open_ports: list[int]
    vuln_count: int
    max_cvss: float
    vulns: list[VulnSummary]
    flags: dict[str, bool] = {}


class AssetListResponse(BaseModel):
    assets: list[AssetDetail]
