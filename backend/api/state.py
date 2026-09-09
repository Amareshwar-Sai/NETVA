"""Pipeline run state — module-level singleton shared by all routes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import uuid

import networkx as nx

from backend.normalization.schema import NormalizedNetwork
from backend.amc.results import AMCResults
from backend.mdp.policy import PolicyResult
from backend.mdp.state_space import DefenderState


@dataclass
class PipelineRun:
    """Holds the state of a single pipeline execution."""
    job_id: str = ""
    status: str = "pending"
    stage: str = ""
    progress: float = 0.0
    message: str = ""
    error: str = ""

    # Pipeline results
    network: Optional[NormalizedNetwork] = None
    G: Optional[nx.DiGraph] = None
    paths: list[dict] = field(default_factory=list)
    amc: Optional[AMCResults] = None
    policy: Optional[PolicyResult] = None
    posture: Optional[DefenderState] = None

    # Live simulation state — accumulated remediations
    simulated_G: Optional[nx.DiGraph] = None
    simulated_amc: Optional[AMCResults] = None
    applied_actions: list[dict] = field(default_factory=list)


class AppState:
    """Module-level application state."""

    def __init__(self):
        self.current_run: Optional[PipelineRun] = None
        self.run_history: list[PipelineRun] = []

    @property
    def ready(self) -> bool:
        """True when current_run is complete with a valid graph."""
        return (
            self.current_run is not None
            and self.current_run.status == "complete"
            and self.current_run.G is not None
        )

    def new_run(self) -> PipelineRun:
        """Create a new pipeline run."""
        run = PipelineRun(job_id=str(uuid.uuid4())[:8])
        self.current_run = run
        self.run_history.append(run)
        return run

    def get_run(self, job_id: str) -> Optional[PipelineRun]:
        for run in self.run_history:
            if run.job_id == job_id:
                return run
        return None


# Module-level singleton
app_state = AppState()
