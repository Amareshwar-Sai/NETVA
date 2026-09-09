"""NETVA — FastAPI application entry point.

19 routes:
  GET  /                    Root info
  GET  /health              Ready check
  POST /scan                Trigger pipeline
  GET  /scan/{job_id}       Poll status
  GET  /scan/latest/status  Latest status
  GET  /graph               Full attack graph
  GET  /graph/assets        Per-asset detail
  GET  /risk                Full AMC metrics
  GET  /risk/paths          Critical attack paths
  GET  /risk/summary        Dashboard header cards
  GET  /remediation         MDP policy steps
  GET  /remediation/actions Action catalogue
  POST /remediation/simulate What-if preview
  POST /execute             Real SSH or dry_run
  GET  /report/pdf          Download full PDF report
  WS   /ws/live             WebSocket progress
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, WebSocket

from backend.api.middleware import setup_middleware
from backend.api.ws import ws_endpoint
from backend.api.routes import scan, graph, risk, remediation, execute, report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="NETVA",
    description="Network-Level Vulnerability Assessment — AMC-MDP Hybrid Framework",
    version="1.0.0",
)

# Middleware
setup_middleware(app)

# Routes
app.include_router(scan.router, tags=["Scan"])
app.include_router(graph.router, tags=["Graph"])
app.include_router(risk.router, tags=["Risk"])
app.include_router(remediation.router, tags=["Remediation"])
app.include_router(execute.router, tags=["Execute"])
app.include_router(report.router, tags=["Report"])


@app.get("/")
async def root():
    return {
        "name": "NETVA",
        "version": "1.0.0",
        "description": "Network-Level Vulnerability Assessment — AMC-MDP Hybrid Framework",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    from backend.api.state import app_state
    return {
        "status": "ready" if app_state.ready else "idle",
        "has_run": app_state.current_run is not None,
    }


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await ws_endpoint(websocket)
