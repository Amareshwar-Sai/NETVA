"""CMDB parser — reads asset inventory and criticality from a CMDB JSON export.

In production deployments this would query a real CMDB (ServiceNow, Atlassian
JSM, custom asset registry, etc.). For our lab demonstration we read from a
static JSON file that mirrors the shape of a real CMDB export.

The CMDB is the authoritative source for:
- Asset name, owner, environment
- Business function (what does this asset do for the business?)
- Data classification (public, internal, pii-restricted, etc.)
- Compliance scope (GDPR, PCI-DSS, SOC2, HIPAA, etc.)
- Criticality (0-1) — when present, this OVERRIDES type-based heuristics

If an asset is not in the CMDB (e.g. newly discovered, unmanaged), the
normalizer falls back to type-based criticality inference.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CMDBAsset:
    """Per-asset metadata sourced from CMDB."""
    ip: str = ""
    asset_name: str = ""
    asset_type: str = ""
    owner: str = ""
    environment: str = ""
    business_function: str = ""
    data_classification: str = ""
    compliance_scope: list[str] = field(default_factory=list)
    criticality: Optional[float] = None
    criticality_rationale: str = ""
    last_reviewed: str = ""


@dataclass
class CMDBData:
    """Container for parsed CMDB output."""
    assets: dict[str, CMDBAsset] = field(default_factory=dict)
    source: str = ""
    version: str = ""
    last_synced: str = ""

    def get(self, ip: str) -> Optional[CMDBAsset]:
        """Look up an asset by IP. Returns None if not in CMDB."""
        return self.assets.get(ip)


def parse_cmdb(data: str | dict) -> CMDBData:
    """Parse CMDB JSON content."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return CMDBData()

    if not isinstance(data, dict):
        return CMDBData()

    metadata = data.get("metadata", {})
    raw_assets = data.get("assets", {})

    cmdb = CMDBData(
        source=metadata.get("source", "unknown"),
        version=metadata.get("version", ""),
        last_synced=metadata.get("last_synced", ""),
    )

    for ip, info in raw_assets.items():
        if not isinstance(info, dict):
            continue
        crit = info.get("criticality")
        if crit is not None:
            try:
                crit = float(crit)
                crit = max(0.0, min(1.0, crit))  # clamp to [0,1]
            except (TypeError, ValueError):
                crit = None

        cmdb.assets[ip] = CMDBAsset(
            ip=ip,
            asset_name=info.get("asset_name", ""),
            asset_type=info.get("asset_type", ""),
            owner=info.get("owner", ""),
            environment=info.get("environment", ""),
            business_function=info.get("business_function", ""),
            data_classification=info.get("data_classification", ""),
            compliance_scope=list(info.get("compliance_scope", [])),
            criticality=crit,
            criticality_rationale=info.get("criticality_rationale", ""),
            last_reviewed=info.get("last_reviewed", ""),
        )

    return cmdb


def load_lab_cmdb() -> CMDBData:
    """Load the lab CMDB fixture from disk if available."""
    cmdb_path = Path(__file__).resolve().parents[2] / "lab" / "cmdb.json"
    if not cmdb_path.is_file():
        return CMDBData()
    try:
        return parse_cmdb(cmdb_path.read_text())
    except Exception:
        return CMDBData()


def generate_lab_cmdb_json() -> str:
    """Return synthetic lab CMDB data for demos when the file isn't on disk.

    Kept in sync with lab/cmdb.json so the synthetic fallback produces the same
    rich metadata as the real CMDB fixture.
    """
    return json.dumps({
        "metadata": {
            "source": "lab-cmdb-synthetic",
            "version": "1.0",
            "last_synced": "2026-04-26T12:00:00Z",
        },
        "assets": {
            "10.10.0.10": {
                "asset_name": "webserver-prod-01",
                "asset_type": "webserver",
                "owner": "platform-team",
                "environment": "production",
                "business_function": "customer-facing-marketing-site",
                "data_classification": "public",
                "compliance_scope": [],
                "criticality": 0.55,
                "criticality_rationale": "Public-facing site with no sensitive data; reputational risk only",
                "last_reviewed": "2026-03-15",
            },
            "10.10.0.20": {
                "asset_name": "appserver-prod-01",
                "asset_type": "appserver",
                "owner": "application-team",
                "environment": "production",
                "business_function": "order-processing-api",
                "data_classification": "internal",
                "compliance_scope": ["SOC2"],
                "criticality": 0.80,
                "criticality_rationale": "Processes business transactions; only authorized cross-zone path to database",
                "last_reviewed": "2026-03-20",
            },
            "10.20.0.20": {
                "asset_name": "database-prod-01",
                "asset_type": "database",
                "owner": "data-team",
                "environment": "production",
                "business_function": "customer-records-and-transactions",
                "data_classification": "pii-restricted",
                "compliance_scope": ["GDPR", "PCI-DSS", "SOC2"],
                "criticality": 0.98,
                "criticality_rationale": "Crown jewel — stores customer PII, payment data, and transaction history",
                "last_reviewed": "2026-04-01",
            },
            "10.10.0.2": {
                "asset_name": "perimeter-firewall-01",
                "asset_type": "firewall",
                "owner": "network-team",
                "environment": "production",
                "business_function": "zone-segmentation-enforcement",
                "data_classification": "internal",
                "compliance_scope": ["SOC2", "PCI-DSS"],
                "criticality": 0.90,
                "criticality_rationale": "Single point of zone enforcement; compromise enables full lateral movement",
                "last_reviewed": "2026-03-10",
            },
        },
    })