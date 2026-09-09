"""Unified schema — canonical dataclasses used throughout the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ──────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> float:
        return {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
            Severity.INFO: 0.0,
        }[self]


class Zone(Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    PROD = "prod"
    CLOUD = "cloud"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class PrivilegeLevel(Enum):
    NONE = "none"
    USER = "user"
    SUDO = "sudo"
    ADMIN = "admin"
    ROOT = "root"

    @property
    def numeric(self) -> float:
        return {
            PrivilegeLevel.NONE: 0.0,
            PrivilegeLevel.USER: 0.25,
            PrivilegeLevel.SUDO: 0.50,
            PrivilegeLevel.ADMIN: 0.75,
            PrivilegeLevel.ROOT: 1.0,
        }[self]


# ── Core Dataclasses ───────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """A deduplicated, normalised vulnerability finding."""
    vuln_id: str = ""
    cve: Optional[str] = None
    name: str = ""
    description: str = ""
    solution: str = ""
    severity: Severity = Severity.INFO
    cvss: float = 0.0
    cvss3: float = 0.0
    epss: float = 0.0
    exploit_available: bool = False
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    plugin_id: str = ""
    plugin_output: str = ""


@dataclass
class NetworkEdge:
    """Directed connection between two assets."""
    src_id: str = ""
    dst_id: str = ""
    edge_type: str = "network"
    permitted_by: str = ""
    ports: list[int] = field(default_factory=list)
    protocol: str = "tcp"
    privilege_level: PrivilegeLevel = PrivilegeLevel.NONE
    link_type: str = ""
    description: str = ""


@dataclass
class NetworkAsset:
    """Full asset record after normalisation."""
    asset_id: str = ""
    hostname: str = ""
    ip: str = ""
    os: str = ""
    asset_type: str = "server"
    zone: Zone = Zone.UNKNOWN
    criticality: float = 0.5
    risk_score: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    vulns: list[Vulnerability] = field(default_factory=list)

    # ── CMDB metadata (populated when asset is in CMDB) ─────────────────────
    cmdb_managed: bool = False
    cmdb_owner: str = ""
    cmdb_environment: str = ""
    cmdb_business_function: str = ""
    cmdb_data_classification: str = ""
    cmdb_compliance_scope: list[str] = field(default_factory=list)
    cmdb_criticality_rationale: str = ""

    # ── Misconfiguration flags ──────────────────────────────────────────────
    ssh_root_login_enabled: bool = False
    has_weak_ssh_password: bool = False
    has_world_writable_files: bool = False
    has_exposed_backup_files: bool = False
    has_default_credentials: bool = False
    has_suid_binary: bool = False
    has_command_injection: bool = False
    has_exposed_git: bool = False
    has_cgi_enabled: bool = False
    has_phpinfo: bool = False
    db_listens_all_interfaces: bool = False
    has_pii_data: bool = False

    @property
    def vuln_count(self) -> int:
        return len(self.vulns)

    @property
    def max_cvss(self) -> float:
        if not self.vulns:
            return 0.0
        return max(v.cvss for v in self.vulns)

    @property
    def has_exploit(self) -> bool:
        return any(v.exploit_available for v in self.vulns)

    @property
    def critical_vuln_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == Severity.CRITICAL)

    @property
    def high_vuln_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == Severity.HIGH)


@dataclass
class NormalizedNetwork:
    """Container for the fully normalised network model."""
    assets: dict[str, NetworkAsset] = field(default_factory=dict)
    edges: list[NetworkEdge] = field(default_factory=list)

    @property
    def asset_list(self) -> list[NetworkAsset]:
        return list(self.assets.values())

    def get_asset(self, ip: str) -> Optional[NetworkAsset]:
        return self.assets.get(ip)

    def get_edges_from(self, src_id: str) -> list[NetworkEdge]:
        return [e for e in self.edges if e.src_id == src_id]

    def get_edges_to(self, dst_id: str) -> list[NetworkEdge]:
        return [e for e in self.edges if e.dst_id == dst_id]