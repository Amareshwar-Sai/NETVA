"""Raw input dataclasses — before normalization.

These represent the direct output of each parser, before any deduplication,
enrichment, or schema unification.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── Nessus ──────────────────────────────────────────────────────────────────

@dataclass
class RawVuln:
    plugin_id: str = ""
    plugin_name: str = ""
    severity: str = "0"          # "0"-"4"
    cve: Optional[str] = None
    cvss_base: float = 0.0
    cvss3_base: float = 0.0
    exploit_available: bool = False
    description: str = ""
    solution: str = ""
    plugin_output: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""


@dataclass
class RawNessusHost:
    ip: str = ""
    hostname: str = ""
    os: str = ""
    vulns: list[RawVuln] = field(default_factory=list)


@dataclass
class RawNessusScan:
    hosts: list[RawNessusHost] = field(default_factory=list)


# ── Nmap ────────────────────────────────────────────────────────────────────

@dataclass
class RawPort:
    port: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class RawNmapHost:
    ip: str = ""
    hostname: str = ""
    os: str = ""
    ports: list[RawPort] = field(default_factory=list)
    status: str = "up"


@dataclass
class RawNmapScan:
    hosts: list[RawNmapHost] = field(default_factory=list)


# ── IaC (Terraform / CloudFormation) ────────────────────────────────────────

@dataclass
class RawIaCResource:
    resource_type: str = ""      # e.g. "aws_security_group"
    resource_id: str = ""
    name: str = ""
    properties: dict = field(default_factory=dict)
    misconfigs: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)  # resource_ids it connects to


@dataclass
class RawIaCScan:
    resources: list[RawIaCResource] = field(default_factory=list)


# ── ACL / Firewall ──────────────────────────────────────────────────────────

@dataclass
class RawACLRule:
    chain: str = "FORWARD"       # INPUT / FORWARD / OUTPUT
    action: str = "ACCEPT"       # ACCEPT / DROP / REJECT
    protocol: str = "all"
    src: str = "0.0.0.0/0"
    dst: str = "0.0.0.0/0"
    port: Optional[int] = None
    direction: str = "in"        # in / out / forward
    comment: str = ""


@dataclass
class RawACLConfig:
    rules: list[RawACLRule] = field(default_factory=list)
    default_policy: str = "ACCEPT"   # overall default policy


# ── IAM / Privilege ─────────────────────────────────────────────────────────

@dataclass
class RawPrivilegeLink:
    src_host: str = ""
    dst_host: str = ""
    link_type: str = ""          # "ssh_key", "password", "sudo", "cred_reuse"
    username: str = ""
    privilege: str = "user"      # "user", "root", "admin"
    description: str = ""


@dataclass
class RawIAMData:
    links: list[RawPrivilegeLink] = field(default_factory=list)
