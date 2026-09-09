"""IaC parser — Terraform state JSON / CloudFormation + lab-data generator."""
from __future__ import annotations

import json
from typing import Any

from backend.ingestion.models import RawIaCResource, RawIaCScan


def parse_iac(data: str | dict) -> RawIaCScan:
    """Parse Terraform state JSON or CloudFormation JSON."""
    if isinstance(data, str):
        data = json.loads(data)

    resources: list[RawIaCResource] = []

    # Terraform state format
    if "resources" in data:
        for res in data["resources"]:
            resource_type = res.get("type", "")
            for inst in res.get("instances", [{}]):
                attrs = inst.get("attributes", {})
                rid = attrs.get("id", res.get("name", ""))
                name = attrs.get("name", res.get("name", ""))
                misconfigs = _check_misconfigs(resource_type, attrs)
                connections = _extract_connections(resource_type, attrs)

                resources.append(RawIaCResource(
                    resource_type=resource_type,
                    resource_id=rid,
                    name=name,
                    properties=attrs,
                    misconfigs=misconfigs,
                    connections=connections,
                ))

    # Docker-compose / custom format
    elif "containers" in data:
        for container in data["containers"]:
            rid = container.get("id", container.get("name", ""))
            misconfigs = container.get("misconfigs", [])
            connections = container.get("connections", [])
            resources.append(RawIaCResource(
                resource_type=container.get("type", "docker_container"),
                resource_id=rid,
                name=container.get("name", ""),
                properties=container,
                misconfigs=misconfigs,
                connections=connections,
            ))

    return RawIaCScan(resources=resources)


def _check_misconfigs(resource_type: str, attrs: dict[str, Any]) -> list[str]:
    """Run misconfiguration checkers per resource type."""
    findings: list[str] = []

    if resource_type == "aws_security_group":
        for rule in attrs.get("ingress", []):
            cidrs = rule.get("cidr_blocks", [])
            if "0.0.0.0/0" in cidrs:
                port = rule.get("from_port", "any")
                findings.append(f"Ingress from 0.0.0.0/0 on port {port}")

    elif resource_type == "aws_db_instance":
        if attrs.get("publicly_accessible", False):
            findings.append("Database is publicly accessible")
        if attrs.get("master_password") in ("root", "password", "admin", ""):
            findings.append("Default or weak database password")
        if not attrs.get("storage_encrypted", False):
            findings.append("Database storage not encrypted")

    elif resource_type == "aws_s3_bucket":
        acl = attrs.get("acl", "private")
        if acl in ("public-read", "public-read-write"):
            findings.append(f"S3 bucket has public ACL: {acl}")
        if not attrs.get("server_side_encryption_configuration"):
            findings.append("S3 bucket missing server-side encryption")

    elif resource_type == "docker_container":
        if attrs.get("privileged", False):
            findings.append("Container running in privileged mode")
        caps = attrs.get("cap_add", [])
        if "NET_ADMIN" in caps:
            findings.append("Container has NET_ADMIN capability")

    return findings


def _extract_connections(resource_type: str, attrs: dict[str, Any]) -> list[str]:
    """Extract topology edges from resource attributes."""
    connections: list[str] = []
    for key in ("vpc_security_group_ids", "subnet_id", "network_id", "depends_on", "connections"):
        val = attrs.get(key)
        if isinstance(val, list):
            connections.extend(val)
        elif isinstance(val, str) and val:
            connections.append(val)
    return connections


def generate_lab_iac_json() -> str:
    """Generate lab Docker network as IaC-style JSON."""
    return json.dumps({
        "containers": [
            {
                "type": "docker_container",
                "id": "lab_webserver",
                "name": "webserver",
                "ip": "10.10.0.10",
                "subnet": "10.10.0.0/24",
                "zone": "dmz",
                "cap_add": ["NET_ADMIN"],
                "ports": [22, 80],
                "connections": ["lab_appserver", "lab_firewall"],
                "misconfigs": [
                    "Container has NET_ADMIN capability",
                    "Exposed web root with backup files",
                ],
            },
            {
                "type": "docker_container",
                "id": "lab_appserver",
                "name": "appserver",
                "ip": "10.10.0.20",
                "subnet": "10.10.0.0/24",
                "zone": "dmz",
                "cap_add": ["NET_ADMIN"],
                "ports": [22, 3000],
                "connections": ["lab_webserver", "lab_database", "lab_firewall"],
                "misconfigs": [
                    "Container has NET_ADMIN capability",
                    "SUID binary: python3",
                    "World-writable cron script",
                ],
            },
            {
                "type": "docker_container",
                "id": "lab_database",
                "name": "database",
                "ip": "10.20.0.20",
                "subnet": "10.20.0.0/24",
                "zone": "internal",
                "cap_add": ["NET_ADMIN"],
                "ports": [22, 3306],
                "connections": ["lab_firewall"],
                "misconfigs": [
                    "Container has NET_ADMIN capability",
                    "MySQL listening on 0.0.0.0",
                    "Default database password: root",
                ],
            },
            {
                "type": "docker_container",
                "id": "lab_firewall",
                "name": "firewall",
                "ip": "10.10.0.1",
                "subnet": "10.10.0.0/24",
                "zone": "dmz",
                "privileged": True,
                "cap_add": ["NET_ADMIN"],
                "ports": [22],
                "connections": ["lab_webserver", "lab_appserver", "lab_database"],
                "misconfigs": [
                    "Container running in privileged mode",
                    "Container has NET_ADMIN capability",
                    "Default FORWARD ACCEPT policy",
                ],
            },
        ]
    })
