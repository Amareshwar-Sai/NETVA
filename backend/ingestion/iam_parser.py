"""IAM / privilege relationship parser + lab-data generator."""
from __future__ import annotations

import json
from typing import Any

from backend.ingestion.models import RawPrivilegeLink, RawIAMData


def parse_iam(data: str | dict) -> RawIAMData:
    """Parse privilege/trust relationships from JSON."""
    if isinstance(data, str):
        data = json.loads(data)

    links: list[RawPrivilegeLink] = []

    for link in data.get("links", []):
        links.append(RawPrivilegeLink(
            src_host=link.get("src_host", ""),
            dst_host=link.get("dst_host", ""),
            link_type=link.get("link_type", ""),
            username=link.get("username", ""),
            privilege=link.get("privilege", "user"),
            description=link.get("description", ""),
        ))

    # Parse sudo rules if present
    for sudo in data.get("sudo_rules", []):
        links.append(RawPrivilegeLink(
            src_host=sudo.get("host", ""),
            dst_host=sudo.get("host", ""),
            link_type="sudo",
            username=sudo.get("user", ""),
            privilege="root" if sudo.get("nopasswd", False) else "sudo",
            description=sudo.get("rule", ""),
        ))

    # Parse credential reuse hints
    for cred in data.get("credential_reuse", []):
        for dst in cred.get("reused_on", []):
            links.append(RawPrivilegeLink(
                src_host=cred.get("origin_host", ""),
                dst_host=dst,
                link_type="cred_reuse",
                username=cred.get("username", ""),
                privilege=cred.get("privilege", "user"),
                description=f"Credential reuse: {cred.get('username', '')}",
            ))

    return RawIAMData(links=links)


def generate_lab_iam_json() -> str:
    """Generate lab IAM data — SSH trust from webserver to appserver at root."""
    return json.dumps({
        "links": [
            {
                "src_host": "10.10.0.10",
                "dst_host": "10.10.0.20",
                "link_type": "ssh_key",
                "username": "root",
                "privilege": "root",
                "description": "Webserver root SSH key trusted on appserver (authorized_keys)",
            },
            {
                "src_host": "10.10.0.20",
                "dst_host": "10.20.0.20",
                "link_type": "password",
                "username": "root",
                "privilege": "root",
                "description": "Appserver has MySQL root password in bash_history",
            },
        ],
        "sudo_rules": [
            {
                "host": "10.10.0.20",
                "user": "appuser",
                "nopasswd": True,
                "rule": "appuser ALL=(ALL) NOPASSWD: /usr/bin/python3, /opt/app/cleanup.sh",
            },
        ],
        "credential_reuse": [
            {
                "origin_host": "10.10.0.10",
                "username": "admin",
                "privilege": "user",
                "reused_on": ["10.10.0.20"],
            },
        ],
    })
