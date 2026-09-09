"""Segment executor — firewall segmentation rules."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Execute segmentation via iptables on the firewall."""
    outputs = []

    if action.action_id == "segment_dmz_internal":
        commands = [
            "iptables -I FORWARD -s 10.10.0.0/24 -d 10.20.0.0/24 -j DROP",
            "iptables -A FORWARD -s 10.10.0.0/24 -d 10.20.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ]
        for cmd in commands:
            out = client.run_sudo(cmd)
            outputs.append(f"$ {cmd}\n{out}")
        outputs.append("DMZ → Internal segmentation applied")

    elif action.action_id == "segment_internal_prod":
        commands = [
            "iptables -I FORWARD -s 10.20.0.0/24 -d 10.30.0.0/24 -j DROP",
            "iptables -A FORWARD -s 10.20.0.0/24 -d 10.30.0.0/24 -p tcp --dport 3306 -j ACCEPT",
        ]
        for cmd in commands:
            out = client.run_sudo(cmd)
            outputs.append(f"$ {cmd}\n{out}")
        outputs.append("Internal → Prod segmentation applied (MySQL-only)")

    return "\n".join(outputs) if outputs else f"Segment action {action.action_id} completed"
