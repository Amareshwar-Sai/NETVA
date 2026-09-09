"""Isolate executor — network isolation via iptables."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Execute isolation action via SSH."""
    commands = [
        "iptables -I INPUT -j DROP",
        "iptables -I OUTPUT -j DROP",
        "iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]

    outputs = []
    for cmd in commands:
        out = client.run_sudo(cmd)
        outputs.append(f"$ {cmd}\n{out}")

    return "\n".join(outputs)
