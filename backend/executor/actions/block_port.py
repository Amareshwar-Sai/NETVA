"""Block port executor — iptables port blocking."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Block a specific port via iptables."""
    port = action.applies_to_port
    if port is None:
        return "No port specified for block_port action"

    cmd = f"iptables -I INPUT -p tcp --dport {port} -j DROP"
    out = client.run_sudo(cmd)
    return f"$ {cmd}\n{out}\nPort {port} blocked on {asset.ip}"
