"""Patch executor — OS and service patching."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Execute patch action via SSH."""
    outputs = []

    if action.action_id in ("patch_os", "patch_web_server", "patch_db"):
        out = client.run_sudo("apt-get update -y && apt-get upgrade -y --only-upgrade")
        outputs.append(out)

    if action.action_id == "patch_web_server":
        out = client.run_sudo("service apache2 restart")
        outputs.append(out)

    if action.action_id == "patch_app":
        out = client.run_sudo("cd /opt/app && npm install --production")
        outputs.append(out)

    if action.action_id == "patch_db":
        out = client.run_sudo("service mysql restart")
        outputs.append(out)

    return "\n".join(outputs) if outputs else "Patch action completed"
