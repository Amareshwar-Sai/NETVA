"""Revoke credentials executor — SSH keys and weak accounts."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Execute credential revocation via SSH."""
    outputs = []

    if action.action_id == "revoke_ssh_keys":
        out = client.run_sudo(
            'echo "" > /root/.ssh/authorized_keys 2>/dev/null; '
            'find /home -name authorized_keys -exec sh -c \'echo "" > "{}"\' \\; 2>/dev/null; '
            'echo "SSH keys revoked"'
        )
        outputs.append(out)

    elif action.action_id == "disable_weak_accounts":
        out = client.run_sudo(
            "usermod -L oldadmin 2>/dev/null; "
            "passwd -l oldadmin 2>/dev/null; "
            'echo "Weak accounts disabled"'
        )
        outputs.append(out)

    return "\n".join(outputs) if outputs else f"Revoke action {action.action_id} completed"
