"""Stop service / harden executor — CGI disable, SSH harden, etc."""
from __future__ import annotations

from backend.executor.ssh_client import SSHClient
from backend.mdp.action_space import DefenderAction
from backend.normalization.schema import NetworkAsset


def run(client: SSHClient, action: DefenderAction, asset: NetworkAsset) -> str:
    """Execute hardening action via SSH."""
    outputs = []

    if action.action_id == "disable_cgi":
        out = client.run_sudo("a2dismod cgi 2>/dev/null; service apache2 restart")
        outputs.append(out)

    elif action.action_id == "disable_ssh_root_login":
        out = client.run_sudo(
            "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && "
            "service sshd restart"
        )
        outputs.append(out)

    elif action.action_id == "fix_world_writable_files":
        out = client.run_sudo(
            "find / -xdev -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null; echo done"
        )
        outputs.append(out)

    elif action.action_id == "remove_backup_files":
        out = client.run_sudo(
            "find /var/www -name '*.bak' -o -name '*.sql.bak' -o -name '.env.bak' | "
            "xargs rm -f 2>/dev/null; echo done"
        )
        outputs.append(out)

    elif action.action_id == "change_db_password":
        out = client.run_sudo(
            'mysql -u root -proot -e "ALTER USER \'root\'@\'%\' IDENTIFIED BY \'StrongPass123!\'; '
            'DELETE FROM mysql.user WHERE User=\'root\' AND Host=\'%\'; FLUSH PRIVILEGES;"'
        )
        outputs.append(out)

    elif action.action_id == "bind_db_localhost":
        out = client.run_sudo(
            "sed -i 's/bind-address.*/bind-address = 127.0.0.1/' "
            "/etc/mysql/mysql.conf.d/mysqld.cnf && service mysql restart"
        )
        outputs.append(out)

    elif action.action_id == "stop_vulnerable_service":
        # Generic service stop
        if action.executor_cmd and action.executor_cmd != "# Determined at runtime based on target":
            out = client.run_sudo(action.executor_cmd)
            outputs.append(out)
        else:
            outputs.append("No specific service to stop")

    elif action.action_id == "enable_auditd":
        out = client.run_sudo(
            "apt-get install -y auditd 2>/dev/null; "
            "systemctl enable auditd 2>/dev/null; "
            "systemctl start auditd 2>/dev/null; echo done"
        )
        outputs.append(out)

    else:
        # Fallback to executor_cmd
        if action.executor_cmd:
            out = client.run_sudo(action.executor_cmd)
            outputs.append(out)

    return "\n".join(outputs) if outputs else f"Harden action {action.action_id} completed"
