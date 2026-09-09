"""Defender action space — 21 actions across 7 categories."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class DefenderAction:
    """A single remediation action the defender can take."""
    action_id: str
    action_type: str          # patch/isolate/block_port/harden/revoke/segment/monitor
    label: str
    description: str
    target_type: str          # webserver/appserver/database/firewall/any
    cost: float               # 0-1
    disruption: float         # 0-1
    executor_cmd: str = ""
    applies_to_port: Optional[int] = None


# ── All 21 actions ──────────────────────────────────────────────────────────

_ACTIONS = [
    # Patch (4)
    DefenderAction("patch_os", "patch", "Patch OS", "Apply OS security updates",
                   "any", 0.20, 0.15, "apt-get update -y && apt-get upgrade -y"),
    DefenderAction("patch_web_server", "patch", "Patch Web Server",
                   "Update Apache/Nginx to latest stable",
                   "webserver", 0.25, 0.30, "apt-get update -y && apt-get upgrade -y apache2 && service apache2 restart"),
    DefenderAction("patch_app", "patch", "Patch Application",
                   "Update application dependencies",
                   "appserver", 0.30, 0.35, "cd /opt/app && npm install --production"),
    DefenderAction("patch_db", "patch", "Patch Database",
                   "Update MySQL/PostgreSQL to latest",
                   "database", 0.25, 0.40, "apt-get update -y && apt-get upgrade -y mysql-server"),

    # Isolate (2)
    DefenderAction("isolate_host", "isolate", "Isolate Host",
                   "Drop all inbound/outbound traffic except established",
                   "any", 0.10, 0.90,
                   "iptables -I INPUT -j DROP && iptables -I OUTPUT -j DROP && "
                   "iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
    DefenderAction("isolate_from_internet", "isolate", "Isolate from Internet",
                   "Block all internet-facing traffic",
                   "any", 0.10, 0.70,
                   "iptables -I INPUT -s 0.0.0.0/0 -j DROP && "
                   "iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT"),

    # Block Port (4)
    DefenderAction("block_port_80", "block_port", "Block Port 80",
                   "Block HTTP traffic", "webserver", 0.05, 0.60,
                   "iptables -I INPUT -p tcp --dport 80 -j DROP", 80),
    DefenderAction("block_port_22", "block_port", "Block Port 22",
                   "Block SSH access", "any", 0.05, 0.45,
                   "iptables -I INPUT -p tcp --dport 22 -j DROP", 22),
    DefenderAction("block_port_3306", "block_port", "Block Port 3306",
                   "Block external MySQL access", "database", 0.05, 0.30,
                   "iptables -I INPUT -p tcp --dport 3306 -j DROP", 3306),
    DefenderAction("block_port_3000", "block_port", "Block Port 3000",
                   "Block application port", "appserver", 0.05, 0.50,
                   "iptables -I INPUT -p tcp --dport 3000 -j DROP", 3000),

    # Harden (6)
    DefenderAction("disable_ssh_root_login", "harden", "Disable SSH Root Login",
                   "Set PermitRootLogin to no in sshd_config",
                   "any", 0.05, 0.10,
                   "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && service sshd restart"),
    DefenderAction("fix_world_writable_files", "harden", "Fix World-Writable Files",
                   "Remove world-writable permissions from sensitive files",
                   "any", 0.05, 0.05,
                   "find / -xdev -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null"),
    DefenderAction("remove_backup_files", "harden", "Remove Backup Files",
                   "Delete exposed backup files from web root",
                   "webserver", 0.05, 0.05,
                   "find /var/www -name '*.bak' -o -name '*.sql.bak' -o -name '.env.bak' | xargs rm -f"),
    DefenderAction("disable_cgi", "harden", "Disable CGI Module",
                   "Disable Apache CGI module to reduce attack surface",
                   "webserver", 0.05, 0.15,
                   "a2dismod cgi && service apache2 restart"),
    DefenderAction("change_db_password", "harden", "Change DB Password",
                   "Replace default MySQL root password with strong password",
                   "database", 0.05, 0.20,
                   "mysql -u root -proot -e \"ALTER USER 'root'@'%' IDENTIFIED BY 'StrongPass123!'; FLUSH PRIVILEGES;\""),
    DefenderAction("bind_db_localhost", "harden", "Bind DB to Localhost",
                   "Restrict MySQL to listen only on 127.0.0.1",
                   "database", 0.10, 0.25,
                   "sed -i 's/bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf && service mysql restart"),

    # Revoke (2)
    DefenderAction("revoke_ssh_keys", "revoke", "Revoke SSH Keys",
                   "Clear all authorized_keys files to break SSH trust chains",
                   "any", 0.05, 0.15,
                   'echo "" > /root/.ssh/authorized_keys && find /home -name authorized_keys -exec sh -c \'echo "" > "{}"\' \\;'),
    DefenderAction("disable_weak_accounts", "revoke", "Disable Weak Accounts",
                   "Lock old/unused accounts with weak passwords",
                   "any", 0.05, 0.10,
                   "usermod -L oldadmin 2>/dev/null; passwd -l oldadmin 2>/dev/null"),

    # Segment (2)
    DefenderAction("segment_dmz_internal", "segment", "Segment DMZ↔Internal",
                   "Add firewall rules to block DMZ-to-internal traffic",
                   "firewall", 0.15, 0.20,
                   "iptables -I FORWARD -s 10.10.0.0/24 -d 10.20.0.0/24 -j DROP && "
                   "iptables -A FORWARD -s 10.10.0.0/24 -d 10.20.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
    DefenderAction("segment_internal_prod", "segment", "Segment Internal↔Prod",
                   "Restrict internal-to-prod to MySQL only",
                   "firewall", 0.15, 0.15,
                   "iptables -I FORWARD -s 10.20.0.0/24 -d 10.30.0.0/24 -j DROP && "
                   "iptables -A FORWARD -s 10.20.0.0/24 -d 10.30.0.0/24 -p tcp --dport 3306 -j ACCEPT"),

    # Monitor (2)
    DefenderAction("enable_auditd", "monitor", "Enable Audit Logging",
                   "Install and enable auditd for security event logging",
                   "any", 0.10, 0.05,
                   "apt-get install -y auditd && systemctl enable auditd && systemctl start auditd"),
    DefenderAction("stop_vulnerable_service", "monitor", "Stop Vulnerable Service",
                   "Stop a service with known critical vulnerabilities",
                   "any", 0.05, 0.55,
                   "# Determined at runtime based on target"),
]

ACTION_MAP: dict[str, DefenderAction] = {a.action_id: a for a in _ACTIONS}


def get_applicable_actions(asset_type: str) -> list[DefenderAction]:
    """Filter actions applicable to a given asset type."""
    return [a for a in _ACTIONS if a.target_type in (asset_type, "any")]


def get_all_actions() -> list[DefenderAction]:
    """Return all defined defender actions."""
    return list(_ACTIONS)
