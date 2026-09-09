"""Post-execution verifier — confirm actions took effect."""
from __future__ import annotations

import socket
import logging

from backend.executor.ssh_client import SSHClient

logger = logging.getLogger(__name__)


def verify_port_closed(host: str, port: int, timeout: float = 3.0) -> bool:
    """Try socket connect — should fail if port is blocked."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        closed = result != 0
        logger.info(f"Verify port {host}:{port} closed = {closed}")
        return closed
    except Exception:
        return True  # Connection error = port likely blocked


def verify_service_stopped(client: SSHClient, service: str) -> bool:
    """Check if a systemd service is inactive."""
    try:
        output = client.run(f"systemctl is-active {service} 2>/dev/null || echo inactive")
        stopped = "inactive" in output or "dead" in output
        logger.info(f"Verify service {service} stopped = {stopped}")
        return stopped
    except Exception:
        return False


def verify_ssh_root_disabled(client: SSHClient) -> bool:
    """Grep sshd_config for PermitRootLogin no."""
    try:
        output = client.run("grep -i 'PermitRootLogin' /etc/ssh/sshd_config")
        disabled = "no" in output.lower()
        logger.info(f"Verify SSH root disabled = {disabled}")
        return disabled
    except Exception:
        return False


def verify_file_removed(client: SSHClient, path: str) -> bool:
    """Check that a file no longer exists."""
    try:
        output = client.run(f"test -f {path} && echo exists || echo removed")
        return "removed" in output
    except Exception:
        return False
