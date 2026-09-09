"""Post-execution rescan trigger — lightweight verification scan."""
from __future__ import annotations

import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def ping_sweep(hosts: list[str], timeout: float = 2.0) -> dict[str, bool]:
    """Quick connectivity check for a list of hosts."""
    results = {}
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, 22))
            results[host] = result == 0
            sock.close()
        except Exception:
            results[host] = False
    return results


def port_check(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, bool]:
    """Check which ports are open on a host."""
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            results[port] = result == 0
            sock.close()
        except Exception:
            results[port] = False
    return results


async def trigger_rescan(
    affected_host: str,
    affected_ports: list[int],
) -> dict:
    """Trigger a lightweight rescan after action execution.

    Returns scan results that can feed into partial pipeline re-run.
    """
    logger.info(f"Rescan: checking {affected_host} ports {affected_ports}")

    connectivity = ping_sweep([affected_host])
    port_status = port_check(affected_host, affected_ports)

    return {
        "host": affected_host,
        "reachable": connectivity.get(affected_host, False),
        "ports": port_status,
    }
