"""Convert NormalizedNetwork → MulVAL Prolog .P fact file."""
from __future__ import annotations

from backend.normalization.schema import NormalizedNetwork, NetworkAsset, NetworkEdge, Zone


def _ip_to_atom(ip: str) -> str:
    """Convert IP to Prolog atom: 10.10.0.10 → h_10_10_0_10."""
    return "h_" + ip.replace(".", "_")


def _cve_to_atom(cve: str) -> str:
    """Convert CVE to Prolog atom: CVE-2021-41773 → cve_2021_41773."""
    return cve.lower().replace("-", "_")


def generate_mulval_facts(network: NormalizedNetwork, attacker_location: str = "internet") -> str:
    """Generate MulVAL Prolog input facts from normalised network."""
    lines: list[str] = []

    # Attacker location
    lines.append(f"attackerLocated({attacker_location}).")
    lines.append("")

    for ip, asset in network.assets.items():
        atom = _ip_to_atom(ip)

        # Host declaration
        lines.append(f"host({atom}).")

        # Zone
        lines.append(f"inZone({atom}, {asset.zone.value}).")

        # Asset type flags
        if asset.asset_type == "webserver":
            lines.append(f"isWebServer({atom}).")
        elif asset.asset_type == "database":
            lines.append(f"isDatabase({atom}).")
            lines.append(f"crownJewel({atom}, {asset.criticality:.2f}).")

        # Network services
        for port in asset.open_ports:
            svc = asset.services.get(port, "unknown")
            priv = "low"
            lines.append(f"networkServiceInfo({atom}, {port}, tcp, {svc}, {priv}).")

        # Vulnerabilities
        for vuln in asset.vulns:
            if vuln.cve:
                cve_atom = _cve_to_atom(vuln.cve)
                svc = vuln.service or "unknown"
                lines.append(f"vulExists({atom}, {cve_atom}, {svc}).")

                # Vuln property — remote or local
                if vuln.port and vuln.port > 0:
                    lines.append(f"vulProperty({cve_atom}, remoteExploit, privEscalation).")
                else:
                    lines.append(f"vulProperty({cve_atom}, localExploit, privEscalation).")

                lines.append(f"cvssScore({cve_atom}, {vuln.cvss}).")

                if vuln.exploit_available:
                    lines.append(f"exploitAvailable({cve_atom}).")

        lines.append("")

    # Network access control (hacl) facts
    # Attacker can reach DMZ
    for ip, asset in network.assets.items():
        if asset.zone == Zone.DMZ:
            atom = _ip_to_atom(ip)
            lines.append(f"hacl({attacker_location}, {atom}, tcp, _).")

    # Edges between hosts
    seen_hacl: set[tuple[str, str]] = set()
    for edge in network.edges:
        src_atom = _ip_to_atom(edge.src_id)
        dst_atom = _ip_to_atom(edge.dst_id)
        key = (src_atom, dst_atom)
        if key not in seen_hacl:
            lines.append(f"hacl({src_atom}, {dst_atom}, tcp, _).")
            seen_hacl.add(key)

    # IAM trust relationships
    for edge in network.edges:
        if edge.edge_type == "iam" and edge.link_type in ("ssh_key", "password", "cred_reuse"):
            src_atom = _ip_to_atom(edge.src_id)
            dst_atom = _ip_to_atom(edge.dst_id)
            priv = edge.privilege_level.value
            username = f"user_{src_atom}"
            lines.append(f"hasAccount({username}, {dst_atom}, {priv}).")

    lines.append("")
    return "\n".join(lines)
