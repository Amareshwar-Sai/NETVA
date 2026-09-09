"""Nmap XML (-oX) parser + synthetic lab-data generator."""
from __future__ import annotations

import json
import re

from defusedxml import ElementTree as SafeET

from backend.ingestion.models import RawPort, RawNmapHost, RawNmapScan


# ── CVE extraction helpers ──────────────────────────────────────────────────

# Matches "CVE-YYYY-NNNN(N)  X.Y" patterns in vulners output
_CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d+)")

# Matches confirmed-vulnerable scripts (e.g. http-slowloris-check, http-vuln-*)
# These actually probe the service rather than just version-matching.
_CONFIRMED_VULN_PATTERN = re.compile(
    r"State:\s*(?:LIKELY VULNERABLE|VULNERABLE).*?CVE:(CVE-\d{4}-\d{4,7})",
    re.DOTALL,
)

# Matches CVE references in non-vulners scripts that don't have explicit "State: VULNERABLE"
# E.g. "http-vuln-cve2021-41773" outputs that mention the CVE in the body
_INLINE_CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})")


def _extract_cves_from_scripts(scripts: dict[str, str]) -> list[dict]:
    """Pull structured CVE entries out of nmap NSE script output.

    Returns a list of dicts with keys: cve, cvss, source, confirmed, exploit_available
    - source: which script produced it ("vulners", "http-slowloris-check", etc)
    - confirmed: True if the script directly probed and confirmed the vuln
    - exploit_available: True if exploit code is referenced
    """
    found: dict[str, dict] = {}

    # 1. vulners output — high volume, version-based matching, includes CVSS
    vulners_text = scripts.get("vulners", "")
    if vulners_text:
        has_exploit_marker = "*EXPLOIT*" in vulners_text
        for cve_id, cvss_str in _CVE_PATTERN.findall(vulners_text):
            try:
                cvss = float(cvss_str)
            except ValueError:
                continue
            existing = found.get(cve_id)
            if existing is None or cvss > existing["cvss"]:
                found[cve_id] = {
                    "cve": cve_id,
                    "cvss": cvss,
                    "source": "vulners",
                    "confirmed": False,
                    "exploit_available": has_exploit_marker,
                }

    # 2. Confirmed-vulnerable scripts (probed, not just version-matched)
    for script_id, output in scripts.items():
        if script_id == "vulners" or script_id == "__extracted_cves__":
            continue
        for cve_id in _CONFIRMED_VULN_PATTERN.findall(output):
            existing = found.get(cve_id, {})
            found[cve_id] = {
                "cve": cve_id,
                "cvss": existing.get("cvss", 7.5),  # default high if no score
                "source": script_id,
                "confirmed": True,  # this is the key flag
                "exploit_available": True,
            }

    # 3. Inline CVE references in vuln-named scripts (e.g. http-vuln-cve2021-41773)
    for script_id, output in scripts.items():
        if not script_id.startswith("http-vuln-") and "vuln" not in script_id:
            continue
        if script_id == "vulners":
            continue
        # Only consider this script confirmed if its output mentions VULNERABLE
        is_confirmed = "VULNERABLE" in output.upper()
        for cve_id in _INLINE_CVE_PATTERN.findall(output):
            if cve_id not in found:
                found[cve_id] = {
                    "cve": cve_id,
                    "cvss": 7.5,  # default; we don't have a score here
                    "source": script_id,
                    "confirmed": is_confirmed,
                    "exploit_available": is_confirmed,
                }

    return list(found.values())


# ── Main parser ─────────────────────────────────────────────────────────────

def parse_nmap(xml_content: str | bytes) -> RawNmapScan:
    """Parse nmap XML output (-oX format)."""
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    root = SafeET.fromstring(xml_content)
    hosts: list[RawNmapHost] = []

    for host_el in root.iter("host"):
        # Status check
        status_el = host_el.find("status")
        status = status_el.get("state", "down") if status_el is not None else "down"
        if status != "up":
            continue

        # Address
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break

        # Hostname — strip Docker network suffix (e.g. "lab_webserver.lab_dmz" → "lab_webserver")
        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "").split(".")[0]

        # OS
        os_name = ""
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")

        # Ports
        ports: list[RawPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                version = service_el.get("product", "") if service_el is not None else ""
                if service_el is not None and service_el.get("version"):
                    version += " " + service_el.get("version", "")

                # NSE scripts
                scripts: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")

                # Extract structured CVE data from scripts and stash inside scripts dict
                # under a synthetic key. The normalizer will pick this up.
                extracted_cves = _extract_cves_from_scripts(scripts)
                if extracted_cves:
                    scripts["__extracted_cves__"] = json.dumps(extracted_cves)

                ports.append(RawPort(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state="open",
                    service=service,
                    version=version.strip(),
                    scripts=scripts,
                ))

        hosts.append(RawNmapHost(ip=ip, hostname=hostname, os=os_name, ports=ports, status=status))

    return RawNmapScan(hosts=hosts)


def generate_lab_nmap_xml() -> str:
    """Generate synthetic nmap XML for the lab network."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -oX" start="1700000000">

<host>
  <status state="up"/>
  <address addr="10.10.0.10" addrtype="ipv4"/>
  <hostnames><hostname name="webserver"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
      <script id="ssh-auth-methods" output="Supported: publickey,password"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.49"/>
      <script id="http-headers" output="Server: Apache/2.4.49 (Ubuntu)"/>
      <script id="http-vuln-cve2021-41773" output="VULNERABLE: Path Traversal CVE-2021-41773"/>
      <script id="http-git" output="/.git/ found: Git repository exposed"/>
      <script id="http-backup-finder" output="backup.sql.bak, .env.bak found"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.10.0.20" addrtype="ipv4"/>
  <hostnames><hostname name="appserver"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="3000">
      <state state="open"/>
      <service name="http" product="Node.js Express" version="4.18"/>
      <script id="http-vuln-cve" output="Command injection via ?cmd= parameter"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.20.0.20" addrtype="ipv4"/>
  <hostnames><hostname name="database"/></hostnames>
  <os><osmatch name="Linux 5.x (Ubuntu 22.04)" accuracy="95"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="open"/>
      <service name="mysql" product="MySQL" version="8.0.35"/>
      <script id="mysql-info" output="Protocol: 10, Server: MySQL 8.0.35"/>
      <script id="mysql-vuln-cve" output="Default credentials: root:root"/>
    </port>
  </ports>
</host>

<host>
  <status state="up"/>
  <address addr="10.10.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="firewall"/></hostnames>
  <os><osmatch name="Linux (Alpine)" accuracy="90"/></os>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.0"/>
    </port>
  </ports>
</host>

</nmaprun>"""