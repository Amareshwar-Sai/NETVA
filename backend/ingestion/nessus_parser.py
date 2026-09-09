"""Nessus v2 XML parser + synthetic lab-data generator."""
from __future__ import annotations

from typing import Optional
from lxml import etree
from defusedxml import ElementTree as SafeET

from backend.ingestion.models import RawVuln, RawNessusHost, RawNessusScan

SEVERITY_MAP = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}


def parse_nessus(xml_content: str | bytes) -> RawNessusScan:
    """Parse a .nessus (Nessus v2) XML file."""
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    root = SafeET.fromstring(xml_content)
    hosts: list[RawNessusHost] = []

    for report_host in root.iter("ReportHost"):
        ip = report_host.get("name", "")
        hostname = ""
        os_name = ""

        # Extract host properties
        props = report_host.find("HostProperties")
        if props is not None:
            for tag in props.findall("tag"):
                attr_name = tag.get("name", "")
                if attr_name == "host-ip":
                    ip = tag.text or ip
                elif attr_name == "hostname":
                    hostname = tag.text or ""
                elif attr_name == "operating-system":
                    os_name = tag.text or ""

        vulns: list[RawVuln] = []
        for item in report_host.iter("ReportItem"):
            severity = item.get("severity", "0")
            cve_el = item.find("cve")
            cvss_el = item.find("cvss_base_score")
            cvss3_el = item.find("cvss3_base_score")
            exploit_el = item.find("exploit_available")
            desc_el = item.find("description")
            sol_el = item.find("solution")
            output_el = item.find("plugin_output")

            vuln = RawVuln(
                plugin_id=item.get("pluginID", ""),
                plugin_name=item.get("pluginName", ""),
                severity=severity,
                cve=cve_el.text if cve_el is not None else None,
                cvss_base=float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0,
                cvss3_base=float(cvss3_el.text) if cvss3_el is not None and cvss3_el.text else 0.0,
                exploit_available=(exploit_el is not None and exploit_el.text == "true"),
                description=desc_el.text if desc_el is not None else "",
                solution=sol_el.text if sol_el is not None else "",
                plugin_output=output_el.text if output_el is not None else "",
                port=int(item.get("port", 0)),
                protocol=item.get("protocol", "tcp"),
                service=item.get("svc_name", ""),
            )
            vulns.append(vuln)

        hosts.append(RawNessusHost(ip=ip, hostname=hostname, os=os_name, vulns=vulns))

    return RawNessusScan(hosts=hosts)


def generate_lab_nessus_xml() -> str:
    """Generate synthetic Nessus XML matching the lab network vulnerabilities."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
<Report name="Lab Network Scan">

<!-- Webserver 10.10.0.10 -->
<ReportHost name="10.10.0.10">
  <HostProperties>
    <tag name="host-ip">10.10.0.10</tag>
    <tag name="hostname">webserver</tag>
    <tag name="operating-system">Ubuntu 22.04</tag>
  </HostProperties>

  <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="155432"
    pluginName="Apache 2.4.49 Path Traversal (CVE-2021-41773)" severity="4">
    <cve>CVE-2021-41773</cve>
    <cvss_base_score>9.8</cvss_base_score>
    <cvss3_base_score>9.8</cvss3_base_score>
    <exploit_available>true</exploit_available>
    <description>Apache HTTP Server 2.4.49 allows path traversal and remote code execution via crafted URI.</description>
    <solution>Upgrade Apache to 2.4.51 or later.</solution>
  </ReportItem>

  <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="100200"
    pluginName="Web Server phpinfo() Page Found" severity="2">
    <cvss_base_score>5.3</cvss_base_score>
    <description>phpinfo() page exposes server configuration details.</description>
    <solution>Remove phpinfo.php from production servers.</solution>
  </ReportItem>

  <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="100201"
    pluginName="Exposed .git Directory" severity="3">
    <cvss_base_score>7.5</cvss_base_score>
    <description>.git directory is publicly accessible, leaking source code and secrets.</description>
    <solution>Block access to .git directories in web server configuration.</solution>
  </ReportItem>

  <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="100202"
    pluginName="Backup Files Accessible" severity="2">
    <cvss_base_score>5.0</cvss_base_score>
    <description>Backup files (.bak, .sql.bak) are publicly accessible.</description>
    <solution>Remove backup files from web root.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10267"
    pluginName="SSH Server Allows Root Login" severity="2">
    <cvss_base_score>5.3</cvss_base_score>
    <description>SSH server permits root login with password authentication.</description>
    <solution>Set PermitRootLogin to no in sshd_config.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10270"
    pluginName="Weak SSH Password Detected" severity="3">
    <cvss_base_score>7.5</cvss_base_score>
    <description>SSH user admin has a weak, easily guessable password.</description>
    <solution>Enforce strong password policy or use key-based authentication.</solution>
  </ReportItem>

  <ReportItem port="80" protocol="tcp" svc_name="www" pluginID="100203"
    pluginName="CGI Module Enabled" severity="2">
    <cve>CVE-2021-41773</cve>
    <cvss_base_score>5.5</cvss_base_score>
    <description>CGI module is enabled, increasing attack surface for path traversal.</description>
    <solution>Disable CGI module if not needed.</solution>
  </ReportItem>
</ReportHost>

<!-- Appserver 10.10.0.20 -->
<ReportHost name="10.10.0.20">
  <HostProperties>
    <tag name="host-ip">10.10.0.20</tag>
    <tag name="hostname">appserver</tag>
    <tag name="operating-system">Ubuntu 22.04</tag>
  </HostProperties>

  <ReportItem port="3000" protocol="tcp" svc_name="http" pluginID="200100"
    pluginName="Command Injection via Query Parameter" severity="4">
    <cvss_base_score>9.8</cvss_base_score>
    <cvss3_base_score>9.8</cvss3_base_score>
    <exploit_available>true</exploit_available>
    <description>Application passes user input directly to system shell via ?cmd= parameter.</description>
    <solution>Sanitize all user input; never pass to shell commands.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="200101"
    pluginName="SUID Binary Found: python3" severity="3">
    <cvss_base_score>7.8</cvss_base_score>
    <description>python3 binary has SUID bit set, allowing privilege escalation.</description>
    <solution>Remove SUID bit from python3: chmod u-s $(which python3).</solution>
  </ReportItem>

  <ReportItem port="0" protocol="tcp" svc_name="" pluginID="200102"
    pluginName="World-Writable Cron Script" severity="3">
    <cvss_base_score>7.8</cvss_base_score>
    <description>Cron job /opt/app/cleanup.sh is world-writable, allowing privilege escalation to root.</description>
    <solution>Set proper permissions: chmod 755 /opt/app/cleanup.sh.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10270"
    pluginName="Weak SSH Password Detected" severity="3">
    <cvss_base_score>7.5</cvss_base_score>
    <description>SSH user appuser has a weak password.</description>
    <solution>Enforce strong password policy.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="200103"
    pluginName="Sudo NOPASSWD Configured" severity="2">
    <cvss_base_score>6.7</cvss_base_score>
    <description>User appuser has NOPASSWD sudo access to python3 and cleanup.sh.</description>
    <solution>Remove NOPASSWD entries from sudoers.</solution>
  </ReportItem>
</ReportHost>

<!-- Database 10.20.0.20 -->
<ReportHost name="10.20.0.20">
  <HostProperties>
    <tag name="host-ip">10.20.0.20</tag>
    <tag name="hostname">database</tag>
    <tag name="operating-system">Ubuntu 22.04</tag>
  </HostProperties>

  <ReportItem port="3306" protocol="tcp" svc_name="mysql" pluginID="300100"
    pluginName="MySQL Default Credentials (root:root)" severity="4">
    <cvss_base_score>9.8</cvss_base_score>
    <cvss3_base_score>9.8</cvss3_base_score>
    <exploit_available>true</exploit_available>
    <description>MySQL server accepts default root password.</description>
    <solution>Change default MySQL root password immediately.</solution>
  </ReportItem>

  <ReportItem port="3306" protocol="tcp" svc_name="mysql" pluginID="300101"
    pluginName="MySQL Listening on All Interfaces" severity="3">
    <cvss_base_score>7.5</cvss_base_score>
    <description>MySQL bind-address is 0.0.0.0, accepting connections from any network.</description>
    <solution>Set bind-address to 127.0.0.1 or specific internal IP.</solution>
  </ReportItem>

  <ReportItem port="3306" protocol="tcp" svc_name="mysql" pluginID="300102"
    pluginName="PII Data Detected in Database" severity="3">
    <cvss_base_score>8.0</cvss_base_score>
    <description>Database contains unencrypted PII including SSNs, salaries, and API keys.</description>
    <solution>Encrypt PII at rest and restrict access with least privilege.</solution>
  </ReportItem>

  <ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="10267"
    pluginName="SSH Server Allows Root Login" severity="2">
    <cvss_base_score>5.3</cvss_base_score>
    <description>SSH root login is enabled on a critical database server.</description>
    <solution>Disable root login via SSH.</solution>
  </ReportItem>
</ReportHost>

</Report>
</NessusClientData_v2>"""
