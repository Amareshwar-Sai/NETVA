"""Three-pass vulnerability deduplicator."""
from __future__ import annotations

from backend.normalization.schema import (
    Severity, Vulnerability, NormalizedNetwork,
)


class Deduplicator:
    """Deduplicate vulnerabilities across all assets in a NormalizedNetwork."""

    def deduplicate(self, network: NormalizedNetwork) -> NormalizedNetwork:
        """Run three-pass deduplication on every asset's vuln list."""
        for asset in network.assets.values():
            asset.vulns = self._deduplicate_vulns(asset.vulns)
        return network

    def _deduplicate_vulns(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Three-pass dedup returning sorted list."""

        # Pass 1: CVE-based grouping — same CVE = merge, keep highest CVSS
        cve_groups: dict[str, Vulnerability] = {}
        no_cve: list[Vulnerability] = []

        for v in vulns:
            if v.cve:
                key = v.cve
                if key in cve_groups:
                    existing = cve_groups[key]
                    if v.cvss > existing.cvss:
                        # Keep higher CVSS, merge description
                        v.description = v.description or existing.description
                        v.solution = v.solution or existing.solution
                        v.exploit_available = v.exploit_available or existing.exploit_available
                        cve_groups[key] = v
                    else:
                        existing.exploit_available = existing.exploit_available or v.exploit_available
                else:
                    cve_groups[key] = v
            else:
                no_cve.append(v)

        # Pass 2: Plugin-name + port grouping — for vulns without CVE
        name_port_groups: dict[str, Vulnerability] = {}
        for v in no_cve:
            key = f"{v.name}:{v.port}"
            if key in name_port_groups:
                existing = name_port_groups[key]
                if v.cvss > existing.cvss:
                    name_port_groups[key] = v
            else:
                name_port_groups[key] = v

        # Combine
        merged = list(cve_groups.values()) + list(name_port_groups.values())

        # Pass 3: Re-derive severity from merged CVSS
        for v in merged:
            v.severity = self._cvss_to_severity(v.cvss)

        # Sort: critical first, then descending CVSS
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        merged.sort(key=lambda v: (severity_order.get(v.severity, 5), -v.cvss))

        return merged

    @staticmethod
    def _cvss_to_severity(cvss: float) -> Severity:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        if cvss > 0:
            return Severity.LOW
        return Severity.INFO
