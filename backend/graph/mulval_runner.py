"""MulVAL runner — Docker or Python fallback emulator.

The Python fallback implements the five core MulVAL interaction rules:
1. Internet + remote vuln → execCode(host, user)
2. execCode(user) + local privesc → execCode(root)
3. execCode(src) + hacl + vulExists(dst) → execCode(dst)
4. execCode(src) + hasAccount(src→dst) → execCode(dst, privilege)
5. execCode(db_host) → dbAccess(crown_jewel)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MulVALVertex:
    id: int
    label: str
    vertex_type: str = "AND"  # AND / OR / LEAF


@dataclass
class MulVALArc:
    src: int
    dst: int
    weight: float = 1.0


@dataclass
class MulVALResult:
    vertices: list[MulVALVertex] = field(default_factory=list)
    arcs: list[MulVALArc] = field(default_factory=list)
    used_fallback: bool = False
    facts_used: list[str] = field(default_factory=list)


def run_mulval(facts: str) -> MulVALResult:
    """Try Docker MulVAL, fall back to Python emulator."""
    # Try Docker first (optional)
    try:
        result = _run_docker(facts)
        if result is not None:
            return result
    except Exception:
        pass

    # Fallback: Python emulator
    return _run_fallback(facts)


def _run_docker(facts: str) -> Optional[MulVALResult]:
    """Attempt to run MulVAL in Docker. Returns None if unavailable."""
    # MulVAL Docker is optional per spec — we skip it
    return None


def _run_fallback(facts: str) -> MulVALResult:
    """Python emulator implementing five core MulVAL interaction rules."""
    result = MulVALResult(used_fallback=True)
    vid = 0

    # Parse facts
    hosts = set(re.findall(r"host\((\w+)\)", facts))
    attacker_loc = "internet"
    m = re.search(r"attackerLocated\((\w+)\)", facts)
    if m:
        attacker_loc = m.group(1)

    hacl: list[tuple[str, str]] = re.findall(r"hacl\((\w+),\s*(\w+),", facts)
    vul_exists: list[tuple[str, str, str]] = re.findall(
        r"vulExists\((\w+),\s*(\w+),\s*(\w+)\)", facts
    )
    vul_props: dict[str, str] = {}
    for m_prop in re.finditer(r"vulProperty\((\w+),\s*(\w+),", facts):
        vul_props[m_prop.group(1)] = m_prop.group(2)

    has_account: list[tuple[str, str, str]] = re.findall(
        r"hasAccount\((\w+),\s*(\w+),\s*(\w+)\)", facts
    )
    crown_jewels: set[str] = set(re.findall(r"crownJewel\((\w+),", facts))
    cvss_scores: dict[str, float] = {}
    for m_cvss in re.finditer(r"cvssScore\((\w+),\s*([\d.]+)\)", facts):
        cvss_scores[m_cvss.group(1)] = float(m_cvss.group(2))

    exploit_avail: set[str] = set(re.findall(r"exploitAvailable\((\w+)\)", facts))

    # Build derived access
    exec_code: dict[str, str] = {}  # host → privilege_level

    # Hosts reachable from attacker via hacl
    attacker_reachable: set[str] = set()
    for src, dst in hacl:
        if src == attacker_loc:
            attacker_reachable.add(dst)

    # Rule 1: Internet + remote vuln → execCode(host, user)
    for host, vuln, svc in vul_exists:
        if host in attacker_reachable:
            prop = vul_props.get(vuln, "")
            if prop == "remoteExploit":
                exec_code[host] = "user"
                vid += 1
                result.vertices.append(MulVALVertex(
                    id=vid,
                    label=f"execCode({host}, user) via {vuln}",
                    vertex_type="OR",
                ))
                result.facts_used.append(f"Rule1: {vuln} on {host}")

    # Rule 2: execCode(user) + local privesc → execCode(root)
    for host, vuln, svc in vul_exists:
        if host in exec_code:
            prop = vul_props.get(vuln, "")
            if prop == "localExploit":
                exec_code[host] = "root"
                vid += 1
                result.vertices.append(MulVALVertex(
                    id=vid,
                    label=f"execCode({host}, root) via local {vuln}",
                    vertex_type="AND",
                ))
                result.facts_used.append(f"Rule2: local {vuln} on {host}")

    # Rule 3: execCode(src) + hacl + vulExists(dst) → execCode(dst)
    changed = True
    max_iter = 10
    while changed and max_iter > 0:
        changed = False
        max_iter -= 1
        for src, dst in hacl:
            if src in exec_code and dst not in exec_code:
                # Check if dst has a remote vuln
                for h, vuln, svc in vul_exists:
                    if h == dst and vul_props.get(vuln, "") == "remoteExploit":
                        exec_code[dst] = "user"
                        vid += 1
                        result.vertices.append(MulVALVertex(
                            id=vid,
                            label=f"execCode({dst}, user) via lateral from {src}",
                            vertex_type="OR",
                        ))
                        result.arcs.append(MulVALArc(
                            src=vid - 1, dst=vid,
                            weight=cvss_scores.get(vuln, 5.0) / 10.0,
                        ))
                        result.facts_used.append(f"Rule3: {src}->{dst} via {vuln}")
                        changed = True
                        break

    # Rule 4: execCode(src) + hasAccount(src→dst) → execCode(dst, privilege)
    for user, dst, priv in has_account:
        # Find src host for this account
        for src in list(exec_code):
            for s, d in hacl:
                if s == src and d == dst:
                    old = exec_code.get(dst, "")
                    new_priv = priv
                    if _priv_rank(new_priv) > _priv_rank(old):
                        exec_code[dst] = new_priv
                        vid += 1
                        result.vertices.append(MulVALVertex(
                            id=vid,
                            label=f"execCode({dst}, {priv}) via account from {src}",
                            vertex_type="AND",
                        ))
                        result.facts_used.append(f"Rule4: {src}->{dst} as {priv}")

    # Rule 5: execCode(db_host) → dbAccess(crown_jewel)
    for cj in crown_jewels:
        if cj in exec_code:
            vid += 1
            result.vertices.append(MulVALVertex(
                id=vid,
                label=f"dbAccess({cj}) — crown jewel compromised",
                vertex_type="AND",
            ))
            result.facts_used.append(f"Rule5: crown jewel {cj} compromised")

    return result


def _priv_rank(priv: str) -> int:
    return {"": 0, "none": 0, "user": 1, "sudo": 2, "admin": 3, "root": 4}.get(priv, 0)
