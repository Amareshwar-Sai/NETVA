"""EPSS enrichment — batch-fetch exploit prediction scores for CVEs."""
from __future__ import annotations

import asyncio
from typing import Optional

from backend.normalization.schema import NormalizedNetwork

# In-process cache so same CVE not fetched twice
_epss_cache: dict[str, float] = {}


async def enrich_epss(network: NormalizedNetwork, timeout: int = 10) -> NormalizedNetwork:
    """Fetch EPSS scores for all CVEs in the network.

    Gracefully falls back to 0.0 if the API is unreachable (offline mode).
    """
    # Collect all unique CVEs
    cves: set[str] = set()
    for asset in network.assets.values():
        for vuln in asset.vulns:
            if vuln.cve and vuln.cve not in _epss_cache:
                cves.add(vuln.cve)

    if cves:
        await _batch_fetch(list(cves), timeout)

    # Apply cached scores
    for asset in network.assets.values():
        for vuln in asset.vulns:
            if vuln.cve:
                vuln.epss = _epss_cache.get(vuln.cve, 0.0)

    return network


async def _batch_fetch(cves: list[str], timeout: int) -> None:
    """Batch-fetch from EPSS API. Silently fails if offline."""
    try:
        import httpx
    except ImportError:
        return

    url = "https://api.first.org/data/v1/epss"

    # Batch in groups of 30
    for i in range(0, len(cves), 30):
        batch = cves[i : i + 30]
        params = {"cve": ",".join(batch)}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("data", []):
                        cve_id = entry.get("cve", "")
                        score = float(entry.get("epss", 0.0))
                        _epss_cache[cve_id] = score
        except Exception:
            # Graceful fallback — offline is fine
            for cve in batch:
                _epss_cache.setdefault(cve, 0.0)


def enrich_sync(network: NormalizedNetwork, timeout: int = 10) -> NormalizedNetwork:
    """Synchronous wrapper for non-async contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in async context — schedule and return
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = pool.submit(asyncio.run, enrich_epss(network, timeout)).result()
        return result
    else:
        return asyncio.run(enrich_epss(network, timeout))
