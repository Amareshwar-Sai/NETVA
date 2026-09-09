"""Normalization layer — unified schema and merging."""
from backend.normalization.normalizer import Normalizer
from backend.normalization.schema import (
    Severity, Zone, PrivilegeLevel,
    Vulnerability, NetworkEdge, NetworkAsset, NormalizedNetwork,
)
from backend.normalization.deduplicator import Deduplicator
from backend.normalization.enricher import enrich_epss, enrich_sync
from backend.normalization.reachability import ReachabilityMatrix, build_reachability

__all__ = [
    "Normalizer",
    "Deduplicator",
    "Severity", "Zone", "PrivilegeLevel",
    "Vulnerability", "NetworkEdge", "NetworkAsset", "NormalizedNetwork",
    "enrich_epss", "enrich_sync",
    "ReachabilityMatrix", "build_reachability",
]
