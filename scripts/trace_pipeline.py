"""Pipeline trace script — runs the NETVA pipeline once and dumps each stage
to a separate JSON file for debugging and audit.

USAGE (from project root):
    python -m scripts.trace_pipeline
    or:
    python scripts\trace_pipeline.py

OUTPUT:
    Writes JSON files to ./trace_output/ — one per pipeline stage.

This is a developer tool. It uses defensive imports so that even if the
attack-graph or AMC entry points have different names than expected, the
critical earlier stages (parsing, normalization, edges, reachability)
still produce their JSON dumps.
"""
from __future__ import annotations

import json
import sys
import traceback
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

# Add project root to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ingestion import ingest_all
from backend.normalization.normalizer import Normalizer
from backend.normalization.reachability import build_reachability, effective_reachability_summary

OUT_DIR = Path(__file__).resolve().parents[1] / "trace_output"


# ── Defensive imports for attack-graph and AMC entry points ────────────────

def _resolve_attack_graph_builder() -> Optional[Callable]:
    """Try several known names for the attack-graph builder."""
    candidates = [
        ("backend.graph.attack_graph", "build_attack_graph"),
        ("backend.graph.attack_graph", "build_nx_graph"),
        ("backend.graph", "build_attack_graph"),
        ("backend.graph", "build_nx_graph"),
    ]
    for module_path, fn_name in candidates:
        try:
            mod = __import__(module_path, fromlist=[fn_name])
            if hasattr(mod, fn_name):
                print(f"  [import] using {module_path}.{fn_name}")
                return getattr(mod, fn_name)
        except ImportError:
            continue
    return None


def _resolve_amc_runner() -> Optional[Callable]:
    """Try several known names for the AMC runner."""
    candidates = [
        ("backend.amc.runner", "run_amc"),
        ("backend.amc", "run_amc"),
        ("backend.amc.solver", "run_amc"),
        ("backend.amc.solver", "solve_amc"),
        ("backend.amc.solver", "solve"),
        ("backend.amc.builder", "build_amc"),
    ]
    for module_path, fn_name in candidates:
        try:
            mod = __import__(module_path, fromlist=[fn_name])
            if hasattr(mod, fn_name):
                print(f"  [import] using {module_path}.{fn_name}")
                return getattr(mod, fn_name)
        except ImportError:
            continue
    return None


def _resolve_critical_paths() -> Optional[Callable]:
    """Try several known names for critical-paths extraction."""
    candidates = [
        ("backend.graph.centrality", "get_critical_paths"),
        ("backend.graph", "get_critical_paths"),
        ("backend.graph.attack_graph", "get_critical_paths"),
    ]
    for module_path, fn_name in candidates:
        try:
            mod = __import__(module_path, fromlist=[fn_name])
            if hasattr(mod, fn_name):
                return getattr(mod, fn_name)
        except ImportError:
            continue
    return None


# ── Serialization helper ───────────────────────────────────────────────────

def _serialize(obj: Any) -> Any:
    """Recursively convert dataclasses, enums, and unknown types into JSON-friendly forms."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_serialize(x) for x in obj]
    if hasattr(obj, "__dict__"):
        return {k: _serialize(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj


def _write(filename: str, payload: Any) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_serialize(payload), f, indent=2, default=str)
    print(f"  wrote {path.relative_to(Path.cwd())} ({path.stat().st_size:,} bytes)")


# ── Main pipeline ──────────────────────────────────────────────────────────

def main() -> None:
    print("\n=== NETVA Pipeline Trace ===\n")

    # ── Stage 1: raw ingestion ─────────────────────────────────────────────
    print("Stage 1: ingesting raw scan data...")
    raw = ingest_all(use_lab_defaults=True)

    _write("01_raw_nmap.json", {
        "host_count": len(raw["nmap"].hosts) if raw["nmap"] else 0,
        "hosts": raw["nmap"].hosts if raw["nmap"] else [],
    })
    _write("01_raw_acl.json", {
        "default_policy": raw["acl"].default_policy if raw["acl"] else None,
        "rule_count": len(raw["acl"].rules) if raw["acl"] else 0,
        "rules": raw["acl"].rules if raw["acl"] else [],
    })
    _write("01_raw_iam.json", {
        "link_count": len(raw["iam"].links) if raw["iam"] else 0,
        "links": raw["iam"].links if raw["iam"] else [],
    })
    _write("01_raw_cmdb.json", raw["cmdb"])

    # ── Stage 2: normalization ──────────────────────────────────────────────
    print("\nStage 2: normalizing into unified network model...")
    normalizer = Normalizer(cmdb=raw["cmdb"])
    network = normalizer.normalize(
        nessus=raw["nessus"],
        nmap=raw["nmap"],
        iac=raw["iac"],
        acl=raw["acl"],
        iam=raw["iam"],
        cmdb=raw["cmdb"],
    )

    assets_summary = []
    for ip, asset in network.assets.items():
        assets_summary.append({
            "ip": ip,
            "hostname": asset.hostname,
            "type": asset.asset_type,
            "zone": asset.zone.value,
            "criticality": asset.criticality,
            "criticality_source": "cmdb" if asset.cmdb_managed else "type-heuristic",
            "criticality_rationale": asset.cmdb_criticality_rationale or f"Type-based default for '{asset.asset_type}'",
            "open_ports": asset.open_ports,
            "vuln_count": asset.vuln_count,
            "max_cvss": asset.max_cvss,
            "cmdb_managed": asset.cmdb_managed,
            "cmdb_environment": asset.cmdb_environment,
            "cmdb_business_function": asset.cmdb_business_function,
            "cmdb_data_classification": asset.cmdb_data_classification,
            "cmdb_compliance_scope": asset.cmdb_compliance_scope,
            "flags": {
                k: v for k, v in vars(asset).items()
                if isinstance(v, bool) and v and k != "cmdb_managed"
            },
        })
    _write("02_assets_normalized.json", assets_summary)

    # ── Stage 3: edges grouped by source ───────────────────────────────────
    print("\nStage 3: edges grouped by inference source...")
    by_source: dict[str, list] = {"acl": [], "iam": [], "iac": [], "subnet": [], "other": []}
    for e in network.edges:
        rec = {
            "src": e.src_id,
            "dst": e.dst_id,
            "edge_type": e.edge_type,
            "ports": e.ports,
            "permitted_by": e.permitted_by,
            "link_type": e.link_type,
            "privilege_level": e.privilege_level.value,
        }
        if "ACL:" in e.permitted_by:
            by_source["acl"].append(rec)
        elif "IAM:" in e.permitted_by:
            by_source["iam"].append(rec)
        elif "IaC:" in e.permitted_by:
            by_source["iac"].append(rec)
        elif e.permitted_by == "same-subnet":
            by_source["subnet"].append(rec)
        else:
            by_source["other"].append(rec)
    _write("03_edges_by_source.json", {
        "totals": {k: len(v) for k, v in by_source.items()},
        "edges": by_source,
    })

    # ── Stage 4: reachability matrix ───────────────────────────────────────
    print("\nStage 4: building reachability matrix...")
    matrix = build_reachability(network)
    summary = effective_reachability_summary(matrix)
    _write("04_reachability.json", {
        "edge_count": len(summary),
        "edges": summary,
    })

    # ── Stage 5: attack graph (best-effort) ────────────────────────────────
    print("\nStage 5: building attack graph...")
    builder = _resolve_attack_graph_builder()
    G = None
    if builder is None:
        _write("05_attack_graph.json", {
            "error": "No attack-graph builder found. Tried backend.graph.attack_graph.build_attack_graph, build_nx_graph, etc."
        })
    else:
        try:
            # Try the wrapper signature first: builder(network)
            try:
                G = builder(network)
            except TypeError:
                # Fall back to build_nx_graph(mulval_result, network) signature.
                # Pass a minimal MulVAL stub.
                try:
                    from backend.graph.mulval_runner import MulVALResult  # type: ignore
                    G = builder(MulVALResult(), network)
                except Exception:
                    raise

            nodes_out = []
            for nid, data in G.nodes(data=True):
                nodes_out.append({
                    "id": nid,
                    "node_role": data.get("node_role", ""),
                    "host_id": data.get("host_id", ""),
                    "privilege": data.get("privilege", ""),
                    "criticality": data.get("criticality", 0.0),
                    "is_absorbing": data.get("is_absorbing", False),
                    "termination_reason": data.get("termination_reason", ""),
                    "zone": data.get("zone", ""),
                })

            edges_out = []
            for u, v, data in G.edges(data=True):
                edges_out.append({
                    "src": u,
                    "dst": v,
                    "edge_type": data.get("edge_type", ""),
                    "weight": round(float(data.get("weight", 0.0)), 4),
                    "vuln_id": data.get("vuln_id", ""),
                    "mechanism": data.get("mechanism", ""),
                    "requires_port": data.get("requires_port", 0),
                })

            _write("05_attack_graph.json", {
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "absorbing_states": [n for n, d in G.nodes(data=True) if d.get("is_absorbing")],
                "nodes": nodes_out,
                "edges": edges_out,
            })
        except Exception as e:
            _write("05_attack_graph.json", {
                "error": str(e),
                "traceback": traceback.format_exc(),
            })
            G = None

    # ── Stage 6: AMC results (best-effort) ─────────────────────────────────
    print("\nStage 6: running AMC solver...")
    amc_runner = _resolve_amc_runner()
    if amc_runner is None or G is None:
        _write("06_amc_results.json", {
            "error": "AMC runner not found or attack graph unavailable. "
                     "Tried backend.amc.runner.run_amc, backend.amc.solver.run_amc, etc."
        })
    else:
        try:
            try:
                amc = amc_runner(G, network)
            except TypeError:
                amc = amc_runner(G)
            _write("06_amc_results.json", {
                "transient_states": list(getattr(amc, "transient_states", [])),
                "absorbing_states": list(getattr(amc, "absorbing_states", [])),
                "absorption_per_node": {
                    nid: round(amc.absorption_prob(nid), 4)
                    for nid in getattr(amc, "transient_states", [])
                } if hasattr(amc, "absorption_prob") else {},
                "expected_steps_per_node": {
                    nid: round(amc.expected_steps(nid), 4)
                    for nid in getattr(amc, "transient_states", [])
                } if hasattr(amc, "expected_steps") else {},
                "node_risk": getattr(amc, "node_risk", {}),
            })
        except Exception as e:
            _write("06_amc_results.json", {
                "error": str(e),
                "traceback": traceback.format_exc(),
            })

    # ── Stage 7: critical paths (best-effort) ──────────────────────────────
    print("\nStage 7: extracting critical paths...")
    paths_fn = _resolve_critical_paths()
    if paths_fn is None or G is None:
        _write("07_critical_paths.json", {
            "error": "get_critical_paths not found or attack graph unavailable."
        })
    else:
        try:
            paths = paths_fn(G, top_n=5)
            _write("07_critical_paths.json", {
                "path_count": len(paths),
                "paths": [
                    {
                        "nodes": p.get("nodes", []),
                        "probability": round(float(p.get("probability", 0.0)), 4),
                        "length": p.get("length", 0),
                    }
                    for p in (paths or [])
                ],
            })
        except Exception as e:
            _write("07_critical_paths.json", {
                "error": str(e),
                "traceback": traceback.format_exc(),
            })

    print(f"\n=== Trace complete. Output in: {OUT_DIR} ===\n")


if __name__ == "__main__":
    main()