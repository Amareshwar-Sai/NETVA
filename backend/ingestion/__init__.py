"""Ingestion layer — parse all scan data sources."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from backend.ingestion.nessus_parser import parse_nessus, generate_lab_nessus_xml
from backend.ingestion.nmap_parser import parse_nmap, generate_lab_nmap_xml
from backend.ingestion.iac_parser import parse_iac, generate_lab_iac_json
from backend.ingestion.acl_parser import parse_acl, generate_lab_acl
from backend.ingestion.iam_parser import parse_iam, generate_lab_iam_json
from backend.ingestion.cmdb_parser import parse_cmdb, generate_lab_cmdb_json, load_lab_cmdb


_REAL_NMAP_PATH = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "lab_nmap_scan.xml"
_REAL_CMDB_PATH = Path(__file__).resolve().parents[2] / "lab" / "cmdb.json"


def _load_real_nmap_xml() -> str | None:
    if _REAL_NMAP_PATH.is_file():
        try:
            return _REAL_NMAP_PATH.read_text()
        except Exception:
            return None
    return None


def _load_real_cmdb_json() -> str | None:
    if _REAL_CMDB_PATH.is_file():
        try:
            return _REAL_CMDB_PATH.read_text()
        except Exception:
            return None
    return None


def ingest_all(
    *,
    use_lab_defaults: bool = False,
    nessus_xml: str | None = None,
    nmap_xml: str | None = None,
    iac_json: str | None = None,
    acl_text: str | None = None,
    iam_json: str | None = None,
    cmdb_json: str | None = None,
) -> dict[str, Any]:
    """Ingest data from all sources, returning raw parsed objects.

    Priority for each source:
      1. Explicitly passed argument
      2. Real file on disk (nmap, cmdb)
      3. Synthetic generator (only if use_lab_defaults=True)
    """

    nmap_source = "synthetic"
    if nmap_xml is not None:
        nmap_source = "api_argument"
    else:
        real_nmap = _load_real_nmap_xml()
        if real_nmap:
            nmap_xml = real_nmap
            nmap_source = f"real_file ({_REAL_NMAP_PATH})"
    print(f"[ingest_all] nmap source: {nmap_source}")

    cmdb_source = "synthetic"
    if cmdb_json is not None:
        cmdb_source = "api_argument"
    else:
        real_cmdb = _load_real_cmdb_json()
        if real_cmdb:
            cmdb_json = real_cmdb
            cmdb_source = f"real_file ({_REAL_CMDB_PATH})"
    print(f"[ingest_all] cmdb source: {cmdb_source}")

    if use_lab_defaults:
        nessus_xml = nessus_xml or generate_lab_nessus_xml()
        nmap_xml = nmap_xml or generate_lab_nmap_xml()
        iac_json = iac_json or generate_lab_iac_json()
        acl_text = acl_text or generate_lab_acl()
        iam_json = iam_json or generate_lab_iam_json()
        cmdb_json = cmdb_json or generate_lab_cmdb_json()

    result: dict[str, Any] = {}
    result["nessus"] = parse_nessus(nessus_xml) if nessus_xml else None
    result["nmap"] = parse_nmap(nmap_xml) if nmap_xml else None
    result["iac"] = parse_iac(iac_json) if iac_json else None
    result["acl"] = parse_acl(acl_text) if acl_text else None
    result["iam"] = parse_iam(iam_json) if iam_json else None
    result["cmdb"] = parse_cmdb(cmdb_json) if cmdb_json else None

    return result