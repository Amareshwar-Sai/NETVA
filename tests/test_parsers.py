"""Tests for ingestion parsers."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ingestion.nessus_parser import parse_nessus, generate_lab_nessus_xml
from backend.ingestion.nmap_parser import parse_nmap, generate_lab_nmap_xml
from backend.ingestion.iac_parser import parse_iac, generate_lab_iac_json
from backend.ingestion.acl_parser import parse_acl, generate_lab_acl
from backend.ingestion.iam_parser import parse_iam, generate_lab_iam_json
from backend.ingestion import ingest_all


class TestNessusParser:
    def test_parse_lab_xml(self):
        xml = generate_lab_nessus_xml()
        result = parse_nessus(xml)
        assert len(result.hosts) == 3
        ips = {h.ip for h in result.hosts}
        assert "10.10.0.10" in ips
        assert "10.10.0.20" in ips
        assert "10.20.0.20" in ips

    def test_parse_fixture(self):
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "sample.nessus")
        with open(fixture) as f:
            result = parse_nessus(f.read())
        assert len(result.hosts) == 1
        assert result.hosts[0].vulns[0].cve == "CVE-2023-0001"


class TestNmapParser:
    def test_parse_lab_xml(self):
        xml = generate_lab_nmap_xml()
        result = parse_nmap(xml)
        assert len(result.hosts) >= 3
        webserver = [h for h in result.hosts if h.ip == "10.10.0.10"][0]
        ports = [p.port for p in webserver.ports]
        assert 80 in ports
        assert 22 in ports


class TestIaCParser:
    def test_parse_lab_json(self):
        data = generate_lab_iac_json()
        result = parse_iac(data)
        assert len(result.resources) == 4


class TestACLParser:
    def test_parse_lab_acl(self):
        text = generate_lab_acl()
        result = parse_acl(text)
        assert result.default_policy == "ACCEPT"
        assert len(result.rules) > 0


class TestIAMParser:
    def test_parse_lab_iam(self):
        data = generate_lab_iam_json()
        result = parse_iam(data)
        assert len(result.links) >= 2
        ssh_links = [l for l in result.links if l.link_type == "ssh_key"]
        assert len(ssh_links) >= 1


class TestIngestAll:
    def test_lab_defaults(self):
        raw = ingest_all(use_lab_defaults=True)
        assert raw["nessus"] is not None
        assert raw["nmap"] is not None
        assert raw["iac"] is not None
        assert raw["acl"] is not None
        assert raw["iam"] is not None
