import sys
sys.path.insert(0, '.')
from backend.ingestion import ingest_all
from backend.normalization import Normalizer, Deduplicator

# Use real nmap, synthetic for everything else
raw = ingest_all(use_lab_defaults=True)
network = Normalizer().normalize(**raw)
network = Deduplicator().deduplicate(network)

print(f"\nTotal assets: {len(network.assets)}")
print(f"Total edges: {len(network.edges)}\n")

for ip, asset in network.assets.items():
    print(f"=== {asset.hostname or ip} ({ip}) ===")
    print(f"  Type: {asset.asset_type}, Zone: {asset.zone.value}, Criticality: {asset.criticality:.2f}")
    print(f"  Open ports: {asset.open_ports}")
    print(f"  Total vulns: {len(asset.vulns)}")
    print(f"  Critical/High: {asset.critical_vuln_count}/{asset.high_vuln_count}, Max CVSS: {asset.max_cvss:.1f}")

    flags_set = [k for k, v in {
        'phpinfo': asset.has_phpinfo,
        'exposed_git': asset.has_exposed_git,
        'backup_files': asset.has_exposed_backup_files,
        'default_creds': asset.has_default_credentials,
        'cmd_injection': asset.has_command_injection,
        'ssh_root_login': asset.ssh_root_login_enabled,
        'world_writable': asset.has_world_writable_files,
        'suid': asset.has_suid_binary,
    }.items() if v]
    if flags_set:
        print(f"  Flags: {', '.join(flags_set)}")

    # Top 5 vulns by CVSS
    top = sorted(asset.vulns, key=lambda v: v.cvss, reverse=True)[:5]
    for v in top:
        exp = "[EXP]" if v.exploit_available else "     "
        print(f"    {exp} {v.cve or v.vuln_id:18}  CVSS {v.cvss:.1f}  ({v.severity.value})")
    print()